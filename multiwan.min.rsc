#!/usr/bin/env lua

:local gwList [:toarray "192.168.66.1, 192.168.77.1"]
:local connDelay 200s
:local inetDelay 5s
:local realIpList [:toarray "172.10.32.144, 173.12.145.222"]
:global portsList [:toarray "80, 1050, 2222, 5555"]
:global pingTarget 208.67.222.222
:global pingCount 5
:global ipPbx "192.168.88.2"
:global routeComment "ROUTE"
:global pbxComment "BLOCK"
:global dstnatComment "DSTNAT"

:local IsINetUp do={
    :global pingCount
    :global pingTarget
    :if ([ping $pingTarget count=$pingCount]=0) do={
        :return false
    } else={
        :return true
    }
}

:local GetDefaultRoute do={
    :global routeComment
    :return [/ip route get [find comment=$routeComment] gateway]
}

:local AddDefaultRoute do={
    :global routeComment
    /ip route add dst-address="0.0.0.0/0" gateway=$1 comment=$routeComment
}

:local RemDefaultRoute do={
    :global routeComment
    /ip route remove [find comment=$routeComment]
}

:local RemPbxConns do={
    :global ipPbx
    /ip firewall connection remove [find src-address=$ipPbx]
}

:local BlockPbxConns do={
    :global ipPbx
    :global pbxComment
    /ip firewall filter add chain=forward src-address=$ipPbx action=drop comment=$pbxComment
}

:local UnBlockPbxConns do={
    :global pbxComment
    /ip firewall filter remove [find comment=$pbxComment]
}

:local AddDstNatRules do={
    :global dstnatComment
    :global ipPbx
    :global portsList
    foreach i in=$portsList do={
        /ip firewall nat add chain=dstnat protocol=tcp action=dst-nat dst-address=$1 dst-port=[:tonum $i] to-addresses=$ipPbx to-ports=[:tonum $i] comment=$dstnatComment
        /ip firewall nat add chain=dstnat protocol=udp action=dst-nat dst-address=$1 dst-port=[:tonum $i] to-addresses=$ipPbx to-ports=[:tonum $i] comment=$dstnatComment
    }
}

:local RemDstNatRules do={
    :global dstnatComment
    /ip firewall nat remove [find comment=$dstnatComment]
}

:local NatRulesExist do={
    :global dstnatComment
    :local natRulesCount [:len [/ip firewall nat find comment=$dstnatComment]]
    if ($natRulesCount>0) do={
        :return true
    } else={
        :return false
    }
}

:local currentGW
:do {
    :set currentGW [$GetDefaultRoute]
} on-error={ :set currentGW [:tostr [:pick $gwList 0]] }
:local loopCount [:len $gwList]
:local counter 0
:if ([$IsINetUp]=false) do={
    :while ($counter<$loopCount) do={
        :local gwAddress [:tostr [:pick $gwList $counter]]
        :local realIP [:tostr [:pick $realIpList $counter]]
        if ($gwAddress!=$currentGW) do={
            $BlockPbxConns
            $RemPbxConns
            $RemDstNatRules
            $RemDefaultRoute
            $AddDefaultRoute $gwAddress
            :delay $inetDelay
            :if ([$IsINetUp]=true) do={
                :delay $connDelay
                :set counter $loopCount
            }
            $UnBlockPbxConns
            $AddDstNatRules $realIP
        }
        :set counter ($counter + 1)
    }
} else={
    :if ([$NatRulesExist]=false) do={
        :local pos [:find $gwList $currentGW]
        $AddDstNatRules [:tostr [:pick $realIpList $pos]]
    }
}
