############################################################################
#                                                                          #
#                        Mikrotik MultiWAN PBX Script                      #
#                                Version 1.0                               #
#                                                                          #
############################################################################
#                                                                          #
#  Вне зависимости от количества шлюзов, существует один основной          #
#  канал, все остальные являются резервными. При падении основного канала  #
#  осуществляется поиск первого рабочего и переход на него. Переход на     #
#  новый канал выполняется путем удаления текущего маршута по-умолчанию    #
#  и добавления нового с указанием адреса шлюза резервного канала.         #
#  Перед переключением выжидается пауза для сброса сессии голосового       #
#  шлюза по таймауту, а также удаление всех соединений с голосовым шлюзом  #
#  в таблице conntrack.                                                    #
#                                                                          #
############################################################################


##############################################
## Инициализация
##############################################

# Массив из адресов шлюзов каждого  из каналов
# В начале массива следует расположить адрес
# более стабильно работающего канала
:local gwList [:toarray "192.168.66.1, 192.168.77.1"]
# Продолжительность паузы между переключениями
:local connDelay 200s
# Продолжительность паузы перед повторной проверкой связи
:local inetDelay 5s
# Адрес, используемый для проверки связи
:global pingTarget 208.67.222.222
# Количество пингов при проверке
:global pingCount 5
# Адрес голосового шлюза
:global ipPbx "192.168.88.2"
# Комментарий для маршрута по-умолчанию
:global routeComment "ROUTE"
# Комментарий для правила блокировки
:global pbxComment "BLOCK"


##############################################
## Функции
##############################################

# Функция проверят, есть ли связь
# Формат вызова :put [$IsINetUp]
:local IsINetUp do={
    :global pingCount
    :global pingTarget
    :if ([ping $pingTarget count=$pingCount]=0) do={
        :return false
    } else={
        :return true
    }
}

# Функция возвращает шлюз маршрута по-умолчанию
# Формат вызова :put [$GetDefaultRoute]
:local GetDefaultRoute do={
    :global routeComment
    :return [/ip route get [find comment=$routeComment] gateway]
}

# Функция добавляет маршрут по-умолчанию с указанным шлюзом
# Формат вызова $AddDefaultRoute "192.168.66.1"
:local AddDefaultRoute do={
    :global routeComment
    /ip route add dst-address="0.0.0.0/0" gateway=$1 comment=$routeComment
}

# Функция удаляет маршрут по-умолчанию
# Формат вызова $RemDefaultRoute
:local RemDefaultRoute do={
    :global routeComment
    /ip route remove [find comment=$routeComment]
}

# Функция удаляет все соединения голосового шлюза
# Формат вызова $RemPbxConns
:local RemPbxConns do={
    :global ipPbx
    /ip firewall connection remove [find src-address=$ipPbx]
}

# Функция блокирует соединения голосового шлюза
# Формат вызова $BlockPbxConns
:local BlockPbxConns do={
    :global ipPbx
    :global pbxComment
    /ip firewall filter add chain=forward src-address=$ipPbx action=drop comment=$pbxComment
}

# Функция разблокирует соединения голосового шлюза
# Формат вызова $UnBlockPbxConns
:local UnBlockPbxConns do={
    :global pbxComment
    /ip firewall filter remove [find comment=$pbxComment]
}


##############################################
## Основной код
##############################################

# Получив адрес шлюза мы поймем какой
# из каналов в данный момент активен
:local currentGW
:do {
    :set currentGW [$GetDefaultRoute]
} on-error={ :set currentGW [:tostr [:pick $gwList 0]] }
# Максимальное количество итераций цикла
# должно быть равно количеству шлюзов
:local loopCount [:len $gwList]
# Счеткик цикла
:local counter 0
# Проверку имеет смысл делать только, если
# на активном канале нет связи
:if ([$IsINetUp]=false) do={
    :while ($counter<$loopCount) do={
        # Получаем адрес шлюза из массива
        :local gwAddress [:tostr [:pick $gwList $counter]]
        # Проверять будем только шлюз,
        # отличный от активного
        if ($gwAddress!=$currentGW) do={
            # Если соединение голосового шлюза активно и
            # при этом осуществляется попытка соединения
            # с другого адреса, учетная запись отправляется
            # в бан на 40 минут. Чтобы избежать этого, мы
            # блокируем соединение на файрволе, а позже 
            # выставляем паузу в 3 минуты для предварительного
            # отключения соединения по таймауту
            $BlockPbxConns
            $RemPbxConns
            $RemDefaultRoute
            $AddDefaultRoute $gwAddress
            # Канал может заработать не мгновенно,
            # поэтому стоит выдержать небольшую
            # паузу перед его проверкой
            :delay $inetDelay
            # Генерировать паузу стоит лишь в случае
            # наличия связи на проверяемом канале
            :if ([$IsINetUp]=true) do={
                :delay $connDelay
                # Работающий резервный канал найден,
                # поэтому нет смысла перебирать остальные
                :set $counter $loopCount
            }
            $UnBlockPbxConns
        }
        # Нумерация начинается с 0
        :set counter ($counter + 1)
    }
}