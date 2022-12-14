# hack

Для запуска достаточно просто выполнить `docker-compose up`  
Открываем в браузере `http://localhost:80/` и вуаля - можем работать (если порт не занят)

## Конфигурация
Создав файл `.env` можно задать в нем следующие параметры:
- `POSTGRES_USER`=
- `POSTGRES_PASSWORD`=
- `POSTGRES_DB`=

Если эти значения не заданы, выставляются значения по умолчанию

## Архитектура
Продукт построен на пяти микросервисах:
- **frontend** [:80]: "лицо" - web ui для взаимодействия кликами, а не по API
- **engine** [:5000]: "сердце системы" - поисковик сертификатов
- **validator** [:5001]: "контролер" - сервис, обеспечивающий проверку соответствия сертификатов заданным конфигурацией правилам
- **storage** [:5002]: "хранилище" - микросервис для работы с БД, хранящей сертификаты
- **db** [:5432]: "БД" - непосредственно само хранилище данных (СУБД PostgreSQL)

## Endpoint'ы
### frontend
- `/`: html-страничка с сертификатами из БД
- `/hosts`: страница с хостами, на которых обнаружены сертификаты
- `/scan`: страница для запуска сканирования
- `/config`: страница для настройки валидатора
###

### engine
- `/` [GET: `ip`]: проверяет [диапазон] IP адресов на всех портах на наличие сертификата.  
Возвращает JSON вида `host: {port[..s]: {<cert_data>} }`

### validator
- `/` [GET]: возвращает проверенный в соответствии с конфигурацией список сертификатов с выявленными замечаниями
- `/` [POST: `filters`]: устанавливает фильтры конфигурации
- `/filters` [GET]: возвращает текущий список установленных фильтров

### storage
- `/certs` [GET]: возвращает сертификаты из БД в JSON формате
- `/certs` [POST: `cert`]: добавляет сертификаты в БД
- `/hosts` [GET]: возвращает хосты из БД в JSON формате
- `/hosts` [POST: `host`]: добавляет хосты в БД

## Структуры
`ip`: IPv4 или IPv6 (в т.ч. с маской) 

 `filters`:  
 {  
    `check_expired`: *bool*,  
    `expire_in`: *int*,  
    `issuers`: *[]*,  
    `key_length`: *int*,  
    `tls_disallowed`: *[]*,  
    `validity_period`: *int*,  
    `warn_self_signed`: *bool*,  
    `warn_weak_ciphers`: *bool*  
}

`cert`:  
{  
    `cipher`: "",  
    `fingerprint`: "",  
    `issuer`: "",  
    `pubkey_bit_size`: *int*,  
    `self_signed`: *bool*,  
    `tls_version`: "",  
    `v_end`: *int*,  
    `v_length`: *int*,  
    `v_start`: *int*  
}  

`host`:  
{  
    `host`: `ip`,  
    `port`: *int*,  
    `cert_id`: *int*  
}
