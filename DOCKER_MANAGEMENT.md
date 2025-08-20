# Docker команды для управления RSS коннектором

Полный набор команд Docker и Docker Compose для установки, управления, мониторинга и удаления RSS коннектора.

## Установка и запуск

### Первый запуск
```bash
# Сборка и запуск в фоновом режиме
docker-compose up --build -d

# Сборка без кеша (принудительная пересборка)
docker-compose build --no-cache
docker-compose up -d

# Запуск с выводом логов
docker-compose up --build
```

### Перезапуск
```bash
# Перезапуск контейнера
docker-compose restart

# Перезапуск с пересборкой
docker-compose down
docker-compose up --build -d

# Перезапуск только коннектора
docker-compose restart rss-poc-connector
```

## Мониторинг и анализ

### Статус контейнеров
```bash
# Список всех контейнеров
docker ps -a

# Только запущенные контейнеры
docker ps

# Контейнеры RSS коннектора
docker ps | grep rss

# Статус конкретного контейнера
docker inspect rss-rss-poc-connector-1
```

### Логи и отладка
```bash
# Логи контейнера (все)
docker logs rss-rss-poc-connector-1

# Последние N строк логов
docker logs rss-rss-poc-connector-1 --tail 50

# Логи в реальном времени
docker logs rss-rss-poc-connector-1 -f

# Логи с временными метками
docker logs rss-rss-poc-connector-1 -t

# Логи за определенный период
docker logs rss-rss-poc-connector-1 --since "2025-08-20T10:00:00"
docker logs rss-rss-poc-connector-1 --until "2025-08-20T11:00:00"
```

### Анализ ресурсов
```bash
# Использование ресурсов контейнера
docker stats rss-rss-poc-connector-1

# Статистика всех контейнеров
docker stats

# Информация о контейнере
docker inspect rss-rss-poc-connector-1 | grep -A 10 -B 5 "State"

# Размер контейнера
docker system df
```

## Управление контейнером

### Остановка и запуск
```bash
# Остановка контейнера
docker-compose stop

# Запуск остановленного контейнера
docker-compose start

# Пауза контейнера
docker pause rss-rss-poc-connector-1

# Возобновление работы
docker unpause rss-rss-poc-connector-1
```

### Выполнение команд в контейнере
```bash
# Вход в контейнер (интерактивная оболочка)
docker exec -it rss-rss-poc-connector-1 /bin/sh

# Выполнение команды без входа
docker exec rss-rss-poc-connector-1 ls -la /opt/opencti-rss-connector/

# Проверка файла логов
docker exec rss-rss-poc-connector-1 cat /opt/opencti-rss-connector/connector.log

# Проверка кеша
docker exec rss-rss-poc-connector-1 cat poc_cache.json

# Проверка процессов
docker exec rss-rss-poc-connector-1 ps aux
```

### Копирование файлов
```bash
# Копирование файла из контейнера
docker cp rss-rss-poc-connector-1:/opt/opencti-rss-connector/connector.log ./connector.log

# Копирование файла в контейнер
docker cp ./config.yml rss-rss-poc-connector-1:/opt/opencti-rss-connector/

# Копирование директории
docker cp rss-rss-poc-connector-1:/opt/opencti-rss-connector/logs ./logs/
```

## Управление образами

### Работа с образами
```bash
# Список всех образов
docker images

# Образы RSS коннектора
docker images | grep rss

# Информация об образе
docker inspect rss-rss-poc-connector:latest

# История образа
docker history rss-rss-poc-connector:latest

# Размер образа
docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" | grep rss
```

### Управление кешем сборки
```bash
# Очистка неиспользуемых образов
docker image prune

# Очистка всех неиспользуемых образов
docker image prune -a

# Очистка кеша сборки
docker builder prune

# Полная очистка системы Docker
docker system prune -a
```

## Диагностика и отладка

### Анализ сети
```bash
# Сетевые настройки контейнера
docker network inspect docker_default

# Проверка подключения к OpenCTI
docker exec rss-rss-poc-connector-1 ping opencti

# Проверка DNS
docker exec rss-rss-poc-connector-1 nslookup opencti

# Сетевые порты
docker port rss-rss-poc-connector-1
```

### Анализ файловой системы
```bash
# Проверка дискового пространства в контейнере
docker exec rss-rss-poc-connector-1 df -h

# Размер рабочей директории
docker exec rss-rss-poc-connector-1 du -sh /opt/opencti-rss-connector/

# Список файлов в рабочей директории
docker exec rss-rss-poc-connector-1 find /opt/opencti-rss-connector/ -type f -name "*.log"
```

### Проверка переменных окружения
```bash
# Все переменные окружения
docker exec rss-rss-poc-connector-1 env

# Конкретные переменные
docker exec rss-rss-poc-connector-1 env | grep -E "(OPENCTI|CONNECTOR|RSS)"
```

## Очистка и удаление

### Остановка и удаление
```bash
# Остановка и удаление контейнера
docker-compose down

# Удаление контейнера без остановки
docker rm -f rss-rss-poc-connector-1

# Удаление образа
docker rmi rss-rss-poc-connector:latest

# Принудительное удаление образа
docker rmi -f rss-rss-poc-connector:latest
```

### Полная очистка
```bash
# Остановка всех контейнеров
docker stop $(docker ps -aq)

# Удаление всех контейнеров
docker rm $(docker ps -aq)

# Удаление всех образов
docker rmi $(docker images -q)

# Очистка всех данных Docker
docker system prune -a --volumes
```

## Мониторинг производительности

### Метрики контейнера
```bash
# Мониторинг в реальном времени
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"

# Детальная статистика
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}\t{{.PIDs}}"
```

### Анализ логов
```bash
# Поиск ошибок в логах
docker logs rss-rss-poc-connector-1 2>&1 | grep -i error

# Поиск предупреждений
docker logs rss-rss-poc-connector-1 2>&1 | grep -i warning

# Подсчет строк логов
docker logs rss-rss-poc-connector-1 | wc -l

# Экспорт логов в файл
docker logs rss-rss-poc-connector-1 > connector_logs.txt
```

## Резервное копирование

### Сохранение данных
```bash
# Экспорт контейнера в tar архив
docker export rss-rss-poc-connector-1 > rss_connector_backup.tar

# Сохранение образа в tar архив
docker save rss-rss-poc-connector:latest > rss_connector_image.tar

# Копирование важных файлов
docker cp rss-rss-poc-connector-1:/opt/opencti-rss-connector/config.yml ./backup/
docker cp rss-rss-poc-connector-1:/opt/opencti-rss-connector/poc_cache.json ./backup/
```

### Восстановление
```bash
# Загрузка образа из tar архива
docker load < rss_connector_image.tar

# Импорт контейнера из tar архива
cat rss_connector_backup.tar | docker import - rss-connector-backup:latest
```

## Полезные скрипты

### Автоматический перезапуск
```bash
#!/bin/bash
# restart_connector.sh
echo "Restarting RSS connector..."
docker-compose down
docker-compose up --build -d
echo "Connector restarted successfully"
```

### Мониторинг статуса
```bash
#!/bin/bash
# check_status.sh
if docker ps | grep -q rss-rss-poc-connector-1; then
    echo "✅ RSS connector is running"
    docker logs rss-rss-poc-connector-1 --tail 1
else
    echo "❌ RSS connector is not running"
    exit 1
fi
```

### Очистка старых логов
```bash
#!/bin/bash
# cleanup_logs.sh
echo "Cleaning up old logs..."
docker system prune -f
docker image prune -f
echo "Cleanup completed"
```

## Устранение неполадок

### Контейнер не запускается
```bash
# Проверка логов запуска
docker logs rss-rss-poc-connector-1

# Проверка конфигурации
docker-compose config

# Проверка переменных окружения
docker-compose config --services
```

### Проблемы с сетью
```bash
# Проверка сети Docker
docker network ls
docker network inspect docker_default

# Тест подключения
docker exec rss-rss-poc-connector-1 curl -I http://opencti:8080
```

### Проблемы с ресурсами
```bash
# Проверка использования ресурсов
docker stats --no-stream

# Очистка неиспользуемых ресурсов
docker system prune -f

# Проверка дискового пространства
df -h
docker system df
```
