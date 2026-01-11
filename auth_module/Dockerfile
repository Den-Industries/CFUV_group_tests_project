FROM golang:1.21-alpine

WORKDIR /app

# Устанавливаем зависимости для сборки
RUN apk add --no-cache git

# Копируем файлы зависимостей
COPY go.mod go.sum* ./

# Загружаем зависимости
RUN go mod download

# Копируем исходный код
COPY main.go ./

# Собираем приложение
RUN go build -o auth_service .

EXPOSE 8080

CMD ["./auth_service"]
