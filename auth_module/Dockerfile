FROM golang:1.21-alpine
WORKDIR /app
RUN apk add --no-cache git
COPY go.mod go.sum* ./
RUN go mod download
COPY main.go ./
RUN go build -o auth_service .
EXPOSE 8080
CMD ["./auth_service"]
