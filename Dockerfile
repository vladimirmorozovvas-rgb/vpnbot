# Сборка (используем официальный образ 1.25)
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o bot main.go


# Финальный образ
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata && \
    cp /usr/share/zoneinfo/Etc/UTC /etc/localtime && \
    echo "UTC" > /etc/timezone && \
    adduser -D -g '' botuser

COPY --from=builder /app/bot /usr/local/bin/bot
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

USER botuser
WORKDIR /home/botuser

ENTRYPOINT ["bot"]