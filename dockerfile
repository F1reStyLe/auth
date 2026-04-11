FROM golang:1.25

WORKDIR /app

CMD ["sh", "-c", "go run ./cmd"]
