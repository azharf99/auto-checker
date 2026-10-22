# Stage 1: Build binary Golang (Zero CGO dengan modernc.org/sqlite)
FROM golang:1.26-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /app/auto-checker ./cmd/auto-checker

# Stage 2: Runtime ringan menggunakan Alpine
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata && mkdir -p /app/data
ENV TZ=Asia/Jakarta

WORKDIR /app
COPY --from=builder /app/auto-checker /app/auto-checker

EXPOSE 8080

ENTRYPOINT ["/app/auto-checker"]
CMD ["--serve", "--addr=:8080"]
