# Multi-stage build for minimal attack surface
FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod ./
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /bin/proxy ./cmd/proxy
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /bin/token-dispenser ./cmd/token-dispenser
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /bin/upstream ./examples/upstream

# Minimal runtime image
FROM alpine:3.20

RUN apk --no-cache add ca-certificates curl

WORKDIR /root/
COPY --from=builder /bin/proxy /usr/local/bin/proxy
COPY --from=builder /bin/token-dispenser /usr/local/bin/token-dispenser
COPY --from=builder /bin/upstream /usr/local/bin/upstream
COPY examples/config.json /etc/ztna/config.json

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/proxy", "-config", "/etc/ztna/config.json"]
