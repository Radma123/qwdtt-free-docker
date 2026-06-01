# Stage 1: Build the Go application
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git make gcc musl-dev

WORKDIR /app

# Copy dependency manifests
COPY go.mod go.sum ./
RUN go mod download

# Copy the lightweight server source code
COPY socks-relay/server_socks.go ./

# Build the server binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server server_socks.go

# Stage 2: Runtime environment
FROM alpine:3.19

# Install iptables, iproute2 and ca-certificates (for secure public DNS TCP dials)
RUN apk add --no-cache \
    iproute2 \
    iptables \
    bash \
    ca-certificates

WORKDIR /app

COPY --from=builder /app/server /app/server

# Expose DTLS listen port
EXPOSE 56000/udp

ENTRYPOINT ["/app/server"]
CMD ["-listen", "0.0.0.0:56000", "-password", "secret", "-socks-server", "127.0.0.1:1080"]
