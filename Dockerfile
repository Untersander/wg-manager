# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/wg-manager ./cmd/wg-manager

FROM alpine:3.23
RUN apk add --no-cache wireguard-tools nftables iproute2 ca-certificates
COPY --from=build /out/wg-manager /usr/local/bin/wg-manager
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
WORKDIR /app
COPY web /app/web
EXPOSE 8080/udp
EXPOSE 8080/tcp
ENTRYPOINT ["/entrypoint.sh"]
