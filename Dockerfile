# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go tool templ generate
RUN CGO_ENABLED=0 go build -o /out/wg-manager ./cmd/wg-manager

FROM alpine:3.23
RUN apk add --no-cache wireguard-tools nftables iproute2 ca-certificates
COPY --from=build /out/wg-manager /usr/local/bin/wg-manager
WORKDIR /app
COPY web /app/web
EXPOSE 8080/tcp
EXPOSE 51820/udp
ENTRYPOINT ["/usr/local/bin/wg-manager"]
