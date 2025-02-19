FROM golang:1.21-bullseye AS builder

ENV GO111MODULE=on \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /build

COPY . /build/
RUN set -xe \
    && go mod download \
    && go build -o ./bin/smtpforwarder -ldflags "-s -w" -a ./main.go

FROM debian:11-slim

WORKDIR /app

RUN set -xe \
    && apt-get update && apt-get upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
ENV TZ=Asia/Shanghai

COPY --from=builder /build/bin /app/

EXPOSE 25 465 587
CMD ["/app/smtpforwarder"]