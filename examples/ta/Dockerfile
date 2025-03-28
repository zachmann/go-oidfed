FROM golang:1.24-alpine AS builder
WORKDIR /app


COPY ./ ./
RUN go mod download

RUN go build -o /oidfed-go-ta github.com/zachmann/go-oidfed/examples/ta
RUN go build -o /tacli github.com/zachmann/go-oidfed/examples/ta/cli

FROM debian:stable
RUN apt-get update && apt-get install -y ca-certificates && apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/*

COPY --from=builder /oidfed-go-ta .
COPY --from=builder /tacli .

CMD bash -c "update-ca-certificates && /oidfed-go-ta /data/config.yaml"
