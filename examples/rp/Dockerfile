FROM golang:1.24-alpine AS builder
WORKDIR /app


COPY ./ ./
RUN go mod download

RUN go build -o /oidfed-go-rp github.com/go-oidfed/lib/examples/rp

FROM debian:stable
RUN apt-get update && apt-get install -y ca-certificates && apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/*

COPY --from=builder /oidfed-go-rp .

EXPOSE 3333

CMD bash -c "update-ca-certificates && /oidfed-go-rp"
