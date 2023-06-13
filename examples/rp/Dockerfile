FROM golang:1.20-alpine AS builder
WORKDIR /app


COPY ./ ./
RUN go mod download

RUN go build -o /oidcfed-go-rp github.com/zachmann/go-oidcfed/examples/rp

FROM debian:stable
RUN apt-get update && apt-get install -y ca-certificates && apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/*

COPY --from=builder /oidcfed-go-rp .

EXPOSE 3333

CMD bash -c "update-ca-certificates && /oidcfed-go-rp"
