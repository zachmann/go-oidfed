# Example RP using go-oidcfed library
This is an example RP that uses the go-oidcfed library from this repository.

It is very rudimentary and by no-means meant as a production RP. It's just for demonstration purposes.

## How to deploy / setup

### Domain name

To change the domain name, replace `gorp.fedservice.lh` with the new domain name everywhere where it appears in:
- `config.yaml`
- `docker-compose.yaml`

### Traefik & Cert
We assume a traefik instance is running within the `traefik` docker network.
You also need a certificate for the hostname.

Additional certificates for possibly other instances (i.e. federation entities), can be provided in a `mkcertRootCA.
pem` file.

### Config
Look into the `config.yaml` and adapt the config to your needs.

### Run it
```bash
docker-compose up
```