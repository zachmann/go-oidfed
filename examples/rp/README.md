# Example RP using go-oidfed library
This is an example RP that uses the go-oidfed library from this repository.

It is very rudimentary and by no-means meant as a production RP. It's just for demonstration purposes.

It also does not do anything useful.

## How to deploy / setup

The gorp is provided as an docker image `myoidc/oidfed-gorp`.

One can run it like:
```bash
docker run -v gorp-keys:/keys -v /path/to/config/config.yaml:/config.yaml
```

However, you probably want to run it with other components, so a docker compose
might make more sense. We provide an example set up it the ta example.

Here is an example `config.yaml`:

```yaml
server_addr: ":3333"
entity_id: "https://gorp.fedservice.lh"
organisation_name: Example Organisation
trust_anchors:
  - entity_id: "https://trust-anchor.fedservice.lh/"
authority_hints:
  - "https://ia.fedservice.lh/"
key_storage: /keys
filter_to_automatic_ops: false
enable_debug_log: true

trust_marks:
  - id: https://example.com/trustmark
    trust_mark: "eyJhbGciOiJFUzUxMiIsImtpZCI6IlpsSFBmQXJTRnFGdjNHRlh3ZUptbmFkZDI4YTM4X3plcEJybEZkWHdIaTQiLCJ0eXAiOiJ0cnVzdC1tYXJrK2p3dCJ9.eyJleHAi...."
```

