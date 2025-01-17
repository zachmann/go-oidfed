# Example TA/IA using go-oidfed library
This is an example Trust Anchor / Intermediate Authority / Trust Mark Issuer that uses the go-oidfed library from this repository.

It showcases how to easily set up a configurable federation entity.

The following is an example `config.yaml` file:

```yaml
server_port: 8765
entity_id: "https://go-ia.fedservice.lh"
authority_hints:
  - "https://trust-anchor.fedservice.lh/"
signing_key_file: "/data/signing.key"
organization_name: "GO oidc-fed Intermediate"
data_location: "/data/data"
human_readable_storage: true
metadata_policy_file: "/data/metadata-policy.json"
endpoints:
  fetch:
    path: "/fetch"
    url: "https://go-ia.fedservice.lh/fetch"
  list:
    path: "/list"
    url: "https://go-ia.fedservice.lh/list"
  resolve:
    path: "/resolve"
    url: "https://go-ia.fedservice.lh/resolve"
  trust_mark:
    path: "/trustmark"
    url: "https://go-ia.fedservice.lh/trustmark"
  trust_mark_status:
    path: "/trustmark/status"
    url: "https://go-ia.fedservice.lh/trustmark/status"
  trust_mark_list:
    path: "/trustmark/list"
    url: "https://go-ia.fedservice.lh/trustmark/list"
  enroll:
    path: "/enroll"
    url: "https://go-ia.fedservice.lh/enroll"
    checker:
        type: trust_mark
        config:
          trust_mark_id: https://go-ia.federservice.lh/tm/federation-member
          trust_anchors:
            - entity_id: https://go-ia.fedservice.lh
trust_mark_specs:
  - trust_mark_id: "https://go-ia.federservice.lh/tm/federation-member"
    lifetime: 86400
    extra_claim: "example"
    checker:
      type: none
trust_mark_issuers:
  "https://go-ia.federservice.lh/tm/federation-member":
    - "https://go-ia.fedservice.lh"
trust_marks:
  - id: "https://go-ia.federservice.lh/tm/federation-member"
    trust_mark: "eyJhbGciOiJFUzUxMiIsImtpZCI6IlpsSFBmQXJTRnFGdjNHRlh3ZUptbmFkZDI4YTM4X3plcEJybEZkWHdIaTQiLCJ0eXAiOiJ0cnVzdC1tYXJrK2p3dCJ9.eyJleHAiOj..."
  - id: "https://trust-anchor.federservice.lh/tm/federation-member"
    trust_mark: "eyJhbGciOiJFUzUxMiIsImtpZCI6InpFLTlhVlhJanJZOUcxVU0tYURQVkxVR1RkWmFuOTk0NlJJUWhraWFjUVkiLCJ0eXAiOiJ0cnVzdC1tYXJrK2p3dCJ9.eyJleHAiO..."
```

An example docker compose file to run multiple intermediate /
trust anchors and relying parties in a small example federation can be found 
at [examples/edugain-pilot](../edugain-pilot):

## Endpoints

The following endpoints are available:

| Endpoint                      | Config Parameter     | Description                                                                                                                                                                                |
|-------------------------------|----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Federation Config             | n/a                  | Always enabled. The federation endpoint where the entity configuration is published.                                                                                                       |
| Fetch                         | `fetch`              | Federation Subordinate Fetch Endpoint per Spec Section 8.1                                                                                                                                 |
| Subordinate Listing           | `list`               | Federation Subordinate Listing Endpoint per Spec Section 8.2                                                                                                                               |
| Resolve                       | `resolve`            | Resolve Endpoint per Spec Section 8.3                                                                                                                                                      |
| Trust Mark Status             | `trust_mark_status`  | Trust Mark Status Endpoint per Spec Section 8.4 but without the `iat` parameter                                                                                                            |
| Trust Marked Entities Listing | `trust_mark_listing` | Trust Marked Entities Listing Endpoint per Spec Section 8.5                                                                                                                                |
| Trust Mark                    | `trust_mark`         | Trust Mark Endpoint per Spec Section 8.6                                                                                                                                                   |
| Federation Historical Keys    | `historical_keys`    | Not Yet Implemented! Historical Keys Endpoint per Spec Section 8.7                                                                                                                         |
| Enrollment                    | `enroll`             | An endpoint where entities can automatically enroll into the federation. For details see #enrolling-entities                                                                               |
| Request Enrollment            | `enroll_request`     | An endpoint where entities can request enrollment into the federation. An federation administrator then can check and approve the request. The request is analog to the enroll request     |
| Trust Mark Request            | `trust_mark_request` | An endpoint where entities can request to be entitled for a trust mark. A federation administrator then can check and approve the request. The request is analog to the trust mark request |

## Enrolling Entities

The TA/IA has a custom enrollment / onboarding endpoint that can be configured as all endpoints in the config file.
This endpoint is used to easily add entities to the federation. Entities can
also be manually added to the database (or with a simple command line
application).

The enrollment endpoint can also be guarded by so-called *entity checks* (for
more information about entity checks, see below). If the enroll endpoint is
enabled, but no checks defined, all entities can enroll.

### Enrollment Request

To enroll, the entity sends a `POST` request to the enroll endpoint with the following request parameter:
- `sub` REQUIRED: Its entity id
- `entity_type` RECOMMENDED: Its entity type

`entity_type` can be provided multiple times to pass multiple entity types.

The TA/IA will query the entities federation endpoint for its entity configuration and obtain the jwks from there and (if configured) performs the entity checks.

## Entity Checks
With the *entity checks* mechanism checks on an entity can be defined. The
One can define their own entity checks by implementing the `EntityChecker` interface and registering it through the `RegisterEntityChecker` function before loading the config file.

The following entity checks are already implemented and supported by this
library:
- `none`: Always forbids access
- `trust_mark`: Checks if the entity advertises a trust mark and verifies that it is valid
- `trust_path`: Checks if there is a valid trust path from the entity to the defined trust anchor
- `authority_hints`: Checks if the entity's `authority_hints` contains the defined entity id
- `entity_id`: Checks if the entity's `entity_id` is one of the defined ones
- `multiple_and`: Used to combine multiple `EntityChecker` using AND
- `multiple_or`: Used to combine multiple `EntityChecker` using OR

In the following we describe in more details how to configure the different
entity checkers:

### None
No additional configuration applicable.

#### Example
```yaml
checker:
  type: none
```

### Trust Mark
For a trust mark entity checker you must configure the trust mark id of the
trust mark that should be checked. Additional one must provide either trust
anchors or the trust mark issuer's jwks and in the case of delegation
information about the trust mark owner.

#### Config Attributes

| Claim                  | Necessity                                                       | Description                                                  |
|------------------------|-----------------------------------------------------------------|--------------------------------------------------------------|
| `trust_mark_id`         | REQUIRED                                                        | The trust mark id of the trust mark to check                 |
| `trust_anchors`          | REQUIRED unless `trust_mark_issuer_jwks` is given               | A list of trust anchors used to verify the trust mark issuer |
| `trust_mark_issuer_jwks` | REQUIRED if `trust_anchors` is not given                        | The jwks of the trust mark issuer                            |
| `trust_mark_owner`      | REQUIRED if `trust_anchors` is not given and delegation is used | Information about the trust mark owner                       |

The `trust_anchors` claim is a list where each element can have the following
attributes:

| Claim       | Necessity | Description                                                                     |
|-------------|-----------|---------------------------------------------------------------------------------|
| `entity_id` | REQUIRED  | The entity id of the trust anchor                                               |
| `jwks`      | OPTIONAL  | The trust anchors jwks; if omitted it is obtained from its Entity Configuration |

The `trust_mark_owner` claim has the following attributes:

| Claim       | Necessity | Description                           |
|-------------|-----------|---------------------------------------|
| `entity_id` | REQUIRED  | The entity id of the trust mark owner |
| `jwks`      | REQUIRED  | The trust mark owner's jwks           |


#### Examples
```yaml
checker:
  type: trust_mark
  config:
    trust_mark_id: https://tm.example.org
    trust_anchors:
      - entity_id: https://ta.example.org
```

```yaml
checker:
  type: trust_mark
  config:
    trust_mark_id: https://tm.example.org
    mark_issuer_jwks: {"keys":[{"alg":"ES512","crv":"P-521","kid":"E6XirVKtuO2_76Ly8Lw1cS_W4FUfw_lx5M_z33aMO-I","kty":"EC","use":"sig","x":"AbZpRmHJVpqqJ2q4bFMPto5jVhReNe0toBHWm0y-AhdpqYIqLA-J3ICr_I42BgmC4pG9lQE4qU8mJjkX1I__PDK8","y":"AFl9aVDzsUJPbyxDe96FuLWJNYNOo68WcljWEXJ0QzsFaTDUtykNe1lf3UoOXQWnvNQ1eD2iyWTef1gRR9A6HOSI"}]}
    trust_mark_owner:
      entity_id: https://ta.example.org
      jwks: {"keys":[{"alg":"ES512","crv":"P-521","kid":"gChx94HqIDTscqMzxDps6degt2j_Z7OrDsx0Fc24rKA","kty":"EC","use":"sig","x":"AAyVRMA84JsAtJ9z3qKVzgBN1DL8lDIrHRRYtnYiSkfe-i0V7W21QJ_VBBRF3kWFEYadRL9z4yJC7gYvsojF6p8C","y":"AYx1JCtCfrvNR8x8KibI2mQJKAsszjslfd8WlTha8lxtvncpg5c-UxjJgpCYRo3jwdvxUCa6LKHu0TzbUhKfFK8f"}]}
```

### Trust Path

For a trust path entity checker you must configure the trust anchors that should
be used to verify that there is an existing trust path to one of these trust
anchors.

#### Config Attributes

| Claim           | Necessity | Description                                           |
|-----------------|-----------|-------------------------------------------------------|
| `trust_anchors` | REQUIRED  | A list of trust anchors used to verify the trust path |

The `trust_anchors` claim is a list where each element can have the following
attributes:

| Claim       | Necessity | Description                                                                     |
|-------------|-----------|---------------------------------------------------------------------------------|
| `entity_id` | REQUIRED  | The entity id of the trust anchor                                               |
| `jwks`      | OPTIONAL  | The trust anchors jwks; if omitted it is obtained from its Entity Configuration |


#### Example
```yaml
checker:
  type: trust_path
  config:
    trust_anchors:
      - entity_id: https://ta.example.org
```

### Authority Hints

For an authority hints entity checker you must configure the entity id that
should be present in the authority hints.

#### Config Attributes

| Claim       | Necessity | Description                                                          |
|-------------|-----------|----------------------------------------------------------------------|
| `entity_id` | REQUIRED  | The entity id that should be present in the entity's authority hints |

#### Example
```yaml
checker:
  type: authority_hints
  config:
    entity_id: https://ia.example.org
```

### Entity IDs

For an entity id entity checker you must configure the entity id(s) that
are allowed.

#### Config Attributes

| Claim        | Necessity | Description                  |
|--------------|-----------|------------------------------|
| `entity_ids` | REQUIRED  | A list of allowed entity ids |

#### Example
```yaml
checker:
  type: entity_id
  config:
    entity_ids: 
      - https://op1.example.org
      - https://op2.example.org
```

### Multiple
To combine multiple entity checkers (either with and or or) one must provide all
entity checkers:

#### Examples:
```yaml
checker:
  type: multiple_and
  config:
    - type: trust_path
      config:
        trust_anchors:
          - entity_id: https://ta.example.org
    - type: multiple_or
      config:
        - type: trust_mark
          config: 
            trust_mark_id: https://tm.example.com
            trust_anchors:
              - entity_id: https://ta.example.com
        - type: trust_mark
          config: 
          trust_mark_id: https://tm.example.org
            trust_anchors:
              - entity_id: https://ta.example.org
```



## Trust Mark Issuance
The issuance of trust marks boils down to "if you are on the list of entities
that can obtain this trust mark, we will issue the trust mark".
Therefore, our trust mark issuer implementation manages a list of entities that
can obtain each trust mark.

It is possible to use the entity checks mechanism to dynamically add entities to
that list. I.e. any `EntityChecker` can be used on the trust mark endpoint,
resulting in the following behavior of the trust mark issuer:
- If the subject entity is already in the list the trust mark is issued.
- If not, and no checks are defined, no trust mark is issued.
- If not, and checks are defined, the checks are evaluated.
- If the checks are positive, the entity is added to the list and a trust mark is issued.
- If the checks are negative, no trust mark is issued.

