# Example TA/IA using go-oidcfed library
This is an example Trust Anchor / Intermediate Authority that uses the go-oidcfed library from this repository.

It is not production-ready, but serves as a demonstration.

## Enrolling Entities

The TA/IA has an enrollment / onboarding endpoint under `/enroll`. This endpoint can be used to easily add entities 
to the federation. In a production system this should not be public.

The enrolling entities does a `POST` request to this endpoint with the following request parameter:
- `sub` REQUIRED: Its entity id
- `entity_type` RECOMMENDED: Its entity type

The TA will query the entities federation endpoint for its entity configuration and obtain the jwks from there. The 
TA also checks that it is listed in the entity's `authority_hints`.


