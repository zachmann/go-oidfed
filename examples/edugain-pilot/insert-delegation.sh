#!/bin/bash

GID=$(id -g)

docker run --rm --user "${UID}":"${GID}" -v "${PWD}/refeds/:/refeds" myoidc/oidfed-gota /tacli delegation --json /refeds/tm_delegation.yaml

REFEDS_JWKS=$(jq -c .jwks < refeds/tm_delegation.json)

find . -type f -name "config.yaml" -exec sed -i "s/%REFEDS_JWKS%/${REFEDS_JWKS}/g" {} +
jq -c '.trust_marks[0].trust_mark_issuers[]' < refeds/tm_delegation.json | while read -r obj; do
  ENTITY_ID=$(echo "$obj" | jq -r '.entity_id')
  DELEGATION_JWT=$(echo "$obj" | jq -r '.delegation_jwt')
  DOMAIN=${ENTITY_ID#https://}   # Remove the scheme (https://)
  ENTITY=${DOMAIN%%.*}     # Extract everything before the first dot
  ENTITY=${ENTITY^^}
  VAR_NAME="%REFEDS_DELEGATION_JWT_${ENTITY}%"
  find . -type f -name "config.yaml" -exec sed -i "s/${VAR_NAME}/${DELEGATION_JWT}/g" {} +
done