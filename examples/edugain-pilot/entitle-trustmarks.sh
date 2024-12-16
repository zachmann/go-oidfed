#!/bin/bash

docker exec edugain-pilot-edugain-1 /tacli -c /data/config.yaml tm add https://edugain.org/member https://edugain.fedservice.lh

docker exec edugain-pilot-garr-1 /tacli -c /data/config.yaml tm add https://refeds.org/sirtfi https://garr.fedservice.lh

docker exec edugain-pilot-puhuri-1 /tacli -c /data/config.yaml tm add https://puhuri.io https://puhuri.fedservice.lh
docker exec edugain-pilot-puhuri-1 /tacli -c /data/config.yaml tm add https://puhuri.io https://haka.fedservice.lh
docker exec edugain-pilot-puhuri-1 /tacli -c /data/config.yaml tm add https://puhuri.io https://surf-rp.fedservice.lh
docker exec edugain-pilot-puhuri-1 /tacli -c /data/config.yaml tm add https://puhuri.io https://puhuri-rp.fedservice.lh
