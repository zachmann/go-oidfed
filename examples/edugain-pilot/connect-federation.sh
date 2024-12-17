#!/bin/bash

docker exec edugain-pilot-edugain-1 /tacli -c /data/config.yaml subordinates add https://surfconext.fedservice.lh
docker exec edugain-pilot-edugain-1 /tacli -c /data/config.yaml subordinates add https://garr.fedservice.lh
docker exec edugain-pilot-edugain-1 /tacli -c /data/config.yaml subordinates add https://incommon.fedservice.lh
docker exec edugain-pilot-edugain-1 /tacli -c /data/config.yaml subordinates add https://haka.fedservice.lh
docker exec edugain-pilot-edugain-1 /tacli -c /data/config.yaml subordinates add https://sunet.fedservice.lh
docker exec edugain-pilot-edugain-1 /tacli -c /data/config.yaml subordinates add https://erasmus-plus.fedservice.lh

docker exec edugain-pilot-surf-1 /tacli -c /data/config.yaml subordinates add https://surf-rp.fedservice.lh

docker exec edugain-pilot-garr-1 /tacli -c /data/config.yaml subordinates add https://garr-rp.fedservice.lh

docker exec edugain-pilot-haka-1 /tacli -c /data/config.yaml subordinates add https://helsinki.fedservice.lh
docker exec edugain-pilot-haka-1 /tacli -c /data/config.yaml subordinates add https://puhuri.fedservice.lh

docker exec edugain-pilot-helsinki-1 /tacli -c /data/config.yaml subordinates add https://helsinki-rp.fedservice.lh

docker exec edugain-pilot-puhuri-1 /tacli -c /data/config.yaml subordinates add https://puhuri-rp.fedservice.lh
