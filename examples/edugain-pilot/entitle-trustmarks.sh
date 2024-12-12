#!/bin/bash

docker exec edugain-pilot-puhuri-1 /tacli -c /data/config.yaml tm add https://puhuri.io https://puhuri.fedservice.lh
docker exec edugain-pilot-puhuri-1 /tacli -c /data/config.yaml tm add https://puhuri.io https://haka.fedservice.lh
docker exec edugain-pilot-puhuri-1 /tacli -c /data/config.yaml tm add https://puhuri.io https://surf-rp.fedservice.lh
docker exec edugain-pilot-puhuri-1 /tacli -c /data/config.yaml tm add https://puhuri.io https://puhuri-rp.fedservice.lh
