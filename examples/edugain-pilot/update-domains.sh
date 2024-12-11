#!/bin/bash

find . -type f  -name "*.yaml"-exec sed -i "s/fedservice\.lh/${1}/g" {} +