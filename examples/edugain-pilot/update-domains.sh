#!/bin/bash

find . -type f -exec sed -i "s/fedservice\.lh/${1}/g" {} +