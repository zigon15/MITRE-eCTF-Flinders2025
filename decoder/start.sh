#!/bin/bash
set -e

echo "Files:"
ls /global.secrets
printf "\n\n"

echo "Mount Files:"
ls ./
printf "\n\n"

echo "Path:"
pwd

make release DECODER_ID=${DECODER_ID}
cp build/max78000.elf build/max78000.bin /out