#!/bin/bash
set -e

echo "Files:"
ls /global.secrets
printf "\n\n"

make release DECODER_ID=${DECODER_ID}
cp build/max78000.elf build/max78000.bin /out