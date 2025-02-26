cd ../
./scripts/build-release.sh
python -m ectf25.utils.flash ./build/decoder_release.bin /dev/ttyACM0
