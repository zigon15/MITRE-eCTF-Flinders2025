python -m ectf25.utils.stress_test --test-size=100000 encode --dump="./enc_frames.bin" "../../global.secrets/secrets.bin"

# python -m ectf25.utils.stress_test --test-size=100000 decode "/dev/ttyACM0" "./enc_frames.bin"