# Generate global secrets
# python3 ../ectf25_design/gen_secrets.py ../../global.secrets 4294967295 --force

# Generate subscription
python3 ../ectf25_design/gen_subscription.py ../../global.secrets ./output/subscription.bin 0xDEADBEEF 32 128 4294967295 --force

# Encode frame
python ../ectf25_design/encoder.py ../../global.secrets 1 "frame to encode" 100