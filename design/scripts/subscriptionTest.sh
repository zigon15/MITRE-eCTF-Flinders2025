mkdir ./output
python3 ../ectf25_design/gen_subscription.py ../../global.secrets ./output/subscription.bin 0xDEADBEEF 32 128 1 --force
# python3 ../ectf25_design/gen_subscription.py ../output/secrets.bin ../output/subscription.bin 0x12982789 32 128 3 --force