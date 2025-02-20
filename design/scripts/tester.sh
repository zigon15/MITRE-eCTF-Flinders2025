mkdir output

python3 -m ectf25_design.gen_subscription ../../global.secrets/secrets.bin ./output/subscription_c1.bin 0xDEADBEEF 32 128 1 --force
python -m ectf25.tv.subscribe ./output/subscription_c1.bin /dev/ttyACM0

python3 -m ectf25_design.gen_subscription ../../global.secrets/secrets.bin ./output/subscription_c2.bin 0xDEADBEEF 32 128 2 --force
python -m ectf25.tv.subscribe ./output/subscription_c2.bin /dev/ttyACM0

python3 -m ectf25_design.gen_subscription ../../global.secrets/secrets.bin ./output/subscription_c3.bin 0xDEADBEEF 32 128 3 --force
python -m ectf25.tv.subscribe ./output/subscription_c3.bin /dev/ttyACM0

python3 -m ectf25_design.gen_subscription ../../global.secrets/secrets.bin ./output/subscription_c4.bin 0xDEADBEEF 32 128 4 --force
python -m ectf25.tv.subscribe ./output/subscription_c4.bin /dev/ttyACM0

python -m ectf25.utils.tester -s="../../global.secrets/secrets.bin" -p="/dev/ttyACM0" --perf rand 