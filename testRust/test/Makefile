TARGET = thumbv7em-none-eabi

debug:
	cargo build --target=$(TARGET)
	cp target/$(TARGET)/debug/test target/$(TARGET)/debug/test.bin
	cargo strip --target=$(TARGET) -- --strip-all target/$(TARGET)/debug/test.bin
	cargo objcopy --target=$(TARGET) -- -O binary target/$(TARGET)/debug/test.bin

release:
	cargo build --target=$(TARGET) --release
	cp target/$(TARGET)/release/test target/$(TARGET)/release/test.bin
	cargo strip --target=$(TARGET) -- --strip-all target/$(TARGET)/release/test.bin
	cargo objcopy --target=$(TARGET) -- -O binary target/$(TARGET)/release/test.bin