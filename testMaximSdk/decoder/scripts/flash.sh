PROGRAM_FILE="Decoder.elf"
SYMBOL_FILE="Decoder.elf"

OCD_path="$MAXIM_PATH/Tools/OpenOCD"
M4_OCD_interface_file="cmsis-dap.cfg"
M4_OCD_target_file="max78000.cfg"

arm-none-eabi-gdb --cd="./" --se="./build/$PROGRAM_FILE" --symbols="./build/$SYMBOL_FILE" -x="./scripts/flash.gdb" --ex="flash_m4 $OCD_path $M4_OCD_interface_file $M4_OCD_target_file build/$SYMBOL_FILE" --batch
            