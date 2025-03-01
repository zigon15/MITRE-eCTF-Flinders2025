PROGRAM_FILE="max78000.elf"
SYMBOL_FILE="max78000.elf"

OCD_path="$MAXIM_PATH/Tools/OpenOCD"
M4_OCD_interface_file="cmsis-dap.cfg"
M4_OCD_target_file="max78000.cfg"

arm-none-eabi-gdb --cd="./" --se="../deadbeef_build/$PROGRAM_FILE" --symbols="../deadbeef_build/$SYMBOL_FILE" -x="./scripts/flash.gdb" --ex="flash_m4 $OCD_path $M4_OCD_interface_file $M4_OCD_target_file build/$SYMBOL_FILE" --batch
            