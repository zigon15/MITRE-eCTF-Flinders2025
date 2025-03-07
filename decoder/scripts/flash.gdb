define flash_m4
    set architecture armv7e-m
    set remotetimeout 10
    target remote | openocd -c "gdb_port pipe;log_output flash.log" -s $arg0/scripts -f interface/$arg1 -f target/$arg2 -c "init; reset halt"
    load
    compare-sections
    monitor reset halt
end
