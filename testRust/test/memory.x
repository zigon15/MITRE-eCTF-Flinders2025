/* YOU LIKELY DON'T NEED TO CHANGE THIS FILE */
MEMORY {
   FLASH       (rx) : ORIGIN = 0x10000000, LENGTH = 0x00038000 /* Location of team firmware */
   RAM        (rwx): ORIGIN = 0x20000000, LENGTH = 0x00020000 /* 128kB SRAM */
}