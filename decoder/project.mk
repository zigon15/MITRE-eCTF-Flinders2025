# This file can be used to set build configuration
# variables.  These variables are defined in a file called 
# "Makefile" that is located next to this one.

# For instructions on how to use this system, see
# https://analog-devices-msdk.github.io/msdk/USERGUIDE/#build-system

#MXC_OPTIMIZE_CFLAGS = -Og
# ^ For example, you can uncomment this line to 
# optimize the project for debugging

# **********************************************************

# This code is only compatible with the FTHR board,
# so we override the BOARD value to hard-set it.
override BOARD=FTHR_RevA
MFLOAT_ABI=softfp

# Header file locations
IPATH+=core/inc
IPATH+=core/tasks
IPATH+=core/drivers/crypto
IPATH+=core/tasks/crypto_manager/
IPATH+=core/tasks/subscription_manager/
IPATH+=core/tasks/serial_interface_manager/
IPATH+=core/tasks/channel_manager/
IPATH+=core/tasks/frame_manager/

IPATH+=/global_secrets.S

# Source file locations
VPATH+=core/src/
VPATH+=core/tasks/
VPATH+=core/drivers/crypto
VPATH+=core/tasks/crypto_manager
VPATH+=core/tasks/subscription_manager
VPATH+=core/tasks/serial_interface_manager
VPATH+=core/tasks/channel_manager
VPATH+=core/tasks/frame_manager

# ****************** FREE RTOS Flags *******************
LIB_FREERTOS=1

# Can provide a value for the FREERTOS heap allocation scheme
# Default value is 4
# FREERTOS_HEAP_TYPE := 2
# export FREERTOS_HEAP_TYPE

# ****************** Security Compiler Flags *******************
# There may have been a lot of chatgpt and google here
# - Maybe check if we screwed something up making it actually more insecure? ;(

# Prevent unexpected stack growth
PROJ_CFLAGS += -fstack-clash-protection

# Protects against stack-based buffer overflows by adding canaries
PROJ_CFLAGS += -fstack-protector-strong
# Need to overide the internal __stack_chk_fail function which infinite loops
# - Replaces called to __stack_chk_fail symbol with __wrap___stack_chk_fail
PROJ_LDFLAGS += -Wl,--wrap=__stack_chk_fail

PROJ_CFLAGS += -Wstack-protector

# Warn about format security
PROJ_CFLAGS += -Wformat -Wformat-security

# Warn about variable shadowing
PROJ_CFLAGS += -Wshadow

# Enables compile-time and runtime checks for buffer overflows
# - Requires optimization level -O2 or higher.
PROJ_CFLAGS += -D_FORTIFY_SOURCE=3
# Need to overide the internal __chk_fail function which gets called on buffer overflow
# - Replaces called to __chk_fail symbol with __wrap__chk_fail
PROJ_LDFLAGS += -Wl,--wrap=__chk_fail
# PROJ_LDFLAGS += -Wl,--wrap=__fortify_fail

# ****************** eCTF Bootloader *******************
# DO NOT REMOVE
LINKERFILE=firmware.ld
STARTUPFILE=startup_firmware.S
ENTRY=firmware_startup

BINS+=secrets.S

# Set assembler flag if development build
# - Uses different global secrets location
ifeq ($(DEV_BUILD),1) 
	PROJ_AFLAGS+=-DDEV_BUILD
endif