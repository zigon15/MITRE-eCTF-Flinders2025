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
IPATH+=/secrets

IPATH+=/global_secrets.S

# Source file locations
VPATH+=core/src/
VPATH+=core/tasks/
VPATH+=core/drivers/crypto

# Add your config here!
DEBUG=1

LIB_FREERTOS = 1

# Can provide a value for the FREERTOS heap allocation scheme
# Default value is 4
# FREERTOS_HEAP_TYPE := 2
# export FREERTOS_HEAP_TYPE

# ****************** eCTF Bootloader *******************
# DO NOT REMOVE
LINKERFILE=firmware.ld
STARTUPFILE=startup_firmware.S
ENTRY=firmware_startup

# BINS+=secrets.S

# Set assembler flag if development build
# - Uses different global secrets location
ifeq ($(DEV_BUILD),1) 
	PROJ_AFLAGS+=-DDEV_BUILD
endif