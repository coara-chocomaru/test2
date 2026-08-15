LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := root_shell
LOCAL_SRC_FILES := root_shell.c
LOCAL_CFLAGS := -std=gnu99 -O2 -march=armv7-a -mfloat-abi=softfp -mfpu=neon -fstack-protector-strong
LOCAL_LDFLAGS := -static
include $(BUILD_EXECUTABLE)
