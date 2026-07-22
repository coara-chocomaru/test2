LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := root_shell
LOCAL_SRC_FILES := root_shell.c

LOCAL_CFLAGS := -fPIE -Wall -Wextra -O2 -Wno-unused-result -Wno-format
LOCAL_LDFLAGS := -fPIE -pie

include $(BUILD_EXECUTABLE)
