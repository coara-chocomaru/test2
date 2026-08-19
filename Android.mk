LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := test
LOCAL_SRC_FILES := test.c
LOCAL_CFLAGS := -fPIE -Wall -Wextra -O2 -Wno-unused-result -Wno-format
LOCAL_LDFLAGS := -fPIE -pie -ldl

include $(BUILD_EXECUTABLE)
