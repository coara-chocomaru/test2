# Android.mk
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := check_poc
LOCAL_SRC_FILES := check_poc.c
LOCAL_CFLAGS := -fPIE -Wall -Wextra -O2 -Wno-unused-result -Wno-format
LOCAL_LDFLAGS := -fPIE -pie

include $(BUILD_EXECUTABLE)
