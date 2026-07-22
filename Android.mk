LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := avc_bypass
LOCAL_SRC_FILES := avc_bypass.c

LOCAL_CFLAGS := -fPIE -Wall -Wextra -O2 -Wno-unused-result -Wno-format
LOCAL_LDFLAGS := -fPIE -pie
LOCAL_LDLIBS := -lpthread

include $(BUILD_EXECUTABLE)
