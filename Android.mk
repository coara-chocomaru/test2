LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := binder_test
LOCAL_SRC_FILES := binder_test.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)
LOCAL_CFLAGS := -Wall -Wextra -O2 -static
include $(BUILD_EXECUTABLE)
