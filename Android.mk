LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := binder_test
LOCAL_SRC_FILES := binder_test.c
LOCAL_CFLAGS := -Wall -Wextra -O0 -g
LOCAL_LDFLAGS := -pthread

include $(BUILD_EXECUTABLE)
