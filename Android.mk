LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := run_as_exploit_tester
LOCAL_SRC_FILES := run_as_exploit_tester.c
LOCAL_CFLAGS := -O2 -Wall -pthread
LOCAL_LDFLAGS := -pthread
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)
