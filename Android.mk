LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := exploit_tester
LOCAL_SRC_FILES := main.c tests.c utils.c
LOCAL_CFLAGS := -Wall -Wextra -O0 -g
LOCAL_LDFLAGS := -static
include $(BUILD_EXECUTABLE)
