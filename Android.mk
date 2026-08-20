LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := rtsp_fuzzer
LOCAL_SRC_FILES := rtsp_fuzzer.c
LOCAL_CFLAGS := -Wall -O0 -g -fno-stack-protector -U_FORTIFY_SOURCE
LOCAL_SHARED_LIBRARIES := libc
include $(BUILD_EXECUTABLE)
