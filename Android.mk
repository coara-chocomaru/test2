LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := root_shell
LOCAL_SRC_FILES := main/main.c util/kgsl_ops.c util/cache_ops.c util/kaslr.c util/common.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/h
LOCAL_CFLAGS := -fPIE -Wall -Wextra -O2 -Wno-unused-result -Wno-format
LOCAL_LDFLAGS := -fPIE -pie

include $(BUILD_EXECUTABLE)