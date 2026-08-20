LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := run_as_exploit_tester
LOCAL_SRC_FILES := run_as_exploit_tester.c
LOCAL_CFLAGS := -O2 -Wall -pthread
LOCAL_LDFLAGS := -pthread
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := malicious
LOCAL_SRC_FILES := malicious.c
LOCAL_CFLAGS := -O2 -Wall -fPIC
LOCAL_LDFLAGS := -fPIC -shared -ldl
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_SUFFIX := .so
include $(BUILD_SHARED_LIBRARY)
