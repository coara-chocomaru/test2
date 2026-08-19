LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE            := exploit
LOCAL_SRC_FILES         := exploit.c
LOCAL_CFLAGS            := -fPIC -Wall -O2
LOCAL_LDFLAGS           := -fPIC
LOCAL_LDLIBS            := -ldl -llog
include $(BUILD_SHARED_LIBRARY)


include $(CLEAR_VARS)
LOCAL_MODULE            := launcher
LOCAL_SRC_FILES         := launcher.c
LOCAL_CFLAGS            := -fPIE -Wall -O2
LOCAL_LDFLAGS           := -fPIE -pie
include $(BUILD_EXECUTABLE)
