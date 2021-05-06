#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <android/log.h>
#include <sys/system_properties.h>    //需要添加的头文件
#include <sys/types.h>
#include <android/bitmap.h>
#include <android/native_window.h>
#include <android/native_window_jni.h>
#include <android/log.h>
#include <pthread.h>
#include <sys/system_properties.h>
#include <cstring>
//#include <asm/unistd-common.h>
#include "Substrate/CydiaSubstrate.h"
#include "hook.h"

//ndk 开发 android 日志信息显示模块
#include "android/log.h"
//#include "Memory.h"
#include "SymbolFinder.h"

#define TAG    "VA-NATIVE"
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
//#define TAG    "jni-log"




extern "C"
JNIEXPORT void JNICALL
Java_LoadNative_Native_init(JNIEnv *env, jclass clazz, jint pid) {
    LOGE("查看其他应用起来的pid %d ",pid);
}

/*void* initFreeze(void *)*//*读写内存线程*//*{

}*/
JNIEnv* mEnv = NULL;
JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
    vm->GetEnv((void**) &mEnv, JNI_VERSION_1_4);
    /* pthread_t tid;
     pthread_create(&tid, NULL, initFreeze, NULL);*/
    return JNI_VERSION_1_4;
}








