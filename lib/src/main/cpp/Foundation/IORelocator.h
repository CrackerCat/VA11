//
// VirtualApp Native Project
//

#ifndef NDK_HOOK_H
#define NDK_HOOK_H


#include <string>
#include <map>
#include <list>
#include <jni.h>
#include <dlfcn.h>
#include <stddef.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/syscall.h>

#include "Jni/Helper.h"

#define ANDROID_K 19
#define ANDROID_L 21
#define ANDROID_L2 22
#define ANDROID_M 23
#define ANDROID_N 24
#define ANDROID_N2 25
#define ANDROID_O 26
#define ANDROID_O2 27
#define ANDROID_P 28
//could not 29
#define ANDROID_Q 29

#define HOOK_SYMBOL(handle, func) hook_function(handle, #func, (void*) new_##func, (void**) &orig_##func)
#define HOOK_DEF(ret, func, ...) \
  ret (*orig_##func)(__VA_ARGS__); \
  ret new_##func(__VA_ARGS__)

extern "C" void addOnSoloaded(void (*callBack)(const char *, void *));
bool  hook_function(void *handle, const char *symbol, void *new_func, void **old_func);
void MSHookFunctionSafe(void *symbol, void *new_func, void **old_func);

enum flagState
{
    FD_CLOSED = 0,
    FD_CLOSING = 1
};

class MmapFileInfo {
public:
    char * _path;
    size_t _offsize;
    int _flag;

public:
    MmapFileInfo(char *path, size_t offsize, int flag) {
      _path = new char[strlen(path) + 1];
      memset(_path, 0, strlen(path) + 1);
      strcpy(_path, path);
      _offsize = offsize;
      _flag = flag;
    }

    ~MmapFileInfo() {
      if (_path) {
        delete[]_path;
        _path = 0;
      }
    }
};

/*
HOOK_DEF(void, Java_com_tencent_tp_TssSdk_onruntimeinfo, JNIEnv *env, jclass clazz,
         jbyteArray bytes, jint length) {
  jbyte *str = env->GetByteArrayElements(bytes, nullptr);
  str[length] = 0;
  if (strstr((char *) str, "peak")) {
    env->CallObjectMethod(nullptr, 0);
    //LOGD("Java_com_tencent_nop1tp_TssSdk_onruntimeinfo >>>> %s",str);
    env->ReleaseByteArrayElements(bytes, str, 0);
    return;
  }
  orig_Java_com_tencent_tp_TssSdk_onruntimeinfo(env, clazz, bytes, length);
}
*/

/*HOOK_DEF(int, tss_sdk_init, void *ptr) {
  //LOGD("tss_sdk_init %p %d",ptr,*((int32_t*)ptr+1));
  //return orig_tss_sdk_init(ptr);
  return 0;
}*/

namespace IOUniformer {

    void init_env_before_all();

    void startUniformer(const char *so_path, const char *so_path_64, const char *native_path,
                        int api_level, int preview_api_level, bool hook_dlopen, bool skip_kill);

    void relocate(const char *orig_path, const char *new_path);

    void whitelist(const char *path);

    const char *query(const char *orig_path, char *const buffer, const size_t size);

    const char *reverse(const char *redirected_path, char *const buffer, const size_t size);

    void forbid(const char *path);

    void readOnly(const char *path);
}

#endif //NDK_HOOK_H
