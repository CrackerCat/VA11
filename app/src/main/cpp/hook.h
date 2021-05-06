//
// Created by 86151 on 2021/5/2.
//

#ifndef VIRTUALAPP11_MASTER_HOOK_H
#define VIRTUALAPP11_MASTER_HOOK_H


#include <fcntl.h>

#define HOOK_SYMBOL(handle, func) hookByHandle(handle, #func, (void*) new_##func, (void**) &orig_##func)
#define HOOK_DEF(ret, func, ...) \
  static ret (*orig_##func)(__VA_ARGS__); \
  static ret new_##func(__VA_ARGS__)
#define PTR_DEF(ret, func, ...) ret (*func)(__VA_ARGS__)

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

HOOK_DEF(int, tss_sdk_init, void *ptr) {
  //LOGD("tss_sdk_init %p %d",ptr,*((int32_t*)ptr+1));
  //return orig_tss_sdk_init(ptr);
  return 0;
}





#endif //VIRTUALAPP11_MASTER_HOOK_H
