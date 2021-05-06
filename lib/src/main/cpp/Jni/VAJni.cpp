
// VirtualApp Native Project
//
#include <Foundation/IORelocator.h>
#include <Foundation/Log.h>
#include <Socket/server/MySocketServer.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <unordered_map>
#include <Memory/Memory.h>
#include <Foundation/hideSegments.h>
#include "VAJni.h"

static bool channelController(JNIEnv *evn,jstring hostPackageName, jstring appPackageName);
#define SOCKET_INJECT_CHECK 0
#define SOCKET_INJECT_SEARCH 1
#define SOCKET_INJECT_WRITE 2
#define SOCKET_INJECT_READ 3
#define SOCKET_INJECT_SET_AUTO_EXIT 9
#define SOCKET_INJECT_LOOP 10
#define SOCKET_INJECT_RECV_FD 11

#define SOCKET_INJECT_SIG_ACCEPT (SIGRTMIN+13)

static void jni_nativeLaunchEngine(JNIEnv *env, jclass clazz, jobjectArray javaMethods,
                                   jstring hostPackageName, jstring appPackageName,
                                   jboolean isArt, jint apiLevel, jint cameraMethodType,
                                   jint audioRecordMethodType) {

    //channelController(env,hostPackageName,appPackageName);
    hookAndroidVM(env, javaMethods, hostPackageName, appPackageName, isArt, apiLevel, cameraMethodType,
                  audioRecordMethodType);
}

static bool channelController(JNIEnv *env,jstring hostPackageName, jstring appPackageName){
    const char *hostPKG = (char *) env->GetStringUTFChars(hostPackageName, NULL);
    const char *appPGK = (char *) env->GetStringUTFChars(hostPackageName, NULL);

    //ALOGD("查看應用報名 hostPackageName = %s, appPackageName = %s",hostPKG,appPGK);
    // exit(0); com.lody.virtual.client.core
    jclass virtualCoreClass = env->FindClass("com/lody/virtual/client/core/VirtualCore");
    jmethodID getMethodID = env->GetStaticMethodID(virtualCoreClass,"get", "()Lcom/lody/virtual/client/core/VirtualCore;");
    jobject virtualCore = env->CallStaticObjectMethod(virtualCoreClass,getMethodID);

    jmethodID getContextMethodID = env->GetMethodID(virtualCoreClass,"getContext", "()Landroid/content/Context;");
    jobject context = env->CallObjectMethod(virtualCore,getContextMethodID);


    jclass channelConfigClass = env->FindClass("com/kook/controller/config/ChannelConfig");
    jmethodID checkChannelMethodID = env->GetStaticMethodID(channelConfigClass,"checkChannel", "(Landroid/content/Context;Ljava/lang/String;)Z");

    bool check = env->CallStaticBooleanMethod(channelConfigClass,checkChannelMethodID,context,appPackageName);

    ALOGD("启动 %d",check);
    if(check){
        return check;
    } else{
        //exit(0);
    }
}

static void
jni_nativeEnableIORedirect(JNIEnv *env, jclass, jstring soPath, jstring soPath64,
                           jstring nativePath, jint apiLevel,
                           jint preview_api_level, bool hook_dlopen,
                           bool skip_kill) {
    ScopeUtfString so_path(soPath);
    ScopeUtfString so_path_64(soPath64);
    ScopeUtfString native_path(nativePath);
    IOUniformer::startUniformer(so_path.c_str(), so_path_64.c_str(), native_path.c_str(), apiLevel,
                                preview_api_level, hook_dlopen, skip_kill);
}

static void jni_nativeIOWhitelist(JNIEnv *env, jclass jclazz, jstring _path) {
    ScopeUtfString path(_path);
    IOUniformer::whitelist(path.c_str());
}

static void jni_nativeIOForbid(JNIEnv *env, jclass jclazz, jstring _path) {
    ScopeUtfString path(_path);
    IOUniformer::forbid(path.c_str());
}

static void jni_nativeIOReadOnly(JNIEnv *env, jclass jclazz, jstring _path) {
    ScopeUtfString path(_path);
    IOUniformer::readOnly(path.c_str());
}


static void jni_nativeIORedirect(JNIEnv *env, jclass jclazz, jstring origPath, jstring newPath) {
    ScopeUtfString orig_path(origPath);
    ScopeUtfString new_path(newPath);
    IOUniformer::relocate(orig_path.c_str(), new_path.c_str());

}

static jstring jni_nativeGetRedirectedPath(JNIEnv *env, jclass jclazz, jstring origPath) {
    ScopeUtfString orig_path(origPath);
    char buffer[PATH_MAX];
    const char *redirected_path = IOUniformer::query(orig_path.c_str(), buffer, sizeof(buffer));
    if (redirected_path != NULL) {
        return env->NewStringUTF(redirected_path);
    }
    return NULL;
}

static jstring jni_nativeReverseRedirectedPath(JNIEnv *env, jclass jclazz, jstring redirectedPath) {
    ScopeUtfString redirected_path(redirectedPath);
    char buffer[PATH_MAX];
    const char *orig_path = IOUniformer::reverse(redirected_path.c_str(), buffer, sizeof(buffer));
    return env->NewStringUTF(orig_path);
}

static void Jni_necuil_crash(JNIEnv *env, jclass jclazz) {
    ((JNIEnv*)nullptr)->ExceptionClear();
    *(int32_t*)nullptr=1;
}

int onLoopBufCallBack=0;
void (*onLoopBuf[100])(const char *bytes);
bool (*dlopen_ptr)(JNIEnv *env,std::unordered_map<std::string,void*>*,const char *parameters,bool isRootMode);
extern "C" void addOnLoop(void (*callBack)(const char *bytes)){
    onLoopBuf[onLoopBufCallBack++]=callBack;
}
int onRecvFdBufCallBack=0;
void (*onRecvFdBuf[100])(int fd);
extern "C" void addOnRecvFd(void (*callBack)(int fd)){
    onRecvFdBuf[onRecvFdBufCallBack++]=callBack;
}

static void hookByAddress(void *symbol, void *replace, void **result,const char* name){
    MSHookFunctionSafe(symbol,replace,result);
}


bool find_lib(const char *name) {
    char buf[BUFSIZ], *tok[6];
    int i;
    FILE *fp;

    snprintf(buf, sizeof(buf), "/proc/self/maps");

    if ((fp = fopen(buf, "r")) == NULL) {
        perror("get_linker_addr: fopen");
        return false;
    }

    while (fgets(buf, sizeof(buf), fp)) {
        i = strlen(buf);
        if (i > 0 && buf[i - 1] == '\n')
            buf[i - 1] = 0;

        tok[0] = strtok(buf, " ");
        for (i = 1; i < 6; i++)
            tok[i] = strtok(nullptr, " ");

        if (tok[5] && strstr(tok[5], name) != nullptr) {
            return true;
        }
    }
    return false;
}



static jboolean Jni_necuil_loadNative(JNIEnv *env, jclass clazz, jstring _libPath,
                                      jstring _funcName, jstring _content){
    ScopeUtfString libPath(_libPath);
    void *handle;
    bool ret= false;
    bool everLoad=find_lib(libPath.c_str());
    handle=dlopen(libPath.c_str(),RTLD_NOW);
    if(handle){
        if(_funcName) {
            ScopeUtfString funcName(_funcName);
            ScopeUtfString content(_content);
            static std::unordered_map<std::string,void*> *funcs = nullptr;
            static std::unordered_map<std::string,void*> *rootfuncs = nullptr;
            if(funcs== nullptr) {
                funcs = new std::unordered_map<std::string, void *>;
                funcs->insert(std::pair<std::string, void *>("ensureEnvCreated",(void *) (ensureEnvCreated)));
                funcs->insert(std::pair<std::string, void *>("addOnSoloaded",(void *) (addOnSoloaded)));
                funcs->insert(std::pair<std::string, void *>("hookByHandle",(void *) (hook_function)));
                funcs->insert(std::pair<std::string, void *>("hookByAddress",(void *) (hookByAddress)));
                funcs->insert(std::pair<std::string, void *>("addHideSegment",(void *) (hideSegments::addHideSegment)));
                funcs->insert(std::pair<std::string, void *>("getHiddenSegments",(void *) (hideSegments::getHiddenSegments)));
                funcs->insert(std::pair<std::string, void *>("addOnLoop",(void *) (addOnLoop)));
                funcs->insert(std::pair<std::string, void *>("addOnRecvFd",(void *) (addOnRecvFd)));
                funcs->insert(std::pair<std::string, void *>("memory",(void *) (Memory::get())));
            }
            *(void**)&(dlopen_ptr) = (dlsym(handle, funcName.c_str()));
            if(dlopen_ptr)
                ret=dlopen_ptr(env, funcs, content.c_str(), false);
        } else
            ret=true;
    }
    if(everLoad)
        dlclose(handle);
    return static_cast<jboolean>(ret ? 1 : 0);
}

std::string cacheFilePath;
MySocketServer *mySocketServer= nullptr;
static void segv_inject(int sig, siginfo *info, void *context) {
    if (sig == SOCKET_INJECT_SIG_ACCEPT) {
        mySocketServer->accept();
    }
}
void loop(char *bytes){
    for (int i = 0; i < onLoopBufCallBack; ++i)
        onLoopBuf[i](bytes);
}
void onRecvFd(int fd){
    ALOGD("onRecvFd %d",fd);
    for (int i = 0; i < onRecvFdBufCallBack; ++i)
        onRecvFdBuf[i](fd);
}
void myClientThread(int id, int client_sockfd) {
    bool autoExit=false;
    char buf[PAGE_SIZE+4];
    char *content=buf+3;
    char *parameters=content+1;
    ssize_t recv_ret;
    Memory *memory=Memory::get();
    memory->attach(getpid(),cacheFilePath.c_str());
    SearchValue searchValue;
    static char *strs[1000];
    static const int strs_length=sizeof(char*)*1000;
    bzero(strs,strs_length);
    bzero(content,PAGE_SIZE+1);
    bool ret;
    ALOGD("connect with client!");
    send(client_sockfd,content,1,0);
    while((recv_ret=recv(client_sockfd, content, PAGE_SIZE,0))>0){
        switch (content[0]){
            case SOCKET_INJECT_CHECK:
                send(client_sockfd,content,1,0);
                break;
            case SOCKET_INJECT_SEARCH:
                //LOGD("search %s %s",parameters+8,getRegionTypeName(*(int32_t *)parameters).c_str());
                ret = memory->search(parameters+8, (int)*(int64_t *) parameters);
                send(client_sockfd,(char*)&ret,1,0);
                break;
            case SOCKET_INJECT_WRITE:
                ret=memory->write((void*)*(int64_t*)parameters,parameters+12,(size_t)*(int32_t*)(parameters+8));
                send(client_sockfd,&ret,1,0);
                break;
            case SOCKET_INJECT_READ:
                size_t length;
                length=static_cast<size_t>(*(parameters + 12));
                //LOGD("read %llx",*(int64_t*)parameters);
                content[0]=memory->read((void*)*(int64_t*)parameters, parameters,length);
                send(client_sockfd,content,length+1,0);
                break;
            case SOCKET_INJECT_SET_AUTO_EXIT:
                autoExit=parameters[0];
                ALOGD("autoExit >>>> %d",autoExit);
                send(client_sockfd,content,1,0);
                break;
            case SOCKET_INJECT_LOOP:
                loop(parameters);
                send(client_sockfd,content,1,0);
                break;
            case SOCKET_INJECT_RECV_FD:
                ALOGD("SOCKET_INJECT_RECV_FD!");
                send(client_sockfd,content,1,0);
                onRecvFd(mySocketServer->recv_fd(client_sockfd));
                send(client_sockfd,content,1,0);
                break;
            default:
                break;
        }
        bzero(content,recv_ret);
    }
    if(autoExit)
        while(true){
            close(client_sockfd);
            exit(0);
            *(int32_t*)1=0;
        }
    close(client_sockfd);
    mySocketServer->close(client_sockfd);
}

static jboolean Jni_necuil_initServerSocket(JNIEnv *env, jclass clazz, jstring _socketTag,jstring _path){
    ScopeUtfString path(_path);
    ScopeUtfString socketTag(_socketTag);
    cacheFilePath=path.toString()+"cache/."+socketTag.toString();
    ALOGD("cacheFilePath %s",cacheFilePath.c_str());
    struct sigaction siga{};
    sigemptyset(&siga.sa_mask);
    siga.sa_flags = SA_SIGINFO;
    siga.sa_sigaction = segv_inject;
    sigaction(SOCKET_INJECT_SIG_ACCEPT, &siga, nullptr);

    //LOGD("cacheFilePath %s",cacheFilePath.c_str());
    //LOGD("ServerSocket %s",(path.toString()+"socket").c_str());

    if(mySocketServer!= nullptr)
        delete(mySocketServer);
    mySocketServer=new MySocketServer();

    if(mySocketServer->reuseAddr().setClientThread(myClientThread).bind(socketTag.c_str(),ABSTRACT)) {
        mySocketServer->listen(1);
    }

    ALOGD("jni_initServerSocket success!");

    return 1;
}



jclass nativeEngineClass;
JavaVM *vm;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *_vm, void *) {
    vm = _vm;
    JNIEnv *env;
    _vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
    nativeEngineClass = (jclass) env->NewGlobalRef(env->FindClass(JNI_CLASS_NAME));
    static JNINativeMethod methods[] = {
            {"O0OOO00OO0",                                       "()V",                                                                   (void *) Jni_necuil_crash},
            {"O0O0O00OO0",                                       "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z",             (void *) Jni_necuil_loadNative},
            {"O0OO000OO0",                                       "(Ljava/lang/String;Ljava/lang/String;)Z",                               (void *) Jni_necuil_initServerSocket},
            {"nativeLaunchEngine",                     "([Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;ZIII)V",                (void *) jni_nativeLaunchEngine},
            {"nativeReverseRedirectedPath",            "(Ljava/lang/String;)Ljava/lang/String;",                                        (void *) jni_nativeReverseRedirectedPath},
            {"nativeGetRedirectedPath",                "(Ljava/lang/String;)Ljava/lang/String;",                                        (void *) jni_nativeGetRedirectedPath},
            {"nativeIORedirect",                       "(Ljava/lang/String;Ljava/lang/String;)V",                                       (void *) jni_nativeIORedirect},
            {"nativeIOWhitelist",                      "(Ljava/lang/String;)V",                                                         (void *) jni_nativeIOWhitelist},
            {"nativeIOForbid",                         "(Ljava/lang/String;)V",                                                         (void *) jni_nativeIOForbid},
            {"nativeIOReadOnly",                       "(Ljava/lang/String;)V",                                                         (void *) jni_nativeIOReadOnly},
            {"nativeEnableIORedirect",                 "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IIZZ)V",                 (void *) jni_nativeEnableIORedirect},
    };
    if (env->RegisterNatives(nativeEngineClass, methods, sizeof(methods) / sizeof(methods[0])) < 0) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}

JNIEnv *getEnv() {
    JNIEnv *env;
    vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
    return env;
}

static void onSoLoaded(const char *filename, void* handle){;
#ifdef DEBUG_MODE
#endif
}

JNIEnv *ensureEnvCreated() {
    JNIEnv *env = getEnv();
    if (env == NULL) {
        vm->AttachCurrentThread(&env, NULL);
    }
    return env;
}

extern "C" __attribute__((constructor)) void _init(void) {
    IOUniformer::init_env_before_all();
}