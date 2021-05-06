#ifndef INJECT_H
#define INJECT_H

#if defined(__aarch64__)
#define voidPtr uint64_t
#else
#define voidPtr uint32_t
#endif


int inject_remote_process(pid_t target_pid, const char *library_path,const char *cacheFile, bool isZygote);

int inject_remote_process(pid_t target_pid, const char *library_path,const char *cacheFile, char* funcName ,char* funcParameter,bool isZygote);

static int inject_remote_process(pid_t target_pid, const char *library_path,bool isZygote){
    return inject_remote_process(target_pid,library_path, nullptr,isZygote);
}

static int inject_remote_process(pid_t target_pid, const char *library_path, char* funcName ,char* funcParameter,bool isZygote){
    return inject_remote_process(target_pid,library_path, nullptr,funcName,funcParameter,isZygote);
}

pid_t getTracerPid(pid_t target_pid);

char** split(char* content,const char* delimiter,int num);

char* split_s(char **ptr,char* content,const char* delimiter,int num);

bool file_exists(const char* path);

long setxattr(const char *path, const char *value);

#endif //HOOKS_H