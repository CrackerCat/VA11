//
// Created by z742978469 on 20-1-26.
//

#ifndef PEAK_ROOT_SUPPORT_MEMORY_H
#define PEAK_ROOT_SUPPORT_MEMORY_H

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fstream>
#include <string>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <setjmp.h>
#include <csetjmp>
#include <utility>
#include <vector>

#include "FileWriteBuffer.h"
#include "SearchValue.h"

#define regionType_Stack 2
#define regionType_Heap 4
#define regionType_Xs 8
#define regionType_Xa 16
#define regionType_Java 32
#define regionType_JavaHeap 64
#define regionType_Bad 128
#define regionType_Anonymous 256
#define regionType_Cd 512
#define regionType_Cb 1024
#define regionType_Ca 2048
#define regionType_As 4096
#define regionType_Media 8192
#define regionType_Other 16384

typedef struct maps_filter_result{
    int isNull;
    std::string start_address;
    std::string end_address;
    std::string permission;
    std::string from;
} maps_filter_result;

typedef struct filter_value_ret{
    std::vector<value_reg> values;
    int32_t maxOffset;
} filter_value_ret;

class Memory {
private:
    int pid;
    bool isAttach=false;
    int threadCounts;

    filter_value_ret regex_value(char* value);

    Memory();

public:
    char maps_path[50]{}, status_path[50]{};
    int32_t maxOffset;
    FileWriteBuffer *searchResultWriteBuffer;
    int regionType=regionType_Anonymous|regionType_Cd|regionType_Ca|regionType_Heap;
    char cacheFilePath[PATH_MAX];

    value_t *valueTemp;
    size_t valueNum;
    std::vector<value_reg> *value_all;

    static Memory*& get();

    int getAttachingPid();

    bool findInValue(const size_t num,const char* buff);

    void attach(int _pid, const char *_cacheFilePath);

    std::string getRegionTypeName(int type);

    int judgeRegionType(std::string& permission,std::string& from);

    maps_filter_result filterRegions(char *line);

    /**
     *
     * @param regionType
     * @param context "value1:offset1:type1;value2:offset2:type2;...:...:...;"
     * @return
     */
    bool search(char *context,int regionType);

    bool search(SearchValue &searchValue,int _regionType);

    bool search(SearchValue &valueClass){
        return search(valueClass,regionType_Anonymous|regionType_Cd|regionType_Ca|regionType_Heap);
    }

    template <typename T>
    T getFirstSearchResult(){
        int fd=syscall(__NR_openat,AT_FDCWD,cacheFilePath,O_RDONLY);
        if(fd==-1)
            return 0;
        uint64_t size =lseek64(fd,0,2);
        if(size==0){
            close(fd);
            return 0;
        }
        lseek(fd,0,0);
        uint64_t ret=0;
        ::read(fd, &ret, 8);
        close(fd);
        return (T)ret;
    }

    template <typename T>
    std::vector<T> getSearchResult(){
        static std::vector<T> zero{0};
        int fd=syscall(__NR_openat,AT_FDCWD,cacheFilePath,O_RDONLY);
        if(fd==-1)
            return zero;
        uint64_t size =lseek64(fd,0,2);
        if(size==0){
            close(fd);
            return zero;
        }
        lseek64(fd,0,0);
        uint64_t num= size >> 3;
        std::vector<T> ret;
        uint64_t *buf=new uint64_t[num];
        ::read(fd, buf, (size_t)size);
        for (int i = 0; i < num; ++i) {
            ret.push_back((T)buf[i]);
        }
        delete[](buf);
        close(fd);
        return ret;
    }

    bool read(void *address, void *buffer, size_t size);

    bool write(void *address, void *buffer, size_t size);

    template <typename T>
    T read(void* address){
        static T null;
        T local_result;
        if(read(address, &local_result, sizeof(T)))
            return local_result;
        else
            return null;
    }

    template <typename T>
    T read(uint32_t address){
        return read<T>((void*)address);
    }

    template <typename T>
    T read(uint64_t address){
        return read<T>((void*)address);
    }

    template <typename T>
    T read(int32_t address){
        return read<T>((void*)address);
    }

    template <typename T>
    T read(int64_t address){
        return read<T>((void*)address);
    }

    template <typename T>
    bool write(void* address,T value){
        return write(address, &value, sizeof(T));
    }

    template <typename T>
    bool write(uint32_t address,T value){
        return write((void*)address, &value, sizeof(T));
    }

    template <typename T>
    bool write(uint64_t address,T value){
        return write((void*)address, &value, sizeof(T));
    }

    template <typename T>
    bool write(int32_t address,T value){
        return write((void*)address, &value, sizeof(T));
    }

    template <typename T>
    bool write(int64_t  address,T value){
        return write((void*)address, &value, sizeof(T));
    }

    bool inject(char *context,const char* cachePath= nullptr) ;

    bool injectWithFunc(char *context,const char* cachePath= nullptr);

    bool check();

    long long getModuleAddress(const char* libName);

    long long getFuncAddress(const char* libName,const char *funcName);

    bool dump(const char* name);

    bool dump(void* startAddress,size_t length,const char* name);

    Memory& setThreadCount(int threadCount);

    static bool getProcessName(pid_t pid,char* buf,size_t bufSize);

    static bool getPackageName(pid_t pid,char* buf,size_t bufSize);

    static int open(const char* __path, int __flags, mode_t mode=0);

    static FILE* fopen(const char* __path, int __flags,char* ___flags, mode_t mode=0);
};

#endif //PEAK_ROOT_SUPPORT_MEMORY_H
