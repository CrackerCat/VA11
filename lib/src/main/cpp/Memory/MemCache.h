//
// Created by z742978469 on 20-1-26.
//

#ifndef PEAK_ROOT_SUPPORT_MEMCACHE_H
#define PEAK_ROOT_SUPPORT_MEMCACHE_H

#include "Memory.h"

#define cache_reading 0
#define cache_full 1
#define cache_read_over 2

typedef struct{
    char *buff;
    int32_t length;
    long long realBaseAddress;
} CacheInfo;

class MemCache{
private:
    volatile int  readState=cache_reading;
    volatile int32_t bufPosition=0;
    int32_t pageSize;
    uint32_t bufLength;
    char *buf;
    int threadNum;
    CacheInfo **infos;
    volatile int *infosWritePos;
    volatile int *getIndex;
    volatile bool *isReadOver;

    size_t mmapLength;
public:
    int32_t maxOffset;
    Memory* memory;

    MemCache(int32_t maxOffset,int threadNum,uint32_t length=219430400);

    void initinfosWritePos();

    inline int nextInfoIndex();

    bool allReadOver();

    int readFromMem(long long offset, int32_t length);

    CacheInfo *get(int index);

    void readOver();

    ~MemCache();
};

#endif //PEAK_ROOT_SUPPORT_MEMCACHE_H
