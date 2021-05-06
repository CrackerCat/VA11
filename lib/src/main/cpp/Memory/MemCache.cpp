//
// Created by z742978469 on 20-1-26.
//

#include <cstdint>
#include <cstdlib>
#include <zconf.h>
#include <cstring>
#include <strings.h>

#include "MemCache.h"


#define FIX_MMAP_LENGTH(length) (((length)&0xFFF)!=0?(((length)|0xFFF)+1):(length))

#define FIX_LENGTH(length,bit) ((length)%(bit)==0?length:(((length)/(bit)+1)*(bit)))

MemCache::MemCache(int32_t maxOffset,int threadNum,uint32_t length){
    this->memory=Memory::get();
    this->threadNum=threadNum;
    this->bufLength=length;
    this->maxOffset=maxOffset;
    this->pageSize=40960%maxOffset?maxOffset*(40960/maxOffset+1):40960; //0.1171

    size_t sizes[]={
            FIX_LENGTH(threadNum*sizeof(bool),4),
            threadNum*sizeof(int),
            threadNum*sizeof(int),
            threadNum*sizeof(CacheInfo*),
            100000 * sizeof(CacheInfo)
    };

    mmapLength=length+sizes[0]+sizes[1]+sizes[2]+sizes[3]+threadNum*sizes[4];
    mmapLength = FIX_MMAP_LENGTH(mmapLength);
    buf = (char*)mmap64(nullptr,mmapLength,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,0,0);
    bzero(buf,mmapLength);

    isReadOver=(bool*)(buf+length);
    getIndex=(int*)((char*)isReadOver+sizes[0]);
    infosWritePos=(int*)((char*)getIndex+sizes[1]);
    initinfosWritePos();
    infos=(CacheInfo**)((char*)infosWritePos+sizes[2]);

    infos[0]=(CacheInfo *)((char*)infos+sizes[3]);
    for(int i=1;i<threadNum;i++)
        infos[i] = (infos[i - 1]) + 100000;
}

void MemCache::initinfosWritePos(){
    for(int i=0;i<threadNum;i++)
        infosWritePos[i]=-1;
}

inline int MemCache::nextInfoIndex() {
    static int infoIndex=0;
    if (infoIndex == threadNum){
        infoIndex = 1;
        return 0;
    }
    return infoIndex++;
}

bool MemCache::allReadOver(){
    for(int i=0;i<threadNum;i++) {
        if (!isReadOver[i])
            return false;
    }
    return true;
}


int MemCache::readFromMem(long long offset, int32_t length) {
    int32_t needbufLength = length + bufPosition;
    size_t realReadLength;
    CacheInfo *cacheInfoBuf;
    int i;
    int posBuf;
    int32_t pageSum;
    int32_t restPageSize;
    int infoIndex;
    int tmp;
    bool isFull=false;
    if (needbufLength >= this->bufLength) {
        isFull=true;
        realReadLength = this->bufLength - bufPosition;
        pageSum = realReadLength / pageSize;
        restPageSize = realReadLength - pageSize * pageSum;
    }else {
        realReadLength=(size_t)length;
        pageSum = length / pageSize;
        restPageSize= length - pageSize*pageSum;
    }

    memory->read((void*)(offset),buf+bufPosition,realReadLength);

    switch (pageSum) {
        case 0:
            infoIndex=nextInfoIndex();
            posBuf=infosWritePos[infoIndex]+1;
            cacheInfoBuf=&infos[infoIndex][posBuf];
            cacheInfoBuf->buff = buf+bufPosition;
            cacheInfoBuf->length = realReadLength;
            cacheInfoBuf->realBaseAddress = offset;
            infosWritePos[infoIndex]=posBuf;
            break;
        case 1:
            infoIndex=nextInfoIndex();
            posBuf=infosWritePos[infoIndex]+1;
            cacheInfoBuf=&infos[infoIndex][posBuf];
            cacheInfoBuf->buff = buf+bufPosition;
            cacheInfoBuf->length = pageSize;
            cacheInfoBuf->realBaseAddress = offset;
            infosWritePos[infoIndex]=posBuf;

            infoIndex=nextInfoIndex();
            posBuf=infosWritePos[infoIndex]+1;
            cacheInfoBuf=&infos[infoIndex][posBuf];
            cacheInfoBuf->buff = buf+bufPosition+pageSize;
            cacheInfoBuf->length = restPageSize;
            cacheInfoBuf->realBaseAddress = offset+pageSize;
            infosWritePos[infoIndex]=posBuf;
        default:
            tmp=0;
            for(i=0;i<pageSum;i++){
                infoIndex=nextInfoIndex();
                posBuf=infosWritePos[infoIndex]+1;
                cacheInfoBuf=&infos[infoIndex][posBuf];
                cacheInfoBuf->buff = buf+bufPosition+tmp;
                cacheInfoBuf->length = pageSize;
                cacheInfoBuf->realBaseAddress = offset+tmp;
                infosWritePos[infoIndex]=posBuf;
                tmp+=pageSize;
            }
            if(restPageSize>0) {
                infoIndex=nextInfoIndex();
                posBuf=infosWritePos[infoIndex]+1;
                cacheInfoBuf=&infos[infoIndex][posBuf];
                cacheInfoBuf->buff = buf + bufPosition + tmp;
                cacheInfoBuf->length = restPageSize + maxOffset;
                cacheInfoBuf->realBaseAddress = offset + tmp ;
                infosWritePos[infoIndex]=posBuf;
            }
    }

    if(isFull) {
        readState = cache_full;
        while (!allReadOver()) usleep(50000);
        initinfosWritePos();
        bufPosition = 0;
        for (i = 0; i < threadNum; i++)
            isReadOver[i] = false;
        readState = cache_reading;
    }else {
        bufPosition = needbufLength;
        return 0;
    }
    return realReadLength;
}

CacheInfo *MemCache::get(int index){
    while(getIndex[index] == infosWritePos[index] + 1) {
        switch (readState) {
            case cache_reading:
                usleep(20000);
                continue;
            case cache_full:
                isReadOver[index] = true;
                while (isReadOver[index]) usleep(20000);
                getIndex[index] = 0;
                continue;
            default:
                return nullptr;
        }
    }
    return &infos[index][getIndex[index]++];
}

void MemCache::readOver(){
    readState=cache_read_over;
}

MemCache::~MemCache(){
    munmap(buf,mmapLength);
}
