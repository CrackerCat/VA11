//
// Created by z742978469 on 20-1-26.
//

#include <asm/mman.h>
#include <sys/mman.h>
#include <syscall.h>
#include <bits/pthread_types.h>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <zconf.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>

//#include <log.h>
#include "FileWriteBuffer.h"

#define FIX_MMAP_LENGTH(length) (((length)&0xFFF)!=0?(((length)|0xFFF)+1):(length))

void FileWriteBuffer::flush(){
    auto buf=(iovec*)malloc(sizeof(iovec)*threadCount);

    int sum=0;
    for (int i = 0; i < threadCount; ++i) {
        if(position[i]>0) {
            alreadyFlushLength[i]+=position[i];
            buf[sum].iov_base=ptr_real[i];
            buf[sum].iov_len=position[i];
            sum++;
        }
    }
    writev(flushFile,buf,sum);
    free(buf);
}

void FileWriteBuffer::flush(int id){
    pthread_mutex_lock(&mutex);
    write(flushFile,ptr_real[id],position[id]);
    pthread_mutex_unlock(&mutex);
    alreadyFlushLength[id]+=position[id];
}

FileWriteBuffer::FileWriteBuffer(const char *flushPath,int _threadCount,size_t _buff_size){
    threadCount=_threadCount;
    buff_size=_buff_size;

    size_t sizes[]={
            threadCount* sizeof(char*),
            threadCount*_buff_size,
            threadCount* sizeof(size_t),
            threadCount* sizeof(off64_t)
    };

    mmapLength=sizes[0]+sizes[1]+sizes[2]+sizes[3];
    mmapLength = FIX_MMAP_LENGTH(mmapLength);
    ptr_real = (char**)mmap64(nullptr,mmapLength,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,0,0);
    bzero(ptr_real,mmapLength);

    ptr_real[0]=(char*)ptr_real+sizes[0];
    for (int i = 1; i < threadCount; ++i)
        ptr_real[i]=ptr_real[i-1]+_buff_size;

    position=(size_t*)(ptr_real[threadCount-1]+_buff_size);

    alreadyFlushLength=(off64_t *)((char*)position+sizes[2]);

    umask(0);
    flushFile=syscall(__NR_openat,AT_FDCWD,flushPath, O_RDWR | O_CREAT | O_TRUNC | O_LARGEFILE | O_CLOEXEC,  S_IRUSR|S_IWUSR  |S_IRGRP|S_IWGRP  |S_IROTH|S_IWOTH);

    pthread_mutexattr_init(&mutexAttr);
    pthread_mutexattr_setpshared(&mutexAttr, PTHREAD_PROCESS_PRIVATE);
    pthread_mutexattr_settype(&mutexAttr, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&mutex,&mutexAttr);
}

void FileWriteBuffer::append(const char *str,int id){
    size_t str_size=strlen(str);
    size_t size=str_size+position[id];
    if (size>this->buff_size){
        flush(id);
        position[id]=str_size;
    } else
        position[id]=size;
    memcpy(ptr_real[id]+position[id]-str_size,str,str_size);
}

void FileWriteBuffer::append(const char *str,size_t length,int id){
    size_t size=length+position[id];
    if (size>this->buff_size){
        flush(id);
        position[id]=length;
    } else
        position[id]=size;
    memcpy(ptr_real[id]+position[id]-length,str,length);
}

void FileWriteBuffer::append(long long value,int id){
    size_t size=8+position[id];
    if (size>this->buff_size){
        flush(id);
        position[id]=8;
    } else
        position[id]=size;
    *(long long*)(ptr_real[id]+position[id]-8)=value;
}

long long FileWriteBuffer::getLength(){
    long long sumLength=0;
    for (int i = 0; i < threadCount; ++i)
        sumLength+=alreadyFlushLength[i]+(off64_t)position[i];
    return sumLength;
}

FileWriteBuffer::~FileWriteBuffer(){
    flush();
    munmap(ptr_real,mmapLength);
    close(flushFile);
}
