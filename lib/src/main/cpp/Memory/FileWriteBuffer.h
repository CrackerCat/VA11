//
// Created by z742978469 on 20-1-26.
//

#ifndef PEAK_ROOT_SUPPORT_FILEWRITEBUFFER_H
#define PEAK_ROOT_SUPPORT_FILEWRITEBUFFER_H

#include <bits/pthread_types.h>

class FileWriteBuffer{
private:
    pthread_mutexattr_t mutexAttr;
    pthread_mutex_t mutex;
    char **ptr_real;
    size_t buff_size;
    size_t *position;
    off64_t *alreadyFlushLength;
    int flushFile;
    size_t mmapLength;

    int threadCount;

    void flush();

    void flush(int id);
public:
    FileWriteBuffer(const char *flushPath,int _threadCount,size_t _buff_size=10485760);

    void append(const char *str,int id);

    void append(const char *str,size_t length,int id);

    void append(long long value,int id);

    long long getLength();

    ~FileWriteBuffer();
};

#endif //PEAK_ROOT_SUPPORT_FILEWRITEBUFFER_H
