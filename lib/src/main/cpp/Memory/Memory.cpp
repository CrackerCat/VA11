//
// Created by z742978469 on 20-1-26.
//

#include <sys/mman.h>
#include <fstream>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <regex>
#include <dlfcn.h>
#include <sys/mount.h>
#include <syscall.h>
#include <cstring>
#include <cstdlib>

//#include <Log.h>
#include "Symbol.h"
#include "Memory.h"
#include "MemCache.h"
#include "inject.h"
#include "FileWriteBuffer.h"
#include "SearchValue.h"
#include "ctpl_stl.h"



#define regionType_error 1073741824


static void* readMemThread(void *cache_);

static void scanPerCache8(int id, MemCache &mapsCache);

static void scanPerCache16(int id, MemCache &mapsCache);

static void scanPerCache32(int id, MemCache &mapsCache);

static void scanPerCache64(int id, MemCache &mapsCache);

filter_value_ret Memory::regex_value(char* value){
    int32_t lastOffset=0,offsetTemp=0;
    value_reg valueTemp;
    std::vector<value_reg> ret;
    filter_value_ret realRet;
    realRet.maxOffset=0;
    int i=0,bitLengthAddOffset;
    char *param[4];
    char *values[100];

    split_s(values,value,";",100);
    while(values[i]!= nullptr){
        split_s(param,values[i++],":",3);
        lastOffset=offsetTemp;
        offsetTemp=atoi(param[1]);
        valueTemp.offset=offsetTemp-lastOffset;
        if(!strncmp(param[2],"f32",3) or !strncmp(param[2],"F32",3)){
            valueTemp.value.float32_value = (float)strtod(param[0], nullptr);
            valueTemp.type=f32;
            bitLengthAddOffset=offsetTemp+4;
        }else if(!strncmp(param[2],"f64",3) or !strncmp(param[2],"F64",3)) {
            valueTemp.value.float64_value = strtod(param[0], nullptr);
            valueTemp.type=f64;
            bitLengthAddOffset=offsetTemp+8;
        }else{
            valueTemp.value.int64_value = atoll(param[0]);
            if(!strncmp(param[2],"i32",3) or !strncmp(param[2],"I32",3)){
                valueTemp.type=i32;
                bitLengthAddOffset=offsetTemp+4;
            }else if(!strncmp(param[2],"i64",3) or !strncmp(param[2],"I64",3)){
                valueTemp.type=i64;
                bitLengthAddOffset=offsetTemp+8;
            }else if(!strncmp(param[2],"i8",2) or !strncmp(param[2],"I8",2)){
                valueTemp.type=i8;
                bitLengthAddOffset=offsetTemp+1;
            }else {
                valueTemp.type = i16;
                bitLengthAddOffset=offsetTemp+2;
            }
        }
        if(bitLengthAddOffset>realRet.maxOffset)
            realRet.maxOffset=bitLengthAddOffset;
        ret.push_back(valueTemp);
    }
    realRet.values=ret;
    return realRet;
}

Memory::Memory(){
    threadCounts=(int)sysconf( _SC_NPROCESSORS_ONLN)+3;
    if(threadCounts<8)
        threadCounts=8;
    else if(threadCounts>10)
        threadCounts=10;
}

Memory*& Memory::get(){
    static Memory *memory=new Memory();
    return memory;
}

int Memory::getAttachingPid(){
    return pid;
}

bool Memory::findInValue(const size_t num,const char* buff){
    if (num==1)
        return true;
    valueTemp=(value_t*)(buff);
    for (size_t i=1;i<num;i++) {
        valueTemp= (value_t *)((char*)valueTemp + (*value_all)[i].offset);
        switch((*value_all)[i].type){
            case f64:
                if ((*value_all)[i].value.float64_value!=valueTemp->float64_value)
                    return false;
                break;
            case f32:
                if ((*value_all)[i].value.float32_value!=valueTemp->float32_value)
                    return false;
                break;
            case i32:
                if ((*value_all)[i].value.int32_value!=valueTemp->int32_value)
                    return false;
                break;
            case i8:
                if ((*value_all)[i].value.int8_value!=valueTemp->int8_value)
                    return false;
                break;
            case i16:
                if ((*value_all)[i].value.int16_value!=valueTemp->int16_value)
                    return false;
                break;
            case i64:
                if ((*value_all)[i].value.int64_value!=valueTemp->int64_value)
                    return false;
                break;
            default:
                return false;
        }
    }
    return true;
}

void Memory::attach(int _pid, const char *_cacheFilePath) {
    pid=_pid;
    strcpy(cacheFilePath,_cacheFilePath);
    sprintf(maps_path, "/proc/%d/maps", _pid);
    sprintf(status_path, "/proc/%d/status",  _pid);
    isAttach=true;
}

std::string Memory::getRegionTypeName(int type){
    switch (type) {
        case regionType_Stack:
            return "regionType_Stack";
        case regionType_Heap:
            return "regionType_Heap";
        case regionType_Xs:
            return "regionType_Xs";
        case regionType_Xa:
            return "regionType_Xa";
        case regionType_Java:
            return "regionType_Java";
        case regionType_JavaHeap:
            return "regionType_JavaHeap";
        case regionType_Bad:
            return "regionType_Bad";
        case regionType_Anonymous:
            return "regionType_Anonymous";
        case regionType_Cd:
            return "regionType_Cd";
        case regionType_Cb:
            return "regionType_Cb";
        case regionType_Ca:
            return "regionType_Ca";
        case regionType_As:
            return "regionType_As";
        case regionType_Media:
            return "regionType_Media";
        case regionType_Other:
            return "regionType_Other";
        default:
            break;
    }
    return "error";
};

int Memory::judgeRegionType(std::string& permission,std::string& from){
    if(permission[0]!='r')
        return regionType_error;

    if(from.empty()){
        if(permission[3]=='p')
            return regionType_Anonymous;
        return regionType_Other;
    }

    if(from.find("/system/")!=-1){
        if(from.find("/fonts/")!=-1)
            return regionType_Bad;
        if(from.find("/buggy")!=-1)
            return regionType_error;
        if(permission[2]=='x')
            return regionType_Xs;
        return regionType_Other;
    }

    if(from.find("/dev/")!=-1) {
        if(from.find("binder")!=-1)
            return regionType_error;
        if(from.find("/xLog")!=-1)
            return regionType_Bad;
        if(from.find("/zero")!=-1) {
            if(permission=="rwxs")
                return regionType_error;
            return regionType_Ca;
        }

        if(from.find("ashmem")!=-1) {
            if (permission[3] == 's')
                return regionType_As;

            if (from.find("dalvik") != -1) {
                if (permission=="rw-p" and
                    (from.find("object") != -1 or from.find("allocation") != -1 or from.find("main space") != -1))
                    return regionType_JavaHeap;
                return regionType_Java;
            }
        }
        if(from.find("input")!=-1 or
           from.find("graphics")!=-1 or
           from.find("kgsl")!=-1 or
           from.find("v4l")!=-1 or
           from.find("video")!=-1 or
           from.find("media")!=-1 or
           from.find("mali")!=-1 or
           from.find("nv")!=-1 or
           from.find("tegra")!=-1 or
           from.find("ion")!=-1 or
           from.find("pvr")!=-1 or
           from.find("render")!=-1 or
           from.find("galcore")!=-1 or
           from.find("fimg2d")!=-1 or
           from.find("quadd")!=-1 or
           from.find("mm_")!=-1 or
           from.find("dri/")!=-1)
            return regionType_Media;
        if(permission[2]=='x')
            return regionType_Xs;
        return regionType_Other;
    }

    if(from.find("/data/")!=-1){
        if(from.find("/buggy")!=-1)
            return regionType_error;
        if(permission[2]=='x')
            return regionType_Xa;
        if(from.find(".dex")!=-1 or from.find(".odex")!=-1 or from.find(".art")!=-1 or from.find(".apk")!=-1)
            return regionType_Other;
        if(permission[3]=='s')
            return regionType_As;
        return regionType_Cd;
    }

    if(from.find("[stack")!=-1)
        return regionType_Stack;
    if(from.find("libc_malloc")!=-1)
        return regionType_Ca;
    if(from.find("[anon:.bss")!=-1)
        return regionType_Cb;
    if(from.find("[vdso]")!=-1)
        return regionType_Xs;
    if(from.find("[vvar]")!=-1)
        return regionType_error;
    if(from.find("[heap")!=-1)
        return regionType_Heap;
    if(from.find("dmabuf")!=-1)
        return regionType_Bad;
    if(from.find("MemoryHeapBase")!=-1)
        return regionType_As;
    if(from.find("PPSSPP_RAM")!=-1)
        return regionType_As;
    if(permission[2]=='x')
        return regionType_Xs;
    return regionType_Other;
}

maps_filter_result Memory::filterRegions(char *line){
    maps_filter_result filter;
    char *strs[6];
    char *address[2];
    filter.from = split_s(strs,line," ",5);
    filter.permission=strs[1];
    split_s(address,strs[0],"-",2);
    filter.start_address=address[0];
    filter.end_address=address[1];
    filter.isNull = 1;
    int _regionType=judgeRegionType(filter.permission,filter.from);

    if(_regionType==regionType_error)
        return filter;
    if(regionType&_regionType) {
        //LOGD("fit  %s %s %s", filter.permission.c_str(), filter.from.c_str(),getRegionTypeName(_regionType).c_str());
        filter.isNull = 0;
    }
    return filter;
}

bool Memory::search(SearchValue &searchValue,int _regionType){
    if(!isAttach)
        return false;

    regionType=_regionType;

    std::vector<value_reg> value=searchValue.getValue();
    value_all=&value;
    valueNum=searchValue.getNum();
    maxOffset=searchValue.getMaxLength();

    searchResultWriteBuffer=new FileWriteBuffer(cacheFilePath,threadCounts);

    MemCache memCache= MemCache(maxOffset,threadCounts);
    pthread_t myThread;
    pthread_create(&myThread, nullptr,readMemThread,&memCache);
    ctpl::thread_pool threadPool(threadCounts);

    switch (value[0].type) {
        case i8:
            for(int i=0;i<threadCounts;i++)
                threadPool.push(scanPerCache8, std::ref(memCache));
            break;
        case i16:
            for(int i=0;i<threadCounts;i++)
                threadPool.push(scanPerCache16, std::ref(memCache));
            break;
        case f32:
        case i32:
            for(int i=0;i<threadCounts;i++)
                threadPool.push(scanPerCache32, std::ref(memCache));
            break;
        case f64:
        case i64:
            for(int i=0;i<threadCounts;i++)
                threadPool.push(scanPerCache64, std::ref(memCache));
            break;
        default:
            break;
    }
    threadPool.stop(true);
    delete(searchResultWriteBuffer);
    return true;
}

bool Memory::search(char *context,int regionType){
    if(!isAttach)
        return false;

    int i=0;

    this->regionType= regionType;

    filter_value_ret retValue=regex_value(context);

    searchResultWriteBuffer=new FileWriteBuffer(cacheFilePath,threadCounts);

    maxOffset=retValue.maxOffset;
    value_all=&retValue.values;
    valueNum=value_all->size();

    MemCache mapsCache= MemCache(maxOffset,threadCounts);
    pthread_t myThread;
    pthread_create(&myThread, nullptr,readMemThread,&mapsCache);
    ctpl::thread_pool threadPool(threadCounts);

    switch ((*value_all)[0].type) {
        case f32:
        case i32:
            for(;i<threadCounts;i++)
                threadPool.push(scanPerCache32, std::ref(mapsCache));
            break;
        case i8:
            for(;i<threadCounts;i++)
                threadPool.push(scanPerCache8, std::ref(mapsCache));
            break;
        case i16:
            for(;i<threadCounts;i++)
                threadPool.push(scanPerCache16, std::ref(mapsCache));
            break;
        case f64:
        case i64:
            for(;i<threadCounts;i++)
                threadPool.push(scanPerCache64, std::ref(mapsCache));
            break;
        default:
            break;
    }
    threadPool.stop(true);
    delete(searchResultWriteBuffer);
    return true;
}

bool Memory::read(void *address, void *buffer, size_t size){
    if(pid<=0)
        return false;
    struct iovec local[1];
    struct iovec remote[1];
    local[0].iov_base = buffer;
    local[0].iov_len = size;
    remote[0].iov_base = address;
    remote[0].iov_len = size;
    return syscall(__NR_process_vm_readv, pid, local, 1, remote, 1, 0)!=-1;
}

bool Memory::write(void *address, void *buffer, size_t size){
    if(pid<=0)
        return false;
    struct iovec local[1];
    struct iovec remote[1];
    local[0].iov_base = buffer;
    local[0].iov_len = size;
    remote[0].iov_base = address;
    remote[0].iov_len = size;
    return syscall(__NR_process_vm_writev, pid, local, 1, remote, 1, 0)!=-1;
}

bool Memory::inject(char *context, const char* cachePath) {
    return inject_remote_process(pid,context+8,cachePath,(bool)*context)==0;
}

bool Memory::injectWithFunc(char *context, const char* cachePath) {
    char *strs[3];
    char *paramRest=split_s(strs, context+8, " ", 2);
    return inject_remote_process(pid,strs[0],cachePath,strs[1],paramRest,(bool)*context)==0;
}

Memory& Memory::setThreadCount(int threadCount){
    threadCounts=threadCount;
    return *this;
}

bool Memory::check() {
    char buf[PATH_MAX];
    int fd=syscall(__NR_openat,AT_FDCWD,"/proc/self/maps",O_RDONLY,0);
    if (fd==-1) {
        //LOGE("check: open /proc/self/maps >>>> %s",strerror(errno));
        return false;
    }
    FILE* fp=fdopen(fd,"r");
    do {
        fgets(buf, PATH_MAX, fp);
    }while(!strstr(buf,"tate:"));
    fclose(fp);
    return strstr(buf, "stop") != nullptr;
}

long long Memory::getModuleAddress(const char* libName) {
    if(!isAttach)
        return 0;

    std::string line,name="/";
    name.append(libName);
    maps_filter_result filter;

    off64_t ret=0;
    size_t i;
    FILE *fp;
    char buf[PAGE_SIZE];
    if ((fp = fopen(maps_path,O_RDONLY, "r")) == nullptr)
        return 0;
    while (fgets(buf, sizeof(buf), fp)) {
        i = strlen(buf);
        if (i > 0 && buf[i - 1] == '\n')
            buf[i - 1] = 0;
        filter = filterRegions(buf);
        if (filter.isNull == 0) {
            if(filter.from.find(name)!=-1 and filter.permission == "r-xp"){
                sscanf(filter.start_address.c_str(), "%llx", &ret);
                fclose(fp);
                return ret;
            }
        }
    }
    fclose(fp);
    return 0;
}


long long Memory::getFuncAddress(const char* libName,const char *funcName){
    if(!isAttach)
        return 0;
    off64_t ret=0;

    std::string line,name="/";
    name.append(libName);
    maps_filter_result filter;
    size_t i;
    FILE *fp;
    char buf[PAGE_SIZE];
    if ((fp = fopen(maps_path,O_RDONLY, "r")) == nullptr)
        return 0;
    while (fgets(buf, sizeof(buf), fp)) {
        i = strlen(buf);
        if (i > 0 && buf[i - 1] == '\n')
            buf[i - 1] = 0;
        filter = filterRegions(buf);
        if (filter.isNull == 0) {
            if(filter.from.find(name)!=-1 and filter.permission == "r-xp"){
//                //LOGD("%s,%s",filter.from.c_str(),funcName);
                long long offset;
                resolve_symbol(filter.from.c_str(),funcName,(intptr_t*)&offset);
               // LOGD("%lld",offset);
                if(offset<=0){
                    fclose(fp);
                    return 0;
                }
                sscanf(filter.start_address.c_str(), "%llx", &ret);
                fclose(fp);
                return ret+offset;
            }
        }
    }
    fclose(fp);
    return 0;
}


bool Memory::dump(const char* name){
    if(!isAttach)
        return false;
    long long startAddress, endAddress;
    maps_filter_result filter;
    size_t i;
    FILE *fp;
    char buf[PAGE_SIZE];
    int fd;
    if ((fd = syscall(__NR_openat,AT_FDCWD,maps_path, O_RDONLY)) == -1) {
        return false;
    }
    fp=fdopen(fd,"r");
    std::vector<maps_filter_result> segments;

    int regionType=this->regionType;

    this->regionType=-1;
    while (fgets(buf, sizeof(buf), fp)) {
        i = strlen(buf);
        if (i > 0 && buf[i - 1] == '\n')
            buf[i - 1] = 0;
        filter = filterRegions(buf);
        if (filter.from.find(name)!=-1) {
            segments.push_back(filter);
        }
    }
    this->regionType=regionType;
    fclose(fp);
    umask(0);
    if(segments.empty())
        return false;

    char dumpPath[500];
    char* cacheDir=strdup(cacheFilePath);
    *(strrchr(cacheDir,'/'))=0;
    sprintf(dumpPath,"%s/dump/",cacheDir);
    free(cacheDir);

    mkdir(dumpPath,00755);
    sprintf(dumpPath,"%s%s-%s_%s",dumpPath,segments[0].start_address.c_str(),segments[segments.size()-1].end_address.c_str(),strrchr(segments[0].from.c_str(),'/')+1);

    //LOGD("dump >>>> %s",dumpPath);

    sscanf(segments[0].start_address.c_str(), "%llx", &startAddress);
    sscanf(segments[segments.size()-1].end_address.c_str(), "%llx", &endAddress);

    size_t size= static_cast<size_t>(endAddress - startAddress);
    char* dumpBuf=new char[size];
    if(!read((void*)startAddress,dumpBuf,size)) {
        //LOGE("read filed %p >>>> %s",(void*)startAddress,strerror(errno));
        delete(dumpBuf);
        return false;
    }
    fd=open(dumpPath,O_RDWR|O_TRUNC|O_CREAT,S_IRWXU | S_IRWXG | S_IRWXO);
    if(fd== -1) {
        //LOGE("%s open filed >>>> %s",dumpPath,strerror(errno));
        return false;
    }
    ftruncate64(fd,size);
    ::write(fd,(void*)dumpBuf,size);
    close(fd);
    delete[](dumpBuf);
    return true;
}

bool Memory::dump(void *startAddress, size_t length, const char *name) {
    if(!isAttach)
        return false;

    int i;
    char buf[PATH_MAX];
    maps_filter_result filter;
    FILE* fp=fopen(maps_path,O_RDONLY,"r");
    if(fp== nullptr) {
        //LOGE("dump: fopen %s error >>>> %s",maps_path,strerror(errno));
        return false;
    }
    long long segmentStart;
    long long segmentEnd;
    int regionType=this->regionType;
    this->regionType=-1;
    while (!name and fgets(buf, sizeof(buf), fp)) {
        i = strlen(buf);
        if (i > 0 && buf[i - 1] == '\n')
            buf[i - 1] = 0;
        filter = filterRegions(buf);
        sscanf(filter.start_address.c_str(), "%llx", &segmentStart);
        sscanf(filter.end_address.c_str(), "%llx", &segmentEnd);
        if (segmentStart<=(long long)startAddress and segmentEnd>=(long long)startAddress) {
            const char *segmentName=strrchr(filter.from.c_str(),'/');
            if(segmentName){
                name=segmentName+1;
            }
            break;
        }
    }
    this->regionType=regionType;
    fclose(fp);

    if(!name){
        name=buf;
        sprintf(buf,"%p_%zu",startAddress,length);
    }

    char dumpPath[500];
    char* cacheDir=strdup(cacheFilePath);
    *(strrchr(cacheDir,'/'))=0;
    sprintf(dumpPath,"%s/dump/",cacheDir);
    free(cacheDir);
    mkdir(dumpPath,00755);
    strcat(dumpPath,name);

    //LOGD("dump >>>> %s",dumpPath);

    char* dumpBuf=new char[length];
    if(!read(startAddress,dumpBuf,length)){
        //LOGE("read filed %p >>>> %s",startAddress,strerror(errno));
        delete(dumpBuf);
        return false;
    }
    int fd=open(dumpPath,O_RDWR|O_TRUNC|O_CREAT,S_IRWXU | S_IRWXG | S_IRWXO);
    if(fd== -1) {
       // LOGE("%s open filed >>>> %s",dumpPath,strerror(errno));
        delete(dumpBuf);
        return false;
    }
    ftruncate64(fd,length);
    ::write(fd, dumpBuf, length);
    close(fd);
    delete[](dumpBuf);
    return true;
}


bool Memory::getProcessName(pid_t pid, char *buf,size_t bufSize) {
    sprintf(buf, "/proc/%d/cmdline",pid);
    int fd = syscall(__NR_openat,AT_FDCWD,buf, O_RDONLY,0);
    if (fd != -1) {
        ::read(fd, buf, bufSize);
        close(fd);
        return true;
    }else{
        *buf=0;
        return false;
    }
}

bool Memory::getPackageName(pid_t pid, char *buf, size_t bufSize){
    if(!getProcessName(pid,buf,bufSize))
        return false;
    char* ptr;
    if((ptr=strstr(buf,":")))
        *ptr=0;
    return true;
}

int Memory::open(const char *__path, int __flags, mode_t mode) {
    if(!__path)
        return -1;
    return syscall(__NR_openat,AT_FDCWD,__path,__flags,mode);
}

FILE* Memory::fopen(const char *__path, int __flags, char *___flags, mode_t mode) {
    int fd=open(__path,__flags,mode);
    if(fd==-1)
        return nullptr;
    return fdopen(fd,___flags);
}

static void scanPerCache8(int id, MemCache &mapsCache){
    int32_t length,buff_pos;
    CacheInfo *ptr;
    Memory memory=*Memory::get();
    int8_t value=(*memory.value_all)[0].value.int8_value;
    int rest;
    while((ptr=mapsCache.get(id))) {
        rest=ptr->length%memory.maxOffset;
        length= rest ? ptr->length-rest : ptr->length ;
        buff_pos=0;
        while (buff_pos <= length) {
            if (* (ptr->buff + buff_pos) == value and memory.findInValue(memory.valueNum, ptr->buff + buff_pos))
                memory.searchResultWriteBuffer->append(ptr->realBaseAddress + buff_pos,id);
            buff_pos += 1;
        }
    }
}

static void scanPerCache16(int id, MemCache &mapsCache){
    int32_t length,buff_pos;
    CacheInfo *ptr;
    Memory memory=*Memory::get();
    int8_t value=(*memory.value_all)[0].value.int16_value;
    int rest;
    while((ptr=mapsCache.get(id))) {
        rest=ptr->length%memory.maxOffset;
        length= rest ? ptr->length-rest : ptr->length ;
        buff_pos=0;
        while (buff_pos <= length) {
            if (* (ptr->buff + buff_pos) == value and memory.findInValue(memory.valueNum, ptr->buff + buff_pos))
                memory.searchResultWriteBuffer->append(ptr->realBaseAddress + buff_pos,id);
            buff_pos += 1;
        }
    }
}

static void scanPerCache32(int id, MemCache &mapsCache){
    int32_t length,buff_pos;
    CacheInfo *ptr;
    Memory memory=*Memory::get();
    int32_t value=(*memory.value_all)[0].value.int32_value;
    int rest;
    while((ptr=mapsCache.get(id))) {
        rest=ptr->length%memory.maxOffset;
        length= rest ? ptr->length-rest : ptr->length ;
        buff_pos=0;
        while (buff_pos <= length) {
            if (*(int32_t *) (ptr->buff + buff_pos) == value and memory.findInValue(memory.valueNum, ptr->buff + buff_pos)) {
                memory.searchResultWriteBuffer->append(ptr->realBaseAddress + buff_pos, id);
            }
            buff_pos += 4;
        }
    }
}

static void scanPerCache64(int id, MemCache &mapsCache){
    int32_t length,buff_pos;
    CacheInfo *ptr;
    Memory memory=*Memory::get();
    int64_t value=(*memory.value_all)[0].value.int64_value;
    int rest;
    while((ptr=mapsCache.get(id))) {
        rest=ptr->length%memory.maxOffset;
        length= rest ? ptr->length-rest : ptr->length ;
        buff_pos=0;
        while (buff_pos <= length) {
            if (*(int64_t *) (ptr->buff + buff_pos) == value and memory.findInValue(memory.valueNum, ptr->buff + buff_pos))
                memory.searchResultWriteBuffer->append(ptr->realBaseAddress + buff_pos,id);
            buff_pos += 4;
        }
    }
}

static void* readMemThread(void *cache_){
    auto cache=( MemCache*)cache_;
    long long startAddress,endAddress;
    maps_filter_result filter;

    int readRest;
    size_t i;
    FILE *fp;
    char buf[PAGE_SIZE];
    Memory memory=*Memory::get();

    int fd=syscall(__NR_openat,AT_FDCWD,memory.maps_path,O_RDONLY,0);
    if(fd==-1){
        //LOGE("readMemThread: open %s >>>> %s",memory.maps_path,strerror(errno));
        cache->readOver();
        return nullptr;
    }

    fp=fdopen(fd,"r");
    while (fgets(buf, sizeof(buf), fp)) {
        i = strlen(buf);
        if (i > 0 && buf[i - 1] == '\n')
            buf[i - 1] = 0;
        filter = memory.filterRegions(buf);
        if (filter.isNull == 0) {
            sscanf(filter.start_address.c_str(), "%llx", &startAddress);
            sscanf(filter.end_address.c_str(), "%llx", &endAddress);
            while((readRest= cache->readFromMem(startAddress, (size_t) (endAddress - startAddress)))>0)
                startAddress=startAddress+(readRest>memory.maxOffset?readRest-memory.maxOffset:0);
        }
    }
    fclose(fp);
    cache->readOver();
    return nullptr;
}
