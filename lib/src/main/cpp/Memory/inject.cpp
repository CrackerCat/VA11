#pragma clang diagnostic push
#pragma ide diagnostic ignored "cppcoreguidelines-avoid-goto"
#include <cstdio>
#include <cstdlib>
#include <sys/user.h>
#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <cstring>
#include <elf.h>
#include <android/log.h>
#include <syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <cerrno>
#include <fstream>
#include <fcntl.h>
#include <regex>
#include "Symbol.h"
#include <sys/stat.h>

#include "inject.h"
#include <Log.h>


#if defined(__i386__)
#define pt_regs	user_regs_struct
#elif defined(__aarch64__)
#define pt_regs         user_pt_regs
#define uregs   regs
#define ARM_pc  pc
#define ARM_sp  sp
#define ARM_cpsr    pstate
#define ARM_lr      regs[30]
#define ARM_r0      regs[0]
#define PTRACE_GETREGS PTRACE_GETREGSET
#define PTRACE_SETREGS PTRACE_SETREGSET
#endif

#define CPSR_T_MASK     ( 1u << 5 )

static int openattr(pid_t pid, const char *attr, int flags){
    int fd, rc;
    char *path;
    pid_t tid;

    if (pid > 0) {
        rc = asprintf(&path, "/proc/%d/attr/%s", pid, attr);
    } else if (pid == 0) {
        rc = asprintf(&path, "/proc/thread-self/attr/%s", attr);
        if (rc < 0)
            return -1;
        fd = open(path, flags | O_CLOEXEC);
        if (fd >= 0 || errno != ENOENT)
            goto out;
        free(path);
        tid = gettid();
        rc = asprintf(&path, "/proc/self/task/%d/attr/%s", tid, attr);
    } else {
        errno = EINVAL;
        return -1;
    }
    if (rc < 0)
        return -1;

    fd = open(path, flags | O_CLOEXEC);
    out:
    free(path);
    return fd;
}

static int set_proc_attr(pid_t pid, const char *attr,char* context){
    int ret;
    int fd = openattr(pid, attr, O_RDWR);
    if (fd < 0)
        return -1;
    if (context) {
        do {
            ret = write(fd, context, strlen(context) + 1);
        } while (ret < 0 && errno == EINTR);
    } else {
        do {
            ret = write(fd, NULL, 0);
        } while (ret < 0 && errno == EINTR);
    }
    close(fd);
    return ret;
}

static bool ensure_set_proc_attr(pid_t pid, const char *attr,char* context) {
    if(set_proc_attr(pid,attr,context)<0){
        //LOGE("set_proc_attr  %d  %s  %s   error >>>> %s",pid,attr,context,strerror(errno));
        return false;
    }
    return true;
}

static std::string get_proc_attr(pid_t pid, const char *attr){
    int ret;
    char buf[BUFSIZ];
    int fd = openattr(0, attr, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return "";
    do {
        ret = read(fd, buf, BUFSIZ);
    } while (ret < 0 && errno == EINTR);

    close(fd);
    return buf;
}

static inline __always_inline bool isStop(pid_t pid) {
    char buf[PATH_MAX];
    sprintf(buf,"/proc/%d/status",pid);
    int fd=syscall(__NR_openat,AT_FDCWD,buf,O_RDONLY,0);
    if (fd==-1) {
        //LOGE("isStop: open >>>> %s",strerror(errno));
        return false;
    }else {
        FILE *fp=fdopen(fd,"r");
        do {
            fgets(buf, PATH_MAX, fp);
        }while(!strstr(buf,"tate:"));
        fclose(fp);
        return strstr(buf, "stop") != nullptr;
    }
}

static inline __always_inline void stop(pid_t pid){
    while(!isStop(pid)){
        kill(pid,SIGSTOP);
        usleep(100);
    };
}

static inline __always_inline void recovery(pid_t pid){
    while(isStop(pid)){
        kill(pid,SIGCONT);
        usleep(100);
    };
}

static int proc_get_int (pid_t lwpid, const char *field){
    size_t field_len = strlen (field);
    FILE *status_file;
    char buf[100];
    int retval = -1;

    snprintf (buf, sizeof (buf), "/proc/%d/status", (int) lwpid);
    int fd=syscall(__NR_openat,AT_FDCWD,buf,O_RDONLY,0);
    if (fd==-1) {
        //LOGE("proc_get_int: open %s >>>> %s",buf,strerror(errno));
        return -1;
    }
    status_file=fdopen(fd,"r");
    if (status_file == nullptr){
        //LOGE("fopen %s error >>>> %s", buf,strerror(errno));
        return -1;
    }

    while (fgets (buf, sizeof (buf), status_file)) {
        if (strncmp(buf, field, field_len) == 0 && buf[field_len] == ':') {
            retval = strtol(&buf[field_len + 1], nullptr, 10);
            break;
        }
    }

    fclose (status_file);
    return retval;
}

char** split(char* content,const char* delimiter,int num){
    int position=0;
    if(num<=0)
        num=999;
    char** ptr=new char*[num+1];
    char *buf_ptr;
    ptr[0]=strtok_r(content,delimiter,&buf_ptr);
    while(ptr[position] and ++position<num)
        ptr[position]=strtok_r(nullptr,delimiter,&buf_ptr);
    ptr[position]= nullptr;
    return ptr;
}

char* split_s(char **ptr,char* content,const char* delimiter,int num){
    int position=0;
    char *buf_ptr;
    ptr[0]=strtok_r(content,delimiter,&buf_ptr);
    while(ptr[position] and ++position<num)
        ptr[position]=strtok_r(nullptr,delimiter,&buf_ptr);
    ptr[position]= nullptr;
    return buf_ptr;
}

int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size){
    size_t i, j, remain;
    uint8_t *laddr;

    union u {
        long val;
        char chars[sizeof(long)];
    } d;

    j = size / 4;
    remain = size % 4;

    laddr = data;

    for (i = 0; i < j; i ++) {
        memcpy(d.chars, laddr, 4);
        ptrace(PTRACE_POKETEXT, pid, dest, d.val);

        dest  += 4;
        laddr += 4;
    }

    if (remain > 0) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);
        for (i = 0; i < remain; i ++) {
            d.chars[i] = *laddr ++;
        }

        ptrace(PTRACE_POKETEXT, pid, dest, d.val);
    }

    return 0;
}

int ptrace_setregs(pid_t pid, struct pt_regs * regs){
#if defined (__aarch64__)
    int regset = NT_PRSTATUS;
        struct iovec ioVec;

        ioVec.iov_base = regs;
        ioVec.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void*)regset, &ioVec) < 0) {
        LOGE("ptrace_setregs: Can not get register values");
        return -1;
    }

    return 0;
#else
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
        //LOGE("ptrace_setregs: Can not set register values");
        return -1;
    }

    return 0;
#endif
}

int ptrace_continue(pid_t pid){
    if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
        //LOGE("ptrace_cont");
        return -1;
    }
    return 0;
}

#if defined(__arm__) || defined(__aarch64__)
int ptrace_call(pid_t pid, voidPtr addr, voidPtr *params, int num_params, struct pt_regs* regs){
    int i;
    int num_param_registers = sizeof(voidPtr);

    for (i = 0; i < num_params && i < num_param_registers; i ++) {
        regs->uregs[i] = params[i];
    }

    if (i < num_params) {
        regs->ARM_sp -= (num_params - i) * sizeof(long) ;
        ptrace_writedata(pid, (uint8_t *)(regs->ARM_sp), (uint8_t *)& params[i], (num_params - i) * sizeof(long));
    }
    //将PC寄存器值设为目标函数的地址
    regs->ARM_pc = addr;
    //进行指令集判断
    if (regs->ARM_pc & 1) {
        /* thumb */
        regs->ARM_pc &= (~1u);
        // #define CPSR_T_MASK  ( 1u << 5 )  CPSR为程序状态寄存器
        regs->ARM_cpsr |= CPSR_T_MASK;
    } else {
        /* arm */
        regs->ARM_cpsr &= ~CPSR_T_MASK;
    }

    regs->ARM_lr = 0;

    if (ptrace_setregs(pid, regs) == -1
        || ptrace_continue(pid) == -1) {
        //LOGE("error\n");
        return -1;
    }

    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);

    while (stat != 0xb7f) {
        if (ptrace_continue(pid) == -1) {
            //LOGE("error\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    return 0;
}
#elif defined(__i386__)
int ptrace_call(pid_t pid, voidPtr addr, voidPtr *params, uint32_t num_params, struct user_regs_struct * regs) {
    regs->esp -= (num_params) * sizeof(voidPtr);
    ptrace_writedata(pid, (uint8_t *)regs->esp, (uint8_t *)params, (num_params) * sizeof(long));

    long tmp_addr = 0x00;
    regs->esp -= sizeof(long);
    ptrace_writedata(pid, (uint8_t *)regs->esp, (uint8_t *)&tmp_addr, sizeof(tmp_addr));
    regs->eip = addr;
    if (ptrace_setregs(pid, regs) == -1
        || ptrace_continue( pid) == -1) {
        LOGE("error\n");
        return -1;
    }
    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
    while (stat != 0xb7f) {
        if (ptrace_continue(pid) == -1) {
            LOGE("error\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }
    return 0;
}
#else
#error "Not supported"
#endif

int ptrace_getregs(pid_t pid, struct pt_regs * regs){
#if defined (__aarch64__)
    int regset = NT_PRSTATUS;
        struct iovec ioVec;

        ioVec.iov_base = regs;
        ioVec.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void*)regset, &ioVec) < 0) {
        LOGE("ptrace_getregs: Can not get register values");
        LOGE(" io %llx, %d", ioVec.iov_base, ioVec.iov_len);
        return -1;
    }

    return 0;
#else
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
        //LOGE("ptrace_getregs: Can not get register values");
        return -1;
    }
    return 0;
#endif
}

int ptrace_detach(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {
        //LOGE("ptrace_detach >>>> %s",strerror(errno));
        return -1;
    }
    return 0;
}

int ptrace_attach(pid_t pid, bool is_zygote) {
    struct pt_regs regs{};
    int status = 0;
    if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {
        //LOGE("ptrace_attach >>>> %s",strerror(errno));
        return -1;
    }
    if (is_zygote) {
        while (waitpid(pid, &status, __WNOTHREAD) == -1 && (EINTR == errno));
        int times = 50;
        while ((times--) != 0) {
            if (ptrace(PTRACE_SYSCALL, pid, NULL, 0) < 0) {
                //LOGE("ptrace_syscall >>>> %s",strerror(errno));
                ptrace_detach(pid);
                kill(pid, SIGCONT);
                return -1;
            }
            while (waitpid(pid, &status, __WNOTHREAD) == -1 && (EINTR == errno));
            ptrace_getregs(pid, &regs);
            if (ptrace_continue(pid) < 0) {
                ptrace_detach(pid);
                kill(pid, SIGCONT);
                return -1;
            }
            usleep(100000u);
            kill(pid, SIGSTOP);
            while (waitpid(pid, &status, __WNOTHREAD) == -1 && (EINTR == errno));
        }
        return 0;
    } else {
        waitpid(pid, &status , WUNTRACED);
        return 0;
    }
}

void* get_module_base(pid_t pid, const char* module_name,const char* permission, const char* file_offset) {
    size_t i;
    char buf[BUFSIZ], *tok[6];
    FILE *fp;

    if (pid < 0) {
        snprintf(buf, sizeof(buf), "/proc/self/maps");
    } else {
        snprintf(buf, sizeof(buf), "/proc/%d/maps", pid);
    }

    int fd=syscall(__NR_openat,AT_FDCWD,buf,O_RDONLY,0);
    if (fd==-1) {
        //LOGE("get_module_base: open %s >>>> %s",buf,strerror(errno));
        return nullptr;
    }
    fp=fdopen(fd,"r");

    long long startAddress;

    while (fgets(buf, sizeof(buf), fp)) {
        i = strlen(buf);
        if (i > 0 && buf[i - 1] == '\n')
            buf[i - 1] = 0;

        tok[0] = strtok(buf, " ");
        for (i = 1; i < 6; i++)
            tok[i] = strtok(nullptr, " ");

        if (tok[5] and strstr(tok[5],module_name) and !strcmp(permission,tok[1]) and !strcmp(file_offset,tok[2])) {
            char **ptr=split(tok[0],"-",2);
            sscanf(ptr[0], "%llx", &startAddress);
            delete(ptr);
            return (void*)startAddress;
        }
    }

    fclose(fp);
    return nullptr;
}

void* get_remote_addr(pid_t target_pid, const char* module_name, const char* permission, const char* file_offset,long long offset) {
    //LOGD("get_remote_addr %d %s %s %s %llx",target_pid,permission,file_offset,module_name,offset);
    void* remote_handle = get_module_base(target_pid, module_name,permission,file_offset);
    if(remote_handle== nullptr)
        return nullptr;
    auto * ret_addr = (void *)(offset + (long long)remote_handle );
#if defined(__i386__)
    if (strstr(module_name, "libc.so")) {
        char* ret=(char*)ret_addr + 2;
        return ret;
    }
#endif
    return ret_addr;
}

void* get_remote_func(pid_t target_pid, void* address) {
    size_t i;
    char buf[BUFSIZ];
    char *tok[6];
    FILE *fp;

    int fd=syscall(__NR_openat,AT_FDCWD,"/proc/self/maps",O_RDONLY,0);
    if (fd==-1) {
        //LOGE("get_remote_func: open /proc/self/maps >>>> %s",strerror(errno));
        return nullptr;
    }
    fp=fdopen(fd,"r");
    long long startAddress;
    long long endAddress;

    while (fgets(buf, sizeof(buf), fp)) {
        i = strlen(buf);
        if (i > 0 && buf[i - 1] == '\n')
            buf[i - 1] = 0;

        tok[0] = strtok(buf, " ");
        for (i = 1; i < 6; i++)
            tok[i] = strtok(nullptr, " ");

        if (tok[5]) {
            char **ptr=split(tok[0],"-",2);
            sscanf(ptr[0], "%llx", &startAddress);
            sscanf(ptr[1], "%llx", &endAddress);
            delete(ptr);
            if(startAddress<(long long)address and (long long)address<endAddress) {
                fclose(fp);
                return get_remote_addr(target_pid,tok[5],tok[1],tok[2],(long long)address-startAddress);
            }
        }
    }

   // LOGE("find %p failed !",address);

    fclose(fp);
    return nullptr;
}

voidPtr ptrace_retval(struct pt_regs * regs){
#if defined(__arm__) || defined(__aarch64__)
    return regs->ARM_r0;
#elif defined(__i386__)
    return regs->eax;
#else
#error "Not supported"
#endif
}

voidPtr ptrace_ip(struct pt_regs * regs){
#if defined(__arm__) || defined(__aarch64__)
    return regs->ARM_pc;
#elif defined(__i386__)
    return regs->eip;
#else
#error "Not supported"
#endif
}

int ptrace_call_wrapper(pid_t target_pid, void* func_addr, voidPtr *parameters, uint32_t param_num, struct pt_regs * regs) {
    if (ptrace_call(target_pid, (voidPtr)func_addr, parameters, param_num, regs) == -1)
        return -1;
    if (ptrace_getregs(target_pid, regs) == -1)
        return -1;
    return 0;
}

bool file_exists(const char* path){
    return access(path, 0) == 0;
}

long setxattr(const char *path, const char *value) {
    if (!file_exists("/sys/fs/selinux")) {
        return 0;
    }
    return syscall(__NR_setxattr, path, "security.selinux", value, strlen(value),0);
}


pid_t getTracerPid(pid_t target_pid){
    return proc_get_int(target_pid, "TracerPid");
}

const char* fixLibPath(const char* cachePath,const char* orig){
    if(!cachePath)
        return orig;
    char cmd[BUFSIZ];
    sprintf(cmd,"cp %s %s",orig,cachePath);
    system(cmd);
    umask(0);
    chmod(cachePath,S_IRUSR|S_IWUSR|S_IXUSR|   S_IRGRP|S_IXGRP|   S_IROTH|S_IXOTH);
    return cachePath;
}

int inject_remote_process(pid_t target_pid, const char *library_path,const char *cachePath,bool isZygote){
    //LOGD("%d,%s,%d",target_pid,library_path,isZygote);

    library_path=fixLibPath(cachePath,library_path);

    int ret = -1;
    void *malloc_addr;
    void *dlopen_addr;
    void *free_addr;
    struct pt_regs regs{};
    struct pt_regs original_regs{};

    voidPtr map_base = 0 ;
    voidPtr parameters[10];

    //保存现场
    if (ptrace_attach(target_pid,isZygote) == -1) {
        //LOGE("ptrace_attach error >>>> %s",strerror(errno));
        return ret;
    }

    if (ptrace_getregs(target_pid, &regs) == -1) {
        //LOGE("ptrace_getregs error >>>> %s",strerror(errno));
        goto exit;
    }
    memcpy(&original_regs, &regs, sizeof(regs));

    //malloc申请空间用于储存接下来调用dlopen以及目标函数时需要的字符串参数
    malloc_addr = get_remote_func(target_pid, (void *)malloc);
    free_addr = get_remote_func(target_pid, (void *)free);

    //LOGD("malloc_addr >>>> %p",malloc_addr);
    //LOGD("free_addr >>>> %p",free_addr);

    parameters[0] = 0x1000;
    if (ptrace_call_wrapper(target_pid,  malloc_addr, parameters, 1, &regs) == -1) {
        //LOGE("ptrace_call_wrapper error >>>> %s",strerror(errno));
        goto exit;
    }
    map_base = ptrace_retval(&regs);

    if(map_base==0 or (void*)map_base== nullptr) {
        //LOGE("ptrace_retval error >>>> %s",strerror(errno));
        goto exit;
    }

#if defined(__aarch64__)
    LOGD("map_base >>>> 0x%llX",map_base);
#else
    //LOGD("map_base >>>> 0x%lX",map_base);
#endif


    //获取dlopen目标进程中的虚拟地址
    dlopen_addr = get_remote_func(target_pid, (void *)dlopen);

    //LOGD("dlopen_addr >>>> %p",dlopen_addr);

    //判断是否开启了selinux并进行处理，随后远程调用dlopen加载目标模块
    setxattr(library_path, "u:object_r:system_file:s0");
    ptrace_writedata(target_pid, (uint8_t*)map_base, (uint8_t*)library_path, strlen(library_path) + 1);
    parameters[0] = map_base;
    parameters[1] = RTLD_NOW| RTLD_GLOBAL;
    if (ptrace_call_wrapper(target_pid, dlopen_addr, parameters, 2, &regs) == -1){
        //LOGE("ptrace_call_wrapper dlopen error >>>> %s",strerror(errno));
        goto exit;
    }

    //释放malloc申请的空间
    parameters[0] = map_base;
    if (ptrace_call_wrapper(target_pid,free_addr, parameters,1, &regs) == -1) {
        //LOGE("ptrace_call_wrapper malloc error >>>> %s", strerror(errno));
        goto exit;
    }

    //恢复现场
    ret = 0;
    exit:
    ptrace_setregs(target_pid, &original_regs);
    ptrace_detach(target_pid);
    kill(target_pid,SIGCONT);
    return ret;
}

int inject_remote_process(pid_t target_pid, const char *library_path,const char *cachePath,char* funcName,char* funcParameter,bool isZygote){
    //LOGD("%d,%s,%s,%s,%d",target_pid,library_path,funcName,funcParameter,isZygote);

    library_path=fixLibPath(cachePath,library_path);

    int ret = -1;
    void *malloc_addr;
    void *dlopen_addr;
    void *dlsym_addr;
    void *free_addr;
    void *func_addr;
    struct pt_regs regs{};
    struct pt_regs original_regs{};

    voidPtr map_base = 0 ;
    voidPtr parameters[10];

    //保存现场
    if (ptrace_attach(target_pid,isZygote) == -1) {
        //LOGE("ptrace_attach error >>>> %s",strerror(errno));
        return ret;
    }
    if (ptrace_getregs(target_pid, &regs) == -1)
        goto exit;
    memcpy(&original_regs, &regs, sizeof(regs));

    //malloc申请空间用于储存接下来调用dlopen以及目标函数时需要的字符串参数
    malloc_addr = get_remote_func(target_pid, (void *)malloc);
    free_addr = get_remote_func(target_pid, (void *)free);

    //LOGD("malloc_addr >>>> %p",malloc_addr);
    //LOGD("free_addr >>>> %p",free_addr);

    parameters[0] = 0x1000;
    if (ptrace_call_wrapper(target_pid,  malloc_addr, parameters, 1, &regs) == -1)
        goto exit;
    map_base = ptrace_retval(&regs);

    if(map_base==0 or (void*)map_base== nullptr)
        goto exit;

#if defined(__aarch64__)
    LOGD("map_base >>>> 0x%llX",map_base);
#else
    //LOGD("map_base >>>> 0x%lX",map_base);
#endif

    //获取dlopen目标进程中的虚拟地址
    dlopen_addr = get_remote_func(target_pid, (void *)dlopen);
    //获取dlsym目标进程中的虚拟地址
    dlsym_addr = get_remote_func(target_pid, (void *)dlsym);

    //LOGD("dlopen_addr >>>> %p",dlopen_addr);

    //判断是否开启了selinux并进行处理，随后远程调用dlopen加载目标模块
    setxattr(library_path, "u:object_r:system_file:s0");
    ptrace_writedata(target_pid, (uint8_t*)map_base, (uint8_t*)library_path, strlen(library_path) + 1);
    parameters[0] = map_base;
    parameters[1] = RTLD_NOW| RTLD_GLOBAL;
    if (ptrace_call_wrapper(target_pid, dlopen_addr, parameters, 2, &regs) == -1)
        goto exit;


    //远程调用dlsym
    ptrace_writedata(target_pid,(uint8_t*)(map_base), (uint8_t*)funcName, strlen(funcName) + 1);
    parameters[0] = ptrace_retval(&regs);
    parameters[1] = map_base;
    if (ptrace_call_wrapper(target_pid, dlsym_addr, parameters, 2, &regs) == -1)
        goto exit;

    func_addr=(void*)ptrace_retval(&regs);

    ptrace_writedata(target_pid,(uint8_t*)(map_base), (uint8_t*)funcParameter, strlen(funcParameter) + 1);
    parameters[0] = map_base;
    if (ptrace_call_wrapper(target_pid,func_addr, parameters,1, &regs) == -1)
        goto exit;

    //释放malloc申请的空间
    parameters[0] = map_base;
    if (ptrace_call_wrapper(target_pid,free_addr, parameters,1, &regs) == -1)
        goto exit;

    ret = 0;

    //恢复现场
    exit:
    ptrace_setregs(target_pid, &original_regs);
    ptrace_detach(target_pid);
    kill(target_pid,SIGCONT);
    return ret;
}
#pragma clang diagnostic pop