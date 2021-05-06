//
// Created by 86151 on 2021/5/1.
//

#ifndef GM_MEMORY_H
#define GM_MEMORY_H

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <dirent.h>
#include <syscall.h>
#include <linux/uio.h>
#include <zconf.h>

#define BYTE0 0x00000000
#define BYTE4 0x00000004
#define BYTE8 0x00000008
#define BYTE16 0x00000010
#define BYTE24 0x00000018
#define BYTE32 0x00000020
#define BYTE64 0x00000040
#define BYTE128 0x00000080
#define BYTE256 0x00000100
#define BYTE512 0x00000200
#define BYTE1024 0x00000400
#define BYTE2048 0x00000800

char *Shell(const char *cmd);

int find_pid_of(const char *process_name);

long GetModuleBase(const char *moduleName);

long int preadv(int pid, void *buffer, ssize_t size, off_t off);

long ReadDword64(long Address);

long ReadInt32(long Address);

float ReadFloat64(long Address);

int pid = -1;

/*查找进程pid*/
int initPid() {
    pid = find_pid_of("com.tencent.tmgp.sgame");
    return pid;
}

/**
 * 底层读写函数
 * @param pid
 * @param buffer
 * @param size
 * @param off
 * @return
 */
long int preadv(int pid, void *buffer, ssize_t size, off_t off) {
    struct iovec iov_ReadBuffer, iov_ReadOffset;
    iov_ReadBuffer.iov_base = buffer;
    iov_ReadBuffer.iov_len = size;
    iov_ReadOffset.iov_base = (void *) off;
    iov_ReadOffset.iov_len = size;
    return syscall(SYS_process_vm_readv, pid, &iov_ReadBuffer, 1, &iov_ReadOffset, 1, 0);
}

/*64位指针*/
long ReadDword64(long Address) {
    long temp = 0;
    preadv(pid, &temp, BYTE16, Address);
    return temp;
}

//32位指针
long ReadDword32(long Address) {
    long temp = 0;
    preadv(pid, &temp, BYTE4, Address);
    return temp;
}

/*读取dword类型的值*/
long ReadInt32(long Address) {
    int temp = 0;
    preadv(pid, &temp, BYTE4, Address);
    return temp;
}

/*读取float类型的值*/
float ReadFloat64(long Address) {
    float temp = 0;
    preadv(pid, &temp, BYTE4, Address);
    return temp;
}

/*执行shell命令*/
char *Shell(const char *cmd) {
    FILE *file = NULL;
    char line[BYTE256] = {};
    char *result = (char *) malloc(BYTE2048);
    memset(result, 0, sizeof(result));
    file = popen(cmd, "r");
    while (fgets(line, sizeof(line), file)) {
        strncat(result, line, strlen(line));
    }
    pclose(file);
    return result;
}

/**
 * 查找包名的进程id
 * @param process_name
 * @return
 */
int find_pid_of(const char *process_name) {
    int id;
    pid_t pid = -1;
    DIR *dir;
    FILE *fp;
    char filename[32];
    char cmdline[256];
    struct dirent *entry;
    if (process_name == NULL)
        return -1;
    dir = opendir("/proc");
    if (dir == NULL)
        return -1;
    while ((entry = readdir(dir)) != NULL) {
        id = atoi(entry->d_name);
        if (id != 0) {
            sprintf(filename, "/proc/self/cmdline", id);
            fp = fopen(filename, "r");
            if (fp) {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);
                if (strcmp(process_name, cmdline) == 0) {
                    pid = id;
                    break;
                }
            }
        }
    }
    closedir(dir);
    return pid;
}

/**
 * 读取模块地址
 * @param moduleName
 * @return
 */
long GetModuleBase(const char *moduleName) {
    char path[BYTE1024], line[BYTE1024];
    if (pid == -1)
        sprintf(path, "/proc/self/maps");
    else
        sprintf(path, "/proc/%d/maps", pid);
    FILE *file = fopen(path, "r");
    long len = 0;
    if (file) {
        while (fgets(line, sizeof(line), file)) {
            if (strstr(line, moduleName) != NULL) {
                len = strtoul(line, NULL, BYTE16);
                break;
            }
        }
    }
    return len;
}


#endif //GM_MEMORY_H
