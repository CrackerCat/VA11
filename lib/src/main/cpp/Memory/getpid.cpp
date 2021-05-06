//
// Created by z742978469 on 20-1-26.
//

#include <linux/fcntl.h>
#include <cstring>
#include <cstdio>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <zconf.h>
#include <fcntl.h>
#include <cstdlib>
#include <vector>

//#include <Log.h>
#include "getpid.h"


// Return how long the file at fd is, if there's any way to determine it.
static inline __always_inline off_t fdlength(int fd){
    struct stat st{};
    off_t base = 0;
    off_t range = 1;
    off_t expand = 1;
    off_t old;

    if (!fstat(fd, &st) && S_ISREG(st.st_mode))
        return st.st_size;

    // If the ioctl works for this, return it.
    // TODO: is blocksize still always 512, or do we stat for it?
    // unsigned int size;
    // if (ioctl(fd, BLKGETSIZE, &size) >= 0) return size*512L;

    // If not, do a binary search for the last location we can read.  (Some
    // block devices don't do BLKGETSIZE right.)  This should probably have
    // a CONFIG option...

    // If not, do a binary search for the last location we can read.

    old = lseek(fd, 0, SEEK_CUR);
    do {
        char temp;
        off_t pos = base + range / 2;

        if (lseek(fd, pos, 0)>=0 && read(fd, &temp, 1)==1) {
            off_t delta = (pos + 1) - base;

            base += delta;
            if (expand) range = (expand <<= 1) - base;
            else range -= delta;
        } else {
            expand = 0;
            range = pos - base;
        }
    } while (range > 0);

    lseek(fd, old, SEEK_SET);

    return base;
}

// Keep reading until full or EOF
static inline __always_inline ssize_t readall(int fd, void *buf, size_t len){
    size_t count = 0;

    while (count<len) {
        int i = read(fd, (char *)buf+count, len-count);
        if (!i) break;
        if (i<0) return i;
        count += i;
    }

    return count;
}

static inline __always_inline char *readfileat(int dirfd, char *name, char *ibuf, off_t *plen) {
    off_t len, rlen;
    int fd;
    char *buf, *rbuf;

    // Unsafe to probe for size with a supplied buffer, don't ever do that.
    if ((ibuf ? !*plen : *plen)) {
       // LOGE("readfileat >>> bad readfileat");
        return nullptr;
    }

    if (-1 == (fd = openat(dirfd, name, O_RDONLY)))
        return nullptr;

    // If we dunno the length, probe it. If we can't probe, start with 1 page.
    if (!*plen) {
        if ((len = fdlength(fd)) > 0)
            *plen = len;
        else
            len = 4096;
    } else
        len = *plen - 1;

    if (!ibuf)
        buf = (char *) malloc(len + 1);
    else
        buf = ibuf;

    for (rbuf = buf;;) {
        rlen = readall(fd, rbuf, len);
        if (*plen || rlen < len)
            break;

        // If reading unknown size, expand buffer by 1.5 each time we fill it up.
        rlen += rbuf - buf;
        buf = (char *) realloc(buf, len = (rlen * 3) / 2);
        rbuf = buf + rlen;
        len -= rlen;
    }
    *plen = len = rlen + (rbuf - buf);
    close(fd);

    if (rlen < 0) {
        if (ibuf != buf) free(buf);
        buf = 0;
    } else
        buf[len] = 0;

    return buf;
}

// This just gives after the last '/' or the whole stirng if no /
static inline __always_inline char *getbasename(char *name){
    char *s = strrchr(name, '/');

    if (s)
        return s+1;

    return name;
}

/**
 *
 * @param level : 0>>contain  1>>equal
 */
static inline __always_inline bool matchProcess(char *processName,char *aimName,int level){
    switch (level){
        case GET_PID_LEVEL_CONTAIN:
            return strstr(processName,aimName)!= nullptr;
        case GET_PID_LEVEL_EQUAL:
            return strcmp(processName,aimName)==0;
        default:
            return false;
    }
}

/**
 *
 * @param name : process name
 * @param pids : output
 * @param level : 0>>contain  1>>equal
 * @return
 */
bool getpid(char *name,std::vector<int>& pids,int level){
    DIR *dp;
    char buf[PATH_MAX];
    struct dirent *entry;

    if (!(dp = opendir("/proc"))) {
        //LOGE("getPid >>>> no /proc");
        return false;
    }

    pids.clear();

    char *cmd;
    char *comm;
    off_t len;
    while ((entry = readdir(dp))) {
        unsigned u = atoi(entry->d_name);

        if (!u)
            continue;

        // Comm is original name of executable (argv[0] could be #! interpreter)
        // but it's limited to 15 characters
        sprintf(buf, "/proc/%u/comm", u);
        len = sizeof(buf);
        if (!(comm = readfileat(AT_FDCWD, buf, buf, &len)) || !len)
            continue;
        if (buf[len-1] == '\n') buf[--len] = 0;

        struct stat st1{};
        struct stat st2{};
        char *bb = getbasename(name);
        len = static_cast<off_t>(strlen(bb));

        // Fast path: only matching a filename (no path) that fits in comm.
        // `len` must be 14 or less because with a full 15 bytes we don't
        // know whether the name fit or was truncated.
        if (len<=14 && bb==name && matchProcess(comm, bb,level))
            goto match;

        // If we have a path to existing file only match if same inode
        if (bb!=name && !stat(name, &st1)) {
            sprintf(buf, "/proc/%u/exe", u);
            if (stat(buf, &st1))
                continue;
            if (st1.st_dev != st2.st_dev || st1.st_ino != st2.st_ino)
                continue;
            goto match;
        }

        // gotta read command line to confirm
        sprintf(cmd = buf+16, "/proc/%u/cmdline", u);
        len = sizeof(buf)-17;
        if (!(cmd = readfileat(AT_FDCWD, cmd, cmd, &len)))
            continue;
        // readfile only guarantees one null terminator and we need two
        // (yes the kernel should do this for us, don't care)
        cmd[len] = 0;

        if (matchProcess(getbasename(cmd),bb, level))
            goto match;
        if (bb!=name && matchProcess(getbasename(cmd+strlen(cmd)+1), bb, level))
            goto match;
        continue;
        match:
        pids.push_back(u);
    }
    closedir(dp);
    return !pids.empty();
}
