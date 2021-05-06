//
// Created by 2689480146 on 2019/8/1.
//
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <sys/stat.h>
#include <vector>
#include <arpa/inet.h>

#include <Socket/client/MySocketClient.h>
#include <SLog.h>
#include <pthread.h>
#include <cerrno>


#define ABS_SOCKET_LEN(sun) (sizeof(sa_family_t) + strlen(sun.sun_path + 1) + 1)
#define FILE_SOCKET_LEN(sun) (sizeof(sa_family_t) + strlen(sun.sun_path) + 1)

void* MySocketClient::recvThread(void* _sockfd) {
    long sockfd=(long)_sockfd;
    char content[PAGE_SIZE];
    LOGE("server connect !\n");
    while(::recv(sockfd, &content, PAGE_SIZE,0)>0) {
        LOGD("recv from server >>>>\t%s\n", content);
    }
    LOGE("server disconnect !\n");
    return nullptr;
}

MySocketClient::MySocketClient(){
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(sockfd < 0){
        LOGE("socket err >>>> %s\n",strerror(errno));
        exit(-1);
    }
}

MySocketClient::MySocketClient(int __af, int __type, int __protocol){
    sockfd = socket(__af, __type, __protocol);
    if(sockfd < 0){
        LOGE("socket err >>>> %s\n",strerror(errno));
        exit(-1);
    }
}

bool MySocketClient::connect(const char* path,int namespacz,bool needToCreateRecvThread){
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if(namespacz==ABSTRACT) {
        addr.sun_path[0]=0;
        strcpy(addr.sun_path+1, path);
        if (::connect(sockfd, (struct sockaddr *) &addr, ABS_SOCKET_LEN(addr)) < 0) {
            LOGE("connect err >>>> %s\n", strerror(errno));
            return false;
        }
    }else if(namespacz==FILESYSTEM){
        strcpy(addr.sun_path, path);
        if (::connect(sockfd, (struct sockaddr *) &addr, FILE_SOCKET_LEN(addr)) < 0) {
            LOGE("connect err >>>> %s\n", strerror(errno));
            return false;
        }
    }
    if(needToCreateRecvThread) {
        pthread_t pthread;
        pthread_create(&pthread, nullptr, recvThread, (void *) (sockfd));
    }
    return true;
}

bool MySocketClient::connect(int port,bool needToCreateRecvThread){
    struct sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;//使用网络套接字
    server_addr.sin_addr.s_addr = inet_addr("127.122.255.71");//localhost
    server_addr.sin_port = htons(port); //服务器监听端口
    if(::connect(sockfd, (struct sockaddr *)&server_addr, sizeof(sockaddr_in)) < 0){
        LOGE("connect err >>>> %s\n",strerror(errno));
        return false;
    }
    if(needToCreateRecvThread) {
        pthread_t pthread;
        pthread_create(&pthread, nullptr,recvThread, (void *)(sockfd));
    }
    return true;
}

int MySocketClient::send(const char* content){
    return ::send(sockfd,content,strlen(content),0);
}

int MySocketClient::send(const char* content,size_t num){
    return ::send(sockfd,content,num,0);
}

int MySocketClient::recv(char *buff,size_t buffSize){
    return ::recv(sockfd,buff,buffSize,0);
}

ssize_t MySocketClient::send_fd(int fd){
    struct msghdr   msg;
    struct cmsghdr  *cmptr;
    struct iovec    iov[1];
    int dummy;

    union {
        struct cmsghdr    cm;
        char              control[CMSG_SPACE(sizeof(int))];
    } control_un;


    iov[0].iov_base = &dummy;
    iov[0].iov_len = 1;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control_un.control;
    msg.msg_controllen = sizeof(control_un.control);
    msg.msg_name = NULL;
    msg.msg_namelen = 0;

    cmptr = CMSG_FIRSTHDR(&msg);
    cmptr->cmsg_len = CMSG_LEN(sizeof(int));
    cmptr->cmsg_level = SOL_SOCKET;
    cmptr->cmsg_type = SCM_RIGHTS;

    *((int *) CMSG_DATA(cmptr)) = fd;

    return sendmsg(sockfd, &msg, 0);
}

int MySocketClient::recv_fd(){
    struct msghdr   msg;
    struct cmsghdr  *cmptr;
    struct iovec    iov[1];
    ssize_t         n;
    int dummy;

    union {
        struct cmsghdr    cm;
        char              control[CMSG_SPACE(sizeof(int))];
    } control_un;

    iov[0].iov_base = &dummy;
    iov[0].iov_len = 1;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control_un.control;
    msg.msg_controllen = sizeof(control_un.control);
    msg.msg_name = NULL;
    msg.msg_namelen = 0;

    if ( (n = recvmsg(sockfd, &msg, 0)) <= 0)
        return n;

    if ( (cmptr = CMSG_FIRSTHDR(&msg)) != NULL &&
         cmptr->cmsg_len == CMSG_LEN(sizeof(int))) {
        if (cmptr->cmsg_level != SOL_SOCKET) {
            LOGE("control level != SOL_SOCKET");
            return -1;
        }else if (cmptr->cmsg_type != SCM_RIGHTS) {
            LOGE("control type != SCM_RIGHTS");
            return -1;
        }
        return  *((int *) CMSG_DATA(cmptr));
    } else
        return -1;
}

MySocketClient::~MySocketClient(){
    close(sockfd);
}
