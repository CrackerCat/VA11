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

#include <Socket/ctpl_stl.h>
#include <Socket/server/MySocketServer.h>
#include <arpa/inet.h>
#include <Foundation/Log.h>
#include "MySocketServer.h"

#define ABS_SOCKET_LEN(sun) (sizeof(sa_family_t) + strlen(sun.sun_path + 1) + 1)
#define FILE_SOCKET_LEN(sun) (sizeof(sa_family_t) + strlen(sun.sun_path) + 1)

MySocketServer::MySocketServer(){
    sockfd=socket(AF_UNIX, SOCK_STREAM, 0);
    if(sockfd <= 0){
        ALOGD("socket init error >>>> %s",strerror(errno));
    }
    pthread_mutexattr_init(&mutexAttr);
    pthread_mutexattr_setpshared(&mutexAttr, PTHREAD_PROCESS_PRIVATE);
    pthread_mutexattr_settype(&mutexAttr, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&mutex,&mutexAttr);
}

MySocketServer::MySocketServer(int __af, int __type, int __protocol){
    sockfd=socket(__af, __type, __protocol);
    if(sockfd <= 0){
        ALOGD("socket init error >>>> %s",strerror(errno));
    }
    pthread_mutexattr_init(&mutexAttr);
    pthread_mutexattr_setpshared(&mutexAttr, PTHREAD_PROCESS_PRIVATE);
    pthread_mutexattr_settype(&mutexAttr, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&mutex,&mutexAttr);
}

MySocketServer& MySocketServer::reuseAddr() {
    int on=1;
    if(setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(int))<0){
        ALOGD("setsockopt error >>>> %s",strerror(errno));
    }
    return *this;
}

MySocketServer& MySocketServer::ignoreChild(){
    signal(SIGCHLD, SIG_IGN);
    return *this;
}

MySocketServer& MySocketServer::setClientThread(void (*ptr)(int, int)){
    clientThreadPtr=ptr;
    return *this;
}


bool MySocketServer::bind(const char *path,int namespacz){
    if(hasBind)
        return false;
    unlink(path);
    struct sockaddr_un server_addr{};
    memset(&server_addr,0, sizeof(sockaddr_un));
    server_addr.sun_family = AF_UNIX;//指定网络套接字

    int ret=-1;
    if(namespacz==ABSTRACT){
        server_addr.sun_path[0]=0;
        strcpy(server_addr.sun_path+1,path);
        ret=::bind(sockfd, (struct sockaddr*)&server_addr, ABS_SOCKET_LEN(server_addr)); //绑定（命名）套接字
    }else if(namespacz==FILESYSTEM){
        strcpy(server_addr.sun_path,path);
        ret=::bind(sockfd, (struct sockaddr*)&server_addr, FILE_SOCKET_LEN(server_addr)); //绑定（命名）套接字
    }
    if(ret<0){
        ALOGD("bind error >>>> %s",strerror(errno));
        return false;
    }else
        hasBind=true;
    return true;
}

bool MySocketServer::bind(unsigned int port){
    if(hasBind)
        return false;
    struct sockaddr_in server_addr{};
    memset(&server_addr,0, sizeof(sockaddr_in));
    server_addr.sin_family = AF_INET;//指定网络套接字
    server_addr.sin_addr.s_addr = inet_addr("127.122.255.71");//接受所有IP地址的连接
    server_addr.sin_port = htons(port);//绑定到指定端口
    int ret=::bind(sockfd, (struct sockaddr*)&server_addr, sizeof(sockaddr_in)); //绑定（命名）套接字
    if(ret<0){
        ALOGD("bind error >>>> %s",strerror(errno));
        return false;
    }else
        hasBind=true;
    return true;
}

MySocketServer& MySocketServer::listen(int num){
    if(!hasBind)
        return *this;
    thread_pool=new ctpl::thread_pool(num);
    int ret=::listen(sockfd, num); //创建套接字队列，监听套接字
    if(ret<0){
        ALOGD("listen error >>>> %s",strerror(errno));
        exit(-1);
    }
    return *this;
}

MySocketServer& MySocketServer::listenWithoutThreadPool(int num){
    int ret=::listen(sockfd, num); //创建套接字队列，监听套接字
    if(ret!=0){
        exit(-1);
    }
    return *this;
}

MySocketServer& MySocketServer::accept(){
    if(!hasBind)
        return *this;
    struct sockaddr __addr;
    socklen_t __addr_length= sizeof(__addr);
    int client_sockfd = ::accept(sockfd, &__addr, &__addr_length);
    if(client_sockfd<=0){
        ALOGE("accept error >>>> %s",strerror(errno));
        return *this;
    }
    MySocketServer::client_ids.push_back(client_sockfd);
    if(clientThreadPtr!= nullptr)
        thread_pool->push(clientThreadPtr, client_sockfd);
    return *this;
}

int MySocketServer::acceptWithoutCreateClientThread(){
    if(!hasBind)
        return -1;
    struct sockaddr __addr;
    socklen_t __addr_length= sizeof(__addr);
    int client_sockfd = ::accept(sockfd, &__addr, &__addr_length);
    if(client_sockfd<=0){
        return -1;
    }
    return client_sockfd;
}

MySocketServer& MySocketServer::send(int clientSocketFd,const char* centent){
    ::send(clientSocketFd,centent,strlen(centent),0);
    return *this;
}

ssize_t MySocketServer::recv(int clientSocketFd,char* buff,size_t buffSize){
    bzero(buff,buffSize);
    return ::recv(clientSocketFd, (void *) buff, buffSize, 0);
}

MySocketServer& MySocketServer::close(int socketId){
    pthread_mutex_lock(&mutex);
    auto it=std::find(client_ids.begin(),client_ids.end(),socketId);
    if(it!=client_ids.end())
        client_ids.erase(it);
    pthread_mutex_unlock(&mutex);
    return *this;
}

MySocketServer::~MySocketServer(){
    close(sockfd);
    if(thread_pool!= nullptr)
        delete(thread_pool);
    unsigned long clientNum=client_ids.size();
    for(int i=0;i<clientNum;i++)
        ::close(client_ids[i]);
}

ssize_t MySocketServer::send_fd(int fd,int sendfd){
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

    *((int *) CMSG_DATA(cmptr)) = sendfd;

    return sendmsg(fd, &msg, 0);
}

int MySocketServer::recv_fd(int fd){
    struct msghdr   msg;
    struct iovec    iov[1];
    ssize_t         n;
    int             newfd;
    int dummy;

    union {
      struct cmsghdr    cm;
      char              control[CMSG_SPACE(sizeof(int))];
    } control_un;
    struct cmsghdr  *cmptr;

    msg.msg_control = control_un.control;
    msg.msg_controllen = sizeof(control_un.control);

    msg.msg_name = NULL;
    msg.msg_namelen = 0;

    iov[0].iov_base = &dummy;
    iov[0].iov_len = 1;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    if ( (n = recvmsg(fd, &msg, 0)) <= 0)
        return n;

    if ( (cmptr = CMSG_FIRSTHDR(&msg)) != NULL &&
        cmptr->cmsg_len == CMSG_LEN(sizeof(int))) {
        if (cmptr->cmsg_level != SOL_SOCKET) {
            ALOGE("control level != SOL_SOCKET");
            return -1;
        }else if (cmptr->cmsg_type != SCM_RIGHTS) {
            ALOGE("control type != SCM_RIGHTS");
            return -1;
        }
        return  *((int *) CMSG_DATA(cmptr));
    } else
        return -1;
}