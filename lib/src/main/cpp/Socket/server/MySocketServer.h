//
// Created by 2689480146 on 2019/8/1.
//

#ifndef SOCKET_MYSOCKETSERVER_H
#define SOCKET_MYSOCKETSERVER_H

#include <Socket/ctpl_stl.h>

#define ABSTRACT 0
#define FILESYSTEM 2

class MySocketServer{
private:
    pthread_mutexattr_t mutexAttr;
    pthread_mutex_t mutex;

    int sockfd=-1;
    bool hasBind=false;
    ctpl::thread_pool *thread_pool= nullptr;

    void (*clientThreadPtr)(int id, int client_sockfd);

    std::vector<int> client_ids;

public:
    MySocketServer();

    MySocketServer(int __af, int __type, int __protocol);

    MySocketServer& reuseAddr();

    MySocketServer& ignoreChild();

    bool bind(const char *path,int namespacz);

    bool bind(unsigned int port);

    MySocketServer& listen(int num);

    MySocketServer& accept();

    MySocketServer& listenWithoutThreadPool(int num);

    MySocketServer& setClientThread(void (*ptr)(int, int));

    MySocketServer& close(int socketId);

    int acceptWithoutCreateClientThread();

    MySocketServer& send(int clientSocketFd,const char* centent);

    ssize_t recv(int clientSocketFd,char* buff,size_t buffSize);

    static ssize_t send_fd(int fd,int sendfd);

    static int recv_fd(int fd);

    ~MySocketServer();
};

#endif //SOCKET_MYSOCKETSERVER_H
