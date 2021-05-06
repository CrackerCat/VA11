//
// Created by 2689480146 on 2019/8/1.
//

#ifndef SOCKET_MYSOCKETCLIENT_H
#define SOCKET_MYSOCKETCLIENT_H

#define ABSTRACT 0
#define FILESYSTEM 2

class MySocketClient{
private:
    int sockfd=-1;

    static void* recvThread(void* _sockfd);

public:
    MySocketClient();

    MySocketClient(int __af, int __type, int __protocol);

    bool connect(const char* path,int namespacz,bool needToCreateRecvThread);

    bool connect(int port,bool needToCreateRecvThread);

    int send(const char *content);

    int send(const char* content,size_t num);

    int recv(char *buff,size_t buffSize);

    ssize_t send_fd(int fd);

    int recv_fd();

    ~MySocketClient();
};

#endif //SOCKET_MYSOCKETCLIENT_H
