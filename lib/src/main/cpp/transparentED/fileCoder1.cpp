//
// Created by zhangsong on 17-11-27.
//

#include "fileCoder1.h"
#include <utils/zJNIEnv.h>
//extern jclass vskmClass;
extern jclass vsckmsClass;
int ckmsInfo::getSize() {
    return sizeof(uint32_t);
}

int ckmsInfo::read(int fd) {
    if(originalInterface::original_read(fd, (char *)&group_id, sizeof(uint32_t)) != sizeof(uint32_t))
        return -1;

    return 0;
}

int ckmsInfo::write(int fd) {
    if(originalInterface::original_write(fd, (char *)&group_id, sizeof(uint32_t)) != sizeof(uint32_t))
        return -1;

    return 0;
}

int operatorKey(char *input, int inputlen, char *output, int outputlen, int mode) {

    log("SafeKeyJni operatorKey start mode %d keylen %d", mode, inputlen);
    int ret = 0;
    zJNIEnv env;
    if(env.get() == NULL) {
        log("JNIEnv is NULL");
        return -1;
    }

    jbyteArray _input = env.get()->NewByteArray(inputlen);
    env.get()->SetByteArrayRegion(_input, 0, inputlen, (jbyte*)input);
    jbyteArray _output;
    jmethodID mid = NULL;
    jclass vskmClass;
    if(mode == 0){
        mid = env.get()->GetStaticMethodID(vskmClass, "encryptKey", "([BI)[B");
    }else{
        mid = env.get()->GetStaticMethodID(vskmClass, "decryptKey", "([BI)[B");
    }
    _output = (jbyteArray)env.get()->CallStaticObjectMethod(vskmClass, mid ,_input, inputlen);
    jbyte* a = env.get()->GetByteArrayElements(_output, JNI_FALSE);
    memcpy(output, a, (size_t)inputlen);

    for(int i=0; i<inputlen; i++){
        if(output[i] != 0){
            ret = 0;
            break;
        }
        ret = -1;
    }
    log("SafeKeyJni operatorKey ret = %d", ret);

    env.get()->ReleaseByteArrayElements(_output, a, 0);
    env.get()->DeleteLocalRef(_input);
    env.get()->DeleteLocalRef(_output);

    /*zString tmp;
    char * p = tmp.getBuf();
    for(int i = 0; i < inputlen; i++)
    {
        sprintf(p + i*2, "%02hhx", output[i]);
    }
    log("SafeKeyJni operatorKey end return %d [%s]", ret, p);*/
    return ret;
}
int encryptKey(char *input, int inputlen, char *output, int outputlen){
    return operatorKey(input, inputlen, output, outputlen, 0);
    /* for(int i = 0; i < inputlen; i++)
         output[i] = input[i] + (char)3;

     return 0;*/
}

bool ckmsInfo::encrypt(char *input, uint32_t inputlen, char *output, uint32_t &outputlen) {
//    for(int i = 0; i < inputlen; i++)
//        output[i] = input[i] + (char)3;
    int ret = encryptKey(input, inputlen, output, outputlen);
    outputlen = inputlen;
    return ret>=0;
}

int decryptKey(char *input, int inputlen, char *output, int outputlen){
    return operatorKey(input, inputlen, output, outputlen, 1);
    /* for(int i = 0; i < inputlen; i++)
         output[i] = input[i] - (char)3;

     return 0;*/
}


bool ckmsInfo::decrypt(char *input, uint32_t inputlen, char *output, uint32_t &outputlen) {
//    for(int i = 0; i < inputlen; i++)
//        output[i] = input[i] - (char)3;
    int ret = decryptKey(input, inputlen, output, outputlen);
    outputlen = inputlen;
    return ret>=0;
}
/********************************************************************************/

EncryptInfo_v1::EncryptInfo_v1() {
    key = 0;
    keyLen = 0;

    key2 = 0;
    keyLen2 = 0;
}

EncryptInfo_v1::EncryptInfo_v1(EncryptInfo_v1 &ei) {
    keyLen = ei.keyLen;
    keyLen2 = ei.keyLen2;

    key = (char *)malloc(keyLen);
    key2 = (char *)malloc(keyLen2);

    memcpy(key, ei.key, keyLen);
    memcpy(key2, ei.key2, keyLen2);
}

EncryptInfo_v1::~EncryptInfo_v1() {
    if(key)
        delete []key;

    if(key2)
        delete []key2;
}

int EncryptInfo_v1::read(int fd) {
    if(originalInterface::original_read(fd, (char *)&keyLen2, sizeof(uint32_t)) != sizeof(uint32_t))
        return -1;

    if(keyLen2 < 0 || keyLen2 > 1024)
        return -1;

    key2 = (char *)malloc(keyLen2);

    if(originalInterface::original_read(fd, key2, keyLen2) != keyLen2)
        return -1;

    if(ci.read(fd))
        return -1;

    keyLen = keyLen2;
    key = (char *)malloc(keyLen);
    if(!ci.decrypt(key2, keyLen2, key, keyLen))
        return -1;

    return 0;
}

int EncryptInfo_v1::write(int fd) {
    size_t tmpkl = 16;
    char * tmpk = keyGenerator::generate(tmpkl);


    keyLen = tmpkl;
    key = (char *)malloc(keyLen);
    memcpy(key, tmpk, keyLen);

    free(tmpk);

    keyLen2 = keyLen;
    key2 = (char *)malloc(keyLen2);

    if(!ci.encrypt(key, keyLen, key2, keyLen2))
        return -1;

    if(originalInterface::original_write(fd, (char *)&keyLen2, sizeof(uint32_t)) != sizeof(uint32_t))
        return -1;

    if(originalInterface::original_write(fd, key2, keyLen2) != keyLen2)
        return -1;

    return ci.write(fd);
}

int EncryptInfo_v1::getSize() {
    return ci.getSize() + sizeof(uint32_t) + keyLen2;
}

char* EncryptInfo_v1::getKey() {
    return key;
}

int EncryptInfo_v1::getKeyLen() {
    return keyLen;
}

int ckmsInfo_v2::getSize() {
    return sizeof(uint32_t);
}

int ckmsInfo_v2::read(int fd) {
    if(originalInterface::original_read(fd, (char *)&group_id, sizeof(uint32_t)) != sizeof(uint32_t)) {
        return -1;
    }

    return 0;
}

int ckmsInfo_v2::write(int fd) {
    if(originalInterface::original_write(fd, (char *)&group_id, sizeof(uint32_t)) != sizeof(uint32_t)){
        return -1;
    }

    return 0;
}

char * ckmsInfo_v2::ckmsEncryptKey(char *input, uint32_t inputlen, uint32_t &outputlen) {
    return ckmsEncryptKey(input, inputlen, outputlen);

}


char * ckmsInfo_v2::ckmsDecryptKey(char *input, uint32_t inputlen, uint32_t &outputlen) {
    return ckmsDecryptKey(input,inputlen,outputlen);

}

EncryptInfo_v2::EncryptInfo_v2() {
    key = 0;
    keyLen = 0;

    key2 = 0;
    keyLen2 = 0;
}

EncryptInfo_v2::EncryptInfo_v2(EncryptInfo_v2 &ei) {
    keyLen = ei.keyLen;
    keyLen2 = ei.keyLen2;

    key = (char *)malloc(keyLen);
    key2 = (char *)malloc(keyLen2);

    memcpy(key,ei.key,keyLen);
    memcpy(key2,ei.key2,keyLen2);
}

EncryptInfo_v2::~EncryptInfo_v2() {
    if (key) {
        delete []key;
    }

    if(key2) {
        delete []key2;
    }
}

int EncryptInfo_v2::read(int fd) {
    if(originalInterface::original_read(fd, (char *)&keyLen2, sizeof(uint32_t)) != sizeof(uint32_t))
        return -1;

    if(keyLen2 < 0 || keyLen2 > 1024)
        return -1;

    key2 = (char *)malloc(keyLen2);

    if(originalInterface::original_read(fd, key2, keyLen2) != keyLen2) {
        return -1;
    }

    if(ci.read(fd)) {
        return -1;
    }

    key = ci.ckmsDecryptKey(key2,keyLen2,keyLen);
    if(key == NULL) {
        return -1;
    }

    return 0;
}

int EncryptInfo_v2::write(int fd) {
    size_t tmpkl = 16;
    char * tmpk = keyGenerator::generate(tmpkl);

    keyLen = tmpkl;
    key = (char *)malloc(keyLen);
    memcpy(key, tmpk, keyLen);

    free(tmpk);

    key2 = ci.ckmsEncryptKey(key,keyLen,keyLen2);
    if(key2 == NULL) {
        return -1;
    }

    if(originalInterface::original_write(fd, (char *)&keyLen2, sizeof(uint32_t)) != sizeof(uint32_t)) {
        return -1;
    }

    if(originalInterface::original_write(fd, key2, keyLen2) != keyLen2) {
        return -1;
    }

    return ci.write(fd);
}

int EncryptInfo_v2::getSize() {
    return ci.getSize() + sizeof(uint32_t) + keyLen2;
}

char * EncryptInfo_v2::getKey() {
    return key;
}

int EncryptInfo_v2::getKeyLen() {
    return keyLen;
}