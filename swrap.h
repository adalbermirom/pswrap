
#ifndef SWRAP_H
#define SWRAP_H


#ifdef SWRAP_STATIC
    #define SWRAP_IMPLEMENTATION
    #define SWDEF static
#else 
    #define SWDEF extern
#endif


#define SWRAP_TCP 0
#define SWRAP_UDP 1
#define SWRAP_BIND 0
#define SWRAP_CONNECT 1
#define SWRAP_DEFAULT 0x00
#define SWRAP_NOBLOCK 0x01
#define SWRAP_NODELAY 0x02


struct swrap_addr {
    char data[128]; 
};


SWDEF int swrapInit();
    
SWDEF int swrapSocket(int, int, char, const char*, const char*);
    
    
    
    
    
    
    
    
    
    
    
    
    
    
SWDEF void swrapClose(int);
    
SWDEF void swrapTerminate();
    
SWDEF int swrapListen(int, int);
    
    
SWDEF int swrapAccept(int, struct swrap_addr*);
    
    
SWDEF int swrapAddress(int, struct swrap_addr*);
    
    
SWDEF int swrapAddressInfo(struct swrap_addr*, char*, int, char*, int);
    
    
SWDEF int swrapSend(int, const char*, int);
    
    
SWDEF int swrapReceive(int, char*, int);
    
    
SWDEF int swrapSendTo(int, struct swrap_addr*, const char*, int);
    
    
SWDEF int swrapReceiveFrom(int, struct swrap_addr*, char*, int);
    
    
SWDEF int swrapSelect(int, double);
    
    
    
SWDEF int swrapMultiSelect(int*, int, double);
    
    
    

#endif 


#ifdef SWRAP_IMPLEMENTATION
#undef SWRAP_IMPLEMENTATION


#ifdef _WIN32 
    #include <ws2tcpip.h>
#else 
    #include <sys/socket.h>
    #include <netdb.h>
    #include <fcntl.h>
    #include <unistd.h>
    #ifndef TCP_NODELAY
        #include <netinet/in.h>
        #include <netinet/tcp.h>
    #endif
#endif
#include <stddef.h> 




#include <stdio.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <errno.h>
#include <string.h>
#endif



void swrapGetLastSocketError(char* buf, size_t buf_size) {
#ifdef _WIN32
    int err = WSAGetLastError();
    FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        buf, (DWORD)buf_size, NULL);
#else
    strerror_r(errno, buf, buf_size);
#endif
}





SWDEF int swrapInit () {
    #ifdef _WIN32
        WSADATA WsaData;
        return (WSAStartup(MAKEWORD(2,2), &WsaData) != NO_ERROR);
    #else
        return 0;
    #endif
}

SWDEF int swrapSocket (int prot, int mode, char flags, const char* host, const char* serv) {
    
    struct addrinfo* result, hint = {
        (mode == SWRAP_BIND) ? AI_PASSIVE : 0, 
        AF_UNSPEC, 
        (prot == SWRAP_TCP) ? SOCK_STREAM : SOCK_DGRAM, 
        0, 0, NULL, NULL, NULL};
    
    if (getaddrinfo(host, serv, &hint, &result)) return -1;
    
    #ifdef _WIN32
        SOCKET wsck = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (wsck == INVALID_SOCKET) return -1;
        
        if (wsck > INT_MAX) {
            closesocket(wsck);
            return -1;
        }
        
        int sock = wsck;
    #else
        int sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (sock == -1) return -1;
    #endif
    
    if (result->ai_family == AF_INET6) {
        int no = 0;
        #ifdef _WIN32
            setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&no, sizeof(no));
        #else
            setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&no, sizeof(no));
        #endif
    }
    
    if (prot == SWRAP_TCP) {
        int nodelay = (flags&SWRAP_NODELAY);
        #ifdef _WIN32
            setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));
        #else
            setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void*)&nodelay, sizeof(nodelay));
        #endif
    }
    
    if ((mode == SWRAP_BIND)&&(bind(sock, result->ai_addr, result->ai_addrlen))) {
        swrapClose(sock);
        return -1;
    }
    
    if (flags&SWRAP_NOBLOCK) {
        #ifdef _WIN32
            DWORD no_block = 1;
            if (ioctlsocket(sock, FIONBIO, &no_block)) {
                swrapClose(sock);
                return -1;
            }
        #else
            if (fcntl(sock, F_SETFL, O_NONBLOCK, 1) == -1) {
                swrapClose(sock);
                return -1;
            }
        #endif
    }
    
    if ((mode == SWRAP_CONNECT)&&(connect(sock, result->ai_addr, result->ai_addrlen))&&(!(flags&SWRAP_NOBLOCK))) {
        swrapClose(sock);
        return -1;
    }
    
    freeaddrinfo(result);
    
    return sock;
}
SWDEF void swrapClose (int sock) {
    #ifdef _WIN32
        closesocket(sock);
    #else
        close(sock);
    #endif
}
SWDEF void swrapTerminate () {
    #ifdef _WIN32
        WSACleanup();
    #endif
}


SWDEF int swrapListen (int sock, int blog) {
    return listen(sock, blog);
}
SWDEF int swrapAccept (int sock, struct swrap_addr* addr) {
    #ifdef _WIN32
        int addr_size = sizeof(struct swrap_addr);
        SOCKET wsck = accept(sock, (struct sockaddr*)addr, (addr) ? &addr_size : NULL);
        if (wsck == INVALID_SOCKET) return -1;
        
        if (wsck > INT_MAX) {
            closesocket(wsck);
            return -1;
        }
        
        return wsck;
    #else
        socklen_t addr_size = sizeof(struct swrap_addr);
        return accept(sock, (struct sockaddr*)addr, (addr) ? &addr_size : NULL);
    #endif
}


SWDEF int swrapAddress (int sock, struct swrap_addr* addr) {
    #ifdef _WIN32
        int addr_size = sizeof(struct swrap_addr);
    #else
        socklen_t addr_size = sizeof(struct swrap_addr);
    #endif
    return getsockname(sock, (struct sockaddr*)addr, &addr_size);
}
SWDEF int swrapAddressInfo (struct swrap_addr* addr, char* host, int host_size, char* serv, int serv_size) {
    return getnameinfo((struct sockaddr*)addr, sizeof(struct swrap_addr), host, host_size, serv, serv_size, 0);
}


SWDEF int swrapSend (int sock, const char* data, int data_size) {
    return send(sock, data, data_size, 0);
}
SWDEF int swrapReceive (int sock, char* data, int data_size) {
    return recv(sock, data, data_size, 0);
}
SWDEF int swrapSendTo (int sock, struct swrap_addr* addr, const char* data, int data_size) {
    return sendto(sock, data, data_size, 0, (struct sockaddr*)addr, sizeof(struct swrap_addr));
}
SWDEF int swrapReceiveFrom (int sock, struct swrap_addr* addr, char* data, int data_size) {
    #ifdef _WIN32
        int addr_size = sizeof(struct swrap_addr);
    #else
        socklen_t addr_size = sizeof(struct swrap_addr);
    #endif
    return recvfrom(sock, data, data_size, 0, (struct sockaddr*)addr, &addr_size);
}


SWDEF int swrapSelect (int sock, double timeout) {
    fd_set set; struct timeval time;
    
    FD_ZERO(&set);
    if (sock > -1) FD_SET(sock, &set);
    
    time.tv_sec = timeout;
    time.tv_usec = (timeout - time.tv_sec)*1000000.0;
    
    return select(sock+1, &set, NULL, NULL, &time);
}

/*
SWDEF int swrapMultiSelect (int* socks, int socks_size, double timeout) {
    fd_set set; struct timeval time; int sock_max = -1;
    
    FD_ZERO(&set);
    for (int i = 0; i < socks_size; i++) {
        if (socks[i] > sock_max) sock_max = socks[i];
        if (socks[i] > -1) FD_SET(socks[i], &set);
    }
    
    time.tv_sec = timeout;
    time.tv_usec = (timeout - time.tv_sec)*1000000.0;
    
    return select(sock_max+1, &set, NULL, NULL, &time);
}
*/

/** BETO MODIFICATION */

SWDEF int swrapMultiSelect (int* socks, int socks_size, double timeout) {
    fd_set set; 
    struct timeval time; 
    int sock_max = -1;
    
    FD_ZERO(&set);
    for (int i = 0; i < socks_size; i++) {
        if (socks[i] > sock_max) sock_max = socks[i];
        if (socks[i] > -1) FD_SET(socks[i], &set);
    }
    
    time.tv_sec = (int)timeout;
    time.tv_usec = (timeout - time.tv_sec) * 1000000.0;
    
    // 1. Chama select() como antes
    int ret = select(sock_max+1, &set, NULL, NULL, &time);

    // 2. Se for erro ou timeout, retorna o código (como antes)
    if (ret <= 0) {
        return ret; // Retorna -1 (erro) ou 0 (timeout)
    }

    // 3. SUCESSO! (ret > 0). Agora, descubra QUAL socket está pronto.
    for (int i = 0; i < socks_size; i++) {
        // FD_ISSET() verifica se o socket 'socks[i]' está pronto
        if (socks[i] > -1 && FD_ISSET(socks[i], &set)) {
            // Encontramos! Retorna o *handle* do socket.
            return socks[i]; 
        }
    }
    
    // Isso não deve acontecer se select() > 0, mas é um fallback
    return -1; 
}

#endif
