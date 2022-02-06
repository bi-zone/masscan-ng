#ifndef PIXIE_SOCKETS_H
#define PIXIE_SOCKETS_H
#include <stddef.h>
#if defined(WIN32)
#include <WinSock2.h>
#else
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
typedef int SOCKET;
#endif

#endif
