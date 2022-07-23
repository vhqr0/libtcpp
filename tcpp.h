#ifndef TCPP_H
#define TCPP_H

#include <pthread.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <exception>
#include <iostream>
#include <string>
#include <utility>

///////////////////////////////////////////////////////////////////////////////
//                                  Address                                  //
///////////////////////////////////////////////////////////////////////////////

#define AF_DOMAIN 0
#define DOMAIN_MAX 253
struct sockaddr_domain {
  unsigned short sd_family;
  unsigned short sd_port;
  char sd_addr[DOMAIN_MAX + 1];
};

typedef union {
  struct sockaddr sa;
  struct sockaddr_in sin4;
  struct sockaddr_in6 sin6;
  struct sockaddr_domain sd;
} Address;

///////////////////////////////////////////////////////////////////////////////
//                                   Error                                   //
///////////////////////////////////////////////////////////////////////////////

class OSError : std::exception {
public:
  pthread_t tid;
  int no;
  std::string scname;
  OSError(const char *scname);
  OSError(int no, const char *scname);
  std::string what();
};

class GAIError : std::exception {
public:
  pthread_t tid;
  int no;
  std::string domain;
  GAIError(int no, const char *domain);
  std::string what();
};

///////////////////////////////////////////////////////////////////////////////
//                                   Socket                                  //
///////////////////////////////////////////////////////////////////////////////

class Socket {
public:
  int fd, family;

  Socket();
  Socket(Socket &&sock);
  ~Socket();
  void open(int family);
  void close();
  void shutdown(int how);

  void bind(Address &addr);
  void listen(int backlog);
  void accept(Socket &sock, Address &addr);
  void connect(Address &addr);

  ssize_t recv(void *buf, size_t len, int flags);
  ssize_t send(void *buf, size_t len, int flags);
  void recvall(void *buf, size_t len);
  void sendall(void *buf, size_t len);

  void getsockname(Address &addr);
  void getpeername(Address &addr);
  void getsockopt(int level, int opt, void *val, socklen_t *len);
  void setsockopt(int level, int opt, void *val, socklen_t len);
  int getsockopt(int level, int opt);
  void setsockopt(int level, int opt, int val);

  static socklen_t addrlen(int family);
  static void getaddrinfo(Address &addr);

  static std::string addr_ntop(Address &addr);
  static int addr_pton(Address &addr, std::string src, int family);
  static int addr_pton(Address &addr, std::string src);
};

///////////////////////////////////////////////////////////////////////////////
//                                   Server                                  //
///////////////////////////////////////////////////////////////////////////////

#define defineRequestHandler(NAME, BODY)                                       \
  class NAME {                                                                 \
  public:                                                                      \
    Socket *sock;                                                              \
    NAME(void *arg) {                                                          \
      sock = (Socket *)arg;                                                    \
      pthread_detach(pthread_self());                                          \
    }                                                                          \
    ~NAME() { delete sock; }                                                   \
    void run() BODY                                                            \
  };

template <class Handler> void *requestHandle(void *arg) {
  Handler handler(arg);
  handler.run();
  return NULL;
}

template <class Handler> class Server {
public:
  Address &addr;

  Server(Address &addr) : addr(addr) {}
  void run() {
    int err;
    pthread_t tid;
    Socket srvsock, clisock, *arg;
    Address srvaddr, cliaddr;

    srvaddr = addr;
    Socket::getaddrinfo(srvaddr);
    srvsock.open(srvaddr.sa.sa_family);
    srvsock.bind(srvaddr);
    srvsock.listen(5);
    srvsock.getsockname(srvaddr);
    std::cout << "listen at " << Socket::addr_ntop(srvaddr) << std::endl;

    for (;;) {
      srvsock.accept(clisock, cliaddr);
      std::cout << "accept from " << Socket::addr_ntop(cliaddr) << std::endl;
      arg = new Socket(std::move(clisock));
    docreate:
      err = pthread_create(&tid, NULL, requestHandle<Handler>, (void *)arg);
      if (err) {
        if (err == EAGAIN)
          goto docreate;
        delete arg;
        throw OSError(err, "PTHREAD_CREATE");
      }
    }
  }
};

#endif
