#ifndef TCPP_H
#define TCPP_H

#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>

#include <exception>
#include <string>

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
  int no;
  OSError();
  OSError(int no);
  std::string what();
};

class GAIError : std::exception {
public:
  int no;
  GAIError(int no);
  std::string what();
};

///////////////////////////////////////////////////////////////////////////////
//                                   Socket                                  //
///////////////////////////////////////////////////////////////////////////////

class Socket {
public:
  int fd, family;

  Socket();
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

#endif
