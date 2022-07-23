#ifndef TCPP_H
#define TCPP_H

#include <pthread.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

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
  pthread_t tid;
  int no;
  std::string scname;
  OSError(int no, std::string scname);
  std::string str() const;
};

class GAIError : std::exception {
public:
  pthread_t tid;
  int no;
  std::string domain;
  GAIError(int no, std::string domain);
  std::string str() const;
};

class PTONError : std::exception {
public:
  pthread_t tid;
  std::string pres;
  PTONError(std::string pres);
  std::string str() const;
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
  static void addr_pton(Address &addr, std::string src);
  static int addr_pton_af(Address &addr, std::string src, int family);
};

#endif
