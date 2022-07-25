#ifndef TCPP_H
#define TCPP_H

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <exception>
#include <string>

///////////////////////////////////////////////////////////////////////////////
//                                   Error                                   //
///////////////////////////////////////////////////////////////////////////////

class TCPPError : public std::exception {
public:
  TCPPError();
  virtual std::string str() const noexcept = 0;
};

class ASSERTError : public TCPPError {
public:
  std::string msg;
  ASSERTError(std::string msg);
  std::string str() const noexcept override;
  const char *what() const noexcept override;
};

#define ASSERT(EXPR, MSG)                                                      \
  if (!(EXPR))                                                                 \
    throw ASSERTError(MSG);

class OSError : public TCPPError {
public:
  int no;
  std::string scname;
  OSError(int no, std::string scname);
  std::string str() const noexcept override;
  const char *what() const noexcept override;
};

class GAIError : public TCPPError {
public:
  int no;
  std::string domain;
  GAIError(int no, std::string domain);
  std::string str() const noexcept override;
  const char *what() const noexcept override;
};

class PTONError : public TCPPError {
public:
  std::string pres;
  PTONError(std::string pres);
  std::string str() const noexcept override;
  const char *what() const noexcept override;
};

///////////////////////////////////////////////////////////////////////////////
//                                  Address                                  //
///////////////////////////////////////////////////////////////////////////////

#define AF_DOMAIN 0
#define DOMAIN_MAX 255
struct sockaddr_domain {
  unsigned short sd_family;
  unsigned short sd_port;
  char sd_addr[DOMAIN_MAX + 1];
};

union Address {
  struct sockaddr sa;
  struct sockaddr_in sin4;
  struct sockaddr_in6 sin6;
  struct sockaddr_domain sd;

  static socklen_t length(int family);
  socklen_t length();
  void getaddrinfo();

  std::string ntop();
  void pton(std::string pres);
  int pton(std::string pres, int family);
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
  void open(Address &addr);
  void close();
  void shutdown(int how);

  void bind(Address &addr);
  void listen(int backlog = 5);
  void accept(Socket &sock, Address &addr);
  void connect(Address &addr);

  ssize_t recv(void *buf, size_t len, int flags = 0);
  ssize_t send(void *buf, size_t len, int flags = 0);
  void recvall(void *buf, size_t len);
  void sendall(void *buf, size_t len);

  void getsockname(Address &addr);
  void getpeername(Address &addr);
  std::string getsockstr();
  std::string getpeerstr();
  void getsockopt(int level, int opt, void *val, socklen_t *len);
  void setsockopt(int level, int opt, void *val, socklen_t len);
  int getsockopt(int level, int opt);
  void setsockopt(int level, int opt, int val);
};

#endif
