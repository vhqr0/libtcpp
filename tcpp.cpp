#include "tcpp.hpp"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netdb.h>

#include <sstream>

///////////////////////////////////////////////////////////////////////////////
//                                   Error                                   //
///////////////////////////////////////////////////////////////////////////////

OSError::OSError(int no, std::string scname)
    : tid(pthread_self()), no(no), scname(scname) {}
std::string OSError::str() const {
  std::ostringstream oss;
  oss << '{' << tid << '}';
  oss << '[' << scname << ']';
  oss << '(' << strerror(no) << ')';
  return oss.str();
}

GAIError::GAIError(int no, std::string domain)
    : tid(pthread_self()), no(no), domain(domain) {}
std::string GAIError::str() const {
  std::ostringstream oss;
  oss << '{' << tid << '}';
  oss << "[GAI]";
  oss << '<' << domain << '>';
  oss << '(' << gai_strerror(no) << ')';
  return oss.str();
}

PTONError::PTONError(std::string pres) : tid(pthread_self()), pres(pres) {}
std::string PTONError::str() const {
  std::ostringstream oss;
  oss << '{' << tid << '}';
  oss << "[PTON]";
  oss << '<' << pres << '>';
  return oss.str();
}

///////////////////////////////////////////////////////////////////////////////
//                                  Address                                  //
///////////////////////////////////////////////////////////////////////////////

socklen_t Socket::addrlen(int family) {
  switch (family) {
  case AF_INET:
    return sizeof(struct sockaddr_in);
  case AF_INET6:
    return sizeof(struct sockaddr_in6);
  default:
    return 0;
  }
}

void Socket::getaddrinfo(Address &addr) {
  int err;
  unsigned short port;
  struct addrinfo hints, *rai;

  if (addr.sa.sa_family != AF_DOMAIN)
    return;
  port = addr.sd.sd_port;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  err = ::getaddrinfo(addr.sd.sd_addr, NULL, &hints, &rai);
  if (err)
    throw GAIError(err, addr.sd.sd_addr);
  switch (rai->ai_family) {
  case AF_INET:
    addr.sin4 = *(struct sockaddr_in *)rai->ai_addr;
    addr.sin4.sin_port = port;
    freeaddrinfo(rai);
    break;
  case AF_INET6:
    addr.sin6 = *(struct sockaddr_in6 *)rai->ai_addr;
    addr.sin6.sin6_port = port;
    freeaddrinfo(rai);
    break;
  default:
    freeaddrinfo(rai);
    throw GAIError(EAI_ADDRFAMILY, addr.sd.sd_addr);
  }
}

std::string Socket::addr_ntop(Address &addr) {
  std::ostringstream oss;
  char buf[INET6_ADDRSTRLEN];

  switch (addr.sa.sa_family) {
  case AF_INET:
    inet_ntop(AF_INET, &addr.sin4.sin_addr, buf, INET_ADDRSTRLEN);
    oss << buf << ':' << ntohs(addr.sin4.sin_port);
    break;
  case AF_INET6:
    inet_ntop(AF_INET6, &addr.sin6.sin6_addr, buf, INET6_ADDRSTRLEN);
    oss << '[' << buf << ']' << ':' << ntohs(addr.sin6.sin6_port);
    break;
  case AF_DOMAIN:
    oss << addr.sd.sd_addr << ':' << ntohs(addr.sd.sd_port);
    break;
  default:
    oss << '?' << addr.sa.sa_family << '?';
  }
  return oss.str();
}

void Socket::addr_pton(Address &addr, std::string src) {
  if (!addr_pton_af(addr, src, AF_INET))
    return;
  if (!addr_pton_af(addr, src, AF_INET6))
    return;
  if (!addr_pton_af(addr, src, AF_DOMAIN))
    return;
  throw PTONError(src);
}

int Socket::addr_pton_af(Address &addr, std::string src, int family) {
  unsigned short port;
  std::string addrstr, portstr;
  std::string::size_type pos;

  if (!src.length()) {
    return -1;
  } else if (src[0] == '[') {
    pos = src.find(']');
    if (pos == std::string::npos || pos + 1 == std::string::npos ||
        src[pos + 1] != ':')
      return -1;
    addrstr = src.substr(1, pos - 1);
    portstr = src.substr(pos + 2);
  } else {
    pos = src.find(':');
    if (pos == std::string::npos)
      return -1;
    addrstr = src.substr(0, pos);
    portstr = src.substr(pos + 1);
  }

  try {
    port = std::stoi(portstr);
  } catch (std::invalid_argument) {
    return -1;
  }

  memset(&addr, 0, sizeof(addr));
  switch (family) {
  case AF_INET:
    addr.sin4.sin_family = AF_INET;
    addr.sin4.sin_port = htons(port);
    if (inet_pton(AF_INET, addrstr.c_str(), &addr.sin4.sin_addr) != 1)
      return -1;
    break;
  case AF_INET6:
    addr.sin6.sin6_family = AF_INET6;
    addr.sin6.sin6_port = htons(port);
    if (inet_pton(AF_INET6, addrstr.c_str(), &addr.sin6.sin6_addr) != 1)
      return -1;
    break;
  case AF_DOMAIN:
    addr.sd.sd_family = AF_DOMAIN;
    addr.sd.sd_port = htons(port);
    strncpy(addr.sd.sd_addr, addrstr.c_str(), DOMAIN_MAX);
    break;
  default:
    return -1;
  }

  return 0;
}

///////////////////////////////////////////////////////////////////////////////
//                                   Socket                                  //
///////////////////////////////////////////////////////////////////////////////

Socket::Socket() : fd(-1), family(-1) {}
Socket::Socket(Socket &&sock) : fd(sock.fd), family(sock.family) {
  sock.fd = -1;
  sock.family = -1;
}
Socket::~Socket() { close(); }

void Socket::open(int family) {
  int fd;

  if (family != AF_INET && family != AF_INET6)
    throw OSError(EAFNOSUPPORT, "OPEN");
  fd = ::socket(family, SOCK_STREAM, 0);
  if (fd < 0)
    throw OSError(errno, "OPEN");
  this->fd = fd;
  this->family = family;
}

void Socket::close() {
  int fd, err;
  socklen_t len = sizeof(err);

  fd = this->fd;
  this->fd = -1;
  if (fd > 0) {
    ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
    ::shutdown(fd, SHUT_RDWR);
  doclose:
    err = ::close(fd);
    if (err && errno == EINTR)
      goto doclose;
  }
}

void Socket::shutdown(int how) {
  if (fd > 0)
    ::shutdown(fd, how);
}

void Socket::bind(Address &addr) {
  int err;

  if (addr.sa.sa_family != family)
    throw OSError(EINVAL, "BIND");
  err = ::bind(fd, &addr.sa, addrlen(addr.sa.sa_family));
  if (err)
    throw OSError(errno, "BIND");
}

void Socket::listen(int backlog) {
  int err;

  err = ::listen(fd, backlog);
  if (err)
    throw OSError(errno, "LISTEN");
}

void Socket::accept(Socket &sock, Address &addr) {
  int fd;
  socklen_t len = addrlen(family);

  memset(&addr, 0, sizeof(addr));
  fd = ::accept(this->fd, &addr.sa, &len);
  if (fd < -1)
    throw OSError(errno, "ACCEPT");
  sock.fd = fd;
  sock.family = addr.sa.sa_family;
}

void Socket::connect(Address &addr) {
  int err;

  if (addr.sa.sa_family != family)
    throw OSError(EINVAL, "CONNECT");
doconnect:
  err = ::connect(fd, &addr.sa, addrlen(addr.sa.sa_family));
  if (err) {
    if (errno == EINTR)
      goto doconnect;
    throw OSError(errno, "CONNECT");
  }
}

///////////////////////////////////////////////////////////////////////////////
//                              Socket Recv&Send                             //
///////////////////////////////////////////////////////////////////////////////

ssize_t Socket::recv(void *buf, size_t len, int flags) {
  ssize_t n;

dorecv:
  n = ::recv(fd, buf, len, flags);
  if (n < 0) {
    if (errno == EINTR)
      goto dorecv;
    throw OSError(errno, "RECV");
  }
  return n;
}

ssize_t Socket::send(void *buf, size_t len, int flags) {
  ssize_t n;

dosend:
  n = ::send(fd, buf, len, flags | MSG_NOSIGNAL);
  if (n < 0) {
    if (errno == EINTR)
      goto dosend;
    if (errno == EPIPE)
      return -1;
    throw OSError(errno, "SEND");
  }
  return n;
}

void Socket::recvall(void *buf, size_t len) {
  ssize_t n;

dorecv:
  n = ::recv(fd, buf, len, MSG_WAITALL);
  if (n < 0) {
    if (errno == EINTR)
      goto dorecv;
    throw OSError(errno, "RECV");
  }
  if (n != len)
    throw OSError(EFAULT, "RECV");
}

void Socket::sendall(void *buf, size_t len) {
  ssize_t n;
  char *cur = (char *)buf;

  while (len) {
    n = ::send(fd, cur, len, MSG_NOSIGNAL);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      throw OSError(errno, "SEND");
    }
    cur += n;
    len -= n;
  }
}

///////////////////////////////////////////////////////////////////////////////
//                               Socket Get&Set                              //
///////////////////////////////////////////////////////////////////////////////

void Socket::getsockname(Address &addr) {
  int err;
  socklen_t len = addrlen(family);

  memset(&addr, 0, sizeof(addr));
  err = ::getsockname(fd, &addr.sa, &len);
  if (err)
    throw OSError(errno, "GETSOCKNAME");
}

void Socket::getpeername(Address &addr) {
  int err;
  socklen_t len = addrlen(family);

  memset(&addr, 0, sizeof(addr));
  err = ::getpeername(fd, &addr.sa, &len);
  if (err)
    throw OSError(errno, "GETPEERNAME");
}

void Socket::getsockopt(int level, int opt, void *val, socklen_t *len) {
  int err;

  err = ::getsockopt(fd, level, opt, val, len);
  if (err)
    throw OSError(errno, "GETSOCKOPT");
}

void Socket::setsockopt(int level, int opt, void *val, socklen_t len) {
  int err;

  err = ::setsockopt(fd, level, opt, val, len);
  if (err)
    throw OSError(errno, "SETSOCKOPT");
}

int Socket::getsockopt(int level, int opt) {
  int val;
  socklen_t len = sizeof(val);

  getsockopt(level, opt, &val, &len);
  return val;
}

void Socket::setsockopt(int level, int opt, int val) {
  setsockopt(level, opt, &val, sizeof(val));
}
