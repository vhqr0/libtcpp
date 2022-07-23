#ifndef TCPPSERVER_H
#define TCPPSERVER_H

#include "tcpp.hpp"

#include <iostream>
#include <utility>

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
    srvaddr.getaddrinfo();
    srvsock.open(srvaddr);
    srvsock.bind(srvaddr);
    srvsock.listen(5);
    srvsock.getsockname(srvaddr);
    std::cout << "listen at " << srvaddr.ntop() << std::endl;

    for (;;) {
      srvsock.accept(clisock, cliaddr);
      std::cout << "accept from " << cliaddr.ntop() << std::endl;
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
