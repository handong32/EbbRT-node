#include <cstring>

#include "node.h"
#include "req_wrap.h"

#include <ebbrt/CDebug.h>

namespace node {

namespace cares_wrap {

using v8::Arguments;
using v8::Array;
using v8::Context;
using v8::Function;
using v8::Handle;
using v8::HandleScope;
using v8::Integer;
using v8::Local;
using v8::Null;
using v8::Object;
using v8::Persistent;
using v8::String;
using v8::Value;

static Persistent<String> oncomplete_sym;

static Handle<Value> QueryA(const Arguments &args) { EBBRT_UNIMPLEMENTED(); }

static Handle<Value> QueryAaaa(const Arguments &args) { EBBRT_UNIMPLEMENTED(); }

static Handle<Value> QueryCname(const Arguments &args) {
  EBBRT_UNIMPLEMENTED();
}

static Handle<Value> QueryMx(const Arguments &args) { EBBRT_UNIMPLEMENTED(); }

static Handle<Value> QueryNs(const Arguments &args) { EBBRT_UNIMPLEMENTED(); }

static Handle<Value> QueryTxt(const Arguments &args) { EBBRT_UNIMPLEMENTED(); }

static Handle<Value> QuerySrv(const Arguments &args) { EBBRT_UNIMPLEMENTED(); }

static Handle<Value> QueryNaptr(const Arguments &args) {
  EBBRT_UNIMPLEMENTED();
}

static Handle<Value> GetHostByAddr(const Arguments &args) {
  EBBRT_UNIMPLEMENTED();
}

static Handle<Value> GetHostByName(const Arguments &args) {
  EBBRT_UNIMPLEMENTED();
}

typedef class ReqWrap<uv_getaddrinfo_t> GetAddrInfoReqWrap;

void AfterGetAddrInfo(uv_getaddrinfo_t *req, int status, struct addrinfo *res) {
  HandleScope scope;

  GetAddrInfoReqWrap *req_wrap = (GetAddrInfoReqWrap *)req->data;

  Local<Value> argv[1];

  if (status) {
    // Error
    SetErrno(uv_last_error(uv_default_loop()));
    argv[0] = Local<Value>::New(Null());
  } else {
    // Success
    struct addrinfo *address;
    int n = 0;

    // Count the number of responses.
    for (address = res; address; address = address->ai_next) {
      n++;
    }

    // Create the response array.
    Local<Array> results = Array::New(n);

    char ip[INET6_ADDRSTRLEN];
    const char *addr;

    n = 0;

    // Iterate over the IPv4 responses again this time creating javascript
    // strings for each IP and filling the results array.
    address = res;
    while (address) {
      assert(address->ai_socktype == SOCK_STREAM);

      // Ignore random ai_family types.
      if (address->ai_family == AF_INET) {
        // Juggle pointers
        addr = (char *)&((struct sockaddr_in *)address->ai_addr)->sin_addr;
        uv_err_t err =
            uv_inet_ntop(address->ai_family, addr, ip, INET6_ADDRSTRLEN);
        if (err.code != UV_OK)
          continue;

        // Create JavaScript string
        Local<String> s = String::New(ip);
        results->Set(n, s);
        n++;
      }

      // Increment
      address = address->ai_next;
    }

    // Iterate over the IPv6 responses putting them in the array.
    address = res;
    while (address) {
      assert(address->ai_socktype == SOCK_STREAM);

      // Ignore random ai_family types.
      if (address->ai_family == AF_INET6) {
        // Juggle pointers
        addr = (char *)&((struct sockaddr_in6 *)address->ai_addr)->sin6_addr;
        uv_err_t err =
            uv_inet_ntop(address->ai_family, addr, ip, INET6_ADDRSTRLEN);
        if (err.code != UV_OK)
          continue;

        // Create JavaScript string
        Local<String> s = String::New(ip);
        results->Set(n, s);
        n++;
      }

      // Increment
      address = address->ai_next;
    }

    argv[0] = results;
  }

  uv_freeaddrinfo(res);

  // Make the callback into JavaScript
  MakeCallback(req_wrap->object_, oncomplete_sym, ARRAY_SIZE(argv), argv);

  delete req_wrap;
}

static Handle<Value> GetAddrInfo(const Arguments &args) {
  HandleScope scope;

  String::Utf8Value hostname(args[0]);

  int fam = AF_UNSPEC;
  if (args[1]->IsInt32()) {
    switch (args[1]->Int32Value()) {
    case 6:
      fam = AF_INET6;
      break;

    case 4:
      fam = AF_INET;
      break;
    }
  }

  GetAddrInfoReqWrap *req_wrap = new GetAddrInfoReqWrap();

  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = fam;
  hints.ai_socktype = SOCK_STREAM;

  int r = uv_getaddrinfo(uv_default_loop(), &req_wrap->req_, AfterGetAddrInfo,
                         *hostname, NULL, &hints);
  req_wrap->Dispatched();

  if (r) {
    SetErrno(uv_last_error(uv_default_loop()));
    delete req_wrap;
    return scope.Close(v8::Null());
  } else {
    return scope.Close(req_wrap->object_);
  }
}

static Handle<Value> IsIP(const Arguments &args) {
  HandleScope scope;

  String::AsciiValue ip(args[0]);
  char address_buffer[sizeof(struct in6_addr)];

  if (uv_inet_pton(AF_INET, *ip, &address_buffer).code == UV_OK) {
    return scope.Close(v8::Integer::New(4));
  }

  if (uv_inet_pton(AF_INET6, *ip, &address_buffer).code == UV_OK) {
    return scope.Close(v8::Integer::New(6));
  }

  return scope.Close(v8::Integer::New(0));
}

static void Initialize(Handle<Object> target) {
  HandleScope scope;

  NODE_SET_METHOD(target, "queryA", QueryA);
  NODE_SET_METHOD(target, "queryAaaa", QueryAaaa);
  NODE_SET_METHOD(target, "queryCname", QueryCname);
  NODE_SET_METHOD(target, "queryMx", QueryMx);
  NODE_SET_METHOD(target, "queryNs", QueryNs);
  NODE_SET_METHOD(target, "queryTxt", QueryTxt);
  NODE_SET_METHOD(target, "querySrv", QuerySrv);
  NODE_SET_METHOD(target, "queryNaptr", QueryNaptr);
  NODE_SET_METHOD(target, "getHostByAddr", GetHostByAddr);
  NODE_SET_METHOD(target, "getHostByName", GetHostByName);

  NODE_SET_METHOD(target, "getaddrinfo", GetAddrInfo);
  NODE_SET_METHOD(target, "isIP", IsIP);

  target->Set(String::NewSymbol("AF_INET"), Integer::New(AF_INET));
  target->Set(String::NewSymbol("AF_INET6"), Integer::New(AF_INET6));
  target->Set(String::NewSymbol("AF_UNSPEC"), Integer::New(0));

  oncomplete_sym = NODE_PSYMBOL("oncomplete");
}
}
}

NODE_MODULE(node_cares_wrap, node::cares_wrap::Initialize)
