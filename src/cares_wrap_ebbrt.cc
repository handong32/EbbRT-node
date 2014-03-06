#include "node.h"

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
static Handle<Value> GetAddrInfo(const Arguments &args) {
  EBBRT_UNIMPLEMENTED();
}
static Handle<Value> IsIP(const Arguments &args) { EBBRT_UNIMPLEMENTED(); }

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
