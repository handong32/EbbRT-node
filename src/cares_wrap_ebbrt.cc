#include "node.h"

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

static void Initialize(Handle<Object> target) { EBBRT_UNIMPLEMENTED(); }
}
}

NODE_MODULE(node_cares_wrap, node::cares_wrap::Initialize)
