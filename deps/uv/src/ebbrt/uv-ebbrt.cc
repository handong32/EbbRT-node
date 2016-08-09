#undef ebbrt

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstring>
#include <queue>

#include <ebbrt/Clock.h>
#include <ebbrt/Debug.h>
#include <ebbrt/Net.h>
#include <ebbrt/NetMisc.h>
#include <ebbrt/Timer.h>
#include <ebbrt/UniqueIOBuf.h>

#include <ebbrt-filesystem/FileSystem.h>

#include "uv.h"
extern "C" {
#include "uv-common.h"
}

//#define COUNTERS

class Counter {
public:
  Counter() : sum_(0), start_(), counts_(0) {}
  void Enter() {
#ifdef COUNTERS
    start_ = ebbrt::clock::Wall::Now();
#endif
  }
  void Exit() {
#ifdef COUNTERS
    if (start_.time_since_epoch() != std::chrono::nanoseconds(0)) {
      sum_ += std::chrono::duration_cast<std::chrono::nanoseconds>(
          ebbrt::clock::Wall::Now() - start_);
      start_ = ebbrt::clock::Wall::time_point(std::chrono::nanoseconds(0));
      counts_++;
    }
#endif
  }
  double Mean() {
    return static_cast<double>(sum_.count()) / static_cast<double>(counts_);
  }
  std::chrono::nanoseconds Total() { return sum_; }
  void Clear() {
    sum_ = std::chrono::nanoseconds(0);
    start_ = ebbrt::clock::Wall::time_point(std::chrono::nanoseconds(0));
    counts_ = 0;
  }

private:
  std::chrono::nanoseconds sum_;
  ebbrt::clock::Wall::time_point start_;
  size_t counts_;
};
extern "C" int uv_async_init(uv_loop_t *loop, uv_async_t *handle,
                             uv_async_cb async_cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_async_send(uv_async_t *handle) { EBBRT_UNIMPLEMENTED(); }

namespace {
Counter activate_ctr;
Counter idle_ctr;
Counter tcp_write_ctr;
Counter tcp_output_ctr;
Counter tcp_write_cb_ctr;
Counter tcp_read_cb_ctr;
Counter tcp_read_alloc_ctr;
Counter tcp_accept_ctr;
Counter tcp_prereceive_ctr;
Counter tcp_receive_ctr;
/* handle flags */
enum {
  UV_CLOSING = 0x01,           /* uv_close() called but not finished. */
  UV_CLOSED = 0x02,            /* close(2) finished. */
  UV_STREAM_READING = 0x04,    /* uv_read_start() called. */
  UV_STREAM_SHUTTING = 0x08,   /* uv_shutdown() called but not complete. */
  UV_STREAM_SHUT = 0x10,       /* Write side closed. */
  UV_STREAM_READABLE = 0x20,   /* The stream is readable */
  UV_STREAM_WRITABLE = 0x40,   /* The stream is writable */
  UV_STREAM_BLOCKING = 0x80,   /* Synchronous writes. */
  UV_TCP_NODELAY = 0x100,      /* Disable Nagle. */
  UV_TCP_KEEPALIVE = 0x200,    /* Turn on keep-alive. */
  UV_TCP_SINGLE_ACCEPT = 0x400 /* Only accept() when idle. */
};

template <typename T>
void uv__req_init(uv_loop_t *loop, T *req, uv_req_type type) {
  auto r = (uv_req_t *)req;
  r->type = type;
  uv__req_register(loop, r);
}

uv_loop_t default_loop_struct;
uv_loop_t *default_loop_ptr;

void activate_loop(uv_loop_t *loop) {
  if (loop->event_context) {
    auto context =
        static_cast<ebbrt::EventManager::EventContext *>(loop->event_context);
    loop->event_context = nullptr;
    ebbrt::event_manager->ActivateContextSync(std::move(*context));
  }
}

void uv_tcp_enqueue_read(uv_tcp_t *handle);

class UVTcpHandler : public ebbrt::TcpHandler {
public:
  explicit UVTcpHandler(ebbrt::NetworkManager::TcpPcb pcb)
      : ebbrt::TcpHandler(std::move(pcb)) {}

  void Receive(std::unique_ptr<ebbrt::MutIOBuf> buf) override {
    if (buf_) {
      buf_->PrependChain(std::move(buf));
    } else {
      buf_ = std::move(buf);
    }
    if (likely(client_ &&
               !(client_->flags & UV_CLOSING || client_->flags & UV_CLOSED))) {
      if (client_->flags & UV_STREAM_READING) {
        uv_tcp_enqueue_read(client_);
        activate_loop(client_->loop);
      }
    }
  }

  void Close() override {
    if (client_) {
      if (!(client_->flags & UV_STREAM_READING))
        EBBRT_UNIMPLEMENTED();
      auto cb_queue = static_cast<std::queue<std::function<void()> > *>(
          client_->loop->callbacks);

      cb_queue->emplace([this]() {
        auto uv_buf = client_->alloc_cb((uv_handle_t *)client_, 8);
        assert(uv_buf.len > 0);
        assert(uv_buf.base);
        uv__set_artificial_error(client_->loop, UV_EOF);
        client_->read_cb((uv_stream_t *)client_, -1, uv_buf);
      });
      activate_loop(client_->loop);
    }
    Shutdown();
  }
  void Abort() override {}

  std::unique_ptr<ebbrt::IOBuf> buf_;
  uv_tcp_t *client_;
};

void uv_tcp_enqueue_read(uv_tcp_t *handle) {
  auto handler = static_cast<UVTcpHandler *>(handle->handler);
  kassert(handler);

  if (unlikely(!handler->buf_))
    return;

  auto cb_queue = static_cast<std::queue<std::function<void()> > *>(
      handle->loop->callbacks);
  cb_queue->emplace([handle, handler]() {
    kassert(handler->buf_);
    auto &b = handler->buf_;
    auto len = b->ComputeChainDataLength();
    auto uv_buf = handle->alloc_cb((uv_handle_t *)handle, len);
    kassert(uv_buf.len > 0);
    kassert(uv_buf.base);
    auto copy_len = std::min(len, uv_buf.len);
    if (copy_len < len)
      EBBRT_UNIMPLEMENTED();
    size_t copied = 0;
    while (copied < copy_len) {
      auto to_copy = copy_len - copied;
      if (b->Length() > to_copy) {
        memcpy(&uv_buf.base[copied], b->Data(), to_copy);
        copied += to_copy;
        b->Advance(to_copy);
      } else {
        memcpy(&uv_buf.base[copied], b->Data(), b->Length());
        copied += b->Length();
        b = std::move(b->Pop());
      }
    }
    handle->read_cb((uv_stream_t *)handle, copy_len, uv_buf);
  });

  //   auto &b = *static_cast<std::unique_ptr<ebbrt::IOBuf> *>(handle->buf);
  //   if (unlikely(!b))
  //     return;

  //   auto cb_queue = static_cast<std::queue<std::function<void()> > *>(
  //       handle->loop->callbacks);
  //   cb_queue->emplace([handle]() {
  //     tcp_read_cb_ctr.Enter();
  //     auto &b = *static_cast<std::unique_ptr<ebbrt::IOBuf> *>(handle->buf);
  //     auto len = b->ComputeChainDataLength();
  //     tcp_read_alloc_ctr.Enter();
  //     auto uv_buf = handle->alloc_cb((uv_handle_t *)handle, len);
  //     tcp_read_alloc_ctr.Exit();
  //     assert(uv_buf.len > 0);
  //     assert(uv_buf.base);
  //     auto copy_len = std::min(len, uv_buf.len);
  //     if (copy_len < len)
  //       EBBRT_UNIMPLEMENTED();
  //     size_t copied = 0;
  //     while (copied < copy_len) {
  //       auto to_copy = copy_len - copied;
  //       if (b->Length() > to_copy) {
  //         memcpy(&uv_buf.base[copied], b->Data(), to_copy);
  //         copied += to_copy;
  //         b->Advance(to_copy);
  //       } else {
  //         memcpy(&uv_buf.base[copied], b->Data(), b->Length());
  //         copied += b->Length();
  //         b = std::move(b->Pop());
  //       }
  //     }
  //     handle->read_cb((uv_stream_t *)handle, copy_len, uv_buf);
  //     tcp_read_cb_ctr.Exit();
  //   });
}

int uv_tcp_listen(uv_tcp_t *handle, int backlog, uv_connection_cb cb) {
  kassert(!handle->tcp_pcb);
  auto pcb = new ebbrt::NetworkManager::ListeningTcpPcb;
  handle->tcp_pcb = pcb;
  handle->accepted_queue = new std::queue<UVTcpHandler *>();
  pcb->Bind(handle->bind_port, [cb, handle](ebbrt::NetworkManager::TcpPcb pcb) {
    auto handler = new UVTcpHandler(std::move(pcb));
    handler->Install();
    auto accept_queue =
        static_cast<std::queue<UVTcpHandler *> *>(handle->accepted_queue);
    kassert(accept_queue);
    accept_queue->push(std::move(handler));

    auto cb_queue = static_cast<std::queue<std::function<void()> > *>(
        handle->loop->callbacks);
    cb_queue->emplace([handle, cb]() { cb((uv_stream_t *)handle, 0); });
    activate_loop(handle->loop);
  });
  return 0;
  // auto pcb = static_cast<ebbrt::NetworkManager::TcpPcb *>(handle->tcp_pcb);
  // pcb->ListenWithBacklog(backlog);
  // pcb->Accept([cb, handle](ebbrt::NetworkManager::TcpPcb pcb) {
  //   tcp_accept_ctr.Enter();
  //   auto t = new uv_tcp_t;
  //   auto tcp_pcb = new ebbrt::NetworkManager::TcpPcb(std::move(pcb));
  //   t->tcp_pcb = tcp_pcb;
  //   t->buf = new std::unique_ptr<ebbrt::IOBuf>();
  //   tcp_pcb->Receive([t](ebbrt::NetworkManager::TcpPcb &pcb,
  //                        std::unique_ptr<ebbrt::IOBuf> &&buf) {
  //     tcp_prereceive_ctr.Enter();
  //     if (buf->ComputeChainDataLength() <= 0)
  //       EBBRT_UNIMPLEMENTED();

  //     auto &b = *static_cast<std::unique_ptr<ebbrt::IOBuf> *>(t->buf);
  //     if (b) {
  //       b->Prev()->AppendChain(std::move(buf));
  //     } else {
  //       b = std::move(buf);
  //     }
  //     tcp_prereceive_ctr.Exit();
  //   });

  //   auto accept_queue =
  //       static_cast<std::queue<uv_tcp_t *> *>(handle->accepted_queue);
  //   accept_queue->push(std::move(t));

  //   auto cb_queue = static_cast<std::queue<std::function<void()> > *>(
  //       handle->loop->callbacks);

  //   cb_queue->emplace([handle, cb]() { cb((uv_stream_t *)handle, 0); });
  //   activate_loop(handle->loop);
  //   tcp_accept_ctr.Exit();
  // });
  // return 0;
}

int uv_tcp_accept(uv_tcp_t *server, uv_tcp_t *client) {
  auto accept_queue =
      static_cast<std::queue<UVTcpHandler *> *>(server->accepted_queue);
  kassert(accept_queue);
  kassert(!accept_queue->empty());
  auto handler = accept_queue->front();
  client->flags |= UV_STREAM_READABLE | UV_STREAM_WRITABLE;
  client->handler = handler;
  handler->client_ = client;

  // delete the previously allocated bufs
  // delete static_cast<ebbrt::NetworkManager::ListeningTcpPcb
  // *>(client->tcp_pcb);
  // delete static_cast<std::unique_ptr<ebbrt::IOBuf> *>(client->buf);
  // client->tcp_pcb = uv_tcp->tcp_pcb;
  // client->buf = uv_tcp->buf;
  accept_queue->pop();
  // auto pcb = static_cast<ebbrt::NetworkManager::TcpPcb *>(client->tcp_pcb);
  // pcb->Receive([client](ebbrt::NetworkManager::TcpPcb &pcb,
  //                       std::unique_ptr<ebbrt::IOBuf> &&buf) {
  //   if (likely(!(client->flags & UV_CLOSING || client->flags & UV_CLOSED))) {
  //     if (unlikely(buf->ComputeChainDataLength() <= 0)) {
  //       if (!(client->flags & UV_STREAM_READING))
  //         EBBRT_UNIMPLEMENTED();
  //       auto cb_queue = static_cast<std::queue<std::function<void()> > *>(
  //           client->loop->callbacks);

  //       cb_queue->emplace([client]() {
  //         auto uv_buf = client->alloc_cb((uv_handle_t *)client, 8);
  //         assert(uv_buf.len > 0);
  //         assert(uv_buf.base);
  //         uv__set_artificial_error(client->loop, UV_EOF);
  //         client->read_cb((uv_stream_t *)client, -1, uv_buf);
  //       });
  //       activate_loop(client->loop);
  //     } else {
  //       auto &b = *static_cast<std::unique_ptr<ebbrt::IOBuf> *>(client->buf);
  //       if (b) {
  //         b->Prev()->AppendChain(std::move(buf));
  //       } else {
  //         b = std::move(buf);
  //       }

  //       if (client->flags & UV_STREAM_READING) {
  //         uv_tcp_enqueue_read(client);
  //         activate_loop(client->loop);
  //       }
  //     }
  //   }
  // });

  return 0;
}

int uv_pipe_listen(uv_pipe_t *handle, int backlog, uv_connection_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

void uv__update_time(uv_loop_t *loop) {
  auto time_ns = ebbrt::clock::Wall::Now().time_since_epoch();
  auto time_us = std::chrono::duration_cast<std::chrono::microseconds>(time_ns);
  loop->time = time_us.count();
}
}

int uv__loop_init(uv_loop_t *loop) {
  memset(loop, 0, sizeof(*loop));
  RB_INIT(&loop->timer_handles);
  ngx_queue_init(&loop->handle_queue);
  ngx_queue_init(&loop->active_reqs);
  ngx_queue_init(&loop->idle_handles);
#if __EXCEPTIONS
  try {
#endif
    loop->callbacks = new std::queue<std::function<void()> >();
#if __EXCEPTIONS
  }
  catch (...) {
    return -1;
  }
#endif
  uv__update_time(loop);

  return 0;
}

extern "C" uv_loop_t *uv_default_loop(void) {
  if (!default_loop_ptr) {
    default_loop_ptr = &default_loop_struct;
    if (uv__loop_init(default_loop_ptr) < 0) {
      return NULL;
    }
  }

  return default_loop_ptr;
}

namespace {
void uv__run_idle(uv_loop_t *loop) {
#ifdef COUNTERS
  idle_ctr.Enter();
#endif
  uv_idle_t *h;
  ngx_queue_t *q;
  ngx_queue_foreach(q, &loop->idle_handles) {
    h = ngx_queue_data(q, uv_idle_t, queue);
    h->idle_cb(h, 0);
  }
#ifdef COUNTERS
  idle_ctr.Exit();
#endif
}

bool uv__loop_alive(uv_loop_t *loop) {
  return uv__has_active_handles(loop) || uv__has_active_reqs(loop);
}

bool uv__block(uv_loop_t *loop) {
  if (loop->stop_flag != 0)
    return false;

  if (!uv__has_active_handles(loop) && !uv__has_active_reqs(loop))
    return false;

  if (!ngx_queue_empty(&loop->idle_handles))
    return false;

  return true;
}
}

void uv__run_timers(uv_loop_t *loop);

extern "C" int uv_run(uv_loop_t *loop, uv_run_mode mode) {
#ifdef COUNTERS
  ebbrt::timer->Start(
      std::chrono::seconds(5),
      []() {
        ebbrt::kprintf("On this context for %lld nanoseconds\n",
                       activate_ctr.Total().count());
        activate_ctr.Clear();
        ebbrt::kprintf("Running idles for %lld nanoseconds\n",
                       idle_ctr.Total().count());
        idle_ctr.Clear();
        ebbrt::kprintf("Running tcp_write for %lld nanoseconds\n",
                       tcp_write_ctr.Total().count());
        tcp_write_ctr.Clear();
        ebbrt::kprintf("Running tcp_output for %lld nanoseconds\n",
                       tcp_output_ctr.Total().count());
        tcp_output_ctr.Clear();
        ebbrt::kprintf("Running tcp_write_cb for %lld nanoseconds\n",
                       tcp_write_cb_ctr.Total().count());
        tcp_write_cb_ctr.Clear();
        ebbrt::kprintf("Running tcp_read_cb for %lld nanoseconds\n",
                       tcp_read_cb_ctr.Total().count());
        tcp_read_cb_ctr.Clear();
      },
      /* repeat = */ true);
#endif
  auto r = uv__loop_alive(loop);
  while (r != 0 && loop->stop_flag == 0) {
    uv__update_time(loop);
    uv__run_timers(loop);
    uv__run_idle(loop);

    auto queue =
        static_cast<std::queue<std::function<void()> > *>(loop->callbacks);
    if (queue->empty()) {
      // no pending callbacks, do we block or not?
      bool block;
      if (mode & UV_RUN_NOWAIT) {
        block = false;
      } else {
        block = uv__block(loop);
      }

      if (uv__has_active_handles(loop) || uv__has_active_reqs(loop)) {
        loop->blocking = block;
        ebbrt::EventManager::EventContext context;
        loop->event_context = &context;
        // if we don't block then enqueue a callback to wake us up
        if (!block)
          EBBRT_UNIMPLEMENTED();
#ifdef COUNTERS
        activate_ctr.Exit();
#endif
        ebbrt::event_manager->SaveContext(context);
#ifdef COUNTERS
        activate_ctr.Enter();
#endif
      }
    }

    if (queue->empty() && mode & UV_RUN_NOWAIT)
      // We woke up, if there are still no callbacks and we were asked not to
      // wait, then just break
      break;

    if (!queue->empty()) {
      assert(!queue->empty());
      auto f = std::move(queue->front());
      queue->pop();
      f();
    }

    r = uv__loop_alive(loop);

    if (mode & UV_RUN_ONCE)
      break;
  }

  if (loop->stop_flag != 0)
    loop->stop_flag = 0;

  return r;
}

extern "C" int uv_dlopen(const char *filename, uv_lib_t *lib) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_dlsym(uv_lib_t *lib, const char *name, void **ptr) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" const char *uv_dlerror(uv_lib_t *lib) { EBBRT_UNIMPLEMENTED(); }

extern "C" uv_err_code uv_translate_sys_error(int sys_errno) {
  EBBRT_UNIMPLEMENTED();
}

extern ebbrt::EbbRef<FileSystem> node_fs_ebb;

#define FS_INIT(type)                                                          \
  uv__req_init((loop), (req), UV_FS);                                          \
  (req)->fs_type = UV_FS_##type;                                               \
  (req)->loop = (loop);                                                        \
  (req)->cb = cb;                                                              \
  (req)->result = 0;                                                           \
  (req)->ptr = nullptr;                                                        \
  (req)->path = nullptr;                                                       \
  (req)->errorno = UV_OK;

#define FS_PATH                                                                \
  do {                                                                         \
    if (NULL == ((req)->path = strdup((path))))                                \
      return uv__set_sys_error((loop), ENOMEM);                                \
  } while (0)

extern "C" int uv_fs_close(uv_loop_t *loop, uv_fs_t *req, uv_file file,
                           uv_fs_cb cb) {
  ebbrt::kprintf("TODO(dschatz): Actually close\n");
  FS_INIT(CLOSE);
  req->result = 0;
  if (req->cb) {
    auto cb_queue =
        static_cast<std::queue<std::function<void()> > *>(req->loop->callbacks);
    cb_queue->emplace([req]() {
      uv__req_unregister(req->loop, req);
      req->cb(req);
    });
  } else {
    uv__req_unregister(req->loop, req);
  }
  return req->result;
}

extern const char __attribute__((weak)) node_script[];
extern size_t __attribute__((weak)) node_script_len;

extern "C" int uv_fs_open(uv_loop_t *loop, uv_fs_t *req, const char *path,
                          int flags, int mode, uv_fs_cb cb) {
  if (node_script) {
    EBBRT_UNIMPLEMENTED();
  } else {
    FS_INIT(OPEN);
    FS_PATH;
    auto func = [req](ebbrt::Future<int> f) {
      req->result = f.Get();
      if (req->cb) {
        auto cb_queue = static_cast<std::queue<std::function<void()> > *>(
            req->loop->callbacks);
        cb_queue->emplace([req]() {
          uv__req_unregister(req->loop, req);
          req->cb(req);
        });
        activate_loop(req->loop);
      } else {
        uv__req_unregister(req->loop, req);
      }
      return req->result;
    };
    auto f = node_fs_ebb->Open(path, flags, mode);
    if (cb) {
      f.Then(std::move(func));
      return 0;
    } else {
      return func(f.Block());
    }
  }
}

namespace {
size_t read_len = 0;
}

extern "C" int uv_fs_read(uv_loop_t *loop, uv_fs_t *req, uv_file fd, void *buf,
                          size_t length, int64_t offset, uv_fs_cb cb) {
  FS_INIT(READ);
  if (node_script && fd == 0) {
    if (!cb)
      EBBRT_UNIMPLEMENTED();

    if (offset != -1)
      EBBRT_UNIMPLEMENTED();

    auto cb_queue =
        static_cast<std::queue<std::function<void()> > *>(loop->callbacks);
    cb_queue->emplace([req, buf, length, cb]() {
      auto script_len = node_script_len;
      if (read_len < script_len) {
        auto len = std::min(script_len - read_len, length);
        std::strncpy(static_cast<char *>(buf), node_script + read_len, len);
        read_len += len;
        req->result = len;
      } else {
        req->result = 0;
      }

      uv__req_unregister(req->loop, req);

      cb(req);
    });
    return 0;
  } else {
    auto func = [req, buf, cb](ebbrt::Future<std::string> f) {
      auto &str = f.Get();
      req->result = str.length();
      memcpy(buf, str.data(), str.length());
      if (req->cb) {
        auto cb_queue = static_cast<std::queue<std::function<void()> > *>(
            req->loop->callbacks);
        cb_queue->emplace([req]() {
          uv__req_unregister(req->loop, req);
          if (req->cb) {
            req->cb(req);
          }
        });
        activate_loop(req->loop);
      } else {
        uv__req_unregister(req->loop, req);
      }
      return req->result;
    };
    auto f = node_fs_ebb->Read(fd, length, offset);
    if (cb) {
      f.Then(std::move(func));
      return 0;
    } else {
      return func(f.Block());
    }
  }
}

extern "C" int uv_fs_unlink(uv_loop_t *loop, uv_fs_t *req, const char *path,
                            uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_write(uv_loop_t *loop, uv_fs_t *req, uv_file fd, void *buf,
                           size_t length, int64_t offset, uv_fs_cb cb) {
  FS_INIT(WRITE);

  if (!(fd == 1 || fd == 2))
    EBBRT_UNIMPLEMENTED();

  if (offset != -1)
    EBBRT_UNIMPLEMENTED();

  if (cb)
    EBBRT_UNIMPLEMENTED();

  ebbrt::force_kprintf("%.*s", length, static_cast<const char *>(buf));
  uv__req_unregister(req->loop, req);

  return 0;
}

extern "C" int uv_fs_mkdir(uv_loop_t *loop, uv_fs_t *req, const char *path,
                           int mode, uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_rmdir(uv_loop_t *loop, uv_fs_t *req, const char *path,
                           uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_readdir(uv_loop_t *loop, uv_fs_t *req, const char *path,
                             int flags, uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_link(uv_loop_t *loop, uv_fs_t *req, const char *path,
                          const char *new_path, uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_symlink(uv_loop_t *loop, uv_fs_t *req, const char *path,
                             const char *new_path, int flags, uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_readlink(uv_loop_t *loop, uv_fs_t *req, const char *path,
                              uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_chown(uv_loop_t *loop, uv_fs_t *req, const char *path,
                           uv_uid_t uid, uv_gid_t gid, uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_fchown(uv_loop_t *loop, uv_fs_t *req, uv_file fd,
                            uv_uid_t uid, uv_gid_t gid, uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_stat(uv_loop_t *loop, uv_fs_t *req, const char *path,
                          uv_fs_cb cb) {
  if (node_script) {
    EBBRT_UNIMPLEMENTED();
  } else {
    FS_INIT(STAT);
    FS_PATH;
    auto func = [req](ebbrt::Future<FileSystem::StatInfo> f) {
      auto &stat_info = f.Get();
      req->result = 0;
      req->statbuf.st_dev = stat_info.stat_dev;
      req->statbuf.st_ino = stat_info.stat_ino;
      req->statbuf.st_mode = stat_info.stat_mode;
      req->statbuf.st_nlink = stat_info.stat_nlink;
      req->statbuf.st_uid = stat_info.stat_uid;
      req->statbuf.st_gid = stat_info.stat_gid;
      req->statbuf.st_rdev = stat_info.stat_rdev;
      req->statbuf.st_size = stat_info.stat_size;
      req->statbuf.st_atime = stat_info.stat_atime;
      req->statbuf.st_mtime = stat_info.stat_mtime;
      req->statbuf.st_ctime = stat_info.stat_ctime;
      req->ptr = &req->statbuf;
      if (req->cb) {
        auto cb_queue = static_cast<std::queue<std::function<void()> > *>(
            req->loop->callbacks);
        cb_queue->emplace([req]() {
          uv__req_unregister(req->loop, req);
          req->cb(req);
        });
        activate_loop(req->loop);
      } else {
        uv__req_unregister(req->loop, req);
      }
    };
    auto f = node_fs_ebb->Stat(path);
    if (cb) {
      f.Then(std::move(func));
    } else {
      func(f.Block());
    }
    return 0;
  }
}

extern "C" int uv_fs_lstat(uv_loop_t *loop, uv_fs_t *req, const char *path,
                           uv_fs_cb cb) {
  if (node_script) {
    EBBRT_UNIMPLEMENTED();
  } else {
    FS_INIT(LSTAT);
    FS_PATH;
    auto func = [req](ebbrt::Future<FileSystem::StatInfo> f) {
      auto &stat_info = f.Get();
      req->result = 0;
      req->statbuf.st_dev = stat_info.stat_dev;
      req->statbuf.st_ino = stat_info.stat_ino;
      req->statbuf.st_mode = stat_info.stat_mode;
      req->statbuf.st_nlink = stat_info.stat_nlink;
      req->statbuf.st_uid = stat_info.stat_uid;
      req->statbuf.st_gid = stat_info.stat_gid;
      req->statbuf.st_rdev = stat_info.stat_rdev;
      req->statbuf.st_size = stat_info.stat_size;
      req->statbuf.st_atime = stat_info.stat_atime;
      req->statbuf.st_mtime = stat_info.stat_mtime;
      req->statbuf.st_ctime = stat_info.stat_ctime;
      req->ptr = &req->statbuf;
      if (req->cb) {
        auto cb_queue = static_cast<std::queue<std::function<void()> > *>(
            req->loop->callbacks);
        cb_queue->emplace([req]() {
          uv__req_unregister(req->loop, req);
          req->cb(req);
        });
        activate_loop(req->loop);
      } else {
        uv__req_unregister(req->loop, req);
      }
    };
    auto f = node_fs_ebb->LStat(path);
    if (cb) {
      f.Then(std::move(func));
    } else {
      func(f.Block());
    }
    return 0;
  }
}

extern "C" int uv_fs_fstat(uv_loop_t *loop, uv_fs_t *req, uv_file fd,
                           uv_fs_cb cb) {
  if (node_script) {
    EBBRT_UNIMPLEMENTED();
  } else {
    FS_INIT(FSTAT);
    auto func = [req](ebbrt::Future<FileSystem::StatInfo> f) {
      auto &stat_info = f.Get();
      req->result = 0;
      req->statbuf.st_dev = stat_info.stat_dev;
      req->statbuf.st_ino = stat_info.stat_ino;
      req->statbuf.st_mode = stat_info.stat_mode;
      req->statbuf.st_nlink = stat_info.stat_nlink;
      req->statbuf.st_uid = stat_info.stat_uid;
      req->statbuf.st_gid = stat_info.stat_gid;
      req->statbuf.st_rdev = stat_info.stat_rdev;
      req->statbuf.st_size = stat_info.stat_size;
      req->statbuf.st_atime = stat_info.stat_atime;
      req->statbuf.st_mtime = stat_info.stat_mtime;
      req->statbuf.st_ctime = stat_info.stat_ctime;
      req->ptr = &req->statbuf;
      if (req->cb) {
        auto cb_queue = static_cast<std::queue<std::function<void()> > *>(
            req->loop->callbacks);
        cb_queue->emplace([req]() {
          uv__req_unregister(req->loop, req);
          req->cb(req);
        });
        activate_loop(req->loop);
      } else {
        uv__req_unregister(req->loop, req);
      }
    };
    auto f = node_fs_ebb->FStat(fd);
    if (cb) {
      f.Then(std::move(func));
    } else {
      func(f.Block());
    }
    return 0;
  }
}

extern "C" int uv_fs_rename(uv_loop_t *loop, uv_fs_t *req, const char *path,
                            const char *new_path, uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_fsync(uv_loop_t *loop, uv_fs_t *req, uv_file fd,
                           uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_fdatasync(uv_loop_t *loop, uv_fs_t *req, uv_file fd,
                               uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_ftruncate(uv_loop_t *loop, uv_fs_t *req, uv_file fd,
                               int64_t offset, uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_sendfile(uv_loop_t *loop, uv_fs_t *req, uv_file fd_out,
                              uv_file fd_in, int64_t in_offset, size_t length,
                              uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_chmod(uv_loop_t *loop, uv_fs_t *req, const char *path,
                           int mode, uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_fchmod(uv_loop_t *loop, uv_fs_t *req, uv_file fd, int mode,
                            uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_utime(uv_loop_t *loop, uv_fs_t *req, const char *path,
                           double atime, double mtime, uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_futime(uv_loop_t *loop, uv_fs_t *req, uv_file fd,
                            double atime, double mtime, uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" void uv_process_fs_req(uv_loop_t *loop, uv_fs_t *req) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" void uv_fs_req_cleanup(uv_fs_t *req) {}

extern "C" int uv_fs_event_init(uv_loop_t *loop, uv_fs_event_t *handle,
                                const char *filename, uv_fs_event_cb cb,
                                int flags) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" uv_handle_type uv_guess_handle(uv_file file) {
  if (file == 0 || file == 1 || file == 2) {
    return UV_FILE;
  }

  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_is_active(const uv_handle_t *handle) {
  EBBRT_UNIMPLEMENTED();
}

namespace {
void uv__tcp_close(uv_tcp_t *handle, uv_close_cb cb) {
  // TODO(dschatz): This is really tricky, a bunch of outstanding requests could
  // still exist in which case they should be canceled (if possible)
  if (handle->shutdown_req) {
    handle->close_cb = cb;
    return;
  }

  if (handle->pending_writes > 0)
    EBBRT_UNIMPLEMENTED();

  uv_read_stop((uv_stream_t *)handle);
  uv__handle_stop((uv_handle_t *)handle);

  auto accept_queue =
      static_cast<std::queue<ebbrt::NetworkManager::TcpPcb *> *>(
          handle->accepted_queue);

  while (accept_queue && !accept_queue->empty()) {
    auto pcb = accept_queue->front();
    accept_queue->pop();
    delete pcb;
  }

  auto pcb =
      static_cast<ebbrt::NetworkManager::ListeningTcpPcb *>(handle->tcp_pcb);
  delete pcb;
  auto handler = static_cast<UVTcpHandler *>(handle->handler);
  if (handler)
    handler->client_ = nullptr;
  handle->flags &= ~UV_CLOSING;
  handle->flags |= UV_CLOSED;

  uv__handle_unref(handle);
  ngx_queue_remove(&handle->handle_queue);

  auto cb_queue = static_cast<std::queue<std::function<void()> > *>(
      handle->loop->callbacks);

  cb_queue->emplace([handle, cb]() { cb((uv_handle_t *)handle); });
}
}

extern "C" void uv_close(uv_handle_t *handle, uv_close_cb cb) {
  handle->flags |= UV_CLOSING;

  switch (handle->type) {
  case UV_TCP:
    uv__tcp_close((uv_tcp_t *)handle, cb);
    break;
  default:
    EBBRT_UNIMPLEMENTED();
    break;
  }
}

extern "C" int uv_idle_init(uv_loop_t *loop, uv_idle_t *handle) {
  uv__handle_init(loop, (uv_handle_t *)handle, UV_IDLE);
  handle->idle_cb = nullptr;
  return 0;
}

extern "C" int uv_idle_start(uv_idle_t *handle, uv_idle_cb cb) {
  if (uv__is_active(handle))
    return 0;
  if (cb == nullptr)
    return uv__set_artificial_error(handle->loop, UV_EINVAL);
  ngx_queue_insert_head(&handle->loop->idle_handles, &handle->queue);
  handle->idle_cb = cb;
  uv__handle_start(handle);
  return 0;
}

extern "C" int uv_idle_stop(uv_idle_t *handle) {
  if (!uv__is_active(handle))
    return 0;
  ngx_queue_remove(&handle->queue);
  uv__handle_stop(handle);
  return 0;
}

extern "C" int uv_check_init(uv_loop_t *loop, uv_check_t *handle) {
  uv__handle_init(loop, (uv_handle_t *)handle, UV_CHECK);
  handle->check_cb = nullptr;
  return 0;
}

extern "C" int uv_check_start(uv_check_t *handle, uv_check_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_check_stop(uv_check_t *handle) { EBBRT_UNIMPLEMENTED(); }

extern "C" int uv_pipe_init(uv_loop_t *loop, uv_pipe_t *handle, int ipc) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_pipe_bind(uv_pipe_t *handle, const char *name) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" void uv_pipe_connect(uv_connect_t *req, uv_pipe_t *handle,
                                const char *name, uv_connect_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_pipe_open(uv_pipe_t *pipe, uv_file file) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" void uv_tty_reset_mode(void) { EBBRT_UNIMPLEMENTED(); }

extern "C" uv_err_t uv_cwd(char *buffer, size_t size) {
  if (!buffer || !size) {
    return uv__new_artificial_error(UV_EINVAL);
  }

  if (node_script) {
    if (size < 2)
      return uv__new_sys_error(ERANGE);

    buffer[0] = '/';
    buffer[1] = '\0';

    return uv_ok_;
  } else {
    auto f = node_fs_ebb->GetCwd().Block();
    auto &str = f.Get();
    if (size < str.size())
      return uv__new_sys_error(ERANGE);
    strncpy(buffer, str.data(), size);

    return uv_ok_;
  }
}

extern "C" uv_err_t uv_chdir(const char *dir) { EBBRT_UNIMPLEMENTED(); }

extern "C" uv_err_t uv_uptime(double *uptime) {
  auto t = ebbrt::clock::Uptime();
  *uptime = static_cast<double>(t.count()) / 1000000000;
  return uv_ok_;
}

extern "C" uv_err_t uv_resident_set_memory(size_t *rss) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" uv_err_t uv_kill(int pid, int signum) { EBBRT_UNIMPLEMENTED(); }

extern "C" uint64_t uv_hrtime(void) { return ebbrt::clock::Uptime().count(); }

extern "C" uv_err_t uv_get_process_title(char *buffer, size_t size) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" uv_err_t uv_set_process_title(const char *title) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_exepath(char *buffer, size_t *size_ptr) { return 0; }

extern "C" void uv_disable_stdio_inheritance(void) {}

extern "C" char **uv_setup_args(int argc, char **argv) {
  /* TODO(dschatz): Save process_title */
  return argv;
}

extern "C" uv_err_t uv_cpu_info(uv_cpu_info_t **cpu_infos, int *count) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" void uv_free_cpu_info(uv_cpu_info_t *cpu_infos, int count) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" uint64_t uv_get_free_memory(void) { EBBRT_UNIMPLEMENTED(); }

extern "C" uint64_t uv_get_total_memory(void) { EBBRT_UNIMPLEMENTED(); }

extern "C" void uv_loadavg(double avg[3]) { EBBRT_UNIMPLEMENTED(); }

extern "C" uv_err_t uv_interface_addresses(uv_interface_address_t **addresses,
                                           int *count) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" void uv_free_interface_addresses(uv_interface_address_t *addresses,
                                            int count) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_queue_work(uv_loop_t *loop, uv_work_t *req,
                             uv_work_cb work_cb,
                             uv_after_work_cb after_work_cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_listen(uv_stream_t *stream, int backlog,
                         uv_connection_cb cb) {
  int r;

  switch (stream->type) {
  case UV_TCP:
    r = uv_tcp_listen((uv_tcp_t *)stream, backlog, cb);
    break;

  case UV_NAMED_PIPE:
    r = uv_pipe_listen((uv_pipe_t *)stream, backlog, cb);
    break;

  default:
    EBBRT_UNIMPLEMENTED();
    return -1;
  }

  if (r == 0)
    uv__handle_start(stream);

  return r;
}

extern "C" int uv_accept(uv_stream_t *server, uv_stream_t *client) {
  assert(server->loop == client->loop);

  switch (server->type) {
  case UV_TCP:
    assert(server->type == client->type);
    return uv_tcp_accept((uv_tcp_t *)server, (uv_tcp_t *)client);
    break;
  default:
    EBBRT_UNIMPLEMENTED();
    break;
  }
}

extern "C" int uv_is_readable(const uv_stream_t *handle) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_is_writable(const uv_stream_t *handle) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_signal_init(uv_loop_t *loop, uv_signal_t *handle) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_signal_start(uv_signal_t *handle, uv_signal_cb signal_cb,
                               int signum) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_signal_stop(uv_signal_t *handle) { EBBRT_UNIMPLEMENTED(); }

extern "C" int uv_read_start(uv_stream_t *stream, uv_alloc_cb alloc_cb,
                             uv_read_cb read_cb) {
  if (stream->flags & UV_CLOSING)
    return uv__set_sys_error(stream->loop, EINVAL);

  stream->flags |= UV_STREAM_READING;
  stream->read_cb = read_cb;
  stream->alloc_cb = alloc_cb;
  uv__handle_start(stream);

  switch (stream->type) {
  case UV_TCP:
    uv_tcp_enqueue_read((uv_tcp_t *)stream);
    break;
  default:
    EBBRT_UNIMPLEMENTED();
    break;
  }
  return 0;
}

extern "C" int uv_read_stop(uv_stream_t *stream) {
  stream->flags &= ~UV_STREAM_READING;
  stream->read_cb = nullptr;
  stream->read2_cb = nullptr;
  stream->alloc_cb = nullptr;
  return 0;
}

extern "C" int uv_read2_start(uv_stream_t *stream, uv_alloc_cb alloc_cb,
                              uv_read2_cb read_cb) {
  EBBRT_UNIMPLEMENTED();
}

namespace {
void check_shutdown(uv_stream_t *handle) {
  if (handle->pending_writes == 0) {
    auto cb_queue = static_cast<std::queue<std::function<void()> > *>(
        handle->loop->callbacks);
    cb_queue->emplace([handle]() {
      assert(handle->shutdown_req);
      auto req = handle->shutdown_req;
      handle->shutdown_req = nullptr;
      handle->flags &= ~UV_STREAM_SHUTTING;
      uv__req_unregister(handle->loop, req);
      // actually shutdown?
      // switch (handle->type) {
      // case UV_TCP: {
      //   auto tcp_stream = (uv_tcp_t *)handle;
      //   auto pcb =
      // static_cast<ebbrt::NetworkManager::TcpPcb*>(tcp_stream->tcp_pcb);
      //   pcb->ShutdownTx();
      //   break;
      // }
      // default:
      //   EBBRT_UNIMPLEMENTED();
      //   break;
      // }
      handle->flags |= UV_STREAM_SHUT;

      if (req->cb != nullptr)
        req->cb(req, 0);

      if (handle->flags | UV_CLOSING) {
        uv_close((uv_handle_t *)handle, handle->close_cb);
      }
    });
  }
}
}

extern "C" int uv_write(uv_write_t *req, uv_stream_t *handle, uv_buf_t bufs[],
                        int bufcnt, uv_write_cb cb) {
  uv__req_init(handle->loop, req, UV_WRITE);
  req->cb = cb;
  req->handle = handle;
  req->send_handle = nullptr;

  switch (handle->type) {
  case UV_TCP: {
    kassert(bufcnt > 0);
    // TODO(dschatz): zero copy
    auto b = ebbrt::MakeUniqueIOBuf(bufs[0].len);
    memcpy(b->MutData(), bufs[0].base, bufs[0].len);
    for (int i = 1; i < bufcnt; ++i) {
      auto buf = ebbrt::MakeUniqueIOBuf(bufs[i].len);
      memcpy(buf->MutData(), bufs[i].base, bufs[i].len);
      b->PrependChain(std::move(buf));
    }

    auto tcp_stream = (uv_tcp_t *)handle;
    auto handler = static_cast<UVTcpHandler *>(tcp_stream->handler);
    handle->pending_writes++;
    handler->Send(std::move(b));
    handler->Pcb().Output();
    auto cb_queue = static_cast<std::queue<std::function<void()> > *>(
        handle->loop->callbacks);
    cb_queue->emplace([handle, req, cb]() {
      uv__req_unregister(handle->loop, req);
      if (handle->flags & UV_CLOSING) {
        cb(req, UV_ECANCELED);
      } else {
        cb(req, 0);
      }
      handle->pending_writes--;
      if (handle->flags & UV_STREAM_SHUTTING) {
        check_shutdown(handle);
      }
    });
    break;
  }
  default:
    EBBRT_UNIMPLEMENTED();
    break;
  }
  return 0;
}

extern "C" int uv_write2(uv_write_t *req, uv_stream_t *handle, uv_buf_t bufs[],
                         int bufcnt, uv_stream_t *send_handle, uv_write_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_shutdown(uv_shutdown_t *req, uv_stream_t *handle,
                           uv_shutdown_cb cb) {
  if (!(handle->flags & UV_STREAM_WRITABLE) || handle->flags & UV_STREAM_SHUT ||
      handle->flags & UV_STREAM_SHUTTING || handle->flags & UV_CLOSED ||
      handle->flags & UV_CLOSING) {
    uv__set_artificial_error(handle->loop, UV_ENOTCONN);
    return -1;
  }

  uv__req_init(handle->loop, req, UV_SHUTDOWN);
  req->handle = handle;
  req->cb = cb;
  handle->shutdown_req = req;
  handle->flags |= UV_STREAM_SHUTTING;

  check_shutdown(handle);

  return 0;
}

static int uv__timer_cmp(const uv_timer_t *a, const uv_timer_t *b) {
  if (a->timeout < b->timeout)
    return -1;
  if (a->timeout > b->timeout)
    return 1;
  /*
   *  compare start_id when both has the same timeout. start_id is
   *  allocated with loop->timer_counter in uv_timer_start().
   */
  if (a->start_id < b->start_id)
    return -1;
  if (a->start_id > b->start_id)
    return 1;
  return 0;
}

RB_GENERATE_STATIC(uv__timers, uv_timer_s, tree_entry, uv__timer_cmp)

extern "C" int uv_timer_init(uv_loop_t *loop, uv_timer_t *handle) {
  uv__handle_init(loop, (uv_handle_t *)handle, UV_TIMER);
  handle->timer_cb = NULL;
  handle->repeat = 0;

  return 0;
}

extern "C" int uv_timer_start(uv_timer_t *handle, uv_timer_cb cb,
                              uint64_t timeout, uint64_t repeat) {
  uint64_t clamped_timeout;

  if (uv__is_active(handle))
    uv_timer_stop(handle);

  clamped_timeout = handle->loop->time + timeout;
  if (clamped_timeout < timeout)
    clamped_timeout = (uint64_t) - 1;

  handle->timer_cb = cb;
  handle->timeout = clamped_timeout;
  handle->repeat = repeat;
  /* start_id is the second index to be compared in uv__timer_cmp() */
  handle->start_id = handle->loop->timer_counter++;

  RB_INSERT(uv__timers, (uv__timers *)&handle->loop->timer_handles, handle);
  uv__handle_start(handle);

  return 0;
}

extern "C" int uv_timer_stop(uv_timer_t *handle) {
  if (!uv__is_active(handle))
    return 0;

  RB_REMOVE(uv__timers, (uv__timers *)&handle->loop->timer_handles, handle);
  uv__handle_stop(handle);

  return 0;
}

extern "C" int uv_timer_again(uv_timer_t *handle) {
  if (handle->timer_cb == NULL)
    return uv__set_artificial_error(handle->loop, UV_EINVAL);

  if (handle->repeat) {
    uv_timer_stop(handle);
    uv_timer_start(handle, handle->timer_cb, handle->repeat, handle->repeat);
  }

  return 0;
}

extern "C" void uv_timer_set_repeat(uv_timer_t *handle, uint64_t repeat) {
  handle->repeat = repeat;
}

extern "C" uint64_t uv_timer_get_repeat(const uv_timer_t *handle) {
  return handle->repeat;
}

extern "C" int uv__next_timeout(const uv_loop_t *loop) {
  const uv_timer_t *handle;
  uint64_t diff;

  /* RB_MIN expects a non-const tree root. That's okay, it doesn't modify it. */
  handle = RB_MIN(uv__timers, (struct uv__timers *)&loop->timer_handles);

  if (handle == NULL)
    return -1; /* block indefinitely */

  if (handle->timeout <= loop->time)
    return 0;

  diff = handle->timeout - loop->time;
  if (diff > INT_MAX)
    diff = INT_MAX;

  return diff;
}

void uv__run_timers(uv_loop_t *loop) {
  uv_timer_t *handle;

  while ((handle = (uv_timer_t *)RB_MIN((uv__timers *)uv__timers,
                                        (uv__timers *)&loop->timer_handles))) {
    if (handle->timeout > loop->time)
      break;

    uv_timer_stop(handle);
    uv_timer_again(handle);
    handle->timer_cb(handle, 0);
  }
}

extern "C" void uv__timer_close(uv_timer_t *handle) { uv_timer_stop(handle); }

extern "C" int uv_tty_init(uv_loop_t *loop, uv_tty_t *handle, uv_file fd,
                           int readable) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_tty_set_mode(uv_tty_t *handle, int mode) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_tty_get_winsize(uv_tty_t *handle, int *width, int *height) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_spawn(uv_loop_t *loop, uv_process_t *handle,
                        uv_process_options_t options) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_process_kill(uv_process_t *handle, int signum) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_udp_init(uv_loop_t *loop, uv_udp_t *handle) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_udp_set_ttl(uv_udp_t *handle, int ttl) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_udp_getsockname(uv_udp_t *handle, struct sockaddr *name,
                                  int *namelen) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_udp_set_membership(uv_udp_t *handle,
                                     const char *multicast_addr,
                                     const char *interface_addr,
                                     uv_membership membership) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_udp_set_multicast_loop(uv_udp_t *handle, int on) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_udp_set_multicast_ttl(uv_udp_t *handle, int ttl) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_udp_set_broadcast(uv_udp_t *handle, int on) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_tcp_init(uv_loop_t *loop, uv_tcp_t *handle) {
  uv__handle_init(loop, (uv_handle_t *)handle, UV_TCP);

  handle->pending_writes = 0;
  handle->shutdown_req = nullptr;
  handle->bind_port = 0;
  handle->tcp_pcb = nullptr;
  handle->handler = nullptr;
  handle->accepted_queue = nullptr;
  return 0;
}

extern "C" int uv_tcp_open(uv_tcp_t *handle, uv_os_sock_t sock) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_tcp_nodelay(uv_tcp_t *handle, int enable) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_tcp_keepalive(uv_tcp_t *handle, int enable,
                                unsigned int delay) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_tcp_simultaneous_accepts(uv_tcp_t *handle, int enable) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_tcp_getsockname(uv_tcp_t *handle, struct sockaddr *name,
                                  int *namelen) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_tcp_getpeername(uv_tcp_t *handle, struct sockaddr *name,
                                  int *namelen) {
  EBBRT_UNIMPLEMENTED();
}

// extern "C" uint16_t htons(uint16_t n) { return __builtin_bswap16(n); }

// extern "C" uint16_t ntohs(uint16_t n) { return htons(n); }

// extern "C" uint32_t htonl(uint32_t n) { return __builtin_bswap32(n); }

/** From FreeBSD and licensed under their license terms */
extern "C" int inet_aton(const char *cp, struct in_addr *addr) {
  u_long parts[4];
  in_addr_t val;
  const char *c;
  char *endptr;
  int gotend, n;

  c = (const char *)cp;
  n = 0;

  /*
  * Run through the string, grabbing numbers until
  * the end of the string, or some error
  */
  gotend = 0;
  while (!gotend) {
    unsigned long l;

    l = strtoul(c, &endptr, 0);

    if (l == ULONG_MAX || (l == 0 && endptr == c))
      return (0);

    val = (in_addr_t)l;

    /*
    * If the whole string is invalid, endptr will equal
    * c.. this way we can make sure someone hasn't
    * gone '.12' or something which would get past
    * the next check.
    */
    if (endptr == c)
      return (0);
    parts[n] = val;
    c = endptr;

    /* Check the next character past the previous number's end */
    switch (*c) {
    case '.':

      /* Make sure we only do 3 dots .. */
      if (n == 3) /* Whoops. Quit. */
        return (0);
      n++;
      c++;
      break;

    case '\0':
      gotend = 1;
      break;

    default:
      if (isspace((unsigned char)*c)) {
        gotend = 1;
        break;
      } else {

        /* Invalid character, then fail. */
        return (0);
      }
    }
  }

  /* Concoct the address according to the number of parts specified. */
  switch (n) {
  case 0: /* a -- 32 bits */

    /*
    * Nothing is necessary here. Overflow checking was
    * already done in strtoul().
    */
    break;
  case 1: /* a.b -- 8.24 bits */
    if (val > 0xffffff || parts[0] > 0xff)
      return (0);
    val |= parts[0] << 24;
    break;

  case 2: /* a.b.c -- 8.8.16 bits */
    if (val > 0xffff || parts[0] > 0xff || parts[1] > 0xff)
      return (0);
    val |= (parts[0] << 24) | (parts[1] << 16);
    break;

  case 3: /* a.b.c.d -- 8.8.8.8 bits */
    if (val > 0xff || parts[0] > 0xff || parts[1] > 0xff || parts[2] > 0xff)
      return (0);
    val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
    break;
  }

  if (addr != NULL)
    addr->s_addr = htonl(val);
  return (1);
}

extern "C" in_addr_t inet_addr(const char *cp) {

  struct in_addr val;

  if (inet_aton(cp, &val))
    return val.s_addr;
  return INADDR_NONE;
}

extern "C" int uv__tcp_bind(uv_tcp_t *handle, struct sockaddr_in addr) {
  if (!(addr.sin_addr.s_addr == 0 ||
        addr.sin_addr.s_addr == inet_addr("127.0.0.1")))
    EBBRT_UNIMPLEMENTED();

  handle->flags |= UV_STREAM_READABLE | UV_STREAM_WRITABLE;
  handle->bind_port = ntohs(addr.sin_port);

  return 0;
}

extern "C" int uv__tcp_bind6(uv_tcp_t *handle, struct sockaddr_in6 addr) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv__udp_bind(uv_udp_t *handle, struct sockaddr_in addr,
                            unsigned flags) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv__udp_bind6(uv_udp_t *handle, struct sockaddr_in6 addr,
                             unsigned flags) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv__tcp_connect(uv_connect_t *req, uv_tcp_t *handle,
                               struct sockaddr_in address, uv_connect_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv__tcp_connect6(uv_connect_t *req, uv_tcp_t *handle,
                                struct sockaddr_in6 address, uv_connect_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv__udp_send(uv_udp_send_t *req, uv_udp_t *handle,
                            uv_buf_t bufs[], int bufcnt,
                            struct sockaddr_in addr, uv_udp_send_cb send_cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv__udp_send6(uv_udp_send_t *req, uv_udp_t *handle,
                             uv_buf_t bufs[], int bufcnt,
                             struct sockaddr_in6 addr, uv_udp_send_cb send_cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv__udp_recv_start(uv_udp_t *handle, uv_alloc_cb alloccb,
                                  uv_udp_recv_cb recv_cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv__udp_recv_stop(uv_udp_t *handle) { EBBRT_UNIMPLEMENTED(); }

extern "C" int uv_getaddrinfo(uv_loop_t *loop, uv_getaddrinfo_t *req,
                              uv_getaddrinfo_cb getaddrinfo_cb,
                              const char *node, const char *service,
                              const struct addrinfo *hints) {
  if (req == NULL || getaddrinfo_cb == NULL ||
      (node == NULL && service == NULL))
    return uv__set_artificial_error(loop, UV_EINVAL);

  uv__req_init(loop, req, UV_GETADDRINFO);
  req->loop = loop;
  req->cb = getaddrinfo_cb;
  req->res = static_cast<struct addrinfo *>(malloc(sizeof(struct addrinfo)));
  req->retcode = 0;

  if (req->res == nullptr) {
    return uv__set_artificial_error(loop, UV_ENOMEM);
  }

  if (strcmp(node, "localhost") != 0)
    EBBRT_UNIMPLEMENTED();

  if (hints->ai_flags != 0)
    EBBRT_UNIMPLEMENTED();
  req->res->ai_flags = 0;

  if (hints->ai_family != AF_UNSPEC)
    EBBRT_UNIMPLEMENTED();
  req->res->ai_family = AF_INET;

  if (hints->ai_socktype != SOCK_STREAM)
    EBBRT_UNIMPLEMENTED();
  req->res->ai_socktype = SOCK_STREAM;

  if (hints->ai_protocol != 0)
    EBBRT_UNIMPLEMENTED();
  req->res->ai_protocol = 0; // ?? not sure what to return

  req->res->ai_addrlen = sizeof(sockaddr_in);

  req->res->ai_addr =
      static_cast<struct sockaddr *>(calloc(1, sizeof(sockaddr_in)));
  if (req->res->ai_addr == nullptr) {
    free(req->res);
    return uv__set_artificial_error(loop, UV_ENOMEM);
  }
  auto addr = reinterpret_cast<sockaddr_in *>(req->res->ai_addr);
  addr->sin_family = AF_INET;
  addr->sin_port = 0;
  uv_inet_pton(AF_INET, "127.0.0.1", &addr->sin_addr.s_addr);

  req->res->ai_canonname = strdup("localhost");
  if (req->res->ai_canonname == nullptr) {
    free(req->res->ai_addr);
    free(req->res);
    return uv__set_artificial_error(loop, UV_ENOMEM);
  }
  req->res->ai_next = nullptr;

  auto cb_queue =
      static_cast<std::queue<std::function<void()> > *>(loop->callbacks);
  cb_queue->emplace([req]() {
    uv__req_unregister(req->loop, req);

    req->cb(req, req->retcode, req->res);
  });

  return 0;
}

extern "C" void uv_freeaddrinfo(struct addrinfo *ai) {
  if (ai) {
    if (ai->ai_addr) {
      free(ai->ai_addr);
    }
    if (ai->ai_canonname) {
      free(ai->ai_canonname);
    }
    free(ai);
  }
}
