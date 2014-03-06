#undef ebbrt

#include <algorithm>
#include <cerrno>
#include <cstring>

#include <ebbrt/Clock.h>
#include <ebbrt/Debug.h>

#include "uv.h"
extern "C" {
#include "uv-common.h"
}

extern "C" int uv_async_init(uv_loop_t *loop, uv_async_t *handle,
                             uv_async_cb async_cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_async_send(uv_async_t *handle) { EBBRT_UNIMPLEMENTED(); }

namespace {
uv_loop_t default_loop_struct;
uv_loop_t *default_loop_ptr;
}

void uv__loop_init(uv_loop_t *loop) {
  ngx_queue_init(&loop->handle_queue);
  ngx_queue_init(&loop->active_reqs);
  ngx_queue_init(&loop->idle_handles);
}

extern "C" uv_loop_t *uv_default_loop(void) {
  if (!default_loop_ptr) {
    default_loop_ptr = &default_loop_struct;
    uv__loop_init(default_loop_ptr);
  }

  return default_loop_ptr;
}

namespace {
uv_fs_t *fs_req;
size_t read_len;

void uv__run_idle(uv_loop_t *loop) {
  uv_idle_t *h;
  ngx_queue_t *q;
  ngx_queue_foreach(q, &loop->idle_handles) {
    h = ngx_queue_data(q, uv_idle_t, queue);
    h->idle_cb(h, 0);
  }
}
}

extern "C" int uv_run(uv_loop_t *loop, uv_run_mode mode) {
  while (1) {
    uv__run_idle(loop);
    if (!fs_req)
      EBBRT_UNIMPLEMENTED();

    if (fs_req->file != 0)
      EBBRT_UNIMPLEMENTED();

    const char script[] = "console.log(\"Hello World\");";
    auto script_len = strlen(script);
    if (read_len < script_len) {
      auto len = std::min(script_len, fs_req->len);
      std::strncpy(static_cast<char *>(fs_req->buf), script, len);
      read_len += len;
      fs_req->result = len;
      fs_req->cb(fs_req);
    } else {
      fs_req->result = 0;
      fs_req->cb(fs_req);
      fs_req = nullptr;
    }
  }
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

extern "C" int uv_fs_close(uv_loop_t *loop, uv_fs_t *req, uv_file file,
                           uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_open(uv_loop_t *loop, uv_fs_t *req, const char *path,
                          int flags, int mod, uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_read(uv_loop_t *loop, uv_fs_t *req, uv_file fd, void *buf,
                          size_t length, int64_t offset, uv_fs_cb cb) {
  req->type = UV_FS;
  req->fs_type = UV_FS_READ;
  req->loop = loop;
  req->cb = cb;
  req->result = 0;
  req->ptr = nullptr;
  req->path = nullptr;
  req->file = fd;
  req->buf = buf;
  req->len = length;
  req->offset = offset;

  if (!cb)
    EBBRT_UNIMPLEMENTED();

  fs_req = req;

  return 0;
}

extern "C" int uv_fs_unlink(uv_loop_t *loop, uv_fs_t *req, const char *path,
                            uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_write(uv_loop_t *loop, uv_fs_t *req, uv_file fd, void *buf,
                           size_t length, int64_t offset, uv_fs_cb cb) {
  if (fd == 1 && !cb) {
    ebbrt::kprintf("%.*s", length, static_cast<const char *>(buf));
    return 0;
  } else {
    EBBRT_UNIMPLEMENTED();
  }
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
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_lstat(uv_loop_t *loop, uv_fs_t *req, const char *path,
                           uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_fs_fstat(uv_loop_t *loop, uv_fs_t *req, uv_file fd,
                           uv_fs_cb cb) {
  EBBRT_UNIMPLEMENTED();
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

extern "C" void uv_close(uv_handle_t *handle, uv_close_cb cb) {
  EBBRT_UNIMPLEMENTED();
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

extern "C" int uv_check_init(uv_loop_t *loop, uv_check_t *handle) { return 0; }

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

  if (size < 2)
    return uv__new_sys_error(ERANGE);

  buffer[0] = '/';
  buffer[1] = '\0';

  return uv_ok_;
}

extern "C" uv_err_t uv_chdir(const char *dir) { EBBRT_UNIMPLEMENTED(); }

extern "C" uv_err_t uv_uptime(double *uptime) {
  auto t = ebbrt::clock::Time();
  *uptime = static_cast<double>(t.count()) / 1000000000;
  return uv_ok_;
}

extern "C" uv_err_t uv_resident_set_memory(size_t *rss) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" uv_err_t uv_kill(int pid, int signum) { EBBRT_UNIMPLEMENTED(); }

extern "C" uint64_t uv_hrtime(void) { EBBRT_UNIMPLEMENTED(); }

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
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_accept(uv_stream_t *server, uv_stream_t *client) {
  EBBRT_UNIMPLEMENTED();
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
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_read_stop(uv_stream_t *stream) { EBBRT_UNIMPLEMENTED(); }

extern "C" int uv_read2_start(uv_stream_t *stream, uv_alloc_cb alloc_cb,
                              uv_read2_cb read_cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_write(uv_write_t *req, uv_stream_t *handle, uv_buf_t bufs[],
                        int bufcnt, uv_write_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_write2(uv_write_t *req, uv_stream_t *handle, uv_buf_t bufs[],
                         int bufcnt, uv_stream_t *send_handle, uv_write_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_shutdown(uv_shutdown_t *req, uv_stream_t *handle,
                           uv_shutdown_cb cb) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_timer_init(uv_loop_t *loop, uv_timer_t *handle) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_timer_start(uv_timer_t *handle, uv_timer_cb cb,
                              uint64_t timeout, uint64_t repeat) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" int uv_timer_stop(uv_timer_t *handle) { EBBRT_UNIMPLEMENTED(); }

extern "C" int uv_timer_again(uv_timer_t *handle) { EBBRT_UNIMPLEMENTED(); }

extern "C" void uv_timer_set_repeat(uv_timer_t *handle, uint64_t repeat) {
  EBBRT_UNIMPLEMENTED();
}

extern "C" uint64_t uv_timer_get_repeat(const uv_timer_t *handle) {
  EBBRT_UNIMPLEMENTED();
}

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
  EBBRT_UNIMPLEMENTED();
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

extern "C" uint16_t htons(uint16_t n) {
  return ((n & 0xff) << 8) | ((n & 0xff00) >> 8);
}

extern "C" uint16_t ntohs(uint16_t n) { return htons(n); }

extern "C" in_addr_t inet_addr(const char *cp) { EBBRT_UNIMPLEMENTED(); }

extern "C" int uv__tcp_bind(uv_tcp_t *handle, struct sockaddr_in addr) {
  EBBRT_UNIMPLEMENTED();
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
