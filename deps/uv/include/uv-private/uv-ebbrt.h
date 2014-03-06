#ifndef UV_EBBRT_H
#define UV_EBBRT_H

#include "ngx-queue.h"

struct addrinfo {
  void *p;
};

#define AF_INET 2
#define AF_INET6 10

typedef uint16_t sa_family_t;

struct sockaddr {
  sa_family_t sa_family;
  char sa_data[14];
};

typedef unsigned long in_addr_t;

struct in_addr {
  in_addr_t s_addr;
};

struct sockaddr_in {
  sa_family_t sin_family;
  unsigned short sin_port;
  struct in_addr sin_addr;
  char sin_zero[8];
};

struct in6_addr {
  unsigned char s6_addr[16];
};

struct sockaddr_in6 {
  sa_family_t sin6_family;
  uint16_t sin6_port;
  uint32_t sin6_flowinfo;
  struct in6_addr sin6_addr;
  uint32_t sin6_scope_id;
};

#define _SS_MAXSIZE 128
#define _SS_ALIGNSIZE (sizeof(int64_t))

#define _SS_PAD1SIZE (_SS_ALIGNSIZE - sizeof(sa_family_t))
#define _SS_PAD2SIZE                                                           \
  (_SS_MAXSIZE - (sizeof(sa_family_t) + _SS_PAD1SIZE + _SS_ALIGNSIZE))

struct sockaddr_storage {
  sa_family_t ss_family;

  char _ss_pad1[_SS_PAD1SIZE];
  int64_t _ss_align;
  char _ss_pad2[_SS_PAD2SIZE];
};

#define INET6_ADDRSTRLEN 46

uint16_t htons(uint16_t n);
uint16_t ntohs(uint16_t n);

in_addr_t inet_addr(const char *cp);

typedef struct {
  int fd;
} uv__io_t;

typedef struct {
  char *base;
  size_t len;
} uv_buf_t;

typedef struct {
  uint64_t st_dev;
  uint64_t st_ino;
  uint64_t st_mode;
  uint64_t st_nlink;
  uint64_t st_uid;
  uint64_t st_gid;
  uint64_t st_rdev;
  uint64_t st_size;
  uint64_t st_atime;
  uint64_t st_mtime;
  uint64_t st_ctime;
} uv_statbuf_t;

typedef int uv_os_sock_t;

typedef int uv_file;

typedef uint32_t uv_uid_t;

typedef uint32_t uv_gid_t;

typedef struct {
  void *p;
} uv_lib_t;

typedef struct {
  void *p;
} uv_mutex_t;

typedef struct {
  void *p;
} uv_rwlock_t;

typedef struct {
  void *p;
} uv_sem_t;

typedef struct {
  void *p;
} uv_cond_t;

typedef struct {
  void *p;
} uv_barrier_t;

typedef struct {
  void *p;
} uv_once_t;

typedef struct {
  void *p;
} uv_thread_t;

#define UV_REQ_TYPE_PRIVATE /* empty */

#define UV_REQ_PRIVATE_FIELDS /* empty */

#define UV_PRIVATE_REQ_TYPES /* empty */

#define UV_SHUTDOWN_PRIVATE_FIELDS /* empty */

#define UV_HANDLE_PRIVATE_FIELDS                                               \
  int flags;                                                                   \
  uv_handle_t *next_closing;

#define UV_STREAM_PRIVATE_FIELDS /* empty */

#define UV_WRITE_PRIVATE_FIELDS /* empty */

#define UV_TCP_PRIVATE_FIELDS /* empty */

#define UV_CONNECT_PRIVATE_FIELDS /* empty */

#define UV_UDP_PRIVATE_FIELDS uv__io_t io_watcher;

#define UV_UDP_SEND_PRIVATE_FIELDS /* empty */

#define UV_TTY_PRIVATE_FIELDS /* empty */

#define UV_PIPE_PRIVATE_FIELDS /* empty */

#define UV_POLL_PRIVATE_FIELDS /* empty */

#define UV_PREPARE_PRIVATE_FIELDS /* empty */

#define UV_CHECK_PRIVATE_FIELDS /* empty */

#define UV_IDLE_PRIVATE_FIELDS                                                 \
  uv_idle_cb idle_cb;                                                          \
  ngx_queue_t queue;

#define UV_ASYNC_PRIVATE_FIELDS /* empty */

#define UV_TIMER_PRIVATE_FIELDS /* empty */

#define UV_GETADDRINFO_PRIVATE_FIELDS /* empty */

#define UV_PROCESS_PRIVATE_FIELDS /* empty */

#define UV_WORK_PRIVATE_FIELDS /* empty */

#define UV_FS_PRIVATE_FIELDS                                                   \
  uv_file file;                                                                \
  void *buf;                                                                   \
  size_t len;                                                                  \
  int64_t offset;

#define UV_FS_EVENT_PRIVATE_FIELDS /* empty */

#define UV_SIGNAL_PRIVATE_FIELDS /* empty */

#define UV_LOOP_PRIVATE_FIELDS                                                 \
  uint64_t time;                                                               \
  ngx_queue_t idle_handles;

#define UV_DYNAMIC /* empty */

#endif /* UV_EBBRT_H */
