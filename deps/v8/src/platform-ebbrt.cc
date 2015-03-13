//          Copyright Boston University SESA Group 2013 - 2014.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include "platform.h"

#include <malloc.h>
#include <sys/time.h>

#include <cinttypes>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <mutex>
#include <unordered_map>
#include <utility>

#include <ebbrt/Clock.h>
#include <ebbrt/Debug.h>
#include <ebbrt/Fls.h>
#include <ebbrt/PageAllocator.h>
#include <ebbrt/VMem.h>
#include <ebbrt/VMemAllocator.h>

using std::isnan;
using std::isfinite;

#include "v8.h"

#include "codegen.h"

double v8::internal::ceiling(double x) { return ceil(x); }

double v8::internal::modulo(double x, double y) { return fmod(x, y); }

#define UNARY_MATH_FUNCTION(name, generator)                                   \
  static v8::internal::UnaryMathFunction fast_##name##_function = NULL;        \
  void init_fast_##name##_function() { fast_##name##_function = generator; }   \
  double v8::internal::fast_##name(double x) {                                 \
    return (*fast_##name##_function)(x);                                       \
  }

UNARY_MATH_FUNCTION(sin, v8::internal::CreateTranscendentalFunction(
                             v8::internal::TranscendentalCache::SIN))
UNARY_MATH_FUNCTION(cos, v8::internal::CreateTranscendentalFunction(
                             v8::internal::TranscendentalCache::COS))
UNARY_MATH_FUNCTION(tan, v8::internal::CreateTranscendentalFunction(
                             v8::internal::TranscendentalCache::TAN))
UNARY_MATH_FUNCTION(log, v8::internal::CreateTranscendentalFunction(
                             v8::internal::TranscendentalCache::LOG))
UNARY_MATH_FUNCTION(sqrt, v8::internal::CreateSqrtFunction())

#undef MATH_FUNCTION

namespace {
  v8::internal::Mutex* limit_mutex;
}

void v8::internal::OS::SetUp() {
  limit_mutex = CreateMutex();
}

void v8::internal::OS::PostSetUp() {
  init_fast_sin_function();
  init_fast_cos_function();
  init_fast_tan_function();
  init_fast_log_function();
  init_fast_sqrt_function();
}

void v8::internal::OS::TearDown() {
  delete limit_mutex;
}

int v8::internal::OS::GetUserTime(uint32_t *secs, uint32_t *usecs) {
  EBBRT_UNIMPLEMENTED();
  return 0;
}

int64_t v8::internal::OS::Ticks() {
  // gettimeofday has microsecond resolution.
  struct timeval tv;
  if (gettimeofday(&tv, NULL) < 0)
    return 0;
  return (static_cast<int64_t>(tv.tv_sec) * 1000000) + tv.tv_usec;
  // auto micros = std::chrono::duration_cast<std::chrono::microseconds>(
  //     ebbrt::clock::Time());
  // return micros.count();
}

double v8::internal::OS::TimeCurrentMillis() {
  struct timeval tv;
  if (gettimeofday(&tv, NULL) < 0)
    return 0.0;
  return (static_cast<double>(tv.tv_sec) * 1000) +
         (static_cast<double>(tv.tv_usec) / 1000);
  // auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
  //     ebbrt::clock::Time());
  // return millis.count();
}

const char *v8::internal::OS::LocalTimezone(double time) {
  EBBRT_UNIMPLEMENTED();
  return nullptr;
}

double v8::internal::OS::LocalTimeOffset() {
  auto tv = time(nullptr);
  auto local_tv = *localtime(&tv);
  auto gm_tv = *gmtime(&tv);
  return difftime(mktime(&local_tv), mktime(&gm_tv)) * 1000;
}

double v8::internal::OS::DaylightSavingsOffset(double time) {
  if (std::isnan(time))
    return nan_value();
  time_t tv = static_cast<time_t>(floor(time / 1000));
  struct tm *t = localtime(&tv);
  if (t == NULL)
    return nan_value();
  return t->tm_isdst > 0 ? 3600 * 1000 : 0;
}

int v8::internal::OS::GetLastError() {
  EBBRT_UNIMPLEMENTED();
  return 0;
}

FILE *v8::internal::OS::FOpen(const char *path, const char *mode) {
  EBBRT_UNIMPLEMENTED();
  return nullptr;
}

bool v8::internal::OS::Remove(const char *path) {
  EBBRT_UNIMPLEMENTED();
  return false;
}

FILE *v8::internal::OS::OpenTemporaryFile() {
  EBBRT_UNIMPLEMENTED();
  return nullptr;
}

const char *const v8::internal::OS::LogFileOpenMode = "w";

void v8::internal::OS::Print(const char *format, ...) { EBBRT_UNIMPLEMENTED(); }

void v8::internal::OS::VPrint(const char *format, va_list args) {
  EBBRT_UNIMPLEMENTED();
}

void v8::internal::OS::FPrint(FILE *out, const char *format, ...) {
  EBBRT_UNIMPLEMENTED();
}

void v8::internal::OS::VFPrint(FILE *out, const char *format, va_list args) {
  EBBRT_UNIMPLEMENTED();
}

void v8::internal::OS::PrintError(const char *format, ...) {
  EBBRT_UNIMPLEMENTED();
}

void v8::internal::OS::VPrintError(const char *format, va_list args) {
  EBBRT_UNIMPLEMENTED();
}

namespace {
  uintptr_t lowest_ever_allocated = UINTPTR_MAX;
  uintptr_t highest_ever_allocated = 0;

  void UpdateAllocatedSpaceLimits(void* address, int size) {
    ASSERT(limit_mutex != NULL);
    v8::internal::ScopedLock lock(limit_mutex);

    auto addr = reinterpret_cast<uintptr_t>(address);

    lowest_ever_allocated = v8::internal::Min(lowest_ever_allocated, addr);
    highest_ever_allocated = v8::internal::Max(highest_ever_allocated, addr + size);
  }
}

void *v8::internal::OS::Allocate(const size_t requested, size_t *allocated,
                                 bool is_executable) {
  const size_t msize = RoundUp(requested, AllocateAlignment());
  auto mbase = malloc(msize);

  *allocated = msize;
  UpdateAllocatedSpaceLimits(mbase, msize);
  return mbase;
}

void v8::internal::OS::Free(void *address, const size_t size) {
  delete[] static_cast<uint8_t *>(address);
}

intptr_t v8::internal::OS::CommitPageSize() { return ebbrt::pmem::kPageSize; }

void v8::internal::OS::ProtectCode(void *address, const size_t size) {}

void v8::internal::OS::Guard(void *address, const size_t size) {
  EBBRT_UNIMPLEMENTED();
}

void *v8::internal::OS::GetRandomMmapAddr() {
  EBBRT_UNIMPLEMENTED();
  return nullptr;
}

size_t v8::internal::OS::AllocateAlignment() { return 8; }

bool v8::internal::OS::IsOutsideAllocatedSpace(void *pointer) { 
  auto addr = reinterpret_cast<uintptr_t>(pointer);
  return addr < lowest_ever_allocated || addr >= highest_ever_allocated;
}

void v8::internal::OS::Sleep(const int milliseconds) { EBBRT_UNIMPLEMENTED(); }

void v8::internal::OS::Abort() { EBBRT_UNIMPLEMENTED(); }

void v8::internal::OS::DebugBreak() { EBBRT_UNIMPLEMENTED(); }

namespace {
class StdMutexWrapper : public v8::internal::Mutex {
  int Lock() override {
    mut_.lock();
    return 0;
  }

  int Unlock() override {
    mut_.unlock();
    return 0;
  }

  bool TryLock() override { return mut_.try_lock(); }

private:
  std::recursive_mutex mut_;
};
}
v8::internal::Mutex *v8::internal::OS::CreateMutex() {
  return new StdMutexWrapper();
}

namespace {
class EbbRTSemaphore : public v8::internal::Semaphore {
  void Wait() override { EBBRT_UNIMPLEMENTED(); }

  bool Wait(int timeout) override { EBBRT_UNIMPLEMENTED(); }

#ifdef __JA_V8_PROFILE_HACK__
  void Signal() override { return; }
#else
  void Signal() override { EBBRT_UNIMPLEMENTED(); }
#endif
};
}

v8::internal::Semaphore *v8::internal::OS::CreateSemaphore(int count) {
  return new EbbRTSemaphore();
}

v8::internal::Socket *v8::internal::OS::CreateSocket() {
  EBBRT_UNIMPLEMENTED();
}

v8::internal::OS::MemoryMappedFile *
v8::internal::OS::MemoryMappedFile::open(const char *name) {
  EBBRT_UNIMPLEMENTED();
  return nullptr;
}

v8::internal::OS::MemoryMappedFile *
v8::internal::OS::MemoryMappedFile::create(const char *name, int size,
                                           void *initial) {
  EBBRT_UNIMPLEMENTED();
  return nullptr;
}

int v8::internal::OS::SNPrintF(Vector<char> str, const char *format, ...) {
  va_list args;
  va_start(args, format);
  auto result = VSNPrintF(str, format, args);
  va_end(args);
  return result;
}

int v8::internal::OS::VSNPrintF(Vector<char> str, const char *format,
                                va_list args) {
  int n = vsnprintf(str.start(), str.length(), format, args);
  if (n < 0 || n >= str.length()) {
    if (str.length() > 0)
      str[str.length() - 1] = '\0';
    return -1;
  } else {
    return n;
  }
}

char *v8::internal::OS::StrChr(char *str, int c) {
  EBBRT_UNIMPLEMENTED();
  return nullptr;
}

void v8::internal::OS::StrNCpy(Vector<char> dest, const char *src, size_t n) {
  EBBRT_UNIMPLEMENTED();
}

#ifdef __JA_V8_PROFILE_HACK__
void v8::internal::OS::LogSharedLibraryAddresses() { return; }
#else
void v8::internal::OS::LogSharedLibraryAddresses() { EBBRT_UNIMPLEMENTED(); }
#endif

void v8::internal::OS::SignalCodeMovingGC() { EBBRT_UNIMPLEMENTED(); }

uint64_t v8::internal::OS::CpuFeaturesImpliedByPlatform() { return 0; }

intptr_t v8::internal::OS::MaxVirtualMemory() { return 0xFFFFFFFF; }

double v8::internal::OS::nan_value() { return NAN; }

bool v8::internal::OS::ArmUsingHardFloat() {
  EBBRT_UNIMPLEMENTED();
  return false;
}

int v8::internal::OS::ActivationFrameAlignment() { return 16; }

void v8::internal::OS::ReleaseStore(volatile AtomicWord *ptr,
                                    AtomicWord value) {
  EBBRT_UNIMPLEMENTED();
}

int v8::internal::OS::GetCurrentProcessId() {
  EBBRT_UNIMPLEMENTED();
  return 0;
}

#define LARGE_PAGES

#ifndef LARGE_PAGES
namespace {
class V8PFHandler : public ebbrt::VMemAllocator::PageFaultHandler {
  void HandleFault(ebbrt::idt::ExceptionFrame *ef,
                   uintptr_t faulted_address) override {
    auto page = ebbrt::Pfn::Down(faulted_address);
    auto it = mappings_.find(page);
    if (it == mappings_.end()) {
      auto backing_page = ebbrt::page_allocator->Alloc();
      ebbrt::kbugon(backing_page == ebbrt::Pfn::None(),
                    "Failed to allocate page for stack\n");
      ebbrt::vmem::MapMemory(page, backing_page);
      mappings_[page] = backing_page;
    } else {
      ebbrt::vmem::MapMemory(page, it->second);
    }
  }

private:
  std::unordered_map<ebbrt::Pfn, ebbrt::Pfn> mappings_;
};

const constexpr size_t max_phys_mem_allocation = 8 * 1024 * 1024;
}
#endif

v8::internal::VirtualMemory::VirtualMemory() : address_{ nullptr }, size_(0) {}

v8::internal::VirtualMemory::VirtualMemory(size_t size) {
#ifndef LARGE_PAGES
  if (size <= max_phys_mem_allocation) {
#endif
    size_ = size;
    address_ = malloc(size);
#ifndef LARGE_PAGES
  } else {
    auto sz = ebbrt::Pfn::Up(size).val();
    auto pfn = ebbrt::vmem_allocator->Alloc(
        sz, std::unique_ptr<V8PFHandler>(new V8PFHandler()));
    ebbrt::kbugon(pfn == ebbrt::Pfn::None(), "Page allocation failed\n");
    size_ = size;
    address_ = reinterpret_cast<void *>(pfn.ToAddr());
  }
#endif
  UpdateAllocatedSpaceLimits(address_, size_);
  // ebbrt::kprintf("Allocated virtual region %#018" PRIx64 " - %#018" PRIx64
  // "\n",
  //                pfn.ToAddr(), pfn.ToAddr() + size_ - 1);
}

v8::internal::VirtualMemory::VirtualMemory(size_t size, size_t alignment) {
#ifndef LARGE_PAGES
  if (size <= max_phys_mem_allocation) {
#endif
    size_ = size;
    address_ = memalign(alignment, size);
#ifndef LARGE_PAGES
  } else {
    auto sz = ebbrt::Pfn::Up(size).val();
    auto align = ebbrt::Pfn::Up(alignment).val();

    auto pfn = ebbrt::vmem_allocator->Alloc(
                                            sz, align, std::unique_ptr<V8PFHandler>(new V8PFHandler()));
    ebbrt::kbugon(pfn == ebbrt::Pfn::None(), "Page allocation failed\n");

    size_ = size;
    address_ = reinterpret_cast<void *>(pfn.ToAddr());
    ebbrt::kbugon(pfn.ToAddr() % alignment != 0, "Alignment failure\n");
  }
#endif
  UpdateAllocatedSpaceLimits(address_, size_);
  // ebbrt::kprintf("Allocated virtual region %#018" PRIx64 " - %#018" PRIx64
  // "\n",
  //                pfn.ToAddr(), pfn.ToAddr() + size_ - 1);
}

v8::internal::VirtualMemory::~VirtualMemory() {
  if (address_ != nullptr) {
    ebbrt::kprintf("TODO(dschatz): Free Virtual Region\n");
  }
}

bool v8::internal::VirtualMemory::IsReserved() { return address_ != nullptr; }

void v8::internal::VirtualMemory::Reset() { address_ = nullptr; }

bool v8::internal::VirtualMemory::Commit(void *address, size_t size,
                                         bool is_executable) {
  return CommitRegion(address, size, is_executable);
}

bool v8::internal::VirtualMemory::Uncommit(void *address, size_t size) {
  return UncommitRegion(address, size);
}

bool v8::internal::VirtualMemory::Guard(void *address) {
  // TODO(dschatz): Actually implement this
  return true;
}

void *v8::internal::VirtualMemory::ReserveRegion(size_t size) {
  EBBRT_UNIMPLEMENTED();
  return nullptr;
}

bool v8::internal::VirtualMemory::CommitRegion(void *base, size_t size,
                                               bool is_executable) {
  // auto addr = reinterpret_cast<uint64_t>(base);
  // ebbrt::kprintf("Committed virtual region %#018" PRIx64 " - %#018" PRIx64
  // "\n",
  //                addr, addr + size - 1);
  return true;
}

bool v8::internal::VirtualMemory::UncommitRegion(void *base, size_t size) {
  // auto addr = reinterpret_cast<uint64_t>(base);
  // ebbrt::kprintf("TODO(dschatz): Actually uncommit region %#018" PRIx64
  //                " - %#018" PRIx64 "\n",
  //                addr, addr + size - 1);
  return true;
}

bool v8::internal::VirtualMemory::ReleaseRegion(void *base, size_t size) {
  auto addr = reinterpret_cast<uint64_t>(base);
  ebbrt::kprintf("TODO(dschatz): Actually release region %#018" PRIx64
                 " - %#018" PRIx64 "\n",
                 addr, addr + size - 1);
  return true;
}

v8::internal::Thread::Thread(const Options &options) {
  set_name(options.name());
}

v8::internal::Thread::~Thread() {}

void v8::internal::Thread::Start() { ebbrt::kprintf("Unstarted Thread!!!\n"); }

void v8::internal::Thread::set_name(const char *name) {
  strncpy(name_, name, sizeof(name_));
  name_[sizeof(name_) - 1] = '\0';
}

#ifdef __JA_V8_PROFILE_HACK__
void v8::internal::Thread::Join() { return; }
#else
void v8::internal::Thread::Join() { EBBRT_UNIMPLEMENTED(); }
#endif

namespace {
std::mutex key_map_mut;
std::unordered_map<int, __gthread_key_t> key_map
    __attribute__((init_priority(101)));
}

v8::internal::Thread::LocalStorageKey
v8::internal::Thread::CreateThreadLocalKey() {
  std::lock_guard<std::mutex> lock(key_map_mut);
  static_assert(sizeof(int) == sizeof(LocalStorageKey), "Size mismatch");
  __gthread_key_t key;
  ebbrt_gthread_key_create(&key, nullptr);
  LocalStorageKey lskey =
      static_cast<LocalStorageKey>(std::hash<__gthread_key_t>()(key));
  auto p = key_map.emplace(lskey, key);
  ebbrt::kbugon(!p.second, "Key hash collision!\n");
  return lskey;
}

void v8::internal::Thread::DeleteThreadLocalKey(LocalStorageKey key) {
  EBBRT_UNIMPLEMENTED();
}

void *v8::internal::Thread::GetThreadLocal(LocalStorageKey key) {
  std::lock_guard<std::mutex> lock(key_map_mut);
  auto it = key_map.find(key);
  ebbrt::kbugon(it == key_map.end(), "Could not find key in map\n");
  return ebbrt_gthread_getspecific(it->second);
}

void v8::internal::Thread::SetThreadLocal(LocalStorageKey key, void *value) {
  std::lock_guard<std::mutex> lock(key_map_mut);
  auto it = key_map.find(key);
  ebbrt::kbugon(it == key_map.end(), "Could not find key in map\n");
  ebbrt_gthread_setspecific(it->second, value);
}

void v8::internal::Thread::YieldCPU() { EBBRT_UNIMPLEMENTED(); }

bool v8::internal::Socket::SetUp() { EBBRT_UNIMPLEMENTED(); }
int v8::internal::Socket::LastError() { EBBRT_UNIMPLEMENTED(); }

class v8::internal::Sampler::PlatformData {};

v8::internal::Sampler::Sampler(Isolate *isolate, int interval)
    : isolate_(isolate), interval_(interval), profiling_(false), active_(false),
      samples_taken_(0) {
  data_ = new PlatformData;
}

v8::internal::Sampler::~Sampler() { ASSERT(!IsActive()); }

void v8::internal::Sampler::Start() {
  ASSERT(!IsActive());
  SetActive(true);
}

void v8::internal::Sampler::Stop() {
  ASSERT(IsActive());
  SetActive(false);
}
