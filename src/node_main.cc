// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "node.h"

#ifdef _WIN32
int wmain(int argc, wchar_t *wargv[]) {
  // Convert argv to to UTF8
  char** argv = new char*[argc];
  for (int i = 0; i < argc; i++) {
    // Compute the size of the required buffer
    DWORD size = WideCharToMultiByte(CP_UTF8,
                                     0,
                                     wargv[i],
                                     -1,
                                     NULL,
                                     0,
                                     NULL,
                                     NULL);
    if (size == 0) {
      // This should never happen.
      fprintf(stderr, "Could not convert arguments to utf8.");
      exit(1);
    }
    // Do the actual conversion
    argv[i] = new char[size];
    DWORD result = WideCharToMultiByte(CP_UTF8,
                                       0,
                                       wargv[i],
                                       -1,
                                       argv[i],
                                       size,
                                       NULL,
                                       NULL);
    if (result == 0) {
      // This should never happen.
      fprintf(stderr, "Could not convert arguments to utf8.");
      exit(1);
    }
  }
  // Now that conversion is done, we can finally start.
  return node::Start(argc, argv);
}
#elif __ebbrt__
#include <ebbrt/native/Acpi.h>
#include <ebbrt/native/Debug.h>
#include <ebbrt/native/StaticIds.h>
#include <ebbrt/EventManager.h>
#include <ebbrt/native/Cpu.h>

#include "TcpCommand.h"

#include <ebbrt-filesystem/FileSystem.h>
ebbrt::EbbRef<FileSystem> node_fs_ebb;

void AppMain() {

  uint32_t ncores = static_cast<uint32_t>(ebbrt::Cpu::Count());  
  for (uint32_t i = 0; i < ncores; i++) {
    ebbrt::Promise<void> p;
    auto f = p.GetFuture();
    ebbrt::event_manager->SpawnRemote(
      [ncores, i, &p] () mutable {
	// disables turbo boost, thermal control circuit
	ebbrt::msr::Write(IA32_MISC_ENABLE, 0x4000850081);
	// same p state as Linux with performance governor
	ebbrt::msr::Write(IA32_PERF_CTL, 0x1D00);

	uint64_t ii, jj, sum=0, sum2=0;
	for(ii=0;ii<ncores;ii++) {	  
	  for(jj=0;jj<IXGBE_LOG_SIZE;jj++) {
	    sum += ixgbe_logs[ii][jj].Fields.tsc;
	  }
	  
	  uint8_t* ptr = bsendbufs[ii]->MutData();
	  for(jj=0;jj<IXGBE_MAX_DATA_PER_TXD;jj++) {
	    sum2 += ptr[ii];
	  }
	}
	
	ebbrt::kprintf_force("Cpu=%u Sum=%llu Sum2=%llu\n", i, sum, sum2);
	p.SetValue();
      }, i);
    f.Block();
  }
  
  ebbrt::event_manager->SpawnRemote(
    [] () mutable {
      putenv(const_cast<char *>("TZ=EST5EDT4,M3.2.0,M11.1.0"));

      auto id2 = ebbrt::ebb_allocator->AllocateLocal();
      auto tcps = ebbrt::EbbRef<ebbrt::TcpCommand>(id2);
      tcps->Start(5002);
      ebbrt::kprintf_force("TcpCommand server listening on port %d\n", 5002);
  
      /*auto uid = ebbrt::ebb_allocator->AllocateLocal();
	auto udpc = ebbrt::EbbRef<ebbrt::UdpCommand>(uid);
      udpc->Start(6666);
      ebbrt::kprintf("Core %u: UdpCommand server listening on port %d\n", static_cast<uint32_t>(ebbrt::Cpu::GetMine()), 6666);*/
      
      int argc = 0;
      const char *argv[] = { "node" };
      argc += 1;
      auto i =node::Start(argc, const_cast<char **>(argv));
      
      ebbrt::kprintf("Return Code: %d\n", i);
      ebbrt::acpi::PowerOff();
    }, 1);
}
#else
// UNIX
int main(int argc, char *argv[]) {
  return node::Start(argc, argv);
}
#endif
