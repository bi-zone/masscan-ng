/*
    When program crashes, print backtrace with line numbers
*/
#include "pixie-backtrace.h"
#include "logger.h"
#include "masscan-version.h"
#include "string_s.h"
#include "util-cross.h"

#include <signal.h>

char global_self[512] = "";

#if defined(__GLIBC__) && !defined(WIN32)
#include <dlfcn.h>
#include <execinfo.h>
#include <unistd.h>

#define BACKTRACE_SIZE 256
static void handle_segfault(int sig) {
  void *func[BACKTRACE_SIZE];
  char **symb = NULL;
  int size;

  printf(
      "======================================================================");
  printf(" Segmentation fault: please post this backtrace to:\n");
  printf(" " MASSCAN_REPO_LINK "\n");
  printf(
      "======================================================================");
  size = backtrace(func, BACKTRACE_SIZE);
  symb = backtrace_symbols(func, size);
  while (size > 0) {
    const char *symbol = symb[size - 1];
    char foo[1024];
    printf("%d: [%s]\n", size, symbol);
    if (strstr(symbol, "(+0x")) {
      char *p = strstr(symbol, "(+0x") + 1;
      char *pp = strchr(p, ')');

      snprintf(foo, sizeof(foo), "addr2line -p -i -f -e %s %.*s", global_self,
               (unsigned)(pp - p), p);
      if (system(foo) == -1)
        printf("(addr2line missing)\n");
    } else if (strstr(symbol, "[0x")) {
      char *p = strstr(symbol, "[0x") + 1;
      char *pp = strchr(p, ']');

      snprintf(foo, sizeof(foo), "addr2line -p -i -f -e %s %.*s", global_self,
               (unsigned)(pp - p), p);
      if (system(foo) == -1)
        printf("(addr2line missing)\n");
    }
    size--;
  }
  exit(1);
}

/***************************************************************************
 ***************************************************************************/
void pixie_backtrace_finish(void) {}

/***************************************************************************
 ***************************************************************************/
void pixie_backtrace_init(const char *self) {
  ssize_t x;

  /* Need to get a handle to the currently executing program. On Linux,
   * we'll get this with /proc/self/exe, but on other platforms, we may
   * need to do other things */
  /* TODO: should we use readlink() to get the actual filename? */
#if defined(__linux__)
  x = readlink("/proc/self/exe", global_self, sizeof(global_self));
#elif defined(__FreeBSD__)
  x = readlink("/proc/curproc/file", global_self, sizeof(global_self));
#elif defined(__Solaris__)
  x = readlink("/proc/self/path/a.out", global_self, sizeof(global_self));
#else
  x = -1;
#endif

  if (x == -1)
    snprintf(global_self, sizeof(global_self), "%s", self);

  signal(SIGSEGV, handle_segfault);
}
#elif defined(__MINGW32__)

void pixie_backtrace_init(const char *self) {}

#elif defined(WIN32)
#include <Windows.h>

typedef struct _SYMBOL_INFO {
  ULONG SizeOfStruct;
  ULONG TypeIndex; // Type Index of symbol
  ULONG64 Reserved[2];
  ULONG Index;
  ULONG Size;
  ULONG64 ModBase; // Base Address of module containing this symbol
  ULONG Flags;
  ULONG64 Value;   // Value of symbol, ValuePresent should be 1
  ULONG64 Address; // Address of symbol including base address of module
  ULONG Register;  // register holding value or pointer to value
  ULONG Scope;     // scope of the symbol
  ULONG Tag;       // pdb classification
  ULONG NameLen;   // Actual length of name
  ULONG MaxNameLen;
  CHAR Name[1]; // Name of symbol
} SYMBOL_INFO, *PSYMBOL_INFO;

typedef BOOL(NTAPI *FUNC_SymInitialize)(HANDLE hProcess, PCSTR UserSearchPath,
                                        BOOL fInvadeProcess);
typedef BOOL(NTAPI *FUNC_SymFromAddr)(HANDLE hProcess, DWORD64 Address,
                                      PDWORD64 Displacement,
                                      PSYMBOL_INFO Symbol);
typedef WORD(NTAPI *FUNC_RtlCaptureStackBackTrace)(DWORD FramesToSkip,
                                                   DWORD FramesToCapture,
                                                   PVOID *BackTrace,
                                                   PDWORD BackTraceHash);

struct _Dbg {
  FUNC_SymInitialize SymInitialize;
  FUNC_SymFromAddr SymFromAddr;
  FUNC_RtlCaptureStackBackTrace RtlCaptureStackBackTrace;
} Dbg;

void printStack() {
  unsigned int i;
  void *stack[100];
  unsigned short frames;
  SYMBOL_INFO *symbol;
  HANDLE process;

  process = GetCurrentProcess();

  if (Dbg.SymInitialize == NULL)
    return;
  if (Dbg.SymFromAddr == NULL)
    return;
  if (Dbg.RtlCaptureStackBackTrace == NULL)
    return;

  Dbg.SymInitialize(process, NULL, TRUE);

  frames = CaptureStackBackTrace(0, 100, stack, NULL);
  symbol = (SYMBOL_INFO *)calloc(
      offsetof(SYMBOL_INFO, Name) + 256 * sizeof(symbol->Name[0]), 1);
  if (symbol == NULL) {
    printf("Can't print stack. Allocate error\n");
    return;
  }
  symbol->MaxNameLen = 255;
  symbol->SizeOfStruct = sizeof(SYMBOL_INFO);

  for (i = 0; i < frames; i++) {
    Dbg.SymFromAddr(process, (DWORD64)(stack[i]), 0, symbol);
    printf("%u: %s - 0x%0" PRIx64 "\n", frames - i - 1, symbol->Name,
           symbol->Address);
  }

  free(symbol);
}

static void handle_segfault(int sig) {

  UNUSEDPARM(sig);
  printf(
      "======================================================================");
  printf(" Segmentation fault: please post this backtrace to:\n");
  printf(" " MASSCAN_REPO_LINK "\n");
  printf(
      "======================================================================");
  exit(1);
}

void pixie_backtrace_init(const char *self) {
  self;

  GetModuleFileNameA(NULL, global_self, sizeof(global_self));

  {
    HMODULE h;

    h = LoadLibraryA("DbgHelp.dll");
    if (h != NULL) {
      // printf("found DbgHelp.dll\n");
      Dbg.SymFromAddr = (FUNC_SymFromAddr)GetProcAddress(h, "SymFromAddr");
      if (Dbg.SymFromAddr == NULL) {
        LOG(LEVEL_WARNING, "not found DbgHelp.SymFromAddr\n");
      }
      Dbg.SymInitialize =
          (FUNC_SymInitialize)GetProcAddress(h, "SymInitialize");
      if (Dbg.SymInitialize == NULL) {
        LOG(LEVEL_WARNING, "not found DbgHelp.SymInitialize\n");
      }
    } else {
      LOG(LEVEL_WARNING, "not found DbgHelp.dll\n");
    }
    h = LoadLibraryA("NtDll.dll");
    if (h != NULL) {
      Dbg.RtlCaptureStackBackTrace =
          (FUNC_RtlCaptureStackBackTrace)GetProcAddress(
              h, "RtlCaptureStackBackTrace");
      if (Dbg.RtlCaptureStackBackTrace == NULL) {
        LOG(LEVEL_WARNING, "not found NtDll.RtlCaptureStackBackTrace\n");
      }
    } else {
      LOG(LEVEL_WARNING, "not found NtDll.dll\n");
    }
    // if(GetProcAddress(h, "RtlCaptureStackBackTrace") != NULL);
    // printf("found Dbg.SymInitialize\n");
  }

  // signal(SIGSEGV, handle_segfault);
}
#else
void pixie_backtrace_init(const char *self) {}
#endif
