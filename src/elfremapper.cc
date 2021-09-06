#include <alloca.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <vector>

#ifndef __linux__
#error The code below supports Linux platform only
#endif

#ifndef __GNUC__
#error Tested only with GNU GCC/Clang
#endif

namespace {

#define VERBOSE_LEVEL 0
#define MAX_LOG_LENGTH 256

#define HUGE_PAGE_SIZE 0x200000
#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif
#ifndef MAP_HUGE_2MB
#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
#endif

#define ATTRIBUTE(A) __attribute__((A))

/* API: https://gcc.gnu.org/onlinedocs/gcc/Return-Address.html

NB! For correct behaviour with clang this DSO should be compiled with
"-fno-omit-frame-pointer"
*/
#define GET_FUNCTION_RETURN_ADDRESS                                            \
  __builtin_extract_return_addr(__builtin_return_address(0))

class TLogger {
private:
  using THook = void (*)(const char *);
  static THook LoggerHook;

public:
  TLogger(THook logger) { LoggerHook = logger; }
  ~TLogger() { LoggerHook = nullptr; }
  ATTRIBUTE(format(printf, 1, 2))
  static inline int SendMsg(const char *format, ...) {
    if (LoggerHook == nullptr)
      return -1;

    char msg[MAX_LOG_LENGTH];

    va_list args;
    va_start(args, format);
    int ret = vsnprintf(msg, sizeof(msg), format, args);
    va_end(args);
    if (ret < 0)
      return ret;

    size_t size = static_cast<size_t>(ret);
    if (size >= sizeof(msg)) {
      msg[sizeof(msg) - 1] = '\0';
    }
    LoggerHook(msg);
    return ret;
  }
};
TLogger::THook TLogger::LoggerHook = nullptr;

#define LOG_PRINTER(...) TLogger::SendMsg(__VA_ARGS__)
#define PRINT_ERROR(...) LOG_PRINTER(__VA_ARGS__)
#define PRINT_ERROR_ERRNO_IMPL(ERRNO, FORMAT, ...)                             \
  do {                                                                         \
    char buf[256];                                                             \
    const char *msg = strerror_r(ERRNO, buf, sizeof(buf));                     \
    LOG_PRINTER(FORMAT ": %s", ##__VA_ARGS__, msg);                            \
  } while (0)
#define PRINT_ERROR_ERRNO(FORMAT, ...)                                         \
  PRINT_ERROR_ERRNO_IMPL(errno, FORMAT, ##__VA_ARGS__)

#if VERBOSE_LEVEL == 1
#define DEBUG(...) LOG_PRINTER(__VA_ARGS__)
#else
#define DEBUG(...)
#endif

static inline size_t AlignMeDown(size_t addr) {
  return addr & ~(HUGE_PAGE_SIZE - 1);
}

static inline size_t AlignMeUp(size_t addr) {
  return (addr + HUGE_PAGE_SIZE - 1) & ~(HUGE_PAGE_SIZE - 1);
}

struct TStringBuf {
  void Split(TStringBuf *cols, size_t count) const {
    uint32_t coll = 0;
    char *line = Data, *const end = Data + Len;
    for (char *start = line; start < end && coll < count; ++start) {
      if (*start != ' ')
        continue;

      TStringBuf &curr = cols[coll++];
      curr.Len = start - line;
      curr.Data = line;
      while (++start < end && *start == ' ')
        ;
      line = start;
    }
    if (coll < count) {
      TStringBuf &finalCol = cols[coll];
      finalCol.Len = end - line;
      finalCol.Data = line;
    }
  }
  bool operator==(const TStringBuf &rhs) const noexcept {
    if (Len != rhs.Len)
      return false;
    return memcmp(Data, rhs.Data, Len) == 0;
  }

  size_t Len;
  char *Data;
};

class TFileReader {
private:
  FILE *Input;
  size_t Len;
  char *Line;

public:
  TFileReader(const char *fileName)
      : Input(fopen(fileName, "r")), Len(128), Line(nullptr) {
    if (Input == nullptr) {
      PRINT_ERROR_ERRNO("TFileReader: fopen(%s,'r') failed", fileName);
      destroy();
    }
    if ((Line = (char *)malloc(Len)) == nullptr) {
      PRINT_ERROR_ERRNO("TFileReader: malloc(%lu) failed", Len);
      destroy();
    }
  }
  void destroy() {
    if (Line) {
      free(Line);
      Line = nullptr;
    }
    if (Input) {
      fclose(Input);
      Input = nullptr;
    }
  }

  ~TFileReader() { destroy(); }

  bool IsOk() const noexcept { return Input != nullptr; }

  operator bool() const noexcept { return IsOk(); }

  bool Read(TStringBuf &out) {
    while (ssize_t read = getline(&Line, &Len, Input)) {
      if (read == -1) {
        destroy();
        return false;
      }
      if (Line[read - 1] == '\n')
        --read;
      out.Len = read;
      out.Data = Line;
      return true;
    }
    return false;
  }
};

class TLinkResolver {
private:
  size_t Len;
  char *Data;

public:
  TLinkResolver() : Len(128), Data((char *)calloc(1, Len)) {}
  ~TLinkResolver() { free(Data); }
  bool Resolve(const char *path, TStringBuf &out) {
    if (Data == nullptr)
      return false;
    ssize_t ret = 0;
    while ((ret = readlink(path, Data, Len)) != -1) {
      if ((size_t)ret < Len) {
        out.Data = Data;
        out.Len = strlen(Data);
        return true;
      }
      Len <<= 1;
      if ((Data = (char *)realloc(Data, Len)) == nullptr) {
        PRINT_ERROR_ERRNO("TLinkResolver: realloc(%p,%lu) failed", Data, Len);
        return false;
      }
      memset(Data, 0, Len);
    }
    PRINT_ERROR_ERRNO("TLinkResolver: readlink(%s) failed", path);
    return false;
  }
};

struct TMapRegion {
  size_t AddressStart;
  size_t AddressStop;
  size_t AddressStartAligned;
  size_t AddressStopAligned;
  size_t Flags;

  /* Flags mask, the value is passed to the "prot" mmap parameter,
     since "prot" has type int, we use major bits for our needs.
  */
  static constexpr size_t HEAP = 0x100000000ULL;
};

class TRemapper {
private:
  std::vector<TMapRegion> Regions;
  std::vector<uint32_t> Exe;

private:
  bool ReadSelfMaps() noexcept {
    /* Read return address of this function (or the one above).
       Frankly, we don't care what address is returned, it only must
       be from our DSO: we check that our code aren't linked in the
       application statically.
    */
    size_t localPC = (size_t)GET_FUNCTION_RETURN_ADDRESS;

    TLinkResolver resolver;
    TStringBuf exe;
    if (!resolver.Resolve("/proc/self/exe", exe))
      return false;

    enum {
      START_STOP_ADDRESS = 0,
      PERMISSIONS = 1,
      OFFSET = 2,
      DEVICE = 3,
      INODE = 4,
      PATHNAME = 5,
      COUNT
    };

    TFileReader reader("/proc/self/maps");
    TStringBuf line;
    TStringBuf columns[COUNT] = {};
    while (reader.Read(line)) {
      line.Split(columns, COUNT);

      TMapRegion reg;

      /* Address looks like "12345-67890 " */
      TStringBuf &address = columns[START_STOP_ADDRESS];
      char *next;
      reg.AddressStart = strtoull(address.Data, &next, 16);
      reg.AddressStop = strtoull(next + 1, NULL, 16);
      reg.AddressStartAligned = AlignMeDown(reg.AddressStart);
      reg.AddressStopAligned = AlignMeUp(reg.AddressStop);

      /* Permission flags field looks like "rwxp" */
      TStringBuf &perm = columns[PERMISSIONS];
      reg.Flags = 0;
      if (perm.Data[0] == 'r')
        reg.Flags |= PROT_READ;
      if (perm.Data[1] == 'w')
        reg.Flags |= PROT_WRITE;
      if (perm.Data[2] == 'x')
        reg.Flags |= PROT_EXEC;

      if ((reg.Flags & PROT_READ) == 0) {
        DEBUG("Section without READ permission [%#lx, %#lx]: skipping",
              reg.AddressStart, reg.AddressStop);
        continue;
      }

      TStringBuf &pathname = columns[PATHNAME];
      if (pathname == exe) {
        DEBUG("Found load: [%#lx, %#lx)", reg.AddressStart, reg.AddressStop);
        if (reg.AddressStartAligned <= localPC &&
            localPC <= reg.AddressStopAligned) {
          PRINT_ERROR(
              "ElfRemapper source code overlaps with aligned LOAD segment: "
              "%#lx inside [%#lx, %#lx). You MUST use ElfRemapper as DSO.",
              localPC, reg.AddressStartAligned, reg.AddressStopAligned);
          Exe.clear();
          return false;
        }
        Exe.push_back(Regions.size());
      }

      Regions.push_back(reg);
    }
    return true;
  }

  void FindHeap() {
    /* Make sure no heap allocations are done after this line */
    Exe.reserve(Exe.size() + 1);

    /* We check only one segment next to the .bss */
    size_t brk = (size_t)sbrk(0);
    size_t last = Exe.back();

    /* no heap at all ? */
    if (brk <= Regions[last].AddressStop) {
      DEBUG("No heap found");
      return;
    }

    /* find heap segment and add it to the load segments */
    for (size_t next = last + 1; next < Regions.size(); ++next) {
      TMapRegion &reg = Regions[next];
      if (brk == reg.AddressStop) {
        /* Add only overlapping heap segment:
           - if ASLR is turned on, heap could be quite far away
           - if dynamic loader is used to start application - heap is
             attached to the dynamic loader LOAD segments (too far).
        */
        if (reg.AddressStartAligned < Regions[last].AddressStopAligned) {
          DEBUG("Found overlapping heap: [0x%lx, 0x%lx)", reg.AddressStart,
                reg.AddressStop);
          Exe.push_back(next);
          reg.Flags |= TMapRegion::HEAP;
        }
        break;
      }
    }
  }

public:
  TRemapper() {
    if (ReadSelfMaps()) {
      FindHeap();
      DEBUG("Loaded %lu sections, remapping %lu", Regions.size(), Exe.size());
    }
  }

  operator bool() const noexcept { return !Exe.empty(); }

  uint32_t DoRemap(size_t beg, size_t end, size_t addrBeg, size_t addrEnd,
                   size_t perm) const noexcept {

    /* Idea is pretty simple:
       - move LOAD segments to the different addresses using mremap
       - allocate huge private anonymous mapping right on the old addresses
       - copy LOAD segments content to new pages
       - remove "mremapped" segments if everything is ok, or move them back
         to the old addresses

       Major limitation here is that we can't mremap huge pages - it's still
       forbidden by the kernel (checked with kernel 5.9)
    */

    struct TRegionInfo {
      void *RealAddr;
      void *RemapAddr;
      size_t RemapSize;
    };
    const size_t infoSize = end - beg + 1;
    TRegionInfo *info =
        static_cast<TRegionInfo *>(alloca(sizeof(TRegionInfo) * (infoSize)));

    size_t heapEnd = 0;

    /* Allocate new mapping: here we exploit kernel ability to find a proper
       place in the virtual address space, we don't need this memory at all,
       it will be unmapped silently by kernel during the next mremap calls:
       that's why we drop read/write/execute rights.
    */
    for (size_t idx = beg, i = 0; idx <= end; ++idx, ++i) {
      const TMapRegion &reg = Regions[idx];
      size_t size = reg.AddressStop - reg.AddressStart;
      void *remap =
          mmap(nullptr, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (remap == MAP_FAILED) {
        PRINT_ERROR_ERRNO("Can't find virtual space(mmap(nullptr, %lu, ...))",
                          size);
        /* unmaping previous allocations */
        while (i--) {
          const TRegionInfo &r = info[i];
          munmap(r.RemapAddr, r.RemapSize);
        }
        return 0;
      }
      if (reg.Flags & TMapRegion::HEAP) {
        heapEnd = reg.AddressStop;
      }
      info[i] = {(void *)reg.AddressStart, remap, size};
    }

    /* Save heap segment (if exists): we noticed that if huge mapping is put
       into the addresses where heap segment resides and heap is fully
       occupied by new huge mapping, kernel removes heap totally:
       futher calls to brk/sbrk fail with ENOMEM.

       Careful here: we call sbrk/brk directly - any code around must fully
       avoid heap usage.
    */
    if (heapEnd) {
      /* advance heap break to the addrEnd + 2M */
      size_t addrInc = addrEnd - heapEnd + HUGE_PAGE_SIZE;
      if (sbrk(addrInc) == MAP_FAILED) {
        PRINT_ERROR_ERRNO("Can't save heap(sbrk(%#lx))", addrInc);
        /* Modern memory allocators switch to anonymous mappings if
           heap segment  isn't accessible - so, we continue.
           NB! After further mremap and mmap calls kernel will remove
           heap segment since it's included into new huge mapping.
        */
        heapEnd = 0;
      }
    }

    /* Dangerous part of code (the dark deep abyss - wormwhole):
       - the code below must be run as DSO part
         (overwise you'll get SIGSEGV after mremap)
       - we don't print any errors (no hook: it isn't accessible)
       - we don't use .data/.bss/heap segments
         (mremap kills all addressing consistency: relocations'll be mess)
       - only stack memory is safe

       Notes:
       * Move our LOAD segment to the previously allocated by mmap regions
         (right over these mappings).
       * Cut off first part of heap segment
         (its original size, i.e. before we called sbrk).
       * Here we basically kill our .text/.data/.bss/heap because each
         address inside segment is invalid after they are moved.
    */
    int err = 0;
    for (size_t i = 0; i < infoSize; ++i) {
      const TRegionInfo &ri = info[i];
      void *res = mremap(ri.RealAddr, ri.RemapSize, ri.RemapSize,
                         MREMAP_MAYMOVE | MREMAP_FIXED, ri.RemapAddr);
      if (res == MAP_FAILED) {
        /* we can't print the error right now, just save it */
        err = errno;
        /* anonymous mappings < i are already remapped, >= i are not */
        size_t currI = i;
        /* move back everything what we've managed to mremap away */
        while (i--) {
          const TRegionInfo &r = info[i];
          if (mremap(r.RemapAddr, r.RemapSize, r.RemapSize,
                     MREMAP_MAYMOVE | MREMAP_FIXED, r.RealAddr) == MAP_FAILED) {
            /* this should never happen, if we have this - everything is very,
             * very bad */
            exit(13);
          }
        }
        /* unmap regions which are still anonymously mapped */
        for (i = currI; i < infoSize; ++i) {
          const TRegionInfo &r = info[i];
          munmap(r.RemapAddr, r.RemapSize);
        }
        /* restore heap break back */
        if (heapEnd) {
          if (brk((void *)heapEnd) == -1) {
            /* should not happen, anyway, now it's safe to print error */
            PRINT_ERROR_ERRNO("Can't restore heap back(brk(%#lx))", heapEnd);
            /* we can continue with new break */
          }
        }
        /* everything is reverted back, now we can print error */
        PRINT_ERROR_ERRNO_IMPL(err, "Can't mremap %p -> %p (size=%lu)",
                               ri.RealAddr, ri.RemapAddr, ri.RemapSize);
        return 0;
      }
    }

    /* Now we are in the middle of wormwhole: no .text/.data/.bss at all -
       just DSO code and stack are accessible.

       Actions:
       - allocate huge pages to the addresses where were LOAD segments
         before mremap.
       - further cut off heap segment (if any): now we drop the part which
         was manually added
       - since we write to the huge mapping, it should be writable (at least
         temporarily)
    */
    size_t hugeSize = addrEnd - addrBeg;
    size_t hugePerm = perm | PROT_WRITE;
    void *huge = mmap((void *)addrBeg, hugeSize, hugePerm,
                      MAP_HUGETLB | MAP_HUGE_2MB | MAP_PRIVATE | MAP_ANONYMOUS |
                          MAP_FIXED,
                      -1, 0);
    if (huge == MAP_FAILED) {
      /* can't print error */
      err = errno;
      /* move everything back */
      size_t i = infoSize;
      while (i--) {
        const TRegionInfo &r = info[i];
        if (mremap(r.RemapAddr, r.RemapSize, r.RemapSize,
                   MREMAP_MAYMOVE | MREMAP_FIXED, r.RealAddr) == MAP_FAILED) {
          /* this should never happen, if we have this - everything is very,
           * very bad */
          exit(13);
        }
      }
      /* restore heap break back */
      if (heapEnd) {
        if (brk((void *)heapEnd) == -1) {
          /* should not happen, anyway, now it's safe to print error */
          PRINT_ERROR_ERRNO("Can't restore heap back(brk(%#lx))", heapEnd);
          /* we can continue with new break */
        }
      }
      /* everything is reverted back, now we can print error */
      PRINT_ERROR_ERRNO_IMPL(err,
                             "Hugepages(mmap(%#lx,%#lx,%d,MAP_HUGE_2MB...))",
                             addrBeg, hugeSize, (int)perm);
      return 0;
    }

    /* copy our LOAD segments to the huge pages, then release mappings */
    for (size_t i = 0; i < infoSize; ++i) {
      const TRegionInfo &ri = info[i];
      memcpy(ri.RealAddr, ri.RemapAddr, ri.RemapSize);
      munmap(ri.RemapAddr, ri.RemapSize);
    }

    /* remove PROT_WRITE from the mapping */
    if (perm != hugePerm) {
      if (mprotect(huge, hugeSize, perm) == -1) {
        err = errno;
      }
    }

    /* return 2M from heap segment which we added to save it */
    if (heapEnd) {
      if (brk((void *)addrEnd) == -1) {
        PRINT_ERROR_ERRNO("Can't return heap's 2M to kernel(brk(%#lx))",
                          addrEnd);
        /* we continue */
      }
    }

    /* safe to print errors */
    if (err) {
      PRINT_ERROR_ERRNO_IMPL(err, "Drop write access (mprotect(%p, %#lx, %d))",
                             huge, hugeSize, static_cast<int>(perm));
    }

    hugeSize /= HUGE_PAGE_SIZE;
    DEBUG("Remapped [%#lx, %#lx) to %lu pages (2M)", addrBeg, addrEnd,
          hugeSize);
    return hugeSize;
  }

  uint32_t Remap() const noexcept {
    if (Exe.empty())
      return 0;

    /* Check that previous mapping doesn't overlap with the first 'Exe' segment.
       Usually the very first mapping is the LOAD segment (.text): first == 0,
       so it should not happen.
    */
    uint32_t first = Exe.front();
    if (first != 0 && Regions[first - 1].AddressStopAligned >
                          Regions[first].AddressStartAligned) {
      PRINT_ERROR("First LOAD segments overlaps with previous mapping "
                  "prev=[0x%lx, 0x%lx), first=[0x%lx, 0x%lx)",
                  Regions[first - 1].AddressStart,
                  Regions[first - 1].AddressStop, Regions[first].AddressStart,
                  Regions[first].AddressStop);
      return 0;
    }

    size_t idx = 0, total = 0;
    while (idx < Exe.size()) {
      size_t beg = idx, end = idx;
      const TMapRegion &reg = Regions[Exe[idx++]];

      size_t addrBeg = reg.AddressStartAligned;
      size_t addrEnd = reg.AddressStopAligned;
      size_t perm = reg.Flags;
      DEBUG("Remapping [%#lx %#lx) -> [%#lx %#lx)", reg.AddressStart,
            reg.AddressStop, addrBeg, addrEnd);

      while (idx < Exe.size()) {
        const TMapRegion &curr = Regions[Exe[idx]];
        if (addrEnd <= curr.AddressStartAligned)
          break;

        DEBUG("Merging segment [0x%lx, 0x%lx)", curr.AddressStart,
              curr.AddressStop);
        perm |= curr.Flags;
        addrEnd = curr.AddressStopAligned;
        end = idx++;
      }
      total += DoRemap(beg, end, addrBeg, addrEnd, perm);
    }
    return total;
  }

  void DebugPrint() const noexcept {
    uint32_t exe = 0;
    for (uint32_t idx = 0; idx < Regions.size(); ++idx) {
      const TMapRegion &reg = Regions[idx];
      LOG_PRINTER("%u [0x%lx, 0x%lx) [%lu]", idx, reg.AddressStart,
                  reg.AddressStop, reg.Flags);
      if (exe < Exe.size() && Exe[exe] == idx) {
        LOG_PRINTER(" [LOAD]");
        ++exe;
      }
      LOG_PRINTER("\n");
    }
  }
};

size_t RemapMe(void (*logger)(const char *)) {
  TLogger log(logger);
  TRemapper remapper;
  return remapper.Remap();
}

} /* anonymous namespace */

#ifndef MAKE_LD_PRELOAD_LIBRARY

extern "C" {
size_t remap_v1(void (*logger)(const char *)) { return RemapMe(logger); }
asm(".symver remap_v1,remap_text_and_data_to_huge_pages@@ELFREMAPPER_1.0");
}

#else
namespace {

ATTRIBUTE(constructor)
void InitializeDSO() {
  size_t npages =
      RemapMe([](const char *msg) { fprintf(stderr, "%s\n", msg); });
  if (npages)
    fprintf(stderr, "Successfully remapped code and data to huge pages (%lu)\n",
            npages);
  else
    fprintf(stderr, "Failed to remap code and data to huge pages\n");
}

} /* anonymous namespace */
#endif