#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
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

#define ATTRIBUTE(...) __attribute__((__VA_ARGS__))

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
    if (ret > 0)
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

#if VERBOSE_LEVEL >= 1
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

static constexpr size_t EMPTY = (size_t)(-1);

struct TExeInode {
  /* max uint64_t decimal is 20 digits + '\0' */
  char Inode[21];
  /* major and minor device ids are uint32_t, so
     ist's maximum 8 + 8 hex digits + ':' + '\0'
  */
  char Device[18];
  inline bool Equal(const char *inode, const char *device) const noexcept {
    return strncmp(Inode, inode, sizeof(Inode)) == 0 &&
           strncmp(Device, device, sizeof(Device)) == 0;
  }
  inline bool GetSelfExeInode() noexcept {
    union {
      struct stat statBuf;
      char charBuf[sizeof(struct stat)];
    } u;
    if (stat("/proc/self/exe", &u.statBuf) == -1) {
      PRINT_ERROR_ERRNO("Can't stat /proc/self/exe");
      return false;
    }

    /* Inode looks like 10-based int, Device look like "08:02" */
    snprintf(Inode, sizeof(TExeInode::Inode), "%llu",
             static_cast<unsigned long long>(u.statBuf.st_ino));
    snprintf(Device, sizeof(TExeInode::Device), "%02x:%02x",
             major(u.statBuf.st_dev), minor(u.statBuf.st_dev));
#if VERBOSE_LEVEL >= 1
    /* for debug purposes only, so the output is truncated at sizeof(u.charBuf),
       which is 144UL
    */
    ssize_t ret = readlink("/proc/self/exe", u.charBuf, sizeof(u.charBuf));
    if (ret > 0) {
      size_t nbytes = static_cast<size_t>(ret);
      u.charBuf[nbytes >= sizeof(u.charBuf) ? nbytes - 1 : nbytes] = '\0';
      LOG_PRINTER(
          "TExeInode: /proc/self/exe has inode='%s', device='%s', path='%s'",
          Inode, Device, u.charBuf);
    }
#endif
    return true;
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

  /* Assumption: LOAD segments go one after another in one bunch */
  size_t ExeFirst = 0;
  size_t ExeLast = EMPTY;

private:
  bool inline ProcessLineSelfMaps(char *line, const size_t localPC,
                                  const TExeInode &exeInode) noexcept {
    enum {
      START_STOP_ADDRESS = 0,
      PERMISSIONS = 1,
      OFFSET = 2,
      DEVICE = 3,
      INODE = 4,
      PATHNAME = 5,
      COUNT
    };
    char *columns[COUNT];

    size_t i = 0;
    char *saveptr;
    columns[i++] = strtok_r(line, " ", &saveptr);
    while (i < COUNT && (columns[i] = strtok_r(nullptr, " ", &saveptr)))
      ++i;

    TMapRegion reg;

    /* Address looks like "12345-67890 " */
    char *address = columns[START_STOP_ADDRESS];
    char *next;
    reg.AddressStart = strtoull(address, &next, 16);
    reg.AddressStop = strtoull(next + 1, NULL, 16);
    reg.AddressStartAligned = AlignMeDown(reg.AddressStart);
    reg.AddressStopAligned = AlignMeUp(reg.AddressStop);

    /* Permission flags field looks like "rwxp" */
    char *perm = columns[PERMISSIONS];
    reg.Flags = 0;
    if (perm[0] == 'r')
      reg.Flags |= PROT_READ;
    if (perm[1] == 'w')
      reg.Flags |= PROT_WRITE;
    if (perm[2] == 'x')
      reg.Flags |= PROT_EXEC;

    if ((reg.Flags & PROT_READ) == 0) {
      DEBUG("Section without READ permission [%#lx, %#lx]: skipping",
            reg.AddressStart, reg.AddressStop);
      return true;
    }

    if (exeInode.Equal(columns[INODE], columns[DEVICE])) {
      DEBUG("Found load: [%#lx, %#lx) size: %#lx", reg.AddressStart,
            reg.AddressStop, reg.AddressStop - reg.AddressStart);
      if (reg.AddressStartAligned <= localPC &&
          localPC <= reg.AddressStopAligned) {
        PRINT_ERROR(
            "ElfRemapper source code overlaps with aligned LOAD segment: "
            "%#lx inside [%#lx, %#lx). You MUST use ElfRemapper as DSO.",
            localPC, reg.AddressStartAligned, reg.AddressStopAligned);
        ExeLast = EMPTY;
        return false;
      }
      if (ExeLast == EMPTY)
        ExeFirst = ExeLast = Regions.size();
      else
        ExeLast = Regions.size();
    }
    Regions.push_back(reg);
    return true;
  }

  bool ReadSelfMaps() noexcept {
    /* Read return address of this function (or the one above).
       Frankly, we don't care what address is returned, it only must
       be from our DSO: we check that our code aren't linked in the
       application statically.
    */
    size_t localPC = (size_t)GET_FUNCTION_RETURN_ADDRESS;

    TExeInode exeInode;
    if (!exeInode.GetSelfExeInode())
      return false;

    FILE *input = fopen("/proc/self/maps", "r");
    if (input == nullptr) {
      PRINT_ERROR_ERRNO("ReadSelfMaps: can't open /proc/self/maps");
      return false;
    }
    size_t len = 128;
    char *line = (char *)malloc(len);
    if (line == nullptr) {
      PRINT_ERROR_ERRNO("ReadSelfMaps: can't malloc(%lu)", len);
      return false;
    }
    bool ok = true;
    while (ssize_t read = getline(&line, &len, input)) {
      if (read == -1) {
        if (!feof(input)) {
          PRINT_ERROR_ERRNO("ReadSelfMaps: getline(%p, %p, %p) failed", &line,
                            &len, input);
          ok = false;
        }
        break;
      }
      if (line[read - 1] == '\n')
        line[--read] = '\0';

      if (!ProcessLineSelfMaps(line, localPC, exeInode)) {
        ok = false;
        break;
      }
    }
    free(line);
    fclose(input);
    return ok && (ExeLast != EMPTY);
  }

  void FindHeap() {
    /* We check only one segment next to the .bss */
    size_t brk = (size_t)sbrk(0);

    /* no heap at all ? */
    if (brk <= Regions[ExeLast].AddressStop) {
      DEBUG("No heap found");
      return;
    }

    /* find heap segment and add it to the load segments */
    for (size_t next = ExeLast + 1; next < Regions.size(); ++next) {
      TMapRegion &reg = Regions[next];
      if (brk == reg.AddressStop) {
        /* Add only overlapping heap segment:
           - if ASLR is turned on, heap could be quite far away
           - if dynamic loader is used to start application - heap is
             attached to the dynamic loader LOAD segments (too far).
        */
        if (reg.AddressStartAligned < Regions[ExeLast].AddressStopAligned) {
          DEBUG("Found overlapping heap: [0x%lx, 0x%lx)", reg.AddressStart,
                reg.AddressStop);
          ExeLast = next;
          reg.Flags |= TMapRegion::HEAP;
        }
        break;
      }
    }
  }

public:
  TRemapper() {
    if (!ReadSelfMaps()) {
      DEBUG("Loaded %lu sections, no sections for remapping found",
            Regions.size());
      return;
    }

    FindHeap();
    DEBUG("Loaded %lu sections, remapping %lu", Regions.size(),
          ExeLast - ExeFirst + 1);
  }

  operator bool() const noexcept { return ExeLast != EMPTY; }

  size_t DoRemap(size_t beg, size_t end, size_t addrBeg, size_t addrEnd,
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

    auto remapBack = [&info](size_t i) {
      while (i--) {
        const TRegionInfo &r = info[i];
        if (mremap(r.RemapAddr, r.RemapSize, r.RemapSize,
                   MREMAP_MAYMOVE | MREMAP_FIXED, r.RealAddr) == MAP_FAILED) {
          /* this should never happen, if we have this - everything is very,
           * very bad */
          exit(13);
        }
      }
    };

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
        remapBack(currI);
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
      remapBack(infoSize);
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

  size_t Remap() const noexcept {
    if (ExeLast == EMPTY)
      return 0;

    /* Check that previous mapping doesn't overlap with the first 'Exe' segment.
       Usually the very first mapping is the LOAD segment (.text): first == 0,
       so it should not happen.
    */
    if (ExeFirst != 0 && Regions[ExeFirst - 1].AddressStopAligned >
                             Regions[ExeFirst].AddressStartAligned) {
      PRINT_ERROR(
          "First LOAD segments overlaps with previous mapping "
          "prev=[0x%lx, 0x%lx), first=[0x%lx, 0x%lx)",
          Regions[ExeFirst - 1].AddressStart, Regions[ExeFirst - 1].AddressStop,
          Regions[ExeFirst].AddressStart, Regions[ExeFirst].AddressStop);
      return 0;
    }

    size_t idx = ExeFirst, total = 0;
    while (idx <= ExeLast) {
      size_t beg = idx, end = idx;
      const TMapRegion &reg = Regions[idx++];

      size_t addrBeg = reg.AddressStartAligned;
      size_t addrEnd = reg.AddressStopAligned;
      size_t perm = reg.Flags;
      DEBUG("Remapping [%#lx %#lx) -> [%#lx %#lx)", reg.AddressStart,
            reg.AddressStop, addrBeg, addrEnd);

      /* Overlapping might come over ExeLast */
      while (idx < Regions.size()) {
        const TMapRegion &curr = Regions[idx];
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
    for (size_t idx = 0; idx < Regions.size(); ++idx) {
      const TMapRegion &reg = Regions[idx];
      LOG_PRINTER("%lu [0x%lx, 0x%lx) [%lu]", idx, reg.AddressStart,
                  reg.AddressStop, reg.Flags);
      if (ExeFirst <= idx && idx <= ExeLast)
        LOG_PRINTER(" [LOAD]");
      LOG_PRINTER("\n");
    }
  }
};

void PrintSelfMaps() {
#if VERBOSE_LEVEL >= 2
  /* for debug purposes only, so no proper error handling is provided */
  int fd = open("/proc/self/maps", O_RDONLY);
  if (fd == -1)
    return;
  char buf[128];
  while (ssize_t bytes = read(fd, buf, sizeof(buf))) {
    ssize_t ret ATTRIBUTE(unused) = write(STDOUT_FILENO, buf, bytes);
  }
  close(fd);
#endif
}

size_t RemapMe(void (*logger)(const char *)) {
  PrintSelfMaps();

  TLogger log(logger);
  TRemapper remapper;
  size_t total = remapper.Remap();

  PrintSelfMaps();
  return total;
}

} /* anonymous namespace */

#ifndef MAKE_LD_PRELOAD_LIBRARY

extern "C" {

/* LTO + symver reliable support is added in GCC 10, workaround for older GCC */
#if __GNUC__ >= 10
ATTRIBUTE(__symver__("remap_text_and_data_to_huge_pages@@ELFREMAPPER_1.0"))
#else
asm(".symver remap_v1,remap_text_and_data_to_huge_pages@@ELFREMAPPER_1.0");
ATTRIBUTE(visibility("default"), externally_visible)
#endif
size_t remap_v1(void (*logger)(const char *)) { return RemapMe(logger); }
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
