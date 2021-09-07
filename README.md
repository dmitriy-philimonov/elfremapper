# History

The applications usually benefit from remapping .text and .data ELF sections to huge pages. The performance speedup comes from significant reduction of iTLB and dTLB misses. Of course, the approach isn't new. For example, well known implementations at the moment are:
  * libhugetlbfs: https://github.com/libhugetlbfs/libhugetlbfs/blob/master/elflink.c ('remap_segments' function)
  * Google: https://chromium.googlesource.com/chromium/src/+/refs/heads/master/chromeos/hugepage_text/... ('RemapHugetlbText*' functions)
  * Facebook: https://github.com/facebook/hhvm/blob/master/hphp/runtime/base/program-functions.cpp ('HugifyText' function)
  * Intel: https://github.com/intel/iodlr/blob/master/large_page-c/large_page.c ('MoveRegionToLargePages' function)

libhugetlbfs uses huge pages, meanwhile Google/Facebook/Intel rely on transparent huge pages. The approach which is used by libhugetlbfs looks better, since it has less dependency on the particular kernel allocation/defragmentation algorithm, so provides more persistent results.

However, libhugetlbfs has several major drawbacks:
1. A bug with position independent executables (linked with '--pie' parameter): https://github.com/libhugetlbfs/libhugetlbfs/issues/49
2. It might potentially unmap heap segment which immediately follows data segment in popular OS systems (e.g. Linux).
3. It supports remapping of maximum 3 ELF segments.
4. No integration with the target application: it works silently right during the startup.
5. It requires a proper managed hugetlbfs mount point (due to the backward compatibility with older kernels)
6. It requires LOAD segments aligned to a huge page size (e.g.compiled with common-page-size=2M max-page-size=2M)

# Performance

Performance improves significantly for CPU-bound applications with big text/data sections (much more than 2 MB).  The technique was tested on MySQL server (https://github.com/mysql/mysql-server) in Cloud environment. The server consumes about 40-50 large pages (~100 MB). The CPU bound scenarious become faster up to 10% in sysbench OLTP PS/RO (especially for very small x86_64 cloud instances with 1 vCPU and 2 GB RAM). Speedup on AArch64 CPUs is usually much better, however it should be tested in each particular case.

# Implementation

ElfRemapper does the following steps:
1. Read /proc/self/exe symbolic link to figure out the application name
2. Load /proc/self/maps to the memory, filter out LOAD segments using application name
3. mmap private anonymous memory with the size of LOAD segment
4. mremap LOAD segment to the previously mapped memory region
5. mmap private anonymous memory backed with huge pages with fixed address to the region where the original LOAD segment was before mremap
6. copy all the content of LOAD segment to the huge pages
7. unmap old LOAD segment
8. shift the break of heap segment if it overlaps with new huge page allocation
9. in case of errors, mremap old LOAD segment back

Advantages:
1. Support for position independent code (--pie)
2. Heap segment preserved
3. Any number of LOAD segments could be remapped
4. Could be easily integrated to the application code (e.g. using application configuration file to turn on/off the feature)
5. No hugetlbfs is needed (which implies no support for kernels < 2.6.32)
6. Application LOAD segments could have the default alignment (e.g. 4K), the algorithm merges the segments in that case. However, for security reasons it's better to link your application with the 2MB alignment for LOAD segments (see below)

Limitations:
1. Currently works with 2MB huge pages only
2. /proc filesystem is needed
3. Support is provided only for Linux systems (tested for kernels >= 5.4, GCC 10.3.0)
4. The default symbol resolution stops working for "perf" with unstripped ELF files. The workaround is to use perf JIT API (see below)

# Build options

The library could be built in two ways:
* With published API (default): a user must call the API manually from his application.
* Without API (using cmake option `MAKE_LD_PRELOAD_LIBRARY`): as it stands, the functionality is called automatically during the library load, and the main usage is via `LD_PRELOAD` or an application may just link against the library and doesn't do anything else.

The second option might be convenient for the testing/benchmarking purposes, e.g. you want to try the library with your application and you don't want to recompile it.

# Maintenance

Linkage with 2MB alignement for LOAD segments:
* GNU ld.bfd/ld.gold linker
  ```
  -zcommon-page-size=0x200000 -zmax-page-size=0x200000
  ```
* LLVM ld.lld linker
  ```
  -zcommon-page-size=0x200000
  ```

Using perf JIT API:
1. Compile your application with debug symbols (-g)
2. Create symbols map suitable for the perf ($app - application, pid - application pid):
   ```
   nm --numeric-sort --print-size --demangle $app | awk '$4{print $1" "$2" "$4}' | grep -Ee"^0" > /tmp/perf-$pid.map
   ```
3. Run perf tool, it loads symbols automatically from /tmp/perf-$pid.map file

Huge page allocation:
1. The easiest way is to preallocate the necessary amount of huge pages for each NUMA node, e.g. (NUMA0):
   ```
   # echo 64 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
   ```
2. Allocation of the huge pages on the fly using 'overcommit' (if memory defragmentation is too high for the kernel, the huge pages accocation might fail):
   ```
   # echo 64 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_overcommit_hugepages
   ```

Code formatting:
```
$ clang-format-12 -i elfremapper.cc
```

Debugging:
* Turn on verbose mode inside elfremapper.cc: `VERBOSE_LEVEL = 1`
* Recompile the shared object
* All debug messages are going to be written to the logger hook as usual

Want library to be silent? Pass `nullptr` as the logger hook.


# Acknowledgements

Many thanks to:
* Alexey Kopytov
* Alexey Stroganov
* Sergey Glushchenko
* Sergey Vojtovich
* Georgy Kirichenko
