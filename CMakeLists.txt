CMAKE_MINIMUM_REQUIRED(VERSION 3.9)

PROJECT(elfremapper
    VERSION 1.0
    DESCRIPTION "Remap ELF LOAD segments to huge pages"
)

IF(NOT EXISTS ${CMAKE_BINARY_DIR}/CMakeCache.txt)
  IF(NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)
  ENDIF()
ENDIF()

OPTION(MAKE_LD_PRELOAD_LIBRARY
  "Make remapping in DSO contructor, don't publish the interface"
  OFF
)

IF(MAKE_LD_PRELOAD_LIBRARY)
  STRING(APPEND CMAKE_CXX_FLAGS " -DMAKE_LD_PRELOAD_LIBRARY")
ENDIF()

ADD_LIBRARY(elfremapper SHARED
    src/elfremapper.cc
)

# Linker flags are tested with the default linker GNU ld.bfd.
# 1. GOT/PLT tables must be filled at startup otherwise you get SIGSEGV
# 2. Optionally GNU RELRO protection technology is turned off:
#    a separate 4K page just for 1 local exported function + 34 libc functions
#    looks like a waste of memory. If you need this security - remove it
# 3. Optionally reduced the number of LOAD segments (4 -> 2) by skipping the 
#    separate code segment / readonly segment for constants / etc...
#    Again: waste of memory, but if you need this security feature - remove this
#    linker flag.
#    If you use ld.gold - remove it too.
TARGET_LINK_LIBRARIES(elfremapper
    -Wl,-znow                                             # required (GOT/PLT)
    -Wl,-znorelro                                         # optional (GNU RELRO)
    -Wl,-znoseparate-code                                 # optional (exe. LOAD)
)

IF(NOT MAKE_LD_PRELOAD_LIBRARY)
# Linker version script provides ABI versioning
  TARGET_LINK_LIBRARIES(elfremapper
    -Wl,--version-script=${CMAKE_SOURCE_DIR}/src/abi.map  # required (ABI ver))
  )
ENDIF()

SET_TARGET_PROPERTIES(elfremapper PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER include/elfremapper.h
)

INCLUDE(GNUInstallDirs)
CONFIGURE_FILE(src/elfremapper.pc.in elfremapper.pc @ONLY)
INSTALL(
    TARGETS elfremapper
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
INSTALL(
    FILES ${CMAKE_BINARY_DIR}/elfremapper.pc
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig
)

MESSAGE(STATUS "CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS}")
MESSAGE(STATUS "CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}")