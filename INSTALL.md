# Release build

```shell
$ mkdir build && cd build && cmake ..
$ make install # default $DEST_DIR is /usr/local
```

# Debug build

```shell
$ mkdir build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug
$ make install
```

# Build without API

```shell
$ mkdir build && cd build && cmake .. -DMAKE_LD_PRELOAD_LIBRARY=1
$ make install
```

Simple test:
```shell
$ sudo bash -c "echo 10 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
$ LD_PRELOAD=./libelfremapper.so cat /proc/self/maps
```