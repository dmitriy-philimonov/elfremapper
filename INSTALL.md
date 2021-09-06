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