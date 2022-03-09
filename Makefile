CFLAGS = -Wall -Werror
BCONF = -O2 -ggdb3
DEP := $(shell pkg-config --libs --cflags nix-store)
TARGET := libnix.so

all: build/$(TARGET)

build/$(TARGET): lib/nix.cpp lib/nix.h
	mkdir -pv build
	$(CXX) $(BCONF) $(CFLAGS) $(DEP) -shared -fPIC lib/nix.cpp -o build/libnix.so

build/nixtest: build/$(TARGET) test/main.c
	$(CC) $(BCONF) $(CFLAGS) -I./lib -L./build -lnix test/main.c -o build/nixtest

.PHONY: style test clean
style:
	clang-format --style=file --dry-run -Werror lib/nix.cpp lib/nix.h test/main.c

test: build/nixtest
	@LD_LIBRARY_PATH=${PWD}/build:${LD_LIBRARY_PATH} ./build/nixtest

clean:
	rm -rf build
