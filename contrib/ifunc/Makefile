#
# Copyright (C) ARM Ltd. 2016-2021.  ALL RIGHTS RESERVED.
# See file LICENSE for terms.
#

UCX_PATH = ${HOME}/opt
UCX_FLAGS = -I${UCX_PATH}/include -L${UCX_PATH}/lib -Wl,-rpath,${UCX_PATH}/lib -lucp -lucs

# Don't use -fsanitize=address on dynamic libs, manually add it to *.cpp.
# -O3 creates large code sections in the ifunc dynamic libs.
OPT_FLAGS = -O2 -march=native -Wl,-O1
DBG_FLAGS = -O0 -g3 -fno-omit-frame-pointer -rdynamic

CFLAGS = -Wall -Wextra -pedantic -std=c11 ${OPT_FLAGS}
CXXFLAGS = -Wall -Wextra -pedantic -std=c++17 ${OPT_FLAGS}

SOURCES = $(wildcard *.cpp)
TARGETS = $(SOURCES:.cpp=.x)

LIB_SOURCES = $(wildcard *.c)
LIB_TARGETS = $(LIB_SOURCES:.c=.so)

all: $(TARGETS) $(LIB_TARGETS)

%.x: %.cpp
	g++ $< ${CXXFLAGS} ${UCX_FLAGS} -o $@

%.so: %.c
	gcc ${CFLAGS} -mcmodel=tiny -fPIC -fno-plt -S $<
	./patch_asm.py $(basename $<) < $(basename $<).s > $(basename $<).patched.s
	gcc ${CFLAGS} -mcmodel=tiny -fPIC -fno-plt -shared $(basename $<).patched.s -o $@

clean:
	rm -f *.so *.s *.x
