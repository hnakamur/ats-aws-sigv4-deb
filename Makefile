CC =       cc
LINK =     $(CC)
COV =      llvm-cov
PROFDATA = llvm-profdata

INCS = -Isrc -Idep/aws-sigv4/include
WARNING_FLAGS = -Wall -Wno-unused-value -Wno-unused-function -Wno-nullability-completeness -Wno-expansion-to-defined -Werror=implicit-function-declaration -Werror=incompatible-pointer-types -Wno-format-truncation
COMMON_CFLAGS = $(INCS) -pipe $(WARNING_FLAGS)
COV_FLAGS = -fprofile-instr-generate -fcoverage-mapping

CFLAGS = -O2 -fPIC $(COMMON_CFLAGS) $(shell pkg-config --cflags libsodium)
LDFLAGS = $(shell pkg-config --libs libsodium)

AWS_SIG_V4_HDRS = dep/aws-sigv4/include/sigv4_config_defaults.h \
                  dep/aws-sigv4/include/sigv4.h \
                  dep/aws-sigv4/include/sigv4_internal.h \
                  dep/aws-sigv4/include/sigv4_quicksort.h

AWS_SIG_V4_SRCS = dep/aws-sigv4/sigv4.c \
                  dep/aws-sigv4/sigv4_quicksort.c

AWS_SIG_V4_OBJS = objs/aws-sigv4/sigv4.o \
                  objs/aws-sigv4/sigv4_quicksort.o

MY_HDRS = src/generate_aws_sigv4.h \
          src/sigv4_config.h

MY_OBJS = objs/generate_aws_sigv4.o

OBJS = $(MY_OBJS) $(AWS_SIG_V4_OBJS)

LUA_FILES = atsgenawssigv4.lua \
            genawssigv4.lua

SHLIBS = objs/libgenawssigv4.so

build: $(SHLIBS)

install: $(SHLIBS)
	install -D -t $(DESTDIR)$(PREFIX)/$(MULTILIB)/ $(SHLIBS)
	install -D -t $(DESTDIR)$(PREFIX)/share/luajit-2.1.0-beta3/ $(LUA_FILES)

objs/libgenawssigv4.so: $(OBJS)
	 $(LINK) -o $@ $^ -shared $(LDFLAGS)

format:
	ls src/*.[ch] | xargs clang-format -i -style=file

objs/generate_aws_sigv4.o: src/generate_aws_sigv4.c $(MY_HDRS) $(AWS_SIG_V4_HDRS)
	@mkdir -p objs
	$(CC) -c $(CFLAGS) -o $@ $<

objs/aws-sigv4/sigv4.o: dep/aws-sigv4/sigv4.c $(AWS_SIG_V4_HDRS)
	@mkdir -p objs/aws-sigv4
	$(CC) -c $(CFLAGS) -o $@ $<

objs/aws-sigv4/sigv4_quicksort.o: dep/aws-sigv4/sigv4_quicksort.c $(AWS_SIG_V4_HDRS)
	@mkdir -p objs/aws-sigv4
	$(CC) -c $(CFLAGS) -o $@ $<

clean:
	@rm -rf objs

distclean: clean

.PHONY: install clean distclean
