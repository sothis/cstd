PROJECT_NAME	:= cstd

VERSION		:= $(shell ./version)
UNAMEEXISTS	:= $(shell uname > /dev/null 2>&1; echo $$?)
PWDEXISTS	:= $(shell pwd > /dev/null 2>&1; echo $$?)
GCCEXISTS	:= $(shell gcc --version > /dev/null 2>&1; echo $$?)
CLANGEXISTS	:= $(shell clang --version > /dev/null 2>&1; echo $$?)
#ICCEXISTS	:= $(shell icc --version > /dev/null 2>&1; echo $$?)
GITEXISTS	:= $(shell git --version > /dev/null 2>&1; echo $$?)
TAREXISTS	:= $(shell tar --version > /dev/null 2>&1; echo $$?)
BZIP2EXISTS	:= $(shell bzip2 --help > /dev/null 2>&1; echo $$?)

ifeq ($(VERSION),)
$(error can't determine version string)
endif
ifneq ($(PWDEXISTS), 0)
$(error command 'pwd' not found)
endif
ifneq ($(UNAMEEXISTS), 0)
$(error command 'uname' not found)
endif
ifneq ($(GCCEXISTS), 0)
ifneq ($(CLANGEXISTS), 0)
ifneq ($(ICCEXISTS), 0)
$(error neither 'gcc', 'icc' nor 'clang' found)
endif
endif
endif

PLATFORM	:= $(shell uname)
PWD		:= $(shell pwd)

GCC_MAJOR	:= 0
GCC_MINOR	:= 0
ifeq ($(CONF), debug)
	DEBUG		:= Yes
endif
ifeq ($(CONF), release)
	RELEASE		:= Yes
endif
ifeq ($(CLANGEXISTS), 0)
	HAVE_CLANG	:= Yes
endif
ifeq ($(GCCEXISTS), 0)
	HAVE_GCC	:= Yes
endif
ifeq ($(ICCEXISTS), 0)
	HAVE_ICC	:= Yes
endif
ifndef VERBOSE
	VERB		:= -s
endif

ifeq ($(PLATFORM), Linux)
	PLAT_LINUX	:= Yes
	PLATFORM	:= LINUX
	SO_EXT		:= so
else ifeq ($(PLATFORM), OpenBSD)
	PLAT_OPENBSD	:= Yes
	PLATFORM	:= OPENBSD
	SO_EXT		:= so
else ifeq ($(PLATFORM), FreeBSD)
	PLAT_FREEBSD	:= Yes
	PLATFORM	:= FREEBSD
	SO_EXT		:= so
else ifeq ($(PLATFORM), Darwin)
	PLAT_DARWIN	:= Yes
	PLATFORM	:= DARWIN
	SO_EXT		:= dylib
else ifeq ($(PLATFORM), MINGW32_NT-6.1)
	PLAT_WINNT	:= Yes
	PLATFORM	:= WINNT
	SO_EXT		:= dll
	M32		:= Yes
else ifeq ($(PLATFORM), MINGW32_NT-5.1)
	PLAT_WINNT	:= Yes
	PLATFORM	:= WINNT
	SO_EXT		:= dll
	M32		:= Yes
else
$(error unsupported platform: $(PLATFORM))
endif

ifdef HAVE_GCC
ifndef PLAT_WINNT
# TODO: write shellscript in order to get detailed compiler version information
# and advanced testing possibilities (i.e. greater/less than, not just equality)
	GCC_MAJOR	:= $(shell gcc --version 2>&1 | head -n 1 | \
		cut -d' ' -f3 | cut -d'.' -f1)
	GCC_MINOR	:= $(shell gcc --version 2>&1 | head -n 1 | \
		cut -d' ' -f3 | cut -d'.' -f1)
endif
endif


OUTDIR		:= ./build
BUILDDIR	:= $(OUTDIR)/$(TOOLCHAIN)_$(CONF)

################################################################################

LIBRARIES	+= -lpthread

INCLUDES	+= -I.
INCLUDES	+= -I./sdtl/src
INCLUDES	+= -I./sdtl/include

INCLUDES	+= -I./libk/include

INCLUDES	+= -I./src
INCLUDES	+= -I./src/mp
INCLUDES	+= -I./src/socket
INCLUDES	+= -I./src/apps
INCLUDES	+= -I./src/apps/kfile

SRC		+= ./src/version.c
.PHONY: ./src/version.c

SRC		+= ./src/cstd_main.c
SRC		+= ./src/fs.c
SRC		+= ./src/mem.c
SRC		+= ./src/path.c
SRC		+= ./src/proc.c
SRC		+= ./src/string.c
SRC		+= ./src/syslog.c
SRC		+= ./src/file.c
SRC		+= ./src/xio.c
SRC		+= ./src/dir.c

SRC		+= ./src/mp/cond.c
SRC		+= ./src/mp/mutex.c
SRC		+= ./src/mp/queue.c
SRC		+= ./src/mp/thread.c
SRC		+= ./src/mp/workerpool.c

SRC		+= ./src/socket/sio.c


SRC_TEST	+= ./src/apps/test.c
SRC_TEST	+= ./src/apps/kfile/kfile.c
SRC_TEST	+= ./src/apps/kfile/create.c

SRC_CLIENT	+= ./src/apps/client.c
SRC_CLIENT	+= ./sdtl/src/sdtl.c
SRC_CLIENT	+= ./src/apps/sdtl_session.c
SRC_CLIENT	+= ./src/apps/restrans_client.c

SRC_SERVER	+= ./src/apps/server.c
SRC_SERVER	+= ./sdtl/src/sdtl.c
SRC_SERVER	+= ./src/apps/kfile/kfile.c
SRC_SERVER	+= ./src/apps/restrans_srv.c

################################################################################


# preprocessor definitions
ifdef RELEASE
DEFINES		+= -DNDEBUG
endif
DEFINES		+= -D_GNU_SOURCE=1
ifndef PLAT_DARWIN
DEFINES		+= -D_POSIX_C_SOURCE=200809L
endif
ifdef PLAT_WINNT
DEFINES		+= -D_CRT_RAND_S=1
DEFINES		+= -D_WIN32=1
DEFINES		+= -DWIN32=1
endif
DEFINES		+= -D_BSD_SOURCE=1
DEFINES		+= -D_DEFAULT_SOURCE=1
DEFINES		+= -D_FILE_OFFSET_BITS=64
DEFINES		+= -D_LARGEFILE64_SOURCE=1
DEFINES		+= -D_LARGEFILE_SOURCE=1
DEFINES		+= -D_REENTRANT=1
DEFINES		+= -D__$(PLATFORM)__=1
DEFINES		+= -DVERSION='"$(VERSION)"'
DEFINES		+= -D__$(TOOLCHAIN)__=1
DEFINES		+= -D__LIBRARY_BUILD=1

# toolchain configuration
# common flags
CFLAGS		:= -Wall

ifeq ($(TOOLCHAIN), gcc)
ifeq ($(GCC_MAJOR), 4)
CFLAGS		+= -fvisibility=hidden
endif
else
CFLAGS		+= -fvisibility=hidden
endif

ifdef PLAT_DARWIN
CFLAGS		+= -mmacosx-version-min=10.7
endif
ifdef M32
CFLAGS		+= -m32
endif

ifdef DEBUG
CFLAGS		+= -O0 -g
endif

ifdef RELEASE
CFLAGS		+= -O3
ifdef PLAT_WINNT
CFLAGS		+= -flto -fwhole-program
else

ifeq ($(GCC_MAJOR), 4)
ifeq ($(GCC_MINOR), 5)
CFLAGS		+= -flto -fuse-linker-plugin
endif
endif
ifeq ($(GCC_MAJOR), 4)
ifeq ($(GCC_MINOR), 6)
CFLAGS		+= -flto -fuse-linker-plugin
endif
endif

endif
endif #RELEASE
CXXFLAGS	:= $(CFLAGS)

# language dependent flags
ifneq ($(TOOLCHAIN), clang)
CFLAGS		+= -std=c99
endif
ifdef RELEASE
CXXFLAGS	+= -fvisibility-inlines-hidden
endif

LDFLAGS		:= $(CFLAGS)
ifdef PLAT_LINUX
#LDFLAGS		+= -static-libgcc
endif
ifdef PLAT_DARWIN
ARFLAGS		:= -static -o
else
ARFLAGS		:= cru
STRIPFLAGS	:= -s
endif


# determine intermediate object filenames
C_SRC		:= $(filter %.c, $(SRC))
CXX_SRC		:= $(filter %.cpp, $(SRC))

DEPS		:= $(patsubst %.c, $(BUILDDIR)/.obj/%_C.dep, $(C_SRC))
DEPS		+= $(patsubst %.cpp, $(BUILDDIR)/.obj/%_CXX.dep, $(CXX_SRC))

DEPS		+= $(patsubst %.c, $(BUILDDIR)/.obj/%_C.dep, $(SRC_TEST))
DEPS		+= $(patsubst %.c, $(BUILDDIR)/.obj/%_C.dep, $(SRC_CLIENT))
DEPS		+= $(patsubst %.c, $(BUILDDIR)/.obj/%_C.dep, $(SRC_SERVER))

OBJECTS		:= $(patsubst %.c, $(BUILDDIR)/.obj/%_C.o, $(C_SRC))
OBJECTS		+= $(patsubst %.cpp, $(BUILDDIR)/.obj/%_CXX.o, $(CXX_SRC))

OBJECTS_TEST	:= $(patsubst %.c, $(BUILDDIR)/.obj/%_C.o, $(SRC_TEST))
OBJECTS_CLIENT	:= $(patsubst %.c, $(BUILDDIR)/.obj/%_C.o, $(SRC_CLIENT))
OBJECTS_SERVER	:= $(patsubst %.c, $(BUILDDIR)/.obj/%_C.o, $(SRC_SERVER))

# tools
INSTALL		:= install
STRIP		:=  $(CROSS)strip
ifeq ($(TOOLCHAIN), gcc)
	CC		:= $(CROSS)gcc
	CXX		:= $(CROSS)g++
	ifeq ($(CXX_SRC),)
		LD	:= $(CROSS)gcc
	else
		LD	:= $(CROSS)g++
	endif
endif
ifeq ($(TOOLCHAIN), clang)
	CC		:= clang
	CXX		:= clang++
	ifeq ($(CXX_SRC),)
		LD	:= clang
	else
		LD	:= clang++
	endif
endif
ifeq ($(TOOLCHAIN), icc)
	CC		:= icc -ipo -no-prec-div -static-intel -wd,1338
	CXX		:= icc -ipo -no-prec-div -static-intel -wd,1338
	LD		:= icc -ipo -no-prec-div -static-intel \
				-wd,1338,11021,11000,11001,11006
endif

ifdef PLAT_DARWIN
	AR		:= libtool
else
	AR		:= $(CROSS)ar
endif


print_cp	:= echo $(eflags) "COPY "
print_ar	:= echo $(eflags) "AR   "
print_tar	:= echo $(eflags) "TAR  "
print_ld	:= echo $(eflags) "LD   "
print_as	:= echo $(eflags) "ASM  "
print_cc	:= echo $(eflags) "CC   "
print_cxx	:= echo $(eflags) "CXX  "
print_strip	:= echo $(eflags) "STRIP"
print_inst	:= echo $(eflags) "INST "

# targets
all: release

help:
	@echo "following make targets are available:"
	@echo "  help        - print this"
	@echo "  release     - build release version of $(PROJECT_NAME) (*)"
	@echo "  debug       - build debug version of $(PROJECT_NAME)"
	@echo "  clean       - recursively delete the output directory"	\
		"'$(OUTDIR)'"
	@echo ""
	@echo "(*) denotes the default target if none or 'all' is specified"
debug:
	@$(MAKE) CONF=debug $(VERB) -C . all-recursive
release:
	@$(MAKE) CONF=release $(VERB) -C . all-recursive

Release: release
Debug: debug

clean:
	@echo "deleting '$(OUTDIR)'"
	@-rm -rf $(OUTDIR)

all-recursive:
ifdef HAVE_GCC
	$(MAKE) $(VERB) -C . TOOLCHAIN=gcc final-all-recursive
endif
ifdef HAVE_CLANG
	$(MAKE) $(VERB) -C . TOOLCHAIN=clang final-all-recursive
endif
ifdef HAVE_ICC
	$(MAKE) $(VERB) -C . TOOLCHAIN=icc final-all-recursive
endif

final-all-recursive:							\
	$(BUILDDIR)/$(PROJECT_NAME).a					\
	$(BUILDDIR)/$(PROJECT_NAME)_test				\
	$(BUILDDIR)/$(PROJECT_NAME)_client				\
	$(BUILDDIR)/$(PROJECT_NAME)_server

$(BUILDDIR)/$(PROJECT_NAME)_test:					\
	$(OBJECTS_TEST) libk/build/$(TOOLCHAIN)_$(CONF)/libk.a		\
	$(BUILDDIR)/$(PROJECT_NAME).a
	$(print_ld) $(subst $(PWD)/,./,$(abspath $(@)))
	@-mkdir -p $(dir $(@))
ifdef PLAT_DARWIN
	$(LD) -Wl,-rpath,"@loader_path/" $(MACARCHS) $(LDFLAGS)		\
	$(LPATH) $(FRAMEWORKS) -o $(@) $(^) $(LIBRARIES)
else
	@export LD_RUN_PATH='$${ORIGIN}' && $(LD) $(MACARCHS) $(LDFLAGS)\
	$(LPATH) -o $(@) $(^) $(LIBRARIES)
endif

$(BUILDDIR)/$(PROJECT_NAME)_client:					\
	$(OBJECTS_CLIENT) $(BUILDDIR)/$(PROJECT_NAME).a
	$(print_ld) $(subst $(PWD)/,./,$(abspath $(@)))
	@-mkdir -p $(dir $(@))
ifdef PLAT_DARWIN
	$(LD) -Wl,-rpath,"@loader_path/" $(MACARCHS) $(LDFLAGS)		\
	$(LPATH) $(FRAMEWORKS) -o $(@) $(^) $(LIBRARIES)
else
	@export LD_RUN_PATH='$${ORIGIN}' && $(LD) $(MACARCHS) $(LDFLAGS)\
	$(LPATH) -o $(@) $(^) $(LIBRARIES)
endif

$(BUILDDIR)/$(PROJECT_NAME)_server:					\
	$(OBJECTS_SERVER) libk/build/$(TOOLCHAIN)_$(CONF)/libk.a	\
	$(BUILDDIR)/$(PROJECT_NAME).a
	$(print_ld) $(subst $(PWD)/,./,$(abspath $(@)))
	@-mkdir -p $(dir $(@))
ifdef PLAT_DARWIN
	$(LD) -Wl,-rpath,"@loader_path/" $(MACARCHS) $(LDFLAGS)		\
	$(LPATH) $(FRAMEWORKS) -o $(@) $(^) $(LIBRARIES)
else
	@export LD_RUN_PATH='$${ORIGIN}' && $(LD) $(MACARCHS) $(LDFLAGS)\
	$(LPATH) -o $(@) $(^) $(LIBRARIES)
endif

libk/build/$(TOOLCHAIN)_$(CONF)/libk.a:
	$(MAKE) $(VERB) -C libk TOOLCHAIN=$(TOOLCHAIN) $(CONF)

.PHONY: libk/build/$(TOOLCHAIN)_$(CONF)/libk.a

$(BUILDDIR)/.obj/$(PROJECT_NAME).ro: $(OBJECTS)
	@$(print_ld) $(subst $(PWD)/,./,$(abspath $(@)))
	@-mkdir -p $(dir $(@))
	$(LD) -nostdlib -Wl,-r $(MACARCHS) $(LDFLAGS)			\
	$(LPATH) $(FRAMEWORKS) -o $(@) $(^)

$(BUILDDIR)/$(PROJECT_NAME).a: $(BUILDDIR)/.obj/$(PROJECT_NAME).ro
	@$(print_ar) $(subst $(PWD)/,./,$(abspath $(@)))
	@-mkdir -p $(dir $(@))
	@$(AR) $(ARFLAGS) $(@) $(^)

$(BUILDDIR)/.obj/%_C.o: %.c
	$(print_cc) $(subst $(PWD)/,./,$(abspath $(<)))
	-mkdir -p $(dir $(@))
	$(CC) $(CFLAGS) $(DEFINES) $(INCLUDES) -E -M -MT		\
		"$(@) $(@:.o=.dep)" -o $(@:.o=.dep) $(<)
	$(CC) $(CFLAGS) $(MACARCHS) $(DEFINES) $(INCLUDES) -c -o $(@) $(<)

$(BUILDDIR)/.obj/%_C_PIC.o: %.c
	$(print_cc) $(subst $(PWD)/,./,$(abspath $(<)))
	-mkdir -p $(dir $(@))
	$(CC) $(CFLAGS) $(DEFINES) -DPIC $(INCLUDES) -E -M -MT		\
		"$(@) $(@:.o=.dep)" -o $(@:.o=.dep) $(<)
	$(CC) -fPIC $(CFLAGS) -DPIC $(MACARCHS) $(DEFINES)		\
		$(INCLUDES) -c -o $(@) $(<)

$(BUILDDIR)/.obj/%_CXX.o: %.cpp
	$(print_cxx) $(subst $(PWD)/,./,$(abspath $(<)))
	-mkdir -p $(dir $(@))
	$(CXX) $(CXXFLAGS) $(DEFINES) $(INCLUDES) -E -M -MT		\
		"$(@) $(@:.o=.dep)" -o $(@:.o=.dep) $(<)
	$(CXX) $(CXXFLAGS) $(MACARCHS) $(DEFINES) $(INCLUDES) -c -o $(@) $(<)

$(BUILDDIR)/.obj/%_CXX_PIC.o: %.cpp
	$(print_cxx) $(subst $(PWD)/,./,$(abspath $(<)))
	-mkdir -p $(dir $(@))
	$(CXX) $(CXXFLAGS) $(DEFINES) -DPIC $(INCLUDES) -E -M -MT	\
		"$(@) $(@:.o=.dep)" -o $(@:.o=.dep) $(<)
	$(CXX) -fPIC $(CXXFLAGS) $(MACARCHS) $(DEFINES) -DPIC		\
		$(INCLUDES) -c -o $(@) $(<)

-include $(DEPS)
