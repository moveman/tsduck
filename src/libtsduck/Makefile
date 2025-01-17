#-----------------------------------------------------------------------------
#
#  TSDuck - The MPEG Transport Stream Toolkit
#  Copyright (c) 2005-2021, Thierry Lelegard
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#  1. Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
#  THE POSSIBILITY OF SUCH DAMAGE.
#
#-----------------------------------------------------------------------------
#
#  Makefile for libtsduck.
#
#-----------------------------------------------------------------------------

OBJSUBDIR = objs-libtsduck

# Some source files are located in subdirectories but should be considered as part of libtsduck.

SKIPDIR := $(if $(findstring darwin,$(shell uname -s | tr A-Z a-z)),linux,mac)
CXXVPATH = $(patsubst ./%,%,$(shell find . -type d ! -name . ! -name windows ! -name $(SKIPDIR)))

# Detect the presence of the Dektec DTAPI.
# Define NODTAPI to compile without Dektec support.
# NODTAPI is automatically defined if no DTAPI is found.

ifeq ($(NODTAPI),)
    ifeq ($(filter-out default headers libs configs,$(MAKECMDGOALS)),)
        DTAPI_OBJECT := $(shell ../../build/dtapi-config.sh --object --download $(if $(M32),--m32,))
        DTAPI_HEADER := $(shell ../../build/dtapi-config.sh --header)
    endif
    ifeq ($(DTAPI_OBJECT)$(DTAPI_HEADER),)
        NODTAPI := true
        CXXFLAGS_INCLUDES += -DTS_NO_DTAPI=1
    else
        CXXFLAGS_INCLUDES += -isystem $(dir $(DTAPI_HEADER))
    endif
endif

# JNI headers (or disable JNI).

JNI_CFLAGS := $(shell ../../build/java-config.sh --cflags)
CXXFLAGS_INCLUDES += $(JNI_CFLAGS)

# Now, we can include the common makefile.

include ../../Makefile.tsduck

# Building the TSDuck library.

default: headers libs configs
	+@$(RECURSE)

# The GEN_HEADERS headers are automatically generated from SRC_HEADERS using BUILD_PROJ_FILES.

GEN_HEADERS = tsduck.h dtv/private/tsRefType.h
SRC_HEADERS = $(filter-out $(GEN_HEADERS),$(wildcard *.h */*.h */*/*.h))
BUILD_PROJ_FILES = $(ROOTDIR)/build/build-project-files.sh

.PHONY: headers
headers: $(GEN_HEADERS)
$(GEN_HEADERS): $(BUILD_PROJ_FILES) $(SRCROOT)/HEADER.txt $(SRC_HEADERS)
	@echo '  [REBUILD] $@'; \
	$(BUILD_PROJ_FILES) $@

# These header files are regenerated and, normally, make should know that they must be
# finished before building tsVersionInfo.o. However, the .dep file contains full paths
# of dependencies and make cannot realize it is the same header files.

$(OBJDIR)/tsduck.o: tsduck.h
$(OBJDIR)/tsStaticReferencesDVB.o: dtv/private/tsRefType.h tsduck.h

# Specific (per-module) compilation options:

$(OBJDIR)/tsAES.o:     CFLAGS_OPTIMIZE = $(CFLAGS_FULLSPEED)
$(OBJDIR)/tsDES.o:     CFLAGS_OPTIMIZE = $(CFLAGS_FULLSPEED)
$(OBJDIR)/tsTDES.o:    CFLAGS_OPTIMIZE = $(CFLAGS_FULLSPEED)
$(OBJDIR)/tsSHA1.o:    CFLAGS_OPTIMIZE = $(CFLAGS_FULLSPEED)
$(OBJDIR)/tsSHA256.o:  CFLAGS_OPTIMIZE = $(CFLAGS_FULLSPEED)
$(OBJDIR)/tsSHA512.o:  CFLAGS_OPTIMIZE = $(CFLAGS_FULLSPEED)
$(OBJDIR)/tsDVBCSA2.o: CFLAGS_OPTIMIZE = $(CFLAGS_FULLSPEED)

# Dektec code (if not empty) is encapsulated into the TSDuck library.

OBJS += $(DTAPI_OBJECT)

# Add libtsduck internal headers.

CFLAGS_INCLUDES += $(addprefix -I,$(shell find . -type d -name private))

# Generate and copy TSDuck configuration files in output bin directory.

DEKTEC_NAMES = config/tsduck.dektec.names
GEN_DEKTEC_NAMES = $(ROOTDIR)/build/generate-dektec-names.sh

.PHONY: configs
configs: $(addprefix $(BINDIR)/,$(notdir $(wildcard config/tsduck*.xml config/tsduck*.names) $(DEKTEC_NAMES)))
$(BINDIR)/%: config/%
	@echo '  [COPY] $<'; \
	mkdir -p $(BINDIR); \
	cp $< $@
ifneq ($(DTAPI_HEADER),)
$(DEKTEC_NAMES): $(DTAPI_HEADER) $(GEN_DEKTEC_NAMES)
	@echo '  [GEN] $@'; \
	$(GEN_DEKTEC_NAMES) >$@
endif

# Library containing all modules.
# - Both static and dynamic libraries are created but only use the dynamic one when building
#   tools and plugins.
# - There are so many object files that one single big 'ar' command is faster than individual
#   'ar' commands per object module.
# - The module tsStaticReferencesDVB is used only in the static library. It is useless in
#   the dynamic library. In fact, it would only slow down application startup.

.PHONY: libs
libs: $(STATIC_LIBTSDUCK) $(if $(STATIC),,$(SHARED_LIBTSDUCK))

$(STATIC_LIBTSDUCK): $(OBJS)
	@echo '  [AR] $@'; $(AR) $(ARFLAGS) $@ $^

$(SHARED_LIBTSDUCK): $(filter-out $(OBJDIR)/tsStaticReferencesDVB.o,$(OBJS))
	@echo '  [DTAPI] $(if $(DTAPI_OBJECT),using $(DTAPI_OBJECT),no DTAPI available)'; \
	echo '  [CC] $@'; \
	$(CC) $(CFLAGS) $(SOFLAGS) $^ $(LDLIBS) -shared -o $@

# Installation targets.

.PHONY: install install-tools install-devel
install: install-tools install-devel

install-tools: $(SHARED_LIBTSDUCK) $(DEKTEC_NAMES)
	install -d -m 755 $(SYSROOT)$(USRLIBDIR)/tsduck $(SYSROOT)$(SYSPREFIX)/share/tsduck/python
ifdef MACOS
	rm -rf $(SYSROOT)$(USRLIBDIR)/libtsduck.so
endif
	install -m 644 $(SHARED_LIBTSDUCK) $(SYSROOT)$(USRLIBDIR)
	install -m 644 config/tsduck*.xml config/tsduck*.names $(SYSROOT)$(SYSPREFIX)/share/tsduck
	$(MAKE) -C python install
	$(MAKE) -C java install

install-devel: $(STATIC_LIBTSDUCK) tsduck.h
	rm -rf $(SYSROOT)$(SYSPREFIX)/include/tsduck
	install -d -m 755 $(SYSROOT)$(USRLIBDIR) $(SYSROOT)$(SYSPREFIX)/include/tsduck
	rm -f $(SYSROOT)$(SYSPREFIX)/include/tsduck/tsduck.mk
	install -m 644 $(STATIC_LIBTSDUCK) $(SYSROOT)$(USRLIBDIR)
	install -m 644 $(shell find . -name 'ts*.h' ! -path '*/private/*' ! -path '*/windows/*' ! -path '*/$(SKIPDIR)/*' $(if $(NOTELETEXT),! -name tsTeletextDemux.h,)) $(SYSROOT)$(SYSPREFIX)/include/tsduck
ifdef NOTELETEXT
	sed tsduck.h -e '/tsTeletextDemux.h/d' >$(SYSROOT)$(SYSPREFIX)/include/tsduck/tsduck.h
endif
