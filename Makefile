#!/usr/bin/make -f
#
#   This file is part of ubridge, a program to bridge network interfaces
#   to UDP tunnels.
#
#   Copyright (C) 2015 GNS3 Technologies Inc.
#
#   ubridge is free software: you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   ubridge is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

NAME    =   ubridge

SRC     =   src/ubridge.c               \
            src/nio.c                   \
            src/nio_udp.c               \
            src/nio_unix.c              \
            src/nio_ethernet.c          \
            src/nio_tap.c               \
            src/parse.c                 \
            src/packet_filter.c         \
            src/buffer_pool.c           \
            src/event_loop.c            \
            src/packet_batch.c          \
            src/pcap_capture.c          \
            src/pcap_filter.c           \
            src/hypervisor.c            \
            src/hypervisor_parser.c     \
            src/hypervisor_bridge.c     \
            src/cpu_affinity.c          \
            src/simd_optimizations.c    \
            src/nio_af_xdp.c


OBJ     =   $(SRC:.c=.o)

CC      ?=   gcc

# Performance optimizations (Phase 1)
CFLAGS  +=   -O3 -march=native -mtune=native -flto
CFLAGS  +=   -DNDEBUG -fno-semantic-interposition
CFLAGS  +=   -funroll-loops -fprefetch-loop-arrays
CFLAGS  +=   -Wall

# Phase 4: SIMD and advanced optimizations
CFLAGS  +=   -msse2 -msse4.1 -mavx -mavx2
CFLAGS  +=   -DHAVE_CPU_AFFINITY -DHAVE_SIMD

BINDIR  =   /usr/local/bin

ifeq ($(shell uname), Darwin)
   LIBS =   -lpthread -lpcap
   SRC +=   src/nio_fusion_vmnet.c    \

else ifeq ($(shell uname -o), Cygwin)
   CFLAGS += -DCYGWIN
   LIBS =   -lpthread -lwpcap
else
   LIBS =   -lpthread -lpcap
endif

# RAW Ethernet support for Linux
ifeq ($(shell uname), Linux)
    CFLAGS += -DLINUX_RAW -DHAVE_EVENT_DRIVEN
    SRC += src/nio_linux_raw.c             \
           src/hypervisor_docker.c         \
           src/hypervisor_iol_bridge.c     \
           src/hypervisor_brctl.c          \
           src/epoll_manager.c             \
           src/netlink/nl.c
    
    # Check for AF_XDP support (requires libbpf and kernel headers)
    ifneq ($(shell pkg-config --exists libbpf 2>/dev/null && echo yes),)
        CFLAGS += -DHAVE_AF_XDP
        LIBS += -lbpf
    endif
    
    # Check for NUMA support
    ifneq ($(shell pkg-config --exists libnuma 2>/dev/null && echo yes),)
        CFLAGS += -DHAVE_NUMA
        LIBS += -lnuma
    endif
endif

ifeq ($(SYSTEM_INIPARSER),1)
    CFLAGS += -DUSE_SYSTEM_INIPARSER
    LIBS += -liniparser
else
    SRC += src/iniparser/iniparser.c   \
	   src/iniparser/dictionary.c
endif

##############################

$(NAME)	: $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -flto -o $(NAME) $(OBJ) $(LIBS)

.PHONY: clean

clean:
	-rm -f $(OBJ)
	-rm -f *~
	-rm -f $(NAME)

all	: $(NAME)

ifeq ($(shell uname), Darwin)
install : $(NAME)
	cp $(NAME) $(BINDIR)
	chown root:admin $(BINDIR)/$(NAME)
	chmod 4750 $(BINDIR)/$(NAME)
else ifeq ($(shell uname), FreeBSD)
install : $(NAME)
	cp $(NAME) $(DESTDIR)$(BINDIR)
	chmod 4750 $(DESTDIR)$(BINDIR)/$(NAME)
else
install : $(NAME)
	chmod +x $(NAME)
	cp -p $(NAME) $(BINDIR)
	setcap cap_net_admin,cap_net_raw=ep $(BINDIR)/$(NAME)
endif
