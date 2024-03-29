CC=gcc
CFLAGS=-std=gnu11 -Wall -Werror
BUILDDIR=./build

ifndef RELEASE
	CFLAGS+= -g
endif

ifdef RELEASE
	CFLAGS+= -O3
endif

ifdef SAN
	CFLAGS+= -fsanitize=address,leak,undefined
	LDFLAGS+=-fsanitize=address,leak,undefined
endif

$(BUILDDIR)/abdhcp: $(BUILDDIR)/main.o $(BUILDDIR)/dhcp_pkt.o $(BUILDDIR)/dhcp_manager.o
	mkdir -p $(BUILDDIR)
	$(CC) -o $@ $^ $(LDFLAGS)

$(BUILDDIR)/main.o: main.c core.h dhcp_pkt.h dhcp_manager.h
	mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/dhcp_pkt.o: dhcp_pkt.c dhcp_pkt.h
	mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/dhcp_manager.o: dhcp_manager.c dhcp_manager.h core.h
	mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILDDIR)