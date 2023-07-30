CC=gcc
CFLAGS=-std=gnu11 -Wall -g -Werror
BUILDDIR=./build

ifdef SAN
	CFLAGS+= -fsanitize=address
	LDFLAGS+=-fsanitize=address
endif

$(BUILDDIR)/abdhcp: $(BUILDDIR)/main.o $(BUILDDIR)/ab_dhcp.o $(BUILDDIR)/dhcp_manager.o
	mkdir -p $(BUILDDIR)
	$(CC) -o $@ $^ $(LDFLAGS)

$(BUILDDIR)/main.o: main.c core.h ab_dhcp.h dhcp_manager.h
	mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/ab_dhcp.o: ab_dhcp.c ab_dhcp.h
	mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/dhcp_manager.o: dhcp_manager.c dhcp_manager.h core.h
	mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILDDIR)