CC=gcc
CFLAGS=-std=gnu11 -Wall -g -Werror
BUILDDIR=./build

$(BUILDDIR)/abdhcp: $(BUILDDIR)/main.o $(BUILDDIR)/ab_dhcp.o
	mkdir -p $(BUILDDIR)
	$(CC) -o $@ $^

$(BUILDDIR)/main.o: main.c
	mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/ab_dhcp.o: ab_dhcp.c ab_dhcp.h
	mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILDDIR)