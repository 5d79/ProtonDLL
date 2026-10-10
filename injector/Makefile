CC64 = x86_64-w64-mingw32-g++
CC32 = i686-w64-mingw32-g++
CFLAGS = -O2 -Wall -municode -fno-toplevel-reorder -std=c++17

BINDIR = ../../bin
SRC = wininjector.cpp

all: $(BINDIR)/win_inject64.exe $(BINDIR)/win_inject32.exe

$(BINDIR)/win_inject64.exe: $(SRC) | $(BINDIR)
	$(CC64) $(CFLAGS) $< -o $@

$(BINDIR)/win_inject32.exe: $(SRC) | $(BINDIR)
	$(CC32) $(CFLAGS) $< -o $@

$(BINDIR):
	mkdir -p $(BINDIR)

clean:
	rm -f $(BINDIR)/win_inject64.exe $(BINDIR)/win_inject32.exe

.PHONY: all clean
