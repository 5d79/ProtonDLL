# ProtonDLL

inject dlls into windows games running under steam proton or wine on linux.

![preview](https://i.imgur.com/yxCbl3C.png)

## about

protondll is a simple gui tool for injecting dlls into proton games. it detects your running proton games automatically and lets you inject any dll with a few clicks. built in c++ with gtk3 and packaged as an appimage so it runs anywhere without installing anything!

## features

- three injection methods: loadlibraryw, thread hijack trampoline, and in memory manual pe mapping
- protontricks container bridge to bypass steam linux runtime isolation
- automatic running game detection with appid and wine prefix resolution
- automatic 32/64 bit architecture detection from pe headers
- optional pe header wipe after manual mapping for stealth
- optional delay before injection for launch timing
- colored console output with error detail dumps on failure
- clean prism launcher inspired dark ui
- single appimage, no installation required

## building from source

```bash
# build the windows injectors (requires mingw)
make -C src/injector

# build the app (requires gtk3 dev)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target protondll
```

## usage

1. start your proton game through steam
2. launch protondll
3. select the running game from the list
4. browse for your dll
5. pick an injection method and options
6. click inject dll

## injection methods

| method | how it works | best for |
|--------|--------------|----------|
| loadlibraryw | create remotethread calling kernel32 loadlibraryw | most dlls, most reliable |
| thread hijack | suspended remote thread running a trampoline that calls loadlibraryw and restores flow | dlls that need a cleaner load |
| manual mapping | parses pe headers in memory, maps sections, applies relocations, resolves imports, runs tls callbacks and dllmain without registering in the peb | stealth, unregistered modules |
