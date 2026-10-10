#include "core.h"
#include <fstream>
#include <cstdint>
#include <cstring>

namespace backend {

std::string getpearch(const std::string& filepath) {
    std::ifstream f(filepath, std::ios::binary);
    if (!f) return "unknown";

    char dos[64];
    f.read(dos, 64);
    if (f.gcount() < 64) return "unknown";
    if (dos[0] != 'M' || dos[1] != 'Z') return "unknown";

    uint32_t lfanew;
    std::memcpy(&lfanew, dos + 60, 4);
    f.seekg(lfanew);
    char sig[4];
    f.read(sig, 4);
    if (f.gcount() < 4) return "unknown";
    if (sig[0] != 'P' || sig[1] != 'E' || sig[2] != 0 || sig[3] != 0) return "unknown";

    char machine[2];
    f.read(machine, 2);
    if (f.gcount() < 2) return "unknown";
    uint16_t m;
    std::memcpy(&m, machine, 2);
    if (m == 0x8664) return "64";
    if (m == 0x014C) return "32";
    return "unknown";
}

}
