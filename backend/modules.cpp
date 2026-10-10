#include "core.h"
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <cstdio>

namespace backend {

std::vector<module> getmodules(int pid) {
    std::vector<module> modules;
    std::ifstream f("/proc/" + std::to_string(pid) + "/maps");
    if (!f) return modules;

    std::map<std::string, module> bypath;
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string addr, perms, offset, dev, inode, pathname;
        iss >> addr >> perms >> offset >> dev >> inode;
        std::getline(iss, pathname);
        pathname.erase(0, pathname.find_first_not_of(" \t"));
        if (pathname.empty() || pathname[0] == '[') continue;

        std::regex delre(R"(\s*\(deleted\)$)");
        pathname = std::regex_replace(pathname, delre, "");

        size_t dash = addr.find('-');
        if (dash == std::string::npos) continue;
        uint64_t start = std::stoull(addr.substr(0, dash), nullptr, 16);
        uint64_t end = std::stoull(addr.substr(dash + 1), nullptr, 16);

        auto it = bypath.find(pathname);
        if (it == bypath.end()) {
            module m;
            m.path = pathname;
            size_t slash = pathname.find_last_of('/');
            m.name = (slash == std::string::npos) ? pathname : pathname.substr(slash + 1);
            m.base = start;
            m.end = end;
            std::string lower = m.name;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
            m.isdll = lower.size() >= 4 && lower.substr(lower.size() - 4) == ".dll";
            m.isexe = lower.size() >= 4 && lower.substr(lower.size() - 4) == ".exe";
            m.isso = lower.find(".so") != std::string::npos;
            if (m.isdll) m.type = "Windows DLL";
            else if (m.isexe) m.type = "Windows EXE";
            else if (m.isso) m.type = "Linux Shared Library";
            else m.type = "Other Mapped File";
            bypath[pathname] = m;
        } else {
            it->second.base = std::min(it->second.base, start);
            it->second.end = std::max(it->second.end, end);
        }
    }

    for (auto& kv : bypath) {
        module& m = kv.second;
        m.sizebytes = m.end - m.base;
        m.sizekb = m.sizebytes / 1024;
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%012llX", (unsigned long long)m.base);
        m.basehex = buf;
        modules.push_back(m);
    }

    std::sort(modules.begin(), modules.end(), [](const module& a, const module& b) {
        return a.base < b.base;
    });
    return modules;
}

}
