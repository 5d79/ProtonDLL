#include "core.h"
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <unistd.h>
#include <sys/stat.h>

namespace backend {

static std::string dllbase(const std::string& dllname) {
    std::string base = dllname;
    std::transform(base.begin(), base.end(), base.begin(), ::tolower);
    if (base.size() >= 4 && base.substr(base.size() - 4) == ".dll") {
        base = base.substr(0, base.size() - 4);
    }
    return base;
}

static void fixowner(const fs::path& prefixpath, const fs::path& userreg) {
    if (geteuid() != 0) return;
    struct stat st;
    if (stat(prefixpath.c_str(), &st) != 0) return;
    if (st.st_uid != 0) {
        chown(userreg.c_str(), st.st_uid, st.st_gid);
    }
}

bool setoverride(const fs::path& prefixpath, const std::string& dllname, const std::string& mode) {
    fs::path userreg = prefixpath / "user.reg";
    if (!fs::is_regular_file(userreg)) {
        log("[!] Wine registry file not found at: " + userreg.string());
        return false;
    }

    std::string base = dllbase(dllname);
    std::string entryline = "\"" + base + "\"=\"" + mode + "\"\n";

    std::ifstream in(userreg);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) {
        lines.push_back(line);
    }
    in.close();

    int sectionidx = -1;
    for (size_t i = 0; i < lines.size(); i++) {
        std::string t = lines[i];
        t.erase(0, t.find_first_not_of(" \t"));
        if (t.rfind("[Software\\\\Wine\\\\DllOverrides]", 0) == 0) {
            sectionidx = (int)i;
            break;
        }
    }

    bool updated = false;
    if (sectionidx != -1) {
        std::regex keyre("^\\s*\"" + base + "\"\\s*=", std::regex::icase);
        for (size_t j = sectionidx + 1; j < lines.size(); j++) {
            std::string t = lines[j];
            t.erase(0, t.find_first_not_of(" \t"));
            if (!t.empty() && t[0] == '[') break;
            if (std::regex_search(lines[j], keyre)) {
                lines[j] = entryline;
                updated = true;
                break;
            }
        }
        if (!updated) {
            lines.insert(lines.begin() + sectionidx + 1, entryline);
        }
    } else {
        lines.push_back("");
        lines.push_back("[Software\\\\Wine\\\\DllOverrides]");
        lines.push_back(entryline);
    }

    std::ofstream out(userreg);
    for (size_t i = 0; i < lines.size(); i++) {
        out << lines[i];
        if (i + 1 < lines.size()) out << "\n";
    }
    out.close();

    fixowner(prefixpath, userreg);
    log("[+] Wine prefix registry updated: '" + base + "' -> '" + mode + "'");
    return true;
}

bool removeoverride(const fs::path& prefixpath, const std::string& dllname) {
    fs::path userreg = prefixpath / "user.reg";
    if (!fs::is_regular_file(userreg)) return false;

    std::string base = dllbase(dllname);
    std::regex keyre("^\\s*\"" + base + "\"\\s*=", std::regex::icase);

    std::ifstream in(userreg);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) {
        lines.push_back(line);
    }
    in.close();

    bool insection = false;
    std::vector<std::string> newlines;
    for (const auto& l : lines) {
        std::string t = l;
        t.erase(0, t.find_first_not_of(" \t"));
        if (t.rfind("[Software\\\\Wine\\\\DllOverrides]", 0) == 0) {
            insection = true;
            newlines.push_back(l);
            continue;
        } else if (!t.empty() && t[0] == '[') {
            insection = false;
        }
        if (insection && std::regex_search(l, keyre)) {
            continue;
        }
        newlines.push_back(l);
    }

    std::ofstream out(userreg);
    for (size_t i = 0; i < newlines.size(); i++) {
        out << newlines[i];
        if (i + 1 < newlines.size()) out << "\n";
    }
    out.close();

    fixowner(prefixpath, userreg);
    log("[+] Removed DLL override for '" + base + "' from Wine prefix");
    return true;
}

}
