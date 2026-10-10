#include "core.h"
#include <cstdio>
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <set>
#include <memory>
#include <array>

namespace backend {

static const std::vector<std::string> kignored = {
    "tabtip.exe", "epicwebhelper.exe", "crashpad_handler.exe", "cef.exe",
    "xalia.exe", "steam.exe", "winedevice.exe", "explorer.exe",
    "services.exe", "plugplay.exe", "svchost.exe", "rpcss.exe", "conhost.exe"
};

static std::string readfile(const std::string& path) {
    std::ifstream f(path);
    if (!f) return "";
    return std::string((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());
}

static std::string findprefixforappid(const std::string& appid) {
    auto steamroot = findsteamroot();
    if (!steamroot) return "";
    for (const auto& lib : getsteamlibraries(*steamroot)) {
        fs::path p = lib / "steamapps" / "compatdata" / appid / "pfx";
        if (fs::is_directory(p)) return p.string();
    }
    return "";
}

static std::string findprotondir() {
    auto steamroot = findsteamroot();
    if (!steamroot) return "";
    std::string fallback;
    for (const auto& lib : getsteamlibraries(*steamroot)) {
        fs::path common = lib / "steamapps" / "common";
        if (!fs::is_directory(common)) continue;
        std::error_code ec;
        for (auto& entry : fs::directory_iterator(common, ec)) {
            if (ec) break;
            std::string name = entry.path().filename().string();
            if (name.rfind("Proton", 0) != 0) continue;
            if (fs::is_regular_file(entry.path() / "files" / "bin" / "wine")) {
                if (name.find("Experimental") != std::string::npos) return entry.path().string();
                if (fallback.empty()) fallback = entry.path().string();
            }
        }
    }
    return fallback;
}

static std::string runps() {
    std::string result;
    std::array<char, 128> buffer;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen("ps -eo pid,args", "r"), pclose);
    if (pipe) {
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            result += buffer.data();
        }
    }
    return result;
}

std::vector<runningprocess> getrunningprocesses() {
    std::vector<runningprocess> running;
    auto gamesdb = getinstalledgames(true);
    std::string psdata = runps();

    std::vector<std::pair<std::string, std::string>> wineprocs;
    std::istringstream iss(psdata);
    std::string line;
    std::getline(iss, line);
    while (std::getline(iss, line)) {
        if (line.empty()) continue;
        size_t start = line.find_first_not_of(" \t");
        if (start == std::string::npos) continue;
        line = line.substr(start);
        size_t sp = line.find(' ');
        if (sp == std::string::npos) continue;
        std::string pid = line.substr(0, sp);
        std::string cmd = line.substr(sp + 1);
        std::string lower = cmd;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.find(".exe") != std::string::npos ||
            lower.find("wineserver") != std::string::npos ||
            lower.find("proton") != std::string::npos) {
            wineprocs.push_back({pid, cmd});
        }
    }

    for (const auto& wp : wineprocs) {
        const std::string& pid = wp.first;
        const std::string& cmd = wp.second;

        std::smatch exem;
        std::regex exere(R"(([a-zA-Z0-9_\-\s\(\)]+\.exe))", std::regex::icase);
        if (!std::regex_search(cmd, exem, exere)) continue;
        std::string exename = exem[1].str();
        std::string exelower = exename;
        std::transform(exelower.begin(), exelower.end(), exelower.begin(), ::tolower);
        if (std::find(kignored.begin(), kignored.end(), exelower) != kignored.end()) continue;

        std::string appid;
        std::smatch m;
        std::regex appidre(R"(AppId=(\d+))");
        std::regex compatre(R"(compatdata/(\d+))");
        if (std::regex_search(cmd, m, appidre)) {
            appid = m[1].str();
        } else if (std::regex_search(cmd, m, compatre)) {
            appid = m[1].str();
        }

        if (appid.empty()) {
            std::string env = readfile("/proc/" + pid + "/environ");
            std::regex envappid(R"(SteamAppId=(\d+))");
            std::regex envcompat(R"(STEAM_COMPAT_DATA_PATH=.*?compatdata/(\d+))");
            if (std::regex_search(env, m, envappid)) {
                appid = m[1].str();
            } else if (std::regex_search(env, m, envcompat)) {
                appid = m[1].str();
            }
        }

        std::string gamename = "Unknown Game";
        if (!appid.empty()) {
            auto it = gamesdb.find(appid);
            if (it != gamesdb.end()) gamename = it->second.name;
        }

        runningprocess r;
        r.pid = pid;
        r.exename = exename;
        r.appid = appid.empty() ? "Unknown" : appid;
        r.gamename = gamename;
        r.prefix = appid.empty() ? "" : findprefixforappid(appid);
        r.protondir = findprotondir();
        r.cmd = cmd;
        running.push_back(r);
    }

    std::sort(running.begin(), running.end(), [](const runningprocess& a, const runningprocess& b) {
        bool at = a.exename.size() >= 6 && a.exename.substr(0, 6) == "tavern";
        bool bt = b.exename.size() >= 6 && b.exename.substr(0, 6) == "tavern";
        if (at != bt) return !at;
        return a.exename < b.exename;
    });

    std::vector<runningprocess> unique;
    std::set<std::string> seen;
    for (const auto& r : running) {
        std::string key = r.exename + "|" + r.appid;
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        if (seen.insert(key).second) {
            unique.push_back(r);
        }
    }
    return unique;
}

}
