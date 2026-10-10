#include "core.h"
#include <cstdlib>
#include <fstream>
#include <regex>
#include <algorithm>

namespace backend {

static const std::vector<fs::path> ksteampaths = [] {
    const char* home = std::getenv("HOME");
    fs::path h = home ? fs::path(home) : fs::path("/");
    return std::vector<fs::path>{
        h / ".steam" / "steam",
        h / ".steam" / "root",
        h / ".steam" / "debian-installation",
        h / ".local" / "share" / "Steam",
        h / ".var" / "app" / "com.valvesoftware.Steam" / ".steam" / "steam",
        h / ".var" / "app" / "com.valvesoftware.Steam" / ".local" / "share" / "Steam",
    };
}();

static const std::vector<std::string> kignoredapps = {
    "steamworks common redistributables",
    "proton",
    "steam linux runtime"
};

std::optional<fs::path> findsteamroot() {
    for (const auto& p : ksteampaths) {
        if (fs::exists(p) && fs::is_directory(p / "steamapps")) {
            return fs::weakly_canonical(p);
        }
    }
    return std::nullopt;
}

std::vector<fs::path> getsteamlibraries(const fs::path& steamroot) {
    std::vector<fs::path> libraries;
    libraries.push_back(steamroot);

    fs::path vdfpath = steamroot / "steamapps" / "libraryfolders.vdf";
    if (fs::is_regular_file(vdfpath)) {
        std::ifstream f(vdfpath);
        std::string content((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
        std::regex pathre(R"re("path"\s+"([^"]+)")re");
        auto begin = std::sregex_iterator(content.begin(), content.end(), pathre);
        auto end = std::sregex_iterator();
        for (auto it = begin; it != end; ++it) {
            fs::path libp((*it)[1].str());
            if (fs::is_directory(libp) &&
                std::find(libraries.begin(), libraries.end(), libp) == libraries.end()) {
                libraries.push_back(libp);
            }
        }
    }
    return libraries;
}

std::map<std::string, steamgame> getinstalledgames(bool includeruntimes) {
    std::map<std::string, steamgame> games;
    auto steamroot = findsteamroot();
    if (!steamroot) return games;

    auto libraries = getsteamlibraries(*steamroot);
    for (const auto& lib : libraries) {
        fs::path steamapps = lib / "steamapps";
        if (!fs::is_directory(steamapps)) continue;

        std::error_code ec;
        for (auto& entry : fs::directory_iterator(steamapps, ec)) {
            if (ec) break;
            std::string fname = entry.path().filename().string();
            if (fname.rfind("appmanifest_", 0) != 0) continue;
            if (fname.size() < 13 || fname.substr(fname.size() - 4) != ".acf") continue;

            std::ifstream f(entry.path());
            std::string content((std::istreambuf_iterator<char>(f)),
                                std::istreambuf_iterator<char>());

            std::smatch appidm, namem, dirm;
            std::regex appidre(R"re("appid"\s+"(\d+)")re");
            std::regex namere(R"re("name"\s+"([^"]+)")re");
            std::regex dirre(R"re("installdir"\s+"([^"]+)")re");

            if (!std::regex_search(content, appidm, appidre)) continue;
            if (!std::regex_search(content, namem, namere)) continue;

            std::string appid = appidm[1].str();
            std::string name = namem[1].str();
            bool hasdir = std::regex_search(content, dirm, dirre);

            if (!includeruntimes) {
                std::string lower = name;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                bool ignored = false;
                for (const auto& r : kignoredapps) {
                    if (lower.find(r) != std::string::npos) { ignored = true; break; }
                }
                if (ignored) continue;
            }

            std::string installdir = hasdir ? dirm[1].str() : "";
            fs::path gamepath = steamapps / "common" / installdir;
            fs::path compatpath = steamapps / "compatdata" / appid / "pfx";

            steamgame g;
            g.appid = appid;
            g.name = name;
            g.installdir = installdir;
            g.gamepath = gamepath.string();
            g.compatpath = compatpath.string();
            g.steamapps = steamapps.string();
            games[appid] = g;
        }
    }
    return games;
}

}
