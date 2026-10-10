#pragma once
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <filesystem>

namespace backend {

namespace fs = std::filesystem;

struct steamgame {
    std::string appid;
    std::string name;
    std::string installdir;
    std::string gamepath;
    std::string compatpath;
    std::string steamapps;
};

struct runningprocess {
    std::string pid;
    std::string exename;
    std::string appid;
    std::string gamename;
    std::string prefix;
    std::string protondir;
    std::string cmd;
};

struct module {
    std::string path;
    std::string name;
    uint64_t base = 0;
    uint64_t end = 0;
    bool isdll = false;
    bool isexe = false;
    bool isso = false;
    std::string type;
    uint64_t sizebytes = 0;
    uint64_t sizekb = 0;
    std::string basehex;
};

std::optional<fs::path> findsteamroot();
std::vector<fs::path> getsteamlibraries(const fs::path& steamroot);
std::map<std::string, steamgame> getinstalledgames(bool includeruntimes = false);
std::vector<runningprocess> getrunningprocesses();
std::string getpearch(const std::string& filepath);
bool setoverride(const fs::path& prefixpath, const std::string& dllname, const std::string& mode = "native,builtin");
bool removeoverride(const fs::path& prefixpath, const std::string& dllname);
std::string towinepath(const std::string& linuxpath);
std::optional<std::string> findprotontricks();
bool runinjection(const std::string& target, const std::string& dllpath, const std::string& prefixpath,
                  const std::string& protondir, int waitseconds, const std::string& method,
                  bool useprotontricks, const std::string& appid, bool erasepe, const std::string& arch);
std::vector<module> getmodules(int pid);
void setlogsink(void (*sink)(const std::string&));
void log(const std::string& text);

}
