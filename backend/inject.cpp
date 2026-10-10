#include "core.h"
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <regex>
#include <memory>
#include <array>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

namespace backend {

static fs::path findbindir() {
    char buf[4096];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    std::vector<fs::path> candidates;
    if (len > 0) {
        buf[len] = 0;
        fs::path exe = fs::path(buf);
        candidates.push_back(exe.parent_path() / "bin");
        candidates.push_back(exe.parent_path().parent_path() / "bin");
        candidates.push_back(exe.parent_path() / ".." / "bin");
    }
    const char* appdir = std::getenv("APPDIR");
    if (appdir) {
        candidates.push_back(fs::path(appdir) / "usr" / "bin" / "bin");
        candidates.push_back(fs::path(appdir) / "bin");
    }
    std::error_code ec;
    std::vector<std::pair<fs::file_time_type, fs::path>> tmpdirs;
    for (auto& entry : fs::directory_iterator("/tmp", ec)) {
        std::string name = entry.path().filename().string();
        if (name.rfind("appimage_extracted_", 0) == 0) {
            fs::path cand = entry.path() / "usr" / "bin" / "bin";
            std::error_code ec2;
            if (fs::is_directory(cand, ec2) &&
                fs::is_regular_file(cand / "win_inject64.exe", ec2)) {
                std::error_code ec3;
                auto t = fs::last_write_time(entry.path(), ec3);
                tmpdirs.push_back({t, cand});
            }
        }
    }
    std::sort(tmpdirs.begin(), tmpdirs.end(), [](const auto& a, const auto& b) {
        return a.first > b.first;
    });
    for (const auto& td : tmpdirs) candidates.push_back(td.second);
    for (const auto& c : candidates) {
        std::error_code ec2;
        if (fs::is_directory(c, ec2) &&
            fs::is_regular_file(c / "win_inject64.exe", ec2)) {
            return c;
        }
    }
    return fs::path("bin");
}

static const fs::path kbindir = findbindir();

std::string towinepath(const std::string& linuxpath) {
    fs::path p = fs::absolute(linuxpath);
    std::string s = p.string();
    std::string out = "Z:";
    for (char c : s) {
        out += (c == '/') ? '\\' : c;
    }
    return out;
}

std::optional<std::string> findprotontricks() {
    const char* home = std::getenv("HOME");
    if (home) {
        fs::path local = fs::path(home) / ".local" / "bin" / "protontricks";
        if (fs::is_regular_file(local) && access(local.c_str(), X_OK) == 0) {
            return local.string();
        }
    }
    const char* path = std::getenv("PATH");
    if (path) {
        std::string p = path;
        std::istringstream iss(p);
        std::string dir;
        while (std::getline(iss, dir, ':')) {
            fs::path cand = fs::path(dir) / "protontricks";
            if (fs::is_regular_file(cand) && access(cand.c_str(), X_OK) == 0) {
                return cand.string();
            }
        }
    }
    return std::nullopt;
}

static bool runcmd(const std::vector<std::string>& args, const std::string& envprefix,
                   const std::string& envld, bool filternoise, std::vector<std::string>* capture = nullptr) {
    int outfd[2];
    if (pipe(outfd) != 0) {
        log("[!] failed to create pipe for injection command.");
        return false;
    }

    std::vector<char*> argv;
    for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);

    std::string ldval = envld;
    {
        const char* existing = std::getenv("LD_LIBRARY_PATH");
        if (existing && *existing) {
            if (!ldval.empty()) ldval += ":";
            ldval += existing;
        }
    }

    pid_t pid = fork();
    if (pid == 0) {
        dup2(outfd[1], STDOUT_FILENO);
        dup2(outfd[1], STDERR_FILENO);
        close(outfd[0]);
        close(outfd[1]);
        unsetenv("LD_LIBRARY_PATH");
        unsetenv("GTK_PATH");
        unsetenv("GIO_MODULE_DIR");
        unsetenv("GDK_PIXBUF_MODULE_FILE");
        unsetenv("APPDIR");
        unsetenv("APPIMAGE");
        unsetenv("OWD");
        unsetenv("ARGV0");
        setenv("WINEPREFIX", envprefix.c_str(), 1);
        if (!ldval.empty()) setenv("LD_LIBRARY_PATH", ldval.c_str(), 1);
        execvp(argv[0], argv.data());
        _exit(127);
    }
    close(outfd[1]);

    std::string pending;
    char buf[512];
    ssize_t n;
    while ((n = read(outfd[0], buf, sizeof(buf))) > 0) {
        pending.append(buf, n);
        size_t pos;
        while ((pos = pending.find('\n')) != std::string::npos) {
            std::string line = pending.substr(0, pos);
            pending.erase(0, pos + 1);
            if (filternoise) {
                if (line.find("Fontconfig") != std::string::npos ||
                    line.find("fonts.conf") != std::string::npos ||
                    line.find("pressure-vessel") != std::string::npos ||
                    line.find("pv-locale") != std::string::npos ||
                    line.find("pv-adverb") != std::string::npos ||
                    line.find("Current Steam Runtime not recognized") != std::string::npos) {
                    continue;
                }
            }
            if (capture) {
                capture->push_back(line);
            } else {
                log(line);
            }
        }
    }
    if (!pending.empty()) log(pending);
    close(outfd[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code != 0) {
            log("[!] injection command exited with code " + std::to_string(code));
        }
        return code == 0;
    }
    log("[!] injection command crashed or was killed.");
    return false;
}

static std::string extractappid(const std::string& prefixpath) {
    std::smatch m;
    std::regex re(R"(compatdata/(\d+))");
    if (std::regex_search(prefixpath, m, re)) return m[1].str();
    return "";
}

bool runinjection(const std::string& target, const std::string& dllpath, const std::string& prefixpath,
                  const std::string& protondir, int waitseconds, const std::string& method,
                  bool useprotontricks, const std::string& appid, bool erasepe, const std::string& arch) {
    fs::path dllabs = fs::absolute(dllpath);
    if (!fs::is_regular_file(dllabs)) {
        log("[!] Target DLL file not found: " + dllabs.string());
        return false;
    }

    fs::path injector64 = kbindir / "win_inject64.exe";
    fs::path injector32 = kbindir / "win_inject32.exe";

    fs::path selected = injector64;
    std::string detected = getpearch(dllabs.string());
    if (arch == "32") {
        selected = injector32;
    } else if (arch == "64") {
        selected = injector64;
    } else if (detected == "32") {
        selected = injector32;
        log("[*] Detected 32-bit PE binary. Using 32-bit injector (win_inject32.exe)");
    } else {
        log("[*] Using 64-bit injector (win_inject64.exe)");
    }

    if (!fs::is_regular_file(selected)) {
        log("[!] Compiled injector not found at: " + selected.string());
        log("[!] Searched bin dir: " + kbindir.string());
        return false;
    }

    fs::path stagedir = fs::temp_directory_path() / "protondll-injector";
    std::error_code mkc;
    fs::create_directories(stagedir, mkc);
    fs::path staged = stagedir / selected.filename();
    fs::copy_file(selected, staged, fs::copy_options::overwrite_existing, mkc);
    if (mkc) {
        log("[!] Failed to stage injector: " + mkc.message());
        return false;
    }
    selected = staged;
    log("[*] Staged injector at: " + selected.string());

    std::string winedll = towinepath(dllabs.string());

    auto protontricksbin = useprotontricks ? findprotontricks() : std::nullopt;
    if (useprotontricks && !protontricksbin) {
        log("[!] Warning: Protontricks not found on system. Falling back to direct Wine execution...");
        useprotontricks = false;
    }

    std::string resolvedappid = appid;
    if (useprotontricks && resolvedappid.empty()) {
        resolvedappid = extractappid(prefixpath);
        if (resolvedappid.empty()) {
            for (const auto& r : getrunningprocesses()) {
                if (target == r.pid || target == r.exename ||
                    target.find(r.exename) != std::string::npos) {
                    if (!r.appid.empty() && r.appid != "Unknown") {
                        resolvedappid = r.appid;
                        break;
                    }
                }
            }
        }
    }

    if (useprotontricks && resolvedappid.empty()) {
        log("[!] Warning: Could not identify Steam AppID for target. Falling back to direct Wine...");
        useprotontricks = false;
    }

    std::vector<std::string> inner = {
        "wine", selected.string(), target, winedll, "--method", method
    };
    if (erasepe) inner.push_back("--erase-pe");
    if (waitseconds > 0) {
        inner.push_back("--wait");
        inner.push_back(std::to_string(waitseconds));
    }

    if (useprotontricks) {
        log("[*] Executing injection via Protontricks Container Bridge (AppID: " + resolvedappid + "):");
        log("    Target:     " + target);
        log("    DLL:        " + dllabs.string() + " (" + winedll + ")");
        log("    Method:     " + method);
        log("    Erase PE:   " + std::string(erasepe ? "true" : "false"));
        log("    Injector:   " + selected.filename().string());

        std::string innercmd;
        for (const auto& a : inner) {
            if (!innercmd.empty()) innercmd += " ";
            innercmd += "'" + a + "'";
        }
        std::vector<std::string> cmd = {*protontricksbin, "-c", innercmd, resolvedappid};
        std::vector<std::string> captured;
        bool ok = runcmd(cmd, prefixpath, "", true, &captured);
        if (!ok) {
            log("[!] === injection failure details ===");
            for (const auto& l : captured) log("    " + l);
            log("[!] === end failure details ===");
        }
        return ok;
    }

    std::string envld;
    if (!protondir.empty()) {
        fs::path pbin = fs::path(protondir) / "files" / "bin" / "wine";
        fs::path plib64 = fs::path(protondir) / "files" / "lib64";
        fs::path plib32 = fs::path(protondir) / "files" / "lib";
        if (fs::is_regular_file(pbin)) {
            const char* existing = std::getenv("LD_LIBRARY_PATH");
            envld = plib64.string() + ":" + plib32.string();
            if (existing && *existing) envld += ":" + std::string(existing);
        }
    }

    log("[*] Executing direct Wine/Proton injection:");
    log("    Target:     " + target);
    log("    DLL:        " + dllabs.string() + " (" + winedll + ")");
    log("    Method:     " + method);
    log("    Erase PE:   " + std::string(erasepe ? "true" : "false"));
    log("    Prefix:     " + prefixpath);
    log("    Wine:       wine");

    std::vector<std::string> captured;
    bool ok = runcmd(inner, prefixpath, envld, true, &captured);
    if (!ok) {
        log("[!] === injection failure details ===");
        for (const auto& l : captured) log("    " + l);
        log("[!] === end failure details ===");
    }
    return ok;
}

}
