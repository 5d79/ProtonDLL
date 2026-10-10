#include "core.h"
#include <cstdio>

namespace backend {

static void (*glogsink)(const std::string&) = nullptr;

void setlogsink(void (*sink)(const std::string&)) {
    glogsink = sink;
}

void log(const std::string& text) {
    if (glogsink) {
        glogsink(text);
    } else {
        std::printf("%s\n", text.c_str());
        std::fflush(stdout);
    }
}

}
