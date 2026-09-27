#include "../mcp_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

static int failures;

static void check(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        failures++;
    }
}

int main(void) {
#ifdef _WIN32
    char temporary[MAX_PATH];
    check(GetTempPathA(sizeof(temporary), temporary) != 0, "GetTempPath");
    char root[MAX_PATH];
    check(GetTempFileNameA(temporary, "mcp", 0, root) != 0, "GetTempFileName");
    DeleteFileA(root);
    check(CreateDirectoryA(root, NULL) != 0, "CreateDirectory");
#else
    char root[] = "/tmp/mcp-path-test-XXXXXX";
    check(mkdtemp(root) != NULL, "mkdtemp");
#endif
    char child[4096];
    snprintf(child, sizeof(child), "%s/child", root);
#ifdef _WIN32
    check(CreateDirectoryA(child, NULL) != 0, "CreateDirectory child");
#else
    check(mkdir(child, 0700) == 0, "mkdir child");
#endif

    char native[4096];
    check(mcp_path_resolve(root, "/child/new.txt", 1,
                           native, sizeof(native)) == 0,
          "resolve a new logical path");
    char logical[4096];
    check(mcp_path_to_virtual(root, native, logical, sizeof(logical)) == 0,
          "convert native path to logical path");
    check(strcmp(logical, "/child/new.txt") == 0, "logical form uses slash root");
    check(mcp_path_resolve(root, "/../escape", 1,
                           native, sizeof(native)) != 0,
          "reject parent traversal");
#ifdef _WIN32
    check(mcp_path_resolve(root, "C:/escape", 1,
                           native, sizeof(native)) != 0,
          "reject drive-qualified client path");
    RemoveDirectoryA(child);
    RemoveDirectoryA(root);
#else
    rmdir(child);
    rmdir(root);
#endif
    if (!failures) puts("path backend tests passed");
    return failures ? 1 : 0;
}
