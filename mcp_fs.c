#include "mcp_core.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static wchar_t *utf8_to_wide(const char *text) {
    int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                     text, -1, NULL, 0);
    if (!length) return NULL;
    wchar_t *wide = calloc((size_t)length, sizeof(*wide));
    if (!wide) return NULL;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                             text, -1, wide, length)) {
        free(wide);
        return NULL;
    }
    for (wchar_t *p = wide; *p; p++) if (*p == L'/') *p = L'\\';
    return wide;
}

static time_t filetime_to_time_t(FILETIME value) {
    ULARGE_INTEGER ticks;
    ticks.LowPart = value.dwLowDateTime;
    ticks.HighPart = value.dwHighDateTime;
    const ULONGLONG windows_epoch = 116444736000000000ULL;
    if (ticks.QuadPart < windows_epoch) return (time_t)0;
    return (time_t)((ticks.QuadPart - windows_epoch) / 10000000ULL);
}

int mcp_file_stat(const char *path, struct stat *status) {
    if (!path || !status) { errno = EINVAL; return -1; }
    wchar_t *wide = utf8_to_wide(path);
    if (!wide) { errno = EINVAL; return -1; }
    WIN32_FILE_ATTRIBUTE_DATA data;
    BOOL ok = GetFileAttributesExW(wide, GetFileExInfoStandard, &data);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    free(wide);
    if (!ok) {
        errno = error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND
            ? ENOENT : error == ERROR_ACCESS_DENIED ? EACCES : EIO;
        return -1;
    }
    memset(status, 0, sizeof(*status));
    status->st_mode = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        ? S_IFDIR | 0555 : S_IFREG | 0444;
    if (!(data.dwFileAttributes & FILE_ATTRIBUTE_READONLY))
        status->st_mode |= 0222;
    ULARGE_INTEGER size;
    size.LowPart = data.nFileSizeLow;
    size.HighPart = data.nFileSizeHigh;
    status->st_size = (off_t)size.QuadPart;
    status->st_atime = filetime_to_time_t(data.ftLastAccessTime);
    status->st_mtime = filetime_to_time_t(data.ftLastWriteTime);
    status->st_ctime = filetime_to_time_t(data.ftCreationTime);
    status->st_nlink = 1;
    return 0;
}

int mcp_file_size_bytes(const char *path, int64_t *size_bytes) {
    if (!path || !size_bytes) { errno = EINVAL; return -1; }
    wchar_t *wide = utf8_to_wide(path);
    if (!wide) { errno = EINVAL; return -1; }
    WIN32_FILE_ATTRIBUTE_DATA data;
    BOOL ok = GetFileAttributesExW(wide, GetFileExInfoStandard, &data);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    free(wide);
    if (!ok) {
        errno = error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND
            ? ENOENT : error == ERROR_ACCESS_DENIED ? EACCES : EIO;
        return -1;
    }
    ULARGE_INTEGER size;
    size.LowPart = data.nFileSizeLow;
    size.HighPart = data.nFileSizeHigh;
    if (size.QuadPart > INT64_MAX) { errno = EOVERFLOW; return -1; }
    *size_bytes = (int64_t)size.QuadPart;
    return 0;
}

static int move_file(const char *source, const char *destination, DWORD flags) {
    wchar_t *wide_source = utf8_to_wide(source);
    wchar_t *wide_destination = utf8_to_wide(destination);
    if (!wide_source || !wide_destination) {
        free(wide_source);
        free(wide_destination);
        errno = EINVAL;
        return -1;
    }
    BOOL moved = MoveFileExW(wide_source, wide_destination, flags);
    DWORD error = moved ? ERROR_SUCCESS : GetLastError();
    free(wide_source);
    free(wide_destination);
    if (moved) return 0;
    errno = error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS
        ? EEXIST : error == ERROR_ACCESS_DENIED ? EACCES : EIO;
    return -1;
}

int mcp_file_set_descriptor_mode(int descriptor, unsigned int mode) {
    /* NTFS access is controlled by the inherited AppContainer/user ACL. */
    (void)descriptor;
    (void)mode;
    return 0;
}

int mcp_file_replace(const char *temporary_path, const char *destination_path) {
    return move_file(temporary_path, destination_path,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
}

int mcp_file_publish_exclusive(const char *temporary_path,
                               const char *destination_path) {
    return move_file(temporary_path, destination_path, MOVEFILE_WRITE_THROUGH);
}

#else

#include <sys/stat.h>
#include <unistd.h>

int mcp_file_stat(const char *path, struct stat *status) {
    return stat(path, status);
}

int mcp_file_size_bytes(const char *path, int64_t *size_bytes) {
    if (!size_bytes) { errno = EINVAL; return -1; }
    struct stat status;
    if (stat(path, &status) != 0) return -1;
    if (status.st_size < 0) { errno = EOVERFLOW; return -1; }
    *size_bytes = (int64_t)status.st_size;
    return 0;
}

int mcp_file_set_descriptor_mode(int descriptor, unsigned int mode) {
    return fchmod(descriptor, (mode_t)mode);
}

int mcp_file_replace(const char *temporary_path, const char *destination_path) {
    return rename(temporary_path, destination_path);
}

int mcp_file_publish_exclusive(const char *temporary_path,
                               const char *destination_path) {
    return link(temporary_path, destination_path);
}

#endif
