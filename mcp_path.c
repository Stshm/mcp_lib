#include "mcp_core.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wchar.h>
#else
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#ifdef _WIN32
#define MCP_NATIVE_PATH_MAX 32768
#else
#define MCP_NATIVE_PATH_MAX PATH_MAX
#endif

static int copy_path(char *output, size_t size, const char *value) {
    int written = snprintf(output, size, "%s", value);
    if (written < 0 || (size_t)written >= size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int normalize_virtual(const char *input, char *output, size_t size) {
    if (!input || !*input || !output || size < 2) {
        errno = EINVAL;
        return -1;
    }
    const char *cursor = input;
    while (*cursor == '/' || *cursor == '\\') cursor++;
    if (cursor[0] == '.' && cursor[1] == '\0') {
        output[0] = '/';
        output[1] = '\0';
        return 0;
    }
    size_t used = 0;
    output[used++] = '/';
    while (*cursor) {
        while (*cursor == '/' || *cursor == '\\') cursor++;
        if (!*cursor) break;
        const char *component = cursor;
        while (*cursor && *cursor != '/' && *cursor != '\\') cursor++;
        size_t length = (size_t)(cursor - component);
        if ((length == 1 && component[0] == '.') ||
            (length == 2 && component[0] == '.' && component[1] == '.')) {
            errno = EINVAL;
            return -1;
        }
#ifdef _WIN32
        if (memchr(component, ':', length)) {
            errno = EINVAL; /* Reject drive-qualified and ADS paths. */
            return -1;
        }
#endif
        if (used > 1) {
            if (used + 1 >= size) { errno = ENAMETOOLONG; return -1; }
            output[used++] = '/';
        }
        if (used + length >= size) { errno = ENAMETOOLONG; return -1; }
        memcpy(output + used, component, length);
        used += length;
    }
    output[used] = '\0';
    return 0;
}

#ifdef _WIN32

static wchar_t *utf8_to_wide(const char *text) {
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, NULL, 0);
    if (!count) return NULL;
    wchar_t *wide = calloc((size_t)count, sizeof(*wide));
    if (!wide) return NULL;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, wide, count)) {
        free(wide);
        return NULL;
    }
    for (wchar_t *p = wide; *p; p++) if (*p == L'/') *p = L'\\';
    return wide;
}

static char *wide_to_utf8(const wchar_t *wide) {
    int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                    wide, -1, NULL, 0, NULL, NULL);
    if (!count) return NULL;
    char *text = malloc((size_t)count);
    if (!text) return NULL;
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                             wide, -1, text, count, NULL, NULL)) {
        free(text);
        return NULL;
    }
    return text;
}

static wchar_t *final_path_from_handle(HANDLE handle, DWORD name_flag) {
    DWORD flags = name_flag | VOLUME_NAME_DOS;
    DWORD needed = GetFinalPathNameByHandleW(handle, NULL, 0, flags);
    if (!needed) return NULL;
    wchar_t *final = calloc((size_t)needed + 1, sizeof(*final));
    if (!final) return NULL;
    if (!GetFinalPathNameByHandleW(handle, final, needed + 1, flags)) {
        free(final);
        return NULL;
    }
    return final;
}

static int wide_path_to_utf8_slashes(wchar_t *wide, char *output, size_t size) {
    const wchar_t *plain = wide;
    if (!wcsncmp(wide, L"\\\\?\\UNC\\", 8)) {
        wide[6] = L'\\';
        wide[7] = L'\\';
        plain = wide + 6;
    } else if (!wcsncmp(wide, L"\\\\?\\", 4)) {
        plain = wide + 4;
    }
    char *utf8 = wide_to_utf8(plain);
    if (!utf8) { errno = EINVAL; return -1; }
    for (char *p = utf8; *p; p++) if (*p == '\\') *p = '/';
    int result = copy_path(output, size, utf8);
    free(utf8);
    return result;
}

static int check_unc_components(wchar_t *path) {
    if (path[0] != L'\\' || path[1] != L'\\') return -1;
    wchar_t *server_end = wcschr(path + 2, L'\\');
    if (!server_end || !server_end[1]) return -1;
    wchar_t *share_end = wcschr(server_end + 1, L'\\');
    if (!share_end || !share_end[1]) {
        /* GetFileAttributesW may reject the root of an otherwise accessible
         * network share. CreateFileW was already attempted, so accept the
         * syntactically complete \\server\share fallback here. */
        return 0;
    }
    wchar_t *scan = wcschr(share_end + 1, L'\\');
    if (!scan) scan = path + wcslen(path);
    for (;;) {
        wchar_t saved = *scan;
        *scan = L'\0';
        DWORD attributes = GetFileAttributesW(path);
        DWORD error = attributes == INVALID_FILE_ATTRIBUTES
            ? GetLastError() : ERROR_SUCCESS;
        *scan = saved;
        if (attributes == INVALID_FILE_ATTRIBUTES ||
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            if (attributes == INVALID_FILE_ATTRIBUTES) {
                fprintf(stderr,
                        "mcp_path: GetFileAttributesW(UNC component): Windows error %lu\n",
                        (unsigned long)error);
            } else {
                fprintf(stderr,
                        "mcp_path: UNC component is a reparse point\n");
            }
            errno = attributes == INVALID_FILE_ATTRIBUTES ? ENOENT : EACCES;
            return -1;
        }
        if (!saved) return 0;
        scan = wcschr(scan + 1, L'\\');
        if (!scan) scan = path + wcslen(path);
    }
}

static int canonical_without_handle(const wchar_t *path, int is_unc,
                                    char *output, size_t size) {
    DWORD needed = GetFullPathNameW(path, 0, NULL, NULL);
    if (!needed) { errno = ENOENT; return -1; }
    wchar_t *full = calloc((size_t)needed + 1, sizeof(*full));
    if (!full) return -1;
    if (!GetFullPathNameW(path, needed + 1, full, NULL)) {
        free(full);
        errno = ENOENT;
        return -1;
    }
    if (is_unc) {
        if (check_unc_components(full) != 0) {
            free(full);
            return -1;
        }
    } else {
        DWORD attributes = GetFileAttributesW(full);
        if (attributes == INVALID_FILE_ATTRIBUTES ||
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            free(full);
            errno = attributes == INVALID_FILE_ATTRIBUTES ? ENOENT : EACCES;
            return -1;
        }
    }
    int result = wide_path_to_utf8_slashes(full, output, size);
    free(full);
    return result;
}

static int canonical_existing(const char *path, char *output, size_t size) {
    wchar_t *wide = utf8_to_wide(path);
    if (!wide) { errno = EINVAL; return -1; }
    int is_unc = wide[0] == L'\\' && wide[1] == L'\\';
    HANDLE handle = CreateFileW(wide, FILE_READ_ATTRIBUTES,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD open_error = GetLastError();
        int result = is_unc
            ? canonical_without_handle(wide, 1, output, size) : -1;
        free(wide);
        if (result != 0) {
            fprintf(stderr, "mcp_path: CreateFileW: Windows error %lu\n",
                    (unsigned long)open_error);
            errno = open_error == ERROR_FILE_NOT_FOUND ||
                    open_error == ERROR_PATH_NOT_FOUND ? ENOENT : EACCES;
        }
        return result;
    }
    wchar_t *final = final_path_from_handle(handle, FILE_NAME_NORMALIZED);
    DWORD normalized_error = final ? ERROR_SUCCESS : GetLastError();
    if (!final) {
        /* AppContainer path-disclosure rules and some SMB/NAS implementations
         * can reject normalized per-component queries. The opened name remains
         * handle-derived; root containment and reparse checks still apply. */
        final = final_path_from_handle(handle, FILE_NAME_OPENED);
    }
    if (!final) {
        DWORD opened_error = GetLastError();
        CloseHandle(handle);
        /* The handle proves that the object is accessible. AppContainer may
         * nevertheless deny both path-disclosure queries with ERROR_ACCESS_DENIED.
         * Fall back to lexical absolute-path expansion plus attribute checks. */
        int result = canonical_without_handle(wide, is_unc, output, size);
        free(wide);
        if (result != 0) {
            fprintf(stderr,
                    "mcp_path: GetFinalPathNameByHandleW: Windows errors %lu/%lu\n",
                    (unsigned long)normalized_error,
                    (unsigned long)opened_error);
            errno = EACCES;
        }
        return result;
    }
    CloseHandle(handle);
    free(wide);
    int result = wide_path_to_utf8_slashes(final, output, size);
    free(final);
    return result;
}

static int reject_reparse_below_root(const char *root, const char *candidate,
                                     int allow_missing_leaf) {
    wchar_t *wide_root = utf8_to_wide(root);
    wchar_t *wide_candidate = utf8_to_wide(candidate);
    if (!wide_root || !wide_candidate) {
        free(wide_root);
        free(wide_candidate);
        errno = EINVAL;
        return -1;
    }
    size_t root_length = wcslen(wide_root);
    wchar_t *scan = wide_candidate + root_length;
    while (*scan == L'\\') scan++;
    for (;;) {
        wchar_t *separator = wcschr(scan, L'\\');
        wchar_t *end = separator ? separator : wide_candidate + wcslen(wide_candidate);
        wchar_t saved = *end;
        *end = L'\0';
        DWORD attributes = GetFileAttributesW(wide_candidate);
        DWORD attribute_error = attributes == INVALID_FILE_ATTRIBUTES
            ? GetLastError() : ERROR_SUCCESS;
        *end = saved;
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            int not_found = attribute_error == ERROR_FILE_NOT_FOUND ||
                            attribute_error == ERROR_PATH_NOT_FOUND;
            int missing_leaf = allow_missing_leaf && !saved && not_found;
            free(wide_root);
            free(wide_candidate);
            errno = missing_leaf ? 0 :
                    attribute_error == ERROR_ACCESS_DENIED ? EACCES :
                    not_found ? ENOENT : EIO;
            return missing_leaf ? 0 : -1;
        }
        if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            free(wide_root);
            free(wide_candidate);
            errno = EACCES;
            return -1;
        }
        if (!saved) break;
        scan = end + 1;
    }
    free(wide_root);
    free(wide_candidate);
    return 0;
}

static int path_prefix(const char *path, const char *root) {
    size_t length = strlen(root);
    if (_strnicmp(path, root, length) != 0) return 0;
    return path[length] == '\0' || root[length - 1] == '/' || path[length] == '/';
}

#else

static int canonical_existing(const char *path, char *output, size_t size) {
    char resolved[PATH_MAX];
    if (!realpath(path, resolved)) return -1;
    return copy_path(output, size, resolved);
}

static int path_prefix(const char *path, const char *root) {
    size_t length = strlen(root);
    if (strncmp(path, root, length) != 0) return 0;
    return path[length] == '\0' || root[length - 1] == '/' || path[length] == '/';
}

#endif

int mcp_path_resolve(const char *native_root, const char *virtual_path,
                     int allow_missing_leaf, char *native_path,
                     size_t native_path_size) {
    if (!native_root || !*native_root || !native_path || !native_path_size) {
        errno = EINVAL;
        return -1;
    }
    char root[MCP_NATIVE_PATH_MAX];
    if (canonical_existing(native_root, root, sizeof(root)) != 0) return -1;
    char logical[MCP_NATIVE_PATH_MAX];
    if (normalize_virtual(virtual_path, logical, sizeof(logical)) != 0) return -1;
    if (!strcmp(logical, "/"))
        return copy_path(native_path, native_path_size, root);

    char candidate[MCP_NATIVE_PATH_MAX];
    int written = snprintf(candidate, sizeof(candidate), "%s/%s",
                           root, logical + 1);
    if (written < 0 || (size_t)written >= sizeof(candidate)) {
        errno = ENAMETOOLONG;
        return -1;
    }
#ifdef _WIN32
    if (reject_reparse_below_root(root, candidate, allow_missing_leaf) != 0)
        return -1;
#endif

    char resolved[MCP_NATIVE_PATH_MAX] = {0};
    int existing_result = canonical_existing(candidate, resolved, sizeof(resolved));
    if (existing_result != 0 && !allow_missing_leaf) return -1;
    if (existing_result != 0) {
        char *slash = strrchr(candidate, '/');
        if (!slash || !slash[1]) { errno = EINVAL; return -1; }
        char leaf[MCP_NATIVE_PATH_MAX];
        if (copy_path(leaf, sizeof(leaf), slash + 1) != 0) return -1;
        *slash = '\0';
        char parent[MCP_NATIVE_PATH_MAX];
        if (canonical_existing(candidate, parent, sizeof(parent)) != 0) return -1;
        written = snprintf(resolved, sizeof(resolved), "%s/%s", parent, leaf);
        if (written < 0 || (size_t)written >= sizeof(resolved)) {
            errno = ENAMETOOLONG;
            return -1;
        }
    }
    if (!path_prefix(resolved, root)) { errno = EACCES; return -1; }
    return copy_path(native_path, native_path_size, resolved);
}

int mcp_path_to_virtual(const char *native_root, const char *native_path,
                        char *virtual_path, size_t virtual_path_size) {
    char root[MCP_NATIVE_PATH_MAX];
    if (!native_root || !native_path ||
        canonical_existing(native_root, root, sizeof(root)) != 0 ||
        !path_prefix(native_path, root)) {
        errno = EACCES;
        return -1;
    }
    const char *relative = native_path + strlen(root);
    while (*relative == '/' || *relative == '\\') relative++;
    if (!*relative) return copy_path(virtual_path, virtual_path_size, "/");
    int written = snprintf(virtual_path, virtual_path_size, "/%s", relative);
    if (written < 0 || (size_t)written >= virtual_path_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    for (char *p = virtual_path; *p; p++) if (*p == '\\') *p = '/';
    return 0;
}

int mcp_path_canonicalize(const char *native_path, char *canonical_path,
                          size_t canonical_path_size) {
    if (!native_path || !*native_path || !canonical_path || !canonical_path_size) {
        errno = EINVAL;
        return -1;
    }
    return canonical_existing(native_path, canonical_path, canonical_path_size);
}

int mcp_path_is_link(const char *native_path) {
    if (!native_path) return -1;
#ifdef _WIN32
    wchar_t *wide = utf8_to_wide(native_path);
    if (!wide) return -1;
    DWORD attributes = GetFileAttributesW(wide);
    free(wide);
    if (attributes == INVALID_FILE_ATTRIBUTES) return -1;
    return (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
    struct stat status;
    if (lstat(native_path, &status) != 0) return -1;
    return S_ISLNK(status.st_mode) != 0;
#endif
}
