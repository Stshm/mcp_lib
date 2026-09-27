#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "mcp_core.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <userenv.h>
#else
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

static int child_exit_code;

int mcp_sandbox_child_exit_code(void) {
    return child_exit_code;
}

#ifdef _WIN32

static char startup_file[32768];

int mcp_sandbox_allow_startup_file(const char *native_path) {
    if (!native_path || !*native_path) return 0;
    int length = snprintf(startup_file, sizeof(startup_file), "%s", native_path);
    if (length < 0 || (size_t)length >= sizeof(startup_file)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int win32_error(const char *operation, DWORD error) {
    fprintf(stderr, "mcp_sandbox_enter: %s: Windows error %lu\n",
            operation, (unsigned long)error);
    errno = EACCES;
    return -1;
}

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

static unsigned long long fnv1a64(const char *text) {
    unsigned long long hash = 1469598103934665603ULL;
    while (*text) {
        hash ^= (unsigned char)*text++;
        hash *= 1099511628211ULL;
    }
    return hash;
}

static DWORD grant_path(PCWSTR path, PSID sid, ACCESS_MASK permissions,
                        int inherit_to_children) {
    PACL old_acl = NULL;
    PACL new_acl = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    DWORD error = GetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT,
                                        DACL_SECURITY_INFORMATION,
                                        NULL, NULL, &old_acl, NULL, &descriptor);
    if (error != ERROR_SUCCESS) return error;

    EXPLICIT_ACCESSW access;
    ZeroMemory(&access, sizeof(access));
    access.grfAccessPermissions = permissions;
    access.grfAccessMode = GRANT_ACCESS;
    access.grfInheritance = inherit_to_children
        ? CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE : NO_INHERITANCE;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_USER;
    access.Trustee.ptstrName = (LPWSTR)sid;
    error = SetEntriesInAclW(1, &access, old_acl, &new_acl);
    if (error == ERROR_SUCCESS) {
        error = SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT,
                                      DACL_SECURITY_INFORMATION,
                                      NULL, NULL, new_acl, NULL);
    }
    if (new_acl) LocalFree(new_acl);
    if (descriptor) LocalFree(descriptor);
    return error;
}

static int current_process_is_appcontainer(void) {
    HANDLE token = NULL;
    DWORD is_appcontainer = 0;
    DWORD returned = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return -1;
    BOOL ok = GetTokenInformation(token, TokenIsAppContainer,
                                  &is_appcontainer, sizeof(is_appcontainer),
                                  &returned);
    CloseHandle(token);
    return ok ? (is_appcontainer != 0) : -1;
}

static PSID get_profile_sid(const char *root_dir) {
    wchar_t profile_name[64];
    _snwprintf(profile_name, sizeof(profile_name) / sizeof(profile_name[0]),
               L"McpCore2.%016llx", fnv1a64(root_dir));
    PSID internet_sid = NULL;
    if (!ConvertStringSidToSidW(L"S-1-15-3-1", &internet_sid)) {
        DWORD error = GetLastError();
        SetLastError(error);
        return NULL;
    }
    SID_AND_ATTRIBUTES capabilities[1] = {
        {internet_sid, SE_GROUP_ENABLED}
    };
    PSID sid = NULL;
    HRESULT result = CreateAppContainerProfile(profile_name,
                                                L"MCP filesystem sandbox",
                                                L"Filesystem root for a local MCP server",
                                                capabilities, 1, &sid);
    if (result == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
        result = DeriveAppContainerSidFromAppContainerName(profile_name, &sid);
    }
    LocalFree(internet_sid);
    if (FAILED(result)) {
        SetLastError(HRESULT_CODE(result));
        return NULL;
    }
    return sid;
}

int mcp_sandbox_enter(const char *root_dir, char *visible_root,
                      size_t visible_root_size) {
    if (!root_dir || !*root_dir) {
        errno = EINVAL;
        return -1;
    }
    int is_unc_root = (root_dir[0] == '/' && root_dir[1] == '/') ||
                      (root_dir[0] == '\\' && root_dir[1] == '\\');
    if (is_unc_root) {
        fprintf(stderr,
                "mcp_sandbox_enter: UNC roots are not supported by the Windows AppContainer backend\n");
        errno = ENOTSUP;
        return -1;
    }
    int contained = current_process_is_appcontainer();
    if (contained < 0) return win32_error("query AppContainer token", GetLastError());
    if (contained) {
        if (visible_root && visible_root_size) {
            int length = snprintf(visible_root, visible_root_size, "%s", root_dir);
            if (length < 0 || (size_t)length >= visible_root_size) {
                errno = ENAMETOOLONG;
                return -1;
            }
        }
        return 0;
    }

    wchar_t *root = utf8_to_wide(root_dir);
    if (!root) return win32_error("convert root path to UTF-16", GetLastError());
    PSID package_sid = get_profile_sid(root_dir);
    if (!package_sid) {
        DWORD error = GetLastError();
        free(root);
        return win32_error("create AppContainer profile", error);
    }

    DWORD error = grant_path(root, package_sid,
                                  FILE_GENERIC_READ | FILE_GENERIC_WRITE |
                                  FILE_GENERIC_EXECUTE | DELETE | FILE_DELETE_CHILD, 1);
    if (error != ERROR_SUCCESS) {
        FreeSid(package_sid);
        free(root);
        return win32_error("grant AppContainer access to root", error);
    }
    if (startup_file[0]) {
        wchar_t *allowed_file = utf8_to_wide(startup_file);
        if (!allowed_file) {
            FreeSid(package_sid);
            free(root);
            return win32_error("convert startup file path to UTF-16", GetLastError());
        }
        error = grant_path(allowed_file, package_sid, FILE_GENERIC_READ, 0);
        free(allowed_file);
        if (error != ERROR_SUCCESS) {
            FreeSid(package_sid);
            free(root);
            return win32_error("grant AppContainer access to startup file", error);
        }
    }

    wchar_t executable[32768];
    DWORD executable_length = GetModuleFileNameW(NULL, executable,
                                                 (DWORD)(sizeof(executable) / sizeof(executable[0])));
    if (!executable_length || executable_length >= sizeof(executable) / sizeof(executable[0])) {
        error = GetLastError();
        FreeSid(package_sid);
        free(root);
        return win32_error("get executable path", error);
    }
    wchar_t executable_dir[32768];
    memcpy(executable_dir, executable, (executable_length + 1) * sizeof(wchar_t));
    wchar_t *separator = wcsrchr(executable_dir, L'\\');
    if (separator) *separator = L'\0';
    error = grant_path(executable_dir, package_sid,
                       FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, 1);
    if (error != ERROR_SUCCESS) {
        FreeSid(package_sid);
        free(root);
        return win32_error("grant AppContainer access to executable directory", error);
    }

    PSID internet_sid = NULL;
    if (!ConvertStringSidToSidW(L"S-1-15-3-1", &internet_sid)) {
        error = GetLastError();
        FreeSid(package_sid);
        free(root);
        return win32_error("create internetClient capability SID", error);
    }
    SID_AND_ATTRIBUTES capabilities[1] = {
        {internet_sid, SE_GROUP_ENABLED}
    };
    SECURITY_CAPABILITIES security_capabilities;
    ZeroMemory(&security_capabilities, sizeof(security_capabilities));
    security_capabilities.AppContainerSid = package_sid;
    security_capabilities.Capabilities = capabilities;
    security_capabilities.CapabilityCount = 1;

    HANDLE inherited_handles[3] = {NULL, NULL, NULL};
    DWORD standard_ids[3] = {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
    for (size_t i = 0; i < 3; i++) {
        HANDLE source = GetStdHandle(standard_ids[i]);
        if (!source || source == INVALID_HANDLE_VALUE ||
            !DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(),
                             &inherited_handles[i], 0, TRUE,
                             DUPLICATE_SAME_ACCESS)) {
            error = source && source != INVALID_HANDLE_VALUE
                ? GetLastError() : ERROR_INVALID_HANDLE;
            for (size_t j = 0; j < i; j++) CloseHandle(inherited_handles[j]);
            LocalFree(internet_sid);
            FreeSid(package_sid);
            free(root);
            return win32_error("duplicate standard handles", error);
        }
    }

    SIZE_T attribute_size = 0;
    InitializeProcThreadAttributeList(NULL, 2, 0, &attribute_size);
    LPPROC_THREAD_ATTRIBUTE_LIST attributes =
        HeapAlloc(GetProcessHeap(), 0, attribute_size);
    BOOL attributes_initialized = attributes &&
        InitializeProcThreadAttributeList(attributes, 2, 0, &attribute_size);
    BOOL attributes_prepared = attributes_initialized &&
        UpdateProcThreadAttribute(attributes, 0,
                                  PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                  &security_capabilities,
                                  sizeof(security_capabilities), NULL, NULL) &&
        UpdateProcThreadAttribute(attributes, 0,
                                  PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                  inherited_handles,
                                  sizeof(inherited_handles), NULL, NULL);
    if (!attributes_prepared) {
        error = GetLastError();
        if (attributes_initialized) DeleteProcThreadAttributeList(attributes);
        if (attributes) HeapFree(GetProcessHeap(), 0, attributes);
        for (size_t i = 0; i < 3; i++) CloseHandle(inherited_handles[i]);
        LocalFree(internet_sid);
        FreeSid(package_sid);
        free(root);
        return win32_error("prepare AppContainer process attributes", error);
    }

    STARTUPINFOEXW startup;
    ZeroMemory(&startup, sizeof(startup));
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = inherited_handles[0];
    startup.StartupInfo.hStdOutput = inherited_handles[1];
    startup.StartupInfo.hStdError = inherited_handles[2];
    startup.lpAttributeList = attributes;

    const wchar_t *original_command = GetCommandLineW();
    size_t command_bytes = (wcslen(original_command) + 1) * sizeof(wchar_t);
    wchar_t *command = malloc(command_bytes);
    if (command) memcpy(command, original_command, command_bytes);
    PROCESS_INFORMATION process;
    ZeroMemory(&process, sizeof(process));
    BOOL created = command && CreateProcessW(executable, command, NULL, NULL, TRUE,
                                              EXTENDED_STARTUPINFO_PRESENT |
                                              CREATE_UNICODE_ENVIRONMENT,
                                              NULL, NULL, &startup.StartupInfo,
                                              &process);
    error = created ? ERROR_SUCCESS : GetLastError();
    free(command);
    DeleteProcThreadAttributeList(attributes);
    HeapFree(GetProcessHeap(), 0, attributes);
    for (size_t i = 0; i < 3; i++) CloseHandle(inherited_handles[i]);
    LocalFree(internet_sid);
    FreeSid(package_sid);
    free(root);
    if (!created) return win32_error("launch AppContainer child", error);

    CloseHandle(process.hThread);
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exit_code = 1;
    GetExitCodeProcess(process.hProcess, &exit_code);
    CloseHandle(process.hProcess);
    child_exit_code = (int)exit_code;
    return 1;
}

#else

int mcp_sandbox_allow_startup_file(const char *native_path) {
    (void)native_path;
    return 0;
}

static int sandbox_error(const char *operation) {
    int saved_errno = errno;
    fprintf(stderr, "mcp_sandbox_enter: %s: %s\n",
            operation, strerror(saved_errno));
    errno = saved_errno;
    return -1;
}

static int write_map(const char *path, const char *value) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    size_t len = strlen(value);
    ssize_t written = write(fd, value, len);
    int saved_errno = errno;
    close(fd);
    if (written != (ssize_t)len) {
        errno = written < 0 ? saved_errno : EIO;
        return -1;
    }
    return 0;
}

int mcp_sandbox_enter(const char *root_dir, char *visible_root, size_t visible_root_size) {
    char root[PATH_MAX];
    uid_t host_uid = getuid();
    gid_t host_gid = getgid();

    if (!root_dir) {
        errno = EINVAL;
        return sandbox_error("root directory");
    }
    if (!realpath(root_dir, root)) return sandbox_error("realpath");
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0)
        return sandbox_error("unshare(CLONE_NEWUSER | CLONE_NEWNS)");

    int fd = open("/proc/self/setgroups", O_WRONLY);
    if (fd >= 0) {
        /* Keep the historical behavior: kernels may accept the write with
         * different procfs semantics, but the mapping is still valid. */
        ssize_t ignored = write(fd, "deny", 4);
        (void)ignored;
        close(fd);
    } else {
        return sandbox_error("open /proc/self/setgroups");
    }

    char map[64];
    snprintf(map, sizeof(map), "0 %ld 1\n", (long)host_uid);
    if (write_map("/proc/self/uid_map", map) != 0)
        return sandbox_error("write /proc/self/uid_map");
    snprintf(map, sizeof(map), "0 %ld 1\n", (long)host_gid);
    if (write_map("/proc/self/gid_map", map) != 0)
        return sandbox_error("write /proc/self/gid_map");

    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
        return sandbox_error("mount / private");
    /* Recursive bind is important when the configured root contains mounted
     * subtrees, and matches the pre-library implementation. */
    if (mount(root, root, NULL, MS_BIND | MS_REC, NULL) != 0)
        return sandbox_error("recursive bind mount root");

    char old_root[PATH_MAX];
    int old_root_length = snprintf(old_root, sizeof(old_root),
                                   "%s/tmp/.old.XXXXXX", root);
    if (old_root_length < 0 || old_root_length >= (int)sizeof(old_root)) {
        errno = ENAMETOOLONG;
        return sandbox_error("build tmp/.old path");
    }
    if (!mkdtemp(old_root))
        return sandbox_error("mkdtemp tmp/.old");

    const char *old_root_name = strrchr(old_root, '/');
    char visible_old_root[PATH_MAX];
    int visible_old_root_length = snprintf(visible_old_root,
                                           sizeof(visible_old_root),
                                           "/tmp/%s", old_root_name + 1);
    if (visible_old_root_length < 0 ||
        visible_old_root_length >= (int)sizeof(visible_old_root)) {
        int saved_errno = ENAMETOOLONG;
        rmdir(old_root);
        errno = saved_errno;
        return sandbox_error("build visible tmp/.old path");
    }

    if (syscall(SYS_pivot_root, root, old_root) != 0) {
        int saved_errno = errno;
        rmdir(old_root);
        errno = saved_errno;
        return sandbox_error("pivot_root");
    }
    if (chdir("/") != 0) return sandbox_error("chdir /");
    if (umount2(visible_old_root, MNT_DETACH) != 0)
        return sandbox_error("unmount /tmp/.old");
    if (rmdir(visible_old_root) != 0 && errno != ENOENT)
        return sandbox_error("rmdir /tmp/.old");
    if (visible_root && visible_root_size > 0) {
        snprintf(visible_root, visible_root_size, "/");
    }
    return 0;
}

#endif
