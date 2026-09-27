#ifndef MCP_CORE_H
#define MCP_CORE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <time.h>
#include <json-c/json.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*mcp_request_handler)(json_object *request, void *userdata);

/*
 * Enter the platform sandbox rooted at root_dir.
 *
 * Linux enters a user/mount namespace in the current process.  Windows first
 * launches the same command line in an AppContainer and returns 1 from the
 * broker process; the AppContainer child returns 0 and continues normally.
 */
int mcp_sandbox_enter(const char *root_dir, char *visible_root, size_t visible_root_size);

/* Exit status of the sandbox child when mcp_sandbox_enter() returned 1. */
int mcp_sandbox_child_exit_code(void);
/* Grant an additional read-only startup file to the Windows AppContainer. */
int mcp_sandbox_allow_startup_file(const char *native_path);

/* OS-path backend. Client-visible paths always use '/' and have no drive. */
int mcp_path_resolve(const char *native_root, const char *virtual_path,
                     int allow_missing_leaf, char *native_path,
                     size_t native_path_size);
int mcp_path_to_virtual(const char *native_root, const char *native_path,
                        char *virtual_path, size_t virtual_path_size);
int mcp_path_canonicalize(const char *native_path, char *canonical_path,
                          size_t canonical_path_size);
int mcp_path_is_link(const char *native_path);

/* Small file-operation backend used where POSIX and Win32 semantics differ. */
int mcp_file_stat(const char *path, struct stat *status);
int mcp_file_size_bytes(const char *path, int64_t *size_bytes);
int mcp_file_set_descriptor_mode(int descriptor, unsigned int mode);
int mcp_file_replace(const char *temporary_path, const char *destination_path);
int mcp_file_publish_exclusive(const char *temporary_path,
                               const char *destination_path);
int mcp_time_utc(const time_t *value, struct tm *result);

/* Read newline-delimited JSON-RPC messages from stdin until EOF. */
int mcp_transport_run(mcp_request_handler handler, void *userdata);

void mcp_transport_send_response(json_object *id, json_object *result);
void mcp_transport_send_error(json_object *id, int code, const char *message);

#ifdef __cplusplus
}
#endif

#endif
