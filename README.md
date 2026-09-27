# MCP core library

`libmcp_core.a` contains the parts shared by local MCP servers:

- `mcp_sandbox_enter()` selects the platform sandbox: Linux uses a user/mount
  namespace plus `pivot_root`; Windows brokers the same command line into an
  AppContainer child.
- `mcp_path_resolve()` and `mcp_path_to_virtual()` form a small SQLite-VFS-like
  path backend. MCP paths remain `/directory/file` on every OS while native
  drive/UNC paths stay inside this layer.
- `mcp_transport_run()` reads newline-delimited JSON-RPC from stdin and calls
  the application request handler.
- `mcp_transport_send_response()` and `mcp_transport_send_error()` emit
  JSON-RPC 2.0 responses on stdout.

Example:

```c
#include "mcp_core.h"

static void dispatch(json_object *request, void *userdata) {
    (void)userdata;
    /* application-specific method dispatch */
}

int main(void) {
    char root[4096];
    if (mcp_sandbox_enter("/path/to/worktree", root, sizeof(root)) != 0)
        return 1;
    return mcp_transport_run(dispatch, NULL);
}
```

Build the archive with:

```sh
make -C devel/mcp_lib
```

Link with `devel/mcp_lib/libmcp_core.a`, `-ljson-c`, and `-lpthread`.

On Windows, compile the same sources with `_WIN32_WINNT=0x0A00` and link
`userenv` and `advapi32`. The broker creates a stable, root-specific
AppContainer profile, grants that SID access to the selected root, grants
read/execute access to the executable directory, and starts the same command
line with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`. The outgoing Internet
capability is included because `download_file` is part of the server.

The Windows ACL entries are persistent and scoped to the root-specific package
SID. This is intentional: files created after startup inherit the same access,
and subsequent launches do not need to rewrite every descendant ACL.
