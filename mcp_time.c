#include "mcp_core.h"

int mcp_time_utc(const time_t *value, struct tm *result) {
    if (!value || !result) return -1;
#ifdef _WIN32
    return gmtime_s(result, value) == 0 ? 0 : -1;
#else
    return gmtime_r(value, result) ? 0 : -1;
#endif
}
