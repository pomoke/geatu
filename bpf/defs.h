// BTF exports does not include constants.

#define AF_INET 2
#define AF_INET6 10

#define XATTR_NAME "security.geatu1"

enum {
    ENABLED = 0,
    // Connecting to endpoints on localhost applies to classic unix authentication.
    CONF_PROTECT_LOCALHOST = 1,

};

enum {
    // localhost addr+host pair not to be protected.
    // type: localhost_h
    LIST_UNPROTECTED_ENDPOINT = 1,

};