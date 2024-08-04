# Geatu

Geatu is a type-based access policy engine (for now).

## Security Data

### Tags
Geatu tags files. Path-based approach may be an useful replacement for filesystems does not support xattr.

### Sensitivity
Sensitivity is a signed integer.
Unlike serious MLP implementations, .

### Rules
In Geatu, rules map a given tag to other tags for matching permissions.

## Cloaking
Processes with the same executbale may drop some categories, lower sensitivity or change its security context.

## Tainting (TBD)
Script interpreter open some script the same as oridinal files. However, 

### Explicit tainting
A call will be provided to use the security profile of target script. The executable is to be flagged `explicit taint` to apply for this tainting.

### Implicit tainting
The security profile of the process is the intersection of all files opened for read.
Or, files may designate categories to drop on reading.

#### Forcibly tainting
Process open file with this flag to read or map as executable will be affected regardless of original flags.
Useful for security-related libraries.

## xattr
* Filesystem must be capable of xattr.
* Some fs may expose size limit on all xattr items. ext* is block size.
* names:
    * `security.geatu1`: basic tags
    * `security.geatu1e`: extended tags (TBD)

## Non-file Resources (TODO)
This section also applies files unable to append xattr.

### `localhost` protection
When a process bind to `localhost`, its security data are kept for check.
On connecting, the security tag of client will be matched against it.
Administrator may choose to match ids, sensitivity level or/and Geatu tags.

Localhost is `127.0.0.0/8` and `::1`.

### Explicit rules
This means storing paths (preferably with globs) and policys in global context.