#include "vmlinux.h"
#include "bits/types.h"
#include "defs.h"
#include <bits/endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <errno.h>
#include "common.h"

char __license[] SEC("license") = "GPL";

#define IPv6_LOCAL 0x8000000

struct localhost_h {
    u32 addr;
    u16 port;
};

struct net_policy {
    uid_t uid;
    gid_t gid;
};

struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __type(key, struct localhost_h);
    __type(value, struct net_policy);
    __uint(max_entries, 1<<16);
    __uint(map_flags, BPF_F_NO_PREALLOC);

} localhostmap SEC(".maps");

struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct localhost_h);
    __uint(max_entries, 1<<16);
    __uint(map_flags, BPF_F_NO_PREALLOC);

} inode_addr_map SEC(".maps");


/*
struct bpf_map_def SEC("maps") localmap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct localhost_h),
    .value_size = sizeof(u32),
    .max_entries = 1<<23,
};
*/

SEC("lsm/socket_bind")
int BPF_PROG(socket_bind,struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    // We cannot override denies.
    FALLTHROUGH()

    unsigned short type = address->sa_family;
    struct net_policy value = {
        .uid = bpf_get_current_uid_gid() & 0xfffffffful,
        .gid = bpf_get_current_uid_gid() >> 32,
    };

    if (type == AF_INET)
    {
        // IP is big endian.
        struct sockaddr_in *addr = address;
        u32 ip4 = BPF_CORE_READ(addr,sin_addr.s_addr);
        u16 port = BPF_CORE_READ(addr,sin_port);
        port = bpf_ntohs(port);
        if ((ip4 & 127) && port)
        {
            // Insert into maps.
            struct localhost_h key = {
                .addr = ip4,
                .port = port,
            };
            int ret = bpf_map_update_elem(&localhostmap, &key, &value, BPF_NOEXIST);
            if (!ret)
            {
                // Track for inode item.
                struct inode *inode = sock->file->f_inode;
                bpf_map_update_elem(&inode_addr_map, &inode, &key, 0);
                bpf_printk("geatu-net: localhost:%d in.", key.port);
            }
        }
    }
    else if (type == AF_INET6)
    {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)address;
        u32 a1,a2,a3,a4;
        bpf_core_read(&a1, 4, a->sin6_addr.in6_u.u6_addr32 + 0);
        bpf_core_read(&a2, 4, a->sin6_addr.in6_u.u6_addr32 + 1);
        bpf_core_read(&a3, 4, a->sin6_addr.in6_u.u6_addr32 + 2);
        bpf_core_read(&a4, 4, a->sin6_addr.in6_u.u6_addr32 + 3);
        if (
            a1 == 0 &&
            a2 == 0 &&
            a3 == 0 &&
            a4 == bpf_htonl(1) 
        ) {
            struct localhost_h key = {
                .addr = IPv6_LOCAL,
                .port = bpf_ntohs(a->sin6_port),
            };
            int ret = bpf_map_update_elem(&localhostmap, &key, &value, BPF_NOEXIST);
            bpf_printk("geatu-net: [::1]:%d in.\n", bpf_ntohs(a->sin6_port));
            if (!ret)
            {
                // Track for inode item.
                struct inode *inode = sock->file->f_inode;
                bpf_map_update_elem(&inode_addr_map, &inode, &key, 0);
                bpf_printk("geatu-net: localhost:%d in.", key.port);
            }
        }
    }
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *addr, int addr_len, int ret)
{
    if (ret) return ret; 
    int type = addr->sa_family;

    if (type == AF_INET)
    {
        // IP is big endian.
        u32 ip4 = BPF_CORE_READ((struct sockaddr_in *)addr,sin_addr.s_addr);
        if ((ip4 & 0xff) == 127)
        {
            // target in map?
            u16 port = BPF_CORE_READ((struct sockaddr_in *)addr,sin_port);
            struct localhost_h key = {
                .addr = ip4, 
                .port = bpf_ntohs(port),
            };
            //bpf_printk("geatu-net: %pI4:%d", &key.addr, key.port);
            struct net_policy *policy = bpf_map_lookup_elem(&localhostmap, &key);
            if (policy)
            {
                // Test
                int uid = bpf_get_current_uid_gid() & 0xfffffffful;
                // root access is unlimited.
                if (uid != 0 && uid != policy->uid)
                {
                    bpf_printk("geatu-net: deny %d\n", key.port);
                    // Reject connection as if there are no server here.
                    return -ECONNREFUSED;
                }
                else
                {
                    bpf_printk("geatu-net: allow %d from %d to %d\n", key.port, uid, policy->uid);
                }
            }
            else
            {
                //bpf_printk("geatu-net: allow by no policy found");
            }
        }
    }
    else if (type == AF_INET6)
    {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)addr;
        u32 a1,a2,a3,a4;
        bpf_core_read(&a1, 4, a->sin6_addr.in6_u.u6_addr32 + 0);
        bpf_core_read(&a2, 4, a->sin6_addr.in6_u.u6_addr32 + 1);
        bpf_core_read(&a3, 4, a->sin6_addr.in6_u.u6_addr32 + 2);
        bpf_core_read(&a4, 4, a->sin6_addr.in6_u.u6_addr32 + 3);
        if (
            a1 == 0 &&
            a2 == 0 &&
            a3 == 0 &&
            a4 == bpf_htonl(1))
        {
            struct localhost_h key = {
                .addr = IPv6_LOCAL,
                .port = bpf_ntohs(a->sin6_port),
            };
            struct net_policy *policy = bpf_map_lookup_elem(&localhostmap, &key);
            if (policy)
            {
                // Test
                int uid = bpf_get_current_uid_gid() & 0xfffffffful;
                // root access is unlimited.
                if (uid != 0 && uid != policy->uid)
                {
                    bpf_printk("geatu-net: deny [::1]:%d\n", key.port);
                    // Reject connection as if there are no server here.
                    return -ECONNREFUSED;
                }
                else
                {
                    bpf_printk("geatu-net: allow [::1]:%d from %d to %d\n", key.port, uid, policy->uid);
                }
            }
        }
    }
    return 0;
}
    
/// If there is anything better to watch for socket closing, submit a PR.
SEC("lsm/inode_free_security")
void BPF_PROG(geatu_socket_release, struct inode *inode) {
    struct localhost_h *ret = bpf_map_lookup_elem(&inode_addr_map, &inode);
    if (ret) {
        bpf_map_delete_elem(&localhostmap, ret);
        bpf_map_delete_elem(&inode_addr_map, &inode);
        bpf_printk("geatu-net: %pI4:%d left.\n", &ret->addr, ret->port);
    }
}