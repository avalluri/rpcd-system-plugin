/*
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
 * DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define _GNU_SOURCE /* crypt() */

#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <glob.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include <rpcd/plugin.h>

static const struct rpc_daemon_ops *ops;
static struct blob_buf buf;

/*
 * system.info = {
 *   localtime,
 *   uptime,
 *   load[3],
 *   memory = {
 *     total,
 *     free,
 *     shared,
 *     buffered,
 *   }
 * }
 */

static int
system_info(struct ubus_context *ctx, struct ubus_object *obj,
                 struct ubus_request_data *req, const char *method,
                                  struct blob_attr *msg)
{
    time_t t;
    struct tm *tm;
    struct sysinfo info;
    void *p = NULL;

    if(sysinfo(&info))
        return UBUS_STATUS_UNKNOWN_ERROR;

    t = time(NULL);
    if (!(tm = localtime(&t)))
        return UBUS_STATUS_UNKNOWN_ERROR;

    blob_buf_init(&buf, 0);
    blobmsg_add_u32(&buf, "localtime", t + tm->tm_gmtoff);
    blobmsg_add_u32(&buf, "uptime", info.uptime);

    p = blobmsg_open_array(&buf, "load");
    blobmsg_add_u32(&buf, NULL, info.loads[0]);
    blobmsg_add_u32(&buf, NULL, info.loads[1]);
    blobmsg_add_u32(&buf, NULL, info.loads[2]);
    blobmsg_close_array(&buf, p);

    p = blobmsg_open_table(&buf, "memory");
    blobmsg_add_u64(&buf, "total", info.mem_unit * info.totalram);
    blobmsg_add_u64(&buf, "free", info.mem_unit * info.freeram);
    blobmsg_add_u64(&buf, "shared", info.mem_unit * info.sharedram);
    blobmsg_add_u64(&buf, "buffered", info.mem_unit * info.bufferram);
    blobmsg_close_table(&buf, p);

    p = blobmsg_open_table(&buf, "swap");
    blobmsg_add_u64(&buf, "total", info.mem_unit * info.totalswap);
    blobmsg_add_u64(&buf, "free", info.mem_unit * info.freeswap);
    blobmsg_close_table(&buf, p);

    ubus_send_reply(ctx, req, buf.head);

    return UBUS_STATUS_OK;
}

/*
 * system.board = {
 *   kernel,
 *   hostname,
 *   system,
 *   model
 * }
 */

static int
system_boardinfo(struct ubus_context *ctx, struct ubus_object *obj,
                 struct ubus_request_data *req, const char *method,
                 struct blob_attr *msg)
{
    struct utsname u;
    FILE *fp = NULL;
    char line[256], *key = NULL, *val = NULL;

 	blob_buf_init(&buf, 0);

    if (uname(&u) >= 0) {
	    blobmsg_add_string(&buf, "kernel", u.release);
        blobmsg_add_string(&buf, "hostname", u.nodename);
    }

    if ((fp = fopen("/proc/cpuinfo", "r"))) {
        while (fgets(line, sizeof(line), fp)) {
            key = strtok(line, "\t:");
            val = strtok(NULL, "\t\n");

            if (key && val) {
                if (!strcasecmp(key, "processor") ||
                    !strcasecmp(key, "model name")) {
                    blobmsg_add_string(&buf, "system", val + 2);
                } else if(!strcasecmp(key, "machine") ||
                          !strcasecmp(key, "hardware")) {
                    blobmsg_add_string(&buf, "model", val + 2);
                }
            }
        }
        fclose(fp);
    }

    if ((fp = fopen("/etc/os-release", "r"))) {
        enum {
            KEY_NAME = 0x01,
            KEY_ID = 0x02,
            KEY_VERSION = 0x04,
            KEY_PRETTY = 0x08,
            FOUND_ALL = KEY_NAME | KEY_ID | KEY_VERSION | KEY_PRETTY
        };
        int found = 0x00;
        void *p = NULL;

        p = blobmsg_open_table(&buf, "release");
        
        while(fgets(line, sizeof(line), fp)) {
            key = strtok(line, "=");
            val = strtok(NULL, "\n");

            if (key && val) {
                if (!(found & KEY_ID) && !strcasecmp(key, "ID")) {
                    found |= KEY_ID;
                    blobmsg_add_string(&buf, "distribution", val+1);
                } else if (!(found & KEY_PRETTY) && !strcasecmp(key, "PRETTY_NAME")) {
                    found |= KEY_PRETTY;
                    blobmsg_add_string(&buf, "description", val+1);
                } else if (!(found & (KEY_NAME | KEY_PRETTY)) &&
                           !strcasecmp(key, "NAME")) {
                    found = KEY_NAME;
                    blobmsg_add_string(&buf, "description", val+1);
                } else if (!(found & KEY_VERSION) && strcasecmp(key, "VERSION")) {
                    found = KEY_VERSION;
                    blobmsg_add_string(&buf, "version", val+1);
                }
                if (found == FOUND_ALL) break;
            }
        }

        blobmsg_close_table(&buf, p);
        fclose(fp);
    }

	ubus_send_reply(ctx, req, buf.head);

	return UBUS_STATUS_OK;
}

static int
plugin_init(const struct rpc_daemon_ops *o, struct ubus_context *ctx)
{
	int rv = 0;

	static const struct ubus_method system_methods[] = {
		UBUS_METHOD_NOARG("board", system_boardinfo),
		UBUS_METHOD_NOARG("info",  system_info),
    };

	static struct ubus_object_type system_type =
		UBUS_OBJECT_TYPE("system", system_methods);

	static struct ubus_object system_obj = {
		.name = "system",
		.type = &system_type,
		.methods = system_methods,
		.n_methods = ARRAY_SIZE(system_methods),
	};

	ops = o;

	if ((rv = ubus_add_object(ctx, &system_obj))) {
        fprintf(stderr, "Failed to add ubs object:%d", rv);
    }

	return rv;
}

struct rpc_plugin rpc_plugin = {
	.init = plugin_init
};

