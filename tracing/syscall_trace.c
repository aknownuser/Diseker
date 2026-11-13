/*
 * syscall_trace — a QEMU TCG plugin that records guest syscalls on the HOST.
 *
 * This is the stealth replacement for in-guest auditd. QEMU itself invokes the
 * callbacks below as the guest executes, so from inside the guest there is no
 * tracer process, no ptrace, no auditd, nothing to enumerate: the machine looks
 * clean. The trace is written to a host file.
 *
 * Build:  see tracing/Makefile and tracing/README.md (needs a QEMU built with
 *         --enable-plugins and its qemu-plugin.h header).
 * Run:    qemu-system-arm ... -plugin ./libsyscall_trace.so,out=syscalls.log \
 *                             -d plugin
 *
 * NOTE / known gap: the TCG syscall callback reports the syscall number and
 * arguments at the CPU level, not the guest's PID/ppid or argv. Rebuilding the
 * process tree the HTML report wants requires guest introspection (reading the
 * task_struct via the guest CR3). That is why auditd is still the default
 * backend today; this plugin is the foundation for removing it. See STEALTH.md.
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static FILE *trace_out;

/* Called on every guest syscall entry. */
static void vcpu_syscall(qemu_plugin_id_t id, unsigned int vcpu_index,
                         int64_t num, uint64_t a1, uint64_t a2, uint64_t a3,
                         uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
                         uint64_t a8)
{
    if (!trace_out) {
        return;
    }
    fprintf(trace_out,
            "CALL vcpu=%u num=%" PRId64
            " a1=0x%" PRIx64 " a2=0x%" PRIx64 " a3=0x%" PRIx64
            " a4=0x%" PRIx64 "\n",
            vcpu_index, num, a1, a2, a3, a4);
    fflush(trace_out);
}

/* Called on syscall return, carrying the result. */
static void vcpu_syscall_ret(qemu_plugin_id_t id, unsigned int vcpu_index,
                             int64_t num, int64_t ret)
{
    if (!trace_out) {
        return;
    }
    fprintf(trace_out, "RET  vcpu=%u num=%" PRId64 " ret=%" PRId64 "\n",
            vcpu_index, num, ret);
    fflush(trace_out);
}

static void plugin_exit(qemu_plugin_id_t id, void *userdata)
{
    if (trace_out) {
        fclose(trace_out);
        trace_out = NULL;
    }
}

/*
 * Entry point. Accepts a single argument "out=<path>" selecting the trace file
 * (defaults to syscalls.log in the cwd QEMU was launched from).
 */
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    const char *out_path = "syscalls.log";

    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "out=", 4) == 0) {
            out_path = argv[i] + 4;
        }
    }

    trace_out = fopen(out_path, "w");
    if (!trace_out) {
        fprintf(stderr, "[syscall_trace] cannot open %s\n", out_path);
        return -1;
    }

    qemu_plugin_register_vcpu_syscall_cb(id, vcpu_syscall);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, vcpu_syscall_ret);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
