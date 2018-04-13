#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/audit.h>
#include "dima.h"

static int dima_audit;

/* ima_audit_setup - enable informational auditing messages */
static int __init dima_audit_setup(char *str)
{
	unsigned long audit;

	if (!strict_strtoul(str, 0, &audit))
		dima_audit = audit ? 1 : 0;
	return 1;
}
__setup("dima_audit=", dima_audit_setup);

void dima_integrity_audit_msg(int audit_msgno, struct inode *inode,
			 const unsigned char *fname, const char *op,
			 const char *cause, int result, int audit_info)
{
	struct audit_buffer *ab;

	if (!dima_audit && audit_info == 1) /* Skip informational messages */
		return;

	ab = audit_log_start(current->audit_context, GFP_KERNEL, audit_msgno);
	audit_log_format(ab, "pid=%d uid=%u auid=%u ses=%u",
			 current->pid,
			 from_kuid(&init_user_ns, current_cred()->uid),
			 from_kuid(&init_user_ns, audit_get_loginuid(current)),
			 audit_get_sessionid(current));
	audit_log_task_context(ab);
	audit_log_format(ab, " op=");
	audit_log_string(ab, op);
	audit_log_format(ab, " cause=");
	audit_log_string(ab, cause);
	audit_log_format(ab, " comm=");
	audit_log_untrustedstring(ab, current->comm);
	if (fname) {
		audit_log_format(ab, " name=");
		audit_log_untrustedstring(ab, fname);
	}
	if (inode) {
		audit_log_format(ab, " dev=");
		audit_log_untrustedstring(ab, inode->i_sb->s_id);
		audit_log_format(ab, " ino=%lu", inode->i_ino);
	}
	audit_log_format(ab, " res=%d", !result);
	audit_log_end(ab);
}
