#ifndef __LINUX_DIMA_H
#define __LINUX_DIMA_H

#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/security.h>
#include <linux/hash.h>
#include <linux/tpm.h>
#include <linux/audit.h>
#include <linux/types.h>
#include <linux/integrity.h>
#include <crypto/sha.h>
#include <crypto/hash_info.h>
#include <crypto/hash.h>
#include <crypto/sm3.h> /*need explant */
#include <linux/key.h>
#include <linux/tpm.h>
#include <linux/module.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>

#define DIMA_SET_MEASUREMENT_MODE_CMD _IOW('d', 1, int)
#define DIMA_MEASUREMENT_PROCESS_CMD    _IOW('d', 2, int)
#define DIMA_MEASUREMENT_MODULE_CMD	   _IOW('d', 3, char[MODULE_NAME_LEN])

#define CMD_ERR_OK 0
#define CMD_ERR_NOSEACH -ESRCH
#define CMD_ERR_FAILMEASURE -1

#define DIMA_MODE_PROCESS 1
#define DIMA_MODE_MODULE 2

#define DIMA_NAME_LEN 100
/*need explant */
#define DIMA_DIGEST_SIZE SM3_DIGEST_SIZE

struct dima_struct {
	char comm[DIMA_NAME_LEN];
	u8 digest[DIMA_DIGEST_SIZE];
	unsigned long count;
	unsigned long fails;
	int mode;
	struct rtc_time lasttm;
	struct list_head	dimas;
};

extern char *dima_hash;
extern int dima_hash_digest_size;
extern struct list_head dima_list;
extern int dima_used_chip;

int dima_init_crypto(void);

int dima_fs_init(void);

int dima_set_measurement_mode_cmd(int mode);
int dima_measurement_process_cmd(int pid);
int dima_measurement_module_cmd(const char* name);

void dima_integrity_audit_msg(int audit_msgno, struct inode *inode,
    const unsigned char *fname, const char *op,
    const char *cause, int result, int info);

#endif