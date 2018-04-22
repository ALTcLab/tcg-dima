#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/file.h>
#include "dima.h"

char* dima_hash = "sm3";
int dima_hash_digest_size = SM3_DIGEST_SIZE;
static int __init hash_setup(char *str)
{
	if (strncmp(str, "md5", 3) == 0){
		dima_hash = "md5";
		dima_hash_digest_size = MD5_DIGEST_SIZE;
	}else if (strncmp(str, "sha1", 4) == 0){
		dima_hash = "sha1";
		dima_hash_digest_size = SHA1_DIGEST_SIZE;
	}
	return 1;
}
__setup("dima_hash=", hash_setup);

static struct mutex		dima_mutex;
static int dima_lock = 1; 

int dima_used_chip = 0;

static int dima_release(struct inode *nodp, struct file *filp)
{
	return 0;
}

static int dima_open(struct inode *nodp, struct file *filp)
{
	return 0;
}

static long dima_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	void __user *argp = (void __user *) arg;

	mutex_lock(&dima_mutex);

	switch (cmd) 
	{
		case DIMA_SET_MEASUREMENT_MODE_CMD:
		{
			int mode;
			if (copy_from_user(&mode, argp, sizeof(mode))) {
				ret = -EFAULT;
				break;
			}
			ret = dima_set_measurement_mode_cmd(mode);
			break;
		}
		case DIMA_MEASUREMENT_PROCESS_CMD:
		{
			if(dima_lock) break;

			int pid;
			if (copy_from_user(&pid, argp, sizeof(pid))) {
				ret = -EFAULT;
				break;
			}
			ret = dima_measurement_process_cmd(pid);
			break;
		}
		case DIMA_MEASUREMENT_MODULE_CMD:
		{
			if(dima_lock) break;

			char name[MODULE_NAME_LEN];
			if (copy_from_user(name, argp, sizeof(name))) {
				ret = -EFAULT;
				break;
			}
			ret = dima_measurement_module_cmd(name);
			break;
		}
		case DIMA_SET_MEASUREMENT_LOCK_MODE_CMD:
		{
			dima_lock = 1;
			break;
		}
		case DIMA_SET_MEASUREMENT_UNLOCK_MODE_CMD:
		{
			dima_lock = 0;
			break;
		}

	}

	mutex_unlock(&dima_mutex);

	return ret;
}

static const struct file_operations dima_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = dima_ioctl,
	.open = dima_open,
	.release = dima_release,
};

static struct miscdevice dima_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "dima",
	.fops = &dima_fops
};

static int __init init_dima(void)
{
	int error = 0;
	u8 pcr_i[SHA1_DIGEST_SIZE];

	/* 0th:  has tpm ?! */
	dima_used_chip = 0;
	error = tpm_pcr_read(TPM_ANY_NUM, 0, pcr_i);
	if (error == 0)
		dima_used_chip = 1;
	if (!dima_used_chip)
		pr_info("DIMA: No TPM chip found, activating TPM-bypass!\n");

	/* 1th:  init crypto hash cal */
	error = dima_init_crypto();
	if (unlikely(error)) {
		pr_err("failed to register crypto hash cal for dima !\n");
		goto out;
	}

	/* 2th:  init mutex  */
	mutex_init(&dima_mutex);

	/* 3th:  init misc  */
	error = misc_register(&dima_miscdev);
	if (unlikely(error)) {
		pr_err("failed to register misc device for dima !\n");
		goto out;
	}

	/* end:  init fs  */
	return dima_fs_init();

out:
	return error;
}

late_initcall(init_dima);

MODULE_DESCRIPTION("Dynamic Integrity Measurement Architecture");
MODULE_LICENSE("GPL");