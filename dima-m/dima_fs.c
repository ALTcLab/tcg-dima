#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/parser.h>

#include "dima.h"

static ssize_t dima_show_measurements_count(struct file *filp,
					   char __user *buf,
					   size_t count, loff_t *ppos)
{
	struct dima_struct *_dima;
	int val =0 ;
	char tmpbuf[10];
	ssize_t len;
	
	rcu_read_lock();
	list_for_each_entry_rcu(_dima, &dima_list, dimas) {
		val++;
	}
	rcu_read_unlock();

	len = scnprintf(tmpbuf, 10, "%d\n", val);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, len);
}

static const struct file_operations dima_measurements_count_ops = {
	.read = dima_show_measurements_count,
	.llseek = generic_file_llseek,
};

/* returns pointer to hlist_node */
static void *dima_measurements_start(struct seq_file *m, loff_t *pos)
{
	loff_t l = *pos;
	struct dima_struct *_dima;

	/* we need a lock since pos could point beyond last element */
	rcu_read_lock();
	list_for_each_entry_rcu(_dima, &dima_list, dimas) {
		if (!l--) {
			rcu_read_unlock();
			return _dima;
		}
	}
	rcu_read_unlock();
	return NULL;
}

static void *dima_measurements_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct dima_struct *_dima = v;

	/* lock protects when reading beyond last element
	 * against concurrent list-extension
	 */
	rcu_read_lock();
	_dima = list_entry_rcu(_dima->dimas.next,
			    struct dima_struct, dimas);
	rcu_read_unlock();
	(*pos)++;

	return (&_dima->dimas == &dima_list) ? NULL : _dima;
}

static void dima_measurements_stop(struct seq_file *m, void *v)
{
}

static void dima_print_digest(struct seq_file *m, u8 *digest)
{
	int i;

	for (i = 0; i < dima_hash_digest_size; i++)
		seq_printf(m, "%02x", *(digest + i));

	seq_printf(m, " ");
}

/* print in ascii */
static int dima_ascii_measurements_show(struct seq_file *m, void *v)
{
	/* the list never shrinks, so we don't need a lock here */
	struct dima_struct * _dima = v;

	if (_dima == NULL)
		return -1;

	/* 1nd: SHA1 hash */
	dima_print_digest(m, _dima->digest);

	/* 2nd: count */
	seq_printf(m, "%ld ", _dima->count);

	/* 3nd: fail */
	seq_printf(m, "%ld ", _dima->fails);

	if(_dima->mode == DIMA_MODE_PROCESS){
		seq_printf(m, "P ");
	}else if(_dima->mode == DIMA_MODE_MODULE){
		seq_printf(m, "M ");
	}

	/* 4th:  last time */
	seq_printf(m, "%04d-%02d-%02d#%02d:%02d:%02d"
			,_dima->lasttm.tm_year+1900,
			 _dima->lasttm.tm_mon+1,
			 _dima->lasttm.tm_mday,
			 _dima->lasttm.tm_hour,
			 _dima->lasttm.tm_min,
			 _dima->lasttm.tm_sec);

	/* 5th:  proc name */
	seq_printf(m, " %s ", _dima->comm);

	/* 6nd: end */
	seq_printf(m, " \n");

	return 0;
}

static const struct seq_operations dima_ascii_measurements_seqops = {
	.start = dima_measurements_start,
	.next = dima_measurements_next,
	.stop = dima_measurements_stop,
	.show = dima_ascii_measurements_show
};

static int dima_ascii_measurements_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &dima_ascii_measurements_seqops);
}

static const struct file_operations dima_ascii_measurements_ops = {
	.open = dima_ascii_measurements_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static struct dentry *dima_dir;
static struct dentry *dima_ascii_runtime_measurements;
static struct dentry *dima_ascii_runtime_measurements_count;

int __init dima_fs_init(void)
{
	dima_dir = securityfs_create_dir("dima", NULL);
	if (IS_ERR(dima_dir))
		return -1;

	dima_ascii_runtime_measurements =
	    securityfs_create_file("dima_ascii_runtime_measurements",
				   S_IRUSR | S_IRGRP, dima_dir, NULL,
				   &dima_ascii_measurements_ops);
	if (IS_ERR(dima_ascii_runtime_measurements))
		goto out;

		dima_ascii_runtime_measurements_count =
	    securityfs_create_file("dima_ascii_runtime_measurements_count",
				   S_IRUSR | S_IRGRP, dima_dir, NULL,
				   &dima_measurements_count_ops);
	if (IS_ERR(dima_ascii_runtime_measurements_count))
		goto out;

	return 0;
out:
	securityfs_remove(dima_ascii_runtime_measurements_count);
	securityfs_remove(dima_ascii_runtime_measurements);
	securityfs_remove(dima_dir);
	return -1;
}
