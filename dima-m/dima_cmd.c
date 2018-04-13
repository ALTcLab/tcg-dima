#include <linux/kernel.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/oom.h>
#include "dima.h"

LIST_HEAD(dima_list);

static int dima_measurement_mode = 0;

static struct crypto_shash *dima_shash_tfm;

int dima_init_crypto(void)
{
	long rc;

	dima_shash_tfm = crypto_alloc_shash(dima_hash, 0, 0);
	if (IS_ERR(dima_shash_tfm)) {
		rc = PTR_ERR(dima_shash_tfm);
		pr_err("Can not allocate dima %s (reason: %ld)\n", dima_hash, rc);
		return rc;
	}
	return 0;
}

static int dima_pcr_extend(const u8 *hash)
{
	int result = 0;

	if (!dima_used_chip)
		return result;

	result = tpm_pcr_extend(TPM_ANY_NUM, CONFIG_IMA_MEASURE_PCR_IDX+1, hash);
	if (result != 0)
		pr_err("DIMA: Error Communicating to TPM chip, result: %d\n",
		       result);
	return result;
}

static int cmp_dima_list(pid_t pid,const char* name,int mode,const char* comm,const u8* digest)
{
	struct dima_struct *_dima;
	struct dima_struct *a;
	struct timex  txc;
	struct task_struct *target;

	rcu_read_lock();
	list_for_each_entry_rcu(_dima, &dima_list, dimas)
		if (strncmp(_dima->comm,comm,DIMA_NAME_LEN) == 0 &&
			_dima->mode == mode)
		{
			_dima->count++;
			do_gettimeofday(&(txc.time));
			txc.time.tv_sec += 8*60*60;
			rtc_time_to_tm(txc.time.tv_sec,&_dima->lasttm);

			if(memcmp(_dima->digest, digest, DIMA_DIGEST_SIZE)){
				dima_integrity_audit_msg(AUDIT_INTEGRITY_DATA, NULL, 
						comm,"measurement_dima","invalid-hash", 0, 0);

				if(dima_measurement_mode){
					if(mode == DIMA_MODE_PROCESS){
						target = find_task_by_vpid(pid);
						if (target && !(target->flags & PF_KTHREAD) 
							&&!test_tsk_thread_flag(target, TIF_MEMDIE) ){
							send_sig(SIGKILL, target, 0);
							set_tsk_thread_flag(target, TIF_MEMDIE);

							pr_info("kill process %s %d \n",target->comm,pid);
						}
					}else if(mode == DIMA_MODE_MODULE){
						//mod = find_module(comm);
						// user space can delete_module
						pr_info("delete module %s \n",comm);
					}
				}

				_dima->fails++;
				rcu_read_unlock();
				return CMD_ERR_FAILMEASURE;
			}
			
			rcu_read_unlock();
			return CMD_ERR_OK;
		}
	rcu_read_unlock();

	a = kzalloc(sizeof(struct dima_struct), GFP_KERNEL);
	if (unlikely(a == NULL)) {
		return -ENOMEM;
	}

	strncpy(a->comm,comm,DIMA_NAME_LEN);
	memcpy(a->digest,digest,DIMA_DIGEST_SIZE);
	a->count = 1;
	a->fails  = 0;
	a->mode = mode;
	do_gettimeofday(&(txc.time));
	txc.time.tv_sec += 8*60*60;
	rtc_time_to_tm(txc.time.tv_sec,&a->lasttm);

	INIT_LIST_HEAD(&a->dimas);
	list_add_tail_rcu(&a->dimas, &dima_list);

	dima_pcr_extend(digest);
	return CMD_ERR_OK;
}

static int dima_calc_buffer_hash(char * data, unsigned long len, u8 *digest)
{
	struct {
		struct shash_desc shash;
		char ctx[crypto_shash_descsize(dima_shash_tfm)];
	} desc;

	desc.shash.tfm = dima_shash_tfm;
	desc.shash.flags = 0;

	return crypto_shash_digest(&desc.shash, data, len, digest);
}

static int dima_calc_task_buffer_hash(struct task_struct *tsk, unsigned long index, unsigned long len, u8 *digest)
{
	unsigned long offset = 0;
	char *rbuf;
	int rc;
	struct {
		struct shash_desc shash;
		char ctx[crypto_shash_descsize(dima_shash_tfm)];
	} desc;

	desc.shash.tfm = dima_shash_tfm;
	desc.shash.flags = 0;

	rc = crypto_shash_init(&desc.shash);
	if (rc != 0)
		return rc;

	rbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (unlikely(!rbuf)) {
		rc = -ENOMEM;
		goto out;
	}

	while (offset < len) {
		int rlen;
		int retval = 0;

		if((len-offset) > PAGE_SIZE){
			rlen = PAGE_SIZE;
		}else{
			rlen = (len-offset);
		}

		retval = access_process_vm(tsk,index+offset,rbuf, rlen,0);
		if (!retval) {
			pr_err("Can not read process vm \n");
			rc = -EIO;
			break;
		}

		offset += retval;

		rc = crypto_shash_update(&desc.shash, rbuf, retval);
		if (rc){
			pr_err("Can not hash data err %d \n",rc);
			break;
		}
	}

	kfree(rbuf);

	if (!rc)
		rc = crypto_shash_final(&desc.shash, digest);
out:
	return rc;
}

static int dima_calc_task_code_by_pid(pid_t pid, char* comm, u8* digest)
{
	int ret = CMD_ERR_OK;
	struct mm_struct *target_mm;
	struct task_struct *target;
	unsigned long code_size;
	unsigned long code_index;

	rcu_read_lock();
	target = find_task_by_vpid(pid);
	if (target){
		get_task_struct(target);
	}
	rcu_read_unlock();

	if (!target)
		return CMD_ERR_NOSEACH;

	target_mm = get_task_mm(target);
	if(unlikely(target_mm == NULL)){
		ret =  CMD_ERR_NOSEACH;
		goto out_put;
	}

	code_size = target_mm->end_code - target_mm->start_code;
	if(unlikely(code_size <= 0)){
		ret = CMD_ERR_NOSEACH;
		mmput(target_mm);
		goto out_put;
	}
	code_index = target_mm->start_code;
	mmput(target_mm);

	//pr_info("PID=%d Text Starts at 0x%lx, Size  0x%lx\n",pid,code_index, code_size);

	if((ret = dima_calc_task_buffer_hash(target,code_index,code_size,digest))){
		pr_err("dima process calc hash err = %d \n",ret);
		goto out_put;
	}

	strncpy(comm,target->comm,TASK_COMM_LEN);
out_put:
	put_task_struct(target);
	return ret;
}

static int dima_calc_module_by_name(const char* name, char* comm, u8* digest)
{
	struct module *mod;
	int ret = CMD_ERR_OK;

	mod = find_module(name);
	if(!mod)
		return CMD_ERR_NOSEACH;

	preempt_disable();
	
	if(strlen(mod->name) == 0){
		ret =  CMD_ERR_NOSEACH;
		goto out_put;
	}

	if(mod->core_size <= 0){
		ret =  CMD_ERR_NOSEACH;
		goto out_put;
	}

	if((ret = dima_calc_buffer_hash(mod->module_core, mod->core_size,digest))){
		pr_err("dima module calc hash err = %d \n",ret);
		goto out_put;
	}

	strncpy(comm,mod->name,MODULE_NAME_LEN);
out_put:
	preempt_enable();
	return ret;
}

int dima_set_measurement_mode_cmd(int mode)
{
	dima_measurement_mode = mode;
	return CMD_ERR_OK;
}

int dima_measurement_process_cmd(int pid)
{
	char comm[DIMA_NAME_LEN]={0};
	u8 digest[DIMA_DIGEST_SIZE]={0};
	int ret = CMD_ERR_OK;

	ret = dima_calc_task_code_by_pid(pid,comm,digest);
	if(ret == CMD_ERR_NOSEACH){
		return ret;
	} else if(ret != CMD_ERR_OK){
		dima_integrity_audit_msg(AUDIT_INTEGRITY_DATA, NULL, comm,
				"measurement_dima","unknown-dima-data", 0, 0);
		return ret;
	}

	return cmp_dima_list(pid,NULL,DIMA_MODE_PROCESS,comm,digest);
}

int dima_measurement_module_cmd(const char* name)
{
	char comm[DIMA_NAME_LEN]={0};
	u8 digest[DIMA_DIGEST_SIZE]={0};
	int ret = CMD_ERR_OK;

	ret = dima_calc_module_by_name(name,comm,digest);
	if(ret == CMD_ERR_NOSEACH){
		return ret;
	} else if(ret != CMD_ERR_OK){
		dima_integrity_audit_msg(AUDIT_INTEGRITY_DATA, NULL, comm,
				"measurement_dima","unknown-dima-data", 0, 0);
		return ret;
	}

	return cmp_dima_list(-1,name,DIMA_MODE_MODULE,comm,digest);
}

