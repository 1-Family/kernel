#include <../kernel/setid_perms.h>
#include <linux/fs.h>
#include <linux/slab.h>

#define DEBUG 0
#define EXTRA_DEBUG 0
#define SWAPPER "swapper/0"
#define ZYGOTE "main"
#define APP_PROC_32_PATH "/system/bin/app_process32"
#define APP_PROC_64_PATH "/system/bin/app_process64"

#define EXTRA_DEBUG_LOG(fmt, args...) if (is_extra_debug) printk(KERN_DEBUG fmt, ##args);
#define DEBUG_LOG(fmt, args...) if (is_debug) printk(KERN_DEBUG fmt, ##args);

/*
 *
 * struct uid_cond {
	uid_t current_uid;
	uid_t min_uid;
	uid_t max_uid;
	size_t to_uids_size;
	uid_t to_uids[MAX_UID_LIST_SIZE];
};

struct setid_cond {
	struct uid_cond uid_info;
	size_t processes_size;
	struct pid_cond processes[MAX_PID_LIST_SIZE];
};
 */
static const struct setid_cond setuid_conds[] = {
		//from init.rc
		{
			{0, 0, 0, 4, {0, 1001, 9999, -1},},
			3,
			{{ "ueventd", "/init", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1036},},
			3,
			{{ "logd", "/system/bin/logd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},		
		{//all service running from init.*.rc
		// This happens for general init.rc or specific device init.*.rc (init.shamu.rc), which is spawned by init.
		// Meaning the setuid is triggered by init and not the process itself at a later stage.
			{0, 0, 0, 11, {1000, 1001, 1002, 1003, 1006, 1013, 1017, 1019, 1020, 1021, 1500, 2000},},
			3,
			{{ "init", "/init", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1032},},
			3,
			{{ "auditd", "/system/bin/auditd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {2000},},
			3,
			{{ "adbd", "/sbin/adbd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1001},},
			3,
			{{ "netd", "/system/bin/netd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		//netd has a child netd,hostapd that also need permissions
		{
			{0, 0, 0, 1, {1001},},
			4,
			{{ "netd", "/system/bin/netd", false, 0,},
			 { "netd", "/system/bin/netd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1010},},
			4,
			{{ "hostapd", "/system/bin/hostapd", false, 0,},
			 { "netd", "/system/bin/netd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {9999},},
			4,
			{{ "dnsmasq", "/system/bin/dnsmasq", false, 0,},
			 { "netd", "/system/bin/netd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},				
		//end of netd children
		{
			{0, 0, 0, 1, {1001},},
			3,
			{{ "rild", "/system/bin/rild", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{1001, 0, 0, 1, {1001},},
			4,
			{{ "qmi_motext_hook", "/system/bin/qmi_motext_hook", false, 0,},
			 { "rild", "/system/bin/rild", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1000},},
			3,
			{{ "time_daemon", "/system/bin/time_daemon", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 10000, 0, 7, {1000, 1001, 1002, 1027, 1037, 1300, 2000},},
			4,
			{{ ZYGOTE, APP_PROC_32_PATH, false, 0,},
			 { ZYGOTE, APP_PROC_32_PATH, false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 2, {0, 9999},},
			3,
			{{ ZYGOTE, APP_PROC_32_PATH, false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{1012, 10000, 0, 5, {1000, 1001, 1002, 1300, 2000},},
			4,
			{{ "installd", "/system/bin/installd", false, 0,},
			 { "installd", "/system/bin/installd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1012},},
			3,
			{{ "installd", "/system/bin/installd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {2000},},
			3,
			{{ "dumpstate", "/system/bin/dumpstate", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		//from init.mako.rc
		{
			{0, 0, 0, 1, {1010},},
			3,
			{{ "wpa_supplicant", "/system/bin/wpa_supplicant", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1014},},
			3,
			{{ "dhcpcd", "/system/bin/dhcpcd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1023},},
			3,
			{{ "sdcard", "/system/bin/sdcard", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1000},},
			3,
			{{ "qrngd", "/system/bin/qrngd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {9999},},
			3,
			{{ "rmt_storage", "/system/bin/rmt_storage", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {9999},},
			3,
			{{ "sensors.qcom", "/system/bin/sensors.qcom", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1000},},
			3,
			{{ "qseecomd", "/system/bin/qseecomd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1001},},
			3,
			{{ "netmgrd", "/system/bin/netmgrd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1020},},
			3,
			{{ "mdnsd", "/system/bin/mdnsd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{1020, 0, 0, 1, {1020},},
			3,
			{{ "mdnsd", "/system/bin/mdnsd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
};

static const struct setid_cond setgid_conds[] = {
		//from init.rc
		{
			{0, 0, 0, 20, {-1, 0, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1016, 1011, 1018, 1024, 1026, 1027, 2000, 3008, 3010, 9999},},
			3,
			{{ "ueventd", "/init", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1036},},
			3,
			{{ "logd", "/system/bin/logd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},		
		{//all service running from init.*.rc
			{0, 0, 0, 14, {-1, 1000, 1001, 1003, 1005, 1006, 1007, 1013, 1017, 1019, 1021, 1500, 2000, 3003},},
			3,
			{{ "init", "/init", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1032},},
			3,
			{{ "auditd", "/system/bin/auditd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {2000},},
			3,
			{{ "adbd", "/sbin/adbd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {3004},},
			3,
			{{ "time_daemon", "/system/bin/time_daemon", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {3004},},
			3,
			{{ "sensors.qcom", "/system/bin/sensors.qcom", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1000},},
			3,
			{{ "qseecomd", "/system/bin/qseecomd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1001},},
			3,
			{{ "netd", "/system/bin/netd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		//netd has a child netd,hostapd that also need permissions
		{
			{0, 0, 0, 1, {1001},},
			4,
			{{ "netd", "/system/bin/netd", false, 0,},
			 { "netd", "/system/bin/netd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1010},},
			4,
			{{ "hostapd", "/system/bin/hostapd", false, 0,},
			 { "netd", "/system/bin/netd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {9999},},
			4,
			{{ "dnsmasq", "/system/bin/dnsmasq", false, 0,},
			 { "netd", "/system/bin/netd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},		
		//end of netd children
		{
			{0, 10000, 0, 7, {1000, 1001, 1002, 1027, 1037, 1300, 2000},},
			4,
			{{ ZYGOTE, APP_PROC_32_PATH, false, 0,},
			 { ZYGOTE, APP_PROC_32_PATH, false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 2, {0, 9999},},
			3,
			{{ ZYGOTE, APP_PROC_32_PATH, false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{1012, 10000, 0, 5, {1000, 1001, 1002, 1300, 2000},},
			4,
			{{ "installd", "/system/bin/installd", false, 0,},
			 { "installd", "/system/bin/installd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1012},},
			3,
			{{ "installd", "/system/bin/installd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {2000},},
			3,
			{{ "dumpstate", "/system/bin/dumpstate", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		//from init.mako.rc
		{
			{0, 0, 0, 1, {1010},},
			3,
			{{ "wpa_supplicant", "/system/bin/wpa_supplicant", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1014},},
			3,
			{{ "dhcpcd", "/system/bin/dhcpcd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1023},},
			3,
			{{ "sdcard", "/system/bin/sdcard", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1000},},
			3,
			{{ "qrngd", "/system/bin/qrngd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {3004},},
			3,
			{{ "rmt_storage", "/system/bin/rmt_storage", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {9999},},
			3,
			{{ "sensors.qcom", "/system/bin/sensors.qcom", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
		{
			{0, 0, 0, 1, {1000},},
			3,
			{{ "netmgrd", "/system/bin/netmgrd", false, 0,},
			 { "init", "/init", true, 1,},
			 { SWAPPER, NULL, true, 0,},},
		},
};
char * get_process_path(struct task_struct * task) {
	char * pathname;
	char * rv = NULL;
	bool is_extra_debug = EXTRA_DEBUG == 1 ? true : false;
	if (task->tgid != 0) {
		struct mm_struct *mm = task->mm;
		if (mm) {
			down_read(&mm->mmap_sem);
			if (mm->exe_file) {
				pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
				if (pathname) {
					rv = d_path(&mm->exe_file->f_path, pathname, PATH_MAX);
				}
				kfree(pathname);
			}
			up_read(&mm->mmap_sem);
		} else {
			printk(KERN_ERR "setid_perms - %s - error getting mm\n", __FUNCTION__);
		}
	} else {
		EXTRA_DEBUG_LOG("setid_perms - tgid = 0, not checking process path\n");
	}
	return rv;
}

bool is_user_in_array(uid_t uid_to_find, size_t size, const uid_t uids[]) {
	bool rv = false;
	size_t i=0;
	while (!rv && i < size) {
		rv = uid_to_find == uids[i];
		i++;
	}
	return rv;
}


bool IsAllowIdChange(bool is_debug, const struct setid_cond conds[], size_t conds_size , uid_t to_ruid, uid_t to_euid, uid_t to_suid) {

	bool is_extra_debug = EXTRA_DEBUG == 1 ? true : false;
	bool rv = false;
	size_t j = 0;
	size_t i = 0;
	bool check_user_in_list = false;
	struct task_struct * temp_current = NULL;

	DEBUG_LOG("setid_perms - DEBUGGING setid_perms\n");
	DEBUG_LOG("setid_perms - my uid=<%d>, require change to to_ruid=<%d>, to_euid=<%d>, to_suid=<%d>\n", current_cred()->uid, to_ruid,to_euid, to_suid);

	if(DEBUG) {
		DEBUG_LOG("setid_perms - My Process tree:\n");
		temp_current = current;
		//tgid is the actual pid as we know it from outside the kernel
		//We run on a chain of process starting from the current process up to swapper
		//This is why we stop once we get to tgid==0 (swapper tgid is 0)
		while (temp_current->tgid != 0) {
			char * p = get_process_path(temp_current);
			DEBUG_LOG("setid_perms - \tpid=<%d>, comm=<%s>, full_path=<%s>\n", temp_current->tgid, temp_current->comm , p);
			temp_current = temp_current->real_parent;
		}
		DEBUG_LOG("setid_perms - \tpid=<%d>, comm=<%s>, full_path=<%s>\n", temp_current->tgid, temp_current->comm , get_process_path(temp_current));
	}

	EXTRA_DEBUG_LOG("setid_perms - Going over conditions:\n");
	while (!rv && j< conds_size) {
		EXTRA_DEBUG_LOG("setid_perms - starting condition #%d:\n------------------------------------",  j);

		rv = conds[j].uid_info.current_uid == current_cred()->uid;

		if (rv) {
			if (conds[j].uid_info.min_uid == conds[j].uid_info.max_uid) {
				EXTRA_DEBUG_LOG("min_uid and max_uid are equal\n");
				check_user_in_list = true;
			} else {
				 rv = (conds[j].uid_info.min_uid == 0 ||
					   (conds[j].uid_info.min_uid <= to_ruid &&
							   conds[j].uid_info.min_uid <= to_euid &&
							   conds[j].uid_info.min_uid <= to_suid)) &&
					  (conds[j].uid_info.max_uid == 0 ||
					   (conds[j].uid_info.max_uid >= to_ruid &&
							   conds[j].uid_info.max_uid >= to_euid &&
							   conds[j].uid_info.max_uid >= to_suid));

				 if (!rv) {

					 EXTRA_DEBUG_LOG("setid_perms - The id is not in the range\n");
				 }
				 check_user_in_list = !rv;
			}
			if (check_user_in_list) {
				EXTRA_DEBUG_LOG("setid_perms - Checking id in list: (");
				if (DEBUG) {
					int idx=0;
					for(idx=0;idx<conds[j].uid_info.to_uids_size; idx++) {
						EXTRA_DEBUG_LOG("setid_perms - %d,", conds[j].uid_info.to_uids[idx]);
					}
					EXTRA_DEBUG_LOG(")\n");
				}
				rv = is_user_in_array(to_ruid, conds[j].uid_info.to_uids_size, conds[j].uid_info.to_uids) &&
					 is_user_in_array(to_euid, conds[j].uid_info.to_uids_size, conds[j].uid_info.to_uids) &&
					 is_user_in_array(to_suid, conds[j].uid_info.to_uids_size, conds[j].uid_info.to_uids);
				 if (!rv) {
					 EXTRA_DEBUG_LOG("setid_perms - The id is not in the list\n");
				 }
			}
		}
		else {
			EXTRA_DEBUG_LOG("setid_perms - id check not passed - I need to be <%d> and I am actually <%d>\n", conds[j].uid_info.current_uid, current_cred()->uid);
		}

		if (rv) {
			temp_current = current;
			i = 0;
			EXTRA_DEBUG_LOG("setid_perms - Now checking process info:\n");
			while (rv && i<conds[j].processes_size) {
				EXTRA_DEBUG_LOG("setid_perms - Comparing to pid <%d>, comm <%s>, full_path = <%s>, use_pid? = <%s>\n",
						conds[j].processes[i].pid, conds[j].processes[i].comm,
						conds[j].processes[i].full_path,
						conds[j].processes[i].use_pid ? "true" : "false");

				rv = (strcmp(temp_current->comm, conds[j].processes[i].comm) == 0 &&
					 (!conds[j].processes[i].use_pid || conds[j].processes[i].pid == temp_current->tgid) &&
					 (conds[j].processes[i].full_path == NULL || strcmp(conds[j].processes[i].full_path, get_process_path(temp_current)) == 0));
				EXTRA_DEBUG_LOG("setid_perms - passed current process condition value is <%s>\n", rv ? "yes" : "no");
				i++;
				temp_current = temp_current->real_parent;
			}
		}
		EXTRA_DEBUG_LOG("setid_perms - at this point (%d) the value of rv is <%s>\n", j, rv ? "true" : "false");
		EXTRA_DEBUG_LOG("setid_perms - ---------------------------------------------\n");
		j++;
	}
	EXTRA_DEBUG_LOG("setid_perms - at this point (out of loop) the value of rv is <%s>\n", rv ? "true" : "false");
	if (!rv) {
		EXTRA_DEBUG_LOG("setid_perms - The id ultimately did NOT pass!!:\n\n\n");
	}
	return rv;
}

bool IsAllowUidChange(uid_t to_ruid, uid_t to_euid, uid_t to_suid) {
	size_t size = sizeof(setuid_conds)/sizeof(struct setid_cond);
	bool rv = IsAllowIdChange(false, setuid_conds, size, to_ruid, to_euid, to_suid);
	if (!rv && DEBUG){
		printk(KERN_DEBUG "setid_perms - In %s", __FUNCTION__);
		IsAllowIdChange(true, setuid_conds, size, to_ruid, to_euid, to_suid);
	}
	return rv;
	//return true;
}

bool IsAllowGidChange(uid_t to_ruid, uid_t to_euid, uid_t to_suid) {
	size_t size = sizeof(setgid_conds)/sizeof(struct setid_cond);
	bool rv = IsAllowIdChange(false, setgid_conds, size, to_ruid, to_euid, to_suid);
	if (!rv && DEBUG){
		printk(KERN_DEBUG "setid_perms - In %s", __FUNCTION__); 
		IsAllowIdChange(true, setgid_conds, size, to_ruid, to_euid, to_suid);
	}
	return rv;
	//return true;
}
