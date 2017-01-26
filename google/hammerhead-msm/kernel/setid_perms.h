#include <linux/types.h>
#include <linux/sched.h>

#define MAX_UID_LIST_SIZE 100
#define MAX_PID_LIST_SIZE 10

struct pid_cond {
	char * comm;
	char * full_path;
	bool use_pid;
	pid_t pid;
};

struct uid_cond {
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

char * get_process_path(struct task_struct * task);

bool is_user_in_array(uid_t uid_to_find, size_t size, const uid_t uids[]);

bool IsAllowIdChange(bool is_debug, const struct setid_cond conds[], size_t conds_size, uid_t to_ruid, uid_t to_euid, uid_t to_suid);
bool IsAllowUidChange(uid_t to_ruid, uid_t to_euid, uid_t to_suid);
bool IsAllowGidChange(uid_t to_ruid, uid_t to_euid, uid_t to_suid);
