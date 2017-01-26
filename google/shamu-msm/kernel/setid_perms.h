#include <linux/types.h>
#include <linux/sched.h>

#define MAX_UID_LIST_SIZE 100
#define MAX_PID_LIST_SIZE 10

// A condition to check if the current process has the expected info such as name (comm),
// full path and if use_pid=1 (true) also match the current pid to "pid"
struct pid_cond {
	char * comm;
	char * full_path;
	bool use_pid;
	pid_t pid;
};

// A condition to check which current uid can setuid to which target uid's
//(target uid's can be set by specific list (to_uids) or by range (min_uid - max_uid)
struct uid_cond {
	uid_t current_uid;
	uid_t min_uid;
	uid_t max_uid;
	size_t to_uids_size;
	uid_t to_uids[MAX_UID_LIST_SIZE];
};

//The main condition - contain a uid (source and target) condition and a chain of process conditions (...->grandparent -> parent -> mypid)
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
