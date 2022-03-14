#pragma once

#include <stdio.h>
#include <sys/syscall.h>

void mysyscall(long orig)
{
	switch(orig)
	{
		case __NR_read :
			printf("read\n");
			break;
		case __NR_write :
			printf("write\n");
			break;
		case __NR_open :
			printf("open\n");
			break;
		case __NR_close :
			printf("close\n");
			break;
		case __NR_stat :
			printf("stat\n");
			break;
		case __NR_fstat :
			printf("fstat\n");
			break;
		case __NR_lstat :
			printf("lstat\n");
			break;
		case __NR_poll :
			printf("poll\n");
			break;
		case __NR_lseek :
			printf("lseek\n");
			break;
		case __NR_mmap :
			printf("mmap\n");
			break;
		case __NR_mprotect :
			printf("mprotect\n");
			break;
		case __NR_munmap :
			printf("munmap\n");
			break;
		case __NR_brk :
			printf("brk\n");
			break;
		case __NR_rt_sigaction :
			printf("rt_sigaction\n");
			break;
		case __NR_rt_sigprocmask :
			printf("rt_sigprocmask\n");
			break;
		case __NR_rt_sigreturn :
			printf("rt_sigreturn\n");
			break;
		case __NR_ioctl :
			printf("ioctl\n");
			break;
		case __NR_pread64 :
			printf("pread64\n");
			break;
		case __NR_pwrite64 :
			printf("pwrite64\n");
			break;
		case __NR_readv :
			printf("readv\n");
			break;
		case __NR_writev :
			printf("writev\n");
			break;
		case __NR_access :
			printf("access\n");
			break;
		case __NR_pipe :
			printf("pipe\n");
			break;
		case __NR_select :
			printf("select\n");
			break;
		case __NR_sched_yield :
			printf("sched_yield\n");
			break;
		case __NR_mremap :
			printf("mremap\n");
			break;
		case __NR_msync :
			printf("msync\n");
			break;
		case __NR_mincore :
			printf("mincore\n");
			break;
		case __NR_madvise :
			printf("madvise\n");
			break;
		case __NR_shmget :
			printf("shmget\n");
			break;
		case __NR_shmat :
			printf("shmat\n");
			break;
		case __NR_shmctl :
			printf("shmctl\n");
			break;
		case __NR_dup :
			printf("dup\n");
			break;
		case __NR_dup2 :
			printf("dup2\n");
			break;
		case __NR_pause :
			printf("pause\n");
			break;
		case __NR_nanosleep :
			printf("nanosleep\n");
			break;
		case __NR_getitimer :
			printf("getitimer\n");
			break;
		case __NR_alarm :
			printf("alarm\n");
			break;
		case __NR_setitimer :
			printf("setitimer\n");
			break;
		case __NR_getpid :
			printf("getpid\n");
			break;
		case __NR_sendfile :
			printf("sendfile\n");
			break;
		case __NR_socket :
			printf("socket\n");
			break;
		case __NR_connect :
			printf("connect\n");
			break;
		case __NR_accept :
			printf("accept\n");
			break;
		case __NR_sendto :
			printf("sendto\n");
			break;
		case __NR_recvfrom :
			printf("recvfrom\n");
			break;
		case __NR_sendmsg :
			printf("sendmsg\n");
			break;
		case __NR_recvmsg :
			printf("recvmsg\n");
			break;
		case __NR_shutdown :
			printf("shutdown\n");
			break;
		case __NR_bind :
			printf("bind\n");
			break;
		case __NR_listen :
			printf("listen\n");
			break;
		case __NR_getsockname :
			printf("getsockname\n");
			break;
		case __NR_getpeername :
			printf("getpeername\n");
			break;
		case __NR_socketpair :
			printf("socketpair\n");
			break;
		case __NR_setsockopt :
			printf("setsockopt\n");
			break;
		case __NR_getsockopt :
			printf("getsockopt\n");
			break;
		case __NR_clone :
			printf("clone\n");
			break;
		case __NR_fork :
			printf("fork\n");
			break;
		case __NR_vfork :
			printf("vfork\n");
			break;
		case __NR_execve :
			printf("execve\n");
			break;
		case __NR_exit :
			printf("exit\n");
			break;
		case __NR_wait4 :
			printf("wait4\n");
			break;
		case __NR_kill :
			printf("kill\n");
			break;
		case __NR_uname :
			printf("uname\n");
			break;
		case __NR_semget :
			printf("semget\n");
			break;
		case __NR_semop :
			printf("semop\n");
			break;
		case __NR_semctl :
			printf("semctl\n");
			break;
		case __NR_shmdt :
			printf("shmdt\n");
			break;
		case __NR_msgget :
			printf("msgget\n");
			break;
		case __NR_msgsnd :
			printf("msgsnd\n");
			break;
		case __NR_msgrcv :
			printf("msgrcv\n");
			break;
		case __NR_msgctl :
			printf("msgctl\n");
			break;
		case __NR_fcntl :
			printf("fcntl\n");
			break;
		case __NR_flock :
			printf("flock\n");
			break;
		case __NR_fsync :
			printf("fsync\n");
			break;
		case __NR_fdatasync :
			printf("fdatasync\n");
			break;
		case __NR_truncate :
			printf("truncate\n");
			break;
		case __NR_ftruncate :
			printf("ftruncate\n");
			break;
		case __NR_getdents :
			printf("getdents\n");
			break;
		case __NR_getcwd :
			printf("getcwd\n");
			break;
		case __NR_chdir :
			printf("chdir\n");
			break;
		case __NR_fchdir :
			printf("fchdir\n");
			break;
		case __NR_rename :
			printf("rename\n");
			break;
		case __NR_mkdir :
			printf("mkdir\n");
			break;
		case __NR_rmdir :
			printf("rmdir\n");
			break;
		case __NR_creat :
			printf("creat\n");
			break;
		case __NR_link :
			printf("link\n");
			break;
		case __NR_unlink :
			printf("unlink\n");
			break;
		case __NR_symlink :
			printf("symlink\n");
			break;
		case __NR_readlink :
			printf("readlink\n");
			break;
		case __NR_chmod :
			printf("chmod\n");
			break;
		case __NR_fchmod :
			printf("fchmod\n");
			break;
		case __NR_chown :
			printf("chown\n");
			break;
		case __NR_fchown :
			printf("fchown\n");
			break;
		case __NR_lchown :
			printf("lchown\n");
			break;
		case __NR_umask :
			printf("umask\n");
			break;
		case __NR_gettimeofday :
			printf("gettimeofday\n");
			break;
		case __NR_getrlimit :
			printf("getrlimit\n");
			break;
		case __NR_getrusage :
			printf("getrusage\n");
			break;
		case __NR_sysinfo :
			printf("sysinfo\n");
			break;
		case __NR_times :
			printf("times\n");
			break;
		case __NR_ptrace :
			printf("ptrace\n");
			break;
		case __NR_getuid :
			printf("getuid\n");
			break;
		case __NR_syslog :
			printf("syslog\n");
			break;
		case __NR_getgid :
			printf("getgid\n");
			break;
		case __NR_setuid :
			printf("setuid\n");
			break;
		case __NR_setgid :
			printf("setgid\n");
			break;
		case __NR_geteuid :
			printf("geteuid\n");
			break;
		case __NR_getegid :
			printf("getegid\n");
			break;
		case __NR_setpgid :
			printf("setpgid\n");
			break;
		case __NR_getppid :
			printf("getppid\n");
			break;
		case __NR_getpgrp :
			printf("getpgrp\n");
			break;
		case __NR_setsid :
			printf("setsid\n");
			break;
		case __NR_setreuid :
			printf("setreuid\n");
			break;
		case __NR_setregid :
			printf("setregid\n");
			break;
		case __NR_getgroups :
			printf("getgroups\n");
			break;
		case __NR_setgroups :
			printf("setgroups\n");
			break;
		case __NR_setresuid :
			printf("setresuid\n");
			break;
		case __NR_getresuid :
			printf("getresuid\n");
			break;
		case __NR_setresgid :
			printf("setresgid\n");
			break;
		case __NR_getresgid :
			printf("getresgid\n");
			break;
		case __NR_getpgid :
			printf("getpgid\n");
			break;
		case __NR_setfsuid :
			printf("setfsuid\n");
			break;
		case __NR_setfsgid :
			printf("setfsgid\n");
			break;
		case __NR_getsid :
			printf("getsid\n");
			break;
		case __NR_capget :
			printf("capget\n");
			break;
		case __NR_capset :
			printf("capset\n");
			break;
		case __NR_rt_sigpending :
			printf("rt_sigpending\n");
			break;
		case __NR_rt_sigtimedwait :
			printf("rt_sigtimedwait\n");
			break;
		case __NR_rt_sigqueueinfo :
			printf("rt_sigqueueinfo\n");
			break;
		case __NR_rt_sigsuspend :
			printf("rt_sigsuspend\n");
			break;
		case __NR_sigaltstack :
			printf("sigaltstack\n");
			break;
		case __NR_utime :
			printf("utime\n");
			break;
		case __NR_mknod :
			printf("mknod\n");
			break;
		case __NR_uselib :
			printf("uselib\n");
			break;
		case __NR_personality :
			printf("personality\n");
			break;
		case __NR_ustat :
			printf("ustat\n");
			break;
		case __NR_statfs :
			printf("statfs\n");
			break;
		case __NR_fstatfs :
			printf("fstatfs\n");
			break;
		case __NR_sysfs :
			printf("sysfs\n");
			break;
		case __NR_getpriority :
			printf("getpriority\n");
			break;
		case __NR_setpriority :
			printf("setpriority\n");
			break;
		case __NR_sched_setparam :
			printf("sched_setparam\n");
			break;
		case __NR_sched_getparam :
			printf("sched_getparam\n");
			break;
		case __NR_sched_setscheduler :
			printf("sched_setscheduler\n");
			break;
		case __NR_sched_getscheduler :
			printf("sched_getscheduler\n");
			break;
		case __NR_sched_get_priority_max :
			printf("sched_get_priority_max\n");
			break;
		case __NR_sched_get_priority_min :
			printf("sched_get_priority_min\n");
			break;
		case __NR_sched_rr_get_interval :
			printf("sched_rr_get_interval\n");
			break;
		case __NR_mlock :
			printf("mlock\n");
			break;
		case __NR_munlock :
			printf("munlock\n");
			break;
		case __NR_mlockall :
			printf("mlockall\n");
			break;
		case __NR_munlockall :
			printf("munlockall\n");
			break;
		case __NR_vhangup :
			printf("vhangup\n");
			break;
		case __NR_modify_ldt :
			printf("modify_ldt\n");
			break;
		case __NR_pivot_root :
			printf("pivot_root\n");
			break;
		case __NR__sysctl :
			printf("_sysctl\n");
			break;
		case __NR_prctl :
			printf("prctl\n");
			break;
		case __NR_arch_prctl :
			printf("arch_prctl\n");
			break;
		case __NR_adjtimex :
			printf("adjtimex\n");
			break;
		case __NR_setrlimit :
			printf("setrlimit\n");
			break;
		case __NR_chroot :
			printf("chroot\n");
			break;
		case __NR_sync :
			printf("sync\n");
			break;
		case __NR_acct :
			printf("acct\n");
			break;
		case __NR_settimeofday :
			printf("settimeofday\n");
			break;
		case __NR_mount :
			printf("mount\n");
			break;
		case __NR_umount2 :
			printf("umount2\n");
			break;
		case __NR_swapon :
			printf("swapon\n");
			break;
		case __NR_swapoff :
			printf("swapoff\n");
			break;
		case __NR_reboot :
			printf("reboot\n");
			break;
		case __NR_sethostname :
			printf("sethostname\n");
			break;
		case __NR_setdomainname :
			printf("setdomainname\n");
			break;
		case __NR_iopl :
			printf("iopl\n");
			break;
		case __NR_ioperm :
			printf("ioperm\n");
			break;
		case __NR_create_module :
			printf("create_module\n");
			break;
		case __NR_init_module :
			printf("init_module\n");
			break;
		case __NR_delete_module :
			printf("delete_module\n");
			break;
		case __NR_get_kernel_syms :
			printf("get_kernel_syms\n");
			break;
		case __NR_query_module :
			printf("query_module\n");
			break;
		case __NR_quotactl :
			printf("quotactl\n");
			break;
		case __NR_nfsservctl :
			printf("nfsservctl\n");
			break;
		case __NR_getpmsg :
			printf("getpmsg\n");
			break;
		case __NR_putpmsg :
			printf("putpmsg\n");
			break;
		case __NR_afs_syscall :
			printf("afs_syscall\n");
			break;
		case __NR_tuxcall :
			printf("tuxcall\n");
			break;
		case __NR_security :
			printf("security\n");
			break;
		case __NR_gettid :
			printf("gettid\n");
			break;
		case __NR_readahead :
			printf("readahead\n");
			break;
		case __NR_setxattr :
			printf("setxattr\n");
			break;
		case __NR_lsetxattr :
			printf("lsetxattr\n");
			break;
		case __NR_fsetxattr :
			printf("fsetxattr\n");
			break;
		case __NR_getxattr :
			printf("getxattr\n");
			break;
		case __NR_lgetxattr :
			printf("lgetxattr\n");
			break;
		case __NR_fgetxattr :
			printf("fgetxattr\n");
			break;
		case __NR_listxattr :
			printf("listxattr\n");
			break;
		case __NR_llistxattr :
			printf("llistxattr\n");
			break;
		case __NR_flistxattr :
			printf("flistxattr\n");
			break;
		case __NR_removexattr :
			printf("removexattr\n");
			break;
		case __NR_lremovexattr :
			printf("lremovexattr\n");
			break;
		case __NR_fremovexattr :
			printf("fremovexattr\n");
			break;
		case __NR_tkill :
			printf("tkill\n");
			break;
		case __NR_time :
			printf("time\n");
			break;
		case __NR_futex :
			printf("futex\n");
			break;
		case __NR_sched_setaffinity :
			printf("sched_setaffinity\n");
			break;
		case __NR_sched_getaffinity :
			printf("sched_getaffinity\n");
			break;
		case __NR_set_thread_area :
			printf("set_thread_area\n");
			break;
		case __NR_io_setup :
			printf("io_setup\n");
			break;
		case __NR_io_destroy :
			printf("io_destroy\n");
			break;
		case __NR_io_getevents :
			printf("io_getevents\n");
			break;
		case __NR_io_submit :
			printf("io_submit\n");
			break;
		case __NR_io_cancel :
			printf("io_cancel\n");
			break;
		case __NR_get_thread_area :
			printf("get_thread_area\n");
			break;
		case __NR_lookup_dcookie :
			printf("lookup_dcookie\n");
			break;
		case __NR_epoll_create :
			printf("epoll_create\n");
			break;
		case __NR_epoll_ctl_old :
			printf("epoll_ctl_old\n");
			break;
		case __NR_epoll_wait_old :
			printf("epoll_wait_old\n");
			break;
		case __NR_remap_file_pages :
			printf("remap_file_pages\n");
			break;
		case __NR_getdents64 :
			printf("getdents64\n");
			break;
		case __NR_set_tid_address :
			printf("set_tid_address\n");
			break;
		case __NR_restart_syscall :
			printf("restart_syscall\n");
			break;
		case __NR_semtimedop :
			printf("semtimedop\n");
			break;
		case __NR_fadvise64 :
			printf("fadvise64\n");
			break;
		case __NR_timer_create :
			printf("timer_create\n");
			break;
		case __NR_timer_settime :
			printf("timer_settime\n");
			break;
		case __NR_timer_gettime :
			printf("timer_gettime\n");
			break;
		case __NR_timer_getoverrun :
			printf("timer_getoverrun\n");
			break;
		case __NR_timer_delete :
			printf("timer_delete\n");
			break;
		case __NR_clock_settime :
			printf("clock_settime\n");
			break;
		case __NR_clock_gettime :
			printf("clock_gettime\n");
			break;
		case __NR_clock_getres :
			printf("clock_getres\n");
			break;
		case __NR_clock_nanosleep :
			printf("clock_nanosleep\n");
			break;
		case __NR_exit_group :
			printf("exit_group\n");
			break;
		case __NR_epoll_wait :
			printf("epoll_wait\n");
			break;
		case __NR_epoll_ctl :
			printf("epoll_ctl\n");
			break;
		case __NR_tgkill :
			printf("tgkill\n");
			break;
		case __NR_utimes :
			printf("utimes\n");
			break;
		case __NR_vserver :
			printf("vserver\n");
			break;
		case __NR_mbind :
			printf("mbind\n");
			break;
		case __NR_set_mempolicy :
			printf("set_mempolicy\n");
			break;
		case __NR_get_mempolicy :
			printf("get_mempolicy\n");
			break;
		case __NR_mq_open :
			printf("mq_open\n");
			break;
		case __NR_mq_unlink :
			printf("mq_unlink\n");
			break;
		case __NR_mq_timedsend :
			printf("mq_timedsend\n");
			break;
		case __NR_mq_timedreceive :
			printf("mq_timedreceive\n");
			break;
		case __NR_mq_notify :
			printf("mq_notify\n");
			break;
		case __NR_mq_getsetattr :
			printf("mq_getsetattr\n");
			break;
		case __NR_kexec_load :
			printf("kexec_load\n");
			break;
		case __NR_waitid :
			printf("waitid\n");
			break;
		case __NR_add_key :
			printf("add_key\n");
			break;
		case __NR_request_key :
			printf("request_key\n");
			break;
		case __NR_keyctl :
			printf("keyctl\n");
			break;
		case __NR_ioprio_set :
			printf("ioprio_set\n");
			break;
		case __NR_ioprio_get :
			printf("ioprio_get\n");
			break;
		case __NR_inotify_init :
			printf("inotify_init\n");
			break;
		case __NR_inotify_add_watch :
			printf("inotify_add_watch\n");
			break;
		case __NR_inotify_rm_watch :
			printf("inotify_rm_watch\n");
			break;
		case __NR_migrate_pages :
			printf("migrate_pages\n");
			break;
		case __NR_openat :
			printf("openat\n");
			break;
		case __NR_mkdirat :
			printf("mkdirat\n");
			break;
		case __NR_mknodat :
			printf("mknodat\n");
			break;
		case __NR_fchownat :
			printf("fchownat\n");
			break;
		case __NR_futimesat :
			printf("futimesat\n");
			break;
		case __NR_newfstatat :
			printf("newfstatat\n");
			break;
		case __NR_unlinkat :
			printf("unlinkat\n");
			break;
		case __NR_renameat :
			printf("renameat\n");
			break;
		case __NR_linkat :
			printf("linkat\n");
			break;
		case __NR_symlinkat :
			printf("symlinkat\n");
			break;
		case __NR_readlinkat :
			printf("readlinkat\n");
			break;
		case __NR_fchmodat :
			printf("fchmodat\n");
			break;
		case __NR_faccessat :
			printf("faccessat\n");
			break;
		case __NR_pselect6 :
			printf("pselect6\n");
			break;
		case __NR_ppoll :
			printf("ppoll\n");
			break;
		case __NR_unshare :
			printf("unshare\n");
			break;
		case __NR_set_robust_list :
			printf("set_robust_list\n");
			break;
		case __NR_get_robust_list :
			printf("get_robust_list\n");
			break;
		case __NR_splice :
			printf("splice\n");
			break;
		case __NR_tee :
			printf("tee\n");
			break;
		case __NR_sync_file_range :
			printf("sync_file_range\n");
			break;
		case __NR_vmsplice :
			printf("vmsplice\n");
			break;
		case __NR_move_pages :
			printf("move_pages\n");
			break;
		case __NR_utimensat :
			printf("utimensat\n");
			break;
		case __NR_epoll_pwait :
			printf("epoll_pwait\n");
			break;
		case __NR_signalfd :
			printf("signalfd\n");
			break;
		case __NR_timerfd_create :
			printf("timerfd_create\n");
			break;
		case __NR_eventfd :
			printf("eventfd\n");
			break;
		case __NR_fallocate :
			printf("fallocate\n");
			break;
		case __NR_timerfd_settime :
			printf("timerfd_settime\n");
			break;
		case __NR_timerfd_gettime :
			printf("timerfd_gettime\n");
			break;
		case __NR_accept4 :
			printf("accept4\n");
			break;
		case __NR_signalfd4 :
			printf("signalfd4\n");
			break;
		case __NR_eventfd2 :
			printf("eventfd2\n");
			break;
		case __NR_epoll_create1 :
			printf("epoll_create1\n");
			break;
		case __NR_dup3 :
			printf("dup3\n");
			break;
		case __NR_pipe2 :
			printf("pipe2\n");
			break;
		case __NR_inotify_init1 :
			printf("inotify_init1\n");
			break;
		case __NR_preadv :
			printf("preadv\n");
			break;
		case __NR_pwritev :
			printf("pwritev\n");
			break;
		case __NR_rt_tgsigqueueinfo :
			printf("rt_tgsigqueueinfo\n");
			break;
		case __NR_perf_event_open :
			printf("perf_event_open\n");
			break;
		case __NR_recvmmsg :
			printf("recvmmsg\n");
			break;
		case __NR_fanotify_init :
			printf("fanotify_init\n");
			break;
		case __NR_fanotify_mark :
			printf("fanotify_mark\n");
			break;
		case __NR_prlimit64 :
			printf("prlimit64\n");
			break;
		case __NR_name_to_handle_at :
			printf("name_to_handle_at\n");
			break;
		case __NR_open_by_handle_at :
			printf("open_by_handle_at\n");
			break;
		case __NR_clock_adjtime :
			printf("clock_adjtime\n");
			break;
		case __NR_syncfs :
			printf("syncfs\n");
			break;
		case __NR_sendmmsg :
			printf("sendmmsg\n");
			break;
		case __NR_setns :
			printf("setns\n");
			break;
		case __NR_getcpu :
			printf("getcpu\n");
			break;
		case __NR_process_vm_readv :
			printf("process_vm_readv\n");
			break;
		case __NR_process_vm_writev :
			printf("process_vm_writev\n");
			break;
		case __NR_kcmp :
			printf("kcmp\n");
			break;
		case __NR_finit_module :
			printf("finit_module\n");
			break;
		case __NR_sched_setattr :
			printf("sched_setattr\n");
			break;
		case __NR_sched_getattr :
			printf("sched_getattr\n");
			break;
		case __NR_renameat2 :
			printf("renameat2\n");
			break;
		case __NR_seccomp :
			printf("seccomp\n");
			break;
		case __NR_getrandom :
			printf("getrandom\n");
			break;
		case __NR_memfd_create :
			printf("memfd_create\n");
			break;
		case __NR_kexec_file_load :
			printf("kexec_file_load\n");
			break;
		case __NR_bpf :
			printf("bpf\n");
			break;
		case __NR_execveat :
			printf("execveat\n");
			break;
		case __NR_userfaultfd :
			printf("userfaultfd\n");
			break;
		case __NR_membarrier :
			printf("membarrier\n");
			break;
		case __NR_mlock2 :
			printf("mlock2\n");
			break;
		case __NR_copy_file_range :
			printf("copy_file_range\n");
			break;
		case __NR_preadv2 :
			printf("preadv2\n");
			break;
		case __NR_pwritev2 :
			printf("pwritev2\n");
			break;
		case __NR_pkey_mprotect :
			printf("pkey_mprotect\n");
			break;
		case __NR_pkey_alloc :
			printf("pkey_alloc\n");
			break;
		case __NR_pkey_free :
			printf("pkey_free\n");
			break;
		case __NR_statx :
			printf("statx\n");
			break;
		case __NR_io_pgetevents :
			printf("io_pgetevents\n");
			break;
		case __NR_rseq :
			printf("rseq\n");
			break;
		case __NR_pidfd_send_signal :
			printf("pidfd_send_signal\n");
			break;
		case __NR_io_uring_setup :
			printf("io_uring_setup\n");
			break;
		case __NR_io_uring_enter :
			printf("io_uring_enter\n");
			break;
		case __NR_io_uring_register :
			printf("io_uring_register\n");
			break;
		case __NR_open_tree :
			printf("open_tree\n");
			break;
		case __NR_move_mount :
			printf("move_mount\n");
			break;
		case __NR_fsopen :
			printf("fsopen\n");
			break;
		case __NR_fsconfig :
			printf("fsconfig\n");
			break;
		case __NR_fsmount :
			printf("fsmount\n");
			break;
		case __NR_fspick :
			printf("fspick\n");
			break;
		case __NR_pidfd_open :
			printf("pidfd_open\n");
			break;
		case __NR_clone3 :
			printf("clone3\n");
			break;
		case __NR_close_range :
			printf("close_range\n");
			break;
		case __NR_openat2 :
			printf("openat2\n");
			break;
		case __NR_pidfd_getfd :
			printf("pidfd_getfd\n");
			break;
		case __NR_faccessat2 :
			printf("faccessat2\n");
			break;
		case __NR_process_madvise :
			printf("process_madvise\n");
			break;
		case __NR_epoll_pwait2 :
			printf("epoll_pwait2\n");
			break;
		case __NR_mount_setattr :
			printf("mount_setattr\n");
			break;
		case __NR_quotactl_fd :
			printf("quotactl_fd\n");
			break;
		case __NR_landlock_create_ruleset :
			printf("landlock_create_ruleset\n");
			break;
		case __NR_landlock_add_rule :
			printf("landlock_add_rule\n");
			break;
		case __NR_landlock_restrict_self :
			printf("landlock_restrict_self\n");
			break;
		case __NR_memfd_secret :
			printf("memfd_secret\n");
			break;
		case __NR_process_mrelease :
			printf("process_mrelease\n");
			break;
		case __NR_futex_waitv :
			printf("futex_waitv\n");
			break;
		default:
			printf("Unknown syscall\n");
	}
}
