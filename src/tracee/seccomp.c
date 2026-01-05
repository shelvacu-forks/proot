#include <errno.h>     /* E*, */
#include <signal.h>    /* SIGSYS, */
#include <unistd.h>    /* getpgid, */
#include <utime.h>     /* utimbuf, */
#include <sys/vfs.h>   /* statfs64 */
#include <string.h>    /* memset   */
#include <linux/net.h> /* SYS_SENDMMSG */
#include <assert.h>    /* assert(3), */
#include <time.h>      /* time(2), */

#include "extension/extension.h"
#include "cli/note.h"
#include "syscall/chain.h"
#include "syscall/syscall.h"
#include "tracee/seccomp.h"
#include "tracee/mem.h"
#include "tracee/statx.h"
#include "path/path.h"

static int handle_seccomp_event_common(Tracee *tracee);

/**
 * Restart syscall that caused seccomp event
 * after changing it in tracee registers
 *
 * Syscall that will be restarted will be translated by proot
 * so SIGSYS handler sees untranslated paths and should leave
 * them untranslated.
 */
void restart_syscall_after_seccomp(Tracee* tracee) {
	word_t instr_pointer;

	/* Enable restore regs at end of replaced call.
	 * This also defers delivering of signals until restarted syscall finishes.  */
	tracee->restore_original_regs_after_seccomp_event = true;
	tracee->restart_how = PTRACE_SYSCALL;

	/* Move the instruction pointer back to the original trap */
	instr_pointer = peek_reg(tracee, CURRENT, INSTR_POINTER);
	poke_reg(tracee, INSTR_POINTER, instr_pointer - get_systrap_size(tracee));

	/* X86 usually uses orig_rax when selecting syscall,
	 * but as this code is happening outside syscall handler
	 * we need to copy orig_eax back to eax.  */
#if defined(ARCH_X86_64)
	tracee->_regs[CURRENT].rax = tracee->_regs[CURRENT].orig_rax;
#elif defined(ARCH_X86)
	tracee->_regs[CURRENT].eax = tracee->_regs[CURRENT].orig_eax;
#endif

	/* Write registers. (Omiting special sysnum logic as we're not during syscall
	 * execution, but we're queueing new syscall to be called) */
	push_specific_regs(tracee, false);
}

/**
 * Set specified result (negative for errno) and do not restart syscall.
 */
void set_result_after_seccomp(Tracee *tracee, word_t result) {
	VERBOSE(tracee, 3, "Setting result after SIGSYS to 0x%lx", result);
	poke_reg(tracee, SYSARG_RESULT, result);
	push_specific_regs(tracee, false);
}

/**
 * Handle SIGSYS signal that was caused by system seccomp policy.
 *
 * Return 0 to swallow signal or SIGSYS to deliver it to process.
 */
int handle_seccomp_event(Tracee* tracee)
{
	int ret;

	/* Reset status so next SIGTRAP | 0x80 is
	 * recognized as syscall entry.  */
	tracee->status = 0;

	/* Registers are never restored at this stage as they weren't saved.  */
	tracee->restore_original_regs = false;

	/* Fetch registers.  */
	ret = fetch_regs(tracee);
	if (ret != 0) {
		VERBOSE(tracee, 1, "Couldn't fetch regs on seccomp SIGSYS");
		return SIGSYS;
	}

	/* Save regs so they can be restored at end of replaced call.  */
	save_current_regs(tracee, ORIGINAL_SECCOMP_REWRITE);

	/* X86 uses orig_rax when selecting syscall,
	 * however at this point we are after syscall has been rejected
	 * and orig_rax was reset to -1.  */
#if defined(ARCH_X86_64)
	tracee->_regs[CURRENT].orig_rax = tracee->_regs[CURRENT].rax;
#elif defined(ARCH_X86)
	tracee->_regs[CURRENT].orig_eax = tracee->_regs[CURRENT].eax;
#endif

	print_current_regs(tracee, 3, "seccomp SIGSYS");

	return handle_seccomp_event_common(tracee);
}

void fix_and_restart_enosys_syscall(Tracee* tracee)
{
	/* Reset tracee state so we're not handling syscall exit */
	tracee->status = 0;
	tracee->restore_original_regs = false;

	/* Restore and save original registers */
	memcpy(&tracee->_regs[CURRENT], &tracee->_regs[ORIGINAL], sizeof(tracee->_regs[CURRENT]));
	save_current_regs(tracee, ORIGINAL_SECCOMP_REWRITE);

	handle_seccomp_event_common(tracee);
}

static int handle_seccomp_event_common(Tracee *tracee)
{
	int ret;
	int status;
	Sysnum sysnum = get_sysnum(tracee, CURRENT);

	sysnum = get_sysnum(tracee, CURRENT);

	status = notify_extensions(tracee, SIGSYS_OCC, 0, 0);
	if (status < 0) {
		VERBOSE(tracee, 4, "SIGSYS errored out when being handled by an extension");
		set_result_after_seccomp(tracee, status);
		return 0;
	}
	if (status == 1) {
		VERBOSE(tracee, 4, "SIGSYS fully handled by an extension");
		set_result_after_seccomp(tracee, 0);
		return 0;
	}
	if (status == 2) {
		VERBOSE(tracee, 4, "SIGSYS fully handled by an extension with result set");
		return 0;
	}

	switch (sysnum) {
	case PR_open:
		set_sysnum(tracee, PR_openat);
		poke_reg(tracee, SYSARG_4, peek_reg(tracee, CURRENT, SYSARG_3));
		poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
		poke_reg(tracee, SYSARG_1, AT_FDCWD);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_accept:
		set_sysnum(tracee, PR_accept4);
		poke_reg(tracee, SYSARG_4, 0);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_setgroups:
	case PR_setgroups32:
		set_result_after_seccomp(tracee, 0);
		break;

	case PR_getpgrp:
		/* Query value with getpgid and set it as result.  */
		set_result_after_seccomp(tracee, getpgid(tracee->pid));
		break;

	case PR_symlink:
		set_sysnum(tracee, PR_symlinkat);
		poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2, AT_FDCWD);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_link:
		set_sysnum(tracee, PR_linkat);
		poke_reg(tracee, SYSARG_4, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
		poke_reg(tracee, SYSARG_1, AT_FDCWD);
		poke_reg(tracee, SYSARG_3, AT_FDCWD);
		poke_reg(tracee, SYSARG_5, 0);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_chmod:
		set_sysnum(tracee, PR_fchmodat);
		poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
		poke_reg(tracee, SYSARG_1, AT_FDCWD);
		poke_reg(tracee, SYSARG_4, 0);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_chown:
	case PR_lchown:
	case PR_chown32:
	case PR_lchown32:
		set_sysnum(tracee, PR_fchownat);
		poke_reg(tracee, SYSARG_4, peek_reg(tracee, CURRENT, SYSARG_3));
		poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
		poke_reg(tracee, SYSARG_1, AT_FDCWD);
		if (sysnum == PR_lchown || sysnum == PR_lchown32) {
			poke_reg(tracee, SYSARG_5, AT_SYMLINK_NOFOLLOW);
		} else {
			poke_reg(tracee, SYSARG_5, 0);
		}
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_unlink:
	case PR_rmdir:
		set_sysnum(tracee, PR_unlinkat);
		poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
		poke_reg(tracee, SYSARG_1, AT_FDCWD);
		poke_reg(tracee, SYSARG_3, sysnum==PR_rmdir ? AT_REMOVEDIR : 0);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_send:
		set_sysnum(tracee, PR_sendto);
		poke_reg(tracee, SYSARG_5, 0);
		poke_reg(tracee, SYSARG_6, 0);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_recv:
		set_sysnum(tracee, PR_recvfrom);
		poke_reg(tracee, SYSARG_5, 0);
		poke_reg(tracee, SYSARG_6, 0);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_waitpid:
		set_sysnum(tracee, PR_wait4);
		poke_reg(tracee, SYSARG_4, 0);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_statfs:
	{
		int size;
		char path[PATH_MAX];
		char original[PATH_MAX];
		char devshm_path[PATH_MAX];
		struct statfs64 my_statfs64;
		struct compat_statfs my_statfs;
		size = read_string(tracee, original, peek_reg(tracee, CURRENT, SYSARG_1), PATH_MAX);
		if (size < 0) {
			set_result_after_seccomp(tracee, size);
			break;
		}
		if (size >= PATH_MAX) { 
			set_result_after_seccomp(tracee, -ENAMETOOLONG);
			break;
		}
            	translate_path(tracee, path, AT_FDCWD, original, true);
		errno = 0;
		status = statfs64(path, &my_statfs64); 
		if (errno != 0) {
			set_result_after_seccomp(tracee, -errno);
			break;
		}

		/* Fake /dev/shm being tmpfs, see statfs handler in syscall/exit.c */
		if (translate_path(tracee, devshm_path, AT_FDCWD, "/dev/shm", true) >= 0) {
			Comparison comparison = compare_paths(devshm_path, path);
			if (comparison == PATHS_ARE_EQUAL || comparison == PATH1_IS_PREFIX) {
				my_statfs64.f_type = 0x01021994;
			}
		}

		if ((my_statfs64.f_blocks | my_statfs64.f_bfree | my_statfs64.f_bavail |
     		     my_statfs64.f_bsize | my_statfs64.f_frsize | my_statfs64.f_files | 
		     my_statfs64.f_ffree) & 0xffffffff00000000ULL) { 
			set_result_after_seccomp(tracee, -EOVERFLOW);
			break;
		}
		my_statfs.f_type = my_statfs64.f_type;
		my_statfs.f_bsize = my_statfs64.f_bsize;
		my_statfs.f_blocks = my_statfs64.f_blocks;
		my_statfs.f_bfree = my_statfs64.f_bfree;
		my_statfs.f_bavail = my_statfs64.f_bavail;
		my_statfs.f_files = my_statfs64.f_files;
		my_statfs.f_ffree = my_statfs64.f_ffree;
		my_statfs.f_fsid = my_statfs64.f_fsid;
		my_statfs.f_namelen = my_statfs64.f_namelen;
		my_statfs.f_frsize = my_statfs64.f_frsize;
		my_statfs.f_flags = my_statfs64.f_flags;
		memset(my_statfs.f_spare, 0, sizeof(my_statfs.f_spare));
                write_data(tracee, peek_reg(tracee, CURRENT, SYSARG_2), &my_statfs, sizeof(struct compat_statfs));

		set_result_after_seccomp(tracee, 0);
		break;
	}

	case PR_utimes:
	{
		/* int utimes(const char *filename, const struct timeval times[2]);
		 *
		 * convert to:
		 * int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags);  */
		struct timeval times[2];
		struct timespec timens[2];

		set_sysnum(tracee, PR_utimensat);
		if (peek_reg(tracee, CURRENT, SYSARG_2) != 0) {
			ret = read_data(tracee, times, peek_reg(tracee, CURRENT, SYSARG_2), sizeof(times));
			if (ret < 0) {
				set_result_after_seccomp(tracee, ret);
				break;
			}
			timens[0].tv_sec = (time_t)times[0].tv_sec;
			timens[0].tv_nsec = (long)times[0].tv_usec * 1000;
			timens[1].tv_sec = (time_t)times[1].tv_sec;
			timens[1].tv_nsec = (long)times[1].tv_usec * 1000;
			ret = set_sysarg_data(tracee, timens, sizeof(timens), SYSARG_2);
			if (ret < 0) {
				set_result_after_seccomp(tracee, ret);
				break;
			}
		}
		poke_reg(tracee, SYSARG_4, 0);
		poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
		poke_reg(tracee, SYSARG_1, AT_FDCWD);
		restart_syscall_after_seccomp(tracee);
		break;
	}

	case PR_utime:
	{
		/* int utime(const char *filename, const struct utimbuf *times);
		 *
		 * convert to:
		 * int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags);  */
		struct utimbuf times;
		struct timespec timens[2];

		set_sysnum(tracee, PR_utimensat);
		if (peek_reg(tracee, CURRENT, SYSARG_2) != 0) {
			ret = read_data(tracee, &times, peek_reg(tracee, CURRENT, SYSARG_2), sizeof(times));
			if (ret < 0) {
				set_result_after_seccomp(tracee, ret);
				break;
			}
			timens[0].tv_sec = (time_t)times.actime;
			timens[0].tv_nsec = 0;
			timens[1].tv_sec = (time_t)times.modtime;
			timens[1].tv_nsec = 0;
			ret = set_sysarg_data(tracee, timens, sizeof(timens), SYSARG_2);
			if (ret < 0) {
				set_result_after_seccomp(tracee, ret);
				break;
			}
		}
		poke_reg(tracee, SYSARG_4, 0);
		poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
		poke_reg(tracee, SYSARG_1, AT_FDCWD);
		restart_syscall_after_seccomp(tracee);
		break;
	}

#if defined(ARCH_X86) || defined(ARCH_X86_64)
	case PR_sendmmsg:
	{
		/* Convert direct sendmmsg syscall to socketcall.
		 * This affects only 32-bit x86, in other archs
		 * bionic doesn't use socketcall() for sendmmsg.  */
		size_t arg_size = sizeof_word(tracee);
		assert(arg_size <= sizeof(word_t));
		byte_t args[arg_size * 4];
		memset(args, 0, arg_size * 4);
		*(word_t*)(args) = peek_reg(tracee, CURRENT, SYSARG_1);
		*(word_t*)(args + arg_size) = peek_reg(tracee, CURRENT, SYSARG_2);
		*(word_t*)(args + 2 * arg_size) = peek_reg(tracee, CURRENT, SYSARG_3);
		*(word_t*)(args + 3 * arg_size) = peek_reg(tracee, CURRENT, SYSARG_4);
		word_t tracee_args = alloc_mem(tracee, arg_size * 4);
		write_data(tracee, tracee_args, args, arg_size * 4);
		set_sysnum(tracee, PR_socketcall);
		poke_reg(tracee, SYSARG_1, SYS_SENDMMSG);
		poke_reg(tracee, SYSARG_2, tracee_args);
		restart_syscall_after_seccomp(tracee);
		break;
	}
#endif

	case PR_stat:
	case PR_lstat:
		set_sysnum(tracee, PR_newfstatat);
		poke_reg(tracee, SYSARG_4, sysnum == PR_lstat ? AT_SYMLINK_NOFOLLOW : 0);
		poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
		poke_reg(tracee, SYSARG_1, AT_FDCWD);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_pipe:
		set_sysnum(tracee, PR_pipe2);
		poke_reg(tracee, SYSARG_2, 0);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_dup2:
		set_sysnum(tracee, PR_dup3);
		poke_reg(tracee, SYSARG_3, 0);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_access:
		set_sysnum(tracee, PR_faccessat);
		poke_reg(tracee, SYSARG_4, 0);
		poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
		poke_reg(tracee, SYSARG_1, AT_FDCWD);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_mkdir:
		set_sysnum(tracee, PR_mkdirat);
		poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
		poke_reg(tracee, SYSARG_1, AT_FDCWD);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_rename:
		set_sysnum(tracee, PR_renameat);
		poke_reg(tracee, SYSARG_4, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_3, AT_FDCWD);
		poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_1));
		poke_reg(tracee, SYSARG_1, AT_FDCWD);
		restart_syscall_after_seccomp(tracee);
		break;

	case PR_select:
	{
		// TODO: This doesn't update timeout with time spent inside select(2)
		//       after returning from syscall
		word_t timeval_arg = peek_reg(tracee, CURRENT, SYSARG_5);
		word_t timespec_arg = 0;
		if (timeval_arg != 0) {
			struct timeval tv = {};
			if (read_data(tracee, &tv, timeval_arg, sizeof(tv))) {
				set_result_after_seccomp(tracee, -EFAULT);
				break;
			}
			if (tv.tv_usec >= 1000000 || tv.tv_usec < 0) {
				set_result_after_seccomp(tracee, -EINVAL);
				break;
			}
			struct timespec ts = {
				.tv_sec = tv.tv_sec,
				.tv_nsec = tv.tv_usec * 1000
			};
			timespec_arg = alloc_mem(tracee, sizeof(ts));
			if(write_data(tracee, timespec_arg, &ts, sizeof(ts))) {
				set_result_after_seccomp(tracee, -EFAULT);
				break;
			}
		}
		set_sysnum(tracee, PR_pselect6);
		poke_reg(tracee, SYSARG_5, timespec_arg);
		poke_reg(tracee, SYSARG_6, 0);
		restart_syscall_after_seccomp(tracee);
		break;
	}

	case PR_poll:
	{
		int ms_arg = (int) peek_reg(tracee, CURRENT, SYSARG_3);
		word_t timespec_arg = 0;
		if (ms_arg >= 0) {
			struct timespec ts = {
				.tv_sec = ms_arg / 1000,
				.tv_nsec = (ms_arg % 1000) * 1000000
			};
			timespec_arg = alloc_mem(tracee, sizeof(ts));
			if(write_data(tracee, timespec_arg, &ts, sizeof(ts))) {
				set_result_after_seccomp(tracee, -EFAULT);
				break;
			}
		}
		set_sysnum(tracee, PR_ppoll);
		poke_reg(tracee, SYSARG_3, timespec_arg);
		poke_reg(tracee, SYSARG_4, 0);
		poke_reg(tracee, SYSARG_5, 0);
		restart_syscall_after_seccomp(tracee);
		break;
	}

	case PR_epoll_wait:
	{
		set_sysnum(tracee, PR_epoll_pwait);
		poke_reg(tracee, SYSARG_5, 0);
		poke_reg(tracee, SYSARG_6, 0);
		restart_syscall_after_seccomp(tracee);
		break;
	}

	case PR_time:
	{
		time_t t = time(NULL);
		word_t addr = peek_reg(tracee, CURRENT, SYSARG_1);
		errno = 0;
		if (addr != 0) {
			poke_word(tracee, addr, t);
		}
		set_result_after_seccomp(tracee, errno ? -EFAULT : t);
		break;
	}

	case PR_statx:
	{
		set_result_after_seccomp(tracee, handle_statx_syscall(tracee, true));
		break;
	}

	case PR_ftruncate:
	{
		if (detranslate_sysnum(get_abi(tracee), PR_ftruncate64) == SYSCALL_AVOIDER) {
			set_result_after_seccomp(tracee, -ENOSYS);
			break;
		}
		set_sysnum(tracee, PR_ftruncate64);
		poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
		poke_reg(tracee, SYSARG_2, 0);
		poke_reg(tracee, SYSARG_4, 0);
		restart_syscall_after_seccomp(tracee);
		break;
	}

	case PR_setresuid:
	case PR_setresgid:
	{
		gid_t rxid, exid, sxid, rxid_, exid_, sxid_;
		rxid = peek_reg(tracee, CURRENT, SYSARG_1);
		exid = peek_reg(tracee, CURRENT, SYSARG_2);
		sxid = peek_reg(tracee, CURRENT, SYSARG_3);
		if (sysnum == PR_setresuid)
			ret = getresuid(&rxid_, &exid_, &sxid_);
		else // sysnum == PR_setresgid
			ret = getresgid(&rxid_, &exid_, &sxid_);
		if (ret) {  // EFAULT = address outside address space
			set_result_after_seccomp(tracee, -EPERM);
			break;
		}
		ret = 0;
                gid_t bad = (gid_t) -1;
		if (rxid != rxid_ && rxid != bad)
			ret = -EPERM;
		if (exid != exid_ && exid != bad)
			ret = -EPERM;
		if (sxid != sxid_ && sxid != bad)
			ret = -EPERM;
		set_result_after_seccomp(tracee, ret);
		break;
	}

        // Android prefers to give SIGSYS for all the syscalls it blocks with SECCOMP, even when you can return an error instead.
        case PR_idle:
	case PR_accept4:
        {
                set_result_after_seccomp(tracee, -EPERM);
                break;
        }

        case PR_mpx:
	case PR_set_robust_list:
        case PR_void:
	case PR_acct:
	case PR_add_key:
	case PR_adjtimex:
	case PR_arch_prctl:
	case PR_arm_sync_file_range:
	case PR_bind:
	case PR_bpf:
	case PR_brk:
	case PR_cacheflush:
	case PR_capget:
	case PR_capset:
	case PR_chdir:
	case PR_chroot:
	case PR_clock_adjtime:
	case PR_clock_getres:
	case PR_clock_gettime:
	case PR_clock_settime:
	case PR_clone:
	case PR_close:
	case PR_connect:
	case PR_copy_file_range:
	case PR_creat:
	case PR_create_module:
	case PR_delete_module:
	case PR_dup:
	case PR_dup3:
	case PR_epoll_create:
	case PR_epoll_create1:
	case PR_epoll_ctl:
	case PR_epoll_ctl_old:
	case PR_epoll_pwait:
	case PR_epoll_wait_old:
	case PR_eventfd:
	case PR_eventfd2:
	case PR_execve:
	case PR_execveat:
	case PR_faccessat:
	case PR_faccessat2:
	case PR_fallocate:
	case PR_fanotify_init:
	case PR_fanotify_mark:
	case PR_fchdir:
	case PR_fchmod:
	case PR_fchmodat:
	case PR_fchown:
	case PR_fchown32:
	case PR_fchownat:
	case PR_fcntl:
	case PR_fcntl64:
	case PR_fdatasync:
	case PR_fgetxattr:
	case PR_finit_module:
	case PR_flistxattr:
	case PR_flock:
	case PR_fork:
	case PR_fremovexattr:
	case PR_fsetxattr:
	case PR_fstat:
	case PR_fstat64:
	case PR_fstatat64:
	case PR_fstatfs:
	case PR_fstatfs64:
	case PR_fsync:
	case PR_ftruncate64:
	case PR_futex:
	case PR_futimesat:
	case PR_getcpu:
	case PR_getcwd:
	case PR_getdents:
	case PR_getdents64:
	case PR_getgroups:
	case PR_getgroups32:
	case PR_getitimer:
	case PR_get_kernel_syms:
	case PR_get_mempolicy:
	case PR_getpeername:
	case PR_getpgid:
	case PR_getpriority:
	case PR_getrandom:
	case PR_getresgid:
	case PR_getresgid32:
	case PR_getresuid:
	case PR_getresuid32:
	case PR_getrlimit:
	case PR_getrusage:
	case PR_getsid:
	case PR_getsockname:
	case PR_getsockopt:
	case PR_get_thread_area:
	case PR_gettimeofday:
	case PR_getxattr:
	case PR_idle:
	case PR_init_module:
	case PR_inotify_add_watch:
	case PR_inotify_init:
	case PR_inotify_init1:
	case PR_inotify_rm_watch:
	case PR_io_cancel:
	case PR_ioctl:
	case PR_io_destroy:
	case PR_io_getevents:
	case PR_ioperm:
	case PR_iopl:
	case PR_ioprio_get:
	case PR_ioprio_set:
	case PR_io_setup:
	case PR_io_submit:
	case PR_kcmp:
	case PR_kexec_file_load:
	case PR_kexec_load:
	case PR_keyctl:
	case PR_kill:
	case PR_lgetxattr:
	case PR_linkat:
	case PR_listen:
	case PR_listxattr:
	case PR_llistxattr:
	case PR__llseek:
	case PR_lookup_dcookie:
	case PR_lremovexattr:
	case PR_lseek:
	case PR_lsetxattr:
	case PR_lstat64:
	case PR_madvise:
	case PR_mbind:
	case PR_membarrier:
	case PR_memfd_create:
	case PR_migrate_pages:
	case PR_mincore:
	case PR_mkdirat:
	case PR_mknod:
	case PR_mknodat:
	case PR_mlock:
	case PR_mlock2:
	case PR_mlockall:
	case PR_mmap:
	case PR_mmap2:
	case PR_modify_ldt:
	case PR_mount:
	case PR_move_pages:
	case PR_mprotect:
	case PR_mpx:
	case PR_mq_getsetattr:
	case PR_mq_notify:
	case PR_mq_open:
	case PR_mq_timedreceive:
	case PR_mq_timedsend:
	case PR_mq_unlink:
	case PR_mremap:
	case PR_msgctl:
	case PR_msgget:
	case PR_msgrcv:
	case PR_msgsnd:
	case PR_msync:
	case PR_munlock:
	case PR_munlockall:
	case PR_munmap:
	case PR_name_to_handle_at:
	case PR_nanosleep:
	case PR_newfstatat:
	case PR__newselect:
	case PR_nfsservctl:
	case PR_nice:
	case PR_oldfstat:
	case PR_oldlstat:
	case PR_oldolduname:
	case PR_oldstat:
	case PR_olduname:
	case PR_openat:
	case PR_open_by_handle_at:
	case PR_pciconfig_iobase:
	case PR_pciconfig_read:
	case PR_pciconfig_write:
	case PR_perf_event_open:
	case PR_personality:
	case PR_pipe2:
	case PR_pivot_root:
	case PR_pkey_alloc:
	case PR_pkey_free:
	case PR_pkey_mprotect:
	case PR_ppoll:
	case PR_prctl:
	case PR_pread64:
	case PR_preadv:
	case PR_preadv2:
	case PR_prlimit64:
	case PR_process_vm_readv:
	case PR_process_vm_writev:
	case PR_pselect6:
	case PR_ptrace:
	case PR_pwrite64:
	case PR_pwritev:
	case PR_pwritev2:
	case PR_query_module:
	case PR_quotactl:
	case PR_read:
	case PR_readahead:
	case PR_readdir:
	case PR_readlink:
	case PR_readlinkat:
	case PR_readv:
	case PR_reboot:
	case PR_recvfrom:
	case PR_recvmmsg:
	case PR_recvmsg:
	case PR_remap_file_pages:
	case PR_removexattr:
	case PR_renameat:
	case PR_renameat2:
	case PR_request_key:
	case PR_rt_sigaction:
	case PR_rt_sigpending:
	case PR_rt_sigprocmask:
	case PR_rt_sigqueueinfo:
	case PR_rt_sigsuspend:
	case PR_rt_sigtimedwait:
	case PR_rt_tgsigqueueinfo:
	case PR_sched_getaffinity:
	case PR_sched_getattr:
	case PR_sched_getparam:
	case PR_sched_get_priority_max:
	case PR_sched_get_priority_min:
	case PR_sched_getscheduler:
	case PR_sched_rr_get_interval:
	case PR_sched_setaffinity:
	case PR_sched_setattr:
	case PR_sched_setparam:
	case PR_sched_setscheduler:
	case PR_sched_yield:
	case PR_seccomp:
	case PR_semctl:
	case PR_semget:
	case PR_semop:
	case PR_semtimedop:
	case PR_sendfile:
	case PR_sendfile64:
	case PR_sendmsg:
	case PR_sendto:
	case PR_setdomainname:
	case PR_setgid:
	case PR_setgid32:
	case PR_sethostname:
	case PR_setitimer:
	case PR_set_mempolicy:
	case PR_setns:
	case PR_setpgid:
	case PR_setpriority:
	case PR_setregid:
	case PR_setregid32:
	case PR_setresgid32:
	case PR_setresuid32:
	case PR_setreuid:
	case PR_setreuid32:
	case PR_setrlimit:
	case PR_setsid:
	case PR_setsockopt:
	case PR_set_thread_area:
	case PR_settimeofday:
	case PR_setuid:
	case PR_setuid32:
	case PR_setxattr:
	case PR_shmat:
	case PR_shmctl:
	case PR_shmdt:
	case PR_shmget:
	case PR_shutdown:
	case PR_sigaction:
	case PR_sigaltstack:
	case PR_signal:
	case PR_signalfd:
	case PR_signalfd4:
	case PR_sigpending:
	case PR_sigprocmask:
	case PR_sigsuspend:
	case PR_socket:
	case PR_socketcall:
	case PR_socketpair:
	case PR_splice:
	case PR_stat64:
	case PR_statfs64:
	case PR_stime:
	case PR_swapoff:
	case PR_swapon:
	case PR_symlinkat:
	case PR_sync_file_range:
	case PR_syncfs:
	case PR__sysctl:
	case PR_sysfs:
	case PR_sysinfo:
	case PR_syslog:
	case PR_tee:
	case PR_tgkill:
	case PR_timer_create:
	case PR_timer_delete:
	case PR_timerfd_create:
	case PR_timerfd_gettime:
	case PR_timerfd_settime:
	case PR_timer_getoverrun:
	case PR_timer_gettime:
	case PR_timer_settime:
	case PR_times:
	case PR_tkill:
	case PR_truncate:
	case PR_truncate64:
	case PR_ugetrlimit:
	case PR_umount:
	case PR_umount2:
	case PR_uname:
	case PR_unlinkat:
	case PR_unshare:
	case PR_uselib:
	case PR_userfaultfd:
	case PR_ustat:
	case PR_utimensat:
	case PR_vfork:
	case PR_vhangup:
	case PR_vm86:
	case PR_vm86old:
	case PR_vmsplice:
	case PR_wait4:
	case PR_waitid:
	case PR_write:
	case PR_writev:
	case PR_get_robust_list:
        // Unimplemented syscalls
        case PR_epoll_wait_old:
        case PR_epoll_ctl_old:
	case PR_afs_syscall:
	case PR_bdflush:
	case PR_break:
	case PR_ftime:
	case PR_getpmsg:
	case PR_gtty:
	case PR_lock:
	case PR_prof:
	case PR_profil:
	case PR_putpmsg:
	case PR_security:
	case PR_stty:
	case PR_tuxcall:
	case PR_ulimit:
	case PR_vserver:
        // ipc is weird
        case PR_ipc:
	case PR_arm_fadvise64_64:
	case PR_fadvise64:
	case PR_fadvise64_64:
	case PR_clock_nanosleep:
        {
                VERBOSE(tracee, 4, "In case for -ENOSYS");
		/* Set errno to -ENOSYS */
		set_result_after_seccomp(tracee, -ENOSYS);
                break;
        }

        case PR_sigreturn:
        case PR_rt_sigreturn:
        {
                return SIGSEG;
        }

        // Not really sure what else to do with these...
        case PR_exit:
        case PR_exit_group:
        case PR_restart_syscall:
        // These syscalls "never fail" by spec; the only consistent thing to do is kill the program
	case PR_alarm:
	case PR_getegid:
	case PR_getegid32:
	case PR_geteuid:
	case PR_geteuid32:
	case PR_getgid:
	case PR_getgid32:
	case PR_getpid:
	case PR_getppid:
	case PR_gettid:
	case PR_getuid:
	case PR_getuid32:
	case PR_pause:
	case PR_setfsgid:
	case PR_setfsgid32:
	case PR_setfsuid:
	case PR_setfsuid32:
	case PR_set_tid_address:
	case PR_sgetmask:
	case PR_ssetmask:
	case PR_sync:
	case PR_umask:
	default:
                VERBOSE(tracee, 4, "In case for SIGSYS");
                // not all syscalls are specified to return an error; ex: `alarm` *always* returns the value of the previous alarm, or 0
                // categorizing all the syscalls into whether they should have a negative return or a SIGSYS or something else would be a lot of work. Fortunately, we're only here *because* the host's seccomp policies already made that decision, and decided it should be SIGSYS. We have no reason to think that was incorrect.
                return SIGSYS;
	}

	return 0;
}
