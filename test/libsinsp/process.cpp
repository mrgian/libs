#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "sys_call_test.h"

#include <gtest/gtest.h>

TEST_F(sys_call_test, process_signalfd_kill)
{
	int callnum = 0;

	int ptid;          // parent tid
	int ctid;          // child tid
	int gptid;         // grandparent tid
	int xstatus = 33;  // child exit value
	int ssfd;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt)
	{ return evt->get_tid() == ptid || evt->get_tid() == ctid; };

	//
	// TEST CODE
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector)
	{
		int status;
		int sfd;
		ctid = fork();

		if (ctid >= 0)  // fork succeeded
		{
			if (ctid == 0)
			{
				//
				// CHILD PROCESS
				//
				sigset_t mask;

				/* We will handle SIGTERM and SIGINT. */
				sigemptyset(&mask);
				sigaddset(&mask, SIGTERM);
				sigaddset(&mask, SIGINT);

				/* Block the signals that we handle using signalfd(), so they don't
				 * cause signal handlers or default signal actions to execute. */
				if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
				{
					FAIL();
				}

				/* Create a file descriptor from which we will read the signals. */
				sfd = signalfd(-1, &mask, 0);
				if (sfd < 0)
				{
					FAIL();
				}

				while (true)
				{
					/** The buffer for read(), this structure contains information
					 * about the signal we've read. */
					struct signalfd_siginfo si;

					ssize_t res;

					res = read(sfd, &si, sizeof(si));

					if (res < 0)
					{
						FAIL();
					}
					if (res != sizeof(si))
					{
						FAIL();
					}

					if (si.ssi_signo == SIGTERM)
					{
						continue;
					}
					else if (si.ssi_signo == SIGINT)
					{
						break;
					}
					else
					{
						FAIL();
					}
				}

				/* Close the file descriptor if we no longer need it. */
				close(sfd);

				sleep(1);

				//
				// Remember to use _exit or the test system will get fucked!!
				//
				_exit(xstatus);
			}
			else
			{
				//
				// PARENT PROCESS
				//
				ptid = getpid();
				gptid = getppid();

				//
				// Give the client some time install its handlers
				//
				usleep(200000);

				kill(ctid, SIGTERM);
				kill(ctid, SIGINT);

				//
				// Wait for child to exit, and store its status
				//
				ASSERT_EQ(waitpid(ctid, &status, 0), ctid);
			}
		}
		else
		{
			FAIL();
		}
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if (type == PPME_SYSCALL_SIGNALFD_E)
		{
			EXPECT_EQ(-1, std::stoi(e->get_param_value_str("fd", false)));
			EXPECT_EQ(0, std::stoi(e->get_param_value_str("mask")));
			EXPECT_EQ(0, std::stoi(e->get_param_value_str("flags")));
			callnum++;
		}
		else if (type == PPME_SYSCALL_SIGNALFD4_E)
		{
			EXPECT_EQ(-1, std::stoi(e->get_param_value_str("fd", false)));
			EXPECT_EQ(0, std::stoi(e->get_param_value_str("mask")));
			callnum++;
		}
		else if (type == PPME_SYSCALL_SIGNALFD_X || type == PPME_SYSCALL_SIGNALFD4_X)
		{
			ssfd = std::stoi(e->get_param_value_str("res", false));
			callnum++;
		}
		else if (type == PPME_SYSCALL_READ_E)
		{
			if (callnum == 2)
			{
				EXPECT_EQ("<s>", e->get_param_value_str("fd"));
				EXPECT_EQ(ssfd, std::stoi(e->get_param_value_str("fd", false)));
				callnum++;
			}
		}
		else if (type == PPME_SYSCALL_KILL_E)
		{
			if (callnum == 3)
			{
				EXPECT_EQ("tests", e->get_param_value_str("pid"));
				EXPECT_EQ(ctid, std::stoi(e->get_param_value_str("pid", false)));
				EXPECT_EQ("SIGTERM", e->get_param_value_str("sig"));
				EXPECT_EQ(SIGTERM, std::stoi(e->get_param_value_str("sig", false)));
				callnum++;
			}
			else if (callnum == 5)
			{
				EXPECT_EQ("tests", e->get_param_value_str("pid"));
				EXPECT_EQ(ctid, std::stoi(e->get_param_value_str("pid", false)));
				EXPECT_EQ("SIGINT", e->get_param_value_str("sig"));
				EXPECT_EQ(SIGINT, std::stoi(e->get_param_value_str("sig", false)));
				callnum++;
			}
		}
		else if (type == PPME_SYSCALL_KILL_X)
		{
			EXPECT_EQ(0, std::stoi(e->get_param_value_str("res", false)));
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	EXPECT_EQ(7, callnum);
}

TEST_F(sys_call_test, process_usleep)
{
	int callnum = 0;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector)
	{
		usleep(123456);
		sleep(5);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if (type == PPME_SYSCALL_NANOSLEEP_E)
		{
			if (callnum == 0)
			{
				if (std::stoi(e->get_param_value_str("interval", false)) == 123456000)
				{
					callnum++;
				}
			}
			else if (callnum == 2)
			{
				EXPECT_EQ(5000000000,
				          std::stoi(e->get_param_value_str("interval", false)));
				callnum++;
			}
		}
		else if (type == PPME_SYSCALL_NANOSLEEP_X)
		{
			EXPECT_EQ(0, std::stoi(e->get_param_value_str("res", false)));
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	EXPECT_EQ(4, callnum);
}

#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

TEST_F(sys_call_test, process_inotify)
{
	int callnum = 0;
	int fd;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector)
	{
		int length;
		int wd;
		char buffer[EVENT_BUF_LEN];

		//
		// creating the INOTIFY instance
		//
		fd = inotify_init();

		/*checking for error*/
		if (fd < 0)
		{
			FAIL();
		}

		//
		// The IN_MODIFY flag causes a notification when a file is written, which should
		// happen immediately in captures
		//
		wd = inotify_add_watch(fd, "./captures", IN_MODIFY);

		//
		// read to determine the event changes
		//
		length = read(fd, buffer, EVENT_BUF_LEN);
		if (length < 0)
		{
			FAIL();
		}

		//
		// removing the watch
		//
		inotify_rm_watch(fd, wd);

		//
		// closing the INOTIFY instance
		//
		close(fd);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if (type == PPME_SYSCALL_INOTIFY_INIT_E)
		{
			EXPECT_EQ(0, std::stoi(e->get_param_value_str("flags")));
			callnum++;
		}
		else if (type == PPME_SYSCALL_INOTIFY_INIT_X)
		{
			EXPECT_EQ(fd, std::stoi(e->get_param_value_str("res", false)));
			callnum++;
		}
		else if (type == PPME_SYSCALL_READ_E)
		{
			if (callnum == 2)
			{
				EXPECT_EQ("<i>", e->get_param_value_str("fd"));
				EXPECT_EQ(fd, std::stoi(e->get_param_value_str("fd", false)));
				callnum++;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	EXPECT_EQ(3, callnum);
}

/*TEST(procinfo, process_not_existent)
{
	sinsp inspector;

	test_helpers::get_and_execute_load_plan(inspector, {});

	//
	// The first lookup should fail
	//
	EXPECT_EQ(NULL, inspector.get_thread_ref(0xffff, false, true).get());

	//
	// Even the second, to confirm that nothing was added to the table
	//
	EXPECT_EQ(NULL, inspector.get_thread_ref(0xffff, false, true).get());

	//
	// Now a new entry should be added to the process list...
	//
	sinsp_threadinfo* tinfo = inspector.get_thread_ref(0xffff, true, true).get();
	EXPECT_NE((sinsp_threadinfo*)NULL, tinfo);
	if (tinfo)
	{
		EXPECT_EQ("<NA>", tinfo->m_comm);
	}

	//
	// ...and confirm
	//
	tinfo = inspector.get_thread_ref(0xffff, false, true).get();
	EXPECT_NE((sinsp_threadinfo*)NULL, tinfo);
	if (tinfo)
	{
		EXPECT_EQ("<NA>", tinfo->m_comm);
	}

	inspector.close();
}*/

TEST_F(sys_call_test, process_rlimit)
{
	int callnum = 0;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector)
	{
		struct rlimit rl;

		// Called directly because libc likes prlimit()
		syscall(SYS_getrlimit, RLIMIT_NOFILE, (struct rlimit*)33);
		syscall(SYS_getrlimit, RLIMIT_NOFILE, &rl);
		rl.rlim_cur = 500;
		rl.rlim_max = 1000;
		syscall(SYS_setrlimit, RLIMIT_NOFILE, &rl);
		syscall(SYS_getrlimit, RLIMIT_NOFILE, &rl);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if (type == PPME_SYSCALL_GETRLIMIT_E)
		{
			EXPECT_EQ((int64_t)PPM_RLIMIT_NOFILE,
			          std::stoi(e->get_param_value_str("resource", false)));
			callnum++;
		}
		if (type == PPME_SYSCALL_GETRLIMIT_X)
		{
			if (callnum == 1)
			{
				EXPECT_GT((int64_t)0, std::stoi(e->get_param_value_str("res", false)));
			}
			else
			{
				EXPECT_EQ((int64_t)0, std::stoi(e->get_param_value_str("res", false)));

				if (callnum == 7)
				{
					EXPECT_EQ((int64_t)500,
					          std::stoi(e->get_param_value_str("cur", false)));
					EXPECT_EQ((int64_t)1000,
					          std::stoi(e->get_param_value_str("max", false)));
				}
			}

			callnum++;
		}
		if (type == PPME_SYSCALL_SETRLIMIT_E)
		{
			EXPECT_EQ((int64_t)PPM_RLIMIT_NOFILE,
			          std::stoi(e->get_param_value_str("resource", false)));
			callnum++;
		}
		if (type == PPME_SYSCALL_SETRLIMIT_X)
		{
			EXPECT_EQ((int64_t)0, std::stoi(e->get_param_value_str("res", false)));

			if (callnum == 5)
			{
				EXPECT_EQ((int64_t)500,
				          std::stoi(e->get_param_value_str("cur", false)));
				EXPECT_EQ((int64_t)1000,
				          std::stoi(e->get_param_value_str("max", false)));
			}

			callnum++;
		}
		if (type == PPME_SYSCALL_PRLIMIT_E)
		{
			EXPECT_EQ((int64_t)PPM_RLIMIT_NOFILE,
			          std::stoi(e->get_param_value_str("resource", false)));
			callnum++;
		}
		if (type == PPME_SYSCALL_PRLIMIT_X)
		{
			int64_t res = std::stoi(e->get_param_value_str("res", false));
			int64_t newcur = std::stoi(e->get_param_value_str("newcur", false));
			int64_t newmax = std::stoi(e->get_param_value_str("newmax", false));
			int64_t oldcur = std::stoi(e->get_param_value_str("oldcur", false));
			int64_t oldmax = std::stoi(e->get_param_value_str("oldmax", false));
			switch (callnum)
			{
			case 1:
				EXPECT_GT(0, res);
				break;
			case 3:
				EXPECT_EQ(0, res);
				EXPECT_EQ(-1, newcur);
				EXPECT_EQ(-1, newmax);
				break;
			case 5:
				EXPECT_EQ(0, res);
				EXPECT_EQ(500, newcur);
				EXPECT_EQ(1000, newmax);
				EXPECT_EQ(-1, oldcur);
				EXPECT_EQ(-1, oldmax);
				break;
			case 7:
				EXPECT_EQ(0, res);
				EXPECT_EQ(-1, newcur);
				EXPECT_EQ(-1, newmax);
				EXPECT_EQ(500, oldcur);
				EXPECT_EQ(1000, oldmax);
				break;
			}
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	EXPECT_EQ(8, callnum);
}

TEST_F(sys_call_test, process_prlimit)
{
	int callnum = 0;
	struct rlimit tmprl;
	struct rlimit orirl;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector)
	{
		struct rlimit newrl;
		struct rlimit oldrl;

		syscall(SYS_prlimit64, getpid(), RLIMIT_NOFILE, NULL, &orirl);
		newrl.rlim_cur = 500;
		newrl.rlim_max = 1000;
		syscall(SYS_prlimit64, getpid(), RLIMIT_NOFILE, &newrl, &oldrl);
		syscall(SYS_prlimit64, getpid(), RLIMIT_NOFILE, NULL, &oldrl);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if (type == PPME_SYSCALL_PRLIMIT_E)
		{
			EXPECT_EQ((int64_t)PPM_RLIMIT_NOFILE,
			          std::stoi(e->get_param_value_str("resource", false)));
			EXPECT_EQ((int64_t)getpid(),
			          std::stoi(e->get_param_value_str("pid", false)));
			callnum++;
		}
		else if (type == PPME_SYSCALL_PRLIMIT_X)
		{
			EXPECT_GE((int64_t)0, std::stoi(e->get_param_value_str("res", false)));

			if (callnum == 1)
			{
				EXPECT_EQ((int64_t)0,
				          std::stoi(e->get_param_value_str("newcur", false)));
				EXPECT_EQ((int64_t)0,
				          std::stoi(e->get_param_value_str("newmax", false)));
				EXPECT_EQ((int64_t)orirl.rlim_cur,
				          std::stoi(e->get_param_value_str("oldcur", false)));
				EXPECT_EQ((int64_t)orirl.rlim_max,
				          std::stoi(e->get_param_value_str("oldmax", false)));
			}
			else if (callnum == 3)
			{
				EXPECT_EQ((int64_t)500,
				          std::stoi(e->get_param_value_str("newcur", false)));
				EXPECT_EQ((int64_t)1000,
				          std::stoi(e->get_param_value_str("newmax", false)));
				EXPECT_EQ((int64_t)orirl.rlim_cur,
				          std::stoi(e->get_param_value_str("oldcur", false)));
				EXPECT_EQ((int64_t)orirl.rlim_max,
				          std::stoi(e->get_param_value_str("oldmax", false)));
			}
			else if (callnum == 5)
			{
				EXPECT_EQ((int64_t)0,
				          std::stoi(e->get_param_value_str("newcur", false)));
				EXPECT_EQ((int64_t)0,
				          std::stoi(e->get_param_value_str("newmax", false)));
				EXPECT_EQ((int64_t)500,
				          std::stoi(e->get_param_value_str("oldcur", false)));
				EXPECT_EQ((int64_t)1000,
				          std::stoi(e->get_param_value_str("oldmax", false)));
			}

			callnum++;
		}
	};

	if (syscall(SYS_prlimit64, getpid(), RLIMIT_NOFILE, NULL, &tmprl) != 0)
	{
		return;
	}

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	EXPECT_EQ(6, callnum);
}