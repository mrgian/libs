#include "event_capture.h"
#include "sys_call_test.h"

#include <gtest/gtest.h>

#include <sys/quota.h>
#include <sys/resource.h>
#include <sys/syscall.h>

#include <memory>
#include <mutex>
#include <thread>

struct test_helper_args
{
	bool start_before;
	bool suppress_before;
	bool spawn_with_bash;
};

static void test_helper_quotactl(test_helper_args& hargs)
{
	// We start the test_helper process before starting the
	// capture, so the initial proc scan will see the pid. Once
	// the capture has started we let the test_helper process
	// perform its work.
	pid_t pid = getpid();
	bool test_helper_done = false;

	//proc test_proc = proc("./test_helper", {"threaded", "quotactl_ko"});
	subprocess test_proc = subprocess("./test/libsinsp/test_helper", {"threaded", "quotactl_ko"}, false);

	if (hargs.spawn_with_bash)
	{
		//test_proc = proc("./test_helper.sh", {"threaded", "quotactl_ko"});
		test_proc = subprocess("./test/libsinsp/test_helper.sh", {"threaded", "quotactl_ko"}, false);
	}

	//std::shared_ptr<Poco::ProcessHandle> test_helper_h;
	//Poco::Pipe* test_helper_stdin;
	int64_t test_helper_pid = 0;

	if (hargs.start_before)
	{
		/*auto test_proc_handle = start_process_sync(&test_proc);
		test_helper_h = std::make_shared<Poco::ProcessHandle>(std::get<0>(test_proc_handle));
		test_helper_stdin = std::get<1>(test_proc_handle);
		delete std::get<2>(test_proc_handle);
		test_helper_pid = test_helper_h->id();*/
		test_proc.start();
		test_proc.wait_for_start();
		std::printf("after wait\n");
		test_helper_pid = test_proc.get_pid();
		std::printf("PID: %ld\n");
	}

	//
	// Access/modify inspector before opening
	//

	before_open_t before_open = [&](sinsp* inspector)
	{
        std::printf("before open");
		if (hargs.suppress_before)
		{
			inspector->suppress_events_comm(
			    std::string((hargs.spawn_with_bash ? "test_helper.sh" : "test_helper")));
		}
	};

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) {
		return (evt->get_type() == PPME_SYSCALL_QUOTACTL_X || evt->get_type() == PPME_PROCEXIT_1_E);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
	{
        std::printf("start test\n");
		if (!hargs.suppress_before)
		{
			std::scoped_lock inspector_handle_lock(inspector_handle);
			inspector_handle->suppress_events_comm(
			    std::string((hargs.spawn_with_bash ? "test_helper.sh" : "test_helper")));
		}

		if (!hargs.start_before)
		{
			/*auto test_proc_handle = start_process_sync(&test_proc);
			test_helper_h = std::make_shared<Poco::ProcessHandle>(std::get<0>(test_proc_handle));
			test_helper_stdin = std::get<1>(test_proc_handle);
			delete std::get<2>(test_proc_handle);
			test_helper_pid = test_helper_h->id();*/
			test_proc.start();
			test_proc.wait_for_start();
			test_helper_pid = test_proc.get_pid();
		}

        std::printf("start");

		// Send a message to test_helper. This instructs it to continue.
		//test_helper_stdin->writeBytes("START", 5);
		test_proc.in() << "START";


		// Wait for it to finish
		//test_helper_h->wait();
		test_proc.wait();

		// Do a quotactl--when the callback loop sees this,
		// it's an indication that all the relevant events
		// have been received.
		quotactl(QCMD(Q_QUOTAOFF, GRPQUOTA), "/dev/xxx", 0, NULL);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* evt = param.m_evt;

		// make sure we don't add suppresed threads during initial /proc scan
		if (param.m_inspector->check_suppressed(evt->get_tid()))
		{
			ASSERT_EQ(nullptr, param.m_inspector->get_thread_ref(evt->get_tid(), false, true));
		}

		switch (evt->get_type())
		{
		case PPME_SYSCALL_QUOTACTL_X:
			if (evt->get_tid() != pid)
			{
				FAIL() << "Should not have observed any quotactl event";
			}
			else
			{
				test_helper_done = true;
			}
			break;
		case PPME_PROCEXIT_1_E:
			ASSERT_FALSE(param.m_inspector->check_suppressed(evt->get_tid()));
			break;
		}
	};

	capture_continue_t should_continue = [&]() { return (!test_helper_done); };

	before_close_t before_close = [](sinsp* inspector)
	{
		scap_stats st;

		inspector->get_capture_stats(&st);

		ASSERT_GT(st.n_suppressed, 0u);
		ASSERT_EQ(0u, st.n_tids_suppressed);
	};

	/*ASSERT_NO_FATAL_FAILURE({
		event_capture::run(test,
		                   callback,
		                   filter,
		                   nullptr,
		                   131072,
		                   6000,
		                   6000,
		                   SINSP_MODE_LIVE,
		                   before_open,
		                   before_close,
		                   should_continue,
		                   1000);
	});
	delete test_helper_stdin;*/
	ASSERT_NO_FATAL_FAILURE({
		event_capture::run(test,
				callback,
				filter,
				before_open,
				before_close,
				should_continue,
				131072,
				6000,
				6000,
				SINSP_MODE_LIVE,
				1000);
	});
}

TEST_F(sys_call_test, suppress_existing_process)
{
	test_helper_args hargs;
	hargs.start_before = true;
	hargs.suppress_before = true;
	hargs.spawn_with_bash = false;

	test_helper_quotactl(hargs);
}

TEST_F(sys_call_test, suppress_new_process)
{
	test_helper_args hargs;
	hargs.start_before = false;
	hargs.suppress_before = true;
	hargs.spawn_with_bash = false;

	test_helper_quotactl(hargs);
}

TEST_F(sys_call_test, suppress_add_new_value_while_running)
{
	test_helper_args hargs;
	hargs.start_before = false;
	hargs.suppress_before = false;
	hargs.spawn_with_bash = false;

	test_helper_quotactl(hargs);
}

TEST_F(sys_call_test, suppress_grandchildren)
{
	test_helper_args hargs;
	hargs.start_before = false;
	hargs.suppress_before = true;
	hargs.spawn_with_bash = true;

	test_helper_quotactl(hargs);
}