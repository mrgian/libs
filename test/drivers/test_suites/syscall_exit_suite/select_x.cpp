#include "../../event_class/event_class.h"

#ifdef __NR_select

TEST(SyscallExit, selectX) {
	auto evt_test = get_syscall_event_test(__NR_select, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	assert_syscall_state(SYSCALL_FAILURE,
	                     "select",
	                     syscall(__NR_select, -1, nullptr, nullptr, nullptr, nullptr));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif
