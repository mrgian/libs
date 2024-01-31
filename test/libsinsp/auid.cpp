// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include "sys_call_test.h"

#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>

#include <pwd.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <istream>
#include <memory>
#include <string>

static sinsp_filter_check_list s_filterlist;

TEST_F(sys_call_test, auid)
{
	std::shared_ptr<sinsp_evt_formatter> userinfo_fmt;
	std::string expected_userinfo;
	int64_t loginuid;
	uid_t uid;
	struct passwd* user;
	std::atomic<bool> saw_socket_event(false);

	// Get uid and name
	uid = getuid();
	expected_userinfo = std::to_string(uid);
	user = getpwuid(uid);
	ASSERT_TRUE(user != NULL);
	expected_userinfo += std::string(" ") + user->pw_name;

	// Separately find out loginuid
	std::ifstream lfile("/proc/self/loginuid");
	ASSERT_TRUE(lfile.is_open());
	lfile >> loginuid;

	expected_userinfo += std::string(" ") + std::to_string(loginuid);
	user = getpwuid(loginuid);
	ASSERT_TRUE(user != NULL);
	expected_userinfo += std::string(" ") + user->pw_name;

	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
	{
		if (!userinfo_fmt)
		{
			std::scoped_lock inspector_handle_lock(inspector_handle);
			userinfo_fmt = std::make_shared<sinsp_evt_formatter>(
			    inspector_handle.safe_ptr(),
			    std::string("%user.uid %user.name %user.loginuid %user.loginname"),
			    s_filterlist);
		}

		int fd = socket(PF_LOCAL, SOCK_STREAM, 0);
		close(fd);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		std::string actual_userinfo;
		sinsp_evt* evt = param.m_evt;

		if (strcmp(evt->get_name(), "socket") == 0)
		{
			userinfo_fmt->tostring(evt, &actual_userinfo);
			ASSERT_STREQ(expected_userinfo.c_str(), actual_userinfo.c_str());
			saw_socket_event.store(true);
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	ASSERT_TRUE(saw_socket_event.load());
};

TEST_F(sys_call_test, auid_through_exec)
{
	std::shared_ptr<sinsp_evt_formatter> userinfo_fmt;
	std::string expected_userinfo;
	int64_t loginuid;
	uid_t uid;
	struct passwd* user;
	std::shared_ptr<sinsp_filter> spawned_by_test;
	bool saw_execve = false;

	// Get uid and name
	uid = getuid();
	expected_userinfo = std::to_string(uid);
	user = getpwuid(uid);
	ASSERT_TRUE(user != NULL);
	expected_userinfo += std::string(" ") + user->pw_name;

	// Separately find out loginuid
	std::ifstream lfile("/proc/self/loginuid");
	ASSERT_TRUE(lfile.is_open());
	lfile >> loginuid;

	expected_userinfo += std::string(" ") + std::to_string(loginuid);
	user = getpwuid(loginuid);
	ASSERT_TRUE(user != NULL);
	expected_userinfo += std::string(" ") + user->pw_name;

	// INIT FILTER
	before_open_t before_open = [&](sinsp* inspector)
	{
		sinsp_filter_compiler compiler(
		    inspector,
		    std::string("evt.type=execve and evt.dir=< and proc.name=ls and proc.apid=") +
		        std::to_string(getpid()));
		spawned_by_test.reset(compiler.compile());
	};

	event_filter_t filter = [&](sinsp_evt* evt) { return spawned_by_test->run(evt); };

	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
	{
		if (!userinfo_fmt)
		{
			std::scoped_lock inspector_handle_lock(inspector_handle);
			userinfo_fmt = std::make_shared<sinsp_evt_formatter>(
			    inspector_handle.safe_ptr(),
			    std::string("%user.uid %user.name %user.loginuid %user.loginname"),
			    s_filterlist);
		}

		ASSERT_EQ(system("ls > /dev/null 2>&1"), 0);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		std::string actual_userinfo;
		sinsp_evt* evt = param.m_evt;

		if (strcmp(evt->get_name(), "execve") == 0)
		{
			userinfo_fmt->tostring(evt, &actual_userinfo);
			ASSERT_STREQ(expected_userinfo.c_str(), actual_userinfo.c_str());
			saw_execve = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter, before_open); });

	ASSERT_TRUE(saw_execve);
};

TEST_F(sys_call_test, auid_sudo_nobody)
{
	std::shared_ptr<sinsp_evt_formatter> userinfo_fmt;
	std::string expected_userinfo;
	int64_t loginuid;
	uid_t uid;
	struct passwd* user;
	std::shared_ptr<sinsp_filter> spawned_by_test;
	bool saw_execve = false;

	// This depends on a user "nobody" existing.
	user = getpwnam("nobody");

	if (user == NULL)
	{
		printf("Skipping test, user \"nobody\" does not exist.\n");
		return;
	}

	// Get uid and name
	uid = user->pw_uid;
	expected_userinfo = std::to_string(uid);
	expected_userinfo += std::string(" ") + user->pw_name;

	// Separately find out loginuid
	std::ifstream lfile("/proc/self/loginuid");
	ASSERT_TRUE(lfile.is_open());
	lfile >> loginuid;

	expected_userinfo += std::string(" ") + std::to_string(loginuid);
	user = getpwuid(loginuid);
	ASSERT_TRUE(user != NULL);
	expected_userinfo += std::string(" ") + user->pw_name;

	before_open_t before_open = [&](sinsp* inspector)
	{
		sinsp_filter_compiler compiler(
		    inspector,
		    std::string("evt.type=execve and evt.dir=< and proc.name=ls and proc.apid=") +
		        std::to_string(getpid()));
		spawned_by_test.reset(compiler.compile());
	};

	event_filter_t filter = [&](sinsp_evt* evt) { return spawned_by_test->run(evt); };

	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
	{
		if (!userinfo_fmt)
		{
			std::scoped_lock inspector_handle_lock(inspector_handle);
			userinfo_fmt = std::make_shared<sinsp_evt_formatter>(
			    inspector_handle.safe_ptr(),
			    std::string("%user.uid %user.name %user.loginuid %user.loginname"),
			    s_filterlist);
		}

		ASSERT_EQ(system("sudo -u nobody ls > /dev/null 2>&1"), 0);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		std::string actual_userinfo;
		sinsp_evt* evt = param.m_evt;

		if (strcmp(evt->get_name(), "execve") == 0)
		{
			userinfo_fmt->tostring(evt, &actual_userinfo);
			ASSERT_STREQ(expected_userinfo.c_str(), actual_userinfo.c_str());
			saw_execve = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter, before_open); });

	ASSERT_TRUE(saw_execve);
};
