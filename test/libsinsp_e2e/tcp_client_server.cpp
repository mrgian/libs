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
#include "utils.h"
#define VISIBILITY_PRIVATE

#include "event_capture.h"
#include "subprocess.h"
#include "sys_call_test.h"
#include "tcp_client_server.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <event.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <algorithm>
#include <cassert>
#include <list>

using namespace std;

#include <libsinsp/sinsp_int.h>

static const string default_payload = "0123456789QWERTYUIOPASDFGHJKLZXCVBNM";
static const string http_payload =
    "GET / "
    "0123456789QWERTYUIOPASDFGHJKLZXCVBNM0123456789QWERTYUIOPASDFGHJKLZXCVBNM0123456789QWERTYUIOPAS"
    "DFGHJKLZXCVBNM0123456789QWERTYUIOPASDFGHJKLZXCVBNM0123456789QWERTYUIOPASDFGHJKLZXCVBNM01234567"
    "89QWERTYUIOPASDFGHJKLZXCVBNO";

void runtest(iotype iot,
             const string& payload = default_payload,
             bool use_shutdown = false,
             bool use_accept4 = false,
             uint32_t ntransactions = 1,
             bool exit_no_close = false,
             bool ia32_mode = false)
{
	proc_started_filter client_started_filter;
	proc_started_filter server_started_filter;
	auto stringify_bool = [](bool v)
	{
		if (v)
			return "true";
		else
			return "false";
	};
	unsigned callnum = 0;
	string helper_exe = "./test_helper";
	if (ia32_mode)
	{
		helper_exe += "_32";
	}
	auto iot_s = to_string(iot);
	auto ntransactions_s = to_string(ntransactions);
	subprocess server_proc(helper_exe,
	                 {"tcp_server",
	                  iot_s.c_str(),
	                  "false",
	                  stringify_bool(use_shutdown),
	                  stringify_bool(use_accept4),
	                  ntransactions_s.c_str(),
	                  stringify_bool(exit_no_close)}, false);
	int64_t server_pid;
	int64_t client_pid;
	struct in_addr server_in_addr;
	server_in_addr.s_addr = get_server_address();
	char* server_address = inet_ntoa(server_in_addr);
	string sport;
	int state = 0;
	int ctid;
	subprocess test_proc(helper_exe,
	               {"tcp_client",
	                server_address,
	                iot_s.c_str(),
	                payload,
	                stringify_bool(false),
	                ntransactions_s,
	                stringify_bool(exit_no_close)}, false);
	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt)
	{
		auto tinfo = evt->get_thread_info(false);
		if (tinfo && tinfo->m_exe == helper_exe)
		{
			if (tinfo->m_pid == server_pid)
			{
				return server_started_filter(evt);
			}
			else if (tinfo->m_pid == client_pid)
			{
				return client_started_filter(evt);
			}
		}
		return false;
	};

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
	{
		{
			std::scoped_lock inspector_handle_lock(inspector_handle);
			inspector_handle->dynamic_snaplen(true);
		}
		server_proc.start();
		server_proc.wait_for_start();
		server_pid = server_proc.get_pid();

		test_proc.start();
		test_proc.wait_for_start();
		client_pid = test_proc.get_pid();

		// We use a random call to tee to signal that we're done
		tee(-1, -1, 0, 0);
	};

	function<void(const callback_param&)> log_param = [](const callback_param& param)
	{
		// cerr << param.m_evt->get_name() << endl;
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		std::string src_addr;
		std::string src_port;
		std::string dst_addr;
		std::string dst_port;

		sinsp_evt* evt = param.m_evt;
		if (evt->get_type() == PPME_SOCKET_CONNECT_X)
		{
			string tuple = evt->get_param_value_str("tuple");

			EXPECT_NE((sinsp_fdinfo*)NULL, evt->m_fdinfo);

			if (evt->m_fdinfo->m_type != SCAP_FD_IPV4_SOCK)
			{
				//
				// Skip non-tcp sockets. Python opens unix sockets
				// to god knows what.
				//
				return;
			}

			parse_tuple(tuple, src_addr, src_port, dst_addr, dst_port);

			//
			// Looks like python 2.x connect to 127.0.0.1:0 before
			// doing the real connection to port SERVER_PORT_STR.
			// If it does it, we skip it.
			//
			//if (dst.count() != 2 || dst[1] == "0")
			//{
			//	return;
			//}

			EXPECT_EQ(server_address, src_addr);
			if (sport == "")
			{
				EXPECT_NE("0", src_port);
				sport = src_port;
			}
			else
			{
				EXPECT_EQ(sport, src_port);
			}

			EXPECT_EQ(server_address, dst_addr);
			if (!exit_no_close)
			{
				EXPECT_EQ(SERVER_PORT_STR, dst_port);
			}
			log_param(param);
			callnum++;
		}
		else if (evt->get_type() == PPME_SOCKET_LISTEN_E)
		{
			EXPECT_EQ("1", evt->get_param_value_str("backlog"));
			log_param(param);
			callnum++;
		}
		else if (evt->get_type() == PPME_SOCKET_LISTEN_X)
		{
			EXPECT_EQ("0", evt->get_param_value_str("res"));
			log_param(param);
			callnum++;
		}
		else if (evt->get_type() == PPME_SOCKET_ACCEPT4_6_E)
		{
			EXPECT_EQ("0", evt->get_param_value_str("flags"));
		}
		else if (evt->get_type() == PPME_SOCKET_ACCEPT_5_X ||
		         evt->get_type() == PPME_SOCKET_ACCEPT4_6_X)
		{
			parse_tuple(evt->get_param_value_str("tuple"), src_addr, src_port, dst_addr, dst_port);

			EXPECT_EQ(server_address, src_addr);
			if (sport == "")
			{
				EXPECT_NE("0", src_port);
				sport = src_port;
			}
			else
			{
				EXPECT_EQ(sport, src_port);
			}

			EXPECT_EQ(server_address, dst_addr);
			if (!exit_no_close)
			{
				EXPECT_EQ(SERVER_PORT_STR, dst_port);
			}

			log_param(param);
			callnum++;
		}

		if (callnum < 1)
		{
			return;
		}

		//
		// 32bit uses send() and recv(), while 64bit always uses sendto() and
		// recvfrom() and sets the address to NULL
		//
		if ((evt->get_type() == PPME_SOCKET_SEND_E || evt->get_type() == PPME_SOCKET_RECV_E ||
		     evt->get_type() == PPME_SOCKET_SENDTO_E || evt->get_type() == PPME_SOCKET_RECVFROM_E ||
		     evt->get_type() == PPME_SYSCALL_READ_E || evt->get_type() == PPME_SYSCALL_WRITE_E ||
		     evt->get_type() == PPME_SYSCALL_READV_E || evt->get_type() == PPME_SYSCALL_WRITEV_E) &&
		    evt->m_fdinfo->m_type == SCAP_FD_IPV4_SOCK)
		{
			if (evt->get_type() == PPME_SOCKET_RECVFROM_E)
			{
				if (evt->get_param_value_str("tuple") != "")
				{
					EXPECT_EQ("NULL", evt->get_param_value_str("tuple"));
				}
			}

			std::string tuple = evt->get_param_value_str("fd");
			tuple = tuple.substr(tuple.find(">")+1);
			parse_tuple(tuple, src_addr, src_port, dst_addr, dst_port);
			EXPECT_EQ(server_address, src_addr);
			EXPECT_EQ(sport, src_port);

			EXPECT_EQ(server_address, dst_addr);
			if (!exit_no_close)
			{
				EXPECT_EQ(SERVER_PORT_STR, dst_port);
			}

			log_param(param);
			callnum++;
		}
		else if ((evt->get_type() == PPME_SOCKET_RECV_X ||
		          evt->get_type() == PPME_SOCKET_RECVFROM_X ||
		          evt->get_type() == PPME_SYSCALL_READ_X ||
		          evt->get_type() == PPME_SYSCALL_READV_X ||
		          evt->get_type() == PPME_SYSCALL_WRITEV_X ||
		          evt->get_type() == PPME_SYSCALL_WRITE_X ||
		          evt->get_type() == PPME_SOCKET_SENDTO_X ||
		          evt->get_type() == PPME_SOCKET_SEND_X) &&
		         evt->m_fdinfo->m_type == SCAP_FD_IPV4_SOCK)
		{
			if (evt->get_type() == PPME_SOCKET_RECVFROM_X)
			{
				//TODO(therealbobo): this fails with modernbpf
				EXPECT_EQ("NULL", evt->get_param_value_str("tuple"));
			}

			EXPECT_EQ(payload, evt->get_param_value_str("data"));

			log_param(param);
			callnum++;
		}

	};

	//
	// OUTPUT VALDATION
	//
	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	ASSERT_GT(callnum,0);
}

TEST_F(sys_call_test, tcp_client_server)
{
	runtest(SENDRECEIVE);
}

TEST_F(sys_call_test, tcp_client_server_read_write)
{
	runtest(READWRITE);
}

TEST_F(sys_call_test, tcp_client_server_readv_writev)
{
	runtest(READVWRITEV);
}

TEST_F(sys_call_test, tcp_client_server_shutdown)
{
	runtest(SENDRECEIVE, default_payload, true);
}

TEST_F(sys_call_test, tcp_client_server_accept4)
{
	runtest(SENDRECEIVE, default_payload, false, true);
}

TEST_F(sys_call_test, tcp_client_server_multiple)
{
	runtest(SENDRECEIVE, default_payload, false, false, 10);
}

TEST_F(sys_call_test, tcp_client_server_noclose)
{
	runtest(SENDRECEIVE, default_payload, false, false, 1, true);
}

TEST_F(sys_call_test, tcp_client_server_http_snaplen)
{
	runtest(SENDRECEIVE, http_payload);
}

TEST_F(sys_call_test, tcp_client_server_read_write_http_snaplen)
{
	runtest(READWRITE, http_payload);
}

TEST_F(sys_call_test, tcp_client_server_readv_writev_http_snaplen)
{
	runtest(READVWRITEV, http_payload);
}

TEST_F(sys_call_test, tcp_client_server_with_connection_before_capturing_starts)
{
	std::thread server_thread;
	std::thread client_thread;
	std::shared_ptr<tcp_server> server = std::make_shared<tcp_server>(SENDRECEIVE, true);
	uint32_t server_ip_address = get_server_address();
	std::shared_ptr<tcp_client> client = std::make_shared<tcp_client>(server_ip_address, SENDRECEIVE, default_payload, true);

	//Poco::RunnableAdapter<tcp_server> server_runnable(server, &tcp_server::run);
	//Poco::RunnableAdapter<tcp_client> client_runnable(client, &tcp_client::run);
	int state = 0;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt)
	{ return evt->get_tid() == server->get_tid() || evt->get_tid() == client->get_tid(); };

	//
	// INITIALIZATION
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
	{
		server->signal_continue();
		client->signal_continue();
		server_thread.join();
		client_thread.join();
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* evt = param.m_evt;
		if (PPME_SYSCALL_CLOSE_X == evt->get_type() && evt->get_tid() == server->get_tid())
		{
			state = 1;
		}
	};

	server_thread = std::thread(&tcp_server::run, server);
	server->wait_till_ready();
	client_thread = std::thread(&tcp_client::run, client);
	client->wait_till_ready();

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	ASSERT_EQ(1, state);
}


#ifdef __x86_64__
TEST_F(sys_call_test32, tcp_client_server)
{
	runtest(SENDRECEIVE, default_payload, false, false, 1, false, true);
}

TEST_F(sys_call_test32, tcp_client_server_read_write)
{
	runtest(READWRITE, default_payload, false, false, 1, false, true);
}

TEST_F(sys_call_test32, tcp_client_server_readv_writev)
{
	runtest(READVWRITEV, default_payload, false, false, 1, false, true);
}

TEST_F(sys_call_test32, tcp_client_server_shutdown)
{
	runtest(SENDRECEIVE, default_payload, true, false, 1, false, true);
}

TEST_F(sys_call_test32, tcp_client_server_accept4)
{
	runtest(SENDRECEIVE, default_payload, false, true, 1, false, true);
}

TEST_F(sys_call_test32, tcp_client_server_multiple)
{
	runtest(SENDRECEIVE, default_payload, false, false, 10, false, true);
}

TEST_F(sys_call_test32, tcp_client_server_noclose)
{
	runtest(SENDRECEIVE, default_payload, false, false, 1, true, true);
}
#endif