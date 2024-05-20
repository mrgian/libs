#
# bshoshany/thread-pool (https://github.com/bshoshany/thread-pool)
#

if(BS_THREADPOOL_INCLUDE)
	# we already have bs_thread_pool
else()
	set(BS_THREADPOOL_SRC "${PROJECT_BINARY_DIR}/bs_threadpool-prefix/src/bs_threadpool")
	set(BS_THREADPOOL_INCLUDE "${BS_THREADPOOL_SRC}/include")

	message(STATUS "Using bundled bs_threadpool in '${BS_THREADPOOL_SRC}'")

	ExternalProject_Add(bs_threadpool
		PREFIX "${PROJECT_BINARY_DIR}/bs_threadpool-prefix"
		URL "https://github.com/bshoshany/thread-pool/archive/refs/tags/v4.1.0.tar.gz"
		URL_HASH "SHA256=be7abecbc420bb87919eeef729b13ff7c29d5ce547bdae284923296c695415bd"
		CONFIGURE_COMMAND ""
		BUILD_COMMAND ""
		INSTALL_COMMAND "")	
endif()

if(NOT TARGET bs_threadpool)
	add_custom_target(bs_threadpool)
endif()

include_directories("${BS_THREADPOOL_INCLUDE}")