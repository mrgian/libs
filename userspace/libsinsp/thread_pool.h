#include "BS_thread_pool.hpp"
#include <iostream>
#include <unistd.h>
#include <chrono>
#include <utility>

#include <plugin/plugin_api.h>

#define THREAD_POOL_SIZE 0
#define THREAD_POOL_TIMEOUT 1500

class routine
{
public:
	routine(ss_plugin_routine_fn_t func, ss_plugin_t* plugin_state, ss_plugin_routine_state_t* routine_state) 
	{
        run = [func, plugin_state, routine_state]() -> bool { 
			return func(plugin_state, routine_state);
		};
    }

	routine(std::function<bool()> func) 
	{
		run = func;
    }

    std::function<bool()> run;

	int set_id(int i)
	{
		if(i >= 0)
		{
			id = i;
		}

		return id;
	}

	int get_id()
	{
		return id;
	}	

	void enable()
	{
		enabled = true;
	}

	void disable()
	{
		enabled = false;
	}

	bool is_enabled()
	{
		return enabled;
	}

private:
	int id = -1;
	bool enabled = false;
};

class thread_pool
{
public:
	//
	//
	thread_pool() = default;

	//
	//
	virtual ~thread_pool() = default;

	//
	//
	virtual int subscribe(routine r) = 0;

	//
	//
	virtual void unsubscribe(int id) = 0;

	//
	//
	virtual void purge() = 0;

	//
	//
	virtual int routines_num() = 0;
};

class bs_thread_pool : public thread_pool
{
public:
	bs_thread_pool() = default;
	~bs_thread_pool()
	{
		purge();
	}

	int subscribe(routine r);

	void unsubscribe(int id);

    void purge();

	int routines_num();

private:
	bool is_subscribed(int id);

	void run_routine(int id);

	std::unique_ptr<BS::thread_pool> pool;
	std::vector<routine> routines;
};