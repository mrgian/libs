#include <libsinsp/thread_pool.h>

int bs_thread_pool::subscribe(routine r)
{
	if(!pool)
	{
#if THREAD_POOL_SIZE == 0
		pool = std::make_unique<BS::thread_pool>();
#else
		pool = std::make_unique<BS::thread_pool>(THREAD_POOL_SIZE);
#endif
	}

	r.enable();
	int id = r.set_id(routines.size());

	routines.push_back(r);
	run_routine(id);

	return id;
}

void bs_thread_pool::unsubscribe(int id)
{
	if(is_subscribed(id) && id >= 0)
	{
		routines.at(id).disable();
	}
}

void bs_thread_pool::purge()
{
	for(auto& r : routines)
	{
		r.disable();
	}

	if(pool)
	{
		pool->purge();
		pool->wait();
	}	
}

int bs_thread_pool::routines_num()
{
	int num = 0;

	for(auto& r : routines)
	{
		if(r.is_enabled())
		{
			num++;
		}
	}

	return num;
}

bool bs_thread_pool::is_subscribed(int id)
{
	if(id < 0)
	{
		return false;
	}

	return routines.at(id).is_enabled();
}

void bs_thread_pool::run_routine(int id)
{
	if(id < 0)
	{
		return;
	}

	pool->detach_task([this, id]{
		bool ret = routines.at(id).run();

		if(!ret)
		{
			unsubscribe(id);
			return;
		}

		if(is_subscribed(id))
		{
			pool->detach_task([this, id]{
				run_routine(id);
			});
		}
	});		
}