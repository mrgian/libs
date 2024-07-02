#include <libsinsp/thread_pool.h>

#include <BS_thread_pool.hpp>

void bs_thread_pool::default_bs_tp_deleter::operator()(BS::thread_pool* __ptr) const
{
	std::default_delete<BS::thread_pool>{}(__ptr);
}

void bs_thread_pool::bs_thread_pool(size_t num_workers): m_pool(nullptr), m_routines()
{
	if (num_workers == 0)
	{
		pool = std::make_unique<BS::thread_pool>();
	}
	else
	{
		pool = std::make_unique<BS::thread_pool>(num_workers);
	}
}

bs_thread_pool::routine_id_t bs_thread_pool::subscribe(const bs_thread_pool::rountine_info& r)
{
	routines.push_back(std::make_shared<thread_pool::routine_info>(r));
	auto& new_routine = routines.back();
	run_routine(new_routine);
	return static_cast<bs_thread_pool::routine_id_t>(new_routine.get());
}

void bs_thread_pool::unsubscribe(bs_thread_pool::routine_id_t id)
{
	routines.remove_if([id](const shared_ptr<thread_pool::routine_info>& v)
		{
			return v.get() == static_cast<thread_pool::routine_info*>(id);
		});
}

void bs_thread_pool::purge()
{
	routines.clear();
	pool->purge();
	pool->wait();
}

size_t bs_thread_pool::routines_num()
{
	return routines.size();
}

void bs_thread_pool::run_routine(std::shared_ptr<thread_pool::routine_info> routine)
{
	pool->detach_task([this, routine]
		{
			if (routine.use_count() <= 1 || !(routine->func && routine->func()))
			{
				return;
			}

			run_routine(routine);
		});
}