#include <list>
#include <cstdint>

class thread_pool
{
public:
	using routine_id_t = uintptr_t;

	struct routine_info
	{
		std::function<bool()> func;
		bool alive = false;
	};

	//
	//
	thread_pool() = default;

	//
	//
	virtual ~thread_pool() = default;

	//
	//
	virtual routine_id_t subscribe(const routine_info& r) = 0;

	//
	//
	virtual void unsubscribe(routine_id_t id) = 0;

	//
	//
	virtual void purge() = 0;

	//
	//
	virtual size_t routines_num() = 0;
};

namespace BS {
	class thread_pool;
};

class bs_thread_pool : public thread_pool
{
public:
	bs_thread_pool(size_t num_workers = 0);

	virtual ~bs_thread_pool()
	{
		purge();
	}

	thread_pool::routine_id_t subscribe(const thread_pool::routine_info& r);

	void unsubscribe(thread_pool::routine_id_t id);

    void purge();

	size_t routines_num();

private:
	struct default_bs_tp_deleter { void operator()(BS::thread_pool* __ptr) const; };

	void run_routine(std::shared_ptr<thread_pool::routine_info> id);

	std::unique_ptr<BS::thread_pool, default_bs_tp_deleter> m_pool;
	std::list<std::shared_ptr<thread_pool::routine_info>> m_routines;
};