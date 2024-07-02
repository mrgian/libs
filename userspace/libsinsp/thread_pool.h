#include <list>
#include <cstdint>
#include <cstddef>
#include <functional>
#include <memory>

class thread_pool
{
public:
	/*struct routine_info
	{
		std::function<bool()> func;
		bool alive = false;
	};*/

	using routine_id_t = std::function<bool()>*;

	//
	//
	thread_pool() = default;

	//
	//
	virtual ~thread_pool() = default;

	//
	//
	//virtual routine_id_t subscribe(const routine_info& r) = 0;
	virtual routine_id_t subscribe(const std::function<bool()>& f) = 0;

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

	thread_pool::routine_id_t subscribe(const std::function<bool()>& f);

	void unsubscribe(thread_pool::routine_id_t id);

    void purge();

	size_t routines_num();

private:
	struct default_bs_tp_deleter { void operator()(BS::thread_pool* __ptr) const; };

	void run_routine(std::shared_ptr<std::function<bool()>> id);

	std::unique_ptr<BS::thread_pool, default_bs_tp_deleter> m_pool;
	std::list<std::shared_ptr<std::function<bool()>>> m_routines;
};