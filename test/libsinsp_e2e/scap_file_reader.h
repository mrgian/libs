#pragma once

#include <libsinsp/sinsp.h>

#include <functional>
#include <memory>
#include <string>

class scap_file_reader
{
public:
	virtual ~scap_file_reader() { m_inspector = nullptr; }

	virtual std::shared_ptr<sinsp> setup_read_file()
	{
		if (!m_inspector)
		{
			m_inspector = std::make_shared<sinsp>();
			m_inspector->set_hostname_and_port_resolution_mode(true);
		}
		return m_inspector;
	}

	virtual void run_inspector(const char* filename,
	                           const std::string filter,
	                           std::function<void(sinsp_evt*)> evtcb)
	{
		m_inspector->open_savefile(filename);
		m_inspector->set_filter(filter.c_str());

		while (true)
		{
			int32_t res;
			sinsp_evt* evt;

			res = m_inspector->next(&evt);

			if (res == SCAP_TIMEOUT)
			{
				continue;
			}
			else if (res == SCAP_FILTERED_EVENT)
			{
				continue;
			}
			else if (res == SCAP_EOF)
			{
				break;
			}
			else if (res != SCAP_SUCCESS)
			{
				break;
			}

			evtcb(evt);
		}

		m_inspector->close();
	}

	virtual void read_file_filtered(const char* filename,
	                                const std::string filter,
	                                std::function<void(sinsp_evt*)> evtcb)
	{
		setup_read_file();
		run_inspector(filename, filter, evtcb);
	}

private:
	std::shared_ptr<sinsp> m_inspector;
};