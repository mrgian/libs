#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <iostream>
#include <unistd.h>

#include "../userspace/plugin/plugin_api.h"


static constexpr uint16_t PPME_SYSCALL_OPEN_E = 2;
static constexpr uint16_t PPME_SYSCALL_OPEN_X = 3;

struct plugin_state
{
    std::string lasterr;
    ss_plugin_table_t* thread_table;
    ss_plugin_table_t* subtable;



    //ss_plugin_table_field_t* table_field_comm;
    ss_plugin_table_field_t* table_field_fdtable;
    ss_plugin_table_field_t* table_field_fdtable_name;



    ss_plugin_table_reader_vtable_ext* table_reader;

    ss_plugin_state_data data;

    ss_plugin_owner_t* owner;
    ss_plugin_log_fn_t log;
    bool once = false;
    uint64_t count = 1000;
    const ss_plugin_event_parse_input* in;
};

inline bool evt_type_is_open(uint16_t type)
{
    return type == PPME_SYSCALL_OPEN_E
        || type == PPME_SYSCALL_OPEN_X
    ;
}

extern "C" {

const char* plugin_get_required_api_version()
{
    return PLUGIN_API_VERSION_STR;
}

const char* plugin_get_version()
{
    return "0.1.0";
}

const char* plugin_get_name()
{
    return "dummy";
}

const char* plugin_get_description()
{
    return "some desc";
}

const char* plugin_get_contact()
{
    return "some contact";
}

const char* plugin_get_parse_event_sources()
{
    return "[\"syscall\"]";
}

uint16_t* plugin_get_parse_event_types(uint32_t* num_types, ss_plugin_t* s)
{
    static uint16_t types[] = {
        PPME_SYSCALL_OPEN_E,
        PPME_SYSCALL_OPEN_X,
    };
    *num_types = sizeof(types) / sizeof(uint16_t);
    return &types[0];
}

ss_plugin_t* plugin_init(const ss_plugin_init_input* in, ss_plugin_rc* rc)
{
    *rc = SS_PLUGIN_SUCCESS;
    plugin_state *ret = new plugin_state();

    //save logger and owner in the state
    ret->log = in->log_fn;
    ret->owner = in->owner;

    ret->log(ret->owner, NULL, "initializing plugin...", SS_PLUGIN_LOG_SEV_INFO);

    // get accessor for thread table
    ret->thread_table = in->tables->get_table(in->owner, "threads", ss_plugin_state_type::SS_PLUGIN_ST_INT64);
    if (!ret->thread_table)
    {
        printf("null ret->thread_table\n");
        *rc = SS_PLUGIN_FAILURE;
        return NULL;
    }

    // todo key type will be here
    // todo dynamic fields of subtables
    ret->table_field_fdtable = in->tables->fields_ext->get_table_field(ret->thread_table, "fdtable", ss_plugin_state_type::SS_PLUGIN_ST_RAWPTR);
    if (!ret->table_field_fdtable)
    {
        printf("null ret->table_field_fdtable\n");
        *rc = SS_PLUGIN_FAILURE;
        return NULL;
    }

    ret->subtable = in->tables->fields_ext->get_subtable(ret->thread_table, ret->table_field_fdtable);
    if (!ret->subtable)
    {
        printf("null ret->subtable\n");
        *rc = SS_PLUGIN_FAILURE;
        return NULL;
    }

    std::printf("Thread table addr: %p\n", ret->thread_table);
    std::printf("Sub table addr: %p\n", ret->subtable);

    ret->table_field_fdtable_name = in->tables->fields_ext->get_table_field(ret->subtable, "name", ss_plugin_state_type::SS_PLUGIN_ST_STRING);
    if (!ret->table_field_fdtable_name)
    {
        printf("null ret->table_field_fdtable_name\n");
        *rc = SS_PLUGIN_FAILURE;
        return NULL;
    }

    if (!ret->thread_table)
    {
        *rc = SS_PLUGIN_FAILURE;
        auto err = in->get_owner_last_error(in->owner);
        ret->lasterr = err ? err : "can't access thread table";
        return ret;
    }

    return ret;
}

void plugin_destroy(ss_plugin_t* s)
{
    plugin_state *ps = (plugin_state *) s;
    ps->log(ps->owner, NULL, "destroying plugin...", SS_PLUGIN_LOG_SEV_INFO);

    delete ((plugin_state *) s);
}

const char* plugin_get_last_error(ss_plugin_t* s)
{
    return ((plugin_state *) s)->lasterr.c_str();
}

ss_plugin_bool entry_iterator(ss_plugin_table_iterator_state_t* s, ss_plugin_table_entry_t* e)
{
    plugin_state *ps = (plugin_state *) s;
    auto* in = ps->in;

    if(ps->count == 0)
    {
        return false;
    }

    auto res = in->table_reader_ext->read_entry_field(ps->thread_table, e, ps->table_field_fdtable, &ps->data);
    if (res != SS_PLUGIN_SUCCESS)
    {
        printf("err in->table_reader_ext->read_entry_field\n");
        return SS_PLUGIN_FAILURE;
    }

    std::printf("FD table addr for %p :\n", ps->data.rawptr);

    ss_plugin_state_data key;
    key.s64 = 1;

    auto fdinfo = in->table_reader_ext->get_table_entry(ps->data.rawptr, &key);
    if (fdinfo == NULL)
    {
        // printf("err in->table_reader_ext->get_table_entry: %s\n", in->get_owner_last_error(in->owner));
        return SS_PLUGIN_FAILURE;
    }

    res = in->table_reader_ext->read_entry_field(ps->data.rawptr, fdinfo, ps->table_field_fdtable_name, &ps->data);
    if (res != SS_PLUGIN_SUCCESS)
    {
        printf("err in->table_reader_ext->read_entry_field (2): %s\n", in->get_owner_last_error(in->owner));
        return SS_PLUGIN_FAILURE;
    }

    std::printf("name: %s\n", ps->data.str);

    ps->count--;
    return true;
}

ss_plugin_rc plugin_parse_event(ss_plugin_t *s, const ss_plugin_event_input *ev, const ss_plugin_event_parse_input* in)
{
    plugin_state *ps = (plugin_state *) s;

    if(ps->once)
    {
        return SS_PLUGIN_SUCCESS;
    }

    ps->in = in;
    in->table_reader_ext->iterate_entries(ps->thread_table, &entry_iterator, ps);

    ps->once = true;
    return SS_PLUGIN_SUCCESS;
}

}