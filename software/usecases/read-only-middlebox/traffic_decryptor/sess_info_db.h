#ifndef _SESSION_INFO_DB_H_
#define _SESSION_INFO_DB_H_

#include <map>
#include <vector>
#include <deque>
#include "edge_defines.h"


// vector for better (deep-)copy and memory management support
// TODO: simplify -- 1 client, 1 server key; add seq. number to each
typedef struct sess_key_entry {
    connection_info_t conn_info;
    std::vector<session_handle_t> sess_handle_vec;
} skbndl_entry_t;

struct ConnectionInfoCompare {
   bool operator() (const connection_info_t& lhs, const connection_info_t& rhs) const
   {
       return lhs.client_port < rhs.client_port || lhs.server_port < rhs.server_port;
   }
};

// TODO: simplify by removing 
// we use deque such that an iteration will always try the newest keys first
extern std::map<connection_info_t, std::deque<skbndl_entry_t>, ConnectionInfoCompare> session_info_map;

#endif /* _SESSION_INFO_DB_H_ */
