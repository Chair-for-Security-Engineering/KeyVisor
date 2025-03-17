#include "sess_info_db.h"

std::map<connection_info_t, std::deque<skbndl_entry_t>, ConnectionInfoCompare> session_info_map = {};