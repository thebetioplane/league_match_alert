#include "logging.hpp"

#include <ctime>
#include <ostream>

#include "string_util.hpp"

std::ostream &log_custom_timestamp_full(std::ostream &o, const time_t timestamp)
{
    const std::tm *const t = std::localtime(&timestamp);
    o << "[" << (t->tm_year + 1900) << "-" << two_char_pad(t->tm_mon + 1) << "-" << two_char_pad(t->tm_mday) << "] ";
    o << "[" << two_char_pad(t->tm_hour) << ':' << two_char_pad(t->tm_min) << ':' << two_char_pad(t->tm_sec) << "]";
    return o;
}

std::ostream &logtimestamp(std::ostream &o)
{
    time_t timestamp;
    std::time(&timestamp);
    log_custom_timestamp_full(o, timestamp);
    o << ' ';
    return o;
}