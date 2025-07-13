#include "logging.hpp"

#include <ctime>
#include <ostream>

#include "string_util.hpp"

std::string timestamp_to_string(const time_t timestamp)
{
    const std::tm *const t = std::localtime(&timestamp);
    uint32ToStringBuffer tm_year_buf;
    TwoCharPadBuffer tm_mon_buf;
    TwoCharPadBuffer tm_mday_buf;
    TwoCharPadBuffer tm_hour_buf;
    TwoCharPadBuffer tm_min_buf;
    TwoCharPadBuffer tm_sec_buf;
    return string_cat({
        "[",
        uint32_to_string(t->tm_year + 1900, tm_year_buf),
        "-",
        two_char_pad(t->tm_mon + 1, tm_mon_buf),
        "-",
        two_char_pad(t->tm_mday, tm_mday_buf),
        "] [",
        two_char_pad(t->tm_hour, tm_hour_buf),
        ":",
        two_char_pad(t->tm_min, tm_min_buf),
        ":",
        two_char_pad(t->tm_sec, tm_sec_buf),
        "]",
    });
}

std::string current_timestamp_string()
{
    time_t timestamp;
    std::time(&timestamp);
    return timestamp_to_string(timestamp);
}