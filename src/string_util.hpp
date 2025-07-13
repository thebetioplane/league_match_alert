#pragma once

#include <cstdint>
#include <ctime>
#include <initializer_list>
#include <string>
#include <string_view>

void string_to_lower(std::string &s);

std::string escape_json_string(std::string_view s);

using TwoCharPadBuffer = char[2];
std::string_view two_char_pad(int n, char *buffer);

using uint32ToStringBuffer = char[10];
std::string_view uint32_to_string(uint32_t n, char *buffer);

using int32ToStringBuffer = char[11];
std::string_view int32_to_string(int32_t n, char *buffer);

using uint64ToStringBuffer = char[20];
std::string_view uint64_to_string(uint64_t n, char *buffer);

using int64ToStringBuffer = char[21];
std::string_view int64_to_string(int64_t n, char *buffer);

using timeSecToStringBuffer = uint64ToStringBuffer;
std::string_view time_sec_to_string(time_t n, char *buffer);

std::string string_cat(std::initializer_list<std::string_view> pieces);
