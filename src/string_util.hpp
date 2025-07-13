#pragma once

#include <string>
#include <string_view>

void string_to_lower(std::string &s);
std::string escape_json_string(std::string_view s);
std::string_view two_char_pad(int n);
