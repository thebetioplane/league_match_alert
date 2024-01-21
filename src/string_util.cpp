#include "string_util.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>

void string_to_lower(std::string &s)
{
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
}

std::string_view two_char_pad(int n)
{
    static char buffer[2];
    buffer[0] = (n / 10 % 10) + '0';
    buffer[1] = (n % 10) + '0';
    return std::string_view(buffer, 2);
}
