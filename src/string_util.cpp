#include "string_util.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>

// To make building escape sequencs easier to read and avoid typo.
#define BACKSLASH "\\"

void string_to_lower(std::string &s)
{
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
}

std::string escape_json_string(const std::string_view s)
{
    std::string result;
    for (const char c : s) {
        // Per JSON standard the only characters that need escaping are the 32 control characters, double quote and
        // backslash. And \b, \f, \n, \r, \t', '\uXXXX' are the only documented escape sequences.
        switch (c) {
        case '"':
            result += BACKSLASH "\"";
            break;
        case '\\':
            result += BACKSLASH BACKSLASH;
            break;
        case '\b':
            result += BACKSLASH "b";
            break;
        case '\f':
            result += BACKSLASH "f";
            break;
        case '\n':
            result += BACKSLASH "n";
            break;
        case '\r':
            result += BACKSLASH "r";
            break;
        case '\t':
            result += BACKSLASH "t";
            break;
        default:
            if (c >= 0 && c <= 31) {
                constexpr const char *hex_alphabet = "0123456789abcdef";
                result += BACKSLASH "u00";
                result += hex_alphabet[(c >> 4) & 0xF];
                result += hex_alphabet[c & 0xF];
            } else {
                result += c;
            }
        }
    }
    return result;
}

std::string_view two_char_pad(int n)
{
    static char buffer[2];
    buffer[0] = (n / 10 % 10) + '0';
    buffer[1] = (n % 10) + '0';
    return std::string_view(buffer, 2);
}
