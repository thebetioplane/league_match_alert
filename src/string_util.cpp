#include "string_util.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <limits>
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

std::string_view two_char_pad(int n, char *buffer)
{
    buffer[0] = (n / 10 % 10) + '0';
    buffer[1] = (n % 10) + '0';
    return std::string_view(buffer, 2);
}

std::string_view uint32_to_string(uint32_t n, char *buffer)
{
    if (n < 10) {
        buffer[0] = n + '0';
        return std::string_view(buffer, 1);
    }
    int offset = 0;
    for (int i = 9; i >= 0; --i) {
        const int digit = n % 10;
        buffer[i] = digit + '0';
        n /= 10;
        if (digit) {
            offset = i;
        }
    }
    return std::string_view(buffer + offset, 10 - offset);
}

std::string_view int32_to_string(int32_t n, char *buffer)
{
    if (n >= 0) {
        return uint32_to_string(static_cast<uint32_t>(n), buffer);
    } else {
        n = -n;
        std::string_view result = uint32_to_string(static_cast<uint32_t>(n), buffer + 1);
        int offset = result.data() - buffer;
        buffer[offset - 1] = '-';
        return std::string_view(result.data() - 1, result.size() + 1);
    }
}

std::string_view uint64_to_string(uint64_t n, char *buffer)
{
    if (n <= std::numeric_limits<uint32_t>::max()) {
        return uint32_to_string(static_cast<uint32_t>(n), buffer);
    }
    int offset = 0;
    for (int i = 19; i >= 0; --i) {
        const int digit = n % 10;
        buffer[i] = digit + '0';
        n /= 10;
        if (digit) {
            offset = i;
        }
    }
    return std::string_view(buffer + offset, 20 - offset);
}

std::string_view int64_to_string(int64_t n, char *buffer)
{
    if (n >= 0) {
        return uint64_to_string(static_cast<uint64_t>(n), buffer);
    } else {
        n = -n;
        std::string_view result = uint64_to_string(static_cast<uint64_t>(n), buffer + 1);
        int offset = result.data() - buffer;
        buffer[offset - 1] = '-';
        return std::string_view(result.data() - 1, result.size() + 1);
    }
}

std::string_view time_sec_to_string(time_t n, char *buffer)
{
    return uint64_to_string(static_cast<uint64_t>(n), buffer);
}

std::string string_cat(std::initializer_list<std::string_view> pieces)
{
    size_t total_size = 0;
    for (const std::string_view piece : pieces) {
        total_size += piece.size();
    }
    std::string result;
    result.resize(total_size);
    char *append_at = &result[0];
    for (const std::string_view piece : pieces) {
        const size_t len = piece.size();
        std::memcpy(append_at, piece.data(), len);
        append_at += len;
    }
    return result;
}
