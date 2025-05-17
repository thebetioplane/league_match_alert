#pragma once

#include <ostream>

enum class RiotErrorType {
    // 200
    SUCCESS,

    // 401, etc requires config change.
    ABORT,

    // Transient error, like 500 errors, will try again later.
    RETRY,

    // Not a transient error, like a 404, this URL will never resolve but not a fatal error to the application.
    SKIP
};

RiotErrorType get_riot_error_type(const int status);

const char *RiotErrorTypeToString(RiotErrorType riot_error_type);
std::ostream &operator<<(std::ostream &o, RiotErrorType riot_error_type);
