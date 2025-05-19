#include "riot_error_types.hpp"

#include <ostream>

const char *RiotErrorTypeToString(RiotErrorType riot_error_type)
{
    switch (riot_error_type) {
    case RiotErrorType::SUCCESS:
        return "SUCCESS";
    case RiotErrorType::ABORT:
        return "ABORT";
    case RiotErrorType::RETRY:
        return "RETRY";
    case RiotErrorType::SKIP:
        return "SKIP";
    }
    return "(unknown)";
}

std::ostream &operator<<(std::ostream &o, const RiotErrorType riot_error_type)
{
    o << RiotErrorTypeToString(riot_error_type);
    return o;
}

RiotErrorType get_riot_error_type(const int status)
{
    const int error_family = status / 100;
    switch (error_family) {
    case 2:
        return RiotErrorType::SUCCESS;
    case 4: {
        switch (status) {
        case 401:
            return RiotErrorType::ABORT;
        case 429:
            return RiotErrorType::RETRY;
        default:
            // Riot may return 4XX errors for matches even if they are returned from the API.
            // https://github.com/RiotGames/developer-relations/issues/1075
            return RiotErrorType::SKIP;
        }
    }
    default:
        return RiotErrorType::RETRY;
    }
}
