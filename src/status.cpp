#include "status.hpp"

#include <ostream>

std::ostream &operator<<(std::ostream &o, const Status &status)
{
    if (status.ok()) {
        o << "Ok";
    } else {
        o << status.msg;
    }
    return o;
}
