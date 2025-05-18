#pragma once

#include <ostream>
#include <source_location>
#include <string>

class Status
{
public:
    explicit Status(std::string msg_, std::source_location source_location_ = std::source_location::current())
        : msg(msg_),
          source_location(source_location_)
    {
    }
    static Status Ok() { return Status(); }
    bool ok() const { return msg.empty(); }

    const std::string msg;
    const std::source_location source_location;

private:
    Status() : msg() {}
};

std::ostream &operator<<(std::ostream &o, const Status &status);