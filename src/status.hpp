#pragma once

#include <ostream>
#include <string>

class Status
{
public:
    explicit Status(std::string msg_) : msg(msg_) {}
    static Status Ok() { return Status(); }
    const std::string msg;
    bool ok() const { return msg.empty(); }

private:
    Status() : msg() {}
};

std::ostream &operator<<(std::ostream &o, const Status &status);