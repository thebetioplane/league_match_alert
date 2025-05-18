#pragma once

#include <iostream>
#include <ctime>
#include <ostream>

#define LOG logtimestamp(std::cout)

std::ostream &log_custom_timestamp_full(std::ostream &o, const time_t timestamp);

std::ostream &logtimestamp(std::ostream &o);