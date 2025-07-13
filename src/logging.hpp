#pragma once

#include <ctime>
#include <iostream>
#include <ostream>

#define LOG (std::cout << current_timestamp_string() << ' ')

std::string timestamp_to_string(const time_t timestamp);

std::string current_timestamp_string();
