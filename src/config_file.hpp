#pragma once

#include <string>
#include <utility>
#include <vector>

class ConfigRule
{
public:
    std::string player_name;
    std::string puuid;
    int min_death;
    int max_kd_k;
    int max_kd_d;
    std::string webhook_username;
    std::string webhook_route;
};

bool load_config(std::vector<ConfigRule> &old_rules, std::pair<std::string, std::string> &error_report_webhook);
