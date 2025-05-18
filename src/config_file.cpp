#include "config_file.hpp"

#include <fstream>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "config.hpp"
#include "logging.hpp"

namespace
{

enum class FileSection { None, WebhookDefs, PlayerDefs, RuleDefs };

bool stoi_noexcept(const std::string &s, int &n) noexcept
{
    try {
        n = std::stoi(s);
        return true;
    } catch (std::invalid_argument &e) {
        LOG << "\"" << s << "\" was not a valid int" << std::endl;
        return false;
    }
}

std::vector<std::string> pipe_split(const std::string &input)
{
    std::vector<std::string> res;
    size_t start = 0;
    size_t end;
    while ((end = input.find('|', start)) != std::string::npos) {
        res.emplace_back(input.substr(start, end - start));
        start = end + 1;
    }
    res.emplace_back(input.substr(start, input.size() - start));
    return res;
}

}  // namespace

bool load_config(std::vector<ConfigRule> &old_rules, std::pair<std::string, std::string> &error_report_webhook)
{
    std::ifstream f(config_file_name);
    if (!f.good()) {
        return false;
    }
    std::string line;
    FileSection section = FileSection::None;
    std::map<std::string, std::pair<std::string, std::string>> webhook_map;
    std::map<std::string, std::string> player_map;
    std::vector<ConfigRule> rules;
    while (std::getline(f, line)) {
        if (line.size() <= 1)
            continue;
        if (line[0] == '#')
            continue;
        if (line == "Webhook Defs") {
            section = FileSection::WebhookDefs;
        } else if (line == "Player Defs") {
            section = FileSection::PlayerDefs;
        } else if (line == "Rule Defs") {
            section = FileSection::RuleDefs;
        } else {
            switch (section) {
            case FileSection::None:
                LOG << "Unexpected line outside of section" << std::endl;
                std::cout << "Line was \"" << line << "\"" << std::endl;
                return false;
            case FileSection::WebhookDefs: {
                const auto res = pipe_split(line);
                if (res.size() != 3) {
                    LOG << "Item in webhook def section has size " << res.size() << " but should be 3" << std::endl;
                    return false;
                }
                if (res[2][0] != '/') {
                    LOG << "webhook route does not start with /" << std::endl;
                    return false;
                }
                webhook_map.emplace(res[0], std::make_pair(res[1], res[2]));
                break;
            }
            case FileSection::PlayerDefs: {
                const auto res = pipe_split(line);
                if (res.size() != 2) {
                    LOG << "Item in player def section has size " << res.size() << " but should be 2" << std::endl;
                    return false;
                }
                player_map.emplace(res[0], res[1]);
                break;
            }
            case FileSection::RuleDefs: {
                const auto res = pipe_split(line);
                if (res.size() != 5) {
                    LOG << "Item in rule def section has size " << res.size() << " but should be 5" << std::endl;
                    return false;
                }
                auto player_iter = player_map.find(res[0]);
                if (player_iter == player_map.end()) {
                    LOG << "\"" << res[0] << "\" did not name a valid player" << std::endl;
                    return false;
                }
                auto webhook_iter = webhook_map.find(res[4]);
                if (webhook_iter == webhook_map.end()) {
                    LOG << "\"" << res[4] << "\" did not name a valid webhook" << std::endl;
                    return false;
                }
                int min_death = 0;
                if (!stoi_noexcept(res[1], min_death))
                    return false;
                int max_kd_k = 0;
                if (!stoi_noexcept(res[2], max_kd_k))
                    return false;
                int max_kd_d = 0;
                if (!stoi_noexcept(res[3], max_kd_d))
                    return false;
                ConfigRule rule{ player_iter->first, player_iter->second, min_death, max_kd_k, max_kd_d,
                    webhook_iter->second.first, webhook_iter->second.second };
                rules.emplace_back(std::move(rule));
                break;
            }
            }
        }
    }
    {
        auto iter = webhook_map.find("Error Report");
        if (iter != webhook_map.end()) {
            error_report_webhook = iter->second;
        }
    }
    if (rules.size() > rate_limit_1) {
        LOG << "number of players to watch (" << rules.size() << ") exceeds 1 second rate limit (" << rate_limit_1
            << ")";
        return false;
    }
    for (auto rule : rules) {
        if (rule.player_name.empty()) {
            LOG << "player name is empty" << std::endl;
            return false;
        }
        if (rule.puuid.empty()) {
            LOG << "player puuid is empty" << std::endl;
            return false;
        }
        if (rule.webhook_route.empty()) {
            LOG << "webhook route is empty" << std::endl;
            return false;
        }
    }
    old_rules = std::move(rules);
    return true;
}
