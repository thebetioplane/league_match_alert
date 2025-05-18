#include <Poco/JSON/Parser.h>
#include <Poco/JSON/Stringifier.h>
#include <Poco/Net/HTTPMessage.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/HTTPSClientSession.h>
#include <Poco/Net/NetException.h>
#include <Poco/Net/Socket.h>
#include <Poco/Timespan.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "config.hpp"
#include "config_file.hpp"
#include "logging.hpp"
#include "queue_name_map.hpp"
#include "riot_error_types.hpp"
#include "status.hpp"
#include "string_util.hpp"

#define UNUSED __attribute__((unused))
#define BOOL_LITERAL(b) ((b) ? "true" : "false")

namespace
{

std::pair<std::string, std::string> error_report_webhook;
std::atomic<bool> needs_config_reload(true);

class GameInfo
{
public:
    bool silently_skip;
    int queue_id;
    std::string champion_name;
    int kills;
    int deaths;
#ifdef SHOW_ASSISTS
    int assists;
#endif
    int duration;
    time_t time_end;
    std::string win_result;
    std::string role;
    std::string position;
};

std::ostream &operator<<(std::ostream &o, const GameInfo &game_info)
{
    o << "  silently_skip = " << BOOL_LITERAL(game_info.silently_skip) << '\n';
    o << "  queue_id = " << game_info.queue_id << '\n';
    o << "  champion_name = " << game_info.champion_name << '\n';
    o << "  kills = " << game_info.kills << '\n';
    o << "  deaths = " << game_info.deaths << '\n';
#ifdef SHOW_ASSISTS
    o << "  assists = " << game_info.assists << '\n';
#endif
    o << "  duration = " << game_info.duration << '\n';
    o << "  time_end = " << game_info.time_end << '\n';
    o << "  win_result = " << game_info.win_result << '\n';
    o << "  role = " << game_info.role << '\n';
    o << "  position = " << game_info.position;
    return o;
}

Status get_game_info(const std::string &riot_token, const std::string &puuid, const std::string &game_id,
    GameInfo &game_info);
Status get_games_between(const std::string &riot_token, const std::string &puuid, const time_t start_time,
    const time_t end_time, const int rule_id, std::vector<std::pair<int, std::string>> &results);
Status process_rules(const std::string &riot_token, const std::vector<ConfigRule> &rules, const time_t last_update,
    const time_t now);
bool does_rule_match(const GameInfo &game_info, const ConfigRule &rule);
int compare_ratio(int n0, int d0, int n1, int d1);
bool run(const int sleep_interval);
std::string get_queue_name(int queue_id);
std::string read_first_line(const char *fname);
void dispatch_webhook(const GameInfo &game_info, const ConfigRule &rule);
void format_pair(const std::pair<std::string, std::string> &p, std::ostringstream &json_ss);
void log_error_generic(const Status &status);
void log_http_error(const std::string &method, const std::string &route, int status, RiotErrorType riot_error_type);
void my_sa_handler(int sig);
void print_usage(const char *const argv0);
void send_to_webhook(const std::string &webhook_route, const std::string &username, const std::string &msg,
    const std::initializer_list<std::pair<std::string, std::string>> embeds, bool log_if_error);
void sleep_ms(int ms);

// Once a rate limit is exhausted it sleeps for that amount
class RateCounter
{
public:
    RateCounter(int l_max_amt, int l_sleep_amt) : max_amt(l_max_amt), sleep_amt(l_sleep_amt), current_value(l_max_amt)
    {
    }
    void operator--()
    {
        --current_value;
        if (current_value <= 0) {
            current_value = max_amt;
            sleep_ms(sleep_amt);
        }
    }

private:
    const int max_amt;
    const int sleep_amt;
    int current_value;
};

std::string read_first_line(const char *fname)
{
    std::ifstream f(fname);
    std::string result;
    if (f.good()) {
        std::getline(f, result);
    }
    return result;
}

// This is a wrapper to nanosleep
// It is written this way so the sleep resumes where it left off after a signal
void sleep_ms(int ms)
{
#ifdef LOG_SLEEPS
    LOG << "Sleeping for " << ms << " ms" << std::endl;
#endif
    struct timespec req;
    req.tv_sec = ms / 1000;
    req.tv_nsec = (ms % 1000) * 1000000L;
    struct timespec rem;
    for (;;) {
        const int res = nanosleep(&req, &rem);
        if (res < 0 && errno == EINTR) {
            std::memcpy(&req, &rem, sizeof(req));
        } else {
            return;
        }
    }
}

void log_http_error(const std::string &method, const std::string &route, const int status,
    const RiotErrorType riot_error_type)
{
    LOG << status << "|" << riot_error_type << "|" << method << "|" << route << std::endl;
    if (!error_report_webhook.second.empty()) {
        std::ostringstream ss;
        logtimestamp(ss) << "Got HTTP error";
        send_to_webhook(error_report_webhook.second, error_report_webhook.first, ss.str(),
            {
                { "Status", std::to_string(status) },
                { "Action", RiotErrorTypeToString(riot_error_type) },
                { "Method", method },
                { "Route", route },
            },
            false);
        if (riot_error_type == RiotErrorType::ABORT) {
            std::ostringstream ss2;
            logtimestamp(ss2) << "Permanent abortable error " << status;
            send_to_webhook(error_report_webhook.second, error_report_webhook.first, ss2.str(), {}, false);
        }
    }
    if (riot_error_type == RiotErrorType::ABORT) {
        LOG << "Exiting due to " << status << std::endl;
        std::exit(1);
    }
}

void log_error_generic(const Status &status)
{
    LOG << status << std::endl;
    if (!error_report_webhook.second.empty()) {
        std::ostringstream ss;
        logtimestamp(ss) << status.msg;
        send_to_webhook(error_report_webhook.second, error_report_webhook.first, ss.str(), {}, false);
    }
}

void format_pair(const std::pair<std::string, std::string> &p, std::ostringstream &json_ss)
{
    json_ss << "{\"name\":";
    Poco::JSON::Stringifier::formatString(p.first, json_ss);
    json_ss << ",\"value\":";
    Poco::JSON::Stringifier::formatString(p.second, json_ss);
    json_ss << ",\"inline\":true}";
}

void send_to_webhook(const std::string &webhook_route, const std::string &username, const std::string &msg,
    const std::initializer_list<std::pair<std::string, std::string>> embeds, bool log_if_error)
{
    constexpr int default_sleep_amt = 1000;
    try {
        using Poco::Net::HTTPMessage;
        using Poco::Net::HTTPRequest;
        using Poco::Net::HTTPResponse;
        using Poco::Net::HTTPSClientSession;

        HTTPSClientSession cs("discord.com", 443);
        HTTPRequest request(HTTPRequest::HTTP_POST, webhook_route, HTTPMessage::HTTP_1_1);
        request.set("Content-Type", "application/json");
        std::ostringstream json_ss;
        json_ss << "{\"content\":";
        Poco::JSON::Stringifier::formatString(msg, json_ss);
        json_ss << ",\"username\":";
        Poco::JSON::Stringifier::formatString(username, json_ss);
        json_ss << ",";
        if (!std::empty(embeds)) {
            json_ss << "\"embeds\":[{\"fields\":[";
            const auto *embed_iter = embeds.begin();
            format_pair(*embed_iter, json_ss);
            ++embed_iter;
            for (; embed_iter != embeds.end(); ++embed_iter) {
                json_ss << ',';
                format_pair(*embed_iter, json_ss);
            }
            json_ss << "]}],";
        }
        json_ss << "\"allowed_mentions\":{\"parse\":[]}}";
        const std::string &json = json_ss.str();
        request.setContentLength(json.size());
        cs.sendRequest(request) << json;
        HTTPResponse response;
        cs.receiveResponse(response);
        const int status = response.getStatus();
        const RiotErrorType riot_error_type = get_riot_error_type(status);
        if (riot_error_type != RiotErrorType::SUCCESS) {
            LOG << "I tried to POST to webhook and got response " << status << std::endl;
            // trace(json);
            if (log_if_error) {
                log_http_error("POST", "webhook", status, riot_error_type);
            }
        }
        const int remaining = std::stoi(response.get("x-ratelimit-remaining"));
        if (remaining == 0) {
            double after = std::stod(response.get("x-ratelimit-reset-after"));
            after = std::ceil(after * 1000);
            sleep_ms(static_cast<int>(after));
        }
        return;
    } catch (std::invalid_argument &e) {
        LOG << "std::invalid_argument while sending message: " << e.what() << std::endl;
    } catch (Poco::Exception &e) {
        LOG << "Poco::Exception while sending message: " << e.displayText() << std::endl;
    }
    sleep_ms(default_sleep_amt);
}

std::string get_queue_name(int queue_id)
{
    auto iter = queue_name_map.find(queue_id);
    if (iter == queue_name_map.end())
        return "League of Legends";
    return iter->second;
}

int compare_ratio(int n0, int d0, int n1, int d1)
{
    return n0 * d1 - d0 * n1;
}

bool does_rule_match(const GameInfo &game_info, const ConfigRule &rule)
{
    if (game_info.silently_skip) {
        LOG << "Silently skipping game\n" << game_info << std::endl;
        return false;
    }
    if (game_info.deaths < rule.min_death) {
        return false;
    }
    if (compare_ratio(game_info.kills, game_info.deaths, rule.max_kd_k, rule.max_kd_d) > 0) {
        return false;
    }
    return true;
}

void dispatch_webhook(const GameInfo &game_info, const ConfigRule &rule)
{
    std::ostringstream ss;
    ss << rule.player_name;
    ss << " went **" << game_info.kills << "/" << game_info.deaths << "**";
#ifdef SHOW_ASSISTS
    ss << "/" << game_info.assists;
#endif
    ss << " on ";
    if (!game_info.role.empty() && game_info.role != "none") {
        ss << game_info.role << " ";
    }
    if (!game_info.position.empty() && game_info.position != "none") {
        ss << game_info.position << " ";
    }
    ss << "**" << game_info.champion_name;
    ss << "** while playing " << get_queue_name(game_info.queue_id);
    std::ostringstream played_on_ss;
    played_on_ss << "<t:" << game_info.time_end << ">";
    std::ostringstream duration_ss;
    duration_ss << (game_info.duration / 60) << ":" << two_char_pad(game_info.duration % 60);
    send_to_webhook(rule.webhook_route, rule.webhook_username, ss.str(),
        { { "Played on", played_on_ss.str() }, { "Duration", duration_ss.str() }, { "Result", game_info.win_result } },
        true);
}

Status get_game_info(const std::string &riot_token, const std::string &puuid, const std::string &game_id,
    GameInfo &game_info)
{
    game_info.silently_skip = false;
    try {
        using Poco::Net::HTTPMessage;
        using Poco::Net::HTTPRequest;
        using Poco::Net::HTTPResponse;
        using Poco::Net::HTTPSClientSession;
        using namespace Poco::JSON;

        std::ostringstream route;
        route << "/lol/match/v5/matches/" << game_id;

        HTTPSClientSession cs(riot_endpoint, 443);
        HTTPRequest request(HTTPRequest::HTTP_GET, route.str(), HTTPMessage::HTTP_1_1);
        request.setContentLength(0);
        request.set("X-Riot-Token", riot_token);
        cs.sendRequest(request);
        HTTPResponse response;
        auto &stream = cs.receiveResponse(response);
        const int status = response.getStatus();
        const RiotErrorType riot_error_type = get_riot_error_type(status);
        if (riot_error_type != RiotErrorType::SUCCESS) {
            LOG << "I tried to GET match info by gameid and got response " << status << std::endl;
            log_http_error("GET", route.str(), status, riot_error_type);
            if (riot_error_type == RiotErrorType::RETRY) {
                return Status("HTTP error when getting match info by game id");
            }
            LOG << "Skipped bad match\n  puuid = " << puuid << "\n  game_id = " << game_id << std::endl;
            game_info = GameInfo{};
            game_info.silently_skip = true;
            return Status::Ok();
        }
        Parser parser;
        Poco::Dynamic::Var result = parser.parse(stream);
        Object::Ptr obj = result.extract<Object::Ptr>();
        auto info_obj = obj->getObject("info");
        game_info.queue_id = info_obj->getValue<int>("queueId");
        game_info.duration = info_obj->getValue<time_t>("gameDuration");
        const time_t game_start = info_obj->getValue<time_t>("gameCreation") / 1000;
        if (game_start == 0) {
            // See https://github.com/RiotGames/developer-relations/issues/642
            // This is a corrupted match, so it should be skipped
            game_info.silently_skip = true;
            LOG << "Skipped corrupted match\n  puuid = " << puuid << "\n  game_id = " << game_id << std::endl;
            return Status::Ok();
        }
        game_info.time_end = game_start + game_info.duration;
        int num_winning_teams = 0;
        int winning_team = 0;
        Array::Ptr teams = info_obj->getArray("teams");
        for (auto iter = teams->begin(); iter != teams->end(); ++iter) {
            Object::Ptr p = iter->extract<Object::Ptr>();
            if (p->getValue<bool>("win")) {
                winning_team = p->getValue<int>("teamId");
                ++num_winning_teams;
            }
        }
        Array::Ptr players = info_obj->getArray("participants");
        for (auto iter = players->begin(); iter != players->end(); ++iter) {
            Object::Ptr p = iter->extract<Object::Ptr>();
            if (p->getValue<std::string>("puuid") == puuid) {
                game_info.champion_name = p->getValue<std::string>("championName");
                game_info.kills = p->getValue<int>("kills");
                game_info.deaths = p->getValue<int>("deaths");
#ifdef SHOW_ASSISTS
                game_info.assists = p->getValue<int>("assists");
#endif
                const int team_id = p->getValue<int>("teamId");
                const bool early_surrender = p->getValue<bool>("gameEndedInEarlySurrender");
                const bool surrender = early_surrender || p->getValue<bool>("gameEndedInSurrender");
                if (num_winning_teams == 1) {
                    game_info.win_result = (winning_team == team_id) ? "WIN" : "LOSS";
                    if (surrender) {
                        if (early_surrender) {
                            game_info.win_result += " (By early surrender)";
                        } else {
                            game_info.win_result += " (By surrender)";
                        }
                    }
                } else {
                    game_info.win_result = "-";
                }
                game_info.role = p->getValue<std::string>("role");
                string_to_lower(game_info.role);
                game_info.position = p->getValue<std::string>(POSITION);
                string_to_lower(game_info.position);
                return Status::Ok();
            }
        }
        LOG << "Player not in array." << std::endl;
        LOG << "  puuid = " << puuid << std::endl;
        LOG << "  game_id = " << game_id << std::endl;
        return Status("Target player was not in the array");
    } catch (Poco::Exception &e) {
        return Status(std::string("[Poco::Exception] ") + e.displayText());
    }
    return Status("Failed to process rules");
}

Status get_games_between(const std::string &riot_token, const std::string &puuid, const time_t start_time,
    const time_t end_time, const int rule_id, std::vector<std::pair<int, std::string>> &results)
{
    try {
        using Poco::Net::HTTPMessage;
        using Poco::Net::HTTPRequest;
        using Poco::Net::HTTPResponse;
        using Poco::Net::HTTPSClientSession;
        using namespace Poco::JSON;

        std::ostringstream route;
        route << "/lol/match/v5/matches/by-puuid/";
        route << puuid;
        route << "/ids?startTime=";
        route << start_time;
        route << "&endTime=";
        route << end_time;
        route << "&count=100";

        HTTPSClientSession cs(riot_endpoint, 443);
        HTTPRequest request(HTTPRequest::HTTP_GET, route.str(), HTTPMessage::HTTP_1_1);
        request.setContentLength(0);
        request.set("X-Riot-Token", riot_token);
        cs.sendRequest(request);
        HTTPResponse response;
        auto &stream = cs.receiveResponse(response);
        const int status = response.getStatus();
        const RiotErrorType riot_error_type = get_riot_error_type(status);
        if (riot_error_type != RiotErrorType::SUCCESS) {
            LOG << "I tried to GET matches by puuid and got response " << status << std::endl;
            log_http_error("GET", route.str(), status, riot_error_type);
            if (riot_error_type == RiotErrorType::RETRY) {
                return Status("HTTP error when getting matches by puuid");
            }
        }
        Parser parser;
        Poco::Dynamic::Var result = parser.parse(stream);
        Array::Ptr arr = result.extract<Array::Ptr>();
        for (auto iter = arr->begin(); iter != arr->end(); ++iter) {
            std::string s;
            iter->convert(s);
            results.emplace_back(std::make_pair(rule_id, s));
        }
        return Status::Ok();
    } catch (Poco::Exception &e) {
        return Status(std::string("[Poco::Exception] ") + e.displayText());
    }
    return Status("Failed to process rules");
}

Status process_rules(const std::string &riot_token, const std::vector<ConfigRule> &rules, const time_t last_update,
    const time_t now)
{
    std::vector<std::pair<int, std::string>> matches_to_search;
    RateCounter r120(rate_limit_120, sleep_amt_120);
    RateCounter r1(rate_limit_1, sleep_amt_1);
    for (size_t i = 0; i < rules.size(); ++i) {
        const Status status = get_games_between(riot_token, rules[i].puuid, last_update, now, i, matches_to_search);
        if (!status.ok()) {
            return status;
        }
        --r120;
        --r1;
    }
    using GameInfoAndRule = std::pair<GameInfo, int>;
    std::vector<std::pair<GameInfo, int>> games_to_dispatch;
    for (const auto &matches : matches_to_search) {
        const ConfigRule &rule = rules[matches.first];
        GameInfo game_info = {};
        const Status status = get_game_info(riot_token, rule.puuid, matches.second, game_info);
        if (!status.ok()) {
            return status;
        } else {
            if (does_rule_match(game_info, rule)) {
                games_to_dispatch.emplace_back(std::make_pair(game_info, matches.first));
            }
        }
        --r120;
        --r1;
    }
    if (games_to_dispatch.size() > 1) {
        // sort them in chronological order if there is more than one
        std::sort(games_to_dispatch.begin(), games_to_dispatch.end(),
            [](const GameInfoAndRule &lhs, const GameInfoAndRule &rhs) {
            return lhs.first.time_end < rhs.first.time_end;
        });
    }
    for (const auto &game_info_and_rule : games_to_dispatch) {
        dispatch_webhook(game_info_and_rule.first, rules[game_info_and_rule.second]);
    }
    LOG << "Dispatched " << games_to_dispatch.size() << " games" << std::endl;
    return Status::Ok();
}

void my_sa_handler(int sig)
{
    if (sig == SIGHUP) {
        needs_config_reload = true;
    }
}

bool run(const int sleep_interval)
{
    if (sleep_interval < 120) {
        LOG << "WARNING: Setting the sleep interval under 120 seconds put you at "
               "risk of exceeding riot rate limits"
            << std::endl;
    }
    {
        struct sigaction info;
        std::memset(&info, 0, sizeof(info));
        info.sa_handler = &my_sa_handler;
        if (sigaction(SIGHUP, &info, nullptr) == -1) {
            perror("sigaction");
            return false;
        }
    }
    std::string riot_token = read_first_line(riot_api_key_file_name);
    if (riot_token.size() <= 1) {
        std::cerr << "Invalid riot token" << std::endl;
        return false;
    }
    {
        std::ofstream f(pid_file_name);
        f << getpid() << std::endl;
    }
    time_t last_update = 0;
    {
        std::ifstream f(timestamp_file_name);
        if (f.good()) {
            f >> last_update;
        }
    }
    if (last_update == 0) {
        last_update = std::time(nullptr);
    }
    std::vector<ConfigRule> rules;
    for (;;) {
        if (needs_config_reload) {
            needs_config_reload = false;
            if (load_config(rules, error_report_webhook)) {
                LOG << "Config loaded successfully" << std::endl;
            } else {
                LOG << "Config failed to load -- still using old config" << std::endl;
            }
            const std::string new_riot_token = read_first_line(riot_api_key_file_name);
            if (new_riot_token.size() <= 1) {
                LOG << "Invalid riot token... still using old one" << std::endl;
            } else {
                riot_token = std::move(new_riot_token);
            }
        }
        const time_t now = std::time(nullptr) - 5;
        const Status status = process_rules(riot_token, rules, last_update, now);
        if (status.ok()) {
            last_update = now + 1;
            std::ofstream f(timestamp_file_name);
            f << last_update << std::endl;
        } else {
            log_error_generic(status);
        }
        sleep_ms(sleep_interval);
    }
    return true;
}

void print_usage(const char *const argv0)
{
    std::cerr << "Usage:" << std::endl;
    std::cerr << "(0) " << argv0 << " help -- prints this description" << std::endl;
    std::cerr << "(1) " << argv0
              << " run {Sleep interval in seconds} {Initial sleep before processing in seconds} -- starts the program"
              << std::endl;
    std::cerr << "(2) " << argv0 << " stop       -- stops the program via SIGTERM" << std::endl;
    std::cerr << "(3) " << argv0 << " reload     -- reloads config via SIGHUP" << std::endl;
    std::cerr << "(4) " << argv0 << " validate   -- validates the config file" << std::endl;
    std::cerr << "(5) " << argv0 << " dump_rules -- validates the config file and displays all rules" << std::endl;
    std::cerr << "(6) " << argv0 << " timestamp  -- utility for changing " << timestamp_file_name << " file"
              << std::endl;
}

}  // namespace

int main(int argc, char **argv)
{
    constexpr int SUCCESS = EXIT_SUCCESS;
    constexpr int FAILURE = EXIT_FAILURE;
    if (argc == 0) {
        print_usage("league_match_alert");
        return SUCCESS;
    }
    if (argc == 1) {
        print_usage(argv[0]);
        return SUCCESS;
    }
    const std::string_view arg(argv[1]);
    if (arg == "help") {
        print_usage(argv[0]);
        return SUCCESS;
    }
    if (argc != 2 && arg != "run" && arg != "timestamp") {
        std::cerr << "Wrong number of args" << std::endl;
        print_usage(argv[0]);
        return FAILURE;
    }
    if (arg == "stop" || arg == "reload") {
        pid_t target_pid = 0;
        {
            std::ifstream f(pid_file_name);
            if (f.good()) {
                f >> target_pid;
            }
        }
        if (target_pid <= 1) {
            std::cerr << "Unable to load pid from file... or it is invalid" << std::endl;
            unlink(pid_file_name);
            return FAILURE;
        }
        int res = 0;
        if (arg == "stop") {
            res = kill(target_pid, SIGTERM);
            unlink(pid_file_name);
        } else {
            res = kill(target_pid, SIGHUP);
        }
        perror("kill");
        return res;
    } else if (arg == "validate" || arg == "dump_rules") {
        std::vector<ConfigRule> rules;
        if (load_config(rules, error_report_webhook)) {
            LOG << "Validation successful" << std::endl;
            if (arg == "dump_rules") {
                if (rules.size() == 1) {
                    std::cout << rules.size() << " rules loaded" << std::endl;
                } else {
                    std::cout << "1 rule loaded" << std::endl;
                }
                for (size_t i = 0; i < rules.size(); ++i) {
                    const ConfigRule &r = rules[i];
                    std::cout << "Rule #" << (i + 1) << std::endl;
                    std::cout << "  player_name  = [" << r.player_name << "]" << std::endl;
                    std::cout << "  puuid        = [" << r.puuid << "]" << std::endl;
                    std::cout << "  min_death    = [" << r.min_death << "]" << std::endl;
                    std::cout << "  max_kd       = [" << r.max_kd_k << "/" << r.max_kd_d << "]" << std::endl;
                    std::cout << "  webhook_name = [" << r.webhook_username << "]" << std::endl;
                    std::cout << "  webhook_path = [" << r.webhook_route << "]" << std::endl;
                }
            }
        } else {
            LOG << "Validation failed" << std::endl;
        }
        return SUCCESS;
    } else if (arg == "timestamp") {
        time_t timestamp = 0;
        {
            std::ifstream f(timestamp_file_name);
            if (f.good()) {
                f >> timestamp;
            }
        }
        if (timestamp == 0) {
            std::cerr << "Timestamp file " << timestamp_file_name << " missing or corrupted" << std::endl;
        } else {
            std::cerr << timestamp_file_name << ": ";
            log_custom_timestamp_full(std::cerr, timestamp) << std::endl;
        }
        if (argc != 5) {
            std::cerr << "Modify with: " << argv[0] << " timestamp {+ or -} {amt} {secs or mins or hours or days}"
                      << std::endl;
            return SUCCESS;
        }
        const char op = argv[2][0];
        int amt = std::atoi(argv[3]);
        const char unit = argv[4][0];
        if (op == '-') {
            amt = -amt;
        } else if (op != '+') {
            std::cerr << "Unexpected operator '" << op << "', should be + or -" << std::endl;
            return FAILURE;
        }
        switch (unit) {
        case 's':
            break;
        case 'm':
            amt *= 60;
            break;
        case 'h':
            amt *= 3600;
            break;
        case 'd':
            amt *= 86400;
            break;
        default:
            std::cerr << "Unexpected unit '" << unit << "', should be s, m, h, d" << std::endl;
            return FAILURE;
        }
        timestamp = std::time(nullptr) + amt;
        {
            std::ofstream f(timestamp_file_name);
            f << timestamp << std::endl;
        }
        std::cerr << timestamp_file_name << ": ";
        log_custom_timestamp_full(std::cerr, timestamp) << std::endl;
        return SUCCESS;
    } else if (arg == "run") {
        if (argc < 3) {
            std::cerr << "Needs interval in sec for command \"run\"" << std::endl;
            return FAILURE;
        }
        const int interval = std::atoi(argv[2]);
        constexpr int max_sleep_range = 1000000;
        if (interval <= 1 || interval > max_sleep_range) {
            std::cerr << "Invalid interval, must be > 1 and < " << max_sleep_range << std::endl;
            return FAILURE;
        }

        int initial_sleep = 0;
        if (argc == 4) {
            initial_sleep = std::atoi(argv[3]);
            if (initial_sleep < 0 || initial_sleep > max_sleep_range) {
                std::cerr << "Invalid initial sleep, must be >= 0 and < " << max_sleep_range << std::endl;
                return FAILURE;
            }
        } else if (argc != 3) {
            std::cerr << "Wrong number of args for command \"run\"" << std::endl;
            return FAILURE;
        }
        if (initial_sleep > 0) {
            sleep_ms(initial_sleep * 1000);
        }
        return run(interval * 1000) ? SUCCESS : FAILURE;
    } else {
        std::cerr << "Unknown arg: " << arg << std::endl;
        print_usage(argv[0]);
        return SUCCESS;
    }
}
