#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/HTTPMessage.h>
#include <Poco/Net/HTTPSClientSession.h>
#include <Poco/Net/NetException.h>
#include <Poco/JSON/Parser.h>
#include <Poco/JSON/Stringifier.h>
#include <Poco/Timespan.h>
#include <Poco/Net/Socket.h>

#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <cstring>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <signal.h>
#include <ctime>
#include <atomic>
#include <cstdlib>
#include <errno.h>
#include <atomic>
#include <utility>

#define riot_endpoint "americas.api.riotgames.com"
// requests per second
#define rate_limit_1 20
// request per 2 mins
#define rate_limit_120 100
//#define SHOW_ASSISTS

#define riot_api_key_file_name "riot_api_key.secret"
#define pid_file_name "pid.info"
#define config_file_name "config.txt"
#define timestamp_file_name "last_timestamp.info"

#define TRACE (std::cout << "[line " << __LINE__ << "] ")
#define trace(what) (TRACE << #what " = " << (what) << std::endl)

#define UNUSED __attribute__((unused))
#define LOG logtimestamp(std::cout)

extern std::map<int, std::string> queue_name_map;
static std::pair<std::string, std::string> error_report_webhook;
static std::atomic<bool> needs_config_reload(true);

class ConfigRule {
public:
	std::string player_name;
	std::string puuid;
	int min_death;
	int max_kd_k;
	int max_kd_d;
	std::string webhook_username;
	std::string webhook_route;
};

class GameInfo {
public:
	int queue_id;
	std::string champion_name;
	int kills;
	int deaths;
#ifdef SHOW_ASSISTS
	int assists;
#endif
};

static bool load_config(std::vector<ConfigRule> &old_rules);
static int send_to_webhook(const std::string &webhook_route, const std::string &username, const std::string &msg, bool log_if_error);

static const char *two_char_pad(int n)
{
	static char res[3];
	res[0] = (n / 10 % 10) + '0';
	res[1] = (n % 10) + '0';
	return res;
}

static std::ostream &logtimestamp(std::ostream &o)
{
	time_t timestamp;
	std::time(&timestamp);
	const std::tm *const now = std::localtime(&timestamp);
	o << '[' << two_char_pad(now->tm_hour) << ':' << two_char_pad(now->tm_min) << ':' << two_char_pad(now->tm_sec) << "] ";
	return o;
}

static std::string read_first_line(const char *fname)
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
static void sleep_ms(int ms)
{
	struct timespec req;
	req.tv_sec = ms / 1000;
	req.tv_nsec = (ms % 1000) * 1000000L;
	struct timespec rem;
	for ( ; ; ) {
		const int res = nanosleep(&req, &rem);
		if (res < 0 && errno == EINTR) {
			std::memcpy(&req, &rem, sizeof(req));
		} else {
			return;
		}
	}
}

static void log_http_error(const std::string &method, const std::string &route, const int status)
{
	if (! error_report_webhook.second.empty()) {
		std::ostringstream ss;
		logtimestamp(ss) << method << " `" << route << "`\n resulted in **" << status << "**";
		send_to_webhook(error_report_webhook.second, error_report_webhook.first, ss.str(), false);
		if (status == 403) {
			std::ostringstream ss2;
			logtimestamp(ss2) << "Exiting due to 403. You must update the token.";
			send_to_webhook(error_report_webhook.second, error_report_webhook.first, ss2.str(), false);
		}
	}
	if (status == 403) {
		LOG << "Calling std::exit(403)" << std::endl;
		std::exit(403);
	}
}

static void log_error_generic(const std::string &msg)
{
	LOG << msg << std::endl;
	if (! error_report_webhook.second.empty()) {
		std::ostringstream ss;
		logtimestamp(ss) << msg;
		send_to_webhook(error_report_webhook.second, error_report_webhook.first, ss.str(), false);
	}
}

static int send_to_webhook(const std::string &webhook_route, const std::string &username, const std::string &msg, bool log_if_error)
{
	constexpr int default_sleep_amt = 1000;
	try {
		using Poco::Net::HTTPSClientSession;
		using Poco::Net::HTTPRequest;
		using Poco::Net::HTTPResponse;
		using Poco::Net::HTTPMessage;

		HTTPSClientSession cs("discord.com", 443);
		HTTPRequest request(HTTPRequest::HTTP_POST, webhook_route, HTTPMessage::HTTP_1_1);
		request.set("Content-Type", "application/json");
		std::ostringstream json_ss;
		json_ss << "{\"content\":";
		Poco::JSON::Stringifier::formatString(msg, json_ss);
		json_ss << ",\"username\":";
		Poco::JSON::Stringifier::formatString(username, json_ss);
		json_ss << ",\"allowed_mentions\":{\"parse\":[]}}";
		const std::string &json = json_ss.str();
		request.setContentLength(json.size());
		cs.sendRequest(request) << json;
		HTTPResponse response;
		cs.receiveResponse(response);
		const int status = response.getStatus();
		if (status / 100 != 2) {
			LOG << "I tried to POST to webhook and got response " << status << std::endl;
			//trace(json);
			if (log_if_error) {
				log_http_error("POST", "webhook", status);
			}
		}
		const int remaining = std::stoi(response.get("x-ratelimit-remaining"));
		if (remaining == 0) {
			double after = std::stod(response.get("x-ratelimit-reset-after"));
			after = std::ceil(after * 1000);
			return static_cast<int>(after);
		} else {
			return 0;
		}
	} catch (std::invalid_argument &e) {
		LOG << "exception while sending message: " << e.what() << std::endl;
	} catch (Poco::Exception &e) {
		LOG << "exception while sending message: " << e.displayText() << std::endl;
	}
	return default_sleep_amt;
}

static std::string get_queue_name(int queue_id)
{
	auto iter = queue_name_map.find(queue_id);
	if (iter == queue_name_map.end())
		return "League of Legends";
	return iter->second;
}

static int compare_ratio(int n0, int d0, int n1, int d1)
{
	return n0*d1 - d0*n1;
}

static void dispatch_if_rule_matches(const GameInfo &game_info, const ConfigRule &rule)
{
	if (game_info.deaths < rule.min_death) {
		return;
	}
	if (compare_ratio(game_info.kills, game_info.deaths, rule.max_kd_k, rule.max_kd_d) > 0) {
		return;
	}
	std::ostringstream ss;
	ss << rule.player_name;
	ss << " went **" << game_info.kills << "/" << game_info.deaths << "**";
#ifdef SHOW_ASSISTS
	ss << "/" << game_info.assists;
#endif
	ss << " on " << game_info.champion_name;
	ss << " while playing ";
	ss << get_queue_name(game_info.queue_id);
	send_to_webhook(rule.webhook_route, rule.webhook_username, ss.str(), true);
}

static bool get_game_info(const std::string &riot_token, const std::string &puuid, const std::string &game_id, GameInfo &game_info)
{
	try {
		using Poco::Net::HTTPSClientSession;
		using Poco::Net::HTTPRequest;
		using Poco::Net::HTTPResponse;
		using Poco::Net::HTTPMessage;
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
		if (status / 100 != 2) {
			LOG << "I tried to GET match info by gameid and got response " << status << std::endl;
			log_http_error("GET", route.str(), status);
			return false;
		}
		Parser parser;
		Poco::Dynamic::Var result = parser.parse(stream);
		Object::Ptr obj = result.extract<Object::Ptr>();
		auto info_obj = obj->getObject("info");
		game_info.queue_id = info_obj->getValue<int>("queueId");
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
				return true;
			}
		}
		return false;
	} catch (Poco::Exception &e) {
		LOG << "exception while getting game info: " << e.displayText() << std::endl;
	}
	return false;
}

static bool get_games_since(const std::string &riot_token, const std::string &puuid, const time_t since, const int rule_id, std::vector<std::pair<int, std::string>> &results)
{
	try {
		using Poco::Net::HTTPSClientSession;
		using Poco::Net::HTTPRequest;
		using Poco::Net::HTTPResponse;
		using Poco::Net::HTTPMessage;
		using namespace Poco::JSON;

		std::ostringstream route;
		route << "/lol/match/v5/matches/by-puuid/";
		route << puuid;
		route << "/ids?startTime=";
		route << since;
		route << "&count=20";

		HTTPSClientSession cs(riot_endpoint, 443);
		HTTPRequest request(HTTPRequest::HTTP_GET, route.str(), HTTPMessage::HTTP_1_1);
		request.setContentLength(0);
		request.set("X-Riot-Token", riot_token);
		cs.sendRequest(request);
		HTTPResponse response;
		auto &stream = cs.receiveResponse(response);
		const int status = response.getStatus();
		if (status / 100 != 2) {
			LOG << "I tried to GET matches by puuid and got response " << status << std::endl;
			log_http_error("GET", route.str(), status);
			return false;
		}
		Parser parser;
		Poco::Dynamic::Var result = parser.parse(stream);
		Array::Ptr arr = result.extract<Array::Ptr>();
		for (auto iter = arr->begin(); iter != arr->end(); ++iter) {
			std::string s;
			iter->convert(s);
			results.emplace_back(std::make_pair(rule_id, s));
		}
		return true;
	} catch (Poco::Exception &e) {
		LOG << "exception while getting games: " << e.displayText() << std::endl;
	}
	return false;
}

static bool process_rules(const std::string &riot_token, const std::vector<ConfigRule> &rules, const time_t last_update)
{
	std::vector<std::pair<int, std::string>> matches_to_search;
	for (size_t i = 0; i < rules.size(); ++i) {
		if (! get_games_since(riot_token, rules[i].puuid, last_update, i, matches_to_search)) {
			return false;
		}
	}
	const int requests_left_120 = rate_limit_120 - rules.size();
	if (static_cast<int>(matches_to_search.size()) > requests_left_120) {
		std::ostringstream ss;
		ss << "Too many game ids returned. Got " << matches_to_search.size() << " but I only have " << requests_left_120 << " requests left for the next 120 seconds.";
		log_error_generic(ss.str());
		return false;
	}
	int requests_left = rate_limit_1 - rules.size();
	for (const auto &matches : matches_to_search) {
		const ConfigRule &rule = rules[matches.first];
		GameInfo game_info;
		if (get_game_info(riot_token, rule.puuid, matches.second, game_info)) {
			dispatch_if_rule_matches(game_info, rule);
		}
		--requests_left;
		if (requests_left == 0) {
			sleep_ms(1000);
			requests_left = rate_limit_1;
		}
	}
	return true;
}

static void my_sa_handler(int sig)
{
	if (sig == SIGHUP) {
		needs_config_reload = true;
	}
}

static int run(const int sleep_interval)
{
	if (sleep_interval < 120) {
		LOG << "WARNING: Setting the sleep interval under 120 seconds put you at risk of exceeding riot rate limits" << std::endl;
	}
	{
		struct sigaction info;
		std::memset(&info, 0, sizeof(info));
		info.sa_handler = &my_sa_handler;
		if (sigaction(SIGHUP, &info, nullptr) == -1) {
			perror("sigaction");
			return 1;
		}
	}
	std::string riot_token = read_first_line(riot_api_key_file_name);
	if (riot_token.size() <= 1) {
		std::cerr << "Invalid riot token" << std::endl;
		return 1;
	}
	{
		std::ofstream f(pid_file_name);
		f << getpid() << std::endl;
	}
	//send_to_webhook(webhook_url, "Message");
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
	for ( ; ; ) {
		if (needs_config_reload) {
			needs_config_reload = false;
			if (load_config(rules)) {
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
		const time_t now = std::time(nullptr);
		if (process_rules(riot_token, rules, last_update)) {
			last_update = now;
			std::ofstream f(timestamp_file_name);
			f << last_update << std::endl;
		}
		sleep_ms(sleep_interval);
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		std::cerr << "Usage:" << std::endl;
		std::cerr << "(1) ./{Program name} {Sleep interval in seconds} -- starts the program" << std::endl;
		std::cerr << "(2) ./{Program name} stop       -- stops the program via SIGTERM" << std::endl;
		std::cerr << "(3) ./{Program name} reload     -- reloads config via SIGHUP" << std::endl;
		std::cerr << "(4) ./{Program name} validate   -- validates the config file" << std::endl;
		std::cerr << "(5) ./{Program name} dump_rules -- validates the config file and displays all rules" << std::endl;
		return 0;
	}
	const std::string arg(argv[1]);
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
			return 1;
		}
		const int res = kill(target_pid, (arg == "stop") ? SIGTERM : SIGHUP);
		if (res) {
			perror("kill");
			return 1;
		}
		return 0;
	} else if (arg == "validate" || arg == "dump_rules") {
		std::vector<ConfigRule> rules;
		if (load_config(rules)) {
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
		return 0;
	} else {
		const int interval = std::atoi(argv[1]);
		constexpr int max_sleep_range = 1000000;
		if (interval <= 1 || interval > max_sleep_range) {
			std::cerr << "Invalid interval, must be >= 1 and < " << max_sleep_range << std::endl;
			return 1;
		}
		return run(interval * 1000);
	}
}

// Config parsing code

enum class FileSection {
	None, WebhookDefs, PlayerDefs, RuleDefs
};

static std::vector<std::string> pipe_split(const std::string &input)
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

static bool stoi_noexcept(const std::string &s, int &n) noexcept
{
	try {
		n = std::stoi(s);
		return true;
	} catch (std::invalid_argument &e) {
		LOG << "\"" << s << "\" was not a valid int" << std::endl;
		return false;
	}
}

static bool load_config(std::vector<ConfigRule> &old_rules)
{
	std::ifstream f(config_file_name);
	if (! f.good()) {
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
				trace(line);
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
				if (! stoi_noexcept(res[1], min_death))
					return false;
				int max_kd_k = 0;
				if (! stoi_noexcept(res[2], max_kd_k))
					return false;
				int max_kd_d = 0;
				if (! stoi_noexcept(res[3], max_kd_d))
					return false;
				ConfigRule rule{
					player_iter->first,
					player_iter->second,
					min_death,
					max_kd_k,
					max_kd_d,
					webhook_iter->second.first,
					webhook_iter->second.second
				};
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
		LOG << "number of players to watch (" << rules.size() << ") exceeds 1 second rate limit (" << rate_limit_1 << ")";
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
