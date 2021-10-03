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

#define riot_endpoint "americas.api.riotgames.com"

#define riot_api_key_file_name "riot_api_key.secret"
#define pid_file_name "pid.info"
#define config_file_name "config.txt"
#define timestamp_file_name "last_timestamp.info"

#define TRACE (std::cout << "[line " << __LINE__ << "] ")
#define trace(what) (TRACE << #what " = " << (what) << std::endl)

#define UNUSED __attribute__((unused))
#define LOG logtimestamp(std::cout)
#define RATIO(a, b) (static_cast<float>(a) / static_cast<float>(b))

extern std::map<int, std::string> queue_name_map;

static std::atomic<bool> needs_config_reload(true);

class ConfigRule {
public:
	std::string player_name;
	std::string puuid;
	int min_death;
	float max_kd;
	std::string webhook_username;
	std::string webhook_route;
};

class GameInfo {
public:
	int queue_id;
	std::string champion_name;
	int kills;
	int deaths;
};

static bool load_config(std::vector<ConfigRule> &old_rules);

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

static int send_to_webhook(const std::string &webhook_route, const std::string &username, const std::string &msg)
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
			trace(json);
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

static void dispatch_if_rule_matches(const GameInfo &game_info, const ConfigRule &rule)
{
	if (game_info.deaths < rule.min_death || game_info.deaths == 0) {
		return;
	}
	const float kd = RATIO(game_info.kills, game_info.deaths);
	if (kd > rule.max_kd) {
		return;
	}
	std::ostringstream ss;
	ss << rule.player_name << " went " << game_info.kills << "/" << game_info.deaths;
	ss << " on " << game_info.champion_name;
	ss << " while playing ";
	ss << get_queue_name(game_info.queue_id);
	send_to_webhook(rule.webhook_route, rule.webhook_username, ss.str());
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
				return true;
			}
		}
		return false;
	} catch (Poco::Exception &e) {
		LOG << "exception while getting game info: " << e.displayText() << std::endl;
	}
	return false;
}

static std::vector<std::string> get_games_since(const std::string &riot_token, const std::string &puuid, const time_t since)
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
			return {};
		}
		Parser parser;
		Poco::Dynamic::Var result = parser.parse(stream);
		Array::Ptr arr = result.extract<Array::Ptr>();
		std::vector<std::string> ret;
		for (auto iter = arr->begin(); iter != arr->end(); ++iter) {
			std::string s;
			iter->convert(s);
			ret.emplace_back(s);
		}
		return ret;
	} catch (Poco::Exception &e) {
		LOG << "exception while getting games: " << e.displayText() << std::endl;
	}
	return {};
}

static void my_sa_handler(int sig)
{
	if (sig == SIGHUP) {
		needs_config_reload = true;
	}
}

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


static int run(const int sleep_interval)
{
	{
		struct sigaction info;
		std::memset(&info, 0, sizeof(info));
		info.sa_handler = &my_sa_handler;
		if (sigaction(SIGHUP, &info, nullptr) == -1) {
			perror("sigaction");
			return 1;
		}
	}
	const std::string riot_token = read_first_line(riot_api_key_file_name);
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
		}
		for (const auto &rule : rules) {
			auto game_ids = get_games_since(riot_token, rule.puuid, last_update);
			if (game_ids.size() >= 5) {
				LOG << "got too many game ids: " << game_ids.size() << std::endl;
			} else {
				for (const auto &game_id : game_ids) {
					GameInfo game_info;
					if (get_game_info(riot_token, rule.puuid, game_id, game_info)) {
						dispatch_if_rule_matches(game_info, rule);
					}
				}
			}
		}
		const time_t now = std::time(nullptr);
		last_update = now;
		{
			std::ofstream f(timestamp_file_name);
			f << now << std::endl;
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
					std::cout << "  puuid         = [" << r.puuid << "]" << std::endl;
					std::cout << "  min_death    = [" << r.min_death << "]" << std::endl;
					std::cout << "  max_kd      = [" << r.max_kd << "]" << std::endl;
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
				if (res.size() != 4) {
					LOG << "Item in rule def section has size " << res.size() << " but should be 4" << std::endl;
					return false;
				}
				auto player_iter = player_map.find(res[0]);
				if (player_iter == player_map.end()) {
					LOG << "\"" << res[0] << "\" did not name a valid player" << std::endl;
					return false;
				}
				auto webhook_iter = webhook_map.find(res[3]);
				if (webhook_iter == webhook_map.end()) {
					LOG << "\"" << res[3] << "\" did not name a valid webhook" << std::endl;
					return false;
				}
				int min_death = 0;
				float max_kd = 0.f;
				try {
					min_death = std::stoi(res[1]);
				} catch (std::invalid_argument &e) {
					LOG << "\"" << res[1] << "\" was not a valid int" << std::endl;
					return false;
				}
				try {
					max_kd = std::stof(res[2]);
				} catch (std::invalid_argument &e) {
					LOG << "\"" << res[2] << "\" was not a valid number" << std::endl;
					return false;
				}
				ConfigRule rule{
					player_iter->first,
					player_iter->second,
					min_death,
					max_kd,
					webhook_iter->second.first,
					webhook_iter->second.second
				};
				rules.emplace_back(std::move(rule));
				break;
			}
			}
		}
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
		if (rule.webhook_route[0] != '/') {
			LOG << "webhook route does not start with /" << std::endl;
			return false;
		}
	}
	old_rules = std::move(rules);
	return true;
}
