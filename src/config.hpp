#pragma once

#define riot_endpoint "americas.api.riotgames.com"
// requests per second
#define rate_limit_1 20
// request per 2 mins
#define rate_limit_120 100
// #define SHOW_ASSISTS
#define LOG_SLEEPS

// The API field to use for position. "lane", "teamPosition", "individualPosition"
#define POSITION "lane"
#define sleep_amt_1 1500
#define sleep_amt_120 130000

#define riot_api_key_file_name "riot_api_key.secret"
#define pid_file_name "pid.info"
#define config_file_name "config.txt"
#define timestamp_file_name "last_timestamp.info"