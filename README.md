This program watches a list of players via the League of Legends API in order to provide
automated alerts via a webhook whenever a game is played that is below a certain KD ratio
and above a certain death count.

**Compiling**

Use the makefile. Requires libpoco and POSIX

**Running**

1. Make a file with your League API key in `riot_api_key.secret`
2. Make a config.txt file
3. Run with `$ ./league_match_alert 300 &` where 300 represents the interval in seconds that the
program should wake up and query.

The program catches the HUP signal so you can run it in the bg like this and it will stay running
once you close your shell (like a daemon).

In order to quit you can run `./league_match_alert stop` to send a signal to the running process

Sample config.txt:

```
# Lines starting with # are ignored

Webhook Defs
# Webhook name|Webhook username|Webhook route
My Webhook|League Alert|/api/webhooks/33232/defdfdfskdjf
Other Webhook|Game Alert|/api/webhooks/1234/abcsdkjfkj

Player Defs
# Note that the nickname you put here will be used in the alert message
# Nickname|PUID
Player One|skdfjksdfjdskfdsfk
Player Two|dsfkdfjkdjdkfj
Player Three|skdjfksdjfkdsfjdskfdjfkdjf

Rule Defs
# Nickname|Min death|Max KD|Webhook name
Player One|5|0.2|My Webhook
Player Two|7|0.3|Other Webhook
Player Three|10|0.1|Other Webhook
```
