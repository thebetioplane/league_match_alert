#!/bin/sh

TOKEN=`cat riot_api_key.secret`

if [ -z "$TOKEN" ]
then
	echo 'No riot token'
	exit 1
fi

if [ -z "$1" ]
then
	echo 'Please supply username as an argument'
	exit 1
fi

URL='https://na1.api.riotgames.com/lol/summoner/v4/summoners/by-name/'$1

curl -H "X-Riot-Token: $TOKEN" -X GET $URL

echo
