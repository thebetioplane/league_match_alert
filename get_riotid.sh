#!/bin/sh

TOKEN=`cat riot_api_key.secret`

if [ -z "$TOKEN" ]
then
	echo 'No riot token'
	exit 1
fi

if [ -z "$1" ]
then
	echo 'Please supply puuid an argument'
	exit 1
fi

URL='https://americas.api.riotgames.com/riot/account/v1/accounts/by-puuid/'$1

curl -H "X-Riot-Token: $TOKEN" -X GET $URL

echo
