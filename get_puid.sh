#!/bin/sh

TOKEN=`cat riot_api_key.secret`

if [ -z "$TOKEN" ]
then
	echo 'No riot token'
	exit 1
fi

if [ -z "$1" ]
then
	echo 'Please supply riot id in the form of name/tag as an argument'
	exit 1
fi

URL='https://americas.api.riotgames.com/riot/account/v1/accounts/by-riot-id/'$1

curl -H "X-Riot-Token: $TOKEN" -X GET $URL

echo
