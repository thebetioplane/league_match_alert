const https = require('https');
const fs = require('fs');

const req = https.request({
	hostname: 'static.developer.riotgames.com',
	port: 443,
	path: '/docs/lol/queues.json',
	method: 'GET'
}, res => {
	console.log('Request performed, status ' + res.statusCode);
	let json_string = '';
	res.on('data', chunk => {
		json_string += chunk;
	});
	res.on('end', () => {
		processObj(JSON.parse(json_string));
	});
});

req.on('error', err => {
	console.log(err);
});

req.end();


function processObj(arr) {
	let stream = fs.createWriteStream('../src/queue_name_map.cpp');
	stream.write('#include <map>\n#include <string>\n');
	stream.write('std::map<int, std::string> queue_name_map {\n')
	for (let item of arr) {
		let name = item.description ? item.description : item.map;
		name = name.replace(/[ ]*games?/g, '');
		stream.write('{');
		stream.write(item.queueId.toString());
		stream.write(',"');
		stream.write(name);
		stream.write('"},\n');
	}
	stream.write('};\n')
	stream.close();
}