#!/bin/sh

node get_queue_info.js

clang-format -i ../src/queue_name_map.cpp
