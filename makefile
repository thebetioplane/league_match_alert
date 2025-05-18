MAKEFLAGS += Rr
CXX := g++
CXXFLAGS := -Wall -Wextra -Wpedantic -Wshadow -std=c++20 -O2 -march=native
LDLIBS := -lPocoJSON -lPocoNetSSL -lPocoNet -lPocoFoundation
TARGET := league_match_alert

.PHONY: clean all

all: $(TARGET)

$(TARGET): obj/logging.o obj/main.o obj/queue_name_map.o obj/riot_error_types.o obj/status.o obj/string_util.o
	$(CXX) $^ $(LDLIBS) -o $@

obj/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) $< -c -o $@

clean:
	rm -f $(TARGET) && rm -rf obj && mkdir obj

obj/logging.o: src/logging.cpp src/logging.hpp src/string_util.hpp
obj/main.o: src/main.cpp src/config.hpp src/logging.hpp src/queue_name_map.hpp \
 src/riot_error_types.hpp src/status.hpp src/string_util.hpp
obj/queue_name_map.o: src/queue_name_map.cpp
obj/riot_error_types.o: src/riot_error_types.cpp src/riot_error_types.hpp
obj/status.o: src/status.cpp src/status.hpp
obj/string_util.o: src/string_util.cpp src/string_util.hpp
