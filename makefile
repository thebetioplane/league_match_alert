MAKEFLAGS += Rr
CXX := g++
CXXFLAGS := -Wall -Wextra -Wpedantic -Wshadow -std=c++17 -O2 -march=native
LDLIBS := -lPocoJSON -lPocoNetSSL -lPocoNet -lPocoFoundation
TARGET := league_match_alert

.PHONY: clean all

all: $(TARGET)

$(TARGET): obj/main.o obj/queue_name_map.o obj/riot_error_types.o obj/status.o obj/string_util.o
	$(CXX) $^ $(LDLIBS) -o $@

obj/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) $< -c -o $@

clean:
	rm -f $(TARGET) && rm -rf obj && mkdir obj


main.o: src/main.cpp src/config.hpp src/queue_name_map.hpp \
 src/riot_error_types.hpp src/status.hpp src/string_util.hpp
queue_name_map.o: src/queue_name_map.cpp
riot_error_types.o: src/riot_error_types.cpp src/riot_error_types.hpp
status.o: src/status.cpp src/status.hpp
string_util.o: src/string_util.cpp src/string_util.hpp
