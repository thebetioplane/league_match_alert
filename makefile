MAKEFLAGS += Rr
CXX := g++
CXXFLAGS := -Wall -Wextra -Wpedantic -Wshadow -std=c++17 -O2 -march=native
LDLIBS := -lPocoJSON -lPocoNetSSL -lPocoNet -lPocoFoundation
TARGET := league_match_alert

.PHONY: clean all

all: $(TARGET)

$(TARGET): obj/main.o obj/queue_name_map.o obj/status.o obj/string_util.o
	$(CXX) $^ $(LDLIBS) -o $@

obj/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) $< -c -o $@

clean:
	rm -f $(TARGET) && rm -rf obj && mkdir obj


obj/main.o: src/main.cpp src/config.hpp src/queue_name_map.hpp src/status.hpp \
 src/string_util.hpp
obj/queue_name_map.o: src/queue_name_map.cpp
obj/status.o: src/status.cpp src/status.hpp
obj/string_util.o: src/string_util.cpp src/string_util.hpp
