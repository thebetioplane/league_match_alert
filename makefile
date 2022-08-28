MAKEFLAGS += Rr
CXX := g++
CXXFLAGS := -Wall -Wextra -Wpedantic -Wshadow -std=c++11 -O2 -march=native
LDLIBS := -lPocoJSON -lPocoNetSSL -lPocoNet -lPocoFoundation
TARGET := league_match_alert

.PHONY: clean all

all: $(TARGET)

$(TARGET): obj/main.o obj/queue_name_map.o
	$(CXX) $^ $(LDLIBS) -o $@

obj/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) $< -c -o $@

clean:
	rm -f $(TARGET) && rm -rf obj && mkdir obj

obj/main.o: src/main.cpp src/config.hpp