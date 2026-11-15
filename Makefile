CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic
CXXFLAGS += -pthread -Iinclude -MMD -MP
LDFLAGS  += -pthread

TARGET   := portscan
SRC_DIR  := src
BUILD    := build
SOURCES  := $(wildcard $(SRC_DIR)/*.cpp)
OBJECTS  := $(patsubst $(SRC_DIR)/%.cpp,$(BUILD)/%.o,$(SOURCES))
DEPS     := $(OBJECTS:.o=.d)

.PHONY: all clean run debug

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)

$(BUILD)/%.o: $(SRC_DIR)/%.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD):
	mkdir -p $(BUILD)

run: $(TARGET)
	./$(TARGET) 127.0.0.1 -p 1-1024

# Build com sanitizers para caçar data races e vazamentos
debug:
	$(MAKE) clean
	$(MAKE) CXXFLAGS="-std=c++17 -O1 -g -fsanitize=thread -Wall -Wextra -Wpedantic" LDFLAGS="-fsanitize=thread"

clean:
	rm -rf $(BUILD) $(TARGET)

-include $(DEPS)
