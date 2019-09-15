# Job Vranish (2016)
.SILENT:

TARGET_EXEC ?= a.out

TOOL_DIRS ?= ./tool
TEST_DIRS ?= ./test
BUILD_DIR ?= ./build~
SRC_DIRS ?= ./src

MKDIR_P ?= mkdir -p

SRCS := $(shell find $(SRC_DIRS) -name '*.cpp' -or -name '*.c' -or -name '*.s')
TEST := $(shell find $(TEST_DIRS) -name '*.cpp' -or -name '*.c' -or -name '*.s')
TOOL := $(shell find $(TOOL_DIRS) -name '*.cpp' -or -name '*.c' -or -name '*.s')
OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)
OBJS_TEST := $(TEST:%=$(BUILD_DIR)/%.o)
OBJS_TEST += $(OBJS)
OBJS_TOOL := $(TOOL:%=$(BUILD_DIR)/%.o)
OBJS_TOOL += $(OBJS)

INC_DIRS := $(shell find $(SRC_DIRS) -type d)
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

CFLAGS := -D _DEFAULT_SOURCE -std=c11 -Wall -Wextra -Werror -O0
CPPFLAGS ?= $(INC_FLAGS) -MMD -MP -std=c++11 -Wall -Weffc++ -Wextra -Wsign-conversion -Werror

$(BUILD_DIR)/$(TARGET_EXEC): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# assembly
$(BUILD_DIR)/%.s.o: %.s
	$(MKDIR_P) $(dir $@)
	$(AS) $(ASFLAGS) -c $< -o $@

# c source
$(BUILD_DIR)/%.c.o: %.c
	$(MKDIR_P) $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# c++ source
$(BUILD_DIR)/%.cpp.o: %.cpp
	$(MKDIR_P) $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

.PHONY: clean
clean:
	$(RM) -r $(BUILD_DIR)

.PHONY: tool
tool: $(OBJS_TOOL)
	$(MKDIR_P) $(dir $@)
	$(CC) $(OBJS_TOOL) -o $(BUILD_DIR)/$@/$(TARGET_EXEC) $(LDFLAGS)

.PHONY: test
test: $(OBJS_TEST)
	$(MKDIR_P) $(dir $@)
	$(CC) $(OBJS_TEST) -o $(BUILD_DIR)/$@/$(TARGET_EXEC) $(LDFLAGS)
