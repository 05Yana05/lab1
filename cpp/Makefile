# ============================================================
#  Makefile для C++ клиента аутентификации
#  Сборка:  make
#  Запуск:  make run
#  Очистка: make clean
# ============================================================

CXX      := g++
CXXFLAGS := -std=c++17 -Wall -I.
LDLIBS   := -lsodium -lwinhttp -lws2_32

BUILD_DIR := build
BIN_DIR   := bin
TARGET    := $(BIN_DIR)/auth-client.exe

SRCS := AuthSystem.cpp Hash.cpp HttpClient.cpp JsonHelper.cpp \
        Lab_1KB.cpp User.cpp Validator.cpp
OBJS := $(patsubst %.cpp,$(BUILD_DIR)/%.o,$(SRCS))

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(OBJS) $(LDLIBS) -o $@
	@echo ""
	@echo "=========================================="
	@echo " Готово! Клиент собран: $@"
	@echo "=========================================="

$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

run: all
	./$(TARGET)

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
	@echo "Очищено"

.PHONY: all run clean