# ============================================================
#  Makefile for C++ authentication client
#  Build:            make
#  Build w/ cover:   make coverage
#  Run:              make run
#  Clean:            make clean
# ============================================================

CXX      := g++
CXXFLAGS := -std=c++17 -Wall -I.
LDLIBS   := -lsodium -lwinhttp -lws2_32

BUILD_DIR := build
BIN_DIR   := bin
TARGET    := $(BIN_DIR)/auth-client.exe

SRCS := AuthSystem.cpp HttpClient.cpp JsonHelper.cpp \
        Lab_1KB.cpp Validator.cpp
OBJS := $(patsubst %.cpp,$(BUILD_DIR)/%.o,$(SRCS))

# ---- Standard build ----
all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(OBJS) $(LDLIBS) -o $@
	@echo ""
	@echo "=========================================="
	@echo " Build complete: $@"
	@echo "=========================================="

$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

run: all
	./$(TARGET)

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
	@echo "Cleaned."

.PHONY: all run clean


# ============================================================
#  Code Coverage
# ============================================================

COVERAGE_DIR := coverage-report
COV_FLAGS    := --coverage -fprofile-arcs -ftest-coverage

COV_TARGET := $(BIN_DIR)/auth-client-cov.exe
COV_OBJS   := $(patsubst %.cpp,$(BUILD_DIR)/%.cov.o,$(SRCS))

coverage:
	@echo ">>> Cleaning old build..."
	@rm -rf $(BUILD_DIR) $(BIN_DIR)
	@mkdir -p $(BUILD_DIR) $(BIN_DIR)
	@echo ">>> Building with coverage flags..."
	@for src in $(SRCS); do \
	    echo "  [cov] compiling $$src"; \
	    $(CXX) $(CXXFLAGS) $(COV_FLAGS) -c $$src -o $(BUILD_DIR)/$$src.cov.o || exit 1; \
	done
	@echo ">>> Linking..."
	$(CXX) $(COV_FLAGS) $(BUILD_DIR)/*.cov.o $(LDLIBS) -o $(COV_TARGET)
	@echo ""
	@echo "=========================================="
	@echo " Coverage build complete: $(COV_TARGET)"
	@echo " 1. Run:  ./$(COV_TARGET)"
	@echo " 2. Go through ALL menu options"
	@echo " 3. Then: mingw32-make coverage-report"
	@echo "=========================================="

coverage-report:
	@mkdir -p $(COVERAGE_DIR)
	@echo ">>> Checking for .gcda files..."
	@ls build/*.gcda 2>/dev/null | head -5 || echo "  (no .gcda found!)"
	@echo ">>> Generating HTML report..."
	gcovr --html-details \
	      --gcov-executable gcov \
	      --object-directory build \
	      --root . \
	      -o $(COVERAGE_DIR)/index.html \
	      .
	@echo ""
	@echo "=========================================="
	@echo " Report ready: $(COVERAGE_DIR)/index.html"
	@echo "=========================================="

clean-coverage:
	@rm -rf $(COVERAGE_DIR)
	@find . -name "*.gcda" -delete
	@find . -name "*.gcno" -delete
	@echo "Coverage data cleaned."

.PHONY: all run clean coverage coverage-report clean-coverage