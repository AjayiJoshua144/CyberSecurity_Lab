# ===========================================
# CyberShield Lab — C++ Build File
# Run:  make
# Clean: make clean
# ===========================================

CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -pthread
TARGET   = port_scanner
SRC      = port_scanner.cpp

all: $(TARGET)
	@echo ""
	@echo "  [OK] port_scanner built successfully!"
	@echo "  Usage: ./port_scanner <ip> <start_port> <end_port>"
	@echo "  Example: ./port_scanner 127.0.0.1 1 1024"
	@echo ""

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)
	@echo "  [OK] Cleaned build files."
