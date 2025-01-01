# Define the compiler and flags
CXX = clang++
CXXFLAGS = -std=c++14 -I/opt/homebrew/Cellar/openssl@3/3.4.0/include/openssl -I/opt/homebrew/Cellar/openssl@3/3.4.0/include/
LDFLAGS = -L/opt/homebrew/Cellar/openssl@3/3.4.0/lib -lssl -lcrypto
# Target executable name
# TARGET = client
TARGET = client

# Source files
# SRCS = client.cpp
SRCS = client.cpp

# Build the executable directly from the source
all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(TARGET) $(SRCS)

# Clean up
clean:
	rm -f $(TARGET)