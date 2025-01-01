# Define the compiler and flags
CXX = clang++
CXXFLAGS = -std=c++14
# Target executable name
# TARGET = client
TARGET = server

# Source files
# SRCS = client.cpp
SRCS = server.cpp
# Build the executable directly from the source
all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS)

# Clean up
clean:
	rm -f $(TARGET)