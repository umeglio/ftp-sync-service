CXX = g++
CXXFLAGS = -O2 -Wall
LDFLAGS = -lwininet -ladvapi32 -lpsapi -static
TARGET = ftp_sync_service.exe
SRC = ftp_sync_service.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	del /Q $(TARGET) 2>NUL || rm -f $(TARGET)

install: $(TARGET)
	$(TARGET) --install

.PHONY: all clean install
