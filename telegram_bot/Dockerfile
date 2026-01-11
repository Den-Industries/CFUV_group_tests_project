FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libcurl4-openssl-dev \
    libjsoncpp-dev \
    libhiredis-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source files
COPY main.cpp .

# Compile the bot with proper include path for jsoncpp
RUN g++ -std=c++17 -I/usr/include/jsoncpp -o telegram_bot main.cpp \
    -lcurl \
    -ljsoncpp \
    -lhiredis \
    -pthread

# Run the bot
CMD ["./telegram_bot"]
