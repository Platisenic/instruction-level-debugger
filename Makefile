
.PHONY: all clean

all: hw4

hw4: hw4.cpp
	g++ -g -std=c++11 -o hw4 hw4.cpp -lcapstone

clean: rm hw4