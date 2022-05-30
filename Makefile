CXX = g++
CFLAGS = -g -std=c++11
PACKNAME= 310552029_hw4

.PHONY: all clean

all: hw4

hw4: hw4.o putils.o debugger.o
	$(CXX) $(CFLAGS) -o $@ $^ -lcapstone

hw4.o: hw4.cpp
	$(CXX) $(CFLAGS) -c -o $@ $<

putils.o : putils.cpp putils.h
	$(CXX) $(CFLAGS) -c -o $@ $<

debugger.o : debugger.cpp debugger.h
	$(CXX) $(CFLAGS) -c -o $@ $<

clean:
	rm -f hw4 *.o core $(PACKNAME).zip

pack: clean
	mkdir -p $(PACKNAME)
	cp *.cpp *.h Makefile $(PACKNAME)
	zip -r $(PACKNAME).zip $(PACKNAME)
	rm -rf $(PACKNAME)
