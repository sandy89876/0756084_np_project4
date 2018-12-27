CXX=clang++
CXXFLAGS=-std=c++11 -Wall -pedantic -pthread -lboost_system
CXX_INCLUDE_DIRS=-I/usr/local/include
CXX_LIB_DIRS=-L/usr/local/lib


all:
	rm -f socks_server hw4.cgi
	g++ socks_server.cpp -o socks_server
	$(CXX) console.cpp -o hw4.cgi $(CXX_INCLUDE_DIRS) $(CXX_LIB_DIRS) $(CXXFLAGS)
