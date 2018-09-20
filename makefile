cxx = g++
CXXFLAGS += -std=c++11 
LIB += -lcrypto -lssl
all : rsa
.PHONY : all

rsa: rsa.o 
	$(cxx) $(CXXFLAGS) -o rsa rsa.o $(LIB)
rsa.o: rsa.cpp 
	$(cxx) -c $(CXXFLAGS) rsa.cpp $(LIB)

.PHONY : clean
clean :
	-rm rsa rsa.o
