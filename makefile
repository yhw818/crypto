cxx = g++
CXXFLAGS += -std=c++11 
LIB += -lcrypto -lssl
all : rsa dgst
.PHONY : all

rsa: rsa.o 
	$(cxx) $(CXXFLAGS) -o rsa rsa.o $(LIB)

dgst: dgst.o crypto.o
	$(cxx) $(CXXFLAGS) -o dgst dgst.o crypto.o $(LIB)

rsa.o: rsa.cpp 
	$(cxx) -c $(CXXFLAGS) rsa.cpp $(LIB)
dgst.o: dgst.cpp 
	$(cxx) -c $(CXXFLAGS) dgst.cpp $(LIB)
crypto.o: crypto.cpp
	$(cxx) -c $(CXXFLAGS) crypto.cpp $(LIB)

.PHONY : clean
clean :
	-rm rsa rsa.o dgst dgst.o crypto.o
