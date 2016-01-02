#
# To compile, type "make" 
# To remove files, type "make clean"
#
LIBS = -lpthread -lrt
all: wspace_server_unicast

wspace_server_unicast: time_util.o tun.o wspace_asym_util.o
	$(CXX) $(CXXFLAGS) $^ -o wspace_server_unicast $(LIBS)

%.o: %.cc
	$(CXX) $(CXXFLAGS) -o $@ -c $<

clean:
	rm -rf wspace_server_unicast *.o 

tag: 
	ctags -R *
