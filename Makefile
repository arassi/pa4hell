MYDEFS = -g -Wall -std=c++11 -DLOCALHOST=\"127.0.0.1\"

all: pa4

pa4: pa4.cpp my_socket.cpp my_socket.h my_timestamp.cpp my_timestamp.h
	g++ ${MYDEFS} -o pa4 pa4.cpp my_socket.cpp my_timestamp.cpp -pthread 

clean:
	rm -f *.o pa4

