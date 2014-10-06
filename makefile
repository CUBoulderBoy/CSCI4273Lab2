# Lab 2: EchoServer and EchoClient with SSL
# Christopher Jordan
# CSCI 4273 Fall 2014

EXE=echoClient echoServer
SERVER=echoServer
CLIENT=echoClient

# Main target
all: $(EXE)
client: $(CLIENT)
server: $(SERVER)

CFLG=-O3 -Wall -w
LIBS=-lcrypto -lssl
CLEAN=rm -f $(EXE) *.o *.a

# Compile rules
.c.o:
	gcc -c $(CFLG) $<
.cpp.o:
	g++ -c $(CFLG) $<

#  Link
echoServer:echoServer.o
	gcc -O3 -o $@ $^ $(LIBS)

#  Link
echoClient:echoClient.o
	gcc -O3 -o $@ $^ $(LIBS)

#  Clean
clean:
	$(CLEAN)
