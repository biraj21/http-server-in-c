cc=gcc
flags=-Wall -Werror
src=src
bin=bin

all: setup clean $(bin)/server

setup:
	mkdir -p $(bin)

clean:
	rm -f $(bin)/*

$(bin)/server: $(src)/server.c
	$(cc) $(flags) -o $@ $^
