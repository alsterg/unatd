all:
	gcc -o tproxy -O3 -g main.c -lev

static:
	gcc -o tproxy -O3 -g main.c -lev -lm -static

debug:
	gcc -o tproxy -O0 -g main.c -lev

