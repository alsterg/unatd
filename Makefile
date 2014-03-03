all:
	gcc -o unatd -O3 -g main.c -lev

static:
	gcc -o unatd -O3 -g main.c -lev -lm -static

debug:
	gcc -o unatd -O0 -g main.c -lev

