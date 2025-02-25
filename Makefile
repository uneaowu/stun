FLAGS=-g -Wall -Werror -O3 -Os -flto -ffunction-sections -fdata-sections -Wl,--gc-sections

build/stun: stun.c stun.h
	mkdir -p ./build && cc $(FLAGS) stun.c -o build/stun

run: build/stun
	./build/stun $(ARGS)

test: build/stun
	./test.sh
