build-debug:
  gcc -O1 -g -fsanitize=address -Werror -Wall -lpcap -o ./build/out ./src/*.c

build-release:
  gcc -O3 -Werror -Wall -lpcap -o ./build/out ./src/*.c
