build-debug:
  gcc -O1 -g -fsanitize=address -Werror -Wall -lpcap -o ./build/out ./src/main.c ./src/parser.c ./src/helper.c ./src/ring_buffer.c ./src/shared_queue.c

build-release:
  gcc -O3 -Werror -Wall -lpcap -o ./build/out ./src/main.c ./src/parser.c ./src/helper.c ./src/ring_buffer.c ./src/shared_queue.c
