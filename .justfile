build:
  gcc -g -fsanitize=address -Werror -Wall -lpcap -o ./build/out ./src/main.c ./src/parser.c ./src/helper.c ./src/ring_buffer.c
