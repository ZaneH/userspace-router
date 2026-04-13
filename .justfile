build:
  gcc -fsanitize=address -Werror -Wall -lpcap -o out ./src/main.c ./src/parser.c
