#!/bin/bash
# Получение имени файла без расширения
filename=$(basename -- "$1")
extension="${filename##*.}"
filename="${filename%.*}"

# Выполнение команд
clang-format -style=file:$CLANG_FORMAT_STYLE -i $1
clang-tidy -checks=$CLANG_TIDY_CHECKS $1 -- -g3 -O0 -std=c++17 -Wall -Wextra -fsanitize=address -fsanitize=undefined
clang++ -g3 -O0 -std=c++17 -Wall -Wextra -fsanitize=address -fsanitize=undefined $1 -o $filename.out
