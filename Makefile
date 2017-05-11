fmt:
	clang-format -i ./*.c ./*.h -style="{BasedOnStyle: Google, ColumnLimit: 120}"
	clang-format -i ./test/main/*.c -style="{BasedOnStyle: Google, ColumnLimit: 120}"

test/esp-idf:
	git clone --recursive --depth 1 https://github.com/espressif/esp-idf.git test/esp-idf

build: test/esp-idf
	cd ./test; make
