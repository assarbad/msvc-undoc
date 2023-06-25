all: documented.txt

cpp-docs/docs/build/reference/linker-options.md:
	git clone https://github.com/MicrosoftDocs/cpp-docs.git

documented.txt: cpp-docs/docs/build/reference/linker-options.md
	git -C cpp-docs clean -dfx
	git -C cpp-docs reset --hard
	rg  '\| \[`(/[^`]+)' -or '$$1' cpp-docs/docs/build/reference/linker-options.md |cut -d : -f 2|tr 'A-Z' 'a-z'|sort -u|tee $@

clean:
	rm -f documented.txt

CLEAN: clean
	rm -rf cpp-docs

rebuild: clean all

REBUILD: CLEAN all

.DEFAULT: all
.PHONY: all
.NOTPARALLEL: all clean rebuild CLEAN REBUILD
