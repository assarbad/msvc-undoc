PYSCRIPTS:=update-yaml.py IDAPython/get_envvar_refs.py
all: linkexe_documented.txt black lint vulture msvc.yaml

cpp-docs/docs/build/reference/linker-options.md:
	git clone https://github.com/MicrosoftDocs/cpp-docs.git

linkexe_documented.txt: cpp-docs/docs/build/reference/linker-options.md
	git -C cpp-docs clean -dfx
	git -C cpp-docs reset --hard
	rg  '\| \[`(/[^`]+)' -or '$$1' cpp-docs/docs/build/reference/linker-options.md |cut -d : -f 2|tr 'A-Z' 'a-z'|sort -u|tee $@

msvc: black lint msvc.yaml

msvc.yaml: update-yaml.py
	./update-yaml.py -vY $@

clean:
	rm -f linkexe_documented.txt

CLEAN: clean
	rm -rf cpp-docs

rebuild: clean all

REBUILD: CLEAN all

lint: $(PYSCRIPTS)
	flake8 $^

pretty: black

prerequisites: requirements.txt install-python-prerequisites.sh
	./install-python-prerequisites.sh

black: $(PYSCRIPTS)
	$@ $^

vulture: $(PYSCRIPTS)
	$@ $^

.DEFAULT: all
.PHONY: all black lint pretty prerequisites vulture msvc.yaml msvc
.NOTPARALLEL: all clean rebuild CLEAN REBUILD
