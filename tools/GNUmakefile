PYSCRIPTS:=update-yaml.py update-docs.py IDAPython/get_envvar_refs.py
all: linkexe_documented.txt black lint vulture msvc.yaml

mirrors/cpp-docs/docs/build/reference/linker-options.md:
	git -C mirrors clone https://github.com/MicrosoftDocs/cpp-docs.git

linkexe_documented.txt: mirrors/cpp-docs/docs/build/reference/linker-options.md
	git -C mirror/cpp-docs clean -dfx
	git -C mirror/cpp-docs reset --hard
	rg  '\| \[`(/[^`]+)' -or '$$1' mirror/cpp-docs/docs/build/reference/linker-options.md |cut -d : -f 2|tr 'A-Z' 'a-z'|sort -u|tee $@

msvc: black lint ../msvc.yaml

../msvc.yaml: update-yaml.py
	./update-yaml.py -vY $@

../%: %.j2
	./update-docs.py -vY ../msvc.yaml -i $< -d $(dir $@)

../LINK.exe.md: ./update-yaml.py

docs: ../LINK.exe.md

clean:
	rm -f linkexe_documented.txt

CLEAN: clean
	rm -rf mirrors/cpp-docs ../msvc.backup.yaml ../msvc.dryrun.yaml

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

check: pretty lint vulture

.DEFAULT: all
.PHONY: all black check docs lint pretty prerequisites vulture msvc ../msvc.yaml
.NOTPARALLEL: all clean docs rebuild CLEAN REBUILD
