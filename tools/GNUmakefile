PYSCRIPTS:=update-yaml.py update-docs.py IDAPython/toolchain_prepare.py
UPDDOCS:=./update-docs.py
UPDYAML:=./update-yaml.py
ifneq ($(PIPENV_ACTIVE),1) # use the shell wrapper scripts instead, which prepare and enter the venv
UPDDOCS:=$(patsubst %.py,%,$(UPDDOCS))
UPDYAML:=$(patsubst %.py,%,$(UPDYAML))
endif
all: linkexe_documented.txt black lint vulture msvc.yaml

mirrors:
	test -d $@ || mkdir $@

mirrors/www.geoffchappell.com/studies/msvc: mirrors
	cd $< && wget --mirror --convert-links --adjust-extension --page-requisites --exclude-directories=studies/windows,studies/msvc/libraries/atl --no-parent https://www.geoffchappell.com/studies/msvc

mirrors/cpp-docs: mirrors
	test -d "$@" || git -C "$(dir $@)" clone https://github.com/MicrosoftDocs/cpp-docs.git
	git -C mirrors/cpp-docs clean -dfx
	git -C mirrors/cpp-docs reset --hard

mirrors/cpp-docs/docs/build/reference/linker-options.md mirrors/cpp-docs/docs/build/reference/compiler-options-listed-alphabetically.md: mirrors/cpp-docs

linkexe_documented.txt: mirrors/cpp-docs/docs/build/reference/linker-options.md mirrors/cpp-docs
	rg  '\| \[`(/[^`]+)' -or '$$1' mirrors/cpp-docs/docs/build/reference/linker-options.md |cut -d : -f 2|tr 'A-Z' 'a-z'|sort -u|tee $@

clexe_documented.txt: mirrors/cpp-docs/docs/build/reference/linker-options.md mirrors/cpp-docs
	rg  '\| \[`(/[^`]+)' -or '$$1' mirrors/cpp-docs/docs/build/reference/compiler-options-listed-alphabetically.md |cut -d : -f 2|tr 'A-Z' 'a-z'|sort -u|tee $@

documented: linkexe_documented.txt clexe_documented.txt mirrors/www.geoffchappell.com/studies/msvc

msvc: black lint yaml

yaml: ../msvc.yaml

../msvc.yaml: update-yaml.py documented
	$(UPDYAML) -vY $@

../%: %.j2
	$(UPDDOCS) -vY ../msvc.yaml -i $< -d $(dir $@)

../LINK.exe.md: ./update-yaml.py

docs: ../LINK.exe.md

clean-docs:
	rm -f ../LINK.exe.md

redocs: clean-docs docs

clean:
	rm -f clexe_documented.txt linkexe_documented.txt

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
.PHONY: all black check docs documented lint pretty prerequisites vulture msvc yaml mirrors/cpp-docs redocs clean-docs
.NOTPARALLEL: all clean docs documented rebuild CLEAN REBUILD redocs clean-docs
