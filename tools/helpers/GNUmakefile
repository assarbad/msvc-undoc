PYSCRIPTS:=normalize-buildlogs.py
ifneq ($(COMSPEC)$(ComSpec),)
BLACK:=py -3 -m black
FLAKE8:=py -3 -m flake8
VULTURE:=py -3 -m vulture
else
BLACK:=black
FLAKE8:=flake8
VULTURE:=vulture
endif
all: black lint vulture

lint: $(PYSCRIPTS)
	$(FLAKE8) $^

pretty: black

black: $(PYSCRIPTS)
	$(BLACK) $^

vulture: $(PYSCRIPTS)
	$(VULTURE) $^

check: pretty lint vulture

.DEFAULT: all
.PHONY: all black check lint pretty vulture
.NOTPARALLEL: all
