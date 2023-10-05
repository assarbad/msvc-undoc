#!/usr/bin/env bash
FNAME="ntnative.h"
declare -a FCTNAMES=()
while read -r fctname; do
	# echo "$fctname"
	NO_T=${fctname%_t}
	FCTNAMES+=("$NO_T")
	COUNTX=$(grep -v "^#" "$FNAME"|grep -cP "$NO_T\\W")
	COUNTY=$(grep -v "^#" "$FNAME"|grep -cP "$fctname\\W")
	if ((COUNTX == 1)) && ((COUNTY == 1)); then
		: # "balanced"
	elif ((COUNTX == 0)) && ((COUNTY == 1)); then
		if ! grep -P "$fctname\\W" "$FNAME"|grep -q '// winternl\.h'; then
			printf "Type found, but not marked as winternl.h: %s exists %d/%d times\n" "$NO_T" "$COUNTX" "$COUNTY"
		else
			: # winternl.h-declared function for which we only declare the type!
		fi
	else
		printf "UNICORN: %s exists %d/%d times\n" "$NO_T" "$COUNTX" "$COUNTY"
	fi
done < <(set -x; grep -P 'typedef\s+?\w+?\s*?\(NTAPI\s*?\*\s*?(?:Rtl|Nt|Ldr)\w+?_t(?!>\))' "$FNAME"|grep -Po '(?:Rtl|Nt|Ldr)\w+?_t(?!>\))'|sort -u)

for fct in "${FCTNAMES[@]}"; do
	case "$fct" in
	Nt*)
		printf "#define %s %s\n" "Zw${fct#Nt}" "$fct"
		;;
	esac
done

test -d "ntdll-stubs" || mkdir "ntdll-stubs"
(
	echo -e "LIBRARY ntdll.dll\n"
	echo "EXPORTS"
	for fct in "${FCTNAMES[@]}"; do
		echo "    $fct"
	done
) > "ntdll-stubs/ntdll.def"
