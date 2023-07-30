#!/usr/bin/env bash
# SPDX-License-Identifier: Unlicense
[[ -t 1 ]] && { cG="\e[1;32m"; cR="\e[1;31m"; cB="\e[1;34m"; cW="\e[1;37m"; cY="\e[1;33m"; cG_="\e[0;32m"; cR_="\e[0;31m"; cB_="\e[0;34m"; cW_="\e[0;37m"; cY_="\e[0;33m"; cZ="\e[0m"; export cR cG cB cY cW cR_ cG_ cB_ cY_ cW_ cZ; }
for tool in dirname env find readlink; do type $tool > /dev/null 2>&1 || { echo -e "${cR}ERROR:${cZ} couldn't find '$tool' which is required by this script."; exit 1; }; done
pushd $(dirname $0) > /dev/null; CURRABSPATH=$(readlink -nf "$(pwd)"); popd > /dev/null; # Get the directory in which the script resides
# Allow our callers to override the name (think clang-format-13 or similar stuff)
CLANGFMT=${CLANGFMT:-"clang-format"}

if [[ "$CLANGFMT" == "clang-format" ]] && [[ -n "$COMSPEC" ]]; then # assume Windows
	for tool in cygpath; do type $tool > /dev/null 2>&1 || { echo -e "${cR}ERROR:${cZ} couldn't find '$tool' which is required by this script."; exit 1; }; done
	PF86="$(cygpath -amF 42)"
	VSWHERE="$PF86/Microsoft Visual Studio/Installer/vswhere.exe"
	echo -e "${cG}VSWHERE${cZ}=$VSWHERE"
	if [[ -f "$VSWHERE" && -x "$VSWHERE" ]]; then
		WIN_VSINSTPATH="$(set -x; "$VSWHERE" -products \* -format value -property installationPath -latest)"
		VSINSTPATH="$(cygpath -u "$WIN_VSINSTPATH")"
		if [[ -n "$VSINSTPATH" ]]; then
			echo -e "${cG}VSINSTPATH${cZ}=$VSINSTPATH"
			LLVMPATH="$VSINSTPATH/VC/Tools/Llvm/bin"
			if [[ ! -d "$LLVMPATH" ]]; then
				echo -e "${cR}ERROR:${cZ} couldn't find '$LLVMPATH' inside of which we hoped to find '$CLANGFMT'."; exit 1
			fi
			if (export PATH="$LLVMPATH:$PATH"; "$CLANGFMT" --version 2> /dev/null); then
				export PATH="$LLVMPATH:$PATH"
			else
				echo -e "${cR}ERROR:${cZ} couldn't find '$CLANGFMT' inside '$LLVMPATH'."; exit 1
			fi
		fi
	else
		echo -e "${cR}ERROR:${cZ} couldn't find '$VSWHERE' which is required by this script, unless you have set ${cW}CLANGFMT${cZ} to point to ${cW}clang-format${cZ}."; exit 1
	fi
else
	echo "$CLANGFMT"
fi

command find -type f \( -name '*.cpp' -o -name '*.h' -o -name '*.hpp' \) |while read fname; do
	case "${fname#./}" in
		# Ignore a bunch of folders
		bin/* | obj/* | .vs/* ) ;;
		# Only process what remains
		*)
			echo -e "Formatting: ${cW}${fname#./}${cZ}"
			( set -x; "$CLANGFMT" -i "${fname#./}" )
			;;
	esac
done
