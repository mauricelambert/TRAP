#!/usr/bin/env bash

# TRAP - Tool for Regex Analysis with Perl
# 2022-01-26
# Maurice LAMBERT <mauricelambert434@gmail.com>
# https://github.com/mauricelambert/TRAP

###################
#    This file compares strings between multiple files
#    Copyright (C) 2022  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

NAME="TRAP";
VERSION="0.0.1";
AUTHOR="Maurice Lambert";
MAINTAINER="Maurice Lambert";
AUTHOR_MAIL='mauricelambert434@gmail.com';
MAINTAINER_MAIL='mauricelambert434@gmail.com';

DESCRIPTION="This file compares strings between multiple files.";
URL="https://github.com/mauricelambert/${NAME}";
LICENSE="GPL-3.0 License";

COPYRIGHT="\n
TRAP (Tool for Regex Analysis with Perl)  Copyright (C) 2022  Maurice Lambert\n
This program comes with ABSOLUTELY NO WARRANTY.\n
This is free software, and you are welcome to redistribute it\n
under certain conditions.\n
"

NAME_ARTS='

____________________________________________
_|_____|____|____|_________|______|____|____
__|_____|_____|____|___|_______|____|____|__
\_      __/\____     \__/  _  \__\____  _  \
__|    |_|__|       _/_/  /_\  \__|     ___/
|_|    |____|    |   \/    |    \_|    |_|__
__|____|_|__|____|_  /\____|__  /_|____|__|_
___|_____|____|____\/___|_____\/____|____|__
__|_____|___|____|_______|___|_____|___|____

'

echo -e $COPYRIGHT
printf "%s\n" "${NAME_ARTS}"

if [[ $# -eq 0 ]]; then
    echo "USAGES: bash StringsCompare.sh file1 files* ..."
    echo "ERROR: file(s) argument(s) is/are required."
    exit 1
fi

declare -A _founds
declare -A files_founds

for file in "$@"; do
     tmp_strings=$(strings -n 6 "${file}")
     files_founds["${file}"]="${tmp_strings}"
done

tmp_strings=""

for file in "${!files_founds[@]}"; do
     for file_in in "${!files_founds[@]}"; do
        if [[ "${file_in}" != "${file}" ]]; then
            while read string; do
                if [[ ${#string} -gt 5 && "${files_founds[${file_in}]}" == *"${string}"* ]]; then
                        if [[ "${_founds[-${string}-]}" != *"<${file_in}>"* ]]; then
                            if [[ -z ${_founds[-$string-]+x} ]]; then
                                _founds[-$string-]="<${file_in}>"
                            else
                                _founds[-$string-]+="|<${file_in}>"
                            fi
                        fi

                    if [[ "${_founds[-${string}-]}" == *"<${file}>"* ]]; then
                        continue
                    # elif [[ ${#string} -gt 5 && -z ${_founds[-$string-]+x} ]]; then
                    #     _founds[$string]="-${file}-|-${file_in}-"
                    # elif [[ -n ${_founds[-$string-]} ]]; then
                    else
                        _founds[-$string-]+="|<${file}>"
                    fi
                fi
            done <<< "${files_founds[${file}]}"
        fi
    done
done

echo '"File number","Files","Match"' > "matches.csv"

for found in "${!_founds[@]}"; do
    substring=${_founds[$found]//[^|]}
    number=$((${#substring}+1))
    if [[ ${number} -gt 1 ]]; then
        files="${_founds[$found]//|/ }"
        echo "[${number}] ${files} : ${found}"
        echo "\"${number}\",\"${files}\",\"${found//\"/\'}\"" >> "matches.csv"
    fi
done

exit 0