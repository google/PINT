# Copyright 2022 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#!/bin/bash

set -e

# From https://github.com/project-everest/everparse/releases/download/v2022.06.13/everparse_v2022.06.13_Linux_x86_64.tar.gz
EVERPARSE="~/everparse/everparse.sh"

TEMP_D=`mktemp -d`

in_file="SPDM.3d"

# Strip path and extension
filename=`basename -- "${in_file}"`
filename="${filename%.*}"

dir=`dirname -- "${in_file}"`

eval "${EVERPARSE} --odir ${TEMP_D} ${in_file}"

mv "${TEMP_D}/${filename}.c" "${dir}/"
mv "${TEMP_D}/${filename}.h" "${dir}/"

rm -rf "${TEMP_D}"
