// Copyright 2022 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "common/error.h"

#include "common/messages.h"
#include "common/utils.h"
#include "common/version.h"

int spdm_write_error(uint8_t code, byte_writer* output) {
  SDPM_ERROR err_msg = {};

  err_msg.preamble.version = SPDM_THIS_VER;
  err_msg.preamble.request_response_code = SPDM_CODE_ERROR;
  err_msg.param_1_error_code = code;

  return write_to_writer(output, &err_msg, sizeof(err_msg));
}
