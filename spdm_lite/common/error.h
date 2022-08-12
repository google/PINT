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

#ifndef SPDM_LITE_COMMON_ERROR_H_
#define SPDM_LITE_COMMON_ERROR_H_

#include <stdint.h>

#include "common/utils.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

// Table 48
enum SpdmErrorCode {
  SPDM_ERR_INVALID_REQUEST = 0x01,
  SPDM_ERR_BUSY = 0x03,
  SPDM_ERR_UNSPECIFIED = 0x05,
  SPDM_ERR_VERSION_MISMATCH = 0x41,
  SPDM_ERR_SESSION_REQURED = 0x0B,
  // TODO(jeffandersen): fill in.
};

// Writes an SPDM ERROR message to the given output buffer, with no extended
// error data.
int spdm_write_error(uint8_t code, byte_writer* output);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SPDM_LITE_COMMON_ERROR_H_
