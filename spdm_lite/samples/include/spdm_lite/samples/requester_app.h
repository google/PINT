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

#ifndef SPDM_LITE_SAMPLES_REQUESTER_APP_H_
#define SPDM_LITE_SAMPLES_REQUESTER_APP_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

// Should be called first. Initializes the session.
int sample_app_initialize_spdm_session(void);

// Passes `input` to the Responder via a secure SPDM channel, which performs
// ROT128 on the input. Writes the result to `output`.
int sample_app_rot128_byte(uint8_t input, uint8_t* output);

// Tears down the session.
int sample_app_end_spdm_session(void);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SPDM_LITE_SAMPLES_REQUESTER_APP_H_
