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

#ifndef SPDM_LITE_SAMPLES_RESPONDER_APP_H_
#define SPDM_LITE_SAMPLES_RESPONDER_APP_H_

// This file declares an entry-point for a sample SPDM app that performs ROT-128
// on a given uint8_t and returns the result.
//
// Application requests are required to be encapsulated within a vendor-defined
// command whose standard_id is 0x1701 and whose vendor_id is 0x42.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SAMPLE_APP_STANDARD_ID 0x1701
#define SAMPLE_APP_VENDOR_ID 0x42

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

// Dispatches an incoming SPDM request. `is_secure` indicates whether `req`
// holds an encrypted or plaintext SPDM request. `rsp_size` is an input/output
// argument.
int sample_app_dispatch_spdm_request(bool is_secure, const uint8_t* req,
                                     size_t req_size, uint8_t* rsp,
                                     size_t* rsp_size);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SPDM_LITE_SAMPLES_RESPONDER_APP_H_
