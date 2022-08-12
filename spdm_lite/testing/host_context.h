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

#ifndef SPDM_LITE_TESTING_HOST_CONTEXT_H_
#define SPDM_LITE_TESTING_HOST_CONTEXT_H_

#include "common/crypto_types.h"
#include "crypto_impl/mbedtls_crypto.h"
#include "requester/requester.h"
#include "responder/responder.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#define SPDM_HOST_CT_EXPONENT 10
#define SPDM_HOST_DATA_TRANSFER_SIZE 1024

void initialize_host_requester_context(SpdmAsymPrivKey* priv_key,
                                       SpdmAsymPubKey* pub_key,
                                       SpdmResponderContext* target_responder,
                                       SpdmRequesterContext* ctx);

void initialize_host_responder_context(
    SpdmAsymPrivKey* priv_key, SpdmAsymPubKey* pub_key,
    SpdmResponderContext* ctx,
    spdm_app_dispatch_request_fn app_fn);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SPDM_LITE_TESTING_HOST_CONTEXT_H_
