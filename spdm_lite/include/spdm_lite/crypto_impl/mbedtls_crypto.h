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

#ifndef SPDM_LITE_CRYPTO_IMPL_MBEDTLS_CRYPTO_H_
#define SPDM_LITE_CRYPTO_IMPL_MBEDTLS_CRYPTO_H_

#include "spdm_lite/common/crypto_types.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

// Provides base functionality for low-level crypto primitives used by
// spdm-lite. Does not provide asymmetric signing or public key serialization.
// See `mbedtls_sign.h` and `raw_serialize.h` for that functionality. Users may
// bring their own as well.
extern const SpdmCryptoSpec MBEDTLS_BASE_CRYPTO_SPEC;

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SPDM_LITE_CRYPTO_IMPL_MBEDTLS_CRYPTO_H_
