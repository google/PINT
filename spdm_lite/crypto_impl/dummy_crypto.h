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

#ifndef SPDM_LITE_CRYPTO_IMPL_DUMMY_CRYPTO_H_
#define SPDM_LITE_CRYPTO_IMPL_DUMMY_CRYPTO_H_

#include "spdm_lite/common/crypto_types.h"

// An implementation of the spdm-lite crypto spec that does no real
// cryptography.
extern const SpdmCryptoSpec DUMMY_CRYPTO_SPEC;

#endif  // SPDM_LITE_CRYPTO_IMPL_DUMMY_CRYPTO_H_
