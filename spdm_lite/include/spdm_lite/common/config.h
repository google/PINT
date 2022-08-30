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

#ifndef SPDM_LITE_COMMON_CONFIG_H_
#define SPDM_LITE_COMMON_CONFIG_H_

// This file contains configuration values for SPDM-Lite. They can be overridden
// by defining an `SPDM_CONFIG_FILE`.

#ifdef SPDM_CONFIG_FILE
#include SPDM_CONFIG_FILE
#endif

#ifndef SPDM_MAX_HASH_CTX_SIZE
// Enough space for a reasonable implementation to hold a SHA512 hash context.
#define SPDM_MAX_HASH_CTX_SIZE 256
#endif

#ifndef SPDM_MAX_SERIALIZED_ASYM_PUB_KEY_SIZE
// An (x || y) pair of ECDSA P521 coordinates.
#define SPDM_MAX_SERIALIZED_ASYM_PUB_KEY_SIZE (2 * 66)
#endif

#endif  // SPDM_LITE_COMMON_CONFIG_H_
