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

#ifndef SPDM_LITE_COMMON_VENDOR_DEFINED_PUB_KEY_H_
#define SPDM_LITE_COMMON_VENDOR_DEFINED_PUB_KEY_H_

// This header defines a VENDOR_DEFINED_REQUEST/RESPONSE for exchanging public
// keys, rather than full certificates. This command must only be sent after the
// VCA handshake.
//
// The request message has the following field values:
//
// * StandardID = 0 (DMTF)
// * Len = 0
// * ReqLength = 5
// * VendorDefinedReqPayload[0] = 1
// * VendorDefinedReqPayload[1..4] = "PUBK"
//
// The response message has the following field values:
//
// * StandardID = 0 (DMTF)
// * Len = 0
// * ReqLength = 5 + D
// * VendorDefinedReqPayload[0] = 1
// * VendorDefinedReqPayload[1..4] = "PUBK"
// * VendorDefinedReqPayload[5..] = public key of length D, as selected during
//                                  algorithm negotiation.

#include <stdint.h>

#define DMTF_STANDARD_ID 0
#define DMTF_VD_ID 1
#define DMTF_VD_PUBKEY_CODE 0x6B6D7570  // "PUBK"

typedef struct {
  uint8_t vd_id;  // DMTF_VD_ID
  uint32_t vd_req;  // DMTF_VD_PUBKEY_CODE
} SPDM_VendorDefinedPubKeyReq;

typedef struct {
  uint8_t vd_id;  // DMTF_VD_ID
  uint32_t vd_rsp;  // DMTF_VD_PUBKEY_CODE
  // uint8_t vd_pubkey[D];
} SPDM_VendorDefinedPubKeyRsp;

#endif  // SPDM_LITE_COMMON_VENDOR_DEFINED_PUB_KEY_H_
