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

// This header defines VENDOR_DEFINED_REQUEST/RESPONSE messages for exchanging
// public keys, rather than full certificates.
//
// GET_PUB_KEY must only be sent after the VCA handshake. GIVE_PUB_KEY must be
// sent after KEY_EXCHANGE and before FINISH.
//
// Note: these vendor-defined commands have not been endorsed by DMTF or any
// other standards body.
//
// The GET_PUB_KEY request message has the following field values:
//
// * StandardID = 0 (DMTF)
// * Len = 0
// * ReqLength = 5
// * VendorDefinedReqPayload[0] = 1
// * VendorDefinedReqPayload[1..8] = "GET_PUBK"
//
// The GET_PUB_KEY response message has the following field values:
//
// * StandardID = 0 (DMTF)
// * Len = 0
// * ReqLength = 5 + D
// * VendorDefinedReqPayload[0] = 1
// * VendorDefinedReqPayload[1..8] = "GET_PUBK"
// * VendorDefinedReqPayload[9..] = public key of length D, as selected during
//                                  algorithm negotiation.
//
// The GIVE_PUB_KEY request message has the following field values:
//
// * StandardID = 0 (DMTF)
// * Len = 0
// * ReqLength = 5 + D
// * VendorDefinedReqPayload[0] = 1
// * VendorDefinedReqPayload[1..8] = "GIVE_PUB"
// * VendorDefinedReqPayload[9..] = public key of length D, as selected during
//                                  algorithm negotiation.
//
// The GIVE_PUB_KEY response message has the following field values:
//
// * StandardID = 0 (DMTF)
// * Len = 0
// * ReqLength = 5
// * VendorDefinedReqPayload[0] = 1
// * VendorDefinedReqPayload[1..8] = "GIVE_PUB"

#include <stdint.h>

#include "spdm_lite/common/crypto_types.h"
#include "spdm_lite/common/utils.h"

#define DMTF_STANDARD_ID 0
#define DMTF_VD_ID 1
#define DMTF_VD_GET_PUBKEY_CODE 0x4B4255505F544547   // "GET_PUBK"
#define DMTF_VD_GIVE_PUBKEY_CODE 0x4255505F45564947  // "GIVE_PUB"

// Either a GET_PUB_KEY request or a GIVE_PUB_KEY response.
typedef struct {
  uint8_t vd_id;        // DMTF_VD_ID
  uint64_t vd_req_rsp;  // DMTF_VD_[GET/GIVE]_PUBKEY_CODE
} SPDM_VendorDefinedPubKeyEmptyMsg;

// Either a GET_PUB_KEY response or a GIVE_PUB_KEY request.
typedef struct {
  uint8_t vd_id;        // DMTF_VD_ID
  uint64_t vd_req_rsp;  // DMTF_VD_[GET/GIVE]_PUBKEY_CODE
  // uint8_t vd_pubkey[D];
} SPDM_VendorDefinedPubKeyMsg;

int spdm_write_get_pub_key_req(byte_writer* output);
int spdm_check_get_pub_key_req(buffer input);

int spdm_write_get_pub_key_rsp(const SpdmAsymPubKey* pub_key,
                               byte_writer* output);
int spdm_check_get_pub_key_rsp(buffer input, SpdmAsymAlgorithm alg,
                               SpdmAsymPubKey* pub_key);

int spdm_write_give_pub_key_req(const SpdmAsymPubKey* pub_key,
                                byte_writer* output);
int spdm_check_give_pub_key_req(buffer input, SpdmAsymAlgorithm alg,
                                SpdmAsymPubKey* pub_key);

int spdm_write_give_pub_key_rsp(byte_writer* output);
int spdm_check_give_pub_key_rsp(buffer input);

#endif  // SPDM_LITE_COMMON_VENDOR_DEFINED_PUB_KEY_H_
