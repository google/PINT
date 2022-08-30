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

#include "spdm_lite/common/vendor_defined_pub_key.h"

#include <string.h>

#include "spdm_lite/common/crypto.h"
#include "spdm_lite/common/crypto_types.h"
#include "spdm_lite/common/messages.h"
#include "spdm_lite/common/utils.h"
#include "spdm_lite/common/version.h"
#include "spdm_lite/everparse/SPDMWrapper.h"

static int write_empty_msg(bool is_request, uint64_t vd_code,
                           byte_writer* output) {
  SPDM_VENDOR_DEFINED_REQ_RSP vendor_defined_msg = {};
  SPDM_VendorDefinedPubKeyEmptyMsg pub_key_msg = {};
  uint16_t req_len = sizeof(pub_key_msg);

  vendor_defined_msg.preamble.version = SPDM_THIS_VER;
  vendor_defined_msg.preamble.request_response_code =
      is_request ? SPDM_CODE_VENDOR_DEFINED_REQUEST
                 : SPDM_CODE_VENDOR_DEFINED_RESPONSE;
  vendor_defined_msg.standard_id = DMTF_STANDARD_ID;

  pub_key_msg.vd_id = DMTF_VD_ID;
  pub_key_msg.vd_req_rsp = vd_code;

  const uint32_t msg_len =
      sizeof(vendor_defined_msg) + sizeof(req_len) + sizeof(pub_key_msg);

  uint8_t* out = reserve_from_writer(output, msg_len);
  if (out == NULL) {
    return -1;
  }

  memcpy(out, &vendor_defined_msg, sizeof(vendor_defined_msg));
  out += sizeof(vendor_defined_msg);

  // TODO(jeffandersen): endianness.
  memcpy(out, &req_len, sizeof(req_len));
  out += sizeof(req_len);

  memcpy(out, &pub_key_msg, sizeof(pub_key_msg));
  out += sizeof(pub_key_msg);

  return 0;
}

static int check_empty_msg(buffer input, bool is_request, uint64_t vd_code) {
  int rc;
  uint16_t standard_id;
  buffer vendor_id;
  buffer payload;
  SPDM_VendorDefinedPubKeyEmptyMsg pub_key_msg;

  if (is_request) {
    rc = SpdmCheckVendorDefinedRequest(&input, /*rest=*/NULL, &standard_id,
                                       &vendor_id.data, &vendor_id.size,
                                       &payload.data, &payload.size);
  } else {
    rc = SpdmCheckVendorDefinedResponse(&input, /*rest=*/NULL, &standard_id,
                                        &vendor_id.data, &vendor_id.size,
                                        &payload.data, &payload.size);
  }

  if (rc != 0) {
    return -1;
  }

  if (standard_id != DMTF_STANDARD_ID || vendor_id.size != 0 ||
      payload.size != sizeof(pub_key_msg)) {
    return -1;
  }

  memcpy(&pub_key_msg, payload.data, sizeof(pub_key_msg));

  // TODO(jeffandersen): endianness
  if (pub_key_msg.vd_id != DMTF_VD_ID || pub_key_msg.vd_req_rsp != vd_code) {
    return -1;
  }

  return 0;
}

static int write_pub_key_msg(const SpdmCryptoSpec* crypto_spec, bool is_request,
                             uint64_t vd_code, const SpdmAsymPubKey* pub_key,
                             SpdmHashAlgorithm hash_alg, byte_writer* output) {
  SPDM_VENDOR_DEFINED_REQ_RSP vendor_defined_msg = {};
  SPDM_VendorDefinedPubKeyMsg pub_key_msg = {};
  SpdmSerializedAsymPubKey serialized_pub_key;
  uint8_t* out;

  int rc = spdm_serialize_asym_key(crypto_spec, pub_key, hash_alg,
                                   &serialized_pub_key);
  if (rc != 0) {
    return rc;
  }

  uint16_t rsp_len = sizeof(pub_key_msg) + serialized_pub_key.size;
  uint32_t out_len = sizeof(vendor_defined_msg) + sizeof(rsp_len) + rsp_len;

  out = reserve_from_writer(output, out_len);
  if (out == NULL) {
    return -1;
  }

  vendor_defined_msg.preamble.version = SPDM_THIS_VER;
  vendor_defined_msg.preamble.request_response_code =
      is_request ? SPDM_CODE_VENDOR_DEFINED_REQUEST
                 : SPDM_CODE_VENDOR_DEFINED_RESPONSE;
  vendor_defined_msg.standard_id = DMTF_STANDARD_ID;
  vendor_defined_msg.vendor_id_len = 0;

  pub_key_msg.vd_id = DMTF_VD_ID;
  // TODO(jeffandersen): endianness
  pub_key_msg.vd_req_rsp = vd_code;

  memcpy(out, &vendor_defined_msg, sizeof(vendor_defined_msg));
  out += sizeof(vendor_defined_msg);

  memcpy(out, &rsp_len, sizeof(rsp_len));
  out += sizeof(rsp_len);

  memcpy(out, &pub_key_msg, sizeof(pub_key_msg));
  out += sizeof(pub_key_msg);

  memcpy(out, serialized_pub_key.data, serialized_pub_key.size);
  return 0;
}

static int check_pub_key_msg(const SpdmCryptoSpec* crypto_spec, buffer input,
                             bool is_request, uint64_t vd_code,
                             SpdmAsymAlgorithm asym_alg,
                             SpdmHashAlgorithm hash_alg,
                             SpdmAsymPubKey* pub_key) {
  int rc;
  uint16_t standard_id;
  buffer vendor_id;
  buffer payload;
  SPDM_VendorDefinedPubKeyMsg pub_key_msg;

  if (is_request) {
    rc = SpdmCheckVendorDefinedRequest(&input, /*rest=*/NULL, &standard_id,
                                       &vendor_id.data, &vendor_id.size,
                                       &payload.data, &payload.size);
  } else {
    rc = SpdmCheckVendorDefinedResponse(&input, /*rest=*/NULL, &standard_id,
                                        &vendor_id.data, &vendor_id.size,
                                        &payload.data, &payload.size);
  }

  if (rc != 0) {
    return rc;
  }

  if (standard_id != DMTF_STANDARD_ID || vendor_id.size != 0) {
    return -1;
  }

  if (payload.size < sizeof(pub_key_msg)) {
    return -1;
  }

  consume_from_buffer(&payload, &pub_key_msg, sizeof(pub_key_msg));

  if (pub_key_msg.vd_id != DMTF_VD_ID || pub_key_msg.vd_req_rsp != vd_code) {
    return -1;
  }

  return spdm_deserialize_asym_key(crypto_spec, asym_alg, hash_alg,
                                   payload.data, payload.size, pub_key);
}

int spdm_write_get_pub_key_req(byte_writer* output) {
  return write_empty_msg(/*is_request=*/true, DMTF_VD_GET_PUBKEY_CODE, output);
}

int spdm_check_get_pub_key_req(buffer input) {
  return check_empty_msg(input, /*is_request=*/true, DMTF_VD_GET_PUBKEY_CODE);
}

int spdm_write_get_pub_key_rsp(const SpdmCryptoSpec* crypto_spec,
                               const SpdmAsymPubKey* pub_key,
                               SpdmHashAlgorithm hash_alg,
                               byte_writer* output) {
  return write_pub_key_msg(crypto_spec, /*is_request=*/false,
                           DMTF_VD_GET_PUBKEY_CODE, pub_key, hash_alg, output);
}

int spdm_check_get_pub_key_rsp(const SpdmCryptoSpec* crypto_spec, buffer input,
                               SpdmAsymAlgorithm asym_alg,
                               SpdmHashAlgorithm hash_alg,
                               SpdmAsymPubKey* pub_key) {
  return check_pub_key_msg(crypto_spec, input, /*is_request=*/false,
                           DMTF_VD_GET_PUBKEY_CODE, asym_alg, hash_alg,
                           pub_key);
}

int spdm_write_give_pub_key_req(const SpdmCryptoSpec* crypto_spec,
                                const SpdmAsymPubKey* pub_key,
                                SpdmHashAlgorithm hash_alg,
                                byte_writer* output) {
  return write_pub_key_msg(crypto_spec, /*is_request=*/true,
                           DMTF_VD_GIVE_PUBKEY_CODE, pub_key, hash_alg, output);
}

int spdm_check_give_pub_key_req(const SpdmCryptoSpec* crypto_spec, buffer input,
                                SpdmAsymAlgorithm asym_alg,
                                SpdmHashAlgorithm hash_alg,
                                SpdmAsymPubKey* pub_key) {
  return check_pub_key_msg(crypto_spec, input, /*is_request=*/true,
                           DMTF_VD_GIVE_PUBKEY_CODE, asym_alg, hash_alg,
                           pub_key);
}

int spdm_write_give_pub_key_rsp(byte_writer* output) {
  return write_empty_msg(/*is_request=*/false, DMTF_VD_GIVE_PUBKEY_CODE,
                         output);
}

int spdm_check_give_pub_key_rsp(buffer input) {
  return check_empty_msg(input, /*is_request=*/false, DMTF_VD_GIVE_PUBKEY_CODE);
}
