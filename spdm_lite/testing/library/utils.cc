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

#include "spdm_lite/testing/utils.h"

#include <assert.h>
#include <string.h>

#include <algorithm>
#include <iostream>
#include <ostream>
#include <vector>

#include "spdm_lite/common/crypto.h"
#include "spdm_lite/common/crypto_types.h"
#include "spdm_lite/common/key_schedule.h"
#include "spdm_lite/common/messages.h"
#include "spdm_lite/common/session.h"
#include "spdm_lite/common/session_types.h"
#include "spdm_lite/common/sign.h"
#include "spdm_lite/common/utils.h"
#include "spdm_lite/common/vendor_defined_pub_key.h"
#include "spdm_lite/crypto_impl/mbedtls_sign.h"
#include "spdm_lite/testing/host_context.h"

namespace {

// Clang for some reason doesn't like memcpy in .cc files... weird.
void memcopy(uint8_t* dst, const uint8_t* src, uint32_t len) {
  for (int i = 0; i < len; ++i) {
    *dst++ = *src++;
  }
}

}  // namespace

void ExtendHash(SpdmHash* hash, const std::vector<uint8_t>& b) {
  spdm_extend_hash(hash, b.data(), b.size());
}

std::vector<uint8_t> GetDigest(const uint8_t* data, uint32_t len) {
  SpdmHashResult result;

  int rc = spdm_hash(get_mbedtls_crypto_spec(), SPDM_HASH_SHA512, data, len,
                     &result);
  assert(rc == 0);
  (void)rc;

  return std::vector<uint8_t>(result.data, result.data + result.size);
}

std::vector<uint8_t> GetDigest(const SpdmHash& hash) {
  SpdmHashResult digest;

  int rc = spdm_get_hash(&hash, &digest);
  assert(rc == 0);
  (void)rc;

  return std::vector<uint8_t>(digest.data, digest.data + digest.size);
}

SpdmHashResult GetHashResult(const std::vector<uint8_t>& digest) {
  SpdmHashResult result;
  spdm_init_hash_result(&result, SPDM_HASH_SHA512);

  memcopy(result.data, digest.data(), result.size);

  return result;
}

buffer MakeBuffer(std::vector<uint8_t>& vec) {
  return {vec.data(), static_cast<uint32_t>(vec.size())};
}

byte_writer MakeWriter(std::vector<uint8_t>& vec) {
  return {vec.data(), static_cast<uint32_t>(vec.size()), 0};
}

int DispatchRequest(SpdmResponderContext* ctx, std::vector<uint8_t>& req,
                    std::vector<uint8_t>* rsp) {
  size_t output_size = 512;
  std::vector<uint8_t> output(output_size);

  int rc = spdm_dispatch_request(ctx, /*is_secure=*/false, req.data(),
                                 req.size(), output.data(), &output_size);
  if (rc != 0) {
    return rc;
  }

  output.resize(output_size);

  if (rsp != nullptr) {
    *rsp = output;
  }

  return 0;
}

int DispatchSecureRequest(SpdmResponderContext* ctx, SpdmSessionPhase phase,
                          std::vector<uint8_t>& req,
                          std::vector<uint8_t>* rsp) {
  // Borrow the responder's session secrets real quick.
  SpdmSessionParams rsp_session = ctx->session.params;

  std::vector<uint8_t> encrypted_req;

  int rc =
      EncryptMessage(req, rsp_session, SPDM_REQUESTER, phase, &encrypted_req);
  if (rc != 0) {
    std::cerr << "EncryptMessage failed: " << rc << std::endl;
    return rc;
  }

  std::vector<uint8_t> output(512);
  size_t output_size = output.size();

  rc = spdm_dispatch_request(ctx, /*is_secure=*/true, encrypted_req.data(),
                             encrypted_req.size(), output.data(), &output_size);
  if (rc != 0) {
    std::cerr << "spdm_dispatch_secure_request failed: " << rc << std::endl;
    return rc;
  }

  SpdmAeadKeys keys;
  rc = GetSecureMessageKeys(rsp_session, SPDM_RESPONDER, phase, &keys);
  if (rc != 0) {
    std::cerr << "GetSecureMessageKeys failed: " << rc << std::endl;
    return rc;
  }

  buffer response = {output.data(), (uint32_t)output_size};

  rc = spdm_decrypt_secure_message(&ctx->crypto_spec,
                                   &rsp_session.info.session_id,
                                   rsp_session.rsp_seq_num, &keys, &response);
  if (rc != 0) {
    std::cerr << "spdm_decrypt_secure_message failed: " << rc << std::endl;
    return rc;
  }

  if (rsp != nullptr) {
    *rsp = std::vector<uint8_t>(response.data, response.data + response.size);
  }

  return 0;
}

std::vector<uint8_t> MakeGetVersion() {
  std::vector<uint8_t> message(sizeof(SPDM_GET_VERSION));
  *reinterpret_cast<SPDM_GET_VERSION*>(message.data()) = {
      .preamble = {
          .version = 0x10,
          .request_response_code = SPDM_CODE_GET_VERSION,
      }};

  return message;
}

std::vector<uint8_t> MakeGetCapabilities() {
  std::vector<uint8_t> message(sizeof(SPDM_GET_CAPABILITIES));
  *reinterpret_cast<SPDM_GET_CAPABILITIES*>(message.data()) = {
      .preamble =
          {
              .version = 0x12,
              .request_response_code = SPDM_CODE_GET_CAPABILITIES,
          },
      .ct_exponent = 0,
      .flags_ENCRYPT_CAP = 1,
      .flags_MAC_CAP = 1,
      .flags_MUT_AUTH_CAP = 1,
      .flags_KEY_EX_CAP = 1,
      .data_transfer_size = SPDM_HOST_DATA_TRANSFER_SIZE,
      .max_spdm_message_size = SPDM_HOST_DATA_TRANSFER_SIZE,
  };

  return message;
}

std::vector<uint8_t> MakeNegotiateAlgorithms() {
  constexpr size_t kNegotiateAlgsMsgLen =
      sizeof(SPDM_NEGOTIATE_ALGORITHMS) + sizeof(SPDM_AlgStruct_DHE) +
      sizeof(SPDM_AlgStruct_AEAD) + sizeof(SPDM_AlgStruct_BaseAsym) +
      sizeof(SPDM_AlgStruct_KeySchedule);

  std::vector<uint8_t> message(kNegotiateAlgsMsgLen);
  auto* negotiate_algs_msg =
      reinterpret_cast<SPDM_NEGOTIATE_ALGORITHMS*>(message.data());
  auto* dhe_msg = reinterpret_cast<SPDM_AlgStruct_DHE*>(&negotiate_algs_msg[1]);
  auto* aead_msg = reinterpret_cast<SPDM_AlgStruct_AEAD*>(&dhe_msg[1]);
  auto* asym_msg = reinterpret_cast<SPDM_AlgStruct_BaseAsym*>(&aead_msg[1]);
  auto* keyschedule_msg =
      reinterpret_cast<SPDM_AlgStruct_KeySchedule*>(&asym_msg[1]);

  *negotiate_algs_msg = {
      .preamble =
          {
              .version = 0x12,
              .request_response_code = SPDM_CODE_NEGOTIATE_ALGORITHMS,
          },
      .param_1_alg_struct_count = 4,
      .length = kNegotiateAlgsMsgLen,
      .other_params_opaque_data_fmt_1 = 1,
      .asym_hash_algs = {
          .base_asym_alg_ecdsa_ecc_nist_p256 = 1,
          .base_hash_algo_sha_512 = 1,
      }};

  *dhe_msg = {
      .alg_type = SPDM_ALG_TYPE_DHE,
      .alg_count_fixed_width = 2,
      .alg_supported_secp521r1 = 1,
  };

  *aead_msg = {
      .alg_type = SPDM_ALG_TYPE_AEAD,
      .alg_count_fixed_width = 2,
      .alg_supported_aes_256_gcm = 1,
  };

  *asym_msg = {
      .alg_type = SPDM_ALG_TYPE_ASYM,
      .alg_count_fixed_width = 2,
      .alg_supported_ecdsa_ecc_nist_p256 = 1,
  };

  *keyschedule_msg = {
      .alg_type = SPDM_ALG_TYPE_KEYSCHEDULE,
      .alg_count_fixed_width = 2,
      .alg_supported_spdm_key_schedule = 1,
  };

  return message;
}

std::vector<uint8_t> MakeGetPubKey() {
  constexpr size_t kGetPubKeyMsgLen = sizeof(SPDM_VENDOR_DEFINED_REQ_RSP) +
                                      sizeof(uint16_t) +
                                      sizeof(SPDM_VendorDefinedPubKeyEmptyMsg);

  std::vector<uint8_t> message(kGetPubKeyMsgLen);
  auto* vendor_defined_req_msg =
      reinterpret_cast<SPDM_VENDOR_DEFINED_REQ_RSP*>(message.data());
  auto* req_len = reinterpret_cast<uint16_t*>(&vendor_defined_req_msg[1]);
  auto* vendor_defined_pub_key_req =
      reinterpret_cast<SPDM_VendorDefinedPubKeyEmptyMsg*>(&req_len[1]);

  *vendor_defined_req_msg = {
      .preamble =
          {
              .version = 0x12,
              .request_response_code = SPDM_CODE_VENDOR_DEFINED_REQUEST,
          },
      .standard_id = DMTF_STANDARD_ID,
  };

  *req_len = sizeof(*vendor_defined_pub_key_req);

  // TODO(jeffandersen): endianness
  *vendor_defined_pub_key_req = {
      .vd_id = DMTF_VD_ID,
      .vd_req_rsp = DMTF_VD_GET_PUBKEY_CODE,
  };

  return message;
}

std::vector<uint8_t> MakeGivePubKey(const SpdmAsymPubKey& pub_key) {
  SpdmSerializedAsymPubKey serialized_peer_key = {};
  spdm_serialize_asym_key(get_mbedtls_crypto_spec(), &pub_key, SPDM_HASH_SHA512,
                          &serialized_peer_key);

  const size_t kGivePubKeyMsgLen =
      sizeof(SPDM_VENDOR_DEFINED_REQ_RSP) + sizeof(uint16_t) +
      sizeof(SPDM_VendorDefinedPubKeyMsg) + serialized_peer_key.size;

  std::vector<uint8_t> message(kGivePubKeyMsgLen);
  auto* vendor_defined_req_msg =
      reinterpret_cast<SPDM_VENDOR_DEFINED_REQ_RSP*>(message.data());
  auto* req_len = reinterpret_cast<uint16_t*>(&vendor_defined_req_msg[1]);
  auto* vendor_defined_pub_key_req =
      reinterpret_cast<SPDM_VendorDefinedPubKeyMsg*>(&req_len[1]);
  auto* pub_key_bytes =
      reinterpret_cast<uint8_t*>(&vendor_defined_pub_key_req[1]);

  *vendor_defined_req_msg = {
      .preamble =
          {
              .version = 0x12,
              .request_response_code = SPDM_CODE_VENDOR_DEFINED_REQUEST,
          },
      .standard_id = DMTF_STANDARD_ID,
  };

  *req_len = sizeof(*vendor_defined_pub_key_req) + serialized_peer_key.size;

  // TODO(jeffandersen): endianness
  *vendor_defined_pub_key_req = {
      .vd_id = DMTF_VD_ID,
      .vd_req_rsp = DMTF_VD_GIVE_PUBKEY_CODE,
  };

  memcpy(pub_key_bytes, serialized_peer_key.data, serialized_peer_key.size);

  return message;
}

std::vector<uint8_t> MakeKeyExchange(uint8_t req_session_id[2],
                                     const SpdmDhePubKey& dhe_pub_key) {
  const uint16_t kPubKeySize = spdm_get_dhe_pub_key_size(dhe_pub_key.alg);
  const size_t kKeyExchangeMsgLen =
      sizeof(SPDM_KEY_EXCHANGE) + kPubKeySize  // exchange_data
      + sizeof(uint16_t)                       // opaque_data_length
      + sizeof(SPDM_OpaqueDataHeader) + sizeof(SPDM_OpaqueDataElement) +
      sizeof(uint16_t)  // opaque_element_data_len
      + sizeof(SPDM_SecuredMessagesSupportedVersions) +
      sizeof(SPDM_VersionNumberEntry);

  std::vector<uint8_t> message(kKeyExchangeMsgLen +
                               3);  // Up to 3 bytes of padding will be applied.

  auto* key_exchange_msg = reinterpret_cast<SPDM_KEY_EXCHANGE*>(message.data());
  auto* exchange_data = reinterpret_cast<uint8_t*>(&key_exchange_msg[1]);
  auto* opaque_data_length =
      reinterpret_cast<uint16_t*>(exchange_data + kPubKeySize);
  auto* opaque_data_header =
      reinterpret_cast<SPDM_OpaqueDataHeader*>(&opaque_data_length[1]);
  auto* opaque_data_element =
      reinterpret_cast<SPDM_OpaqueDataElement*>(&opaque_data_header[1]);
  auto* opaque_element_data_len =
      reinterpret_cast<uint16_t*>(&opaque_data_element[1]);
  auto* supported_versions =
      reinterpret_cast<SPDM_SecuredMessagesSupportedVersions*>(
          &opaque_element_data_len[1]);
  auto* supported_version =
      reinterpret_cast<SPDM_VersionNumberEntry*>(&supported_versions[1]);

  *key_exchange_msg = {
      .preamble =
          {
              .version = 0x12,
              .request_response_code = SPDM_CODE_KEY_EXCHANGE,
          },
      .param_2_slot_id = 0xFF,
      .req_session_id = {req_session_id[0], req_session_id[1]},
  };

  memcopy(exchange_data, dhe_pub_key.data, kPubKeySize);
  *opaque_data_length =
      sizeof(*opaque_data_header) + sizeof(*opaque_data_element) +
      sizeof(*opaque_element_data_len) + sizeof(*supported_versions) +
      sizeof(*supported_version);

  *opaque_data_header = {
      .total_elements = 1,
  };

  *opaque_data_element = {};
  *opaque_element_data_len =
      sizeof(*supported_versions) + sizeof(*supported_version);
  *supported_versions = {
      .sm_data_version = 1,
      .sm_data_id = 1,
      .num_versions = 1,
  };
  *supported_version = {
      .alpha = 0,
      .update_version = 0,
      .minor_version = 1,
      .major_version = 1,
  };

  // Add padding.
  const uint8_t padding = (4 - (*opaque_data_length % 4)) % 4;
  *opaque_data_length += padding;
  message.resize(kKeyExchangeMsgLen + padding);

  return message;
}

std::vector<uint8_t> MakeFinish(SpdmHash* transcript_hash,
                                const SpdmSessionParams& session,
                                SpdmAsymPrivKey& req_priv_key) {
  const uint16_t kSigSize = spdm_get_asym_signature_size(req_priv_key.alg);
  const size_t kMsgLen = sizeof(SPDM_FINISH) + kSigSize + SHA512_DIGEST_SIZE;

  std::vector<uint8_t> msg(kMsgLen);

  auto* finish_msg = reinterpret_cast<SPDM_FINISH*>(msg.data());
  auto* sig = reinterpret_cast<uint8_t*>(&finish_msg[1]);
  auto* hmac = sig + kSigSize;

  *finish_msg = {
      .preamble{
          .version = 0x12,
          .request_response_code = SPDM_CODE_FINISH,
      },
      .param_1_sig_included = 1,
      .param_2_slot_id = 0xFF,
  };

  spdm_extend_hash(transcript_hash,
                   reinterpret_cast<const uint8_t*>(finish_msg),
                   sizeof(*finish_msg));

  std::vector<uint8_t> digest = GetDigest(*transcript_hash);
  SpdmHashResult digest_result = GetHashResult(digest);

  int rc = spdm_sign(get_mbedtls_crypto_spec(), req_priv_key.alg,
                     reinterpret_cast<void*>(&req_priv_key),
                     /*my_role=*/SPDM_REQUESTER, &digest_result,
                     /*context=*/"finish signing", sig, kSigSize);
  assert(rc == 0);
  (void)rc;

  spdm_extend_hash(transcript_hash, reinterpret_cast<const uint8_t*>(sig),
                   kSigSize);

  SpdmMessageSecrets handshake_secrets;
  SpdmHashResult finish_key;

  rc = spdm_generate_message_secrets(get_mbedtls_crypto_spec(), &session,
                                     SPDM_HANDSHAKE_PHASE, &handshake_secrets);
  assert(rc == 0);
  (void)rc;

  rc = spdm_generate_finished_key(get_mbedtls_crypto_spec(), SPDM_REQUESTER,
                                  &handshake_secrets, &finish_key);
  assert(rc == 0);
  (void)rc;

  digest = GetDigest(*transcript_hash);
  digest_result = GetHashResult(digest);

  SpdmHashResult hmac_result;

  rc = spdm_hmac(get_mbedtls_crypto_spec(), &finish_key, &digest_result,
                 &hmac_result);
  assert(rc == 0);
  (void)rc;

  memcopy(hmac, hmac_result.data, hmac_result.size);

  spdm_extend_hash(transcript_hash, reinterpret_cast<const uint8_t*>(hmac),
                   spdm_get_hash_size(session.info.negotiated_algs.hash_alg));

  return msg;
}

std::vector<uint8_t> MakeEndSession() {
  std::vector<uint8_t> message(sizeof(SPDM_END_SESSION));
  *reinterpret_cast<SPDM_END_SESSION*>(message.data()) = {
      .preamble = {
          .version = 0x12,
          .request_response_code = SPDM_CODE_END_SESSION,
      }};

  return message;
}

int GetSecureMessageKeys(const SpdmSessionParams& session, SPDMRole originator,
                         SpdmSessionPhase phase, SpdmAeadKeys* keys) {
  SpdmMessageSecrets secrets;
  int rc = spdm_generate_message_secrets(get_mbedtls_crypto_spec(), &session,
                                         phase, &secrets);
  if (rc != 0) {
    std::cerr << "spdm_generate_message_secrets failed: " << rc << std::endl;
    return rc;
  }

  SpdmSessionAeadKeys session_keys;
  rc = spdm_generate_aead_keys(get_mbedtls_crypto_spec(), SPDM_AEAD_AES_256_GCM,
                               &secrets, session.req_seq_num,
                               session.rsp_seq_num, &session_keys);
  if (rc != 0) {
    std::cerr << "spdm_generate_aead_keys failed: " << rc << std::endl;
    return rc;
  }

  switch (originator) {
    case SPDM_REQUESTER:
      *keys = session_keys.req_keys;
      break;
    case SPDM_RESPONDER:
      *keys = session_keys.rsp_keys;
      break;
  }

  return 0;
}

int EncryptMessage(const std::vector<uint8_t>& message,
                   const SpdmSessionParams& session, SPDMRole my_role,
                   SpdmSessionPhase phase, std::vector<uint8_t>* output) {
  *output =
      std::vector<uint8_t>(sizeof(SPDM_SecuredMessageRecord) + message.size() +
                           SPDM_MAX_SECURE_MESSAGE_FOOTER_LEN);

  memcopy(output->data() + sizeof(SPDM_SecuredMessageRecord), message.data(),
          message.size());

  byte_writer footer_writer{};
  footer_writer.data =
      output->data() + sizeof(SPDM_SecuredMessageRecord) + message.size();
  footer_writer.size = SPDM_MAX_SECURE_MESSAGE_RAND_LEN + AES_GCM_MAC_SIZE;

  SpdmAeadKeys keys;
  int rc = GetSecureMessageKeys(session, my_role, phase, &keys);
  if (rc != 0) {
    std::cerr << "GetSecureMessageKeys failed: " << rc << std::endl;
    return rc;
  }

  uint64_t seq_num =
      my_role == SPDM_REQUESTER ? session.req_seq_num : session.rsp_seq_num;

  buffer message_buf = {output->data() + sizeof(SPDM_SecuredMessageRecord),
                        static_cast<uint32_t>(message.size())};

  rc = spdm_encrypt_secure_message(get_mbedtls_crypto_spec(),
                                   &session.info.session_id, seq_num, &keys,
                                   output->data(), message_buf, &footer_writer);
  if (rc != 0) {
    std::cerr << "GetSecureMessageKeys failed: " << rc << std::endl;
    return rc;
  }

  // Trim down based on how many random bytes were written.
  output->resize(sizeof(SPDM_SecuredMessageRecord) + message.size() +
                 footer_writer.bytes_written);

  return 0;
}
