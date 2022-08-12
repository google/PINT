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



#ifndef __SPDM_H
#define __SPDM_H

#if defined(__cplusplus)
extern "C"
{
#endif

#include "EverParse.h"
#define SPDM____GET_VERSION ((uint8_t)0x84U)

#define SPDM____GET_CAPABILITIES ((uint8_t)0xE1U)

#define SPDM____NEGOTIATE_ALGORITHMS ((uint8_t)0xE3U)

#define SPDM____GET_MEASUREMENTS ((uint8_t)0xE0U)

#define SPDM____KEY_EXCHANGE ((uint8_t)0xE4U)

#define SPDM____GET_ENCAPSULATED_REQUEST ((uint8_t)0xEAU)

#define SPDM____DELIVER_ENCAPSULATED_RESPONSE ((uint8_t)0xEBU)

#define SPDM____END_SESSION ((uint8_t)0xECU)

#define SPDM____FINISH ((uint8_t)0xE5U)

#define SPDM____VENDOR_DEFINED_REQUEST ((uint8_t)0xFEU)

#define SPDM____VERSION ((uint8_t)0x04U)

#define SPDM____CAPABILITIES ((uint8_t)0x61U)

#define SPDM____ALGORITHMS ((uint8_t)0x63U)

#define SPDM____MEASUREMENTS ((uint8_t)0x60U)

#define SPDM____KEY_EXCHANGE_RSP ((uint8_t)0x64U)

#define SPDM____ENCAPSULATED_REQUEST ((uint8_t)0x6AU)

#define SPDM____ENCAPSULATED_RESPONSE_ACK ((uint8_t)0x6BU)

#define SPDM____END_SESSION_ACK ((uint8_t)0x6CU)

#define SPDM____FINISH_RSP ((uint8_t)0x65U)

#define SPDM____VENDOR_DEFINED_RESPONSE ((uint8_t)0x7EU)

#define SPDM____ERROR ((uint8_t)0x7FU)

    uint64_t
    SpdmValidateGetVersion(
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

#define SPDM____MAX_VERSION_NUMBER_ENTRY_COUNT ((uint8_t)16U)

    uint64_t
    SpdmValidateVersion(
        uint8_t *OutEntryCount,
        uint8_t **OutEntries,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateGetCapabilities(
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateCapabilities(
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

#define SPDM____MAX_ALGS ((uint8_t)20U)

/*
Enum constant
*/
#define SPDM____ALGTYPE_DHE ((uint8_t)2U)

/*
Enum constant
*/
#define SPDM____ALGTYPE_AEAD ((uint8_t)3U)

/*
Enum constant
*/
#define SPDM____ALGTYPE_ASYM ((uint8_t)4U)

/*
Enum constant
*/
#define SPDM____ALGTYPE_KEYSCHEDULE ((uint8_t)5U)

    uint64_t
    SpdmValidateNegotiateAlgorithms(
        uint8_t **OutExtAsymAlgs,
        uint32_t *OutExtAsymCount,
        uint8_t **OutExtHashAlgs,
        uint32_t *OutExtHashCount,
        uint8_t **OutAlgStructs,
        uint32_t *OutAlgStructCount,
        uint32_t *OutAlgStructsLen,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateAlgorithms(
        uint8_t **OutExtAsymAlgs,
        uint32_t *OutExtAsymCount,
        uint8_t **OutExtHashAlgs,
        uint32_t *OutExtHashCount,
        uint8_t **OutAlgStructs,
        uint32_t *OutAlgStructCount,
        uint32_t *OutAlgStructsLen,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateDheAlg(
        BOOLEAN IsResp,
        uint32_t *OutAlgCountExtended,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateAeadAlg(
        BOOLEAN IsResp,
        uint32_t *OutAlgCountExtended,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateAsymAlg(
        BOOLEAN IsResp,
        uint32_t *OutAlgCountExtended,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateKeySchedule(
        BOOLEAN IsResp,
        uint32_t *OutAlgCountExtended,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateGetMeasurements(
        BOOLEAN *OutSignatureRequested,
        BOOLEAN *OutRawBitstreamRequested,
        uint8_t *OutOperation,
        uint8_t **OutNonce,
        uint8_t *OutSlotId,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateMeasurements(
        BOOLEAN ExpectMeasurementCount,
        BOOLEAN ExpectSignature,
        uint32_t SignatureLen,
        uint8_t *OutSlotId,
        uint8_t *OutContentChanged,
        uint32_t *OutNumberOfBlocks,
        uint32_t *OutRecordLength,
        uint8_t **OutRecordData,
        uint8_t **OutNonce,
        uint16_t *OutOpaqueDataLength,
        uint8_t **OutOpaqueData,
        uint8_t **OutSignature,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

#define SPDM____MEASUREMENT_SPEC_DMTF ((uint8_t)0U)

    uint64_t
    SpdmValidateMeasurementBlock(
        uint8_t *OutIndex,
        uint8_t *OutMeasurementSpec,
        uint16_t *OutMeasurementSize,
        uint8_t **OutMeasurement,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateDmtfMeasurement(
        BOOLEAN *OutRawBitstream,
        uint8_t *OutValueType,
        uint16_t *OutValueSize,
        uint8_t **OutValue,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateKeyExchange(
        uint32_t ExchangeDataLen,
        uint8_t *OutRequestedMeasurementSummaryType,
        uint8_t *OutSlotId,
        uint8_t **OutReqSessionId,
        BOOLEAN *OutSessionPolicyTermination,
        uint8_t **OutExchangeData,
        uint8_t **OutOpaqueData,
        uint32_t *OutOpaqueDataLen,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateKeyExchangeRsp(
        uint32_t ExchangeDataLen,
        uint32_t HashLen,
        uint32_t SignatureLen,
        BOOLEAN MeasurementSummaryHashExpected,
        BOOLEAN ResponderVerifyDataExpected,
        uint8_t *OutHeartbeatPeriod,
        uint8_t **OutRspSessionId,
        uint8_t *OutMutAuthRequestedFlow,
        uint8_t *OutSlotId,
        uint8_t **OutExchangeData,
        uint8_t **OutMeasurementSummaryHash,
        uint8_t **OutOpaqueData,
        uint32_t *OutOpaqueDataLen,
        uint8_t **OutSignature,
        uint8_t **OutResponderVerifyData,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateGetEncapsulatedRequest(
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateEncapsulatedRequest(
        uint8_t *OutRequestId,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateDeliverEncapsulatedResponse(
        uint8_t *OutRequestId,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateEncapsulatedResponseAck(
        uint8_t *OutRequestId,
        uint8_t *OutPayloadType,
        uint8_t *OutAckRequestId,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateEndSession(
        BOOLEAN *OutPreserveNegotiatedState,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateEndSessionAck(
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateFinish(
        uint32_t HashLen,
        uint32_t SignatureLen,
        BOOLEAN *OutSigIncluded,
        uint8_t *OutSlotId,
        uint8_t **OutSig,
        uint8_t **OutVerifyData,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateFinishRsp(
        uint32_t HashLen,
        BOOLEAN ResponderVerifyDataExpected,
        uint8_t **OutResponderVerifyData,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateVendorDefinedRequest(
        uint16_t *OutStandardId,
        uint8_t **OutVendorId,
        uint32_t *OutVendorIdLen,
        uint8_t **OutPayload,
        uint32_t *OutPayloadLen,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateVendorDefinedResponse(
        uint16_t *OutStandardId,
        uint8_t **OutVendorId,
        uint32_t *OutVendorIdLen,
        uint8_t **OutPayload,
        uint32_t *OutPayloadLen,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateExtendedError(
        uint8_t Code,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLen,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateError(
        uint8_t *OutErrorCode,
        uint8_t *OutErrorData,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateOpaqueElement(
        uint8_t *OutId,
        uint8_t **OutVendorId,
        uint32_t *OutVendorLen,
        uint8_t **OutOpaqueElementData,
        uint32_t *OutOpaqueElementDataLen,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateSecuredMessageRecord(
        uint32_t SeqNumLen,
        uint32_t MacLen,
        uint32_t *OutSessionId,
        uint8_t **OutSeqNum,
        uint8_t **OutCiphertext,
        uint32_t *OutCiphertextLen,
        uint8_t **OutMac,
        uint8_t *Ctxt,
        void (*Err)(
            EverParseString x0,
            EverParseString x1,
            EverParseString x2,
            uint8_t *x3,
            uint8_t *x4,
            uint64_t x5),
        uint8_t *Input,
        uint64_t InputLength,
        uint64_t StartPosition);

#if defined(__cplusplus)
}
#endif

#define __SPDM_H_DEFINED
#endif
