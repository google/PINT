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



#include "SPDM.h"

static inline uint64_t
ValidateOptionalBuffer(
    BOOLEAN Present,
    uint32_t Size,
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
    uint64_t StartPosition)
{
    if (Present == TRUE)
    {
        /* Validating field buffer */
        BOOLEAN hasEnoughBytes = (uint64_t)Size <= (InputLen - StartPosition);
        uint64_t positionAfterOptionalBuffer;
        if (!hasEnoughBytes)
        {
            positionAfterOptionalBuffer = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
        }
        else
        {
            uint8_t *truncatedInput = Input;
            uint64_t truncatedInputLength = StartPosition + (uint64_t)Size;
            uint64_t result = StartPosition;
            while (TRUE)
            {
                uint64_t position = *&result;
                BOOLEAN ite;
                if (!((uint64_t)1U <= (truncatedInputLength - position)))
                {
                    ite = TRUE;
                }
                else
                {
                    /* Checking that we have enough space for a UINT8, i.e., 1
                     * byte */
                    BOOLEAN hasBytes =
                        (uint64_t)1U <= (truncatedInputLength - position);
                    uint64_t positionAfterOptionalBuffer;
                    if (hasBytes)
                    {
                        positionAfterOptionalBuffer = position + (uint64_t)1U;
                    }
                    else
                    {
                        positionAfterOptionalBuffer =
                            EverParseSetValidatorErrorPos(
                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                position);
                    }
                    uint64_t res;
                    if (EverParseIsSuccess(positionAfterOptionalBuffer))
                    {
                        res = positionAfterOptionalBuffer;
                    }
                    else
                    {
                        Err("_OptionalBuffer",
                            ".element",
                            EverParseErrorReasonOfResult(
                                positionAfterOptionalBuffer),
                            Ctxt,
                            truncatedInput,
                            position);
                        res = positionAfterOptionalBuffer;
                    }
                    uint64_t result1 = res;
                    result = result1;
                    ite = EverParseIsError(result1);
                }
                if (ite)
                {
                    break;
                }
            }
            uint64_t res = result;
            positionAfterOptionalBuffer = res;
        }
        if (EverParseIsSuccess(positionAfterOptionalBuffer))
        {
            return positionAfterOptionalBuffer;
        }
        Err("_OptionalBuffer",
            "missing",
            EverParseErrorReasonOfResult(positionAfterOptionalBuffer),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterOptionalBuffer;
    }
    if (Present == FALSE)
    {
        /* Validating field noop */
        uint64_t positionAfterOptionalBuffer = StartPosition;
        if (EverParseIsSuccess(positionAfterOptionalBuffer))
        {
            return positionAfterOptionalBuffer;
        }
        Err("_OptionalBuffer",
            "missing",
            EverParseErrorReasonOfResult(positionAfterOptionalBuffer),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterOptionalBuffer;
    }
    uint64_t positionAfterOptionalBuffer = EverParseSetValidatorErrorPos(
        EVERPARSE_VALIDATOR_ERROR_IMPOSSIBLE, StartPosition);
    if (EverParseIsSuccess(positionAfterOptionalBuffer))
    {
        return positionAfterOptionalBuffer;
    }
    Err("_OptionalBuffer",
        "missing",
        EverParseErrorReasonOfResult(positionAfterOptionalBuffer),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterOptionalBuffer;
}

static inline uint64_t
ValidatePreamble(
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
    uint64_t InputLength,
    uint64_t StartPosition)
{
    /* Validating field version */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - StartPosition);
    uint64_t positionAfterPreamble;
    if (hasBytes0)
    {
        positionAfterPreamble = StartPosition + (uint64_t)1U;
    }
    else
    {
        positionAfterPreamble = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
    }
    uint64_t res;
    if (EverParseIsSuccess(positionAfterPreamble))
    {
        res = positionAfterPreamble;
    }
    else
    {
        Err("_Preamble",
            "version",
            EverParseErrorReasonOfResult(positionAfterPreamble),
            Ctxt,
            Input,
            StartPosition);
        res = positionAfterPreamble;
    }
    uint64_t positionAfterversion = res;
    if (EverParseIsError(positionAfterversion))
    {
        return positionAfterversion;
    }
    /* Validating field request_response_code */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes = (uint64_t)1U <= (InputLength - positionAfterversion);
    uint64_t positionAfterrequestResponseCode_refinement;
    if (hasBytes)
    {
        positionAfterrequestResponseCode_refinement =
            positionAfterversion + (uint64_t)1U;
    }
    else
    {
        positionAfterrequestResponseCode_refinement =
            EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                positionAfterversion);
    }
    uint64_t positionAfterPreamble0;
    if (EverParseIsError(positionAfterrequestResponseCode_refinement))
    {
        positionAfterPreamble0 = positionAfterrequestResponseCode_refinement;
    }
    else
    {
        /* reading field_value */
        uint8_t requestResponseCode_refinement =
            Input[(uint32_t)positionAfterversion];
        /* start: checking constraint */
        BOOLEAN requestResponseCode_refinementConstraintIsOk =
            requestResponseCode_refinement == Code;
        /* end: checking constraint */
        positionAfterPreamble0 = EverParseCheckConstraintOk(
            requestResponseCode_refinementConstraintIsOk,
            positionAfterrequestResponseCode_refinement);
    }
    if (EverParseIsSuccess(positionAfterPreamble0))
    {
        return positionAfterPreamble0;
    }
    Err("_Preamble",
        "request_response_code.refinement",
        EverParseErrorReasonOfResult(positionAfterPreamble0),
        Ctxt,
        Input,
        positionAfterversion);
    return positionAfterPreamble0;
}

static inline uint64_t
ValidateReservedParams(
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
    uint64_t StartPosition)
{
    /* Validating field param_1_reserved */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - StartPosition);
    uint64_t positionAfterReservedParams;
    if (hasBytes0)
    {
        positionAfterReservedParams = StartPosition + (uint64_t)1U;
    }
    else
    {
        positionAfterReservedParams = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
    }
    uint64_t res;
    if (EverParseIsSuccess(positionAfterReservedParams))
    {
        res = positionAfterReservedParams;
    }
    else
    {
        Err("_ReservedParams",
            "param_1_reserved",
            EverParseErrorReasonOfResult(positionAfterReservedParams),
            Ctxt,
            Input,
            StartPosition);
        res = positionAfterReservedParams;
    }
    uint64_t positionAfterparam1Reserved = res;
    if (EverParseIsError(positionAfterparam1Reserved))
    {
        return positionAfterparam1Reserved;
    }
    /* Validating field param_2_reserved */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes =
        (uint64_t)1U <= (InputLength - positionAfterparam1Reserved);
    uint64_t positionAfterReservedParams0;
    if (hasBytes)
    {
        positionAfterReservedParams0 =
            positionAfterparam1Reserved + (uint64_t)1U;
    }
    else
    {
        positionAfterReservedParams0 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfterparam1Reserved);
    }
    if (EverParseIsSuccess(positionAfterReservedParams0))
    {
        return positionAfterReservedParams0;
    }
    Err("_ReservedParams",
        "param_2_reserved",
        EverParseErrorReasonOfResult(positionAfterReservedParams0),
        Ctxt,
        Input,
        positionAfterparam1Reserved);
    return positionAfterReservedParams0;
}

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
    uint64_t StartPosition)
{
    /* Validating field preamble */
    uint64_t positionAfterGetVersion = ValidatePreamble(
        SPDM____GET_VERSION, Ctxt, Err, Input, InputLength, StartPosition);
    uint64_t positionAfterpreamble;
    if (EverParseIsSuccess(positionAfterGetVersion))
    {
        positionAfterpreamble = positionAfterGetVersion;
    }
    else
    {
        Err("_GetVersion",
            "preamble",
            EverParseErrorReasonOfResult(positionAfterGetVersion),
            Ctxt,
            Input,
            StartPosition);
        positionAfterpreamble = positionAfterGetVersion;
    }
    if (EverParseIsError(positionAfterpreamble))
    {
        return positionAfterpreamble;
    }
    /* Validating field params */
    uint64_t positionAfterGetVersion0 = ValidateReservedParams(
        Ctxt, Err, Input, InputLength, positionAfterpreamble);
    if (EverParseIsSuccess(positionAfterGetVersion0))
    {
        return positionAfterGetVersion0;
    }
    Err("_GetVersion",
        "params",
        EverParseErrorReasonOfResult(positionAfterGetVersion0),
        Ctxt,
        Input,
        positionAfterpreamble);
    return positionAfterGetVersion0;
}

static inline uint64_t
ValidateVersionNumberEntry(
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
    uint64_t StartPosition)
{
    /* Validating field __bitfield_0 */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    BOOLEAN hasBytes = (uint64_t)2U <= (InputLength - StartPosition);
    uint64_t positionAfterVersionNumberEntry;
    if (hasBytes)
    {
        positionAfterVersionNumberEntry = StartPosition + (uint64_t)2U;
    }
    else
    {
        positionAfterVersionNumberEntry = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
    }
    if (EverParseIsSuccess(positionAfterVersionNumberEntry))
    {
        return positionAfterVersionNumberEntry;
    }
    Err("_VersionNumberEntry",
        "__bitfield_0",
        EverParseErrorReasonOfResult(positionAfterVersionNumberEntry),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterVersionNumberEntry;
}

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
    uint64_t StartPosition)
{
    /* Validating field preamble */
    uint64_t positionAfterVersion = ValidatePreamble(
        SPDM____VERSION, Ctxt, Err, Input, InputLength, StartPosition);
    uint64_t positionAfterpreamble;
    if (EverParseIsSuccess(positionAfterVersion))
    {
        positionAfterpreamble = positionAfterVersion;
    }
    else
    {
        Err("_Version",
            "preamble",
            EverParseErrorReasonOfResult(positionAfterVersion),
            Ctxt,
            Input,
            StartPosition);
        positionAfterpreamble = positionAfterVersion;
    }
    if (EverParseIsError(positionAfterpreamble))
    {
        return positionAfterpreamble;
    }
    /* Validating field params */
    uint64_t positionAfterVersion0 = ValidateReservedParams(
        Ctxt, Err, Input, InputLength, positionAfterpreamble);
    uint64_t positionAfterparams;
    if (EverParseIsSuccess(positionAfterVersion0))
    {
        positionAfterparams = positionAfterVersion0;
    }
    else
    {
        Err("_Version",
            "params",
            EverParseErrorReasonOfResult(positionAfterVersion0),
            Ctxt,
            Input,
            positionAfterpreamble);
        positionAfterparams = positionAfterVersion0;
    }
    if (EverParseIsError(positionAfterparams))
    {
        return positionAfterparams;
    }
    /* Validating field reserved */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - positionAfterparams);
    uint64_t positionAfterVersion1;
    if (hasBytes0)
    {
        positionAfterVersion1 = positionAfterparams + (uint64_t)1U;
    }
    else
    {
        positionAfterVersion1 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterparams);
    }
    uint64_t res0;
    if (EverParseIsSuccess(positionAfterVersion1))
    {
        res0 = positionAfterVersion1;
    }
    else
    {
        Err("_Version",
            "reserved",
            EverParseErrorReasonOfResult(positionAfterVersion1),
            Ctxt,
            Input,
            positionAfterparams);
        res0 = positionAfterVersion1;
    }
    uint64_t positionAfterreserved = res0;
    if (EverParseIsError(positionAfterreserved))
    {
        return positionAfterreserved;
    }
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes = (uint64_t)1U <= (InputLength - positionAfterreserved);
    uint64_t positionAfternone;
    if (hasBytes)
    {
        positionAfternone = positionAfterreserved + (uint64_t)1U;
    }
    else
    {
        positionAfternone = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterreserved);
    }
    uint64_t positionAfterVersion2;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterVersion2 = positionAfternone;
    }
    else
    {
        uint8_t none = Input[(uint32_t)positionAfterreserved];
        BOOLEAN noneConstraintIsOk =
            none <= SPDM____MAX_VERSION_NUMBER_ENTRY_COUNT;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterVersion2 = positionAfternone1;
        }
        else
        {
            /* Validating field version_number_entries */
            BOOLEAN
            hasEnoughBytes = (uint64_t)(uint32_t)(none * (uint8_t)2U) <=
                             (InputLength - positionAfternone1);
            uint64_t positionAfterVersion;
            if (!hasEnoughBytes)
            {
                positionAfterVersion = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfternone1);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    positionAfternone1 +
                    (uint64_t)(uint32_t)(none * (uint8_t)2U);
                uint64_t result = positionAfternone1;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        uint64_t positionAfterVersion =
                            ValidateVersionNumberEntry(
                                Ctxt,
                                Err,
                                truncatedInput,
                                truncatedInputLength,
                                position);
                        uint64_t res;
                        if (EverParseIsSuccess(positionAfterVersion))
                        {
                            res = positionAfterVersion;
                        }
                        else
                        {
                            Err("_Version",
                                "version_number_entries.base.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterVersion),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterVersion;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterVersion = res;
            }
            uint64_t positionAfterversionNumberEntries;
            if (EverParseIsSuccess(positionAfterVersion))
            {
                positionAfterversionNumberEntries = positionAfterVersion;
            }
            else
            {
                Err("_Version",
                    "version_number_entries.base",
                    EverParseErrorReasonOfResult(positionAfterVersion),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterversionNumberEntries = positionAfterVersion;
            }
            uint64_t positionAfterVersion0;
            if (EverParseIsSuccess(positionAfterversionNumberEntries))
            {
                uint8_t *hd = Input + (uint32_t)positionAfternone1;
                *OutEntryCount = none;
                *OutEntries = hd;
                BOOLEAN actionSuccessVersionNumberEntries = TRUE;
                if (!actionSuccessVersionNumberEntries)
                {
                    positionAfterVersion0 = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                        positionAfterversionNumberEntries);
                }
                else
                {
                    positionAfterVersion0 = positionAfterversionNumberEntries;
                }
            }
            else
            {
                positionAfterVersion0 = positionAfterversionNumberEntries;
            }
            if (EverParseIsSuccess(positionAfterVersion0))
            {
                positionAfterVersion2 = positionAfterVersion0;
            }
            else
            {
                Err("_Version",
                    "version_number_entries",
                    EverParseErrorReasonOfResult(positionAfterVersion0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterVersion2 = positionAfterVersion0;
            }
        }
    }
    if (EverParseIsSuccess(positionAfterVersion2))
    {
        return positionAfterVersion2;
    }
    Err("_Version",
        "none",
        EverParseErrorReasonOfResult(positionAfterVersion2),
        Ctxt,
        Input,
        positionAfterreserved);
    return positionAfterVersion2;
}

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
    uint64_t StartPosition)
{
    /* Validating field preamble */
    uint64_t positionAfterGetCapabilities = ValidatePreamble(
        SPDM____GET_CAPABILITIES, Ctxt, Err, Input, InputLength, StartPosition);
    uint64_t positionAfterpreamble;
    if (EverParseIsSuccess(positionAfterGetCapabilities))
    {
        positionAfterpreamble = positionAfterGetCapabilities;
    }
    else
    {
        Err("_GetCapabilities",
            "preamble",
            EverParseErrorReasonOfResult(positionAfterGetCapabilities),
            Ctxt,
            Input,
            StartPosition);
        positionAfterpreamble = positionAfterGetCapabilities;
    }
    if (EverParseIsError(positionAfterpreamble))
    {
        return positionAfterpreamble;
    }
    /* Validating field params */
    uint64_t positionAfterGetCapabilities0 = ValidateReservedParams(
        Ctxt, Err, Input, InputLength, positionAfterpreamble);
    uint64_t positionAfterparams;
    if (EverParseIsSuccess(positionAfterGetCapabilities0))
    {
        positionAfterparams = positionAfterGetCapabilities0;
    }
    else
    {
        Err("_GetCapabilities",
            "params",
            EverParseErrorReasonOfResult(positionAfterGetCapabilities0),
            Ctxt,
            Input,
            positionAfterpreamble);
        positionAfterparams = positionAfterGetCapabilities0;
    }
    if (EverParseIsError(positionAfterparams))
    {
        return positionAfterparams;
    }
    /* Validating field reserved_0 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - positionAfterparams);
    uint64_t positionAfterGetCapabilities1;
    if (hasBytes0)
    {
        positionAfterGetCapabilities1 = positionAfterparams + (uint64_t)1U;
    }
    else
    {
        positionAfterGetCapabilities1 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterparams);
    }
    uint64_t res0;
    if (EverParseIsSuccess(positionAfterGetCapabilities1))
    {
        res0 = positionAfterGetCapabilities1;
    }
    else
    {
        Err("_GetCapabilities",
            "reserved_0",
            EverParseErrorReasonOfResult(positionAfterGetCapabilities1),
            Ctxt,
            Input,
            positionAfterparams);
        res0 = positionAfterGetCapabilities1;
    }
    uint64_t positionAfterreserved0 = res0;
    if (EverParseIsError(positionAfterreserved0))
    {
        return positionAfterreserved0;
    }
    /* Validating field ct_exponent */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes1 = (uint64_t)1U <= (InputLength - positionAfterreserved0);
    uint64_t positionAfterGetCapabilities2;
    if (hasBytes1)
    {
        positionAfterGetCapabilities2 = positionAfterreserved0 + (uint64_t)1U;
    }
    else
    {
        positionAfterGetCapabilities2 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterreserved0);
    }
    uint64_t res1;
    if (EverParseIsSuccess(positionAfterGetCapabilities2))
    {
        res1 = positionAfterGetCapabilities2;
    }
    else
    {
        Err("_GetCapabilities",
            "ct_exponent",
            EverParseErrorReasonOfResult(positionAfterGetCapabilities2),
            Ctxt,
            Input,
            positionAfterreserved0);
        res1 = positionAfterGetCapabilities2;
    }
    uint64_t positionAfterctExponent = res1;
    if (EverParseIsError(positionAfterctExponent))
    {
        return positionAfterctExponent;
    }
    /* Validating field reserved_1 */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    BOOLEAN hasBytes2 = (uint64_t)2U <= (InputLength - positionAfterctExponent);
    uint64_t positionAfterGetCapabilities3;
    if (hasBytes2)
    {
        positionAfterGetCapabilities3 = positionAfterctExponent + (uint64_t)2U;
    }
    else
    {
        positionAfterGetCapabilities3 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterctExponent);
    }
    uint64_t res;
    if (EverParseIsSuccess(positionAfterGetCapabilities3))
    {
        res = positionAfterGetCapabilities3;
    }
    else
    {
        Err("_GetCapabilities",
            "reserved_1",
            EverParseErrorReasonOfResult(positionAfterGetCapabilities3),
            Ctxt,
            Input,
            positionAfterctExponent);
        res = positionAfterGetCapabilities3;
    }
    uint64_t positionAfterreserved1 = res;
    if (EverParseIsError(positionAfterreserved1))
    {
        return positionAfterreserved1;
    }
    /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
    BOOLEAN hasBytes3 = (uint64_t)4U <= (InputLength - positionAfterreserved1);
    uint64_t positionAfternone;
    if (hasBytes3)
    {
        positionAfternone = positionAfterreserved1 + (uint64_t)4U;
    }
    else
    {
        positionAfternone = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterreserved1);
    }
    uint64_t positionAfterGetCapabilities4;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterGetCapabilities4 = positionAfternone;
    }
    else
    {
        uint32_t none = Load32Le(Input + (uint32_t)positionAfterreserved1);
        BOOLEAN
        noneConstraintIsOk =
            (EverParseGetBitfield32(none, (uint32_t)9U, (uint32_t)10U) ==
                 (uint32_t)(uint8_t)0U ||
             EverParseGetBitfield32(none, (uint32_t)6U, (uint32_t)7U) ==
                 (uint32_t)(uint8_t)1U ||
             EverParseGetBitfield32(none, (uint32_t)7U, (uint32_t)8U) ==
                 (uint32_t)(uint8_t)1U) &&
            (EverParseGetBitfield32(none, (uint32_t)10U, (uint32_t)12U) ==
                 (uint32_t)(uint8_t)0U ||
             EverParseGetBitfield32(none, (uint32_t)10U, (uint32_t)12U) ==
                 (uint32_t)(uint8_t)1U);
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterGetCapabilities4 = positionAfternone1;
        }
        else
        {
            /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
            BOOLEAN hasBytes0 =
                (uint64_t)4U <= (InputLength - positionAfternone1);
            uint64_t positionAfterGetCapabilities;
            if (hasBytes0)
            {
                positionAfterGetCapabilities =
                    positionAfternone1 + (uint64_t)4U;
            }
            else
            {
                positionAfterGetCapabilities = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfternone1);
            }
            uint64_t positionAfterdataTransferSize;
            if (EverParseIsSuccess(positionAfterGetCapabilities))
            {
                positionAfterdataTransferSize = positionAfterGetCapabilities;
            }
            else
            {
                Err("_GetCapabilities",
                    "data_transfer_size",
                    EverParseErrorReasonOfResult(positionAfterGetCapabilities),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterdataTransferSize = positionAfterGetCapabilities;
            }
            if (EverParseIsError(positionAfterdataTransferSize))
            {
                positionAfterGetCapabilities4 = positionAfterdataTransferSize;
            }
            else
            {
                uint32_t dataTransferSize =
                    Load32Le(Input + (uint32_t)positionAfternone1);
                /* Validating field max_spdm_message_size */
                /* Checking that we have enough space for a UINT32, i.e., 4
                 * bytes */
                BOOLEAN hasBytes =
                    (uint64_t)4U <=
                    (InputLength - positionAfterdataTransferSize);
                uint64_t positionAftermaxSpdmMessageSize_refinement;
                if (hasBytes)
                {
                    positionAftermaxSpdmMessageSize_refinement =
                        positionAfterdataTransferSize + (uint64_t)4U;
                }
                else
                {
                    positionAftermaxSpdmMessageSize_refinement =
                        EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfterdataTransferSize);
                }
                uint64_t positionAfterGetCapabilities;
                if (EverParseIsError(
                        positionAftermaxSpdmMessageSize_refinement))
                {
                    positionAfterGetCapabilities =
                        positionAftermaxSpdmMessageSize_refinement;
                }
                else
                {
                    /* reading field_value */
                    uint32_t maxSpdmMessageSize_refinement = Load32Le(
                        Input + (uint32_t)positionAfterdataTransferSize);
                    /* start: checking constraint */
                    BOOLEAN
                    maxSpdmMessageSize_refinementConstraintIsOk =
                        maxSpdmMessageSize_refinement >= dataTransferSize;
                    /* end: checking constraint */
                    positionAfterGetCapabilities = EverParseCheckConstraintOk(
                        maxSpdmMessageSize_refinementConstraintIsOk,
                        positionAftermaxSpdmMessageSize_refinement);
                }
                if (EverParseIsSuccess(positionAfterGetCapabilities))
                {
                    positionAfterGetCapabilities4 =
                        positionAfterGetCapabilities;
                }
                else
                {
                    Err("_GetCapabilities",
                        "max_spdm_message_size.refinement",
                        EverParseErrorReasonOfResult(
                            positionAfterGetCapabilities),
                        Ctxt,
                        Input,
                        positionAfterdataTransferSize);
                    positionAfterGetCapabilities4 =
                        positionAfterGetCapabilities;
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterGetCapabilities4))
    {
        return positionAfterGetCapabilities4;
    }
    Err("_GetCapabilities",
        "none",
        EverParseErrorReasonOfResult(positionAfterGetCapabilities4),
        Ctxt,
        Input,
        positionAfterreserved1);
    return positionAfterGetCapabilities4;
}

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
    uint64_t StartPosition)
{
    /* Validating field preamble */
    uint64_t positionAfterCapabilities = ValidatePreamble(
        SPDM____CAPABILITIES, Ctxt, Err, Input, InputLength, StartPosition);
    uint64_t positionAfterpreamble;
    if (EverParseIsSuccess(positionAfterCapabilities))
    {
        positionAfterpreamble = positionAfterCapabilities;
    }
    else
    {
        Err("_Capabilities",
            "preamble",
            EverParseErrorReasonOfResult(positionAfterCapabilities),
            Ctxt,
            Input,
            StartPosition);
        positionAfterpreamble = positionAfterCapabilities;
    }
    if (EverParseIsError(positionAfterpreamble))
    {
        return positionAfterpreamble;
    }
    /* Validating field params */
    uint64_t positionAfterCapabilities0 = ValidateReservedParams(
        Ctxt, Err, Input, InputLength, positionAfterpreamble);
    uint64_t positionAfterparams;
    if (EverParseIsSuccess(positionAfterCapabilities0))
    {
        positionAfterparams = positionAfterCapabilities0;
    }
    else
    {
        Err("_Capabilities",
            "params",
            EverParseErrorReasonOfResult(positionAfterCapabilities0),
            Ctxt,
            Input,
            positionAfterpreamble);
        positionAfterparams = positionAfterCapabilities0;
    }
    if (EverParseIsError(positionAfterparams))
    {
        return positionAfterparams;
    }
    /* Validating field reserved_0 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - positionAfterparams);
    uint64_t positionAfterCapabilities1;
    if (hasBytes0)
    {
        positionAfterCapabilities1 = positionAfterparams + (uint64_t)1U;
    }
    else
    {
        positionAfterCapabilities1 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterparams);
    }
    uint64_t res0;
    if (EverParseIsSuccess(positionAfterCapabilities1))
    {
        res0 = positionAfterCapabilities1;
    }
    else
    {
        Err("_Capabilities",
            "reserved_0",
            EverParseErrorReasonOfResult(positionAfterCapabilities1),
            Ctxt,
            Input,
            positionAfterparams);
        res0 = positionAfterCapabilities1;
    }
    uint64_t positionAfterreserved0 = res0;
    if (EverParseIsError(positionAfterreserved0))
    {
        return positionAfterreserved0;
    }
    /* Validating field ct_exponent */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes1 = (uint64_t)1U <= (InputLength - positionAfterreserved0);
    uint64_t positionAfterCapabilities2;
    if (hasBytes1)
    {
        positionAfterCapabilities2 = positionAfterreserved0 + (uint64_t)1U;
    }
    else
    {
        positionAfterCapabilities2 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterreserved0);
    }
    uint64_t res1;
    if (EverParseIsSuccess(positionAfterCapabilities2))
    {
        res1 = positionAfterCapabilities2;
    }
    else
    {
        Err("_Capabilities",
            "ct_exponent",
            EverParseErrorReasonOfResult(positionAfterCapabilities2),
            Ctxt,
            Input,
            positionAfterreserved0);
        res1 = positionAfterCapabilities2;
    }
    uint64_t positionAfterctExponent = res1;
    if (EverParseIsError(positionAfterctExponent))
    {
        return positionAfterctExponent;
    }
    /* Validating field reserved_1 */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    BOOLEAN hasBytes2 = (uint64_t)2U <= (InputLength - positionAfterctExponent);
    uint64_t positionAfterCapabilities3;
    if (hasBytes2)
    {
        positionAfterCapabilities3 = positionAfterctExponent + (uint64_t)2U;
    }
    else
    {
        positionAfterCapabilities3 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterctExponent);
    }
    uint64_t res;
    if (EverParseIsSuccess(positionAfterCapabilities3))
    {
        res = positionAfterCapabilities3;
    }
    else
    {
        Err("_Capabilities",
            "reserved_1",
            EverParseErrorReasonOfResult(positionAfterCapabilities3),
            Ctxt,
            Input,
            positionAfterctExponent);
        res = positionAfterCapabilities3;
    }
    uint64_t positionAfterreserved1 = res;
    if (EverParseIsError(positionAfterreserved1))
    {
        return positionAfterreserved1;
    }
    /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
    BOOLEAN hasBytes3 = (uint64_t)4U <= (InputLength - positionAfterreserved1);
    uint64_t positionAfternone;
    if (hasBytes3)
    {
        positionAfternone = positionAfterreserved1 + (uint64_t)4U;
    }
    else
    {
        positionAfternone = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterreserved1);
    }
    uint64_t positionAfterCapabilities4;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterCapabilities4 = positionAfternone;
    }
    else
    {
        uint32_t none = Load32Le(Input + (uint32_t)positionAfterreserved1);
        BOOLEAN
        noneConstraintIsOk =
            EverParseGetBitfield32(none, (uint32_t)3U, (uint32_t)5U) !=
                (uint32_t)(uint8_t)3U &&
            (EverParseGetBitfield32(none, (uint32_t)9U, (uint32_t)10U) ==
                 (uint32_t)(uint8_t)0U ||
             EverParseGetBitfield32(none, (uint32_t)6U, (uint32_t)7U) ==
                 (uint32_t)(uint8_t)1U ||
             EverParseGetBitfield32(none, (uint32_t)7U, (uint32_t)8U) ==
                 (uint32_t)(uint8_t)1U) &&
            EverParseGetBitfield32(none, (uint32_t)10U, (uint32_t)12U) !=
                (uint32_t)(uint8_t)3U;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterCapabilities4 = positionAfternone1;
        }
        else
        {
            /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
            BOOLEAN hasBytes0 =
                (uint64_t)4U <= (InputLength - positionAfternone1);
            uint64_t positionAfterCapabilities;
            if (hasBytes0)
            {
                positionAfterCapabilities = positionAfternone1 + (uint64_t)4U;
            }
            else
            {
                positionAfterCapabilities = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfternone1);
            }
            uint64_t positionAfterdataTransferSize;
            if (EverParseIsSuccess(positionAfterCapabilities))
            {
                positionAfterdataTransferSize = positionAfterCapabilities;
            }
            else
            {
                Err("_Capabilities",
                    "data_transfer_size",
                    EverParseErrorReasonOfResult(positionAfterCapabilities),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterdataTransferSize = positionAfterCapabilities;
            }
            if (EverParseIsError(positionAfterdataTransferSize))
            {
                positionAfterCapabilities4 = positionAfterdataTransferSize;
            }
            else
            {
                uint32_t dataTransferSize =
                    Load32Le(Input + (uint32_t)positionAfternone1);
                /* Validating field max_spdm_message_size */
                /* Checking that we have enough space for a UINT32, i.e., 4
                 * bytes */
                BOOLEAN hasBytes =
                    (uint64_t)4U <=
                    (InputLength - positionAfterdataTransferSize);
                uint64_t positionAftermaxSpdmMessageSize_refinement;
                if (hasBytes)
                {
                    positionAftermaxSpdmMessageSize_refinement =
                        positionAfterdataTransferSize + (uint64_t)4U;
                }
                else
                {
                    positionAftermaxSpdmMessageSize_refinement =
                        EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfterdataTransferSize);
                }
                uint64_t positionAfterCapabilities;
                if (EverParseIsError(
                        positionAftermaxSpdmMessageSize_refinement))
                {
                    positionAfterCapabilities =
                        positionAftermaxSpdmMessageSize_refinement;
                }
                else
                {
                    /* reading field_value */
                    uint32_t maxSpdmMessageSize_refinement = Load32Le(
                        Input + (uint32_t)positionAfterdataTransferSize);
                    /* start: checking constraint */
                    BOOLEAN
                    maxSpdmMessageSize_refinementConstraintIsOk =
                        maxSpdmMessageSize_refinement >= dataTransferSize;
                    /* end: checking constraint */
                    positionAfterCapabilities = EverParseCheckConstraintOk(
                        maxSpdmMessageSize_refinementConstraintIsOk,
                        positionAftermaxSpdmMessageSize_refinement);
                }
                if (EverParseIsSuccess(positionAfterCapabilities))
                {
                    positionAfterCapabilities4 = positionAfterCapabilities;
                }
                else
                {
                    Err("_Capabilities",
                        "max_spdm_message_size.refinement",
                        EverParseErrorReasonOfResult(positionAfterCapabilities),
                        Ctxt,
                        Input,
                        positionAfterdataTransferSize);
                    positionAfterCapabilities4 = positionAfterCapabilities;
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterCapabilities4))
    {
        return positionAfterCapabilities4;
    }
    Err("_Capabilities",
        "none",
        EverParseErrorReasonOfResult(positionAfterCapabilities4),
        Ctxt,
        Input,
        positionAfterreserved1);
    return positionAfterCapabilities4;
}

static inline uint64_t
ValidateExtendedAlg(
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
    uint64_t StartPosition)
{
    /* Validating field registry_id */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - StartPosition);
    uint64_t positionAfterExtendedAlg;
    if (hasBytes0)
    {
        positionAfterExtendedAlg = StartPosition + (uint64_t)1U;
    }
    else
    {
        positionAfterExtendedAlg = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
    }
    uint64_t res0;
    if (EverParseIsSuccess(positionAfterExtendedAlg))
    {
        res0 = positionAfterExtendedAlg;
    }
    else
    {
        Err("_ExtendedAlg",
            "registry_id",
            EverParseErrorReasonOfResult(positionAfterExtendedAlg),
            Ctxt,
            Input,
            StartPosition);
        res0 = positionAfterExtendedAlg;
    }
    uint64_t positionAfterregistryId = res0;
    if (EverParseIsError(positionAfterregistryId))
    {
        return positionAfterregistryId;
    }
    /* Validating field reserved */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes1 = (uint64_t)1U <= (InputLength - positionAfterregistryId);
    uint64_t positionAfterExtendedAlg0;
    if (hasBytes1)
    {
        positionAfterExtendedAlg0 = positionAfterregistryId + (uint64_t)1U;
    }
    else
    {
        positionAfterExtendedAlg0 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterregistryId);
    }
    uint64_t res;
    if (EverParseIsSuccess(positionAfterExtendedAlg0))
    {
        res = positionAfterExtendedAlg0;
    }
    else
    {
        Err("_ExtendedAlg",
            "reserved",
            EverParseErrorReasonOfResult(positionAfterExtendedAlg0),
            Ctxt,
            Input,
            positionAfterregistryId);
        res = positionAfterExtendedAlg0;
    }
    uint64_t positionAfterreserved = res;
    if (EverParseIsError(positionAfterreserved))
    {
        return positionAfterreserved;
    }
    /* Validating field algorithm_id */
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    BOOLEAN hasBytes = (uint64_t)2U <= (InputLength - positionAfterreserved);
    uint64_t positionAfterExtendedAlg1;
    if (hasBytes)
    {
        positionAfterExtendedAlg1 = positionAfterreserved + (uint64_t)2U;
    }
    else
    {
        positionAfterExtendedAlg1 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterreserved);
    }
    if (EverParseIsSuccess(positionAfterExtendedAlg1))
    {
        return positionAfterExtendedAlg1;
    }
    Err("_ExtendedAlg",
        "algorithm_id",
        EverParseErrorReasonOfResult(positionAfterExtendedAlg1),
        Ctxt,
        Input,
        positionAfterreserved);
    return positionAfterExtendedAlg1;
}

static inline uint64_t
ValidateAlgStruct(
    BOOLEAN IsResp,
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
    uint64_t StartPosition)
{
    /* Validating field alg_type */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - StartPosition);
    uint64_t positionAfterAlgStruct;
    if (hasBytes0)
    {
        positionAfterAlgStruct = StartPosition + (uint64_t)1U;
    }
    else
    {
        positionAfterAlgStruct = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
    }
    uint64_t res0;
    if (EverParseIsSuccess(positionAfterAlgStruct))
    {
        res0 = positionAfterAlgStruct;
    }
    else
    {
        Err("_AlgStruct",
            "alg_type",
            EverParseErrorReasonOfResult(positionAfterAlgStruct),
            Ctxt,
            Input,
            StartPosition);
        res0 = positionAfterAlgStruct;
    }
    uint64_t positionAfteralgType = res0;
    if (EverParseIsError(positionAfteralgType))
    {
        return positionAfteralgType;
    }
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes1 = (uint64_t)1U <= (InputLength - positionAfteralgType);
    uint64_t positionAfternone;
    if (hasBytes1)
    {
        positionAfternone = positionAfteralgType + (uint64_t)1U;
    }
    else
    {
        positionAfternone = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfteralgType);
    }
    uint64_t positionAfterAlgStruct0;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterAlgStruct0 = positionAfternone;
    }
    else
    {
        uint8_t none = Input[(uint32_t)positionAfteralgType];
        BOOLEAN
        noneConstraintIsOk =
            EverParseGetBitfield8(none, (uint32_t)0U, (uint32_t)4U) <=
                SPDM____MAX_ALGS &&
            (EverParseGetBitfield8(none, (uint32_t)4U, (uint32_t)8U) +
             (uint8_t)2U) %
                    (uint8_t)4U ==
                (uint8_t)0U;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterAlgStruct0 = positionAfternone1;
        }
        else
        {
            /* Validating field algs_supported */
            BOOLEAN
            hasEnoughBytes0 = (uint64_t)(uint32_t)EverParseGetBitfield8(
                                  none, (uint32_t)4U, (uint32_t)8U) <=
                              (InputLength - positionAfternone1);
            uint64_t positionAfterAlgStruct;
            if (!hasEnoughBytes0)
            {
                positionAfterAlgStruct = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfternone1);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    positionAfternone1 +
                    (uint64_t)(uint32_t)EverParseGetBitfield8(
                        none, (uint32_t)4U, (uint32_t)8U);
                uint64_t result = positionAfternone1;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes =
                            (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterAlgStruct;
                        if (hasBytes)
                        {
                            positionAfterAlgStruct = position + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterAlgStruct =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    position);
                        }
                        uint64_t res;
                        if (EverParseIsSuccess(positionAfterAlgStruct))
                        {
                            res = positionAfterAlgStruct;
                        }
                        else
                        {
                            Err("_AlgStruct",
                                "algs_supported.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterAlgStruct),
                                Ctxt,
                                truncatedInput,
                                position);
                            res = positionAfterAlgStruct;
                        }
                        uint64_t result1 = res;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res = result;
                positionAfterAlgStruct = res;
            }
            uint64_t positionAfteralgsSupported;
            if (EverParseIsSuccess(positionAfterAlgStruct))
            {
                positionAfteralgsSupported = positionAfterAlgStruct;
            }
            else
            {
                Err("_AlgStruct",
                    "algs_supported",
                    EverParseErrorReasonOfResult(positionAfterAlgStruct),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfteralgsSupported = positionAfterAlgStruct;
            }
            if (EverParseIsError(positionAfteralgsSupported))
            {
                positionAfterAlgStruct0 = positionAfteralgsSupported;
            }
            else
            {
                /* Validating field extended_algs */
                BOOLEAN
                hasEnoughBytes =
                    (uint64_t)(uint32_t)((uint8_t)4U * EverParseGetBitfield8(none, (uint32_t)0U, (uint32_t)4U)) <=
                    (InputLength - positionAfteralgsSupported);
                uint64_t positionAfterAlgStruct;
                if (!hasEnoughBytes)
                {
                    positionAfterAlgStruct = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfteralgsSupported);
                }
                else
                {
                    uint8_t *truncatedInput = Input;
                    uint64_t truncatedInputLength =
                        positionAfteralgsSupported +
                        (uint64_t)(uint32_t)((uint8_t)4U * EverParseGetBitfield8(none, (uint32_t)0U, (uint32_t)4U));
                    uint64_t result = positionAfteralgsSupported;
                    while (TRUE)
                    {
                        uint64_t position = *&result;
                        BOOLEAN ite;
                        if (!((uint64_t)1U <=
                              (truncatedInputLength - position)))
                        {
                            ite = TRUE;
                        }
                        else
                        {
                            uint64_t positionAfterAlgStruct =
                                ValidateExtendedAlg(
                                    Ctxt,
                                    Err,
                                    truncatedInput,
                                    truncatedInputLength,
                                    position);
                            uint64_t result1;
                            if (EverParseIsSuccess(positionAfterAlgStruct))
                            {
                                result1 = positionAfterAlgStruct;
                            }
                            else
                            {
                                Err("_AlgStruct",
                                    "extended_algs.base.element",
                                    EverParseErrorReasonOfResult(
                                        positionAfterAlgStruct),
                                    Ctxt,
                                    truncatedInput,
                                    position);
                                result1 = positionAfterAlgStruct;
                            }
                            result = result1;
                            ite = EverParseIsError(result1);
                        }
                        if (ite)
                        {
                            break;
                        }
                    }
                    uint64_t res = result;
                    positionAfterAlgStruct = res;
                }
                uint64_t positionAfterextendedAlgs;
                if (EverParseIsSuccess(positionAfterAlgStruct))
                {
                    positionAfterextendedAlgs = positionAfterAlgStruct;
                }
                else
                {
                    Err("_AlgStruct",
                        "extended_algs.base",
                        EverParseErrorReasonOfResult(positionAfterAlgStruct),
                        Ctxt,
                        Input,
                        positionAfteralgsSupported);
                    positionAfterextendedAlgs = positionAfterAlgStruct;
                }
                uint64_t positionAfterAlgStruct1;
                if (EverParseIsSuccess(positionAfterextendedAlgs))
                {
                    BOOLEAN actionSuccessExtendedAlgs;
                    if (IsResp)
                    {
                        actionSuccessExtendedAlgs =
                            EverParseGetBitfield8(
                                none, (uint32_t)0U, (uint32_t)4U) <=
                            (uint8_t)1U;
                    }
                    else
                    {
                        actionSuccessExtendedAlgs = TRUE;
                    }
                    if (!actionSuccessExtendedAlgs)
                    {
                        positionAfterAlgStruct1 = EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                            positionAfterextendedAlgs);
                    }
                    else
                    {
                        positionAfterAlgStruct1 = positionAfterextendedAlgs;
                    }
                }
                else
                {
                    positionAfterAlgStruct1 = positionAfterextendedAlgs;
                }
                if (EverParseIsSuccess(positionAfterAlgStruct1))
                {
                    positionAfterAlgStruct0 = positionAfterAlgStruct1;
                }
                else
                {
                    Err("_AlgStruct",
                        "extended_algs",
                        EverParseErrorReasonOfResult(positionAfterAlgStruct1),
                        Ctxt,
                        Input,
                        positionAfteralgsSupported);
                    positionAfterAlgStruct0 = positionAfterAlgStruct1;
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterAlgStruct0))
    {
        return positionAfterAlgStruct0;
    }
    Err("_AlgStruct",
        "none",
        EverParseErrorReasonOfResult(positionAfterAlgStruct0),
        Ctxt,
        Input,
        positionAfteralgType);
    return positionAfterAlgStruct0;
}

static inline uint64_t
ValidateAsymHashAlgs(
    BOOLEAN IsResp,
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
    uint64_t StartPosition)
{
    /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
    BOOLEAN hasBytes = (uint64_t)4U <= (InputLength - StartPosition);
    uint64_t res;
    if (hasBytes)
    {
        res = StartPosition + (uint64_t)4U;
    }
    else
    {
        res = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
    }
    uint64_t positionAfterAsymHashAlgs;
    if (EverParseIsError(res))
    {
        positionAfterAsymHashAlgs = res;
    }
    else
    {
        uint32_t fieldValue = Load32Le(Input + (uint32_t)StartPosition);
        BOOLEAN actionResult;
        if (IsResp)
        {
            actionResult = (EverParseGetBitfield32(
                                fieldValue, (uint32_t)0U, (uint32_t)1U) +
                            EverParseGetBitfield32(
                                fieldValue, (uint32_t)1U, (uint32_t)2U) +
                            EverParseGetBitfield32(
                                fieldValue, (uint32_t)2U, (uint32_t)3U) +
                            EverParseGetBitfield32(
                                fieldValue, (uint32_t)3U, (uint32_t)4U) +
                            EverParseGetBitfield32(
                                fieldValue, (uint32_t)4U, (uint32_t)5U) +
                            EverParseGetBitfield32(
                                fieldValue, (uint32_t)5U, (uint32_t)6U) +
                            EverParseGetBitfield32(
                                fieldValue, (uint32_t)6U, (uint32_t)7U) +
                            EverParseGetBitfield32(
                                fieldValue, (uint32_t)7U, (uint32_t)8U) +
                            EverParseGetBitfield32(
                                fieldValue, (uint32_t)8U, (uint32_t)9U) +
                            EverParseGetBitfield32(
                                fieldValue, (uint32_t)9U, (uint32_t)10U) +
                            EverParseGetBitfield32(
                                fieldValue, (uint32_t)10U, (uint32_t)11U) +
                            EverParseGetBitfield32(
                                fieldValue, (uint32_t)11U, (uint32_t)12U)) <=
                           (uint32_t)(uint8_t)1U;
        }
        else
        {
            actionResult = TRUE;
        }
        if (!actionResult)
        {
            positionAfterAsymHashAlgs = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED, res);
        }
        else
        {
            /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
            BOOLEAN hasBytes = (uint64_t)4U <= (InputLength - res);
            uint64_t res1;
            if (hasBytes)
            {
                res1 = res + (uint64_t)4U;
            }
            else
            {
                res1 = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, res);
            }
            uint64_t positionAfterAsymHashAlgs0;
            if (EverParseIsError(res1))
            {
                positionAfterAsymHashAlgs0 = res1;
            }
            else
            {
                uint32_t fieldValue1 = Load32Le(Input + (uint32_t)res);
                BOOLEAN actionResult1;
                if (IsResp)
                {
                    actionResult1 =
                        (EverParseGetBitfield32(
                             fieldValue1, (uint32_t)0U, (uint32_t)1U) +
                         EverParseGetBitfield32(
                             fieldValue1, (uint32_t)1U, (uint32_t)2U) +
                         EverParseGetBitfield32(
                             fieldValue1, (uint32_t)2U, (uint32_t)3U) +
                         EverParseGetBitfield32(
                             fieldValue1, (uint32_t)3U, (uint32_t)4U) +
                         EverParseGetBitfield32(
                             fieldValue1, (uint32_t)4U, (uint32_t)5U) +
                         EverParseGetBitfield32(
                             fieldValue1, (uint32_t)5U, (uint32_t)6U) +
                         EverParseGetBitfield32(
                             fieldValue1, (uint32_t)6U, (uint32_t)7U)) <=
                        (uint32_t)(uint8_t)1U;
                }
                else
                {
                    actionResult1 = TRUE;
                }
                if (!actionResult1)
                {
                    positionAfterAsymHashAlgs0 = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED, res1);
                }
                else
                {
                    /* Validating field end */
                    uint64_t positionAfterAsymHashAlgs = res1;
                    uint64_t res2;
                    if (EverParseIsSuccess(positionAfterAsymHashAlgs))
                    {
                        res2 = positionAfterAsymHashAlgs;
                    }
                    else
                    {
                        Err("_AsymHashAlgs",
                            "end",
                            EverParseErrorReasonOfResult(
                                positionAfterAsymHashAlgs),
                            Ctxt,
                            Input,
                            res1);
                        res2 = positionAfterAsymHashAlgs;
                    }
                    positionAfterAsymHashAlgs0 = res2;
                }
            }
            if (EverParseIsSuccess(positionAfterAsymHashAlgs0))
            {
                positionAfterAsymHashAlgs = positionAfterAsymHashAlgs0;
            }
            else
            {
                Err("_AsymHashAlgs",
                    "none",
                    EverParseErrorReasonOfResult(positionAfterAsymHashAlgs0),
                    Ctxt,
                    Input,
                    res);
                positionAfterAsymHashAlgs = positionAfterAsymHashAlgs0;
            }
        }
    }
    if (EverParseIsSuccess(positionAfterAsymHashAlgs))
    {
        return positionAfterAsymHashAlgs;
    }
    Err("_AsymHashAlgs",
        "none",
        EverParseErrorReasonOfResult(positionAfterAsymHashAlgs),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterAsymHashAlgs;
}

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
    uint64_t StartPosition)
{
    /* Validating field preamble */
    uint64_t positionAfterNegotiateAlgorithms = ValidatePreamble(
        SPDM____NEGOTIATE_ALGORITHMS,
        Ctxt,
        Err,
        Input,
        InputLength,
        StartPosition);
    uint64_t positionAfterpreamble;
    if (EverParseIsSuccess(positionAfterNegotiateAlgorithms))
    {
        positionAfterpreamble = positionAfterNegotiateAlgorithms;
    }
    else
    {
        Err("_NegotiateAlgorithms",
            "preamble",
            EverParseErrorReasonOfResult(positionAfterNegotiateAlgorithms),
            Ctxt,
            Input,
            StartPosition);
        positionAfterpreamble = positionAfterNegotiateAlgorithms;
    }
    if (EverParseIsError(positionAfterpreamble))
    {
        return positionAfterpreamble;
    }
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - positionAfterpreamble);
    uint64_t positionAfternone;
    if (hasBytes0)
    {
        positionAfternone = positionAfterpreamble + (uint64_t)1U;
    }
    else
    {
        positionAfternone = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterpreamble);
    }
    uint64_t positionAfterNegotiateAlgorithms0;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterNegotiateAlgorithms0 = positionAfternone;
    }
    else
    {
        uint8_t none = Input[(uint32_t)positionAfterpreamble];
        BOOLEAN noneConstraintIsOk = none <= SPDM____MAX_ALGS;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterNegotiateAlgorithms0 = positionAfternone1;
        }
        else
        {
            /* Validating field param_2_reserved */
            /* Checking that we have enough space for a UINT8, i.e., 1 byte */
            BOOLEAN hasBytes0 =
                (uint64_t)1U <= (InputLength - positionAfternone1);
            uint64_t positionAfterNegotiateAlgorithms;
            if (hasBytes0)
            {
                positionAfterNegotiateAlgorithms =
                    positionAfternone1 + (uint64_t)1U;
            }
            else
            {
                positionAfterNegotiateAlgorithms =
                    EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfternone1);
            }
            uint64_t res0;
            if (EverParseIsSuccess(positionAfterNegotiateAlgorithms))
            {
                res0 = positionAfterNegotiateAlgorithms;
            }
            else
            {
                Err("_NegotiateAlgorithms",
                    "param_2_reserved",
                    EverParseErrorReasonOfResult(
                        positionAfterNegotiateAlgorithms),
                    Ctxt,
                    Input,
                    positionAfternone1);
                res0 = positionAfterNegotiateAlgorithms;
            }
            uint64_t positionAfterparam2Reserved = res0;
            if (EverParseIsError(positionAfterparam2Reserved))
            {
                positionAfterNegotiateAlgorithms0 = positionAfterparam2Reserved;
            }
            else
            {
                /* Checking that we have enough space for a UINT16, i.e., 2
                 * bytes */
                BOOLEAN hasBytes0 =
                    (uint64_t)2U <= (InputLength - positionAfterparam2Reserved);
                uint64_t positionAfternone2;
                if (hasBytes0)
                {
                    positionAfternone2 =
                        positionAfterparam2Reserved + (uint64_t)2U;
                }
                else
                {
                    positionAfternone2 = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfterparam2Reserved);
                }
                uint64_t positionAfterNegotiateAlgorithms;
                if (EverParseIsError(positionAfternone2))
                {
                    positionAfterNegotiateAlgorithms = positionAfternone2;
                }
                else
                {
                    uint16_t r =
                        Load16Le(Input + (uint32_t)positionAfterparam2Reserved);
                    uint16_t none1 = (uint16_t)(uint32_t)r;
                    BOOLEAN noneConstraintIsOk1 =
                        none1 <= (uint16_t)(uint8_t)128U;
                    uint64_t positionAfternone3 = EverParseCheckConstraintOk(
                        noneConstraintIsOk1, positionAfternone2);
                    if (EverParseIsError(positionAfternone3))
                    {
                        positionAfterNegotiateAlgorithms = positionAfternone3;
                    }
                    else
                    {
                        /* Validating field __bitfield_0 */
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes0 =
                            (uint64_t)1U <= (InputLength - positionAfternone3);
                        uint64_t positionAfterNegotiateAlgorithms0;
                        if (hasBytes0)
                        {
                            positionAfterNegotiateAlgorithms0 =
                                positionAfternone3 + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterNegotiateAlgorithms0 =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    positionAfternone3);
                        }
                        uint64_t res0;
                        if (EverParseIsSuccess(
                                positionAfterNegotiateAlgorithms0))
                        {
                            res0 = positionAfterNegotiateAlgorithms0;
                        }
                        else
                        {
                            Err("_NegotiateAlgorithms",
                                "__bitfield_0",
                                EverParseErrorReasonOfResult(
                                    positionAfterNegotiateAlgorithms0),
                                Ctxt,
                                Input,
                                positionAfternone3);
                            res0 = positionAfterNegotiateAlgorithms0;
                        }
                        uint64_t positionAfterBitfield0 = res0;
                        if (EverParseIsError(positionAfterBitfield0))
                        {
                            positionAfterNegotiateAlgorithms =
                                positionAfterBitfield0;
                        }
                        else
                        {
                            /* Validating field __bitfield_1 */
                            /* Checking that we have enough space for a UINT8,
                             * i.e., 1 byte */
                            BOOLEAN hasBytes0 =
                                (uint64_t)1U <=
                                (InputLength - positionAfterBitfield0);
                            uint64_t positionAfterNegotiateAlgorithms0;
                            if (hasBytes0)
                            {
                                positionAfterNegotiateAlgorithms0 =
                                    positionAfterBitfield0 + (uint64_t)1U;
                            }
                            else
                            {
                                positionAfterNegotiateAlgorithms0 =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        positionAfterBitfield0);
                            }
                            uint64_t res0;
                            if (EverParseIsSuccess(
                                    positionAfterNegotiateAlgorithms0))
                            {
                                res0 = positionAfterNegotiateAlgorithms0;
                            }
                            else
                            {
                                Err("_NegotiateAlgorithms",
                                    "__bitfield_1",
                                    EverParseErrorReasonOfResult(
                                        positionAfterNegotiateAlgorithms0),
                                    Ctxt,
                                    Input,
                                    positionAfterBitfield0);
                                res0 = positionAfterNegotiateAlgorithms0;
                            }
                            uint64_t positionAfterBitfield1 = res0;
                            if (EverParseIsError(positionAfterBitfield1))
                            {
                                positionAfterNegotiateAlgorithms =
                                    positionAfterBitfield1;
                            }
                            else
                            {
                                /* Validating field asym_hash_algs */
                                uint64_t positionAfterNegotiateAlgorithms0 =
                                    ValidateAsymHashAlgs(
                                        FALSE,
                                        Ctxt,
                                        Err,
                                        Input,
                                        InputLength,
                                        positionAfterBitfield1);
                                uint64_t positionAfterasymHashAlgs;
                                if (EverParseIsSuccess(
                                        positionAfterNegotiateAlgorithms0))
                                {
                                    positionAfterasymHashAlgs =
                                        positionAfterNegotiateAlgorithms0;
                                }
                                else
                                {
                                    Err("_NegotiateAlgorithms",
                                        "asym_hash_algs",
                                        EverParseErrorReasonOfResult(
                                            positionAfterNegotiateAlgorithms0),
                                        Ctxt,
                                        Input,
                                        positionAfterBitfield1);
                                    positionAfterasymHashAlgs =
                                        positionAfterNegotiateAlgorithms0;
                                }
                                if (EverParseIsError(positionAfterasymHashAlgs))
                                {
                                    positionAfterNegotiateAlgorithms =
                                        positionAfterasymHashAlgs;
                                }
                                else
                                {
                                    /* Validating field reserved_0 */
                                    BOOLEAN
                                    hasEnoughBytes0 =
                                        (uint64_t)(uint32_t)(uint8_t)12U <=
                                        (InputLength -
                                         positionAfterasymHashAlgs);
                                    uint64_t positionAfterNegotiateAlgorithms0;
                                    if (!hasEnoughBytes0)
                                    {
                                        positionAfterNegotiateAlgorithms0 =
                                            EverParseSetValidatorErrorPos(
                                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                positionAfterasymHashAlgs);
                                    }
                                    else
                                    {
                                        uint8_t *truncatedInput = Input;
                                        uint64_t truncatedInputLength =
                                            positionAfterasymHashAlgs +
                                            (uint64_t)(uint32_t)(uint8_t)12U;
                                        uint64_t result =
                                            positionAfterasymHashAlgs;
                                        while (TRUE)
                                        {
                                            uint64_t position = *&result;
                                            BOOLEAN ite;
                                            if (!((uint64_t)1U <=
                                                  (truncatedInputLength -
                                                   position)))
                                            {
                                                ite = TRUE;
                                            }
                                            else
                                            {
                                                /* Checking that we have enough
                                                 * space for a UINT8, i.e., 1
                                                 * byte */
                                                BOOLEAN hasBytes =
                                                    (uint64_t)1U <=
                                                    (truncatedInputLength -
                                                     position);
                                                uint64_t
                                                    positionAfterNegotiateAlgorithms;
                                                if (hasBytes)
                                                {
                                                    positionAfterNegotiateAlgorithms =
                                                        position + (uint64_t)1U;
                                                }
                                                else
                                                {
                                                    positionAfterNegotiateAlgorithms =
                                                        EverParseSetValidatorErrorPos(
                                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                            position);
                                                }
                                                uint64_t res;
                                                if (EverParseIsSuccess(
                                                        positionAfterNegotiateAlgorithms))
                                                {
                                                    res =
                                                        positionAfterNegotiateAlgorithms;
                                                }
                                                else
                                                {
                                                    Err("_NegotiateAlgorithms",
                                                        "reserved_0.element",
                                                        EverParseErrorReasonOfResult(
                                                            positionAfterNegotiateAlgorithms),
                                                        Ctxt,
                                                        truncatedInput,
                                                        position);
                                                    res =
                                                        positionAfterNegotiateAlgorithms;
                                                }
                                                uint64_t result1 = res;
                                                result = result1;
                                                ite = EverParseIsError(result1);
                                            }
                                            if (ite)
                                            {
                                                break;
                                            }
                                        }
                                        uint64_t res = result;
                                        positionAfterNegotiateAlgorithms0 = res;
                                    }
                                    uint64_t positionAfterreserved0;
                                    if (EverParseIsSuccess(
                                            positionAfterNegotiateAlgorithms0))
                                    {
                                        positionAfterreserved0 =
                                            positionAfterNegotiateAlgorithms0;
                                    }
                                    else
                                    {
                                        Err("_NegotiateAlgorithms",
                                            "reserved_0",
                                            EverParseErrorReasonOfResult(
                                                positionAfterNegotiateAlgorithms0),
                                            Ctxt,
                                            Input,
                                            positionAfterasymHashAlgs);
                                        positionAfterreserved0 =
                                            positionAfterNegotiateAlgorithms0;
                                    }
                                    if (EverParseIsError(
                                            positionAfterreserved0))
                                    {
                                        positionAfterNegotiateAlgorithms =
                                            positionAfterreserved0;
                                    }
                                    else
                                    {
                                        /* Checking that we have enough space
                                         * for a UINT8, i.e., 1 byte */
                                        BOOLEAN hasBytes0 =
                                            (uint64_t)1U <=
                                            (InputLength -
                                             positionAfterreserved0);
                                        uint64_t positionAfternone4;
                                        if (hasBytes0)
                                        {
                                            positionAfternone4 =
                                                positionAfterreserved0 +
                                                (uint64_t)1U;
                                        }
                                        else
                                        {
                                            positionAfternone4 =
                                                EverParseSetValidatorErrorPos(
                                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                    positionAfterreserved0);
                                        }
                                        uint64_t
                                            positionAfterNegotiateAlgorithms0;
                                        if (EverParseIsError(
                                                positionAfternone4))
                                        {
                                            positionAfterNegotiateAlgorithms0 =
                                                positionAfternone4;
                                        }
                                        else
                                        {
                                            uint8_t none2 = Input
                                                [(uint32_t)
                                                     positionAfterreserved0];
                                            BOOLEAN noneConstraintIsOk2 =
                                                none2 <= SPDM____MAX_ALGS;
                                            uint64_t positionAfternone5 =
                                                EverParseCheckConstraintOk(
                                                    noneConstraintIsOk2,
                                                    positionAfternone4);
                                            if (EverParseIsError(
                                                    positionAfternone5))
                                            {
                                                positionAfterNegotiateAlgorithms0 =
                                                    positionAfternone5;
                                            }
                                            else
                                            {
                                                /* Checking that we have enough
                                                 * space for a UINT8, i.e., 1
                                                 * byte */
                                                BOOLEAN hasBytes0 =
                                                    (uint64_t)1U <=
                                                    (InputLength -
                                                     positionAfternone5);
                                                uint64_t positionAfternone6;
                                                if (hasBytes0)
                                                {
                                                    positionAfternone6 =
                                                        positionAfternone5 +
                                                        (uint64_t)1U;
                                                }
                                                else
                                                {
                                                    positionAfternone6 =
                                                        EverParseSetValidatorErrorPos(
                                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                            positionAfternone5);
                                                }
                                                uint64_t
                                                    positionAfterNegotiateAlgorithms;
                                                if (EverParseIsError(
                                                        positionAfternone6))
                                                {
                                                    positionAfterNegotiateAlgorithms =
                                                        positionAfternone6;
                                                }
                                                else
                                                {
                                                    uint8_t none3 = Input
                                                        [(uint32_t)
                                                             positionAfternone5];
                                                    BOOLEAN
                                                    noneConstraintIsOk3 =
                                                        none3 <=
                                                            SPDM____MAX_ALGS &&
                                                        (none3 + none2) <=
                                                            SPDM____MAX_ALGS &&
                                                        (uint32_t)none1 >=
                                                            ((uint32_t)32U +
                                                             (uint32_t)((uint8_t)4U * (none2 + none3)));
                                                    uint64_t positionAfternone7 =
                                                        EverParseCheckConstraintOk(
                                                            noneConstraintIsOk3,
                                                            positionAfternone6);
                                                    if (EverParseIsError(
                                                            positionAfternone7))
                                                    {
                                                        positionAfterNegotiateAlgorithms =
                                                            positionAfternone7;
                                                    }
                                                    else
                                                    {
                                                        /* Validating field
                                                         * reserved_1 */
                                                        /* Checking that we have
                                                         * enough space for a
                                                         * UINT16, i.e., 2 bytes
                                                         */
                                                        BOOLEAN hasBytes =
                                                            (uint64_t)2U <=
                                                            (InputLength -
                                                             positionAfternone7);
                                                        uint64_t
                                                            positionAfterNegotiateAlgorithms0;
                                                        if (hasBytes)
                                                        {
                                                            positionAfterNegotiateAlgorithms0 =
                                                                positionAfternone7 +
                                                                (uint64_t)2U;
                                                        }
                                                        else
                                                        {
                                                            positionAfterNegotiateAlgorithms0 =
                                                                EverParseSetValidatorErrorPos(
                                                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                    positionAfternone7);
                                                        }
                                                        uint64_t res;
                                                        if (EverParseIsSuccess(
                                                                positionAfterNegotiateAlgorithms0))
                                                        {
                                                            res =
                                                                positionAfterNegotiateAlgorithms0;
                                                        }
                                                        else
                                                        {
                                                            Err("_NegotiateAlgo"
                                                                "rithms",
                                                                "reserved_1",
                                                                EverParseErrorReasonOfResult(
                                                                    positionAfterNegotiateAlgorithms0),
                                                                Ctxt,
                                                                Input,
                                                                positionAfternone7);
                                                            res =
                                                                positionAfterNegotiateAlgorithms0;
                                                        }
                                                        uint64_t
                                                            positionAfterreserved1 =
                                                                res;
                                                        if (EverParseIsError(
                                                                positionAfterreserved1))
                                                        {
                                                            positionAfterNegotiateAlgorithms =
                                                                positionAfterreserved1;
                                                        }
                                                        else
                                                        {
                                                            /* Validating field
                                                             * ext_asym */
                                                            BOOLEAN
                                                            hasEnoughBytes0 =
                                                                (uint64_t)(uint32_t)((uint8_t)4U * none2) <=
                                                                (InputLength -
                                                                 positionAfterreserved1);
                                                            uint64_t
                                                                positionAfterNegotiateAlgorithms0;
                                                            if (!hasEnoughBytes0)
                                                            {
                                                                positionAfterNegotiateAlgorithms0 =
                                                                    EverParseSetValidatorErrorPos(
                                                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                        positionAfterreserved1);
                                                            }
                                                            else
                                                            {
                                                                uint8_t *
                                                                    truncatedInput =
                                                                        Input;
                                                                uint64_t truncatedInputLength =
                                                                    positionAfterreserved1 +
                                                                    (uint64_t)(uint32_t)((uint8_t)4U * none2);
                                                                uint64_t result =
                                                                    positionAfterreserved1;
                                                                while (TRUE)
                                                                {
                                                                    uint64_t
                                                                        position =
                                                                            *&result;
                                                                    BOOLEAN ite;
                                                                    if (!((uint64_t)1U <=
                                                                          (truncatedInputLength -
                                                                           position)))
                                                                    {
                                                                        ite =
                                                                            TRUE;
                                                                    }
                                                                    else
                                                                    {
                                                                        uint64_t positionAfterNegotiateAlgorithms =
                                                                            ValidateExtendedAlg(
                                                                                Ctxt,
                                                                                Err,
                                                                                truncatedInput,
                                                                                truncatedInputLength,
                                                                                position);
                                                                        uint64_t
                                                                            result1;
                                                                        if (EverParseIsSuccess(
                                                                                positionAfterNegotiateAlgorithms))
                                                                        {
                                                                            result1 =
                                                                                positionAfterNegotiateAlgorithms;
                                                                        }
                                                                        else
                                                                        {
                                                                            Err("_NegotiateAlgorithms",
                                                                                "ext_asym.base.element",
                                                                                EverParseErrorReasonOfResult(
                                                                                    positionAfterNegotiateAlgorithms),
                                                                                Ctxt,
                                                                                truncatedInput,
                                                                                position);
                                                                            result1 =
                                                                                positionAfterNegotiateAlgorithms;
                                                                        }
                                                                        result =
                                                                            result1;
                                                                        ite = EverParseIsError(
                                                                            result1);
                                                                    }
                                                                    if (ite)
                                                                    {
                                                                        break;
                                                                    }
                                                                }
                                                                uint64_t res =
                                                                    result;
                                                                positionAfterNegotiateAlgorithms0 =
                                                                    res;
                                                            }
                                                            uint64_t
                                                                positionAfterextAsym;
                                                            if (EverParseIsSuccess(
                                                                    positionAfterNegotiateAlgorithms0))
                                                            {
                                                                positionAfterextAsym =
                                                                    positionAfterNegotiateAlgorithms0;
                                                            }
                                                            else
                                                            {
                                                                Err("_Negotiate"
                                                                    "Algorithm"
                                                                    "s",
                                                                    "ext_asym."
                                                                    "base",
                                                                    EverParseErrorReasonOfResult(
                                                                        positionAfterNegotiateAlgorithms0),
                                                                    Ctxt,
                                                                    Input,
                                                                    positionAfterreserved1);
                                                                positionAfterextAsym =
                                                                    positionAfterNegotiateAlgorithms0;
                                                            }
                                                            uint64_t
                                                                positionAfterNegotiateAlgorithms1;
                                                            if (EverParseIsSuccess(
                                                                    positionAfterextAsym))
                                                            {
                                                                uint8_t *hd =
                                                                    Input +
                                                                    (uint32_t)
                                                                        positionAfterreserved1;
                                                                *OutExtAsymAlgs =
                                                                    hd;
                                                                *OutExtAsymCount =
                                                                    (uint32_t)
                                                                        none2;
                                                                BOOLEAN
                                                                    actionSuccessExtAsym =
                                                                        TRUE;
                                                                if (!actionSuccessExtAsym)
                                                                {
                                                                    positionAfterNegotiateAlgorithms1 =
                                                                        EverParseSetValidatorErrorPos(
                                                                            EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                                                                            positionAfterextAsym);
                                                                }
                                                                else
                                                                {
                                                                    positionAfterNegotiateAlgorithms1 =
                                                                        positionAfterextAsym;
                                                                }
                                                            }
                                                            else
                                                            {
                                                                positionAfterNegotiateAlgorithms1 =
                                                                    positionAfterextAsym;
                                                            }
                                                            uint64_t
                                                                positionAfterextAsym0;
                                                            if (EverParseIsSuccess(
                                                                    positionAfterNegotiateAlgorithms1))
                                                            {
                                                                positionAfterextAsym0 =
                                                                    positionAfterNegotiateAlgorithms1;
                                                            }
                                                            else
                                                            {
                                                                Err("_Negotiate"
                                                                    "Algorithm"
                                                                    "s",
                                                                    "ext_asym",
                                                                    EverParseErrorReasonOfResult(
                                                                        positionAfterNegotiateAlgorithms1),
                                                                    Ctxt,
                                                                    Input,
                                                                    positionAfterreserved1);
                                                                positionAfterextAsym0 =
                                                                    positionAfterNegotiateAlgorithms1;
                                                            }
                                                            if (EverParseIsError(
                                                                    positionAfterextAsym0))
                                                            {
                                                                positionAfterNegotiateAlgorithms =
                                                                    positionAfterextAsym0;
                                                            }
                                                            else
                                                            {
                                                                /* Validating
                                                                 * field
                                                                 * ext_hash */
                                                                BOOLEAN
                                                                hasEnoughBytes0 =
                                                                    (uint64_t)(uint32_t)((uint8_t)4U * none3) <=
                                                                    (InputLength -
                                                                     positionAfterextAsym0);
                                                                uint64_t
                                                                    positionAfterNegotiateAlgorithms0;
                                                                if (!hasEnoughBytes0)
                                                                {
                                                                    positionAfterNegotiateAlgorithms0 =
                                                                        EverParseSetValidatorErrorPos(
                                                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                            positionAfterextAsym0);
                                                                }
                                                                else
                                                                {
                                                                    uint8_t *
                                                                        truncatedInput =
                                                                            Input;
                                                                    uint64_t truncatedInputLength =
                                                                        positionAfterextAsym0 +
                                                                        (uint64_t)(uint32_t)((uint8_t)4U * none3);
                                                                    uint64_t result =
                                                                        positionAfterextAsym0;
                                                                    while (TRUE)
                                                                    {
                                                                        uint64_t position =
                                                                            *&result;
                                                                        BOOLEAN
                                                                            ite;
                                                                        if (!((uint64_t)1U <=
                                                                              (truncatedInputLength -
                                                                               position)))
                                                                        {
                                                                            ite =
                                                                                TRUE;
                                                                        }
                                                                        else
                                                                        {
                                                                            uint64_t positionAfterNegotiateAlgorithms =
                                                                                ValidateExtendedAlg(
                                                                                    Ctxt,
                                                                                    Err,
                                                                                    truncatedInput,
                                                                                    truncatedInputLength,
                                                                                    position);
                                                                            uint64_t
                                                                                result1;
                                                                            if (EverParseIsSuccess(
                                                                                    positionAfterNegotiateAlgorithms))
                                                                            {
                                                                                result1 =
                                                                                    positionAfterNegotiateAlgorithms;
                                                                            }
                                                                            else
                                                                            {
                                                                                Err("_NegotiateAlgorithms",
                                                                                    "ext_hash.base.element",
                                                                                    EverParseErrorReasonOfResult(
                                                                                        positionAfterNegotiateAlgorithms),
                                                                                    Ctxt,
                                                                                    truncatedInput,
                                                                                    position);
                                                                                result1 =
                                                                                    positionAfterNegotiateAlgorithms;
                                                                            }
                                                                            result =
                                                                                result1;
                                                                            ite = EverParseIsError(
                                                                                result1);
                                                                        }
                                                                        if (ite)
                                                                        {
                                                                            break;
                                                                        }
                                                                    }
                                                                    uint64_t res =
                                                                        result;
                                                                    positionAfterNegotiateAlgorithms0 =
                                                                        res;
                                                                }
                                                                uint64_t
                                                                    positionAfterextHash;
                                                                if (EverParseIsSuccess(
                                                                        positionAfterNegotiateAlgorithms0))
                                                                {
                                                                    positionAfterextHash =
                                                                        positionAfterNegotiateAlgorithms0;
                                                                }
                                                                else
                                                                {
                                                                    Err("_Negot"
                                                                        "iateAl"
                                                                        "gorith"
                                                                        "ms",
                                                                        "ext_"
                                                                        "hash."
                                                                        "base",
                                                                        EverParseErrorReasonOfResult(
                                                                            positionAfterNegotiateAlgorithms0),
                                                                        Ctxt,
                                                                        Input,
                                                                        positionAfterextAsym0);
                                                                    positionAfterextHash =
                                                                        positionAfterNegotiateAlgorithms0;
                                                                }
                                                                uint64_t
                                                                    positionAfterNegotiateAlgorithms1;
                                                                if (EverParseIsSuccess(
                                                                        positionAfterextHash))
                                                                {
                                                                    uint8_t *hd =
                                                                        Input +
                                                                        (uint32_t)
                                                                            positionAfterextAsym0;
                                                                    *OutExtHashAlgs =
                                                                        hd;
                                                                    *OutExtHashCount =
                                                                        (uint32_t)
                                                                            none3;
                                                                    BOOLEAN
                                                                        actionSuccessExtHash =
                                                                            TRUE;
                                                                    if (!actionSuccessExtHash)
                                                                    {
                                                                        positionAfterNegotiateAlgorithms1 =
                                                                            EverParseSetValidatorErrorPos(
                                                                                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                                                                                positionAfterextHash);
                                                                    }
                                                                    else
                                                                    {
                                                                        positionAfterNegotiateAlgorithms1 =
                                                                            positionAfterextHash;
                                                                    }
                                                                }
                                                                else
                                                                {
                                                                    positionAfterNegotiateAlgorithms1 =
                                                                        positionAfterextHash;
                                                                }
                                                                uint64_t
                                                                    positionAfterextHash0;
                                                                if (EverParseIsSuccess(
                                                                        positionAfterNegotiateAlgorithms1))
                                                                {
                                                                    positionAfterextHash0 =
                                                                        positionAfterNegotiateAlgorithms1;
                                                                }
                                                                else
                                                                {
                                                                    Err("_Negot"
                                                                        "iateAl"
                                                                        "gorith"
                                                                        "ms",
                                                                        "ext_"
                                                                        "hash",
                                                                        EverParseErrorReasonOfResult(
                                                                            positionAfterNegotiateAlgorithms1),
                                                                        Ctxt,
                                                                        Input,
                                                                        positionAfterextAsym0);
                                                                    positionAfterextHash0 =
                                                                        positionAfterNegotiateAlgorithms1;
                                                                }
                                                                if (EverParseIsError(
                                                                        positionAfterextHash0))
                                                                {
                                                                    positionAfterNegotiateAlgorithms =
                                                                        positionAfterextHash0;
                                                                }
                                                                else
                                                                {
                                                                    /* Validating
                                                                     * field
                                                                     * alg_structs
                                                                     */
                                                                    BOOLEAN
                                                                    hasEnoughBytes =
                                                                        (uint64_t)((uint32_t)none1 - ((uint32_t)32U + (uint32_t)((uint8_t)4U * (none2 + none3)))) <=
                                                                        (InputLength -
                                                                         positionAfterextHash0);
                                                                    uint64_t
                                                                        positionAfterNegotiateAlgorithms0;
                                                                    if (!hasEnoughBytes)
                                                                    {
                                                                        positionAfterNegotiateAlgorithms0 =
                                                                            EverParseSetValidatorErrorPos(
                                                                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                                positionAfterextHash0);
                                                                    }
                                                                    else
                                                                    {
                                                                        uint8_t *
                                                                            truncatedInput =
                                                                                Input;
                                                                        uint64_t truncatedInputLength =
                                                                            positionAfterextHash0 +
                                                                            (uint64_t)((uint32_t)none1 - ((uint32_t)32U + (uint32_t)((uint8_t)4U * (none2 + none3))));
                                                                        uint64_t
                                                                            result =
                                                                                positionAfterextHash0;
                                                                        while (
                                                                            TRUE)
                                                                        {
                                                                            uint64_t position =
                                                                                *&result;
                                                                            BOOLEAN
                                                                                ite;
                                                                            if (!((uint64_t)1U <=
                                                                                  (truncatedInputLength -
                                                                                   position)))
                                                                            {
                                                                                ite =
                                                                                    TRUE;
                                                                            }
                                                                            else
                                                                            {
                                                                                uint64_t positionAfterNegotiateAlgorithms =
                                                                                    ValidateAlgStruct(
                                                                                        FALSE,
                                                                                        Ctxt,
                                                                                        Err,
                                                                                        truncatedInput,
                                                                                        truncatedInputLength,
                                                                                        position);
                                                                                uint64_t
                                                                                    result1;
                                                                                if (EverParseIsSuccess(
                                                                                        positionAfterNegotiateAlgorithms))
                                                                                {
                                                                                    result1 =
                                                                                        positionAfterNegotiateAlgorithms;
                                                                                }
                                                                                else
                                                                                {
                                                                                    Err("_NegotiateAlgorithms",
                                                                                        "alg_structs.base.element",
                                                                                        EverParseErrorReasonOfResult(
                                                                                            positionAfterNegotiateAlgorithms),
                                                                                        Ctxt,
                                                                                        truncatedInput,
                                                                                        position);
                                                                                    result1 =
                                                                                        positionAfterNegotiateAlgorithms;
                                                                                }
                                                                                result =
                                                                                    result1;
                                                                                ite = EverParseIsError(
                                                                                    result1);
                                                                            }
                                                                            if (ite)
                                                                            {
                                                                                break;
                                                                            }
                                                                        }
                                                                        uint64_t
                                                                            res =
                                                                                result;
                                                                        positionAfterNegotiateAlgorithms0 =
                                                                            res;
                                                                    }
                                                                    uint64_t
                                                                        positionAfteralgStructs;
                                                                    if (EverParseIsSuccess(
                                                                            positionAfterNegotiateAlgorithms0))
                                                                    {
                                                                        positionAfteralgStructs =
                                                                            positionAfterNegotiateAlgorithms0;
                                                                    }
                                                                    else
                                                                    {
                                                                        Err("_N"
                                                                            "eg"
                                                                            "ot"
                                                                            "ia"
                                                                            "te"
                                                                            "Al"
                                                                            "go"
                                                                            "ri"
                                                                            "th"
                                                                            "m"
                                                                            "s",
                                                                            "al"
                                                                            "g_"
                                                                            "st"
                                                                            "ru"
                                                                            "ct"
                                                                            "s."
                                                                            "ba"
                                                                            "s"
                                                                            "e",
                                                                            EverParseErrorReasonOfResult(
                                                                                positionAfterNegotiateAlgorithms0),
                                                                            Ctxt,
                                                                            Input,
                                                                            positionAfterextHash0);
                                                                        positionAfteralgStructs =
                                                                            positionAfterNegotiateAlgorithms0;
                                                                    }
                                                                    uint64_t
                                                                        positionAfterNegotiateAlgorithms1;
                                                                    if (EverParseIsSuccess(
                                                                            positionAfteralgStructs))
                                                                    {
                                                                        uint8_t *hd =
                                                                            Input +
                                                                            (uint32_t)
                                                                                positionAfterextHash0;
                                                                        *OutAlgStructs =
                                                                            hd;
                                                                        *OutAlgStructCount =
                                                                            (uint32_t)
                                                                                none;
                                                                        *OutAlgStructsLen =
                                                                            (uint32_t)
                                                                                none1 -
                                                                            ((uint32_t)32U +
                                                                             (uint32_t)((uint8_t)4U * (none2 + none3)));
                                                                        BOOLEAN actionSuccessAlgStructs =
                                                                            TRUE;
                                                                        if (!actionSuccessAlgStructs)
                                                                        {
                                                                            positionAfterNegotiateAlgorithms1 =
                                                                                EverParseSetValidatorErrorPos(
                                                                                    EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                                                                                    positionAfteralgStructs);
                                                                        }
                                                                        else
                                                                        {
                                                                            positionAfterNegotiateAlgorithms1 =
                                                                                positionAfteralgStructs;
                                                                        }
                                                                    }
                                                                    else
                                                                    {
                                                                        positionAfterNegotiateAlgorithms1 =
                                                                            positionAfteralgStructs;
                                                                    }
                                                                    if (EverParseIsSuccess(
                                                                            positionAfterNegotiateAlgorithms1))
                                                                    {
                                                                        positionAfterNegotiateAlgorithms =
                                                                            positionAfterNegotiateAlgorithms1;
                                                                    }
                                                                    else
                                                                    {
                                                                        Err("_N"
                                                                            "eg"
                                                                            "ot"
                                                                            "ia"
                                                                            "te"
                                                                            "Al"
                                                                            "go"
                                                                            "ri"
                                                                            "th"
                                                                            "m"
                                                                            "s",
                                                                            "al"
                                                                            "g_"
                                                                            "st"
                                                                            "ru"
                                                                            "ct"
                                                                            "s",
                                                                            EverParseErrorReasonOfResult(
                                                                                positionAfterNegotiateAlgorithms1),
                                                                            Ctxt,
                                                                            Input,
                                                                            positionAfterextHash0);
                                                                        positionAfterNegotiateAlgorithms =
                                                                            positionAfterNegotiateAlgorithms1;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                if (EverParseIsSuccess(
                                                        positionAfterNegotiateAlgorithms))
                                                {
                                                    positionAfterNegotiateAlgorithms0 =
                                                        positionAfterNegotiateAlgorithms;
                                                }
                                                else
                                                {
                                                    Err("_NegotiateAlgorithms",
                                                        "none",
                                                        EverParseErrorReasonOfResult(
                                                            positionAfterNegotiateAlgorithms),
                                                        Ctxt,
                                                        Input,
                                                        positionAfternone5);
                                                    positionAfterNegotiateAlgorithms0 =
                                                        positionAfterNegotiateAlgorithms;
                                                }
                                            }
                                        }
                                        if (EverParseIsSuccess(
                                                positionAfterNegotiateAlgorithms0))
                                        {
                                            positionAfterNegotiateAlgorithms =
                                                positionAfterNegotiateAlgorithms0;
                                        }
                                        else
                                        {
                                            Err("_NegotiateAlgorithms",
                                                "none",
                                                EverParseErrorReasonOfResult(
                                                    positionAfterNegotiateAlgorithms0),
                                                Ctxt,
                                                Input,
                                                positionAfterreserved0);
                                            positionAfterNegotiateAlgorithms =
                                                positionAfterNegotiateAlgorithms0;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if (EverParseIsSuccess(positionAfterNegotiateAlgorithms))
                {
                    positionAfterNegotiateAlgorithms0 =
                        positionAfterNegotiateAlgorithms;
                }
                else
                {
                    Err("_NegotiateAlgorithms",
                        "none",
                        EverParseErrorReasonOfResult(
                            positionAfterNegotiateAlgorithms),
                        Ctxt,
                        Input,
                        positionAfterparam2Reserved);
                    positionAfterNegotiateAlgorithms0 =
                        positionAfterNegotiateAlgorithms;
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterNegotiateAlgorithms0))
    {
        return positionAfterNegotiateAlgorithms0;
    }
    Err("_NegotiateAlgorithms",
        "none",
        EverParseErrorReasonOfResult(positionAfterNegotiateAlgorithms0),
        Ctxt,
        Input,
        positionAfterpreamble);
    return positionAfterNegotiateAlgorithms0;
}

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
    uint64_t StartPosition)
{
    /* Validating field preamble */
    uint64_t positionAfterAlgorithms = ValidatePreamble(
        SPDM____ALGORITHMS, Ctxt, Err, Input, InputLength, StartPosition);
    uint64_t positionAfterpreamble;
    if (EverParseIsSuccess(positionAfterAlgorithms))
    {
        positionAfterpreamble = positionAfterAlgorithms;
    }
    else
    {
        Err("_Algorithms",
            "preamble",
            EverParseErrorReasonOfResult(positionAfterAlgorithms),
            Ctxt,
            Input,
            StartPosition);
        positionAfterpreamble = positionAfterAlgorithms;
    }
    if (EverParseIsError(positionAfterpreamble))
    {
        return positionAfterpreamble;
    }
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - positionAfterpreamble);
    uint64_t positionAfternone;
    if (hasBytes0)
    {
        positionAfternone = positionAfterpreamble + (uint64_t)1U;
    }
    else
    {
        positionAfternone = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterpreamble);
    }
    uint64_t positionAfterAlgorithms0;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterAlgorithms0 = positionAfternone;
    }
    else
    {
        uint8_t none = Input[(uint32_t)positionAfterpreamble];
        BOOLEAN noneConstraintIsOk = none <= SPDM____MAX_ALGS;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterAlgorithms0 = positionAfternone1;
        }
        else
        {
            /* Validating field param_2_reserved */
            /* Checking that we have enough space for a UINT8, i.e., 1 byte */
            BOOLEAN hasBytes0 =
                (uint64_t)1U <= (InputLength - positionAfternone1);
            uint64_t positionAfterAlgorithms;
            if (hasBytes0)
            {
                positionAfterAlgorithms = positionAfternone1 + (uint64_t)1U;
            }
            else
            {
                positionAfterAlgorithms = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfternone1);
            }
            uint64_t res0;
            if (EverParseIsSuccess(positionAfterAlgorithms))
            {
                res0 = positionAfterAlgorithms;
            }
            else
            {
                Err("_Algorithms",
                    "param_2_reserved",
                    EverParseErrorReasonOfResult(positionAfterAlgorithms),
                    Ctxt,
                    Input,
                    positionAfternone1);
                res0 = positionAfterAlgorithms;
            }
            uint64_t positionAfterparam2Reserved = res0;
            if (EverParseIsError(positionAfterparam2Reserved))
            {
                positionAfterAlgorithms0 = positionAfterparam2Reserved;
            }
            else
            {
                /* Checking that we have enough space for a UINT16, i.e., 2
                 * bytes */
                BOOLEAN hasBytes0 =
                    (uint64_t)2U <= (InputLength - positionAfterparam2Reserved);
                uint64_t positionAfternone2;
                if (hasBytes0)
                {
                    positionAfternone2 =
                        positionAfterparam2Reserved + (uint64_t)2U;
                }
                else
                {
                    positionAfternone2 = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfterparam2Reserved);
                }
                uint64_t positionAfterAlgorithms;
                if (EverParseIsError(positionAfternone2))
                {
                    positionAfterAlgorithms = positionAfternone2;
                }
                else
                {
                    uint16_t r =
                        Load16Le(Input + (uint32_t)positionAfterparam2Reserved);
                    uint16_t none1 = (uint16_t)(uint32_t)r;
                    BOOLEAN noneConstraintIsOk1 =
                        none1 <= (uint16_t)(uint8_t)128U;
                    uint64_t positionAfternone3 = EverParseCheckConstraintOk(
                        noneConstraintIsOk1, positionAfternone2);
                    if (EverParseIsError(positionAfternone3))
                    {
                        positionAfterAlgorithms = positionAfternone3;
                    }
                    else
                    {
                        /* Validating field __bitfield_0 */
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes0 =
                            (uint64_t)1U <= (InputLength - positionAfternone3);
                        uint64_t positionAfterAlgorithms0;
                        if (hasBytes0)
                        {
                            positionAfterAlgorithms0 =
                                positionAfternone3 + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterAlgorithms0 =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    positionAfternone3);
                        }
                        uint64_t res0;
                        if (EverParseIsSuccess(positionAfterAlgorithms0))
                        {
                            res0 = positionAfterAlgorithms0;
                        }
                        else
                        {
                            Err("_Algorithms",
                                "__bitfield_0",
                                EverParseErrorReasonOfResult(
                                    positionAfterAlgorithms0),
                                Ctxt,
                                Input,
                                positionAfternone3);
                            res0 = positionAfterAlgorithms0;
                        }
                        uint64_t positionAfterBitfield0 = res0;
                        if (EverParseIsError(positionAfterBitfield0))
                        {
                            positionAfterAlgorithms = positionAfterBitfield0;
                        }
                        else
                        {
                            /* Validating field __bitfield_1 */
                            /* Checking that we have enough space for a UINT8,
                             * i.e., 1 byte */
                            BOOLEAN hasBytes0 =
                                (uint64_t)1U <=
                                (InputLength - positionAfterBitfield0);
                            uint64_t positionAfterAlgorithms0;
                            if (hasBytes0)
                            {
                                positionAfterAlgorithms0 =
                                    positionAfterBitfield0 + (uint64_t)1U;
                            }
                            else
                            {
                                positionAfterAlgorithms0 =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        positionAfterBitfield0);
                            }
                            uint64_t res0;
                            if (EverParseIsSuccess(positionAfterAlgorithms0))
                            {
                                res0 = positionAfterAlgorithms0;
                            }
                            else
                            {
                                Err("_Algorithms",
                                    "__bitfield_1",
                                    EverParseErrorReasonOfResult(
                                        positionAfterAlgorithms0),
                                    Ctxt,
                                    Input,
                                    positionAfterBitfield0);
                                res0 = positionAfterAlgorithms0;
                            }
                            uint64_t positionAfterBitfield1 = res0;
                            if (EverParseIsError(positionAfterBitfield1))
                            {
                                positionAfterAlgorithms =
                                    positionAfterBitfield1;
                            }
                            else
                            {
                                /* Checking that we have enough space for a
                                 * UINT32, i.e., 4 bytes */
                                BOOLEAN hasBytes0 =
                                    (uint64_t)4U <=
                                    (InputLength - positionAfterBitfield1);
                                uint64_t positionAfternone4;
                                if (hasBytes0)
                                {
                                    positionAfternone4 =
                                        positionAfterBitfield1 + (uint64_t)4U;
                                }
                                else
                                {
                                    positionAfternone4 =
                                        EverParseSetValidatorErrorPos(
                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                            positionAfterBitfield1);
                                }
                                uint64_t positionAfterAlgorithms0;
                                if (EverParseIsError(positionAfternone4))
                                {
                                    positionAfterAlgorithms0 =
                                        positionAfternone4;
                                }
                                else
                                {
                                    uint32_t none2 = Load32Le(
                                        Input +
                                        (uint32_t)positionAfterBitfield1);
                                    BOOLEAN
                                    noneConstraintIsOk2 =
                                        (EverParseGetBitfield32(
                                             none2,
                                             (uint32_t)0U,
                                             (uint32_t)1U) +
                                         EverParseGetBitfield32(
                                             none2,
                                             (uint32_t)1U,
                                             (uint32_t)2U) +
                                         EverParseGetBitfield32(
                                             none2,
                                             (uint32_t)2U,
                                             (uint32_t)3U) +
                                         EverParseGetBitfield32(
                                             none2,
                                             (uint32_t)3U,
                                             (uint32_t)4U) +
                                         EverParseGetBitfield32(
                                             none2,
                                             (uint32_t)4U,
                                             (uint32_t)5U) +
                                         EverParseGetBitfield32(
                                             none2,
                                             (uint32_t)5U,
                                             (uint32_t)6U) +
                                         EverParseGetBitfield32(
                                             none2,
                                             (uint32_t)6U,
                                             (uint32_t)7U) +
                                         EverParseGetBitfield32(
                                             none2,
                                             (uint32_t)7U,
                                             (uint32_t)8U)) <=
                                        (uint32_t)(uint8_t)1U;
                                    uint64_t positionAfternone5 =
                                        EverParseCheckConstraintOk(
                                            noneConstraintIsOk2,
                                            positionAfternone4);
                                    if (EverParseIsError(positionAfternone5))
                                    {
                                        positionAfterAlgorithms0 =
                                            positionAfternone5;
                                    }
                                    else
                                    {
                                        /* Validating field asym_hash_algs */
                                        uint64_t positionAfterAlgorithms =
                                            ValidateAsymHashAlgs(
                                                TRUE,
                                                Ctxt,
                                                Err,
                                                Input,
                                                InputLength,
                                                positionAfternone5);
                                        uint64_t positionAfterasymHashAlgs;
                                        if (EverParseIsSuccess(
                                                positionAfterAlgorithms))
                                        {
                                            positionAfterasymHashAlgs =
                                                positionAfterAlgorithms;
                                        }
                                        else
                                        {
                                            Err("_Algorithms",
                                                "asym_hash_algs",
                                                EverParseErrorReasonOfResult(
                                                    positionAfterAlgorithms),
                                                Ctxt,
                                                Input,
                                                positionAfternone5);
                                            positionAfterasymHashAlgs =
                                                positionAfterAlgorithms;
                                        }
                                        if (EverParseIsError(
                                                positionAfterasymHashAlgs))
                                        {
                                            positionAfterAlgorithms0 =
                                                positionAfterasymHashAlgs;
                                        }
                                        else
                                        {
                                            /* Validating field reserved_0 */
                                            BOOLEAN
                                            hasEnoughBytes0 =
                                                (uint64_t)(uint32_t)(uint8_t)12U <=
                                                (InputLength -
                                                 positionAfterasymHashAlgs);
                                            uint64_t positionAfterAlgorithms;
                                            if (!hasEnoughBytes0)
                                            {
                                                positionAfterAlgorithms =
                                                    EverParseSetValidatorErrorPos(
                                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                        positionAfterasymHashAlgs);
                                            }
                                            else
                                            {
                                                uint8_t *truncatedInput = Input;
                                                uint64_t truncatedInputLength =
                                                    positionAfterasymHashAlgs +
                                                    (uint64_t)(uint32_t)(uint8_t)12U;
                                                uint64_t result =
                                                    positionAfterasymHashAlgs;
                                                while (TRUE)
                                                {
                                                    uint64_t position =
                                                        *&result;
                                                    BOOLEAN ite;
                                                    if (!((uint64_t)1U <=
                                                          (truncatedInputLength -
                                                           position)))
                                                    {
                                                        ite = TRUE;
                                                    }
                                                    else
                                                    {
                                                        /* Checking that we have
                                                         * enough space for a
                                                         * UINT8, i.e., 1 byte
                                                         */
                                                        BOOLEAN hasBytes =
                                                            (uint64_t)1U <=
                                                            (truncatedInputLength -
                                                             position);
                                                        uint64_t
                                                            positionAfterAlgorithms;
                                                        if (hasBytes)
                                                        {
                                                            positionAfterAlgorithms =
                                                                position +
                                                                (uint64_t)1U;
                                                        }
                                                        else
                                                        {
                                                            positionAfterAlgorithms =
                                                                EverParseSetValidatorErrorPos(
                                                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                    position);
                                                        }
                                                        uint64_t res;
                                                        if (EverParseIsSuccess(
                                                                positionAfterAlgorithms))
                                                        {
                                                            res =
                                                                positionAfterAlgorithms;
                                                        }
                                                        else
                                                        {
                                                            Err("_Algorithms",
                                                                "reserved_0."
                                                                "element",
                                                                EverParseErrorReasonOfResult(
                                                                    positionAfterAlgorithms),
                                                                Ctxt,
                                                                truncatedInput,
                                                                position);
                                                            res =
                                                                positionAfterAlgorithms;
                                                        }
                                                        uint64_t result1 = res;
                                                        result = result1;
                                                        ite = EverParseIsError(
                                                            result1);
                                                    }
                                                    if (ite)
                                                    {
                                                        break;
                                                    }
                                                }
                                                uint64_t res = result;
                                                positionAfterAlgorithms = res;
                                            }
                                            uint64_t positionAfterreserved0;
                                            if (EverParseIsSuccess(
                                                    positionAfterAlgorithms))
                                            {
                                                positionAfterreserved0 =
                                                    positionAfterAlgorithms;
                                            }
                                            else
                                            {
                                                Err("_Algorithms",
                                                    "reserved_0",
                                                    EverParseErrorReasonOfResult(
                                                        positionAfterAlgorithms),
                                                    Ctxt,
                                                    Input,
                                                    positionAfterasymHashAlgs);
                                                positionAfterreserved0 =
                                                    positionAfterAlgorithms;
                                            }
                                            if (EverParseIsError(
                                                    positionAfterreserved0))
                                            {
                                                positionAfterAlgorithms0 =
                                                    positionAfterreserved0;
                                            }
                                            else
                                            {
                                                /* Checking that we have enough
                                                 * space for a UINT8, i.e., 1
                                                 * byte */
                                                BOOLEAN hasBytes0 =
                                                    (uint64_t)1U <=
                                                    (InputLength -
                                                     positionAfterreserved0);
                                                uint64_t positionAfternone6;
                                                if (hasBytes0)
                                                {
                                                    positionAfternone6 =
                                                        positionAfterreserved0 +
                                                        (uint64_t)1U;
                                                }
                                                else
                                                {
                                                    positionAfternone6 =
                                                        EverParseSetValidatorErrorPos(
                                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                            positionAfterreserved0);
                                                }
                                                uint64_t
                                                    positionAfterAlgorithms;
                                                if (EverParseIsError(
                                                        positionAfternone6))
                                                {
                                                    positionAfterAlgorithms =
                                                        positionAfternone6;
                                                }
                                                else
                                                {
                                                    uint8_t none3 = Input
                                                        [(uint32_t)
                                                             positionAfterreserved0];
                                                    BOOLEAN
                                                        noneConstraintIsOk3 =
                                                            none3 <=
                                                            (uint8_t)1U;
                                                    uint64_t positionAfternone7 =
                                                        EverParseCheckConstraintOk(
                                                            noneConstraintIsOk3,
                                                            positionAfternone6);
                                                    if (EverParseIsError(
                                                            positionAfternone7))
                                                    {
                                                        positionAfterAlgorithms =
                                                            positionAfternone7;
                                                    }
                                                    else
                                                    {
                                                        /* Checking that we have
                                                         * enough space for a
                                                         * UINT8, i.e., 1 byte
                                                         */
                                                        BOOLEAN hasBytes0 =
                                                            (uint64_t)1U <=
                                                            (InputLength -
                                                             positionAfternone7);
                                                        uint64_t
                                                            positionAfternone8;
                                                        if (hasBytes0)
                                                        {
                                                            positionAfternone8 =
                                                                positionAfternone7 +
                                                                (uint64_t)1U;
                                                        }
                                                        else
                                                        {
                                                            positionAfternone8 =
                                                                EverParseSetValidatorErrorPos(
                                                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                    positionAfternone7);
                                                        }
                                                        uint64_t
                                                            positionAfterAlgorithms0;
                                                        if (EverParseIsError(
                                                                positionAfternone8))
                                                        {
                                                            positionAfterAlgorithms0 =
                                                                positionAfternone8;
                                                        }
                                                        else
                                                        {
                                                            uint8_t none4 = Input
                                                                [(uint32_t)
                                                                     positionAfternone7];
                                                            BOOLEAN
                                                            noneConstraintIsOk4 =
                                                                none4 <=
                                                                    (uint8_t)1U &&
                                                                (uint32_t)
                                                                        none1 >=
                                                                    ((uint32_t)36U +
                                                                     (uint32_t)((uint8_t)4U * (none3 + none4)));
                                                            uint64_t positionAfternone9 =
                                                                EverParseCheckConstraintOk(
                                                                    noneConstraintIsOk4,
                                                                    positionAfternone8);
                                                            if (EverParseIsError(
                                                                    positionAfternone9))
                                                            {
                                                                positionAfterAlgorithms0 =
                                                                    positionAfternone9;
                                                            }
                                                            else
                                                            {
                                                                /* Validating
                                                                 * field
                                                                 * reserved_1 */
                                                                /* Checking that
                                                                 * we have
                                                                 * enough space
                                                                 * for a UINT16,
                                                                 * i.e., 2 bytes
                                                                 */
                                                                BOOLEAN
                                                                hasBytes =
                                                                    (uint64_t)2U <=
                                                                    (InputLength -
                                                                     positionAfternone9);
                                                                uint64_t
                                                                    positionAfterAlgorithms;
                                                                if (hasBytes)
                                                                {
                                                                    positionAfterAlgorithms =
                                                                        positionAfternone9 +
                                                                        (uint64_t)2U;
                                                                }
                                                                else
                                                                {
                                                                    positionAfterAlgorithms =
                                                                        EverParseSetValidatorErrorPos(
                                                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                            positionAfternone9);
                                                                }
                                                                uint64_t res;
                                                                if (EverParseIsSuccess(
                                                                        positionAfterAlgorithms))
                                                                {
                                                                    res =
                                                                        positionAfterAlgorithms;
                                                                }
                                                                else
                                                                {
                                                                    Err("_Algor"
                                                                        "ithms",
                                                                        "reserv"
                                                                        "ed_1",
                                                                        EverParseErrorReasonOfResult(
                                                                            positionAfterAlgorithms),
                                                                        Ctxt,
                                                                        Input,
                                                                        positionAfternone9);
                                                                    res =
                                                                        positionAfterAlgorithms;
                                                                }
                                                                uint64_t
                                                                    positionAfterreserved1 =
                                                                        res;
                                                                if (EverParseIsError(
                                                                        positionAfterreserved1))
                                                                {
                                                                    positionAfterAlgorithms0 =
                                                                        positionAfterreserved1;
                                                                }
                                                                else
                                                                {
                                                                    /* Validating
                                                                     * field
                                                                     * ext_asym
                                                                     */
                                                                    BOOLEAN
                                                                    hasEnoughBytes0 =
                                                                        (uint64_t)(uint32_t)((uint8_t)4U * none3) <=
                                                                        (InputLength -
                                                                         positionAfterreserved1);
                                                                    uint64_t
                                                                        positionAfterAlgorithms;
                                                                    if (!hasEnoughBytes0)
                                                                    {
                                                                        positionAfterAlgorithms =
                                                                            EverParseSetValidatorErrorPos(
                                                                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                                positionAfterreserved1);
                                                                    }
                                                                    else
                                                                    {
                                                                        uint8_t *
                                                                            truncatedInput =
                                                                                Input;
                                                                        uint64_t truncatedInputLength =
                                                                            positionAfterreserved1 +
                                                                            (uint64_t)(uint32_t)((uint8_t)4U * none3);
                                                                        uint64_t
                                                                            result =
                                                                                positionAfterreserved1;
                                                                        while (
                                                                            TRUE)
                                                                        {
                                                                            uint64_t position =
                                                                                *&result;
                                                                            BOOLEAN
                                                                                ite;
                                                                            if (!((uint64_t)1U <=
                                                                                  (truncatedInputLength -
                                                                                   position)))
                                                                            {
                                                                                ite =
                                                                                    TRUE;
                                                                            }
                                                                            else
                                                                            {
                                                                                uint64_t positionAfterAlgorithms =
                                                                                    ValidateExtendedAlg(
                                                                                        Ctxt,
                                                                                        Err,
                                                                                        truncatedInput,
                                                                                        truncatedInputLength,
                                                                                        position);
                                                                                uint64_t
                                                                                    result1;
                                                                                if (EverParseIsSuccess(
                                                                                        positionAfterAlgorithms))
                                                                                {
                                                                                    result1 =
                                                                                        positionAfterAlgorithms;
                                                                                }
                                                                                else
                                                                                {
                                                                                    Err("_Algorithms",
                                                                                        "ext_asym.base.element",
                                                                                        EverParseErrorReasonOfResult(
                                                                                            positionAfterAlgorithms),
                                                                                        Ctxt,
                                                                                        truncatedInput,
                                                                                        position);
                                                                                    result1 =
                                                                                        positionAfterAlgorithms;
                                                                                }
                                                                                result =
                                                                                    result1;
                                                                                ite = EverParseIsError(
                                                                                    result1);
                                                                            }
                                                                            if (ite)
                                                                            {
                                                                                break;
                                                                            }
                                                                        }
                                                                        uint64_t
                                                                            res =
                                                                                result;
                                                                        positionAfterAlgorithms =
                                                                            res;
                                                                    }
                                                                    uint64_t
                                                                        positionAfterextAsym;
                                                                    if (EverParseIsSuccess(
                                                                            positionAfterAlgorithms))
                                                                    {
                                                                        positionAfterextAsym =
                                                                            positionAfterAlgorithms;
                                                                    }
                                                                    else
                                                                    {
                                                                        Err("_A"
                                                                            "lg"
                                                                            "or"
                                                                            "it"
                                                                            "hm"
                                                                            "s",
                                                                            "ex"
                                                                            "t_"
                                                                            "as"
                                                                            "ym"
                                                                            ".b"
                                                                            "as"
                                                                            "e",
                                                                            EverParseErrorReasonOfResult(
                                                                                positionAfterAlgorithms),
                                                                            Ctxt,
                                                                            Input,
                                                                            positionAfterreserved1);
                                                                        positionAfterextAsym =
                                                                            positionAfterAlgorithms;
                                                                    }
                                                                    uint64_t
                                                                        positionAfterAlgorithms1;
                                                                    if (EverParseIsSuccess(
                                                                            positionAfterextAsym))
                                                                    {
                                                                        uint8_t *hd =
                                                                            Input +
                                                                            (uint32_t)
                                                                                positionAfterreserved1;
                                                                        *OutExtAsymAlgs =
                                                                            hd;
                                                                        *OutExtAsymCount =
                                                                            (uint32_t)
                                                                                none3;
                                                                        BOOLEAN actionSuccessExtAsym =
                                                                            TRUE;
                                                                        if (!actionSuccessExtAsym)
                                                                        {
                                                                            positionAfterAlgorithms1 =
                                                                                EverParseSetValidatorErrorPos(
                                                                                    EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                                                                                    positionAfterextAsym);
                                                                        }
                                                                        else
                                                                        {
                                                                            positionAfterAlgorithms1 =
                                                                                positionAfterextAsym;
                                                                        }
                                                                    }
                                                                    else
                                                                    {
                                                                        positionAfterAlgorithms1 =
                                                                            positionAfterextAsym;
                                                                    }
                                                                    uint64_t
                                                                        positionAfterextAsym0;
                                                                    if (EverParseIsSuccess(
                                                                            positionAfterAlgorithms1))
                                                                    {
                                                                        positionAfterextAsym0 =
                                                                            positionAfterAlgorithms1;
                                                                    }
                                                                    else
                                                                    {
                                                                        Err("_A"
                                                                            "lg"
                                                                            "or"
                                                                            "it"
                                                                            "hm"
                                                                            "s",
                                                                            "ex"
                                                                            "t_"
                                                                            "as"
                                                                            "y"
                                                                            "m",
                                                                            EverParseErrorReasonOfResult(
                                                                                positionAfterAlgorithms1),
                                                                            Ctxt,
                                                                            Input,
                                                                            positionAfterreserved1);
                                                                        positionAfterextAsym0 =
                                                                            positionAfterAlgorithms1;
                                                                    }
                                                                    if (EverParseIsError(
                                                                            positionAfterextAsym0))
                                                                    {
                                                                        positionAfterAlgorithms0 =
                                                                            positionAfterextAsym0;
                                                                    }
                                                                    else
                                                                    {
                                                                        /* Validating
                                                                         * field
                                                                         * ext_hash
                                                                         */
                                                                        BOOLEAN
                                                                        hasEnoughBytes0 =
                                                                            (uint64_t)(uint32_t)((uint8_t)4U * none4) <=
                                                                            (InputLength -
                                                                             positionAfterextAsym0);
                                                                        uint64_t
                                                                            positionAfterAlgorithms;
                                                                        if (!hasEnoughBytes0)
                                                                        {
                                                                            positionAfterAlgorithms =
                                                                                EverParseSetValidatorErrorPos(
                                                                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                                    positionAfterextAsym0);
                                                                        }
                                                                        else
                                                                        {
                                                                            uint8_t
                                                                                *truncatedInput =
                                                                                    Input;
                                                                            uint64_t truncatedInputLength =
                                                                                positionAfterextAsym0 +
                                                                                (uint64_t)(uint32_t)((uint8_t)4U * none4);
                                                                            uint64_t
                                                                                result =
                                                                                    positionAfterextAsym0;
                                                                            while (
                                                                                TRUE)
                                                                            {
                                                                                uint64_t position =
                                                                                    *&result;
                                                                                BOOLEAN
                                                                                    ite;
                                                                                if (!((uint64_t)1U <=
                                                                                      (truncatedInputLength -
                                                                                       position)))
                                                                                {
                                                                                    ite =
                                                                                        TRUE;
                                                                                }
                                                                                else
                                                                                {
                                                                                    uint64_t positionAfterAlgorithms =
                                                                                        ValidateExtendedAlg(
                                                                                            Ctxt,
                                                                                            Err,
                                                                                            truncatedInput,
                                                                                            truncatedInputLength,
                                                                                            position);
                                                                                    uint64_t
                                                                                        result1;
                                                                                    if (EverParseIsSuccess(
                                                                                            positionAfterAlgorithms))
                                                                                    {
                                                                                        result1 =
                                                                                            positionAfterAlgorithms;
                                                                                    }
                                                                                    else
                                                                                    {
                                                                                        Err("_Algorithms",
                                                                                            "ext_hash.base.element",
                                                                                            EverParseErrorReasonOfResult(
                                                                                                positionAfterAlgorithms),
                                                                                            Ctxt,
                                                                                            truncatedInput,
                                                                                            position);
                                                                                        result1 =
                                                                                            positionAfterAlgorithms;
                                                                                    }
                                                                                    result =
                                                                                        result1;
                                                                                    ite = EverParseIsError(
                                                                                        result1);
                                                                                }
                                                                                if (ite)
                                                                                {
                                                                                    break;
                                                                                }
                                                                            }
                                                                            uint64_t
                                                                                res =
                                                                                    result;
                                                                            positionAfterAlgorithms =
                                                                                res;
                                                                        }
                                                                        uint64_t
                                                                            positionAfterextHash;
                                                                        if (EverParseIsSuccess(
                                                                                positionAfterAlgorithms))
                                                                        {
                                                                            positionAfterextHash =
                                                                                positionAfterAlgorithms;
                                                                        }
                                                                        else
                                                                        {
                                                                            Err("_Algorithms",
                                                                                "ext_hash.base",
                                                                                EverParseErrorReasonOfResult(
                                                                                    positionAfterAlgorithms),
                                                                                Ctxt,
                                                                                Input,
                                                                                positionAfterextAsym0);
                                                                            positionAfterextHash =
                                                                                positionAfterAlgorithms;
                                                                        }
                                                                        uint64_t
                                                                            positionAfterAlgorithms1;
                                                                        if (EverParseIsSuccess(
                                                                                positionAfterextHash))
                                                                        {
                                                                            uint8_t *hd =
                                                                                Input +
                                                                                (uint32_t)
                                                                                    positionAfterextAsym0;
                                                                            *OutExtHashAlgs =
                                                                                hd;
                                                                            *OutExtHashCount =
                                                                                (uint32_t)
                                                                                    none4;
                                                                            BOOLEAN actionSuccessExtHash =
                                                                                TRUE;
                                                                            if (!actionSuccessExtHash)
                                                                            {
                                                                                positionAfterAlgorithms1 =
                                                                                    EverParseSetValidatorErrorPos(
                                                                                        EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                                                                                        positionAfterextHash);
                                                                            }
                                                                            else
                                                                            {
                                                                                positionAfterAlgorithms1 =
                                                                                    positionAfterextHash;
                                                                            }
                                                                        }
                                                                        else
                                                                        {
                                                                            positionAfterAlgorithms1 =
                                                                                positionAfterextHash;
                                                                        }
                                                                        uint64_t
                                                                            positionAfterextHash0;
                                                                        if (EverParseIsSuccess(
                                                                                positionAfterAlgorithms1))
                                                                        {
                                                                            positionAfterextHash0 =
                                                                                positionAfterAlgorithms1;
                                                                        }
                                                                        else
                                                                        {
                                                                            Err("_Algorithms",
                                                                                "ext_hash",
                                                                                EverParseErrorReasonOfResult(
                                                                                    positionAfterAlgorithms1),
                                                                                Ctxt,
                                                                                Input,
                                                                                positionAfterextAsym0);
                                                                            positionAfterextHash0 =
                                                                                positionAfterAlgorithms1;
                                                                        }
                                                                        if (EverParseIsError(
                                                                                positionAfterextHash0))
                                                                        {
                                                                            positionAfterAlgorithms0 =
                                                                                positionAfterextHash0;
                                                                        }
                                                                        else
                                                                        {
                                                                            /* Validating
                                                                             * field alg_structs */
                                                                            BOOLEAN
                                                                            hasEnoughBytes =
                                                                                (uint64_t)((uint32_t)none1 - ((uint32_t)36U + (uint32_t)((uint8_t)4U * (none3 + none4)))) <=
                                                                                (InputLength -
                                                                                 positionAfterextHash0);
                                                                            uint64_t
                                                                                positionAfterAlgorithms;
                                                                            if (!hasEnoughBytes)
                                                                            {
                                                                                positionAfterAlgorithms =
                                                                                    EverParseSetValidatorErrorPos(
                                                                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                                                        positionAfterextHash0);
                                                                            }
                                                                            else
                                                                            {
                                                                                uint8_t
                                                                                    *truncatedInput =
                                                                                        Input;
                                                                                uint64_t truncatedInputLength =
                                                                                    positionAfterextHash0 +
                                                                                    (uint64_t)((uint32_t)none1 - ((uint32_t)36U + (uint32_t)((uint8_t)4U * (none3 + none4))));
                                                                                uint64_t
                                                                                    result =
                                                                                        positionAfterextHash0;
                                                                                while (
                                                                                    TRUE)
                                                                                {
                                                                                    uint64_t position =
                                                                                        *&result;
                                                                                    BOOLEAN
                                                                                        ite;
                                                                                    if (!((uint64_t)1U <=
                                                                                          (truncatedInputLength -
                                                                                           position)))
                                                                                    {
                                                                                        ite =
                                                                                            TRUE;
                                                                                    }
                                                                                    else
                                                                                    {
                                                                                        uint64_t positionAfterAlgorithms =
                                                                                            ValidateAlgStruct(
                                                                                                TRUE,
                                                                                                Ctxt,
                                                                                                Err,
                                                                                                truncatedInput,
                                                                                                truncatedInputLength,
                                                                                                position);
                                                                                        uint64_t
                                                                                            result1;
                                                                                        if (EverParseIsSuccess(
                                                                                                positionAfterAlgorithms))
                                                                                        {
                                                                                            result1 =
                                                                                                positionAfterAlgorithms;
                                                                                        }
                                                                                        else
                                                                                        {
                                                                                            Err("_Algorithms",
                                                                                                "alg_structs.base.element",
                                                                                                EverParseErrorReasonOfResult(
                                                                                                    positionAfterAlgorithms),
                                                                                                Ctxt,
                                                                                                truncatedInput,
                                                                                                position);
                                                                                            result1 =
                                                                                                positionAfterAlgorithms;
                                                                                        }
                                                                                        result =
                                                                                            result1;
                                                                                        ite = EverParseIsError(
                                                                                            result1);
                                                                                    }
                                                                                    if (ite)
                                                                                    {
                                                                                        break;
                                                                                    }
                                                                                }
                                                                                uint64_t
                                                                                    res =
                                                                                        result;
                                                                                positionAfterAlgorithms =
                                                                                    res;
                                                                            }
                                                                            uint64_t
                                                                                positionAfteralgStructs;
                                                                            if (EverParseIsSuccess(
                                                                                    positionAfterAlgorithms))
                                                                            {
                                                                                positionAfteralgStructs =
                                                                                    positionAfterAlgorithms;
                                                                            }
                                                                            else
                                                                            {
                                                                                Err("_Algorithms",
                                                                                    "alg_structs.base",
                                                                                    EverParseErrorReasonOfResult(
                                                                                        positionAfterAlgorithms),
                                                                                    Ctxt,
                                                                                    Input,
                                                                                    positionAfterextHash0);
                                                                                positionAfteralgStructs =
                                                                                    positionAfterAlgorithms;
                                                                            }
                                                                            uint64_t
                                                                                positionAfterAlgorithms1;
                                                                            if (EverParseIsSuccess(
                                                                                    positionAfteralgStructs))
                                                                            {
                                                                                uint8_t *hd =
                                                                                    Input +
                                                                                    (uint32_t)
                                                                                        positionAfterextHash0;
                                                                                *OutAlgStructs =
                                                                                    hd;
                                                                                *OutAlgStructCount =
                                                                                    (uint32_t)
                                                                                        none;
                                                                                *OutAlgStructsLen =
                                                                                    (uint32_t)
                                                                                        none1 -
                                                                                    ((uint32_t)36U +
                                                                                     (uint32_t)((uint8_t)4U * (none3 + none4)));
                                                                                BOOLEAN actionSuccessAlgStructs =
                                                                                    TRUE;
                                                                                if (!actionSuccessAlgStructs)
                                                                                {
                                                                                    positionAfterAlgorithms1 =
                                                                                        EverParseSetValidatorErrorPos(
                                                                                            EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                                                                                            positionAfteralgStructs);
                                                                                }
                                                                                else
                                                                                {
                                                                                    positionAfterAlgorithms1 =
                                                                                        positionAfteralgStructs;
                                                                                }
                                                                            }
                                                                            else
                                                                            {
                                                                                positionAfterAlgorithms1 =
                                                                                    positionAfteralgStructs;
                                                                            }
                                                                            if (EverParseIsSuccess(
                                                                                    positionAfterAlgorithms1))
                                                                            {
                                                                                positionAfterAlgorithms0 =
                                                                                    positionAfterAlgorithms1;
                                                                            }
                                                                            else
                                                                            {
                                                                                Err("_Algorithms",
                                                                                    "alg_structs",
                                                                                    EverParseErrorReasonOfResult(
                                                                                        positionAfterAlgorithms1),
                                                                                    Ctxt,
                                                                                    Input,
                                                                                    positionAfterextHash0);
                                                                                positionAfterAlgorithms0 =
                                                                                    positionAfterAlgorithms1;
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        if (EverParseIsSuccess(
                                                                positionAfterAlgorithms0))
                                                        {
                                                            positionAfterAlgorithms =
                                                                positionAfterAlgorithms0;
                                                        }
                                                        else
                                                        {
                                                            Err("_Algorithms",
                                                                "none",
                                                                EverParseErrorReasonOfResult(
                                                                    positionAfterAlgorithms0),
                                                                Ctxt,
                                                                Input,
                                                                positionAfternone7);
                                                            positionAfterAlgorithms =
                                                                positionAfterAlgorithms0;
                                                        }
                                                    }
                                                }
                                                if (EverParseIsSuccess(
                                                        positionAfterAlgorithms))
                                                {
                                                    positionAfterAlgorithms0 =
                                                        positionAfterAlgorithms;
                                                }
                                                else
                                                {
                                                    Err("_Algorithms",
                                                        "none",
                                                        EverParseErrorReasonOfResult(
                                                            positionAfterAlgorithms),
                                                        Ctxt,
                                                        Input,
                                                        positionAfterreserved0);
                                                    positionAfterAlgorithms0 =
                                                        positionAfterAlgorithms;
                                                }
                                            }
                                        }
                                    }
                                }
                                if (EverParseIsSuccess(
                                        positionAfterAlgorithms0))
                                {
                                    positionAfterAlgorithms =
                                        positionAfterAlgorithms0;
                                }
                                else
                                {
                                    Err("_Algorithms",
                                        "none",
                                        EverParseErrorReasonOfResult(
                                            positionAfterAlgorithms0),
                                        Ctxt,
                                        Input,
                                        positionAfterBitfield1);
                                    positionAfterAlgorithms =
                                        positionAfterAlgorithms0;
                                }
                            }
                        }
                    }
                }
                if (EverParseIsSuccess(positionAfterAlgorithms))
                {
                    positionAfterAlgorithms0 = positionAfterAlgorithms;
                }
                else
                {
                    Err("_Algorithms",
                        "none",
                        EverParseErrorReasonOfResult(positionAfterAlgorithms),
                        Ctxt,
                        Input,
                        positionAfterparam2Reserved);
                    positionAfterAlgorithms0 = positionAfterAlgorithms;
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterAlgorithms0))
    {
        return positionAfterAlgorithms0;
    }
    Err("_Algorithms",
        "none",
        EverParseErrorReasonOfResult(positionAfterAlgorithms0),
        Ctxt,
        Input,
        positionAfterpreamble);
    return positionAfterAlgorithms0;
}

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
    uint64_t StartPosition)
{
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - StartPosition);
    uint64_t positionAfternone;
    if (hasBytes0)
    {
        positionAfternone = StartPosition + (uint64_t)1U;
    }
    else
    {
        positionAfternone = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
    }
    uint64_t positionAfterDheAlg;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterDheAlg = positionAfternone;
    }
    else
    {
        uint8_t none = Input[(uint32_t)StartPosition];
        BOOLEAN noneConstraintIsOk = none == SPDM____ALGTYPE_DHE;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterDheAlg = positionAfternone1;
        }
        else
        {
            /* Checking that we have enough space for a UINT8, i.e., 1 byte */
            BOOLEAN hasBytes0 =
                (uint64_t)1U <= (InputLength - positionAfternone1);
            uint64_t positionAfternone2;
            if (hasBytes0)
            {
                positionAfternone2 = positionAfternone1 + (uint64_t)1U;
            }
            else
            {
                positionAfternone2 = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfternone1);
            }
            uint64_t positionAfterDheAlg0;
            if (EverParseIsError(positionAfternone2))
            {
                positionAfterDheAlg0 = positionAfternone2;
            }
            else
            {
                uint8_t none1 = Input[(uint32_t)positionAfternone1];
                BOOLEAN
                noneConstraintIsOk1 =
                    EverParseGetBitfield8(none1, (uint32_t)0U, (uint32_t)4U) <=
                        SPDM____MAX_ALGS &&
                    EverParseGetBitfield8(none1, (uint32_t)4U, (uint32_t)8U) ==
                        (uint8_t)2U;
                uint64_t positionAfternone3 = EverParseCheckConstraintOk(
                    noneConstraintIsOk1, positionAfternone2);
                if (EverParseIsError(positionAfternone3))
                {
                    positionAfterDheAlg0 = positionAfternone3;
                }
                else
                {
                    /* Checking that we have enough space for a UINT16, i.e., 2
                     * bytes */
                    BOOLEAN hasBytes =
                        (uint64_t)2U <= (InputLength - positionAfternone3);
                    uint64_t positionAfterDheAlg;
                    if (hasBytes)
                    {
                        positionAfterDheAlg = positionAfternone3 + (uint64_t)2U;
                    }
                    else
                    {
                        positionAfterDheAlg = EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfternone3);
                    }
                    uint64_t positionAfterBitfield1;
                    if (EverParseIsSuccess(positionAfterDheAlg))
                    {
                        positionAfterBitfield1 = positionAfterDheAlg;
                    }
                    else
                    {
                        Err("_DheAlg",
                            "__bitfield_1",
                            EverParseErrorReasonOfResult(positionAfterDheAlg),
                            Ctxt,
                            Input,
                            positionAfternone3);
                        positionAfterBitfield1 = positionAfterDheAlg;
                    }
                    if (EverParseIsError(positionAfterBitfield1))
                    {
                        positionAfterDheAlg0 = positionAfterBitfield1;
                    }
                    else
                    {
                        uint16_t r =
                            Load16Le(Input + (uint32_t)positionAfternone3);
                        uint16_t bitfield1 = (uint16_t)(uint32_t)r;
                        /* Validating field alg_external */
                        BOOLEAN
                        hasEnoughBytes =
                            (uint64_t)(uint32_t)((uint8_t)4U * EverParseGetBitfield8(none1, (uint32_t)0U, (uint32_t)4U)) <=
                            (InputLength - positionAfterBitfield1);
                        uint64_t positionAfterDheAlg;
                        if (!hasEnoughBytes)
                        {
                            positionAfterDheAlg = EverParseSetValidatorErrorPos(
                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                positionAfterBitfield1);
                        }
                        else
                        {
                            uint8_t *truncatedInput = Input;
                            uint64_t truncatedInputLength =
                                positionAfterBitfield1 +
                                (uint64_t)(uint32_t)((uint8_t)4U * EverParseGetBitfield8(none1, (uint32_t)0U, (uint32_t)4U));
                            uint64_t result = positionAfterBitfield1;
                            while (TRUE)
                            {
                                uint64_t position = *&result;
                                BOOLEAN ite;
                                if (!((uint64_t)1U <=
                                      (truncatedInputLength - position)))
                                {
                                    ite = TRUE;
                                }
                                else
                                {
                                    uint64_t positionAfterDheAlg =
                                        ValidateExtendedAlg(
                                            Ctxt,
                                            Err,
                                            truncatedInput,
                                            truncatedInputLength,
                                            position);
                                    uint64_t result1;
                                    if (EverParseIsSuccess(positionAfterDheAlg))
                                    {
                                        result1 = positionAfterDheAlg;
                                    }
                                    else
                                    {
                                        Err("_DheAlg",
                                            "alg_external.base.element",
                                            EverParseErrorReasonOfResult(
                                                positionAfterDheAlg),
                                            Ctxt,
                                            truncatedInput,
                                            position);
                                        result1 = positionAfterDheAlg;
                                    }
                                    result = result1;
                                    ite = EverParseIsError(result1);
                                }
                                if (ite)
                                {
                                    break;
                                }
                            }
                            uint64_t res = result;
                            positionAfterDheAlg = res;
                        }
                        uint64_t positionAfteralgExternal;
                        if (EverParseIsSuccess(positionAfterDheAlg))
                        {
                            positionAfteralgExternal = positionAfterDheAlg;
                        }
                        else
                        {
                            Err("_DheAlg",
                                "alg_external.base",
                                EverParseErrorReasonOfResult(
                                    positionAfterDheAlg),
                                Ctxt,
                                Input,
                                positionAfterBitfield1);
                            positionAfteralgExternal = positionAfterDheAlg;
                        }
                        uint64_t positionAfterDheAlg1;
                        if (EverParseIsSuccess(positionAfteralgExternal))
                        {
                            *OutAlgCountExtended =
                                (uint32_t)EverParseGetBitfield8(
                                    none1, (uint32_t)0U, (uint32_t)4U);
                            BOOLEAN actionSuccessAlgExternal;
                            if (IsResp)
                            {
                                actionSuccessAlgExternal =
                                    ((uint16_t)EverParseGetBitfield8(
                                         none1, (uint32_t)0U, (uint32_t)4U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)0U,
                                         (uint32_t)1U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)1U,
                                         (uint32_t)2U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)2U,
                                         (uint32_t)3U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)3U,
                                         (uint32_t)4U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)4U,
                                         (uint32_t)5U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)5U,
                                         (uint32_t)6U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)6U,
                                         (uint32_t)7U)) <=
                                    (uint16_t)(uint8_t)1U;
                            }
                            else
                            {
                                actionSuccessAlgExternal = TRUE;
                            }
                            if (!actionSuccessAlgExternal)
                            {
                                positionAfterDheAlg1 =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                                        positionAfteralgExternal);
                            }
                            else
                            {
                                positionAfterDheAlg1 = positionAfteralgExternal;
                            }
                        }
                        else
                        {
                            positionAfterDheAlg1 = positionAfteralgExternal;
                        }
                        if (EverParseIsSuccess(positionAfterDheAlg1))
                        {
                            positionAfterDheAlg0 = positionAfterDheAlg1;
                        }
                        else
                        {
                            Err("_DheAlg",
                                "alg_external",
                                EverParseErrorReasonOfResult(
                                    positionAfterDheAlg1),
                                Ctxt,
                                Input,
                                positionAfterBitfield1);
                            positionAfterDheAlg0 = positionAfterDheAlg1;
                        }
                    }
                }
            }
            if (EverParseIsSuccess(positionAfterDheAlg0))
            {
                positionAfterDheAlg = positionAfterDheAlg0;
            }
            else
            {
                Err("_DheAlg",
                    "none",
                    EverParseErrorReasonOfResult(positionAfterDheAlg0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterDheAlg = positionAfterDheAlg0;
            }
        }
    }
    if (EverParseIsSuccess(positionAfterDheAlg))
    {
        return positionAfterDheAlg;
    }
    Err("_DheAlg",
        "none",
        EverParseErrorReasonOfResult(positionAfterDheAlg),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterDheAlg;
}

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
    uint64_t StartPosition)
{
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - StartPosition);
    uint64_t positionAfternone;
    if (hasBytes0)
    {
        positionAfternone = StartPosition + (uint64_t)1U;
    }
    else
    {
        positionAfternone = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
    }
    uint64_t positionAfterAeadAlg;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterAeadAlg = positionAfternone;
    }
    else
    {
        uint8_t none = Input[(uint32_t)StartPosition];
        BOOLEAN noneConstraintIsOk = none == SPDM____ALGTYPE_AEAD;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterAeadAlg = positionAfternone1;
        }
        else
        {
            /* Checking that we have enough space for a UINT8, i.e., 1 byte */
            BOOLEAN hasBytes0 =
                (uint64_t)1U <= (InputLength - positionAfternone1);
            uint64_t positionAfternone2;
            if (hasBytes0)
            {
                positionAfternone2 = positionAfternone1 + (uint64_t)1U;
            }
            else
            {
                positionAfternone2 = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfternone1);
            }
            uint64_t positionAfterAeadAlg0;
            if (EverParseIsError(positionAfternone2))
            {
                positionAfterAeadAlg0 = positionAfternone2;
            }
            else
            {
                uint8_t none1 = Input[(uint32_t)positionAfternone1];
                BOOLEAN
                noneConstraintIsOk1 =
                    EverParseGetBitfield8(none1, (uint32_t)0U, (uint32_t)4U) <=
                        SPDM____MAX_ALGS &&
                    EverParseGetBitfield8(none1, (uint32_t)4U, (uint32_t)8U) ==
                        (uint8_t)2U;
                uint64_t positionAfternone3 = EverParseCheckConstraintOk(
                    noneConstraintIsOk1, positionAfternone2);
                if (EverParseIsError(positionAfternone3))
                {
                    positionAfterAeadAlg0 = positionAfternone3;
                }
                else
                {
                    /* Checking that we have enough space for a UINT16, i.e., 2
                     * bytes */
                    BOOLEAN hasBytes =
                        (uint64_t)2U <= (InputLength - positionAfternone3);
                    uint64_t positionAfterAeadAlg;
                    if (hasBytes)
                    {
                        positionAfterAeadAlg =
                            positionAfternone3 + (uint64_t)2U;
                    }
                    else
                    {
                        positionAfterAeadAlg = EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfternone3);
                    }
                    uint64_t positionAfterBitfield1;
                    if (EverParseIsSuccess(positionAfterAeadAlg))
                    {
                        positionAfterBitfield1 = positionAfterAeadAlg;
                    }
                    else
                    {
                        Err("_AeadAlg",
                            "__bitfield_1",
                            EverParseErrorReasonOfResult(positionAfterAeadAlg),
                            Ctxt,
                            Input,
                            positionAfternone3);
                        positionAfterBitfield1 = positionAfterAeadAlg;
                    }
                    if (EverParseIsError(positionAfterBitfield1))
                    {
                        positionAfterAeadAlg0 = positionAfterBitfield1;
                    }
                    else
                    {
                        uint16_t r =
                            Load16Le(Input + (uint32_t)positionAfternone3);
                        uint16_t bitfield1 = (uint16_t)(uint32_t)r;
                        /* Validating field alg_external */
                        BOOLEAN
                        hasEnoughBytes =
                            (uint64_t)(uint32_t)((uint8_t)4U * EverParseGetBitfield8(none1, (uint32_t)0U, (uint32_t)4U)) <=
                            (InputLength - positionAfterBitfield1);
                        uint64_t positionAfterAeadAlg;
                        if (!hasEnoughBytes)
                        {
                            positionAfterAeadAlg =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    positionAfterBitfield1);
                        }
                        else
                        {
                            uint8_t *truncatedInput = Input;
                            uint64_t truncatedInputLength =
                                positionAfterBitfield1 +
                                (uint64_t)(uint32_t)((uint8_t)4U * EverParseGetBitfield8(none1, (uint32_t)0U, (uint32_t)4U));
                            uint64_t result = positionAfterBitfield1;
                            while (TRUE)
                            {
                                uint64_t position = *&result;
                                BOOLEAN ite;
                                if (!((uint64_t)1U <=
                                      (truncatedInputLength - position)))
                                {
                                    ite = TRUE;
                                }
                                else
                                {
                                    uint64_t positionAfterAeadAlg =
                                        ValidateExtendedAlg(
                                            Ctxt,
                                            Err,
                                            truncatedInput,
                                            truncatedInputLength,
                                            position);
                                    uint64_t result1;
                                    if (EverParseIsSuccess(
                                            positionAfterAeadAlg))
                                    {
                                        result1 = positionAfterAeadAlg;
                                    }
                                    else
                                    {
                                        Err("_AeadAlg",
                                            "alg_external.base.element",
                                            EverParseErrorReasonOfResult(
                                                positionAfterAeadAlg),
                                            Ctxt,
                                            truncatedInput,
                                            position);
                                        result1 = positionAfterAeadAlg;
                                    }
                                    result = result1;
                                    ite = EverParseIsError(result1);
                                }
                                if (ite)
                                {
                                    break;
                                }
                            }
                            uint64_t res = result;
                            positionAfterAeadAlg = res;
                        }
                        uint64_t positionAfteralgExternal;
                        if (EverParseIsSuccess(positionAfterAeadAlg))
                        {
                            positionAfteralgExternal = positionAfterAeadAlg;
                        }
                        else
                        {
                            Err("_AeadAlg",
                                "alg_external.base",
                                EverParseErrorReasonOfResult(
                                    positionAfterAeadAlg),
                                Ctxt,
                                Input,
                                positionAfterBitfield1);
                            positionAfteralgExternal = positionAfterAeadAlg;
                        }
                        uint64_t positionAfterAeadAlg1;
                        if (EverParseIsSuccess(positionAfteralgExternal))
                        {
                            *OutAlgCountExtended =
                                (uint32_t)EverParseGetBitfield8(
                                    none1, (uint32_t)0U, (uint32_t)4U);
                            BOOLEAN actionSuccessAlgExternal;
                            if (IsResp)
                            {
                                actionSuccessAlgExternal =
                                    ((uint16_t)EverParseGetBitfield8(
                                         none1, (uint32_t)0U, (uint32_t)4U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)0U,
                                         (uint32_t)1U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)1U,
                                         (uint32_t)2U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)2U,
                                         (uint32_t)3U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)3U,
                                         (uint32_t)4U)) <=
                                    (uint16_t)(uint8_t)1U;
                            }
                            else
                            {
                                actionSuccessAlgExternal = TRUE;
                            }
                            if (!actionSuccessAlgExternal)
                            {
                                positionAfterAeadAlg1 =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                                        positionAfteralgExternal);
                            }
                            else
                            {
                                positionAfterAeadAlg1 =
                                    positionAfteralgExternal;
                            }
                        }
                        else
                        {
                            positionAfterAeadAlg1 = positionAfteralgExternal;
                        }
                        if (EverParseIsSuccess(positionAfterAeadAlg1))
                        {
                            positionAfterAeadAlg0 = positionAfterAeadAlg1;
                        }
                        else
                        {
                            Err("_AeadAlg",
                                "alg_external",
                                EverParseErrorReasonOfResult(
                                    positionAfterAeadAlg1),
                                Ctxt,
                                Input,
                                positionAfterBitfield1);
                            positionAfterAeadAlg0 = positionAfterAeadAlg1;
                        }
                    }
                }
            }
            if (EverParseIsSuccess(positionAfterAeadAlg0))
            {
                positionAfterAeadAlg = positionAfterAeadAlg0;
            }
            else
            {
                Err("_AeadAlg",
                    "none",
                    EverParseErrorReasonOfResult(positionAfterAeadAlg0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterAeadAlg = positionAfterAeadAlg0;
            }
        }
    }
    if (EverParseIsSuccess(positionAfterAeadAlg))
    {
        return positionAfterAeadAlg;
    }
    Err("_AeadAlg",
        "none",
        EverParseErrorReasonOfResult(positionAfterAeadAlg),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterAeadAlg;
}

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
    uint64_t StartPosition)
{
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - StartPosition);
    uint64_t positionAfternone;
    if (hasBytes0)
    {
        positionAfternone = StartPosition + (uint64_t)1U;
    }
    else
    {
        positionAfternone = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
    }
    uint64_t positionAfterAsymAlg;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterAsymAlg = positionAfternone;
    }
    else
    {
        uint8_t none = Input[(uint32_t)StartPosition];
        BOOLEAN noneConstraintIsOk = none == SPDM____ALGTYPE_ASYM;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterAsymAlg = positionAfternone1;
        }
        else
        {
            /* Checking that we have enough space for a UINT8, i.e., 1 byte */
            BOOLEAN hasBytes0 =
                (uint64_t)1U <= (InputLength - positionAfternone1);
            uint64_t positionAfternone2;
            if (hasBytes0)
            {
                positionAfternone2 = positionAfternone1 + (uint64_t)1U;
            }
            else
            {
                positionAfternone2 = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfternone1);
            }
            uint64_t positionAfterAsymAlg0;
            if (EverParseIsError(positionAfternone2))
            {
                positionAfterAsymAlg0 = positionAfternone2;
            }
            else
            {
                uint8_t none1 = Input[(uint32_t)positionAfternone1];
                BOOLEAN
                noneConstraintIsOk1 =
                    EverParseGetBitfield8(none1, (uint32_t)0U, (uint32_t)4U) <=
                        SPDM____MAX_ALGS &&
                    EverParseGetBitfield8(none1, (uint32_t)4U, (uint32_t)8U) ==
                        (uint8_t)2U;
                uint64_t positionAfternone3 = EverParseCheckConstraintOk(
                    noneConstraintIsOk1, positionAfternone2);
                if (EverParseIsError(positionAfternone3))
                {
                    positionAfterAsymAlg0 = positionAfternone3;
                }
                else
                {
                    /* Checking that we have enough space for a UINT16, i.e., 2
                     * bytes */
                    BOOLEAN hasBytes =
                        (uint64_t)2U <= (InputLength - positionAfternone3);
                    uint64_t positionAfterAsymAlg;
                    if (hasBytes)
                    {
                        positionAfterAsymAlg =
                            positionAfternone3 + (uint64_t)2U;
                    }
                    else
                    {
                        positionAfterAsymAlg = EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfternone3);
                    }
                    uint64_t positionAfterBitfield1;
                    if (EverParseIsSuccess(positionAfterAsymAlg))
                    {
                        positionAfterBitfield1 = positionAfterAsymAlg;
                    }
                    else
                    {
                        Err("_AsymAlg",
                            "__bitfield_1",
                            EverParseErrorReasonOfResult(positionAfterAsymAlg),
                            Ctxt,
                            Input,
                            positionAfternone3);
                        positionAfterBitfield1 = positionAfterAsymAlg;
                    }
                    if (EverParseIsError(positionAfterBitfield1))
                    {
                        positionAfterAsymAlg0 = positionAfterBitfield1;
                    }
                    else
                    {
                        uint16_t r =
                            Load16Le(Input + (uint32_t)positionAfternone3);
                        uint16_t bitfield1 = (uint16_t)(uint32_t)r;
                        /* Validating field alg_external */
                        BOOLEAN
                        hasEnoughBytes =
                            (uint64_t)(uint32_t)((uint8_t)4U * EverParseGetBitfield8(none1, (uint32_t)0U, (uint32_t)4U)) <=
                            (InputLength - positionAfterBitfield1);
                        uint64_t positionAfterAsymAlg;
                        if (!hasEnoughBytes)
                        {
                            positionAfterAsymAlg =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    positionAfterBitfield1);
                        }
                        else
                        {
                            uint8_t *truncatedInput = Input;
                            uint64_t truncatedInputLength =
                                positionAfterBitfield1 +
                                (uint64_t)(uint32_t)((uint8_t)4U * EverParseGetBitfield8(none1, (uint32_t)0U, (uint32_t)4U));
                            uint64_t result = positionAfterBitfield1;
                            while (TRUE)
                            {
                                uint64_t position = *&result;
                                BOOLEAN ite;
                                if (!((uint64_t)1U <=
                                      (truncatedInputLength - position)))
                                {
                                    ite = TRUE;
                                }
                                else
                                {
                                    uint64_t positionAfterAsymAlg =
                                        ValidateExtendedAlg(
                                            Ctxt,
                                            Err,
                                            truncatedInput,
                                            truncatedInputLength,
                                            position);
                                    uint64_t result1;
                                    if (EverParseIsSuccess(
                                            positionAfterAsymAlg))
                                    {
                                        result1 = positionAfterAsymAlg;
                                    }
                                    else
                                    {
                                        Err("_AsymAlg",
                                            "alg_external.base.element",
                                            EverParseErrorReasonOfResult(
                                                positionAfterAsymAlg),
                                            Ctxt,
                                            truncatedInput,
                                            position);
                                        result1 = positionAfterAsymAlg;
                                    }
                                    result = result1;
                                    ite = EverParseIsError(result1);
                                }
                                if (ite)
                                {
                                    break;
                                }
                            }
                            uint64_t res = result;
                            positionAfterAsymAlg = res;
                        }
                        uint64_t positionAfteralgExternal;
                        if (EverParseIsSuccess(positionAfterAsymAlg))
                        {
                            positionAfteralgExternal = positionAfterAsymAlg;
                        }
                        else
                        {
                            Err("_AsymAlg",
                                "alg_external.base",
                                EverParseErrorReasonOfResult(
                                    positionAfterAsymAlg),
                                Ctxt,
                                Input,
                                positionAfterBitfield1);
                            positionAfteralgExternal = positionAfterAsymAlg;
                        }
                        uint64_t positionAfterAsymAlg1;
                        if (EverParseIsSuccess(positionAfteralgExternal))
                        {
                            *OutAlgCountExtended =
                                (uint32_t)EverParseGetBitfield8(
                                    none1, (uint32_t)0U, (uint32_t)4U);
                            BOOLEAN actionSuccessAlgExternal;
                            if (IsResp)
                            {
                                actionSuccessAlgExternal =
                                    ((uint16_t)EverParseGetBitfield8(
                                         none1, (uint32_t)0U, (uint32_t)4U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)0U,
                                         (uint32_t)1U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)1U,
                                         (uint32_t)2U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)2U,
                                         (uint32_t)3U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)3U,
                                         (uint32_t)4U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)4U,
                                         (uint32_t)5U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)5U,
                                         (uint32_t)6U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)6U,
                                         (uint32_t)7U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)7U,
                                         (uint32_t)8U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)8U,
                                         (uint32_t)9U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)9U,
                                         (uint32_t)10U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)10U,
                                         (uint32_t)11U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)11U,
                                         (uint32_t)12U)) <=
                                    (uint16_t)(uint8_t)1U;
                            }
                            else
                            {
                                actionSuccessAlgExternal = TRUE;
                            }
                            if (!actionSuccessAlgExternal)
                            {
                                positionAfterAsymAlg1 =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                                        positionAfteralgExternal);
                            }
                            else
                            {
                                positionAfterAsymAlg1 =
                                    positionAfteralgExternal;
                            }
                        }
                        else
                        {
                            positionAfterAsymAlg1 = positionAfteralgExternal;
                        }
                        if (EverParseIsSuccess(positionAfterAsymAlg1))
                        {
                            positionAfterAsymAlg0 = positionAfterAsymAlg1;
                        }
                        else
                        {
                            Err("_AsymAlg",
                                "alg_external",
                                EverParseErrorReasonOfResult(
                                    positionAfterAsymAlg1),
                                Ctxt,
                                Input,
                                positionAfterBitfield1);
                            positionAfterAsymAlg0 = positionAfterAsymAlg1;
                        }
                    }
                }
            }
            if (EverParseIsSuccess(positionAfterAsymAlg0))
            {
                positionAfterAsymAlg = positionAfterAsymAlg0;
            }
            else
            {
                Err("_AsymAlg",
                    "none",
                    EverParseErrorReasonOfResult(positionAfterAsymAlg0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterAsymAlg = positionAfterAsymAlg0;
            }
        }
    }
    if (EverParseIsSuccess(positionAfterAsymAlg))
    {
        return positionAfterAsymAlg;
    }
    Err("_AsymAlg",
        "none",
        EverParseErrorReasonOfResult(positionAfterAsymAlg),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterAsymAlg;
}

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
    uint64_t StartPosition)
{
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - StartPosition);
    uint64_t positionAfternone;
    if (hasBytes0)
    {
        positionAfternone = StartPosition + (uint64_t)1U;
    }
    else
    {
        positionAfternone = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
    }
    uint64_t positionAfterKeySchedule;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterKeySchedule = positionAfternone;
    }
    else
    {
        uint8_t none = Input[(uint32_t)StartPosition];
        BOOLEAN noneConstraintIsOk = none == SPDM____ALGTYPE_KEYSCHEDULE;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterKeySchedule = positionAfternone1;
        }
        else
        {
            /* Checking that we have enough space for a UINT8, i.e., 1 byte */
            BOOLEAN hasBytes0 =
                (uint64_t)1U <= (InputLength - positionAfternone1);
            uint64_t positionAfternone2;
            if (hasBytes0)
            {
                positionAfternone2 = positionAfternone1 + (uint64_t)1U;
            }
            else
            {
                positionAfternone2 = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                    positionAfternone1);
            }
            uint64_t positionAfterKeySchedule0;
            if (EverParseIsError(positionAfternone2))
            {
                positionAfterKeySchedule0 = positionAfternone2;
            }
            else
            {
                uint8_t none1 = Input[(uint32_t)positionAfternone1];
                BOOLEAN
                noneConstraintIsOk1 =
                    EverParseGetBitfield8(none1, (uint32_t)0U, (uint32_t)4U) <=
                        SPDM____MAX_ALGS &&
                    EverParseGetBitfield8(none1, (uint32_t)4U, (uint32_t)8U) ==
                        (uint8_t)2U;
                uint64_t positionAfternone3 = EverParseCheckConstraintOk(
                    noneConstraintIsOk1, positionAfternone2);
                if (EverParseIsError(positionAfternone3))
                {
                    positionAfterKeySchedule0 = positionAfternone3;
                }
                else
                {
                    /* Checking that we have enough space for a UINT16, i.e., 2
                     * bytes */
                    BOOLEAN hasBytes =
                        (uint64_t)2U <= (InputLength - positionAfternone3);
                    uint64_t positionAfterKeySchedule;
                    if (hasBytes)
                    {
                        positionAfterKeySchedule =
                            positionAfternone3 + (uint64_t)2U;
                    }
                    else
                    {
                        positionAfterKeySchedule =
                            EverParseSetValidatorErrorPos(
                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                positionAfternone3);
                    }
                    uint64_t positionAfterBitfield1;
                    if (EverParseIsSuccess(positionAfterKeySchedule))
                    {
                        positionAfterBitfield1 = positionAfterKeySchedule;
                    }
                    else
                    {
                        Err("_KeySchedule",
                            "__bitfield_1",
                            EverParseErrorReasonOfResult(
                                positionAfterKeySchedule),
                            Ctxt,
                            Input,
                            positionAfternone3);
                        positionAfterBitfield1 = positionAfterKeySchedule;
                    }
                    if (EverParseIsError(positionAfterBitfield1))
                    {
                        positionAfterKeySchedule0 = positionAfterBitfield1;
                    }
                    else
                    {
                        uint16_t r =
                            Load16Le(Input + (uint32_t)positionAfternone3);
                        uint16_t bitfield1 = (uint16_t)(uint32_t)r;
                        /* Validating field alg_external */
                        BOOLEAN
                        hasEnoughBytes =
                            (uint64_t)(uint32_t)((uint8_t)4U * EverParseGetBitfield8(none1, (uint32_t)0U, (uint32_t)4U)) <=
                            (InputLength - positionAfterBitfield1);
                        uint64_t positionAfterKeySchedule;
                        if (!hasEnoughBytes)
                        {
                            positionAfterKeySchedule =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    positionAfterBitfield1);
                        }
                        else
                        {
                            uint8_t *truncatedInput = Input;
                            uint64_t truncatedInputLength =
                                positionAfterBitfield1 +
                                (uint64_t)(uint32_t)((uint8_t)4U * EverParseGetBitfield8(none1, (uint32_t)0U, (uint32_t)4U));
                            uint64_t result = positionAfterBitfield1;
                            while (TRUE)
                            {
                                uint64_t position = *&result;
                                BOOLEAN ite;
                                if (!((uint64_t)1U <=
                                      (truncatedInputLength - position)))
                                {
                                    ite = TRUE;
                                }
                                else
                                {
                                    uint64_t positionAfterKeySchedule =
                                        ValidateExtendedAlg(
                                            Ctxt,
                                            Err,
                                            truncatedInput,
                                            truncatedInputLength,
                                            position);
                                    uint64_t result1;
                                    if (EverParseIsSuccess(
                                            positionAfterKeySchedule))
                                    {
                                        result1 = positionAfterKeySchedule;
                                    }
                                    else
                                    {
                                        Err("_KeySchedule",
                                            "alg_external.base.element",
                                            EverParseErrorReasonOfResult(
                                                positionAfterKeySchedule),
                                            Ctxt,
                                            truncatedInput,
                                            position);
                                        result1 = positionAfterKeySchedule;
                                    }
                                    result = result1;
                                    ite = EverParseIsError(result1);
                                }
                                if (ite)
                                {
                                    break;
                                }
                            }
                            uint64_t res = result;
                            positionAfterKeySchedule = res;
                        }
                        uint64_t positionAfteralgExternal;
                        if (EverParseIsSuccess(positionAfterKeySchedule))
                        {
                            positionAfteralgExternal = positionAfterKeySchedule;
                        }
                        else
                        {
                            Err("_KeySchedule",
                                "alg_external.base",
                                EverParseErrorReasonOfResult(
                                    positionAfterKeySchedule),
                                Ctxt,
                                Input,
                                positionAfterBitfield1);
                            positionAfteralgExternal = positionAfterKeySchedule;
                        }
                        uint64_t positionAfterKeySchedule1;
                        if (EverParseIsSuccess(positionAfteralgExternal))
                        {
                            *OutAlgCountExtended =
                                (uint32_t)EverParseGetBitfield8(
                                    none1, (uint32_t)0U, (uint32_t)4U);
                            BOOLEAN actionSuccessAlgExternal;
                            if (IsResp)
                            {
                                actionSuccessAlgExternal =
                                    ((uint16_t)EverParseGetBitfield8(
                                         none1, (uint32_t)0U, (uint32_t)4U) +
                                     EverParseGetBitfield16(
                                         bitfield1,
                                         (uint32_t)0U,
                                         (uint32_t)1U)) <=
                                    (uint16_t)(uint8_t)1U;
                            }
                            else
                            {
                                actionSuccessAlgExternal = TRUE;
                            }
                            if (!actionSuccessAlgExternal)
                            {
                                positionAfterKeySchedule1 =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                                        positionAfteralgExternal);
                            }
                            else
                            {
                                positionAfterKeySchedule1 =
                                    positionAfteralgExternal;
                            }
                        }
                        else
                        {
                            positionAfterKeySchedule1 =
                                positionAfteralgExternal;
                        }
                        if (EverParseIsSuccess(positionAfterKeySchedule1))
                        {
                            positionAfterKeySchedule0 =
                                positionAfterKeySchedule1;
                        }
                        else
                        {
                            Err("_KeySchedule",
                                "alg_external",
                                EverParseErrorReasonOfResult(
                                    positionAfterKeySchedule1),
                                Ctxt,
                                Input,
                                positionAfterBitfield1);
                            positionAfterKeySchedule0 =
                                positionAfterKeySchedule1;
                        }
                    }
                }
            }
            if (EverParseIsSuccess(positionAfterKeySchedule0))
            {
                positionAfterKeySchedule = positionAfterKeySchedule0;
            }
            else
            {
                Err("_KeySchedule",
                    "none",
                    EverParseErrorReasonOfResult(positionAfterKeySchedule0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterKeySchedule = positionAfterKeySchedule0;
            }
        }
    }
    if (EverParseIsSuccess(positionAfterKeySchedule))
    {
        return positionAfterKeySchedule;
    }
    Err("_KeySchedule",
        "none",
        EverParseErrorReasonOfResult(positionAfterKeySchedule),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterKeySchedule;
}

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
    uint64_t StartPosition)
{
    /* Validating field preamble */
    uint64_t positionAfterGetMeasurements = ValidatePreamble(
        SPDM____GET_MEASUREMENTS, Ctxt, Err, Input, InputLength, StartPosition);
    uint64_t positionAfterpreamble;
    if (EverParseIsSuccess(positionAfterGetMeasurements))
    {
        positionAfterpreamble = positionAfterGetMeasurements;
    }
    else
    {
        Err("_GetMeasurements",
            "preamble",
            EverParseErrorReasonOfResult(positionAfterGetMeasurements),
            Ctxt,
            Input,
            StartPosition);
        positionAfterpreamble = positionAfterGetMeasurements;
    }
    if (EverParseIsError(positionAfterpreamble))
    {
        return positionAfterpreamble;
    }
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - positionAfterpreamble);
    uint64_t positionAfterGetMeasurements0;
    if (hasBytes0)
    {
        positionAfterGetMeasurements0 = positionAfterpreamble + (uint64_t)1U;
    }
    else
    {
        positionAfterGetMeasurements0 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterpreamble);
    }
    uint64_t positionAfterBitfield0;
    if (EverParseIsSuccess(positionAfterGetMeasurements0))
    {
        positionAfterBitfield0 = positionAfterGetMeasurements0;
    }
    else
    {
        Err("_GetMeasurements",
            "__bitfield_0",
            EverParseErrorReasonOfResult(positionAfterGetMeasurements0),
            Ctxt,
            Input,
            positionAfterpreamble);
        positionAfterBitfield0 = positionAfterGetMeasurements0;
    }
    if (EverParseIsError(positionAfterBitfield0))
    {
        return positionAfterBitfield0;
    }
    uint8_t bitfield0 = Input[(uint32_t)positionAfterpreamble];
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes1 = (uint64_t)1U <= (InputLength - positionAfterBitfield0);
    uint64_t positionAfterGetMeasurements1;
    if (hasBytes1)
    {
        positionAfterGetMeasurements1 = positionAfterBitfield0 + (uint64_t)1U;
    }
    else
    {
        positionAfterGetMeasurements1 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterBitfield0);
    }
    uint64_t positionAfterparam2Operation;
    if (EverParseIsSuccess(positionAfterGetMeasurements1))
    {
        positionAfterparam2Operation = positionAfterGetMeasurements1;
    }
    else
    {
        Err("_GetMeasurements",
            "param_2_operation",
            EverParseErrorReasonOfResult(positionAfterGetMeasurements1),
            Ctxt,
            Input,
            positionAfterBitfield0);
        positionAfterparam2Operation = positionAfterGetMeasurements1;
    }
    if (EverParseIsError(positionAfterparam2Operation))
    {
        return positionAfterparam2Operation;
    }
    uint8_t param2Operation = Input[(uint32_t)positionAfterBitfield0];
    /* Validating field nonce */
    uint64_t positionAfterGetMeasurements2 = ValidateOptionalBuffer(
        EverParseGetBitfield8(bitfield0, (uint32_t)0U, (uint32_t)1U) ==
            (uint8_t)1U,
        (uint32_t)(uint8_t)32U,
        Ctxt,
        Err,
        Input,
        InputLength,
        positionAfterparam2Operation);
    uint64_t positionAfternonce0;
    if (EverParseIsSuccess(positionAfterGetMeasurements2))
    {
        positionAfternonce0 = positionAfterGetMeasurements2;
    }
    else
    {
        Err("_GetMeasurements",
            "nonce.base",
            EverParseErrorReasonOfResult(positionAfterGetMeasurements2),
            Ctxt,
            Input,
            positionAfterparam2Operation);
        positionAfternonce0 = positionAfterGetMeasurements2;
    }
    uint64_t positionAfterGetMeasurements3;
    if (EverParseIsSuccess(positionAfternonce0))
    {
        uint8_t *hd = Input + (uint32_t)positionAfterparam2Operation;
        *OutSignatureRequested =
            EverParseGetBitfield8(bitfield0, (uint32_t)0U, (uint32_t)1U) ==
            (uint8_t)1U;
        *OutRawBitstreamRequested =
            EverParseGetBitfield8(bitfield0, (uint32_t)1U, (uint32_t)2U) ==
            (uint8_t)1U;
        *OutOperation = param2Operation;
        *OutNonce = hd;
        BOOLEAN actionSuccessNonce = TRUE;
        if (!actionSuccessNonce)
        {
            positionAfterGetMeasurements3 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED, positionAfternonce0);
        }
        else
        {
            positionAfterGetMeasurements3 = positionAfternonce0;
        }
    }
    else
    {
        positionAfterGetMeasurements3 = positionAfternonce0;
    }
    uint64_t positionAfternonce;
    if (EverParseIsSuccess(positionAfterGetMeasurements3))
    {
        positionAfternonce = positionAfterGetMeasurements3;
    }
    else
    {
        Err("_GetMeasurements",
            "nonce",
            EverParseErrorReasonOfResult(positionAfterGetMeasurements3),
            Ctxt,
            Input,
            positionAfterparam2Operation);
        positionAfternonce = positionAfterGetMeasurements3;
    }
    if (EverParseIsError(positionAfternonce))
    {
        return positionAfternonce;
    }
    /* Validating field __bitfield_1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes = (uint64_t)1U <= (InputLength - positionAfternonce);
    uint64_t positionAfterBitfield1;
    if (hasBytes)
    {
        positionAfterBitfield1 = positionAfternonce + (uint64_t)1U;
    }
    else
    {
        positionAfterBitfield1 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfternonce);
    }
    uint64_t positionAfterGetMeasurements4;
    if (EverParseIsError(positionAfterBitfield1))
    {
        positionAfterGetMeasurements4 = positionAfterBitfield1;
    }
    else
    {
        uint8_t bitfield1 = Input[(uint32_t)positionAfternonce];
        *OutSlotId =
            EverParseGetBitfield8(bitfield1, (uint32_t)0U, (uint32_t)4U);
        if (TRUE)
        {
            positionAfterGetMeasurements4 = positionAfterBitfield1;
        }
        else
        {
            positionAfterGetMeasurements4 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                positionAfterBitfield1);
        }
    }
    if (EverParseIsSuccess(positionAfterGetMeasurements4))
    {
        return positionAfterGetMeasurements4;
    }
    Err("_GetMeasurements",
        "__bitfield_1",
        EverParseErrorReasonOfResult(positionAfterGetMeasurements4),
        Ctxt,
        Input,
        positionAfternonce);
    return positionAfterGetMeasurements4;
}

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
    uint64_t StartPosition)
{
    /* Validating field preamble */
    uint64_t positionAfterMeasurements = ValidatePreamble(
        SPDM____MEASUREMENTS, Ctxt, Err, Input, InputLength, StartPosition);
    uint64_t positionAfterpreamble;
    if (EverParseIsSuccess(positionAfterMeasurements))
    {
        positionAfterpreamble = positionAfterMeasurements;
    }
    else
    {
        Err("_Measurements",
            "preamble",
            EverParseErrorReasonOfResult(positionAfterMeasurements),
            Ctxt,
            Input,
            StartPosition);
        positionAfterpreamble = positionAfterMeasurements;
    }
    if (EverParseIsError(positionAfterpreamble))
    {
        return positionAfterpreamble;
    }
    /* Validating field param_1 */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - positionAfterpreamble);
    uint64_t positionAfterMeasurements0;
    if (hasBytes0)
    {
        positionAfterMeasurements0 = positionAfterpreamble + (uint64_t)1U;
    }
    else
    {
        positionAfterMeasurements0 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterpreamble);
    }
    uint64_t res0;
    if (EverParseIsSuccess(positionAfterMeasurements0))
    {
        res0 = positionAfterMeasurements0;
    }
    else
    {
        Err("_Measurements",
            "param_1",
            EverParseErrorReasonOfResult(positionAfterMeasurements0),
            Ctxt,
            Input,
            positionAfterpreamble);
        res0 = positionAfterMeasurements0;
    }
    uint64_t positionAfterparam1 = res0;
    if (EverParseIsError(positionAfterparam1))
    {
        return positionAfterparam1;
    }
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes1 = (uint64_t)1U <= (InputLength - positionAfterparam1);
    uint64_t positionAfterMeasurements1;
    if (hasBytes1)
    {
        positionAfterMeasurements1 = positionAfterparam1 + (uint64_t)1U;
    }
    else
    {
        positionAfterMeasurements1 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterparam1);
    }
    uint64_t positionAfterBitfield0;
    if (EverParseIsSuccess(positionAfterMeasurements1))
    {
        positionAfterBitfield0 = positionAfterMeasurements1;
    }
    else
    {
        Err("_Measurements",
            "__bitfield_0",
            EverParseErrorReasonOfResult(positionAfterMeasurements1),
            Ctxt,
            Input,
            positionAfterparam1);
        positionAfterBitfield0 = positionAfterMeasurements1;
    }
    if (EverParseIsError(positionAfterBitfield0))
    {
        return positionAfterBitfield0;
    }
    uint8_t bitfield0 = Input[(uint32_t)positionAfterparam1];
    /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
    BOOLEAN hasBytes2 = (uint64_t)4U <= (InputLength - positionAfterBitfield0);
    uint64_t res;
    if (hasBytes2)
    {
        res = positionAfterBitfield0 + (uint64_t)4U;
    }
    else
    {
        res = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterBitfield0);
    }
    uint64_t positionAfterMeasurements2;
    if (EverParseIsError(res))
    {
        positionAfterMeasurements2 = res;
    }
    else
    {
        uint32_t fieldValue =
            Load32Le(Input + (uint32_t)positionAfterBitfield0);
        BOOLEAN
        actionResult =
            !ExpectMeasurementCount ||
            (EverParseGetBitfield32(fieldValue, (uint32_t)0U, (uint32_t)8U) ==
                 (uint32_t)(uint8_t)0U &&
             EverParseGetBitfield32(fieldValue, (uint32_t)8U, (uint32_t)32U) ==
                 (uint32_t)(uint8_t)0U);
        if (!actionResult)
        {
            positionAfterMeasurements2 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED, res);
        }
        else
        {
            /* Validating field record_data */
            BOOLEAN
            hasEnoughBytes0 = (uint64_t)EverParseGetBitfield32(
                                  fieldValue, (uint32_t)8U, (uint32_t)32U) <=
                              (InputLength - res);
            uint64_t positionAfterMeasurements;
            if (!hasEnoughBytes0)
            {
                positionAfterMeasurements = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, res);
            }
            else
            {
                uint8_t *truncatedInput = Input;
                uint64_t truncatedInputLength =
                    res + (uint64_t)EverParseGetBitfield32(
                              fieldValue, (uint32_t)8U, (uint32_t)32U);
                uint64_t result = res;
                while (TRUE)
                {
                    uint64_t position = *&result;
                    BOOLEAN ite;
                    if (!((uint64_t)1U <= (truncatedInputLength - position)))
                    {
                        ite = TRUE;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT8, i.e.,
                         * 1 byte */
                        BOOLEAN hasBytes =
                            (uint64_t)1U <= (truncatedInputLength - position);
                        uint64_t positionAfterMeasurements;
                        if (hasBytes)
                        {
                            positionAfterMeasurements = position + (uint64_t)1U;
                        }
                        else
                        {
                            positionAfterMeasurements =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    position);
                        }
                        uint64_t res1;
                        if (EverParseIsSuccess(positionAfterMeasurements))
                        {
                            res1 = positionAfterMeasurements;
                        }
                        else
                        {
                            Err("_Measurements",
                                "record_data.base.element",
                                EverParseErrorReasonOfResult(
                                    positionAfterMeasurements),
                                Ctxt,
                                truncatedInput,
                                position);
                            res1 = positionAfterMeasurements;
                        }
                        uint64_t result1 = res1;
                        result = result1;
                        ite = EverParseIsError(result1);
                    }
                    if (ite)
                    {
                        break;
                    }
                }
                uint64_t res1 = result;
                positionAfterMeasurements = res1;
            }
            uint64_t positionAfterrecordData;
            if (EverParseIsSuccess(positionAfterMeasurements))
            {
                positionAfterrecordData = positionAfterMeasurements;
            }
            else
            {
                Err("_Measurements",
                    "record_data.base",
                    EverParseErrorReasonOfResult(positionAfterMeasurements),
                    Ctxt,
                    Input,
                    res);
                positionAfterrecordData = positionAfterMeasurements;
            }
            uint64_t positionAfterMeasurements0;
            if (EverParseIsSuccess(positionAfterrecordData))
            {
                uint8_t *hd = Input + (uint32_t)res;
                *OutSlotId = EverParseGetBitfield8(
                    bitfield0, (uint32_t)0U, (uint32_t)4U);
                *OutContentChanged = EverParseGetBitfield8(
                    bitfield0, (uint32_t)4U, (uint32_t)6U);
                *OutNumberOfBlocks = EverParseGetBitfield32(
                    fieldValue, (uint32_t)0U, (uint32_t)8U);
                *OutRecordLength = EverParseGetBitfield32(
                    fieldValue, (uint32_t)8U, (uint32_t)32U);
                *OutRecordData = hd;
                BOOLEAN actionSuccessRecordData = TRUE;
                if (!actionSuccessRecordData)
                {
                    positionAfterMeasurements0 = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                        positionAfterrecordData);
                }
                else
                {
                    positionAfterMeasurements0 = positionAfterrecordData;
                }
            }
            else
            {
                positionAfterMeasurements0 = positionAfterrecordData;
            }
            uint64_t positionAfterrecordData0;
            if (EverParseIsSuccess(positionAfterMeasurements0))
            {
                positionAfterrecordData0 = positionAfterMeasurements0;
            }
            else
            {
                Err("_Measurements",
                    "record_data",
                    EverParseErrorReasonOfResult(positionAfterMeasurements0),
                    Ctxt,
                    Input,
                    res);
                positionAfterrecordData0 = positionAfterMeasurements0;
            }
            if (EverParseIsError(positionAfterrecordData0))
            {
                positionAfterMeasurements2 = positionAfterrecordData0;
            }
            else
            {
                /* Validating field nonce */
                BOOLEAN
                hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)32U <=
                                  (InputLength - positionAfterrecordData0);
                uint64_t positionAfterMeasurements;
                if (!hasEnoughBytes0)
                {
                    positionAfterMeasurements = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfterrecordData0);
                }
                else
                {
                    uint8_t *truncatedInput = Input;
                    uint64_t truncatedInputLength =
                        positionAfterrecordData0 +
                        (uint64_t)(uint32_t)(uint8_t)32U;
                    uint64_t result = positionAfterrecordData0;
                    while (TRUE)
                    {
                        uint64_t position = *&result;
                        BOOLEAN ite;
                        if (!((uint64_t)1U <=
                              (truncatedInputLength - position)))
                        {
                            ite = TRUE;
                        }
                        else
                        {
                            /* Checking that we have enough space for a UINT8,
                             * i.e., 1 byte */
                            BOOLEAN hasBytes =
                                (uint64_t)1U <=
                                (truncatedInputLength - position);
                            uint64_t positionAfterMeasurements;
                            if (hasBytes)
                            {
                                positionAfterMeasurements =
                                    position + (uint64_t)1U;
                            }
                            else
                            {
                                positionAfterMeasurements =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        position);
                            }
                            uint64_t res1;
                            if (EverParseIsSuccess(positionAfterMeasurements))
                            {
                                res1 = positionAfterMeasurements;
                            }
                            else
                            {
                                Err("_Measurements",
                                    "nonce.base.element",
                                    EverParseErrorReasonOfResult(
                                        positionAfterMeasurements),
                                    Ctxt,
                                    truncatedInput,
                                    position);
                                res1 = positionAfterMeasurements;
                            }
                            uint64_t result1 = res1;
                            result = result1;
                            ite = EverParseIsError(result1);
                        }
                        if (ite)
                        {
                            break;
                        }
                    }
                    uint64_t res1 = result;
                    positionAfterMeasurements = res1;
                }
                uint64_t positionAfternonce0;
                if (EverParseIsSuccess(positionAfterMeasurements))
                {
                    positionAfternonce0 = positionAfterMeasurements;
                }
                else
                {
                    Err("_Measurements",
                        "nonce.base",
                        EverParseErrorReasonOfResult(positionAfterMeasurements),
                        Ctxt,
                        Input,
                        positionAfterrecordData0);
                    positionAfternonce0 = positionAfterMeasurements;
                }
                uint64_t positionAfterMeasurements0;
                if (EverParseIsSuccess(positionAfternonce0))
                {
                    uint8_t *hd = Input + (uint32_t)positionAfterrecordData0;
                    *OutNonce = hd;
                    BOOLEAN actionSuccessNonce = TRUE;
                    if (!actionSuccessNonce)
                    {
                        positionAfterMeasurements0 =
                            EverParseSetValidatorErrorPos(
                                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                                positionAfternonce0);
                    }
                    else
                    {
                        positionAfterMeasurements0 = positionAfternonce0;
                    }
                }
                else
                {
                    positionAfterMeasurements0 = positionAfternonce0;
                }
                uint64_t positionAfternonce;
                if (EverParseIsSuccess(positionAfterMeasurements0))
                {
                    positionAfternonce = positionAfterMeasurements0;
                }
                else
                {
                    Err("_Measurements",
                        "nonce",
                        EverParseErrorReasonOfResult(
                            positionAfterMeasurements0),
                        Ctxt,
                        Input,
                        positionAfterrecordData0);
                    positionAfternonce = positionAfterMeasurements0;
                }
                if (EverParseIsError(positionAfternonce))
                {
                    positionAfterMeasurements2 = positionAfternonce;
                }
                else
                {
                    /* Checking that we have enough space for a UINT16, i.e., 2
                     * bytes */
                    BOOLEAN hasBytes0 =
                        (uint64_t)2U <= (InputLength - positionAfternonce);
                    uint64_t positionAfternone;
                    if (hasBytes0)
                    {
                        positionAfternone = positionAfternonce + (uint64_t)2U;
                    }
                    else
                    {
                        positionAfternone = EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfternonce);
                    }
                    uint64_t positionAfterMeasurements;
                    if (EverParseIsError(positionAfternone))
                    {
                        positionAfterMeasurements = positionAfternone;
                    }
                    else
                    {
                        uint16_t r =
                            Load16Le(Input + (uint32_t)positionAfternonce);
                        uint16_t none = (uint16_t)(uint32_t)r;
                        BOOLEAN noneConstraintIsOk = none <= (uint16_t)1024U;
                        uint64_t positionAfternone1 =
                            EverParseCheckConstraintOk(
                                noneConstraintIsOk, positionAfternone);
                        if (EverParseIsError(positionAfternone1))
                        {
                            positionAfterMeasurements = positionAfternone1;
                        }
                        else
                        {
                            /* Validating field opaque_data */
                            BOOLEAN
                            hasEnoughBytes = (uint64_t)(uint32_t)none <=
                                             (InputLength - positionAfternone1);
                            uint64_t positionAfterMeasurements0;
                            if (!hasEnoughBytes)
                            {
                                positionAfterMeasurements0 =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        positionAfternone1);
                            }
                            else
                            {
                                uint8_t *truncatedInput = Input;
                                uint64_t truncatedInputLength =
                                    positionAfternone1 +
                                    (uint64_t)(uint32_t)none;
                                uint64_t result = positionAfternone1;
                                while (TRUE)
                                {
                                    uint64_t position = *&result;
                                    BOOLEAN ite;
                                    if (!((uint64_t)1U <=
                                          (truncatedInputLength - position)))
                                    {
                                        ite = TRUE;
                                    }
                                    else
                                    {
                                        /* Checking that we have enough space
                                         * for a UINT8, i.e., 1 byte */
                                        BOOLEAN hasBytes =
                                            (uint64_t)1U <=
                                            (truncatedInputLength - position);
                                        uint64_t positionAfterMeasurements;
                                        if (hasBytes)
                                        {
                                            positionAfterMeasurements =
                                                position + (uint64_t)1U;
                                        }
                                        else
                                        {
                                            positionAfterMeasurements =
                                                EverParseSetValidatorErrorPos(
                                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                    position);
                                        }
                                        uint64_t res1;
                                        if (EverParseIsSuccess(
                                                positionAfterMeasurements))
                                        {
                                            res1 = positionAfterMeasurements;
                                        }
                                        else
                                        {
                                            Err("_Measurements",
                                                "opaque_data.base.element",
                                                EverParseErrorReasonOfResult(
                                                    positionAfterMeasurements),
                                                Ctxt,
                                                truncatedInput,
                                                position);
                                            res1 = positionAfterMeasurements;
                                        }
                                        uint64_t result1 = res1;
                                        result = result1;
                                        ite = EverParseIsError(result1);
                                    }
                                    if (ite)
                                    {
                                        break;
                                    }
                                }
                                uint64_t res1 = result;
                                positionAfterMeasurements0 = res1;
                            }
                            uint64_t positionAfteropaqueData;
                            if (EverParseIsSuccess(positionAfterMeasurements0))
                            {
                                positionAfteropaqueData =
                                    positionAfterMeasurements0;
                            }
                            else
                            {
                                Err("_Measurements",
                                    "opaque_data.base",
                                    EverParseErrorReasonOfResult(
                                        positionAfterMeasurements0),
                                    Ctxt,
                                    Input,
                                    positionAfternone1);
                                positionAfteropaqueData =
                                    positionAfterMeasurements0;
                            }
                            uint64_t positionAfterMeasurements1;
                            if (EverParseIsSuccess(positionAfteropaqueData))
                            {
                                uint8_t *hd =
                                    Input + (uint32_t)positionAfternone1;
                                *OutOpaqueDataLength = none;
                                *OutOpaqueData = hd;
                                BOOLEAN actionSuccessOpaqueData = TRUE;
                                if (!actionSuccessOpaqueData)
                                {
                                    positionAfterMeasurements1 =
                                        EverParseSetValidatorErrorPos(
                                            EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                                            positionAfteropaqueData);
                                }
                                else
                                {
                                    positionAfterMeasurements1 =
                                        positionAfteropaqueData;
                                }
                            }
                            else
                            {
                                positionAfterMeasurements1 =
                                    positionAfteropaqueData;
                            }
                            uint64_t positionAfteropaqueData0;
                            if (EverParseIsSuccess(positionAfterMeasurements1))
                            {
                                positionAfteropaqueData0 =
                                    positionAfterMeasurements1;
                            }
                            else
                            {
                                Err("_Measurements",
                                    "opaque_data",
                                    EverParseErrorReasonOfResult(
                                        positionAfterMeasurements1),
                                    Ctxt,
                                    Input,
                                    positionAfternone1);
                                positionAfteropaqueData0 =
                                    positionAfterMeasurements1;
                            }
                            if (EverParseIsError(positionAfteropaqueData0))
                            {
                                positionAfterMeasurements =
                                    positionAfteropaqueData0;
                            }
                            else
                            {
                                /* Validating field signature */
                                uint64_t positionAfterMeasurements0 =
                                    ValidateOptionalBuffer(
                                        ExpectSignature,
                                        SignatureLen,
                                        Ctxt,
                                        Err,
                                        Input,
                                        InputLength,
                                        positionAfteropaqueData0);
                                uint64_t positionAftersignature;
                                if (EverParseIsSuccess(
                                        positionAfterMeasurements0))
                                {
                                    positionAftersignature =
                                        positionAfterMeasurements0;
                                }
                                else
                                {
                                    Err("_Measurements",
                                        "signature.base",
                                        EverParseErrorReasonOfResult(
                                            positionAfterMeasurements0),
                                        Ctxt,
                                        Input,
                                        positionAfteropaqueData0);
                                    positionAftersignature =
                                        positionAfterMeasurements0;
                                }
                                uint64_t positionAfterMeasurements1;
                                if (EverParseIsSuccess(positionAftersignature))
                                {
                                    uint8_t *hd =
                                        Input +
                                        (uint32_t)positionAfteropaqueData0;
                                    *OutSignature = hd;
                                    BOOLEAN actionSuccessSignature = TRUE;
                                    if (!actionSuccessSignature)
                                    {
                                        positionAfterMeasurements1 =
                                            EverParseSetValidatorErrorPos(
                                                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                                                positionAftersignature);
                                    }
                                    else
                                    {
                                        positionAfterMeasurements1 =
                                            positionAftersignature;
                                    }
                                }
                                else
                                {
                                    positionAfterMeasurements1 =
                                        positionAftersignature;
                                }
                                if (EverParseIsSuccess(
                                        positionAfterMeasurements1))
                                {
                                    positionAfterMeasurements =
                                        positionAfterMeasurements1;
                                }
                                else
                                {
                                    Err("_Measurements",
                                        "signature",
                                        EverParseErrorReasonOfResult(
                                            positionAfterMeasurements1),
                                        Ctxt,
                                        Input,
                                        positionAfteropaqueData0);
                                    positionAfterMeasurements =
                                        positionAfterMeasurements1;
                                }
                            }
                        }
                    }
                    if (EverParseIsSuccess(positionAfterMeasurements))
                    {
                        positionAfterMeasurements2 = positionAfterMeasurements;
                    }
                    else
                    {
                        Err("_Measurements",
                            "none",
                            EverParseErrorReasonOfResult(
                                positionAfterMeasurements),
                            Ctxt,
                            Input,
                            positionAfternonce);
                        positionAfterMeasurements2 = positionAfterMeasurements;
                    }
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterMeasurements2))
    {
        return positionAfterMeasurements2;
    }
    Err("_Measurements",
        "none",
        EverParseErrorReasonOfResult(positionAfterMeasurements2),
        Ctxt,
        Input,
        positionAfterBitfield0);
    return positionAfterMeasurements2;
}

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
    uint64_t StartPosition)
{
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - StartPosition);
    uint64_t positionAfterMeasurementBlock;
    if (hasBytes0)
    {
        positionAfterMeasurementBlock = StartPosition + (uint64_t)1U;
    }
    else
    {
        positionAfterMeasurementBlock = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
    }
    uint64_t positionAfterindex;
    if (EverParseIsSuccess(positionAfterMeasurementBlock))
    {
        positionAfterindex = positionAfterMeasurementBlock;
    }
    else
    {
        Err("_MeasurementBlock",
            "index",
            EverParseErrorReasonOfResult(positionAfterMeasurementBlock),
            Ctxt,
            Input,
            StartPosition);
        positionAfterindex = positionAfterMeasurementBlock;
    }
    if (EverParseIsError(positionAfterindex))
    {
        return positionAfterindex;
    }
    uint8_t index = Input[(uint32_t)StartPosition];
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes1 = (uint64_t)1U <= (InputLength - positionAfterindex);
    uint64_t res;
    if (hasBytes1)
    {
        res = positionAfterindex + (uint64_t)1U;
    }
    else
    {
        res = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterindex);
    }
    uint64_t positionAfterMeasurementBlock0;
    if (EverParseIsError(res))
    {
        positionAfterMeasurementBlock0 = res;
    }
    else
    {
        uint8_t fieldValue = Input[(uint32_t)positionAfterindex];
        BOOLEAN actionResult;
        if (EverParseGetBitfield8(fieldValue, (uint32_t)0U, (uint32_t)1U) ==
            (uint8_t)1U)
        {
            *OutMeasurementSpec = SPDM____MEASUREMENT_SPEC_DMTF;
            actionResult = TRUE;
        }
        else
        {
            actionResult = FALSE;
        }
        if (!actionResult)
        {
            positionAfterMeasurementBlock0 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED, res);
        }
        else
        {
            /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
            BOOLEAN hasBytes0 = (uint64_t)2U <= (InputLength - res);
            uint64_t positionAfterMeasurementBlock;
            if (hasBytes0)
            {
                positionAfterMeasurementBlock = res + (uint64_t)2U;
            }
            else
            {
                positionAfterMeasurementBlock = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, res);
            }
            uint64_t positionAftermeasurementSize;
            if (EverParseIsSuccess(positionAfterMeasurementBlock))
            {
                positionAftermeasurementSize = positionAfterMeasurementBlock;
            }
            else
            {
                Err("_MeasurementBlock",
                    "measurement_size",
                    EverParseErrorReasonOfResult(positionAfterMeasurementBlock),
                    Ctxt,
                    Input,
                    res);
                positionAftermeasurementSize = positionAfterMeasurementBlock;
            }
            if (EverParseIsError(positionAftermeasurementSize))
            {
                positionAfterMeasurementBlock0 = positionAftermeasurementSize;
            }
            else
            {
                uint16_t r = Load16Le(Input + (uint32_t)res);
                uint16_t measurementSize = (uint16_t)(uint32_t)r;
                /* Validating field measurement */
                BOOLEAN
                hasEnoughBytes = (uint64_t)(uint32_t)measurementSize <=
                                 (InputLength - positionAftermeasurementSize);
                uint64_t positionAfterMeasurementBlock;
                if (!hasEnoughBytes)
                {
                    positionAfterMeasurementBlock =
                        EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAftermeasurementSize);
                }
                else
                {
                    uint8_t *truncatedInput = Input;
                    uint64_t truncatedInputLength =
                        positionAftermeasurementSize +
                        (uint64_t)(uint32_t)measurementSize;
                    uint64_t result = positionAftermeasurementSize;
                    while (TRUE)
                    {
                        uint64_t position = *&result;
                        BOOLEAN ite;
                        if (!((uint64_t)1U <=
                              (truncatedInputLength - position)))
                        {
                            ite = TRUE;
                        }
                        else
                        {
                            /* Checking that we have enough space for a UINT8,
                             * i.e., 1 byte */
                            BOOLEAN hasBytes =
                                (uint64_t)1U <=
                                (truncatedInputLength - position);
                            uint64_t positionAfterMeasurementBlock;
                            if (hasBytes)
                            {
                                positionAfterMeasurementBlock =
                                    position + (uint64_t)1U;
                            }
                            else
                            {
                                positionAfterMeasurementBlock =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        position);
                            }
                            uint64_t res1;
                            if (EverParseIsSuccess(
                                    positionAfterMeasurementBlock))
                            {
                                res1 = positionAfterMeasurementBlock;
                            }
                            else
                            {
                                Err("_MeasurementBlock",
                                    "measurement.base.element",
                                    EverParseErrorReasonOfResult(
                                        positionAfterMeasurementBlock),
                                    Ctxt,
                                    truncatedInput,
                                    position);
                                res1 = positionAfterMeasurementBlock;
                            }
                            uint64_t result1 = res1;
                            result = result1;
                            ite = EverParseIsError(result1);
                        }
                        if (ite)
                        {
                            break;
                        }
                    }
                    uint64_t res1 = result;
                    positionAfterMeasurementBlock = res1;
                }
                uint64_t positionAftermeasurement;
                if (EverParseIsSuccess(positionAfterMeasurementBlock))
                {
                    positionAftermeasurement = positionAfterMeasurementBlock;
                }
                else
                {
                    Err("_MeasurementBlock",
                        "measurement.base",
                        EverParseErrorReasonOfResult(
                            positionAfterMeasurementBlock),
                        Ctxt,
                        Input,
                        positionAftermeasurementSize);
                    positionAftermeasurement = positionAfterMeasurementBlock;
                }
                uint64_t positionAfterMeasurementBlock1;
                if (EverParseIsSuccess(positionAftermeasurement))
                {
                    uint8_t *hd =
                        Input + (uint32_t)positionAftermeasurementSize;
                    *OutIndex = index;
                    *OutMeasurementSize = measurementSize;
                    *OutMeasurement = hd;
                    BOOLEAN actionSuccessMeasurement = TRUE;
                    if (!actionSuccessMeasurement)
                    {
                        positionAfterMeasurementBlock1 =
                            EverParseSetValidatorErrorPos(
                                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                                positionAftermeasurement);
                    }
                    else
                    {
                        positionAfterMeasurementBlock1 =
                            positionAftermeasurement;
                    }
                }
                else
                {
                    positionAfterMeasurementBlock1 = positionAftermeasurement;
                }
                if (EverParseIsSuccess(positionAfterMeasurementBlock1))
                {
                    positionAfterMeasurementBlock0 =
                        positionAfterMeasurementBlock1;
                }
                else
                {
                    Err("_MeasurementBlock",
                        "measurement",
                        EverParseErrorReasonOfResult(
                            positionAfterMeasurementBlock1),
                        Ctxt,
                        Input,
                        positionAftermeasurementSize);
                    positionAfterMeasurementBlock0 =
                        positionAfterMeasurementBlock1;
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterMeasurementBlock0))
    {
        return positionAfterMeasurementBlock0;
    }
    Err("_MeasurementBlock",
        "none",
        EverParseErrorReasonOfResult(positionAfterMeasurementBlock0),
        Ctxt,
        Input,
        positionAfterindex);
    return positionAfterMeasurementBlock0;
}

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
    uint64_t StartPosition)
{
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - StartPosition);
    uint64_t positionAfterDmtfMeasurement;
    if (hasBytes0)
    {
        positionAfterDmtfMeasurement = StartPosition + (uint64_t)1U;
    }
    else
    {
        positionAfterDmtfMeasurement = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
    }
    uint64_t positionAfterBitfield0;
    if (EverParseIsSuccess(positionAfterDmtfMeasurement))
    {
        positionAfterBitfield0 = positionAfterDmtfMeasurement;
    }
    else
    {
        Err("_DmtfMeasurement",
            "__bitfield_0",
            EverParseErrorReasonOfResult(positionAfterDmtfMeasurement),
            Ctxt,
            Input,
            StartPosition);
        positionAfterBitfield0 = positionAfterDmtfMeasurement;
    }
    if (EverParseIsError(positionAfterBitfield0))
    {
        return positionAfterBitfield0;
    }
    uint8_t bitfield0 = Input[(uint32_t)StartPosition];
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    BOOLEAN hasBytes1 = (uint64_t)2U <= (InputLength - positionAfterBitfield0);
    uint64_t positionAfterDmtfMeasurement0;
    if (hasBytes1)
    {
        positionAfterDmtfMeasurement0 = positionAfterBitfield0 + (uint64_t)2U;
    }
    else
    {
        positionAfterDmtfMeasurement0 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterBitfield0);
    }
    uint64_t positionAftervalueSize;
    if (EverParseIsSuccess(positionAfterDmtfMeasurement0))
    {
        positionAftervalueSize = positionAfterDmtfMeasurement0;
    }
    else
    {
        Err("_DmtfMeasurement",
            "value_size",
            EverParseErrorReasonOfResult(positionAfterDmtfMeasurement0),
            Ctxt,
            Input,
            positionAfterBitfield0);
        positionAftervalueSize = positionAfterDmtfMeasurement0;
    }
    if (EverParseIsError(positionAftervalueSize))
    {
        return positionAftervalueSize;
    }
    uint16_t r = Load16Le(Input + (uint32_t)positionAfterBitfield0);
    uint16_t valueSize = (uint16_t)(uint32_t)r;
    /* Validating field value */
    BOOLEAN
    hasEnoughBytes =
        (uint64_t)(uint32_t)valueSize <= (InputLength - positionAftervalueSize);
    uint64_t positionAfterDmtfMeasurement1;
    if (!hasEnoughBytes)
    {
        positionAfterDmtfMeasurement1 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAftervalueSize);
    }
    else
    {
        uint8_t *truncatedInput = Input;
        uint64_t truncatedInputLength =
            positionAftervalueSize + (uint64_t)(uint32_t)valueSize;
        uint64_t result = positionAftervalueSize;
        while (TRUE)
        {
            uint64_t position = *&result;
            BOOLEAN ite;
            if (!((uint64_t)1U <= (truncatedInputLength - position)))
            {
                ite = TRUE;
            }
            else
            {
                /* Checking that we have enough space for a UINT8, i.e., 1 byte
                 */
                BOOLEAN hasBytes =
                    (uint64_t)1U <= (truncatedInputLength - position);
                uint64_t positionAfterDmtfMeasurement;
                if (hasBytes)
                {
                    positionAfterDmtfMeasurement = position + (uint64_t)1U;
                }
                else
                {
                    positionAfterDmtfMeasurement =
                        EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            position);
                }
                uint64_t res;
                if (EverParseIsSuccess(positionAfterDmtfMeasurement))
                {
                    res = positionAfterDmtfMeasurement;
                }
                else
                {
                    Err("_DmtfMeasurement",
                        "value.base.element",
                        EverParseErrorReasonOfResult(
                            positionAfterDmtfMeasurement),
                        Ctxt,
                        truncatedInput,
                        position);
                    res = positionAfterDmtfMeasurement;
                }
                uint64_t result1 = res;
                result = result1;
                ite = EverParseIsError(result1);
            }
            if (ite)
            {
                break;
            }
        }
        uint64_t res = result;
        positionAfterDmtfMeasurement1 = res;
    }
    uint64_t positionAftervalue;
    if (EverParseIsSuccess(positionAfterDmtfMeasurement1))
    {
        positionAftervalue = positionAfterDmtfMeasurement1;
    }
    else
    {
        Err("_DmtfMeasurement",
            "value.base",
            EverParseErrorReasonOfResult(positionAfterDmtfMeasurement1),
            Ctxt,
            Input,
            positionAftervalueSize);
        positionAftervalue = positionAfterDmtfMeasurement1;
    }
    uint64_t positionAfterDmtfMeasurement2;
    if (EverParseIsSuccess(positionAftervalue))
    {
        uint8_t *hd = Input + (uint32_t)positionAftervalueSize;
        *OutRawBitstream =
            EverParseGetBitfield8(bitfield0, (uint32_t)0U, (uint32_t)1U) ==
            (uint8_t)1U;
        *OutValueType =
            EverParseGetBitfield8(bitfield0, (uint32_t)1U, (uint32_t)8U);
        *OutValueSize = valueSize;
        *OutValue = hd;
        BOOLEAN actionSuccessValue = TRUE;
        if (!actionSuccessValue)
        {
            positionAfterDmtfMeasurement2 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED, positionAftervalue);
        }
        else
        {
            positionAfterDmtfMeasurement2 = positionAftervalue;
        }
    }
    else
    {
        positionAfterDmtfMeasurement2 = positionAftervalue;
    }
    if (EverParseIsSuccess(positionAfterDmtfMeasurement2))
    {
        return positionAfterDmtfMeasurement2;
    }
    Err("_DmtfMeasurement",
        "value",
        EverParseErrorReasonOfResult(positionAfterDmtfMeasurement2),
        Ctxt,
        Input,
        positionAftervalueSize);
    return positionAfterDmtfMeasurement2;
}

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
    uint64_t StartPosition)
{
    /* Validating field preamble */
    uint64_t positionAfterKeyExchange = ValidatePreamble(
        SPDM____KEY_EXCHANGE, Ctxt, Err, Input, InputLength, StartPosition);
    uint64_t positionAfterpreamble;
    if (EverParseIsSuccess(positionAfterKeyExchange))
    {
        positionAfterpreamble = positionAfterKeyExchange;
    }
    else
    {
        Err("_KeyExchange",
            "preamble",
            EverParseErrorReasonOfResult(positionAfterKeyExchange),
            Ctxt,
            Input,
            StartPosition);
        positionAfterpreamble = positionAfterKeyExchange;
    }
    if (EverParseIsError(positionAfterpreamble))
    {
        return positionAfterpreamble;
    }
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - positionAfterpreamble);
    uint64_t positionAfterKeyExchange0;
    if (hasBytes0)
    {
        positionAfterKeyExchange0 = positionAfterpreamble + (uint64_t)1U;
    }
    else
    {
        positionAfterKeyExchange0 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterpreamble);
    }
    uint64_t positionAfternone;
    if (EverParseIsSuccess(positionAfterKeyExchange0))
    {
        positionAfternone = positionAfterKeyExchange0;
    }
    else
    {
        Err("_KeyExchange",
            "none",
            EverParseErrorReasonOfResult(positionAfterKeyExchange0),
            Ctxt,
            Input,
            positionAfterpreamble);
        positionAfternone = positionAfterKeyExchange0;
    }
    if (EverParseIsError(positionAfternone))
    {
        return positionAfternone;
    }
    uint8_t none = Input[(uint32_t)positionAfterpreamble];
    BOOLEAN noneConstraintIsOk = none <= (uint8_t)1U || none == (uint8_t)255U;
    uint64_t positionAfternone1 =
        EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
    if (EverParseIsError(positionAfternone1))
    {
        return positionAfternone1;
    }
    *OutRequestedMeasurementSummaryType = none;
    if (!TRUE)
    {
        return EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED, positionAfternone1);
    }
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes1 = (uint64_t)1U <= (InputLength - positionAfternone1);
    uint64_t positionAfterKeyExchange1;
    if (hasBytes1)
    {
        positionAfterKeyExchange1 = positionAfternone1 + (uint64_t)1U;
    }
    else
    {
        positionAfterKeyExchange1 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfternone1);
    }
    uint64_t positionAfternone2;
    if (EverParseIsSuccess(positionAfterKeyExchange1))
    {
        positionAfternone2 = positionAfterKeyExchange1;
    }
    else
    {
        Err("_KeyExchange",
            "none",
            EverParseErrorReasonOfResult(positionAfterKeyExchange1),
            Ctxt,
            Input,
            positionAfternone1);
        positionAfternone2 = positionAfterKeyExchange1;
    }
    if (EverParseIsError(positionAfternone2))
    {
        return positionAfternone2;
    }
    uint8_t none1 = Input[(uint32_t)positionAfternone1];
    BOOLEAN noneConstraintIsOk1 =
        none1 <= (uint8_t)7U || none1 == (uint8_t)255U;
    uint64_t positionAfternone3 =
        EverParseCheckConstraintOk(noneConstraintIsOk1, positionAfternone2);
    if (EverParseIsError(positionAfternone3))
    {
        return positionAfternone3;
    }
    *OutSlotId = none1;
    if (!TRUE)
    {
        return EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED, positionAfternone3);
    }
    /* Validating field req_session_id */
    BOOLEAN
    hasEnoughBytes0 =
        (uint64_t)(uint32_t)(uint8_t)2U <= (InputLength - positionAfternone3);
    uint64_t positionAfterKeyExchange2;
    if (!hasEnoughBytes0)
    {
        positionAfterKeyExchange2 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfternone3);
    }
    else
    {
        uint8_t *truncatedInput = Input;
        uint64_t truncatedInputLength =
            positionAfternone3 + (uint64_t)(uint32_t)(uint8_t)2U;
        uint64_t result = positionAfternone3;
        while (TRUE)
        {
            uint64_t position = *&result;
            BOOLEAN ite;
            if (!((uint64_t)1U <= (truncatedInputLength - position)))
            {
                ite = TRUE;
            }
            else
            {
                /* Checking that we have enough space for a UINT8, i.e., 1 byte
                 */
                BOOLEAN hasBytes =
                    (uint64_t)1U <= (truncatedInputLength - position);
                uint64_t positionAfterKeyExchange;
                if (hasBytes)
                {
                    positionAfterKeyExchange = position + (uint64_t)1U;
                }
                else
                {
                    positionAfterKeyExchange = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, position);
                }
                uint64_t res;
                if (EverParseIsSuccess(positionAfterKeyExchange))
                {
                    res = positionAfterKeyExchange;
                }
                else
                {
                    Err("_KeyExchange",
                        "req_session_id.base.element",
                        EverParseErrorReasonOfResult(positionAfterKeyExchange),
                        Ctxt,
                        truncatedInput,
                        position);
                    res = positionAfterKeyExchange;
                }
                uint64_t result1 = res;
                result = result1;
                ite = EverParseIsError(result1);
            }
            if (ite)
            {
                break;
            }
        }
        uint64_t res = result;
        positionAfterKeyExchange2 = res;
    }
    uint64_t positionAfterreqSessionId;
    if (EverParseIsSuccess(positionAfterKeyExchange2))
    {
        positionAfterreqSessionId = positionAfterKeyExchange2;
    }
    else
    {
        Err("_KeyExchange",
            "req_session_id.base",
            EverParseErrorReasonOfResult(positionAfterKeyExchange2),
            Ctxt,
            Input,
            positionAfternone3);
        positionAfterreqSessionId = positionAfterKeyExchange2;
    }
    uint64_t positionAfterKeyExchange3;
    if (EverParseIsSuccess(positionAfterreqSessionId))
    {
        uint8_t *hd = Input + (uint32_t)positionAfternone3;
        *OutReqSessionId = hd;
        BOOLEAN actionSuccessReqSessionId = TRUE;
        if (!actionSuccessReqSessionId)
        {
            positionAfterKeyExchange3 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                positionAfterreqSessionId);
        }
        else
        {
            positionAfterKeyExchange3 = positionAfterreqSessionId;
        }
    }
    else
    {
        positionAfterKeyExchange3 = positionAfterreqSessionId;
    }
    uint64_t positionAfterreqSessionId0;
    if (EverParseIsSuccess(positionAfterKeyExchange3))
    {
        positionAfterreqSessionId0 = positionAfterKeyExchange3;
    }
    else
    {
        Err("_KeyExchange",
            "req_session_id",
            EverParseErrorReasonOfResult(positionAfterKeyExchange3),
            Ctxt,
            Input,
            positionAfternone3);
        positionAfterreqSessionId0 = positionAfterKeyExchange3;
    }
    if (EverParseIsError(positionAfterreqSessionId0))
    {
        return positionAfterreqSessionId0;
    }
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes2 =
        (uint64_t)1U <= (InputLength - positionAfterreqSessionId0);
    uint64_t res;
    if (hasBytes2)
    {
        res = positionAfterreqSessionId0 + (uint64_t)1U;
    }
    else
    {
        res = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfterreqSessionId0);
    }
    uint64_t positionAfterKeyExchange4;
    if (EverParseIsError(res))
    {
        positionAfterKeyExchange4 = res;
    }
    else
    {
        uint8_t fieldValue = Input[(uint32_t)positionAfterreqSessionId0];
        *OutSessionPolicyTermination =
            EverParseGetBitfield8(fieldValue, (uint32_t)0U, (uint32_t)1U) ==
            (uint8_t)1U;
        BOOLEAN actionResult = TRUE;
        if (!actionResult)
        {
            positionAfterKeyExchange4 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED, res);
        }
        else
        {
            /* Validating field reserved */
            /* Checking that we have enough space for a UINT8, i.e., 1 byte */
            BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - res);
            uint64_t positionAfterKeyExchange;
            if (hasBytes0)
            {
                positionAfterKeyExchange = res + (uint64_t)1U;
            }
            else
            {
                positionAfterKeyExchange = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, res);
            }
            uint64_t res10;
            if (EverParseIsSuccess(positionAfterKeyExchange))
            {
                res10 = positionAfterKeyExchange;
            }
            else
            {
                Err("_KeyExchange",
                    "reserved",
                    EverParseErrorReasonOfResult(positionAfterKeyExchange),
                    Ctxt,
                    Input,
                    res);
                res10 = positionAfterKeyExchange;
            }
            uint64_t positionAfterreserved = res10;
            if (EverParseIsError(positionAfterreserved))
            {
                positionAfterKeyExchange4 = positionAfterreserved;
            }
            else
            {
                /* Validating field random_data */
                BOOLEAN
                hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)32U <=
                                  (InputLength - positionAfterreserved);
                uint64_t positionAfterKeyExchange;
                if (!hasEnoughBytes0)
                {
                    positionAfterKeyExchange = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfterreserved);
                }
                else
                {
                    uint8_t *truncatedInput = Input;
                    uint64_t truncatedInputLength =
                        positionAfterreserved +
                        (uint64_t)(uint32_t)(uint8_t)32U;
                    uint64_t result = positionAfterreserved;
                    while (TRUE)
                    {
                        uint64_t position = *&result;
                        BOOLEAN ite;
                        if (!((uint64_t)1U <=
                              (truncatedInputLength - position)))
                        {
                            ite = TRUE;
                        }
                        else
                        {
                            /* Checking that we have enough space for a UINT8,
                             * i.e., 1 byte */
                            BOOLEAN hasBytes =
                                (uint64_t)1U <=
                                (truncatedInputLength - position);
                            uint64_t positionAfterKeyExchange;
                            if (hasBytes)
                            {
                                positionAfterKeyExchange =
                                    position + (uint64_t)1U;
                            }
                            else
                            {
                                positionAfterKeyExchange =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        position);
                            }
                            uint64_t res1;
                            if (EverParseIsSuccess(positionAfterKeyExchange))
                            {
                                res1 = positionAfterKeyExchange;
                            }
                            else
                            {
                                Err("_KeyExchange",
                                    "random_data.element",
                                    EverParseErrorReasonOfResult(
                                        positionAfterKeyExchange),
                                    Ctxt,
                                    truncatedInput,
                                    position);
                                res1 = positionAfterKeyExchange;
                            }
                            uint64_t result1 = res1;
                            result = result1;
                            ite = EverParseIsError(result1);
                        }
                        if (ite)
                        {
                            break;
                        }
                    }
                    uint64_t res1 = result;
                    positionAfterKeyExchange = res1;
                }
                uint64_t positionAfterrandomData;
                if (EverParseIsSuccess(positionAfterKeyExchange))
                {
                    positionAfterrandomData = positionAfterKeyExchange;
                }
                else
                {
                    Err("_KeyExchange",
                        "random_data",
                        EverParseErrorReasonOfResult(positionAfterKeyExchange),
                        Ctxt,
                        Input,
                        positionAfterreserved);
                    positionAfterrandomData = positionAfterKeyExchange;
                }
                if (EverParseIsError(positionAfterrandomData))
                {
                    positionAfterKeyExchange4 = positionAfterrandomData;
                }
                else
                {
                    /* Validating field exchange_data */
                    BOOLEAN
                    hasEnoughBytes0 = (uint64_t)ExchangeDataLen <=
                                      (InputLength - positionAfterrandomData);
                    uint64_t positionAfterKeyExchange;
                    if (!hasEnoughBytes0)
                    {
                        positionAfterKeyExchange =
                            EverParseSetValidatorErrorPos(
                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                positionAfterrandomData);
                    }
                    else
                    {
                        uint8_t *truncatedInput = Input;
                        uint64_t truncatedInputLength =
                            positionAfterrandomData + (uint64_t)ExchangeDataLen;
                        uint64_t result = positionAfterrandomData;
                        while (TRUE)
                        {
                            uint64_t position = *&result;
                            BOOLEAN ite;
                            if (!((uint64_t)1U <=
                                  (truncatedInputLength - position)))
                            {
                                ite = TRUE;
                            }
                            else
                            {
                                /* Checking that we have enough space for a
                                 * UINT8, i.e., 1 byte */
                                BOOLEAN hasBytes =
                                    (uint64_t)1U <=
                                    (truncatedInputLength - position);
                                uint64_t positionAfterKeyExchange;
                                if (hasBytes)
                                {
                                    positionAfterKeyExchange =
                                        position + (uint64_t)1U;
                                }
                                else
                                {
                                    positionAfterKeyExchange =
                                        EverParseSetValidatorErrorPos(
                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                            position);
                                }
                                uint64_t res1;
                                if (EverParseIsSuccess(
                                        positionAfterKeyExchange))
                                {
                                    res1 = positionAfterKeyExchange;
                                }
                                else
                                {
                                    Err("_KeyExchange",
                                        "exchange_data.base.element",
                                        EverParseErrorReasonOfResult(
                                            positionAfterKeyExchange),
                                        Ctxt,
                                        truncatedInput,
                                        position);
                                    res1 = positionAfterKeyExchange;
                                }
                                uint64_t result1 = res1;
                                result = result1;
                                ite = EverParseIsError(result1);
                            }
                            if (ite)
                            {
                                break;
                            }
                        }
                        uint64_t res1 = result;
                        positionAfterKeyExchange = res1;
                    }
                    uint64_t positionAfterexchangeData;
                    if (EverParseIsSuccess(positionAfterKeyExchange))
                    {
                        positionAfterexchangeData = positionAfterKeyExchange;
                    }
                    else
                    {
                        Err("_KeyExchange",
                            "exchange_data.base",
                            EverParseErrorReasonOfResult(
                                positionAfterKeyExchange),
                            Ctxt,
                            Input,
                            positionAfterrandomData);
                        positionAfterexchangeData = positionAfterKeyExchange;
                    }
                    uint64_t positionAfterKeyExchange0;
                    if (EverParseIsSuccess(positionAfterexchangeData))
                    {
                        uint8_t *hd = Input + (uint32_t)positionAfterrandomData;
                        *OutExchangeData = hd;
                        BOOLEAN actionSuccessExchangeData = TRUE;
                        if (!actionSuccessExchangeData)
                        {
                            positionAfterKeyExchange0 =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                                    positionAfterexchangeData);
                        }
                        else
                        {
                            positionAfterKeyExchange0 =
                                positionAfterexchangeData;
                        }
                    }
                    else
                    {
                        positionAfterKeyExchange0 = positionAfterexchangeData;
                    }
                    uint64_t positionAfterexchangeData0;
                    if (EverParseIsSuccess(positionAfterKeyExchange0))
                    {
                        positionAfterexchangeData0 = positionAfterKeyExchange0;
                    }
                    else
                    {
                        Err("_KeyExchange",
                            "exchange_data",
                            EverParseErrorReasonOfResult(
                                positionAfterKeyExchange0),
                            Ctxt,
                            Input,
                            positionAfterrandomData);
                        positionAfterexchangeData0 = positionAfterKeyExchange0;
                    }
                    if (EverParseIsError(positionAfterexchangeData0))
                    {
                        positionAfterKeyExchange4 = positionAfterexchangeData0;
                    }
                    else
                    {
                        /* Checking that we have enough space for a UINT16,
                         * i.e., 2 bytes */
                        BOOLEAN hasBytes0 =
                            (uint64_t)2U <=
                            (InputLength - positionAfterexchangeData0);
                        uint64_t positionAfterKeyExchange;
                        if (hasBytes0)
                        {
                            positionAfterKeyExchange =
                                positionAfterexchangeData0 + (uint64_t)2U;
                        }
                        else
                        {
                            positionAfterKeyExchange =
                                EverParseSetValidatorErrorPos(
                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                    positionAfterexchangeData0);
                        }
                        uint64_t positionAfternone4;
                        if (EverParseIsSuccess(positionAfterKeyExchange))
                        {
                            positionAfternone4 = positionAfterKeyExchange;
                        }
                        else
                        {
                            Err("_KeyExchange",
                                "none",
                                EverParseErrorReasonOfResult(
                                    positionAfterKeyExchange),
                                Ctxt,
                                Input,
                                positionAfterexchangeData0);
                            positionAfternone4 = positionAfterKeyExchange;
                        }
                        if (EverParseIsError(positionAfternone4))
                        {
                            positionAfterKeyExchange4 = positionAfternone4;
                        }
                        else
                        {
                            uint16_t r = Load16Le(
                                Input + (uint32_t)positionAfterexchangeData0);
                            uint16_t none2 = (uint16_t)(uint32_t)r;
                            BOOLEAN noneConstraintIsOk2 =
                                none2 <= (uint16_t)1024U;
                            uint64_t positionAfternone5 =
                                EverParseCheckConstraintOk(
                                    noneConstraintIsOk2, positionAfternone4);
                            if (EverParseIsError(positionAfternone5))
                            {
                                positionAfterKeyExchange4 = positionAfternone5;
                            }
                            else
                            {
                                *OutOpaqueDataLen = (uint32_t)none2;
                                if (!TRUE)
                                {
                                    positionAfterKeyExchange4 =
                                        EverParseSetValidatorErrorPos(
                                            EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                                            positionAfternone5);
                                }
                                else
                                {
                                    /* Validating field opaque_data */
                                    BOOLEAN
                                    hasEnoughBytes =
                                        (uint64_t)(uint32_t)none2 <=
                                        (InputLength - positionAfternone5);
                                    uint64_t positionAfterKeyExchange;
                                    if (!hasEnoughBytes)
                                    {
                                        positionAfterKeyExchange =
                                            EverParseSetValidatorErrorPos(
                                                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                positionAfternone5);
                                    }
                                    else
                                    {
                                        uint8_t *truncatedInput = Input;
                                        uint64_t truncatedInputLength =
                                            positionAfternone5 +
                                            (uint64_t)(uint32_t)none2;
                                        uint64_t result = positionAfternone5;
                                        while (TRUE)
                                        {
                                            uint64_t position = *&result;
                                            BOOLEAN ite;
                                            if (!((uint64_t)1U <=
                                                  (truncatedInputLength -
                                                   position)))
                                            {
                                                ite = TRUE;
                                            }
                                            else
                                            {
                                                /* Checking that we have enough
                                                 * space for a UINT8, i.e., 1
                                                 * byte */
                                                BOOLEAN hasBytes =
                                                    (uint64_t)1U <=
                                                    (truncatedInputLength -
                                                     position);
                                                uint64_t
                                                    positionAfterKeyExchange;
                                                if (hasBytes)
                                                {
                                                    positionAfterKeyExchange =
                                                        position + (uint64_t)1U;
                                                }
                                                else
                                                {
                                                    positionAfterKeyExchange =
                                                        EverParseSetValidatorErrorPos(
                                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                            position);
                                                }
                                                uint64_t res1;
                                                if (EverParseIsSuccess(
                                                        positionAfterKeyExchange))
                                                {
                                                    res1 =
                                                        positionAfterKeyExchange;
                                                }
                                                else
                                                {
                                                    Err("_KeyExchange",
                                                        "opaque_data.base."
                                                        "element",
                                                        EverParseErrorReasonOfResult(
                                                            positionAfterKeyExchange),
                                                        Ctxt,
                                                        truncatedInput,
                                                        position);
                                                    res1 =
                                                        positionAfterKeyExchange;
                                                }
                                                uint64_t result1 = res1;
                                                result = result1;
                                                ite = EverParseIsError(result1);
                                            }
                                            if (ite)
                                            {
                                                break;
                                            }
                                        }
                                        uint64_t res1 = result;
                                        positionAfterKeyExchange = res1;
                                    }
                                    uint64_t positionAfteropaqueData;
                                    if (EverParseIsSuccess(
                                            positionAfterKeyExchange))
                                    {
                                        positionAfteropaqueData =
                                            positionAfterKeyExchange;
                                    }
                                    else
                                    {
                                        Err("_KeyExchange",
                                            "opaque_data.base",
                                            EverParseErrorReasonOfResult(
                                                positionAfterKeyExchange),
                                            Ctxt,
                                            Input,
                                            positionAfternone5);
                                        positionAfteropaqueData =
                                            positionAfterKeyExchange;
                                    }
                                    uint64_t positionAfterKeyExchange0;
                                    if (EverParseIsSuccess(
                                            positionAfteropaqueData))
                                    {
                                        uint8_t *hd =
                                            Input +
                                            (uint32_t)positionAfternone5;
                                        *OutOpaqueData = hd;
                                        BOOLEAN actionSuccessOpaqueData = TRUE;
                                        if (!actionSuccessOpaqueData)
                                        {
                                            positionAfterKeyExchange0 =
                                                EverParseSetValidatorErrorPos(
                                                    EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                                                    positionAfteropaqueData);
                                        }
                                        else
                                        {
                                            positionAfterKeyExchange0 =
                                                positionAfteropaqueData;
                                        }
                                    }
                                    else
                                    {
                                        positionAfterKeyExchange0 =
                                            positionAfteropaqueData;
                                    }
                                    if (EverParseIsSuccess(
                                            positionAfterKeyExchange0))
                                    {
                                        positionAfterKeyExchange4 =
                                            positionAfterKeyExchange0;
                                    }
                                    else
                                    {
                                        Err("_KeyExchange",
                                            "opaque_data",
                                            EverParseErrorReasonOfResult(
                                                positionAfterKeyExchange0),
                                            Ctxt,
                                            Input,
                                            positionAfternone5);
                                        positionAfterKeyExchange4 =
                                            positionAfterKeyExchange0;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterKeyExchange4))
    {
        return positionAfterKeyExchange4;
    }
    Err("_KeyExchange",
        "none",
        EverParseErrorReasonOfResult(positionAfterKeyExchange4),
        Ctxt,
        Input,
        positionAfterreqSessionId0);
    return positionAfterKeyExchange4;
}

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
    uint64_t StartPosition)
{
    /* Validating field preamble */
    uint64_t positionAfterKeyExchangeRsp = ValidatePreamble(
        SPDM____KEY_EXCHANGE_RSP, Ctxt, Err, Input, InputLength, StartPosition);
    uint64_t positionAfterpreamble;
    if (EverParseIsSuccess(positionAfterKeyExchangeRsp))
    {
        positionAfterpreamble = positionAfterKeyExchangeRsp;
    }
    else
    {
        Err("_KeyExchangeRsp",
            "preamble",
            EverParseErrorReasonOfResult(positionAfterKeyExchangeRsp),
            Ctxt,
            Input,
            StartPosition);
        positionAfterpreamble = positionAfterKeyExchangeRsp;
    }
    if (EverParseIsError(positionAfterpreamble))
    {
        return positionAfterpreamble;
    }
    /* Validating field param_1_heartbeat_period */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - positionAfterpreamble);
    uint64_t positionAfterparam1HeartbeatPeriod;
    if (hasBytes0)
    {
        positionAfterparam1HeartbeatPeriod =
            positionAfterpreamble + (uint64_t)1U;
    }
    else
    {
        positionAfterparam1HeartbeatPeriod = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterpreamble);
    }
    uint64_t positionAfterKeyExchangeRsp0;
    if (EverParseIsError(positionAfterparam1HeartbeatPeriod))
    {
        positionAfterKeyExchangeRsp0 = positionAfterparam1HeartbeatPeriod;
    }
    else
    {
        uint8_t param1HeartbeatPeriod = Input[(uint32_t)positionAfterpreamble];
        *OutHeartbeatPeriod = param1HeartbeatPeriod;
        if (TRUE)
        {
            positionAfterKeyExchangeRsp0 = positionAfterparam1HeartbeatPeriod;
        }
        else
        {
            positionAfterKeyExchangeRsp0 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                positionAfterparam1HeartbeatPeriod);
        }
    }
    uint64_t positionAfterparam1HeartbeatPeriod0;
    if (EverParseIsSuccess(positionAfterKeyExchangeRsp0))
    {
        positionAfterparam1HeartbeatPeriod0 = positionAfterKeyExchangeRsp0;
    }
    else
    {
        Err("_KeyExchangeRsp",
            "param_1_heartbeat_period",
            EverParseErrorReasonOfResult(positionAfterKeyExchangeRsp0),
            Ctxt,
            Input,
            positionAfterpreamble);
        positionAfterparam1HeartbeatPeriod0 = positionAfterKeyExchangeRsp0;
    }
    if (EverParseIsError(positionAfterparam1HeartbeatPeriod0))
    {
        return positionAfterparam1HeartbeatPeriod0;
    }
    /* Validating field param_2_reserved */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes1 =
        (uint64_t)1U <= (InputLength - positionAfterparam1HeartbeatPeriod0);
    uint64_t positionAfterKeyExchangeRsp1;
    if (hasBytes1)
    {
        positionAfterKeyExchangeRsp1 =
            positionAfterparam1HeartbeatPeriod0 + (uint64_t)1U;
    }
    else
    {
        positionAfterKeyExchangeRsp1 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfterparam1HeartbeatPeriod0);
    }
    uint64_t res0;
    if (EverParseIsSuccess(positionAfterKeyExchangeRsp1))
    {
        res0 = positionAfterKeyExchangeRsp1;
    }
    else
    {
        Err("_KeyExchangeRsp",
            "param_2_reserved",
            EverParseErrorReasonOfResult(positionAfterKeyExchangeRsp1),
            Ctxt,
            Input,
            positionAfterparam1HeartbeatPeriod0);
        res0 = positionAfterKeyExchangeRsp1;
    }
    uint64_t positionAfterparam2Reserved = res0;
    if (EverParseIsError(positionAfterparam2Reserved))
    {
        return positionAfterparam2Reserved;
    }
    /* Validating field rsp_session_id */
    BOOLEAN
    hasEnoughBytes0 = (uint64_t)(uint32_t)(uint8_t)2U <=
                      (InputLength - positionAfterparam2Reserved);
    uint64_t positionAfterKeyExchangeRsp2;
    if (!hasEnoughBytes0)
    {
        positionAfterKeyExchangeRsp2 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfterparam2Reserved);
    }
    else
    {
        uint8_t *truncatedInput = Input;
        uint64_t truncatedInputLength =
            positionAfterparam2Reserved + (uint64_t)(uint32_t)(uint8_t)2U;
        uint64_t result = positionAfterparam2Reserved;
        while (TRUE)
        {
            uint64_t position = *&result;
            BOOLEAN ite;
            if (!((uint64_t)1U <= (truncatedInputLength - position)))
            {
                ite = TRUE;
            }
            else
            {
                /* Checking that we have enough space for a UINT8, i.e., 1 byte
                 */
                BOOLEAN hasBytes =
                    (uint64_t)1U <= (truncatedInputLength - position);
                uint64_t positionAfterKeyExchangeRsp;
                if (hasBytes)
                {
                    positionAfterKeyExchangeRsp = position + (uint64_t)1U;
                }
                else
                {
                    positionAfterKeyExchangeRsp = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, position);
                }
                uint64_t res;
                if (EverParseIsSuccess(positionAfterKeyExchangeRsp))
                {
                    res = positionAfterKeyExchangeRsp;
                }
                else
                {
                    Err("_KeyExchangeRsp",
                        "rsp_session_id.base.element",
                        EverParseErrorReasonOfResult(
                            positionAfterKeyExchangeRsp),
                        Ctxt,
                        truncatedInput,
                        position);
                    res = positionAfterKeyExchangeRsp;
                }
                uint64_t result1 = res;
                result = result1;
                ite = EverParseIsError(result1);
            }
            if (ite)
            {
                break;
            }
        }
        uint64_t res = result;
        positionAfterKeyExchangeRsp2 = res;
    }
    uint64_t positionAfterrspSessionId;
    if (EverParseIsSuccess(positionAfterKeyExchangeRsp2))
    {
        positionAfterrspSessionId = positionAfterKeyExchangeRsp2;
    }
    else
    {
        Err("_KeyExchangeRsp",
            "rsp_session_id.base",
            EverParseErrorReasonOfResult(positionAfterKeyExchangeRsp2),
            Ctxt,
            Input,
            positionAfterparam2Reserved);
        positionAfterrspSessionId = positionAfterKeyExchangeRsp2;
    }
    uint64_t positionAfterKeyExchangeRsp3;
    if (EverParseIsSuccess(positionAfterrspSessionId))
    {
        uint8_t *hd = Input + (uint32_t)positionAfterparam2Reserved;
        *OutRspSessionId = hd;
        BOOLEAN actionSuccessRspSessionId = TRUE;
        if (!actionSuccessRspSessionId)
        {
            positionAfterKeyExchangeRsp3 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                positionAfterrspSessionId);
        }
        else
        {
            positionAfterKeyExchangeRsp3 = positionAfterrspSessionId;
        }
    }
    else
    {
        positionAfterKeyExchangeRsp3 = positionAfterrspSessionId;
    }
    uint64_t positionAfterrspSessionId0;
    if (EverParseIsSuccess(positionAfterKeyExchangeRsp3))
    {
        positionAfterrspSessionId0 = positionAfterKeyExchangeRsp3;
    }
    else
    {
        Err("_KeyExchangeRsp",
            "rsp_session_id",
            EverParseErrorReasonOfResult(positionAfterKeyExchangeRsp3),
            Ctxt,
            Input,
            positionAfterparam2Reserved);
        positionAfterrspSessionId0 = positionAfterKeyExchangeRsp3;
    }
    if (EverParseIsError(positionAfterrspSessionId0))
    {
        return positionAfterrspSessionId0;
    }
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes2 =
        (uint64_t)1U <= (InputLength - positionAfterrspSessionId0);
    uint64_t positionAfterKeyExchangeRsp4;
    if (hasBytes2)
    {
        positionAfterKeyExchangeRsp4 =
            positionAfterrspSessionId0 + (uint64_t)1U;
    }
    else
    {
        positionAfterKeyExchangeRsp4 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfterrspSessionId0);
    }
    uint64_t positionAfternone;
    if (EverParseIsSuccess(positionAfterKeyExchangeRsp4))
    {
        positionAfternone = positionAfterKeyExchangeRsp4;
    }
    else
    {
        Err("_KeyExchangeRsp",
            "none",
            EverParseErrorReasonOfResult(positionAfterKeyExchangeRsp4),
            Ctxt,
            Input,
            positionAfterrspSessionId0);
        positionAfternone = positionAfterKeyExchangeRsp4;
    }
    if (EverParseIsError(positionAfternone))
    {
        return positionAfternone;
    }
    uint8_t none = Input[(uint32_t)positionAfterrspSessionId0];
    BOOLEAN
    noneConstraintIsOk =
        EverParseGetBitfield8(none, (uint32_t)0U, (uint32_t)1U) +
            EverParseGetBitfield8(none, (uint32_t)1U, (uint32_t)2U) +
            EverParseGetBitfield8(none, (uint32_t)2U, (uint32_t)3U) ==
        (uint8_t)1U;
    uint64_t positionAfternone1 =
        EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
    if (EverParseIsError(positionAfternone1))
    {
        return positionAfternone1;
    }
    BOOLEAN ite0;
    if (EverParseGetBitfield8(none, (uint32_t)0U, (uint32_t)1U) == (uint8_t)1U)
    {
        *OutMutAuthRequestedFlow = (uint8_t)0U;
        ite0 = TRUE;
    }
    else if (
        EverParseGetBitfield8(none, (uint32_t)1U, (uint32_t)2U) == (uint8_t)1U)
    {
        *OutMutAuthRequestedFlow = (uint8_t)1U;
        ite0 = TRUE;
    }
    else
    {
        *OutMutAuthRequestedFlow = (uint8_t)2U;
        ite0 = TRUE;
    }
    if (!ite0)
    {
        return EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED, positionAfternone1);
    }
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes3 = (uint64_t)1U <= (InputLength - positionAfternone1);
    uint64_t positionAfterKeyExchangeRsp5;
    if (hasBytes3)
    {
        positionAfterKeyExchangeRsp5 = positionAfternone1 + (uint64_t)1U;
    }
    else
    {
        positionAfterKeyExchangeRsp5 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfternone1);
    }
    uint64_t positionAfternone2;
    if (EverParseIsSuccess(positionAfterKeyExchangeRsp5))
    {
        positionAfternone2 = positionAfterKeyExchangeRsp5;
    }
    else
    {
        Err("_KeyExchangeRsp",
            "none",
            EverParseErrorReasonOfResult(positionAfterKeyExchangeRsp5),
            Ctxt,
            Input,
            positionAfternone1);
        positionAfternone2 = positionAfterKeyExchangeRsp5;
    }
    if (EverParseIsError(positionAfternone2))
    {
        return positionAfternone2;
    }
    uint8_t none1 = Input[(uint32_t)positionAfternone1];
    BOOLEAN
    noneConstraintIsOk1 =
        (EverParseGetBitfield8(none, (uint32_t)0U, (uint32_t)1U) ==
             (uint8_t)1U &&
         (EverParseGetBitfield8(none1, (uint32_t)0U, (uint32_t)4U) <=
              (uint8_t)7U ||
          EverParseGetBitfield8(none1, (uint32_t)0U, (uint32_t)4U) ==
              (uint8_t)15U)) ||
        EverParseGetBitfield8(none1, (uint32_t)0U, (uint32_t)4U) == (uint8_t)0U;
    uint64_t positionAfternone3 =
        EverParseCheckConstraintOk(noneConstraintIsOk1, positionAfternone2);
    if (EverParseIsError(positionAfternone3))
    {
        return positionAfternone3;
    }
    *OutSlotId = EverParseGetBitfield8(none1, (uint32_t)0U, (uint32_t)4U);
    if (!TRUE)
    {
        return EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED, positionAfternone3);
    }
    /* Validating field random_data */
    BOOLEAN
    hasEnoughBytes1 =
        (uint64_t)(uint32_t)(uint8_t)32U <= (InputLength - positionAfternone3);
    uint64_t positionAfterKeyExchangeRsp6;
    if (!hasEnoughBytes1)
    {
        positionAfterKeyExchangeRsp6 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfternone3);
    }
    else
    {
        uint8_t *truncatedInput = Input;
        uint64_t truncatedInputLength =
            positionAfternone3 + (uint64_t)(uint32_t)(uint8_t)32U;
        uint64_t result = positionAfternone3;
        while (TRUE)
        {
            uint64_t position = *&result;
            BOOLEAN ite;
            if (!((uint64_t)1U <= (truncatedInputLength - position)))
            {
                ite = TRUE;
            }
            else
            {
                /* Checking that we have enough space for a UINT8, i.e., 1 byte
                 */
                BOOLEAN hasBytes =
                    (uint64_t)1U <= (truncatedInputLength - position);
                uint64_t positionAfterKeyExchangeRsp;
                if (hasBytes)
                {
                    positionAfterKeyExchangeRsp = position + (uint64_t)1U;
                }
                else
                {
                    positionAfterKeyExchangeRsp = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, position);
                }
                uint64_t res;
                if (EverParseIsSuccess(positionAfterKeyExchangeRsp))
                {
                    res = positionAfterKeyExchangeRsp;
                }
                else
                {
                    Err("_KeyExchangeRsp",
                        "random_data.element",
                        EverParseErrorReasonOfResult(
                            positionAfterKeyExchangeRsp),
                        Ctxt,
                        truncatedInput,
                        position);
                    res = positionAfterKeyExchangeRsp;
                }
                uint64_t result1 = res;
                result = result1;
                ite = EverParseIsError(result1);
            }
            if (ite)
            {
                break;
            }
        }
        uint64_t res = result;
        positionAfterKeyExchangeRsp6 = res;
    }
    uint64_t positionAfterrandomData;
    if (EverParseIsSuccess(positionAfterKeyExchangeRsp6))
    {
        positionAfterrandomData = positionAfterKeyExchangeRsp6;
    }
    else
    {
        Err("_KeyExchangeRsp",
            "random_data",
            EverParseErrorReasonOfResult(positionAfterKeyExchangeRsp6),
            Ctxt,
            Input,
            positionAfternone3);
        positionAfterrandomData = positionAfterKeyExchangeRsp6;
    }
    if (EverParseIsError(positionAfterrandomData))
    {
        return positionAfterrandomData;
    }
    /* Validating field exchange_data */
    BOOLEAN hasEnoughBytes2 =
        (uint64_t)ExchangeDataLen <= (InputLength - positionAfterrandomData);
    uint64_t positionAfterKeyExchangeRsp7;
    if (!hasEnoughBytes2)
    {
        positionAfterKeyExchangeRsp7 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterrandomData);
    }
    else
    {
        uint8_t *truncatedInput = Input;
        uint64_t truncatedInputLength =
            positionAfterrandomData + (uint64_t)ExchangeDataLen;
        uint64_t result = positionAfterrandomData;
        while (TRUE)
        {
            uint64_t position = *&result;
            BOOLEAN ite;
            if (!((uint64_t)1U <= (truncatedInputLength - position)))
            {
                ite = TRUE;
            }
            else
            {
                /* Checking that we have enough space for a UINT8, i.e., 1 byte
                 */
                BOOLEAN hasBytes =
                    (uint64_t)1U <= (truncatedInputLength - position);
                uint64_t positionAfterKeyExchangeRsp;
                if (hasBytes)
                {
                    positionAfterKeyExchangeRsp = position + (uint64_t)1U;
                }
                else
                {
                    positionAfterKeyExchangeRsp = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, position);
                }
                uint64_t res;
                if (EverParseIsSuccess(positionAfterKeyExchangeRsp))
                {
                    res = positionAfterKeyExchangeRsp;
                }
                else
                {
                    Err("_KeyExchangeRsp",
                        "exchange_data.base.element",
                        EverParseErrorReasonOfResult(
                            positionAfterKeyExchangeRsp),
                        Ctxt,
                        truncatedInput,
                        position);
                    res = positionAfterKeyExchangeRsp;
                }
                uint64_t result1 = res;
                result = result1;
                ite = EverParseIsError(result1);
            }
            if (ite)
            {
                break;
            }
        }
        uint64_t res = result;
        positionAfterKeyExchangeRsp7 = res;
    }
    uint64_t positionAfterexchangeData;
    if (EverParseIsSuccess(positionAfterKeyExchangeRsp7))
    {
        positionAfterexchangeData = positionAfterKeyExchangeRsp7;
    }
    else
    {
        Err("_KeyExchangeRsp",
            "exchange_data.base",
            EverParseErrorReasonOfResult(positionAfterKeyExchangeRsp7),
            Ctxt,
            Input,
            positionAfterrandomData);
        positionAfterexchangeData = positionAfterKeyExchangeRsp7;
    }
    uint64_t positionAfterKeyExchangeRsp8;
    if (EverParseIsSuccess(positionAfterexchangeData))
    {
        uint8_t *hd = Input + (uint32_t)positionAfterrandomData;
        *OutExchangeData = hd;
        BOOLEAN actionSuccessExchangeData = TRUE;
        if (!actionSuccessExchangeData)
        {
            positionAfterKeyExchangeRsp8 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                positionAfterexchangeData);
        }
        else
        {
            positionAfterKeyExchangeRsp8 = positionAfterexchangeData;
        }
    }
    else
    {
        positionAfterKeyExchangeRsp8 = positionAfterexchangeData;
    }
    uint64_t positionAfterexchangeData0;
    if (EverParseIsSuccess(positionAfterKeyExchangeRsp8))
    {
        positionAfterexchangeData0 = positionAfterKeyExchangeRsp8;
    }
    else
    {
        Err("_KeyExchangeRsp",
            "exchange_data",
            EverParseErrorReasonOfResult(positionAfterKeyExchangeRsp8),
            Ctxt,
            Input,
            positionAfterrandomData);
        positionAfterexchangeData0 = positionAfterKeyExchangeRsp8;
    }
    if (EverParseIsError(positionAfterexchangeData0))
    {
        return positionAfterexchangeData0;
    }
    /* Validating field measurement_summary_hash */
    uint64_t positionAfterKeyExchangeRsp9 = ValidateOptionalBuffer(
        MeasurementSummaryHashExpected,
        HashLen,
        Ctxt,
        Err,
        Input,
        InputLength,
        positionAfterexchangeData0);
    uint64_t positionAftermeasurementSummaryHash;
    if (EverParseIsSuccess(positionAfterKeyExchangeRsp9))
    {
        positionAftermeasurementSummaryHash = positionAfterKeyExchangeRsp9;
    }
    else
    {
        Err("_KeyExchangeRsp",
            "measurement_summary_hash.base",
            EverParseErrorReasonOfResult(positionAfterKeyExchangeRsp9),
            Ctxt,
            Input,
            positionAfterexchangeData0);
        positionAftermeasurementSummaryHash = positionAfterKeyExchangeRsp9;
    }
    uint64_t positionAfterKeyExchangeRsp10;
    if (EverParseIsSuccess(positionAftermeasurementSummaryHash))
    {
        uint8_t *hd = Input + (uint32_t)positionAfterexchangeData0;
        *OutMeasurementSummaryHash = hd;
        BOOLEAN actionSuccessMeasurementSummaryHash = TRUE;
        if (!actionSuccessMeasurementSummaryHash)
        {
            positionAfterKeyExchangeRsp10 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                positionAftermeasurementSummaryHash);
        }
        else
        {
            positionAfterKeyExchangeRsp10 = positionAftermeasurementSummaryHash;
        }
    }
    else
    {
        positionAfterKeyExchangeRsp10 = positionAftermeasurementSummaryHash;
    }
    uint64_t positionAftermeasurementSummaryHash0;
    if (EverParseIsSuccess(positionAfterKeyExchangeRsp10))
    {
        positionAftermeasurementSummaryHash0 = positionAfterKeyExchangeRsp10;
    }
    else
    {
        Err("_KeyExchangeRsp",
            "measurement_summary_hash",
            EverParseErrorReasonOfResult(positionAfterKeyExchangeRsp10),
            Ctxt,
            Input,
            positionAfterexchangeData0);
        positionAftermeasurementSummaryHash0 = positionAfterKeyExchangeRsp10;
    }
    if (EverParseIsError(positionAftermeasurementSummaryHash0))
    {
        return positionAftermeasurementSummaryHash0;
    }
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    BOOLEAN hasBytes4 =
        (uint64_t)2U <= (InputLength - positionAftermeasurementSummaryHash0);
    uint64_t positionAfterKeyExchangeRsp11;
    if (hasBytes4)
    {
        positionAfterKeyExchangeRsp11 =
            positionAftermeasurementSummaryHash0 + (uint64_t)2U;
    }
    else
    {
        positionAfterKeyExchangeRsp11 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAftermeasurementSummaryHash0);
    }
    uint64_t positionAfternone4;
    if (EverParseIsSuccess(positionAfterKeyExchangeRsp11))
    {
        positionAfternone4 = positionAfterKeyExchangeRsp11;
    }
    else
    {
        Err("_KeyExchangeRsp",
            "none",
            EverParseErrorReasonOfResult(positionAfterKeyExchangeRsp11),
            Ctxt,
            Input,
            positionAftermeasurementSummaryHash0);
        positionAfternone4 = positionAfterKeyExchangeRsp11;
    }
    if (EverParseIsError(positionAfternone4))
    {
        return positionAfternone4;
    }
    uint16_t r =
        Load16Le(Input + (uint32_t)positionAftermeasurementSummaryHash0);
    uint16_t none2 = (uint16_t)(uint32_t)r;
    BOOLEAN noneConstraintIsOk2 = none2 <= (uint16_t)1024U;
    uint64_t positionAfternone5 =
        EverParseCheckConstraintOk(noneConstraintIsOk2, positionAfternone4);
    if (EverParseIsError(positionAfternone5))
    {
        return positionAfternone5;
    }
    *OutOpaqueDataLen = (uint32_t)none2;
    if (!TRUE)
    {
        return EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED, positionAfternone5);
    }
    /* Validating field opaque_data */
    BOOLEAN hasEnoughBytes3 =
        (uint64_t)(uint32_t)none2 <= (InputLength - positionAfternone5);
    uint64_t positionAfterKeyExchangeRsp12;
    if (!hasEnoughBytes3)
    {
        positionAfterKeyExchangeRsp12 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfternone5);
    }
    else
    {
        uint8_t *truncatedInput = Input;
        uint64_t truncatedInputLength =
            positionAfternone5 + (uint64_t)(uint32_t)none2;
        uint64_t result = positionAfternone5;
        while (TRUE)
        {
            uint64_t position = *&result;
            BOOLEAN ite;
            if (!((uint64_t)1U <= (truncatedInputLength - position)))
            {
                ite = TRUE;
            }
            else
            {
                /* Checking that we have enough space for a UINT8, i.e., 1 byte
                 */
                BOOLEAN hasBytes =
                    (uint64_t)1U <= (truncatedInputLength - position);
                uint64_t positionAfterKeyExchangeRsp;
                if (hasBytes)
                {
                    positionAfterKeyExchangeRsp = position + (uint64_t)1U;
                }
                else
                {
                    positionAfterKeyExchangeRsp = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, position);
                }
                uint64_t res;
                if (EverParseIsSuccess(positionAfterKeyExchangeRsp))
                {
                    res = positionAfterKeyExchangeRsp;
                }
                else
                {
                    Err("_KeyExchangeRsp",
                        "opaque_data.base.element",
                        EverParseErrorReasonOfResult(
                            positionAfterKeyExchangeRsp),
                        Ctxt,
                        truncatedInput,
                        position);
                    res = positionAfterKeyExchangeRsp;
                }
                uint64_t result1 = res;
                result = result1;
                ite = EverParseIsError(result1);
            }
            if (ite)
            {
                break;
            }
        }
        uint64_t res = result;
        positionAfterKeyExchangeRsp12 = res;
    }
    uint64_t positionAfteropaqueData;
    if (EverParseIsSuccess(positionAfterKeyExchangeRsp12))
    {
        positionAfteropaqueData = positionAfterKeyExchangeRsp12;
    }
    else
    {
        Err("_KeyExchangeRsp",
            "opaque_data.base",
            EverParseErrorReasonOfResult(positionAfterKeyExchangeRsp12),
            Ctxt,
            Input,
            positionAfternone5);
        positionAfteropaqueData = positionAfterKeyExchangeRsp12;
    }
    uint64_t positionAfterKeyExchangeRsp13;
    if (EverParseIsSuccess(positionAfteropaqueData))
    {
        uint8_t *hd = Input + (uint32_t)positionAfternone5;
        *OutOpaqueData = hd;
        BOOLEAN actionSuccessOpaqueData = TRUE;
        if (!actionSuccessOpaqueData)
        {
            positionAfterKeyExchangeRsp13 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                positionAfteropaqueData);
        }
        else
        {
            positionAfterKeyExchangeRsp13 = positionAfteropaqueData;
        }
    }
    else
    {
        positionAfterKeyExchangeRsp13 = positionAfteropaqueData;
    }
    uint64_t positionAfteropaqueData0;
    if (EverParseIsSuccess(positionAfterKeyExchangeRsp13))
    {
        positionAfteropaqueData0 = positionAfterKeyExchangeRsp13;
    }
    else
    {
        Err("_KeyExchangeRsp",
            "opaque_data",
            EverParseErrorReasonOfResult(positionAfterKeyExchangeRsp13),
            Ctxt,
            Input,
            positionAfternone5);
        positionAfteropaqueData0 = positionAfterKeyExchangeRsp13;
    }
    if (EverParseIsError(positionAfteropaqueData0))
    {
        return positionAfteropaqueData0;
    }
    /* Validating field signature */
    BOOLEAN hasEnoughBytes =
        (uint64_t)SignatureLen <= (InputLength - positionAfteropaqueData0);
    uint64_t positionAfterKeyExchangeRsp14;
    if (!hasEnoughBytes)
    {
        positionAfterKeyExchangeRsp14 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfteropaqueData0);
    }
    else
    {
        uint8_t *truncatedInput = Input;
        uint64_t truncatedInputLength =
            positionAfteropaqueData0 + (uint64_t)SignatureLen;
        uint64_t result = positionAfteropaqueData0;
        while (TRUE)
        {
            uint64_t position = *&result;
            BOOLEAN ite;
            if (!((uint64_t)1U <= (truncatedInputLength - position)))
            {
                ite = TRUE;
            }
            else
            {
                /* Checking that we have enough space for a UINT8, i.e., 1 byte
                 */
                BOOLEAN hasBytes =
                    (uint64_t)1U <= (truncatedInputLength - position);
                uint64_t positionAfterKeyExchangeRsp;
                if (hasBytes)
                {
                    positionAfterKeyExchangeRsp = position + (uint64_t)1U;
                }
                else
                {
                    positionAfterKeyExchangeRsp = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, position);
                }
                uint64_t res;
                if (EverParseIsSuccess(positionAfterKeyExchangeRsp))
                {
                    res = positionAfterKeyExchangeRsp;
                }
                else
                {
                    Err("_KeyExchangeRsp",
                        "signature.base.element",
                        EverParseErrorReasonOfResult(
                            positionAfterKeyExchangeRsp),
                        Ctxt,
                        truncatedInput,
                        position);
                    res = positionAfterKeyExchangeRsp;
                }
                uint64_t result1 = res;
                result = result1;
                ite = EverParseIsError(result1);
            }
            if (ite)
            {
                break;
            }
        }
        uint64_t res = result;
        positionAfterKeyExchangeRsp14 = res;
    }
    uint64_t positionAftersignature0;
    if (EverParseIsSuccess(positionAfterKeyExchangeRsp14))
    {
        positionAftersignature0 = positionAfterKeyExchangeRsp14;
    }
    else
    {
        Err("_KeyExchangeRsp",
            "signature.base",
            EverParseErrorReasonOfResult(positionAfterKeyExchangeRsp14),
            Ctxt,
            Input,
            positionAfteropaqueData0);
        positionAftersignature0 = positionAfterKeyExchangeRsp14;
    }
    uint64_t positionAfterKeyExchangeRsp15;
    if (EverParseIsSuccess(positionAftersignature0))
    {
        uint8_t *hd = Input + (uint32_t)positionAfteropaqueData0;
        *OutSignature = hd;
        BOOLEAN actionSuccessSignature = TRUE;
        if (!actionSuccessSignature)
        {
            positionAfterKeyExchangeRsp15 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                positionAftersignature0);
        }
        else
        {
            positionAfterKeyExchangeRsp15 = positionAftersignature0;
        }
    }
    else
    {
        positionAfterKeyExchangeRsp15 = positionAftersignature0;
    }
    uint64_t positionAftersignature;
    if (EverParseIsSuccess(positionAfterKeyExchangeRsp15))
    {
        positionAftersignature = positionAfterKeyExchangeRsp15;
    }
    else
    {
        Err("_KeyExchangeRsp",
            "signature",
            EverParseErrorReasonOfResult(positionAfterKeyExchangeRsp15),
            Ctxt,
            Input,
            positionAfteropaqueData0);
        positionAftersignature = positionAfterKeyExchangeRsp15;
    }
    if (EverParseIsError(positionAftersignature))
    {
        return positionAftersignature;
    }
    /* Validating field responder_verify_data */
    uint64_t positionAfterKeyExchangeRsp16 = ValidateOptionalBuffer(
        ResponderVerifyDataExpected,
        HashLen,
        Ctxt,
        Err,
        Input,
        InputLength,
        positionAftersignature);
    uint64_t positionAfterresponderVerifyData;
    if (EverParseIsSuccess(positionAfterKeyExchangeRsp16))
    {
        positionAfterresponderVerifyData = positionAfterKeyExchangeRsp16;
    }
    else
    {
        Err("_KeyExchangeRsp",
            "responder_verify_data.base",
            EverParseErrorReasonOfResult(positionAfterKeyExchangeRsp16),
            Ctxt,
            Input,
            positionAftersignature);
        positionAfterresponderVerifyData = positionAfterKeyExchangeRsp16;
    }
    uint64_t positionAfterKeyExchangeRsp17;
    if (EverParseIsSuccess(positionAfterresponderVerifyData))
    {
        uint8_t *hd = Input + (uint32_t)positionAftersignature;
        *OutResponderVerifyData = hd;
        BOOLEAN actionSuccessResponderVerifyData = TRUE;
        if (!actionSuccessResponderVerifyData)
        {
            positionAfterKeyExchangeRsp17 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                positionAfterresponderVerifyData);
        }
        else
        {
            positionAfterKeyExchangeRsp17 = positionAfterresponderVerifyData;
        }
    }
    else
    {
        positionAfterKeyExchangeRsp17 = positionAfterresponderVerifyData;
    }
    if (EverParseIsSuccess(positionAfterKeyExchangeRsp17))
    {
        return positionAfterKeyExchangeRsp17;
    }
    Err("_KeyExchangeRsp",
        "responder_verify_data",
        EverParseErrorReasonOfResult(positionAfterKeyExchangeRsp17),
        Ctxt,
        Input,
        positionAftersignature);
    return positionAfterKeyExchangeRsp17;
}

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
    uint64_t StartPosition)
{
    /* Validating field preamble */
    uint64_t positionAfterGetEncapsulatedRequest = ValidatePreamble(
        SPDM____GET_ENCAPSULATED_REQUEST,
        Ctxt,
        Err,
        Input,
        InputLength,
        StartPosition);
    uint64_t positionAfterpreamble;
    if (EverParseIsSuccess(positionAfterGetEncapsulatedRequest))
    {
        positionAfterpreamble = positionAfterGetEncapsulatedRequest;
    }
    else
    {
        Err("_GetEncapsulatedRequest",
            "preamble",
            EverParseErrorReasonOfResult(positionAfterGetEncapsulatedRequest),
            Ctxt,
            Input,
            StartPosition);
        positionAfterpreamble = positionAfterGetEncapsulatedRequest;
    }
    if (EverParseIsError(positionAfterpreamble))
    {
        return positionAfterpreamble;
    }
    /* Validating field params */
    uint64_t positionAfterGetEncapsulatedRequest0 = ValidateReservedParams(
        Ctxt, Err, Input, InputLength, positionAfterpreamble);
    if (EverParseIsSuccess(positionAfterGetEncapsulatedRequest0))
    {
        return positionAfterGetEncapsulatedRequest0;
    }
    Err("_GetEncapsulatedRequest",
        "params",
        EverParseErrorReasonOfResult(positionAfterGetEncapsulatedRequest0),
        Ctxt,
        Input,
        positionAfterpreamble);
    return positionAfterGetEncapsulatedRequest0;
}

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
    uint64_t StartPosition)
{
    /* Validating field preamble */
    uint64_t positionAfterEncapsulatedRequest = ValidatePreamble(
        SPDM____ENCAPSULATED_REQUEST,
        Ctxt,
        Err,
        Input,
        InputLength,
        StartPosition);
    uint64_t positionAfterpreamble;
    if (EverParseIsSuccess(positionAfterEncapsulatedRequest))
    {
        positionAfterpreamble = positionAfterEncapsulatedRequest;
    }
    else
    {
        Err("_EncapsulatedRequest",
            "preamble",
            EverParseErrorReasonOfResult(positionAfterEncapsulatedRequest),
            Ctxt,
            Input,
            StartPosition);
        positionAfterpreamble = positionAfterEncapsulatedRequest;
    }
    if (EverParseIsError(positionAfterpreamble))
    {
        return positionAfterpreamble;
    }
    /* Validating field param_1_request_id */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - positionAfterpreamble);
    uint64_t positionAfterparam1RequestId;
    if (hasBytes0)
    {
        positionAfterparam1RequestId = positionAfterpreamble + (uint64_t)1U;
    }
    else
    {
        positionAfterparam1RequestId = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterpreamble);
    }
    uint64_t positionAfterEncapsulatedRequest0;
    if (EverParseIsError(positionAfterparam1RequestId))
    {
        positionAfterEncapsulatedRequest0 = positionAfterparam1RequestId;
    }
    else
    {
        uint8_t param1RequestId = Input[(uint32_t)positionAfterpreamble];
        *OutRequestId = param1RequestId;
        if (TRUE)
        {
            positionAfterEncapsulatedRequest0 = positionAfterparam1RequestId;
        }
        else
        {
            positionAfterEncapsulatedRequest0 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                positionAfterparam1RequestId);
        }
    }
    uint64_t positionAfterparam1RequestId0;
    if (EverParseIsSuccess(positionAfterEncapsulatedRequest0))
    {
        positionAfterparam1RequestId0 = positionAfterEncapsulatedRequest0;
    }
    else
    {
        Err("_EncapsulatedRequest",
            "param_1_request_id",
            EverParseErrorReasonOfResult(positionAfterEncapsulatedRequest0),
            Ctxt,
            Input,
            positionAfterpreamble);
        positionAfterparam1RequestId0 = positionAfterEncapsulatedRequest0;
    }
    if (EverParseIsError(positionAfterparam1RequestId0))
    {
        return positionAfterparam1RequestId0;
    }
    /* Validating field param_2_reserved */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes =
        (uint64_t)1U <= (InputLength - positionAfterparam1RequestId0);
    uint64_t positionAfterEncapsulatedRequest1;
    if (hasBytes)
    {
        positionAfterEncapsulatedRequest1 =
            positionAfterparam1RequestId0 + (uint64_t)1U;
    }
    else
    {
        positionAfterEncapsulatedRequest1 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfterparam1RequestId0);
    }
    if (EverParseIsSuccess(positionAfterEncapsulatedRequest1))
    {
        return positionAfterEncapsulatedRequest1;
    }
    Err("_EncapsulatedRequest",
        "param_2_reserved",
        EverParseErrorReasonOfResult(positionAfterEncapsulatedRequest1),
        Ctxt,
        Input,
        positionAfterparam1RequestId0);
    return positionAfterEncapsulatedRequest1;
}

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
    uint64_t StartPosition)
{
    /* Validating field preamble */
    uint64_t positionAfterDeliverEncapsulatedResponse = ValidatePreamble(
        SPDM____DELIVER_ENCAPSULATED_RESPONSE,
        Ctxt,
        Err,
        Input,
        InputLength,
        StartPosition);
    uint64_t positionAfterpreamble;
    if (EverParseIsSuccess(positionAfterDeliverEncapsulatedResponse))
    {
        positionAfterpreamble = positionAfterDeliverEncapsulatedResponse;
    }
    else
    {
        Err("_DeliverEncapsulatedResponse",
            "preamble",
            EverParseErrorReasonOfResult(
                positionAfterDeliverEncapsulatedResponse),
            Ctxt,
            Input,
            StartPosition);
        positionAfterpreamble = positionAfterDeliverEncapsulatedResponse;
    }
    if (EverParseIsError(positionAfterpreamble))
    {
        return positionAfterpreamble;
    }
    /* Validating field param_1_request_id */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - positionAfterpreamble);
    uint64_t positionAfterparam1RequestId;
    if (hasBytes0)
    {
        positionAfterparam1RequestId = positionAfterpreamble + (uint64_t)1U;
    }
    else
    {
        positionAfterparam1RequestId = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterpreamble);
    }
    uint64_t positionAfterDeliverEncapsulatedResponse0;
    if (EverParseIsError(positionAfterparam1RequestId))
    {
        positionAfterDeliverEncapsulatedResponse0 =
            positionAfterparam1RequestId;
    }
    else
    {
        uint8_t param1RequestId = Input[(uint32_t)positionAfterpreamble];
        *OutRequestId = param1RequestId;
        if (TRUE)
        {
            positionAfterDeliverEncapsulatedResponse0 =
                positionAfterparam1RequestId;
        }
        else
        {
            positionAfterDeliverEncapsulatedResponse0 =
                EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                    positionAfterparam1RequestId);
        }
    }
    uint64_t positionAfterparam1RequestId0;
    if (EverParseIsSuccess(positionAfterDeliverEncapsulatedResponse0))
    {
        positionAfterparam1RequestId0 =
            positionAfterDeliverEncapsulatedResponse0;
    }
    else
    {
        Err("_DeliverEncapsulatedResponse",
            "param_1_request_id",
            EverParseErrorReasonOfResult(
                positionAfterDeliverEncapsulatedResponse0),
            Ctxt,
            Input,
            positionAfterpreamble);
        positionAfterparam1RequestId0 =
            positionAfterDeliverEncapsulatedResponse0;
    }
    if (EverParseIsError(positionAfterparam1RequestId0))
    {
        return positionAfterparam1RequestId0;
    }
    /* Validating field param_2_reserved */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes =
        (uint64_t)1U <= (InputLength - positionAfterparam1RequestId0);
    uint64_t positionAfterDeliverEncapsulatedResponse1;
    if (hasBytes)
    {
        positionAfterDeliverEncapsulatedResponse1 =
            positionAfterparam1RequestId0 + (uint64_t)1U;
    }
    else
    {
        positionAfterDeliverEncapsulatedResponse1 =
            EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                positionAfterparam1RequestId0);
    }
    if (EverParseIsSuccess(positionAfterDeliverEncapsulatedResponse1))
    {
        return positionAfterDeliverEncapsulatedResponse1;
    }
    Err("_DeliverEncapsulatedResponse",
        "param_2_reserved",
        EverParseErrorReasonOfResult(positionAfterDeliverEncapsulatedResponse1),
        Ctxt,
        Input,
        positionAfterparam1RequestId0);
    return positionAfterDeliverEncapsulatedResponse1;
}

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
    uint64_t StartPosition)
{
    /* Validating field preamble */
    uint64_t positionAfterEncapsulatedResponseAck = ValidatePreamble(
        SPDM____ENCAPSULATED_RESPONSE_ACK,
        Ctxt,
        Err,
        Input,
        InputLength,
        StartPosition);
    uint64_t positionAfterpreamble;
    if (EverParseIsSuccess(positionAfterEncapsulatedResponseAck))
    {
        positionAfterpreamble = positionAfterEncapsulatedResponseAck;
    }
    else
    {
        Err("_EncapsulatedResponseAck",
            "preamble",
            EverParseErrorReasonOfResult(positionAfterEncapsulatedResponseAck),
            Ctxt,
            Input,
            StartPosition);
        positionAfterpreamble = positionAfterEncapsulatedResponseAck;
    }
    if (EverParseIsError(positionAfterpreamble))
    {
        return positionAfterpreamble;
    }
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - positionAfterpreamble);
    uint64_t positionAfterEncapsulatedResponseAck0;
    if (hasBytes0)
    {
        positionAfterEncapsulatedResponseAck0 =
            positionAfterpreamble + (uint64_t)1U;
    }
    else
    {
        positionAfterEncapsulatedResponseAck0 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterpreamble);
    }
    uint64_t positionAfterparam1RequestId;
    if (EverParseIsSuccess(positionAfterEncapsulatedResponseAck0))
    {
        positionAfterparam1RequestId = positionAfterEncapsulatedResponseAck0;
    }
    else
    {
        Err("_EncapsulatedResponseAck",
            "param_1_request_id",
            EverParseErrorReasonOfResult(positionAfterEncapsulatedResponseAck0),
            Ctxt,
            Input,
            positionAfterpreamble);
        positionAfterparam1RequestId = positionAfterEncapsulatedResponseAck0;
    }
    if (EverParseIsError(positionAfterparam1RequestId))
    {
        return positionAfterparam1RequestId;
    }
    uint8_t param1RequestId = Input[(uint32_t)positionAfterpreamble];
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes1 =
        (uint64_t)1U <= (InputLength - positionAfterparam1RequestId);
    uint64_t positionAfternone;
    if (hasBytes1)
    {
        positionAfternone = positionAfterparam1RequestId + (uint64_t)1U;
    }
    else
    {
        positionAfternone = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfterparam1RequestId);
    }
    uint64_t positionAfterEncapsulatedResponseAck1;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterEncapsulatedResponseAck1 = positionAfternone;
    }
    else
    {
        uint8_t none = Input[(uint32_t)positionAfterparam1RequestId];
        BOOLEAN noneConstraintIsOk = none <= (uint8_t)2U;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterEncapsulatedResponseAck1 = positionAfternone1;
        }
        else
        {
            /* Checking that we have enough space for a UINT8, i.e., 1 byte */
            BOOLEAN hasBytes0 =
                (uint64_t)1U <= (InputLength - positionAfternone1);
            uint64_t positionAfterEncapsulatedResponseAck;
            if (hasBytes0)
            {
                positionAfterEncapsulatedResponseAck =
                    positionAfternone1 + (uint64_t)1U;
            }
            else
            {
                positionAfterEncapsulatedResponseAck =
                    EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfternone1);
            }
            uint64_t positionAfterackRequestId;
            if (EverParseIsSuccess(positionAfterEncapsulatedResponseAck))
            {
                positionAfterackRequestId =
                    positionAfterEncapsulatedResponseAck;
            }
            else
            {
                Err("_EncapsulatedResponseAck",
                    "ack_request_id",
                    EverParseErrorReasonOfResult(
                        positionAfterEncapsulatedResponseAck),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAfterackRequestId =
                    positionAfterEncapsulatedResponseAck;
            }
            if (EverParseIsError(positionAfterackRequestId))
            {
                positionAfterEncapsulatedResponseAck1 =
                    positionAfterackRequestId;
            }
            else
            {
                uint8_t ackRequestId = Input[(uint32_t)positionAfternone1];
                /* Validating field reserved */
                BOOLEAN
                hasEnoughBytes = (uint64_t)(uint32_t)(uint8_t)3U <=
                                 (InputLength - positionAfterackRequestId);
                uint64_t positionAfterEncapsulatedResponseAck;
                if (!hasEnoughBytes)
                {
                    positionAfterEncapsulatedResponseAck =
                        EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAfterackRequestId);
                }
                else
                {
                    uint8_t *truncatedInput = Input;
                    uint64_t truncatedInputLength =
                        positionAfterackRequestId +
                        (uint64_t)(uint32_t)(uint8_t)3U;
                    uint64_t result = positionAfterackRequestId;
                    while (TRUE)
                    {
                        uint64_t position = *&result;
                        BOOLEAN ite;
                        if (!((uint64_t)1U <=
                              (truncatedInputLength - position)))
                        {
                            ite = TRUE;
                        }
                        else
                        {
                            /* Checking that we have enough space for a UINT8,
                             * i.e., 1 byte */
                            BOOLEAN hasBytes =
                                (uint64_t)1U <=
                                (truncatedInputLength - position);
                            uint64_t positionAfterEncapsulatedResponseAck;
                            if (hasBytes)
                            {
                                positionAfterEncapsulatedResponseAck =
                                    position + (uint64_t)1U;
                            }
                            else
                            {
                                positionAfterEncapsulatedResponseAck =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        position);
                            }
                            uint64_t res;
                            if (EverParseIsSuccess(
                                    positionAfterEncapsulatedResponseAck))
                            {
                                res = positionAfterEncapsulatedResponseAck;
                            }
                            else
                            {
                                Err("_EncapsulatedResponseAck",
                                    "reserved.base.element",
                                    EverParseErrorReasonOfResult(
                                        positionAfterEncapsulatedResponseAck),
                                    Ctxt,
                                    truncatedInput,
                                    position);
                                res = positionAfterEncapsulatedResponseAck;
                            }
                            uint64_t result1 = res;
                            result = result1;
                            ite = EverParseIsError(result1);
                        }
                        if (ite)
                        {
                            break;
                        }
                    }
                    uint64_t res = result;
                    positionAfterEncapsulatedResponseAck = res;
                }
                uint64_t positionAfterreserved;
                if (EverParseIsSuccess(positionAfterEncapsulatedResponseAck))
                {
                    positionAfterreserved =
                        positionAfterEncapsulatedResponseAck;
                }
                else
                {
                    Err("_EncapsulatedResponseAck",
                        "reserved.base",
                        EverParseErrorReasonOfResult(
                            positionAfterEncapsulatedResponseAck),
                        Ctxt,
                        Input,
                        positionAfterackRequestId);
                    positionAfterreserved =
                        positionAfterEncapsulatedResponseAck;
                }
                uint64_t positionAfterEncapsulatedResponseAck0;
                if (EverParseIsSuccess(positionAfterreserved))
                {
                    *OutRequestId = param1RequestId;
                    *OutPayloadType = none;
                    *OutAckRequestId = ackRequestId;
                    BOOLEAN actionSuccessReserved = TRUE;
                    if (!actionSuccessReserved)
                    {
                        positionAfterEncapsulatedResponseAck0 =
                            EverParseSetValidatorErrorPos(
                                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                                positionAfterreserved);
                    }
                    else
                    {
                        positionAfterEncapsulatedResponseAck0 =
                            positionAfterreserved;
                    }
                }
                else
                {
                    positionAfterEncapsulatedResponseAck0 =
                        positionAfterreserved;
                }
                if (EverParseIsSuccess(positionAfterEncapsulatedResponseAck0))
                {
                    positionAfterEncapsulatedResponseAck1 =
                        positionAfterEncapsulatedResponseAck0;
                }
                else
                {
                    Err("_EncapsulatedResponseAck",
                        "reserved",
                        EverParseErrorReasonOfResult(
                            positionAfterEncapsulatedResponseAck0),
                        Ctxt,
                        Input,
                        positionAfterackRequestId);
                    positionAfterEncapsulatedResponseAck1 =
                        positionAfterEncapsulatedResponseAck0;
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterEncapsulatedResponseAck1))
    {
        return positionAfterEncapsulatedResponseAck1;
    }
    Err("_EncapsulatedResponseAck",
        "none",
        EverParseErrorReasonOfResult(positionAfterEncapsulatedResponseAck1),
        Ctxt,
        Input,
        positionAfterparam1RequestId);
    return positionAfterEncapsulatedResponseAck1;
}

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
    uint64_t StartPosition)
{
    /* Validating field preamble */
    uint64_t positionAfterEndSession = ValidatePreamble(
        SPDM____END_SESSION, Ctxt, Err, Input, InputLength, StartPosition);
    uint64_t positionAfterpreamble;
    if (EverParseIsSuccess(positionAfterEndSession))
    {
        positionAfterpreamble = positionAfterEndSession;
    }
    else
    {
        Err("_EndSession",
            "preamble",
            EverParseErrorReasonOfResult(positionAfterEndSession),
            Ctxt,
            Input,
            StartPosition);
        positionAfterpreamble = positionAfterEndSession;
    }
    if (EverParseIsError(positionAfterpreamble))
    {
        return positionAfterpreamble;
    }
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes = (uint64_t)1U <= (InputLength - positionAfterpreamble);
    uint64_t res;
    if (hasBytes)
    {
        res = positionAfterpreamble + (uint64_t)1U;
    }
    else
    {
        res = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterpreamble);
    }
    uint64_t positionAfterEndSession0;
    if (EverParseIsError(res))
    {
        positionAfterEndSession0 = res;
    }
    else
    {
        uint8_t fieldValue = Input[(uint32_t)positionAfterpreamble];
        *OutPreserveNegotiatedState =
            EverParseGetBitfield8(fieldValue, (uint32_t)0U, (uint32_t)1U) ==
            (uint8_t)1U;
        BOOLEAN actionResult = TRUE;
        if (!actionResult)
        {
            positionAfterEndSession0 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED, res);
        }
        else
        {
            /* Validating field param_2_reserved */
            /* Checking that we have enough space for a UINT8, i.e., 1 byte */
            BOOLEAN hasBytes = (uint64_t)1U <= (InputLength - res);
            uint64_t positionAfterEndSession;
            if (hasBytes)
            {
                positionAfterEndSession = res + (uint64_t)1U;
            }
            else
            {
                positionAfterEndSession = EverParseSetValidatorErrorPos(
                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, res);
            }
            uint64_t res1;
            if (EverParseIsSuccess(positionAfterEndSession))
            {
                res1 = positionAfterEndSession;
            }
            else
            {
                Err("_EndSession",
                    "param_2_reserved",
                    EverParseErrorReasonOfResult(positionAfterEndSession),
                    Ctxt,
                    Input,
                    res);
                res1 = positionAfterEndSession;
            }
            positionAfterEndSession0 = res1;
        }
    }
    if (EverParseIsSuccess(positionAfterEndSession0))
    {
        return positionAfterEndSession0;
    }
    Err("_EndSession",
        "none",
        EverParseErrorReasonOfResult(positionAfterEndSession0),
        Ctxt,
        Input,
        positionAfterpreamble);
    return positionAfterEndSession0;
}

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
    uint64_t StartPosition)
{
    /* Validating field preamble */
    uint64_t positionAfterEndSessionAck = ValidatePreamble(
        SPDM____END_SESSION_ACK, Ctxt, Err, Input, InputLength, StartPosition);
    uint64_t positionAfterpreamble;
    if (EverParseIsSuccess(positionAfterEndSessionAck))
    {
        positionAfterpreamble = positionAfterEndSessionAck;
    }
    else
    {
        Err("_EndSessionAck",
            "preamble",
            EverParseErrorReasonOfResult(positionAfterEndSessionAck),
            Ctxt,
            Input,
            StartPosition);
        positionAfterpreamble = positionAfterEndSessionAck;
    }
    if (EverParseIsError(positionAfterpreamble))
    {
        return positionAfterpreamble;
    }
    /* Validating field params */
    uint64_t positionAfterEndSessionAck0 = ValidateReservedParams(
        Ctxt, Err, Input, InputLength, positionAfterpreamble);
    if (EverParseIsSuccess(positionAfterEndSessionAck0))
    {
        return positionAfterEndSessionAck0;
    }
    Err("_EndSessionAck",
        "params",
        EverParseErrorReasonOfResult(positionAfterEndSessionAck0),
        Ctxt,
        Input,
        positionAfterpreamble);
    return positionAfterEndSessionAck0;
}

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
    uint64_t StartPosition)
{
    /* Validating field preamble */
    uint64_t positionAfterFinish = ValidatePreamble(
        SPDM____FINISH, Ctxt, Err, Input, InputLength, StartPosition);
    uint64_t positionAfterpreamble;
    if (EverParseIsSuccess(positionAfterFinish))
    {
        positionAfterpreamble = positionAfterFinish;
    }
    else
    {
        Err("_Finish",
            "preamble",
            EverParseErrorReasonOfResult(positionAfterFinish),
            Ctxt,
            Input,
            StartPosition);
        positionAfterpreamble = positionAfterFinish;
    }
    if (EverParseIsError(positionAfterpreamble))
    {
        return positionAfterpreamble;
    }
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - positionAfterpreamble);
    uint64_t positionAfterFinish0;
    if (hasBytes0)
    {
        positionAfterFinish0 = positionAfterpreamble + (uint64_t)1U;
    }
    else
    {
        positionAfterFinish0 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterpreamble);
    }
    uint64_t positionAfterBitfield0;
    if (EverParseIsSuccess(positionAfterFinish0))
    {
        positionAfterBitfield0 = positionAfterFinish0;
    }
    else
    {
        Err("_Finish",
            "__bitfield_0",
            EverParseErrorReasonOfResult(positionAfterFinish0),
            Ctxt,
            Input,
            positionAfterpreamble);
        positionAfterBitfield0 = positionAfterFinish0;
    }
    if (EverParseIsError(positionAfterBitfield0))
    {
        return positionAfterBitfield0;
    }
    uint8_t bitfield0 = Input[(uint32_t)positionAfterpreamble];
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes1 = (uint64_t)1U <= (InputLength - positionAfterBitfield0);
    uint64_t positionAfternone;
    if (hasBytes1)
    {
        positionAfternone = positionAfterBitfield0 + (uint64_t)1U;
    }
    else
    {
        positionAfternone = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterBitfield0);
    }
    uint64_t positionAfterFinish1;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterFinish1 = positionAfternone;
    }
    else
    {
        uint8_t none = Input[(uint32_t)positionAfterBitfield0];
        BOOLEAN noneConstraintIsOk =
            none <= (uint8_t)7U || none == (uint8_t)255U;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterFinish1 = positionAfternone1;
        }
        else
        {
            /* Validating field signature */
            uint64_t positionAfterFinish = ValidateOptionalBuffer(
                EverParseGetBitfield8(bitfield0, (uint32_t)0U, (uint32_t)1U) ==
                    (uint8_t)1U,
                SignatureLen,
                Ctxt,
                Err,
                Input,
                InputLength,
                positionAfternone1);
            uint64_t positionAftersignature0;
            if (EverParseIsSuccess(positionAfterFinish))
            {
                positionAftersignature0 = positionAfterFinish;
            }
            else
            {
                Err("_Finish",
                    "signature.base",
                    EverParseErrorReasonOfResult(positionAfterFinish),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAftersignature0 = positionAfterFinish;
            }
            uint64_t positionAfterFinish0;
            if (EverParseIsSuccess(positionAftersignature0))
            {
                uint8_t *hd = Input + (uint32_t)positionAfternone1;
                *OutSigIncluded =
                    EverParseGetBitfield8(
                        bitfield0, (uint32_t)0U, (uint32_t)1U) == (uint8_t)1U;
                *OutSlotId = none;
                *OutSig = hd;
                BOOLEAN actionSuccessSignature = TRUE;
                if (!actionSuccessSignature)
                {
                    positionAfterFinish0 = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                        positionAftersignature0);
                }
                else
                {
                    positionAfterFinish0 = positionAftersignature0;
                }
            }
            else
            {
                positionAfterFinish0 = positionAftersignature0;
            }
            uint64_t positionAftersignature;
            if (EverParseIsSuccess(positionAfterFinish0))
            {
                positionAftersignature = positionAfterFinish0;
            }
            else
            {
                Err("_Finish",
                    "signature",
                    EverParseErrorReasonOfResult(positionAfterFinish0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAftersignature = positionAfterFinish0;
            }
            if (EverParseIsError(positionAftersignature))
            {
                positionAfterFinish1 = positionAftersignature;
            }
            else
            {
                /* Validating field requester_verify_data */
                BOOLEAN hasEnoughBytes =
                    (uint64_t)HashLen <= (InputLength - positionAftersignature);
                uint64_t positionAfterFinish;
                if (!hasEnoughBytes)
                {
                    positionAfterFinish = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAftersignature);
                }
                else
                {
                    uint8_t *truncatedInput = Input;
                    uint64_t truncatedInputLength =
                        positionAftersignature + (uint64_t)HashLen;
                    uint64_t result = positionAftersignature;
                    while (TRUE)
                    {
                        uint64_t position = *&result;
                        BOOLEAN ite;
                        if (!((uint64_t)1U <=
                              (truncatedInputLength - position)))
                        {
                            ite = TRUE;
                        }
                        else
                        {
                            /* Checking that we have enough space for a UINT8,
                             * i.e., 1 byte */
                            BOOLEAN hasBytes =
                                (uint64_t)1U <=
                                (truncatedInputLength - position);
                            uint64_t positionAfterFinish;
                            if (hasBytes)
                            {
                                positionAfterFinish = position + (uint64_t)1U;
                            }
                            else
                            {
                                positionAfterFinish =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        position);
                            }
                            uint64_t res;
                            if (EverParseIsSuccess(positionAfterFinish))
                            {
                                res = positionAfterFinish;
                            }
                            else
                            {
                                Err("_Finish",
                                    "requester_verify_data.base.element",
                                    EverParseErrorReasonOfResult(
                                        positionAfterFinish),
                                    Ctxt,
                                    truncatedInput,
                                    position);
                                res = positionAfterFinish;
                            }
                            uint64_t result1 = res;
                            result = result1;
                            ite = EverParseIsError(result1);
                        }
                        if (ite)
                        {
                            break;
                        }
                    }
                    uint64_t res = result;
                    positionAfterFinish = res;
                }
                uint64_t positionAfterrequesterVerifyData;
                if (EverParseIsSuccess(positionAfterFinish))
                {
                    positionAfterrequesterVerifyData = positionAfterFinish;
                }
                else
                {
                    Err("_Finish",
                        "requester_verify_data.base",
                        EverParseErrorReasonOfResult(positionAfterFinish),
                        Ctxt,
                        Input,
                        positionAftersignature);
                    positionAfterrequesterVerifyData = positionAfterFinish;
                }
                uint64_t positionAfterFinish0;
                if (EverParseIsSuccess(positionAfterrequesterVerifyData))
                {
                    uint8_t *hd = Input + (uint32_t)positionAftersignature;
                    *OutVerifyData = hd;
                    BOOLEAN actionSuccessRequesterVerifyData = TRUE;
                    if (!actionSuccessRequesterVerifyData)
                    {
                        positionAfterFinish0 = EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                            positionAfterrequesterVerifyData);
                    }
                    else
                    {
                        positionAfterFinish0 = positionAfterrequesterVerifyData;
                    }
                }
                else
                {
                    positionAfterFinish0 = positionAfterrequesterVerifyData;
                }
                if (EverParseIsSuccess(positionAfterFinish0))
                {
                    positionAfterFinish1 = positionAfterFinish0;
                }
                else
                {
                    Err("_Finish",
                        "requester_verify_data",
                        EverParseErrorReasonOfResult(positionAfterFinish0),
                        Ctxt,
                        Input,
                        positionAftersignature);
                    positionAfterFinish1 = positionAfterFinish0;
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterFinish1))
    {
        return positionAfterFinish1;
    }
    Err("_Finish",
        "none",
        EverParseErrorReasonOfResult(positionAfterFinish1),
        Ctxt,
        Input,
        positionAfterBitfield0);
    return positionAfterFinish1;
}

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
    uint64_t StartPosition)
{
    /* Validating field preamble */
    uint64_t positionAfterFinishRsp = ValidatePreamble(
        SPDM____FINISH_RSP, Ctxt, Err, Input, InputLength, StartPosition);
    uint64_t positionAfterpreamble;
    if (EverParseIsSuccess(positionAfterFinishRsp))
    {
        positionAfterpreamble = positionAfterFinishRsp;
    }
    else
    {
        Err("_FinishRsp",
            "preamble",
            EverParseErrorReasonOfResult(positionAfterFinishRsp),
            Ctxt,
            Input,
            StartPosition);
        positionAfterpreamble = positionAfterFinishRsp;
    }
    if (EverParseIsError(positionAfterpreamble))
    {
        return positionAfterpreamble;
    }
    /* Validating field params */
    uint64_t positionAfterFinishRsp0 = ValidateReservedParams(
        Ctxt, Err, Input, InputLength, positionAfterpreamble);
    uint64_t positionAfterparams;
    if (EverParseIsSuccess(positionAfterFinishRsp0))
    {
        positionAfterparams = positionAfterFinishRsp0;
    }
    else
    {
        Err("_FinishRsp",
            "params",
            EverParseErrorReasonOfResult(positionAfterFinishRsp0),
            Ctxt,
            Input,
            positionAfterpreamble);
        positionAfterparams = positionAfterFinishRsp0;
    }
    if (EverParseIsError(positionAfterparams))
    {
        return positionAfterparams;
    }
    /* Validating field responder_verify_data */
    uint64_t positionAfterFinishRsp1 = ValidateOptionalBuffer(
        ResponderVerifyDataExpected,
        HashLen,
        Ctxt,
        Err,
        Input,
        InputLength,
        positionAfterparams);
    uint64_t positionAfterresponderVerifyData;
    if (EverParseIsSuccess(positionAfterFinishRsp1))
    {
        positionAfterresponderVerifyData = positionAfterFinishRsp1;
    }
    else
    {
        Err("_FinishRsp",
            "responder_verify_data.base",
            EverParseErrorReasonOfResult(positionAfterFinishRsp1),
            Ctxt,
            Input,
            positionAfterparams);
        positionAfterresponderVerifyData = positionAfterFinishRsp1;
    }
    uint64_t positionAfterFinishRsp2;
    if (EverParseIsSuccess(positionAfterresponderVerifyData))
    {
        uint8_t *hd = Input + (uint32_t)positionAfterparams;
        *OutResponderVerifyData = hd;
        BOOLEAN actionSuccessResponderVerifyData = TRUE;
        if (!actionSuccessResponderVerifyData)
        {
            positionAfterFinishRsp2 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                positionAfterresponderVerifyData);
        }
        else
        {
            positionAfterFinishRsp2 = positionAfterresponderVerifyData;
        }
    }
    else
    {
        positionAfterFinishRsp2 = positionAfterresponderVerifyData;
    }
    if (EverParseIsSuccess(positionAfterFinishRsp2))
    {
        return positionAfterFinishRsp2;
    }
    Err("_FinishRsp",
        "responder_verify_data",
        EverParseErrorReasonOfResult(positionAfterFinishRsp2),
        Ctxt,
        Input,
        positionAfterparams);
    return positionAfterFinishRsp2;
}

static inline uint64_t
ValidateVendorDefinedBody(
    uint8_t Code,
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
    uint64_t StartPosition)
{
    /* Validating field preamble */
    uint64_t positionAfterVendorDefinedBody =
        ValidatePreamble(Code, Ctxt, Err, Input, InputLength, StartPosition);
    uint64_t positionAfterpreamble;
    if (EverParseIsSuccess(positionAfterVendorDefinedBody))
    {
        positionAfterpreamble = positionAfterVendorDefinedBody;
    }
    else
    {
        Err("_VendorDefinedBody",
            "preamble",
            EverParseErrorReasonOfResult(positionAfterVendorDefinedBody),
            Ctxt,
            Input,
            StartPosition);
        positionAfterpreamble = positionAfterVendorDefinedBody;
    }
    if (EverParseIsError(positionAfterpreamble))
    {
        return positionAfterpreamble;
    }
    /* Validating field param_1_reserved */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - positionAfterpreamble);
    uint64_t positionAfterVendorDefinedBody0;
    if (hasBytes0)
    {
        positionAfterVendorDefinedBody0 = positionAfterpreamble + (uint64_t)1U;
    }
    else
    {
        positionAfterVendorDefinedBody0 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterpreamble);
    }
    uint64_t res0;
    if (EverParseIsSuccess(positionAfterVendorDefinedBody0))
    {
        res0 = positionAfterVendorDefinedBody0;
    }
    else
    {
        Err("_VendorDefinedBody",
            "param_1_reserved",
            EverParseErrorReasonOfResult(positionAfterVendorDefinedBody0),
            Ctxt,
            Input,
            positionAfterpreamble);
        res0 = positionAfterVendorDefinedBody0;
    }
    uint64_t positionAfterparam1Reserved = res0;
    if (EverParseIsError(positionAfterparam1Reserved))
    {
        return positionAfterparam1Reserved;
    }
    /* Validating field param_2_reserved */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes1 =
        (uint64_t)1U <= (InputLength - positionAfterparam1Reserved);
    uint64_t positionAfterVendorDefinedBody1;
    if (hasBytes1)
    {
        positionAfterVendorDefinedBody1 =
            positionAfterparam1Reserved + (uint64_t)1U;
    }
    else
    {
        positionAfterVendorDefinedBody1 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfterparam1Reserved);
    }
    uint64_t res1;
    if (EverParseIsSuccess(positionAfterVendorDefinedBody1))
    {
        res1 = positionAfterVendorDefinedBody1;
    }
    else
    {
        Err("_VendorDefinedBody",
            "param_2_reserved",
            EverParseErrorReasonOfResult(positionAfterVendorDefinedBody1),
            Ctxt,
            Input,
            positionAfterparam1Reserved);
        res1 = positionAfterVendorDefinedBody1;
    }
    uint64_t positionAfterparam2Reserved = res1;
    if (EverParseIsError(positionAfterparam2Reserved))
    {
        return positionAfterparam2Reserved;
    }
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    BOOLEAN hasBytes2 =
        (uint64_t)2U <= (InputLength - positionAfterparam2Reserved);
    uint64_t positionAfterVendorDefinedBody2;
    if (hasBytes2)
    {
        positionAfterVendorDefinedBody2 =
            positionAfterparam2Reserved + (uint64_t)2U;
    }
    else
    {
        positionAfterVendorDefinedBody2 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfterparam2Reserved);
    }
    uint64_t positionAfterstandardId;
    if (EverParseIsSuccess(positionAfterVendorDefinedBody2))
    {
        positionAfterstandardId = positionAfterVendorDefinedBody2;
    }
    else
    {
        Err("_VendorDefinedBody",
            "standard_id",
            EverParseErrorReasonOfResult(positionAfterVendorDefinedBody2),
            Ctxt,
            Input,
            positionAfterparam2Reserved);
        positionAfterstandardId = positionAfterVendorDefinedBody2;
    }
    if (EverParseIsError(positionAfterstandardId))
    {
        return positionAfterstandardId;
    }
    uint16_t r0 = Load16Le(Input + (uint32_t)positionAfterparam2Reserved);
    uint16_t standardId = (uint16_t)(uint32_t)r0;
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes3 = (uint64_t)1U <= (InputLength - positionAfterstandardId);
    uint64_t positionAfterVendorDefinedBody3;
    if (hasBytes3)
    {
        positionAfterVendorDefinedBody3 =
            positionAfterstandardId + (uint64_t)1U;
    }
    else
    {
        positionAfterVendorDefinedBody3 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterstandardId);
    }
    uint64_t positionAftervendorIdLen;
    if (EverParseIsSuccess(positionAfterVendorDefinedBody3))
    {
        positionAftervendorIdLen = positionAfterVendorDefinedBody3;
    }
    else
    {
        Err("_VendorDefinedBody",
            "vendor_id_len",
            EverParseErrorReasonOfResult(positionAfterVendorDefinedBody3),
            Ctxt,
            Input,
            positionAfterstandardId);
        positionAftervendorIdLen = positionAfterVendorDefinedBody3;
    }
    if (EverParseIsError(positionAftervendorIdLen))
    {
        return positionAftervendorIdLen;
    }
    uint8_t vendorIdLen = Input[(uint32_t)positionAfterstandardId];
    /* Validating field vendor_id */
    BOOLEAN
    hasEnoughBytes0 = (uint64_t)(uint32_t)vendorIdLen <=
                      (InputLength - positionAftervendorIdLen);
    uint64_t positionAfterVendorDefinedBody4;
    if (!hasEnoughBytes0)
    {
        positionAfterVendorDefinedBody4 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAftervendorIdLen);
    }
    else
    {
        uint8_t *truncatedInput = Input;
        uint64_t truncatedInputLength =
            positionAftervendorIdLen + (uint64_t)(uint32_t)vendorIdLen;
        uint64_t result = positionAftervendorIdLen;
        while (TRUE)
        {
            uint64_t position = *&result;
            BOOLEAN ite;
            if (!((uint64_t)1U <= (truncatedInputLength - position)))
            {
                ite = TRUE;
            }
            else
            {
                /* Checking that we have enough space for a UINT8, i.e., 1 byte
                 */
                BOOLEAN hasBytes =
                    (uint64_t)1U <= (truncatedInputLength - position);
                uint64_t positionAfterVendorDefinedBody;
                if (hasBytes)
                {
                    positionAfterVendorDefinedBody = position + (uint64_t)1U;
                }
                else
                {
                    positionAfterVendorDefinedBody =
                        EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            position);
                }
                uint64_t res;
                if (EverParseIsSuccess(positionAfterVendorDefinedBody))
                {
                    res = positionAfterVendorDefinedBody;
                }
                else
                {
                    Err("_VendorDefinedBody",
                        "vendor_id.base.element",
                        EverParseErrorReasonOfResult(
                            positionAfterVendorDefinedBody),
                        Ctxt,
                        truncatedInput,
                        position);
                    res = positionAfterVendorDefinedBody;
                }
                uint64_t result1 = res;
                result = result1;
                ite = EverParseIsError(result1);
            }
            if (ite)
            {
                break;
            }
        }
        uint64_t res = result;
        positionAfterVendorDefinedBody4 = res;
    }
    uint64_t positionAftervendorId;
    if (EverParseIsSuccess(positionAfterVendorDefinedBody4))
    {
        positionAftervendorId = positionAfterVendorDefinedBody4;
    }
    else
    {
        Err("_VendorDefinedBody",
            "vendor_id.base",
            EverParseErrorReasonOfResult(positionAfterVendorDefinedBody4),
            Ctxt,
            Input,
            positionAftervendorIdLen);
        positionAftervendorId = positionAfterVendorDefinedBody4;
    }
    uint64_t positionAfterVendorDefinedBody5;
    if (EverParseIsSuccess(positionAftervendorId))
    {
        uint8_t *hd = Input + (uint32_t)positionAftervendorIdLen;
        *OutStandardId = standardId;
        *OutVendorId = hd;
        *OutVendorIdLen = (uint32_t)vendorIdLen;
        BOOLEAN actionSuccessVendorId = TRUE;
        if (!actionSuccessVendorId)
        {
            positionAfterVendorDefinedBody5 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED, positionAftervendorId);
        }
        else
        {
            positionAfterVendorDefinedBody5 = positionAftervendorId;
        }
    }
    else
    {
        positionAfterVendorDefinedBody5 = positionAftervendorId;
    }
    uint64_t positionAftervendorId0;
    if (EverParseIsSuccess(positionAfterVendorDefinedBody5))
    {
        positionAftervendorId0 = positionAfterVendorDefinedBody5;
    }
    else
    {
        Err("_VendorDefinedBody",
            "vendor_id",
            EverParseErrorReasonOfResult(positionAfterVendorDefinedBody5),
            Ctxt,
            Input,
            positionAftervendorIdLen);
        positionAftervendorId0 = positionAfterVendorDefinedBody5;
    }
    if (EverParseIsError(positionAftervendorId0))
    {
        return positionAftervendorId0;
    }
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    BOOLEAN hasBytes4 = (uint64_t)2U <= (InputLength - positionAftervendorId0);
    uint64_t positionAfterVendorDefinedBody6;
    if (hasBytes4)
    {
        positionAfterVendorDefinedBody6 = positionAftervendorId0 + (uint64_t)2U;
    }
    else
    {
        positionAfterVendorDefinedBody6 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAftervendorId0);
    }
    uint64_t positionAfterreqLen;
    if (EverParseIsSuccess(positionAfterVendorDefinedBody6))
    {
        positionAfterreqLen = positionAfterVendorDefinedBody6;
    }
    else
    {
        Err("_VendorDefinedBody",
            "req_len",
            EverParseErrorReasonOfResult(positionAfterVendorDefinedBody6),
            Ctxt,
            Input,
            positionAftervendorId0);
        positionAfterreqLen = positionAfterVendorDefinedBody6;
    }
    if (EverParseIsError(positionAfterreqLen))
    {
        return positionAfterreqLen;
    }
    uint16_t r = Load16Le(Input + (uint32_t)positionAftervendorId0);
    uint16_t reqLen = (uint16_t)(uint32_t)r;
    /* Validating field req_payload */
    BOOLEAN hasEnoughBytes =
        (uint64_t)(uint32_t)reqLen <= (InputLength - positionAfterreqLen);
    uint64_t positionAfterVendorDefinedBody7;
    if (!hasEnoughBytes)
    {
        positionAfterVendorDefinedBody7 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterreqLen);
    }
    else
    {
        uint8_t *truncatedInput = Input;
        uint64_t truncatedInputLength =
            positionAfterreqLen + (uint64_t)(uint32_t)reqLen;
        uint64_t result = positionAfterreqLen;
        while (TRUE)
        {
            uint64_t position = *&result;
            BOOLEAN ite;
            if (!((uint64_t)1U <= (truncatedInputLength - position)))
            {
                ite = TRUE;
            }
            else
            {
                /* Checking that we have enough space for a UINT8, i.e., 1 byte
                 */
                BOOLEAN hasBytes =
                    (uint64_t)1U <= (truncatedInputLength - position);
                uint64_t positionAfterVendorDefinedBody;
                if (hasBytes)
                {
                    positionAfterVendorDefinedBody = position + (uint64_t)1U;
                }
                else
                {
                    positionAfterVendorDefinedBody =
                        EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            position);
                }
                uint64_t res;
                if (EverParseIsSuccess(positionAfterVendorDefinedBody))
                {
                    res = positionAfterVendorDefinedBody;
                }
                else
                {
                    Err("_VendorDefinedBody",
                        "req_payload.base.element",
                        EverParseErrorReasonOfResult(
                            positionAfterVendorDefinedBody),
                        Ctxt,
                        truncatedInput,
                        position);
                    res = positionAfterVendorDefinedBody;
                }
                uint64_t result1 = res;
                result = result1;
                ite = EverParseIsError(result1);
            }
            if (ite)
            {
                break;
            }
        }
        uint64_t res = result;
        positionAfterVendorDefinedBody7 = res;
    }
    uint64_t positionAfterreqPayload;
    if (EverParseIsSuccess(positionAfterVendorDefinedBody7))
    {
        positionAfterreqPayload = positionAfterVendorDefinedBody7;
    }
    else
    {
        Err("_VendorDefinedBody",
            "req_payload.base",
            EverParseErrorReasonOfResult(positionAfterVendorDefinedBody7),
            Ctxt,
            Input,
            positionAfterreqLen);
        positionAfterreqPayload = positionAfterVendorDefinedBody7;
    }
    uint64_t positionAfterVendorDefinedBody8;
    if (EverParseIsSuccess(positionAfterreqPayload))
    {
        uint8_t *hd = Input + (uint32_t)positionAfterreqLen;
        *OutPayload = hd;
        *OutPayloadLen = (uint32_t)reqLen;
        BOOLEAN actionSuccessReqPayload = TRUE;
        if (!actionSuccessReqPayload)
        {
            positionAfterVendorDefinedBody8 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                positionAfterreqPayload);
        }
        else
        {
            positionAfterVendorDefinedBody8 = positionAfterreqPayload;
        }
    }
    else
    {
        positionAfterVendorDefinedBody8 = positionAfterreqPayload;
    }
    if (EverParseIsSuccess(positionAfterVendorDefinedBody8))
    {
        return positionAfterVendorDefinedBody8;
    }
    Err("_VendorDefinedBody",
        "req_payload",
        EverParseErrorReasonOfResult(positionAfterVendorDefinedBody8),
        Ctxt,
        Input,
        positionAfterreqLen);
    return positionAfterVendorDefinedBody8;
}

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
    uint64_t StartPosition)
{
    /* Validating field body */
    uint64_t positionAfterVendorDefinedRequest = ValidateVendorDefinedBody(
        SPDM____VENDOR_DEFINED_REQUEST,
        OutStandardId,
        OutVendorId,
        OutVendorIdLen,
        OutPayload,
        OutPayloadLen,
        Ctxt,
        Err,
        Input,
        InputLength,
        StartPosition);
    if (EverParseIsSuccess(positionAfterVendorDefinedRequest))
    {
        return positionAfterVendorDefinedRequest;
    }
    Err("_VendorDefinedRequest",
        "body",
        EverParseErrorReasonOfResult(positionAfterVendorDefinedRequest),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterVendorDefinedRequest;
}

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
    uint64_t StartPosition)
{
    /* Validating field body */
    uint64_t positionAfterVendorDefinedResponse = ValidateVendorDefinedBody(
        SPDM____VENDOR_DEFINED_RESPONSE,
        OutStandardId,
        OutVendorId,
        OutVendorIdLen,
        OutPayload,
        OutPayloadLen,
        Ctxt,
        Err,
        Input,
        InputLength,
        StartPosition);
    if (EverParseIsSuccess(positionAfterVendorDefinedResponse))
    {
        return positionAfterVendorDefinedResponse;
    }
    Err("_VendorDefinedResponse",
        "body",
        EverParseErrorReasonOfResult(positionAfterVendorDefinedResponse),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterVendorDefinedResponse;
}

static inline uint64_t
ValidateResponseNotReadyExtendedError(
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
    uint64_t StartPosition)
{
    /* Validating field rdt_exponent */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - StartPosition);
    uint64_t positionAfterResponseNotReadyExtendedError;
    if (hasBytes0)
    {
        positionAfterResponseNotReadyExtendedError =
            StartPosition + (uint64_t)1U;
    }
    else
    {
        positionAfterResponseNotReadyExtendedError =
            EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
    }
    uint64_t res0;
    if (EverParseIsSuccess(positionAfterResponseNotReadyExtendedError))
    {
        res0 = positionAfterResponseNotReadyExtendedError;
    }
    else
    {
        Err("_ResponseNotReadyExtendedError",
            "rdt_exponent",
            EverParseErrorReasonOfResult(
                positionAfterResponseNotReadyExtendedError),
            Ctxt,
            Input,
            StartPosition);
        res0 = positionAfterResponseNotReadyExtendedError;
    }
    uint64_t positionAfterrdtExponent = res0;
    if (EverParseIsError(positionAfterrdtExponent))
    {
        return positionAfterrdtExponent;
    }
    /* Validating field request_code */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes1 =
        (uint64_t)1U <= (InputLength - positionAfterrdtExponent);
    uint64_t positionAfterResponseNotReadyExtendedError0;
    if (hasBytes1)
    {
        positionAfterResponseNotReadyExtendedError0 =
            positionAfterrdtExponent + (uint64_t)1U;
    }
    else
    {
        positionAfterResponseNotReadyExtendedError0 =
            EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                positionAfterrdtExponent);
    }
    uint64_t res1;
    if (EverParseIsSuccess(positionAfterResponseNotReadyExtendedError0))
    {
        res1 = positionAfterResponseNotReadyExtendedError0;
    }
    else
    {
        Err("_ResponseNotReadyExtendedError",
            "request_code",
            EverParseErrorReasonOfResult(
                positionAfterResponseNotReadyExtendedError0),
            Ctxt,
            Input,
            positionAfterrdtExponent);
        res1 = positionAfterResponseNotReadyExtendedError0;
    }
    uint64_t positionAfterrequestCode = res1;
    if (EverParseIsError(positionAfterrequestCode))
    {
        return positionAfterrequestCode;
    }
    /* Validating field token */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes2 =
        (uint64_t)1U <= (InputLength - positionAfterrequestCode);
    uint64_t positionAfterResponseNotReadyExtendedError1;
    if (hasBytes2)
    {
        positionAfterResponseNotReadyExtendedError1 =
            positionAfterrequestCode + (uint64_t)1U;
    }
    else
    {
        positionAfterResponseNotReadyExtendedError1 =
            EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                positionAfterrequestCode);
    }
    uint64_t res;
    if (EverParseIsSuccess(positionAfterResponseNotReadyExtendedError1))
    {
        res = positionAfterResponseNotReadyExtendedError1;
    }
    else
    {
        Err("_ResponseNotReadyExtendedError",
            "token",
            EverParseErrorReasonOfResult(
                positionAfterResponseNotReadyExtendedError1),
            Ctxt,
            Input,
            positionAfterrequestCode);
        res = positionAfterResponseNotReadyExtendedError1;
    }
    uint64_t positionAftertoken = res;
    if (EverParseIsError(positionAftertoken))
    {
        return positionAftertoken;
    }
    /* Validating field rdtm */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes = (uint64_t)1U <= (InputLength - positionAftertoken);
    uint64_t positionAfterResponseNotReadyExtendedError2;
    if (hasBytes)
    {
        positionAfterResponseNotReadyExtendedError2 =
            positionAftertoken + (uint64_t)1U;
    }
    else
    {
        positionAfterResponseNotReadyExtendedError2 =
            EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAftertoken);
    }
    if (EverParseIsSuccess(positionAfterResponseNotReadyExtendedError2))
    {
        return positionAfterResponseNotReadyExtendedError2;
    }
    Err("_ResponseNotReadyExtendedError",
        "rdtm",
        EverParseErrorReasonOfResult(
            positionAfterResponseNotReadyExtendedError2),
        Ctxt,
        Input,
        positionAftertoken);
    return positionAfterResponseNotReadyExtendedError2;
}

static inline uint64_t
ValidateVendorDefinedExtendedError(
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
    uint64_t StartPosition)
{
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - StartPosition);
    uint64_t positionAfterVendorDefinedExtendedError;
    if (hasBytes0)
    {
        positionAfterVendorDefinedExtendedError = StartPosition + (uint64_t)1U;
    }
    else
    {
        positionAfterVendorDefinedExtendedError = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
    }
    uint64_t positionAfterlen;
    if (EverParseIsSuccess(positionAfterVendorDefinedExtendedError))
    {
        positionAfterlen = positionAfterVendorDefinedExtendedError;
    }
    else
    {
        Err("_VendorDefinedExtendedError",
            "len",
            EverParseErrorReasonOfResult(
                positionAfterVendorDefinedExtendedError),
            Ctxt,
            Input,
            StartPosition);
        positionAfterlen = positionAfterVendorDefinedExtendedError;
    }
    if (EverParseIsError(positionAfterlen))
    {
        return positionAfterlen;
    }
    uint8_t len = Input[(uint32_t)StartPosition];
    /* Validating field vendor_id */
    BOOLEAN hasEnoughBytes =
        (uint64_t)(uint32_t)len <= (InputLength - positionAfterlen);
    uint64_t positionAfterVendorDefinedExtendedError0;
    if (!hasEnoughBytes)
    {
        positionAfterVendorDefinedExtendedError0 =
            EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterlen);
    }
    else
    {
        uint8_t *truncatedInput = Input;
        uint64_t truncatedInputLength =
            positionAfterlen + (uint64_t)(uint32_t)len;
        uint64_t result = positionAfterlen;
        while (TRUE)
        {
            uint64_t position = *&result;
            BOOLEAN ite;
            if (!((uint64_t)1U <= (truncatedInputLength - position)))
            {
                ite = TRUE;
            }
            else
            {
                /* Checking that we have enough space for a UINT8, i.e., 1 byte
                 */
                BOOLEAN hasBytes =
                    (uint64_t)1U <= (truncatedInputLength - position);
                uint64_t positionAfterVendorDefinedExtendedError;
                if (hasBytes)
                {
                    positionAfterVendorDefinedExtendedError =
                        position + (uint64_t)1U;
                }
                else
                {
                    positionAfterVendorDefinedExtendedError =
                        EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            position);
                }
                uint64_t res;
                if (EverParseIsSuccess(positionAfterVendorDefinedExtendedError))
                {
                    res = positionAfterVendorDefinedExtendedError;
                }
                else
                {
                    Err("_VendorDefinedExtendedError",
                        "vendor_id.element",
                        EverParseErrorReasonOfResult(
                            positionAfterVendorDefinedExtendedError),
                        Ctxt,
                        truncatedInput,
                        position);
                    res = positionAfterVendorDefinedExtendedError;
                }
                uint64_t result1 = res;
                result = result1;
                ite = EverParseIsError(result1);
            }
            if (ite)
            {
                break;
            }
        }
        uint64_t res = result;
        positionAfterVendorDefinedExtendedError0 = res;
    }
    if (EverParseIsSuccess(positionAfterVendorDefinedExtendedError0))
    {
        return positionAfterVendorDefinedExtendedError0;
    }
    Err("_VendorDefinedExtendedError",
        "vendor_id",
        EverParseErrorReasonOfResult(positionAfterVendorDefinedExtendedError0),
        Ctxt,
        Input,
        positionAfterlen);
    return positionAfterVendorDefinedExtendedError0;
}

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
    uint64_t StartPosition)
{
    if (Code == (uint8_t)13U)
    {
        /* Validating field error_response_too_large */
        /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
        BOOLEAN hasBytes = (uint64_t)4U <= (InputLen - StartPosition);
        uint64_t positionAfterExtendedError;
        if (hasBytes)
        {
            positionAfterExtendedError = StartPosition + (uint64_t)4U;
        }
        else
        {
            positionAfterExtendedError = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
        }
        if (EverParseIsSuccess(positionAfterExtendedError))
        {
            return positionAfterExtendedError;
        }
        Err("_ExtendedError",
            "missing",
            EverParseErrorReasonOfResult(positionAfterExtendedError),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterExtendedError;
    }
    if (Code == (uint8_t)15U)
    {
        /* Validating field error_large_response */
        /* Checking that we have enough space for a UINT8, i.e., 1 byte */
        BOOLEAN hasBytes = (uint64_t)1U <= (InputLen - StartPosition);
        uint64_t positionAfterExtendedError;
        if (hasBytes)
        {
            positionAfterExtendedError = StartPosition + (uint64_t)1U;
        }
        else
        {
            positionAfterExtendedError = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
        }
        if (EverParseIsSuccess(positionAfterExtendedError))
        {
            return positionAfterExtendedError;
        }
        Err("_ExtendedError",
            "missing",
            EverParseErrorReasonOfResult(positionAfterExtendedError),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterExtendedError;
    }
    if (Code == (uint8_t)66U)
    {
        /* Validating field error_response_not_ready */
        uint64_t positionAfterExtendedError =
            ValidateResponseNotReadyExtendedError(
                Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterExtendedError))
        {
            return positionAfterExtendedError;
        }
        Err("_ExtendedError",
            "missing",
            EverParseErrorReasonOfResult(positionAfterExtendedError),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterExtendedError;
    }
    if (Code == (uint8_t)255U)
    {
        /* Validating field error_vendor_defined */
        uint64_t positionAfterExtendedError =
            ValidateVendorDefinedExtendedError(
                Ctxt, Err, Input, InputLen, StartPosition);
        if (EverParseIsSuccess(positionAfterExtendedError))
        {
            return positionAfterExtendedError;
        }
        Err("_ExtendedError",
            "missing",
            EverParseErrorReasonOfResult(positionAfterExtendedError),
            Ctxt,
            Input,
            StartPosition);
        return positionAfterExtendedError;
    }
    /* Validating field noop */
    uint64_t positionAfterExtendedError = StartPosition;
    if (EverParseIsSuccess(positionAfterExtendedError))
    {
        return positionAfterExtendedError;
    }
    Err("_ExtendedError",
        "missing",
        EverParseErrorReasonOfResult(positionAfterExtendedError),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterExtendedError;
}

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
    uint64_t StartPosition)
{
    /* Validating field preamble */
    uint64_t positionAfterError = ValidatePreamble(
        SPDM____ERROR, Ctxt, Err, Input, InputLength, StartPosition);
    uint64_t positionAfterpreamble;
    if (EverParseIsSuccess(positionAfterError))
    {
        positionAfterpreamble = positionAfterError;
    }
    else
    {
        Err("_Error",
            "preamble",
            EverParseErrorReasonOfResult(positionAfterError),
            Ctxt,
            Input,
            StartPosition);
        positionAfterpreamble = positionAfterError;
    }
    if (EverParseIsError(positionAfterpreamble))
    {
        return positionAfterpreamble;
    }
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - positionAfterpreamble);
    uint64_t positionAfterError0;
    if (hasBytes0)
    {
        positionAfterError0 = positionAfterpreamble + (uint64_t)1U;
    }
    else
    {
        positionAfterError0 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterpreamble);
    }
    uint64_t positionAfterparam1ErrorCode;
    if (EverParseIsSuccess(positionAfterError0))
    {
        positionAfterparam1ErrorCode = positionAfterError0;
    }
    else
    {
        Err("_Error",
            "param_1_error_code",
            EverParseErrorReasonOfResult(positionAfterError0),
            Ctxt,
            Input,
            positionAfterpreamble);
        positionAfterparam1ErrorCode = positionAfterError0;
    }
    if (EverParseIsError(positionAfterparam1ErrorCode))
    {
        return positionAfterparam1ErrorCode;
    }
    uint8_t param1ErrorCode = Input[(uint32_t)positionAfterpreamble];
    /* Validating field param_2_error_data */
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes =
        (uint64_t)1U <= (InputLength - positionAfterparam1ErrorCode);
    uint64_t positionAfterparam2ErrorData;
    if (hasBytes)
    {
        positionAfterparam2ErrorData =
            positionAfterparam1ErrorCode + (uint64_t)1U;
    }
    else
    {
        positionAfterparam2ErrorData = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfterparam1ErrorCode);
    }
    uint64_t positionAfterError1;
    if (EverParseIsError(positionAfterparam2ErrorData))
    {
        positionAfterError1 = positionAfterparam2ErrorData;
    }
    else
    {
        uint8_t param2ErrorData = Input[(uint32_t)positionAfterparam1ErrorCode];
        *OutErrorCode = param1ErrorCode;
        *OutErrorData = param2ErrorData;
        if (TRUE)
        {
            positionAfterError1 = positionAfterparam2ErrorData;
        }
        else
        {
            positionAfterError1 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                positionAfterparam2ErrorData);
        }
    }
    if (EverParseIsSuccess(positionAfterError1))
    {
        return positionAfterError1;
    }
    Err("_Error",
        "param_2_error_data",
        EverParseErrorReasonOfResult(positionAfterError1),
        Ctxt,
        Input,
        positionAfterparam1ErrorCode);
    return positionAfterError1;
}

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
    uint64_t StartPosition)
{
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes0 = (uint64_t)1U <= (InputLength - StartPosition);
    uint64_t positionAfterOpaqueElement;
    if (hasBytes0)
    {
        positionAfterOpaqueElement = StartPosition + (uint64_t)1U;
    }
    else
    {
        positionAfterOpaqueElement = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
    }
    uint64_t positionAfterid;
    if (EverParseIsSuccess(positionAfterOpaqueElement))
    {
        positionAfterid = positionAfterOpaqueElement;
    }
    else
    {
        Err("_OpaqueElement",
            "id",
            EverParseErrorReasonOfResult(positionAfterOpaqueElement),
            Ctxt,
            Input,
            StartPosition);
        positionAfterid = positionAfterOpaqueElement;
    }
    if (EverParseIsError(positionAfterid))
    {
        return positionAfterid;
    }
    uint8_t id = Input[(uint32_t)StartPosition];
    /* Checking that we have enough space for a UINT8, i.e., 1 byte */
    BOOLEAN hasBytes1 = (uint64_t)1U <= (InputLength - positionAfterid);
    uint64_t positionAfterOpaqueElement0;
    if (hasBytes1)
    {
        positionAfterOpaqueElement0 = positionAfterid + (uint64_t)1U;
    }
    else
    {
        positionAfterOpaqueElement0 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAfterid);
    }
    uint64_t positionAftervendorLen;
    if (EverParseIsSuccess(positionAfterOpaqueElement0))
    {
        positionAftervendorLen = positionAfterOpaqueElement0;
    }
    else
    {
        Err("_OpaqueElement",
            "vendor_len",
            EverParseErrorReasonOfResult(positionAfterOpaqueElement0),
            Ctxt,
            Input,
            positionAfterid);
        positionAftervendorLen = positionAfterOpaqueElement0;
    }
    if (EverParseIsError(positionAftervendorLen))
    {
        return positionAftervendorLen;
    }
    uint8_t vendorLen = Input[(uint32_t)positionAfterid];
    /* Validating field vendor_id */
    BOOLEAN
    hasEnoughBytes0 =
        (uint64_t)(uint32_t)vendorLen <= (InputLength - positionAftervendorLen);
    uint64_t positionAfterOpaqueElement1;
    if (!hasEnoughBytes0)
    {
        positionAfterOpaqueElement1 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAftervendorLen);
    }
    else
    {
        uint8_t *truncatedInput = Input;
        uint64_t truncatedInputLength =
            positionAftervendorLen + (uint64_t)(uint32_t)vendorLen;
        uint64_t result = positionAftervendorLen;
        while (TRUE)
        {
            uint64_t position = *&result;
            BOOLEAN ite;
            if (!((uint64_t)1U <= (truncatedInputLength - position)))
            {
                ite = TRUE;
            }
            else
            {
                /* Checking that we have enough space for a UINT8, i.e., 1 byte
                 */
                BOOLEAN hasBytes =
                    (uint64_t)1U <= (truncatedInputLength - position);
                uint64_t positionAfterOpaqueElement;
                if (hasBytes)
                {
                    positionAfterOpaqueElement = position + (uint64_t)1U;
                }
                else
                {
                    positionAfterOpaqueElement = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, position);
                }
                uint64_t res;
                if (EverParseIsSuccess(positionAfterOpaqueElement))
                {
                    res = positionAfterOpaqueElement;
                }
                else
                {
                    Err("_OpaqueElement",
                        "vendor_id.base.element",
                        EverParseErrorReasonOfResult(
                            positionAfterOpaqueElement),
                        Ctxt,
                        truncatedInput,
                        position);
                    res = positionAfterOpaqueElement;
                }
                uint64_t result1 = res;
                result = result1;
                ite = EverParseIsError(result1);
            }
            if (ite)
            {
                break;
            }
        }
        uint64_t res = result;
        positionAfterOpaqueElement1 = res;
    }
    uint64_t positionAftervendorId;
    if (EverParseIsSuccess(positionAfterOpaqueElement1))
    {
        positionAftervendorId = positionAfterOpaqueElement1;
    }
    else
    {
        Err("_OpaqueElement",
            "vendor_id.base",
            EverParseErrorReasonOfResult(positionAfterOpaqueElement1),
            Ctxt,
            Input,
            positionAftervendorLen);
        positionAftervendorId = positionAfterOpaqueElement1;
    }
    uint64_t positionAfterOpaqueElement2;
    if (EverParseIsSuccess(positionAftervendorId))
    {
        uint8_t *hd = Input + (uint32_t)positionAftervendorLen;
        *OutId = id;
        *OutVendorId = hd;
        *OutVendorLen = (uint32_t)vendorLen;
        BOOLEAN actionSuccessVendorId = TRUE;
        if (!actionSuccessVendorId)
        {
            positionAfterOpaqueElement2 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED, positionAftervendorId);
        }
        else
        {
            positionAfterOpaqueElement2 = positionAftervendorId;
        }
    }
    else
    {
        positionAfterOpaqueElement2 = positionAftervendorId;
    }
    uint64_t positionAftervendorId0;
    if (EverParseIsSuccess(positionAfterOpaqueElement2))
    {
        positionAftervendorId0 = positionAfterOpaqueElement2;
    }
    else
    {
        Err("_OpaqueElement",
            "vendor_id",
            EverParseErrorReasonOfResult(positionAfterOpaqueElement2),
            Ctxt,
            Input,
            positionAftervendorLen);
        positionAftervendorId0 = positionAfterOpaqueElement2;
    }
    if (EverParseIsError(positionAftervendorId0))
    {
        return positionAftervendorId0;
    }
    /* Checking that we have enough space for a UINT16, i.e., 2 bytes */
    BOOLEAN hasBytes2 = (uint64_t)2U <= (InputLength - positionAftervendorId0);
    uint64_t positionAfterOpaqueElement3;
    if (hasBytes2)
    {
        positionAfterOpaqueElement3 = positionAftervendorId0 + (uint64_t)2U;
    }
    else
    {
        positionAfterOpaqueElement3 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, positionAftervendorId0);
    }
    uint64_t positionAfteropaqueElementDataLen;
    if (EverParseIsSuccess(positionAfterOpaqueElement3))
    {
        positionAfteropaqueElementDataLen = positionAfterOpaqueElement3;
    }
    else
    {
        Err("_OpaqueElement",
            "opaque_element_data_len",
            EverParseErrorReasonOfResult(positionAfterOpaqueElement3),
            Ctxt,
            Input,
            positionAftervendorId0);
        positionAfteropaqueElementDataLen = positionAfterOpaqueElement3;
    }
    if (EverParseIsError(positionAfteropaqueElementDataLen))
    {
        return positionAfteropaqueElementDataLen;
    }
    uint16_t r = Load16Le(Input + (uint32_t)positionAftervendorId0);
    uint16_t opaqueElementDataLen = (uint16_t)(uint32_t)r;
    /* Validating field opaque_element_data */
    BOOLEAN
    hasEnoughBytes1 = (uint64_t)(uint32_t)opaqueElementDataLen <=
                      (InputLength - positionAfteropaqueElementDataLen);
    uint64_t positionAfterOpaqueElement4;
    if (!hasEnoughBytes1)
    {
        positionAfterOpaqueElement4 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfteropaqueElementDataLen);
    }
    else
    {
        uint8_t *truncatedInput = Input;
        uint64_t truncatedInputLength =
            positionAfteropaqueElementDataLen +
            (uint64_t)(uint32_t)opaqueElementDataLen;
        uint64_t result = positionAfteropaqueElementDataLen;
        while (TRUE)
        {
            uint64_t position = *&result;
            BOOLEAN ite;
            if (!((uint64_t)1U <= (truncatedInputLength - position)))
            {
                ite = TRUE;
            }
            else
            {
                /* Checking that we have enough space for a UINT8, i.e., 1 byte
                 */
                BOOLEAN hasBytes =
                    (uint64_t)1U <= (truncatedInputLength - position);
                uint64_t positionAfterOpaqueElement;
                if (hasBytes)
                {
                    positionAfterOpaqueElement = position + (uint64_t)1U;
                }
                else
                {
                    positionAfterOpaqueElement = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, position);
                }
                uint64_t res;
                if (EverParseIsSuccess(positionAfterOpaqueElement))
                {
                    res = positionAfterOpaqueElement;
                }
                else
                {
                    Err("_OpaqueElement",
                        "opaque_element_data.base.element",
                        EverParseErrorReasonOfResult(
                            positionAfterOpaqueElement),
                        Ctxt,
                        truncatedInput,
                        position);
                    res = positionAfterOpaqueElement;
                }
                uint64_t result1 = res;
                result = result1;
                ite = EverParseIsError(result1);
            }
            if (ite)
            {
                break;
            }
        }
        uint64_t res = result;
        positionAfterOpaqueElement4 = res;
    }
    uint64_t positionAfteropaqueElementData;
    if (EverParseIsSuccess(positionAfterOpaqueElement4))
    {
        positionAfteropaqueElementData = positionAfterOpaqueElement4;
    }
    else
    {
        Err("_OpaqueElement",
            "opaque_element_data.base",
            EverParseErrorReasonOfResult(positionAfterOpaqueElement4),
            Ctxt,
            Input,
            positionAfteropaqueElementDataLen);
        positionAfteropaqueElementData = positionAfterOpaqueElement4;
    }
    uint64_t positionAfterOpaqueElement5;
    if (EverParseIsSuccess(positionAfteropaqueElementData))
    {
        uint8_t *hd = Input + (uint32_t)positionAfteropaqueElementDataLen;
        *OutOpaqueElementData = hd;
        *OutOpaqueElementDataLen = (uint32_t)opaqueElementDataLen;
        BOOLEAN actionSuccessOpaqueElementData = TRUE;
        if (!actionSuccessOpaqueElementData)
        {
            positionAfterOpaqueElement5 = EverParseSetValidatorErrorPos(
                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                positionAfteropaqueElementData);
        }
        else
        {
            positionAfterOpaqueElement5 = positionAfteropaqueElementData;
        }
    }
    else
    {
        positionAfterOpaqueElement5 = positionAfteropaqueElementData;
    }
    uint64_t positionAfteropaqueElementData0;
    if (EverParseIsSuccess(positionAfterOpaqueElement5))
    {
        positionAfteropaqueElementData0 = positionAfterOpaqueElement5;
    }
    else
    {
        Err("_OpaqueElement",
            "opaque_element_data",
            EverParseErrorReasonOfResult(positionAfterOpaqueElement5),
            Ctxt,
            Input,
            positionAfteropaqueElementDataLen);
        positionAfteropaqueElementData0 = positionAfterOpaqueElement5;
    }
    if (EverParseIsError(positionAfteropaqueElementData0))
    {
        return positionAfteropaqueElementData0;
    }
    /* Validating field padding */
    BOOLEAN
    hasEnoughBytes =
        (uint64_t)(uint32_t)(((uint16_t)(uint8_t)4U - ((uint16_t)(vendorLen % (uint8_t)4U) + opaqueElementDataLen % (uint16_t)(uint8_t)4U) % (uint16_t)(uint8_t)4U) % (uint16_t)(uint8_t)4U) <=
        (InputLength - positionAfteropaqueElementData0);
    uint64_t positionAfterOpaqueElement6;
    if (!hasEnoughBytes)
    {
        positionAfterOpaqueElement6 = EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
            positionAfteropaqueElementData0);
    }
    else
    {
        uint8_t *truncatedInput = Input;
        uint64_t truncatedInputLength =
            positionAfteropaqueElementData0 +
            (uint64_t)(uint32_t)(((uint16_t)(uint8_t)4U - ((uint16_t)(vendorLen % (uint8_t)4U) + opaqueElementDataLen % (uint16_t)(uint8_t)4U) % (uint16_t)(uint8_t)4U) % (uint16_t)(uint8_t)4U);
        uint64_t result = positionAfteropaqueElementData0;
        while (TRUE)
        {
            uint64_t position = *&result;
            BOOLEAN ite;
            if (!((uint64_t)1U <= (truncatedInputLength - position)))
            {
                ite = TRUE;
            }
            else
            {
                /* Checking that we have enough space for a UINT8, i.e., 1 byte
                 */
                BOOLEAN hasBytes =
                    (uint64_t)1U <= (truncatedInputLength - position);
                uint64_t positionAfterOpaqueElement;
                if (hasBytes)
                {
                    positionAfterOpaqueElement = position + (uint64_t)1U;
                }
                else
                {
                    positionAfterOpaqueElement = EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, position);
                }
                uint64_t res;
                if (EverParseIsSuccess(positionAfterOpaqueElement))
                {
                    res = positionAfterOpaqueElement;
                }
                else
                {
                    Err("_OpaqueElement",
                        "padding.element",
                        EverParseErrorReasonOfResult(
                            positionAfterOpaqueElement),
                        Ctxt,
                        truncatedInput,
                        position);
                    res = positionAfterOpaqueElement;
                }
                uint64_t result1 = res;
                result = result1;
                ite = EverParseIsError(result1);
            }
            if (ite)
            {
                break;
            }
        }
        uint64_t res = result;
        positionAfterOpaqueElement6 = res;
    }
    if (EverParseIsSuccess(positionAfterOpaqueElement6))
    {
        return positionAfterOpaqueElement6;
    }
    Err("_OpaqueElement",
        "padding",
        EverParseErrorReasonOfResult(positionAfterOpaqueElement6),
        Ctxt,
        Input,
        positionAfteropaqueElementData0);
    return positionAfterOpaqueElement6;
}

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
    uint64_t StartPosition)
{
    uint64_t positionAfternone = StartPosition;
    uint64_t positionAfterSecuredMessageRecord;
    if (EverParseIsError(positionAfternone))
    {
        positionAfterSecuredMessageRecord = positionAfternone;
    }
    else
    {
        BOOLEAN noneConstraintIsOk = MacLen <= (uint32_t)(uint16_t)512U;
        uint64_t positionAfternone1 =
            EverParseCheckConstraintOk(noneConstraintIsOk, positionAfternone);
        if (EverParseIsError(positionAfternone1))
        {
            positionAfterSecuredMessageRecord = positionAfternone1;
        }
        else
        {
            /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
            BOOLEAN hasBytes0 =
                (uint64_t)4U <= (InputLength - positionAfternone1);
            uint64_t positionAfterSecuredMessageRecord0;
            if (hasBytes0)
            {
                positionAfterSecuredMessageRecord0 =
                    positionAfternone1 + (uint64_t)4U;
            }
            else
            {
                positionAfterSecuredMessageRecord0 =
                    EverParseSetValidatorErrorPos(
                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                        positionAfternone1);
            }
            uint64_t positionAftersessionId;
            if (EverParseIsSuccess(positionAfterSecuredMessageRecord0))
            {
                positionAftersessionId = positionAfterSecuredMessageRecord0;
            }
            else
            {
                Err("_SecuredMessageRecord",
                    "session_id",
                    EverParseErrorReasonOfResult(
                        positionAfterSecuredMessageRecord0),
                    Ctxt,
                    Input,
                    positionAfternone1);
                positionAftersessionId = positionAfterSecuredMessageRecord0;
            }
            if (EverParseIsError(positionAftersessionId))
            {
                positionAfterSecuredMessageRecord = positionAftersessionId;
            }
            else
            {
                uint32_t sessionId =
                    Load32Le(Input + (uint32_t)positionAfternone1);
                /* Validating field sequence_number */
                BOOLEAN hasEnoughBytes0 =
                    (uint64_t)SeqNumLen <=
                    (InputLength - positionAftersessionId);
                uint64_t positionAfterSecuredMessageRecord0;
                if (!hasEnoughBytes0)
                {
                    positionAfterSecuredMessageRecord0 =
                        EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAftersessionId);
                }
                else
                {
                    uint8_t *truncatedInput = Input;
                    uint64_t truncatedInputLength =
                        positionAftersessionId + (uint64_t)SeqNumLen;
                    uint64_t result = positionAftersessionId;
                    while (TRUE)
                    {
                        uint64_t position = *&result;
                        BOOLEAN ite;
                        if (!((uint64_t)1U <=
                              (truncatedInputLength - position)))
                        {
                            ite = TRUE;
                        }
                        else
                        {
                            /* Checking that we have enough space for a UINT8,
                             * i.e., 1 byte */
                            BOOLEAN hasBytes =
                                (uint64_t)1U <=
                                (truncatedInputLength - position);
                            uint64_t positionAfterSecuredMessageRecord;
                            if (hasBytes)
                            {
                                positionAfterSecuredMessageRecord =
                                    position + (uint64_t)1U;
                            }
                            else
                            {
                                positionAfterSecuredMessageRecord =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        position);
                            }
                            uint64_t res;
                            if (EverParseIsSuccess(
                                    positionAfterSecuredMessageRecord))
                            {
                                res = positionAfterSecuredMessageRecord;
                            }
                            else
                            {
                                Err("_SecuredMessageRecord",
                                    "sequence_number.base.element",
                                    EverParseErrorReasonOfResult(
                                        positionAfterSecuredMessageRecord),
                                    Ctxt,
                                    truncatedInput,
                                    position);
                                res = positionAfterSecuredMessageRecord;
                            }
                            uint64_t result1 = res;
                            result = result1;
                            ite = EverParseIsError(result1);
                        }
                        if (ite)
                        {
                            break;
                        }
                    }
                    uint64_t res = result;
                    positionAfterSecuredMessageRecord0 = res;
                }
                uint64_t positionAftersequenceNumber;
                if (EverParseIsSuccess(positionAfterSecuredMessageRecord0))
                {
                    positionAftersequenceNumber =
                        positionAfterSecuredMessageRecord0;
                }
                else
                {
                    Err("_SecuredMessageRecord",
                        "sequence_number.base",
                        EverParseErrorReasonOfResult(
                            positionAfterSecuredMessageRecord0),
                        Ctxt,
                        Input,
                        positionAftersessionId);
                    positionAftersequenceNumber =
                        positionAfterSecuredMessageRecord0;
                }
                uint64_t positionAfterSecuredMessageRecord1;
                if (EverParseIsSuccess(positionAftersequenceNumber))
                {
                    uint8_t *hd = Input + (uint32_t)positionAftersessionId;
                    *OutSessionId = sessionId;
                    *OutSeqNum = hd;
                    BOOLEAN actionSuccessSequenceNumber = TRUE;
                    if (!actionSuccessSequenceNumber)
                    {
                        positionAfterSecuredMessageRecord1 =
                            EverParseSetValidatorErrorPos(
                                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                                positionAftersequenceNumber);
                    }
                    else
                    {
                        positionAfterSecuredMessageRecord1 =
                            positionAftersequenceNumber;
                    }
                }
                else
                {
                    positionAfterSecuredMessageRecord1 =
                        positionAftersequenceNumber;
                }
                uint64_t positionAftersequenceNumber0;
                if (EverParseIsSuccess(positionAfterSecuredMessageRecord1))
                {
                    positionAftersequenceNumber0 =
                        positionAfterSecuredMessageRecord1;
                }
                else
                {
                    Err("_SecuredMessageRecord",
                        "sequence_number",
                        EverParseErrorReasonOfResult(
                            positionAfterSecuredMessageRecord1),
                        Ctxt,
                        Input,
                        positionAftersessionId);
                    positionAftersequenceNumber0 =
                        positionAfterSecuredMessageRecord1;
                }
                if (EverParseIsError(positionAftersequenceNumber0))
                {
                    positionAfterSecuredMessageRecord =
                        positionAftersequenceNumber0;
                }
                else
                {
                    /* Checking that we have enough space for a UINT16, i.e., 2
                     * bytes */
                    BOOLEAN hasBytes0 =
                        (uint64_t)2U <=
                        (InputLength - positionAftersequenceNumber0);
                    uint64_t positionAfternone2;
                    if (hasBytes0)
                    {
                        positionAfternone2 =
                            positionAftersequenceNumber0 + (uint64_t)2U;
                    }
                    else
                    {
                        positionAfternone2 = EverParseSetValidatorErrorPos(
                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                            positionAftersequenceNumber0);
                    }
                    uint64_t positionAfterSecuredMessageRecord0;
                    if (EverParseIsError(positionAfternone2))
                    {
                        positionAfterSecuredMessageRecord0 = positionAfternone2;
                    }
                    else
                    {
                        uint16_t r = Load16Le(
                            Input + (uint32_t)positionAftersequenceNumber0);
                        uint16_t none1 = (uint16_t)(uint32_t)r;
                        BOOLEAN noneConstraintIsOk1 =
                            (uint32_t)none1 >= ((uint32_t)(uint8_t)2U + MacLen);
                        uint64_t positionAfternone3 =
                            EverParseCheckConstraintOk(
                                noneConstraintIsOk1, positionAfternone2);
                        if (EverParseIsError(positionAfternone3))
                        {
                            positionAfterSecuredMessageRecord0 =
                                positionAfternone3;
                        }
                        else
                        {
                            /* Validating field ciphertext */
                            BOOLEAN
                            hasEnoughBytes0 =
                                (uint64_t)((uint32_t)none1 - MacLen) <=
                                (InputLength - positionAfternone3);
                            uint64_t positionAfterSecuredMessageRecord;
                            if (!hasEnoughBytes0)
                            {
                                positionAfterSecuredMessageRecord =
                                    EverParseSetValidatorErrorPos(
                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                        positionAfternone3);
                            }
                            else
                            {
                                uint8_t *truncatedInput = Input;
                                uint64_t truncatedInputLength =
                                    positionAfternone3 +
                                    (uint64_t)((uint32_t)none1 - MacLen);
                                uint64_t result = positionAfternone3;
                                while (TRUE)
                                {
                                    uint64_t position = *&result;
                                    BOOLEAN ite;
                                    if (!((uint64_t)1U <=
                                          (truncatedInputLength - position)))
                                    {
                                        ite = TRUE;
                                    }
                                    else
                                    {
                                        /* Checking that we have enough space
                                         * for a UINT8, i.e., 1 byte */
                                        BOOLEAN hasBytes =
                                            (uint64_t)1U <=
                                            (truncatedInputLength - position);
                                        uint64_t
                                            positionAfterSecuredMessageRecord;
                                        if (hasBytes)
                                        {
                                            positionAfterSecuredMessageRecord =
                                                position + (uint64_t)1U;
                                        }
                                        else
                                        {
                                            positionAfterSecuredMessageRecord =
                                                EverParseSetValidatorErrorPos(
                                                    EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                    position);
                                        }
                                        uint64_t res;
                                        if (EverParseIsSuccess(
                                                positionAfterSecuredMessageRecord))
                                        {
                                            res =
                                                positionAfterSecuredMessageRecord;
                                        }
                                        else
                                        {
                                            Err("_SecuredMessageRecord",
                                                "ciphertext.base.element",
                                                EverParseErrorReasonOfResult(
                                                    positionAfterSecuredMessageRecord),
                                                Ctxt,
                                                truncatedInput,
                                                position);
                                            res =
                                                positionAfterSecuredMessageRecord;
                                        }
                                        uint64_t result1 = res;
                                        result = result1;
                                        ite = EverParseIsError(result1);
                                    }
                                    if (ite)
                                    {
                                        break;
                                    }
                                }
                                uint64_t res = result;
                                positionAfterSecuredMessageRecord = res;
                            }
                            uint64_t positionAfterciphertext0;
                            if (EverParseIsSuccess(
                                    positionAfterSecuredMessageRecord))
                            {
                                positionAfterciphertext0 =
                                    positionAfterSecuredMessageRecord;
                            }
                            else
                            {
                                Err("_SecuredMessageRecord",
                                    "ciphertext.base",
                                    EverParseErrorReasonOfResult(
                                        positionAfterSecuredMessageRecord),
                                    Ctxt,
                                    Input,
                                    positionAfternone3);
                                positionAfterciphertext0 =
                                    positionAfterSecuredMessageRecord;
                            }
                            uint64_t positionAfterSecuredMessageRecord1;
                            if (EverParseIsSuccess(positionAfterciphertext0))
                            {
                                uint8_t *hd =
                                    Input + (uint32_t)positionAfternone3;
                                *OutCiphertext = hd;
                                *OutCiphertextLen = (uint32_t)none1 - MacLen;
                                BOOLEAN actionSuccessCiphertext = TRUE;
                                if (!actionSuccessCiphertext)
                                {
                                    positionAfterSecuredMessageRecord1 =
                                        EverParseSetValidatorErrorPos(
                                            EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                                            positionAfterciphertext0);
                                }
                                else
                                {
                                    positionAfterSecuredMessageRecord1 =
                                        positionAfterciphertext0;
                                }
                            }
                            else
                            {
                                positionAfterSecuredMessageRecord1 =
                                    positionAfterciphertext0;
                            }
                            uint64_t positionAfterciphertext;
                            if (EverParseIsSuccess(
                                    positionAfterSecuredMessageRecord1))
                            {
                                positionAfterciphertext =
                                    positionAfterSecuredMessageRecord1;
                            }
                            else
                            {
                                Err("_SecuredMessageRecord",
                                    "ciphertext",
                                    EverParseErrorReasonOfResult(
                                        positionAfterSecuredMessageRecord1),
                                    Ctxt,
                                    Input,
                                    positionAfternone3);
                                positionAfterciphertext =
                                    positionAfterSecuredMessageRecord1;
                            }
                            if (EverParseIsError(positionAfterciphertext))
                            {
                                positionAfterSecuredMessageRecord0 =
                                    positionAfterciphertext;
                            }
                            else
                            {
                                /* Validating field mac */
                                BOOLEAN
                                hasEnoughBytes =
                                    (uint64_t)MacLen <=
                                    (InputLength - positionAfterciphertext);
                                uint64_t positionAfterSecuredMessageRecord;
                                if (!hasEnoughBytes)
                                {
                                    positionAfterSecuredMessageRecord =
                                        EverParseSetValidatorErrorPos(
                                            EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                            positionAfterciphertext);
                                }
                                else
                                {
                                    uint8_t *truncatedInput = Input;
                                    uint64_t truncatedInputLength =
                                        positionAfterciphertext +
                                        (uint64_t)MacLen;
                                    uint64_t result = positionAfterciphertext;
                                    while (TRUE)
                                    {
                                        uint64_t position = *&result;
                                        BOOLEAN ite;
                                        if (!((uint64_t)1U <=
                                              (truncatedInputLength -
                                               position)))
                                        {
                                            ite = TRUE;
                                        }
                                        else
                                        {
                                            /* Checking that we have enough
                                             * space for a UINT8, i.e., 1 byte
                                             */
                                            BOOLEAN hasBytes =
                                                (uint64_t)1U <=
                                                (truncatedInputLength -
                                                 position);
                                            uint64_t
                                                positionAfterSecuredMessageRecord;
                                            if (hasBytes)
                                            {
                                                positionAfterSecuredMessageRecord =
                                                    position + (uint64_t)1U;
                                            }
                                            else
                                            {
                                                positionAfterSecuredMessageRecord =
                                                    EverParseSetValidatorErrorPos(
                                                        EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
                                                        position);
                                            }
                                            uint64_t res;
                                            if (EverParseIsSuccess(
                                                    positionAfterSecuredMessageRecord))
                                            {
                                                res =
                                                    positionAfterSecuredMessageRecord;
                                            }
                                            else
                                            {
                                                Err("_SecuredMessageRecord",
                                                    "mac.base.element",
                                                    EverParseErrorReasonOfResult(
                                                        positionAfterSecuredMessageRecord),
                                                    Ctxt,
                                                    truncatedInput,
                                                    position);
                                                res =
                                                    positionAfterSecuredMessageRecord;
                                            }
                                            uint64_t result1 = res;
                                            result = result1;
                                            ite = EverParseIsError(result1);
                                        }
                                        if (ite)
                                        {
                                            break;
                                        }
                                    }
                                    uint64_t res = result;
                                    positionAfterSecuredMessageRecord = res;
                                }
                                uint64_t positionAftermac;
                                if (EverParseIsSuccess(
                                        positionAfterSecuredMessageRecord))
                                {
                                    positionAftermac =
                                        positionAfterSecuredMessageRecord;
                                }
                                else
                                {
                                    Err("_SecuredMessageRecord",
                                        "mac.base",
                                        EverParseErrorReasonOfResult(
                                            positionAfterSecuredMessageRecord),
                                        Ctxt,
                                        Input,
                                        positionAfterciphertext);
                                    positionAftermac =
                                        positionAfterSecuredMessageRecord;
                                }
                                uint64_t positionAfterSecuredMessageRecord1;
                                if (EverParseIsSuccess(positionAftermac))
                                {
                                    uint8_t *hd =
                                        Input +
                                        (uint32_t)positionAfterciphertext;
                                    *OutMac = hd;
                                    BOOLEAN actionSuccessMac = TRUE;
                                    if (!actionSuccessMac)
                                    {
                                        positionAfterSecuredMessageRecord1 =
                                            EverParseSetValidatorErrorPos(
                                                EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED,
                                                positionAftermac);
                                    }
                                    else
                                    {
                                        positionAfterSecuredMessageRecord1 =
                                            positionAftermac;
                                    }
                                }
                                else
                                {
                                    positionAfterSecuredMessageRecord1 =
                                        positionAftermac;
                                }
                                if (EverParseIsSuccess(
                                        positionAfterSecuredMessageRecord1))
                                {
                                    positionAfterSecuredMessageRecord0 =
                                        positionAfterSecuredMessageRecord1;
                                }
                                else
                                {
                                    Err("_SecuredMessageRecord",
                                        "mac",
                                        EverParseErrorReasonOfResult(
                                            positionAfterSecuredMessageRecord1),
                                        Ctxt,
                                        Input,
                                        positionAfterciphertext);
                                    positionAfterSecuredMessageRecord0 =
                                        positionAfterSecuredMessageRecord1;
                                }
                            }
                        }
                    }
                    if (EverParseIsSuccess(positionAfterSecuredMessageRecord0))
                    {
                        positionAfterSecuredMessageRecord =
                            positionAfterSecuredMessageRecord0;
                    }
                    else
                    {
                        Err("_SecuredMessageRecord",
                            "none",
                            EverParseErrorReasonOfResult(
                                positionAfterSecuredMessageRecord0),
                            Ctxt,
                            Input,
                            positionAftersequenceNumber0);
                        positionAfterSecuredMessageRecord =
                            positionAfterSecuredMessageRecord0;
                    }
                }
            }
        }
    }
    if (EverParseIsSuccess(positionAfterSecuredMessageRecord))
    {
        return positionAfterSecuredMessageRecord;
    }
    Err("_SecuredMessageRecord",
        "none",
        EverParseErrorReasonOfResult(positionAfterSecuredMessageRecord),
        Ctxt,
        Input,
        StartPosition);
    return positionAfterSecuredMessageRecord;
}
