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

#ifndef __EverParse_H
#define __EverParse_H

#if defined(__cplusplus)
extern "C"
{
#endif

#include "EverParseEndianness.h"
    static inline uint8_t
    EverParseGetBitfield8(uint8_t Value, uint32_t BitsFrom, uint32_t BitsTo)
    {
        uint8_t op1 = Value << ((uint32_t)8U - BitsTo);
        return op1 >> ((uint32_t)8U - BitsTo + BitsFrom);
    }

    static inline uint16_t
    EverParseGetBitfield16(uint16_t Value, uint32_t BitsFrom, uint32_t BitsTo)
    {
        uint16_t bf = Value << ((uint32_t)16U - BitsTo);
        return bf >> ((uint32_t)16U - BitsTo + BitsFrom);
    }

    static inline uint32_t
    EverParseGetBitfield32(uint32_t Value, uint32_t BitsFrom, uint32_t BitsTo)
    {
        return Value << ((uint32_t)32U - BitsTo) >>
               ((uint32_t)32U - BitsTo + BitsFrom);
    }

    static inline uint64_t
    EverParseGetBitfield64(uint64_t Value, uint32_t BitsFrom, uint32_t BitsTo)
    {
        return Value << ((uint32_t)64U - BitsTo) >>
               ((uint32_t)64U - BitsTo + BitsFrom);
    }

#define EVERPARSE_VALIDATOR_MAX_LENGTH ((uint64_t)1152921504606846975U)

    static inline BOOLEAN
    EverParseIsError(uint64_t PositionOrError)
    {
        return PositionOrError > EVERPARSE_VALIDATOR_MAX_LENGTH;
    }

    static inline BOOLEAN
    EverParseIsSuccess(uint64_t PositionOrError)
    {
        return PositionOrError <= EVERPARSE_VALIDATOR_MAX_LENGTH;
    }

    static inline uint64_t
    EverParseSetValidatorErrorPos(uint64_t Error, uint64_t Position)
    {
        return (Error & (uint64_t)17293822569102704640U) | Position
                                                               << (uint32_t)0U;
    }

    static inline uint64_t
    EverParseGetValidatorErrorPos(uint64_t X)
    {
        return (X & (uint64_t)1152921504606846975U) >> (uint32_t)0U;
    }

    static inline uint64_t
    EverParseSetValidatorErrorKind(uint64_t Error, uint64_t Code)
    {
        return (Error & (uint64_t)1152921504606846975U) | Code << (uint32_t)60U;
    }

    static inline uint64_t
    EverParseGetValidatorErrorKind(uint64_t Error)
    {
        return (Error & (uint64_t)17293822569102704640U) >> (uint32_t)60U;
    }

#define EVERPARSE_VALIDATOR_ERROR_GENERIC ((uint64_t)1152921504606846976U)

#define EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA                              \
    ((uint64_t)2305843009213693952U)

#define EVERPARSE_VALIDATOR_ERROR_IMPOSSIBLE ((uint64_t)3458764513820540928U)

#define EVERPARSE_VALIDATOR_ERROR_LIST_SIZE_NOT_MULTIPLE                       \
    ((uint64_t)4611686018427387904U)

#define EVERPARSE_VALIDATOR_ERROR_ACTION_FAILED ((uint64_t)5764607523034234880U)

#define EVERPARSE_VALIDATOR_ERROR_CONSTRAINT_FAILED                            \
    ((uint64_t)6917529027641081856U)

#define EVERPARSE_VALIDATOR_ERROR_UNEXPECTED_PADDING                           \
    ((uint64_t)8070450532247928832U)

    static inline PrimsString
    EverParseErrorReasonOfResult(uint64_t Code)
    {
        switch (EverParseGetValidatorErrorKind(Code))
        {
        case 1U: {
            return "generic error";
        }
        case 2U: {
            return "not enough data";
        }
        case 3U: {
            return "impossible";
        }
        case 4U: {
            return "list size not multiple of element size";
        }
        case 5U: {
            return "action failed";
        }
        case 6U: {
            return "constraint failed";
        }
        case 7U: {
            return "unexpected padding";
        }
        default: {
            return "unspecified";
        }
        }
    }

    static inline uint64_t
    EverParseCheckConstraintOk(BOOLEAN Ok, uint64_t Position)
    {
        if (Ok)
        {
            return Position;
        }
        return EverParseSetValidatorErrorPos(
            EVERPARSE_VALIDATOR_ERROR_CONSTRAINT_FAILED, Position);
    }

    static inline BOOLEAN
    EverParseIsRangeOkay(uint32_t Size, uint32_t Offset, uint32_t AccessSize)
    {
        return Size >= AccessSize && (Size - AccessSize) >= Offset;
    }

    typedef struct EverParseErrorFrame_s
    {
        BOOLEAN filled;
        uint64_t start_pos;
        PrimsString typename_s;
        PrimsString fieldname;
        PrimsString reason;
    } EverParseErrorFrame;

    typedef uint8_t *EverParseInputBuffer;

    static inline void
    EverParseDefaultErrorHandler(
        PrimsString TypenameS,
        PrimsString Fieldname,
        PrimsString Reason,
        EverParseErrorFrame *Context,
        uint8_t *Input,
        uint64_t StartPos)
    {
        if (!(*Context).filled)
        {
            *Context = ((EverParseErrorFrame){
                .filled = TRUE,
                .start_pos = StartPos,
                .typename_s = TypenameS,
                .fieldname = Fieldname,
                .reason = Reason});
            return;
        }
    }

#if defined(__cplusplus)
}
#endif

#define __EverParse_H_DEFINED
#endif
