/*
 *  MinHook - The Minimalistic API Hooking Library for x64/x86
 *  Copyright (C) 2009-2017 Tsuda Kageyu.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 *  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
 *  OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

#pragma pack(push, 1)

//typedef unsigned char unsigned char_t;
//typedef unsigned long unsigned long_t;
//typedef unsigned long long unsigned long long_t;
//#define unsigned long long unsigned long long_t

#ifndef BOOL
#define BOOL bool
#endif

// Structs for writing x86/x64 instructions.

// 8-bit relative jump.
typedef struct _JMP_REL_SHORT
{
    unsigned char  opcode;      // EB xx: JMP +2+xx
    unsigned char  operand;
} JMP_REL_SHORT, *PJMP_REL_SHORT;

// 32-bit direct relative jump/call.
typedef struct _JMP_REL
{
    unsigned char  opcode;      // E9/E8 xxxxxxxx: JMP/CALL +5+xxxxxxxx
    unsigned long operand;     // Relative destination address
} JMP_REL, *PJMP_REL, CALL_REL;

// 64-bit indirect absolute jump.
typedef struct _JMP_ABS
{
    unsigned char  opcode0;     // FF25 00000000: JMP [+6]
    unsigned char  opcode1;
    unsigned long dummy;
    unsigned long long address;     // Absolute destination address
} JMP_ABS, *PJMP_ABS;

// 64-bit indirect absolute call.
typedef struct _CALL_ABS
{
    unsigned char  opcode0;     // FF15 00000002: CALL [+6]
    unsigned char  opcode1;
    unsigned long dummy0;
    unsigned char  dummy1;      // EB 08:         JMP +10
    unsigned char  dummy2;
    unsigned long long address;     // Absolute destination address
} CALL_ABS;

// 32-bit direct relative conditional jumps.
typedef struct _JCC_REL
{
    unsigned char  opcode0;     // 0F8* xxxxxxxx: J** +6+xxxxxxxx
    unsigned char  opcode1;
    unsigned long operand;     // Relative destination address
} JCC_REL;

// 64bit indirect absolute conditional jumps that x64 lacks.
typedef struct _JCC_ABS
{
    unsigned char  opcode;      // 7* 0E:         J** +16
    unsigned char  dummy0;
    unsigned char  dummy1;      // FF25 00000000: JMP [+6]
    unsigned char  dummy2;
    unsigned long dummy3;
    unsigned long long address;     // Absolute destination address
} JCC_ABS;

#pragma pack(pop)

typedef struct _TRAMPOLINE
{
    LPVOID pTarget;         // [In] Address of the target function.
    LPVOID pDetour;         // [In] Address of the detour function.
    LPVOID pTrampoline;     // [In] Buffer address for the trampoline and relay function.

#if defined(_M_X64) || defined(__x86_64__)
    LPVOID pRelay;          // [Out] Address of the relay function.
#endif
    BOOL   patchAbove;      // [Out] Should use the hot patch area?
    UINT   nIP;             // [Out] Number of the instruction boundaries.
    unsigned char  oldIPs[8];       // [Out] Instruction boundaries of the target function.
    unsigned char  newIPs[8];       // [Out] Instruction boundaries of the trampoline function.
} TRAMPOLINE, *PTRAMPOLINE;

BOOL CreateTrampolineFunction(PTRAMPOLINE ct);
