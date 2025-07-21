[BITS 64]

            %define B0 xmm0
            %define B1 xmm1
            %define B2 xmm2
            %define B3 xmm3
            %define B4 xmm4
            %define B5 xmm5
            %define B6 xmm6
            %define B7 xmm7

            %define ACC0 xmm8
            %define ACC1 xmm9
            %define ACCM xmm10

            %define T0 xmm11
            %define T1 xmm12
            %define T2 xmm13
            %define POLY xmm14
            %define LBSWAP xmm15



            %macro reduceround 1 
                movdqu   T0, POLY
                pclmulqdq T0, %1, 1
                pshufd %1, %1, 78
                pxor %1, T0
            %endmacro

            %macro mulroundaad 2 
                movdqu   T1, [producttable+16*(%2*2)]
                movdqu   T2, T1
                pclmulqdq T1, %1, 0
                pxor ACC0, T1
                pclmulqdq T2, %1, 17
                pxor ACC1, T2
                pshufd T1, %1, 78
                pxor %1, T1
                movdqu T1, [producttable+16*(%2*2+1)]
                pclmulqdq T1, %1, 0
                pxor ACCM, T1
            %endmacro

            %macro dincrement 1
                add r10d, 1
                mov r11d, r10d
                xor r11d, r12d
                bswap r11d
                mov [rsp+12+%1*16], r11d
            %endmacro

            %macro combineddecround 1
                movdqu T0, [ks+16*%1]
                aesenc B0, T0
                aesenc B1, T0
                aesenc B2, T0
                aesenc B3, T0
                movdqu T1, [producttable+16*(%1*2)]
                movdqu T2, T1
                aesenc B4, T0
                aesenc B5, T0
                aesenc B6, T0
                aesenc B7, T0
                movdqu T0, [ctx+16*%1]
                pshufb T0, LBSWAP
                pclmulqdq T1, T0, 0
                pxor ACC0, T1
                pshufd T1, T0, 78
                pclmulqdq T2, T0, 17
                pxor T0, T1
                pxor ACC1, T2
                movdqu T2, [producttable+16*(%1*2+1)]
                pclmulqdq T0, T2, 0
                pxor ACCM, T0
            %endmacro

            	
            %macro increment 1
                add r10d, 1
                mov r11d, r10d
                xor r11d, r12d
                bswap r11d
                mov [rsp+12+128+%1*16], r11d
            %endmacro

            %macro aesrnd 1
                aesenc B0, %1
                aesenc B1, %1
                aesenc B2, %1
                aesenc B3, %1
                aesenc B4, %1
                aesenc B5, %1
                aesenc B6, %1
                aesenc B7, %1
            %endmacro

            %macro aesround 1
                movdqu T0, [ks+16*%1]
                aesenc B0, T0
                aesenc B1, T0
                aesenc B2, T0
                aesenc B3, T0
                aesenc B4, T0
                aesenc B5, T0
                aesenc B6, T0
                aesenc B7, T0
            %endmacro

            %macro aesrndlast 1
                aesenclast B0, %1
                aesenclast B1, %1
                aesenclast B2, %1
                aesenclast B3, %1
                aesenclast B4, %1
                aesenclast B5, %1
                aesenclast B6, %1
                aesenclast B7, %1
            %endmacro

            %macro combinedround 1
                movdqu T0, [ks+16*%1]
                aesenc B0, T0
                aesenc B1, T0
                aesenc B2, T0
                aesenc B3, T0
                movdqu T1, [producttable+16*(%1*2)]
                movdqu T2, T1
                aesenc B4, T0
                aesenc B5, T0
                aesenc B6, T0
                aesenc B7, T0
                movdqu T0, [rsp+16*%1]
                pclmulqdq T1, T0, 0
                pxor ACC0, T1
                pshufd T1, T0, 78
                pclmulqdq T2, T0, 17
                pxor T0, T1
                pxor ACC1, T2
                movdqu T2, [producttable+16*(%1*2+1)]
                pclmulqdq T0, T2, 0
                pxor ACCM, T0
            %endmacro

            %macro mulround 1
                movdqu T0, [rsp+16*%1]
                movdqu T1, [producttable+16*(%1*2)]
                movdqu T2, T1
                pclmulqdq T1, T0, 0
                pxor ACC0, T1
                pclmulqdq T2, T0, 17
                pxor ACC1, T2
                pshufd T1, T0, 78
                pxor T0, T1
                movdqu T1, [producttable+16*(%1*2+1)]
                pclmulqdq T1, T0, 0
                pxor ACCM, T1
            %endmacro


    section .data
            Lbswap_mask     dq 0x08090a0b0c0d0e0f, 0x0001020304050607
            Lpoly           dq 0x0000000000000001, 0xc200000000000000
            Land_mask       dq 0ffh, 0h, 0ffffh, 0h, 0ffffffh, 0h, 0ffffffffh, 0h, 0ffffffffffh, 0h, 0ffffffffffffh, 0h, 0ffffffffffffffh, 0h, 0ffffffffffffffffh, 0h, 0ffffffffffffffffh, 0ffh, 0ffffffffffffffffh, 0ffffh, 0ffffffffffffffffh, 0ffffffh, 0ffffffffffffffffh, 0ffffffffh, 0ffffffffffffffffh, 0ffffffffffh, 0ffffffffffffffffh, 0ffffffffffffh, 0ffffffffffffffffh, 0ffffffffffffffh
            

;----------------------------------------------------------------------------------------------------------

    section .text
            global gcmaesinit:function

gcmaesinit:
;
; define the paramter
;
;producttable equ rdi
;keybase equ rsi
;keylen equ rdx 
%define producttable rdi
%define keybase rsi
%define keylen rdx
%idefine rip rel $
;
            shr keylen, 2
            dec keylen

            movups LBSWAP, [rel +Lbswap_mask]
            movups POLY, [rel +Lpoly]

            movdqu B0, [keybase]
            movdqu T0, [keybase+16]
            aesenc B0, T0
            movdqu T0, [keybase+32]
            aesenc B0, T0
            movdqu T0, [keybase+48]
            aesenc B0, T0
            movdqu T0, [keybase+64]
            aesenc B0, T0
            movdqu T0, [keybase+80]
            aesenc B0, T0
            movdqu T0, [keybase+96]
            aesenc B0, T0
            movdqu T0, [keybase+112]
            aesenc B0, T0
            movdqu T0, [keybase+128]
            aesenc B0, T0
            movdqu T0, [keybase+144]
            aesenc B0, T0
            movdqu T0, [keybase+160]
            cmp keylen, 12
            jb initenclast
            aesenc B0, T0
            movdqu T0, [keybase+176]
            aesenc B0, T0
            movdqu T0, [keybase+192]
            je initenclast
            aesenc B0, T0
            movdqu T0, [keybase+208]
            aesenc B0, T0
            movdqu T0, [keybase+224]

initenclast:
            aesenclast B0, T0
            pshufb B0, LBSWAP ; PSHUFB BSWAP, B0
            pshufd T0, B0, 255 ; PSHUFD $0xff, B0, T0
            movdqu T1, B0
            psrad T0, 31 ; PSRAL $31, T0
            pand T0, POLY
            psrld T1, 31 ; PSRLL $31, T1
            pslldq T1, 4 ; PSLLDQ $4, T1
            pslld B0, 1 ; PSLLL $1, B0
            pxor B0, T0
            pxor B0, T1

            movdqu [producttable+224], B0
            pshufd B1, B0, 78 ;PSHUFD $78, B0, B1
            pxor B1, B0
            movdqu [producttable+240], B1

            movdqu B2, B0
            movdqu B3, B1
            mov rax, 7

initloop:
            movdqu T0, B2
            movdqu T1, B2
            movdqu T2, B3
            pclmulqdq T0, B0, 0
            pclmulqdq T1, B0, 17
            pclmulqdq T2, B1, 0

            pxor T2, T0
            pxor T2, T1
            movdqu B4, T2
            pslldq B4, 8 ; PSLLDQ $8, B4
            psrldq T2, 8 ; PSRLDQ $8, T2
            pxor T0, B4
            pxor T1, T2

            movdqu B2, POLY
            pclmulqdq B2, T0, 1
            pshufd T0, T0, 78
            pxor T0, B2
            movdqu B2, POLY
            pclmulqdq B2, T0, 1
            pshufd T0, T0, 78
            pxor B2, T0
            pxor B2, T1

            movdqu [producttable+192], B2
            pshufd B3, B2, 78
            pxor B3, B2
            movdqu [producttable+208], B3

            dec rax
            lea producttable, [producttable-32]
        jne initloop
        ret

%undef producttable
%undef keybase
%undef keylen


;---------------------------------------------------

            section .text
            global aesencblock:function

aesencblock:       
;
; define the parameter
;

%define dst rdi
%define src rsi
%define keybase rdx
%define keylen rcx
;
            shr keylen, 2
            dec keylen

            movdqu xmm0, [src]
            movdqu xmm1, [keybase]
            pxor xmm0, xmm1
            movdqu xmm1, [keybase+16]
            aesenc xmm0, xmm1
            movdqu xmm1, [keybase+32]
            aesenc xmm0, xmm1
            movdqu xmm1, [keybase+48]
            aesenc xmm0, xmm1
            movdqu xmm1, [keybase+64]
            aesenc xmm0, xmm1
            movdqu xmm1, [keybase+80]
            aesenc xmm0, xmm1
            movdqu xmm1, [keybase+96]
            aesenc xmm0, xmm1
            movdqu xmm1, [keybase+112]
            aesenc xmm0, xmm1
            movdqu xmm1, [keybase+128]
            aesenc xmm0, xmm1
            movdqu xmm1, [keybase+144]
            aesenc xmm0, xmm1
            movdqu xmm1, [keybase+160]

            cmp keylen, 12
            jb enclast
            aesenc xmm0, xmm1
            movdqu xmm1, [keybase+176]
            aesenc xmm0, xmm1
            movdqu xmm1, [keybase+192]

            je enclast
            aesenc xmm0, xmm1
            movdqu xmm1, [keybase+208]
            aesenc xmm0, xmm1
            movdqu xmm1, [keybase+224]

enclast:
            aesenclast xmm0, xmm1  
            movdqu [dst], xmm0
            ret

%undef dst
%undef src
%undef keybase
%undef keylen  


;---------------------------------------------------

            section .text
            global gcmaesdata:function
            

gcmaesdata:
;
; define the paramter
;

%define producttable rdi
%define aut rsi
%define tptr rdx
%define autlen rcx
;

			pxor ACC0, ACC0
            movups LBSWAP, [rel +Lbswap_mask]
            movups POLY, [rel +Lpoly]
            test autlen, autlen
            jz databail

            cmp autlen, 13
            je datatls
            cmp autlen, 128
            jb startsinglesloop
            jmp dataoctaloop


    datatls:
    		movdqu T1, [producttable+224]
    		movdqu T2, [producttable+240]
    		pxor B0, B0
    		movq B0, [aut]
    		pinsrd B0, [aut+8], 2
    		pinsrb B0, [aut+12], 12
    		xor autlen, autlen
    		jmp datamul

    dataoctaloop:
    		cmp autlen, 128 
    		jb startsinglesloop
    		sub autlen, 128
    		movdqu xmm0, [aut]
    		movdqu xmm1, [aut+16]
    		movdqu xmm2, [aut+32]
    		movdqu xmm3, [aut+48]
    		movdqu xmm4, [aut+64]
    		movdqu xmm5, [aut+80]
    		movdqu xmm6, [aut+96]
    		movdqu xmm7, [aut+112]
    		lea aut, [aut+128]
    		pshufb xmm0, LBSWAP
    		pshufb xmm1, LBSWAP
    		pshufb xmm2, LBSWAP
    		pshufb xmm3, LBSWAP
    		pshufb xmm4, LBSWAP
    		pshufb xmm5, LBSWAP
    		pshufb xmm6, LBSWAP
    		pshufb xmm7, LBSWAP
    		pxor xmm0, ACC0
    		movdqu ACC0, [producttable]
    		movdqu ACCM, [producttable+16]
    		movdqu ACC1, ACC0
    		pshufd T1, xmm0, 78
    		pxor T1, xmm0
    		pclmulqdq ACC0, xmm0, 0
    		pclmulqdq ACC1, xmm0, 17
    		pclmulqdq ACCM, T1, 0


    		mulroundaad xmm1, 1
    		mulroundaad xmm2, 2
    		mulroundaad xmm3, 3
    		mulroundaad xmm4, 4
    		mulroundaad xmm5, 5
    		mulroundaad xmm6, 6
    		mulroundaad xmm7, 7

    		pxor ACCM, ACC0
    		pxor ACCM, ACC1
    		movdqu T0, ACCM
    		psrldq ACCM, 8 
            pslldq T0, 8
            pxor ACC1, ACCM
            pxor ACC0, T0
            reduceround ACC0
            reduceround ACC0
            pxor ACC0, ACC1

        jmp dataoctaloop

    startsinglesloop:
    		movdqu T1, [producttable+224]
    		movdqu T2, [producttable+240]
    datasinglesloop:
    		cmp autlen, 16 
    		jb dataend
    		sub autlen, 16

    		movdqu B0, [aut]
    datamul:
    		pshufb B0, LBSWAP
    		pxor B0, ACC0

    		movdqu ACC0, T1
    		movdqu ACCM, T2
    		movdqu ACC1, T1

    		pshufd T0, B0, 78
    		pxor T0, B0
    		pclmulqdq ACC0, B0, 0
    		pclmulqdq ACC1, B0, 17
    		pclmulqdq ACCM, T0, 0

    		pxor ACCM, ACC0
    		pxor ACCM, ACC1
    		movdqu T0, ACCM
    		psrldq ACCM, 8
            pslldq T0, 8
    		pxor ACC1, ACCM
    		pxor ACC0, T0

    		movdqu T0, POLY
    		pclmulqdq T0, ACC0, 1
    		pshufd ACC0, ACC0, 78
    		pxor ACC0, T0

    		movdqu T0, POLY
    		pclmulqdq T0, ACC0, 1
    		pshufd ACC0, ACC0, 78
    		pxor ACC0, T0
    		pxor ACC0, ACC1

    		lea aut, [aut+16]

    	jmp datasinglesloop

    dataend:
    		test autlen, autlen
    		jz databail

    		pxor B0, B0
    		lea aut, [aut+(autlen*1)-1]

    dataloadloop:
            pslldq B0, 1
            pinsrb B0, [aut], 0
            lea aut, [aut-1]
            dec autlen
            jne dataloadloop
            jmp datamul

    databail:
    		movdqu [tptr], ACC0
    		ret

%undef producttable
%undef aut
%undef tptr
%undef autlen

;---------------------------------------------------

            section .text
            global gcmaesfinish:function
gcmaesfinish:
;
; define the paramter
;


%define producttable rdi
%define tagmask rsi
%define tptr rdx
%define plen rcx
%define dlen r8
;

            movdqu ACC0, [tptr]
            movdqu T2, [tagmask]

            movups LBSWAP, [rel +Lbswap_mask]
            movups POLY, [rel +Lpoly]
            shl plen, 3
            shl dlen, 3
            movq B0, plen
            pinsrq B0, dlen, 1
            pxor B0, ACC0

            movdqu ACC0, [producttable+224]
            movdqu ACCM, [producttable+240]
            movdqu ACC1, ACC0

            pclmulqdq ACC0, B0, 0
            pclmulqdq ACC1, B0, 17
            pshufd   T0, B0, 78
            pxor T0, B0
            pclmulqdq ACCM, T0, 0

            pxor ACCM, ACC0
            pxor ACCM, ACC1
            movdqu T0, ACCM
            psrldq ACCM, 8
            pslldq T0, 8
            pxor ACC1, ACCM
            pxor ACC0, T0

            movdqu T0, POLY
            pclmulqdq T0, ACC0, 1
            pshufd   ACC0, ACC0, 78
            pxor ACC0, T0

            movdqu T0, POLY
            pclmulqdq T0, ACC0, 1
            pshufd   ACC0, ACC0, 78
            pxor ACC0, T0

            pxor ACC0, ACC1

            pshufb ACC0, LBSWAP
            pxor ACC0, T2
            movdqu [tptr], ACC0

            ret

%undef producttable
%undef tagmask
%undef tptr
%undef plen
%undef dlen







;---------------------------------------------------


            ;section .data
            section .text
            global gcmaesdec:function
            ;section .text

gcmaesdec:
;
; define the paramter
;


%define producttable rdi
%define ptx rsi
%define ctx rdx
%define ctrptr rcx
%define tptr r8
%define ks r9
%define ptxlen r13
%define nr r14

;%define aluctr r10
;%define alutmp r11
;%define aluk r12
            
            sub rsp, 0x88
            mov [rsp+0x80], rbp
            lea rbp, [rsp+0x80]
            mov ptxlen, [rsp+0x90]
            mov nr, [rsp+0x98]

            ;mov ptxlen, [rsp+16]
            ;mov nr, [rsp+24]
            
            shr nr, 2
            dec nr
            
            movups LBSWAP, [rel +Lbswap_mask] ;MOVOU bswapMask<>(SB), BSWAP
            movups POLY, [rel +Lpoly] ;MOVOU gcmPoly<>(SB), POLY

            movdqu ACC0, [tptr]
            pxor ACC1, ACC1
            pxor ACCM, ACCM
            movdqu B0, [ctrptr]
            mov r10d, [ctrptr+12]
            movdqu T0, [ks]
            mov r12d, [ks+12]
            bswap r10d
            bswap r12d

            pxor T0, B0
            movdqu [rsp], T0
            dincrement 0
            ;nop
            cmp ptxlen, 128
            jb gcmaesdecsingles

            movdqu [rsp+16], T0
            dincrement 1
            movdqu [rsp+32], T0
            dincrement 2
            movdqu [rsp+48], T0
            dincrement 3
            movdqu [rsp+64], T0
            dincrement 4
            movdqu [rsp+80], T0
            dincrement 5
            movdqu [rsp+96], T0
            dincrement 6
            movdqu [rsp+112], T0
            dincrement 7
gcmaesdecoctetsloop:
            cmp ptxlen, 128
            jb gcmaesdecendoctets
            sub ptxlen, 128

            movdqu B0, [rsp]
            movdqu B1, [rsp+16]
            movdqu B2, [rsp+32]
            movdqu B3, [rsp+48]
            movdqu B4, [rsp+64]
            movdqu B5, [rsp+80]
            movdqu B6, [rsp+96]
            movdqu B7, [rsp+112]

            movdqu T0, [ctx]
            pshufb T0, LBSWAP
            pxor T0, ACC0
            pshufd T1, T0, 78
            pxor T1, T0

            movdqu ACC0, [producttable]
            movdqu ACCM, [producttable+16]
            movdqu ACC1, ACC0

            pclmulqdq ACCM, T1, 0
            pclmulqdq ACC0, T0, 0
            pclmulqdq ACC1, T0, 17

            combineddecround 1
            dincrement 0
            combineddecround 2
            dincrement 1
            combineddecround 3
            dincrement 2
            combineddecround 4
            dincrement 3
            combineddecround 5
            dincrement 4
            combineddecround 6
            dincrement 5
            combineddecround 7
            dincrement 6

            aesround 8
            dincrement 7

            pxor ACCM, ACC0
            pxor ACCM, ACC1
            movdqu T0, ACCM
            psrldq ACCM, 8
            pslldq T0, 8
            pxor ACC1, ACCM
            pxor ACC0, T0

            reduceround ACC0
            aesround 9

            reduceround ACC0
            pxor ACC0, ACC1

            movdqu T0, [ks+160]
            cmp nr, 12
            jb declast1
            aesrnd T0
            aesround 11
            movdqu T0, [ks+192]
            je declast1
            aesrnd T0
            aesround 13
            movdqu T0, [ks+224]
declast1:
            aesrndlast T0
            movdqu T0, [ctx]
            pxor B0, T0
            movdqu T0, [ctx+16]
            pxor B1, T0
            movdqu T0, [ctx+32]
            pxor B2, T0
            movdqu T0, [ctx+48]
            pxor B3, T0
            movdqu T0, [ctx+64]
            pxor B4, T0
            movdqu T0, [ctx+80]
            pxor B5, T0
            movdqu T0, [ctx+96]
            pxor B6, T0
            movdqu T0, [ctx+112]
            pxor B7, T0

            movdqu [ptx], B0
            movdqu [ptx+16], B1
            movdqu [ptx+32], B2
            movdqu [ptx+48], B3
            movdqu [ptx+64], B4
            movdqu [ptx+80], B5
            movdqu [ptx+96], B6
            movdqu [ptx+112], B7

            lea ptx, [ptx+128]
            lea ctx, [ctx+128]
            jmp gcmaesdecoctetsloop
gcmaesdecendoctets:
            sub r10, 7
gcmaesdecsingles:
            
            movdqu B1, [ks+16]
            movdqu B2, [ks+32]
            movdqu B3, [ks+48]
            movdqu B4, [ks+64]
            movdqu B5, [ks+80]
            movdqu B6, [ks+96]
            movdqu B7, [ks+112]
            
            movdqu T2, [producttable+224]
gcmaesdecsinglesloop:

            cmp ptxlen, 16
            jb gcmaesdectail
            sub ptxlen, 16

            movdqu B0, [ctx]
            movdqu T1, B0
            pshufb B0, LBSWAP
            pxor B0, ACC0

            movdqu ACC0, T2
            movdqu ACC1, T2
            movdqu ACCM, [producttable+240]

            pclmulqdq ACC0, B0, 0
            pclmulqdq ACC1, B0, 17
            pshufd T0, B0, 78
            pxor T0, B0
            pclmulqdq ACCM, T0, 0

            pxor ACCM, ACC0
            pxor ACCM, ACC1
            movdqu T0, ACCM
            psrldq ACCM, 8
            pslldq T0, 8
            pxor ACC1, ACCM
            pxor ACC0, T0

            reduceround ACC0
            reduceround ACC0
            ;nop
            pxor ACC0, ACC1

            movdqu B0, [rsp]
            dincrement 0
            ;nop
            aesenc B0, B1
            aesenc B0, B2
            aesenc B0, B3
            aesenc B0, B4
            aesenc B0, B5
            aesenc B0, B6
            aesenc B0, B7

            movdqu T0, [ks+128]
            aesenc B0, T0
            movdqu T0, [ks+144]
            aesenc B0, T0
            movdqu T0, [ks+160]
            cmp nr, 12
            jb declast2
            aesenc B0, T0
            movdqu T0, [ks+176]
            aesenc B0, T0
            movdqu T0, [ks+192]
            je declast2
            aesenc B0, T0
            movdqu T0, [ks+208]
            aesenc B0, T0
            movdqu T0, [ks+224]
declast2:
            aesenclast B0, T0
            pxor B0, T1
            movdqu [ptx], B0

            lea ptx, [ptx+16]
            lea ctx, [ctx+16]

            jmp gcmaesdecsinglesloop
gcmaesdectail:
            test ptxlen, ptxlen
            je gcmaesdecdone

            mov r11, ptxlen
            shl r11, 4
            lea r10, [rel +Land_mask]
            movdqu T1, [r10+r11*1-16]

            movdqu B0, [ctx]
            pand B0, T1
            movdqu T1, B0
            pshufb B0, LBSWAP
            pxor B0, ACC0

            movdqu ACC0, [producttable+224]
            movdqu ACCM, [producttable+240]
            movdqu ACC1, ACC0

            pclmulqdq ACC0, B0, 0
            pclmulqdq ACC1, B0, 17
            pshufd T0, B0, 78
            pxor T0, B0
            pclmulqdq ACCM, T0, 0

            pxor ACCM, ACC0
            pxor ACCM, ACC1
            movdqu T0, ACCM
            psrldq ACCM, 8
            pslldq T0, 8
            pxor ACC1, ACCM
            pxor ACC0, T0

            reduceround ACC0
            reduceround ACC0
            ;nop
            pxor ACC0, ACC1

            movdqu B0, [rsp]
            dincrement 0
            ;nop
            aesenc B0, B1
            aesenc B0, B2
            aesenc B0, B3
            aesenc B0, B4
            aesenc B0, B5
            aesenc B0, B6
            aesenc B0, B7
            movdqu T0, [ks+128]
            aesenc B0, T0
            movdqu T0, [ks+144]
            aesenc B0, T0
            movdqu T0, [ks+160]
            cmp nr, 12
            jb declast3
            aesenc B0, T0
            movdqu T0, [ks+176]
            aesenc B0, T0
            movdqu T0, [ks+192]
            je declast3
            aesenc B0, T0
            movdqu T0, [ks+208]
            aesenc B0, T0
            movdqu T0, [ks+224]
declast3:
            aesenclast B0, T0
            pxor B0, T1

ptxstoreloop:
            pextrb [ptx], B0, 0
            psrldq B0, 1
            lea ptx, [ptx+1]
            dec ptxlen
            jne ptxstoreloop

gcmaesdecdone:
            movdqu [tptr], ACC0
            mov rbp, [rsp+0x80]
            add rsp, 0x88
            ;mov rsp, rbp
            ;pop rbp
            ;mov rbp, [rsp+16]
            ;add rsp, 24
            ;leave
            ret

%undef producttable
%undef ctx
%undef ctrptr
%undef ptx
%undef ks
%undef tptr
%undef ptxlen
%undef nr
;%undef aluctr
;%undef alutmp
;%undef aluk



;---------------------------------------------------

            ;section .data
            section .text
            global gcmaesenc:function
            ;section .text

gcmaesenc:
;
; define the paramter
;


%define producttable rdi
%define ctx rsi
%define ptx rdx
%define ctrptr rcx
%define tptr r8
%define ks r9
%define ptxlen r13
%define nr r14
;%define aluctr r10
;%define alutmp r11
;%define aluk r12

;
            sub rsp, 0x108
            mov [rsp+0x100], rbp
            lea rbp, [rsp+0x100]

            mov ptxlen, [rsp+0x110]
            mov nr, [rsp+0x118]
            shr nr, 2
            dec nr
            movups LBSWAP, [rel +Lbswap_mask]
            movups POLY, [rel +Lpoly]
            movdqu ACC0, [tptr]
            pxor ACC1, ACC1
            pxor ACCM, ACCM
            movdqu B0, [ctrptr]
            mov r10d, [ctrptr+12]
            movdqu T0, [ks]
            mov r12d, [ks+12]
            bswap r10d
            bswap r12d

            pxor T0, B0
            movdqu [rsp+128], T0
            increment 0

            cmp ptxlen, 128
            jb gcmaesencsingles
            sub ptxlen, 128

            movdqu [rsp+128+16], T0
            increment 1
            movdqu [rsp+128+32], T0
            increment 2
            movdqu [rsp+128+48], T0
            increment 3
            movdqu [rsp+128+64], T0
            increment 4
            movdqu [rsp+128+80], T0
            increment 5
            movdqu [rsp+128+96], T0
            increment 6
            movdqu [rsp+128+112], T0
            increment 7

            movdqu B0, [rsp+128]
            movdqu B1, [rsp+128+16]
            movdqu B2, [rsp+128+32]
            movdqu B3, [rsp+128+48]
            movdqu B4, [rsp+128+64]
            movdqu B5, [rsp+128+80]
            movdqu B6, [rsp+128+96]
            movdqu B7, [rsp+128+112]

            aesround 1
            increment 0
            aesround 2
            increment 1
            aesround 3
            increment 2
            aesround 4
            increment 3
            aesround 5
            increment 4
            aesround 6
            increment 5
            aesround 7
            increment 6
            aesround 8
            increment 7
            aesround 9
            movdqu T0, [ks+160]
            cmp nr, 12
            jb enclast1
            aesrnd T0
            aesround 11
            movdqu T0, [ks+192]
            je enclast1
            aesrnd T0
            aesround 13
            movdqu T0, [ks+224]
enclast1:
            aesrndlast T0
            movdqu T0, [ptx]
            pxor B0, T0
            movdqu T0, [ptx+16]
            pxor B1, T0
            movdqu T0, [ptx+32]
            pxor B2, T0
            movdqu T0, [ptx+48]
            pxor B3, T0
            movdqu T0, [ptx+64]
            pxor B4, T0
            movdqu T0, [ptx+80]
            pxor B5, T0
            movdqu T0, [ptx+96]
            pxor B6, T0
            movdqu T0, [ptx+112]
            pxor B7, T0

            movdqu [ctx], B0
            pshufb B0, LBSWAP
            pxor B0, ACC0
            movdqu [ctx+16], B1
            pshufb B1, LBSWAP
            movdqu [ctx+32], B2
            pshufb B2, LBSWAP
            movdqu [ctx+48], B3
            pshufb B3, LBSWAP
            movdqu [ctx+64], B4
            pshufb B4, LBSWAP
            movdqu [ctx+80], B5
            pshufb B5, LBSWAP
            movdqu [ctx+96], B6
            pshufb B6, LBSWAP
            movdqu [ctx+112], B7
            pshufb B7, LBSWAP

            movdqu [rsp], B0
            movdqu [rsp+16], B1
            movdqu [rsp+32], B2
            movdqu [rsp+48], B3
            movdqu [rsp+64], B4
            movdqu [rsp+80], B5
            movdqu [rsp+96], B6
            movdqu [rsp+112], B7

            lea ptx, [ptx+128]
            lea ctx, [ctx+128]

gcmaesencoctetsloop:
            cmp ptxlen, 128
            jb gcmaesencoctetsend
            sub ptxlen, 128

            movdqu B0, [rsp+128]
            movdqu B1, [rsp+128+16]
            movdqu B2, [rsp+128+32]
            movdqu B3, [rsp+128+48]
            movdqu B4, [rsp+128+64]
            movdqu B5, [rsp+128+80]
            movdqu B6, [rsp+128+96]
            movdqu B7, [rsp+128+112]

            movdqu T0, [rsp]
            pshufd T1, T0, 78
            pxor T1, T0

            movdqu ACC0, [producttable]
            movdqu ACCM, [producttable+16]
            movdqu ACC1, ACC0

            pclmulqdq ACCM, T1, 0
            pclmulqdq ACC0, T0, 0
            pclmulqdq ACC1, T0, 17

            combinedround 1
            increment 0
            combinedround 2
            increment 1
            combinedround 3
            increment 2
            combinedround 4
            increment 3
            combinedround 5
            increment 4
            combinedround 6
            increment 5
            combinedround 7
            increment 6

            aesround 8
            increment 7

            pxor ACCM, ACC0
            pxor ACCM, ACC1
            movdqu T0, ACCM
            psrldq ACCM, 8
            pslldq T0, 8
            pxor ACC1, ACCM
            pxor ACC0, T0

            reduceround ACC0
            aesround 9

            reduceround ACC0
            pxor ACC0, ACC1
            movdqu T0, [ks+160]
            cmp nr, 12
            jb enclast2
            aesrnd T0
            aesround 11
            movdqu T0, [ks+192]
            je enclast2
            aesrnd T0
            aesround 13
            movdqu T0, [ks+224]
enclast2:

            aesrndlast T0
            movdqu T0, [ptx]
            pxor B0, T0
            movdqu T0, [ptx+16]
            pxor B1, T0
            movdqu T0, [ptx+32]
            pxor B2, T0
            movdqu T0, [ptx+48]
            pxor B3, T0
            movdqu T0, [ptx+64]
            pxor B4, T0
            movdqu T0, [ptx+80]
            pxor B5, T0
            movdqu T0, [ptx+96]
            pxor B6, T0
            movdqu T0, [ptx+112]
            pxor B7, T0

            movdqu [ctx], B0
            pshufb B0, LBSWAP
            pxor B0, ACC0
            movdqu [ctx+16], B1
            pshufb B1, LBSWAP
            movdqu [ctx+32], B2
            pshufb B2, LBSWAP
            movdqu [ctx+48], B3
            pshufb B3, LBSWAP
            movdqu [ctx+64], B4
            pshufb B4, LBSWAP
            movdqu [ctx+80], B5
            pshufb B5, LBSWAP
            movdqu [ctx+96], B6
            pshufb B6, LBSWAP
            movdqu [ctx+112], B7
            pshufb B7, LBSWAP

            movdqu [rsp], B0
            movdqu [rsp+16], B1
            movdqu [rsp+32], B2
            movdqu [rsp+48], B3
            movdqu [rsp+64], B4
            movdqu [rsp+80], B5
            movdqu [rsp+96], B6
            movdqu [rsp+112], B7

            lea ptx, [ptx+128]
            lea ctx, [ctx+128]
            jmp gcmaesencoctetsloop

gcmaesencoctetsend:

            movdqu T0, [rsp]
            movdqu ACC0, [producttable]
            movdqu ACCM, [producttable+16]
            movdqu ACC1, ACC0
            pshufd T1, T0, 78
            pxor T1, T0
            pclmulqdq ACC0, T0, 0
            pclmulqdq ACC1, T0, 17
            pclmulqdq ACCM, T1, 0

            mulround 1
            mulround 2
            mulround 3
            mulround 4
            mulround 5
            mulround 6
            mulround 7

            pxor ACCM, ACC0
            pxor ACCM, ACC1
            movdqu T0, ACCM
            psrldq ACCM, 8
            pslldq T0, 8
            pxor ACC1, ACCM
            pxor ACC0, T0

            reduceround ACC0
            reduceround ACC0
            pxor ACC0, ACC1

            test ptxlen, ptxlen
            je gcmaesencdone

            sub r10, 7

gcmaesencsingles:
            
            movdqu B1, [ks+16]
            movdqu B2, [ks+32]
            movdqu B3, [ks+48]
            movdqu B4, [ks+64]
            movdqu B5, [ks+80]
            movdqu B6, [ks+96]
            movdqu B7, [ks+112]
            movdqu T2, [producttable+224]

gcmaesencsinglesloop:

            cmp ptxlen, 16
            jb gcmaesenctail
            sub ptxlen, 16

            movdqu B0, [rsp+128]
            increment 0

            aesenc B0, B1
            aesenc B0, B2
            aesenc B0, B3
            aesenc B0, B4
            aesenc B0, B5
            aesenc B0, B6
            aesenc B0, B7
            movdqu T0, [ks+128]
            aesenc B0, T0
            movdqu T0, [ks+144]
            aesenc B0, T0
            movdqu T0, [ks+160]
            cmp nr, 12
            jb enclast3
            aesenc B0, T0
            movdqu T0, [ks+176]
            aesenc B0, T0
            movdqu T0, [ks+192]
            je enclast3
            aesenc B0, T0
            movdqu T0, [ks+208]
            aesenc B0, T0
            movdqu T0, [ks+224]

enclast3:
            aesenclast B0, T0
            movdqu T0, [ptx]
            pxor B0, T0
            movdqu [ctx], B0

            pshufb B0, LBSWAP
            pxor B0, ACC0

            movdqu ACC0, T2
            movdqu ACC1, T2
            movdqu ACCM, [producttable+240]

            pshufd T0, B0, 78
            pxor T0, B0
            pclmulqdq ACC0, B0, 0
            pclmulqdq ACC1, B0, 17
            pclmulqdq ACCM, T0, 0

            pxor ACCM, ACC0
            pxor ACCM, ACC1
            movdqu T0, ACCM
            psrldq ACCM, 8
            pslldq T0, 8
            pxor ACC1, ACCM
            pxor ACC0, T0

            reduceround ACC0
            reduceround ACC0
            pxor ACC0, ACC1

            lea ptx, [ptx+16]
            lea ctx, [ctx+16]

        jmp gcmaesencsinglesloop

gcmaesenctail:
            test ptxlen, ptxlen
            je gcmaesencdone

            movdqu B0, [rsp+128]
            aesenc B0, B1
            aesenc B0, B2
            aesenc B0, B3
            aesenc B0, B4
            aesenc B0, B5
            aesenc B0, B6
            aesenc B0, B7
            movdqu T0, [ks+128]
            aesenc B0, T0
            movdqu T0, [ks+144]
            aesenc B0, T0
            movdqu T0, [ks+160]
            cmp nr, 12
            jb enclast4
            aesenc B0, T0
            movdqu T0, [ks+176]
            aesenc B0, T0
            movdqu T0, [ks+192]
            je enclast4
            aesenc B0, T0
            movdqu T0, [ks+208]
            aesenc B0, T0
            movdqu T0, [ks+224]

enclast4:
            aesenclast B0, T0
            movdqu T0, B0

            lea ptx, [ptx+ptxlen-1]
            mov r11, ptxlen
            shl r11, 4

            lea r10, [rel +Land_mask]
            movdqu T1, [r10+r11*1-16]

            pxor B0, B0

ptxloadloop:
            pslldq B0, 1
            pinsrb B0, [ptx], 0
            lea ptx, [ptx-1]
            dec ptxlen
        jne ptxloadloop

            pxor B0, T0
            pand B0, T1
            movdqu [ctx], B0
            pshufb B0, LBSWAP
            pxor B0, ACC0

            movdqu ACC0, T2
            movdqu ACC1, T2
            movdqu ACCM, [producttable+240]
            pshufd T0, B0, 78
            pxor T0, B0
            pclmulqdq ACC0, B0, 0
            pclmulqdq ACC1, B0, 17
            pclmulqdq ACCM, T0, 0

            pxor ACCM, ACC0
            pxor ACCM, ACC1
            movdqu T0, ACCM
            psrldq ACCM, 8
            pslldq T0, 8
            pxor ACC1, ACCM
            pxor ACC0, T0

            reduceround ACC0
            reduceround ACC0
            pxor ACC0, ACC1

gcmaesencdone:
            movdqu [tptr], ACC0
            mov rbp, [rsp+0x100]
            add rsp, 0x108
            ret

%undef producttable
%undef ctx
%undef ctrptr
%undef ptx
%undef ks
%undef tptr
%undef ptxlen
%undef nr