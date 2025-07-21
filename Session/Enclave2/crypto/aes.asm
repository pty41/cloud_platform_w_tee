[BITS 64]
            ;section .data

            ;global hasaesni:function
            ;global expandkeyasm:function
            ;global hasgcmasm:function
            ;global foo:function
            ;global test:function

;---------------------------------------------------
          section .data
          global expandkeyasm:function
          section .text

expandkeyasm:
;
; define the paramter
;

;nr equ rdi
;key equ rsi
;enc equ rdx
;des equ rcx

%define nr rdi
%define key rsi
%define enc rdx
%define des rcx
;
            movdqu   xmm0, [key]          ; input
            movdqu   [enc], xmm0          ; output
            add      enc, 16
            pxor     xmm4, xmm4           ;_expand_key_* expect X4 to be zero
            cmp      nr, 12
            je       expenc192
            jb       expenc128
expenc256:
            movdqu   xmm2, [key+16]
            movdqu   [enc], xmm2
            add      enc, 16
            aeskeygenassist xmm1, xmm2, 1
            call     expand128
            aeskeygenassist xmm1, xmm0, 1
            call     expand256
            aeskeygenassist xmm1, xmm2, 2
            call     expand128
            aeskeygenassist xmm1, xmm0, 2
            call     expand256
            aeskeygenassist xmm1, xmm2, 4
            call     expand128
            aeskeygenassist xmm1, xmm0, 4
            call     expand256
            aeskeygenassist xmm1, xmm2, 8
            call     expand128
            aeskeygenassist xmm1, xmm0, 8
            call     expand256
            aeskeygenassist xmm1, xmm2, 16
            call     expand128
            aeskeygenassist xmm1, xmm0, 16
            call     expand256
            aeskeygenassist xmm1, xmm2, 32
            call     expand128
            aeskeygenassist xmm1, xmm0, 32
            call     expand256
            aeskeygenassist xmm1, xmm2, 64
            call     expand128
            jmp expdec
expenc192:
            movdqu   xmm2, [key+16]
            aeskeygenassist xmm1, xmm2, 1
            call     expand192a
            aeskeygenassist xmm1, xmm2, 2
            call     expand192b
            aeskeygenassist xmm1, xmm2, 4
            call     expand192a
            aeskeygenassist xmm1, xmm2, 8
            call     expand192b
            aeskeygenassist xmm1, xmm2, 16
            call     expand192a
            aeskeygenassist xmm1, xmm2, 32
            call     expand192b
            aeskeygenassist xmm1, xmm2, 64
            call     expand192a
            aeskeygenassist xmm1, xmm2, 128
            call     expand192b
            jmp expdec
expenc128:
            aeskeygenassist xmm1, xmm0, 1
            call     expand128
            aeskeygenassist xmm1, xmm0, 2
            call     expand128
            aeskeygenassist xmm1, xmm0, 4
            call     expand128
            aeskeygenassist xmm1, xmm0, 8
            call     expand128
            aeskeygenassist xmm1, xmm0, 16
            call     expand128
            aeskeygenassist xmm1, xmm0, 32
            call     expand128
            aeskeygenassist xmm1, xmm0, 64
            call     expand128
            aeskeygenassist xmm1, xmm0, 128
            call     expand128
            aeskeygenassist xmm1, xmm0, 27
            call     expand128
            aeskeygenassist xmm1, xmm0, 54
            call     expand128

expdec:
            sub      enc, 16
            movups   xmm1, [enc]
            movups   [des], xmm1
            dec      nr
expdecloop:
            movups   xmm1, [enc-16]
            aesimc   xmm0, xmm1
            movups   [des+16], xmm0
            sub      enc, 16
            add      des, 16
            dec      nr
            jnz      expdecloop
            movups   xmm0, [enc-16]
            movups   [des+16], xmm0
            ret

;----------------------------------------
          section .data
          section .text


expand128:
    pshufd   xmm1, xmm1, 255
    shufps   xmm4, xmm0, 16
    pxor     xmm0, xmm4
    shufps   xmm4, xmm0, 140
    pxor     xmm0, xmm4
    pxor     xmm0, xmm1
    movups   [enc], xmm0
    add      enc, 16
    ret
;----------------------------------------
          section .data
          section .text

expand192a:
    pshufd   xmm1, xmm1, 85
    shufps   xmm4, xmm0, 16
    pxor     xmm0, xmm4
    shufps   xmm4, xmm0, 140
    pxor     xmm0, xmm4
    pxor     xmm0, xmm1

    movaps   xmm5, xmm2
    movaps   xmm6, xmm2
    pslldq   xmm5, 4
    pshufd   xmm3, xmm0, 255
    pxor     xmm2, xmm3
    pxor     xmm2, xmm5

    movaps   xmm1, xmm0
    shufps   xmm6, xmm0, 68
    movups   [enc], xmm6
    shufps   xmm1, xmm2, 78
    movups   [enc+16], xmm1
    add      enc, 32
    ret
;----------------------------------------
          section .data
          section .text

expand192b:
    pshufd   xmm1, xmm1, 85
    shufps   xmm4, xmm0, 16
    pxor     xmm0, xmm4
    shufps   xmm4, xmm0, 140
    pxor     xmm0, xmm4
    pxor     xmm0, xmm1

    movaps   xmm5, xmm2
    pslldq   xmm5, 4
    pshufd   xmm3, xmm0, 255
    pxor     xmm2, xmm3
    pxor     xmm2, xmm5

    movups   [enc], xmm0
    add      enc, 16
    ret

;----------------------------------------
          section .data
          section .text

expand256:
    pshufd   xmm1, xmm1, 170
    shufps   xmm4, xmm2, 16
    pxor     xmm2, xmm4
    shufps   xmm4, xmm2, 140
    pxor     xmm2, xmm4
    pxor     xmm2, xmm1

    movdqu   [enc], xmm2
    add      enc, 16
    ret

%undef nr
%undef key
%undef enc
%undef des
;---------------------------------------------------

          section .data
          global encryptblockasm:function
          section .text

encryptblockasm:

%define nr rdi
%define xk rsi
%define dst rdx
%define src rcx

            movups xmm1, [xk]
            movups xmm0, [src]
            add xk, 16
            pxor xmm0, xmm1
            sub nr, 12
            je lenc192
            jb lenc128
lenc256:
            movups xmm1, [xk]
            aesenc xmm0, xmm1
            movups xmm1, [xk+16]
            aesenc xmm0, xmm1
            add xk, 32
lenc192:
            movups xmm1, [xk]
            aesenc xmm0, xmm1
            movups xmm1, [xk+16]
            aesenc xmm0, xmm1
            add xk, 32
lenc128:
            movups xmm1, [xk]
            aesenc xmm0, xmm1
            movups xmm1, [xk+16]
            aesenc xmm0, xmm1

            movups xmm1, [xk+32]
            aesenc xmm0, xmm1
            movups xmm1, [xk+48]
            aesenc xmm0, xmm1

            movups xmm1, [xk+64]
            aesenc xmm0, xmm1
            movups xmm1, [xk+80]
            aesenc xmm0, xmm1

            movups xmm1, [xk+96]
            aesenc xmm0, xmm1
            movups xmm1, [xk+112]
            aesenc xmm0, xmm1

            movups xmm1, [xk+128]
            aesenc xmm0, xmm1
            movups xmm1, [xk+144]
            aesenclast xmm0, xmm1
            movups [dst], xmm0
            ret

%undef nr
%undef xk
%undef dst
%undef src

;---------------------------------------------------

          section .data
          global decryptblockasm:function
          section .text

decryptblockasm:

%define nr rdi
%define xk rsi
%define dst rdx
%define src rcx

            movups xmm1, [xk]
            movups xmm0, [src]
            add xk, 16
            pxor xmm0, xmm1
            sub nr, 12
            je lenc192
            jb lenc128
ldec256:
            movups xmm1, [xk]
            aesdec xmm0, xmm1
            movups xmm1, [xk+16]
            aesdec xmm0, xmm1
            add xk, 32
ldec192:
            movups xmm1, [xk]
            aesdec xmm0, xmm1
            movups xmm1, [xk+16]
            aesdec xmm0, xmm1
            add xk, 32
ldec128:
            movups xmm1, [xk]
            aesdec xmm0, xmm1
            movups xmm1, [xk+16]
            aesdec xmm0, xmm1

            movups xmm1, [xk+32]
            aesdec xmm0, xmm1
            movups xmm1, [xk+48]
            aesdec xmm0, xmm1

            movups xmm1, [xk+64]
            aesdec xmm0, xmm1
            movups xmm1, [xk+80]
            aesdec xmm0, xmm1

            movups xmm1, [xk+96]
            aesdec xmm0, xmm1
            movups xmm1, [xk+112]
            aesdec xmm0, xmm1

            movups xmm1, [xk+128]
            aesdec xmm0, xmm1
            movups xmm1, [xk+144]
            aesdeclast xmm0, xmm1
            movups [dst], xmm0
            ret

%undef nr
%undef xk
%undef dst
%undef src

;---------------------------------------------------

          section .data
          global hasaesni:function
          section .text

hasaesni:
            xor   rax, rax          ;XORQ AX, AX - sets rax to 0
            inc   rax               ;INCL AX
            cpuid                   ;CPUID
            shr  rcx, 25            ;SHRQ $25, CX
            and  rcx, 1             ;ANDQ $1, CX
            mov  rax, rcx           ;MOVB CX, ret+0(FP)
            ret

;---------------------------------------------------
          section .data
          global hasgcmasm:function
          section .text

hasgcmasm:
            push rbp
            mov rbp, rsp
            mov [rbp-8], rdi
            xor   rax, rax;
            inc   rax;
            cpuid;
            mov rdx, rcx;
            shr rcx, 25;
            shr rdx, 1;
            and rcx, rdx;
            and rcx, 1;
            mov rax, [rbp-8]       ; There is an address at [ebp+8] that
            mov eax, [rax]
            lea edx, [rcx]
            mov rax, [rbp-8]
            mov [rax], edx
            ;nop
            ;add qword [rax], 10    ; Add the value 10 to the DWORD value that is at
            ;mov eax, [rbp+8]
            ;add dword [eax], 10
            pop rbp
            ret

;---------------------------------------------------

          section .data
          global foo:function
          section .text
foo:
            push rbp
            mov rbp, rsp
            mov [rbp-8], rdi
            xor   rax, rax
            inc   rax
            cpuid
            shr  rcx, 25 
            and  rcx, 1 
            mov rax, [rbp-8]       ; There is an address at [ebp+8] that
            mov eax, [rax]
            lea edx, [rcx]
            mov rax, [rbp-8]
            mov [rax], edx
            ;nop
            ;add qword [rax], 10    ; Add the value 10 to the DWORD value that is at
            ;mov eax, [rbp+8]
            ;add dword [eax], 10
            pop rbp
            ret
;---------------------------------------------------

          section .data
          global test:function
          section .text
test:
    movdqa   xmm0, [rcx]          ; input
    movdqa   [rdx], xmm0          ; output
    add      rdx, 10
    ret
