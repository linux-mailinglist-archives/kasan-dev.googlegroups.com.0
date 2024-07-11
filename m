Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK6BX22AMGQEEHQNZCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9ACE392E319
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Jul 2024 11:06:53 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-5c6612eb700sf378956eaf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Jul 2024 02:06:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1720688812; cv=pass;
        d=google.com; s=arc-20160816;
        b=wAWIvR1EBuj/jA22NvU7e88Tq+pBTBaWKDvNP9rpFF5CDotLdMNUXWjoRVj/kQS1dd
         AQw4dnUBc14bxdjkAyjqyOS5bQ2PnpVdFpqfvWYZZRKn+Bb+kcM9mM0228q35Kz/JDDf
         iFbLk1K/6jU75J15HpXXutopuR6d7SrYmhBzoLlGRFYwq1Tcm2tqGZSJhGj2gRDikJx4
         R1N9PqKtM1TAgPxq2XV511FGEm9OBseK+j8yCZKkYDKrzp0LJ97/bls5jElhXoyvxd1U
         haomLCyMHjX+tzySTR1g+Sn+/i2ZgHk9QZ9ODUbhMH9hHQ+AYedScQln/d3OYtyiNcQN
         pA+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nvbWfD1JhY4Hd1b7NKHt7ifBBIh6yozrRCeyLc1yq70=;
        fh=yjOoxa4V574tLbqdTUG+8WbtJ0+pD94Nkk9z+aDWPRA=;
        b=qT0ySri7foYKRpCKD5MNNSXJpVVvLuwRNjhoS2LLob0YyqUbQHPka5zmSYKXsZ/Wr+
         d4SliwN7HXaLHWIEPHT4sUjqqQuMoh3oXGIysi/WWWk2dfYjVvz5LfI/qY/97LDvXmYW
         P+cDkurPOc5N7+jJE8rXsZi1stEVLnetAWN73hiKDgZ2zqjafh4PH4ZWuQcMP0iio5EG
         8GMvZt3zgFmjw5/dIi8Mscu2D+QItndC1q6+sde34UHJlfu2rsOg8B9Fah6zi6ViKZrH
         pWZs89IEnGKDgRocU7aKg7c4VMt42tfZvCDMtJIvJkmVTE15f6XfFa24BsCKKeyEECvA
         YKmA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Psxc5g8E;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::936 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1720688812; x=1721293612; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nvbWfD1JhY4Hd1b7NKHt7ifBBIh6yozrRCeyLc1yq70=;
        b=ZFRwx+8ebZDBwNxAkQULgWTU+zDSaaD/GGDmJxsBMcon9hF0XVd0c++iRro6reAk8C
         bYCUdbLr6njWeGjQmuGt82ZCUuiAar70zM9Unl/IPhQ0ZwNHiPwFjLj2Ba9DyDW4Z8Xg
         Gls3pcIkRRUzJWQDjaeOTvZGy7jH6wa6FnubRvobTDHbVydrvmTRHtG/TV3lGGsKPmdb
         BO4UiNXOUjCZ2GujL9XXF31zgol8CIWLy6zT+ls+oJM4a7Cmv3KxqG66WnWW9aUdDZDB
         QPBYM8pchPITlNA0rF3cfIco/nCZResr/DLHcYoJizSFtY15naPOhJHP86ZTAEO52IH3
         AagA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1720688812; x=1721293612;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nvbWfD1JhY4Hd1b7NKHt7ifBBIh6yozrRCeyLc1yq70=;
        b=iCuGx3PwRI3KqCTbUqt5nTcFA3h+M937S+Wmtu97od7YWcas8jpbfOu+qKz+kkOrqU
         a/CQFQYbccZXTiTIwLE/E7mssBH7h5yElLhg54T1gdQKjUC9uCygwsI6/JoQPef9HJeQ
         3qNUt4my5Giw+4ccPy4Y0nlMUcho28usuLKy3sCBIlgfgiOWT+lTWOa8+8yBA03+RrYX
         JT0ALvICoHjJyXAoA0NQmh1tYARiCNNGhom6jhsoIUoJ+nWBPnomlO1oQiZFQLZ6eU/F
         m66moSJprePuVKnEG/c16p4eiLZJEq6PlgytOaEW1V/TFeparLe0IgesCZ3wTEo4Bws7
         CBOg==
X-Forwarded-Encrypted: i=2; AJvYcCXTjpzeD5Mg4Z2vox/26jQbjvsvoSdjP5tymfdJN2jdNHpsSJ1FI48IX6ndvmYMvEePGwUkM2SckQ8adMJ/PvSv/GfTHpNc9A==
X-Gm-Message-State: AOJu0Yy1Y6vtXuX+XERjdhf3VfWAJJCGTWFE9GBPOwWRZf7FDTVBu5JF
	5uvNdng+jZUGFwSoO0QE/kFGD4cwuEmEcRQivxf3PxLqdzgzXMGO
X-Google-Smtp-Source: AGHT+IHct+iiLh4mh30yaa9eQa/i+ekr8UZNmxhsg+80cOKhdmVo0D/zmjE/3S5QFrKChEGt5CmftQ==
X-Received: by 2002:a4a:b445:0:b0:5c6:6162:6869 with SMTP id 006d021491bc7-5ca895120e6mr906649eaf.0.1720688811931;
        Thu, 11 Jul 2024 02:06:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d121:0:b0:5c4:7476:39ec with SMTP id 006d021491bc7-5caad7fe46cls183378eaf.0.-pod-prod-00-us;
 Thu, 11 Jul 2024 02:06:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVU48Kc1RPUCjg4HX3VLZ9rUe9rM8mPVwCsxgX7CsgfGDfqIrAsjcbQEeq9Ekoe8feoXwHA6vd6fqznQR13pw29o4Mwc+yFQX02Cw==
X-Received: by 2002:a05:6808:2d7:b0:3d9:3b45:f56b with SMTP id 5614622812f47-3da9fe6e8f4mr689257b6e.12.1720688810967;
        Thu, 11 Jul 2024 02:06:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1720688810; cv=none;
        d=google.com; s=arc-20160816;
        b=YnYbeekMrRhFDOo7n+F12wGIRkPniEtifwKp6SNfPI+rdxAf7qXiG53kORkniPrPlO
         gr4xp/ZSXZtSEQmCLPwZStbF4ApNKxGFpsP8UY1lQWvNwZVeP2VpmqdBxNDtq9s/ExV2
         cg0z0vPscB5V9ygW02NKzcxCF4WeMJyxw4INq6JxX93VG/Zh8pvQ9RxdO4S6LhEWJQri
         zVTA9nNTlMgZniQCL8N/mpLzfCjKNhydYnC36CQcU+8QuupyYcqIyHt93/hZYYCGMXg9
         5VXONct4eHy2g/0ArOCh88EF24K9/ZHslszJWR4TLOPW517iED4/f4/bRt+/Sl276Xfp
         baJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ehnNMNXfvb4vki4ExU1sjmRzfNAU6K60o3BlICJME1k=;
        fh=7WZzfeCbnsfAvzn2mPGJP9UeFKLGb5NNIVG/OH0g4/U=;
        b=CuNGbGbJN1G6SCgXTeUtq530Fhw8PohGGaHqpk6qwlkYpG4QStmYkfJTX+EGTdG8A1
         aIzaK4g140fVUfKRd6vlT4DMfwHIUv0h3LUoAAYop0dXrJ8mo+EmOBqAowteuPOLVzHt
         /Dg3eTmZkQo6OImkaRHC2+IRAyMPoZlIJ44wL8X+CFIVOrP2zapqBR45EjsnU93jNOM+
         5rgIWkXbahtotw/GGckGOKogB2RaIGjcSBT0Jri4OFQizAKyU/af8yCZyZ4F9uwSKtXq
         hvv9zNqd1N+2oAurfgnyzEX8kL6jws8NIoV0w2w6qo22bUNGQ6oi7rhIdRnysEqLvGyx
         FK7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Psxc5g8E;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::936 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x936.google.com (mail-ua1-x936.google.com. [2607:f8b0:4864:20::936])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-25ea9c2c72esi321659fac.0.2024.07.11.02.06.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Jul 2024 02:06:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::936 as permitted sender) client-ip=2607:f8b0:4864:20::936;
Received: by mail-ua1-x936.google.com with SMTP id a1e0cc1a2514c-80fe89eaa4dso801523241.1
        for <kasan-dev@googlegroups.com>; Thu, 11 Jul 2024 02:06:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXWXsw7k9su62kiulet4zDZkPsM8/A6+q9NylLiM4mdCbsMj+bhlKE8DyMIAV0K026WzPAR+ZXk3vS/724TQ92cvGshBtWVR0nuIg==
X-Received: by 2002:a05:6102:3e02:b0:48f:968b:1714 with SMTP id
 ada2fe7eead31-491119541f8mr377121137.11.1720688810066; Thu, 11 Jul 2024
 02:06:50 -0700 (PDT)
MIME-Version: 1.0
References: <20240710203250.238782-1-gatlin.newhouse@gmail.com> <20240711081031.GB4587@noisy.programming.kicks-ass.net>
In-Reply-To: <20240711081031.GB4587@noisy.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Jul 2024 11:06:12 +0200
Message-ID: <CANpmjNObEzShHvw19EAntPvCYJbqezKBq+pB=mkd7j3sXDEE7A@mail.gmail.com>
Subject: Re: [PATCH v4] x86/traps: Enable UBSAN traps on x86
To: Peter Zijlstra <peterz@infradead.org>
Cc: Gatlin Newhouse <gatlin.newhouse@gmail.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Kees Cook <keescook@chromium.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Baoquan He <bhe@redhat.com>, 
	Rick Edgecombe <rick.p.edgecombe@intel.com>, Pengfei Xu <pengfei.xu@intel.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Changbin Du <changbin.du@huawei.com>, Xin Li <xin3.li@intel.com>, 
	Jason Gunthorpe <jgg@ziepe.ca>, Arnd Bergmann <arnd@arndb.de>, 
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org, 
	llvm@lists.linux.dev, t.p.northover@gmail.com, 
	Fangrui Song <maskray@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Psxc5g8E;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::936 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Thu, 11 Jul 2024 at 10:10, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Wed, Jul 10, 2024 at 08:32:38PM +0000, Gatlin Newhouse wrote:
> > Currently ARM architectures extract which specific sanitizer
> > has caused a trap via encoded data in the trap instruction.
> > Clang on x86 currently encodes the same data in ud1 instructions
> > but the x86 handle_bug() and is_valid_bugaddr() functions
> > currently only look at ud2s.
> >
> > Bring x86 to parity with arm64, similar to commit 25b84002afb9
> > ("arm64: Support Clang UBSAN trap codes for better reporting").
> > Enable the reporting of UBSAN sanitizer detail on x86 architectures
> > compiled with clang when CONFIG_UBSAN_TRAP=y.
>
> Can we please get some actual words on what code clang will generate for
> this? This doesn't even refer to the clang commit.
>
> How am I supposed to know if the below patch matches what clang will
> generate etc..

I got curious what the history of this is - I think it was introduced
in https://github.com/llvm/llvm-project/commit/c5978f42ec8e9, which
was reviewed here: https://reviews.llvm.org/D89959

But besides that, there's very little documentation. Either Gatlin or
one of the other LLVM folks might have more background, but we might
be out of luck if that 1 commit is all there is.

[+Cc Tim, author of the LLVM commit]

> > diff --git a/arch/x86/include/asm/bug.h b/arch/x86/include/asm/bug.h
> > index a3ec87d198ac..ccd573d58edb 100644
> > --- a/arch/x86/include/asm/bug.h
> > +++ b/arch/x86/include/asm/bug.h
> > @@ -13,6 +13,17 @@
> >  #define INSN_UD2     0x0b0f
> >  #define LEN_UD2              2
> >
> > +/*
> > + * In clang we have UD1s reporting UBSAN failures on X86, 64 and 32bit.
> > + */
> > +#define INSN_ASOP    0x67
>
> I asked, but did not receive answer, *WHY* does clang add this silly
> prefix? AFAICT this is entirely spurious and things would be simpler if
> we don't have to deal with it.
>
> > +#define OPCODE_PREFIX        0x0f
>
> This is *NOT* a prefix, it is an escape, please see the SDM Vol 2
> Chapter 'Instruction Format'. That ASOP thing above is a prefix.
>
> > +#define OPCODE_UD1   0xb9
> > +#define OPCODE_UD2   0x0b
>
> These are second byte opcodes. The actual (single byte opcodes) of those
> value exist and are something entirely different (0xB0+r is MOV, and
> 0x0B is OR).
>
> > +#define BUG_NONE     0xffff
> > +#define BUG_UD1              0xfffe
> > +#define BUG_UD2              0xfffd
>
> These are return codes and not related to the defines above and as such
> should be separated from them with some whitespace.
>
> > +
> >  #ifdef CONFIG_GENERIC_BUG
> >
> >  #ifdef CONFIG_X86_32
> > diff --git a/arch/x86/include/asm/ubsan.h b/arch/x86/include/asm/ubsan.h
> > new file mode 100644
> > index 000000000000..ac2080984e83
> > --- /dev/null
> > +++ b/arch/x86/include/asm/ubsan.h
> > @@ -0,0 +1,23 @@
> > +/* SPDX-License-Identifier: GPL-2.0 */
> > +#ifndef _ASM_X86_UBSAN_H
> > +#define _ASM_X86_UBSAN_H
> > +
> > +/*
> > + * Clang Undefined Behavior Sanitizer trap mode support.
> > + */
> > +#include <linux/bug.h>
> > +#include <linux/ubsan.h>
> > +#include <asm/ptrace.h>
> > +
> > +/*
> > + * UBSAN uses the EAX register to encode its type in the ModRM byte.
>
> This is a claim, but I have nothing to verify this against. I mean, I
> could go trawl through the clang sources, but this really should be part
> of the changelog to explain the clang code generation.
>
> > + */
> > +#define UBSAN_REG    0x40
>
> This is a ModRM byte, not a REG. The REG encoded therein is 0.
>
> > +
> > +#ifdef CONFIG_UBSAN_TRAP
> > +void handle_ubsan_failure(struct pt_regs *regs, u16 insn);
> > +#else
> > +static inline void handle_ubsan_failure(struct pt_regs *regs, u16 insn) { return; }
> > +#endif /* CONFIG_UBSAN_TRAP */
> > +
> > +#endif /* _ASM_X86_UBSAN_H */
> > diff --git a/arch/x86/kernel/Makefile b/arch/x86/kernel/Makefile
> > index 74077694da7d..fe1d9db27500 100644
> > --- a/arch/x86/kernel/Makefile
> > +++ b/arch/x86/kernel/Makefile
> > @@ -145,6 +145,7 @@ obj-$(CONFIG_UNWINDER_GUESS)              += unwind_guess.o
> >  obj-$(CONFIG_AMD_MEM_ENCRYPT)                += sev.o
> >
> >  obj-$(CONFIG_CFI_CLANG)                      += cfi.o
> > +obj-$(CONFIG_UBSAN_TRAP)             += ubsan.o
> >
> >  obj-$(CONFIG_CALL_THUNKS)            += callthunks.o
> >
> > diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> > index 4fa0b17e5043..b6664016622a 100644
> > --- a/arch/x86/kernel/traps.c
> > +++ b/arch/x86/kernel/traps.c
> > @@ -67,6 +67,7 @@
> >  #include <asm/vdso.h>
> >  #include <asm/tdx.h>
> >  #include <asm/cfi.h>
> > +#include <asm/ubsan.h>
> >
> >  #ifdef CONFIG_X86_64
> >  #include <asm/x86_init.h>
> > @@ -91,6 +92,45 @@ __always_inline int is_valid_bugaddr(unsigned long addr)
> >       return *(unsigned short *)addr == INSN_UD2;
> >  }
> >
> > +/*
> > + * Check for UD1 or UD2, accounting for Address Size Override Prefixes.
> > + * If it's a UD1, get the ModRM byte to pass along to UBSan.
> > + */
> > +__always_inline int decode_bug(unsigned long addr, u32 *imm)
> > +{
> > +     u8 v;
> > +
> > +     if (addr < TASK_SIZE_MAX)
> > +             return BUG_NONE;
> > +
> > +     v = *(u8 *)(addr++);
> > +     if (v == INSN_ASOP)
> > +             v = *(u8 *)(addr++);
> > +     if (v != OPCODE_PREFIX)
> > +             return BUG_NONE;
> > +
> > +     v = *(u8 *)(addr++);
> > +     if (v == OPCODE_UD2)
> > +             return BUG_UD2;
> > +     if (v != OPCODE_UD1)
> > +             return BUG_NONE;
> > +
> > +     v = *(u8 *)(addr++);
> > +     if (X86_MODRM_RM(v) == 4)
> > +             addr++;
> > +
> > +     *imm = 0;
> > +     if (X86_MODRM_MOD(v) == 1)
> > +             *imm = *(u8 *)addr;
> > +     else if (X86_MODRM_MOD(v) == 2)
> > +             *imm = *(u32 *)addr;
> > +     else
> > +             WARN_ONCE(1, "Unexpected MODRM_MOD: %u\n", X86_MODRM_MOD(v));
> > +
> > +     return BUG_UD1;
> > +}
> > +
> > +
> >  static nokprobe_inline int
> >  do_trap_no_signal(struct task_struct *tsk, int trapnr, const char *str,
> >                 struct pt_regs *regs, long error_code)
> > @@ -216,6 +256,8 @@ static inline void handle_invalid_op(struct pt_regs *regs)
> >  static noinstr bool handle_bug(struct pt_regs *regs)
> >  {
> >       bool handled = false;
> > +     int ud_type;
> > +     u32 imm;
> >
> >       /*
> >        * Normally @regs are unpoisoned by irqentry_enter(), but handle_bug()
> > @@ -223,7 +265,8 @@ static noinstr bool handle_bug(struct pt_regs *regs)
> >        * irqentry_enter().
> >        */
> >       kmsan_unpoison_entry_regs(regs);
> > -     if (!is_valid_bugaddr(regs->ip))
> > +     ud_type = decode_bug(regs->ip, &imm);
> > +     if (ud_type == BUG_NONE)
> >               return handled;
> >
> >       /*
> > @@ -236,10 +279,14 @@ static noinstr bool handle_bug(struct pt_regs *regs)
> >        */
> >       if (regs->flags & X86_EFLAGS_IF)
> >               raw_local_irq_enable();
> > -     if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
> > -         handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
> > -             regs->ip += LEN_UD2;
> > -             handled = true;
> > +     if (ud_type == BUG_UD2) {
> > +             if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
> > +                 handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
> > +                     regs->ip += LEN_UD2;
> > +                     handled = true;
> > +             }
> > +     } else {
> > +             handle_ubsan_failure(regs, imm);
> >       }
> >       if (regs->flags & X86_EFLAGS_IF)
> >               raw_local_irq_disable();
> > diff --git a/arch/x86/kernel/ubsan.c b/arch/x86/kernel/ubsan.c
> > new file mode 100644
> > index 000000000000..c90e337a1b6a
> > --- /dev/null
> > +++ b/arch/x86/kernel/ubsan.c
> > @@ -0,0 +1,21 @@
> > +// SPDX-License-Identifier: GPL-2.0
> > +/*
> > + * Clang Undefined Behavior Sanitizer trap mode support.
> > + */
> > +#include <linux/bug.h>
> > +#include <linux/string.h>
> > +#include <linux/printk.h>
> > +#include <linux/ubsan.h>
> > +#include <asm/ptrace.h>
> > +#include <asm/ubsan.h>
> > +
> > +/*
> > + * Checks for the information embedded in the UD1 trap instruction
> > + * for the UB Sanitizer in order to pass along debugging output.
> > + */
> > +void handle_ubsan_failure(struct pt_regs *regs, u16 type)
> > +{
> > +     if ((type & 0xFF) == UBSAN_REG)
> > +             type >>= 8;
>
> This makes no sense, we've consumed the ModRM byte ealier, this should
> really only ever get the immediate.
>
> > +     pr_crit("%s at %pS\n", report_ubsan_failure(regs, type), (void *)regs->ip);
> > +}
> > --
> > 2.25.1
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNObEzShHvw19EAntPvCYJbqezKBq%2BpB%3Dmkd7j3sXDEE7A%40mail.gmail.com.
