Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEVUQSJQMGQEFSHVFBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 344FD509AF5
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 10:47:16 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id n9-20020a056602340900b006572c443316sf1818212ioz.23
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 01:47:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650530835; cv=pass;
        d=google.com; s=arc-20160816;
        b=lMZ1eC4SQhpSfrVXn48pT2jbTDG0bNe2QIQcYy0ywcDbq6RrYgjnOEBPj7qRVSFGcr
         6WvILYazHecMdp8wMjCX2tQSQBn5sTH/t4e8cqe54LkSse+Kiki0UHo5NbfUqe1+IALH
         hrl+OGL8yq01I9f9ORZrEMqPsx7mnrvXrvN+LpdvNks4pukEvGvH9T7QP+/2OmUu8yxq
         9FzwXwX5YOyf1vzVnfzqJMibVxLb/nw5nWd+yM/FhaGoAnFRlnTvyogkh8lV9hSC6447
         0/qLumg1jsnVuZ16xKUDxfm9ETfsH8y5httxwy2xuZ2td273KcqxjqhPDJxhHWy4alCH
         OSgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qkHrAaRgLb8zBHtsfGkZN7zK6HjIq+YItCEXxnslooQ=;
        b=GQ1n8sx6LObu5NFlUGyvnXq9RUCM11/WMFXiuPr6FIBSP7uVO3T6tPmZADq/g7l8Kx
         zer3ac8MoHbKfEA3Cd9q0fKup2R9GbrR9Q/Ex4EMX4eaIh6yaF7mCyby7vuiig5zA5nU
         PrcalJJizKXcCfD1i25PFobY5P0wp4lGfTWSTOe8P8HM5d87lu7PjWzG1zHXwPC1oxAI
         tvUIb5ipiNo+d97nvnNJvSRO/NRkvxoVPh79Adw2N9KxvzV82/AdplIORyed+BUeE66E
         Ub+Nm3N0Dxg9kiqY5l7MhlQvXNjemdEz7+wobAUs0XXiLQtnJjnsW66OWVfIIY6iERxD
         T5Vg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HQ6BuTHE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qkHrAaRgLb8zBHtsfGkZN7zK6HjIq+YItCEXxnslooQ=;
        b=AYQAzJ3TkFIe52SbTafNi1a/zk/Kgdw0WPRnFc5NudjeZA+Arfg+z7bASpTJojK4Uj
         IVzgTVxlHWraTGYDDg7kZ+xvKE3kZlueCW7zjknQYsJEqnDv8wi4sxYSS+5cfwaRFdcM
         7DUgVeMTJG7NeYujbopWzCvCZoXWkgkaVAbZPnv9YIrvMA54ptcb7UV5TDXj1fr4nBqB
         TvByuAJxdIQN3j0+8TGNibd4HM2tgaJ80jCYT5klAyH4V225mOhMvYlkV4a4qbAxZ6xA
         sWCuUmrLit3jmuEKeeCytrs9vupYXadccBtOSP96cj2FVAgf0Gt3FeOfCZCxUizw9tHm
         shfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qkHrAaRgLb8zBHtsfGkZN7zK6HjIq+YItCEXxnslooQ=;
        b=SyLMe4KV6u9Jab6ng2SuphhkGLczOxYY7XuGzzQkc25+KLvB767Tle32Uow69oEIia
         3O25ZU4L2ZJz4wN/bXuxl0MHwsVC/hmtWYOZYX6JNozFICGjQpF8VXimNeX5prOExQpc
         byUgNh4hLcmPWqsTw6lD/ziw90q2xlbEFXCU4qNOrP0Wu2kcDPOR6wEErX/B7kJD254F
         74GjFiPC5gXeOy2s1DVuNhCkjtWiEncx4lHNGhNV9sGw/P5jNm9knfypy/hhiquVlLwn
         U8L7esnRmTNvJ2rpq7dQ8PiJ7JYqPwNlirxPtxwBt8fzRxKvNr9XEhXms7YwZ+13d+sd
         JsOg==
X-Gm-Message-State: AOAM533DWne8xkfKz8ZOHXp3C5DNxoW4mrOh9uf9oNOeBzgMHAKgFlQ9
	4glboa1Sta4U92d6EkG3SdQ=
X-Google-Smtp-Source: ABdhPJxamTt1mpsHlm8ohYQ+xJ2f1/3oqXKVnzGYy1tYeB/9J3l1bPFZntTiNjjNltUYWcIiLSUE7A==
X-Received: by 2002:a92:130f:0:b0:2cc:2590:766d with SMTP id 15-20020a92130f000000b002cc2590766dmr8398803ilt.270.1650530834871;
        Thu, 21 Apr 2022 01:47:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:6f4d:0:b0:326:5851:8cdf with SMTP id b13-20020a026f4d000000b0032658518cdfls1235593jae.11.gmail;
 Thu, 21 Apr 2022 01:47:14 -0700 (PDT)
X-Received: by 2002:a05:6638:258e:b0:32a:7db9:e769 with SMTP id s14-20020a056638258e00b0032a7db9e769mr4880833jat.113.1650530834388;
        Thu, 21 Apr 2022 01:47:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650530834; cv=none;
        d=google.com; s=arc-20160816;
        b=gEyFMUsqYqL6pnbuWVIBn2HXkODpWRHNc9+aXJtnbJSsgaQH1uP4ayguXoc3pIG7dl
         Mm1PIFuFdZvY53QzDgC7IesUmTu4hTBdTD81k/jqXPTTat3wnne2a5DfuaFdZlLhET4h
         LWn1tLf5PeJs2PmH93n7VAZYpI6FgQ9/7C2tjMbByxGsRVquMCWwraSDvL4Ha8Mzn0zI
         DOyJwXmuXDtLuSLtTfQ5y7eCFussGoDYq4BzSdxAv7+UVIMhnE7zSI4yhBmD6Io+8FFg
         ZCneb4752nabio1Epr1jR83LrK/xGsBzUmohWPUv9kUNkN0jaVa8uuvrMXlYL2Jq2YcR
         n7Zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AAlP0SwMAgEokpC45b/8A58tbYCJ2ulOw6rDhTTZvu8=;
        b=doB5CmK62T56RBESWRpV8xTNdPGZRD/itojT2IqcbRDmTpwtiroe8Tds2PIU4oH7Kf
         gNQamrzbXQ+oof2YsjVq0AEcUlmQ2qHsUssZyUUQT3eqGivTfWjOBZjbRq57a3bCMpAS
         v7i6NHJbMv2CK0vpF8Kpq7Ldrv/VKTyOHqM7u01Ixpmy2tvA22PI+Qfu4KEzX03DeAao
         ky56+0prdBHRR3hTDGH1mGChZdW/BKCzNq3JWpmwvXwCZNydVn/9Wd3fJunsEapL4B3h
         2fjki+AVg/jRR25YGRAHZ4zpLKX12XrsnKMXYzsiyglScYn1XIsAO5EUW8hv04k1p4zr
         +e0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HQ6BuTHE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id v6-20020a056e02164600b002cc062dcde7si336990ilu.0.2022.04.21.01.47.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Apr 2022 01:47:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id b26so1872308ybj.13
        for <kasan-dev@googlegroups.com>; Thu, 21 Apr 2022 01:47:14 -0700 (PDT)
X-Received: by 2002:a25:aaa4:0:b0:641:3506:900 with SMTP id
 t33-20020a25aaa4000000b0064135060900mr23664506ybi.87.1650530833852; Thu, 21
 Apr 2022 01:47:13 -0700 (PDT)
MIME-Version: 1.0
References: <20220420190805.152533-1-jcmvbkbc@gmail.com>
In-Reply-To: <20220420190805.152533-1-jcmvbkbc@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Apr 2022 10:46:37 +0200
Message-ID: <CANpmjNO4nXfqFYcS3xBREZ3TCTe_feOsBFqQ46YJUjSvLWUqGQ@mail.gmail.com>
Subject: Re: [PATCH v2] xtensa: enable KCSAN
To: Max Filippov <jcmvbkbc@gmail.com>
Cc: linux-xtensa@linux-xtensa.org, Chris Zankel <chris@zankel.net>, 
	linux-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=HQ6BuTHE;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as
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

On Wed, 20 Apr 2022 at 21:08, Max Filippov <jcmvbkbc@gmail.com> wrote:
>
> Prefix arch-specific barrier macros with '__' to make use of instrumented
> generic macros.
> Prefix arch-specific bitops with 'arch_' to make use of instrumented
> generic functions.
> Provide stubs for 64-bit atomics when building with KCSAN.
> Disable KCSAN instrumentation in arch/xtensa/boot.
>
> Signed-off-by: Max Filippov <jcmvbkbc@gmail.com>

Acked-by: Marco Elver <elver@google.com>

> ---
> Changes v1->v2:
>
> - fix __wmb definition to use __mb instead of mb
> - provide __smp_{,r,w}mb definitions because definitions from the
>   asm-generic use mb/rmb/wmb instead of __mb/__rmb/__wmb, thus
>   doubling KCSAN instrumentation.
>
>   Both changes fix a few failures in the KCSAN testsuite.
>
>  arch/xtensa/Kconfig               |  1 +
>  arch/xtensa/boot/lib/Makefile     |  1 +
>  arch/xtensa/include/asm/barrier.h | 12 +++++--
>  arch/xtensa/include/asm/bitops.h  | 10 +++---
>  arch/xtensa/lib/Makefile          |  2 ++
>  arch/xtensa/lib/kcsan-stubs.c     | 54 +++++++++++++++++++++++++++++++
>  6 files changed, 73 insertions(+), 7 deletions(-)
>  create mode 100644 arch/xtensa/lib/kcsan-stubs.c
>
> diff --git a/arch/xtensa/Kconfig b/arch/xtensa/Kconfig
> index 797355c142b3..c87f5ab493d9 100644
> --- a/arch/xtensa/Kconfig
> +++ b/arch/xtensa/Kconfig
> @@ -29,6 +29,7 @@ config XTENSA
>         select HAVE_ARCH_AUDITSYSCALL
>         select HAVE_ARCH_JUMP_LABEL if !XIP_KERNEL
>         select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
> +       select HAVE_ARCH_KCSAN
>         select HAVE_ARCH_SECCOMP_FILTER
>         select HAVE_ARCH_TRACEHOOK
>         select HAVE_CONTEXT_TRACKING
> diff --git a/arch/xtensa/boot/lib/Makefile b/arch/xtensa/boot/lib/Makefile
> index e3d717c7bfa1..162d10af36f3 100644
> --- a/arch/xtensa/boot/lib/Makefile
> +++ b/arch/xtensa/boot/lib/Makefile
> @@ -16,6 +16,7 @@ CFLAGS_REMOVE_inffast.o = -pg
>  endif
>
>  KASAN_SANITIZE := n
> +KCSAN_SANITIZE := n
>
>  CFLAGS_REMOVE_inflate.o += -fstack-protector -fstack-protector-strong
>  CFLAGS_REMOVE_zmem.o += -fstack-protector -fstack-protector-strong
> diff --git a/arch/xtensa/include/asm/barrier.h b/arch/xtensa/include/asm/barrier.h
> index d6f8d4ddc2bc..898ea397e9bc 100644
> --- a/arch/xtensa/include/asm/barrier.h
> +++ b/arch/xtensa/include/asm/barrier.h
> @@ -11,9 +11,15 @@
>
>  #include <asm/core.h>
>
> -#define mb()  ({ __asm__ __volatile__("memw" : : : "memory"); })
> -#define rmb() barrier()
> -#define wmb() mb()
> +#define __mb()  ({ __asm__ __volatile__("memw" : : : "memory"); })
> +#define __rmb() barrier()
> +#define __wmb() __mb()
> +
> +#ifdef CONFIG_SMP
> +#define __smp_mb() __mb()
> +#define __smp_rmb() __rmb()
> +#define __smp_wmb() __wmb()
> +#endif
>
>  #if XCHAL_HAVE_S32C1I
>  #define __smp_mb__before_atomic()              barrier()
> diff --git a/arch/xtensa/include/asm/bitops.h b/arch/xtensa/include/asm/bitops.h
> index cd225896c40f..e02ec5833389 100644
> --- a/arch/xtensa/include/asm/bitops.h
> +++ b/arch/xtensa/include/asm/bitops.h
> @@ -99,7 +99,7 @@ static inline unsigned long __fls(unsigned long word)
>  #if XCHAL_HAVE_EXCLUSIVE
>
>  #define BIT_OP(op, insn, inv)                                          \
> -static inline void op##_bit(unsigned int bit, volatile unsigned long *p)\
> +static inline void arch_##op##_bit(unsigned int bit, volatile unsigned long *p)\
>  {                                                                      \
>         unsigned long tmp;                                              \
>         unsigned long mask = 1UL << (bit & 31);                         \
> @@ -119,7 +119,7 @@ static inline void op##_bit(unsigned int bit, volatile unsigned long *p)\
>
>  #define TEST_AND_BIT_OP(op, insn, inv)                                 \
>  static inline int                                                      \
> -test_and_##op##_bit(unsigned int bit, volatile unsigned long *p)       \
> +arch_test_and_##op##_bit(unsigned int bit, volatile unsigned long *p)  \
>  {                                                                      \
>         unsigned long tmp, value;                                       \
>         unsigned long mask = 1UL << (bit & 31);                         \
> @@ -142,7 +142,7 @@ test_and_##op##_bit(unsigned int bit, volatile unsigned long *p)    \
>  #elif XCHAL_HAVE_S32C1I
>
>  #define BIT_OP(op, insn, inv)                                          \
> -static inline void op##_bit(unsigned int bit, volatile unsigned long *p)\
> +static inline void arch_##op##_bit(unsigned int bit, volatile unsigned long *p)\
>  {                                                                      \
>         unsigned long tmp, value;                                       \
>         unsigned long mask = 1UL << (bit & 31);                         \
> @@ -163,7 +163,7 @@ static inline void op##_bit(unsigned int bit, volatile unsigned long *p)\
>
>  #define TEST_AND_BIT_OP(op, insn, inv)                                 \
>  static inline int                                                      \
> -test_and_##op##_bit(unsigned int bit, volatile unsigned long *p)       \
> +arch_test_and_##op##_bit(unsigned int bit, volatile unsigned long *p)  \
>  {                                                                      \
>         unsigned long tmp, value;                                       \
>         unsigned long mask = 1UL << (bit & 31);                         \
> @@ -205,6 +205,8 @@ BIT_OPS(change, "xor", )
>  #undef BIT_OP
>  #undef TEST_AND_BIT_OP
>
> +#include <asm-generic/bitops/instrumented-atomic.h>
> +
>  #include <asm-generic/bitops/le.h>
>
>  #include <asm-generic/bitops/ext2-atomic-setbit.h>
> diff --git a/arch/xtensa/lib/Makefile b/arch/xtensa/lib/Makefile
> index 5848c133f7ea..d4e9c397e3fd 100644
> --- a/arch/xtensa/lib/Makefile
> +++ b/arch/xtensa/lib/Makefile
> @@ -8,3 +8,5 @@ lib-y   += memcopy.o memset.o checksum.o \
>            divsi3.o udivsi3.o modsi3.o umodsi3.o mulsi3.o \
>            usercopy.o strncpy_user.o strnlen_user.o
>  lib-$(CONFIG_PCI) += pci-auto.o
> +lib-$(CONFIG_KCSAN) += kcsan-stubs.o
> +KCSAN_SANITIZE_kcsan-stubs.o := n
> diff --git a/arch/xtensa/lib/kcsan-stubs.c b/arch/xtensa/lib/kcsan-stubs.c
> new file mode 100644
> index 000000000000..2b08faa62b86
> --- /dev/null
> +++ b/arch/xtensa/lib/kcsan-stubs.c
> @@ -0,0 +1,54 @@
> +// SPDX-License-Identifier: GPL-2.0
> +
> +#include <linux/bug.h>
> +#include <linux/types.h>
> +
> +void __atomic_store_8(volatile void *p, u64 v, int i)
> +{
> +       BUG();
> +}
> +
> +u64 __atomic_load_8(const volatile void *p, int i)
> +{
> +       BUG();
> +}
> +
> +u64 __atomic_exchange_8(volatile void *p, u64 v, int i)
> +{
> +       BUG();
> +}
> +
> +bool __atomic_compare_exchange_8(volatile void *p1, void *p2, u64 v, bool b, int i1, int i2)
> +{
> +       BUG();
> +}
> +
> +u64 __atomic_fetch_add_8(volatile void *p, u64 v, int i)
> +{
> +       BUG();
> +}
> +
> +u64 __atomic_fetch_sub_8(volatile void *p, u64 v, int i)
> +{
> +       BUG();
> +}
> +
> +u64 __atomic_fetch_and_8(volatile void *p, u64 v, int i)
> +{
> +       BUG();
> +}
> +
> +u64 __atomic_fetch_or_8(volatile void *p, u64 v, int i)
> +{
> +       BUG();
> +}
> +
> +u64 __atomic_fetch_xor_8(volatile void *p, u64 v, int i)
> +{
> +       BUG();
> +}
> +
> +u64 __atomic_fetch_nand_8(volatile void *p, u64 v, int i)
> +{
> +       BUG();
> +}
> --
> 2.30.2
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO4nXfqFYcS3xBREZ3TCTe_feOsBFqQ46YJUjSvLWUqGQ%40mail.gmail.com.
