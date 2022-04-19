Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3MX7KJAMGQESYJKVOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 984A1506893
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Apr 2022 12:16:15 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id f6-20020a170902ab8600b0015895212d23sf9826699plr.6
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Apr 2022 03:16:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650363374; cv=pass;
        d=google.com; s=arc-20160816;
        b=vXt7uLZREHiJ44V9fcmTxuKmId4llc9FBbRs2cGOSAKx48YAWEkikQc2RSSUPZYglg
         gPoi5zs9A2HkpkwTuPAyZ+oMOxnZS1y84NqbmqfzSSzGXVpb5Zlg/I80Y7MfOF1te1on
         O5RSj3Brd2nh1cd6N77Xixgls9VstMgSd6nlGG30eO7JPC+ti+ynzK2zYWDUph1ErWzF
         hmQPAKliKXhJJEIk5zWLJbalRdPMTJFiKYhgkXWbuDHJTtOdLTuJPus94nwMii2g7e6Q
         h5FExyUQQ/LBfLL4r+QHTihj/+7X7ct3Ru7AI9jVksVskjEE9Io7loo/b0f9yweLxtJk
         y3Vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vCJ9JaYnFN3ZsYJ99YNlcG/Rcf6BpULN0SzPTMBg1ec=;
        b=zd5Dz2Nqfk0Lr/YBHFcRmRxXpDtVCpmKdjjTWuR9/hiq9QsD1s9Ez3bI4n549NHU5P
         e4c33i71gpoaYrJeOENLS+OfEwudgQoc5UZgqumx9UvssfB9yb0kIE8+4JX+ZFSoD3HY
         u6OEj2Bh1TO75dveAzy8658k/H+vF+eLAWpaUyW433z7LWF6N0H7hxDD2tXwDPM1RlmT
         frxiCHBxTctZXhR250G2b8Q5yzh3L7K5wzHE0EgOLXUiS1zg0Wb0vv4Ilk0bxR4vl6Qh
         8/6aP0upfopnOUwAGI9KMCAh1ANvzFNPeaDsASiuDDc7BWjhhJlZxmMvVbPIAF3MQE+X
         CSDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qShyWJlk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vCJ9JaYnFN3ZsYJ99YNlcG/Rcf6BpULN0SzPTMBg1ec=;
        b=fNBeZFNQsmuA84jph/6p/lSA4y1mTAEoWmRBJ2sNAS6fx1S0YaTBJJVIqMPlCpCuXa
         DzzAWLnrlvydm+XnI821V9jZVGlo/0z/bWhX/8Uh7cMLZzaXz2Ympn7O0BjVEMHEa7fI
         +x+9lFN4cOHtaP9k7I/fZMR6ft7i3tsTDPr0CMY+S1IHLWRbu4tSguHM+t3xcoaTr2cM
         +G+2PKVus+9O/PzqI745V8m1D+/kUV0jYE9U6oFLvpRaPC5NqXbg1xzU/YwdzsymeuvN
         aMyL2olc/R0gDdkjpSTCv0Ujd+ZW4ZSjVfD0tl7BGD8JCTaVQ8jG8Eldt+QAvP4Lm/ir
         H20w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vCJ9JaYnFN3ZsYJ99YNlcG/Rcf6BpULN0SzPTMBg1ec=;
        b=fvKvYYWJAFpB9jmGrKgOG4IVORLvLfz4geRzFiYXN9v7ccgqKI+hsyvEk5eX+t6XA+
         +rlvtWEpMis59G8h5fWPY6/ubAkAXf39IrBB/trG6P2MMXzwEvWRv1b/AbcMa5dez9bE
         x7LoTWeXNHeyk7wEHhYXhnhjhzFp2ujYgzS3G+xJMFDIkh+nSDuE69dMaqnxhl0aJmju
         bVM8CTGB0AQpvF3+eE+/U2/bpqteS9WdzPETA7vJ4C6HVwReGMQXLXKPJS17DKsty1y4
         oM67TsJXYB+R4ZARn7RKrQU/Db9u0DFdBWV1Ie6ZV3KJHidDpWVkTnYUsVHvHw2NS0oH
         Datg==
X-Gm-Message-State: AOAM531PVu8ustSsXZgunaBFTRpS9SfMXYuZDyQo8jQcn1++4Ez2lfp6
	ecxO7aQhh6BEZFmQlbs6Mqw=
X-Google-Smtp-Source: ABdhPJwQE/vupf2m4qBXCu74EkiYsnAUhLfFR17NfYk++u2cPl4iqg/sq6I1kI5osjyVYPdbkqKc8w==
X-Received: by 2002:a17:902:7686:b0:156:47a4:fc8f with SMTP id m6-20020a170902768600b0015647a4fc8fmr14878084pll.98.1650363373903;
        Tue, 19 Apr 2022 03:16:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:db0b:b0:159:5a6:28f8 with SMTP id
 m11-20020a170902db0b00b0015905a628f8ls4248173plx.4.gmail; Tue, 19 Apr 2022
 03:16:13 -0700 (PDT)
X-Received: by 2002:a17:90b:1e0c:b0:1d2:7f67:f56c with SMTP id pg12-20020a17090b1e0c00b001d27f67f56cmr13193156pjb.69.1650363373162;
        Tue, 19 Apr 2022 03:16:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650363373; cv=none;
        d=google.com; s=arc-20160816;
        b=AYvRZ6R2OCZR6FN0C2obFnLMVO2BN3HUNAFKId6Ts+0ldVq2eKXYJK3DCoCBsSeToq
         S69kYIwzbYlwivtHaeICa2h82sGCy6/AsYyx9lMCkFqE9EawBzC70V4l1cpYQ67egsny
         Qkr3UxPV0jAn3N1QlkJVPwM48GSBaRGMglqxBw12q7bJ68gwy+z8jlArYws2kIVM59eg
         h17zp5Rx7znALSLUamFAyM5bFse0DBRKvHwfQeRwDX7Q8ER4PNaZfqzXN7uxgvZkKJh/
         iLzTzuPO+MOvVpSkRh1e0q6yX6R8spKqGJdBSN0Vvu+7mzV2IH8Kz7PwNpkKMZJnMmaN
         livQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0A8yKiNSIzt01Wdi2DEzhHefwHABBkNja1VeDIka0hE=;
        b=fgkZ4r3WtgU4PykwnM0c4onk2eS7xcCSBW2H86w6ADhWrpNrdAYLPer2PSO4uV+nnI
         gshuKnbQsj7UjkfRzuC+ANEHJ71iw6WjDjVfCEF9AxNMRgH5K+A9ACFbBUznPZgZ+Csx
         dtiVJin5rQhUL4qt5Q2q4ZvKu1a8dbI2Aqm0jMn7UNh3iie/8BmGZ9bOgqa2NTNZLQqG
         uY389Rd9CdtCYtykYvZuK3mQ+IoAb4NXlksyyA+P3fUX5CgdZ4vS8IUC1v4NDacAQbJ/
         ZzNgs34FR4ZPnjvKn1WOsUNI6TknFhvlkT1RQh5wXWTKqfbSxSJC4suW+j/OTbo8Vpml
         wd1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qShyWJlk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1131.google.com (mail-yw1-x1131.google.com. [2607:f8b0:4864:20::1131])
        by gmr-mx.google.com with ESMTPS id u12-20020a62d44c000000b004e1a39c4e87si1338159pfl.0.2022.04.19.03.16.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Apr 2022 03:16:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) client-ip=2607:f8b0:4864:20::1131;
Received: by mail-yw1-x1131.google.com with SMTP id 00721157ae682-2f19fdba41fso41052137b3.3
        for <kasan-dev@googlegroups.com>; Tue, 19 Apr 2022 03:16:13 -0700 (PDT)
X-Received: by 2002:a81:5781:0:b0:2ef:6043:f3d2 with SMTP id
 l123-20020a815781000000b002ef6043f3d2mr14398581ywb.316.1650363372366; Tue, 19
 Apr 2022 03:16:12 -0700 (PDT)
MIME-Version: 1.0
References: <20220416081355.2155050-1-jcmvbkbc@gmail.com>
In-Reply-To: <20220416081355.2155050-1-jcmvbkbc@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Apr 2022 12:15:36 +0200
Message-ID: <CANpmjNNW0kLf2Ou6i_dNeRLO=Qrru4bOEfJ=be=Dfig4wnQ67g@mail.gmail.com>
Subject: Re: [PATCH] xtensa: enable KCSAN
To: Max Filippov <jcmvbkbc@gmail.com>
Cc: linux-xtensa@linux-xtensa.org, Chris Zankel <chris@zankel.net>, 
	linux-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qShyWJlk;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as
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

Nice to see this happen!

On Sat, 16 Apr 2022 at 10:14, Max Filippov <jcmvbkbc@gmail.com> wrote:
>
> Prefix arch-specific barrier macros with '__' to make use of instrumented
> generic macros.
> Prefix arch-specific bitops with 'arch_' to make use of instrumented
> generic functions.

> Provide stubs for 64-bit atomics when building with KCSAN.

The stubs are the only thing I don't understand. More elaboration on
why this is required would be useful (maybe there's another way to
solve?).

> Disable KCSAN instrumentation in arch/xtensa/boot.

Given you went for barrier instrumentation, I assume you tested with a
CONFIG_KCSAN_STRICT=y config? Did the kcsan_test pass?

> Signed-off-by: Max Filippov <jcmvbkbc@gmail.com>
> ---
>  arch/xtensa/Kconfig               |  1 +
>  arch/xtensa/boot/lib/Makefile     |  1 +
>  arch/xtensa/include/asm/barrier.h |  6 ++--
>  arch/xtensa/include/asm/bitops.h  | 10 +++---
>  arch/xtensa/lib/Makefile          |  2 ++
>  arch/xtensa/lib/kcsan-stubs.c     | 54 +++++++++++++++++++++++++++++++
>  6 files changed, 67 insertions(+), 7 deletions(-)
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
> index d6f8d4ddc2bc..a22d4bb08159 100644
> --- a/arch/xtensa/include/asm/barrier.h
> +++ b/arch/xtensa/include/asm/barrier.h
> @@ -11,9 +11,9 @@
>
>  #include <asm/core.h>
>
> -#define mb()  ({ __asm__ __volatile__("memw" : : : "memory"); })
> -#define rmb() barrier()
> -#define wmb() mb()
> +#define __mb()  ({ __asm__ __volatile__("memw" : : : "memory"); })
> +#define __rmb() barrier()
> +#define __wmb() mb()
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
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220416081355.2155050-1-jcmvbkbc%40gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNW0kLf2Ou6i_dNeRLO%3DQrru4bOEfJ%3Dbe%3DDfig4wnQ67g%40mail.gmail.com.
