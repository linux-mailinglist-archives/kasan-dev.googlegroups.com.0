Return-Path: <kasan-dev+bncBD52JJ7JXILRB5VCQ2JQMGQE5DU7FTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 1466950A6DA
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 19:16:40 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 16-20020a17090a0a9000b001d48f5547fbsf2414342pjw.9
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 10:16:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650561398; cv=pass;
        d=google.com; s=arc-20160816;
        b=RnwMAD5/rZbatSpSBvvlYed/U4BeatqLAuzJe98gtXC/F11sYnlvv4Y1xDNWUpAgvU
         PGhCw0L5zmNuQnC+o7AGwXEtw60PM8v7drMzhFOGGK7rfeTaQEOshZG1SqlA7yWHDQNt
         2s1jK3Jpss8ImWEjQMHBrrclutZVdhh3BE/y+T9S5wDZb7TY+jQzm7U9wUAN9hUsdvxa
         w1sT70FF7aNRDZHqMsCyjCx3x0efAL22Ayt+p5kLkzj5nKBIvmHuNJ345RUCmY0LphzX
         ycI6DeeHRGtRRqF7m/GgziN1hNDdaY7IJK1yDYvn0VoavOUshDyWfxhRyiCYoty1DNTK
         Js1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=63QhHEwsUtmLhJJEnfTmJFig/y6mX2G4n0wh3Zk/VjU=;
        b=H1Lv19UazwkJjiTd1BQA9DVXHtdBVFzeczhWOmQqlZbum3Mj3XPmERI3GJMl7QJF24
         yaCpSaMNJ0XX5QfiQ2rjUzHQwXYM9UbyxHhVMvDkHkHozDvnXuw4wq6lOK8IlZnbSz3A
         K3CZY8m081HUHutm1sKfGHTcUiJcwr+Ca5CA9QTB8bKcwVyjvEMSYLMJnXRtmjCvqv8L
         6CUxMzeMXxSSR0TRpyB5RLMwTfIhEAUhZG0jc0LNuahj1PtkSIs+Vcohs7IXZ8eaa1iR
         6Nq3n7E/ZGOWg4DE49uW/rLkCxbUF6uciUEiSHwwLCa/BINCKvD94SU6Zb+9mSegoh/2
         bbSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gD8UUMPl;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::a29 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=63QhHEwsUtmLhJJEnfTmJFig/y6mX2G4n0wh3Zk/VjU=;
        b=rrWNDLSb38vPWGSzUuh8oGQCl8SIrm42gzNIAbb38c33YoZpWMCcejcvvM3sDstvoQ
         FKgsybq2UMRWSOPirul0GnJigWKIbeuDT0E6EGH2C06EpnQbyn+muz4DCfX2ttJt6SQb
         U1fAeYfeQZe0DFdd1FtJ+yCht6FhqsxTJQyMHzn57+TSf8jxbgySOjMeITYncJDwonEf
         P/s4ZadX74l42I8Pw9FJDY3u6/in5L1C3jJnP4CN7wMVFJ9npqukXAqUlOiNqO3p0H8p
         +f/i2vZFEdaS6bnxxRcET6EiHZQSfDAcVvTkysFvblsHGN4hYF3gUOa0timj0nfDfyG/
         zxMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=63QhHEwsUtmLhJJEnfTmJFig/y6mX2G4n0wh3Zk/VjU=;
        b=XcJFx7EVEuH6GDrgNFIjC4Tvj7zJnayURjV4dBxEYY0N60f4sZyWoiSzrNDt6W+f+3
         qm4N2r8paz1yCCCpT1t7cfeLml+gT4xSIpqUuMwUzAtgzanlODw5Hs1DguIbE4FXxvWF
         iagdZMKVvCNyEiFeznlsXL7Fq2DsYiW5I/nDK9Tl+j1Mm1aGAKJDTrCbjvNy20noIsZv
         Np7DG7tPvMqDHiYBw/OkM8RwEErAUL2/PfO2uF6O2+7fyZqMxigiRgHff0PnkZWGLVI9
         fOtb1O9Mp/bVxWzLHcy6/x6yR52VOWbd6hU6gjaCCqeyPHu0ON/9QEh8hrKots/G0ry1
         KigQ==
X-Gm-Message-State: AOAM532GurOLMwYGv39ppUaC45uT0VxhTYbEiUGkHOoyaZ970F8OibE1
	G5UVlkKUimc79g4V/cppSos=
X-Google-Smtp-Source: ABdhPJykLAp+6Y3HdgMgpuP790WyWKKSmD0kU2PCVU+B09tCijyHAasIW9+VLhXrn+/bZuLvghlDnQ==
X-Received: by 2002:a05:6a00:1152:b0:4be:ab79:fcfa with SMTP id b18-20020a056a00115200b004beab79fcfamr632671pfm.3.1650561398658;
        Thu, 21 Apr 2022 10:16:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:244a:b0:158:fbd0:45a5 with SMTP id
 l10-20020a170903244a00b00158fbd045a5ls5433751pls.3.gmail; Thu, 21 Apr 2022
 10:16:38 -0700 (PDT)
X-Received: by 2002:a17:902:8341:b0:158:d083:3394 with SMTP id z1-20020a170902834100b00158d0833394mr544717pln.62.1650561397992;
        Thu, 21 Apr 2022 10:16:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650561397; cv=none;
        d=google.com; s=arc-20160816;
        b=gnuJ3B3Hv/J8crsSY8qIMaRmwYdYGeC1XjOQSPGH4fKbZAfY4KP4EAMTjivpF0nVXg
         zYZr3QMAPNkwWM7sfe4BRCXWjbVeNMcLQO4aRXoUNsfc1YHa1U3gNqCvSiO6HTlyPSJq
         NKZBz1IgGQdJzuTY0rNdH8g3RgM6qpLVlxeuNCtzFXOSfG0Cm5Z22roODQI4An2bzzGa
         XJHfG6gJfiymX6n4AJl1j9bMQoxBIVxeLtXqzs7EO04KESrQEfb9UKw6UYscmZYOJB+g
         lpPX0E22U6vpJr2HrDGe6lfafyy57+oJ15kbynJgSwOxRysKC06Ly8G5xR9cop8rJyeY
         +Wng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CR57JIdWS1A/HNT68ZqKzgkSo317MWxYpQHNRNRg8Vc=;
        b=JqwU2XtbF23EGgO5Rx6Vpuec+8RI1JGi0B/jt8SiIYEFpXHfVK32THMVMhel9xKXRY
         mewaHVNGXJ0JDYBcdNco/lB/o2uy2jz1Ea49m7dZyPCSul/YunsPmMPJqesGQJqQ9MBz
         h4fgYM8+/nUMit2/T2LcQZGJmxquhKhK4GcP/ckz7lknrHhdFcCUiGBmWqUQHhU4RezC
         H0NhLWPO5HLIv0oCZ5/THzdViYUezfvZsxcob2+2+zHnFQsybVbsgtQpe7Qyi36syrsh
         0ztOMCwqZX/WAmi+jeEH3v5yck2/+6G5a9pU96cSE5rw3eYuOklyd9ZurTQQKHXlb3Bb
         Qfig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gD8UUMPl;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::a29 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa29.google.com (mail-vk1-xa29.google.com. [2607:f8b0:4864:20::a29])
        by gmr-mx.google.com with ESMTPS id s19-20020a17090a441300b001cba2ece140si361983pjg.1.2022.04.21.10.16.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Apr 2022 10:16:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::a29 as permitted sender) client-ip=2607:f8b0:4864:20::a29;
Received: by mail-vk1-xa29.google.com with SMTP id bc42so2620631vkb.12
        for <kasan-dev@googlegroups.com>; Thu, 21 Apr 2022 10:16:37 -0700 (PDT)
X-Received: by 2002:a1f:32cf:0:b0:345:cdce:5dcd with SMTP id
 y198-20020a1f32cf000000b00345cdce5dcdmr150638vky.14.1650561396853; Thu, 21
 Apr 2022 10:16:36 -0700 (PDT)
MIME-Version: 1.0
References: <20220421031738.3168157-1-pcc@google.com> <YmFORWyMAVacycu5@hyeyoo>
In-Reply-To: <YmFORWyMAVacycu5@hyeyoo>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Apr 2022 10:16:25 -0700
Message-ID: <CAMn1gO5xHZvFSSsW5sTVaUBN_gS-cYYNMG3PnpgCmh7kk_Zx7Q@mail.gmail.com>
Subject: Re: [PATCH] mm: make minimum slab alignment a runtime property
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, vbabka@suse.cz, penberg@kernel.org, 
	cl@linux.org, roman.gushchin@linux.dev, iamjoonsoo.kim@lge.com, 
	rientjes@google.com, Catalin Marinas <catalin.marinas@arm.com>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Eric Biederman <ebiederm@xmission.com>, 
	Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=gD8UUMPl;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::a29 as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Thu, Apr 21, 2022 at 5:30 AM Hyeonggon Yoo <42.hyeyoo@gmail.com> wrote:
>
> On Wed, Apr 20, 2022 at 08:17:38PM -0700, Peter Collingbourne wrote:
> > When CONFIG_KASAN_HW_TAGS is enabled we currently increase the minimum
> > slab alignment to 16. This happens even if MTE is not supported in
> > hardware or disabled via kasan=off, which creates an unnecessary
> > memory overhead in those cases. Eliminate this overhead by making
> > the minimum slab alignment a runtime property and only aligning to
> > 16 if KASAN is enabled at runtime.
> >
> > On a DragonBoard 845c (non-MTE hardware) with a kernel built with
> > CONFIG_KASAN_HW_TAGS, waiting for quiescence after a full Android
> > boot I see the following Slab measurements in /proc/meminfo (median
> > of 3 reboots):
> >
> > Before: 169020 kB
> > After:  167304 kB
> >
> > Link: https://linux-review.googlesource.com/id/I752e725179b43b144153f4b6f584ceb646473ead
> > Signed-off-by: Peter Collingbourne <pcc@google.com>
> > ---
> >  arch/arc/include/asm/cache.h        |  4 ++--
> >  arch/arm/include/asm/cache.h        |  2 +-
> >  arch/arm64/include/asm/cache.h      | 19 +++++++++++++------
> >  arch/microblaze/include/asm/page.h  |  2 +-
> >  arch/riscv/include/asm/cache.h      |  2 +-
> >  arch/sparc/include/asm/cache.h      |  2 +-
> >  arch/xtensa/include/asm/processor.h |  2 +-
> >  fs/binfmt_flat.c                    |  9 ++++++---
> >  include/crypto/hash.h               |  2 +-
> >  include/linux/slab.h                | 22 +++++++++++++++++-----
> >  mm/slab.c                           |  7 +++----
> >  mm/slab_common.c                    |  3 +--
> >  mm/slob.c                           |  6 +++---
> >  13 files changed, 51 insertions(+), 31 deletions(-)
>
> [+Cc slab people, Catalin and affected subsystems' folks]
>
> just FYI, There is similar discussion about kmalloc caches' alignment.
> https://lore.kernel.org/linux-mm/20220405135758.774016-1-catalin.marinas@arm.com/
>
> It seems this is another demand for runtime resolution of slab
> alignment, But slightly different from kmalloc as there is no requirement
> for DMA alignment.
>
> >
> > diff --git a/arch/arc/include/asm/cache.h b/arch/arc/include/asm/cache.h
> > index f0f1fc5d62b6..b6a7763fd5d6 100644
> > --- a/arch/arc/include/asm/cache.h
> > +++ b/arch/arc/include/asm/cache.h
> > @@ -55,11 +55,11 @@
> >   * Make sure slab-allocated buffers are 64-bit aligned when atomic64_t uses
> >   * ARCv2 64-bit atomics (LLOCKD/SCONDD). This guarantess runtime 64-bit
> >   * alignment for any atomic64_t embedded in buffer.
> > - * Default ARCH_SLAB_MINALIGN is __alignof__(long long) which has a relaxed
> > + * Default ARCH_SLAB_MIN_MINALIGN is __alignof__(long long) which has a relaxed
> >   * value of 4 (and not 8) in ARC ABI.
> >   */
> >  #if defined(CONFIG_ARC_HAS_LL64) && defined(CONFIG_ARC_HAS_LLSC)
> > -#define ARCH_SLAB_MINALIGN   8
> > +#define ARCH_SLAB_MIN_MINALIGN       8
> >  #endif
> >
>
> Why isn't it just ARCH_SLAB_MINALIGN?

Because this is the minimum possible value of the minimum alignment
decided at runtime. I chose to give it a different name to
arch_slab_minalign() because the two have different meanings.

Granted this isn't a great name because of the stuttering but
hopefully it will prompt folks to investigate the meaning of this
constant if necessary.

> >  extern int ioc_enable;
> > diff --git a/arch/arm/include/asm/cache.h b/arch/arm/include/asm/cache.h
> > index e3ea34558ada..3e1018bb9805 100644
> > --- a/arch/arm/include/asm/cache.h
> > +++ b/arch/arm/include/asm/cache.h
> > @@ -21,7 +21,7 @@
> >   * With EABI on ARMv5 and above we must have 64-bit aligned slab pointers.
> >   */
> >  #if defined(CONFIG_AEABI) && (__LINUX_ARM_ARCH__ >= 5)
> > -#define ARCH_SLAB_MINALIGN 8
> > +#define ARCH_SLAB_MIN_MINALIGN 8
> >  #endif
> >
> >  #define __read_mostly __section(".data..read_mostly")
> > diff --git a/arch/arm64/include/asm/cache.h b/arch/arm64/include/asm/cache.h
> > index a074459f8f2f..38f171591c3f 100644
> > --- a/arch/arm64/include/asm/cache.h
> > +++ b/arch/arm64/include/asm/cache.h
> > @@ -6,6 +6,7 @@
> >  #define __ASM_CACHE_H
> >
> >  #include <asm/cputype.h>
> > +#include <asm/mte-def.h>
> >
> >  #define CTR_L1IP_SHIFT               14
> >  #define CTR_L1IP_MASK                3
> > @@ -49,15 +50,21 @@
> >   */
> >  #define ARCH_DMA_MINALIGN    (128)
> >
> > -#ifdef CONFIG_KASAN_SW_TAGS
> > -#define ARCH_SLAB_MINALIGN   (1ULL << KASAN_SHADOW_SCALE_SHIFT)
> > -#elif defined(CONFIG_KASAN_HW_TAGS)
> > -#define ARCH_SLAB_MINALIGN   MTE_GRANULE_SIZE
> > -#endif
> > -
> >  #ifndef __ASSEMBLY__
> >
> >  #include <linux/bitops.h>
> > +#include <linux/kasan-enabled.h>
> > +
> > +#ifdef CONFIG_KASAN_SW_TAGS
> > +#define ARCH_SLAB_MIN_MINALIGN       (1ULL << KASAN_SHADOW_SCALE_SHIFT)
> > +#elif defined(CONFIG_KASAN_HW_TAGS)
> > +static inline size_t arch_slab_minalign(void)
> > +{
> > +     return kasan_hw_tags_enabled() ? MTE_GRANULE_SIZE :
> > +                                      __alignof__(unsigned long long);
> > +}
> > +#define arch_slab_minalign() arch_slab_minalign()
> > +#endif
> >
>
> kasan_hw_tags_enabled() is also false when kasan is just not initialized yet.
> What about writing a new helper something like kasan_is_disabled()
> instead?

The decision of whether to enable KASAN is made early, before the slab
allocator is initialized (start_kernel -> smp_prepare_boot_cpu ->
kasan_init_hw_tags vs start_kernel -> mm_init -> kmem_cache_init). If
you think about it, this needs to be the case for KASAN to operate
correctly because it influences the behavior of the slab allocator via
the kasan_*poison* hooks. So I don't think we can end up calling this
function before then.

> >  #define ICACHEF_ALIASING     0
> >  #define ICACHEF_VPIPT                1
> > diff --git a/arch/microblaze/include/asm/page.h b/arch/microblaze/include/asm/page.h
> > index 4b8b2fa78fc5..ccdbc1da3c3e 100644
> > --- a/arch/microblaze/include/asm/page.h
> > +++ b/arch/microblaze/include/asm/page.h
> > @@ -33,7 +33,7 @@
> >  /* MS be sure that SLAB allocates aligned objects */
> >  #define ARCH_DMA_MINALIGN    L1_CACHE_BYTES
> >
> > -#define ARCH_SLAB_MINALIGN   L1_CACHE_BYTES
> > +#define ARCH_SLAB_MIN_MINALIGN       L1_CACHE_BYTES
> >
> >  /*
> >   * PAGE_OFFSET -- the first address of the first page of memory. With MMU
> > diff --git a/arch/riscv/include/asm/cache.h b/arch/riscv/include/asm/cache.h
> > index 9b58b104559e..7beb3b5d27c7 100644
> > --- a/arch/riscv/include/asm/cache.h
> > +++ b/arch/riscv/include/asm/cache.h
> > @@ -16,7 +16,7 @@
> >   * the flat loader aligns it accordingly.
> >   */
> >  #ifndef CONFIG_MMU
> > -#define ARCH_SLAB_MINALIGN   16
> > +#define ARCH_SLAB_MIN_MINALIGN       16
> >  #endif
> >
> >  #endif /* _ASM_RISCV_CACHE_H */
> > diff --git a/arch/sparc/include/asm/cache.h b/arch/sparc/include/asm/cache.h
> > index e62fd0e72606..9d8cb4687b7e 100644
> > --- a/arch/sparc/include/asm/cache.h
> > +++ b/arch/sparc/include/asm/cache.h
> > @@ -8,7 +8,7 @@
> >  #ifndef _SPARC_CACHE_H
> >  #define _SPARC_CACHE_H
> >
> > -#define ARCH_SLAB_MINALIGN   __alignof__(unsigned long long)
> > +#define ARCH_SLAB_MIN_MINALIGN       __alignof__(unsigned long long)
> >
> >  #define L1_CACHE_SHIFT 5
> >  #define L1_CACHE_BYTES 32
> > diff --git a/arch/xtensa/include/asm/processor.h b/arch/xtensa/include/asm/processor.h
> > index 4489a27d527a..e3ea278e3fcf 100644
> > --- a/arch/xtensa/include/asm/processor.h
> > +++ b/arch/xtensa/include/asm/processor.h
> > @@ -18,7 +18,7 @@
> >  #include <asm/types.h>
> >  #include <asm/regs.h>
> >
> > -#define ARCH_SLAB_MINALIGN XTENSA_STACK_ALIGNMENT
> > +#define ARCH_SLAB_MIN_MINALIGN XTENSA_STACK_ALIGNMENT
> >
> >  /*
> >   * User space process size: 1 GB.
> > diff --git a/fs/binfmt_flat.c b/fs/binfmt_flat.c
> > index 626898150011..8ff1bf7d1e87 100644
> > --- a/fs/binfmt_flat.c
> > +++ b/fs/binfmt_flat.c
> > @@ -64,7 +64,10 @@
> >   * Here we can be a bit looser than the data sections since this
> >   * needs to only meet arch ABI requirements.
> >   */
> > -#define FLAT_STACK_ALIGN     max_t(unsigned long, sizeof(void *), ARCH_SLAB_MINALIGN)
> > +static size_t flat_stack_align(void)
> > +{
> > +     return max_t(unsigned long, sizeof(void *), arch_slab_minalign());
> > +}
> >
> >  #define RELOC_FAILED 0xff00ff01              /* Relocation incorrect somewhere */
> >  #define UNLOADED_LIB 0x7ff000ff              /* Placeholder for unused library */
> > @@ -148,7 +151,7 @@ static int create_flat_tables(struct linux_binprm *bprm, unsigned long arg_start
> >               sp -= 2; /* argvp + envp */
> >       sp -= 1;  /* &argc */
> >
> > -     current->mm->start_stack = (unsigned long)sp & -FLAT_STACK_ALIGN;
> > +     current->mm->start_stack = (unsigned long)sp & -flat_stack_align();
> >       sp = (unsigned long __user *)current->mm->start_stack;
> >
> >       if (put_user(bprm->argc, sp++))
> > @@ -966,7 +969,7 @@ static int load_flat_binary(struct linux_binprm *bprm)
> >  #endif
> >       stack_len += (bprm->argc + 1) * sizeof(char *);   /* the argv array */
> >       stack_len += (bprm->envc + 1) * sizeof(char *);   /* the envp array */
> > -     stack_len = ALIGN(stack_len, FLAT_STACK_ALIGN);
> > +     stack_len = ALIGN(stack_len, flat_stack_align());
> >
> >       res = load_flat_file(bprm, &libinfo, 0, &stack_len);
> >       if (res < 0)
> > diff --git a/include/crypto/hash.h b/include/crypto/hash.h
> > index f140e4643949..442c290f458c 100644
> > --- a/include/crypto/hash.h
> > +++ b/include/crypto/hash.h
> > @@ -149,7 +149,7 @@ struct ahash_alg {
> >
> >  struct shash_desc {
> >       struct crypto_shash *tfm;
> > -     void *__ctx[] __aligned(ARCH_SLAB_MINALIGN);
> > +     void *__ctx[] __aligned(ARCH_SLAB_MIN_MINALIGN);
> >  };
> >
> >  #define HASH_MAX_DIGESTSIZE   64
> > diff --git a/include/linux/slab.h b/include/linux/slab.h
> > index 373b3ef99f4e..80e517593372 100644
> > --- a/include/linux/slab.h
> > +++ b/include/linux/slab.h
> > @@ -201,21 +201,33 @@ void kmem_dump_obj(void *object);
> >  #endif
> >
> >  /*
> > - * Setting ARCH_SLAB_MINALIGN in arch headers allows a different alignment.
> > + * Setting ARCH_SLAB_MIN_MINALIGN in arch headers allows a different alignment.
> >   * Intended for arches that get misalignment faults even for 64 bit integer
> >   * aligned buffers.
> >   */
> > -#ifndef ARCH_SLAB_MINALIGN
> > -#define ARCH_SLAB_MINALIGN __alignof__(unsigned long long)
> > +#ifndef ARCH_SLAB_MIN_MINALIGN
> > +#define ARCH_SLAB_MIN_MINALIGN __alignof__(unsigned long long)
> > +#endif
> > +
> > +/*
> > + * Arches can define this function if they want to decide the minimum slab
> > + * alignment at runtime. The value returned by the function must be
> > + * >= ARCH_SLAB_MIN_MINALIGN.
> > + */
>
> Not only the value should be bigger than or equal to ARCH_SLAB_MIN_MINALIGN,
> it should be compatible with ARCH_SLAB_MIN_MINALIGN.

What's the difference?

Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMn1gO5xHZvFSSsW5sTVaUBN_gS-cYYNMG3PnpgCmh7kk_Zx7Q%40mail.gmail.com.
