Return-Path: <kasan-dev+bncBD52JJ7JXILRB2G3ROJQMGQEETDSFUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7604C50BF4B
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 20:03:21 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id x71-20020a627c4a000000b0050d1445ee0esf14739pfc.15
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 11:03:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650650600; cv=pass;
        d=google.com; s=arc-20160816;
        b=WlpowDgO6c2rj/f5gTd8kUUHIUMkfH+ifSL6zfxennrwbTUKYjgkf/B88zVlDvrYwI
         LQ0VHR6kJ64KsudeJqO/3jYWbh4U/xq9I9Mjwng9b65YKUNcitqoEWU4ceP6iZZFy4aR
         B17nBO0RgYAMOt8icZgOi1UpeFplliCrvOnB90/ZN+N2m8dvw5FnHdkTJnXV1W+y8lLt
         gC26cUArT8rPnOB7uPEVtlXTlWnzLxdPHvsEMQ6g5YAhad0TJLCtr1ZJt8j8rr2S2JGH
         CAprjXW07BoaRAVHU/LpfZw1qsnwhAiEbT0GxZDNnbBW8JnBwjwCF+YH6srueQ2WUs8k
         ZxOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=SRWINn5ao6/w7MVhPucorJV+yK0trcxCF9aN0iMEyWk=;
        b=Bs1zSra2UZU1obxIPwirEQ8vlWPhgVJrNKfZI77CcqRhlSDpuRv5Hf0h4kn7J/oMoA
         RBX8LV86crmGy7LiW07vA/cCMbHhuqYBh6BBr2XTepo+54MObrLdBQaJjlJcxjEorEBo
         ybVg/PMCP+vFOGv6sUonVA9/8N7j+mhElORweCv4OZN/qf8Azdg3HXSH4nZn3rxT2gtP
         Cx/eR6X5GFpELLOizbuYM8+xdV1NSdAL64PALOjRKQqKhCdDHYK6bnSA6sKWKUMFS0M0
         u7S8cyOLKy7Ss5QaOUFhNebw8b4pIJqnxIjQmWtcI4Fdst1UuHpwXTCU78eR70TLJRsk
         HWjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="pkOd/P6a";
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::e34 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SRWINn5ao6/w7MVhPucorJV+yK0trcxCF9aN0iMEyWk=;
        b=jruJyrR0IqLuHONPkxrarzKmhfx16aMTiIs3RjQFuhbPPzK6FH0Uhs/ZwHVoViLUXQ
         wZkEwhsEV9/lxVpRoOGkOYL5IOvFM+2KlISzqVwgc+FYtw30Wswy9b+Y51nAs0J+QFce
         lAAdRGLbAUbodntsUYpoyOUMbgIA+qKIZlT7QefqgFL7XfLUOzh6SiDSlUUvI37iWnzv
         0WU8szWYqqF+147UqRVd1++Kzxwrvzvp+FxMs58/DiSFEyua1FSNCB25TEW7SEBfUuxb
         rvf5d8Wwz9zg7BF0AtG88QV6wB+311fUULAWHlOtaEW0rkwdtUgtCWQjokgoug9b6Wsm
         EDrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SRWINn5ao6/w7MVhPucorJV+yK0trcxCF9aN0iMEyWk=;
        b=tk9dNm9yxbuaQaBYB1KMIZfOhz+/PJPmfMJ+L24WVjhy+iXfSYLB7s3ZnrpU6ZZaWu
         93jm9SDRHlioQvkMkk66B1h9LGhQzUTq5PVASTB9f7lQB90o/2TFXwgOdk4cgoA/vV1v
         fXM5x1m5kKM5VjOzVheLudZRQxZJPy7q2rC4rvjkxCxHlu0lU9sgc3lpniO9wEiVVCjh
         LEbsGtvg6yqQlU9w9T1tSvyIt97d4Qf3bBUmBNfyXRm3pTghtE99eftXspF//gGoKAe0
         632rax6YHQ+UyZKSmQhqNzP9O8JEcLF0nyngJcxqTPU27As/LW8vcdBSiXh8yMLBZ0pP
         LSnQ==
X-Gm-Message-State: AOAM531CXn7rcC851p62pKseExLN+ePUg5YcZdAgQpDX0DN/pTu7KWc7
	3HvtC9t1dWfB9JSZRJVScUA=
X-Google-Smtp-Source: ABdhPJynfl7+J0wUgARI19Zq+mx7jbi1m2dZjroEukC84ykwejP0/IVNL6Q3himxQF4pxa3vwTwneQ==
X-Received: by 2002:a63:5163:0:b0:3a9:4e90:6d3d with SMTP id r35-20020a635163000000b003a94e906d3dmr4946277pgl.48.1650650600154;
        Fri, 22 Apr 2022 11:03:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ecca:b0:158:f6a7:5bd0 with SMTP id
 a10-20020a170902ecca00b00158f6a75bd0ls8432788plh.5.gmail; Fri, 22 Apr 2022
 11:03:19 -0700 (PDT)
X-Received: by 2002:a17:90b:1b03:b0:1d2:a577:d52 with SMTP id nu3-20020a17090b1b0300b001d2a5770d52mr6634772pjb.58.1650650599440;
        Fri, 22 Apr 2022 11:03:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650650599; cv=none;
        d=google.com; s=arc-20160816;
        b=f7c1nYeWNjLqi4Kp0mn+VjhNF6WAUz4nOPqW2rvnVJbaRFhtjvz0DWDIQXtwNcy46D
         ZeWfijJ5/8P/hrocuzFT1AP8KQbeAT+b8pLZQ6haM8iEfNlO+LQvacqjSMUuQs4YDtEL
         lwBpv3qTvNCVR0DsxP/zNQeilCg+iCkSl1OT8PuABrAb7jrwe2Ia1oH0tJwakS95GIvo
         zt/D7eno6+1mnMu3o4Z9J/k//8GBhu/925Zns6O61PHwcPaIImfkrsDy1+Ky3N5CUcJj
         dlvuxUFoJ2EHd9biOdzi5cDOQD6++AY47vC2hv7NxLnOq7ylVuXV+n0shJ93IWhLCr1g
         0bwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GZVGIj4tUMtOzUQeEJsn9To8y+Iu7srnhe9+RZIuWOI=;
        b=Ix4pGCx4OKH+bznLBw4VauSVDN5ysZY+gqD1occBsBd0x5IJ6DC58UagqNCYKWv3Wi
         KoR7zTyRa3uYoJmxXmgaL8HO/vOZVNtPeHO+W8ooBTF/l8mZaUde8wW9mhcAbAX8PkSY
         mCeWURIJC46sBLcKoY0nP9p+nAK4ga5wNZxFe2Y+RZ5xCJ4tywPe0gzvto6/iMlh32Hu
         ICKnKU0T6H8pqgLE2iMaESIe8OqCLbThTbf2QeTCYMY2V5XAMR3Vykm1Cl9wQViWYMQw
         e6TQyeeQPaf3OX0KATLmB3xZ4JElL3X1zaymcdaaSx9RObPpMIc+/2N7RBwqMDR6k+fl
         Ohmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="pkOd/P6a";
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::e34 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe34.google.com (mail-vs1-xe34.google.com. [2607:f8b0:4864:20::e34])
        by gmr-mx.google.com with ESMTPS id x38-20020a056a000be600b0050cf326d9bbsi145641pfu.3.2022.04.22.11.03.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Apr 2022 11:03:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::e34 as permitted sender) client-ip=2607:f8b0:4864:20::e34;
Received: by mail-vs1-xe34.google.com with SMTP id q2so8175496vsp.4
        for <kasan-dev@googlegroups.com>; Fri, 22 Apr 2022 11:03:19 -0700 (PDT)
X-Received: by 2002:a67:2f44:0:b0:32a:27a3:7319 with SMTP id
 v65-20020a672f44000000b0032a27a37319mr1833795vsv.49.1650650598274; Fri, 22
 Apr 2022 11:03:18 -0700 (PDT)
MIME-Version: 1.0
References: <20220421031738.3168157-1-pcc@google.com> <YmFORWyMAVacycu5@hyeyoo>
 <CAMn1gO5xHZvFSSsW5sTVaUBN_gS-cYYNMG3PnpgCmh7kk_Zx7Q@mail.gmail.com>
 <YmKiDt12Xb/KXX3z@hyeyoo> <f2f7ac96-6fb7-3733-f389-208c7c191caf@suse.cz>
In-Reply-To: <f2f7ac96-6fb7-3733-f389-208c7c191caf@suse.cz>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 22 Apr 2022 11:03:07 -0700
Message-ID: <CAMn1gO5SgwJLWxCSH8z0_DgGHY16hTd7rJLvDwCTPkNAWidiPQ@mail.gmail.com>
Subject: Re: [PATCH] mm: make minimum slab alignment a runtime property
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Pekka Enberg <penberg@kernel.org>, cl@linux.org, 
	roman.gushchin@linux.dev, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	David Rientjes <rientjes@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Eric Biederman <ebiederm@xmission.com>, 
	Kees Cook <keescook@chromium.org>, Linus Torvalds <torvalds@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="pkOd/P6a";       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::e34 as
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

On Fri, Apr 22, 2022 at 9:19 AM Vlastimil Babka <vbabka@suse.cz> wrote:
>
> On 4/22/22 14:39, Hyeonggon Yoo wrote:
> > On Thu, Apr 21, 2022 at 10:16:25AM -0700, Peter Collingbourne wrote:
> >> On Thu, Apr 21, 2022 at 5:30 AM Hyeonggon Yoo <42.hyeyoo@gmail.com> wrote:
> >> >
> >> > On Wed, Apr 20, 2022 at 08:17:38PM -0700, Peter Collingbourne wrote:
> >> > > When CONFIG_KASAN_HW_TAGS is enabled we currently increase the minimum
> >> > > slab alignment to 16. This happens even if MTE is not supported in
> >> > > hardware or disabled via kasan=off, which creates an unnecessary
> >> > > memory overhead in those cases. Eliminate this overhead by making
> >> > > the minimum slab alignment a runtime property and only aligning to
> >> > > 16 if KASAN is enabled at runtime.
> >> > >
> >> > > On a DragonBoard 845c (non-MTE hardware) with a kernel built with
> >> > > CONFIG_KASAN_HW_TAGS, waiting for quiescence after a full Android
> >> > > boot I see the following Slab measurements in /proc/meminfo (median
> >> > > of 3 reboots):
> >> > >
> >> > > Before: 169020 kB
> >> > > After:  167304 kB
> >> > >
> >> > > Link: https://linux-review.googlesource.com/id/I752e725179b43b144153f4b6f584ceb646473ead
> >> > > Signed-off-by: Peter Collingbourne <pcc@google.com>
> >> > > ---
> >> > >  arch/arc/include/asm/cache.h        |  4 ++--
> >> > >  arch/arm/include/asm/cache.h        |  2 +-
> >> > >  arch/arm64/include/asm/cache.h      | 19 +++++++++++++------
> >> > >  arch/microblaze/include/asm/page.h  |  2 +-
> >> > >  arch/riscv/include/asm/cache.h      |  2 +-
> >> > >  arch/sparc/include/asm/cache.h      |  2 +-
> >> > >  arch/xtensa/include/asm/processor.h |  2 +-
> >> > >  fs/binfmt_flat.c                    |  9 ++++++---
> >> > >  include/crypto/hash.h               |  2 +-
> >> > >  include/linux/slab.h                | 22 +++++++++++++++++-----
> >> > >  mm/slab.c                           |  7 +++----
> >> > >  mm/slab_common.c                    |  3 +--
> >> > >  mm/slob.c                           |  6 +++---
> >> > >  13 files changed, 51 insertions(+), 31 deletions(-)
> >> >
> >> > [+Cc slab people, Catalin and affected subsystems' folks]
> >> >
> >> > just FYI, There is similar discussion about kmalloc caches' alignment.
> >> > https://lore.kernel.org/linux-mm/20220405135758.774016-1-catalin.marinas@arm.com/
> >> >
> >> > It seems this is another demand for runtime resolution of slab
> >> > alignment, But slightly different from kmalloc as there is no requirement
> >> > for DMA alignment.
> >> >
> >> > >
> >> > > diff --git a/arch/arc/include/asm/cache.h b/arch/arc/include/asm/cache.h
> >> > > index f0f1fc5d62b6..b6a7763fd5d6 100644
> >> > > --- a/arch/arc/include/asm/cache.h
> >> > > +++ b/arch/arc/include/asm/cache.h
> >> > > @@ -55,11 +55,11 @@
> >> > >   * Make sure slab-allocated buffers are 64-bit aligned when atomic64_t uses
> >> > >   * ARCv2 64-bit atomics (LLOCKD/SCONDD). This guarantess runtime 64-bit
> >> > >   * alignment for any atomic64_t embedded in buffer.
> >> > > - * Default ARCH_SLAB_MINALIGN is __alignof__(long long) which has a relaxed
> >> > > + * Default ARCH_SLAB_MIN_MINALIGN is __alignof__(long long) which has a relaxed
> >> > >   * value of 4 (and not 8) in ARC ABI.
> >> > >   */
> >> > >  #if defined(CONFIG_ARC_HAS_LL64) && defined(CONFIG_ARC_HAS_LLSC)
> >> > > -#define ARCH_SLAB_MINALIGN   8
> >> > > +#define ARCH_SLAB_MIN_MINALIGN       8
> >> > >  #endifh
> >> > >
> >> >
> >> > Why isn't it just ARCH_SLAB_MINALIGN?
> >>
> >> Because this is the minimum possible value of the minimum alignment
> >> decided at runtime. I chose to give it a different name to
> >> arch_slab_minalign() because the two have different meanings.
> >>
> >> Granted this isn't a great name because of the stuttering but
> >> hopefully it will prompt folks to investigate the meaning of this
> >> constant if necessary.
> >
> > To be honest I don't care much about the name but just thought it's just better
> > to be consistent with Catalin's series: ARCH_KMALLOC_MINALIGN for static
> > alignment and arch_kmalloc_minalign() for (possibly bigger) alignment decided
> > at runtime.
>
> Agree it should be consistent, one way or another. I would (not overly
> strongly) prefer Catalin's approach as it's less churn. The name
> ARCH_SLAB_MINALIGN is not wrong as the actual alignment can be only bigger
> than that (or equal).
> Realistically it seems only slab internals are going to use
> arch_kmalloc_minalign(), so there shouldn't be too much need of "prompt
> folks to investigate".

No strong opinion, so I'll change it back to ARCH_SLAB_MINALIGN then.

> >> > >  extern int ioc_enable;
> >> > > diff --git a/arch/arm/include/asm/cache.h b/arch/arm/include/asm/cache.h
> >> > > index e3ea34558ada..3e1018bb9805 100644
> >> > > --- a/arch/arm/include/asm/cache.h
> >> > > +++ b/arch/arm/include/asm/cache.h
> >> > > @@ -21,7 +21,7 @@
> >> > >   * With EABI on ARMv5 and above we must have 64-bit aligned slab pointers.
> >> > >   */
> >> > >  #if defined(CONFIG_AEABI) && (__LINUX_ARM_ARCH__ >= 5)
> >> > > -#define ARCH_SLAB_MINALIGN 8
> >> > > +#define ARCH_SLAB_MIN_MINALIGN 8
> >> > >  #endif
> >> > >
> >> > >  #define __read_mostly __section(".data..read_mostly")
> >> > > diff --git a/arch/arm64/include/asm/cache.h b/arch/arm64/include/asm/cache.h
> >> > > index a074459f8f2f..38f171591c3f 100644
> >> > > --- a/arch/arm64/include/asm/cache.h
> >> > > +++ b/arch/arm64/include/asm/cache.h
> >> > > @@ -6,6 +6,7 @@
> >> > >  #define __ASM_CACHE_H
> >> > >
> >> > >  #include <asm/cputype.h>
> >> > > +#include <asm/mte-def.h>
> >> > >
> >> > >  #define CTR_L1IP_SHIFT               14
> >> > >  #define CTR_L1IP_MASK                3
> >> > > @@ -49,15 +50,21 @@
> >> > >   */
> >> > >  #define ARCH_DMA_MINALIGN    (128)
> >> > >
> >> > > -#ifdef CONFIG_KASAN_SW_TAGS
> >> > > -#define ARCH_SLAB_MINALIGN   (1ULL << KASAN_SHADOW_SCALE_SHIFT)
> >> > > -#elif defined(CONFIG_KASAN_HW_TAGS)
> >> > > -#define ARCH_SLAB_MINALIGN   MTE_GRANULE_SIZE
> >> > > -#endif
> >> > > -
> >> > >  #ifndef __ASSEMBLY__
> >> > >
> >> > >  #include <linux/bitops.h>
> >> > > +#include <linux/kasan-enabled.h>
> >> > > +
> >> > > +#ifdef CONFIG_KASAN_SW_TAGS
> >> > > +#define ARCH_SLAB_MIN_MINALIGN       (1ULL << KASAN_SHADOW_SCALE_SHIFT)
> >> > > +#elif defined(CONFIG_KASAN_HW_TAGS)
> >> > > +static inline size_t arch_slab_minalign(void)
> >> > > +{
> >> > > +     return kasan_hw_tags_enabled() ? MTE_GRANULE_SIZE :
> >> > > +                                      __alignof__(unsigned long long);
> >> > > +}
> >> > > +#define arch_slab_minalign() arch_slab_minalign()
> >> > > +#endif
> >> > >
> >> >
> >> > kasan_hw_tags_enabled() is also false when kasan is just not initialized yet.
> >> > What about writing a new helper something like kasan_is_disabled()
> >> > instead?
> >>
> >> The decision of whether to enable KASAN is made early, before the slab
> >> allocator is initialized (start_kernel -> smp_prepare_boot_cpu ->
> >> kasan_init_hw_tags vs start_kernel -> mm_init -> kmem_cache_init). If
> >> you think about it, this needs to be the case for KASAN to operate
> >> correctly because it influences the behavior of the slab allocator via
> >> the kasan_*poison* hooks. So I don't think we can end up calling this
> >> function before then.
> >
> > Sounds not bad. I wanted to make sure the value of arch_slab_minaligned()
> > is not changed during its execution.
> >
> > Just some part of me thought something like this would be more
> > intuitive/robust.
> >
> > if (systems_supports_mte() && kasan_arg != KASAN_ARG_OFF)
> >       return MTE_GRANULE_SIZE;
> > else
> >       return __alignof__(unsigned long long);
>
> Let's see if kasan or arm folks have an opinion here.
>
> >
> >> > >  #define ICACHEF_ALIASING     0
> >> > >  #define ICACHEF_VPIPT                1
> >> > > diff --git a/arch/microblaze/include/asm/page.h b/arch/microblaze/include/asm/page.h
> >> > > index 4b8b2fa78fc5..ccdbc1da3c3e 100644
> >> > > --- a/arch/microblaze/include/asm/page.h
> >> > > +++ b/arch/microblaze/include/asm/page.h
> >> > > @@ -33,7 +33,7 @@
> >> > >  /* MS be sure that SLAB allocates aligned objects */
> >> > >  #define ARCH_DMA_MINALIGN    L1_CACHE_BYTES
> >> > >
> >> > > -#define ARCH_SLAB_MINALIGN   L1_CACHE_BYTES
> >> > > +#define ARCH_SLAB_MIN_MINALIGN       L1_CACHE_BYTES
> >> > >
> >> > >  /*
> >> > >   * PAGE_OFFSET -- the first address of the first page of memory. With MMU
> >> > > diff --git a/arch/riscv/include/asm/cache.h b/arch/riscv/include/asm/cache.h
> >> > > index 9b58b104559e..7beb3b5d27c7 100644
> >> > > --- a/arch/riscv/include/asm/cache.h
> >> > > +++ b/arch/riscv/include/asm/cache.h
> >> > > @@ -16,7 +16,7 @@
> >> > >   * the flat loader aligns it accordingly.
> >> > >   */
> >> > >  #ifndef CONFIG_MMU
> >> > > -#define ARCH_SLAB_MINALIGN   16
> >> > > +#define ARCH_SLAB_MIN_MINALIGN       16
> >> > >  #endif
> >> > >
> >> > >  #endif /* _ASM_RISCV_CACHE_H */
> >> > > diff --git a/arch/sparc/include/asm/cache.h b/arch/sparc/include/asm/cache.h
> >> > > index e62fd0e72606..9d8cb4687b7e 100644
> >> > > --- a/arch/sparc/include/asm/cache.h
> >> > > +++ b/arch/sparc/include/asm/cache.h
> >> > > @@ -8,7 +8,7 @@
> >> > >  #ifndef _SPARC_CACHE_H
> >> > >  #define _SPARC_CACHE_H
> >> > >
> >> > > -#define ARCH_SLAB_MINALIGN   __alignof__(unsigned long long)
> >> > > +#define ARCH_SLAB_MIN_MINALIGN       __alignof__(unsigned long long)
> >> > >
> >> > >  #define L1_CACHE_SHIFT 5
> >> > >  #define L1_CACHE_BYTES 32
> >> > > diff --git a/arch/xtensa/include/asm/processor.h b/arch/xtensa/include/asm/processor.h
> >> > > index 4489a27d527a..e3ea278e3fcf 100644
> >> > > --- a/arch/xtensa/include/asm/processor.h
> >> > > +++ b/arch/xtensa/include/asm/processor.h
> >> > > @@ -18,7 +18,7 @@
> >> > >  #include <asm/types.h>
> >> > >  #include <asm/regs.h>
> >> > >
> >> > > -#define ARCH_SLAB_MINALIGN XTENSA_STACK_ALIGNMENT
> >> > > +#define ARCH_SLAB_MIN_MINALIGN XTENSA_STACK_ALIGNMENT
> >> > >
> >> > >  /*
> >> > >   * User space process size: 1 GB.
> >> > > diff --git a/fs/binfmt_flat.c b/fs/binfmt_flat.c
> >> > > index 626898150011..8ff1bf7d1e87 100644
> >> > > --- a/fs/binfmt_flat.c
> >> > > +++ b/fs/binfmt_flat.c
> >> > > @@ -64,7 +64,10 @@
> >> > >   * Here we can be a bit looser than the data sections since this
> >> > >   * needs to only meet arch ABI requirements.
> >> > >   */
> >> > > -#define FLAT_STACK_ALIGN     max_t(unsigned long, sizeof(void *), ARCH_SLAB_MINALIGN)
> >> > > +static size_t flat_stack_align(void)
> >> > > +{
> >> > > +     return max_t(unsigned long, sizeof(void *), arch_slab_minalign());
> >> > > +}
>
> I think this might not be necessary at all. There doesn't seem to be actual
> connection to the slab+kasan constraints here. My brief digging into git
> blame suggest they just used the ARCH_SLAB_MINALIGN constant because it
> existed, e.g. commit 2952095c6b2ee includes in changelog "Arguably, this is
> kind of hokey that the FLAT is semi-abusing defines it shouldn't."
> So, there shouldn't be a reason to increase this due to KASAN/MTE granule
> size, it was done unnecessarily as a side-effect before (AFAIU it shouldn't
> have caused existing userspace binaries to break, but maybe in some corner
> case it could?), and if this patch leaves out the binfmt_flat changes, the
> alignment will be (IMHO correctly) decreased again.

Okay, I'll revert this part.

> >> > >
> >> > >  #define RELOC_FAILED 0xff00ff01              /* Relocation incorrect somewhere */
> >> > >  #define UNLOADED_LIB 0x7ff000ff              /* Placeholder for unused library */
> >> > > @@ -148,7 +151,7 @@ static int create_flat_tables(struct linux_binprm *bprm, unsigned long arg_start
> >> > >               sp -= 2; /* argvp + envp */
> >> > >       sp -= 1;  /* &argc */
> >> > >
> >> > > -     current->mm->start_stack = (unsigned long)sp & -FLAT_STACK_ALIGN;
> >> > > +     current->mm->start_stack = (unsigned long)sp & -flat_stack_align();
> >> > >       sp = (unsigned long __user *)current->mm->start_stack;
> >> > >
> >> > >       if (put_user(bprm->argc, sp++))
> >> > > @@ -966,7 +969,7 @@ static int load_flat_binary(struct linux_binprm *bprm)
> >> > >  #endif
> >> > >       stack_len += (bprm->argc + 1) * sizeof(char *);   /* the argv array */
> >> > >       stack_len += (bprm->envc + 1) * sizeof(char *);   /* the envp array */
> >> > > -     stack_len = ALIGN(stack_len, FLAT_STACK_ALIGN);
> >> > > +     stack_len = ALIGN(stack_len, flat_stack_align());
> >> > >
> >> > >       res = load_flat_file(bprm, &libinfo, 0, &stack_len);
> >> > >       if (res < 0)
> >> > > diff --git a/include/crypto/hash.h b/include/crypto/hash.h
> >> > > index f140e4643949..442c290f458c 100644
> >> > > --- a/include/crypto/hash.h
> >> > > +++ b/include/crypto/hash.h
> >> > > @@ -149,7 +149,7 @@ struct ahash_alg {
> >> > >
> >> > >  struct shash_desc {
> >> > >       struct crypto_shash *tfm;
> >> > > -     void *__ctx[] __aligned(ARCH_SLAB_MINALIGN);
> >> > > +     void *__ctx[] __aligned(ARCH_SLAB_MIN_MINALIGN);
> >> > >  };
> >> > >
> >> > >  #define HASH_MAX_DIGESTSIZE   64
> >> > > diff --git a/include/linux/slab.h b/include/linux/slab.h
> >> > > index 373b3ef99f4e..80e517593372 100644
> >> > > --- a/include/linux/slab.h
> >> > > +++ b/include/linux/slab.h
> >> > > @@ -201,21 +201,33 @@ void kmem_dump_obj(void *object);
> >> > >  #endif
> >> > >
> >> > >  /*
> >> > > - * Setting ARCH_SLAB_MINALIGN in arch headers allows a different alignment.
> >> > > + * Setting ARCH_SLAB_MIN_MINALIGN in arch headers allows a different alignment.
> >> > >   * Intended for arches that get misalignment faults even for 64 bit integer
> >> > >   * aligned buffers.
> >> > >   */
> >> > > -#ifndef ARCH_SLAB_MINALIGN
> >> > > -#define ARCH_SLAB_MINALIGN __alignof__(unsigned long long)
> >> > > +#ifndef ARCH_SLAB_MIN_MINALIGN
> >> > > +#define ARCH_SLAB_MIN_MINALIGN __alignof__(unsigned long long)
> >> > > +#endif
> >> > > +
> >> > > +/*
> >> > > + * Arches can define this function if they want to decide the minimum slab
> >> > > + * alignment at runtime. The value returned by the function must be
> >> > > + * >= ARCH_SLAB_MIN_MINALIGN.
> >> > > + */
> >> >
> >> > Not only the value should be bigger than or equal to ARCH_SLAB_MIN_MINALIGN,
> >> > it should be compatible with ARCH_SLAB_MIN_MINALIGN.
> >>
> >> What's the difference?
> >>
> >
> > 231 /*
> > 232  * kmalloc and friends return ARCH_KMALLOC_MINALIGN aligned
> > 233  * pointers. kmem_cache_alloc and friends return ARCH_SLAB_MIN_MINALIGN
> > 234  * aligned pointers.
> > 235  */
> > 236 #define __assume_kmalloc_alignment __assume_aligned(ARCH_KMALLOC_MINALIGN)
> > 237 #define __assume_slab_alignment __assume_aligned(ARCH_SLAB_MIN_MINALIGN)
> > 238 #define __assume_page_alignment __assume_aligned(PAGE_SIZE)
> >
> > I mean actual slab object size should be both ARCH_SLAB_MIN_MINALIGN-aligned and
> > arch_slab_minalign()-aligned. Otherwise we are lying to the compiler.
> >
> > It's okay If we use just power-of-two alignment.
> > But adding a comment wouldn't harm :)
>
> Agreed, technically it's not ">=ARCH_SLAB_MIN_MINALIGN", but "a least common
> multiple of ARCH_SLAB_MIN_MINALIGN and whatever the other alignment
> requirements arch_slab_minalign() wants to guarantee". But AFAIK in practice
> these constraints are always power-of-two.

I think it's pretty much assumed that alignments are a power of two,
so from that viewpoint it's enough to say that it must be
>=ARCH_SLAB_MIN_MINALIGN. I guess I'll change the comment to say that
it must return a power of two since there's no reason not to.

Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMn1gO5SgwJLWxCSH8z0_DgGHY16hTd7rJLvDwCTPkNAWidiPQ%40mail.gmail.com.
