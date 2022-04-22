Return-Path: <kasan-dev+bncBD52JJ7JXILRB64LRSJQMGQEMHL2QMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id DBDC650C080
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 21:46:04 +0200 (CEST)
Received: by mail-ua1-x939.google.com with SMTP id w11-20020ab076cb000000b0035cc6b29920sf3646241uaq.12
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 12:46:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650656763; cv=pass;
        d=google.com; s=arc-20160816;
        b=LfpVX0VpWlSGDEJIjGp2tdxj7ksXIcxV7FyqAi5xKaEVK0l/T/g9YnGletoF6FIBUc
         En5SVsC4n6Me41SO2tj4XDdL2OLG3Vy417JKd+smbK6bW8R6zpW4R4fBc+u7tjvTkkJe
         lVpOrXmEmrWZDe+shfNqECY2NxamqxY5Gmtqs82iFvVlOEq6WO7slv+kv96OFJr1EzTH
         pfRNKJCv1/5Ouf+aRvogvTTnTTnfw+CJ/yvglWFZhcviPX9KDCog1vKeN4nRPMGmzWIJ
         xFZo/GCe1Im8I07zTZvtnR53R0xF9s0+95H8JQkMTJ9LlFvUEo1dfIUVUlEOZ0awERDs
         /vKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zk0J4m9G+M+8/vkV20d84Bpdj8RGz+l5vaM0cRrAZf4=;
        b=yhmmIjl++JJMM1cxZEK0oMI8NiLJIWPII6lTYojX4JRkCcsf4BHH/jepOUk4He8cyl
         u7HmwsM2deLPSYh7s9Xovx48wnw5/+zcOg0zT36OKpoIo/iGjnNuWNWqwknHB5eN/0eY
         jK/hx+yaFv6VZy2zxMNIlcmdweHRwrARRsLFtPV8LicL+Q/OI0HsuOmRcCuur5hH/rf3
         7k+EvmGofYd2631EBc1HK/maC2JPCiwAed4feYLxPawSAtKieyeFGAZiTIvPndI7JYxL
         IAul4vspSgYhx5gKYkXY6bvK0NwzQSAR51xgO8/Bunv0plfYmFUFxrZXASIAm/oTzvII
         ZWXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TLtW1qg6;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::a2f as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zk0J4m9G+M+8/vkV20d84Bpdj8RGz+l5vaM0cRrAZf4=;
        b=ULxcbLNNMOm5jxjaXEEC387XWhmhiIcj44dVWcntesUXikFQT8AOGFIiyY5/MNFdPV
         VNGDSNVzI0A5b4YO+004vKfyXZBalbM9hRtYzAGQukI3ux8enhKezEk0Q6W0E1KwFA/5
         rTYrkZyipqq5C7BprODg7hJrjhCY4gpUvfxEyZKU3lc3JVXsGxXe7mfprguUWNn/6EoQ
         GwVOE1R9jjsNhZ+XgtZD6EbQ98s8FzKMbemURmJD0IjzsnZ0WYkA+T/YvhJYqaKnsGMW
         lcVSZ8+X/gIDoZmonbf4jS5qSODOtCU1FHWF3i+plUP9xGWKRoM+pEzWxxf/zxMOgCQy
         PZVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zk0J4m9G+M+8/vkV20d84Bpdj8RGz+l5vaM0cRrAZf4=;
        b=xVo8spbarJMN9XE4BL5WXbXPuDiXoqdhYYEa9PWMuE+gD0rVGU8/v9i0LGOnoyrvud
         PUZwnDftqwGCLcYwkep/DJ3c0ksCowXvwu6a5E4aejosgDRx1q5qEBdTRMc28W9oDI0A
         UlMR/MrKad0OpLKrtdVc3NN8/UrheYtEOUxM3b47dZvpETB7sBcSro94E//VX8A+ArCB
         /F+aUqAr2iygQZqa5gi/+xmCUDuRz+k/NmuwZxv6EsT1t7vow2JgOe5n1NRWWUatorCP
         4jDaNH4oF4OkbzCDuJomfkw+KKdStKzLC7Xp19gywWdpghB7/GlPN9juvI7VWGHjc0lR
         jn8g==
X-Gm-Message-State: AOAM531CZ6+OhPQ5om5s4Fhyqqu63XkCh7zumkC2OMLuGVZk6iCkPYtU
	DCJYNlwsDD/eQShohE7bAf4=
X-Google-Smtp-Source: ABdhPJwNP65xzKAjbwWU4XvMT34VTKrajOnYqB2nAKY4YkttY6Z1ToY9Vt5XZD1uSk+P0n9hrlAqqA==
X-Received: by 2002:a05:6102:15a1:b0:32a:4c67:644b with SMTP id g33-20020a05610215a100b0032a4c67644bmr2123195vsv.83.1650656763699;
        Fri, 22 Apr 2022 12:46:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:2e6:b0:32a:4ac5:3c7f with SMTP id
 j6-20020a05610202e600b0032a4ac53c7fls2696853vsj.2.gmail; Fri, 22 Apr 2022
 12:46:02 -0700 (PDT)
X-Received: by 2002:a67:c593:0:b0:328:6c97:d9ec with SMTP id h19-20020a67c593000000b003286c97d9ecmr1884956vsk.25.1650656762171;
        Fri, 22 Apr 2022 12:46:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650656762; cv=none;
        d=google.com; s=arc-20160816;
        b=oBqu4OgQP1RunMytfto4jxQ8B9w4cnUMMn/Bvoh82eR7oohKqqDNauJuCwXhDAK+bz
         YpykbvdwC/o9lWf9N/98gB1z4coUhi2azUDfDNygIZRFeYBhdNzjlyDeR+Zsg8+AtygM
         yJ1apIo4FCzNBqF5sIQb2bwFkvmR5G9dur3xBZr/HNQDTJuygE4unAoqApn2joEmOzFw
         IODDFV0GLZ9F77B0Y+XShzrBQoAFJFbGEaj9O8yToZ4tF9SR2dRJCEVWSBkvefL1ONKm
         ambi6foNW6H29c7vs+4Siqqaky0TVdPML0LUEp1YXANLAjjEUXncGnQ6ZFE5HJiAz9Dk
         jIXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NDEqcBhWfl+VEeADqX1cuVP35Bwxo39I117kMXuRP20=;
        b=Vq9YBO8EamzpumAFTaIvsC8y/zkS7zwTNpYFjsmzWDj4LV3Qglo0LBINCYQ2F8Ip7J
         fI2R33JNhDv78Dt2cizkQYQnLncYxyVGPQ9KkBDOiwaJEeGCzvCJ16ZcgK5D6F44ejFr
         l0+ryDQvvRip8GanYulsfgrJvaoRLpaJb1zPFY1fsPfDqf2kKqumptO0DV00cxok5z0T
         ynvbtHYJ0Pc+ruVmWpIZk22j2yMBofH+LiPVENR0ByJ+vlARvF9LJdMexyPCfZDJ7535
         s9NASIAN4QJBbGR1uN/7+rBl7SH98+ZBFasZz/DZJ7VJu+vy4q0P9RbX0PKxWgwnsPnp
         gGWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TLtW1qg6;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::a2f as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa2f.google.com (mail-vk1-xa2f.google.com. [2607:f8b0:4864:20::a2f])
        by gmr-mx.google.com with ESMTPS id j13-20020ac5c64d000000b0034911e6ef9fsi951711vkl.4.2022.04.22.12.46.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Apr 2022 12:46:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::a2f as permitted sender) client-ip=2607:f8b0:4864:20::a2f;
Received: by mail-vk1-xa2f.google.com with SMTP id bc42so4304844vkb.12
        for <kasan-dev@googlegroups.com>; Fri, 22 Apr 2022 12:46:02 -0700 (PDT)
X-Received: by 2002:a1f:314b:0:b0:331:fff6:a89e with SMTP id
 x72-20020a1f314b000000b00331fff6a89emr2323548vkx.26.1650656761610; Fri, 22
 Apr 2022 12:46:01 -0700 (PDT)
MIME-Version: 1.0
References: <20220421211549.3884453-1-pcc@google.com> <CA+fCnZdouu-v1MKndMbeOw96pknGN=77=8B=_K4kedRROrL9pw@mail.gmail.com>
In-Reply-To: <CA+fCnZdouu-v1MKndMbeOw96pknGN=77=8B=_K4kedRROrL9pw@mail.gmail.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 22 Apr 2022 12:45:50 -0700
Message-ID: <CAMn1gO5GXVJ37wgpvnxymWGBhWn=HjopviPC6zd=K4cBkzuTbA@mail.gmail.com>
Subject: Re: [PATCH v2] mm: make minimum slab alignment a runtime property
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Pekka Enberg <penberg@kernel.org>, roman.gushchin@linux.dev, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, David Rientjes <rientjes@google.com>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Eric Biederman <ebiederm@xmission.com>, 
	Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=TLtW1qg6;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::a2f as
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

On Fri, Apr 22, 2022 at 9:04 AM Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Thu, Apr 21, 2022 at 11:16 PM Peter Collingbourne <pcc@google.com> wrote:
> >
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
>
> Thanks for the improvement, Peter!
>
> Overall, the patch looks good to me:
>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

> While looking at the code, I noticed a couple of issues in the already
> existing comments. Not sure if they are worth fixing, but I'll point
> them out just in case.
>
> > Link: https://linux-review.googlesource.com/id/I752e725179b43b144153f4b6f584ceb646473ead
> > Signed-off-by: Peter Collingbourne <pcc@google.com>
> > ---
> > v2:
> > - use max instead of max_t in flat_stack_align()
> >
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
> > -#define ARCH_SLAB_MINALIGN     8
> > +#define ARCH_SLAB_MIN_MINALIGN 8
> >  #endif
> >
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
> >  #define CTR_L1IP_SHIFT         14
> >  #define CTR_L1IP_MASK          3
> > @@ -49,15 +50,21 @@
> >   */
> >  #define ARCH_DMA_MINALIGN      (128)
> >
> > -#ifdef CONFIG_KASAN_SW_TAGS
> > -#define ARCH_SLAB_MINALIGN     (1ULL << KASAN_SHADOW_SCALE_SHIFT)
> > -#elif defined(CONFIG_KASAN_HW_TAGS)
> > -#define ARCH_SLAB_MINALIGN     MTE_GRANULE_SIZE
> > -#endif
> > -
> >  #ifndef __ASSEMBLY__
> >
> >  #include <linux/bitops.h>
> > +#include <linux/kasan-enabled.h>
> > +
> > +#ifdef CONFIG_KASAN_SW_TAGS
> > +#define ARCH_SLAB_MIN_MINALIGN (1ULL << KASAN_SHADOW_SCALE_SHIFT)
> > +#elif defined(CONFIG_KASAN_HW_TAGS)
> > +static inline size_t arch_slab_minalign(void)
> > +{
> > +       return kasan_hw_tags_enabled() ? MTE_GRANULE_SIZE :
> > +                                        __alignof__(unsigned long long);
> > +}
> > +#define arch_slab_minalign() arch_slab_minalign()
> > +#endif
> >
> >  #define ICACHEF_ALIASING       0
> >  #define ICACHEF_VPIPT          1
> > diff --git a/arch/microblaze/include/asm/page.h b/arch/microblaze/include/asm/page.h
> > index 4b8b2fa78fc5..ccdbc1da3c3e 100644
> > --- a/arch/microblaze/include/asm/page.h
> > +++ b/arch/microblaze/include/asm/page.h
> > @@ -33,7 +33,7 @@
> >  /* MS be sure that SLAB allocates aligned objects */
> >  #define ARCH_DMA_MINALIGN      L1_CACHE_BYTES
> >
> > -#define ARCH_SLAB_MINALIGN     L1_CACHE_BYTES
> > +#define ARCH_SLAB_MIN_MINALIGN L1_CACHE_BYTES
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
> > -#define ARCH_SLAB_MINALIGN     16
> > +#define ARCH_SLAB_MIN_MINALIGN 16
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
> > -#define ARCH_SLAB_MINALIGN     __alignof__(unsigned long long)
> > +#define ARCH_SLAB_MIN_MINALIGN __alignof__(unsigned long long)
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
> > index 626898150011..23ce3439eafa 100644
> > --- a/fs/binfmt_flat.c
> > +++ b/fs/binfmt_flat.c
> > @@ -64,7 +64,10 @@
> >   * Here we can be a bit looser than the data sections since this
> >   * needs to only meet arch ABI requirements.
> >   */
> > -#define FLAT_STACK_ALIGN       max_t(unsigned long, sizeof(void *), ARCH_SLAB_MINALIGN)
> > +static size_t flat_stack_align(void)
> > +{
> > +       return max(sizeof(void *), arch_slab_minalign());
> > +}
> >
> >  #define RELOC_FAILED 0xff00ff01                /* Relocation incorrect somewhere */
> >  #define UNLOADED_LIB 0x7ff000ff                /* Placeholder for unused library */
> > @@ -148,7 +151,7 @@ static int create_flat_tables(struct linux_binprm *bprm, unsigned long arg_start
> >                 sp -= 2; /* argvp + envp */
> >         sp -= 1;  /* &argc */
> >
> > -       current->mm->start_stack = (unsigned long)sp & -FLAT_STACK_ALIGN;
> > +       current->mm->start_stack = (unsigned long)sp & -flat_stack_align();
> >         sp = (unsigned long __user *)current->mm->start_stack;
> >
> >         if (put_user(bprm->argc, sp++))
> > @@ -966,7 +969,7 @@ static int load_flat_binary(struct linux_binprm *bprm)
> >  #endif
> >         stack_len += (bprm->argc + 1) * sizeof(char *);   /* the argv array */
> >         stack_len += (bprm->envc + 1) * sizeof(char *);   /* the envp array */
> > -       stack_len = ALIGN(stack_len, FLAT_STACK_ALIGN);
> > +       stack_len = ALIGN(stack_len, flat_stack_align());
> >
> >         res = load_flat_file(bprm, &libinfo, 0, &stack_len);
> >         if (res < 0)
> > diff --git a/include/crypto/hash.h b/include/crypto/hash.h
> > index f140e4643949..442c290f458c 100644
> > --- a/include/crypto/hash.h
> > +++ b/include/crypto/hash.h
> > @@ -149,7 +149,7 @@ struct ahash_alg {
> >
> >  struct shash_desc {
> >         struct crypto_shash *tfm;
> > -       void *__ctx[] __aligned(ARCH_SLAB_MINALIGN);
> > +       void *__ctx[] __aligned(ARCH_SLAB_MIN_MINALIGN);
> >  };
> >
> >  #define HASH_MAX_DIGESTSIZE     64
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
> > +#ifndef arch_slab_minalign
> > +static inline size_t arch_slab_minalign(void)
> > +{
> > +       return ARCH_SLAB_MIN_MINALIGN;
> > +}
> >  #endif
> >
> >  /*
> >   * kmalloc and friends return ARCH_KMALLOC_MINALIGN aligned
> > - * pointers. kmem_cache_alloc and friends return ARCH_SLAB_MINALIGN
> > + * pointers. kmem_cache_alloc and friends return ARCH_SLAB_MIN_MINALIGN
> >   * aligned pointers.
>
> This comment is not precise: kmalloc relies on kmem_cache_alloc, so
> kmalloc technically returns pointers aligned to
> max(ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MIN_MINALIGN). See
> create_kmalloc_cache()->create_boot_cache()->calculate_alignment() for
> SLAB and SLUB and __do_kmalloc_node() for SLOB. This alignment is
> stronger than the one is specified for __assume_kmalloc_alignment
> below, so the code should be fine. However, the comment is confusing.
>
> Also, the comment next to the ARCH_KMALLOC_MINALIGN definition says
> "Setting ARCH_KMALLOC_MINALIGN in arch headers" while it should say
> "Setting ARCH_DMA_MINALIGN in arch headers".

Good catches. Let's fix these issues separately (especially since I
reverted the ARCH_SLAB_MIN_MINALIGN change so the patches shouldn't
conflict). Would you like to send patches? I can if not.

Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMn1gO5GXVJ37wgpvnxymWGBhWn%3DHjopviPC6zd%3DK4cBkzuTbA%40mail.gmail.com.
