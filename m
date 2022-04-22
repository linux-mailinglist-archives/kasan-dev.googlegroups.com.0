Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBGOERKJQMGQE4QGEYYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id D9F0A50B781
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 14:39:54 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id t12-20020a170902a5cc00b001590717a080sf4591226plq.10
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 05:39:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650631193; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z/0SsmfnV+biaKCW2E4IzpZcvxtgrq4n46u4BzAiCMr1bKp46gGl11DPWZ8IVZgyin
         Zrfc8bIFkcmqSR1+Nq6W6qgp8t/sRAvT76lmxsQEYD/Dga5Z9HYFDQJaKc91p7dkgHuG
         6D04NtoQ46WigYg8qFxgPy4KDBNvdP/Pa3OD4H/UAaobrS6n7fxMCGO3YpdhMAWDMqfR
         aqih4B1Q7IDY5sYmzTjxjBojCrdV5MDeimWbRT1XGWosP5yhLT+R5+NQMgKc6RV6urAV
         aPshQaovSncBlIzC0M6uOcEHnmjaz4ZTOEQn5e3oq4tz3Wd3UmdvagRwhVTznqmhqMyr
         S4TA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=utMjmF/56k7+z0O9tNIrZH3HxxpkSXZMkjZ5Cyiav4w=;
        b=Hs86eh4NKQBvAD9wQjs572X1lTAy5ckgyoycv36vy2qmsNjPmvevkW9vI1cdjrpA3z
         KWT+d5lx7+3Yu2c/WQVYEMCd14fIGlO540hUrrAj7vtC8w2DE58la0oxygaqu90VtztG
         XFwULRdXQMoWE6IJMjIOkNzGFJLX89M8CtwJUjDBrs6eBJfx5Mwlqg4UFc+MD8QkWTJl
         51TifUxgINTC38RB3dQYEuU5GuG/0rsZ2CcFH1WdnVsMo1QtEH6w3WGXEcxjq3+Lnxte
         PUCLGzf8fPZ2k1a/zDW2Afq8p0rxzSvx/tbp7C0V1pqlJen9dpl8AaHrvoIgShRoGNdg
         tkVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=YAiSF1MG;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=utMjmF/56k7+z0O9tNIrZH3HxxpkSXZMkjZ5Cyiav4w=;
        b=MBYhhnzST00QXX7FGvA3EwZycdKx6YxYZMIx4rqayzstpb31AGvCtdgyuPvKQ9Xvyn
         TnEnf47iR0+rBjZMKVKQe3ZaezoSv9WcPuuOAy3ALTDH/CUSHi3oTJ8P1DR+H/l4BWS9
         4UL8c8sndbt9Srct/pSQsTl3uj7Dz/0PgqwTY5G6EYPNmG2N29HU1nFtdp2N9bSvHeJa
         5CCeBTY6KSOMULLJNuL+cb1lOe1SajJrEFsguWkpd44Xk1wNhc1YRlwojwjoc3PhNrt/
         dCpI7qIB7kajISTqyNxthz5M+9ClqzFORtjXuOExE9xjXsd0607Z0VuI9tonMqIFMp00
         5Lwg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=utMjmF/56k7+z0O9tNIrZH3HxxpkSXZMkjZ5Cyiav4w=;
        b=jqVYCL4uyPLKVJ6/qVfCwEROIBwSqaDuqOE7nRHlzSUd2sRQ9edtvBo9seWmqhyvHm
         Tzo5NWHsE2Ae32iLgcuCtVbYcul6hTxVFlxdrT7WPoslCkPcYAwFZsw1O7QuYgTOLRPb
         TiO6sXkqgU0Faqc+Dmlq8/1IJz5cuOBFXrbZP4iqb6o7i5L4GJMrPfuN9p58eZInNDXR
         DXl2FsuzN5jtzJDx0dMenFJ/qgDlcUSY7KjGuRy+Sw+S3XmNLT6nszPjoqpHopmmUMva
         /1gkovrhDk9Of5Kxeyv+ED4G7kAemS9ExP9Kcdf01nhbkwDW9CRlCvbqeE7srwA0USc6
         9u2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=utMjmF/56k7+z0O9tNIrZH3HxxpkSXZMkjZ5Cyiav4w=;
        b=s7FiNU5JgKjfbdRhqmSaW0+M6+hwdmIMU+FD8syRjABUx4ro5AUvDgyXeiwCTcayy+
         x/qKkRsJwSiZbQK0GGvYYeywWMNpgAz82S2Y12a0f3LdQKdvSv4NIXwA0P35Zb/W5hbx
         qCSIFjK7tpBMxSTJqA7kD8illSayX/YZTb59tupN1lJ0yq3Cu4p68Md+zh19I2pcLGXj
         mAYojFRaqaP9IgDcU31/RkBnz3G8xab3DN/IFNyW+C4VzUmxT00n2rXPkHCBUzFwxVvM
         GQ4vXgpXbJlj9rCX6b0TAzPLK9Y3/dscvh0oNh5JdMoM5M7hcVlpPN6sJEN/KiWGB9GP
         mUyA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5312gXOSVjX5JiI6WrUcC75uHR69Vhg+7BN/TgJ+nR7RlY/OAo7Y
	naGic8eIxIMfiJAk1OWbEZk=
X-Google-Smtp-Source: ABdhPJzGS+nRFDkeek2SvpnJ1sIKGvioXFOHLv7hbt2evavCcaDPFhFYsSXRCec+sRG9jaK6gvz7kQ==
X-Received: by 2002:a17:90a:d3d3:b0:1bf:2e8d:3175 with SMTP id d19-20020a17090ad3d300b001bf2e8d3175mr5260286pjw.2.1650631193240;
        Fri, 22 Apr 2022 05:39:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2490:b0:50a:57bd:48e5 with SMTP id
 c16-20020a056a00249000b0050a57bd48e5ls5686746pfv.11.gmail; Fri, 22 Apr 2022
 05:39:52 -0700 (PDT)
X-Received: by 2002:a63:d758:0:b0:380:fba9:f6e5 with SMTP id w24-20020a63d758000000b00380fba9f6e5mr3808460pgi.330.1650631192116;
        Fri, 22 Apr 2022 05:39:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650631192; cv=none;
        d=google.com; s=arc-20160816;
        b=FETusfYz/o8iMzefqpa40jRBXr53rUH/CGARdbcU7d7nlFLPkhSJbiPS2Rd+0t69qq
         OazCUz581DN3AcGu9HYJBHIDZDhUPoPItI7Rs7LEKupCy9ujpI0fNHW/ghIr6gIMz7th
         L3Vzf1laTJv1a+h1NJnS4+PKr1LRrFYjKLPtWLvliz8wGKe/jK2cc63BvhKFn66+Gezz
         NJvp0q3cyMk23riKm2afzE/NSnn9Kl/cHwiFXrjM8HjQXLiURiPxkecy8NTwhW+8oAJI
         6dSU2vbXdN4DOUSKOt2WKz6RUTllaCPYYimbeDjD6AGvU0bmQ9RGBCARXlsjrJ5nyI8m
         t26g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=IwbH4EAZhLL7wdohmylm8Erjb2IpSnfnnODWWk60U1g=;
        b=hjcNSxyLETQV4qweI2SN23LrwBfieEisJlSrDCVGbMQd4ga6w4uDh/PuF0jiq3IIFV
         Tt2w+XHS1PIjP201ViZ09GsZWEHo+akcJnw0rjPSudendyxmC7kprmYQJXsvG/YLQ1Tr
         0yzL/+7nR/1Sf1pZY7fkNBMN2E4HIH965hk0MCESvQ0twICNFBRqu/jaVojUNehHRtpF
         3UrC6WpaxczkM4lzqYWtUJZNCzceaw5hg7LCK4W9qAt94mxC8tLVbS29FXTvmR0La6DY
         hKsjajRAj6n8KIPi0YKBhO+2uoeQFSml7GXh79OZeguxgPGp/LpQI4uZskIxqJN0LFPu
         45Nw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=YAiSF1MG;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id t199-20020a635fd0000000b0039d9d897c98si650229pgb.2.2022.04.22.05.39.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Apr 2022 05:39:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id h12so6907642plf.12
        for <kasan-dev@googlegroups.com>; Fri, 22 Apr 2022 05:39:52 -0700 (PDT)
X-Received: by 2002:a17:90b:2691:b0:1d2:72b9:b9b with SMTP id pl17-20020a17090b269100b001d272b90b9bmr5324787pjb.80.1650631191628;
        Fri, 22 Apr 2022 05:39:51 -0700 (PDT)
Received: from hyeyoo ([114.29.24.243])
        by smtp.gmail.com with ESMTPSA id f10-20020a17090a9b0a00b001cd4989ff5asm6082785pjp.33.2022.04.22.05.39.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Apr 2022 05:39:50 -0700 (PDT)
Date: Fri, 22 Apr 2022 21:39:42 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	vbabka@suse.cz, penberg@kernel.org, cl@linux.org,
	roman.gushchin@linux.dev, iamjoonsoo.kim@lge.com,
	rientjes@google.com, Catalin Marinas <catalin.marinas@arm.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Kees Cook <keescook@chromium.org>
Subject: Re: [PATCH] mm: make minimum slab alignment a runtime property
Message-ID: <YmKiDt12Xb/KXX3z@hyeyoo>
References: <20220421031738.3168157-1-pcc@google.com>
 <YmFORWyMAVacycu5@hyeyoo>
 <CAMn1gO5xHZvFSSsW5sTVaUBN_gS-cYYNMG3PnpgCmh7kk_Zx7Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAMn1gO5xHZvFSSsW5sTVaUBN_gS-cYYNMG3PnpgCmh7kk_Zx7Q@mail.gmail.com>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=YAiSF1MG;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::629
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Apr 21, 2022 at 10:16:25AM -0700, Peter Collingbourne wrote:
> On Thu, Apr 21, 2022 at 5:30 AM Hyeonggon Yoo <42.hyeyoo@gmail.com> wrote:
> >
> > On Wed, Apr 20, 2022 at 08:17:38PM -0700, Peter Collingbourne wrote:
> > > When CONFIG_KASAN_HW_TAGS is enabled we currently increase the minimum
> > > slab alignment to 16. This happens even if MTE is not supported in
> > > hardware or disabled via kasan=off, which creates an unnecessary
> > > memory overhead in those cases. Eliminate this overhead by making
> > > the minimum slab alignment a runtime property and only aligning to
> > > 16 if KASAN is enabled at runtime.
> > >
> > > On a DragonBoard 845c (non-MTE hardware) with a kernel built with
> > > CONFIG_KASAN_HW_TAGS, waiting for quiescence after a full Android
> > > boot I see the following Slab measurements in /proc/meminfo (median
> > > of 3 reboots):
> > >
> > > Before: 169020 kB
> > > After:  167304 kB
> > >
> > > Link: https://linux-review.googlesource.com/id/I752e725179b43b144153f4b6f584ceb646473ead
> > > Signed-off-by: Peter Collingbourne <pcc@google.com>
> > > ---
> > >  arch/arc/include/asm/cache.h        |  4 ++--
> > >  arch/arm/include/asm/cache.h        |  2 +-
> > >  arch/arm64/include/asm/cache.h      | 19 +++++++++++++------
> > >  arch/microblaze/include/asm/page.h  |  2 +-
> > >  arch/riscv/include/asm/cache.h      |  2 +-
> > >  arch/sparc/include/asm/cache.h      |  2 +-
> > >  arch/xtensa/include/asm/processor.h |  2 +-
> > >  fs/binfmt_flat.c                    |  9 ++++++---
> > >  include/crypto/hash.h               |  2 +-
> > >  include/linux/slab.h                | 22 +++++++++++++++++-----
> > >  mm/slab.c                           |  7 +++----
> > >  mm/slab_common.c                    |  3 +--
> > >  mm/slob.c                           |  6 +++---
> > >  13 files changed, 51 insertions(+), 31 deletions(-)
> >
> > [+Cc slab people, Catalin and affected subsystems' folks]
> >
> > just FYI, There is similar discussion about kmalloc caches' alignment.
> > https://lore.kernel.org/linux-mm/20220405135758.774016-1-catalin.marinas@arm.com/
> >
> > It seems this is another demand for runtime resolution of slab
> > alignment, But slightly different from kmalloc as there is no requirement
> > for DMA alignment.
> >
> > >
> > > diff --git a/arch/arc/include/asm/cache.h b/arch/arc/include/asm/cache.h
> > > index f0f1fc5d62b6..b6a7763fd5d6 100644
> > > --- a/arch/arc/include/asm/cache.h
> > > +++ b/arch/arc/include/asm/cache.h
> > > @@ -55,11 +55,11 @@
> > >   * Make sure slab-allocated buffers are 64-bit aligned when atomic64_t uses
> > >   * ARCv2 64-bit atomics (LLOCKD/SCONDD). This guarantess runtime 64-bit
> > >   * alignment for any atomic64_t embedded in buffer.
> > > - * Default ARCH_SLAB_MINALIGN is __alignof__(long long) which has a relaxed
> > > + * Default ARCH_SLAB_MIN_MINALIGN is __alignof__(long long) which has a relaxed
> > >   * value of 4 (and not 8) in ARC ABI.
> > >   */
> > >  #if defined(CONFIG_ARC_HAS_LL64) && defined(CONFIG_ARC_HAS_LLSC)
> > > -#define ARCH_SLAB_MINALIGN   8
> > > +#define ARCH_SLAB_MIN_MINALIGN       8
> > >  #endifh
> > >
> >
> > Why isn't it just ARCH_SLAB_MINALIGN?
> 
> Because this is the minimum possible value of the minimum alignment
> decided at runtime. I chose to give it a different name to
> arch_slab_minalign() because the two have different meanings.
> 
> Granted this isn't a great name because of the stuttering but
> hopefully it will prompt folks to investigate the meaning of this
> constant if necessary.

To be honest I don't care much about the name but just thought it's just better
to be consistent with Catalin's series: ARCH_KMALLOC_MINALIGN for static
alignment and arch_kmalloc_minalign() for (possibly bigger) alignment decided
at runtime.

> > >  extern int ioc_enable;
> > > diff --git a/arch/arm/include/asm/cache.h b/arch/arm/include/asm/cache.h
> > > index e3ea34558ada..3e1018bb9805 100644
> > > --- a/arch/arm/include/asm/cache.h
> > > +++ b/arch/arm/include/asm/cache.h
> > > @@ -21,7 +21,7 @@
> > >   * With EABI on ARMv5 and above we must have 64-bit aligned slab pointers.
> > >   */
> > >  #if defined(CONFIG_AEABI) && (__LINUX_ARM_ARCH__ >= 5)
> > > -#define ARCH_SLAB_MINALIGN 8
> > > +#define ARCH_SLAB_MIN_MINALIGN 8
> > >  #endif
> > >
> > >  #define __read_mostly __section(".data..read_mostly")
> > > diff --git a/arch/arm64/include/asm/cache.h b/arch/arm64/include/asm/cache.h
> > > index a074459f8f2f..38f171591c3f 100644
> > > --- a/arch/arm64/include/asm/cache.h
> > > +++ b/arch/arm64/include/asm/cache.h
> > > @@ -6,6 +6,7 @@
> > >  #define __ASM_CACHE_H
> > >
> > >  #include <asm/cputype.h>
> > > +#include <asm/mte-def.h>
> > >
> > >  #define CTR_L1IP_SHIFT               14
> > >  #define CTR_L1IP_MASK                3
> > > @@ -49,15 +50,21 @@
> > >   */
> > >  #define ARCH_DMA_MINALIGN    (128)
> > >
> > > -#ifdef CONFIG_KASAN_SW_TAGS
> > > -#define ARCH_SLAB_MINALIGN   (1ULL << KASAN_SHADOW_SCALE_SHIFT)
> > > -#elif defined(CONFIG_KASAN_HW_TAGS)
> > > -#define ARCH_SLAB_MINALIGN   MTE_GRANULE_SIZE
> > > -#endif
> > > -
> > >  #ifndef __ASSEMBLY__
> > >
> > >  #include <linux/bitops.h>
> > > +#include <linux/kasan-enabled.h>
> > > +
> > > +#ifdef CONFIG_KASAN_SW_TAGS
> > > +#define ARCH_SLAB_MIN_MINALIGN       (1ULL << KASAN_SHADOW_SCALE_SHIFT)
> > > +#elif defined(CONFIG_KASAN_HW_TAGS)
> > > +static inline size_t arch_slab_minalign(void)
> > > +{
> > > +     return kasan_hw_tags_enabled() ? MTE_GRANULE_SIZE :
> > > +                                      __alignof__(unsigned long long);
> > > +}
> > > +#define arch_slab_minalign() arch_slab_minalign()
> > > +#endif
> > >
> >
> > kasan_hw_tags_enabled() is also false when kasan is just not initialized yet.
> > What about writing a new helper something like kasan_is_disabled()
> > instead?
> 
> The decision of whether to enable KASAN is made early, before the slab
> allocator is initialized (start_kernel -> smp_prepare_boot_cpu ->
> kasan_init_hw_tags vs start_kernel -> mm_init -> kmem_cache_init). If
> you think about it, this needs to be the case for KASAN to operate
> correctly because it influences the behavior of the slab allocator via
> the kasan_*poison* hooks. So I don't think we can end up calling this
> function before then.

Sounds not bad. I wanted to make sure the value of arch_slab_minaligned()
is not changed during its execution.

Just some part of me thought something like this would be more
intuitive/robust.

if (systems_supports_mte() && kasan_arg != KASAN_ARG_OFF)
	return MTE_GRANULE_SIZE;
else
	return __alignof__(unsigned long long);

> > >  #define ICACHEF_ALIASING     0
> > >  #define ICACHEF_VPIPT                1
> > > diff --git a/arch/microblaze/include/asm/page.h b/arch/microblaze/include/asm/page.h
> > > index 4b8b2fa78fc5..ccdbc1da3c3e 100644
> > > --- a/arch/microblaze/include/asm/page.h
> > > +++ b/arch/microblaze/include/asm/page.h
> > > @@ -33,7 +33,7 @@
> > >  /* MS be sure that SLAB allocates aligned objects */
> > >  #define ARCH_DMA_MINALIGN    L1_CACHE_BYTES
> > >
> > > -#define ARCH_SLAB_MINALIGN   L1_CACHE_BYTES
> > > +#define ARCH_SLAB_MIN_MINALIGN       L1_CACHE_BYTES
> > >
> > >  /*
> > >   * PAGE_OFFSET -- the first address of the first page of memory. With MMU
> > > diff --git a/arch/riscv/include/asm/cache.h b/arch/riscv/include/asm/cache.h
> > > index 9b58b104559e..7beb3b5d27c7 100644
> > > --- a/arch/riscv/include/asm/cache.h
> > > +++ b/arch/riscv/include/asm/cache.h
> > > @@ -16,7 +16,7 @@
> > >   * the flat loader aligns it accordingly.
> > >   */
> > >  #ifndef CONFIG_MMU
> > > -#define ARCH_SLAB_MINALIGN   16
> > > +#define ARCH_SLAB_MIN_MINALIGN       16
> > >  #endif
> > >
> > >  #endif /* _ASM_RISCV_CACHE_H */
> > > diff --git a/arch/sparc/include/asm/cache.h b/arch/sparc/include/asm/cache.h
> > > index e62fd0e72606..9d8cb4687b7e 100644
> > > --- a/arch/sparc/include/asm/cache.h
> > > +++ b/arch/sparc/include/asm/cache.h
> > > @@ -8,7 +8,7 @@
> > >  #ifndef _SPARC_CACHE_H
> > >  #define _SPARC_CACHE_H
> > >
> > > -#define ARCH_SLAB_MINALIGN   __alignof__(unsigned long long)
> > > +#define ARCH_SLAB_MIN_MINALIGN       __alignof__(unsigned long long)
> > >
> > >  #define L1_CACHE_SHIFT 5
> > >  #define L1_CACHE_BYTES 32
> > > diff --git a/arch/xtensa/include/asm/processor.h b/arch/xtensa/include/asm/processor.h
> > > index 4489a27d527a..e3ea278e3fcf 100644
> > > --- a/arch/xtensa/include/asm/processor.h
> > > +++ b/arch/xtensa/include/asm/processor.h
> > > @@ -18,7 +18,7 @@
> > >  #include <asm/types.h>
> > >  #include <asm/regs.h>
> > >
> > > -#define ARCH_SLAB_MINALIGN XTENSA_STACK_ALIGNMENT
> > > +#define ARCH_SLAB_MIN_MINALIGN XTENSA_STACK_ALIGNMENT
> > >
> > >  /*
> > >   * User space process size: 1 GB.
> > > diff --git a/fs/binfmt_flat.c b/fs/binfmt_flat.c
> > > index 626898150011..8ff1bf7d1e87 100644
> > > --- a/fs/binfmt_flat.c
> > > +++ b/fs/binfmt_flat.c
> > > @@ -64,7 +64,10 @@
> > >   * Here we can be a bit looser than the data sections since this
> > >   * needs to only meet arch ABI requirements.
> > >   */
> > > -#define FLAT_STACK_ALIGN     max_t(unsigned long, sizeof(void *), ARCH_SLAB_MINALIGN)
> > > +static size_t flat_stack_align(void)
> > > +{
> > > +     return max_t(unsigned long, sizeof(void *), arch_slab_minalign());
> > > +}
> > >
> > >  #define RELOC_FAILED 0xff00ff01              /* Relocation incorrect somewhere */
> > >  #define UNLOADED_LIB 0x7ff000ff              /* Placeholder for unused library */
> > > @@ -148,7 +151,7 @@ static int create_flat_tables(struct linux_binprm *bprm, unsigned long arg_start
> > >               sp -= 2; /* argvp + envp */
> > >       sp -= 1;  /* &argc */
> > >
> > > -     current->mm->start_stack = (unsigned long)sp & -FLAT_STACK_ALIGN;
> > > +     current->mm->start_stack = (unsigned long)sp & -flat_stack_align();
> > >       sp = (unsigned long __user *)current->mm->start_stack;
> > >
> > >       if (put_user(bprm->argc, sp++))
> > > @@ -966,7 +969,7 @@ static int load_flat_binary(struct linux_binprm *bprm)
> > >  #endif
> > >       stack_len += (bprm->argc + 1) * sizeof(char *);   /* the argv array */
> > >       stack_len += (bprm->envc + 1) * sizeof(char *);   /* the envp array */
> > > -     stack_len = ALIGN(stack_len, FLAT_STACK_ALIGN);
> > > +     stack_len = ALIGN(stack_len, flat_stack_align());
> > >
> > >       res = load_flat_file(bprm, &libinfo, 0, &stack_len);
> > >       if (res < 0)
> > > diff --git a/include/crypto/hash.h b/include/crypto/hash.h
> > > index f140e4643949..442c290f458c 100644
> > > --- a/include/crypto/hash.h
> > > +++ b/include/crypto/hash.h
> > > @@ -149,7 +149,7 @@ struct ahash_alg {
> > >
> > >  struct shash_desc {
> > >       struct crypto_shash *tfm;
> > > -     void *__ctx[] __aligned(ARCH_SLAB_MINALIGN);
> > > +     void *__ctx[] __aligned(ARCH_SLAB_MIN_MINALIGN);
> > >  };
> > >
> > >  #define HASH_MAX_DIGESTSIZE   64
> > > diff --git a/include/linux/slab.h b/include/linux/slab.h
> > > index 373b3ef99f4e..80e517593372 100644
> > > --- a/include/linux/slab.h
> > > +++ b/include/linux/slab.h
> > > @@ -201,21 +201,33 @@ void kmem_dump_obj(void *object);
> > >  #endif
> > >
> > >  /*
> > > - * Setting ARCH_SLAB_MINALIGN in arch headers allows a different alignment.
> > > + * Setting ARCH_SLAB_MIN_MINALIGN in arch headers allows a different alignment.
> > >   * Intended for arches that get misalignment faults even for 64 bit integer
> > >   * aligned buffers.
> > >   */
> > > -#ifndef ARCH_SLAB_MINALIGN
> > > -#define ARCH_SLAB_MINALIGN __alignof__(unsigned long long)
> > > +#ifndef ARCH_SLAB_MIN_MINALIGN
> > > +#define ARCH_SLAB_MIN_MINALIGN __alignof__(unsigned long long)
> > > +#endif
> > > +
> > > +/*
> > > + * Arches can define this function if they want to decide the minimum slab
> > > + * alignment at runtime. The value returned by the function must be
> > > + * >= ARCH_SLAB_MIN_MINALIGN.
> > > + */
> >
> > Not only the value should be bigger than or equal to ARCH_SLAB_MIN_MINALIGN,
> > it should be compatible with ARCH_SLAB_MIN_MINALIGN.
> 
> What's the difference?
>

231 /*
232  * kmalloc and friends return ARCH_KMALLOC_MINALIGN aligned
233  * pointers. kmem_cache_alloc and friends return ARCH_SLAB_MIN_MINALIGN
234  * aligned pointers.
235  */
236 #define __assume_kmalloc_alignment __assume_aligned(ARCH_KMALLOC_MINALIGN)
237 #define __assume_slab_alignment __assume_aligned(ARCH_SLAB_MIN_MINALIGN)
238 #define __assume_page_alignment __assume_aligned(PAGE_SIZE)

I mean actual slab object size should be both ARCH_SLAB_MIN_MINALIGN-aligned and
arch_slab_minalign()-aligned. Otherwise we are lying to the compiler.

It's okay If we use just power-of-two alignment.
But adding a comment wouldn't harm :)


Thank you for the work. I think the patch makes sense as usually people
don't build and install their kernel for arm64 machines.

> Peter

-- 
Thanks,
Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YmKiDt12Xb/KXX3z%40hyeyoo.
