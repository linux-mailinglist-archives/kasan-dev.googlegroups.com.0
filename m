Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBCNLROJQMGQEJR2WB5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id A256C50BCC2
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 18:19:21 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id b12-20020a05600c4e0c00b003914432b970sf3903371wmq.8
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 09:19:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650644361; cv=pass;
        d=google.com; s=arc-20160816;
        b=w/R7/mrwa77CAAUOEjCcLkRDNE9XRPp01v+wX5LC/A6yn9WXygGBExEKML/5rpC7VQ
         htKFgkXKMascA7Sj5D7jn1LPnIjETeEPFusQzDeZwJSyoPaaIRpDEGmm9CqHPKd4c9Fh
         GT+REI4h4zQSunhXyluD8VXCb0FgJdRMpcXvtGqzq0sSgV0lo1kekw60P5xg9Z/PCPY0
         cPPKLMmswby0lxIQxtQQOXUCO8bErXJC32a4nIYKuxftHbSWj87O6ESQsP9ZqytwWjPX
         FT5Bw6dZGGmUUsunZvBRihrTrHHsO5N2rrcHDHsf/wFUnDklTLhYAIOh3x6inBuHP3Mh
         3hsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:subject:from:references
         :cc:to:content-language:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=em7ifQ9LxLNzLpSvNoE2y3O06q9SPH7vxesXv4O1rBg=;
        b=HEKeNC3jIsvc2PKsfgCrqiKai4jkTBPWU4IBZXt9FY6kIfmOxfctQbbVv+K1k6sTSU
         O96W+bCbKSjvoEO0t75grm67cL83uRU7N8PuQbU54UkYjtLGHURBB5eGXbFrOSnvi3OB
         8D+hAKD4a2VZyXHeq/dZ6sXJErmjgXor+An2574uUPx3NepRTe9zR/tMkNIFR2gFlJXr
         Luq3h/B2YqMpxuCO6LRv+UOQBKQjpPdKO80yt2orJWEoYoBPWC9pw3v+BrQDATiVAMdA
         9mmegDQQwFvoax0Cw48ytthYO5qum34y36wA+ExeUMxOslHC4XcZOY6Qw2vtL5kHq7KY
         FCQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=PxC97LDX;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:content-language:to
         :cc:references:from:subject:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=em7ifQ9LxLNzLpSvNoE2y3O06q9SPH7vxesXv4O1rBg=;
        b=cF2LeHOzWzzKJntDR56AJA0Z7wBt/w8yfDCw2aJWbAlv/eGY3A0N6MvhExXS1EAMsF
         n9H39FkrKB/AJ2V704DDFLu3Hhz8zh4mUeyVLbLtEcbcnP4WXEU7apzZbElXav17dcgI
         pYErIb2i6P0JQNuhjisirkgnvVkvHeVFy7/07VeG02jPND3if2xgGwLBZTGbCOGa5XeR
         2T7g6poCb7LvxKqSfBDs25gp/ApqlODeAgWRSDJF5LF33SH2n839Aq8tuepI7MUdiUB6
         tz0aAzL0rDHZQHlnKV27xXzD2sv3bKQT6r4gNvEY1JrAtxkmVrYs0B91vPGAywBr1Ubw
         NJ0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :content-language:to:cc:references:from:subject:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=em7ifQ9LxLNzLpSvNoE2y3O06q9SPH7vxesXv4O1rBg=;
        b=rugZUAkWlAzQl7/fh5mgvlVFMnNQIjYYrg/C4vNdkvJxfbAKZAgGz4/CLj/Bmp40kd
         5h/2MNSi7ll9My+mFt/Dc/4c5ZNdMUsr2NdiC6EhkT8JyundvtT97mkZh/Oegj4Dl1fd
         F3N5tAhhgdzPcvJFsq6wTXq5I9TOjUt0/pD9iid9HGDmCLXfUKU9oFqfZG1ZAE4yTkmu
         hYd4/B6NMKd8jjW/JHHJMII5Xmox24kvfCZDbXsZfncFCXF3p0ZlMjJB6IuNT97jou57
         5d4ahjaaSOpQz7uoB3AwMn+3f2qj7rWsiql/ZGKVpzYvTFLm+XtNyGz4Ismvpnz2zqjj
         IAQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532JVxc3/5lph0b6b3SCDafS4pvaqBmnTGYBgs1ruOdHxZut5379
	RCrXRwvFoBCGKbyUAY6ri/I=
X-Google-Smtp-Source: ABdhPJzQQZEE9npHW0FWSJnKUrECBUOGfdihorfl4k0fkRmeHqBcl57OGUy7sugU1eCj8QmHXmRXnA==
X-Received: by 2002:a05:6000:1f91:b0:207:b6b1:64a9 with SMTP id bw17-20020a0560001f9100b00207b6b164a9mr4367621wrb.286.1650644361250;
        Fri, 22 Apr 2022 09:19:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4ccf:0:b0:207:a2b0:7a9 with SMTP id c15-20020a5d4ccf000000b00207a2b007a9ls1256822wrt.2.gmail;
 Fri, 22 Apr 2022 09:19:20 -0700 (PDT)
X-Received: by 2002:a05:6000:1c9:b0:20a:8e73:b025 with SMTP id t9-20020a05600001c900b0020a8e73b025mr4395754wrx.145.1650644360024;
        Fri, 22 Apr 2022 09:19:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650644360; cv=none;
        d=google.com; s=arc-20160816;
        b=zCf2w3VQZM6N9oav5DgsN7iO+2YrFs5grEi5EjTZ9WKm52pGyqUjaiJexIUPc6cWYE
         5pqe3SJpSSkOYKa5fuGnEoQRg4t0H2WvbJDZmwQ20Std2HmDvacYyyNw5qo4LhRfFV38
         DN/TAfTdRraYk1gZM8Z7DSN9X00lpBUfi2I8w/9nyF9YiDMjDXMBWIG9Hh/mC92DH3pG
         x7TRV7IfsVQpV7Cl+vb5gY+lUxFrfHWr0zvLyLIp+skG4J9kRiuO6DwHWF2Yz5B3RxDC
         Upc1Yktl7yNDwv+FKON2stVPO356KoCVzRgzNhKKUgIgizv4fdOSDsNLIkqXI6tFQMdo
         Nl4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:subject:from:references:cc:to
         :content-language:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=cme6gBoUqjJf/WmZujopjJFO5loGe8P8NxtU20UCUgI=;
        b=lzrLsBbsU1G+qFsIhk6+/bzI2APQA4X81PCD0hP33rCQYuvxqgV/P3zHxiOAuY7TyB
         Ng4RXXtZWMttuLPcoOpUIds8rJRnjpSItK7+0jRTAZDNicklxQ0VH6xNlnc8oukBl2c5
         nxwT4+dRb9XfCUio6RLcS8pxB0+/eg6a1ZSBZZ/oaY8zp/aA8lzQk7tME1NFa1/QtT+I
         c4RE9tjazy2CP11HDFkXtxpEBSwZGlakhDW3jFuHsoOg9yfoF4HSwqwfeaLNG+8E0wsu
         oLcoXdZ7lCceu3/Og7q0jgnXy5JCEnal+c+YNoDcFjug7/gV8JqH1o+1ZDRecOQ/hps7
         yf2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=PxC97LDX;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id 8-20020a5d47a8000000b002079112400asi399291wrb.2.2022.04.22.09.19.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Apr 2022 09:19:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 9D86A1F388;
	Fri, 22 Apr 2022 16:19:19 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 4A7F5131BD;
	Fri, 22 Apr 2022 16:19:19 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 2assEYfVYmIZMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Fri, 22 Apr 2022 16:19:19 +0000
Message-ID: <f2f7ac96-6fb7-3733-f389-208c7c191caf@suse.cz>
Date: Fri, 22 Apr 2022 18:19:18 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.7.0
Content-Language: en-US
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>, Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Linux Memory Management List <linux-mm@kvack.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 penberg@kernel.org, cl@linux.org, roman.gushchin@linux.dev,
 iamjoonsoo.kim@lge.com, rientjes@google.com,
 Catalin Marinas <catalin.marinas@arm.com>,
 Herbert Xu <herbert@gondor.apana.org.au>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Eric Biederman <ebiederm@xmission.com>, Kees Cook <keescook@chromium.org>,
 Linus Torvalds <torvalds@linux-foundation.org>
References: <20220421031738.3168157-1-pcc@google.com>
 <YmFORWyMAVacycu5@hyeyoo>
 <CAMn1gO5xHZvFSSsW5sTVaUBN_gS-cYYNMG3PnpgCmh7kk_Zx7Q@mail.gmail.com>
 <YmKiDt12Xb/KXX3z@hyeyoo>
From: Vlastimil Babka <vbabka@suse.cz>
Subject: Re: [PATCH] mm: make minimum slab alignment a runtime property
In-Reply-To: <YmKiDt12Xb/KXX3z@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=PxC97LDX;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 4/22/22 14:39, Hyeonggon Yoo wrote:
> On Thu, Apr 21, 2022 at 10:16:25AM -0700, Peter Collingbourne wrote:
>> On Thu, Apr 21, 2022 at 5:30 AM Hyeonggon Yoo <42.hyeyoo@gmail.com> wrote:
>> >
>> > On Wed, Apr 20, 2022 at 08:17:38PM -0700, Peter Collingbourne wrote:
>> > > When CONFIG_KASAN_HW_TAGS is enabled we currently increase the minimum
>> > > slab alignment to 16. This happens even if MTE is not supported in
>> > > hardware or disabled via kasan=off, which creates an unnecessary
>> > > memory overhead in those cases. Eliminate this overhead by making
>> > > the minimum slab alignment a runtime property and only aligning to
>> > > 16 if KASAN is enabled at runtime.
>> > >
>> > > On a DragonBoard 845c (non-MTE hardware) with a kernel built with
>> > > CONFIG_KASAN_HW_TAGS, waiting for quiescence after a full Android
>> > > boot I see the following Slab measurements in /proc/meminfo (median
>> > > of 3 reboots):
>> > >
>> > > Before: 169020 kB
>> > > After:  167304 kB
>> > >
>> > > Link: https://linux-review.googlesource.com/id/I752e725179b43b144153f4b6f584ceb646473ead
>> > > Signed-off-by: Peter Collingbourne <pcc@google.com>
>> > > ---
>> > >  arch/arc/include/asm/cache.h        |  4 ++--
>> > >  arch/arm/include/asm/cache.h        |  2 +-
>> > >  arch/arm64/include/asm/cache.h      | 19 +++++++++++++------
>> > >  arch/microblaze/include/asm/page.h  |  2 +-
>> > >  arch/riscv/include/asm/cache.h      |  2 +-
>> > >  arch/sparc/include/asm/cache.h      |  2 +-
>> > >  arch/xtensa/include/asm/processor.h |  2 +-
>> > >  fs/binfmt_flat.c                    |  9 ++++++---
>> > >  include/crypto/hash.h               |  2 +-
>> > >  include/linux/slab.h                | 22 +++++++++++++++++-----
>> > >  mm/slab.c                           |  7 +++----
>> > >  mm/slab_common.c                    |  3 +--
>> > >  mm/slob.c                           |  6 +++---
>> > >  13 files changed, 51 insertions(+), 31 deletions(-)
>> >
>> > [+Cc slab people, Catalin and affected subsystems' folks]
>> >
>> > just FYI, There is similar discussion about kmalloc caches' alignment.
>> > https://lore.kernel.org/linux-mm/20220405135758.774016-1-catalin.marinas@arm.com/
>> >
>> > It seems this is another demand for runtime resolution of slab
>> > alignment, But slightly different from kmalloc as there is no requirement
>> > for DMA alignment.
>> >
>> > >
>> > > diff --git a/arch/arc/include/asm/cache.h b/arch/arc/include/asm/cache.h
>> > > index f0f1fc5d62b6..b6a7763fd5d6 100644
>> > > --- a/arch/arc/include/asm/cache.h
>> > > +++ b/arch/arc/include/asm/cache.h
>> > > @@ -55,11 +55,11 @@
>> > >   * Make sure slab-allocated buffers are 64-bit aligned when atomic64_t uses
>> > >   * ARCv2 64-bit atomics (LLOCKD/SCONDD). This guarantess runtime 64-bit
>> > >   * alignment for any atomic64_t embedded in buffer.
>> > > - * Default ARCH_SLAB_MINALIGN is __alignof__(long long) which has a relaxed
>> > > + * Default ARCH_SLAB_MIN_MINALIGN is __alignof__(long long) which has a relaxed
>> > >   * value of 4 (and not 8) in ARC ABI.
>> > >   */
>> > >  #if defined(CONFIG_ARC_HAS_LL64) && defined(CONFIG_ARC_HAS_LLSC)
>> > > -#define ARCH_SLAB_MINALIGN   8
>> > > +#define ARCH_SLAB_MIN_MINALIGN       8
>> > >  #endifh
>> > >
>> >
>> > Why isn't it just ARCH_SLAB_MINALIGN?
>> 
>> Because this is the minimum possible value of the minimum alignment
>> decided at runtime. I chose to give it a different name to
>> arch_slab_minalign() because the two have different meanings.
>> 
>> Granted this isn't a great name because of the stuttering but
>> hopefully it will prompt folks to investigate the meaning of this
>> constant if necessary.
> 
> To be honest I don't care much about the name but just thought it's just better
> to be consistent with Catalin's series: ARCH_KMALLOC_MINALIGN for static
> alignment and arch_kmalloc_minalign() for (possibly bigger) alignment decided
> at runtime.

Agree it should be consistent, one way or another. I would (not overly
strongly) prefer Catalin's approach as it's less churn. The name
ARCH_SLAB_MINALIGN is not wrong as the actual alignment can be only bigger
than that (or equal).
Realistically it seems only slab internals are going to use
arch_kmalloc_minalign(), so there shouldn't be too much need of "prompt
folks to investigate".

>> > >  extern int ioc_enable;
>> > > diff --git a/arch/arm/include/asm/cache.h b/arch/arm/include/asm/cache.h
>> > > index e3ea34558ada..3e1018bb9805 100644
>> > > --- a/arch/arm/include/asm/cache.h
>> > > +++ b/arch/arm/include/asm/cache.h
>> > > @@ -21,7 +21,7 @@
>> > >   * With EABI on ARMv5 and above we must have 64-bit aligned slab pointers.
>> > >   */
>> > >  #if defined(CONFIG_AEABI) && (__LINUX_ARM_ARCH__ >= 5)
>> > > -#define ARCH_SLAB_MINALIGN 8
>> > > +#define ARCH_SLAB_MIN_MINALIGN 8
>> > >  #endif
>> > >
>> > >  #define __read_mostly __section(".data..read_mostly")
>> > > diff --git a/arch/arm64/include/asm/cache.h b/arch/arm64/include/asm/cache.h
>> > > index a074459f8f2f..38f171591c3f 100644
>> > > --- a/arch/arm64/include/asm/cache.h
>> > > +++ b/arch/arm64/include/asm/cache.h
>> > > @@ -6,6 +6,7 @@
>> > >  #define __ASM_CACHE_H
>> > >
>> > >  #include <asm/cputype.h>
>> > > +#include <asm/mte-def.h>
>> > >
>> > >  #define CTR_L1IP_SHIFT               14
>> > >  #define CTR_L1IP_MASK                3
>> > > @@ -49,15 +50,21 @@
>> > >   */
>> > >  #define ARCH_DMA_MINALIGN    (128)
>> > >
>> > > -#ifdef CONFIG_KASAN_SW_TAGS
>> > > -#define ARCH_SLAB_MINALIGN   (1ULL << KASAN_SHADOW_SCALE_SHIFT)
>> > > -#elif defined(CONFIG_KASAN_HW_TAGS)
>> > > -#define ARCH_SLAB_MINALIGN   MTE_GRANULE_SIZE
>> > > -#endif
>> > > -
>> > >  #ifndef __ASSEMBLY__
>> > >
>> > >  #include <linux/bitops.h>
>> > > +#include <linux/kasan-enabled.h>
>> > > +
>> > > +#ifdef CONFIG_KASAN_SW_TAGS
>> > > +#define ARCH_SLAB_MIN_MINALIGN       (1ULL << KASAN_SHADOW_SCALE_SHIFT)
>> > > +#elif defined(CONFIG_KASAN_HW_TAGS)
>> > > +static inline size_t arch_slab_minalign(void)
>> > > +{
>> > > +     return kasan_hw_tags_enabled() ? MTE_GRANULE_SIZE :
>> > > +                                      __alignof__(unsigned long long);
>> > > +}
>> > > +#define arch_slab_minalign() arch_slab_minalign()
>> > > +#endif
>> > >
>> >
>> > kasan_hw_tags_enabled() is also false when kasan is just not initialized yet.
>> > What about writing a new helper something like kasan_is_disabled()
>> > instead?
>> 
>> The decision of whether to enable KASAN is made early, before the slab
>> allocator is initialized (start_kernel -> smp_prepare_boot_cpu ->
>> kasan_init_hw_tags vs start_kernel -> mm_init -> kmem_cache_init). If
>> you think about it, this needs to be the case for KASAN to operate
>> correctly because it influences the behavior of the slab allocator via
>> the kasan_*poison* hooks. So I don't think we can end up calling this
>> function before then.
> 
> Sounds not bad. I wanted to make sure the value of arch_slab_minaligned()
> is not changed during its execution.
> 
> Just some part of me thought something like this would be more
> intuitive/robust.
> 
> if (systems_supports_mte() && kasan_arg != KASAN_ARG_OFF)
> 	return MTE_GRANULE_SIZE;
> else
> 	return __alignof__(unsigned long long);

Let's see if kasan or arm folks have an opinion here.

> 
>> > >  #define ICACHEF_ALIASING     0
>> > >  #define ICACHEF_VPIPT                1
>> > > diff --git a/arch/microblaze/include/asm/page.h b/arch/microblaze/include/asm/page.h
>> > > index 4b8b2fa78fc5..ccdbc1da3c3e 100644
>> > > --- a/arch/microblaze/include/asm/page.h
>> > > +++ b/arch/microblaze/include/asm/page.h
>> > > @@ -33,7 +33,7 @@
>> > >  /* MS be sure that SLAB allocates aligned objects */
>> > >  #define ARCH_DMA_MINALIGN    L1_CACHE_BYTES
>> > >
>> > > -#define ARCH_SLAB_MINALIGN   L1_CACHE_BYTES
>> > > +#define ARCH_SLAB_MIN_MINALIGN       L1_CACHE_BYTES
>> > >
>> > >  /*
>> > >   * PAGE_OFFSET -- the first address of the first page of memory. With MMU
>> > > diff --git a/arch/riscv/include/asm/cache.h b/arch/riscv/include/asm/cache.h
>> > > index 9b58b104559e..7beb3b5d27c7 100644
>> > > --- a/arch/riscv/include/asm/cache.h
>> > > +++ b/arch/riscv/include/asm/cache.h
>> > > @@ -16,7 +16,7 @@
>> > >   * the flat loader aligns it accordingly.
>> > >   */
>> > >  #ifndef CONFIG_MMU
>> > > -#define ARCH_SLAB_MINALIGN   16
>> > > +#define ARCH_SLAB_MIN_MINALIGN       16
>> > >  #endif
>> > >
>> > >  #endif /* _ASM_RISCV_CACHE_H */
>> > > diff --git a/arch/sparc/include/asm/cache.h b/arch/sparc/include/asm/cache.h
>> > > index e62fd0e72606..9d8cb4687b7e 100644
>> > > --- a/arch/sparc/include/asm/cache.h
>> > > +++ b/arch/sparc/include/asm/cache.h
>> > > @@ -8,7 +8,7 @@
>> > >  #ifndef _SPARC_CACHE_H
>> > >  #define _SPARC_CACHE_H
>> > >
>> > > -#define ARCH_SLAB_MINALIGN   __alignof__(unsigned long long)
>> > > +#define ARCH_SLAB_MIN_MINALIGN       __alignof__(unsigned long long)
>> > >
>> > >  #define L1_CACHE_SHIFT 5
>> > >  #define L1_CACHE_BYTES 32
>> > > diff --git a/arch/xtensa/include/asm/processor.h b/arch/xtensa/include/asm/processor.h
>> > > index 4489a27d527a..e3ea278e3fcf 100644
>> > > --- a/arch/xtensa/include/asm/processor.h
>> > > +++ b/arch/xtensa/include/asm/processor.h
>> > > @@ -18,7 +18,7 @@
>> > >  #include <asm/types.h>
>> > >  #include <asm/regs.h>
>> > >
>> > > -#define ARCH_SLAB_MINALIGN XTENSA_STACK_ALIGNMENT
>> > > +#define ARCH_SLAB_MIN_MINALIGN XTENSA_STACK_ALIGNMENT
>> > >
>> > >  /*
>> > >   * User space process size: 1 GB.
>> > > diff --git a/fs/binfmt_flat.c b/fs/binfmt_flat.c
>> > > index 626898150011..8ff1bf7d1e87 100644
>> > > --- a/fs/binfmt_flat.c
>> > > +++ b/fs/binfmt_flat.c
>> > > @@ -64,7 +64,10 @@
>> > >   * Here we can be a bit looser than the data sections since this
>> > >   * needs to only meet arch ABI requirements.
>> > >   */
>> > > -#define FLAT_STACK_ALIGN     max_t(unsigned long, sizeof(void *), ARCH_SLAB_MINALIGN)
>> > > +static size_t flat_stack_align(void)
>> > > +{
>> > > +     return max_t(unsigned long, sizeof(void *), arch_slab_minalign());
>> > > +}

I think this might not be necessary at all. There doesn't seem to be actual
connection to the slab+kasan constraints here. My brief digging into git
blame suggest they just used the ARCH_SLAB_MINALIGN constant because it
existed, e.g. commit 2952095c6b2ee includes in changelog "Arguably, this is
kind of hokey that the FLAT is semi-abusing defines it shouldn't."
So, there shouldn't be a reason to increase this due to KASAN/MTE granule
size, it was done unnecessarily as a side-effect before (AFAIU it shouldn't
have caused existing userspace binaries to break, but maybe in some corner
case it could?), and if this patch leaves out the binfmt_flat changes, the
alignment will be (IMHO correctly) decreased again.

>> > >
>> > >  #define RELOC_FAILED 0xff00ff01              /* Relocation incorrect somewhere */
>> > >  #define UNLOADED_LIB 0x7ff000ff              /* Placeholder for unused library */
>> > > @@ -148,7 +151,7 @@ static int create_flat_tables(struct linux_binprm *bprm, unsigned long arg_start
>> > >               sp -= 2; /* argvp + envp */
>> > >       sp -= 1;  /* &argc */
>> > >
>> > > -     current->mm->start_stack = (unsigned long)sp & -FLAT_STACK_ALIGN;
>> > > +     current->mm->start_stack = (unsigned long)sp & -flat_stack_align();
>> > >       sp = (unsigned long __user *)current->mm->start_stack;
>> > >
>> > >       if (put_user(bprm->argc, sp++))
>> > > @@ -966,7 +969,7 @@ static int load_flat_binary(struct linux_binprm *bprm)
>> > >  #endif
>> > >       stack_len += (bprm->argc + 1) * sizeof(char *);   /* the argv array */
>> > >       stack_len += (bprm->envc + 1) * sizeof(char *);   /* the envp array */
>> > > -     stack_len = ALIGN(stack_len, FLAT_STACK_ALIGN);
>> > > +     stack_len = ALIGN(stack_len, flat_stack_align());
>> > >
>> > >       res = load_flat_file(bprm, &libinfo, 0, &stack_len);
>> > >       if (res < 0)
>> > > diff --git a/include/crypto/hash.h b/include/crypto/hash.h
>> > > index f140e4643949..442c290f458c 100644
>> > > --- a/include/crypto/hash.h
>> > > +++ b/include/crypto/hash.h
>> > > @@ -149,7 +149,7 @@ struct ahash_alg {
>> > >
>> > >  struct shash_desc {
>> > >       struct crypto_shash *tfm;
>> > > -     void *__ctx[] __aligned(ARCH_SLAB_MINALIGN);
>> > > +     void *__ctx[] __aligned(ARCH_SLAB_MIN_MINALIGN);
>> > >  };
>> > >
>> > >  #define HASH_MAX_DIGESTSIZE   64
>> > > diff --git a/include/linux/slab.h b/include/linux/slab.h
>> > > index 373b3ef99f4e..80e517593372 100644
>> > > --- a/include/linux/slab.h
>> > > +++ b/include/linux/slab.h
>> > > @@ -201,21 +201,33 @@ void kmem_dump_obj(void *object);
>> > >  #endif
>> > >
>> > >  /*
>> > > - * Setting ARCH_SLAB_MINALIGN in arch headers allows a different alignment.
>> > > + * Setting ARCH_SLAB_MIN_MINALIGN in arch headers allows a different alignment.
>> > >   * Intended for arches that get misalignment faults even for 64 bit integer
>> > >   * aligned buffers.
>> > >   */
>> > > -#ifndef ARCH_SLAB_MINALIGN
>> > > -#define ARCH_SLAB_MINALIGN __alignof__(unsigned long long)
>> > > +#ifndef ARCH_SLAB_MIN_MINALIGN
>> > > +#define ARCH_SLAB_MIN_MINALIGN __alignof__(unsigned long long)
>> > > +#endif
>> > > +
>> > > +/*
>> > > + * Arches can define this function if they want to decide the minimum slab
>> > > + * alignment at runtime. The value returned by the function must be
>> > > + * >= ARCH_SLAB_MIN_MINALIGN.
>> > > + */
>> >
>> > Not only the value should be bigger than or equal to ARCH_SLAB_MIN_MINALIGN,
>> > it should be compatible with ARCH_SLAB_MIN_MINALIGN.
>> 
>> What's the difference?
>>
> 
> 231 /*
> 232  * kmalloc and friends return ARCH_KMALLOC_MINALIGN aligned
> 233  * pointers. kmem_cache_alloc and friends return ARCH_SLAB_MIN_MINALIGN
> 234  * aligned pointers.
> 235  */
> 236 #define __assume_kmalloc_alignment __assume_aligned(ARCH_KMALLOC_MINALIGN)
> 237 #define __assume_slab_alignment __assume_aligned(ARCH_SLAB_MIN_MINALIGN)
> 238 #define __assume_page_alignment __assume_aligned(PAGE_SIZE)
> 
> I mean actual slab object size should be both ARCH_SLAB_MIN_MINALIGN-aligned and
> arch_slab_minalign()-aligned. Otherwise we are lying to the compiler.
> 
> It's okay If we use just power-of-two alignment.
> But adding a comment wouldn't harm :)

Agreed, technically it's not ">=ARCH_SLAB_MIN_MINALIGN", but "a least common
multiple of ARCH_SLAB_MIN_MINALIGN and whatever the other alignment
requirements arch_slab_minalign() wants to guarantee". But AFAIK in practice
these constraints are always power-of-two.

> Thank you for the work. I think the patch makes sense as usually people
> don't build and install their kernel for arm64 machines.
> 
>> Peter
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f2f7ac96-6fb7-3733-f389-208c7c191caf%40suse.cz.
