Return-Path: <kasan-dev+bncBC7OBJGL2MHBBX5S3D5QKGQENYN5E4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 82AD328061C
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 20:01:04 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id u11sf2113250lfk.22
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 11:01:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601575264; cv=pass;
        d=google.com; s=arc-20160816;
        b=CvNC4bbuLrePIyXwxDtszysmDxDsytEqdJnaiGiKiGp0EcLfsBHfleBA7dzhetqZUA
         fmcaMClabXvOBOSNd4gKNT+ygCp+/02Gw3SJ/St0Uab9Jmku8yytjUf1fT9epnQ6DynF
         PTDK3yQcVjxGHnPJEYMVESVKHa3DPFBphHcC80ow91Wqz0I7isW18uijDZf2V15YacUc
         u4kHSzZh1pkAr1E1FvBz3H7PnG3XPpa5qIa5iHVAEBh3GfaJ2jaTCLsZmclsaoD1SY3A
         jnGOGdwYSJ3WsnHbOqqHQnrl4l6q2yXT3tVGR2nUF00Cb3rcOJKt6/d3juBnkkwFBHA+
         u3bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=MriFOAc3ILTQYT9RxUTglofWlYuvz3EilE3cB6fkDHs=;
        b=dfloRCK5jV80EtD2ybD/hoqMMGk7hM9FHOqzzqDav1RyRxeQadrhqf2wO8/Klp4Ghh
         WZ1h5aTw4PrRn8GfiS7kiBcwYsBNeOzWv/bpuz5PpSEORQWxxtu+Fy0XOc7JeJ5htfnf
         T0+QOFyiR9gfyjOZwbCnOb+y5xjPf723o6i7LMehXYWjR9xCdfNzCATIT+E2AMkkWlh0
         tFMB42cbiARqUpU3jaBmlUQ220Ek82EVbwjE8UpQGlDUojppXND0MRq7G4VbR8pY0/Fb
         RUp7gwie0ahONXgqHAut3B4NHh2EVXWOrQtM3i/1nBFcuxcsSRFFIkVH/zVoFGOh32YR
         CaDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LYtcPtyV;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=MriFOAc3ILTQYT9RxUTglofWlYuvz3EilE3cB6fkDHs=;
        b=dD8jcr/HOwSvzL8lDShtyvVG8dY1ODt83apIagtoW7KqktJ2qAe+622/8dJRX8e2wB
         Rt4aQ2dmdCKrHMQPZC2gkA9YXgag4kxDdh3S72XnNWP8pwvtyYvfAtTDWSqqA2Cd1Wrj
         lFs+X7i4uqshmVKKmJamX8VCIBcJxsPPdX/anKYuli3fgaOmkeOcGPt7yHInYvZxrzMS
         jsqrzlngcain5c1NsgaGhC0WKwKNWiOYXW27CSIR9IXZxemurgzdhTUqJKTdc9uvsRpt
         Wwz9BRsWSMoWEHHC/rjJQs1VzKEqZlbyvLWqCdzF2ADM3+dYhFTeLJlFMUmxIqNruAY1
         lrjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MriFOAc3ILTQYT9RxUTglofWlYuvz3EilE3cB6fkDHs=;
        b=ewXn8keH/hNkgFoGHznyzWKYezxfP4iRVU4VFf4vdsXmyE3uxcSL3XDcuFEj5bU2gr
         2Z75yTXBk3lp1SSMwRR1rA17GykvVsGVclmC2VAuwVgs5fGVQQQjiRyYbpg78UHSi1d8
         vZ4U86qHC1SNt4ceP10oQz9Umi9412StMpc7tI20KTbEgc/Vvv4kVC2jQovfmO3svpRZ
         V61qL/vp6IpcknBEuM0QagA1uuttqT1CWjkJ45xOLUJjuIWMPAa71LYxio4BcG12i6FT
         kvF4ashmpoU7jAPdyw2AemrvPo+MCaa41p/LMkqUdgM3hbQwGCRg2Wv5iRJmngLXhTIn
         l7fw==
X-Gm-Message-State: AOAM530qUx0d259oEywhpxmVmtjioCuTBd6pfexxDYuwxM00KH6YOX+O
	n0nVxnNsRE1j7PJggf0+5X8=
X-Google-Smtp-Source: ABdhPJwFg+Ytjr9znaNKsmZ4OgQbDjGbzLRxr4MmdmS5tAglMK6WrBQhZWb/J///gAvGN1lFKP0bjw==
X-Received: by 2002:a19:848d:: with SMTP id g135mr2838651lfd.56.1601575264025;
        Thu, 01 Oct 2020 11:01:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3c13:: with SMTP id j19ls981048lja.10.gmail; Thu, 01 Oct
 2020 11:01:02 -0700 (PDT)
X-Received: by 2002:a2e:8884:: with SMTP id k4mr2866368lji.333.1601575262702;
        Thu, 01 Oct 2020 11:01:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601575262; cv=none;
        d=google.com; s=arc-20160816;
        b=Ra+gRvDb0tno9E0Xa5alUM1v6UxXpVBcp94Ce31Rrv7nF1VoHu86YoRhfuR0W1p1S2
         GTrX+xFaM7URMHt19RbFXeCizGYgTcyHtjbGJXyZ5l6w2xQCONJgcZm7nYqdDqKasRES
         waVTjIkvxx1EzpUjjNwTawdMXzzJjCPlyNZCDRahNQqX2j/0S+GleSpNDt4G1sWBIn0a
         n39FBEPLaWJpsCqbk/YJJC/aicbRxj+rfSUBH9aoGG9iOPgB9MJVZpnXDNOnVmTpAunk
         4q7qLPun1EJ72dEZos5/a5fwxvtfEsyh6YPRKz3Kxfg+8NJIJ0lLomtSVFkKtphPccy1
         1UtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=b+3KiHTF4QPL9gp8eIxPfICCMyUp098bhGRU4jPixZM=;
        b=e/EBeZMpTcgAy4xmD+pT5dJi02C69K4Ab8j0vPdz0OxzOBdFC5oAkfV8RMrAHULCDu
         ix9w00MJ1m6Fd7PP4U/6xe3GJAMaeMP4bD/0e5hBwlc5sFaACFq8aZeanKsWHx5S78pA
         nTPMCfNTzyvABAibYhuQ7KzE7NPDg/owbk6PhUIxFlWe57JSaTeubOGiOFcBCNWOmTAv
         o6K745ow5qRSxUt/xsGK+JDftyY+BVUYxHDZK3oKpYOndV/T3deEWbATt0rXBQhzwIw+
         iEYJQhK6PPdMr22aBjh9st/xTvnVqHzWFu8FjtiKjiq2Vd93vPir+QGgCW/UukuSrQfe
         Efew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LYtcPtyV;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id y17si186285lfg.2.2020.10.01.11.01.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 11:01:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id j136so2798037wmj.2
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 11:01:02 -0700 (PDT)
X-Received: by 2002:a7b:c0ca:: with SMTP id s10mr1175512wmh.103.1601575261714;
        Thu, 01 Oct 2020 11:01:01 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id l17sm993389wme.11.2020.10.01.11.01.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 11:01:00 -0700 (PDT)
Date: Thu, 1 Oct 2020 20:00:55 +0200
From: elver via kasan-dev <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 35/39] kasan, arm64: implement HW_TAGS runtime
Message-ID: <20201001180055.GU4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <391e41cda292731f310367b04a9ee2bd08dc3b6b.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <391e41cda292731f310367b04a9ee2bd08dc3b6b.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LYtcPtyV;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: elver@google.com
Reply-To: elver@google.com
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

On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> Provide implementation of KASAN functions required for the hardware
> tag-based mode. Those include core functions for memory and pointer
> tagging (tags_hw.c) and bug reporting (report_tags_hw.c). Also adapt
> common KASAN code to support the new mode.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Acked-by: Catalin Marinas <catalin.marinas@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: I8a8689ba098174a4d0ef3f1d008178387c80ee1c
> ---
>  arch/arm64/include/asm/memory.h   |  4 +-
>  arch/arm64/kernel/setup.c         |  5 ++-
>  include/linux/kasan.h             |  6 +--
>  include/linux/mm.h                |  2 +-
>  include/linux/page-flags-layout.h |  2 +-
>  mm/kasan/Makefile                 |  5 +++
>  mm/kasan/common.c                 | 15 ++++---
>  mm/kasan/hw_tags.c                | 70 +++++++++++++++++++++++++++++++
>  mm/kasan/kasan.h                  | 17 ++++++--
>  mm/kasan/report_hw_tags.c         | 42 +++++++++++++++++++
>  mm/kasan/report_sw_tags.c         |  2 +-
>  mm/kasan/shadow.c                 |  2 +-
>  mm/kasan/sw_tags.c                |  2 +-
>  13 files changed, 152 insertions(+), 22 deletions(-)
>  create mode 100644 mm/kasan/hw_tags.c
>  create mode 100644 mm/kasan/report_hw_tags.c
> 
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
> index de9af7bea90d..b5d6b824c21c 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -215,7 +215,7 @@ static inline unsigned long kaslr_offset(void)
>  	(__force __typeof__(addr))__addr;				\
>  })
>  
> -#ifdef CONFIG_KASAN_SW_TAGS
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>  #define __tag_shifted(tag)	((u64)(tag) << 56)
>  #define __tag_reset(addr)	__untagged_addr(addr)
>  #define __tag_get(addr)		(__u8)((u64)(addr) >> 56)
> @@ -223,7 +223,7 @@ static inline unsigned long kaslr_offset(void)
>  #define __tag_shifted(tag)	0UL
>  #define __tag_reset(addr)	(addr)
>  #define __tag_get(addr)		0
> -#endif /* CONFIG_KASAN_SW_TAGS */
> +#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>  
>  static inline const void *__tag_set(const void *addr, u8 tag)
>  {
> diff --git a/arch/arm64/kernel/setup.c b/arch/arm64/kernel/setup.c
> index 77c4c9bad1b8..b07d9fbfa8b6 100644
> --- a/arch/arm64/kernel/setup.c
> +++ b/arch/arm64/kernel/setup.c
> @@ -358,7 +358,10 @@ void __init __no_sanitize_address setup_arch(char **cmdline_p)
>  	smp_init_cpus();
>  	smp_build_mpidr_hash();
>  
> -	/* Init percpu seeds for random tags after cpus are set up. */
> +	/*
> +	 * For CONFIG_KASAN_SW_TAGS this initializes percpu seeds and must
> +	 * come after cpus are set up.
> +	 */
>  	kasan_init_tags();
>  
>  #ifdef CONFIG_ARM64_SW_TTBR0_PAN
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 94b974f15892..80a0e5b11f2b 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -178,7 +178,7 @@ static inline void kasan_record_aux_stack(void *ptr) {}
>  
>  #endif /* CONFIG_KASAN_GENERIC */
>  
> -#ifdef CONFIG_KASAN_SW_TAGS
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>  
>  void kasan_init_tags(void);
>  
> @@ -187,7 +187,7 @@ void *kasan_reset_tag(const void *addr);
>  bool kasan_report(unsigned long addr, size_t size,
>  		bool is_write, unsigned long ip);
>  
> -#else /* CONFIG_KASAN_SW_TAGS */
> +#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>  
>  static inline void kasan_init_tags(void) { }
>  
> @@ -196,7 +196,7 @@ static inline void *kasan_reset_tag(const void *addr)
>  	return (void *)addr;
>  }
>  
> -#endif /* CONFIG_KASAN_SW_TAGS */
> +#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS*/
>  
>  #ifdef CONFIG_KASAN_VMALLOC
>  
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index 4312c6c808e9..a3cac68c737c 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -1411,7 +1411,7 @@ static inline bool cpupid_match_pid(struct task_struct *task, int cpupid)
>  }
>  #endif /* CONFIG_NUMA_BALANCING */
>  
> -#ifdef CONFIG_KASAN_SW_TAGS
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>  static inline u8 page_kasan_tag(const struct page *page)
>  {
>  	return (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
> diff --git a/include/linux/page-flags-layout.h b/include/linux/page-flags-layout.h
> index e200eef6a7fd..7d4ec26d8a3e 100644
> --- a/include/linux/page-flags-layout.h
> +++ b/include/linux/page-flags-layout.h
> @@ -77,7 +77,7 @@
>  #define LAST_CPUPID_SHIFT 0
>  #endif
>  
> -#ifdef CONFIG_KASAN_SW_TAGS
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>  #define KASAN_TAG_WIDTH 8
>  #else
>  #define KASAN_TAG_WIDTH 0
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index f1d68a34f3c9..9fe39a66388a 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -10,8 +10,10 @@ CFLAGS_REMOVE_init.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_quarantine.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_report_generic.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_report_hw_tags.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_report_sw_tags.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_shadow.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_hw_tags.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_sw_tags.o = $(CC_FLAGS_FTRACE)
>  
>  # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
> @@ -27,10 +29,13 @@ CFLAGS_init.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_quarantine.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_report.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_report_generic.o := $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_report_hw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_report_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_hw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>  
>  obj-$(CONFIG_KASAN) := common.o report.o
>  obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
> +obj-$(CONFIG_KASAN_HW_TAGS) += hw_tags.o report_hw_tags.o
>  obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_sw_tags.o shadow.o sw_tags.o
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index d0b3ff410b0c..2bb0ef6da6bd 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -113,7 +113,7 @@ void kasan_free_pages(struct page *page, unsigned int order)
>   */
>  static inline unsigned int optimal_redzone(unsigned int object_size)
>  {
> -	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> +	if (!IS_ENABLED(CONFIG_KASAN_GENERIC))
>  		return 0;
>  
>  	return
> @@ -178,14 +178,14 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
>  struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
>  					const void *object)
>  {
> -	return (void *)object + cache->kasan_info.alloc_meta_offset;
> +	return (void *)reset_tag(object) + cache->kasan_info.alloc_meta_offset;
>  }
>  
>  struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
>  				      const void *object)
>  {
>  	BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
> -	return (void *)object + cache->kasan_info.free_meta_offset;
> +	return (void *)reset_tag(object) + cache->kasan_info.free_meta_offset;
>  }
>  
>  void kasan_poison_slab(struct page *page)
> @@ -267,9 +267,8 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
>  	alloc_info = get_alloc_info(cache, object);
>  	__memset(alloc_info, 0, sizeof(*alloc_info));
>  
> -	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> -		object = set_tag(object,
> -				assign_tag(cache, object, true, false));
> +	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
> +		object = set_tag(object, assign_tag(cache, object, true, false));
>  
>  	return (void *)object;
>  }
> @@ -337,10 +336,10 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  	redzone_end = round_up((unsigned long)object + cache->object_size,
>  				KASAN_GRANULE_SIZE);
>  
> -	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> +	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
>  		tag = assign_tag(cache, object, false, keep_tag);
>  
> -	/* Tag is ignored in set_tag without CONFIG_KASAN_SW_TAGS */
> +	/* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
>  	kasan_unpoison_memory(set_tag(object, tag), size);
>  	kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
>  		KASAN_KMALLOC_REDZONE);
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> new file mode 100644
> index 000000000000..7f0568df2a93
> --- /dev/null
> +++ b/mm/kasan/hw_tags.c
> @@ -0,0 +1,70 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * This file contains core hardware tag-based KASAN code.
> + *
> + * Copyright (c) 2020 Google, Inc.
> + * Author: Andrey Konovalov <andreyknvl@google.com>
> + */
> +
> +#include <linux/kasan.h>
> +#include <linux/kernel.h>
> +#include <linux/memory.h>
> +#include <linux/mm.h>
> +#include <linux/string.h>
> +#include <linux/types.h>
> +
> +#include "kasan.h"
> +
> +void kasan_init_tags(void)
> +{
> +	init_tags(KASAN_TAG_MAX);
> +}
> +
> +void *kasan_reset_tag(const void *addr)
> +{
> +	return reset_tag(addr);
> +}
> +
> +void kasan_poison_memory(const void *address, size_t size, u8 value)
> +{
> +	set_mem_tag_range(reset_tag(address),
> +			  round_up(size, KASAN_GRANULE_SIZE), value);
> +}
> +
> +void kasan_unpoison_memory(const void *address, size_t size)
> +{
> +	set_mem_tag_range(reset_tag(address),
> +			  round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
> +}
> +
> +u8 random_tag(void)
> +{
> +	return get_random_tag();
> +}
> +
> +bool check_invalid_free(void *addr)
> +{
> +	u8 ptr_tag = get_tag(addr);
> +	u8 mem_tag = get_mem_tag(addr);
> +
> +	return (mem_tag == KASAN_TAG_INVALID) ||
> +		(ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag);
> +}
> +
> +void kasan_set_free_info(struct kmem_cache *cache,
> +				void *object, u8 tag)
> +{
> +	struct kasan_alloc_meta *alloc_meta;
> +
> +	alloc_meta = get_alloc_info(cache, object);
> +	kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
> +}
> +
> +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> +				void *object, u8 tag)
> +{
> +	struct kasan_alloc_meta *alloc_meta;
> +
> +	alloc_meta = get_alloc_info(cache, object);
> +	return &alloc_meta->free_track[0];
> +}
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index bd51ab72c002..6661ab4dbe3c 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -153,6 +153,10 @@ struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
>  struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
>  					const void *object);
>  
> +void kasan_poison_memory(const void *address, size_t size, u8 value);
> +
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> +
>  static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
>  {
>  	return (void *)(((unsigned long)shadow_addr - KASAN_SHADOW_OFFSET)
> @@ -164,8 +168,6 @@ static inline bool addr_has_metadata(const void *addr)
>  	return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
>  }
>  
> -void kasan_poison_memory(const void *address, size_t size, u8 value);
> -
>  /**
>   * check_memory_region - Check memory region, and report if invalid access.
>   * @addr: the accessed address
> @@ -177,6 +179,15 @@ void kasan_poison_memory(const void *address, size_t size, u8 value);
>  bool check_memory_region(unsigned long addr, size_t size, bool write,
>  				unsigned long ret_ip);
>  
> +#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> +
> +static inline bool addr_has_metadata(const void *addr)
> +{
> +	return true;
> +}
> +
> +#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> +
>  bool check_invalid_free(void *addr);
>  
>  void *find_first_bad_addr(void *addr, size_t size);
> @@ -213,7 +224,7 @@ static inline void quarantine_reduce(void) { }
>  static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
>  #endif
>  
> -#ifdef CONFIG_KASAN_SW_TAGS
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>  
>  void print_tags(u8 addr_tag, const void *addr);
>  
> diff --git a/mm/kasan/report_hw_tags.c b/mm/kasan/report_hw_tags.c
> new file mode 100644
> index 000000000000..d8423d1e3b6b
> --- /dev/null
> +++ b/mm/kasan/report_hw_tags.c
> @@ -0,0 +1,42 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * This file contains hardware tag-based KASAN specific error reporting code.
> + *
> + * Copyright (c) 2020 Google, Inc.
> + * Author: Andrey Konovalov <andreyknvl@google.com>
> + */
> +
> +#include <linux/kasan.h>
> +#include <linux/kernel.h>
> +#include <linux/memory.h>
> +#include <linux/mm.h>
> +#include <linux/string.h>
> +#include <linux/types.h>
> +
> +#include "kasan.h"
> +
> +const char *get_bug_type(struct kasan_access_info *info)
> +{
> +	return "invalid-access";
> +}
> +
> +void *find_first_bad_addr(void *addr, size_t size)
> +{
> +	return reset_tag(addr);
> +}
> +
> +void metadata_fetch_row(char *buffer, void *row)
> +{
> +	int i;
> +
> +	for (i = 0; i < META_BYTES_PER_ROW; i++)
> +		buffer[i] = mte_get_mem_tag(row + i * KASAN_GRANULE_SIZE);
> +}
> +
> +void print_tags(u8 addr_tag, const void *addr)
> +{
> +	u8 memory_tag = mte_get_mem_tag((void *)addr);
> +
> +	pr_err("Pointer tag: [%02x], memory tag: [%02x]\n",
> +		addr_tag, memory_tag);
> +}
> diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
> index add2dfe6169c..aebc44a29e83 100644
> --- a/mm/kasan/report_sw_tags.c
> +++ b/mm/kasan/report_sw_tags.c
> @@ -1,6 +1,6 @@
>  // SPDX-License-Identifier: GPL-2.0
>  /*
> - * This file contains tag-based KASAN specific error reporting code.
> + * This file contains software tag-based KASAN specific error reporting code.
>   *
>   * Copyright (c) 2014 Samsung Electronics Co., Ltd.
>   * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 1fadd4930d54..616ac64c4a21 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -107,7 +107,7 @@ void kasan_unpoison_memory(const void *address, size_t size)
>  
>  		if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
>  			*shadow = tag;
> -		else
> +		else /* CONFIG_KASAN_GENERIC */
>  			*shadow = size & KASAN_GRANULE_MASK;
>  	}
>  }
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index b2638c2cd58a..ccc35a311179 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -1,6 +1,6 @@
>  // SPDX-License-Identifier: GPL-2.0
>  /*
> - * This file contains core tag-based KASAN code.
> + * This file contains core software tag-based KASAN code.
>   *
>   * Copyright (c) 2018 Google, Inc.
>   * Author: Andrey Konovalov <andreyknvl@google.com>
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001180055.GU4162920%40elver.google.com.
