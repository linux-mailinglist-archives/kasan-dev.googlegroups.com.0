Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNF5XSQAMGQELDOV2TI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FB736B7849
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 14:01:43 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id 9-20020a5ea509000000b0074ca36737d2sf6158941iog.7
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 06:01:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678712501; cv=pass;
        d=google.com; s=arc-20160816;
        b=o+AAvpEUiKtjgXkl3kUyMrkGSz++Dsuqh+arEzohyDEBS8iHTpWD0Uo/EQ/CPSfoPw
         vGXUWZGhM+vN/5HMC+hygw9YVnJWIXAD9peG3x4KbHM92GASBV4SjH6vef1CUIoe5QOf
         uKDYRKYrcPy5Sm+HYGZPuRlWI3e5EyejbLxDiljleMtEbGvOCKTBnepRQhEVttWYF9U9
         Qm8jmj6IaPvSBFSlMNErnMJoSmOWkDGxJlZ41zxgzYaGDOrrG7PWMUAQ0/HEf6OS+rFT
         R0sLk4WV4x0UREgYX+btkeuHIGNX4VNCzL+aHDOYoIMGG48zaOPJffR0IIOPRQzyiNbz
         rniQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UMPWYSKutsyyRnKQ0atiQbawNM6IUnk9RA0V5gNntCQ=;
        b=BZM78sQpfLz3R4v25GZPAivVj0h/iCPJN8DrAmN5cWe0tv3SV4OzDGr0fZ/gjBR7ac
         tqDwlRWwHjopmz9sUw3LKOEzpEU8YA0OHD8YShjx2X4o6PneCFHNyKuseUg1e7BPBXq2
         hx8j8h42YLZxMY2b6zb86nBlMwUrcnCMwafenF2bu5rlQmNr1aJ93/VR4nmgz9G5W3xp
         IZ1FUhpeQe/L2t7F6NbplA8UkHaPAFBnwK0tPizqYC7KkZ5Gz2mvb1KkZcEw1mNQnRbP
         eicHVxcO/dnMDJC7pxPB/H57eJfjyAQmnjxr1s324HXGHvjuso0yUw2yrxpG0a6C7xs3
         M2nw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kz6RVKwl;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678712501;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UMPWYSKutsyyRnKQ0atiQbawNM6IUnk9RA0V5gNntCQ=;
        b=I90JWkZYcKeViVzpePi+FWL5J4znGH2luZdd3pXUcuKsXl48G8QtVz4Kxy42Q90Zkg
         x9+bi+dbShDDHAQiUuF2dAkhrgHWexBH4saK5SdREsMoQt/fxA8TjUFlqYuzn13wb3SM
         FSkoME7ghXz74RmW4GbaagJjTwNNIPQjMApt2OSc40dW0gUdkB/hp6IhamfEx2xW/yHB
         EpPtrjltvmsMpa0F4qtaNkRzs4p7OQeWV+PM/wcPKD4NuXMRyvUYuTUppjYGx7lpD6eA
         pjX630VeOudkzED50NAQgm/6tB8b6wLN9/trmZ+ACl2AVBXulSLBDWKZaueJky9EBttH
         9zHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678712501;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=UMPWYSKutsyyRnKQ0atiQbawNM6IUnk9RA0V5gNntCQ=;
        b=vDQVThfjf0Hwj/EpmXeOC8gqAuXUiloEQ5hwyizoElkn9WY2tYPJ1GgJPg/9Uc+uUM
         OCFCPMdQ5fJRgRIhGrotb4fQ3xRg/UT9wHDwfAGDNKSGbHHV0KD3PPSmAuUGBBNNoSk+
         STx+E1iX+ElD0gySLSQ7JfWyiGg6StMIPTIFMHKHnVlKOGaL6r1gn1XmWUMOFc2ZD6AT
         C2F8MJ1C9ltoBDQpaBZrZXPMswAmd1lgbucHCat+rCsf6GBibongGa2WuURiHzPfvLg3
         VyHdVcN/a6BAWdFHS1PUeDrQwLAsndDDfjPsE4zfiL9/21t/yNJcNUfl9jdZPjPZ0uWU
         x1Rw==
X-Gm-Message-State: AO0yUKUnSmPCu0W4VdgRbhKMzNvbh7ZpCH5bcoXRwwU8UEeOefLuNYTR
	mm+/1fqpAlIIbQhyRSFLb0s=
X-Google-Smtp-Source: AK7set8kaLXXTfH/7d+e2/9kq/L6o1zJ2eHxzh+t5/5AaZsTMHlEYyVpRgG22JfbeqOQODXuvV3tKQ==
X-Received: by 2002:a02:85e9:0:b0:3fc:e1f5:961a with SMTP id d96-20020a0285e9000000b003fce1f5961amr3401808jai.2.1678712500507;
        Mon, 13 Mar 2023 06:01:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:2e0f:0:b0:317:3bb1:afbc with SMTP id v15-20020a922e0f000000b003173bb1afbcls3890283ile.0.-pod-prod-gmail;
 Mon, 13 Mar 2023 06:01:38 -0700 (PDT)
X-Received: by 2002:a05:6e02:c30:b0:316:e64b:2367 with SMTP id q16-20020a056e020c3000b00316e64b2367mr7432201ilg.8.1678712498438;
        Mon, 13 Mar 2023 06:01:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678712498; cv=none;
        d=google.com; s=arc-20160816;
        b=iTB/Xtse5x5f3i32mQHLYCYlzhZ6FaNpK/7rhwntKK9KJO81WvzGkaMYcQofCpRyKy
         P7vKhr+4lb7ZNR5PHew+tD/5DciGY6CrsTbslOZ4JJXVrTEh9C3EeesDGWAwJvozUkKg
         inAmZUehxQsVV00gUPM3MoOWgexp7CeWBbpBG5NW7bSNWhV685A17gIZhyy8ue4jStJJ
         RvwBX3P3qZ5RFCC2HyCVbRI4zDn9Ww4mzQnNYpfWNOPBEaMXLEAvZjeC0mIBlpcOG/9D
         PvgejDYO2GATS4JrSyYE0Iob8uDs92WLuoEkUpaa+FiPZOq/4i/zXBq64z2Gvtkxpn/g
         6PNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UUegi1pERaaM+ShYDfaoYG51oElajvWu+QrEVQP0z44=;
        b=sTc6rux7kjsYMP/ddqUkcuc4AKkQK6QRwVOQQjr6Ox+HaJ+xHL7Pq7TlPYCcO23+AT
         FCUmfrpoWqqxypWRHQ1pymrvW7KSGGm3RmOLGybcACickGzno2XCF8vxIg9hcCFSjku5
         AzNekgmFbrlWJcA1GcZAB5S7WUQOPenFW1xkWEOLt5fxQgkFwtExvNAamUV/KN0e94zg
         benxNMjedkjfUWoKLau863JCRD7Xku6bLrQbCi0uoZNiti7QMhR4YIfAADN5r1OC8lWz
         t0L0t4eepk9+lUbRJE6+gpu8QVEPvhlIYWIkIwcTL7MQl1c7YSU2QzUJWXTRUYk4D5Sc
         18vQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kz6RVKwl;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x131.google.com (mail-il1-x131.google.com. [2607:f8b0:4864:20::131])
        by gmr-mx.google.com with ESMTPS id z1-20020a92bf01000000b0031580b246e4si496047ilh.2.2023.03.13.06.01.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Mar 2023 06:01:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::131 as permitted sender) client-ip=2607:f8b0:4864:20::131;
Received: by mail-il1-x131.google.com with SMTP id bp11so1493284ilb.3
        for <kasan-dev@googlegroups.com>; Mon, 13 Mar 2023 06:01:38 -0700 (PDT)
X-Received: by 2002:a05:6e02:4c4:b0:322:fe5b:d776 with SMTP id
 f4-20020a056e0204c400b00322fe5bd776mr2448276ils.4.1678712497945; Mon, 13 Mar
 2023 06:01:37 -0700 (PDT)
MIME-Version: 1.0
References: <1678708637-8669-1-git-send-email-quic_zhenhuah@quicinc.com>
In-Reply-To: <1678708637-8669-1-git-send-email-quic_zhenhuah@quicinc.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Mar 2023 14:00:56 +0100
Message-ID: <CANpmjNNBhfdshGhiycY5S-sMnubQx=qGCBcKL5Hm=WL2HXQ2uw@mail.gmail.com>
Subject: Re: [PATCH v6] mm,kfence: decouple kfence from page granularity
 mapping judgement
To: Zhenhua Huang <quic_zhenhuah@quicinc.com>
Cc: catalin.marinas@arm.com, will@kernel.org, glider@google.com, 
	dvyukov@google.com, akpm@linux-foundation.org, robin.murphy@arm.com, 
	mark.rutland@arm.com, jianyong.wu@arm.com, james.morse@arm.com, 
	wangkefeng.wang@huawei.com, linux-arm-kernel@lists.infradead.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, quic_pkondeti@quicinc.com, 
	quic_guptap@quicinc.com, quic_tingweiz@quicinc.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kz6RVKwl;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::131 as
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

On Mon, 13 Mar 2023 at 12:57, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
>
> Kfence only needs its pool to be mapped as page granularity, if it is
> inited early. Previous judgement was a bit over protected. From [1], Mark
> suggested to "just map the KFENCE region a page granularity". So I
> decouple it from judgement and do page granularity mapping for kfence
> pool only. Need to be noticed that late init of kfence pool still requires
> page granularity mapping.
>
> Page granularity mapping in theory cost more(2M per 1GB) memory on arm64
> platform. Like what I've tested on QEMU(emulated 1GB RAM) with
> gki_defconfig, also turning off rodata protection:
> Before:
> [root@liebao ]# cat /proc/meminfo
> MemTotal:         999484 kB
> After:
> [root@liebao ]# cat /proc/meminfo
> MemTotal:        1001480 kB
>
> To implement this, also relocate the kfence pool allocation before the
> linear mapping setting up, arm64_kfence_alloc_pool is to allocate phys
> addr, __kfence_pool is to be set after linear mapping set up.
>
> LINK: [1] https://lore.kernel.org/linux-arm-kernel/Y+IsdrvDNILA59UN@FVFF77S0Q05N/
> Suggested-by: Mark Rutland <mark.rutland@arm.com>
> Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
> ---
>  arch/arm64/mm/mmu.c      | 42 ++++++++++++++++++++++++++++++++++++++++++
>  arch/arm64/mm/pageattr.c |  8 ++++++--
>  include/linux/kfence.h   | 10 ++++++++++
>  mm/kfence/core.c         |  9 +++++++++
>  4 files changed, 67 insertions(+), 2 deletions(-)
>
> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
> index 6f9d889..ca5c932 100644
> --- a/arch/arm64/mm/mmu.c
> +++ b/arch/arm64/mm/mmu.c
> @@ -24,6 +24,7 @@
>  #include <linux/mm.h>
>  #include <linux/vmalloc.h>
>  #include <linux/set_memory.h>
> +#include <linux/kfence.h>
>
>  #include <asm/barrier.h>
>  #include <asm/cputype.h>
> @@ -525,6 +526,31 @@ static int __init enable_crash_mem_map(char *arg)
>  }
>  early_param("crashkernel", enable_crash_mem_map);
>
> +#ifdef CONFIG_KFENCE
> +
> +static phys_addr_t arm64_kfence_alloc_pool(void)
> +{
> +       phys_addr_t kfence_pool;
> +
> +       if (!kfence_sample_interval)
> +               return 0;
> +
> +       kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
> +       if (!kfence_pool)
> +               pr_err("failed to allocate kfence pool\n");
> +
> +       return kfence_pool;
> +}
> +
> +#else
> +
> +static phys_addr_t arm64_kfence_alloc_pool(void)
> +{
> +       return 0;
> +}
> +
> +#endif
> +
>  static void __init map_mem(pgd_t *pgdp)
>  {
>         static const u64 direct_map_end = _PAGE_END(VA_BITS_MIN);
> @@ -532,6 +558,7 @@ static void __init map_mem(pgd_t *pgdp)
>         phys_addr_t kernel_end = __pa_symbol(__init_begin);
>         phys_addr_t start, end;
>         int flags = NO_EXEC_MAPPINGS;
> +       phys_addr_t kfence_pool;
>         u64 i;
>
>         /*
> @@ -564,6 +591,10 @@ static void __init map_mem(pgd_t *pgdp)
>         }
>  #endif
>
> +       kfence_pool = arm64_kfence_alloc_pool();
> +       if (kfence_pool)
> +               memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
> +
>         /* map all the memory banks */
>         for_each_mem_range(i, &start, &end) {
>                 if (start >= end)
> @@ -608,6 +639,17 @@ static void __init map_mem(pgd_t *pgdp)
>                 }
>         }
>  #endif
> +
> +       /* Kfence pool needs page-level mapping */
> +       if (kfence_pool) {
> +               __map_memblock(pgdp, kfence_pool,
> +                       kfence_pool + KFENCE_POOL_SIZE,
> +                       pgprot_tagged(PAGE_KERNEL),
> +                       NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
> +               memblock_clear_nomap(kfence_pool, KFENCE_POOL_SIZE);
> +               /* kfence_pool really mapped now */
> +               kfence_set_pool(kfence_pool);
> +       }
>  }
>
>  void mark_rodata_ro(void)
> diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
> index 79dd201..25e4a983 100644
> --- a/arch/arm64/mm/pageattr.c
> +++ b/arch/arm64/mm/pageattr.c
> @@ -7,6 +7,7 @@
>  #include <linux/module.h>
>  #include <linux/sched.h>
>  #include <linux/vmalloc.h>
> +#include <linux/kfence.h>
>
>  #include <asm/cacheflush.h>
>  #include <asm/set_memory.h>
> @@ -22,12 +23,15 @@ bool rodata_full __ro_after_init = IS_ENABLED(CONFIG_RODATA_FULL_DEFAULT_ENABLED
>  bool can_set_direct_map(void)
>  {
>         /*
> -        * rodata_full, DEBUG_PAGEALLOC and KFENCE require linear map to be
> +        * rodata_full and DEBUG_PAGEALLOC require linear map to be
>          * mapped at page granularity, so that it is possible to
>          * protect/unprotect single pages.
> +        *
> +        * Kfence pool requires page granularity mapping also if we init it
> +        * late.
>          */
>         return (rodata_enabled && rodata_full) || debug_pagealloc_enabled() ||
> -               IS_ENABLED(CONFIG_KFENCE);
> +           (IS_ENABLED(CONFIG_KFENCE) && !kfence_sample_interval);

If you're struggling with kfence_sample_interval not existing if
!CONFIG_KFENCE, this is one of the occasions where it'd be perfectly
fine to write:

bool can_set_direct_map(void) {
#ifdef CONFIG_KFENCE
    /* ... your comment here ...*/
    if (!kfence_sample_interval)
        return true;
}
#endif
     return .........
}

>  }
>
>  static int change_page_range(pte_t *ptep, unsigned long addr, void *data)
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index 726857a..2b77eee 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -64,6 +64,12 @@ static __always_inline bool is_kfence_address(const void *addr)
>  void __init kfence_alloc_pool(void);
>
>  /**
> + * kfence_set_pool() - allows an arch to set the
> + * KFENCE pool during early init
> + */
> +void __init kfence_set_pool(phys_addr_t addr);
> +
> +/**
>   * kfence_init() - perform KFENCE initialization at boot time
>   *
>   * Requires that kfence_alloc_pool() was called before. This sets up the
> @@ -222,8 +228,12 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
>
>  #else /* CONFIG_KFENCE */
>
> +extern unsigned long kfence_sample_interval;

This variable does not exist if !CONFIG_KFENCE, please remove. See
suggestion above.

> +#define KFENCE_POOL_SIZE 0
>  static inline bool is_kfence_address(const void *addr) { return false; }
>  static inline void kfence_alloc_pool(void) { }
> +static inline void kfence_set_pool(phys_addr_t addr) { }
>  static inline void kfence_init(void) { }
>  static inline void kfence_shutdown_cache(struct kmem_cache *s) { }
>  static inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags) { return NULL; }
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 5349c37..0765395 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -814,12 +814,21 @@ void __init kfence_alloc_pool(void)
>         if (!kfence_sample_interval)
>                 return;
>
> +       /* if the pool has already been initialized by arch, skip the below */
> +       if (__kfence_pool)
> +               return;
> +
>         __kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
>
>         if (!__kfence_pool)
>                 pr_err("failed to allocate pool\n");
>  }
>
> +void __init kfence_set_pool(phys_addr_t addr)
> +{
> +       __kfence_pool = phys_to_virt(addr);
> +}
> +
>  static void kfence_init_enable(void)
>  {
>         if (!IS_ENABLED(CONFIG_KFENCE_STATIC_KEYS))
> --
> 2.7.4
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNBhfdshGhiycY5S-sMnubQx%3DqGCBcKL5Hm%3DWL2HXQ2uw%40mail.gmail.com.
