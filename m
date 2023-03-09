Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIXMU2QAMGQELR55LLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id B55286B217E
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Mar 2023 11:34:11 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id a21-20020a5d9595000000b0074c9dc19e16sf634145ioo.15
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 02:34:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678358050; cv=pass;
        d=google.com; s=arc-20160816;
        b=NKhDxNHtW7dV/bQzgl4k7wrXQnDcY6DBL8DkdcxkaO7DdUzYYhFlvbhMuNRq82VTJd
         1g3MHJIIChpehYARBVRAthSNewIhPvfKdrhQq8N/xLwBgt/ac/4tYD6EQPHy/P4uSBr4
         821x9t7WivbjjQ4gjjxFX3nk1b8d4hNhgICjPXNIrZi8U2yXABdnjipBmT0JAD2CUWRe
         19VUS/Ufyfh+gc6rTRX6jtlZKPaBlcmqaDyBI+iHpz7l7/8cbNCj8O7ofK182cxPXrOW
         eiY4qckn8y+1UbG2M+/OKUoQPXQ75rQMMG2cLXCTnrDsjeS0hjT5nYc+YnaxilbhgmRY
         9n6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=NIBctl0Jt7qGIa8fY1sarffwKC+/GrQAboG/L6uI6Ww=;
        b=sVsNXQQTw9oCVFdSZnSvDdrz9b4i02Urno0IioHQSVhnC3sw9rygDKghbiWZwrovHS
         UkFFjcmZZzRa8cptZb/IQnX8iL0f+IcF3yZJkiqYhKwPYGN1aPiJxRbFdwW8Rwpixgs4
         GbYYtYIBXEodGawyazICmNkAF6ttxqFeJmWEOuXn0Idv0ELUCmheBsgX05d+BvF7KWag
         SJIEbm1RCXQLbJixspF/xjkGlvA2tSU9AHPlNiW7i+Ep2BlmTVbGjUYWjnzIzYpA0E2M
         g26JcVyj4JkI7kaDaoSeWPafP61b4bg9Aakp5BcAZlmPFFwEIvankfGUM2wcvU/WAG9c
         5qNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="d7bLR//u";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678358050;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NIBctl0Jt7qGIa8fY1sarffwKC+/GrQAboG/L6uI6Ww=;
        b=WdW+1x1GotLiaIzT29pAeED9RhNnrLokzrpAw+JxqBRG0Jxvky0YqtlVh2a6hIn3KN
         k/zA/oHgTAI02SD6D57a7r59szHwITD9S8Q4qzQaHx7r2F7+AnKnVKQKWYCLMbs44c5Q
         qXCHA95IraQ9nkiImzEl1z839IKPTq3MdGBxlpBwcdpaxFww1aRblu+qzQA/p9a3MQ5s
         ByMsHIY7zUrunf+TeIIIx5wRzeue82vmaQFygnpbtc9pApkTeNUiBsYi4VRtH/8SfMnX
         PnqfgLD2Fdkdx4MPoyznbxaEEQWlPErqu8qciwiylkOGkl6V5tDNDXjmXQddWld4R5W1
         NWpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678358050;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=NIBctl0Jt7qGIa8fY1sarffwKC+/GrQAboG/L6uI6Ww=;
        b=r78zhf341z849Uf6tRihSCCJAcneWr/9B/NqlxUefF3pr7SpSm03VZlXxZbgCi1f5V
         sQR4Or51KnERAd69FIzorEW8bb3gdZKqw8JLbzMBDCBQUv/CJk650A1T294RzIx6GQRd
         imxp8gIleLA1yrj2amGqLwR8DaDmZLaePU5MplRl7CoN13vm4gkRvWNRHx+sYBM+GVZG
         f+21H+lnIDNL4YD1T3tbWcP4XB6MfOSAxGhfwMArxDuRcu6LesLyo1H7f7qn6anHYLg2
         vc2Bi7oWQCDgJi4BsHs0UQhRZeP2qP1rPawblEKxET7yZ6s60ahK/DA8ZcQ/Nyw8LZ0q
         T3cA==
X-Gm-Message-State: AO0yUKV87pvNUBZgD4XxvQ0bwczTiS/VFiJqNrJMyDeSZM5zwg5Ce4Qu
	Ohpl9bZkiwrTPO3b3wJaBbg=
X-Google-Smtp-Source: AK7set+zOO69qKO9hYqnXJIuPyKqP/+O6opaZN0+WW8SX3zvOMgjmf5lk0oyhXe3KyWqGVHH5PSJhA==
X-Received: by 2002:a02:aa0b:0:b0:3c4:e84b:2a40 with SMTP id r11-20020a02aa0b000000b003c4e84b2a40mr10524366jam.6.1678358050142;
        Thu, 09 Mar 2023 02:34:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:418a:b0:745:6788:14a7 with SMTP id
 bx10-20020a056602418a00b00745678814a7ls154317iob.11.-pod-prod-gmail; Thu, 09
 Mar 2023 02:34:09 -0800 (PST)
X-Received: by 2002:a5d:9158:0:b0:74c:91c2:cb05 with SMTP id y24-20020a5d9158000000b0074c91c2cb05mr12970289ioq.9.1678358049556;
        Thu, 09 Mar 2023 02:34:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678358049; cv=none;
        d=google.com; s=arc-20160816;
        b=0pFDdeIpix1RuJN9myGccwxdrtYyO+wfGl6eV9DkQMig0nDBL0b1WL2WMU1HeF0Wqw
         ZeuCMkao5jiM6oW/6t2vFLaI75xJJYEgt851OGBET0X0gv+kalY9buyP7oxdIkC6XbnN
         /HfUXBuYJt6RHbJ+qsGTa11pyr60BGK9wH2x9j1hLwMyvBagwt88VBhYpLisSyeO1Qeq
         WaGYXyw9lgDhvRsONQLO1PI2dYaYhXDjoqDM2tTZ/UQGsuNkPRpm1I2wEGQNrzGIualI
         Nc5uYi/60XFYQrVfMRYbYroky5pRZ3NucS3QdIVdu6+kgSIRteIFXMx9iBw4rL8Xr8al
         /xzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4DQp9yJyPkEGrEdSLXE5G+gqDSEdWsLMEj9kD3k6bFk=;
        b=oW2FEXkqzLgCaj2na0Ei54rpO36XZlJRpV+IQq2Se+x6OL28zmRBYKO/M2/isW2I1X
         2/fL3cqjhbUQ64QhmAIbbAKRdz/lgFawxy8FbD0Co2YmJFTbqymzTVUHMAvTryop9UeC
         oFrWwq1VAQRlKwmeyauJOTfrJ3XtydSnTmwEVxjSDvavO/H5Ox/p/eJ8aezw81egokQo
         PzaKnJS+LFx68bLHzxCqGfYuryr0nll37F4Cg75r90yEBZ4eaOTcyM22Ei6HcOwIeIL/
         jUQUdt0vV6L6suaOukThJQd8vgSQXM88DtmrXcHgMNObxpnDsbEycdIKL8rFb6ZF4EA9
         mdwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="d7bLR//u";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2b.google.com (mail-vs1-xe2b.google.com. [2607:f8b0:4864:20::e2b])
        by gmr-mx.google.com with ESMTPS id l6-20020a0566022dc600b0074a162394ebsi710677iow.1.2023.03.09.02.34.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Mar 2023 02:34:09 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2b as permitted sender) client-ip=2607:f8b0:4864:20::e2b;
Received: by mail-vs1-xe2b.google.com with SMTP id o2so1160619vss.8
        for <kasan-dev@googlegroups.com>; Thu, 09 Mar 2023 02:34:09 -0800 (PST)
X-Received: by 2002:a67:ce0a:0:b0:416:e50f:8215 with SMTP id
 s10-20020a67ce0a000000b00416e50f8215mr14184989vsl.4.1678358048733; Thu, 09
 Mar 2023 02:34:08 -0800 (PST)
MIME-Version: 1.0
References: <1678349122-19279-1-git-send-email-quic_zhenhuah@quicinc.com>
In-Reply-To: <1678349122-19279-1-git-send-email-quic_zhenhuah@quicinc.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Mar 2023 11:33:30 +0100
Message-ID: <CANpmjNOah6gSB_mRvhsK_9DpBtiYinRd5z34PU+tOFgSqXB8Sw@mail.gmail.com>
Subject: Re: [PATCH] mm,kfence: decouple kfence from page granularity mapping judgement
To: Zhenhua Huang <quic_zhenhuah@quicinc.com>
Cc: catalin.marinas@arm.com, will@kernel.org, glider@google.com, 
	dvyukov@google.com, akpm@linux-foundation.org, robin.murphy@arm.com, 
	mark.rutland@arm.com, jianyong.wu@arm.com, james.morse@arm.com, 
	linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, quic_pkondeti@quicinc.com, quic_guptap@quicinc.com, 
	quic_tingweiz@quicinc.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="d7bLR//u";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2b as
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

On Thu, 9 Mar 2023 at 09:05, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
>
> Kfence only needs its pool to be mapped as page granularity, previous
> judgement was a bit over protected. Decouple it from judgement and do
> page granularity mapping for kfence pool only [1].
>
> To implement this, also relocate the kfence pool allocation before the
> linear mapping setting up, kfence_alloc_pool is to allocate phys addr,
> __kfence_pool is to be set after linear mapping set up.
>
> LINK: [1] https://lore.kernel.org/linux-arm-kernel/1675750519-1064-1-git-send-email-quic_zhenhuah@quicinc.com/T/
> Suggested-by: Mark Rutland <mark.rutland@arm.com>
> Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
> ---
>  arch/arm64/mm/mmu.c      | 24 ++++++++++++++++++++++++
>  arch/arm64/mm/pageattr.c |  5 ++---
>  include/linux/kfence.h   | 10 ++++++++--
>  init/main.c              |  1 -
>  mm/kfence/core.c         | 18 ++++++++++++++----
>  5 files changed, 48 insertions(+), 10 deletions(-)
>
> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
> index 6f9d889..bd79691 100644
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
> @@ -532,6 +533,9 @@ static void __init map_mem(pgd_t *pgdp)
>         phys_addr_t kernel_end = __pa_symbol(__init_begin);
>         phys_addr_t start, end;
>         int flags = NO_EXEC_MAPPINGS;
> +#ifdef CONFIG_KFENCE
> +       phys_addr_t kfence_pool = 0;
> +#endif
>         u64 i;
>
>         /*
> @@ -564,6 +568,12 @@ static void __init map_mem(pgd_t *pgdp)
>         }
>  #endif
>
> +#ifdef CONFIG_KFENCE
> +       kfence_pool = kfence_alloc_pool();
> +       if (kfence_pool)
> +               memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
> +#endif
> +
>         /* map all the memory banks */
>         for_each_mem_range(i, &start, &end) {
>                 if (start >= end)
> @@ -608,6 +618,20 @@ static void __init map_mem(pgd_t *pgdp)
>                 }
>         }
>  #endif
> +
> +       /* Kfence pool needs page-level mapping */
> +#ifdef CONFIG_KFENCE
> +       if (kfence_pool) {
> +               __map_memblock(pgdp, kfence_pool,
> +                       kfence_pool + KFENCE_POOL_SIZE,
> +                       pgprot_tagged(PAGE_KERNEL),
> +                       NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
> +               memblock_clear_nomap(kfence_pool, KFENCE_POOL_SIZE);
> +               /* kfence_pool really mapped now */
> +               kfence_set_pool(kfence_pool);
> +       }
> +#endif
> +
>  }
>
>  void mark_rodata_ro(void)
> diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
> index 79dd201..61156d0 100644
> --- a/arch/arm64/mm/pageattr.c
> +++ b/arch/arm64/mm/pageattr.c
> @@ -22,12 +22,11 @@ bool rodata_full __ro_after_init = IS_ENABLED(CONFIG_RODATA_FULL_DEFAULT_ENABLED
>  bool can_set_direct_map(void)
>  {
>         /*
> -        * rodata_full, DEBUG_PAGEALLOC and KFENCE require linear map to be
> +        * rodata_full and DEBUG_PAGEALLOC require linear map to be
>          * mapped at page granularity, so that it is possible to
>          * protect/unprotect single pages.
>          */
> -       return (rodata_enabled && rodata_full) || debug_pagealloc_enabled() ||
> -               IS_ENABLED(CONFIG_KFENCE);
> +       return (rodata_enabled && rodata_full) || debug_pagealloc_enabled();
>  }
>
>  static int change_page_range(pte_t *ptep, unsigned long addr, void *data)
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index 726857a..0252e74 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -61,7 +61,12 @@ static __always_inline bool is_kfence_address(const void *addr)
>  /**
>   * kfence_alloc_pool() - allocate the KFENCE pool via memblock
>   */
> -void __init kfence_alloc_pool(void);
> +phys_addr_t __init kfence_alloc_pool(void);
> +
> +/**
> + * kfence_set_pool() - KFENCE pool mapped and can be used
> + */
> +void __init kfence_set_pool(phys_addr_t addr);
>
>  /**
>   * kfence_init() - perform KFENCE initialization at boot time
> @@ -223,7 +228,8 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
>  #else /* CONFIG_KFENCE */
>
>  static inline bool is_kfence_address(const void *addr) { return false; }
> -static inline void kfence_alloc_pool(void) { }
> +static inline phys_addr_t kfence_alloc_pool(void) { return (phys_addr_t)NULL; }
> +static inline void kfence_set_pool(phys_addr_t addr) { }
>  static inline void kfence_init(void) { }
>  static inline void kfence_shutdown_cache(struct kmem_cache *s) { }
>  static inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags) { return NULL; }
> diff --git a/init/main.c b/init/main.c
> index 4425d17..9aaf217 100644
> --- a/init/main.c
> +++ b/init/main.c
> @@ -839,7 +839,6 @@ static void __init mm_init(void)
>          */
>         page_ext_init_flatmem();
>         init_mem_debugging_and_hardening();
> -       kfence_alloc_pool();

This breaks other architectures.

>         report_meminit();
>         kmsan_init_shadow();
>         stack_depot_early_init();
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 5349c37..dd5cdd5 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -809,15 +809,25 @@ static void toggle_allocation_gate(struct work_struct *work)
>
>  /* === Public interface ===================================================== */
>
> -void __init kfence_alloc_pool(void)
> +phys_addr_t __init kfence_alloc_pool(void)
>  {

You could just return here:

  if (__kfence_pool)
    return; /* Initialized earlier by arch init code. */

... and see my comments below.

> +       phys_addr_t kfence_pool;
>         if (!kfence_sample_interval)
> -               return;
> +               return 0;
>
> -       __kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
> +       kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
>
> -       if (!__kfence_pool)
> +       if (!kfence_pool) {
>                 pr_err("failed to allocate pool\n");
> +               return 0;
> +       }
> +
> +       return kfence_pool;
> +}
> +
> +void __init kfence_set_pool(phys_addr_t addr)
> +{
> +       __kfence_pool = phys_to_virt(addr);
>  }

I would suggest leaving kfence_alloc_pool() to return nothing (with
the addition above), and just set __kfence_pool as before.
__kfence_pool itself is exported by include/linux/kfence.h, so if you
call kfence_alloc_pool() in arm64 earlier, you can access
__kfence_pool to get the allocated pool.

Because at that point, KFENCE isn't yet running, that only happens
after kfence_init() much later.

With these changes, you should be able to make arm64 work the way you
want, and not break other architectures where we don't need arch init
code to allocate the pool.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOah6gSB_mRvhsK_9DpBtiYinRd5z34PU%2BtOFgSqXB8Sw%40mail.gmail.com.
