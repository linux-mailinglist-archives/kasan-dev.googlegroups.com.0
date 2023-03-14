Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSPGYCQAMGQEV7DFS3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 83E376B8DA8
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Mar 2023 09:41:47 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id q1-20020a170902dac100b0019f1e3ea83dsf5413200plx.4
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Mar 2023 01:41:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678783306; cv=pass;
        d=google.com; s=arc-20160816;
        b=u0b5Efm7xqsikBFaYJ303Tk4O5EmlceNG196yQ9EKnL1cfoOZJedlJbMx4mGvehPE3
         spPLVeaOa4PBp29DLj9j5NypEAnW3aXjuAgyoAwIK4EPRPGhYK3XVstmIXcBKuDU9b0D
         Gvj2Ww4JCh4CtVwmWjXQtiN6u736JBUQ4InZEKhCUeAo9bvUcBZLgNW01XonI6hszjnS
         /3rMWCamevLn72SKR76/5EXSzL57JF5yBxzOGoZCkJkcFbDCEEJUHKpsDifQ4Lnl0npe
         FhfzSh2BZ8oVmNu+5Udjr+wkdvVmar+wC+xIStu/UlsGRAMOnbn6LWkiYXsRv3TzEwvh
         kGLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BsQHQyKG0efxx5mVY+RXH8FpyGxY1iwV7NEgmRSwvvw=;
        b=iGXJn6iiewy1WgNWU6D7HZR7GLBArwDBIAKXquGzCTmsrGw/yjXf14YRE2J/e0ZaPJ
         wPd88KG6fXBXJLkNlJFoIT+ay4Mgsza6Kpk8mexXJ+NQ+Nbz4DAN8+cbG17RGkV4d2zv
         UZspdVjROviphgJRkcdOCRr2aVJtkm9ZbX6bA+AjCzmTG9T5AYTSrI99vWSQaS+lXYuA
         lZa/xc5fB8gbN4Nw2KsI7/WqPdqg7FZSC/FL+qV6xi8EMhHBosG4sm3ZQlZGJhdntYLH
         a1r5n5uZ9jOyjj03apJW4S6/RbkbCrEC+Prk1fKpzr1gD0p6rN7XsuhKjZ+noIvlLVGy
         Uj6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Fa6bULuY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678783306;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BsQHQyKG0efxx5mVY+RXH8FpyGxY1iwV7NEgmRSwvvw=;
        b=LqlQbI5H5RIAEM9o52W8VYiir49WjgG7IfW9VS5lDnX2rM2ie9J/zjZNL+KjZfBHbY
         DAyUuDAUtqXaAegMe40ZLHVfzSImVsS0D6HWgUFIX3D3c2nBZu/CfwJkP6hsT4372Zgk
         m1y2Zx+FDZNgW2UZNhFq2kRJaSO1QBgcQCqWd8dsdkdCE6DJajZHzBTRfmxl0GMOG9Va
         TlJZLax8RdSNvE5iacvHWIZmSO7ArrtqDcPRIVdo5ArejcPTyVcSIvKXTFVSG77OqQ0B
         Rhs5KdYnf0wfqsSVfDsk7LuzBtoexwpy5+n7nKZVpQcqet7skrYdDN6mIakIA3pJTH7+
         kAsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678783306;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=BsQHQyKG0efxx5mVY+RXH8FpyGxY1iwV7NEgmRSwvvw=;
        b=C50FSiMUOB58Lrbzx2wNuI5H8UTH7KrjAVadRqp7iVgZr7fvEQBtAzcPok4eeBVs8+
         oCz9EmoSP1H6GPzlh2uR5CkzOejhdaZtt4oH6EBTPgXkoAU1MDPE2iX9XFkv1JYiFteT
         CbtrFjATtDkVulU0R58Z8kvy65xmHogIYsxP5Dxii8TTu/UGa8WUgj5cSndZtqtVydaP
         VuZsbatPKOtVUSX/G9fb3g+faFeJB7lLDue8z0UORp/wOuWpq0exC6bEmkLnx1lxiWdh
         7/shPGlvWvykNkuPBY/w+Ct6fZeDLNmaplxFqhsGvFDRK8RXPXU1AT15Y3NURTcO2RlF
         WqMw==
X-Gm-Message-State: AO0yUKUTUzh2vSmx3s9W+5bIpe1/tTzoEknc5tpy9Sw6+v7p6eQF7qVw
	X9YrFXoJhIPsKyfvrI+EDco=
X-Google-Smtp-Source: AK7set/ZlafPvEQK2YxKxg8wBaom5yBfZV2OP91JxqTHX62otBO4VFPOCfcRmIFCkXnt9XfLEs5aYQ==
X-Received: by 2002:a17:90a:cb94:b0:23c:fd83:1bbb with SMTP id a20-20020a17090acb9400b0023cfd831bbbmr2327946pju.8.1678783305943;
        Tue, 14 Mar 2023 01:41:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:cf11:b0:199:50f5:6729 with SMTP id
 i17-20020a170902cf1100b0019950f56729ls15090365plg.11.-pod-prod-gmail; Tue, 14
 Mar 2023 01:41:45 -0700 (PDT)
X-Received: by 2002:a17:90a:684b:b0:23d:3913:bc26 with SMTP id e11-20020a17090a684b00b0023d3913bc26mr1397473pjm.2.1678783305069;
        Tue, 14 Mar 2023 01:41:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678783305; cv=none;
        d=google.com; s=arc-20160816;
        b=f0iUUAUyNtibht7oa+43MyRbkRDvrbvUzV5hHVqmkizhZLBQbC4/u/xoO5yI3aYeXv
         Aj4vDKt+6HydnsMOagEEKLXzJD3E1qgy03mRCeRzP4iPbmjX55zR88AkiVDBuqbLDYvk
         n3eKpGLDrVGFuA3VB00kd9yUOzbW/vBATpQd+KAfj/cdjZXdarfpr7guOfgYJnMByrCc
         NXsBkssDsclb7wgBVeGtewA3drbSmECOp4vCev1awvNqGB/pziPARjlk5Q/foiNlTm5r
         oXJN30US01V+ynwzyRGrloRCymMWgBlGyjN/q75NzyAcaaZSrK72JJfALnXZmWtwKCYq
         MB0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WpsiRFIUZLP1ypzQar3A5S28uGiElt2gVT4WHx11HNE=;
        b=veKHk5UJd0WSIQbusRaP4UkMlCv12dwATrwpIBWJGEnSjBAYy7LDm+UgPyvwEMADgv
         MHEz6HgPbVGAXo38ny8R0l2zJjLTeqyssBWCSf+RLFLGoRXaFqtZdbXZRRzlXBJJ8KnW
         +NaRHQksRwzge2DjPBSUu0W7cXqDsuqtAf//9wnLrAkxLq1DPDAHb7BhCkmERk8VES4G
         RqKi8C6aL5yDtKSZ8npXqbMMV28KKznGR1bQQc8XWA1tU0lfc1fyR/ApSNwGTlk62YcY
         iFozXS5JkL6QJ1PM2MUA966/wA4mSuUJejfGRc/vhi34veZ1j8AOYw1J1PmwX4RNZTrw
         UWmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Fa6bULuY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd34.google.com (mail-io1-xd34.google.com. [2607:f8b0:4864:20::d34])
        by gmr-mx.google.com with ESMTPS id pw13-20020a17090b278d00b0023d1e5feec0si77209pjb.0.2023.03.14.01.41.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Mar 2023 01:41:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d34 as permitted sender) client-ip=2607:f8b0:4864:20::d34;
Received: by mail-io1-xd34.google.com with SMTP id b16so6075900iof.11
        for <kasan-dev@googlegroups.com>; Tue, 14 Mar 2023 01:41:45 -0700 (PDT)
X-Received: by 2002:a02:7a07:0:b0:3ec:dc1f:12d8 with SMTP id
 a7-20020a027a07000000b003ecdc1f12d8mr17450127jac.4.1678783304284; Tue, 14 Mar
 2023 01:41:44 -0700 (PDT)
MIME-Version: 1.0
References: <1678777502-6933-1-git-send-email-quic_zhenhuah@quicinc.com>
In-Reply-To: <1678777502-6933-1-git-send-email-quic_zhenhuah@quicinc.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Mar 2023 09:41:02 +0100
Message-ID: <CANpmjNP2zDi9j+14-9Cqi5bMCuq7HcCi6om7SP_gfoVxs_AMbA@mail.gmail.com>
Subject: Re: [PATCH v8] mm,kfence: decouple kfence from page granularity
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
 header.i=@google.com header.s=20210112 header.b=Fa6bULuY;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d34 as
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

On Tue, 14 Mar 2023 at 08:05, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
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
>  arch/arm64/include/asm/kfence.h |  2 ++
>  arch/arm64/mm/mmu.c             | 44 +++++++++++++++++++++++++++++++++++++++++
>  arch/arm64/mm/pageattr.c        |  9 +++++++--
>  include/linux/kfence.h          |  8 ++++++++
>  mm/kfence/core.c                |  9 +++++++++
>  5 files changed, 70 insertions(+), 2 deletions(-)
>
> diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
> index aa855c6..f1f9ca2d 100644
> --- a/arch/arm64/include/asm/kfence.h
> +++ b/arch/arm64/include/asm/kfence.h
> @@ -10,6 +10,8 @@
>
>  #include <asm/set_memory.h>
>
> +extern phys_addr_t early_kfence_pool;
> +
>  static inline bool arch_kfence_init_pool(void) { return true; }
>
>  static inline bool kfence_protect_page(unsigned long addr, bool protect)
> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
> index 6f9d889..7fbf2ed 100644
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
> @@ -38,6 +39,7 @@
>  #include <asm/ptdump.h>
>  #include <asm/tlbflush.h>
>  #include <asm/pgalloc.h>
> +#include <asm/kfence.h>
>
>  #define NO_BLOCK_MAPPINGS      BIT(0)
>  #define NO_CONT_MAPPINGS       BIT(1)
> @@ -525,6 +527,33 @@ static int __init enable_crash_mem_map(char *arg)
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
> +phys_addr_t early_kfence_pool;

The compiler will not optimize out this global. This now exists in all
arm64 kernel builds.

Furthermore, there's no need for this to be phys_addr_t. Nothing
outside map_mem() needs the address, so this can just be a bool.

I'd recommend moving the variable under CONFIG_KFENCE, and in the asm
header, just having a static inline helper function e.g.
arm64_kfence_early_pool(). That helper just returns false in the
!CONFIG_KFENCE case.

>  static void __init map_mem(pgd_t *pgdp)
>  {
>         static const u64 direct_map_end = _PAGE_END(VA_BITS_MIN);
> @@ -543,6 +572,10 @@ static void __init map_mem(pgd_t *pgdp)
>          */
>         BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
>
> +       early_kfence_pool = arm64_kfence_alloc_pool();
> +       if (early_kfence_pool)
> +               memblock_mark_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
> +
>         if (can_set_direct_map())
>                 flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
>
> @@ -608,6 +641,17 @@ static void __init map_mem(pgd_t *pgdp)
>                 }
>         }
>  #endif
> +
> +       /* Kfence pool needs page-level mapping */
> +       if (early_kfence_pool) {
> +               __map_memblock(pgdp, early_kfence_pool,
> +                       early_kfence_pool + KFENCE_POOL_SIZE,
> +                       pgprot_tagged(PAGE_KERNEL),
> +                       NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
> +               memblock_clear_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
> +               /* kfence_pool really mapped now */
> +               kfence_set_pool(early_kfence_pool);
> +       }
>  }
>
>  void mark_rodata_ro(void)
> diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
> index 79dd201..7ce5295 100644
> --- a/arch/arm64/mm/pageattr.c
> +++ b/arch/arm64/mm/pageattr.c
> @@ -7,10 +7,12 @@
>  #include <linux/module.h>
>  #include <linux/sched.h>
>  #include <linux/vmalloc.h>
> +#include <linux/kfence.h>
>
>  #include <asm/cacheflush.h>
>  #include <asm/set_memory.h>
>  #include <asm/tlbflush.h>
> +#include <asm/kfence.h>
>
>  struct page_change_data {
>         pgprot_t set_mask;
> @@ -22,12 +24,15 @@ bool rodata_full __ro_after_init = IS_ENABLED(CONFIG_RODATA_FULL_DEFAULT_ENABLED
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
> +           (IS_ENABLED(CONFIG_KFENCE) && !early_kfence_pool);
>  }
>
>  static int change_page_range(pte_t *ptep, unsigned long addr, void *data)
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index 726857a..570d4e3 100644
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
> @@ -222,8 +228,10 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
>
>  #else /* CONFIG_KFENCE */
>
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

Please move this function to the header as a static inline function,
because nothing else other than arm64 needs this, having this function
be here introduces a .text size increase for everyone.

The function is so short that having it as a static inline function is
fine, and will save a few bytes of .text.

>  static void kfence_init_enable(void)
>  {
>         if (!IS_ENABLED(CONFIG_KFENCE_STATIC_KEYS))
> --
> 2.7.4
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP2zDi9j%2B14-9Cqi5bMCuq7HcCi6om7SP_gfoVxs_AMbA%40mail.gmail.com.
