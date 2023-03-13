Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBNMXOQAMGQEIO2OUZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id BCC416B705A
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 08:51:35 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id pb4-20020a17090b3c0400b00237873bd59bsf4076109pjb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 00:51:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678693894; cv=pass;
        d=google.com; s=arc-20160816;
        b=QMkDHXlhZaPrGZRPtF6sUFXDad+EAV5YFdC86DIaW7d9Se4FQiF0gTClrZtzpiAzjP
         GPPy0zkSdRUIuM1pc26/ATPs+DxeoWGHaCLiT16invdmXnuYK3wi/xSfvvUS3ov98Z3R
         N0xkNFZb8azT5pAGQHFGlFCSSxOi468/nFOa4s/KJsNZl8bgA2o2MlG2qmm8Kdpn3ClW
         Ur7qWhky6bN/0Vh1nn6XbXZn43FKjednzEEF0d67ws3U4Ht59ioNtoYLJ7o17+yJ5C5v
         gdgcM5eEOo2iUaOYe1gohRuhaEqrWorx/SlLakyd9w5WzBDW6nS/pUiiuxs3EvH9drlM
         kLow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jKjefCHYG/z162UivVILartTQ/Ii9BlgtfMZkXYtWok=;
        b=rmcpexxu5o+ZS5nKoUJPkQxiH6r+7bUb1weWHYbL4I2pcGusTnWAGnBp8rFFQQUxlP
         KcQUgWECAv/kg2hOvgInaj2pG0UH/JYLPLN6k4MU6XQ/iUXA00i+GYFtvbSSWK3Dhr+7
         2iqxXP9dkD2VohZnuLtks2Mqllftc2XcK3RyAfqY+ootSBZkvIlUxCzcVgundSEQPMBp
         2IOsIekcoEYFtNNYhRX5SniQ85G1k7jGkz5U/0qQnY03w7BDmJr2jqjgXUHBe4OtWJem
         C8WjRJuUdHAyta3gcVhTXTGmAGSpRJRgjFvDKnIWDagdeErSHYYNl08E6LqF3Qd8BnQj
         oW8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="bHrEW/Uf";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::134 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678693894;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jKjefCHYG/z162UivVILartTQ/Ii9BlgtfMZkXYtWok=;
        b=crnQBWBha8KJCKNqWJNJlGB6OcE05KZuJ6MYigl4iSCoEjh1r7UKC+1SWDpIUH+Lg5
         gr5PqZGzetNBHZLFMzL+pw/jBF/xCplZaKb2UZ+/DKxWq1b563uXKxFPhT48rUaferPI
         ml/o78RKSlZN3uRGYnjx7QvTRS9aOZJF7C+x2rQLRzg+q82Y28t2NsJgFBb+cUKNUAD6
         nyOoh9aQBuek+jQpCLeg8TgFoxCL5ivkO9iteln671nJ2GWWUeXxUW6XSpiY84am0+kN
         TdQBL8ucgUv2X1eYlcERG8Cqj8d/aiumGR/UH7rA8oWRnFF2mNCEpCBOWT5dFz5X5QJI
         4vGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678693894;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=jKjefCHYG/z162UivVILartTQ/Ii9BlgtfMZkXYtWok=;
        b=YUcETRClejLQRRhyKxvNCrcdz4HvJH9YlxgSdaZjO8o/9gv8IUpHsgQA6Gj8+qzD8p
         aXLqxFvk0KKd4H+O0yaFXqXy7n2ZsrKlIxfCSvYAOyp+WTA2qufiHE2rMaC4YwRUy9qY
         bGfjjHAqQVcLO9f30LkgsB/ioXyEMJk9utIrjTL6NctXnUAxM+NOqMQijLTxZZhYkcAp
         xlv8SVJOF7cm8TdGwN+MjnxZz3p71MSW4vVaog+HH8D/L1sdCEoqNZ0bJfBslDilLz9I
         qgUwtBXmfep4qmBt2uvxqOgRZWx2lZJ3qWwHfHqOVXJwNGNkXN3IoF8Wjci6ATZHbHFi
         yjCw==
X-Gm-Message-State: AO0yUKXSOVX09LOntOxRXJiS12dCXUB4JBn/wvwqCs4gBMwwUFEVMWfT
	qAnSzDdXWwJ0tQzFNxFkdX4=
X-Google-Smtp-Source: AK7set+R1AQJaI0TMz+FkWnOfqRjrJ5IFhy/vyRZf0jH8z4y8dH1T+jc59Zw/RgXFQenlIVczbfVhA==
X-Received: by 2002:a17:90a:420b:b0:237:29b1:188f with SMTP id o11-20020a17090a420b00b0023729b1188fmr12119693pjg.8.1678693893801;
        Mon, 13 Mar 2023 00:51:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2406:b0:19c:b41a:3d75 with SMTP id
 e6-20020a170903240600b0019cb41a3d75ls11708993plo.7.-pod-prod-gmail; Mon, 13
 Mar 2023 00:51:32 -0700 (PDT)
X-Received: by 2002:a05:6a20:2446:b0:b5:a231:107f with SMTP id t6-20020a056a20244600b000b5a231107fmr35488979pzc.12.1678693892851;
        Mon, 13 Mar 2023 00:51:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678693892; cv=none;
        d=google.com; s=arc-20160816;
        b=LPgeUw4OAM0T/VE5XZE0yBoxsYryazUDZKTVyX1IDuKX/Ac0Sj8CQRssViLcuwOTId
         lyuSH/aRtubaWK5cG+Q1sB0vdSNTv4t5bVM2sOaJcHmzEUQ+4BQ4NnsdmEWjYZWhRAU+
         o18gMhciPlvF3FqBAA6IuzZnF+BgNK8yd6WZMaObLV7qKb+DCbcy2XPn7h40RWI+idLD
         DMGqq20VJb0S+6nG57nQ/cbuj418rAl8mXnvp/eWgkAq2tglgekQbLPEglyvNwWqW7oz
         oE+g4Zx1m8UkXoGUHww+M7PtQQOXG0my9hdYY62mqChvBslWL4SN2++lv7lY3iJLhD4b
         r2Qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zre3cMMIhgx2jQEOm1j7EJjcBMgwQWtjDIhJZ7Z9Qm4=;
        b=utlAeDVH86Gzc6M0Q7+hUjC6mLPsPjPSzgew0galWSrpAxMYKcpdiYVlY0ffiNhRAU
         hQQUduwQTvWdeUyyX0vg2kzAramcatisBajn2Lksgb2+r+Zwm8CkZnMw5QGqk/YpfPsc
         rWfV+kb122h0J8YkdPIYFWiKDs7K4t4hPaTls+Yzc6xPGcAInJjwStYHmHjbK9jF9z3o
         lyPf9/Rduo8cmp11kxXGEswiAdO70RAV/KwtclimzIotQlceOaaH8qR/OGdj4xls+vJo
         uKqQLe7cfWCdboYZD/N7PjTmpaGQNL2gbQZdBBuBNxvBMOEyQUA1hskgxSMEZoX0tiP7
         tLhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="bHrEW/Uf";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::134 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x134.google.com (mail-il1-x134.google.com. [2607:f8b0:4864:20::134])
        by gmr-mx.google.com with ESMTPS id t62-20020a632d41000000b004fb840b5440si242720pgt.5.2023.03.13.00.51.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Mar 2023 00:51:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::134 as permitted sender) client-ip=2607:f8b0:4864:20::134;
Received: by mail-il1-x134.google.com with SMTP id a13so149563ilr.9
        for <kasan-dev@googlegroups.com>; Mon, 13 Mar 2023 00:51:32 -0700 (PDT)
X-Received: by 2002:a05:6e02:690:b0:323:855:9daa with SMTP id
 o16-20020a056e02069000b0032308559daamr1091203ils.4.1678693892072; Mon, 13 Mar
 2023 00:51:32 -0700 (PDT)
MIME-Version: 1.0
References: <1678683825-11866-1-git-send-email-quic_zhenhuah@quicinc.com>
In-Reply-To: <1678683825-11866-1-git-send-email-quic_zhenhuah@quicinc.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Mar 2023 08:50:50 +0100
Message-ID: <CANpmjNNYgP+4mAdQ1cVaJRFGkKMHWWW7nq9_YjKEPDZZ_uBOYg@mail.gmail.com>
Subject: Re: [PATCH v5] mm,kfence: decouple kfence from page granularity
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
 header.i=@google.com header.s=20210112 header.b="bHrEW/Uf";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::134 as
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

On Mon, 13 Mar 2023 at 06:04, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
>
> Kfence only needs its pool to be mapped as page granularity, previous
> judgement was a bit over protected. From [1], Mark suggested to "just
> map the KFENCE region a page granularity". So I decouple it from judgement
> and do page granularity mapping for kfence pool only.
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

This patch still breaks the late-init capabilities that Kefeng pointed out.

I think the only viable option is:

 1. If KFENCE early init is requested on arm64, do what you're doing here.

 2. If KFENCE is compiled in, but not enabled, do what was done
before, so it can be enabled late.

Am I missing an option?

>
> LINK: [1] https://lore.kernel.org/linux-arm-kernel/Y+IsdrvDNILA59UN@FVFF77S0Q05N/
> Suggested-by: Mark Rutland <mark.rutland@arm.com>
> Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
> ---
>  arch/arm64/mm/mmu.c      | 42 ++++++++++++++++++++++++++++++++++++++++++
>  arch/arm64/mm/pageattr.c |  5 ++---
>  include/linux/kfence.h   |  8 ++++++++
>  mm/kfence/core.c         |  9 +++++++++
>  4 files changed, 61 insertions(+), 3 deletions(-)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNYgP%2B4mAdQ1cVaJRFGkKMHWWW7nq9_YjKEPDZZ_uBOYg%40mail.gmail.com.
