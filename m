Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYP7U6QAMGQECYBDPLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5281A6B2918
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Mar 2023 16:48:51 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id t2-20020a632d02000000b005075b896422sf659483pgt.19
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 07:48:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678376930; cv=pass;
        d=google.com; s=arc-20160816;
        b=TIWqDBAMCTpnuzRd5x+vcrU0GCmy5k5ScQ1uMx/OXFrjaOtpUHPRCe/lxMZFGACgL0
         HiHbDWLgD1ur77rxsyYsKRrPuJiqX2NWtu2USecQonyOco52i1ebZmZO3FJ9/vEtXOb4
         dsjY0T2zoTh1J12KBtUn7fo7pBET0/2A3iCYOuhjPqm1GCB4Dm9fs6czPsIr7U30gEaR
         IvL8xMpI0DHij2G8UL3PqULdtZZCLZ1rs0bF/nVjTlnsf0MwpVrQZ8ubCwNY0mnzKItr
         K26jutZqD1/zpMxg1unnBvazEJESmaipIiGkWm7yQFMRSLmYevPIEz426+sAo3NjV1ny
         1LFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TK1NYAhuvVgiOZ3uDOVUiTHTMDtNdzWl3iBAV+lYVRM=;
        b=YqSXlqg9G6V/DHFcBx0my/T/Pawinlx+X8UOj6TIuKLZaKIYiEgbKL5riaFTvTQb+5
         8a6rIOPU4jd5SwhPfx3RYzkS/KeoWZavjWYmzt80Zj3Pa6d6X3ah/XIvHl/1OiUU4pEd
         jTGA0HltYoFxwuDkl/ZQA3glnm3ihPM1uwnKOXm3ru7nWMlKNYrSMZfpaLbIVExUZ7+g
         qNqFfd6hE6+ole7NXBFmeo6nPbR7X/a0g5gBJvpppdOfbL86FhoQOnvWQxAmPbUbJB06
         E//2wZbF88svBebR2GhHry5NLnVTCaZaMVKRFeeko8bfk6nt2RyDcaUSPuS6iZiCiUpA
         oCQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fE1nYEKP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678376930;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TK1NYAhuvVgiOZ3uDOVUiTHTMDtNdzWl3iBAV+lYVRM=;
        b=BlJRivoJp6KxNQRlxRRi5ADhFQF2kkPEWutJWCOMydR9XVKnYrWgfyEPPPJpB1Mvg7
         1Mxu+GTV6xIVdVjf+UwBBB8cS8JTMTRHL62M9YKQS9ZZWJXldtXAOteSjC/oW1wxZwp8
         xvC0VYrCBQQMcoPW96uiCyzZzHmi4eKmyXyJTVldXHLWxmBxh0daeMkU78g2AAVJomw3
         oz7F7a3UHNGXghnftiANBMQVyPl2zKvCcwuRPRAX4QiMlaqIZ7F58c3S4wyncVDnG5kS
         6k4R6ESS4bC1K+i98Im9NDkMA8iEtyvKwrBK2P5wsJ1NqS1lDS15pfcmKoFbC6k0/dg1
         F/sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678376930;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=TK1NYAhuvVgiOZ3uDOVUiTHTMDtNdzWl3iBAV+lYVRM=;
        b=jg8u47BRpvODHbEAqJetk3vKnaiB7o+qdRrUSqff60ZAuyKld7TLeFO8Gv9YFhReKq
         T3h6yv/NjnMeuVGsRt76oCNtdgfUKBjqIlubDkdkFCE0q1HCmDJQmQIrhVuLMlSnKZEr
         hFugB02SDfpSKAcDEz5hjac/qw6L1JZo5JGgx4MSkVUajpki7vZ+ZSUUkFVmHeBrUPiU
         c8+VTL03jwajrkZI/+bTRy8AqyfD9AyBuRqO/AX/b2EpTKXb5XSw/iUBkhZX7v7oBiEM
         1JXybRPvhRMvAS5QxWEXenzGeUwqN11+m/LKAxdhAOPqQWZwMgnjtqPMDilp2qPITsT3
         3eSQ==
X-Gm-Message-State: AO0yUKWfloEuiVfIJqaifR9xLsYgnSLEsu61ckxgEiL18kNkvDOjDdbW
	LHeVIt2bqqZ+T8fD0+x6Afw=
X-Google-Smtp-Source: AK7set8QAxCoN85fHU2JNNxmK0l2wtZyk0LMQx77cOKRrbp6qLfXPqYy3//jJFYNq3kM8F4CldvbaQ==
X-Received: by 2002:a62:f80d:0:b0:5e6:f9a1:e224 with SMTP id d13-20020a62f80d000000b005e6f9a1e224mr8954863pfh.6.1678376929854;
        Thu, 09 Mar 2023 07:48:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:344d:b0:237:18be:2595 with SMTP id
 lj13-20020a17090b344d00b0023718be2595ls2216956pjb.3.-pod-control-gmail; Thu,
 09 Mar 2023 07:48:49 -0800 (PST)
X-Received: by 2002:a05:6a20:7d9d:b0:cd:91bc:a9af with SMTP id v29-20020a056a207d9d00b000cd91bca9afmr24235421pzj.58.1678376928957;
        Thu, 09 Mar 2023 07:48:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678376928; cv=none;
        d=google.com; s=arc-20160816;
        b=n6JAy+HwhX1sG9rLq4NoLadUs1x9uA7+jBOCWR0cY1HAZn5Ds+XOSL9RlGtV1wH7cd
         R+we3NP6RBtPBwQPmGD/CXf8GoXJAREoMQ+4PY85VyHFHzi14RGO+SkYvK6aWW03xiEC
         CFoKtFkaG5tK0wf9FbVj+ecVuRTQBHkdjnv2C1d0Ui8hqgWBRXKv66+bjEvgXI1MrXQj
         s197JXdW12ZS2eLJ90po+TCduWC9hEcYNfPo9BMuBp8pZv3roKyT3n3xvjqskACmii65
         dLpKyFHlzg0yD9WuiIQI4apRkogqvBIwgZF7yAWQ/QRj8Bn9u9i+SCJIj7z7Xurh4C79
         8DtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bdBTcFq4uhvEA5oTaEAsvRAaPMfrbecdresU0Hqq2NY=;
        b=jFCqpBG9RGhKmA7Axakiuw7Yc3XPxVjge5m5/LWV+G+NaO4kjAkB4pxpWDC3bUjlY0
         FxsSXCqxTq5OOKV3bm2mMtz+ZEtOArDnQ865y8w0i9jSxqXTXAEszS7EkFq9vHGySsIe
         h12R89da6DXpy5+da3nX3FuSSAD8bnAC1mRjaHBSD+mAYnxNAnvDpkZwlpJdFm/ml8Gy
         b6DHROm9QiiysnLXoT/L05PQNKtR99gqnBBTe81TMrrzfVq1WZwuU77deLtjL7UROjkc
         8tw0I1azi+mWZxJJIRpSOnJXYw9ZD7hoDlh4e1RzPgSRJA5K+mQFHnw7O+OdZqNzlEJh
         N28w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fE1nYEKP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x92f.google.com (mail-ua1-x92f.google.com. [2607:f8b0:4864:20::92f])
        by gmr-mx.google.com with ESMTPS id u16-20020a056a00159000b005a8da742642si957103pfk.1.2023.03.09.07.48.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Mar 2023 07:48:48 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92f as permitted sender) client-ip=2607:f8b0:4864:20::92f;
Received: by mail-ua1-x92f.google.com with SMTP id p2so1469485uap.1
        for <kasan-dev@googlegroups.com>; Thu, 09 Mar 2023 07:48:48 -0800 (PST)
X-Received: by 2002:a1f:b292:0:b0:42d:18f9:d0b6 with SMTP id
 b140-20020a1fb292000000b0042d18f9d0b6mr4216436vkf.2.1678376927991; Thu, 09
 Mar 2023 07:48:47 -0800 (PST)
MIME-Version: 1.0
References: <1678376273-7030-1-git-send-email-quic_zhenhuah@quicinc.com>
In-Reply-To: <1678376273-7030-1-git-send-email-quic_zhenhuah@quicinc.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Mar 2023 16:48:07 +0100
Message-ID: <CANpmjNO90KXo3UNCPC6qVt90hJvKLb_o7_99+cWMbtGSNzKTZw@mail.gmail.com>
Subject: Re: [PATCH v2] mm,kfence: decouple kfence from page granularity
 mapping judgement
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
 header.i=@google.com header.s=20210112 header.b=fE1nYEKP;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92f as
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

On Thu, 9 Mar 2023 at 16:38, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
>
> Kfence only needs its pool to be mapped as page granularity, previous
> judgement was a bit over protected. Decouple it from judgement and do
> page granularity mapping for kfence pool only [1].
>
> To implement this, also relocate the kfence pool allocation before the
> linear mapping setting up, arm64_kfence_alloc_pool is to allocate phys
> addr, __kfence_pool is to be set after linear mapping set up.
>
> LINK: [1] https://lore.kernel.org/linux-arm-kernel/1675750519-1064-1-git-send-email-quic_zhenhuah@quicinc.com/T/
> Suggested-by: Mark Rutland <mark.rutland@arm.com>
> Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
> ---
>  arch/arm64/mm/mmu.c      | 44 ++++++++++++++++++++++++++++++++++++++++++++
>  arch/arm64/mm/pageattr.c |  5 ++---
>  include/linux/kfence.h   |  7 +++++++
>  mm/kfence/core.c         |  9 +++++++++
>  4 files changed, 62 insertions(+), 3 deletions(-)
>
> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
> index 6f9d889..46afe3f 100644
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
> @@ -525,6 +526,33 @@ static int __init enable_crash_mem_map(char *arg)
>  }
>  early_param("crashkernel", enable_crash_mem_map);
>
> +#ifdef CONFIG_KFENCE
> +
> +static phys_addr_t arm64_kfence_alloc_pool(void)
> +{
> +       phys_addr_t kfence_pool = 0;
> +
> +       if (!kfence_sample_interval)
> +               return 0;
> +
> +       kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
> +       if (!kfence_pool) {
> +               pr_err("failed to allocate kfence pool\n");
> +               return 0;
> +       }
> +
> +       return kfence_pool;
> +}
> +
> +#else
> +
> +static phys_addr_t arm64_kfence_alloc_pool(void)
> +{
> +       return (phys_addr_t)NULL;

Just return "0" - which the above function does as well on error. Or
the above function should also do (phys_addr_t)NULL for consistency.

> +}
> +
> +#endif
> +
>  static void __init map_mem(pgd_t *pgdp)
>  {
>         static const u64 direct_map_end = _PAGE_END(VA_BITS_MIN);
> @@ -532,6 +560,7 @@ static void __init map_mem(pgd_t *pgdp)
>         phys_addr_t kernel_end = __pa_symbol(__init_begin);
>         phys_addr_t start, end;
>         int flags = NO_EXEC_MAPPINGS;
> +       phys_addr_t kfence_pool = 0;
>         u64 i;
>
>         /*
> @@ -564,6 +593,10 @@ static void __init map_mem(pgd_t *pgdp)
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
> @@ -608,6 +641,17 @@ static void __init map_mem(pgd_t *pgdp)
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
> index 726857a..d982ac2 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -64,6 +64,11 @@ static __always_inline bool is_kfence_address(const void *addr)
>  void __init kfence_alloc_pool(void);
>
>  /**
> + * kfence_set_pool() - KFENCE pool mapped and can be used

I don't understand the comment. Maybe just "allows an arch to set the
KFENCE pool during early init"

> + */
> +void __init kfence_set_pool(phys_addr_t addr);
> +
> +/**
>   * kfence_init() - perform KFENCE initialization at boot time
>   *
>   * Requires that kfence_alloc_pool() was called before. This sets up the
> @@ -222,8 +227,10 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
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
> index 5349c37..a17c20c2 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -814,12 +814,21 @@ void __init kfence_alloc_pool(void)
>         if (!kfence_sample_interval)
>                 return;
>
> +       /* if __kfence_pool already initialized in some arch, abort */

Abort sounds like it's a failure condition, but it's actually ok.

Maybe just write:

 /* Check if the pool has already been initialized by arch; if so,
skip the below. */

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

The rest looks good.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO90KXo3UNCPC6qVt90hJvKLb_o7_99%2BcWMbtGSNzKTZw%40mail.gmail.com.
