Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBSF4R76QKGQEHSV563A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E11F2A7CB2
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 12:13:14 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id t6sf758609ilj.10
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 03:13:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604574793; cv=pass;
        d=google.com; s=arc-20160816;
        b=c9vqHOt8FkBETKO6z91Jxos+5IZ8+uTWu49zJbWJvYi317TNrR69k7KNM2HtQvZwl6
         tq9YesjI4IL4YOocqqDCcjH5z9lDWbwZMquu1i53Zvgt9s3XawVdYkbf9ApYiDP5Cq1m
         gou6QlrFiQHmKheHtQaepZ467UZr+M0M6Z/8BhaQfy1IXpWoeIgyvPmkNKy63Y6bPQoB
         Tl+UvM/5wSm3SjKbkividgLGyTypzrkCzHGfpriMB6jr4xS55ctVwYNUwjuKdhhrpn7B
         3a/FQhgnWI06dHAeTL9rdSIalSxLG7jaQy1KHOUXHlrNKBAQy5t9Z+v/JmrIUhv/H5JY
         ubWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=FP1/2BWsmk9Em9aSEYV/SE6S3qRvozLGeQbSED+70tc=;
        b=Hm7SNxty6LFH0gw599Ojhzs3zV/mosIEINHDHmcUZdUCqMLseRDXV8tjziyTbLnXaN
         fu3rbAiTWzOCgveT6oCGeK9yqu0vZsL9l9UYDZMp/9IrJ2LKPBml8mmTOse3j0+xNJWm
         2Q0xy3GjCzQmufbEHeoXnMAaYI+A30rfbQa3POJZSVrov0/5PUqeg+OvRruEeXM3Gbm7
         3znzKb7P6QPK/SU4y9JcuaWeWh9MTP2+hQNhVsjrJ8/9b6rKeypwwiXbWDAD4kw+XPXX
         Daf10Z8aIfKapbGHLoUthW6XqSru9oQvh+ovGitH/+xfm0+gxGmCnD8/Qrobu90AW37r
         K/5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FP1/2BWsmk9Em9aSEYV/SE6S3qRvozLGeQbSED+70tc=;
        b=pV7b0xjFifLxrreyXxNORKLnmV15S2JpE/00Zg/KzkFGkrsd8Eeu8dp4BFM3qRSPrO
         BxQcg11NQZ6e6pKZGb7vC8e8TIdHzG8F+dDuBFfyr+VmjBKqPfKqsiLCO42w5as1tf7D
         xyhUNnKevgfI2+YSYsWXmFxePTuYjIrnTmiQ6knLS+5wf0bdzk13bR7gNWbHc3O0jZVU
         UUN6qM0qRN4iltxeoPhwJPv3TPm76Y3Gcv11h0kg+j63jjwpLzvtJbasMrZjJpg1HmdJ
         x+jcyWzMfY5IJaV71wDcgQztg9di+QwQ7Tzy+SQEnv1AgijS1M8NcXuLH8YRNCXbnavx
         0D/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FP1/2BWsmk9Em9aSEYV/SE6S3qRvozLGeQbSED+70tc=;
        b=fiB47bt/QzVLZZKV1bSaxyI1KRUBIlDWIag3V2lhJqPKraIXExvT4m083Z3gNG3FuA
         Hm0K5L1MsMZaO1+K+cxdrCcfzhzAzqFjl74SQ8vZW4Sln5b6g+SP7WRCCZ8T67/C8kXR
         FQkNGbRMXWUYRr+XbCEriZQi1geIafEcWfDfIg0mXeyYCJMF5/AS1AAQKESRzzaU2Mj0
         DG3cSfaRoVOH57FNMzfoA3JMX2v/1t4A/E6+RxXZw8dLch4uhl25OPduZtVW3XEVKdLq
         5TCtoFVQJQRDvZr1pquQMuX7DlW+a85DyYELoERTZuih7uD7lDML3kbAZSyXTy4zPr/o
         wslg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532JyNn9YUihrXSM8u4p8fWQOFRx2M22WcAUXbuOXV6eTNbt3y7M
	4WLvKHnhWhU4okqy1eEsq44=
X-Google-Smtp-Source: ABdhPJzUxn041t5vjulQ4htJSikUVElXhA9dBYCtRqTuz8qs0msuQJ8BXrnRkNsZ84RnF0fbyV1X7A==
X-Received: by 2002:a05:6638:626:: with SMTP id h6mr1495107jar.15.1604574792892;
        Thu, 05 Nov 2020 03:13:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:1b42:: with SMTP id b63ls208825ilb.6.gmail; Thu, 05 Nov
 2020 03:13:12 -0800 (PST)
X-Received: by 2002:a05:6e02:1252:: with SMTP id j18mr1350826ilq.119.1604574792460;
        Thu, 05 Nov 2020 03:13:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604574792; cv=none;
        d=google.com; s=arc-20160816;
        b=KFJeH6YSANIa3GMbr6XMAhKpeWbHbr7+hwA7jOJV4arB1f4kJwRzX3BUzC4cF/cwN2
         30vJik+R5QqaB6sKKkUh8xKs8eMCMVnprBAFKwSiYDqGyY0qRyWAnGW0W25IF9PhtCZg
         Y0ayVZnAVQJqlYHPi2RsJ/hDDilpLH3+BZKbh3hOi0cO+gXsCCHlIaR4psNt0DxugdHk
         luZzuMN2AiUWl6aa2iloL0jKZeDg+nUA0GV4h1dKNksDyisUmp57uhTR4oVy9jQE0Fqe
         +z2RSA1/8NU34KUsu7rJSv1o8AFvpiZrp12EmU3Oeed5+tSh/8y8KGsRC4qfP6Mf98/o
         KmLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=ImbZ/pGMX9BDDS8kYSPD4trgaAE1ca62maIOFX47HiY=;
        b=dH/Ix6yRTVBmJFPx3EGbxXCkDxkBsfszpaXCsFCscsWUE5ZtYDfLWLzenOyE2+BquS
         p/+cvxf6sHtl5VgC6S0rqvsxQMz1ZF2JKiyCeYtOmy0nlieBQBw12JmUvxsQ5EnDEkAl
         oC3GYSo5Ms7L9o5CxXsYbrnXHdsa8FpLNgYnLTs9OU5lso77gc5x4RqM9ss3a7pyJMTS
         xbiZlSEAny797cksRAsBtnPnj0vp9rXQQyq6tlg3Gt33/3e5bVFtl2V8yLDsw/2y7TP/
         HRpDsJk4DVNq6X0hVZVC9XeA4XejRXpikNTJjGPHG82Fz+HI7LoPLvsePNWNpnKU54uV
         nusA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id o19si79259ilt.2.2020.11.05.03.13.12
        for <kasan-dev@googlegroups.com>;
        Thu, 05 Nov 2020 03:13:12 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id C6FDF142F;
	Thu,  5 Nov 2020 03:13:11 -0800 (PST)
Received: from [10.37.12.41] (unknown [10.37.12.41])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 645273F66E;
	Thu,  5 Nov 2020 03:13:09 -0800 (PST)
Subject: Re: [PATCH v8 30/43] arm64: kasan: Allow enabling in-kernel MTE
To: Andrey Konovalov <andreyknvl@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1604531793.git.andreyknvl@google.com>
 <5e3c76cac4b161fe39e3fc8ace614400bc2fb5b1.1604531793.git.andreyknvl@google.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <58aae616-f1be-d626-de16-af48cc2512b0@arm.com>
Date: Thu, 5 Nov 2020 11:16:10 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <5e3c76cac4b161fe39e3fc8ace614400bc2fb5b1.1604531793.git.andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Andrey,

On 11/4/20 11:18 PM, Andrey Konovalov wrote:
> Hardware tag-based KASAN relies on Memory Tagging Extension (MTE)
> feature and requires it to be enabled. MTE supports
> 
> This patch adds a new mte_init_tags() helper, that enables MTE in
> Synchronous mode in EL1 and is intended to be called from KASAN runtime
> during initialization.
> 
> The Tag Checking operation causes a synchronous data abort as
> a consequence of a tag check fault when MTE is configured in
> synchronous mode.
> 
> As part of this change enable match-all tag for EL1 to allow the
> kernel to access user pages without faulting. This is required because
> the kernel does not have knowledge of the tags set by the user in a
> page.
> 
> Note: For MTE, the TCF bit field in SCTLR_EL1 affects only EL1 in a
> similar way as TCF0 affects EL0.
> 
> MTE that is built on top of the Top Byte Ignore (TBI) feature hence we
> enable it as part of this patch as well.
> 

seems that in this patch you dropped me as author. Would you mind to clarify the
reason?

> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
> Change-Id: I4d67497268bb7f0c2fc5dcacefa1e273df4af71d
> ---
>  arch/arm64/include/asm/mte-kasan.h |  6 ++++++
>  arch/arm64/kernel/mte.c            |  7 +++++++
>  arch/arm64/mm/proc.S               | 23 ++++++++++++++++++++---
>  3 files changed, 33 insertions(+), 3 deletions(-)
> 
> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
> index 3a70fb1807fd..ae75feaea2d4 100644
> --- a/arch/arm64/include/asm/mte-kasan.h
> +++ b/arch/arm64/include/asm/mte-kasan.h
> @@ -29,6 +29,8 @@ u8 mte_get_mem_tag(void *addr);
>  u8 mte_get_random_tag(void);
>  void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
>  
> +void __init mte_init_tags(u64 max_tag);
> +
>  #else /* CONFIG_ARM64_MTE */
>  
>  static inline u8 mte_get_ptr_tag(void *ptr)
> @@ -49,6 +51,10 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>  	return addr;
>  }
>  
> +static inline void mte_init_tags(u64 max_tag)
> +{
> +}
> +
>  #endif /* CONFIG_ARM64_MTE */
>  
>  #endif /* __ASSEMBLY__ */
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 06ba6c923ab7..fcfbefcc3174 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -121,6 +121,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>  	return ptr;
>  }
>  
> +void __init mte_init_tags(u64 max_tag)
> +{
> +	/* Enable MTE Sync Mode for EL1. */
> +	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> +	isb();

I am fine with the approach of letting cpu_enable_mte() call directly
kasan_init_tags(), but how does it work of the other 2 implementation of KASAN?
Is it still called in arch_setup()?

I would prefer to keep the code that initializes the sync mode in
cpu_enable_mte() (calling kasan_init_tags() before then that) or in a separate
function since setting the mode has nothing to do with initializing the tags.
The second approach probably would come handy when we introduce async mode.

> +}
> +
>  static void update_sctlr_el1_tcf0(u64 tcf0)
>  {
>  	/* ISB required for the kernel uaccess routines */
> diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
> index 23c326a06b2d..7c3304fb15d9 100644
> --- a/arch/arm64/mm/proc.S
> +++ b/arch/arm64/mm/proc.S
> @@ -40,9 +40,15 @@
>  #define TCR_CACHE_FLAGS	TCR_IRGN_WBWA | TCR_ORGN_WBWA
>  
>  #ifdef CONFIG_KASAN_SW_TAGS
> -#define TCR_KASAN_FLAGS TCR_TBI1
> +#define TCR_KASAN_SW_FLAGS TCR_TBI1
>  #else
> -#define TCR_KASAN_FLAGS 0
> +#define TCR_KASAN_SW_FLAGS 0
> +#endif
> +
> +#ifdef CONFIG_KASAN_HW_TAGS
> +#define TCR_KASAN_HW_FLAGS SYS_TCR_EL1_TCMA1 | TCR_TBI1
> +#else
> +#define TCR_KASAN_HW_FLAGS 0
>  #endif
>  
>  /*
> @@ -427,6 +433,10 @@ SYM_FUNC_START(__cpu_setup)
>  	 */
>  	mov_q	x5, MAIR_EL1_SET
>  #ifdef CONFIG_ARM64_MTE
> +	mte_tcr	.req	x20
> +
> +	mov	mte_tcr, #0
> +
>  	/*
>  	 * Update MAIR_EL1, GCR_EL1 and TFSR*_EL1 if MTE is supported
>  	 * (ID_AA64PFR1_EL1[11:8] > 1).
> @@ -447,6 +457,9 @@ SYM_FUNC_START(__cpu_setup)
>  	/* clear any pending tag check faults in TFSR*_EL1 */
>  	msr_s	SYS_TFSR_EL1, xzr
>  	msr_s	SYS_TFSRE0_EL1, xzr
> +
> +	/* set the TCR_EL1 bits */
> +	mov_q	mte_tcr, TCR_KASAN_HW_FLAGS
>  1:
>  #endif
>  	msr	mair_el1, x5
> @@ -456,7 +469,11 @@ SYM_FUNC_START(__cpu_setup)
>  	 */
>  	mov_q	x10, TCR_TxSZ(VA_BITS) | TCR_CACHE_FLAGS | TCR_SMP_FLAGS | \
>  			TCR_TG_FLAGS | TCR_KASLR_FLAGS | TCR_ASID16 | \
> -			TCR_TBI0 | TCR_A1 | TCR_KASAN_FLAGS
> +			TCR_TBI0 | TCR_A1 | TCR_KASAN_SW_FLAGS
> +#ifdef CONFIG_ARM64_MTE
> +	orr	x10, x10, mte_tcr
> +	.unreq	mte_tcr
> +#endif
>  	tcr_clear_errata_bits x10, x9, x5
>  
>  #ifdef CONFIG_ARM64_VA_BITS_52
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/58aae616-f1be-d626-de16-af48cc2512b0%40arm.com.
