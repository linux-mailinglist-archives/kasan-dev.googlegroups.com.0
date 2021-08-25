Return-Path: <kasan-dev+bncBCQ3NB7NQINBBPUGTGEQMGQEETTLNYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id DD8D73F75BA
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 15:18:55 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id u8-20020a0cec880000b029035825559ec4sf17426626qvo.22
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 06:18:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629897535; cv=pass;
        d=google.com; s=arc-20160816;
        b=U38F3Pj2B+7Md8WkUQHvMYqItjILpPtMkY2r4m4JqeAU06nxrIS6QvbIUk63+LynOd
         DRjdJUwAC/puQ7DBC6Gmf3YtqVXJX25H9hx0CPkIs3iFpJkBat9iHj8EXsslAB5MjD2h
         qD4N0rMh2VZSYhX6OrH4Mpgd64KwjzHJ/nQ2oI7X5Wyqx4Vkk1NOGeMrDsMRBwAztN7/
         zPQ9WhTcXf5VF3h5nWZoi0qQlRKf6bhRQ0CPW3wospZlHMdx6bnbzNxRK614WJRyjZgj
         1GLQyAOvl+GNIzp1jats27BRRaP2XANRnbyArP8wKhmahT279TQq2SQVI+ssP8SeJV02
         agRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature:dkim-signature;
        bh=wy0IehZ16VSwUjv3RDt1x0+lV0LhQ5Edl3ckyjO11C8=;
        b=Us8B1MmHzi+wBf8kFE9GVEOsnn493HV1harBSDO+qqs72bR2o0Nj9rhQlxDce6xv9x
         OcezTQdHvDFBONLglD6Kv4068/80DkZySCE9XqHA296uZ3Nm4pcmf7xdpxabyspWvads
         DzllB0Zg2VRpOJ/YQr3BpZguixsEAZQ8NRtYB9N+7qBvrdd41G2LbW286VpkFrwghvPz
         6Q21GsxoNwZX0iSwtMUubWU6V6PykK66bLsD+3QerU+/zyBX+0EJOGTaM9O2qijrjMx3
         txs65vnwvR7wd2hMQTz2Rq/OTd3+AGzPXsd/gKgktmn233UWj6GKE4LWq+ZkhfMuZUSR
         5JSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="SoU40/GX";
       spf=pass (google.com: domain of ownia.linux@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=ownia.linux@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wy0IehZ16VSwUjv3RDt1x0+lV0LhQ5Edl3ckyjO11C8=;
        b=tSl03XS/bgdiaWTzv9oua5cLVAaJfJdUPlV7ag1cntF6xms4SwKheGA5ohrY2+VU/s
         acg+IvEHx4Oy6P4ZyGOAMEwilN3m/n3wc30uKHiWAD4FIJTE4vZtxeGl70DI52+hh0T1
         ChCa5v0GGN9mNciucS7D+RjL+s0PyiCvlG4atl+2D1JJoQMB7l3bszziPt1mm+vkqaqf
         ulJEWy7x+65tRJtECpvvC8x60HX0WTZE9QZ2sX22IMJ38c9EkqKM6qSm2btqyvQok0MV
         h72kYBbBDXDedZJqN329DyFHLiqMd7giEhzB3r7JpjPSnz1rfmmk4CVS0uxrfFKIAD/G
         BS7A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wy0IehZ16VSwUjv3RDt1x0+lV0LhQ5Edl3ckyjO11C8=;
        b=UsOsoFTaeY1SbhQWSdWRSEdPYjUf6v7q3HGGmbB9IbtcjATmgbPgaTNUIbPUfcPvL1
         XD8alMdVA7Zk56pnq+XI6ZEw22JOpBOQ+JjVp8q6kb0ZDbD3XJDXD3rHqqf4jVI0Lcjs
         IYlNT5knNCjEkLm8ZB/82NLukQdaDX+ru2i/Zum4miAO+WOhkDNzJ1NDwXA1Viyrfhcw
         YmccivALYe0hiDPvE9rB9lGEanF6Y0CE5eLDPF6Ht9XizSu6EizxVcRTfjAHEpfqPzAD
         dj/lqeOynotAmdKClhh4A0w6ryGShqMSC2AuUqL3O6bFZbZ7JFFV+wBB3wAsKC4lP/TV
         IRIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wy0IehZ16VSwUjv3RDt1x0+lV0LhQ5Edl3ckyjO11C8=;
        b=YuYXhie4DMbJS2smr9zaFzzutcz1N7+nqcpBBnsVm24GcmZtQ79wFfgDsFJ+2zextG
         42FhwhTVTA95BRwXLjOwNaVLDvMU3GgLrpgmmPRMHApxDyvASig/vhgzfbfBwpP9mwsi
         2oF6Z79+3i2k4UXfVf5j8pkeVam/ynuALfPSTkcSMXr3XJBVtIjZ5F1etgTywoOQhdkx
         p71a1/po8oBxc9OD8eQZwx0RciTh98qFH+598JAVva16gMUET0C6zIJF0qHOHW1a+QWa
         9pkoiXEQG86VINs7Vsoieozwpd+Wv1cFHaiktUhgP4uTIZZ1Pn2EbXMdBDyqKawZsYL+
         z/pA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533FR2n/xjTgrQS5dWtJeWGvqsFiAByIEMoLAarE+OeIIKYCfI/E
	TbT1vtCjm8I4zdKEFtzpyRI=
X-Google-Smtp-Source: ABdhPJxjoNJlErOOy4qfjeTncS81GqpB5NWssefI0UXXYwXj7LCLBXNlxofO/xRl/1tQmzFM3tRFMw==
X-Received: by 2002:a37:9b93:: with SMTP id d141mr31808002qke.236.1629897534964;
        Wed, 25 Aug 2021 06:18:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4111:: with SMTP id q17ls1043332qtl.8.gmail; Wed, 25 Aug
 2021 06:18:54 -0700 (PDT)
X-Received: by 2002:ac8:5805:: with SMTP id g5mr21098274qtg.360.1629897534452;
        Wed, 25 Aug 2021 06:18:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629897534; cv=none;
        d=google.com; s=arc-20160816;
        b=AFhOJpeFREndtpPwp1DVVFjkzkmPsjJcynK6PiZtmoSokEBGQ17oGyeaYcXkSVoI5Z
         ehR4gZYMxv3JhQJ4mQ6tNpJ6TduZq52SixIQk0TgCK55yHxvzTY4OfiodVSBWZZ5BpUu
         NfW4hPgJhI6SwyQwaJPDv4Dge+CBS8eWIiyw8uOwSCYDV9vS27reqWCaWkXCVPRrGlRu
         08bu0uJh90D5z/BVdbf7l8VSegcA5mC/OgwZsBvw5mS7KiJ7cbjfNDcGk4TXgV+IGtVI
         uEykDjRJYHDJnoeE6fmHyCe2Vi+r3FHFmijZ63/XvsfHJeBpLkAa6rn6Y4g7EQJn578O
         GBRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=4ik/eFnY7+CuzmSUYisgf/KLeW0T92g5imVQVoUtu5U=;
        b=oaExTs8pR2c29s310LexaqUhDyxFnnVVMd8mXTKUScLk8Sus+EkAblbCVrLIZxxo8e
         m38eNzWCZO/t75C1k7dKZe5A+rTKmjEXjcSwffZtds+DuJuwLXg9cWF9TbrSGeYnzyY8
         Q+jIBvzbyAaPwUul95EWlXEr8eNL6S6cjU69yRinbEsk4i12Y2+TAZFGrtSHEngdLrlL
         zTeftvfMPqB/RNziem10VV22ByZ5pmLvMOHZ6mURQnv8ITeQK7szNBJQ5lfNDCMc3smW
         00ecs74UpZ1U44iDmGBztJWTTvdgCL7esXq5p2zz0AbgyAmGXTNqfE4PNE6/gO5UuyQn
         LeXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="SoU40/GX";
       spf=pass (google.com: domain of ownia.linux@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=ownia.linux@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id 6si770286qkh.3.2021.08.25.06.18.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Aug 2021 06:18:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of ownia.linux@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id u13-20020a17090abb0db0290177e1d9b3f7so4178104pjr.1
        for <kasan-dev@googlegroups.com>; Wed, 25 Aug 2021 06:18:54 -0700 (PDT)
X-Received: by 2002:a17:90a:c88:: with SMTP id v8mr10716479pja.197.1629897533805;
        Wed, 25 Aug 2021 06:18:53 -0700 (PDT)
Received: from owniadeMacBook-Pro.local ([103.97.201.4])
        by smtp.gmail.com with ESMTPSA id p24sm6945858pfh.136.2021.08.25.06.18.51
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Aug 2021 06:18:53 -0700 (PDT)
Subject: Re: [PATCH 3/4] ARM: Support KFENCE for ARM
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Russell King <linux@armlinux.org.uk>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov
 <dvyukov@google.com>, linux-kernel@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com
References: <20210825092116.149975-1-wangkefeng.wang@huawei.com>
 <20210825092116.149975-4-wangkefeng.wang@huawei.com>
From: ownia <ownia.linux@gmail.com>
Message-ID: <51b02ecd-0f3d-99b0-c943-1d4da26174d0@gmail.com>
Date: Wed, 25 Aug 2021 21:18:49 +0800
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:78.0)
 Gecko/20100101 Thunderbird/78.13.0
MIME-Version: 1.0
In-Reply-To: <20210825092116.149975-4-wangkefeng.wang@huawei.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: ownia.linux@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="SoU40/GX";       spf=pass
 (google.com: domain of ownia.linux@gmail.com designates 2607:f8b0:4864:20::102c
 as permitted sender) smtp.mailfrom=ownia.linux@gmail.com;       dmarc=pass
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


On 2021/8/25 17:21, Kefeng Wang wrote:
> Add architecture specific implementation details for KFENCE and enable
> KFENCE on ARM. In particular, this implements the required interface in
>  <asm/kfence.h>.
>
> KFENCE requires that attributes for pages from its memory pool can
> individually be set. Therefore, force the kfence pool to be mapped
> at page granularity.
>
> Testing this patch using the testcases in kfence_test.c and all passed
> with or without ARM_LPAE.
>
> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> ---
>  arch/arm/Kconfig              |  1 +
>  arch/arm/include/asm/kfence.h | 52 +++++++++++++++++++++++++++++++++++
>  arch/arm/mm/fault.c           |  9 ++++--
>  3 files changed, 60 insertions(+), 2 deletions(-)
>  create mode 100644 arch/arm/include/asm/kfence.h
>
> diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
> index 7a8059ff6bb0..3798f82a0c0d 100644
> --- a/arch/arm/Kconfig
> +++ b/arch/arm/Kconfig
> @@ -73,6 +73,7 @@ config ARM
>  	select HAVE_ARCH_AUDITSYSCALL if AEABI && !OABI_COMPAT
>  	select HAVE_ARCH_BITREVERSE if (CPU_32v7M || CPU_32v7) && !CPU_32v6
>  	select HAVE_ARCH_JUMP_LABEL if !XIP_KERNEL && !CPU_ENDIAN_BE32 && MMU
> +	select HAVE_ARCH_KFENCE if MMU
>  	select HAVE_ARCH_KGDB if !CPU_ENDIAN_BE32 && MMU
>  	select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
>  	select HAVE_ARCH_MMAP_RND_BITS if MMU
> diff --git a/arch/arm/include/asm/kfence.h b/arch/arm/include/asm/kfence.h
> new file mode 100644
> index 000000000000..eae7a12ab2a9
> --- /dev/null
> +++ b/arch/arm/include/asm/kfence.h
> @@ -0,0 +1,52 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +
> +#ifndef __ASM_ARM_KFENCE_H
> +#define __ASM_ARM_KFENCE_H
> +
> +#include <linux/kfence.h>
> +#include <asm/set_memory.h>
> +#include <asm/pgalloc.h>
> +
> +static inline int split_pmd_page(pmd_t *pmd, unsigned long addr)
> +{
> +	int i;
> +	unsigned long pfn = PFN_DOWN(__pa((addr & PMD_MASK)));
> +	pte_t *pte = pte_alloc_one_kernel(&init_mm);
> +
> +	if (!pte)
> +		return -ENOMEM;
> +
> +	for (i = 0; i < PTRS_PER_PTE; i++)
> +		set_pte_ext(pte + i, pfn_pte(pfn + i, PAGE_KERNEL), 0);
> +	pmd_populate_kernel(&init_mm, pmd, pte);
> +
> +	flush_tlb_kernel_range(addr, addr + PMD_SIZE);
> +	return 0;
> +}
> +
> +static inline bool arch_kfence_init_pool(void)
> +{
> +	unsigned long addr;
> +	pmd_t *pmd;
> +
> +	for (addr = (unsigned long)__kfence_pool; is_kfence_address((void *)addr);
> +	     addr += PAGE_SIZE) {
> +		pmd = pmd_off_k(addr);
> +
> +		if (pmd_leaf(*pmd)) {
> +			if (split_pmd_page(pmd, addr))
> +				return false;
> +		}
> +	}
> +
> +	return true;
> +}
> +
> +static inline bool kfence_protect_page(unsigned long addr, bool protect)
> +{
> +	set_memory_valid(addr, 1, !protect);
> +
> +	return true;
> +}
> +
> +#endif /* __ASM_ARM_KFENCE_H */
> diff --git a/arch/arm/mm/fault.c b/arch/arm/mm/fault.c
> index f7ab6dabe89f..9fa221ffa1b9 100644
> --- a/arch/arm/mm/fault.c
> +++ b/arch/arm/mm/fault.c
> @@ -17,6 +17,7 @@
>  #include <linux/sched/debug.h>
>  #include <linux/highmem.h>
>  #include <linux/perf_event.h>
> +#include <linux/kfence.h>
>  
>  #include <asm/system_misc.h>
>  #include <asm/system_info.h>
> @@ -131,10 +132,14 @@ __do_kernel_fault(struct mm_struct *mm, unsigned long addr, unsigned int fsr,
>  	/*
>  	 * No handler, we'll have to terminate things with extreme prejudice.
>  	 */
> -	if (addr < PAGE_SIZE)
> +	if (addr < PAGE_SIZE) {
>  		msg = "NULL pointer dereference";
> -	else
> +	} else {
> +		if (kfence_handle_page_fault(addr, is_write_fault(fsr), regs))
> +			return;
> +
>  		msg = "paging request";
> +	}


I think here should do some fixup to follow upstream mainline code.


>  
>  	die_kernel_fault(msg, mm, addr, fsr, regs);
>  }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/51b02ecd-0f3d-99b0-c943-1d4da26174d0%40gmail.com.
