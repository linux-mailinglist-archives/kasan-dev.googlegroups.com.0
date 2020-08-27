Return-Path: <kasan-dev+bncBDDL3KWR4EBRBB76TX5AKGQEAQCBNQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E9FD254297
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 11:38:16 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id z10sf3929241qvm.0
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 02:38:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598521095; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZbsqqIETi4XWw6NyolNqjZuoI1pXwlwKG/TvaFV47UOwlJGWodjNb22Gt8R78i8v/w
         CBTrKBFg9cRVzpCCspZJby+lZJSBNJ9ZHXAQXAW/an+/nIgjCbaBZVUgC1zZbsh7JV5N
         Es8b6X4e3+lHwO2eXHT5asqzjcj96MjZpJCwH77gAHcWts+hynO115fj4dr2GO2fMfLd
         RmgilX/fLIoBxRPC5fYhfb5zTT5Q95qtsDuKehfq41S8MhWNDOzvIiVjlDyeUgb5Tzpk
         8g0wf/W2Joohja2+aobxUdUAA3WOgssFQY1pAF5knnvwEMCXn3huZYrHi4nsN579X7EB
         eaQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Z4jEUOI4XC2bwzeZRdmIJZzQs2rf0CHsyqeuirqMhB0=;
        b=aGQc3prswyb8We0GjgVAHWzfKxHZgWgJAGpUhj+kpl6720DfgjyzqTtlm0zKv84UwT
         SrNsi/Fmx/7ciVbJnQ5IS/YobI5tb1eV3wYRS7ohnf5g3j12ICfJuEym27uD7gfV9Rtw
         T7Z0EdTf0OXL7voEyvlHTC4oqYNoWwmQuFwtuk1MEPbl3Xx4lV8IBWoWKT5ce2YUyZTM
         nBu9/J8G2UImZhl5PUiJ474FMHN38C3cXvKZBglrKNm4+AzNMMhXNyLplY+KevLrvmXo
         HNrWi+nGPcJ/oOxWyTLrLyR0iBshdIwOWWzgkiST36ZhvUHUR35fo7zeyzWIFTj0rvNJ
         r+/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Z4jEUOI4XC2bwzeZRdmIJZzQs2rf0CHsyqeuirqMhB0=;
        b=ZfFtdAHje3mAz+rYPM9oAv9UnK0GzkkACOst53eOolR8cipLGm/FMz0qGF7Oxf0Drw
         6+SiYsa03wrcPqisFe+XGFAapngLUzgGW9pJHMPlhrDqfMVy0JwbgLWw116LFLzTZs6S
         P0R6LBZkcOZ8M3YuOXEWQbSpzgPUAzpYp07sSQROFZ9qcXFpaAeGAf6evqk6z+f+RYq4
         EjUmSjQ+RGu/zIu7L3xKFkrgu6aNnegV6h/03GBnaku+Q9K2awGatFNhSQj6MoF6cidI
         wsWxjtXtX1xA0f3UJvVuSgqLpZuzr3TL59IUhSznYVcVUQf4gcRb/Be3mhgk2bbuunJv
         Ol+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Z4jEUOI4XC2bwzeZRdmIJZzQs2rf0CHsyqeuirqMhB0=;
        b=WUQvG5Upotm3fKxUU0GDrXCkHrFAccevv5FjCpZ6EZo/to/qMuO2G+FYflgeQIz4RE
         qQiTKr/0qeo7zirlJxDXhCiHPi8B9Byy7eYw+H5541jxJ7VK3H+WwXU/nEYYndKTGbEJ
         Tqh73IKRb21HS/pJXmkia4uyy/TaFePyQ9HM/f1tqEVxz5ezrjANh3MtMtEm10K+OFcK
         dn7WjlFCoyrY+Y21ZlL5Vp8UYQnP4s8ZoTQXDyEkA7mLdkn3G57VnlXjBgQEIrmxlCy+
         9ITKFmdHVyjdG7FvCYeWA+rE85dPQlT+IYEMr5igZopcPu3V9SMxZkT1O93yQIKmWFYO
         qN1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531utECUWbHJxE0g12QtaXBNJ98aGWH3d7t058RRU/p+B4imDpwP
	Xuv/MoGtJ/M+HGYlEwq8/ME=
X-Google-Smtp-Source: ABdhPJzK9cZ5t2yIMwWrh0rBSqzkYYj+0YnpXkcXb5ZKrBzg3qEPBOAf0dfAc+dhItRq6Clp0L8A9A==
X-Received: by 2002:a0c:9a0c:: with SMTP id p12mr17760837qvd.75.1598521095234;
        Thu, 27 Aug 2020 02:38:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:e409:: with SMTP id y9ls693644qkf.11.gmail; Thu, 27 Aug
 2020 02:38:14 -0700 (PDT)
X-Received: by 2002:a05:620a:1304:: with SMTP id o4mr5220867qkj.47.1598521094835;
        Thu, 27 Aug 2020 02:38:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598521094; cv=none;
        d=google.com; s=arc-20160816;
        b=P5qpBtGZxoAXBpJX7kjqexXsokl/rY8F7Cf4Jw8ARIzMCfrVRnup/OCK0ZDST+P43S
         3uXkx1906PON7xjekMvPo8DnwBskbgqckHHisY0RfWoMBA5GeIjOrQ4zemjQ/V3WBnRY
         uMBfwvzQ9yDo4Rlu77F0vmqK9SGX8GKYgbxVij+ho4LMX95vNrkpvcTmAaxr7zJsqpb/
         Q5RAsatGHRAwcRciSZsS+8Q7FY4+AMPHiE3gAajlzTTPlZ3DQ2oyEaF0G0I1vaN8ZacJ
         zTZKQ6SecKLkGkp5Y6q3Gk9Mr4K+uYo2HY0llvg55XfFF6e762ch75CUZ5IPtT6FS4sH
         u5/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=2boAzoZBHJNcv8lVSFxR+h6r1EKobzrihaSShMMGkSs=;
        b=WLN1pBBXzYCz5PptwCsXPeuEkguwoHzox4jeOrYnaomUFrx+zIUTGszWenuZNVZds0
         buoHN9PwL2cGoXiNaJntRqLXAefFzTDymjV2QGkTocldk5t5EhPxl+dlc0y0s7ggKApW
         hc6DD8G3FqMOWgrjpIVSp8h0bCNaYI1bfY+uyaQ8wD+Ka1+99oYYIK01l/icPivTL5Bh
         iLB1E++3r6v0CYrC0tZzQ6cyY89z9+LugbcXiAO8gMG76C4e7VpkKYg8PAPbTV0gQQmw
         ETSArNuUECGRTbzY1RvqVp04vFmGBAfvMTKcunOkR2sF59mu4yIKtdMLmecoKLWc6glo
         kQ5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a189si83874qke.3.2020.08.27.02.38.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Aug 2020 02:38:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.127])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 6333020738;
	Thu, 27 Aug 2020 09:38:11 +0000 (UTC)
Date: Thu, 27 Aug 2020 10:38:08 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 20/35] arm64: mte: Add in-kernel MTE helpers
Message-ID: <20200827093808.GB29264@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <2cf260bdc20793419e32240d2a3e692b0adf1f80.1597425745.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <2cf260bdc20793419e32240d2a3e692b0adf1f80.1597425745.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Fri, Aug 14, 2020 at 07:27:02PM +0200, Andrey Konovalov wrote:
> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> index 1c99fcadb58c..733be1cb5c95 100644
> --- a/arch/arm64/include/asm/mte.h
> +++ b/arch/arm64/include/asm/mte.h
> @@ -5,14 +5,19 @@
>  #ifndef __ASM_MTE_H
>  #define __ASM_MTE_H
>  
> -#define MTE_GRANULE_SIZE	UL(16)
> +#include <asm/mte_asm.h>

So the reason for this move is to include it in asm/cache.h. Fine by
me but...

>  #define MTE_GRANULE_MASK	(~(MTE_GRANULE_SIZE - 1))
>  #define MTE_TAG_SHIFT		56
>  #define MTE_TAG_SIZE		4
> +#define MTE_TAG_MASK		GENMASK((MTE_TAG_SHIFT + (MTE_TAG_SIZE - 1)), MTE_TAG_SHIFT)
> +#define MTE_TAG_MAX		(MTE_TAG_MASK >> MTE_TAG_SHIFT)

... I'd rather move all these definitions in a file with a more
meaningful name like mte-def.h. The _asm implies being meant for .S
files inclusion which isn't the case.

> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index eb39504e390a..e2d708b4583d 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -72,6 +74,47 @@ int memcmp_pages(struct page *page1, struct page *page2)
>  	return ret;
>  }
>  
> +u8 mte_get_mem_tag(void *addr)
> +{
> +	if (system_supports_mte())
> +		addr = mte_assign_valid_ptr_tag(addr);

The mte_assign_valid_ptr_tag() is slightly misleading. All it does is
read the allocation tag from memory.

I also think this should be inline asm, possibly using alternatives.
It's just an LDG instruction (and it saves us from having to invent a
better function name).

> +
> +	return 0xF0 | mte_get_ptr_tag(addr);
> +}
> +
> +u8 mte_get_random_tag(void)
> +{
> +	u8 tag = 0xF;
> +
> +	if (system_supports_mte())
> +		tag = mte_get_ptr_tag(mte_assign_random_ptr_tag(NULL));

Another alternative inline asm with an IRG instruction.

> +
> +	return 0xF0 | tag;
> +}
> +
> +void * __must_check mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> +{
> +	void *ptr = addr;
> +
> +	if ((!system_supports_mte()) || (size == 0))
> +		return addr;
> +
> +	tag = 0xF0 | (tag & 0xF);
> +	ptr = (void *)__tag_set(ptr, tag);
> +	size = ALIGN(size, MTE_GRANULE_SIZE);

I think aligning the size is dangerous. Can we instead turn it into a
WARN_ON if not already aligned? At a quick look, the callers of
kasan_{un,}poison_memory() already align the size.

> +
> +	mte_assign_mem_tag_range(ptr, size);
> +
> +	/*
> +	 * mte_assign_mem_tag_range() can be invoked in a multi-threaded
> +	 * context, ensure that tags are written in memory before the
> +	 * reference is used.
> +	 */
> +	smp_wmb();
> +
> +	return ptr;

I'm not sure I understand the barrier here. It ensures the relative
ordering of memory (or tag) accesses on a CPU as observed by other CPUs.
While the first access here is setting the tag, I can't see what other
access on _this_ CPU it is ordered with.

> +}
> +
>  static void update_sctlr_el1_tcf0(u64 tcf0)
>  {
>  	/* ISB required for the kernel uaccess routines */
> diff --git a/arch/arm64/lib/mte.S b/arch/arm64/lib/mte.S
> index 03ca6d8b8670..8c743540e32c 100644
> --- a/arch/arm64/lib/mte.S
> +++ b/arch/arm64/lib/mte.S
> @@ -149,3 +149,44 @@ SYM_FUNC_START(mte_restore_page_tags)
>  
>  	ret
>  SYM_FUNC_END(mte_restore_page_tags)
> +
> +/*
> + * Assign pointer tag based on the allocation tag
> + *   x0 - source pointer
> + * Returns:
> + *   x0 - pointer with the correct tag to access memory
> + */
> +SYM_FUNC_START(mte_assign_valid_ptr_tag)
> +	ldg	x0, [x0]
> +	ret
> +SYM_FUNC_END(mte_assign_valid_ptr_tag)
> +
> +/*
> + * Assign random pointer tag
> + *   x0 - source pointer
> + * Returns:
> + *   x0 - pointer with a random tag
> + */
> +SYM_FUNC_START(mte_assign_random_ptr_tag)
> +	irg	x0, x0
> +	ret
> +SYM_FUNC_END(mte_assign_random_ptr_tag)

As I said above, these two can be inline asm.

> +
> +/*
> + * Assign allocation tags for a region of memory based on the pointer tag
> + *   x0 - source pointer
> + *   x1 - size
> + *
> + * Note: size is expected to be MTE_GRANULE_SIZE aligned
> + */
> +SYM_FUNC_START(mte_assign_mem_tag_range)
> +	/* if (src == NULL) return; */
> +	cbz	x0, 2f
> +	/* if (size == 0) return; */

You could skip the cbz here and just document that the size should be
non-zero and aligned. The caller already takes care of this check.

> +	cbz	x1, 2f
> +1:	stg	x0, [x0]
> +	add	x0, x0, #MTE_GRANULE_SIZE
> +	sub	x1, x1, #MTE_GRANULE_SIZE
> +	cbnz	x1, 1b
> +2:	ret
> +SYM_FUNC_END(mte_assign_mem_tag_range)

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200827093808.GB29264%40gaia.
