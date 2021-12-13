Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBCWI3WGQMGQETGEIKMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id C0EA2473043
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 16:17:31 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 24-20020ac25f58000000b0041799ebf529sf7612200lfz.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 07:17:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639408651; cv=pass;
        d=google.com; s=arc-20160816;
        b=TQRMeGTyT79ZqTx3xHNSPEwwrg65WrWHoASiPHQjaim1De4El/wyhMICND4DKiqu+a
         TRpE3P1C5+CvzwexTriCYgUuNMl9I/jbHwvvIDZbwz/ZS98xcyEOXURJb+611SL2hV4U
         LuJDwixCTCKRLcLAFw5rTyhcyQx5S9W1huiutoogkDEUpA+J4cGXsR7M3RM0WVVlUwJR
         3y4sVmQw9gnHUaHM5r35oKnsjTHwNt3/7yCMrHBjUQHWhlXtDHbTnR2B2PeiQgjTuzz+
         MNwfC+lIElKNEU8LdIWawIVCgeNPA2f7DYQkfDcVht3MkQ2Riqh3NudwCGnImrraJSC5
         Rkng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=PoaQYYozRx2/0iGTKkv/cD/MeUsfcGayu3XNw8w8lzQ=;
        b=gBtYViAuKPRPnPf1tsID2cPE3IBp3ejP+Kr8RIBNE38/4Z7IQZmOZ6Sxxh5vwmZyBm
         oPq/Z+D/1SqbHbks7nPvCDqsOcQqAc71Qp6SqRSo1KNEUGEEZ7q0njCWdsg7PvZuvz15
         IIaMBCHMXCAOTTi/R3WYPECFYyoACtkTqQMO+9Wjv0Y05EP6ohFekt1ggeH7qE1q/lal
         rCvMWn/NrWisevToGsU+9IDxg5wMT/QEvWElbG0Lo0SLQE8TQjUkhPrEyLjLWA2o3u+x
         pIu1OtXOYr/1H75Vor1biluGqXWuNINKfWhBI5CfSIDtMtfeb6wEFQ8PIRYQOrhUKIug
         IkQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PoaQYYozRx2/0iGTKkv/cD/MeUsfcGayu3XNw8w8lzQ=;
        b=JxnDd+j8oySBR3ihbOXQV53751VWO6uhtgBwCk4xxCA+CZqF0LARZy/JQvK6nS7e5g
         YEPs1/9Qv1WFAvK4SOk6fpqUJFcmtxoZRtdDsN2uh5nNh7qVO/2sutSbm24W2hiH7+Ip
         rFnDxPL8EzKbcSTJogyJxl5JQmcjIfex8/QZTjnfguHw6Rv4QeI6Rfphj6KU5ZboZdEA
         4G4ozdM0D9901XnKg1X3cZP4FmG86t4PUamX/3dyIU8P0FEQkHGk3Buc6NBfUhvgbiOa
         TC0ZLoljOV5N4uiC8EkpClG1G6ejAF2N/aibDezo0fJGx1DjIBBYIa6xzmrqL9uw5xee
         AAqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PoaQYYozRx2/0iGTKkv/cD/MeUsfcGayu3XNw8w8lzQ=;
        b=ROQr4Iez3H4b8NIkyyOGOWQHTBWewcuP7ySpdL+rmv3rfNTtjMF8KnNxq9XhHxqeOL
         jutrX+dHcgqtT5ftR3TyuZFlfi2mz0bumPCJlVCMR6fT5cE9UnEp8Bq3sYEGM8dZFisA
         FD6Ibll5TTXXtL2t56yCrfBFKfaCGB6y7ce1uLnYRiuqmApSyKJKGd6ZZpYp2c4VdWOi
         Ru8zFawRTr8nfXSavMorv/kZ2yz57J0mPwTr671XmehdAVzhn4riPYrWuMCqP+lOSZ/e
         U3U3Bx7eJYGWw/eV0T2CVzEcVFIbjzsah6pnrKuzSYan3LF25TVoPqHWCRiQtx2jJtCj
         DVdQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5334qXgefbBY5oBSPqPOMxd3DitRj8PPZYCOZANljR4nlKgllaCD
	Ze08+VL1XrupfH8osePkGVk=
X-Google-Smtp-Source: ABdhPJwjyeF47f0wQwO2m/C55egu1SJK8FthNUo+67FS7rf+SEJNdpawCDAEip2QD7KFFA+ENcljHg==
X-Received: by 2002:ac2:52a8:: with SMTP id r8mr23915903lfm.560.1639408651173;
        Mon, 13 Dec 2021 07:17:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc09:: with SMTP id b9ls2543057ljf.2.gmail; Mon, 13 Dec
 2021 07:17:30 -0800 (PST)
X-Received: by 2002:a2e:a54d:: with SMTP id e13mr29564880ljn.319.1639408650222;
        Mon, 13 Dec 2021 07:17:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639408650; cv=none;
        d=google.com; s=arc-20160816;
        b=XVA2pSI6/F6rWHvNiZUn6GcwcSxJ2n7jXb4AgsHyxynBkBIGlFendZo7MHmwjfZXz4
         5I12gXKZPyp+PvT5X71FxYUq+EqD/bymV7GnNNbpAq6FBW7owrvSFA3UoiakLaXnPgpO
         UUrULHj/ALrCgV4jrC2/PZJN/LYNTvCzbaDKcxFJZD84Raewlz6+CaJjciL5ankJY1wF
         6g8ZT/qU51ueMQfOcH1gJABk2Ub6NSTwI++W++RB6OMxjopRVyQpuD48Nup37T9rU9kr
         l/Vna4fbTW3/csU/4rh6QufP+Tu/CoSzTGMBSGLNWEfFxJw3JngSFECIDR/SNxrnRaRE
         cEGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=/fIjIQQ4fJIJo52QygBn4DPzCEXyPkAMJWsrIrmVuU4=;
        b=vDOFP6d4YYBODsh224xvdBIGa/x23Ut+X6AKUOw8TeuYvVgCIhAmDC3lLLd2/b9E8A
         OAK0W4vX/viKsMponHOUzbihzD7oBhjA7P0emSbGrBTaBJ/Zw7U7TjUD97+p6dW99Gj/
         AtPMglRjslVXyV0spEhTj4vJyClXzet9bt2hJBj/gPN9zRjcZH0tf7alL3axA2JKWmUr
         IfmwLo4AK+hL3Z/BH6OjoWveEiONZ5OQZhqQcaOzogVgL/pVKbXe7fZ2EehzuKKFjrf3
         GhAE6nWvkfKmXh0EPP3uvz3mg5QRtLWywd2MzXGU8snsKBjZl7zZrEf5TgMXKxfjynv7
         pFKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id y7si691220ljp.7.2021.12.13.07.17.29
        for <kasan-dev@googlegroups.com>;
        Mon, 13 Dec 2021 07:17:30 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id DC612D6E;
	Mon, 13 Dec 2021 07:17:28 -0800 (PST)
Received: from [10.0.0.183] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2D7D43F73B;
	Mon, 13 Dec 2021 07:17:24 -0800 (PST)
Subject: Re: [PATCH v2 24/34] kasan, vmalloc, arm64: mark vmalloc mappings as
 pgprot_tagged
To: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>,
 Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com,
 Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
 Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
 linux-arm-kernel@lists.infradead.org, Evgenii Stepanov <eugenis@google.com>,
 linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
 <a1f0413493eb7db125c3f8086f5d8635b627fd2c.1638825394.git.andreyknvl@google.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <d082aa66-8b6b-2a32-bf7e-8256b9ec3cc4@arm.com>
Date: Mon, 13 Dec 2021 15:17:22 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <a1f0413493eb7db125c3f8086f5d8635b627fd2c.1638825394.git.andreyknvl@google.com>
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

On 12/6/21 9:44 PM, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> HW_TAGS KASAN relies on ARM Memory Tagging Extension (MTE). With MTE,
> a memory region must be mapped as MT_NORMAL_TAGGED to allow setting
> memory tags via MTE-specific instructions.
> 
> This change adds proper protection bits to vmalloc() allocations.

Please avoid "this patch/this change" in patch description and use imperative
mode as if you are giving a command to the code base ([1] paragraph 2).

> These allocations are always backed by page_alloc pages, so the tags
> will actually be getting set on the corresponding physical memory.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

With the change to the commit message:

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

> ---
>  arch/arm64/include/asm/vmalloc.h | 10 ++++++++++
>  include/linux/vmalloc.h          |  7 +++++++
>  mm/vmalloc.c                     |  2 ++
>  3 files changed, 19 insertions(+)
> 
> diff --git a/arch/arm64/include/asm/vmalloc.h b/arch/arm64/include/asm/vmalloc.h
> index b9185503feae..3d35adf365bf 100644
> --- a/arch/arm64/include/asm/vmalloc.h
> +++ b/arch/arm64/include/asm/vmalloc.h
> @@ -25,4 +25,14 @@ static inline bool arch_vmap_pmd_supported(pgprot_t prot)
>  
>  #endif
>  
> +#define arch_vmalloc_pgprot_modify arch_vmalloc_pgprot_modify
> +static inline pgprot_t arch_vmalloc_pgprot_modify(pgprot_t prot)
> +{
> +	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&
> +			(pgprot_val(prot) == pgprot_val(PAGE_KERNEL)))
> +		prot = pgprot_tagged(prot);
> +
> +	return prot;
> +}
> +
>  #endif /* _ASM_ARM64_VMALLOC_H */
> diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
> index b22369f540eb..965c4bf475f1 100644
> --- a/include/linux/vmalloc.h
> +++ b/include/linux/vmalloc.h
> @@ -108,6 +108,13 @@ static inline int arch_vmap_pte_supported_shift(unsigned long size)
>  }
>  #endif
>  
> +#ifndef arch_vmalloc_pgprot_modify
> +static inline pgprot_t arch_vmalloc_pgprot_modify(pgprot_t prot)
> +{
> +	return prot;
> +}
> +#endif
> +
>  /*
>   *	Highlevel APIs for driver use
>   */
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 7be18b292679..f37d0ed99bf9 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -3033,6 +3033,8 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
>  		return NULL;
>  	}
>  
> +	prot = arch_vmalloc_pgprot_modify(prot);
> +
>  	if (vmap_allow_huge && !(vm_flags & VM_NO_HUGE_VMAP)) {
>  		unsigned long size_per_node;
>  
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d082aa66-8b6b-2a32-bf7e-8256b9ec3cc4%40arm.com.
