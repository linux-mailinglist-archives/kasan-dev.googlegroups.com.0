Return-Path: <kasan-dev+bncBDV37XP3XYDRBFNPWTVQKGQEEZLW5UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 586F6A5799
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Sep 2019 15:22:30 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id v15sf8843511wrg.13
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Sep 2019 06:22:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567430550; cv=pass;
        d=google.com; s=arc-20160816;
        b=PqJNwKpMDitBymsAC7Kwwo3tyUGdr3U5CGaYBCZvyUYcALH+fS73QglWuVlfCL+sbO
         DSlP0dNu5GbfNT/ZjwzS588JLf7XtqBuQIYvkD0CnNaKFGU4/l+OVb1ocX+UAqBlCyFt
         AvnEPPOEwzrCkGVcfv/MqMUUBhiVf6Wi/EqSnBjTes8IWJ1PjT92eHrCsfEKKTy5ry2k
         XnswuZ5dIIetyHnLN4dqkMutSUdPd45ITNSg6MlZZafF9SeGu9A4F1KHdTDAvpX9Pvg0
         uGMCHi5CRwWMzBu2eEAxKhQyLK8ZV5KedCBwXASt9EMs/rEY3qrBiSqCA06+Wu/KSTvC
         rZAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=8qkK4pAFwRf5ouZ4X5wsO5xPX5AIQII1omox9bpQlSU=;
        b=V3TJ7IGjFWezTro7b2hnePivHHy1WBm3LPZBSpc/S13ZG4CNxHUivynOickgfnNdie
         DJXBM+zGfMmb/c4/SZzjbV31H0kxNFla227b9tBLP+dA/TCSTESUn7d+9qS0od39YJQq
         T6h87oh5Tzj3mzaA0ktSTJxPLJBGKxV3q+olo01J61ELG2NOOm+Yk7kZzzP72X+g6Peo
         /v/vPmdCUKpvfQsEyDs1pTHj+VjRBWYYtAJQ3zGQyhrleAGu8s0PyY1GBapdUsDXpu3d
         mUi8utDV4xcAX7wQ4g9BfTHJBCzNQVeU63zC9mTJ8LZbnyrvVXAotOR2LUgYdAyXrf73
         FTTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8qkK4pAFwRf5ouZ4X5wsO5xPX5AIQII1omox9bpQlSU=;
        b=d/9uZoEBJOWvurZgzL2LH/Wr9oXEaaBdpPkwjcPECDw4ep6Qm0OOw5XwjC0/fGqpJO
         5plgEWAMe+ndhgcFMbWPdx8iJ1h7Tj4P9Dt05KCpVgaG3K8RNTwHv6UKbiHEtEwNUK0p
         NfFho/B9Q0pk870nLe5h9agx7HU4WoKM7FH/MpySYhN8hGMptBu52fiAU9EkqTNZd7dW
         byGghSmBN87jk8ptKBkZ4BOyKcKO34j5JK5pRza39uKCegBprCNDFAiV/JubGCXxE1r0
         NJqag8IN+D/9rOEq5DbhMEh1AdrMZvfolfajwxOqX5JVdIPknisyaECSSHrDLfAg9pB6
         i+Kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8qkK4pAFwRf5ouZ4X5wsO5xPX5AIQII1omox9bpQlSU=;
        b=uJ4YQfo5PCAcDbF9ySv3+j967lnVWGVzfzRCqUAbLGS7J3yjDE4kh0zoa0yiS00KFB
         +Bju27qzpnB2qSF6ea/3QUITTlQEdSFrkWLqvdlPk+V5u/ormltkUCE8NKzTaOkh4y2A
         pdGP5E+l0Xdz8OodNrqMZOIwPtbRsHHLiiUirlVWWysWXOQkYnlKjcgSlF/v4c1WkF6N
         TcHH3WfAWKaXQGTPPU1c9ylUznGlfqID0MSnAD6VNbun2o/MCwtDNQxef8On9UhNw/RM
         09LpWBNDf53wwDeFORDIYmTjb/zrTTQn7+9f01Mmh2fE/gmx0ZaJlvlC+ndob95D6Haw
         RtPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUuR0za9Cfyds54CgC0xgmoj9pjmYihp0qj+W2O5ZnCOczCkRl8
	0PwRaOw2kXYrsWxsJrdIe/o=
X-Google-Smtp-Source: APXvYqy+j2oQ/LaxX67GKKC4vtEBMgaJEyumXBK1g4jBnXZIW5MXdhdkzp0owx3qoa8oEL2B4Lv1oA==
X-Received: by 2002:adf:eec5:: with SMTP id a5mr36037638wrp.352.1567430549981;
        Mon, 02 Sep 2019 06:22:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:550b:: with SMTP id b11ls449459wrv.1.gmail; Mon, 02 Sep
 2019 06:22:29 -0700 (PDT)
X-Received: by 2002:a5d:4f08:: with SMTP id c8mr9179058wru.51.1567430549361;
        Mon, 02 Sep 2019 06:22:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567430549; cv=none;
        d=google.com; s=arc-20160816;
        b=csAYv55RGaSkzExQ7MY62DpDFdu/4W2PL+LC7YhT10G5WxhyIvcDj2zhbacrpi9mz3
         Ov5N8EIgqJ3ITBh6jFM9ET0NLOUccupzRLlf3JTJIq0vPV4PS3l89fz3auGe8eABj4t2
         Z7WCDbosY2iIvueV/WCQ+4JBVmHGuDbYsFXPGCLTs66oCQtbqhhkMvFjNhpjQebAOcqZ
         UmPqFSmWAdav1CRKmz0nrrkxRiopsuyZjL+xo5NOSfujo0fjgTO2Ry0A1u9LjyEN1BYk
         N1PNvZf1VmtAnPn07qA94+6zn/YMGcYl0DmJBbAfZRmD90h4MQFkab1VDjokKE2oSyB2
         m0dA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=YXtHy3bzn+dKLZLUIhvueZRNQbqFDKjjF+JGENDlZQ8=;
        b=k0mf/mA/X8G5+4/6iN+6auKTeWWH65pPogXWKcMxGeblvVsvoxft+w3JwCykt2PgUq
         OILyOfX9+BmoeeQIFRJqb5CFOV1YrHFCBvWx3A0iQehfNA+WTLus8zZkgNEL6mCAyvPN
         8RrqGIr5sQo4ekEjActGI3/yVpgPlH75dGU91ljD1MfBCIaEFl/eFU1I+Z2/QfCXB1v3
         KWsOH6gDFd1wq4WVUV+Y27UkdGC2GzFUZQnqfJOvXIoX3Ol5Kd20SAZ7RQaEaJi0ucxZ
         M4SqYBZLrsKDV5/drBMREgsuwN9gyY6RrZEz3lPod3Auf0QjfgaeTdFfvyA+Jw2NSiu0
         SKXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id u20si89112wmc.0.2019.09.02.06.22.28
        for <kasan-dev@googlegroups.com>;
        Mon, 02 Sep 2019 06:22:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 6C385337;
	Mon,  2 Sep 2019 06:22:27 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D5D5A3F71A;
	Mon,  2 Sep 2019 06:22:25 -0700 (PDT)
Date: Mon, 2 Sep 2019 14:22:21 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org,
	aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org,
	linux-kernel@vger.kernel.org, dvyukov@google.com,
	christophe.leroy@c-s.fr, linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com
Subject: Re: [PATCH v6 1/5] kasan: support backing vmalloc space with real
 shadow memory
Message-ID: <20190902132220.GA9922@lakrids.cambridge.arm.com>
References: <20190902112028.23773-1-dja@axtens.net>
 <20190902112028.23773-2-dja@axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190902112028.23773-2-dja@axtens.net>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Mon, Sep 02, 2019 at 09:20:24PM +1000, Daniel Axtens wrote:
> Hook into vmalloc and vmap, and dynamically allocate real shadow
> memory to back the mappings.
> 
> Most mappings in vmalloc space are small, requiring less than a full
> page of shadow space. Allocating a full shadow page per mapping would
> therefore be wasteful. Furthermore, to ensure that different mappings
> use different shadow pages, mappings would have to be aligned to
> KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE.
> 
> Instead, share backing space across multiple mappings. Allocate a
> backing page when a mapping in vmalloc space uses a particular page of
> the shadow region. This page can be shared by other vmalloc mappings
> later on.
> 
> We hook in to the vmap infrastructure to lazily clean up unused shadow
> memory.
> 
> To avoid the difficulties around swapping mappings around, this code
> expects that the part of the shadow region that covers the vmalloc
> space will not be covered by the early shadow page, but will be left
> unmapped. This will require changes in arch-specific code.
> 
> This allows KASAN with VMAP_STACK, and may be helpful for architectures
> that do not have a separate module space (e.g. powerpc64, which I am
> currently working on). It also allows relaxing the module alignment
> back to PAGE_SIZE.
> 
> Link: https://bugzilla.kernel.org/show_bug.cgi?id=202009
> Acked-by: Vasily Gorbik <gor@linux.ibm.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> [Mark: rework shadow allocation]
> Signed-off-by: Mark Rutland <mark.rutland@arm.com>
> 
> --
> 
> v2: let kasan_unpoison_shadow deal with ranges that do not use a
>     full shadow byte.
> 
> v3: relax module alignment
>     rename to kasan_populate_vmalloc which is a much better name
>     deal with concurrency correctly
> 
> v4: Mark's rework
>     Poision pages on vfree
>     Handle allocation failures
> 
> v5: Per Christophe Leroy, split out test and dynamically free pages.
> 
> v6: Guard freeing page properly. Drop WARN_ON_ONCE(pte_none(*ptep)),
>      on reflection it's unnecessary debugging cruft with too high a
>      false positive rate.
> ---

[...]

> +static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> +					void *unused)
> +{
> +	unsigned long page;
> +
> +	page = (unsigned long)__va(pte_pfn(*ptep) << PAGE_SHIFT);
> +
> +	spin_lock(&init_mm.page_table_lock);
> +
> +	if (likely(!pte_none(*ptep))) {
> +		pte_clear(&init_mm, addr, ptep);
> +		free_page(page);
> +	}
> +	spin_unlock(&init_mm.page_table_lock);
> +
> +	return 0;
> +}

There needs to be TLB maintenance after unmapping the page, but I don't
see that happening below.

We need that to ensure that errant accesses don't hit the page we're
freeing and that new mappings at the same VA don't cause a TLB conflict
or TLB amalgamation issue.

> +/*
> + * Release the backing for the vmalloc region [start, end), which
> + * lies within the free region [free_region_start, free_region_end).
> + *
> + * This can be run lazily, long after the region was freed. It runs
> + * under vmap_area_lock, so it's not safe to interact with the vmalloc/vmap
> + * infrastructure.
> + */

IIUC we aim to only free non-shared shadow by aligning the start
upwards, and aligning the end downwards. I think it would be worth
mentioning that explicitly in the comment since otherwise it's not
obvious how we handle races between alloc/free.

Thanks,
Mark.

> +void kasan_release_vmalloc(unsigned long start, unsigned long end,
> +			   unsigned long free_region_start,
> +			   unsigned long free_region_end)
> +{
> +	void *shadow_start, *shadow_end;
> +	unsigned long region_start, region_end;
> +
> +	/* we start with shadow entirely covered by this region */
> +	region_start = ALIGN(start, PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
> +	region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
> +
> +	/*
> +	 * We don't want to extend the region we release to the entire free
> +	 * region, as the free region might cover huge chunks of vmalloc space
> +	 * where we never allocated anything. We just want to see if we can
> +	 * extend the [start, end) range: if start or end fall part way through
> +	 * a shadow page, we want to check if we can free that entire page.
> +	 */
> +
> +	free_region_start = ALIGN(free_region_start,
> +				  PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
> +
> +	if (start != region_start &&
> +	    free_region_start < region_start)
> +		region_start -= PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE;
> +
> +	free_region_end = ALIGN_DOWN(free_region_end,
> +				     PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
> +
> +	if (end != region_end &&
> +	    free_region_end > region_end)
> +		region_end += PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE;
> +
> +	shadow_start = kasan_mem_to_shadow((void *)region_start);
> +	shadow_end = kasan_mem_to_shadow((void *)region_end);
> +
> +	if (shadow_end > shadow_start)
> +		apply_to_page_range(&init_mm, (unsigned long)shadow_start,
> +				    (unsigned long)(shadow_end - shadow_start),
> +				    kasan_depopulate_vmalloc_pte, NULL);
> +}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190902132220.GA9922%40lakrids.cambridge.arm.com.
