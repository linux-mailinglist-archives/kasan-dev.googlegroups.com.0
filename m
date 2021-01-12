Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5WC637QKGQEBRKTORY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id C52922F3129
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 14:17:42 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id d9sf366510wmd.5
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 05:17:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610457462; cv=pass;
        d=google.com; s=arc-20160816;
        b=DywmrSEjKOBoTl/1olhcFVxZcWiSH9xe1bnadkUOSBoSQ9I2SM/rjGbaXj3rFXj1yr
         apCkYD4WwATLPx6oGrkUk3WVi8ZUYO/ZvjFmwRBkeEWu5apSe0Lvv4nQC0pxqkVTDWmJ
         t0DHlPzMg+gg+Fqa75ld/wxiDgSPKUsPRWJ6AdZfA/nydm+YAEvzTBirMDOLnkAMxfUJ
         bstTKJhCpzJXhkX9Rx5J/g64NdbDOK4DbR8l/n4qt8FNhc8J7sDQhyO/ehhfoYaLMWJz
         c9AYA6evTXlfle9v8ywJYl+jTvD4elsId4FfYI4B9behA/9X9lB4JdNNjHlOUc3omwVn
         HC2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ngPYA5uPd/KKygZNqOA5U7RJodgPXhRrCaHPEiF8+Lc=;
        b=SPxY7l0yvef957L5J1zGvFm5LLtNeZgP29Tq2ukr2FckVOO8QCsB/r6akSbqn/1siI
         0dl8w6lMn1KqiGaljh9XRp80SzusfJMdqVCMpg4KnzcdNeVrj8Mdek8nYf7OdR+l+/sZ
         onQzigiy+wmSCPVG7B7cs9Uk48eUDlA2YM9ZCyW5iuv3bVs4pOTuGC9nwgyw9m/GJnxM
         KLhDDhWrk550PyGOVh+4M/45c+QBr85edjG+7N1QPVf4G3v7blChyWPiNlN3GYoON0kP
         ePbL1Q2uFy2fm9NpOijM/roUtDx7OvAgLhx76EludJrD0ZDGQlN+wirlk5UcQql7BHYY
         O6bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HSpqfH3t;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ngPYA5uPd/KKygZNqOA5U7RJodgPXhRrCaHPEiF8+Lc=;
        b=XIgtbz31FK67b+4gyka28XHY2hi9KNgDnNA+oqxGO/3L2zH/v50s828/xJn0fj+gsc
         w9jZ+FxTYOtolIHzJUAaxZ2r8KC3Rx2exIg082J0XLV8jRY7ojMlgKPeWt6KEt71xZ7B
         Kwp1gIINoN1S2sbNWCue+VPg+sjayE4j5zQo+8VDnaArKrlC7tHeD/z7g+GWopX/TuOA
         N6S9L1URbkbIoSl6J0RDlVfI6NLFSRGveRtuGdadd8ZxqjlhImv/s1glkZMGQri7KR5X
         EfHynm5dN0lrgZqWEbE6mYLQECrsAczMS3QAx1sp8y1r61jOsT+1IsK6jVarTOftMBct
         NCvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ngPYA5uPd/KKygZNqOA5U7RJodgPXhRrCaHPEiF8+Lc=;
        b=P9fAXQ6ZrXt1PjSlu8pRoEwADYU8iI8kyv9Z56WIkttRKGbn/mh+cdvyJ6lpBDRDCb
         EE6CEoh2LYlNrABYQBcLPBv2khr3pU/4qNw45UnFKXtTipc+7wTLVwel1V8IASCrpdoD
         2cx8bzjFdpVT2nDUSg+25VX8udBzJI4CAWd8bb4hU9NDbnFdXpYpPz1QDSv5XhGN68nw
         CddhJTo9TNbrajzhtQNqxwV1PansXaa8DmVJRgWpbq383r22xMBUw+XnNjfJ649YYqXf
         HNyyyIuRHtXB2xA3zEiKscTUqDkpM20LG0QqVK3kzX5CeafwYYvgiUnldbNPPxurlljJ
         zFJg==
X-Gm-Message-State: AOAM533Dur1b1L2MjmjK0lkDEpmPThe8NmjJku1PqDQ/84jIjbyWQlEG
	x+6MF9zsKQblBLC5eTauNuE=
X-Google-Smtp-Source: ABdhPJwJ1IeL2aZK7VHwukP5W+FXcRm6wFk+DFunwNxYJAbeC+5uVAIDuUfrLqYypiBOrey8nras7w==
X-Received: by 2002:adf:c145:: with SMTP id w5mr4374296wre.400.1610457462562;
        Tue, 12 Jan 2021 05:17:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eb0e:: with SMTP id s14ls3564463wrn.2.gmail; Tue, 12 Jan
 2021 05:17:41 -0800 (PST)
X-Received: by 2002:adf:cc8f:: with SMTP id p15mr3053402wrj.199.1610457461596;
        Tue, 12 Jan 2021 05:17:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610457461; cv=none;
        d=google.com; s=arc-20160816;
        b=ZAWa4ge0+XfGUU/Z95XG2yqFgNmPkdho36282GQHUubdSbxDN637woykWtZisn6q4E
         Ku1AcAPXjvGLg6pkCaLAko/iKQFCid7lg+q3dpGZwbEL7f40xRm/UbUbu+zw80nKnv+o
         GbfegJjnrHnYExcr/0DMKWqwFsBdSGZ6fNXJtB4KT59OHk8JDUhWx2q8vwlouKSf0AUQ
         p5KCcUy0VytsRV20oasF3HfIC4S22VpqPcyI1jqVmjs9X6NmfsDwERGMBoNIx4qlGyCI
         3ddWLucA4tjn3eUGeKjEsTulA+88bNhpYTFZG39aXJQrxk6lsUzh4s+vnIuJ2Brbnm5Y
         /J/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=r2Ei7fyUEnHPknZWOcRP3y5fyGhRG9BocXM6SVWCLZg=;
        b=ArEvN4Hda4hM/WgkvLJxOLF2U+FHXsT0PftUD26iBYfa/kEtNt4R8ggLmCARYNOhXN
         58RS3e27FQryPWLfl2u5WDRkmhPRZPPSfu3MPVLXJp/KH3t3Jg2gHxVmLe0WDV7O+Bxd
         IQ4dZdrL459VUicCnkH90nAZ7dxGHe4/5k0mbiLlbX1AhFpwcZU0/ylAgHqUZa2+N8IG
         2K6rgGpIxfMtPVwc1tAtJfWhlKLanc3EVg6c0lwr4hEwSArcytU7KnKoCYi95bjBB6eK
         Qtyz9LrXfIPHQTjiJPbUnMsj1Nll1pT9qhLvKehjPO2O8kI99DuHplxye+Q+IyXcJzpI
         CrkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HSpqfH3t;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id x130si95473wmg.2.2021.01.12.05.17.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 05:17:41 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id i63so1872751wma.4
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 05:17:41 -0800 (PST)
X-Received: by 2002:a1c:4684:: with SMTP id t126mr3592828wma.165.1610457461081;
        Tue, 12 Jan 2021 05:17:41 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id c20sm3810825wmb.38.2021.01.12.05.17.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Jan 2021 05:17:40 -0800 (PST)
Date: Tue, 12 Jan 2021 14:17:34 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 04/11] kasan: add match-all tag tests
Message-ID: <X/2hboi2Tp87UZFZ@elver.google.com>
References: <cover.1609871239.git.andreyknvl@google.com>
 <0f20f867d747b678604a68173a5f20fb8df9b756.1609871239.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0f20f867d747b678604a68173a5f20fb8df9b756.1609871239.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HSpqfH3t;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as
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

On Tue, Jan 05, 2021 at 07:27PM +0100, Andrey Konovalov wrote:
> Add 3 new tests for tag-based KASAN modes:
> 
> 1. Check that match-all pointer tag is not assigned randomly.
> 2. Check that 0xff works as a match-all pointer tag.
> 3. Check that there are no match-all memory tags.
> 
> Note, that test #3 causes a significant number (255) of KASAN reports
> to be printed during execution for the SW_TAGS mode.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I78f1375efafa162b37f3abcb2c5bc2f3955dfd8e
> ---
>  lib/test_kasan.c | 93 ++++++++++++++++++++++++++++++++++++++++++++++++
>  mm/kasan/kasan.h |  6 ++++
>  2 files changed, 99 insertions(+)
> 
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 46e578c8e842..f1eda0bcc780 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -13,6 +13,7 @@
>  #include <linux/mman.h>
>  #include <linux/module.h>
>  #include <linux/printk.h>
> +#include <linux/random.h>
>  #include <linux/slab.h>
>  #include <linux/string.h>
>  #include <linux/uaccess.h>
> @@ -790,6 +791,95 @@ static void vmalloc_oob(struct kunit *test)
>  	vfree(area);
>  }
>  
> +/*
> + * Check that match-all pointer tag is not assigned randomly for
> + * tag-based modes.
> + */
> +static void match_all_not_assigned(struct kunit *test)
> +{
> +	char *ptr;
> +	struct page *pages;
> +	int i, size, order;
> +
> +	for (i = 0; i < 256; i++) {
> +		size = get_random_int() % KMALLOC_MAX_SIZE;

size appears to be unused?

> +		ptr = kmalloc(128, GFP_KERNEL);
> +		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +		KUNIT_EXPECT_NE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
> +		kfree(ptr);
> +	}
> +
> +	for (i = 0; i < 256; i++) {
> +		order = get_random_int() % 4;
> +		pages = alloc_pages(GFP_KERNEL, order);
> +		ptr = page_address(pages);
> +		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +		KUNIT_EXPECT_NE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
> +		free_pages((unsigned long)ptr, order);
> +	}
> +}
> +
> +/* Check that 0xff works as a match-all pointer tag for tag-based modes. */
> +static void match_all_ptr_tag(struct kunit *test)
> +{
> +	char *ptr;
> +	u8 tag;
> +
> +	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> +		kunit_info(test, "skipping, CONFIG_KASAN_SW/HW_TAGS required");
> +		return;
> +	}
> +
> +	ptr = kmalloc(128, GFP_KERNEL);
> +	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +
> +	/* Backup the assigned tag. */
> +	tag = get_tag(ptr);
> +	KUNIT_EXPECT_NE(test, tag, (u8)KASAN_TAG_KERNEL);
> +
> +	/* Reset the tag to 0xff.*/
> +	ptr = set_tag(ptr, KASAN_TAG_KERNEL);
> +
> +	/* This access shouldn't trigger a KASAN report. */
> +	*ptr = 0;
> +
> +	/* Recover the pointer tag and free. */
> +	ptr = set_tag(ptr, tag);
> +	kfree(ptr);
> +}
> +
> +/* Check that there are no match-all memory tags for tag-based modes. */
> +static void match_all_mem_tag(struct kunit *test)
> +{
> +	char *ptr;
> +	int tag;
> +
> +	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> +		kunit_info(test, "skipping, CONFIG_KASAN_SW/HW_TAGS required");
> +		return;
> +	}
> +
> +	ptr = kmalloc(128, GFP_KERNEL);
> +	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +	KUNIT_EXPECT_NE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
> +
> +	/* For each possible tag value not matching the pointer tag. */
> +	for (tag = KASAN_TAG_MIN; tag <= KASAN_TAG_KERNEL; tag++) {
> +		if (tag == get_tag(ptr))
> +			continue;
> +
> +		/* Mark the first memory granule with the chosen memory tag. */
> +		kasan_poison(ptr, KASAN_GRANULE_SIZE, (u8)tag);
> +
> +		/* This access must cause a KASAN report. */
> +		KUNIT_EXPECT_KASAN_FAIL(test, *ptr = 0);
> +	}
> +
> +	/* Recover the memory tag and free. */
> +	kasan_poison(ptr, KASAN_GRANULE_SIZE, get_tag(ptr));
> +	kfree(ptr);
> +}
> +
>  static struct kunit_case kasan_kunit_test_cases[] = {
>  	KUNIT_CASE(kmalloc_oob_right),
>  	KUNIT_CASE(kmalloc_oob_left),
> @@ -829,6 +919,9 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>  	KUNIT_CASE(kasan_bitops_tags),
>  	KUNIT_CASE(kmalloc_double_kzfree),
>  	KUNIT_CASE(vmalloc_oob),
> +	KUNIT_CASE(match_all_not_assigned),
> +	KUNIT_CASE(match_all_ptr_tag),
> +	KUNIT_CASE(match_all_mem_tag),
>  	{}
>  };
>  
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 3b38baddec47..c3fb9bf241d3 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -36,6 +36,12 @@ extern bool kasan_flag_panic __ro_after_init;
>  #define KASAN_TAG_INVALID	0xFE /* inaccessible memory tag */
>  #define KASAN_TAG_MAX		0xFD /* maximum value for random tags */
>  
> +#ifdef CONFIG_KASAN_HW_TAGS
> +#define KASAN_TAG_MIN		0xF0 /* mimimum value for random tags */
> +#else
> +#define KASAN_TAG_MIN		0x00 /* mimimum value for random tags */
> +#endif
> +
>  #ifdef CONFIG_KASAN_GENERIC
>  #define KASAN_FREE_PAGE         0xFF  /* page was freed */
>  #define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocations */
> -- 
> 2.29.2.729.g45daf8777d-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/X/2hboi2Tp87UZFZ%40elver.google.com.
