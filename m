Return-Path: <kasan-dev+bncBC7OBJGL2MHBB37G637QKGQEOR6JUFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 208692F3300
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 15:34:24 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id t194sf1123492lff.15
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 06:34:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610462063; cv=pass;
        d=google.com; s=arc-20160816;
        b=QODT/7mb6dhBBfafInbrSfMU1HTM5Ch/tBQDITG838eZyVGU+vnrCCAVE70PSpOLRX
         Xo5a+n91h8LBfgg2b8FHE+0uefovYeolWE9nkL2TrNWBRdVvxoimOsbRRaJWP26ezICD
         VKfuoIgX9FsBdSf80JyeCfwzleOo7L5nBwgEqWV3a1K+vlpi5LDz8GiBUA4N3rfTXID8
         Xvs81aiuQw2x3b7CEvOY59l2NOXQskoWnjqoVo6o5IA2H8P5vC++o9dCfwyO57oKAghj
         AeVGQHWvU/gZC2TERf+Z6aYYCL2vYtDVIyVTlUQpuVqfCB2LPXjjMlaFGX0UOCnFrA33
         okIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=xLs25MUrHfEQBlSXrEckGxMDLAphsoR7awGq3XsdOgQ=;
        b=E8yHVCGXyKJoAD3d2p3zbiB39CJpLkH0cgu/2FL6e9atKd6xgZ5DKZvrvKaTNGiPoy
         bSbTxiRhR4yHbjwIqyZInVLUbkkjr5f+oMWXlzkInzOnt/IOw7GW+8KDgHsFMCGe3Nuf
         G+HS0cas56d9IENUD2ZcEITDUBJCYEcY8J8TAhU1AReFS/rNaaRa05t7PrG6hwy+A+cY
         2xmJoMldf/R29nfGlypnr1qzxPo9yOmbUKtk8b6W4nactOO9jJgBW2cUfyyhfnbLixVV
         wZcP1KZJ8YXKCmdAgxdDi3BRChKaaxqC2y317JJK18/ajsiWtdfSXm4XDPFc9TvDfGpC
         9cww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p7sCAvlU;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=xLs25MUrHfEQBlSXrEckGxMDLAphsoR7awGq3XsdOgQ=;
        b=gRr1UoTUSJkazIBo7nqPjCLNSncOYqonpqnlro4FEfVrKN5486aMSV5yJ6PsEqLor/
         5U66qNJ9Vsdb/RYaPC1ncXuB92G2tonG/aRlMgQ0XLsDrvwVmGSFxgBRM4CfiBg4DHeG
         2WTxTDvcFmYsyIdkRnQ1UL29q2jICOIIVaMaPUJzuyAGjlytneIDA5pGj8RNNaI81H08
         UiG5LZNJBmvIs61tbZcTYVoucHxMK8+JQaIxNQEHhn3rOpzq159r9pMM2t7IJ31Gnuyj
         a9mmfvbziH6yvPee3Z0sJVjv7rzRaAjkMlfh7BoMJPLbG8dHXfOu9szlwmp19pywqg3O
         uXXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xLs25MUrHfEQBlSXrEckGxMDLAphsoR7awGq3XsdOgQ=;
        b=s69mBAFY+zbnPnnHP5PAiixzK6UdKJyWS20tFTI7Ud4AzuCnaDrJgnWWhMqaJciKQG
         2sgl22ZwUXxUFypDC0tqAbVV4XYD1Uas46FN2GAYnWSai9tMxHkKyWrDzpOtIyzmjZIV
         aSBdM1C74oMjlPsQbuM9atnolFMJOjxqk8hHCfms2yHX6MGcR6tqEJhLFeKSkz0It17z
         yHtb3jnwZxrTIGS1T2j2Yi26j9L26nI8h3fZpsGzWXiLSMPAlc+R/rKToDP+B//Msa0a
         in3739x06T4Deq7MtDmAH2i1XtQ/v1Nyhqotih4HJmqZbVEx6fb5Vl0V3xj0hycOJUun
         ZDnw==
X-Gm-Message-State: AOAM5308ksV2S32JVI4j2PetKBEn0MqRJ2EXnpn/DBn422MFJSIUIhbI
	KtbePL3y24NQ9g306MT7V78=
X-Google-Smtp-Source: ABdhPJzvvGak8scbcnVBUIerIldlOHSkSKXjzxEZmDTo7dAGDsVJIRu643ki2TzwhspPjrdjVN0/OQ==
X-Received: by 2002:ac2:58dc:: with SMTP id u28mr2242814lfo.332.1610462063629;
        Tue, 12 Jan 2021 06:34:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7806:: with SMTP id t6ls594240ljc.8.gmail; Tue, 12 Jan
 2021 06:34:22 -0800 (PST)
X-Received: by 2002:a2e:a58f:: with SMTP id m15mr2169747ljp.214.1610462062360;
        Tue, 12 Jan 2021 06:34:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610462062; cv=none;
        d=google.com; s=arc-20160816;
        b=vP926te/xkD7AzYVktLaw+bkqknHpRWyd1THuQwThHsMOlvWa6vJQhfdimlOGkNNKf
         eyyZ8o+pXjqwlJbYHyEZYmKM9ZOkKj9MHBtn4twjtuXGHSOqPGMA9IhGUEYqztbGAmpD
         OqGdJZ4ddlXdUoUgDWrTlBOfmOFK9ZhBUM7iOEMy1H96S4xNQ2kun/s48rhdSCg3FpBv
         BBB4ApicIS9X8OCUfuIjuI8OUxMvzE7LZ9rfFQdQjre3fjfimNntrOc1cWmtmQ7LAuNI
         5CoVmnCA+ZXM7seFzXJ4iKO6qvvu9yGXkcZzc723LJCx1OvTb4FeoWpun9CodYgUD3RA
         fBUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=U744HxyOHZ4bYG3Cc/mr37WoBXh+B0nSwCGfLK9zJn0=;
        b=i/LtG+8UwUSOVfyBChL06+C8tiinQjLgrmDrLcSP1M9UxJe/UZ1xeGUKBaitlIPrB1
         2QOJAG/cfnBlpJ4gWv/+b7nCKsZZs/TbDQPv1ZpHtVWnRxqL5oCqCgqfTsFCwykN/XiF
         xA5rd92cxm6lNKy7kvl9cLYbW1zZWduy+/WX+dTwalRa6boKY+k/VEzxjrHxmNI3vfXe
         AyeuG5PgRWmvAZoS87yuhbjucWxkrPDhsvZSgInKKaLJKEbVLJqSdGsBFboDyzrzuq7Z
         tx5worWDyFJbYs2P0UR64YlRaMBzBJhBLO2WTjCthql64cei6HuESVDRZDFBZSviuNVx
         znqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p7sCAvlU;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id d3si162996ljj.4.2021.01.12.06.34.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 06:34:22 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id w5so2695048wrm.11
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 06:34:22 -0800 (PST)
X-Received: by 2002:a5d:6204:: with SMTP id y4mr4678555wru.48.1610462061876;
        Tue, 12 Jan 2021 06:34:21 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id u10sm4120446wmd.43.2021.01.12.06.34.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Jan 2021 06:34:20 -0800 (PST)
Date: Tue, 12 Jan 2021 15:34:15 +0100
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
Subject: Re: [PATCH 11/11] kasan: add proper page allocator tests
Message-ID: <X/2zZ1kuRDVvtq/T@elver.google.com>
References: <cover.1609871239.git.andreyknvl@google.com>
 <15ca1976b26aa9edcec4a9d0f3b73f5b6536e5d0.1609871239.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <15ca1976b26aa9edcec4a9d0f3b73f5b6536e5d0.1609871239.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=p7sCAvlU;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as
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
> The currently existing page allocator tests rely on kmalloc fallback
> with large sizes that is only present for SLUB. Add proper tests that
> use alloc/free_pages().
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Ia173d5a1b215fe6b2548d814ef0f4433cf983570

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  lib/test_kasan.c | 54 +++++++++++++++++++++++++++++++++++++++++++-----
>  1 file changed, 49 insertions(+), 5 deletions(-)
> 
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 6261521e57ad..24798c034d05 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -128,6 +128,12 @@ static void kmalloc_node_oob_right(struct kunit *test)
>  	kfree(ptr);
>  }
>  
> +/*
> + * These kmalloc_pagealloc_* tests try allocating a memory chunk that doesn't
> + * fit into a slab cache and therefore is allocated via the page allocator
> + * fallback. Since this kind of fallback is only implemented for SLUB, these
> + * tests are limited to that allocator.
> + */
>  static void kmalloc_pagealloc_oob_right(struct kunit *test)
>  {
>  	char *ptr;
> @@ -138,14 +144,11 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
>  		return;
>  	}
>  
> -	/*
> -	 * Allocate a chunk that does not fit into a SLUB cache to trigger
> -	 * the page allocator fallback.
> -	 */
>  	ptr = kmalloc(size, GFP_KERNEL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>  
>  	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + OOB_TAG_OFF] = 0);
> +
>  	kfree(ptr);
>  }
>  
> @@ -161,8 +164,8 @@ static void kmalloc_pagealloc_uaf(struct kunit *test)
>  
>  	ptr = kmalloc(size, GFP_KERNEL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> -
>  	kfree(ptr);
> +
>  	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = 0);
>  }
>  
> @@ -182,6 +185,45 @@ static void kmalloc_pagealloc_invalid_free(struct kunit *test)
>  	KUNIT_EXPECT_KASAN_FAIL(test, kfree(ptr + 1));
>  }
>  
> +static void pagealloc_oob_right(struct kunit *test)
> +{
> +	char *ptr;
> +	struct page *pages;
> +	size_t order = 4;
> +	size_t size = (1UL << (PAGE_SHIFT + order));
> +
> +	/*
> +	 * With generic KASAN page allocations have no redzones, thus
> +	 * out-of-bounds detection is not guaranteed.
> +	 * See https://bugzilla.kernel.org/show_bug.cgi?id=210503.
> +	 */
> +	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> +		kunit_info(test, "skipping, CONFIG_KASAN_GENERIC enabled");
> +		return;
> +	}
> +
> +	pages = alloc_pages(GFP_KERNEL, order);
> +	ptr = page_address(pages);
> +	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +
> +	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
> +	free_pages((unsigned long)ptr, order);
> +}
> +
> +static void pagealloc_uaf(struct kunit *test)
> +{
> +	char *ptr;
> +	struct page *pages;
> +	size_t order = 4;
> +
> +	pages = alloc_pages(GFP_KERNEL, order);
> +	ptr = page_address(pages);
> +	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +	free_pages((unsigned long)ptr, order);
> +
> +	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = 0);
> +}
> +
>  static void kmalloc_large_oob_right(struct kunit *test)
>  {
>  	char *ptr;
> @@ -933,6 +975,8 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>  	KUNIT_CASE(kmalloc_pagealloc_oob_right),
>  	KUNIT_CASE(kmalloc_pagealloc_uaf),
>  	KUNIT_CASE(kmalloc_pagealloc_invalid_free),
> +	KUNIT_CASE(pagealloc_oob_right),
> +	KUNIT_CASE(pagealloc_uaf),
>  	KUNIT_CASE(kmalloc_large_oob_right),
>  	KUNIT_CASE(kmalloc_oob_krealloc_more),
>  	KUNIT_CASE(kmalloc_oob_krealloc_less),
> -- 
> 2.29.2.729.g45daf8777d-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/X/2zZ1kuRDVvtq/T%40elver.google.com.
