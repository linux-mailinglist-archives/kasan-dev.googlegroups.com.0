Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPMET2GQMGQEDWYCTLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id B650E464F63
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Dec 2021 15:10:05 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id k32-20020a0565123da000b0041643c6a467sf9567198lfv.5
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Dec 2021 06:10:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638367805; cv=pass;
        d=google.com; s=arc-20160816;
        b=IIMNpBFtfIya1tQYq0ebn06KdaRrkKOE9i054rU/92WE35KGCJi4i8uJamXYglLbPE
         owYXGTsmFe08WZ7CnFLqg/D88wJ4dezzr2alZs9TRUXrKJzY0ZrKFfEdEYvxJqO6DnAe
         fOdf33cnEsoItqrfMkLZSCh28P/trn5YPJ4cF5WBJlZVOdNj4f0bd5lIfyJ6bzETCqT9
         NkoF4tUZx9xYR1huF3k09EY2pOLyT9JOSUdqBh0oKGg1YWq/pIdR2IUTg/SuKFRYXtYE
         qtCaxmV0xzezwYVeKayAhJLD5UXWHpmpOvekV3Z4abcLWWOs65NQciGbvLpj55EPphqI
         1JmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=TLOU3gSrkFfnn1OoeK4wjpl8xkhPD0MxQwsYPBMwQSo=;
        b=gc0OIeW6cjbSJk8kAFpyKZHxwfOLdotNh9drTui4PRn/XbhvuiKfMPcIDJAH8EHgp1
         qN2gifzrtYJZH2t9YKS2wNmFqsr0KAzxrrj6H+a0iAwUgV7UNG5Q63zBhmQ8yOhDScxq
         yNhBQlZU38BSMQFGgzHK5c4MO34oy2npWOUXrZIu4eDJB0dj1q1hdKkRv6ORy02a2ke7
         kQvOMMazr8dLLOr3AgXdJRLzPOVetg+p9jt2aiUMWfmtXylWndVic7XxO7hwjibvdXAf
         egjEBGwt19fxgwuG1vSInynx0KabcPOcIFMANvOoqCIstHWkTFECspJHjN9xDdLn2/Ij
         jffQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KUnaUN2P;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=TLOU3gSrkFfnn1OoeK4wjpl8xkhPD0MxQwsYPBMwQSo=;
        b=sqsTYkif3UjCtsF6OeFcNwp63sCarjdqgJ9+L4EXPijW+DSFRSR9kKd2LNa9i02CF+
         Zmmz1J05buZoXOXSkPRiGzOUeD4mRaKz46VGJ1AVkEvEVzfr4q4AOKVowDQB+x/cxVMg
         8VSaP0XxAFS5Tz5ytxsNrweXZfoz1khhISL1DvoEBq8c0CLgDlR4KpnFXJ/NxknoYRw9
         2FzP7W+IlSEz1RsyhttvAG3Sv01a6zK7WX57L+tSiWzvVmisVs+1xIFJxZHjfdiO2sOq
         oirOgo62JprvfhK8CRnWZatfrkfL/34RVMyeu09rUjC8FQ1zcwQmg/VgZB5Nh1oXUodU
         sl+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TLOU3gSrkFfnn1OoeK4wjpl8xkhPD0MxQwsYPBMwQSo=;
        b=mcfKmnIYLl/4Zg5egIKgI0SNGv/l2buH7v9FqackgemEmSmfntR2bBKEY0pN+H2JVA
         +Y078//X4Wsitm5DI9GfPaVCZMjJuYhcJs7hnTBpmizX8uElwkGYwT/d58bV6eYkZNO/
         OTFkrcgGYrCIkmIFWiwV0BD9iiP46SHJqS4m/9KQy0PLT7Q4pSuIikWnljJqPXHsTOqb
         9+wocxK3JL19RxlkmI+RP58sst3NsyW6ecVioweMbTGvhVCAxkjXkU1s70Kg5DdAnCNF
         VJ5SQp2sMTFWSyyupictjmg8lPZdD8oyGrsrW+GNGpOkzmkOAXlVBmWkTvz+DyFWfsUC
         +rfg==
X-Gm-Message-State: AOAM533zIdm0v46SnU4rAzkB+6zegONO83Ox5UVwLNRzRUgxHdlfEKbm
	wI84egzKQZBgSS2BkFj3Wh8=
X-Google-Smtp-Source: ABdhPJxEFGWHrN++U2CDgTE8xLuJnOmjhxKUgveh7DiWdkl2IcMUCp+Mk7zkKjxcaZILjX/HVx/HTA==
X-Received: by 2002:a05:6512:1087:: with SMTP id j7mr6114092lfg.191.1638367805279;
        Wed, 01 Dec 2021 06:10:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls847761lfu.0.gmail; Wed, 01
 Dec 2021 06:10:04 -0800 (PST)
X-Received: by 2002:a05:6512:1592:: with SMTP id bp18mr5962141lfb.363.1638367804157;
        Wed, 01 Dec 2021 06:10:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638367804; cv=none;
        d=google.com; s=arc-20160816;
        b=QmCX3lWr5BKA1hliatKPAk8fypUHEoUzQ4hxezIbn2AeBcoLPFLSlQFQLTrxBHP2Vf
         t0p1QnkIUUHGknCjpkS50vLlC7kuUk4eZFa71081k8BgnPKw09OZf68+sZ4x59Nc1gvC
         /kf3927uqXlowdJD/pVmve7fUC8SWop3/5j38LV5DDeso/pVa8//uByuEnMwjK6kF917
         4urYrwyq+rNROcdB4rewF5OwBBuEw00IWo6vruL1F1dj3BQJW2PqcqHHnIIXlf4DLKqv
         XAmS3IKgo9fV3V1+KrdRCq6+o9oW3tMJjeAgwdqyVuWV2WtL7dYzz0j7IJgLZmaVnS8P
         YQBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=aUvgIVEScJ2chwYi4PLdpPCh/e6Qof2JA3Rw4wY6NeM=;
        b=ZBrocHhdPJ6nyet1eeABarabFSxAgPA/pPw0LBQ3CG24hf4cz/2k7iYfPG6BVsCUVL
         OG9zJpjIQqkdX5jhOIgTPXUQtjcfB/LNexdPcQgLCKewkVDHuTIuIUVZB+rAx37NM+hc
         3Ykzgwr5krn+DMUN3esD7bFoxtyQqHybYgnoSPw2C/Oi+4i18/MrWG1UW5aXZ+7XO90n
         v6nfaP9CKGxhLxEp31HckzJ0EONDywlzXl4kDwGb6NBK/68ZuXgC4GcgrVTXtneZ8XFP
         QiNljdBH1crjE69GTJE6rWSHIF0Hx+RqIieOTQFOQFNr2hx3LDwvuHz0fAgzVfHU3LYe
         qR4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KUnaUN2P;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id h12si1836053lfv.4.2021.12.01.06.10.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Dec 2021 06:10:04 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id d24so52654916wra.0
        for <kasan-dev@googlegroups.com>; Wed, 01 Dec 2021 06:10:04 -0800 (PST)
X-Received: by 2002:a5d:59ab:: with SMTP id p11mr7011310wrr.340.1638367803580;
        Wed, 01 Dec 2021 06:10:03 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:95ad:1401:cf07:6d1a])
        by smtp.gmail.com with ESMTPSA id k8sm19121353wrn.91.2021.12.01.06.10.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 01 Dec 2021 06:10:02 -0800 (PST)
Date: Wed, 1 Dec 2021 15:09:56 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 04/31] kasan, page_alloc: simplify kasan_poison_pages
 call site
Message-ID: <YaeCNIyblUAk5mmI@elver.google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
 <b28f30ed5d662439fd2354b7a05e4d58a2889e5f.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <b28f30ed5d662439fd2354b7a05e4d58a2889e5f.1638308023.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=KUnaUN2P;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as
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

On Tue, Nov 30, 2021 at 10:39PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Simplify the code around calling kasan_poison_pages() in
> free_pages_prepare().
> 
> Reording kasan_poison_pages() and kernel_init_free_pages() is OK,
> since kernel_init_free_pages() can handle poisoned memory.

Why did they have to be reordered?

> This patch does no functional changes besides reordering the calls.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  mm/page_alloc.c | 18 +++++-------------
>  1 file changed, 5 insertions(+), 13 deletions(-)
> 
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index 3f3ea41f8c64..0673db27dd12 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -1289,6 +1289,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
>  {
>  	int bad = 0;
>  	bool skip_kasan_poison = should_skip_kasan_poison(page, fpi_flags);

skip_kasan_poison is only used once now, so you could remove the
variable -- unless later code will use it in more than once place again.

> +	bool init = want_init_on_free();
>  
>  	VM_BUG_ON_PAGE(PageTail(page), page);
>  
> @@ -1359,19 +1360,10 @@ static __always_inline bool free_pages_prepare(struct page *page,
>  	 * With hardware tag-based KASAN, memory tags must be set before the
>  	 * page becomes unavailable via debug_pagealloc or arch_free_page.
>  	 */
> -	if (kasan_has_integrated_init()) {
> -		bool init = want_init_on_free();
> -
> -		if (!skip_kasan_poison)
> -			kasan_poison_pages(page, order, init);
> -	} else {
> -		bool init = want_init_on_free();
> -
> -		if (init)
> -			kernel_init_free_pages(page, 1 << order);
> -		if (!skip_kasan_poison)
> -			kasan_poison_pages(page, order, init);
> -	}
> +	if (!skip_kasan_poison)
> +		kasan_poison_pages(page, order, init);
> +	if (init && !kasan_has_integrated_init())
> +		kernel_init_free_pages(page, 1 << order);
>  
>  	/*
>  	 * arch_free_page() can make the page's contents inaccessible.  s390
> -- 
> 2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YaeCNIyblUAk5mmI%40elver.google.com.
