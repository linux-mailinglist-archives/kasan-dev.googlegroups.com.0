Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7MI42AAMGQELD2ULFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B11C30C6AA
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 17:57:34 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id x13sf9913277edi.7
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 08:57:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612285054; cv=pass;
        d=google.com; s=arc-20160816;
        b=GLHIuCGqhD4/C14bn9XMO1GDTAe9Sps05ft+UGinZfwWlVMt8GYZtJgWC8VpieCr9T
         TKoYxhBJwU+2LlYrTn7yd9kWG3jVDSb1ai3/WSN/e/qGbeZXaihLxbGIOE17Z85EOdrF
         CzooQPCO0NcHlQDzkKNA50ZY1p3OHjyXfU2KF+3vO6ed4ae6keVkM+GtZSJh4RjphHmy
         UT5jUOqMe0cb+VsXpIoayPb4cRHJR23/VLi26FE5s5XfGoFAHoGD8iCJ12Fnkmcil4Yn
         mR/ZIB70dhpiK0GE0dCUxchLkhV18VfZZGbg0BoTHuzyThDAd6WDeOAhUlhFZHJweAO9
         03BQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=kYvy7pqvPl13xOZ+44yIN3ptmhW6Cep6m04ZQP977os=;
        b=Fu/+wFlPT9g5J8scLIIBUK/0LO1kk450yn9qufUOORhcP1Z9ZtwcRJnGcAbYgpyyE8
         gdqYFAVFgwQFzp3PZmmh9gZ5kK/U18r46CaLBUR4PZ1t197tfNCRnSqDfuRFDcgfL23C
         DGpVc49L8oEMCknjclh16mV8I5OBH2ooBSyJbfAaG+qGzXWOC3wTDbSGFfAhGLLO4xbv
         sKeQoVpbRl7FqdatQa1uSwmM/JseG6Ha27N+UTA+Te5wYL445ogdjTPsgTrWthjAsOk5
         1bKLrlGzWVcjLunGCiMB5axnOgb0ev7ihA3/LajPsVwqLrpDgdirO2uml60uP/goH0jH
         ENGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=emCtWBCS;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=kYvy7pqvPl13xOZ+44yIN3ptmhW6Cep6m04ZQP977os=;
        b=pKVZCYhcncy0veRn5C37IiE65iHoaIRzb0LsMVNi/GD4aPEPt3HNH+cyEkLqK2I3XS
         /TMPZJGoj0wBEPL4q4wzK+KEPI0TicYSyrgufpjfOEeU8S40esvg4RgnWJDbbv1J6Z3m
         V5TD0kQE3P3P9tdXFLc4YCwSPU78bXnr2BeXmiKMGf1OEMlkqLYBFGwoxtJmH7dTFl1L
         TnJToU+zPZChgCQBoMwJC06i6Nm2lWMAAGRjxwhvvonHGXxW3fiDxls8HnVw2+ztmFiT
         0EemFQz9P8YJ4Q+idcKRDrpz1HW5L3M9vP7itbSI5hg9ziO4j5GgOnlDDMjbCez2WRIS
         +4IQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kYvy7pqvPl13xOZ+44yIN3ptmhW6Cep6m04ZQP977os=;
        b=qKnvDcr3edmdzt+pO7YBOvxtdL+3pOB2v5E9o8jUZ3tW70p1BcK77BlAYtxAy4o1X4
         0xuCamymQmngjqQgccLxppj8nuVBzBHtvUPYFM9q2vIfNVAsSsqgH8r49XPEjYehOCjz
         8pYsAXGdkLbmeG6klDsW5Ggrk6bNBssMOGm7u0E0Oot6QV3XfSrjfv/xfgH/tzJaOrkv
         /HGVD33ai235hSNPuKe1cRjvuFHzZkOlCImEd7NnZDWJorIKUEQmwHF9TlQKRVvdPF+q
         PHLvIIVCj/J6N6zifGtVjh8tdttKbvUgKJVw3JZe1HF+is4kcHL4DdtMKS7c/QErmR8V
         4DOg==
X-Gm-Message-State: AOAM530wtSCob33JY4F1F5b1sOAXkUp6FKh27NgBJ4LrzkZQErhthMCS
	riSh66aeHr4AH9K2X62HDnc=
X-Google-Smtp-Source: ABdhPJxz5aLiYWQ5UuNrgbqA7mKS7ya2e5CQVq+b+Qmkv5bET2p567Ue1VoO8kyAaN6iwF7GGptJQQ==
X-Received: by 2002:a17:907:948d:: with SMTP id dm13mr22784939ejc.545.1612285053948;
        Tue, 02 Feb 2021 08:57:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c159:: with SMTP id r25ls760231edp.1.gmail; Tue, 02 Feb
 2021 08:57:33 -0800 (PST)
X-Received: by 2002:a05:6402:5107:: with SMTP id m7mr24315103edd.52.1612285052952;
        Tue, 02 Feb 2021 08:57:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612285052; cv=none;
        d=google.com; s=arc-20160816;
        b=G+Lt4F1VZBPdi+G67M/Zj+c9TAOXVYhWQ1aj5qzYqEX/KUgSIFlWYO6YlLttl+3rLJ
         /bUJpqM3kkCDtrGzWrfJAFjkCslIT4MqASmyN8it5IeUoQjMy7vFusVA4gLxzBhBldxL
         cSu5glPIaJ3Kdi8cq3WC+tfFZhqHm5nOsMlvAmc5B52pSRjKyNhkSzKHqnnDq0++LGbD
         WrQkJjewFP3ZlbH0ZAVsudtJjeRyGPeAlrcO2GPhlKRV2lMOBh9mU/UA+AVvqGoSHI6Y
         Kx3Zhr+SDjCNaDph6DEReWtPHVSCznHq8pV18DgMgsEjr7p/1+Yv+y8S5fd0LBkUgMLr
         9JsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=lO7tj/Femn1+wEijzb4UKh0PnLxDA74JJSIXBjPCjcg=;
        b=PtLbjvB1dbF6F/rMJgGqCAquObXNJ8d7krkVudaMwK2BeW6IB8+0j+Wg4uXz6f/uY8
         rAvnBj25I1Lkx/cE2OLxTkI9wZnoqdf151t6/qdm6uQEAW5GAy2Byy8u53nqpGYXOmnx
         u7Li+o6pCWLqcV5lj0Url5ieafRuNH893tpLhUHF2deSszF3Vl/XV4zjTJTCGDkgK1Ei
         9oB9O2HmtrsZ4ms379hy8pPP8Z9v/mfu77S2zzzd2W23k06Yo6HA6a4YvpfXGqVSD3og
         1yORHL0pO8N9WPnQHFYNlrRFnBwD6mEFKfKi2NCU84m9fDYrJX9lkc/gTMpy/b/AbYSX
         cvrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=emCtWBCS;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id ce26si560432edb.2.2021.02.02.08.57.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Feb 2021 08:57:32 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id m2so3146370wmm.1
        for <kasan-dev@googlegroups.com>; Tue, 02 Feb 2021 08:57:32 -0800 (PST)
X-Received: by 2002:a1c:5608:: with SMTP id k8mr4448012wmb.91.1612285052531;
        Tue, 02 Feb 2021 08:57:32 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id j4sm32514546wru.20.2021.02.02.08.57.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Feb 2021 08:57:31 -0800 (PST)
Date: Tue, 2 Feb 2021 17:57:25 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 03/12] kasan: optimize large kmalloc poisoning
Message-ID: <YBmEdf4T5/0tpalT@elver.google.com>
References: <cover.1612208222.git.andreyknvl@google.com>
 <8fdbf86842f4eaf2458ecd23d0844058dbc2c7a2.1612208222.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8fdbf86842f4eaf2458ecd23d0844058dbc2c7a2.1612208222.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=emCtWBCS;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as
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

On Mon, Feb 01, 2021 at 08:43PM +0100, Andrey Konovalov wrote:
> Similarly to kasan_kmalloc(), kasan_kmalloc_large() doesn't need
> to unpoison the object as it as already unpoisoned by alloc_pages()
> (or by ksize() for krealloc()).
> 
> This patch changes kasan_kmalloc_large() to only poison the redzone.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/common.c | 20 +++++++++++++++-----
>  1 file changed, 15 insertions(+), 5 deletions(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 128cb330ca73..a7eb553c8e91 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -494,7 +494,6 @@ EXPORT_SYMBOL(__kasan_kmalloc);
>  void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
>  						gfp_t flags)
>  {
> -	struct page *page;
>  	unsigned long redzone_start;
>  	unsigned long redzone_end;
>  
> @@ -504,12 +503,23 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
>  	if (unlikely(ptr == NULL))
>  		return NULL;
>  
> -	page = virt_to_page(ptr);
> +	/*
> +	 * The object has already been unpoisoned by kasan_alloc_pages() for
> +	 * alloc_pages() or by ksize() for krealloc().
> +	 */
> +
> +	/*
> +	 * The redzone has byte-level precision for the generic mode.
> +	 * Partially poison the last object granule to cover the unaligned
> +	 * part of the redzone.
> +	 */
> +	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +		kasan_poison_last_granule(ptr, size);
> +
> +	/* Poison the aligned part of the redzone. */
>  	redzone_start = round_up((unsigned long)(ptr + size),
>  				KASAN_GRANULE_SIZE);
> -	redzone_end = (unsigned long)ptr + page_size(page);
> -
> -	kasan_unpoison(ptr, size);
> +	redzone_end = (unsigned long)ptr + page_size(virt_to_page(ptr));
>  	kasan_poison((void *)redzone_start, redzone_end - redzone_start,
>  		     KASAN_PAGE_REDZONE);
>  
> -- 
> 2.30.0.365.g02bc693789-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YBmEdf4T5/0tpalT%40elver.google.com.
