Return-Path: <kasan-dev+bncBCT4XGV33UIBBJUHROBAMGQEJUPK7QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id A48C232F6CC
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Mar 2021 00:49:59 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id e15sf2471514pjg.6
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 15:49:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614988198; cv=pass;
        d=google.com; s=arc-20160816;
        b=TtUS4sMF9woba9LsfxNWnJT/qe+SyYjkBerIlaGZ495wVu5rWK13paLr+84BbCCSXe
         Bo+62Gg336R3UJrTuhlfMA09kwe4qlq2QuRFYvwL3B7TWnJVzQ6qOi6SOcmrFx7SXGam
         /3K5YqZKcH/27B0upQ2yIX+ieNpr+z3o0paK+SoZRpv6w/fqM/cniASfpYlT6ghTPhjn
         mVWQ1IlT43CouiyJezSQStRBlkDsRRXTmELSUisy71Jnj/x55nhsIkf5So+XOIgQh6+p
         OD0wqZsP/Uqrn5H1gFDZlVP8YMhaCjQ0CNDR4fIkFnv8SOugmob+YZy12w8XDrsjyVR/
         0dqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=mFYPbz/c91flVd04ARi5OcBLaFsGzdqxqEYbaq1x80w=;
        b=iBfKjgL+FWCOcIx9ZSnryfZI9RWyMtETu/jqJTwDSdOutiVp5fX/jrjodoJ4HqTVKe
         1dCkl5D74HsLgIvO67cVH6lRfQ7M0WMv9r6mzHZFjRbZlEild6PGEudVua+vDeA6Yihu
         seeJI0+GMOmR3VNlX5qn59wQLbFD8w2797lqfkh6b85K4dXM2eFrb5AIIeclJq8xmUVk
         jhuQTlq3GSWbAgncHTJGTU01PYLfdGftCbiToz6vn35g3maNJJVAUM/Xhzlbrvut2TeW
         sYk7oCSoyjbi+W5dOZKzcwhODj2MDwmGHu4YnZdL/SCTcVAQ9GscLAn20eh46F9kmnmT
         rOmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=2J4OjFKK;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mFYPbz/c91flVd04ARi5OcBLaFsGzdqxqEYbaq1x80w=;
        b=lw+ZQ2Bx/HMidwJRv7NOZgUmP6GK+vYGUZiKi970dOKLgnDKIWIj4+cp3YeBiQypwv
         OqrIYHH9YbLoyLUDdszATTHohwmJFypmmzbdcDrQT51RqHwSKYB4JR6rRAuxm/hu2s3D
         M83pKGZf1DcsANxgID8N00IE5GzJm+MdxzgXcQvaKmTh6WkT9mR7HpVTcl5UIhaR/e3I
         m2x3pbT0GC9K7Hcuvl6YLWHfmZJvUgeZFWmQapW0oN0IM7QTZLSz2b/1u48eG4uiOlm4
         bw3XSPytdtX7dAJ2jjA8jnHdcE8VxhAh/dnXs4gGdyR/jn9rdbqyHijpm+tFJbSlkSli
         OacQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mFYPbz/c91flVd04ARi5OcBLaFsGzdqxqEYbaq1x80w=;
        b=EDM7t0MoBu+p3Z+hSgnVXqeJULpSmzDFfdCa+mdmQOZOTZ4QOdCTjymw6vz2OWWj7O
         MnbYTa44OHtlHmKd5CrOyfwFF6nQMsSCLOmoKZDyrVqTpjREnGV6i818uoUV/aFc+trB
         eh2Hyp/Fwd1T251GqQsFceU0l+TRe979xN/STFyIMPwqmo3K/y+R8CLaRvpAOD6XBAZw
         2A/8xjqGqtaDZVNJUFiAEm3nHnf14DA7BjsvIXd5iBCMm4tpE34ACTif/L3SpFVJjHvg
         k0AroZuY29n9YaRjRufFwnIWyiZVnFwC35CF50x+DwIjehN1TEDX7ywFzWIhp+S9Nt+3
         sLUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532I0HTFThNIbyH+y90VXz8mPL60V0LeeGQahRuw3kyXhROshyb7
	w/P9WLZwwG/+o7HAfqJoTbw=
X-Google-Smtp-Source: ABdhPJzV3sY5Wpa5xVl2dZAxq7G4ZbnI1mYFUlNf9g+U3RfxxZeAoa23CWqmwGxM/qMphX5t9a8tYQ==
X-Received: by 2002:a17:90b:1c03:: with SMTP id oc3mr13142956pjb.124.1614988198230;
        Fri, 05 Mar 2021 15:49:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:5302:: with SMTP id m2ls2725528pgq.5.gmail; Fri, 05 Mar
 2021 15:49:57 -0800 (PST)
X-Received: by 2002:aa7:8d0d:0:b029:1d7:3c52:e1f6 with SMTP id j13-20020aa78d0d0000b02901d73c52e1f6mr11550581pfe.39.1614988197656;
        Fri, 05 Mar 2021 15:49:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614988197; cv=none;
        d=google.com; s=arc-20160816;
        b=piGJiYjWkAbUXehbjkxOrg4cnTE36Gmk1UVso/jKAI6jOhz84vzbOIEW8ZnkyieuL0
         8pY9V102AZHnU+JE5PwlaTHkk75XUGbQvr/Crgvftx59FQRwkm2Mj1dbVb9QmD5G/66X
         o0yQEwVwYavopeFWrvNtHJ+uooUfMW6pMTWoAIQjKDK/iRK956zFYensHNOYf19EsSaF
         iT5X5licyZbkr/DNgIQsONQxWJ0N3TWcLI5SVRW+habsagAQqF1e2odKXiNHRZV5V1ko
         bZ8bKSvJzcXEbTvXfgkyqrKTBI/vsm9Z/r7E4jEBoPwSFH6znI8ix3NWmteHu8mibmw0
         fZfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=3FXaO5u6cXUaj0MT4373b5RoN8HOUa09U+Tw/2T5F5c=;
        b=wygLQ8D/9UuJaT1a67s/l6YJUyqLa0XeRBNxgfS4Phtovwd2YDJhCC3Abp+b6yKCqt
         cbEzWnysSXVP5//wu3zAiip5h7t3DJE52T3XbuJljdqvLHBc0m0DNKi8LknYlgasXGjG
         YX/xn8RnaEJa2JAt4yBF7rqyVvX3FWJLF78hAEWUpXPys+eez9cB18zaafEqRYKaBlBY
         4clWvm5TVg70mRNLhms2MZK/99moSok4vIJXbQ/TxA0DMpRrA2sy76HSRBgAO7bm+/2G
         N3p6ddi0Rp/FBpfuhDdFh/iATasQXb8yZcqLW93PfjIU1nbyCmomCmbfWlLTNf8C0PSI
         m/Cg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=2J4OjFKK;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r23si214749pfr.6.2021.03.05.15.49.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Mar 2021 15:49:57 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id A66BD65073;
	Fri,  5 Mar 2021 23:49:56 +0000 (UTC)
Date: Fri, 5 Mar 2021 15:49:56 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Alexander Potapenko <glider@google.com>, Catalin Marinas
 <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, Vincenzo
 Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>,
 Peter Collingbourne <pcc@google.com>, Evgenii Stepanov
 <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, Kevin
 Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, stable@vger.kernel.org
Subject: Re: [PATCH v2] kasan, mm: fix crash with HW_TAGS and
 DEBUG_PAGEALLOC
Message-Id: <20210305154956.3bbfcedab3f549b708d5e2fa@linux-foundation.org>
In-Reply-To: <24cd7db274090f0e5bc3adcdc7399243668e3171.1614987311.git.andreyknvl@google.com>
References: <24cd7db274090f0e5bc3adcdc7399243668e3171.1614987311.git.andreyknvl@google.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=2J4OjFKK;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Sat,  6 Mar 2021 00:36:33 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:

> Currently, kasan_free_nondeferred_pages()->kasan_free_pages() is called
> after debug_pagealloc_unmap_pages(). This causes a crash when
> debug_pagealloc is enabled, as HW_TAGS KASAN can't set tags on an
> unmapped page.
> 
> This patch puts kasan_free_nondeferred_pages() before
> debug_pagealloc_unmap_pages() and arch_free_page(), which can also make
> the page unavailable.
> 
> ...
>
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -1304,6 +1304,12 @@ static __always_inline bool free_pages_prepare(struct page *page,
>  
>  	kernel_poison_pages(page, 1 << order);
>  
> +	/*
> +	 * With hardware tag-based KASAN, memory tags must be set before the
> +	 * page becomes unavailable via debug_pagealloc or arch_free_page.
> +	 */
> +	kasan_free_nondeferred_pages(page, order, fpi_flags);
> +
>  	/*
>  	 * arch_free_page() can make the page's contents inaccessible.  s390
>  	 * does this.  So nothing which can access the page's contents should
> @@ -1313,8 +1319,6 @@ static __always_inline bool free_pages_prepare(struct page *page,
>  
>  	debug_pagealloc_unmap_pages(page, 1 << order);
>  
> -	kasan_free_nondeferred_pages(page, order, fpi_flags);
> -
>  	return true;
>  }

kasan_free_nondeferred_pages() has only two args in current mainline.

I fixed that in the obvious manner...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210305154956.3bbfcedab3f549b708d5e2fa%40linux-foundation.org.
