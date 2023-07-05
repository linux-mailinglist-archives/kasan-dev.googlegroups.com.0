Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPOOSWSQMGQEOYCW2NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id EE3DB748465
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Jul 2023 14:51:10 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-3fbd8cc134asf20675865e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Jul 2023 05:51:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688561470; cv=pass;
        d=google.com; s=arc-20160816;
        b=QDZOgjpMC44UHZfUBbNIk64mif2qcrOSwJ1KrpdmtrOjwOPUehqsuWd9zLLT2KXjU0
         2tNiW1/qbuteFDxqCTqws2b/cU97CzasD8nMP0bq43jXc6ktAKCKmwb3gcx2Vkao0pyq
         WD3lNf6Hwtlz68W1JbdGhSGq0U4mrR1iDnV9p+Zl/AE73dBBXLkAZ5ylKgCfzWeo/+83
         TrNh10mtP/NmxaxveKj7LlkDpp9O95L6ERi6XL8VYgr4SRZkQt5z07w996F12PVCvclc
         usIunCdOqgAivEEU6EE8aE0qJSiy8GzX9eicRSxezNAGubH9ib6+1x6AdirSsHXpg2yf
         hEfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Quo1dCHWBsq7QDklrLPHMvB64tRuJfY4xxunghoq0fg=;
        fh=0rOTJoc7pmOk2dJBfSHYn2iw94UqAvjJHzdMKBXanA8=;
        b=Rsw4yof8hGl+w+caN0RNupfB7BlmW8ub146WLAdD/E58TnMbTiEgiw1h8xCREkkrhQ
         kDaX1No6P+Z3O6Cf1tqElw8MY8O5z4zqPBqZQXbKL8Vho8jJ+zY+/Sl9yewfr1heMElm
         I37C52yc6QDTQzfklWhO93HUcid00HrWrD4ozJTq/vBAf52rRYL9aZ1KD1F4hxXa2i0P
         bI6Hx1C7Zc6q6YxShgcv2W/qWEM1VujDvGS7pdN3clyO9ahev/umL1Iqvei35NZCAqiT
         RRSpnNuPt8ZTPYlOwhuKFPB3Ua+CwTmUv8thhQ1EgSN5WVsgHkqA682Q5Ydv7JPMMjtG
         jdvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=6+ZPkY1y;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688561470; x=1691153470;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Quo1dCHWBsq7QDklrLPHMvB64tRuJfY4xxunghoq0fg=;
        b=eNZMG+j17LMx3xlSJiS6oRyTMk7bGqsAab0GDs+BAaeyZaPPkheZO1lHo2nbH6Ugx6
         Z6OKZ7XXY6m3XPeZF8kwB77qcgk1QKd1tTMIPFPMwM8qdpxyf40eDhcaNOn9zkH95MEl
         Vw6/1k2T70ZEkfR6ufiRiGZd5ZGhn1mYzHWGwA/qzm+r1OXyW4TnBJ3rZm8b9yP6nw7I
         DUB+4Q5hHaRLvQXbXnqud3qMkTFBwEThOG6qkcFTciUv+5GCW9IBWWXiS+SmFYWOiSv7
         sHmSDLCp+a74x9nWIbbYDw9PGXlZKU32FXY9RSINe4X6FzN0mH8dE0DEzmJsYE0FcShE
         o6pQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688561470; x=1691153470;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Quo1dCHWBsq7QDklrLPHMvB64tRuJfY4xxunghoq0fg=;
        b=TyrDiesTb4de7LYJ7XngzhskK4GSO4KbvDDsqZ1UUHx3Rqa584v/NIr/j6MbNhtpKi
         iMyh4t3oE+ZEdnh1Ims8tl26iD48pCuijvawre6knyn8m8SwiVn6AF7zWE4BehqH08tO
         ZSgfUDgrGQ+JMRgzHqjuf78eGkty6xhIfvMVA/azFZQkA2C+2aWX3sswQIt0YSQqQZH/
         Sl3hH9SsqpOXbTNJZE0vrw080eF0NdcuD7wCSrAw1No1s1Ui8NbRSbBnGAeQo3XeJuk2
         v14gn8k4rg1SElw2aE2P2q6Z5dmV0O6Sx81S5xFF3fwDw9hY5VQfIWsjkwbReuhYeC/Y
         o9pw==
X-Gm-Message-State: AC+VfDx5dCnOMNMBmFHS4DO2EEfiKsUl3jo/7YUaEVIulDTumzUxcSKl
	HHDV7BY2yw2Rv1ArN5mtD+B/mg==
X-Google-Smtp-Source: ACHHUZ79SpJHB0K2ClRb1kqV9aWRNadjjIz8eftFNhMR6C0Wum46rnOuILheqYZvNBSyRvHgRgVEdA==
X-Received: by 2002:a05:600c:364f:b0:3f9:b1e7:8a4b with SMTP id y15-20020a05600c364f00b003f9b1e78a4bmr13031282wmq.21.1688561469743;
        Wed, 05 Jul 2023 05:51:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c20:b0:3fa:95c3:7e99 with SMTP id
 j32-20020a05600c1c2000b003fa95c37e99ls1520645wms.2.-pod-prod-08-eu; Wed, 05
 Jul 2023 05:51:08 -0700 (PDT)
X-Received: by 2002:a05:600c:d7:b0:3f9:b972:731b with SMTP id u23-20020a05600c00d700b003f9b972731bmr13483016wmm.11.1688561467932;
        Wed, 05 Jul 2023 05:51:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688561467; cv=none;
        d=google.com; s=arc-20160816;
        b=R80hQKvRSmA3Oxl3S6wiGL7mXQn7ikuRw028YBOyhPGK7yTLIcXEQ+GEuQGsCoSIST
         kdVYi/BP9PBBxkyKZHXb2djvrvNNd+5dRgy5iElB7PG+8Nr463yga4sZrYMiW7dqeXRL
         5rrXLqcFxOuBxdoMnoqfsrq7Hx7RRz3eMUlvV4Te00dVkVLFIWgOqKPMC2Anv14F63l9
         1uaO/YzSgz6johrXp1IaRGt9WKXji+4GNc0hNKtc58TiDoJoRPjSrcOlwEZkBCZ9kimC
         FLCJ657qVW4odQXTYlj/gZdUc0QltNsPUC7BCAyS1t3ywnVEZNl843fFM0FNt7Pd9hJS
         Wa1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=noF3Ta0PVHsT1dAI560cBu0m3xEmyMOxO2GSiAJv96w=;
        fh=lVNqY5cZmiNjHmRnR8V8FaYN2aI+GZpkqY190eLuoQE=;
        b=mVdk4dU9HU+CRA4gaILHP0dOgaY9HYcvnksxt5LCrUU9HIZh9KA21xaBcKe4nvsSN6
         zwbpWJbIqf/nuk2PXFBYkT0N5+XIGvWS0Qn4SGmeKoxZ6N1A9olBVthD7PObZt5B7NVi
         wTRIvN0ROV1FUGJ/YT0jQLV3dhrX5fHBun84UNthMRgvcNx+puGh32ZVDtAqYnXFVo39
         uGy4Hnz37WUpKYGkb6zqYSEKiby/cVP3uM+0+oaXdbjyyJSi+Yrn7kDZtnq0/A3i7CRD
         aqSC4zJtcjq/SksWGx8vUwftX3gwZ6a1hSEDnnzqXh3BSkMmhxqhM1+rI8QWez5StYn1
         4OfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=6+ZPkY1y;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id fm6-20020a05600c0c0600b003fbd17c6ad0si110102wmb.4.2023.07.05.05.51.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Jul 2023 05:51:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id 5b1f17b1804b1-3fbea14706eso4049605e9.2
        for <kasan-dev@googlegroups.com>; Wed, 05 Jul 2023 05:51:07 -0700 (PDT)
X-Received: by 2002:a1c:4c12:0:b0:3fb:b1af:a455 with SMTP id
 z18-20020a1c4c12000000b003fbb1afa455mr12792094wmf.5.1688561467416; Wed, 05
 Jul 2023 05:51:07 -0700 (PDT)
MIME-Version: 1.0
References: <678ac92ab790dba9198f9ca14f405651b97c8502.1688561016.git.andreyknvl@google.com>
In-Reply-To: <678ac92ab790dba9198f9ca14f405651b97c8502.1688561016.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 5 Jul 2023 14:50:30 +0200
Message-ID: <CANpmjNO+spktteYZezk7PGLFOyoeuFyziKiU-1GXbpeyKLZLPg@mail.gmail.com>
Subject: Re: [PATCH] kasan, slub: fix HW_TAGS zeroing with slub_debug
To: andrey.konovalov@linux.dev
Cc: Mark Rutland <mark.rutland@arm.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	Catalin Marinas <catalin.marinas@arm.com>, Peter Collingbourne <pcc@google.com>, 
	Feng Tang <feng.tang@intel.com>, stable@vger.kernel.org, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=6+ZPkY1y;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as
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

On Wed, 5 Jul 2023 at 14:44, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Commit 946fa0dbf2d8 ("mm/slub: extend redzone check to extra allocated
> kmalloc space than requested") added precise kmalloc redzone poisoning
> to the slub_debug functionality.
>
> However, this commit didn't account for HW_TAGS KASAN fully initializing
> the object via its built-in memory initialization feature. Even though
> HW_TAGS KASAN memory initialization contains special memory initialization
> handling for when slub_debug is enabled, it does not account for in-object
> slub_debug redzones. As a result, HW_TAGS KASAN can overwrite these
> redzones and cause false-positive slub_debug reports.
>
> To fix the issue, avoid HW_TAGS KASAN memory initialization when slub_debug
> is enabled altogether. Implement this by moving the __slub_debug_enabled
> check to slab_post_alloc_hook. Common slab code seems like a more
> appropriate place for a slub_debug check anyway.
>
> Fixes: 946fa0dbf2d8 ("mm/slub: extend redzone check to extra allocated kmalloc space than requested")
> Cc: <stable@vger.kernel.org>
> Reported-by: Mark Rutland <mark.rutland@arm.com>

Is it fixing this issue:

  https://lore.kernel.org/all/20230628154714.GB22090@willie-the-truck/

Or some other issue?

> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Other than the question above, it looks sane:

Acked-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/kasan.h | 12 ------------
>  mm/slab.h        | 16 ++++++++++++++--
>  2 files changed, 14 insertions(+), 14 deletions(-)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index b799f11e45dc..2e973b36fe07 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -466,18 +466,6 @@ static inline void kasan_unpoison(const void *addr, size_t size, bool init)
>
>         if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
>                 return;
> -       /*
> -        * Explicitly initialize the memory with the precise object size to
> -        * avoid overwriting the slab redzone. This disables initialization in
> -        * the arch code and may thus lead to performance penalty. This penalty
> -        * does not affect production builds, as slab redzones are not enabled
> -        * there.
> -        */
> -       if (__slub_debug_enabled() &&
> -           init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
> -               init = false;
> -               memzero_explicit((void *)addr, size);
> -       }
>         size = round_up(size, KASAN_GRANULE_SIZE);
>
>         hw_set_mem_tag_range((void *)addr, size, tag, init);
> diff --git a/mm/slab.h b/mm/slab.h
> index 6a5633b25eb5..9c0e09d0f81f 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -723,6 +723,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
>                                         unsigned int orig_size)
>  {
>         unsigned int zero_size = s->object_size;
> +       bool kasan_init = init;
>         size_t i;
>
>         flags &= gfp_allowed_mask;
> @@ -739,6 +740,17 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
>             (s->flags & SLAB_KMALLOC))
>                 zero_size = orig_size;
>
> +       /*
> +        * When slub_debug is enabled, avoid memory initialization integrated
> +        * into KASAN and instead zero out the memory via the memset below with
> +        * the proper size. Otherwise, KASAN might overwrite SLUB redzones and
> +        * cause false-positive reports. This does not lead to a performance
> +        * penalty on production builds, as slub_debug is not intended to be
> +        * enabled there.
> +        */
> +       if (__slub_debug_enabled())
> +               kasan_init = false;
> +
>         /*
>          * As memory initialization might be integrated into KASAN,
>          * kasan_slab_alloc and initialization memset must be
> @@ -747,8 +759,8 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
>          * As p[i] might get tagged, memset and kmemleak hook come after KASAN.
>          */
>         for (i = 0; i < size; i++) {
> -               p[i] = kasan_slab_alloc(s, p[i], flags, init);
> -               if (p[i] && init && !kasan_has_integrated_init())
> +               p[i] = kasan_slab_alloc(s, p[i], flags, kasan_init);
> +               if (p[i] && init && (!kasan_init || !kasan_has_integrated_init()))
>                         memset(p[i], 0, zero_size);
>                 kmemleak_alloc_recursive(p[i], s->object_size, 1,
>                                          s->flags, flags);
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO%2BspktteYZezk7PGLFOyoeuFyziKiU-1GXbpeyKLZLPg%40mail.gmail.com.
