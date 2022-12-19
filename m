Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6MWQGOQMGQE5LA243Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 37CA6650ABC
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Dec 2022 12:31:07 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id e18-20020ac845d2000000b003a6a5cbbebcsf3898304qto.20
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Dec 2022 03:31:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671449466; cv=pass;
        d=google.com; s=arc-20160816;
        b=pvzSlS5H0J/13UCeSI4fzPkP7TUakVrXzsrG7HAjYjy71VGCIT02iDgKnWcoDJpbCp
         Z4e1RQ5GsWGBu0n5gbK9LwmU1m6DuxVQkjS1lp8/e4OJGGk7iBdUgZ4etxOQC/lm7O8G
         0lfvpNOp5zwNaCnUQadGk9wyTgpmIZwMC68WWByC20/S3glbeLgJDI+lQ0vlyCcDNztV
         ZHzqVSBUeqtYmj6uqmS7MvZu4lR7NoFQDo2sBYXr0fo1XA73kmRC0K+T/ynBV6mOXFyH
         0O6imsTuV1a0urVpW00UZRYRCu6FIWS04rHGH1OoKzFBKOsMXFX3VlnkJNM4Noos44TS
         PBOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KyFHQJUgE4DJoirfFAkv2H7gcRuaAIWYn5QhRXxeGwc=;
        b=YFyeogC9sQLk6TE38NznRLx1LOtCaacceO2GhWvP334MA9/rwGbYyTtMxufBSZBW2Z
         lbsGEmeJaJNi0qHBgLnlyJJzGBW0wd3nIFKRNYf/7G/7iQQR+a7lRn1reCiEJsLFz+tg
         +eGs6d1XAnmV+aFc04WlVjIGAo5rXM/1bvW/LhooHrp4eq1Y565uDH+o5Fb5NXgryiDT
         Zu4tY2os+8B/F9Ht9A+FarnJg0V6w74SImUKKbXlq3Jl0oa4ZhZgbeEJi6DyMH+/bSoK
         lAqjuwwp2HeimH5QbsnFZTOIeZkd7T2iR5x91Rvrb6Q89F7pAPcdPRBPIR7VQYDl3XEB
         NHjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lZpII0Im;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KyFHQJUgE4DJoirfFAkv2H7gcRuaAIWYn5QhRXxeGwc=;
        b=QSUVZZMhDK421E07mqqnzKrjS1bxZdCIIwKxRBB2tmj9SrE3ylTpob3eryudPXEXej
         yv0friGApnMg9n1HL1Y+qGDUSdXgXa+BKkh4tacto6uwV47xuYGznM7vaY1uf8Rstn7N
         py+JjwXriOdva9XT9op6lwOyHmhCfhQkXMIse1M7lx2zTjW73QAKFz2H/MZTdaGB31Rb
         pBtZZqYhnSEooBS0sBGo4HL69ce1BV0Vy+Qc4ZfZRx2jDFhYoBXhcMVeDNLrPgfqxE0Y
         O0uZX8EgJ7A/EFB43Gywt/fEjFqby5lwns4h+QvIzRmXzwsR0o97+AxVVTGhC9F5iyY2
         VvWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=KyFHQJUgE4DJoirfFAkv2H7gcRuaAIWYn5QhRXxeGwc=;
        b=f70ii6eclZ7hyghpSvuhdvfiMIDY9GaCEo6b+wGpUbojUZiKpti//D2gfUZHWjW1EM
         LmWsdWJbE9UzpKS3zwI4BitU7YVrvG4FAZxWaTIb4FZAgcrGWjp+E2EiwlsCXuvqXR1t
         3tdrZIJHdBEY6F9bK7ykuu0K/2eYoUEug2bnD0BxocpPVoGSKBTbUKe9DrhqdsBhZ1Pd
         v9/gjHqzobtNT9IcMukt5/Pfpq+rm0hmrIKp2VP9OIExtukLrDFp8ssyiUiS1DTIapmz
         AxkHy8E0vBE9PbWvxMwNR494LA/JZEg6LeVKuboEbIInt+VtxBTHKrbsqVlSeLrzwETS
         2D4Q==
X-Gm-Message-State: ANoB5pn/4mOPJZVVBh/SHEgUNCZN+cwG5AWNZRoNQ9OiyQyM0yGjsh7B
	iCxyv/Db0y7HAatiBcNG2ik=
X-Google-Smtp-Source: AA0mqf6zGsVWIy/MFJM3+ksMH4q6flA00+DpV4c7gQfr/JML1QvY0SNrsWj8j5Y3AZJt+9DXn7Zz2w==
X-Received: by 2002:ac8:4617:0:b0:3a8:1d32:eec2 with SMTP id p23-20020ac84617000000b003a81d32eec2mr1379294qtn.269.1671449465917;
        Mon, 19 Dec 2022 03:31:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7091:0:b0:3a5:45a4:2fd4 with SMTP id y17-20020ac87091000000b003a545a42fd4ls6684978qto.10.-pod-prod-gmail;
 Mon, 19 Dec 2022 03:31:05 -0800 (PST)
X-Received: by 2002:ac8:6759:0:b0:3a5:4fa8:141c with SMTP id n25-20020ac86759000000b003a54fa8141cmr12441884qtp.23.1671449465307;
        Mon, 19 Dec 2022 03:31:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671449465; cv=none;
        d=google.com; s=arc-20160816;
        b=pvodBgEfIMEuP+jgksXHlsJzaCBOhLyIdsF9HJdUf4FFIq+faw1E+EoJCR0R7qaZW7
         viGSxZcnjH8y4yAjy9AFvRdi2vSwPlvz7MXKDvBkFxLUGE6592/dE5zQJQNx7FnxstA4
         upbSfrfilxJfKlm09zohWs1Zi+mryNjBqgu/ndsk9EMUT/ifOLuj+8CK4oylmBm19XQu
         VX1ZXLWqYNfEGZRG0HJONJCMpy4V0WtPLiHKqJ7rDd5Cz3Rool9+xAterRq8192OmHFa
         Tb+43CvaemGibg6/WbgGrMeN2cdkWWDVajf2UmNRZcbpynzHSd1IOEeEWd4wV4yETcSU
         bU4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iaIBaFR/5sQ1YgIDiJkbC1N+HwzpKqM3wb71PGjyc/g=;
        b=QqNDFpXTy/N93icsilnX0io31fi0R+l0qVWm55u74cdJzNA0yz9AWtJh1KqtJSPgEp
         vnlt+RKSjaO9hClX8ifc8nBLleemCXvXxJxvptbmW1nJNjrJehVjYmR8kewwxCY/VCBc
         9/Sr7lvOdQaM/3TKuuc7bETDHMl4Kd7YbMz1TgDHJpoQVBR4Oe5TZo2p3y++q0EmGZxG
         cLn5gppvD1tDQe1VnAmftkTXanH11E3xAAPvLW0Q7jSdE+vAV0e1HCahJg7IwdomY+oC
         8UBwA9/2GBfpRMkEMaL/2/3OsSXi/h6xLN5OuhjSoaxpopTgwrVil+paaDwdAbn6BGjz
         Xdvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lZpII0Im;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id e6-20020ac84b46000000b003a80e605d25si560875qts.4.2022.12.19.03.31.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Dec 2022 03:31:05 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id 203so4538619yby.10
        for <kasan-dev@googlegroups.com>; Mon, 19 Dec 2022 03:31:05 -0800 (PST)
X-Received: by 2002:a25:bec7:0:b0:738:9bde:1a8d with SMTP id
 k7-20020a25bec7000000b007389bde1a8dmr1627021ybm.93.1671449464708; Mon, 19 Dec
 2022 03:31:04 -0800 (PST)
MIME-Version: 1.0
References: <323d51d422d497b3783dacb130af245f67d77671.1671228324.git.andreyknvl@google.com>
In-Reply-To: <323d51d422d497b3783dacb130af245f67d77671.1671228324.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 19 Dec 2022 12:30:28 +0100
Message-ID: <CANpmjNPKYEohPBnQ59GVKfCYc+dRUo-YtaR0PzPiwtALNghdFA@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: allow sampling page_alloc allocations for HW_TAGS
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Jann Horn <jannh@google.com>, Mark Brand <markbrand@google.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lZpII0Im;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as
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

On Fri, 16 Dec 2022 at 23:17, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> As Hardware Tag-Based KASAN is intended to be used in production, its
> performance impact is crucial. As page_alloc allocations tend to be big,
> tagging and checking all such allocations can introduce a significant
> slowdown.
>
> Add two new boot parameters that allow to alleviate that slowdown:
>
> - kasan.page_alloc.sample, which makes Hardware Tag-Based KASAN tag only
>   every Nth page_alloc allocation with the order configured by the second
>   added parameter (default: tag every such allocation).
>
> - kasan.page_alloc.sample.order, which makes sampling enabled by the first
>   parameter only affect page_alloc allocations with the order equal or
>   greater than the specified value (default: 3, see below).
>
> The exact performance improvement caused by using the new parameters
> depends on their values and the applied workload.
>
> The chosen default value for kasan.page_alloc.sample.order is 3, which
> matches both PAGE_ALLOC_COSTLY_ORDER and SKB_FRAG_PAGE_ORDER. This is done
> for two reasons:
>
> 1. PAGE_ALLOC_COSTLY_ORDER is "the order at which allocations are deemed
>    costly to service", which corresponds to the idea that only large and
>    thus costly allocations are supposed to sampled.
>
> 2. One of the workloads targeted by this patch is a benchmark that sends
>    a large amount of data over a local loopback connection. Most multi-page
>    data allocations in the networking subsystem have the order of
>    SKB_FRAG_PAGE_ORDER (or PAGE_ALLOC_COSTLY_ORDER).
>
> When running a local loopback test on a testing MTE-enabled device in sync
> mode, enabling Hardware Tag-Based KASAN introduces a ~50% slowdown.
> Applying this patch and setting kasan.page_alloc.sampling to a value higher
> than 1 allows to lower the slowdown. The performance improvement saturates
> around the sampling interval value of 10 with the default sampling page
> order of 3. This lowers the slowdown to ~20%. The slowdown in real
> scenarios involving the network will likely be better.
>
> Enabling page_alloc sampling has a downside: KASAN misses bad accesses to
> a page_alloc allocation that has not been tagged. This lowers the value of
> KASAN as a security mitigation.
>
> However, based on measuring the number of page_alloc allocations of
> different orders during boot in a test build, sampling with the default
> kasan.page_alloc.sample.order value affects only ~7% of allocations.
> The rest ~93% of allocations are still checked deterministically.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

On a whole:

Reviewed-by: Marco Elver <elver@google.com>

This looks much better, given it'll automatically do the right thing
without marking costly allocation sites.

Minor comments below.

> ---
>
> Changes v2-v3:
> - Drop __GFP_KASAN_SAMPLE flag.
> - Add kasan.page_alloc.sample.order.
> - Add fast-path for disabled sampling to kasan_sample_page_alloc.
>
> Changes v1->v2:
> - Only sample allocations when __GFP_KASAN_SAMPLE is provided to
>   alloc_pages().
> - Fix build when KASAN is disabled.
> - Add more information about the flag to documentation.
> - Use optimized preemption-safe approach for sampling suggested by Marco.
> ---
>  Documentation/dev-tools/kasan.rst | 16 +++++++++
>  include/linux/kasan.h             | 14 +++++---
>  mm/kasan/common.c                 |  9 +++--
>  mm/kasan/hw_tags.c                | 60 +++++++++++++++++++++++++++++++
>  mm/kasan/kasan.h                  | 27 ++++++++++++++
>  mm/page_alloc.c                   | 43 ++++++++++++++--------
>  6 files changed, 148 insertions(+), 21 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 5c93ab915049..d983e4fcee7c 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -140,6 +140,22 @@ disabling KASAN altogether or controlling its features:
>  - ``kasan.vmalloc=off`` or ``=on`` disables or enables tagging of vmalloc
>    allocations (default: ``on``).
>
> +- ``kasan.page_alloc.sample=<sampling interval>`` makes KASAN tag only every
> +  Nth page_alloc allocation with the order equal or greater than
> +  ``kasan.page_alloc.sample.order``, where N is the value of the ``sample``
> +  parameter (default: ``1``, or tag every such allocation).
> +  This parameter is intended to mitigate the performance overhead introduced
> +  by KASAN.
> +  Note that enabling this parameter makes Hardware Tag-Based KASAN skip checks
> +  of allocations chosen by sampling and thus miss bad accesses to these
> +  allocations. Use the default value for accurate bug detection.
> +
> +- ``kasan.page_alloc.sample.order=<minimum page order>`` specifies the minimum
> +  order of allocations that are affected by sampling (default: ``3``).
> +  Only applies when ``kasan.page_alloc.sample`` is set to a non-default value.

"set to a value greater than 1"? The additional indirection through
"non-default" seems unnecessary.

> +  This parameter is intended to allow sampling only large page_alloc
> +  allocations, which is the biggest source of the performace overhead.

s/performace/performance/

> +
>  Error reports
>  ~~~~~~~~~~~~~
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 96c9d56e5510..5ebbaf672009 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -120,12 +120,13 @@ static __always_inline void kasan_poison_pages(struct page *page,
>                 __kasan_poison_pages(page, order, init);
>  }
>
> -void __kasan_unpoison_pages(struct page *page, unsigned int order, bool init);
> -static __always_inline void kasan_unpoison_pages(struct page *page,
> +bool __kasan_unpoison_pages(struct page *page, unsigned int order, bool init);
> +static __always_inline bool kasan_unpoison_pages(struct page *page,
>                                                  unsigned int order, bool init)
>  {
>         if (kasan_enabled())
> -               __kasan_unpoison_pages(page, order, init);
> +               return __kasan_unpoison_pages(page, order, init);
> +       return false;
>  }
>
>  void __kasan_cache_create_kmalloc(struct kmem_cache *cache);
> @@ -249,8 +250,11 @@ static __always_inline bool kasan_check_byte(const void *addr)
>  static inline void kasan_unpoison_range(const void *address, size_t size) {}
>  static inline void kasan_poison_pages(struct page *page, unsigned int order,
>                                       bool init) {}
> -static inline void kasan_unpoison_pages(struct page *page, unsigned int order,
> -                                       bool init) {}
> +static inline bool kasan_unpoison_pages(struct page *page, unsigned int order,
> +                                       bool init)
> +{
> +       return false;
> +}
>  static inline void kasan_cache_create_kmalloc(struct kmem_cache *cache) {}
>  static inline void kasan_poison_slab(struct slab *slab) {}
>  static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 833bf2cfd2a3..1d0008e1c420 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -95,19 +95,24 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
>  }
>  #endif /* CONFIG_KASAN_STACK */
>
> -void __kasan_unpoison_pages(struct page *page, unsigned int order, bool init)
> +bool __kasan_unpoison_pages(struct page *page, unsigned int order, bool init)
>  {
>         u8 tag;
>         unsigned long i;
>
>         if (unlikely(PageHighMem(page)))
> -               return;
> +               return false;
> +
> +       if (!kasan_sample_page_alloc(order))
> +               return false;
>
>         tag = kasan_random_tag();
>         kasan_unpoison(set_tag(page_address(page), tag),
>                        PAGE_SIZE << order, init);
>         for (i = 0; i < (1 << order); i++)
>                 page_kasan_tag_set(page + i, tag);
> +
> +       return true;
>  }
>
>  void __kasan_poison_pages(struct page *page, unsigned int order, bool init)
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index b22c4f461cb0..d1bcb0205327 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -59,6 +59,24 @@ EXPORT_SYMBOL_GPL(kasan_mode);
>  /* Whether to enable vmalloc tagging. */
>  DEFINE_STATIC_KEY_TRUE(kasan_flag_vmalloc);
>
> +#define PAGE_ALLOC_SAMPLE_DEFAULT      1
> +#define PAGE_ALLOC_SAMPLE_ORDER_DEFAULT        3

Why not just set it to PAGE_ALLOC_COSTLY_ORDER?

> +/*
> + * Sampling interval of page_alloc allocation (un)poisoning.
> + * Defaults to no sampling.
> + */
> +unsigned long kasan_page_alloc_sample = PAGE_ALLOC_SAMPLE_DEFAULT;
> +
> +/*
> + * Minimum order of page_alloc allocations to be affected by sampling.
> + * The default value is chosen to match both
> + * PAGE_ALLOC_COSTLY_ORDER and SKB_FRAG_PAGE_ORDER.
> + */
> +unsigned int kasan_page_alloc_sample_order = PAGE_ALLOC_SAMPLE_ORDER_DEFAULT;
> +
> +DEFINE_PER_CPU(long, kasan_page_alloc_skip);
> +
>  /* kasan=off/on */
>  static int __init early_kasan_flag(char *arg)
>  {
> @@ -122,6 +140,48 @@ static inline const char *kasan_mode_info(void)
>                 return "sync";
>  }
>
> +/* kasan.page_alloc.sample=<sampling interval> */
> +static int __init early_kasan_flag_page_alloc_sample(char *arg)
> +{
> +       int rv;
> +
> +       if (!arg)
> +               return -EINVAL;
> +
> +       rv = kstrtoul(arg, 0, &kasan_page_alloc_sample);
> +       if (rv)
> +               return rv;
> +
> +       if (!kasan_page_alloc_sample || kasan_page_alloc_sample > LONG_MAX) {
> +               kasan_page_alloc_sample = PAGE_ALLOC_SAMPLE_DEFAULT;
> +               return -EINVAL;
> +       }
> +
> +       return 0;
> +}
> +early_param("kasan.page_alloc.sample", early_kasan_flag_page_alloc_sample);
> +
> +/* kasan.page_alloc.sample.order=<minimum page order> */
> +static int __init early_kasan_flag_page_alloc_sample_order(char *arg)
> +{
> +       int rv;
> +
> +       if (!arg)
> +               return -EINVAL;
> +
> +       rv = kstrtouint(arg, 0, &kasan_page_alloc_sample_order);
> +       if (rv)
> +               return rv;
> +
> +       if (kasan_page_alloc_sample_order > INT_MAX) {
> +               kasan_page_alloc_sample_order = PAGE_ALLOC_SAMPLE_ORDER_DEFAULT;
> +               return -EINVAL;
> +       }
> +
> +       return 0;
> +}
> +early_param("kasan.page_alloc.sample.order", early_kasan_flag_page_alloc_sample_order);
> +
>  /*
>   * kasan_init_hw_tags_cpu() is called for each CPU.
>   * Not marked as __init as a CPU can be hot-plugged after boot.
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index ea8cf1310b1e..32413f22aa82 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -42,6 +42,10 @@ enum kasan_mode {
>
>  extern enum kasan_mode kasan_mode __ro_after_init;
>
> +extern unsigned long kasan_page_alloc_sample;
> +extern unsigned int kasan_page_alloc_sample_order;
> +DECLARE_PER_CPU(long, kasan_page_alloc_skip);
> +
>  static inline bool kasan_vmalloc_enabled(void)
>  {
>         return static_branch_likely(&kasan_flag_vmalloc);
> @@ -57,6 +61,24 @@ static inline bool kasan_sync_fault_possible(void)
>         return kasan_mode == KASAN_MODE_SYNC || kasan_mode == KASAN_MODE_ASYMM;
>  }
>
> +static inline bool kasan_sample_page_alloc(unsigned int order)
> +{
> +       /* Fast-path for when sampling is disabled. */
> +       if (kasan_page_alloc_sample == 1)
> +               return true;
> +
> +       if (order < kasan_page_alloc_sample_order)
> +               return true;
> +
> +       if (this_cpu_dec_return(kasan_page_alloc_skip) < 0) {
> +               this_cpu_write(kasan_page_alloc_skip,
> +                              kasan_page_alloc_sample - 1);
> +               return true;
> +       }
> +
> +       return false;
> +}
> +
>  #else /* CONFIG_KASAN_HW_TAGS */
>
>  static inline bool kasan_async_fault_possible(void)
> @@ -69,6 +91,11 @@ static inline bool kasan_sync_fault_possible(void)
>         return true;
>  }
>
> +static inline bool kasan_sample_page_alloc(unsigned int order)
> +{
> +       return true;
> +}
> +
>  #endif /* CONFIG_KASAN_HW_TAGS */
>
>  #ifdef CONFIG_KASAN_GENERIC
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index 0745aedebb37..7d980dc0000e 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -1356,6 +1356,8 @@ static int free_tail_pages_check(struct page *head_page, struct page *page)
>   *    see the comment next to it.
>   * 3. Skipping poisoning is requested via __GFP_SKIP_KASAN_POISON,
>   *    see the comment next to it.
> + * 4. The allocation is excluded from being checked due to sampling,
> + *    see the call to kasan_unpoison_pages.
>   *
>   * Poisoning pages during deferred memory init will greatly lengthen the
>   * process and cause problem in large memory systems as the deferred pages
> @@ -2468,7 +2470,8 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
>  {
>         bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags) &&
>                         !should_skip_init(gfp_flags);
> -       bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
> +       bool zero_tags = init && (gfp_flags & __GFP_ZEROTAGS);
> +       bool reset_tags = !zero_tags;
>         int i;
>
>         set_page_private(page, 0);
> @@ -2491,30 +2494,42 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
>          */
>
>         /*
> -        * If memory tags should be zeroed (which happens only when memory
> -        * should be initialized as well).
> +        * If memory tags should be zeroed
> +        * (which happens only when memory should be initialized as well).
>          */
> -       if (init_tags) {
> +       if (zero_tags) {
>                 /* Initialize both memory and tags. */
>                 for (i = 0; i != 1 << order; ++i)
>                         tag_clear_highpage(page + i);
>
> -               /* Note that memory is already initialized by the loop above. */
> +               /* Take note that memory was initialized by the loop above. */
>                 init = false;
>         }
>         if (!should_skip_kasan_unpoison(gfp_flags)) {
> -               /* Unpoison shadow memory or set memory tags. */
> -               kasan_unpoison_pages(page, order, init);
> -
> -               /* Note that memory is already initialized by KASAN. */
> -               if (kasan_has_integrated_init())
> -                       init = false;
> -       } else {
> -               /* Ensure page_address() dereferencing does not fault. */
> +               /* Try unpoisoning (or setting tags) and initializing memory. */
> +               if (kasan_unpoison_pages(page, order, init)) {
> +                       /* Take note that memory was initialized by KASAN. */
> +                       if (kasan_has_integrated_init())
> +                               init = false;
> +                       /* Take note that memory tags were set by KASAN. */
> +                       reset_tags = false;
> +               } else {
> +                       /*
> +                        * KASAN decided to exclude this allocation from being
> +                        * poisoned due to sampling. Skip poisoning as well.
> +                        */
> +                       SetPageSkipKASanPoison(page);
> +               }
> +       }
> +       /*
> +        * If memory tags have not been set, reset the page tags to ensure
> +        * page_address() dereferencing does not fault.
> +        */
> +       if (reset_tags) {
>                 for (i = 0; i != 1 << order; ++i)
>                         page_kasan_tag_reset(page + i);
>         }
> -       /* If memory is still not initialized, do it now. */
> +       /* If memory is still not initialized, initialize it now. */
>         if (init)
>                 kernel_init_pages(page, 1 << order);
>         /* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPKYEohPBnQ59GVKfCYc%2BdRUo-YtaR0PzPiwtALNghdFA%40mail.gmail.com.
