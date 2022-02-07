Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGV5QOIAMGQE2CL2N6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DB754AB6E3
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 09:55:55 +0100 (CET)
Received: by mail-vk1-xa38.google.com with SMTP id i26-20020ac5cbfa000000b0031f8edd1ad7sf1624512vkn.5
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 00:55:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644224154; cv=pass;
        d=google.com; s=arc-20160816;
        b=eNk9blfPB50t1deHSGx3O+6tK1vv13dg4RTCW7v4I52R2Zqk4vJo4j0kffFPb+ndaD
         K7AUIuBzyppKX1gYFpSw4gBWxzGSRXvnW30nRANNNZpMEqlroqP72WonxjUX7nWU8xHx
         3WFQ0Yx+aOy+xZNtAEjbUnRC0cn5ULCjQWt9FbFkVVoBB1ofzsCgPTMilE0pZOh4/Air
         X/HptHjloBOtfv4u7ffLeSK8teGapwoxe96sw81VzdTpey/hOa0uFHC1ucsSnzOgWysj
         Cx2UGWHJddv+BZhqldApBgZ0L6mXevFol7dFq9o/qjXIiR9dr+uFjzVqsUeViNvTGTkc
         Kb8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HlAL5abHkjGujRTTtYstJXw881x66eyG8bzOW28dbbI=;
        b=tZn6C0B/Boj51r61InQVWTwEhwTluQTtTmm1UAJYxPcihhBJj1YGzqfE/4uFHhjLpi
         YbYykdNr5uOODQyyOyT8vnz6WKuylJrQrw65zpZTsW5YnIPhKfe50ydFGe57n0i8bBoD
         B8tx2/m/7bjerwJtTVNBs0h6WmOXdWECi1iE+DLHG3ls5inHD9QoEbB1tGB2dkhansYh
         fFK9MjkjsYNGbJUS6UMR6AdtAhJtyydhOC4Tf21QMncdYfpEEKbs7XR2o1LbREJBiwLR
         YoOJ4pl5uEzbQfSaXXm6KA7mCQUELXE9HBmkRhPWNgZvuSdEgfUTasPRzePYJWW9uur5
         a9fw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kjKQjXhq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HlAL5abHkjGujRTTtYstJXw881x66eyG8bzOW28dbbI=;
        b=m/vmXDhCfFPpFKQ3k5wCdCKSv9d3rqtlnFhw42fnqPooMXssZnkqHe1RCtZ3cMgg8E
         i4mO2YyKVxiJUIvkT4Fy87ZWrr26eK/yN9uorj7bVQBBqKNMtoXsDOz7Sm+Uj9V4eduS
         1r6GtfKeeL47qxTAHTJ+CsQ57y7UpXUqn+xIDxjENM1t6mbT4/AyKCvCjH1lbSK35Zpn
         02sgOaWQC9u8SP/U9h0QYNExiXAIYFeC2Hi0OtRim/TLc7enZFJCoeN5PVVGJ7YLCV0U
         oRCuMS5beeg7BE2kHow6Md/ygK7ZTjPek/6pc75s8P1gnMAD4AYwnNd37Nn2wyD9a5kb
         MPWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HlAL5abHkjGujRTTtYstJXw881x66eyG8bzOW28dbbI=;
        b=13ojyQglJyDkngTEvErP315GhQwYXy66EA0BU5WNqE53fY5FbCKIzUZXs90AlhhJew
         72uCN5oCvJJ3SZ1ppl9slNCn543vYo2Nu6f3PLAIvg/d4/Az9lU284fuaSYzJnEJTUoz
         gZBbUeJj8suLQ1gIQelaY0BvgWaQRYFvUW/7FSpj9Yf/kKQIrdvTxtlkA9o6qQLSEQ5o
         7hsB+I2MqZa1O/H4Wy4bYqFx4rKrohd/9vMoqLHQqURuKtGa/Roas3DQVaMBU5lm5c4F
         qcSSP1/Se25htxiaqqWqrQr/Y89YVPIPs/coHVgcw/+nkGUD7U61XrOFa43xo6VUJgza
         VnJg==
X-Gm-Message-State: AOAM530xupI+2LyMXdG8pzc83bpsEGO3l6jhhtah5mQ//Iv4iFbS0/8u
	SO1E5LZXdG3SMmXFxmUyUqQ=
X-Google-Smtp-Source: ABdhPJy6/bzECjFEPdjKa8ngcUVRly+pKzZg3O/rA6BLG4rqos0VAe1oTy0rSenhKp6GC+zz5K1QFA==
X-Received: by 2002:a67:d717:: with SMTP id p23mr4422380vsj.38.1644224154189;
        Mon, 07 Feb 2022 00:55:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:6c48:: with SMTP id q8ls177251uas.2.gmail; Mon, 07 Feb
 2022 00:55:53 -0800 (PST)
X-Received: by 2002:ab0:14f1:: with SMTP id f46mr3013912uae.56.1644224153436;
        Mon, 07 Feb 2022 00:55:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644224153; cv=none;
        d=google.com; s=arc-20160816;
        b=J2ZeXK1OvHSOI2yZ8XeLr6BxrV7J8pQ4TYnoHUp8G4ITIuBypcRTIjHGpVzb7OoUcs
         /ZHqNGtrETLajt1JcXjocQsUyn2D454u4InngcH2h9HiGTgUczkjEuMEpP0ut1qae4jJ
         tJHv3/bKRv7NRpBB9WhyYyCSsR2p6xjxMjYzw2rYMl38sBci0HsADsT9dZ2pvNOt74Bk
         2ju0chboY7yDYBQTB9iOdOO7D1bfgcmCvsntykZOxIjU56mR+2Wii0aGixI9A0OeBhVJ
         qXqlfhnFAVnuYLYwhtBVTaHxaBJwtK/FHNafdXsZnTUGX/X/3fCjrowQBEnySVsh57os
         lf+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=knF2fFP9aIoGTNmgPKFlIdzkXuLeb4VSUzI7AmunKNY=;
        b=XXGnAKFQAxMklzE615K9l0SurpVIB38ht/LMeYx/0/B/Z8pA5B8fqAHYTE9EoVTdnv
         j9GVHyMT/JaZi9HuHwyW7HY+XdP1C9cP9nfSDQCrEBm3pnzA3otoRCnDj+DLdbxKq6YF
         QvMu+ka9S4VJd44CtjM+8Hq6DD6P/9hz8QP19z2R4lqyFnNDvHlynyAKwrlP1EVbG1O6
         MF6Kdgxl1ToKYIxGCVy3D78ZRFUN3g+Pje3yr0QuvfXk6gNzfXvMvSb5c/hvmkoGKH5k
         xFz99sBIxqn0g+R8x54FGaCPtdf77Bx0Ba0i0tHQZjQnLuuHThGvSjpdfZXD9nXjFCjZ
         TE2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kjKQjXhq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2b.google.com (mail-yb1-xb2b.google.com. [2607:f8b0:4864:20::b2b])
        by gmr-mx.google.com with ESMTPS id az37si618229uab.1.2022.02.07.00.55.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 00:55:53 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) client-ip=2607:f8b0:4864:20::b2b;
Received: by mail-yb1-xb2b.google.com with SMTP id v186so37930432ybg.1
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 00:55:53 -0800 (PST)
X-Received: by 2002:a81:c505:: with SMTP id k5mr6144103ywi.264.1644224152818;
 Mon, 07 Feb 2022 00:55:52 -0800 (PST)
MIME-Version: 1.0
References: <20220207034432.185532-1-liupeng256@huawei.com>
In-Reply-To: <20220207034432.185532-1-liupeng256@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Feb 2022 09:55:41 +0100
Message-ID: <CANpmjNN=0Q6s5WnKrWm4YXqSj-1rRsL2VTD_QJUfQdv_2nhf0Q@mail.gmail.com>
Subject: Re: [PATCH v3] kfence: Make test case compatible with run time set
 sample interval
To: Peng Liu <liupeng256@huawei.com>
Cc: glider@google.com, dvyukov@google.com, corbet@lwn.net, 
	sumit.semwal@linaro.org, christian.koenig@amd.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linaro-mm-sig@lists.linaro.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kjKQjXhq;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as
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

On Mon, 7 Feb 2022 at 04:29, 'Peng Liu' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> The parameter kfence_sample_interval can be set via boot parameter
> and late shell command, which is convenient for automated tests and
> KFENCE parameter optimization. However, KFENCE test case just uses
> compile-time CONFIG_KFENCE_SAMPLE_INTERVAL, which will make KFENCE
> test case not run as users desired. Export kfence_sample_interval,
> so that KFENCE test case can use run-time-set sample interval.
>
> Signed-off-by: Peng Liu <liupeng256@huawei.com>

Reviewed-by: Marco Elver <elver@google.com>

Thank you.

> ---
> v2->v3:
> - Revise change log description
> v1->v2:
> - Use EXPORT_SYMBOL_GPL replace EXPORT_SYMBOL
>
>  include/linux/kfence.h  | 2 ++
>  mm/kfence/core.c        | 3 ++-
>  mm/kfence/kfence_test.c | 8 ++++----
>  3 files changed, 8 insertions(+), 5 deletions(-)
>
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index 4b5e3679a72c..f49e64222628 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -17,6 +17,8 @@
>  #include <linux/atomic.h>
>  #include <linux/static_key.h>
>
> +extern unsigned long kfence_sample_interval;
> +
>  /*
>   * We allocate an even number of pages, as it simplifies calculations to map
>   * address to metadata indices; effectively, the very first page serves as an
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 5ad40e3add45..13128fa13062 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -47,7 +47,8 @@
>
>  static bool kfence_enabled __read_mostly;
>
> -static unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
> +unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
> +EXPORT_SYMBOL_GPL(kfence_sample_interval); /* Export for test modules. */
>
>  #ifdef MODULE_PARAM_PREFIX
>  #undef MODULE_PARAM_PREFIX
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index a22b1af85577..50dbb815a2a8 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -268,13 +268,13 @@ static void *test_alloc(struct kunit *test, size_t size, gfp_t gfp, enum allocat
>          * 100x the sample interval should be more than enough to ensure we get
>          * a KFENCE allocation eventually.
>          */
> -       timeout = jiffies + msecs_to_jiffies(100 * CONFIG_KFENCE_SAMPLE_INTERVAL);
> +       timeout = jiffies + msecs_to_jiffies(100 * kfence_sample_interval);
>         /*
>          * Especially for non-preemption kernels, ensure the allocation-gate
>          * timer can catch up: after @resched_after, every failed allocation
>          * attempt yields, to ensure the allocation-gate timer is scheduled.
>          */
> -       resched_after = jiffies + msecs_to_jiffies(CONFIG_KFENCE_SAMPLE_INTERVAL);
> +       resched_after = jiffies + msecs_to_jiffies(kfence_sample_interval);
>         do {
>                 if (test_cache)
>                         alloc = kmem_cache_alloc(test_cache, gfp);
> @@ -608,7 +608,7 @@ static void test_gfpzero(struct kunit *test)
>         int i;
>
>         /* Skip if we think it'd take too long. */
> -       KFENCE_TEST_REQUIRES(test, CONFIG_KFENCE_SAMPLE_INTERVAL <= 100);
> +       KFENCE_TEST_REQUIRES(test, kfence_sample_interval <= 100);
>
>         setup_test_cache(test, size, 0, NULL);
>         buf1 = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
> @@ -739,7 +739,7 @@ static void test_memcache_alloc_bulk(struct kunit *test)
>          * 100x the sample interval should be more than enough to ensure we get
>          * a KFENCE allocation eventually.
>          */
> -       timeout = jiffies + msecs_to_jiffies(100 * CONFIG_KFENCE_SAMPLE_INTERVAL);
> +       timeout = jiffies + msecs_to_jiffies(100 * kfence_sample_interval);
>         do {
>                 void *objects[100];
>                 int i, num = kmem_cache_alloc_bulk(test_cache, GFP_ATOMIC, ARRAY_SIZE(objects),
> --
> 2.18.0.huawei.25
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220207034432.185532-1-liupeng256%40huawei.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN%3D0Q6s5WnKrWm4YXqSj-1rRsL2VTD_QJUfQdv_2nhf0Q%40mail.gmail.com.
