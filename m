Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMFPQ6JAMGQEGHRZGLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E2FF4E9B47
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 17:43:46 +0200 (CEST)
Received: by mail-ua1-x93b.google.com with SMTP id z9-20020ab02249000000b00352e93562b3sf4976706uan.15
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 08:43:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648482225; cv=pass;
        d=google.com; s=arc-20160816;
        b=VjlFz1U7NMAbxEH3rLqDOXM83OfWHbq598GuS3FQeC2e1x2FQuolQSyeA+Iyk1RTpY
         BejG0OPjSBoVitnTIR5Vrc0jtzGTVVwA5Am8/I1jI0ub8fEhhrjwbkSCdKGIpISXEjJr
         MLrw5oWA8UFGRrQvbu47ivnWxJqLczd1pR6BEivvI3nG6skivxaM3CARyy/TOuAif3Zd
         JlHR6F2fAMra+PdDUcBNPZQRojEKY/QOpEFCMelDesc6fDX5qJs3zKd3AdFotFNZ3UUP
         8sH7ES2dkHFElysec4Tg1xi/1tsJArjlXoRVMb8zqZfIAga1TOmlj1/ocLZET2bwTHZV
         jrUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MMjO05+qtRJnie0jb2s1cO2FALeLptRTLotCMbEsk7I=;
        b=G30Qu0g0P0PQ0vTLqL6KFRA7/JPSWe8qOR1nJXjQSc10zsASDV2O9o/FZaewYoKpk/
         sbka1hZa52Q951Oa0W7xjiSGQ16Qzpnn5ziiCrkozT6IzMIg6L72WqGlUFg4O0vUauab
         npT2xbMQNHlfUa+21UIDFMdSo/RHrcpCIxmQooi17BxKlvvmWJe5P/FyepxWcruTtAiG
         9Nsm27luJ4WMFsv8zGhofORETNlG0IWW5+NGG9sObdO+V/Q5H1D5XqkMh/USSrnkTAyj
         FzMMgZlxamznD7TFgmIAYhUk+UZew4kPVEBJ7iCcBatxdmDB6uk/C62NuKkFUI3iS1d7
         ilwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GIYTLtun;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MMjO05+qtRJnie0jb2s1cO2FALeLptRTLotCMbEsk7I=;
        b=q5U66JE6c8dFIwKDueZYlzk0p3b2a9utrw8wlQxCsX5ZKxUuWts1v9uaI4k5sUiNUn
         LIyaUrMIn1qrN+QIgyBt5iK/TshzH+/0rzJ92S6JPLt+1BcO5AmwFIqzLqIsj8B4dtLO
         tlduhgOCzyL+MpLSd5Jzef0piMHnRVNHc1Z2Ehn7QMIMPkzbXxihIsrDwrTjRGSh2FgW
         nyh/gRT6Vf8fWOoUXMoNShc+eh8n5A74gExQ1rGcj0chGOol2XX/6iyu67rqm/N4SMh0
         smjR1p0Kuu/vktIhZlYNhT61VydYfxN3cnrSoTPmjhNDBfNQX1UIdAKmCtNbBVakbvgS
         9GCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MMjO05+qtRJnie0jb2s1cO2FALeLptRTLotCMbEsk7I=;
        b=ofm6wICqxRPpgZFmgt+q7JSMj9NiK0BgpJw0qZEKAz9y/rhT1k5khUP7r8N+0is+gF
         /sPnIpvn5bIX26OlSFfO8G2/DwyCbtes9xFVfyamzJGOLcLM7Q07ZAZ6cZsMc5FbpR/w
         rmnLkqCOzVbYID6R8EICMFwapO7gyMpLs1sH/d/t1Wqlax0aOFaGgCYyMovsUjUZ9Q2L
         VSwok7RizBkiSmPEzWxvxCHL0kaApWTIV87DP//ycOQw+goEz2VrPUetTlEPJ8DyQZ73
         TrNMShcLEH0IYsWxR/ABo30WKyC1kLvTkgA9S2B7zNmqe1hmioGRm2LpGTvqsfTmQUy0
         zOqQ==
X-Gm-Message-State: AOAM530RvaLtRlCRvatF+OtNUioxRA2772u9ObhGMHsMeB4ZNtjF4Blb
	QsQz7LbWmCrrmZ/Bsz6vtdk=
X-Google-Smtp-Source: ABdhPJyIYtTrPr5rVnUUCGNk+ncttTKcRW+iXPAd/glFx21ZZw/nyPBF9NqIfP+X/P46dU0KH9fDFg==
X-Received: by 2002:a05:6102:d8c:b0:325:b176:77c1 with SMTP id d12-20020a0561020d8c00b00325b17677c1mr1932254vst.8.1648482224946;
        Mon, 28 Mar 2022 08:43:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:9141:0:b0:343:40df:1cdf with SMTP id t62-20020a1f9141000000b0034340df1cdfls348430vkd.1.gmail;
 Mon, 28 Mar 2022 08:43:44 -0700 (PDT)
X-Received: by 2002:a05:6122:2005:b0:33f:dc0c:8199 with SMTP id l5-20020a056122200500b0033fdc0c8199mr9437380vkd.21.1648482224370;
        Mon, 28 Mar 2022 08:43:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648482224; cv=none;
        d=google.com; s=arc-20160816;
        b=RArTKQSwcJEadbQJ1gYTHVOp4XXdLRNQTtJ5Hxs/6OAsCTY0S4U44WbtoOn9R8d24R
         jgt6lA1IPNnGPH4kVEiMezQHD2kukQ+2GfEzKX/ldwKlAjwjrDo0+RkTPBWDWQAe1aCU
         eR91z6XeDIp+4so470erMNquNHNuq/Ho64QBJquj53wWyQ0TSDdXS+HRC9d/aE2QWCXc
         vTJH4gKRlWlvUQrfoQdQ/PeBsj3izzApoFbzek+aZJn9ZH7x2SehfU+EFQTkGe6GTZ7M
         bt0V57DIMurwqwfZWgF1MKRPWD5vZxlLAHzbyJqy5iJLwsYvKPhY3i+musrlR2dAaF0t
         wCuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JLAMImTBODJ6p1BQ28mgm1zYhXSzYUbNlmQ348cuLdo=;
        b=ybx8yyq3nuvzUau8SuYACBJYfkTe24t7ERYTn5h3+gchp4t1yFNwnA7NxA48hhkaoO
         CBnQDskwYDE5B6EfYeuuFtFEyM0VGMcRE1ud2cIKV6gNY1Uw4EpMrAue8qcVuALG9U2i
         P/LB8E+H8jKqek/O559PDx8oKpoZzVEH9hwkCE2Ka3KSqmdGd5LiiWkIplfeatwg+PDU
         ijnEkbgS1sVPwxOEpCwIldCeNMeiyBlyVpBCcnRSHhO2QIaYcwy8W7/uAbCJvKPIETmX
         QDMIs4pOK4w9cEIwQNYuVQQokqzgn2z9rW8WydJn2ex8mzKJL3xl328ABm1au3v7B2fF
         4/KQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GIYTLtun;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id v6-20020ab036a6000000b0034b372f8c0fsi836663uat.2.2022.03.28.08.43.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Mar 2022 08:43:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id e203so17895891ybc.12
        for <kasan-dev@googlegroups.com>; Mon, 28 Mar 2022 08:43:44 -0700 (PDT)
X-Received: by 2002:a05:6902:24f:b0:62d:69d:c9fc with SMTP id
 k15-20020a056902024f00b0062d069dc9fcmr22422814ybs.87.1648482223855; Mon, 28
 Mar 2022 08:43:43 -0700 (PDT)
MIME-Version: 1.0
References: <20220328132843.16624-1-songmuchun@bytedance.com>
In-Reply-To: <20220328132843.16624-1-songmuchun@bytedance.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 28 Mar 2022 17:43:07 +0200
Message-ID: <CANpmjNO=vMYhL_Uf3ewXvfWoan3q+cYjWV0jEze7toKSh2HRjg@mail.gmail.com>
Subject: Re: [PATCH v2] mm: kfence: fix objcgs vector allocation
To: Muchun Song <songmuchun@bytedance.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	duanxiongchun@bytedance.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=GIYTLtun;       spf=pass
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

On Mon, 28 Mar 2022 at 15:28, Muchun Song <songmuchun@bytedance.com> wrote:
>
> If the kfence object is allocated to be used for objects vector, then
> this slot of the pool eventually being occupied permanently since
> the vector is never freed.  The solutions could be 1) freeing vector
> when the kfence object is freed or 2) allocating all vectors statically.
> Since the memory consumption of object vectors is low, it is better to
> chose 2) to fix the issue and it is also can reduce overhead of vectors
> allocating in the future.
>
> Fixes: d3fb45f370d9 ("mm, kfence: insert KFENCE hooks for SLAB")
> Signed-off-by: Muchun Song <songmuchun@bytedance.com>

Reviewed-by: Marco Elver <elver@google.com>

Btw, how did you test this?

Thanks,
-- Marco

> ---
> v2:
>  - Fix compiler error reported by kernel test robot <lkp@intel.com>.
>
>  mm/kfence/core.c   | 11 ++++++++++-
>  mm/kfence/kfence.h |  3 +++
>  2 files changed, 13 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 13128fa13062..d4c7978cd75e 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -555,6 +555,8 @@ static bool __init kfence_init_pool(void)
>          * enters __slab_free() slow-path.
>          */
>         for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
> +               struct slab *slab = page_slab(&pages[i]);
> +
>                 if (!i || (i % 2))
>                         continue;
>
> @@ -562,7 +564,11 @@ static bool __init kfence_init_pool(void)
>                 if (WARN_ON(compound_head(&pages[i]) != &pages[i]))
>                         goto err;
>
> -               __SetPageSlab(&pages[i]);
> +               __folio_set_slab(slab_folio(slab));
> +#ifdef CONFIG_MEMCG
> +               slab->memcg_data = (unsigned long)&kfence_metadata[i / 2 - 1].objcg |
> +                                  MEMCG_DATA_OBJCGS;
> +#endif
>         }
>
>         /*
> @@ -938,6 +944,9 @@ void __kfence_free(void *addr)
>  {
>         struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
>
> +#ifdef CONFIG_MEMCG
> +       KFENCE_WARN_ON(meta->objcg);
> +#endif
>         /*
>          * If the objects of the cache are SLAB_TYPESAFE_BY_RCU, defer freeing
>          * the object, as the object page may be recycled for other-typed
> diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
> index 2a2d5de9d379..9a6c4b1b12a8 100644
> --- a/mm/kfence/kfence.h
> +++ b/mm/kfence/kfence.h
> @@ -89,6 +89,9 @@ struct kfence_metadata {
>         struct kfence_track free_track;
>         /* For updating alloc_covered on frees. */
>         u32 alloc_stack_hash;
> +#ifdef CONFIG_MEMCG
> +       struct obj_cgroup *objcg;
> +#endif
>  };
>
>  extern struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
> --
> 2.11.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO%3DvMYhL_Uf3ewXvfWoan3q%2BcYjWV0jEze7toKSh2HRjg%40mail.gmail.com.
