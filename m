Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4GDWGFAMGQEFDLPZFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id 64531415CA2
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 13:16:01 +0200 (CEST)
Received: by mail-ua1-x938.google.com with SMTP id u10-20020ab0702a000000b002b825725ef6sf2074941ual.8
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 04:16:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632395760; cv=pass;
        d=google.com; s=arc-20160816;
        b=0VDJRTZdf97Jc6BgttUvn/bbuFV4g1wq02kgYH1D2cgLwN4MwtvNbgp90pNcogK1vc
         9dXGHVjO88N5RbWgyY4caNzn9Oh24eJ01nkWSjFZy7IEgTYbWw3KgrvXoQboFMcruf40
         xcLb2z0/9htE6HtFtdxwS5rSrJBKeHqKuP4d0DpXugRLRmyJkUxjoS1P8oYZ73+MMwi3
         ReVLU92FZVgOuW6Wqcn6G7cbJckZCZ1ncjlV1QDxV6nbWX6azt9DK1Fy4muQlYc2f8sa
         8hezgutiY8O4XYBap9F4BVAryCjfAEpvKvirnJGPEaxxnNf8GlRodMZ0+JwaM0goQBs5
         v9BA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6KQnfvE4yp8KtRfTetbUqmI0ghqy+pNKeURO9MDlwK0=;
        b=A8vcYsxeUZykd5OsMstRwXNrqeB+wdkeHNVFYRsBds4hFTHnVCN3AaZw6BnAcRVtfM
         mDpshlk4JX/Q561hcMgBTO/0JJK0MKD2gYODfMVkLR+hsyVA3myDN68G/rVMAv0fjEKC
         IGI/S1rOMr5iDbO4mCepfi2/A41MCQXHV/dtmDHoeMUj+8rktsm61+VaBS81v91ObpNb
         8Y5OgzI+pmhE7Jy5M2cZ/EZGD9EispydCLY591hbtOW+mh6sdnIKPpv/QLATTUUHRDff
         2CYkqdGiPRX/Ushp0PdfIRDaLi3eIV867QVflKYyOy4gPasIkultGpuTwaUype16t56w
         uUQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=piWpDsjg;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=6KQnfvE4yp8KtRfTetbUqmI0ghqy+pNKeURO9MDlwK0=;
        b=B52ut8pwXtybuiI8T9OPXFKzIWlK7LANKZzeJqsEQS6klfd5QwIqrXwCQm8AxlFp2N
         03vF2uscRGD4+vlO9v44LtqRRCjrJDpgjKUcT0jAjIcXIZtbKBFXJ+IuAIepXalHwKH2
         P3RDRIrb0F67N8wh5PWFX1+pBJLO5ODNdHE9QtFv/On5lkwViQAFoJYlGei2MtEoPrlk
         /cN36XbO/y37ZJSH37LBS0SMYzHMJUCwBAOKsplISK3H3kWgi746hWi2EswGsRxKbyO4
         cDO+fccb9u7szLp/uSu1WdkaILuy2X5Ezr9MjcvchF8R1rseIWSjJ25ZZGteXkYjCoVR
         rD5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6KQnfvE4yp8KtRfTetbUqmI0ghqy+pNKeURO9MDlwK0=;
        b=uRBdElIdOMMFrRihDxbYrWjrXBnpS8a30i3VK7Z+5GEiLyMA06BbbdjKEJrcuW9cYP
         sTG4M+G6mdv4Mm+hvtrUuzr3fk0k+GbKFDWxlPjtNGG1JaMgQDDjQ18PXbyUDV1l7d1F
         UZzv5MtbvzXe4f5QY9bEa6GIojtkCaKYPntvNdUa28bGFETRIu/TJP7NOepv6J6T7ICx
         WqN2c/6JXc3RGabeV08jt8oijMECDJY6sU73dpnGOkgNCThV+7dBgzyXkvaFBssZ71u0
         lZDUMKs8LZS8Q33X5Dnw+pb8ZhO8/80erIFtGrRXFZVGTDQaLMVzEowslvfqFUdtzPve
         hwGw==
X-Gm-Message-State: AOAM531E5WkZLRxCmUkgLq+LwEzf31GceGLysMjOh+YvbtnUZYisYaye
	eo4xciyoXb336DSenLkN1Pk=
X-Google-Smtp-Source: ABdhPJywgJI0MTj9P2PgruqaaY8Tc8upJdzWLECwOq4wwSISFiWZBsbNj3YvLZ5HpSsWeIg3CSux9A==
X-Received: by 2002:ab0:3b92:: with SMTP id p18mr3446314uaw.134.1632395760559;
        Thu, 23 Sep 2021 04:16:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:16c7:: with SMTP id 190ls482934vkw.9.gmail; Thu, 23 Sep
 2021 04:16:00 -0700 (PDT)
X-Received: by 2002:a1f:3a4b:: with SMTP id h72mr2515948vka.19.1632395760095;
        Thu, 23 Sep 2021 04:16:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632395760; cv=none;
        d=google.com; s=arc-20160816;
        b=j8+TudxJMITIQADV147z21GaA0bL+npYhvfC8PgM6FnFmgQVOIcgaed+THO3+XCiv5
         A9rzvdBfRA+pbu8YRJpUEHj2VXwo5O580CSYr1zFFVFQym9RdGTg+NDT0mWcOXCJxFvr
         lbXpkzUoULowFnGcx9c66sBHMYG07PqgwcbrmvDHNBDrCkmo1Z5KJAi1hSJ2gA9Dql0h
         +6aMvkRxU/WokaKZz9P36u1h59rdbD78UMEgETJeDdaPDovCoRQhk4KL1hqa7QnXCmR/
         iEt8ptqmbe8274XusPFpZw+vwevLFXmPOaZhP+WvlKGaPNb+AiJzKPGHzCMx/1slWY3O
         I/PQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WxWyZjqzKABxFGtDm2TtL1V2QPdgvK9G3mFsSj6IZsc=;
        b=R7/uwe65wWbSFB31+g0KlNaWBO43IaweTpCrLItRnaGUK5gk1U5igUkmgIBUB73vdu
         yD2qLDIeGf/xkZhxY+yvuyV1U4Wmqszgbj0h4/saiB/i93OG5OVC0GtLeP2UhpxwlDoD
         TJmoN4ejm3YkSLeIrUM6RTCopp0xoq5egsW4e48AYyjyOuX7yKT5oVfGl1E85mkDK16e
         DIXSZqkowSctXftxf3sXqIT3AD8Oval46qF6YDgljHdJ6HJfN4IWVxETE5fHcKYWloaE
         bw3ZZji8G8d90KNsPN4re0UE82Pth6uDT+FJKFq3YBvSu6/OpEWdwfoHAEHJuF3eqTtv
         3dpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=piWpDsjg;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x732.google.com (mail-qk1-x732.google.com. [2607:f8b0:4864:20::732])
        by gmr-mx.google.com with ESMTPS id 4si353919vke.2.2021.09.23.04.16.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Sep 2021 04:16:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as permitted sender) client-ip=2607:f8b0:4864:20::732;
Received: by mail-qk1-x732.google.com with SMTP id f130so20686504qke.6
        for <kasan-dev@googlegroups.com>; Thu, 23 Sep 2021 04:16:00 -0700 (PDT)
X-Received: by 2002:a37:b483:: with SMTP id d125mr4023411qkf.362.1632395759497;
 Thu, 23 Sep 2021 04:15:59 -0700 (PDT)
MIME-Version: 1.0
References: <20210923104803.2620285-1-elver@google.com> <20210923104803.2620285-2-elver@google.com>
In-Reply-To: <20210923104803.2620285-2-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Sep 2021 13:15:23 +0200
Message-ID: <CAG_fn=Wyd3-yxd3vzX82Q4iTApJr_CsG-gmEq1KenmYYCypP5g@mail.gmail.com>
Subject: Re: [PATCH v3 2/5] kfence: count unexpectedly skipped allocations
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Jann Horn <jannh@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=piWpDsjg;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::732 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Sep 23, 2021 at 12:48 PM Marco Elver <elver@google.com> wrote:
>
> Maintain a counter to count allocations that are skipped due to being
> incompatible (oversized, incompatible gfp flags) or no capacity.
>
> This is to compute the fraction of allocations that could not be
> serviced by KFENCE, which we expect to be rare.
>
> Signed-off-by: Marco Elver <elver@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Alexander Potapenko <glider@google.com>

> ---
> v2:
> * Do not count deadlock-avoidance skips.
> ---
>  mm/kfence/core.c | 16 +++++++++++++---
>  1 file changed, 13 insertions(+), 3 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 7a97db8bc8e7..249d75b7e5ee 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -112,6 +112,8 @@ enum kfence_counter_id {
>         KFENCE_COUNTER_FREES,
>         KFENCE_COUNTER_ZOMBIES,
>         KFENCE_COUNTER_BUGS,
> +       KFENCE_COUNTER_SKIP_INCOMPAT,
> +       KFENCE_COUNTER_SKIP_CAPACITY,
>         KFENCE_COUNTER_COUNT,
>  };
>  static atomic_long_t counters[KFENCE_COUNTER_COUNT];
> @@ -121,6 +123,8 @@ static const char *const counter_names[] =3D {
>         [KFENCE_COUNTER_FREES]          =3D "total frees",
>         [KFENCE_COUNTER_ZOMBIES]        =3D "zombie allocations",
>         [KFENCE_COUNTER_BUGS]           =3D "total bugs",
> +       [KFENCE_COUNTER_SKIP_INCOMPAT]  =3D "skipped allocations (incompa=
tible)",
> +       [KFENCE_COUNTER_SKIP_CAPACITY]  =3D "skipped allocations (capacit=
y)",
>  };
>  static_assert(ARRAY_SIZE(counter_names) =3D=3D KFENCE_COUNTER_COUNT);
>
> @@ -271,8 +275,10 @@ static void *kfence_guarded_alloc(struct kmem_cache =
*cache, size_t size, gfp_t g
>                 list_del_init(&meta->list);
>         }
>         raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
> -       if (!meta)
> +       if (!meta) {
> +               atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_CAPACITY]);
>                 return NULL;
> +       }
>
>         if (unlikely(!raw_spin_trylock_irqsave(&meta->lock, flags))) {
>                 /*
> @@ -740,8 +746,10 @@ void *__kfence_alloc(struct kmem_cache *s, size_t si=
ze, gfp_t flags)
>          * Perform size check before switching kfence_allocation_gate, so=
 that
>          * we don't disable KFENCE without making an allocation.
>          */
> -       if (size > PAGE_SIZE)
> +       if (size > PAGE_SIZE) {
> +               atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_INCOMPAT]);
>                 return NULL;
> +       }
>
>         /*
>          * Skip allocations from non-default zones, including DMA. We can=
not
> @@ -749,8 +757,10 @@ void *__kfence_alloc(struct kmem_cache *s, size_t si=
ze, gfp_t flags)
>          * properties (e.g. reside in DMAable memory).
>          */
>         if ((flags & GFP_ZONEMASK) ||
> -           (s->flags & (SLAB_CACHE_DMA | SLAB_CACHE_DMA32)))
> +           (s->flags & (SLAB_CACHE_DMA | SLAB_CACHE_DMA32))) {
> +               atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_INCOMPAT]);
>                 return NULL;
> +       }
>
>         /*
>          * allocation_gate only needs to become non-zero, so it doesn't m=
ake
> --
> 2.33.0.464.g1972c5931b-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWyd3-yxd3vzX82Q4iTApJr_CsG-gmEq1KenmYYCypP5g%40mail.gmai=
l.com.
