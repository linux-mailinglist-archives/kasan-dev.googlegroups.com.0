Return-Path: <kasan-dev+bncBCMIZB7QWENRBDPRU2FAMGQESFME6DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id C20E64131EE
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 12:48:46 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id y16-20020a929510000000b0024fca7e125bsf11971436ilh.17
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 03:48:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632221325; cv=pass;
        d=google.com; s=arc-20160816;
        b=r/vCIfH11TwvPw4pxOj0Dou5ZlvhV/9djrsPaaPvgRiKtnAmbIipAYvBvCnntmmNkE
         4rA+RNzKLejw9gc7wkag7QOyVeJLsDofr7hM0VsHc0vs0BCqmYIdcLG9awtuGIQbsg9E
         E5TIY37ty5TTBgWzflFV6mPwc6jiPiAYAQjBE9mFxnvhMVqeKsIppTCXXW5pGZI8uEKX
         Duwr/49X6JgLN4ntSMud7VztvAQasK1GaNifA6rcgI6IMnLDzihXtClrxWOcymjjOose
         8N36LsBsM+NoxARb08uh8iCETlV8a0YwmPsfOtrud9CqyHcvRQzpbKad1wg9SeICvbL2
         S4eA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LmW6V0YY0pKPGi73roOMhGc13tSLj7/DCJ7fLoZzZPY=;
        b=aG1IDClPN5b5MtOJtPSmQfF9ydTzymTv4q+3pSy2HaLQvvHvbfpZMUy0bx/7PeWY9N
         rgUXJGkZ5YxeMAE7oryxRKUGoh3nyTwPswQFvTFC9yWHUSYtzukA0N7VsqSWs7CGeaaB
         oFOg5aY1Ys07fxqFEh1fNnSfQxKf4wWJJzUkgkUylXPlydHWSveOdEOD82HD7/owsZkS
         3cgIGseEamBsdlj3Ylf6rWHPLgx6T/gkED1AcAf3VeNZINAcGdQe6nd1+BlsCFtLyvmz
         utJGLjqOCRPM2O8cIqQMr5Omf2BuuTT9PrZGuq5so4r/fq21u3Y5TmiR8T2HuaOFeitT
         fgtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nuqlgHgS;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LmW6V0YY0pKPGi73roOMhGc13tSLj7/DCJ7fLoZzZPY=;
        b=RqwdTxRrowR8J73nv1PSnTzg2n7kNvNPasX0Ew11HcMPFl1OgQqONYIiKWIPYq3CQe
         EMHW5PE8aqqXf7i9MShb5D9ZJ/fHaO2SnOBOP/95vLrHGWo9rWD7Yoz7vrxtS58OBw0Y
         TrWh7bjrUqIpdcSmJbMsfpY6F5WE34EtIaFQ6ZSaGv9bx21PfBM+VUS2PT9bmjU3naxI
         zsElKJNqhd2c6ai9zRQj70IIoP7h0521zuCtEurtRfhGvLM2em6ERsLj1STftCw2xYGG
         mk7vq1Xp9Qc6lWiYpvp3XyZCZmr5em7X/Xw/te5RE7PrwL1EBizYCOFLvzA0PV8sE3av
         S7Tw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LmW6V0YY0pKPGi73roOMhGc13tSLj7/DCJ7fLoZzZPY=;
        b=B9w6fLWyBG5N9bdktJRSdhC9xsCzjnkus7jbQPjxoKIvurifZtf4z3Rh81XCMCb1E+
         kAfGEvoXT4mssRVXXR7UM+chh6UdBaws3vsah7vxXUmkYyGOHWodjaIJO8PSuBCehR2E
         DLXsy9UY0pO3/pEclHPI3u/dx17Z0Q3648XyTmoICJQbnAX7qfMIQn62hQ7gxJDC11Jm
         enGcXZs4thWxkv2nB3m9jP/Vl7XT9dVff77Z9njW1EzKcaAgGtQRYqFYJB4R3UbpNmgs
         rQhxcgLVIiaDR1lGSxlhNN2yW+xNT5iVrz8zvUOB1jx7a9HK++8cJDn8LRxBNpj+Wvq7
         ryZw==
X-Gm-Message-State: AOAM532+n4KzuRR0n0UZVyL7qXLSrTspWSOkef3aBreopWZXPzsy0fJm
	N4uHHEXCtAv8pXnNYVog6ks=
X-Google-Smtp-Source: ABdhPJwt17RrBPouNnF2nRaMdElfLBUSVtlCGlaYP1AP9bRxWxmUzUBPpV0sGibDTRQNcBc4w2YG5g==
X-Received: by 2002:a05:6638:2189:: with SMTP id s9mr5252243jaj.73.1632221325531;
        Tue, 21 Sep 2021 03:48:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2163:: with SMTP id s3ls1463570ilv.9.gmail; Tue, 21
 Sep 2021 03:48:45 -0700 (PDT)
X-Received: by 2002:a92:de41:: with SMTP id e1mr21577370ilr.85.1632221325158;
        Tue, 21 Sep 2021 03:48:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632221325; cv=none;
        d=google.com; s=arc-20160816;
        b=gUSoqvRkLs/U2WwiNmlm755HSyS1N4XSg+8FreWVKqGNaQgc3mPfsqPhJmG/nwKQvV
         Xx+LqnTFKNtvn4DrPMIpjA/mFD8SElQb3e9WoWL5+FTNQFCKkjU6tVksfNRisdNp6KCc
         dDG8mmrV+oytgR5Moc5D40mT48GdbpUFTbHvQo3vQyBZiQziFMl5x6yQJYoqvXGhFwDC
         2V4kJDpSFfudHa5R5Mg211AuRnBFrS4HebZsqh3BiUdFLiFRmYeZ3T20DLjlUMqt+gt+
         nk38HbkpORLgMakAT1J5DGcQjo3pHwhCYs+V7DSPfGTnlj1aPCFyfJDM10v1PG5F0CAn
         xCiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uQD0VoNg7df5hqKOKWbdHthbGkqzCUgLIjjPJbYxGXM=;
        b=BJSFJAeE2UCO4T2yvpt1RjQVskrSGqqmHjhVcjUPQ5IkNEAjXuemR2AtJqvsIf7HFv
         ZChlUWXh1Hvtycr7qezKabNq37KY3MMMSI4yQVxOCYBbxXj6HNBTCca/YFrDo6b/NS/1
         fsWu6hK9InqNZeB5b+p6bkBkOphqb2hAlufFrcoI8eC2AMJQ2YWL8EnkHJ+qXA0GCB8o
         n2n5pimXkLcVy5m65GaLmDa8LPDckGLOurYTZ5+7fjqFBTXRsHy+21ZUa8igiVwGNyBb
         +gG5rdOJ0U4yMz5bnkEzTPPW19xUu57fDKJnKU07974BY14M2/KsxL30l95QXu8FFFC0
         Nkzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nuqlgHgS;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x234.google.com (mail-oi1-x234.google.com. [2607:f8b0:4864:20::234])
        by gmr-mx.google.com with ESMTPS id l68si276345iof.1.2021.09.21.03.48.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Sep 2021 03:48:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::234 as permitted sender) client-ip=2607:f8b0:4864:20::234;
Received: by mail-oi1-x234.google.com with SMTP id z11so2000937oih.1
        for <kasan-dev@googlegroups.com>; Tue, 21 Sep 2021 03:48:45 -0700 (PDT)
X-Received: by 2002:a54:4005:: with SMTP id x5mr3064072oie.160.1632221324643;
 Tue, 21 Sep 2021 03:48:44 -0700 (PDT)
MIME-Version: 1.0
References: <20210921101014.1938382-1-elver@google.com> <20210921101014.1938382-2-elver@google.com>
In-Reply-To: <20210921101014.1938382-2-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Sep 2021 12:48:33 +0200
Message-ID: <CACT4Y+bJ=i=i5eecERcAWMcZuYtU1587WEpRa=SH+bGvmoCayA@mail.gmail.com>
Subject: Re: [PATCH v2 2/5] kfence: count unexpectedly skipped allocations
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Jann Horn <jannh@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=nuqlgHgS;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::234
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, 21 Sept 2021 at 12:10, Marco Elver <elver@google.com> wrote:
>
> Maintain a counter to count allocations that are skipped due to being
> incompatible (oversized, incompatible gfp flags) or no capacity.
>
> This is to compute the fraction of allocations that could not be
> serviced by KFENCE, which we expect to be rare.
>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

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
> @@ -121,6 +123,8 @@ static const char *const counter_names[] = {
>         [KFENCE_COUNTER_FREES]          = "total frees",
>         [KFENCE_COUNTER_ZOMBIES]        = "zombie allocations",
>         [KFENCE_COUNTER_BUGS]           = "total bugs",
> +       [KFENCE_COUNTER_SKIP_INCOMPAT]  = "skipped allocations (incompatible)",
> +       [KFENCE_COUNTER_SKIP_CAPACITY]  = "skipped allocations (capacity)",
>  };
>  static_assert(ARRAY_SIZE(counter_names) == KFENCE_COUNTER_COUNT);
>
> @@ -271,8 +275,10 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
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
> @@ -740,8 +746,10 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
>          * Perform size check before switching kfence_allocation_gate, so that
>          * we don't disable KFENCE without making an allocation.
>          */
> -       if (size > PAGE_SIZE)
> +       if (size > PAGE_SIZE) {
> +               atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_INCOMPAT]);
>                 return NULL;
> +       }
>
>         /*
>          * Skip allocations from non-default zones, including DMA. We cannot
> @@ -749,8 +757,10 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
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
>          * allocation_gate only needs to become non-zero, so it doesn't make
> --
> 2.33.0.464.g1972c5931b-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbJ%3Di%3Di5eecERcAWMcZuYtU1587WEpRa%3DSH%2BbGvmoCayA%40mail.gmail.com.
