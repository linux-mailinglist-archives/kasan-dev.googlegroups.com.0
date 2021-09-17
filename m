Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXNGSKFAMGQEY6MXV4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DC0140F8D2
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 15:08:47 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id n15-20020a170902e54f00b0013b7a095210sf5000169plf.15
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 06:08:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631884126; cv=pass;
        d=google.com; s=arc-20160816;
        b=xUBY/e77qe59jqeTDp7I8uGDNaJIR7s8LLbwjydLRh7WwQzLz9oaieh1vNwn0J2iZI
         QZBJ8P5/aSVjF6Z57pCyTYGusVsQi8AK9wZL7S7HuWBZ6BcKKZ9CbPKMkBLRh+uTau7Y
         wakhZZWjRfX3tS49AjoEMUNieQZMXSq6hrQrSKNXv2AHJ6wconyCpbcNhcY/Sm+18N6a
         29git42e0hte+QHA5gYhDF/XIotC8KkJiYptylLNHzu/R9QMZCUI8f0tCUgMuwMpJyC1
         T1K1f8P0yDWPuWW1AlH1+vvHFdnpzlXAoc1a1xn89V9idSe4arBWqforELiqNDbJku1H
         d3tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IUViDI3bq/dyp83Cv9bxGrbrXhXddgsVh4vbDAVgUdk=;
        b=OLR+aRNW0AbS5vD13pnrGLEXVMlRwmgo9dsT26mpTX3wsZ2T3gEeYDG4jKWZiuqXtU
         y2pheHLUuFV8QFSdwgLlRf0xodc6b+OBSRtIhqNhsH84xOd7pBG3dZnEmCCBaYWBRQ3v
         segMMxTX07WuE50hDsGHic5584fz/n3tNT9OPfKRZe66rLE9HRcbdI77ny/2vOv6N9dM
         d5g9VXHTRqFzSoaZYYFzqAlXdu5nuwfg9AxOk2eSs0DYOOos3SYdUWVvaIL0lfbPIY/S
         NVEwVk9uohCt3zr09nfR5dHQW4CAGTzukPY4WR3NOmNDAY2AiTH0lEUhE8a8uD66cvDj
         EdkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DgjGrVN0;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IUViDI3bq/dyp83Cv9bxGrbrXhXddgsVh4vbDAVgUdk=;
        b=Vzg4MKarZbbFwbGGFxQEIn8AmxDWB2LUmOmR6hlqC/+9SRU2nN2PjqbNm/XsfNnbLW
         VDnsL11COCqtNaTsMCgOjBChMA5rrE5coRBEy+S3vDiu3/NFFfVmB1iRtPCp2m5urmWN
         K3WxnbpDr54IZRsk25tcHJJEGSDLYqFvavN3ywLITSQZh+uxwCjISp4aTE5az9nCn4xY
         LLkU8d5UHEdLIrCoPv+9oRkfDKSb2GoyI97PZBnF7u5FERr4hx4UivOQE3SUvi5WGPKU
         Wmz/83m3NA+bhOq0tpwx/7774vFYBL76+fVgge74nG3rv68IUeCVWAxLhXtxhKz/LDTy
         Wp6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IUViDI3bq/dyp83Cv9bxGrbrXhXddgsVh4vbDAVgUdk=;
        b=zgwaDVkv1E1/6Ixaqt5zVespVffQE8ayz9VwIsgc1BTzs9KdzM0jiVbBtU3TrJnLCn
         JIyvc2hOAPBHV+l49T82wiaL8GQxxm3u/x9lNzqJjb+pwZKOt51ZQvdSU0A3d8CvxJgz
         KfFBOkNRxdjw+fbq5wD4Ev4d5LlOHAoufRONplhzGsjuHnc6Nn9a1QQfix+n6R/+54jO
         tWwG2UYfjOlxDaOuqY8SkhxMAVtt9oAkhhmmkQ/oYAg6C70BsywU+pkcmE9Ju1ddzByg
         SKX59FS7jBLjzA78QpngSqniiSu1ojwlQmVs7w53VIUL+nGmpvvU28HubwEjC2zxcDFT
         KjAg==
X-Gm-Message-State: AOAM532HhX4roEbblDCxUVJ+WIhNE/pn8OvR7cdyHbQ/6EzaqxAlvJIM
	KueXEgJHHw4WAMoigt4Db+I=
X-Google-Smtp-Source: ABdhPJxBY+fvzB/a8UCXtoFSf26Uf/EbAm98d6iG4WXUrnZ6ne5JzyaCGoqRdzNV4QS6wmZavAI9WA==
X-Received: by 2002:a17:90b:17c1:: with SMTP id me1mr21538436pjb.28.1631884125987;
        Fri, 17 Sep 2021 06:08:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3842:: with SMTP id l2ls6734677pjf.3.canary-gmail;
 Fri, 17 Sep 2021 06:08:45 -0700 (PDT)
X-Received: by 2002:a17:90a:b105:: with SMTP id z5mr20627343pjq.64.1631884125305;
        Fri, 17 Sep 2021 06:08:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631884125; cv=none;
        d=google.com; s=arc-20160816;
        b=lEeX03zXuppJXXVLZ0u1jGuOb6B6r9YzohXxkPaJ7tmN93hdbO1X38OiEdSrKYXF7L
         4b0xRDj7riMCtGgR81VxGtidWuwP4ClT8kNQCmCEhfVoqOgTx+u7NlVwH/L3c+A4GILC
         teq2RPp4iNESjTEaj/Bp+uoazm3r7jQRa8uaEBT2t+6GMtzqmQm9L1SdRQbJSh2tXpcK
         k9u5QuTcJFbd6xCHDFgHovI9WmiPehOelOO+hk4JGx/SWE7bHX1h7Gs/R7QBWI3VC/iK
         auuLYdFiplc1U0WfFOI+sJxSXz/YPOxq01130deKO98wPfUvXiDY4M3BpkYXTq9diMXZ
         uImQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VQPtyu3eXHipP/z9ZsA4RP4v90HOcQfM654JXLLWBSI=;
        b=CX46kuSFWOlqH3dk5DUTke0pn5EtrKXyD+5hjN7kAKxUa0a4WPAuANPtNSSqZgE2g6
         kvLWdR1w4A7CsdrOL4D4MywneHx3QRuMeQVGT3VktfKqJM8aB3tFRPg6qsfxGlMAeQ+K
         2cH9LMDFVVXx46YAj5xGq6+Za7b6WGUT4iuN9tStbiCIcSUjN4gVoffpAlEvsG8gYeQH
         /uLGgSryueqy26E8BBt79tSAd0+QsuXTUVvYF92NTl4kioqesz1Ks34KCBCxiOPyAEBS
         7ZhIugS2nru09dCxXHmB7X03gUmbIT1W1E/5wdTULHIgjtYp49WWv5pTFG72wQi752pO
         nefA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DgjGrVN0;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2e.google.com (mail-oo1-xc2e.google.com. [2607:f8b0:4864:20::c2e])
        by gmr-mx.google.com with ESMTPS id y10si280148pjf.2.2021.09.17.06.08.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Sep 2021 06:08:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2e as permitted sender) client-ip=2607:f8b0:4864:20::c2e;
Received: by mail-oo1-xc2e.google.com with SMTP id l17-20020a4ae391000000b00294ad0b1f52so3161423oov.10
        for <kasan-dev@googlegroups.com>; Fri, 17 Sep 2021 06:08:45 -0700 (PDT)
X-Received: by 2002:a4a:7648:: with SMTP id w8mr9019980ooe.0.1631884124392;
 Fri, 17 Sep 2021 06:08:44 -0700 (PDT)
MIME-Version: 1.0
References: <20210917110756.1121272-1-elver@google.com> <CACT4Y+Zzxo19YH-tFOPHGJ25zP=pdjSSjzjQNZTG62bCjZgz3w@mail.gmail.com>
In-Reply-To: <CACT4Y+Zzxo19YH-tFOPHGJ25zP=pdjSSjzjQNZTG62bCjZgz3w@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Sep 2021 15:08:32 +0200
Message-ID: <CANpmjNMWX1QYKHmK4opxPH92QhF+HL5E9=5b1Tx_9g0LStio-Q@mail.gmail.com>
Subject: Re: [PATCH 1/3] kfence: count unexpectedly skipped allocations
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DgjGrVN0;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2e as
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

On Fri, 17 Sept 2021 at 14:58, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Fri, 17 Sept 2021 at 13:08, 'Marco Elver' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > Maintain a counter to count allocations that are skipped due to being
> > incompatible (oversized, incompatible gfp flags) or no capacity.
> >
> > This is to compute the fraction of allocations that could not be
> > serviced by KFENCE, which we expect to be rare.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  mm/kfence/core.c | 20 ++++++++++++++++----
> >  1 file changed, 16 insertions(+), 4 deletions(-)
> >
> > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > index 7a97db8bc8e7..2755800f3e2a 100644
> > --- a/mm/kfence/core.c
> > +++ b/mm/kfence/core.c
> > @@ -112,6 +112,8 @@ enum kfence_counter_id {
> >         KFENCE_COUNTER_FREES,
> >         KFENCE_COUNTER_ZOMBIES,
> >         KFENCE_COUNTER_BUGS,
> > +       KFENCE_COUNTER_SKIP_INCOMPAT,
> > +       KFENCE_COUNTER_SKIP_CAPACITY,
> >         KFENCE_COUNTER_COUNT,
> >  };
> >  static atomic_long_t counters[KFENCE_COUNTER_COUNT];
> > @@ -121,6 +123,8 @@ static const char *const counter_names[] = {
> >         [KFENCE_COUNTER_FREES]          = "total frees",
> >         [KFENCE_COUNTER_ZOMBIES]        = "zombie allocations",
> >         [KFENCE_COUNTER_BUGS]           = "total bugs",
> > +       [KFENCE_COUNTER_SKIP_INCOMPAT]  = "skipped allocations (incompatible)",
> > +       [KFENCE_COUNTER_SKIP_CAPACITY]  = "skipped allocations (capacity)",
> >  };
> >  static_assert(ARRAY_SIZE(counter_names) == KFENCE_COUNTER_COUNT);
> >
> > @@ -272,7 +276,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
> >         }
> >         raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
> >         if (!meta)
> > -               return NULL;
> > +               goto no_capacity;
> >
> >         if (unlikely(!raw_spin_trylock_irqsave(&meta->lock, flags))) {
> >                 /*
> > @@ -289,7 +293,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
> >                 list_add_tail(&meta->list, &kfence_freelist);
> >                 raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
> >
> > -               return NULL;
> > +               goto no_capacity;
>
> Do we expect this case to be so rare that we don't care?
> Strictly speaking it's not no_capacity. So if I see large no_capacity
> numbers, the first question I will have is: is it really no_capacity,
> or some other case that we mixed together?

Hmm, true. I think we can just ignore counting this -- I'd expect some
bug-storm for this to become likely, at which point the system is in a
pretty bad state anyway (and we see bug counts increasing).

I'll remove this one.

>
>
> >         }
> >
> >         meta->addr = metadata_to_pageaddr(meta);
> > @@ -349,6 +353,10 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
> >         atomic_long_inc(&counters[KFENCE_COUNTER_ALLOCS]);
> >
> >         return addr;
> > +
> > +no_capacity:
> > +       atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_CAPACITY]);
> > +       return NULL;
> >  }
> >
> >  static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool zombie)
> > @@ -740,8 +748,10 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
> >          * Perform size check before switching kfence_allocation_gate, so that
> >          * we don't disable KFENCE without making an allocation.
> >          */
> > -       if (size > PAGE_SIZE)
> > +       if (size > PAGE_SIZE) {
> > +               atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_INCOMPAT]);
> >                 return NULL;
> > +       }
> >
> >         /*
> >          * Skip allocations from non-default zones, including DMA. We cannot
> > @@ -749,8 +759,10 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
> >          * properties (e.g. reside in DMAable memory).
> >          */
> >         if ((flags & GFP_ZONEMASK) ||
> > -           (s->flags & (SLAB_CACHE_DMA | SLAB_CACHE_DMA32)))
> > +           (s->flags & (SLAB_CACHE_DMA | SLAB_CACHE_DMA32))) {
> > +               atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_INCOMPAT]);
> >                 return NULL;
> > +       }
> >
> >         /*
> >          * allocation_gate only needs to become non-zero, so it doesn't make
> > --
> > 2.33.0.464.g1972c5931b-goog
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210917110756.1121272-1-elver%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMWX1QYKHmK4opxPH92QhF%2BHL5E9%3D5b1Tx_9g0LStio-Q%40mail.gmail.com.
