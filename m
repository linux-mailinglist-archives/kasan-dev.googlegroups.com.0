Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPOR2KGAMGQENG5DJTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 17F07454189
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 08:01:19 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id t199-20020a4a3ed0000000b002c296d691c4sf1197826oot.8
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 23:01:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637132477; cv=pass;
        d=google.com; s=arc-20160816;
        b=TaEQh0PhL36mxqObbqH9bQ5wMRAMIREz6zrImmz81pWGPii7pqr1LAVQsKhsvZgBxU
         L3qcoaZf25IsNorKCIsE81bH48TqEthKQBL7XXcPWn0JFZUzH3jngW1WVFCB+KmJb7CA
         6pfHJ2IMMd2omlsL2GaYuyCN1YAsrmkrYWJEJdHmWIfNdidddTBDyy+tPA9rn3DJFHqX
         7BHn+QOvksHXAwgPQkg1pOz9vo2WvTTJcJUnreu8SWyKG99XkhvEIltkucwSnc2v9dLj
         vpBghuLPLuJT6jMrcH+StyVIy6QdtAlsQWpyQAQh2FAjdKIdzihH2lASEF9FyLTDe2GF
         WqqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Pm9/3a35puvh2wLbrPMUf3+xdQvatdzVCYfPI1eKO6Q=;
        b=FC2MHU1b1ZcsbFdyPbj+in8r2KU5DQWmZlpWWmWL1vBwksHt3c6OwUGuibza0inkwh
         83xE0y2gBrFV9qfue9/LUYAyDBgj1nLHTnyYD+cAcpF3HVTg2AdvpAtJHbBQD4RQgNR/
         TzvHAucLoX2gpgyjUtxNOLPLOf4va12Kh+Efwi0KzXI4T7J/0Sbu1ybHMzgmDUq0Ky5u
         LfpL7RdrlcUmwxzGWt6VrvK5xAk54ddswqooRytIQjsA9vuXJGyBNGsOLLDmxVAiBYU+
         Bu4KmWy9oqnEjwN1ARAO4M8JOhnRZtKO2xhjhN5wFmr/5S4AnD30hiGncDYh7zHbXNQ5
         I1sg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hWSf2ty4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pm9/3a35puvh2wLbrPMUf3+xdQvatdzVCYfPI1eKO6Q=;
        b=KkmeiFG8cqYD6OKDZvmaV6q1NkqWnxgzgQLrWWiXW4kybVWtlaNmD3k5bcZCEusqTx
         2f536CdXIJLJy3kENI80brND2416JqqOCVUl7AUh8kDmWkKNT2wvpqUw5NIL9VhET2fq
         dAyH8Rg1qf3KbDrhpEZiVU9UmUW9JbccqstbC7JTeRPxUMTGphqBDEq+1/LYN+OedasZ
         +Sn+KUmM4rRR77WeqzGWuxmyeRz3bJ7N1dmDYcfK9BlsTmtVfZizq2P/ILvET8oP4Wlg
         xUztQLnASgucPcNexmSLoEMGUdJ2aENwusdKZLBk06Ppj1dRRxrST4ba3ztMwDtt/2/h
         r/kQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pm9/3a35puvh2wLbrPMUf3+xdQvatdzVCYfPI1eKO6Q=;
        b=o8iZQPMMZ+lC92PGOGrL3b5TjVOQDxvo+v4YniSaZgkBqFSzsn3kfmApZSJIKkOBEp
         5ProG88O1jQN82C+/iC0COel7Z5NVXyQxMQ/+3DqaNp+0L+ynXe3lMm+U38JHheLAvz5
         BmJbP2lw88qt/tETEYZ52m1CkIV7GctgdJUljlvbexeZAKWBn1hs4O4UNNntS4r7COS5
         KjcI/SYpbMvuvmbASO84tBAYXP4VqybxVYh42sweGM7ZnvE2yZM9J/IePChcjfYTS4uj
         iMkFI5gMJxCbeTiM4vxybYkWIH9o9wlkqCKnIyBGeJvDZf8Dc+a2gIN6B8WoaSXu6KUD
         wd3A==
X-Gm-Message-State: AOAM532SjPoKnHrLvtyTYGmG+DGBKKie/j7EqZ0Uex0GoS3q52JZHYlN
	4ebbOTjVzn3F0jWm88X9sEE=
X-Google-Smtp-Source: ABdhPJzRVE+V7SVWzFiD+wlwP5R7tY7hgMmGl+/mFym7V/7BBiJxyzY7OsbtkSIeeLkhs52tZDibUA==
X-Received: by 2002:a05:6808:1a83:: with SMTP id bm3mr12539627oib.173.1637132477619;
        Tue, 16 Nov 2021 23:01:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:3116:: with SMTP id b22ls7094725ots.3.gmail; Tue,
 16 Nov 2021 23:01:17 -0800 (PST)
X-Received: by 2002:a9d:6216:: with SMTP id g22mr12044556otj.46.1637132477228;
        Tue, 16 Nov 2021 23:01:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637132477; cv=none;
        d=google.com; s=arc-20160816;
        b=HGK9vdsDjBWzJ3pyr8Vd/puaGcWISHoSj99yNc2zpr3/gLE/iFXeLzbwZ1YgOJJ3bn
         dYGmFN6Xg0AsCzsgorgBqyT2jflZC7rgTHrSvVQzDEkUkD4Fo7xLiYN1+fXgfmr/UOSp
         8BL2hH3mvp43dKE9fbStoAE0rPmM6LOJJLNkSGiAbe+jiyd6NFBiC+gPA42lU15toQ1T
         47b73MisWmNwLqG74IwNBsinQkQapfo+ziqxSFthaScx/h2S5KP5ryk+qkWefsHSq0Wj
         3ymv5M31m0Awdd75UrK+QXdf9TWNd/upDGD9OlujY1VzW4qJUIPE8fXizND2FIhYjBsR
         +baQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qSRzun9akkuvFASVnjdIZYF2V5fIxudJv97JmVln+5o=;
        b=e5WWqtQB1kMqPvaIpcTxv/FBLq4zYNZANtNIHBG8k17eOXKqk5Wr5E15Rv63yo5rEy
         Rqj/l/ZsWR6hZEFVxknKpxJmQeTFwrFMokrOljZNqMVcJp+x7+I9Z4V8tJrx3dBR+4cF
         C4UXvpqWpFsAKn/mLMxj4c2GxQVTa+o3v2sPlO4Hfq0cDvMeoSGWeIzQtKDWLHGAyugt
         4YPPhJQKKODUv3x5ckGx0yxw5W7Q6F41M/dHU6ZJat5DbrWOD2niMdWAcUjTKeo/CShJ
         iz8O6kxXFLNtU9t1GBlja6FMb4jA0J2JYTOTPIeEPfyB3nfdyFE1JQKYXLyV0PBT7riT
         4Tag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hWSf2ty4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22e.google.com (mail-oi1-x22e.google.com. [2607:f8b0:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id d17si651076oiw.0.2021.11.16.23.01.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Nov 2021 23:01:17 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) client-ip=2607:f8b0:4864:20::22e;
Received: by mail-oi1-x22e.google.com with SMTP id n66so4303324oia.9
        for <kasan-dev@googlegroups.com>; Tue, 16 Nov 2021 23:01:17 -0800 (PST)
X-Received: by 2002:a05:6808:1903:: with SMTP id bf3mr47860461oib.7.1637132476810;
 Tue, 16 Nov 2021 23:01:16 -0800 (PST)
MIME-Version: 1.0
References: <20211116001628.24216-1-vbabka@suse.cz> <20211116001628.24216-31-vbabka@suse.cz>
In-Reply-To: <20211116001628.24216-31-vbabka@suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 17 Nov 2021 08:00:00 +0100
Message-ID: <CANpmjNMjMZE1n-5v2sCZZOrLLs9hDkhVMKfij1GSwi+T0HY7sA@mail.gmail.com>
Subject: Re: [RFC PATCH 30/32] mm/sl*b: Differentiate struct slab fields by
 sl*b implementations
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Matthew Wilcox <willy@infradead.org>, linux-mm@kvack.org, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Pekka Enberg <penberg@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hWSf2ty4;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as
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

On Tue, 16 Nov 2021 at 01:16, Vlastimil Babka <vbabka@suse.cz> wrote:
> With a struct slab definition separate from struct page, we can go further and
> define only fields that the chosen sl*b implementation uses. This means
> everything between __page_flags and __page_refcount placeholders now depends on
> the chosen CONFIG_SL*B. Some fields exist in all implementations (slab_list)
> but can be part of a union in some, so it's simpler to repeat them than
> complicate the definition with ifdefs even more.
>
> The patch doesn't change physical offsets of the fields, although it could be
> done later - for example it's now clear that tighter packing in SLOB could be
> possible.
>
> This should also prevent accidental use of fields that don't exist in given
> implementation. Before this patch virt_to_cache() and and cache_from_obj() was
> visible for SLOB (albeit not used), although it relies on the slab_cache field
> that isn't set by SLOB. With this patch it's now a compile error, so these
> functions are now hidden behind #ifndef CONFIG_SLOB.
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> Cc: Alexander Potapenko <glider@google.com> (maintainer:KFENCE)
> Cc: Marco Elver <elver@google.com> (maintainer:KFENCE)
> Cc: Dmitry Vyukov <dvyukov@google.com> (reviewer:KFENCE)
> Cc: <kasan-dev@googlegroups.com>

Ran kfence_test with both slab and slub, and all passes:

Tested-by: Marco Elver <elver@google.com>

> ---
>  mm/kfence/core.c |  9 +++++----
>  mm/slab.h        | 46 ++++++++++++++++++++++++++++++++++++----------
>  2 files changed, 41 insertions(+), 14 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 4eb60cf5ff8b..46103a7628a6 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -427,10 +427,11 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>         /* Set required slab fields. */
>         slab = virt_to_slab((void *)meta->addr);
>         slab->slab_cache = cache;
> -       if (IS_ENABLED(CONFIG_SLUB))
> -               slab->objects = 1;
> -       if (IS_ENABLED(CONFIG_SLAB))
> -               slab->s_mem = addr;
> +#if defined(CONFIG_SLUB)
> +       slab->objects = 1;
> +#elif defined (CONFIG_SLAB)
> +       slab->s_mem = addr;
> +#endif
>
>         /* Memory initialization. */
>         for_each_canary(meta, set_canary_byte);
> diff --git a/mm/slab.h b/mm/slab.h
> index 58b65e5e5d49..10a9ee195249 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -8,9 +8,24 @@
>  /* Reuses the bits in struct page */
>  struct slab {
>         unsigned long __page_flags;
> +
> +#if defined(CONFIG_SLAB)
> +
> +       union {
> +               struct list_head slab_list;
> +               struct rcu_head rcu_head;
> +       };
> +       struct kmem_cache *slab_cache;
> +       void *freelist; /* array of free object indexes */
> +       void * s_mem;   /* first object */
> +       unsigned int active;
> +
> +#elif defined(CONFIG_SLUB)
> +
>         union {
>                 struct list_head slab_list;
> -               struct {        /* Partial pages */
> +               struct rcu_head rcu_head;
> +               struct {
>                         struct slab *next;
>  #ifdef CONFIG_64BIT
>                         int slabs;      /* Nr of slabs left */
> @@ -18,25 +33,32 @@ struct slab {
>                         short int slabs;
>  #endif
>                 };
> -               struct rcu_head rcu_head;
>         };
> -       struct kmem_cache *slab_cache; /* not slob */
> +       struct kmem_cache *slab_cache;
>         /* Double-word boundary */
>         void *freelist;         /* first free object */
>         union {
> -               void *s_mem;    /* slab: first object */
> -               unsigned long counters;         /* SLUB */
> -               struct {                        /* SLUB */
> +               unsigned long counters;
> +               struct {
>                         unsigned inuse:16;
>                         unsigned objects:15;
>                         unsigned frozen:1;
>                 };
>         };
> +       unsigned int __unused;
> +
> +#elif defined(CONFIG_SLOB)
> +
> +       struct list_head slab_list;
> +       void * __unused_1;
> +       void *freelist;         /* first free block */
> +       void * __unused_2;
> +       int units;
> +
> +#else
> +#error "Unexpected slab allocator configured"
> +#endif
>
> -       union {
> -               unsigned int active;            /* SLAB */
> -               int units;                      /* SLOB */
> -       };
>         atomic_t __page_refcount;
>  #ifdef CONFIG_MEMCG
>         unsigned long memcg_data;
> @@ -47,7 +69,9 @@ struct slab {
>         static_assert(offsetof(struct page, pg) == offsetof(struct slab, sl))
>  SLAB_MATCH(flags, __page_flags);
>  SLAB_MATCH(compound_head, slab_list);  /* Ensure bit 0 is clear */
> +#ifndef CONFIG_SLOB
>  SLAB_MATCH(rcu_head, rcu_head);
> +#endif
>  SLAB_MATCH(_refcount, __page_refcount);
>  #ifdef CONFIG_MEMCG
>  SLAB_MATCH(memcg_data, memcg_data);
> @@ -623,6 +647,7 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s,
>  }
>  #endif /* CONFIG_MEMCG_KMEM */
>
> +#ifndef CONFIG_SLOB
>  static inline struct kmem_cache *virt_to_cache(const void *obj)
>  {
>         struct slab *slab;
> @@ -669,6 +694,7 @@ static inline struct kmem_cache *cache_from_obj(struct kmem_cache *s, void *x)
>                 print_tracking(cachep, x);
>         return cachep;
>  }
> +#endif /* CONFIG_SLOB */
>
>  static inline size_t slab_ksize(const struct kmem_cache *s)
>  {
> --
> 2.33.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMjMZE1n-5v2sCZZOrLLs9hDkhVMKfij1GSwi%2BT0HY7sA%40mail.gmail.com.
