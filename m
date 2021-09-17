Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB65SKFAMGQEYOIDPSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 5353340FB1B
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 17:04:41 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id l23-20020a17090aec1700b0019aefe0a92fsf7530647pjy.5
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 08:04:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631891080; cv=pass;
        d=google.com; s=arc-20160816;
        b=e1IGWZsrfM3C2KGtov4Q1bKcv3QKjEttWKx2IPV76Le7f3Srk2LiQGtDQt06zVhwFk
         e4JcUoeHyosNAGlT+/6novLxIPcl81LouXkRDYs9GLhdPHu2h9W7RWl9n1io8LnWj+vL
         q6UDb3IKp/CJSMS+Cld1u89Gy15Rtu6RWrN4A5fd2a7sjphn6oWyn6F2v5anSATmS4Jk
         +v3aF4n5ja6KwK4LPeVEPy58/Oi5nGp6haB429X+ga8S46oq2s3LcgoLMpkVt9BluqSL
         7SmEFnJxKqrNq7u42oZmnb1XRwygzj8NW5eos6a0qyF9x5WUGwgSfOkKIMfurtTXzp6U
         mbow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=T2acVLfgJ56YydTcPzccut+bhI7PDFml6f4UnnOP4IM=;
        b=XSOOc02MPyk4a0NFbOXqSWZCPaYSRpP8MAnAtbspi9BL4jUab7Eivv6eqksyRZcDSj
         itfKaA77u1uTh8bVTZfLr0xYnlZKyXOppUHJJPmiibCNsggZ6WyhBMOq/ZGK2bV2Jiwj
         5d0ZozFdfAS7rrkGHRKiR237u4xVwwzKD6P20VOBKYcI+5kff29wD6EK7KxEdxrGNEq0
         q3OyOYNEwQVYJk0uy58Ni1aYGNE1sbwTzzkQrrK6N4c4dD+oIc7oiLcrvbHibFWP5IZg
         csZx9UyPzjHiqKmegK3MDl5B/SzSv7ORCbqS2X0BtVmhn2N3BFNQF8gWwAIrvAzJGu4Y
         UIAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="gJ7zRq/b";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T2acVLfgJ56YydTcPzccut+bhI7PDFml6f4UnnOP4IM=;
        b=gna3SGPsiGDB9QjMJzB+wovxk3OQCjWc3dcJf0RFjtOQFuOGTuw8etde2B1jdWDvzr
         3OZNuLP0/bZbOHpx35tfj3vh3wu1J3MNfMyfSNLic7U2HKhHjQ75KapYVI8IUGhIINbx
         ioqtzYqRAdK1U9PFtusu0WStdx9UTFgO+v+PxdA+TuzwcJIoICyQtrqh2RdERK5Hxto2
         +4Wyg7sdFOG8Ghe1FfjqRRm0cDAfBHLMYyLuf0uhdAghf8JrQ7PuJDPS4/6I/o9FiMnk
         iYm3pzLK1EF+Kqrz8rWUVPlEQllnkHSqxOv7x+aKRXYXXWI3aYXL1Iv9FLYo1F/np26Y
         A4vQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T2acVLfgJ56YydTcPzccut+bhI7PDFml6f4UnnOP4IM=;
        b=lSVicJ9rBwYJAIlOGZXEqv40cNc5/Vp9hQdWGi982neTDhKmr/44EFhNUBhfRHS6PB
         QXurv4ncMuYtvLK5cg3QBfqHRiD1P1hssM3piRi2BgyrQdBKvEAMZwMgHYrGqrAbkj4X
         fhVVxLpYEq9GSY+h28h00B1fmIiP6Y+Fs7W/qUHmJA4y/TS8/6+eKB4QRvlhctZhBe/U
         yzW4cmrNwDnVEoztvKryaz59U8goHB6fB6bbWKLkIMwMgRzajz44ZtNnuNLpU3Ja6xw6
         YpgLO0aWBSKINPU5wovgCRIlE0EUoWjmA/WO3qDlOzIyQEQ4kbAkyYG9PXxyjdQzeMg/
         uZ/Q==
X-Gm-Message-State: AOAM530Ui00AIddS0E5wrtmI0+/vAwE8l+V0139d1bd8uc77UYOI6VSa
	okCL9v1HqZfwCTmfiC+83ME=
X-Google-Smtp-Source: ABdhPJypyI7ev8cgzrI9dZO4k516mERgVFJC0Ou3hwVhmTna+1hRErWwO1LGarsDRH8e660dFqfTrQ==
X-Received: by 2002:a17:90b:3b8b:: with SMTP id pc11mr21973235pjb.153.1631891079854;
        Fri, 17 Sep 2021 08:04:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e787:: with SMTP id cp7ls4018050plb.10.gmail; Fri,
 17 Sep 2021 08:04:39 -0700 (PDT)
X-Received: by 2002:a17:90a:b943:: with SMTP id f3mr21852337pjw.147.1631891079192;
        Fri, 17 Sep 2021 08:04:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631891079; cv=none;
        d=google.com; s=arc-20160816;
        b=LenofkNW9rtcLz0uklv0zScPbnTGV3fr58PrXTepOgL1+4crWCCfC7S6Z/WbCC48SB
         Lg3ahQjnCbDVfhUVeP3gyp/qs+OPCfO9G2GKRzCYYxEQg/+8B16FG4W7AxXA0RYkKyVp
         MIr1DHc2l7P//SU3WzuREJrFaoU702Ch98Bwcwmx7PoYtqg5agMpl2orjHkfPZ1dVku6
         ZH0YZiy6WlWUvhhtUExIU4NsbI/vBXQcvabfvxD2NwxM77DBZSDggaECoLu43nCq88b/
         odBl0SZnZ3KNGgr2lbUHoW2to65s7p16FfHCRBo7Ds75QBdodg9dpc+5kBt7AMQSvoyY
         VfxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XUsl9Gygs4sNh6RuSqwsUb3ZhWZQ6AtKMQEzioy+07E=;
        b=D6rxsHkfSGy5w97ETIZJ+j0tGS/2H1BFzaPOt5aYtFGGI4ZLQQmS7BftLlT+rKR6NG
         tZdB+XAc13IzVfjcDeJjMawr0+1T3AGrjmnWodUi7YpM8QoilzxAZ6m8d+gPJaZBaKia
         nWmZqmhq/StE9a+XRm1dcDoamIHGOqRG7gkwswXOu25/5laGg/FZTl+MyRPpV5ZZJcqY
         ftcI1hwszGGydbqUY1MAxx26JYKCj/CeK56cMHWqjM/Xi/DLlWO00d+eniOfJHnJtgdr
         UvZ1bpqkab0glE30PXprs/YRI2/sJJiAtgXrQo6tRyZHY+20kps7E0BjOgMVC2uT34CD
         qSSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="gJ7zRq/b";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x336.google.com (mail-ot1-x336.google.com. [2607:f8b0:4864:20::336])
        by gmr-mx.google.com with ESMTPS id r7si953771pjp.0.2021.09.17.08.04.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Sep 2021 08:04:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) client-ip=2607:f8b0:4864:20::336;
Received: by mail-ot1-x336.google.com with SMTP id i8-20020a056830402800b0051afc3e373aso13258717ots.5
        for <kasan-dev@googlegroups.com>; Fri, 17 Sep 2021 08:04:39 -0700 (PDT)
X-Received: by 2002:a9d:135:: with SMTP id 50mr1442954otu.295.1631891078270;
 Fri, 17 Sep 2021 08:04:38 -0700 (PDT)
MIME-Version: 1.0
References: <20210917110756.1121272-1-elver@google.com> <20210917110756.1121272-2-elver@google.com>
 <CACT4Y+aqfQNv5kjT0uCdgmw9MDYzZGFTXk9XdZ==pZLxRxfG1A@mail.gmail.com>
In-Reply-To: <CACT4Y+aqfQNv5kjT0uCdgmw9MDYzZGFTXk9XdZ==pZLxRxfG1A@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Sep 2021 17:04:26 +0200
Message-ID: <CANpmjNNJv4wt0AhnKP4fuLkeMJdPAKB0GVWDj1VvoC3kZ8bGRw@mail.gmail.com>
Subject: Re: [PATCH 2/3] kfence: limit currently covered allocations when pool
 nearly full
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="gJ7zRq/b";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as
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

On Fri, 17 Sept 2021 at 15:52, Dmitry Vyukov <dvyukov@google.com> wrote:
[...]
> > +/*
> > + * A lossy hash map of allocation stack trace coverage: limits currently covered
> > + * allocations of the same source filling up the pool when close to full.
> > + *
> > + * The required data fits in 64 bits, and therefore we can avoid a per-entry (or
> > + * global) lock by simply storing each entry's data in an atomic64_t.
> > + */
> > +union alloc_covered_entry {
> > +       struct {
> > +               u32 alloc_stack_hash;   /* stack trace hash */
> > +               u32 covered;            /* current coverage count */
> > +       };
> > +       u64 entry;
> > +};
> > +#define ALLOC_COVERED_SIZE (1 << const_ilog2(CONFIG_KFENCE_NUM_OBJECTS | 128)) /* >= 128 */
>
> const_ilog2 rounds down, so for 1023 objects we will have hashtable of
> size 512, or am I missing something? This asking for collisions.
> Hashtable size should be larger than expected population.

That's correct. I wanted to err on the side of allocating more and not
less, if we can afford it. Hence also the choice of lossy hash map.
However, I think if we consider the whole fleet, your proposal below
makes sense and I'll rerun experiments with that and see.

> > +#define ALLOC_COVERED_MASK (ALLOC_COVERED_SIZE - 1)
> > +static atomic64_t alloc_covered[ALLOC_COVERED_SIZE];
> > +/* Stack depth used to determine uniqueness of an allocation. */
> > +#define UNIQUE_ALLOC_STACK_DEPTH 8
> > +/* Pool usage threshold when currently covered allocations are skipped. */
> > +#define SKIP_COVERED_THRESHOLD ((CONFIG_KFENCE_NUM_OBJECTS * 3) / 4) /* 75% */
> > +
> >  /*
> >   * Per-object metadata, with one-to-one mapping of object metadata to
> >   * backing pages (in __kfence_pool).
> > @@ -114,6 +138,7 @@ enum kfence_counter_id {
> >         KFENCE_COUNTER_BUGS,
> >         KFENCE_COUNTER_SKIP_INCOMPAT,
> >         KFENCE_COUNTER_SKIP_CAPACITY,
> > +       KFENCE_COUNTER_SKIP_COVERED,
> >         KFENCE_COUNTER_COUNT,
> >  };
> >  static atomic_long_t counters[KFENCE_COUNTER_COUNT];
> > @@ -125,11 +150,73 @@ static const char *const counter_names[] = {
> >         [KFENCE_COUNTER_BUGS]           = "total bugs",
> >         [KFENCE_COUNTER_SKIP_INCOMPAT]  = "skipped allocations (incompatible)",
> >         [KFENCE_COUNTER_SKIP_CAPACITY]  = "skipped allocations (capacity)",
> > +       [KFENCE_COUNTER_SKIP_COVERED]   = "skipped allocations (covered)",
> >  };
> >  static_assert(ARRAY_SIZE(counter_names) == KFENCE_COUNTER_COUNT);
> >
> >  /* === Internals ============================================================ */
> >
> > +static u32 get_alloc_stack_hash(void)
> > +{
> > +       unsigned long stack_entries[UNIQUE_ALLOC_STACK_DEPTH];
> > +       size_t num_entries;
> > +
> > +       num_entries = stack_trace_save(stack_entries, UNIQUE_ALLOC_STACK_DEPTH, 1);
>
> Strictly speaking, if a bad persistent allocation comes from an
> interrupt it may still consume whole pool. We've hit this problem with
> KASAN stackdepot unbounded growth. It's better to do
> filter_irq_stacks() here, see:
> https://elixir.bootlin.com/linux/v5.15-rc1/source/mm/kasan/common.c#L39

Time to move filter_irq_stacks() out of stackdepot, we should not
depend on stackdepot just for filter_irq_stacks(). I'll probably move
it to kernel/stacktrace.c, which seems most appropriate.

> > +       return jhash(stack_entries, num_entries * sizeof(stack_entries[0]), 0);
> > +}
> > +
> > +/*
> > + * Check if the allocation stack trace hash @alloc_stack_hash is contained in
> > + * @alloc_covered and currently covered.
> > + */
> > +static bool alloc_covered_contains(u32 alloc_stack_hash)
> > +{
> > +       union alloc_covered_entry entry;
> > +
> > +       if (!alloc_stack_hash)
> > +               return false;
> > +
> > +       entry.entry = (u64)atomic64_read(&alloc_covered[alloc_stack_hash & ALLOC_COVERED_MASK]);
> > +       return entry.alloc_stack_hash == alloc_stack_hash && entry.covered;
> > +}
> > +
> > +/*
> > + * Adds (or subtracts) coverage count to entry corresponding to
> > + * @alloc_stack_hash. If @alloc_stack_hash is not yet contained in
> > + * @alloc_covered, resets (potentially evicting existing) entry.
> > + */
> > +static void alloc_covered_add(u32 alloc_stack_hash, int val)
> > +{
> > +       union alloc_covered_entry old;
> > +       union alloc_covered_entry new;
> > +       atomic64_t *bucket;
> > +
> > +       if (!alloc_stack_hash)
> > +               return;
> > +
> > +       bucket = &alloc_covered[alloc_stack_hash & ALLOC_COVERED_MASK];
> > +       old.entry = (u64)atomic64_read(bucket);
> > +       new.alloc_stack_hash = alloc_stack_hash;
> > +       do {
> > +               if (val > 0) {
> > +                       new.covered = old.alloc_stack_hash == alloc_stack_hash
> > +                                       ? old.covered + val     /* increment */
> > +                                       : val;                  /* evict/reset */
>
> I am trying to understand the effects of this eviction policy on the result.
> It seems that it can render the pool overflow protection void.
> Consider, two stacks (ABC, DEF) hash to the same bucket. One
> allocation is frequent and not persistent, another is less frequent
> but almost persistent. The first one will evict the second one, so we
> will always save the second effectively defeating the overflow
> protection.
>
> There are also some interesting effects due to cyclic evictions
> (A->B->A), where we do not count increment, but count decrement.
>
> Have you considered not evicting, but rather simply combining
> allocations with the same hash?

Hmm, good point. It's probably not as bad as a real bloom filter,
because we might successfully remove an entry if all the allocations
that mapped to 1 bucket are freed.

> I.e. doing alloc_covered[hash]++/--.
> It would err on the side of not sampling allocations that are unlucky
> to collide with persistent allocations, but would provide more
> reliable overflow guarantees (at least we continue sampling
> allocations for all other buckets since we have pool capacity).
> FWIW also simpler code.
>
> I am also thinking if collisions can be resolved by adding some salt
> that is generated on boot. Resolving collisions across different
> machines is good enough for KFENCE. Namely, if we have stacks ABC and
> DEF, we hash XABC and XDEF, where X is filled on boot. It should work
> for a good hash function, right? If this works, then the simpler
> alloc_covered[hash]++/-- scheme should work (?).

Good idea, I think I'll introduce a seed for the hash function.

Let me experiment with the simplified version you suggest, and see what I get.

> > +               } else if (old.alloc_stack_hash == alloc_stack_hash && old.covered) {
> > +                       new.covered = old.covered + val;
> > +               } else {
> > +                       /*
> > +                        * Hash mismatch or covered has become zero. The latter
> > +                        * is possible if we race with:
> > +                        *      reset (!= alloc_stack_hash)
> > +                        *       -> reset (== alloc_stack_hash)
> > +                        *        -> decrement
> > +                        */
> > +                       break;
> > +               }
> > +       } while (!atomic64_try_cmpxchg_relaxed(bucket, (s64 *)&old.entry, (s64)new.entry));
> > +}
> > +
> >  static bool kfence_protect(unsigned long addr)
> >  {
> >         return !KFENCE_WARN_ON(!kfence_protect_page(ALIGN_DOWN(addr, PAGE_SIZE), true));
> > @@ -261,7 +348,8 @@ static __always_inline void for_each_canary(const struct kfence_metadata *meta,
> >         }
> >  }
> >
> > -static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp)
> > +static void *
> > +kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp, u32 alloc_stack_hash)
> >  {
> >         struct kfence_metadata *meta = NULL;
> >         unsigned long flags;
> > @@ -322,6 +410,8 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
> >         /* Pairs with READ_ONCE() in kfence_shutdown_cache(). */
> >         WRITE_ONCE(meta->cache, cache);
> >         meta->size = size;
> > +       meta->alloc_stack_hash = alloc_stack_hash;
> > +
> >         for_each_canary(meta, set_canary_byte);
> >
> >         /* Set required struct page fields. */
> > @@ -334,6 +424,8 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
> >
> >         raw_spin_unlock_irqrestore(&meta->lock, flags);
> >
> > +       alloc_covered_add(alloc_stack_hash, 1);
> > +
> >         /* Memory initialization. */
> >
> >         /*
> > @@ -362,6 +454,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
> >  static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool zombie)
> >  {
> >         struct kcsan_scoped_access assert_page_exclusive;
> > +       u32 alloc_stack_hash;
> >         unsigned long flags;
> >
> >         raw_spin_lock_irqsave(&meta->lock, flags);
> > @@ -404,8 +497,13 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
> >         /* Mark the object as freed. */
> >         metadata_update_state(meta, KFENCE_OBJECT_FREED);
> >
> > +       alloc_stack_hash = meta->alloc_stack_hash;
> > +       meta->alloc_stack_hash = 0;
> > +
> >         raw_spin_unlock_irqrestore(&meta->lock, flags);
> >
> > +       alloc_covered_add(alloc_stack_hash, -1);
> > +
> >         /* Protect to detect use-after-frees. */
> >         kfence_protect((unsigned long)addr);
> >
> > @@ -744,6 +842,8 @@ void kfence_shutdown_cache(struct kmem_cache *s)
> >
> >  void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
> >  {
> > +       u32 alloc_stack_hash;
> > +
> >         /*
> >          * Perform size check before switching kfence_allocation_gate, so that
> >          * we don't disable KFENCE without making an allocation.
> > @@ -788,7 +888,23 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
> >         if (!READ_ONCE(kfence_enabled))
> >                 return NULL;
> >
> > -       return kfence_guarded_alloc(s, size, flags);
> > +       /*
> > +        * Do expensive check for coverage of allocation in slow-path after
> > +        * allocation_gate has already become non-zero, even though it might
> > +        * mean not making any allocation within a given sample interval.
> > +        *
> > +        * This ensures reasonable allocation coverage when the pool is almost
> > +        * full, including avoiding long-lived allocations of the same source
> > +        * filling up the pool (e.g. pagecache allocations).
> > +        */
> > +       alloc_stack_hash = get_alloc_stack_hash();
>
> Is it possible to unwind the stack only once per allocation? I.e.
> unwind here into a buffer on stack and then pass it down?

I'll investigate how bad it looks if we do that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNJv4wt0AhnKP4fuLkeMJdPAKB0GVWDj1VvoC3kZ8bGRw%40mail.gmail.com.
