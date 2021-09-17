Return-Path: <kasan-dev+bncBCMIZB7QWENRBEV3SKFAMGQEI4GN6MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id B6E7F40F990
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 15:52:19 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id d202-20020a3768d3000000b003d30722c98fsf66452180qkc.10
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 06:52:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631886738; cv=pass;
        d=google.com; s=arc-20160816;
        b=uZWT3q6QrrRarNj35lH9K4sWgcVjYPJe4XL+u2ebXS8iQaUpb8rcDDTbtj07imNYYt
         MpeEsSvD2Eo5hEsAbNLwd/+QuPBnvPi+axMyMatJhs24CLl4MnWjplfQR9idGSUclg1p
         /zR+W4ryFhJAQuta9tjqoaMbAYh7KhA3qywhImgi5MP5IHZDiTs9JCRpsVp0y0fDXWhk
         n/5ePP6m366c/fCCUhdi9AkrhbxeZ7YRREXrKiM5TIoBgy3aagXkTTH+hDiAIFTCyvxY
         wdlsmCQtL0u4AuvIJw3BkJS7xI2RxxRUttkK88lnf3mzLgUagIqVmnVUKih3WLnr9cy7
         j23w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Y9KddpVCEemkvd9eL/12FZgX2DoVcitxobYxqMwD6Xo=;
        b=kqqgVo52/EGw5xQc7eMKfsKOt4+qmhNCGVtAc3ynsJmjMW+bNFPSBiF3N0Q16y7yt4
         UAgh/nccK+gMq8XSBHKp1Cr7I7IF46J5ixhl+1dEvUVTinmWU4Y6ElsXGIOkl7OUwOC5
         Xw+MG53xfWXX6EbSDPdmaXXjXw8WYLN2LAIuc3NgJACftQb1dEbFkCylXnDS6hovU3gL
         +orlRCNPzfiRg35xyJGgvuQWoqfCT7lVl2HKxkAnLVmoLRXX5gSYATJMCh2Ek8jDo55/
         hOiE+6PKywhMhq5x1QEJNjlSsU1U0ZaHhALsB+QhAX98vdB2PAbJG03nCd8HoqwsCUMb
         EYXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=geAuFp1K;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y9KddpVCEemkvd9eL/12FZgX2DoVcitxobYxqMwD6Xo=;
        b=ao31nYWmaT8GEiLIKgCdhIKYADCO3MsWiLVi/XW6FG05Jy48jy2YSFDxyLaDRDqQnt
         wJ/wz7lB8ktjNn3EetiJtnRuBN6gTqSshz8YtVMo86+6+Dw4hZckcc3fUfc+E7SFb6U9
         9zWArI33rLMmk4AITzTxfligQzOkxMe3V8R4DbM0h/7UlhF9jkvTLeFQ/jpIrnIRE1Ua
         C/Av2zHX5DOw6/ND/Oi/bvL2wjqM4dw12Ly66TEJv3GY+8NQVFkV9K7oq+mSXC1nHr2I
         EaQjhlovkq4XZC8hZ3ujKZFRZCPJbf5AvHoGLowwEQ/yoaHiK53I1uVTFupIgfVP4pP7
         xw9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y9KddpVCEemkvd9eL/12FZgX2DoVcitxobYxqMwD6Xo=;
        b=AA4ij2fjXpaYYxvA5lYzEWD72cAUcQQSBrTCay0da3+3NPRlYGRsJMQ9Py0z2VKz1P
         XG+Fxz9mlcXn/lyzswihAFSmrl5vVqFv/b2/HO0Iutpvcbfhdg8eeYPlNou7mmVO+6o1
         CqG6xrvHY2Myz9qh3eaiazG0RjQkk0ykcwS3GrT6twR10nTubE2klYnx2cUKHRM5TyvF
         +gVaCWbmdMorRs3BNhwxA73MZlAnZ2sr6B4A3iRUX2ZNL7P4JSl5N+yG3T8QhPMLhvWI
         ywQhhNfTvMeMu/VOJOopAlYslvTY7wIf4kXI/tsWQA24daBBIfYhkCvl2FSoo2zpLQDm
         V1JQ==
X-Gm-Message-State: AOAM532vGsbPQXR/KR3WrHDJGN0CJhyjcVSpCfxELzpR949Byodv3F/Z
	DkB5WEvxoE67xrW44NdgFRM=
X-Google-Smtp-Source: ABdhPJxkkQKyt51HJWw0nxmbuWNWTwLq/Vov31UDk04sD7k2XtSApgSP5LT/uPxLZBEJd67nY4833Q==
X-Received: by 2002:a37:a215:: with SMTP id l21mr2148058qke.74.1631886738807;
        Fri, 17 Sep 2021 06:52:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:57c2:: with SMTP id w2ls7136028qta.4.gmail; Fri, 17 Sep
 2021 06:52:18 -0700 (PDT)
X-Received: by 2002:ac8:6edc:: with SMTP id f28mr6400447qtv.310.1631886738247;
        Fri, 17 Sep 2021 06:52:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631886738; cv=none;
        d=google.com; s=arc-20160816;
        b=c+X6GpV3WGMt9QPyBT1VCME6kVHyQ824pw4Ajrqcy3Woetz9prn8A4OtI68TftnhY7
         AzPFnmYKw7RpqmypuLA1q/qSA2pGWG8pdcntrpDqnY/rUGtAEHGejtpavgIMggauZq9V
         DFyoale2w77IazVKHenbPS9Vt/0FLWrdVeMCtAOUI6f1PhW4EhCdXlq6ECu96LLL7jlu
         HTdfWPPVFv6uOBg7yk028CmLsqITwIYCWyu64IWcDrqi3DU6cHIIUW3GVp6D2E8cqePQ
         tfL+qY4MT6YJRRZZKSb5fTvGiGPlurx8SOjWLU6ur/ClX+HPMOKvcgF9KfGWTWJMo6mx
         JGMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GS9W4pNpiTzAkLmjVUyCA7+02vEcDIobbS0Wn48gjPU=;
        b=xP95xcKNEVKZ8CHz6ssv3HdtSux+nVlSK/kTUcqZucL3SryA9s5cwmXSlJ/C+QvYj9
         P79spEDK5UVh4WOvwNc5Hr0dVieYUC18nBXd9X97wD0RJXQyOq1X6WFSYoglAQlpetdA
         OdX+iBI/LOWTYsHgau6ybLrON+Makb/CxDfGyiziqTGRICNQNmJOHETsBZJmAlu+vjTv
         i8SOjmllBh4+B0RRvD5PdyHnqKqNsUB7BKDqhTpStlL9D4VHJfgZToGq8jPhN2PYeu/E
         fvY3jkNTd9c1KBWBdxYxKQNW1sqnDdkMxHnqgpBgs+77zho+aPe1DOhCZLkk6CztzSot
         RSkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=geAuFp1K;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22c.google.com (mail-oi1-x22c.google.com. [2607:f8b0:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id w4si766698qkp.5.2021.09.17.06.52.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Sep 2021 06:52:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22c as permitted sender) client-ip=2607:f8b0:4864:20::22c;
Received: by mail-oi1-x22c.google.com with SMTP id p2so14092653oif.1
        for <kasan-dev@googlegroups.com>; Fri, 17 Sep 2021 06:52:18 -0700 (PDT)
X-Received: by 2002:aca:1109:: with SMTP id 9mr3948867oir.109.1631886737373;
 Fri, 17 Sep 2021 06:52:17 -0700 (PDT)
MIME-Version: 1.0
References: <20210917110756.1121272-1-elver@google.com> <20210917110756.1121272-2-elver@google.com>
In-Reply-To: <20210917110756.1121272-2-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Sep 2021 15:52:05 +0200
Message-ID: <CACT4Y+aqfQNv5kjT0uCdgmw9MDYzZGFTXk9XdZ==pZLxRxfG1A@mail.gmail.com>
Subject: Re: [PATCH 2/3] kfence: limit currently covered allocations when pool
 nearly full
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=geAuFp1K;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22c
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

On Fri, 17 Sept 2021 at 13:08, 'Marco Elver' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> One of KFENCE's main design principles is that with increasing uptime,
> allocation coverage increases sufficiently to detect previously
> undetected bugs.
>
> We have observed that frequent long-lived allocations of the same
> source (e.g. pagecache) tend to permanently fill up the KFENCE pool
> with increasing system uptime, thus breaking the above requirement.
> The workaround thus far had been increasing the sample interval and/or
> increasing the KFENCE pool size, but is no reliable solution.
>
> To ensure diverse coverage of allocations, limit currently covered
> allocations of the same source once pool utilization reaches 75% or
> above. The effect is retaining reasonable allocation coverage when the
> pool is close to full.
>
> A side-effect is that this also limits frequent long-lived allocations
> of the same source filling up the pool permanently.
>
> Uniqueness of an allocation for coverage purposes is based on its
> (partial) allocation stack trace (the source). A lossy hash map is
> used to check if an allocation is covered; if the allocation is
> currently covered, the allocation is skipped by KFENCE.
>
> Testing was done using:
>
>         (a) a synthetic workload that performs frequent long-lived
>             allocations (default config values + <10ms sample intervals
>             + smaller-than-default pool sizes), and
>
>         (b) normal desktop workloads on an otherwise idle machine where
>             the problem was first reported (default config values).
>
> In the case of (b) the observed result confirms that sampled allocation
> rate no longer drops to zero after a few days of uptime, all while
> "allocations skipped (covered)" are no more than 2% of total sampled
> allocations.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  mm/kfence/core.c   | 120 ++++++++++++++++++++++++++++++++++++++++++++-
>  mm/kfence/kfence.h |   2 +
>  2 files changed, 120 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 2755800f3e2a..3b78402d7a5e 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -11,11 +11,13 @@
>  #include <linux/bug.h>
>  #include <linux/debugfs.h>
>  #include <linux/irq_work.h>
> +#include <linux/jhash.h>
>  #include <linux/kcsan-checks.h>
>  #include <linux/kfence.h>
>  #include <linux/kmemleak.h>
>  #include <linux/list.h>
>  #include <linux/lockdep.h>
> +#include <linux/log2.h>
>  #include <linux/memblock.h>
>  #include <linux/moduleparam.h>
>  #include <linux/random.h>
> @@ -86,6 +88,28 @@ module_param_cb(sample_interval, &sample_interval_param_ops, &kfence_sample_inte
>  char *__kfence_pool __ro_after_init;
>  EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
>
> +/*
> + * A lossy hash map of allocation stack trace coverage: limits currently covered
> + * allocations of the same source filling up the pool when close to full.
> + *
> + * The required data fits in 64 bits, and therefore we can avoid a per-entry (or
> + * global) lock by simply storing each entry's data in an atomic64_t.
> + */
> +union alloc_covered_entry {
> +       struct {
> +               u32 alloc_stack_hash;   /* stack trace hash */
> +               u32 covered;            /* current coverage count */
> +       };
> +       u64 entry;
> +};
> +#define ALLOC_COVERED_SIZE (1 << const_ilog2(CONFIG_KFENCE_NUM_OBJECTS | 128)) /* >= 128 */

const_ilog2 rounds down, so for 1023 objects we will have hashtable of
size 512, or am I missing something? This asking for collisions.
Hashtable size should be larger than expected population.

> +#define ALLOC_COVERED_MASK (ALLOC_COVERED_SIZE - 1)
> +static atomic64_t alloc_covered[ALLOC_COVERED_SIZE];
> +/* Stack depth used to determine uniqueness of an allocation. */
> +#define UNIQUE_ALLOC_STACK_DEPTH 8
> +/* Pool usage threshold when currently covered allocations are skipped. */
> +#define SKIP_COVERED_THRESHOLD ((CONFIG_KFENCE_NUM_OBJECTS * 3) / 4) /* 75% */
> +
>  /*
>   * Per-object metadata, with one-to-one mapping of object metadata to
>   * backing pages (in __kfence_pool).
> @@ -114,6 +138,7 @@ enum kfence_counter_id {
>         KFENCE_COUNTER_BUGS,
>         KFENCE_COUNTER_SKIP_INCOMPAT,
>         KFENCE_COUNTER_SKIP_CAPACITY,
> +       KFENCE_COUNTER_SKIP_COVERED,
>         KFENCE_COUNTER_COUNT,
>  };
>  static atomic_long_t counters[KFENCE_COUNTER_COUNT];
> @@ -125,11 +150,73 @@ static const char *const counter_names[] = {
>         [KFENCE_COUNTER_BUGS]           = "total bugs",
>         [KFENCE_COUNTER_SKIP_INCOMPAT]  = "skipped allocations (incompatible)",
>         [KFENCE_COUNTER_SKIP_CAPACITY]  = "skipped allocations (capacity)",
> +       [KFENCE_COUNTER_SKIP_COVERED]   = "skipped allocations (covered)",
>  };
>  static_assert(ARRAY_SIZE(counter_names) == KFENCE_COUNTER_COUNT);
>
>  /* === Internals ============================================================ */
>
> +static u32 get_alloc_stack_hash(void)
> +{
> +       unsigned long stack_entries[UNIQUE_ALLOC_STACK_DEPTH];
> +       size_t num_entries;
> +
> +       num_entries = stack_trace_save(stack_entries, UNIQUE_ALLOC_STACK_DEPTH, 1);

Strictly speaking, if a bad persistent allocation comes from an
interrupt it may still consume whole pool. We've hit this problem with
KASAN stackdepot unbounded growth. It's better to do
filter_irq_stacks() here, see:
https://elixir.bootlin.com/linux/v5.15-rc1/source/mm/kasan/common.c#L39


> +       return jhash(stack_entries, num_entries * sizeof(stack_entries[0]), 0);
> +}
> +
> +/*
> + * Check if the allocation stack trace hash @alloc_stack_hash is contained in
> + * @alloc_covered and currently covered.
> + */
> +static bool alloc_covered_contains(u32 alloc_stack_hash)
> +{
> +       union alloc_covered_entry entry;
> +
> +       if (!alloc_stack_hash)
> +               return false;
> +
> +       entry.entry = (u64)atomic64_read(&alloc_covered[alloc_stack_hash & ALLOC_COVERED_MASK]);
> +       return entry.alloc_stack_hash == alloc_stack_hash && entry.covered;
> +}
> +
> +/*
> + * Adds (or subtracts) coverage count to entry corresponding to
> + * @alloc_stack_hash. If @alloc_stack_hash is not yet contained in
> + * @alloc_covered, resets (potentially evicting existing) entry.
> + */
> +static void alloc_covered_add(u32 alloc_stack_hash, int val)
> +{
> +       union alloc_covered_entry old;
> +       union alloc_covered_entry new;
> +       atomic64_t *bucket;
> +
> +       if (!alloc_stack_hash)
> +               return;
> +
> +       bucket = &alloc_covered[alloc_stack_hash & ALLOC_COVERED_MASK];
> +       old.entry = (u64)atomic64_read(bucket);
> +       new.alloc_stack_hash = alloc_stack_hash;
> +       do {
> +               if (val > 0) {
> +                       new.covered = old.alloc_stack_hash == alloc_stack_hash
> +                                       ? old.covered + val     /* increment */
> +                                       : val;                  /* evict/reset */

I am trying to understand the effects of this eviction policy on the result.
It seems that it can render the pool overflow protection void.
Consider, two stacks (ABC, DEF) hash to the same bucket. One
allocation is frequent and not persistent, another is less frequent
but almost persistent. The first one will evict the second one, so we
will always save the second effectively defeating the overflow
protection.

There are also some interesting effects due to cyclic evictions
(A->B->A), where we do not count increment, but count decrement.

Have you considered not evicting, but rather simply combining
allocations with the same hash?
I.e. doing alloc_covered[hash]++/--.
It would err on the side of not sampling allocations that are unlucky
to collide with persistent allocations, but would provide more
reliable overflow guarantees (at least we continue sampling
allocations for all other buckets since we have pool capacity).
FWIW also simpler code.

I am also thinking if collisions can be resolved by adding some salt
that is generated on boot. Resolving collisions across different
machines is good enough for KFENCE. Namely, if we have stacks ABC and
DEF, we hash XABC and XDEF, where X is filled on boot. It should work
for a good hash function, right? If this works, then the simpler
alloc_covered[hash]++/-- scheme should work (?).



> +               } else if (old.alloc_stack_hash == alloc_stack_hash && old.covered) {
> +                       new.covered = old.covered + val;
> +               } else {
> +                       /*
> +                        * Hash mismatch or covered has become zero. The latter
> +                        * is possible if we race with:
> +                        *      reset (!= alloc_stack_hash)
> +                        *       -> reset (== alloc_stack_hash)
> +                        *        -> decrement
> +                        */
> +                       break;
> +               }
> +       } while (!atomic64_try_cmpxchg_relaxed(bucket, (s64 *)&old.entry, (s64)new.entry));
> +}
> +
>  static bool kfence_protect(unsigned long addr)
>  {
>         return !KFENCE_WARN_ON(!kfence_protect_page(ALIGN_DOWN(addr, PAGE_SIZE), true));
> @@ -261,7 +348,8 @@ static __always_inline void for_each_canary(const struct kfence_metadata *meta,
>         }
>  }
>
> -static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp)
> +static void *
> +kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp, u32 alloc_stack_hash)
>  {
>         struct kfence_metadata *meta = NULL;
>         unsigned long flags;
> @@ -322,6 +410,8 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>         /* Pairs with READ_ONCE() in kfence_shutdown_cache(). */
>         WRITE_ONCE(meta->cache, cache);
>         meta->size = size;
> +       meta->alloc_stack_hash = alloc_stack_hash;
> +
>         for_each_canary(meta, set_canary_byte);
>
>         /* Set required struct page fields. */
> @@ -334,6 +424,8 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>
>         raw_spin_unlock_irqrestore(&meta->lock, flags);
>
> +       alloc_covered_add(alloc_stack_hash, 1);
> +
>         /* Memory initialization. */
>
>         /*
> @@ -362,6 +454,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>  static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool zombie)
>  {
>         struct kcsan_scoped_access assert_page_exclusive;
> +       u32 alloc_stack_hash;
>         unsigned long flags;
>
>         raw_spin_lock_irqsave(&meta->lock, flags);
> @@ -404,8 +497,13 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
>         /* Mark the object as freed. */
>         metadata_update_state(meta, KFENCE_OBJECT_FREED);
>
> +       alloc_stack_hash = meta->alloc_stack_hash;
> +       meta->alloc_stack_hash = 0;
> +
>         raw_spin_unlock_irqrestore(&meta->lock, flags);
>
> +       alloc_covered_add(alloc_stack_hash, -1);
> +
>         /* Protect to detect use-after-frees. */
>         kfence_protect((unsigned long)addr);
>
> @@ -744,6 +842,8 @@ void kfence_shutdown_cache(struct kmem_cache *s)
>
>  void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
>  {
> +       u32 alloc_stack_hash;
> +
>         /*
>          * Perform size check before switching kfence_allocation_gate, so that
>          * we don't disable KFENCE without making an allocation.
> @@ -788,7 +888,23 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
>         if (!READ_ONCE(kfence_enabled))
>                 return NULL;
>
> -       return kfence_guarded_alloc(s, size, flags);
> +       /*
> +        * Do expensive check for coverage of allocation in slow-path after
> +        * allocation_gate has already become non-zero, even though it might
> +        * mean not making any allocation within a given sample interval.
> +        *
> +        * This ensures reasonable allocation coverage when the pool is almost
> +        * full, including avoiding long-lived allocations of the same source
> +        * filling up the pool (e.g. pagecache allocations).
> +        */
> +       alloc_stack_hash = get_alloc_stack_hash();

Is it possible to unwind the stack only once per allocation? I.e.
unwind here into a buffer on stack and then pass it down?

> +       if (atomic_long_read(&counters[KFENCE_COUNTER_ALLOCATED]) > SKIP_COVERED_THRESHOLD &&
> +           alloc_covered_contains(alloc_stack_hash)) {
> +               atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_COVERED]);
> +               return NULL;
> +       }
> +
> +       return kfence_guarded_alloc(s, size, flags, alloc_stack_hash);
>  }
>
>  size_t kfence_ksize(const void *addr)
> diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
> index c1f23c61e5f9..2a2d5de9d379 100644
> --- a/mm/kfence/kfence.h
> +++ b/mm/kfence/kfence.h
> @@ -87,6 +87,8 @@ struct kfence_metadata {
>         /* Allocation and free stack information. */
>         struct kfence_track alloc_track;
>         struct kfence_track free_track;
> +       /* For updating alloc_covered on frees. */
> +       u32 alloc_stack_hash;
>  };
>
>  extern struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
> --
> 2.33.0.464.g1972c5931b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaqfQNv5kjT0uCdgmw9MDYzZGFTXk9XdZ%3D%3DpZLxRxfG1A%40mail.gmail.com.
