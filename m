Return-Path: <kasan-dev+bncBCMIZB7QWENRB27YU2FAMGQEJDO3AVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 51188413241
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 13:05:17 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id v206-20020a627ad7000000b0043e010e5392sf15463642pfc.1
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 04:05:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632222316; cv=pass;
        d=google.com; s=arc-20160816;
        b=qO+/Ws3SDDMCHK/aEP8AaP8g3/SfvaJ57vcQU55BP13mtMrjlXcopy2CWqYHRSgsCH
         Wu4r5ROwKUwAilNrdiFfEgqXsr7Gbl7LL7rhmvoQ/81IKpvmIuYdIzrEMTAnQnFEFoDP
         KPqsvO/VJNg04M2aV2QaMc0RsdpoXDylW+pxcM18YIRKirdeEhduSqL1oUJq82kwJ/G+
         xOQphOgjSJLgv3b0yvLAx6/ABFy99b9irZxyQINivYBwnm0gOOaTqekTbtqyNSt4B2rt
         Amo2NXu5JVtHtOd/N0OlS1Q8XYIYu3AiXShzCla44upgLspshQef4PtXLN/UcAhngEVx
         PlQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dmngewDPiMVZXGPN+le/SDMSDhtejpf+f2kHTbsXaAo=;
        b=A6XhB1riAU2vAjrORvQ3CmYnEh72sRv9Zlz7nokPl67HvBXIOIxRQrVSWrDC7qZQEI
         Wjbie4M8c0KvLhTMFPLEiYCejtJLxkp9/n/I8mw8VmhXNCbq2tnq+t9suM9wGZy9rwmv
         GGwsFl/s5Uj8CFxiIJc+kpjqgIl7Oj3zvOr1igllpnt/9M8lHDnM+l6SRadUfEg4n9ZZ
         cybVt/2qtYuapd8BpXT7b9D8ujNFW7KPR5lFzD4G/2xSuXCYr8uPHtJ0dxu9FzL1iI3r
         gmntCVg6JPMLdUSmzVWfOUupvjoDL+wHUzxieZp8OYXquE/e5f/rEzzA8N5X4yYABwNE
         mxMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="E/Dz5Uem";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dmngewDPiMVZXGPN+le/SDMSDhtejpf+f2kHTbsXaAo=;
        b=OycMpJY0TtwzqZBk3vduxXg1oOsDAzJNm4VKX5F+cxjm1L3IehlNZZOLoiJm2lCS2m
         RvSue2WHyK4Dumm6hlRIG52uqchJbMJXE4UqmbaVWjYiR8qvdpSuxKqL6e+iis07mDs/
         QIVpjHO3SLDDpMAlYbQPB0vIdVhLNjR+J+1+jFHSr2DmVoWzHVSb2pDG5U1WznTdlr8H
         LE9cP+QAdF3KhpDqrvzo/tutaFH+n2Avzu5ETX++K86vVplgtadsG0jG6aPnBFTn1APd
         QePTMGvv2DgkFV6BiUrsZwVGxFT1q/OruQHqDmNFczmn4hJupQARsQf5CASls1X2g2F7
         J8qQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dmngewDPiMVZXGPN+le/SDMSDhtejpf+f2kHTbsXaAo=;
        b=CDoncM3oZYXoJOa6cO8l6bsW71bJML3adqHOEwaoGmgK9oyMrf8fnxBgFWed2DVQHJ
         xY1a0sYPGrLULCSMF0kqzFKy12gtlm3VuCrP/VHgW+70NMYKYzMa6CGxlqu/XWXK2kTu
         ny2Pqy8q74izEYp9ZvdBTgmwOttNTec87B0kjHPKydgr1fban3TshUnqDnT6nEFv/Ohp
         wUPBvM4UOSFOPBgJQaB8FbvmIomY9v2WkSQ7N0y6g/cWQ9UvWq6jLPsJCQvNXDrElq2e
         ihq17/duJSA84jmfuf8OtKTfYHOuIzKQaiqk6Ve7TTkYpuAB8GBnd8SN0RWo3mCAJyIT
         7p0A==
X-Gm-Message-State: AOAM532yKuLG6+zaCA2C3APk36M1dcvPvDZUEhimqdDxKO3YgrU4PC7y
	MAbeLfThGRtwUrWC/N6yYtA=
X-Google-Smtp-Source: ABdhPJw3NfSF+haPQk99AsUWri5cxGX38+/IuasI65JPoaMlPdeqzP/9wjRBlOG6xMyxHfnLSWrvAw==
X-Received: by 2002:a17:90a:1990:: with SMTP id 16mr4626718pji.11.1632222316020;
        Tue, 21 Sep 2021 04:05:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6487:: with SMTP id e7ls7496527pgv.7.gmail; Tue, 21 Sep
 2021 04:05:15 -0700 (PDT)
X-Received: by 2002:a63:e057:: with SMTP id n23mr28088682pgj.183.1632222315388;
        Tue, 21 Sep 2021 04:05:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632222315; cv=none;
        d=google.com; s=arc-20160816;
        b=NFmeHMTU0zx+yGznFYn8lh6YDmre7RLa0mYeyMenJNONpWSSUK77skLEQMz49+fVh/
         cfc8iNyafL8RvSgZNIuIMJjtJHAPlT5NJwuQlJSZKtEKqZ8foY57sgF3pxWwlKt3EvJ2
         AjPwa9kErnGdBMS3fLsUDQAlH7CjbIdI/ECGOaJj+tymfaUhIFKu/pT4aZm3uBkxQxOB
         2sKkYqzJE7N0cDLZcWxh68GHPVeOwbqCILfawcJDILAVO7Qtk7o4U+UkQjQKjQ07d/9g
         sYKDsX7+NifeZdvriT6Uskl/6VNFZyTqyVBm5l67/rEHNp0QJK/nt/Uk0qtbfYYq7rGY
         jLRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=siq9DNizf2XNhKgFT5Nc6HavLskG3clXTf/qLqUtPik=;
        b=CILk9kd4kgH9zHFVReo1/mk3DSScWSYEh4E7IArU/IBBrU1Wh/CuMqkvzbe2wgpq25
         ogFQ/++7l7YBYi51RdcnifBr9RaJWuyXCQgxzDq82mllEagK4jT/E9FA9d46WIDjPGyy
         Crkl2CfXADpKjCSLpDNfAO4/0ILCPV3OgCHRcUEpaNHlXQq+ZtTCLf3R7vHEjoGce3jQ
         buGZFKHJV7paXqy9L/eGB4zJdCgwTCIk3AuuSuSYQ+VpLdhMB+IFBDlacS6HB+Y7GyCA
         Bg9gvTCsJA5lNMhgN14iRW1wO1oXHhr9M8isc9uji2P4jj3krk44GXCmYmHeQRuUyxgm
         6lqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="E/Dz5Uem";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x236.google.com (mail-oi1-x236.google.com. [2607:f8b0:4864:20::236])
        by gmr-mx.google.com with ESMTPS id v7si133657pjk.2.2021.09.21.04.05.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Sep 2021 04:05:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::236 as permitted sender) client-ip=2607:f8b0:4864:20::236;
Received: by mail-oi1-x236.google.com with SMTP id 6so29131764oiy.8
        for <kasan-dev@googlegroups.com>; Tue, 21 Sep 2021 04:05:15 -0700 (PDT)
X-Received: by 2002:aca:3083:: with SMTP id w125mr3073078oiw.109.1632222314447;
 Tue, 21 Sep 2021 04:05:14 -0700 (PDT)
MIME-Version: 1.0
References: <20210921101014.1938382-1-elver@google.com> <20210921101014.1938382-4-elver@google.com>
In-Reply-To: <20210921101014.1938382-4-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Sep 2021 13:05:03 +0200
Message-ID: <CACT4Y+Z6Rss3+oiN5bcKHYeQgG=nZ9VDqwrhOS4VUZ=_a5NoBw@mail.gmail.com>
Subject: Re: [PATCH v2 4/5] kfence: limit currently covered allocations when
 pool nearly full
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Jann Horn <jannh@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="E/Dz5Uem";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::236
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

On Tue, 21 Sept 2021 at 12:10, 'Marco Elver' via kasan-dev
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
> allocations of the same source once pool utilization reaches 75%
> (configurable via `kfence.skip_covered_thresh`) or above. The effect is
> retaining reasonable allocation coverage when the pool is close to full.
>
> A side-effect is that this also limits frequent long-lived allocations
> of the same source filling up the pool permanently.
>
> Uniqueness of an allocation for coverage purposes is based on its
> (partial) allocation stack trace (the source). A Counting Bloom filter
> is used to check if an allocation is covered; if the allocation is
> currently covered, the allocation is skipped by KFENCE.
>
> Testing was done using:
>
>         (a) a synthetic workload that performs frequent long-lived
>             allocations (default config values; sample_interval=1;
>             num_objects=63), and
>
>         (b) normal desktop workloads on an otherwise idle machine where
>             the problem was first reported after a few days of uptime
>             (default config values).
>
> In both test cases the sampled allocation rate no longer drops to zero
> at any point. In the case of (b) we observe (after 2 days uptime) 15%
> unique allocations in the pool, 77% pool utilization, with 20% "skipped
> allocations (covered)".
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v2:
> * Switch to counting bloom filter to guarantee currently covered
>   allocations being skipped.
> * Use a module param for skip_covered threshold.
> * Use kfence pool address as hash entropy.
> * Use filter_irq_stacks().
> ---
>  mm/kfence/core.c   | 113 ++++++++++++++++++++++++++++++++++++++++++++-
>  mm/kfence/kfence.h |   2 +
>  2 files changed, 113 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index db01814f8ff0..9b3fb30f24c3 100644
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
> @@ -82,6 +84,10 @@ static const struct kernel_param_ops sample_interval_param_ops = {
>  };
>  module_param_cb(sample_interval, &sample_interval_param_ops, &kfence_sample_interval, 0600);
>
> +/* Pool usage% threshold when currently covered allocations are skipped. */
> +static unsigned long kfence_skip_covered_thresh __read_mostly = 75;
> +module_param_named(skip_covered_thresh, kfence_skip_covered_thresh, ulong, 0644);
> +
>  /* The pool of pages used for guard pages and objects. */
>  char *__kfence_pool __ro_after_init;
>  EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
> @@ -105,6 +111,25 @@ DEFINE_STATIC_KEY_FALSE(kfence_allocation_key);
>  /* Gates the allocation, ensuring only one succeeds in a given period. */
>  atomic_t kfence_allocation_gate = ATOMIC_INIT(1);
>
> +/*
> + * A Counting Bloom filter of allocation coverage: limits currently covered
> + * allocations of the same source filling up the pool.
> + *
> + * Assuming a range of 15%-85% unique allocations in the pool at any point in
> + * time, the below parameters provide a probablity of 0.02-0.33 for false
> + * positive hits respectively:
> + *
> + *     P(alloc_traces) = (1 - e^(-HNUM * (alloc_traces / SIZE)) ^ HNUM
> + */
> +#define ALLOC_COVERED_HNUM     2
> +#define ALLOC_COVERED_SIZE     (1 << (const_ilog2(CONFIG_KFENCE_NUM_OBJECTS) + 2))
> +#define ALLOC_COVERED_HNEXT(h) (1664525 * (h) + 1013904223)
> +#define ALLOC_COVERED_MASK     (ALLOC_COVERED_SIZE - 1)
> +static atomic_t alloc_covered[ALLOC_COVERED_SIZE];
> +
> +/* Stack depth used to determine uniqueness of an allocation. */
> +#define UNIQUE_ALLOC_STACK_DEPTH 8UL
> +
>  /* Statistics counters for debugfs. */
>  enum kfence_counter_id {
>         KFENCE_COUNTER_ALLOCATED,
> @@ -114,6 +139,7 @@ enum kfence_counter_id {
>         KFENCE_COUNTER_BUGS,
>         KFENCE_COUNTER_SKIP_INCOMPAT,
>         KFENCE_COUNTER_SKIP_CAPACITY,
> +       KFENCE_COUNTER_SKIP_COVERED,
>         KFENCE_COUNTER_COUNT,
>  };
>  static atomic_long_t counters[KFENCE_COUNTER_COUNT];
> @@ -125,11 +151,66 @@ static const char *const counter_names[] = {
>         [KFENCE_COUNTER_BUGS]           = "total bugs",
>         [KFENCE_COUNTER_SKIP_INCOMPAT]  = "skipped allocations (incompatible)",
>         [KFENCE_COUNTER_SKIP_CAPACITY]  = "skipped allocations (capacity)",
> +       [KFENCE_COUNTER_SKIP_COVERED]   = "skipped allocations (covered)",
>  };
>  static_assert(ARRAY_SIZE(counter_names) == KFENCE_COUNTER_COUNT);
>
>  /* === Internals ============================================================ */
>
> +static inline bool should_skip_covered(void)
> +{
> +       unsigned long thresh = (CONFIG_KFENCE_NUM_OBJECTS * kfence_skip_covered_thresh) / 100;
> +
> +       return atomic_long_read(&counters[KFENCE_COUNTER_ALLOCATED]) > thresh;
> +}
> +
> +static u32 get_alloc_stack_hash(unsigned long *stack_entries, size_t num_entries)
> +{
> +       /* Some randomness across reboots / different machines. */
> +       u32 seed = (u32)((unsigned long)__kfence_pool >> (BITS_PER_LONG - 32));
> +
> +       num_entries = min(num_entries, UNIQUE_ALLOC_STACK_DEPTH);
> +       num_entries = filter_irq_stacks(stack_entries, num_entries);
> +       return jhash(stack_entries, num_entries * sizeof(stack_entries[0]), seed);
> +}
> +
> +/*
> + * Adds (or subtracts) count @val for allocation stack trace hash
> + * @alloc_stack_hash from Counting Bloom filter.
> + */
> +static void alloc_covered_add(u32 alloc_stack_hash, int val)
> +{
> +       int i;
> +
> +       if (!alloc_stack_hash)
> +               return;

Nice!
I like the hash seed, non-evicting cache and that threshold become a
command line parameter.

This check is the only place I don't understand. What's special about
alloc_stack_hash == 0? I see that even double-free's won't call this
with 0.


> +       for (i = 0; i < ALLOC_COVERED_HNUM; i++) {
> +               atomic_add(val, &alloc_covered[alloc_stack_hash & ALLOC_COVERED_MASK]);
> +               alloc_stack_hash = ALLOC_COVERED_HNEXT(alloc_stack_hash);
> +       }
> +}
> +
> +/*
> + * Returns true if the allocation stack trace hash @alloc_stack_hash is
> + * currently contained (non-zero count) in Counting Bloom filter.
> + */
> +static bool alloc_covered_contains(u32 alloc_stack_hash)
> +{
> +       int i;
> +
> +       if (!alloc_stack_hash)
> +               return false;
> +
> +       for (i = 0; i < ALLOC_COVERED_HNUM; i++) {
> +               if (!atomic_read(&alloc_covered[alloc_stack_hash & ALLOC_COVERED_MASK]))
> +                       return false;
> +               alloc_stack_hash = ALLOC_COVERED_HNEXT(alloc_stack_hash);
> +       }
> +
> +       return true;
> +}
> +
>  static bool kfence_protect(unsigned long addr)
>  {
>         return !KFENCE_WARN_ON(!kfence_protect_page(ALIGN_DOWN(addr, PAGE_SIZE), true));
> @@ -269,7 +350,8 @@ static __always_inline void for_each_canary(const struct kfence_metadata *meta,
>  }
>
>  static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp,
> -                                 unsigned long *stack_entries, size_t num_stack_entries)
> +                                 unsigned long *stack_entries, size_t num_stack_entries,
> +                                 u32 alloc_stack_hash)
>  {
>         struct kfence_metadata *meta = NULL;
>         unsigned long flags;
> @@ -332,6 +414,8 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>         /* Pairs with READ_ONCE() in kfence_shutdown_cache(). */
>         WRITE_ONCE(meta->cache, cache);
>         meta->size = size;
> +       meta->alloc_stack_hash = alloc_stack_hash;
> +
>         for_each_canary(meta, set_canary_byte);
>
>         /* Set required struct page fields. */
> @@ -344,6 +428,8 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>
>         raw_spin_unlock_irqrestore(&meta->lock, flags);
>
> +       alloc_covered_add(alloc_stack_hash, 1);
> +
>         /* Memory initialization. */
>
>         /*
> @@ -368,6 +454,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>  static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool zombie)
>  {
>         struct kcsan_scoped_access assert_page_exclusive;
> +       u32 alloc_stack_hash;
>         unsigned long flags;
>
>         raw_spin_lock_irqsave(&meta->lock, flags);
> @@ -410,8 +497,13 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
>         /* Mark the object as freed. */
>         metadata_update_state(meta, KFENCE_OBJECT_FREED, NULL, 0);
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
> @@ -752,6 +844,7 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
>  {
>         unsigned long stack_entries[KFENCE_STACK_DEPTH];
>         size_t num_stack_entries;
> +       u32 alloc_stack_hash;
>
>         /*
>          * Perform size check before switching kfence_allocation_gate, so that
> @@ -799,7 +892,23 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
>
>         num_stack_entries = stack_trace_save(stack_entries, KFENCE_STACK_DEPTH, 0);
>
> -       return kfence_guarded_alloc(s, size, flags, stack_entries, num_stack_entries);
> +       /*
> +        * Do expensive check for coverage of allocation in slow-path after
> +        * allocation_gate has already become non-zero, even though it might
> +        * mean not making any allocation within a given sample interval.
> +        *
> +        * This ensures reasonable allocation coverage when the pool is almost
> +        * full, including avoiding long-lived allocations of the same source
> +        * filling up the pool (e.g. pagecache allocations).
> +        */
> +       alloc_stack_hash = get_alloc_stack_hash(stack_entries, num_stack_entries);
> +       if (should_skip_covered() && alloc_covered_contains(alloc_stack_hash)) {
> +               atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_COVERED]);
> +               return NULL;
> +       }
> +
> +       return kfence_guarded_alloc(s, size, flags, stack_entries, num_stack_entries,
> +                                   alloc_stack_hash);
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
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210921101014.1938382-4-elver%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ6Rss3%2BoiN5bcKHYeQgG%3DnZ9VDqwrhOS4VUZ%3D_a5NoBw%40mail.gmail.com.
