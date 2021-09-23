Return-Path: <kasan-dev+bncBCMIZB7QWENRBJOFWGFAMGQEOCQIQZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 14AD4415CB1
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 13:19:03 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id o10-20020a65614a000000b002850cb8c434sf3685511pgv.13
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 04:19:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632395941; cv=pass;
        d=google.com; s=arc-20160816;
        b=LKfZX/LSUJaSETWfqzZizrOwPx+PuvVsfJyhTPs7yt4pyBDiaL07JDA5Q8yHz7KX+F
         2294Lt7fUhqGmj6hnmZZ6G0ab5b6XD3xJoT4RFo47ri4OabHm2A3Z+bAPTVc15vpJi+0
         A57uCfpJLINp5pIu/XSzV69lubViA+Av4MB4p9DURPBAD7YItJs6GcxHONqlPRdvC2nP
         lBptjhsvCp7kl48HTTnFHSYfDFLkjEpLOLKwh1P96l8EsW2pfHixCL6o8kV1aewXTzMx
         HrRUlzFgDF+xj3+gbZ3E++Lkmeip7adpxNpjHdgIRZX1WpesfHCUzR/QCTyzVWphu8IG
         mPGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=CkvdKdRzpYQgHZFLNBUK7xJsSVvHXjA4e5ayNfTpufs=;
        b=ZX5MY/GXr7Ayc5lCMw9PplMLFv46mEltLu88TUtUSiXnUk/WH8vTdUOiHKyAhriC02
         xi3B/YM8ilaRMqN6nZt/F1oA+mBLzffF8X7MvqQCtL08FKHhtO5XaflOTYNXJXakIMNy
         IpNmmy24ATgQhW2mP5XFbK5sJU6yj3rF05k0HAcGiITsIiwHnAhzIZaYEd1Aw+A2jZoD
         D8+CY6wMDnXENbEYEs+5nYuK5PnbX0Lkin4iOskOFmf9M+UqWllCDvCiGp10ht53jbOF
         4ck5iwejjU4lnw4e6PR29cyvdaxWWrh2bHgkGcTnk9ZmRVp63LJPWYb7t3kDLUFdLe1s
         of9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qHGxCAn7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CkvdKdRzpYQgHZFLNBUK7xJsSVvHXjA4e5ayNfTpufs=;
        b=Rfzc7sgqlxvPC4zTcHiOAQt/E6ROoWcMpAZkNiYJ3hXNfWXSbxtWKbN+0uUO436kcf
         2I1ySmDeahMYiCpzHMHC/p3m2kaN6yzsNrBEBNiaiRw28eLsWKnxQD0WCLXxcYvGtYUh
         BJdARGi8a3HiX6PnDABJJow3oXN4xB3zyfqoG+Cz0tn1Ll6CyGqRkDK2dhluvArRP052
         XhdHnAM2S6D3oJYHqEFBOgwuRyIkYa/rLfakKNKCr6A1qXT84ICB1qxLGUPetEVoWm3E
         AbmTGjiUfOOnOfWlHtWD+zucw3i7/rp5oLFDvpkbjeLXODLKP/4V6cu4n/8rdMG9XGoI
         5k5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CkvdKdRzpYQgHZFLNBUK7xJsSVvHXjA4e5ayNfTpufs=;
        b=3lD8cNdXyO6SJNATJeYjfFtXd4+3y2vRd46IG2BgqMM/vmunfjqdv2DnDRvgm7pkEd
         yAzpPqTkrEKcPm6qUOvOJJCMKs6k9mjDVycz/pdSDeAXMw+RIp67hhtObobzkY6trzC7
         c4axuBVGQrYWnzTvkh1n/5jp+0fFEjxs7u7hg4xjriYtWuYu9RbgaxAprisfoSuu1vYH
         isE7XLSCsoE3+vLFSEszKyzWijME+dlIbBgXyOotvU4UnvlctUmjMAuJqmfLATASMhdG
         Ckwp/wePZ4/GeGbl4u0twuRS/6Tkw2+EAhVhF8KyOKA1R+8g3Y7JZ7TdBtgk5mHeXQXC
         M9og==
X-Gm-Message-State: AOAM532Bxo4A7XlwwrR/tXkRGTF6RNhBnxZ1etbgntKdwE/iSj3Mv2LR
	lQwOaQNLUAX50oH3WPoWrSI=
X-Google-Smtp-Source: ABdhPJy8159LV9tCdWM+8j9Oxdf0FA3m2dfSFZRoeF2AIc4p/NtEEjDSxMn/AMevYXxGZ7bU2oDhJw==
X-Received: by 2002:a17:90b:1c92:: with SMTP id oo18mr17423976pjb.56.1632395941348;
        Thu, 23 Sep 2021 04:19:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a708:: with SMTP id w8ls2812352plq.6.gmail; Thu, 23
 Sep 2021 04:19:00 -0700 (PDT)
X-Received: by 2002:a17:902:8a83:b0:13d:9572:86c2 with SMTP id p3-20020a1709028a8300b0013d957286c2mr3481877plo.48.1632395940794;
        Thu, 23 Sep 2021 04:19:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632395940; cv=none;
        d=google.com; s=arc-20160816;
        b=YMxzhWRtQlU1dD8NVQ8SmF9Y1k/RUAJ62/tQHY0QjLhNXZJWcSuwDUSn9c7FMcwhte
         Fjiv4XvnVYAu94aFikERwwQNG5aFn+TUnyiC7Q/ukcp1qlUex0aQwwMJBSknQmUoPLrM
         zOwUIsBRJogZtyeecile2A0ALYVls9xrV3WzN8HFcbZcwy3os6DYI1B9AwrQpcdx1wk8
         jEoKQ5vxX14xxk1FaRjdeVb7N+Ebd47urrf+7llTgIckHb+CPYfVOp/fI1vWmJhezkvW
         MVc0mhDffx4TcttNhrqsSdWMjFmU3cbGLDXg4eTnL714/A2sgvSzZ/EbLeDXIAzeTY6V
         eo+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=s0cPQoIqCHpexQHN8I9O9O1s6hHQIW6w4g54hPahYMY=;
        b=Z0aE7VusJvF4ZOMLFQfAderfCK9R9ykR44wzIO/dSaLLdhOgDF0OA6QR9WP1KV6eOM
         /DyVkwTrymvlmVb6KJwmzOYnA3/S85G5JwslnAzZK+fZKYjZc+ffKI1oLd5mpqF+/fdo
         SDf52XNaPb0SVTzmkm8v7XMPJOctyMEpGyT8ZcF7bQkfnRlBFlJ8wRUKyk/H0tI7VURK
         cucxIF5O6F/AqInT82HCgJDoEVTt1fVE2lNi8JvxwHyF6LNrp+GFnkniC3OHPWUvOqQk
         W2Tn8jYSTwTA3xK7LNktwjBK7bk1+V+ckaBH1rZkpaPVbd6Z26/hrE04GuE4PH7lMx8j
         3tkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qHGxCAn7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x335.google.com (mail-ot1-x335.google.com. [2607:f8b0:4864:20::335])
        by gmr-mx.google.com with ESMTPS id v7si554310pjk.2.2021.09.23.04.19.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Sep 2021 04:19:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::335 as permitted sender) client-ip=2607:f8b0:4864:20::335;
Received: by mail-ot1-x335.google.com with SMTP id h9-20020a9d2f09000000b005453f95356cso7958050otb.11
        for <kasan-dev@googlegroups.com>; Thu, 23 Sep 2021 04:19:00 -0700 (PDT)
X-Received: by 2002:a9d:7244:: with SMTP id a4mr3878121otk.137.1632395940082;
 Thu, 23 Sep 2021 04:19:00 -0700 (PDT)
MIME-Version: 1.0
References: <20210923104803.2620285-1-elver@google.com> <20210923104803.2620285-4-elver@google.com>
In-Reply-To: <20210923104803.2620285-4-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Sep 2021 13:18:48 +0200
Message-ID: <CACT4Y+Zvm4dXQY2tCuypso9aU97_6U2dLhfg2NNA8GTvcQoCLQ@mail.gmail.com>
Subject: Re: [PATCH v3 4/5] kfence: limit currently covered allocations when
 pool nearly full
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Jann Horn <jannh@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qHGxCAn7;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::335
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

On Thu, 23 Sept 2021 at 12:48, Marco Elver <elver@google.com> wrote:
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

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
> v3:
> * Remove unneeded !alloc_stack_hash checks.
> * Remove unneeded meta->alloc_stack_hash=0 in kfence_guarded_free().
>
> v2:
> * Switch to counting bloom filter to guarantee currently covered
>   allocations being skipped.
> * Use a module param for skip_covered threshold.
> * Use kfence pool address as hash entropy.
> * Use filter_irq_stacks().
> ---
>  mm/kfence/core.c   | 103 ++++++++++++++++++++++++++++++++++++++++++++-
>  mm/kfence/kfence.h |   2 +
>  2 files changed, 103 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index db01814f8ff0..58a0f6f1acc5 100644
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
> @@ -125,11 +151,60 @@ static const char *const counter_names[] = {
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
> @@ -269,7 +344,8 @@ static __always_inline void for_each_canary(const struct kfence_metadata *meta,
>  }
>
>  static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp,
> -                                 unsigned long *stack_entries, size_t num_stack_entries)
> +                                 unsigned long *stack_entries, size_t num_stack_entries,
> +                                 u32 alloc_stack_hash)
>  {
>         struct kfence_metadata *meta = NULL;
>         unsigned long flags;
> @@ -332,6 +408,8 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>         /* Pairs with READ_ONCE() in kfence_shutdown_cache(). */
>         WRITE_ONCE(meta->cache, cache);
>         meta->size = size;
> +       meta->alloc_stack_hash = alloc_stack_hash;
> +
>         for_each_canary(meta, set_canary_byte);
>
>         /* Set required struct page fields. */
> @@ -344,6 +422,8 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>
>         raw_spin_unlock_irqrestore(&meta->lock, flags);
>
> +       alloc_covered_add(alloc_stack_hash, 1);
> +
>         /* Memory initialization. */
>
>         /*
> @@ -412,6 +492,8 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
>
>         raw_spin_unlock_irqrestore(&meta->lock, flags);
>
> +       alloc_covered_add(meta->alloc_stack_hash, -1);
> +
>         /* Protect to detect use-after-frees. */
>         kfence_protect((unsigned long)addr);
>
> @@ -752,6 +834,7 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
>  {
>         unsigned long stack_entries[KFENCE_STACK_DEPTH];
>         size_t num_stack_entries;
> +       u32 alloc_stack_hash;
>
>         /*
>          * Perform size check before switching kfence_allocation_gate, so that
> @@ -799,7 +882,23 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZvm4dXQY2tCuypso9aU97_6U2dLhfg2NNA8GTvcQoCLQ%40mail.gmail.com.
