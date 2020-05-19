Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOXFR73AKGQECO3FRJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 70E7A1D9A66
	for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 16:52:43 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id d19sf8478636qvk.8
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 07:52:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589899962; cv=pass;
        d=google.com; s=arc-20160816;
        b=o9F4wpIFeDww/MKCac76+TgwbPZMywdEenfuKw2sW14OZT9S9VMOKUzabZzqV0sOjg
         bzURJsyadMERB8xuhSlHDrynWhHK+vW3BxpcVYT+XUaM/FZv6/YlYnP8Sw4HmV3B7gQX
         XyJOXXu+xSTu+x2vXq4OndH7Bwu7qBI1hfvuN+LNCpwHMguhGid2nH++lutSNYSIFyuZ
         kudwAatOryZilp9n56eo0DRQJ1yDeV11D3zcWX4wqfLPmb2NZPZV/sV6YogCpts4r6Lx
         MS1veCybI00pLX1u6a30RDusR+Zv55saWD3+NmMZN7VO1y6cK2buZqesE4q9TzCsqs6/
         2ejg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ay7kdUVk+b0YhPXkPKJNoPSLPodCrROrvWyBidrWSvY=;
        b=MiqhFCA17trutJJi3d/unsQEKA2B31H8noB2albTNo4fYI+Nre2/01/GAGbv8fgCjV
         FacNocgyH8NPzqklfUDuw6a8QktpSIKZW+WuMhZD4hZX2x6qumd8pY7uTKFfrBpC+tf3
         iOa2vK8fkMZQLJpti7d7Op/sx10N0Qf6nnrlLID8fdNZbVfswIkpUCuspAkhVbMK/qol
         Ghai3GNjHxo+0d8vz7vhM575dZDPCI3FIKoxgAW8Pdfr4OhH2/2tZ9e4ElrNckZ+YBmL
         4VjTm/5pUxGYrEd5gvtWSLJlBbkVoX9PlHKXANGZByxS9IaQWCxmKKmIpCTnx7NHs1uk
         b7GQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="jR44H/Yv";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ay7kdUVk+b0YhPXkPKJNoPSLPodCrROrvWyBidrWSvY=;
        b=bJaEC8lFU2uuAcuuzXYijSHfM9oYjv1nHbjiTT726/xQjptE3Glu83EbzJbY9dnsta
         Vu++LV9LlLSGtbJZm99UGJRg16IJI3zWW2qMYGKGGYb/Vu6p1ufwt6+DBKGx4ZkY0opE
         ITnMGCdkNe9KW6ChFtx3RplxRtlsPfG9qNdqbZfnlQEVsAfS0KN4NLLxGLDd1u00JO/t
         phTU6GMsKo3ucFbz30yNcLrD0YvBxWf6KkJ7BCx75zARtMHRG9nYOuOzD2ckJfCQs54G
         djNpspDXHAZK0r1esDwAQpq9dO6xsAs5U2aBdMtc8wb0XBRUhQ/tOFEe68a3w3wQIpBf
         Q0uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ay7kdUVk+b0YhPXkPKJNoPSLPodCrROrvWyBidrWSvY=;
        b=LJU+XW1R5dW4CdDqWcEd7aZV0NdZObzcJmFcqn7JSlMyxEos/yjvp/65lsxR5b0UK4
         PV3zADR0GSi1VSUiPvrglUJJmWWCE0zvnwvlW2DV3sHF1JLqAVUu0gtQB+MQXlGR0WGq
         YjDUBzKdgTxHwCMXvXt/ijw3CCjwDSczm1A/IH6P7uU5q065lnlTKuoMDTGmL7BViMj3
         d/n0kWBMHP6a7ZGZV0BlUzwRxY1dAO/r62uJKG0LzpqOUCNnwvtlxwKtIqfHmlgSRDbb
         Casr4kDobmkhiTrihRZWdhNCe85fqVWGAfyqF7RsZ2VWZopNLrbDnywL0jqiRnFvObF5
         7P1A==
X-Gm-Message-State: AOAM533V/R2An9SqPfs8UnZzL8yNAGyKLS8RVIos6WPhv6TGB03utKu7
	/RyWW9i31Gar0n/FLB9qDEg=
X-Google-Smtp-Source: ABdhPJzFzEKJ5XPkNqJeD+D1ALVS5Gg3Kc31Wmnoxqmh9QkfnPFWn4zvQbfNo0W5VsUC7ErSDqV6rA==
X-Received: by 2002:a25:3044:: with SMTP id w65mr35684301ybw.207.1589899962342;
        Tue, 19 May 2020 07:52:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:dc1:: with SMTP id 184ls4967274ybn.5.gmail; Tue, 19 May
 2020 07:52:41 -0700 (PDT)
X-Received: by 2002:a25:ad60:: with SMTP id l32mr36170248ybe.84.1589899961441;
        Tue, 19 May 2020 07:52:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589899961; cv=none;
        d=google.com; s=arc-20160816;
        b=zhHymr0vXQpCRRVtIf5d1pPXN4raYRaISnuo3WCqolJgpwRb+spuOsQEdI6VDl7hSW
         cniCKdmN2JUxweKUvsm8dETEHo+cKvGeGUOmqMVpJtQrIKSNCrBJqFopp88/9RDfOSNJ
         9tgbJ6PLOPCQ+2AASbP4O6Qqe+pJX5WIicGYRC8BoOZVbwc5dAoXHL6hOnO51lynGnk4
         SIqcAugvMcR/15qiuWZrg0SHtwUKkG6aghDpdh6VtCVsa9u+0AZCEL093fOgIdL6Vj+N
         gPEEUyKixypxK2iPfHQuy4bMKVBHUljcM5imIpziDPvQGEFIY15BNDJDRztMmRvqwvsO
         aP/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XFAQ0HvjxKI2zefHuxO3sefeYajZXVKpLYZBInzWIBk=;
        b=Al6f/bwGsh0cOOJGGkXmaBX7l0ai4LbSraDpuANdQ3Q1EiBGGVv2MMzk0QmjirbnTs
         hA75hg7PEqqecORpauBzDmNhGUoObn5BOa33yPwptuOL/KKjODDyTW0j9Ke8U7OpO6zq
         wFiOx70swlZOdRxX5pj6rYxA3+WvS73Mcr28rj1LXM2VrI7B1J3W015de6i63eSdnKf5
         tShAheLV2fJNs/AVe51M449aEEj7f5aBzSXszX/OJuaJgNx7MMKtw2KXthSa29nx4Xdk
         Y9epX8mz2XuWQnyk3XDuMuXUdluewCdxo34/iGqxJYQXkbx833vMuW/fA8w3r6atIiWx
         lGdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="jR44H/Yv";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1043.google.com (mail-pj1-x1043.google.com. [2607:f8b0:4864:20::1043])
        by gmr-mx.google.com with ESMTPS id h14si925319ybq.0.2020.05.19.07.52.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 May 2020 07:52:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) client-ip=2607:f8b0:4864:20::1043;
Received: by mail-pj1-x1043.google.com with SMTP id ci21so1474410pjb.3
        for <kasan-dev@googlegroups.com>; Tue, 19 May 2020 07:52:41 -0700 (PDT)
X-Received: by 2002:a17:902:7b89:: with SMTP id w9mr19799522pll.252.1589899960335;
 Tue, 19 May 2020 07:52:40 -0700 (PDT)
MIME-Version: 1.0
References: <20200519022359.24115-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200519022359.24115-1-walter-zh.wu@mediatek.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 May 2020 16:52:28 +0200
Message-ID: <CAAeHK+wHzVVxYkmqVuvg3PSJJMDAh_fNJrg6vULeYYo3063jYg@mail.gmail.com>
Subject: Re: [PATCH v4 1/4] rcu/kasan: record and print call_rcu() call stack
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	"Paul E . McKenney" <paulmck@kernel.org>, Josh Triplett <josh@joshtriplett.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Joel Fernandes <joel@joelfernandes.org>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="jR44H/Yv";       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, May 19, 2020 at 4:24 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> This feature will record the last two call_rcu() call stacks and
> prints up to 2 call_rcu() call stacks in KASAN report.
>
> When call_rcu() is called, we store the call_rcu() call stack into
> slub alloc meta-data, so that the KASAN report can print rcu stack.
>
> [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> [2]https://groups.google.com/forum/#!searchin/kasan-dev/better$20stack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Paul E. McKenney <paulmck@kernel.org>
> Cc: Josh Triplett <josh@joshtriplett.org>
> Cc: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
> Cc: Lai Jiangshan <jiangshanlai@gmail.com>
> Cc: Joel Fernandes <joel@joelfernandes.org>
> ---
>  include/linux/kasan.h |  2 ++
>  kernel/rcu/tree.c     |  2 ++
>  lib/Kconfig.kasan     |  2 ++
>  mm/kasan/common.c     |  4 ++--
>  mm/kasan/generic.c    | 19 +++++++++++++++++++
>  mm/kasan/kasan.h      | 10 ++++++++++
>  mm/kasan/report.c     | 24 ++++++++++++++++++++++++
>  7 files changed, 61 insertions(+), 2 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 31314ca7c635..23b7ee00572d 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -174,11 +174,13 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
>
>  void kasan_cache_shrink(struct kmem_cache *cache);
>  void kasan_cache_shutdown(struct kmem_cache *cache);
> +void kasan_record_aux_stack(void *ptr);
>
>  #else /* CONFIG_KASAN_GENERIC */
>
>  static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
>  static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
> +static inline void kasan_record_aux_stack(void *ptr) {}
>
>  #endif /* CONFIG_KASAN_GENERIC */
>
> diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> index 06548e2ebb72..36a4ff7f320b 100644
> --- a/kernel/rcu/tree.c
> +++ b/kernel/rcu/tree.c
> @@ -57,6 +57,7 @@
>  #include <linux/slab.h>
>  #include <linux/sched/isolation.h>
>  #include <linux/sched/clock.h>
> +#include <linux/kasan.h>
>  #include "../time/tick-internal.h"
>
>  #include "tree.h"
> @@ -2668,6 +2669,7 @@ __call_rcu(struct rcu_head *head, rcu_callback_t func)
>         head->func = func;
>         head->next = NULL;
>         local_irq_save(flags);
> +       kasan_record_aux_stack(head);
>         rdp = this_cpu_ptr(&rcu_data);
>
>         /* Add the callback to our list. */
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 81f5464ea9e1..4e83cf6e3caa 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -58,6 +58,8 @@ config KASAN_GENERIC
>           For better error detection enable CONFIG_STACKTRACE.
>           Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
>           (the resulting kernel does not boot).
> +         In generic mode KASAN prints the last two call_rcu() call stacks in
> +         reports.

I don't think we need this here, mentioning this in the documentation is fine.


>
>  config KASAN_SW_TAGS
>         bool "Software tag-based mode"
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 2906358e42f0..8bc618289bb1 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -41,7 +41,7 @@
>  #include "kasan.h"
>  #include "../slab.h"
>
> -static inline depot_stack_handle_t save_stack(gfp_t flags)
> +depot_stack_handle_t kasan_save_stack(gfp_t flags)
>  {
>         unsigned long entries[KASAN_STACK_DEPTH];
>         unsigned int nr_entries;
> @@ -54,7 +54,7 @@ static inline depot_stack_handle_t save_stack(gfp_t flags)
>  static inline void set_track(struct kasan_track *track, gfp_t flags)
>  {
>         track->pid = current->pid;
> -       track->stack = save_stack(flags);
> +       track->stack = kasan_save_stack(flags);
>  }
>
>  void kasan_enable_current(void)
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 56ff8885fe2e..3372bdcaf92a 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -325,3 +325,22 @@ DEFINE_ASAN_SET_SHADOW(f2);
>  DEFINE_ASAN_SET_SHADOW(f3);
>  DEFINE_ASAN_SET_SHADOW(f5);
>  DEFINE_ASAN_SET_SHADOW(f8);
> +
> +void kasan_record_aux_stack(void *addr)
> +{
> +       struct page *page = kasan_addr_to_page(addr);
> +       struct kmem_cache *cache;
> +       struct kasan_alloc_meta *alloc_info;
> +       void *object;
> +
> +       if (!(page && PageSlab(page)))
> +               return;
> +
> +       cache = page->slab_cache;
> +       object = nearest_obj(cache, page, addr);
> +       alloc_info = get_alloc_info(cache, object);
> +
> +       /* record the last two call_rcu() call stacks */
> +       alloc_info->aux_stack[1] = alloc_info->aux_stack[0];
> +       alloc_info->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
> +}
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index e8f37199d885..a7391bc83070 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -104,7 +104,15 @@ struct kasan_track {
>
>  struct kasan_alloc_meta {
>         struct kasan_track alloc_track;
> +#ifdef CONFIG_KASAN_GENERIC
> +       /*
> +        * call_rcu() call stack is stored into struct kasan_alloc_meta.
> +        * The free stack is stored into struct kasan_free_meta.
> +        */
> +       depot_stack_handle_t aux_stack[2];
> +#else
>         struct kasan_track free_track[KASAN_NR_FREE_STACKS];
> +#endif
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>         u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
>         u8 free_track_idx;
> @@ -159,6 +167,8 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
>
>  struct page *kasan_addr_to_page(const void *addr);
>
> +depot_stack_handle_t kasan_save_stack(gfp_t flags);
> +
>  #if defined(CONFIG_KASAN_GENERIC) && \
>         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
>  void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 80f23c9da6b0..6f8f2bf8f53b 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -179,6 +179,17 @@ static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>         return &alloc_meta->free_track[i];
>  }
>
> +#ifdef CONFIG_KASAN_GENERIC
> +static void print_stack(depot_stack_handle_t stack)

Let's put this function just before print_track() and reuse there.

> +{
> +       unsigned long *entries;
> +       unsigned int nr_entries;
> +
> +       nr_entries = stack_depot_fetch(stack, &entries);
> +       stack_trace_print(entries, nr_entries, 0);
> +}
> +#endif
> +
>  static void describe_object(struct kmem_cache *cache, void *object,
>                                 const void *addr, u8 tag)
>  {
> @@ -192,6 +203,19 @@ static void describe_object(struct kmem_cache *cache, void *object,
>                 free_track = kasan_get_free_track(cache, object, tag);
>                 print_track(free_track, "Freed");
>                 pr_err("\n");
> +
> +#ifdef CONFIG_KASAN_GENERIC
> +               if (alloc_info->aux_stack[0]) {
> +                       pr_err("Last one call_rcu() call stack:\n");

Could you change this to "Last call_rcu():\n",

> +                       print_stack(alloc_info->aux_stack[0]);
> +                       pr_err("\n");
> +               }
> +               if (alloc_info->aux_stack[1]) {
> +                       pr_err("Second to last call_rcu() call stack:\n");

and this to "Second to last call_rcu():\n"?

It's shorter, but provides the same info.



> +                       print_stack(alloc_info->aux_stack[1]);
> +                       pr_err("\n");
> +               }
> +#endif
>         }
>
>         describe_object_addr(cache, object, addr);
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200519022359.24115-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwHzVVxYkmqVuvg3PSJJMDAh_fNJrg6vULeYYo3063jYg%40mail.gmail.com.
