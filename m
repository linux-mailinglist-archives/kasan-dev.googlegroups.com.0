Return-Path: <kasan-dev+bncBCMIZB7QWENRBJHH4T2QKGQEWV55V6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 908E41CD76B
	for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 13:14:45 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id y8sf3231851ybn.20
        for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 04:14:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589195684; cv=pass;
        d=google.com; s=arc-20160816;
        b=OCpMC3DMljbBrWcPDXhDiqpin3bcArQazf08i/Ybxk2Ggjsduxd4X4S7Mt5DBOUd7A
         W5+isxZc6p+CcmBNgwKx6XIrtR7RO31fKvZR2Qi/O6GhGAIuxlkumrr3AjLSNW0KWCJf
         jXnyqnyiipAMd5Cteryk5rcw4ZVTXHNRQwE3wFDO1SRLMS8P/KQDvYS+Udq0bZNieFuH
         O0hHmZ5cBaGQS82Uc6fiTcZip3Og0aR1JxiQ6Xt5izw5PC3kNBIO49yvPfv7Qz5d0YfI
         3kFmc08xainqzQ4VsOdSDlqNTtzU3lU1SmAJiDakvO29ecm8aq60bCYS5X0uQtrCDtP4
         9VXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+aiDNPUQvjL0Pw/enpAZcxq+0p6iG3PlngQAtihLtYA=;
        b=MVZ+2P7709U3J6mQY2B7cYWE7rOMUErOh7SdwQ0CJqK2qN3bOw4Uq8XxuvLpvywjf9
         rBLwU1Gt1rdUd/Fb+rLeypEo06aCkTEuOpz0HAvPd5OlYu89AE77R/CaLpEmEBojTXRz
         mcoRpH7GC2nWfRfU1W1dLhph456+bX8J5Q6/Qczb/KnpYVAziVSi6oOwG4yw3RrUA7pA
         jMc0lVrj+yC5BzbPoAm9UsPQ2Pvx3/S1ZT5Cko/e3eD0rovEmmtok+UY5VmCs5fkP2pk
         vox38wb11flN/AAK34jVcnTuggglwXRBml5iK6ZwI6ZUhLu9P8exau4LmkuZeLoK1+Tm
         kR0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mXiDmvSv;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+aiDNPUQvjL0Pw/enpAZcxq+0p6iG3PlngQAtihLtYA=;
        b=cFH/D7Y4ZglY11VECb4KUAG8CbrjEgXv2dYFMyy/8QsH7Z7dCU/hcmt7LHl3YfQ4tw
         ZUqDCq5cKsocUH46j9tLVYHoq0Nc5OnO363hbmDVOq24WFaxrcyfoLnE9X8PafGLkkhZ
         idkPzCa3a1N1iYpjpDVL8W5x5Kfsv8tNNH1eJOmTW7PtJXrgtfKuUcnT3/0He5bTwW9Z
         9baHrHSdpbTH5pNVuiHoydt74HzhoB05MWl55fJF/4CV7yFylbA9t2cDtbxZ9PfszwF/
         WPfAmlcsd6QTWLWdkoka/Yeq54gYiwfvZpPt90aXNA72VhjmdTSANAuaa8eEkSGVLPUz
         ta0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+aiDNPUQvjL0Pw/enpAZcxq+0p6iG3PlngQAtihLtYA=;
        b=D9gKx5ZE5obZ550YT796TY5Tu5YbBq15aHHGc4l/JHp/x4znVl4HHmBMWMRJ6YeJ5y
         aOMEYKyAMr+LdBYcLeQfdnRcaYrRgsNS6hg7uya5jCnJPB1q8sqiMsJOhwTvupDpZ95J
         AA1uSbveoGImVT10SXm5/wPARhfcblz5jiZfo5ICVVfUP6m9cdZyav5RwYQGb8lRdNcm
         TrEW7Ftr0y9Jej6TPeaqZAqyu+09/mbY3rxpFIu5J08rKxtB0s1wdJO1mdLjnT5w/ihq
         x1Lrkc9UZPC79jXzJVdc0w866a2WiscoA/yQmiKwls98C4z4ztsnB2S18JwmzLAXYvZH
         myjw==
X-Gm-Message-State: AGi0Pua4HSlAPI58HEI5WGZOYWJAOoEcsb9P2Mw6PnC0WsvtMAXZGwpg
	f4dUzNFRZ0WVFhywrMwByg4=
X-Google-Smtp-Source: APiQypLxxKse9sCfJB+FBPz+161UM28ZaVV5BGp2OAahoJs1kLBE7w5koNPipcn4Qg7ezwm26c+tQQ==
X-Received: by 2002:a25:4149:: with SMTP id o70mr23772760yba.235.1589195684356;
        Mon, 11 May 2020 04:14:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:76c9:: with SMTP id r192ls3382494ybc.11.gmail; Mon, 11
 May 2020 04:14:44 -0700 (PDT)
X-Received: by 2002:a25:aaa2:: with SMTP id t31mr25239976ybi.352.1589195683966;
        Mon, 11 May 2020 04:14:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589195683; cv=none;
        d=google.com; s=arc-20160816;
        b=xz29j6jDBNJF/FSlL8nQZKOLkDn8OKjxPxxvTXxEhplzkMhsLOTi/jOWCs5UTBIsGv
         VwysBAKsS0n7oPd+BitjZdeRYrgJ52T3x7go2Au3BnKkb+z3vLvyuyc9yESM2bJMFC4c
         yMNXP88ApuvFjzkVBo6ekD7bprFeV1AcqUk+YS8nMTGKak/zVNklcQsScfKJSAy2gI8p
         FFD/c4F2kehQCF8hyKhYhAraLuSUR3MUU1iZ149SE5njN+2eMaza8+RJE/iR2JutO55H
         44cYJnfQ10KPc3H9Zkyk9ccKhF/+rd0xASaveKs6zliN1E4gKk2TJ3nWevoyf5ccd9r4
         C+7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0Yiq17KeeoPAL2ALedPiCre2LYd91TsHJmWVoUnhISo=;
        b=bLv0G/xnsePVcHs5mcrx9emlOO5YgJwVWGepA/IMEGq9dBRjLlN1tcliLjJhiQKJ7r
         FQyqMvmiRnSay1Icqi0EL/ROZmM49agT68soA/Gyh+6wcnu6DSwfjhEbTWgsplvK6sPD
         moP93FJt8hSsUtNMi1Pqlkz/S0UhPn8AiZ3XlRQXG54o/Wb0NJz40NDnRIhRnrCfnjxd
         K2KskqCPD1HP9W6oaCi1DXpZYVHlBNhHQcc/chS87rAhkfNpwpcocixWj2Wa6jS7Rf6z
         AUbM+MMsgbqsv2rEsB8aGrIcBbN6jEwvX3LuP4uq0++0rNnBn8saSVYV5UGwDS1iZaMv
         YFBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mXiDmvSv;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf43.google.com (mail-qv1-xf43.google.com. [2607:f8b0:4864:20::f43])
        by gmr-mx.google.com with ESMTPS id r206si623558ybc.4.2020.05.11.04.14.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 May 2020 04:14:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) client-ip=2607:f8b0:4864:20::f43;
Received: by mail-qv1-xf43.google.com with SMTP id 59so4335340qva.13
        for <kasan-dev@googlegroups.com>; Mon, 11 May 2020 04:14:43 -0700 (PDT)
X-Received: by 2002:a0c:db03:: with SMTP id d3mr5012984qvk.80.1589195683252;
 Mon, 11 May 2020 04:14:43 -0700 (PDT)
MIME-Version: 1.0
References: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 May 2020 13:14:32 +0200
Message-ID: <CACT4Y+YN7cmx71UKiREV7UhMdTfuxQEOGUrtDVXDvK9PW7qNPw@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] rcu/kasan: record and print call_rcu() call stack
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Josh Triplett <josh@joshtriplett.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mXiDmvSv;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43
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

On Mon, May 11, 2020 at 4:31 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> This feature will record first and last call_rcu() call stack and
> print two call_rcu() call stack in KASAN report.
>
> When call_rcu() is called, we store the call_rcu() call stack into
> slub alloc meta-data, so that KASAN report can print rcu stack.
>
> It doesn't increase the cost of memory consumption. Because we don't
> enlarge struct kasan_alloc_meta size.
> - add two call_rcu() call stack into kasan_alloc_meta, size is 8 bytes.
> - remove free track from kasan_alloc_meta, size is 8 bytes.
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
>  kernel/rcu/tree.c     |  3 +++
>  lib/Kconfig.kasan     |  2 ++
>  mm/kasan/common.c     |  4 ++--
>  mm/kasan/generic.c    | 29 +++++++++++++++++++++++++++++
>  mm/kasan/kasan.h      | 19 +++++++++++++++++++
>  mm/kasan/report.c     | 21 +++++++++++++++++----
>  7 files changed, 74 insertions(+), 6 deletions(-)
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
> index 06548e2ebb72..de872b6cc261 100644
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
> @@ -2694,6 +2695,8 @@ __call_rcu(struct rcu_head *head, rcu_callback_t func)
>                 trace_rcu_callback(rcu_state.name, head,
>                                    rcu_segcblist_n_cbs(&rdp->cblist));
>
> +       kasan_record_aux_stack(head);
> +
>         /* Go handle any RCU core processing required. */
>         if (IS_ENABLED(CONFIG_RCU_NOCB_CPU) &&
>             unlikely(rcu_segcblist_is_offloaded(&rdp->cblist))) {
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 81f5464ea9e1..56a89291f1cc 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -58,6 +58,8 @@ config KASAN_GENERIC
>           For better error detection enable CONFIG_STACKTRACE.
>           Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
>           (the resulting kernel does not boot).
> +         Currently CONFIG_KASAN_GENERIC will print first and last call_rcu()
> +         call stack. It doesn't increase the cost of memory consumption.

We don't plan to change this and this is not a bug, right? So I think
using "Currently" is confusing. What's changing in future?

s/will print/prints/
Simple present tense is the default for documentation, we are just
stating facts.

The remark about not increasing memory consumption is both false and
not useful (we don't give an option to change this).

I would just say:

"In generic mode KASAN prints first and last call_rcu() call stacks in reports."


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
> index 56ff8885fe2e..b86880c338e2 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -325,3 +325,32 @@ DEFINE_ASAN_SET_SHADOW(f2);
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
> +       if (!alloc_info->rcu_stack[0])
> +               /* record first call_rcu() call stack */
> +               alloc_info->rcu_stack[0] = kasan_save_stack(GFP_NOWAIT);
> +       else
> +               /* record last call_rcu() call stack */
> +               alloc_info->rcu_stack[1] = kasan_save_stack(GFP_NOWAIT);
> +}
> +
> +struct kasan_track *kasan_get_aux_stack(struct kasan_alloc_meta *alloc_info,
> +                                               u8 idx)
> +{
> +       return container_of(&alloc_info->rcu_stack[idx],
> +                                               struct kasan_track, stack);
> +}
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index e8f37199d885..1cc1fb7b0de3 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -96,15 +96,28 @@ struct kasan_track {
>         depot_stack_handle_t stack;
>  };
>
> +#ifdef CONFIG_KASAN_GENERIC
> +#define SIZEOF_PTR sizeof(void *)
> +#define KASAN_NR_RCU_CALL_STACKS 2
> +#else /* CONFIG_KASAN_GENERIC */
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>  #define KASAN_NR_FREE_STACKS 5
>  #else
>  #define KASAN_NR_FREE_STACKS 1
>  #endif
> +#endif /* CONFIG_KASAN_GENERIC */
>
>  struct kasan_alloc_meta {
>         struct kasan_track alloc_track;
> +#ifdef CONFIG_KASAN_GENERIC
> +       /*
> +        * call_rcu() call stack is stored into struct kasan_alloc_meta.
> +        * The free stack is stored into freed object.
> +        */
> +       depot_stack_handle_t rcu_stack[KASAN_NR_RCU_CALL_STACKS];
> +#else
>         struct kasan_track free_track[KASAN_NR_FREE_STACKS];
> +#endif
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>         u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
>         u8 free_track_idx;
> @@ -159,16 +172,22 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
>
>  struct page *kasan_addr_to_page(const void *addr);
>
> +depot_stack_handle_t kasan_save_stack(gfp_t flags);
> +
>  #if defined(CONFIG_KASAN_GENERIC) && \
>         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
>  void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
>  void quarantine_reduce(void);
>  void quarantine_remove_cache(struct kmem_cache *cache);
> +struct kasan_track *kasan_get_aux_stack(struct kasan_alloc_meta *alloc_info,
> +                       u8 idx);
>  #else
>  static inline void quarantine_put(struct kasan_free_meta *info,
>                                 struct kmem_cache *cache) { }
>  static inline void quarantine_reduce(void) { }
>  static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
> +static inline struct kasan_track *kasan_get_aux_stack(
> +                       struct kasan_alloc_meta *alloc_info, u8 idx) { return NULL; }
>  #endif
>
>  #ifdef CONFIG_KASAN_SW_TAGS
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 80f23c9da6b0..f16a1a210815 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -105,9 +105,13 @@ static void end_report(unsigned long *flags)
>         kasan_enable_current();
>  }
>
> -static void print_track(struct kasan_track *track, const char *prefix)
> +static void print_track(struct kasan_track *track, const char *prefix,
> +                                               bool is_callrcu)
>  {
> -       pr_err("%s by task %u:\n", prefix, track->pid);
> +       if (is_callrcu)
> +               pr_err("%s:\n", prefix);
> +       else
> +               pr_err("%s by task %u:\n", prefix, track->pid);
>         if (track->stack) {
>                 unsigned long *entries;
>                 unsigned int nr_entries;
> @@ -187,11 +191,20 @@ static void describe_object(struct kmem_cache *cache, void *object,
>         if (cache->flags & SLAB_KASAN) {
>                 struct kasan_track *free_track;
>
> -               print_track(&alloc_info->alloc_track, "Allocated");
> +               print_track(&alloc_info->alloc_track, "Allocated", false);
>                 pr_err("\n");
>                 free_track = kasan_get_free_track(cache, object, tag);
> -               print_track(free_track, "Freed");
> +               print_track(free_track, "Freed", false);
>                 pr_err("\n");
> +
> +               if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> +                       free_track = kasan_get_aux_stack(alloc_info, 0);
> +                       print_track(free_track, "First call_rcu() call stack", true);
> +                       pr_err("\n");
> +                       free_track = kasan_get_aux_stack(alloc_info, 1);
> +                       print_track(free_track, "Last call_rcu() call stack", true);
> +                       pr_err("\n");
> +               }
>         }
>
>         describe_object_addr(cache, object, addr);
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200511023111.15310-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYN7cmx71UKiREV7UhMdTfuxQEOGUrtDVXDvK9PW7qNPw%40mail.gmail.com.
