Return-Path: <kasan-dev+bncBCMIZB7QWENRBNUL4X2QKGQEWKAOZFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 81DDB1CD9E6
	for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 14:31:52 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id 18sf7303487pll.3
        for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 05:31:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589200311; cv=pass;
        d=google.com; s=arc-20160816;
        b=T0PVl3v39/cJEWahiEay4H1W2zdp3tZ/LQMDTe4Lu4SfWfHF0UJ+VRq6/ika+aB/iD
         cVn7qAP73k+YuKM+/X+YsomlY++EgVQ1T8FYtfC9FPiCVVoV3RPL4IOwRKggQ4E58hJq
         6g3G6Do37LZU8Lv+bCZ3sDmL72vD6BhnpxPFDTB+bn/tkNNKsN6/ecdZTViBTSNiplad
         EdVJ0sW83T8TyGtmuaQFVmgaqA0/CLhDdck0IDEMWsNPJ42wsRB1qCOzzia4WoGC2oS+
         /9ry5OZZF2RA0Qmx1oHoBT0Cd8YV+uM8hzgqla8Jya2Kf6wcZEXwT7pr9ilD+WRNd9R7
         UwKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ScMVJAOyawkvrX7iIA8mU1Xnsy9WDKPlw5OmEipfhD4=;
        b=D0oxFtFhfCf2OKP8XG2Xrhk14ZpeEp7kA89LUrC9ZROz593U0y97iZAW8ee4M+vfIo
         cQf+9duxcHUAxekWAGJsEKAs/VtizGA6ylV/74yJCtsk5uhwiFiFfPnpf/LJFeuh5bZK
         JJS+Ls9PWUl4xAK39skqxFw2NHGkL3z94tTxdyLgjTkEvaLmRZL17Ma9HfwY6hi+thaI
         g6j7tf+InRvt6sAECh22MtvGpcg9ZJsnpSSbBdwPkZWBmQz8i8wiTsiVghrrB0Y2pv7a
         csIoFWJb4NOcbg6dg1x/C4S+Q4GdHMiKRV50n+G5IpcWS4KLQ57u/ANUHG79dwEu5iBd
         LNbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="YtQ6H/Ia";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ScMVJAOyawkvrX7iIA8mU1Xnsy9WDKPlw5OmEipfhD4=;
        b=GjDLm+1z1lb6O5D0osC5ubq7r7fCJ54J9DVoCv9NFp6eS7mMyhFsqPWXjZx5JXNZSE
         OCySyJK6KB/DNQPqITlbKRRZ3vrJZoaTeun68qJGRi43/VHzAaEsjmSR+h9l44wFR2yg
         S+bND1qNI+amPFFme54KMDrAckrsn92E9JVicl/kjNmtfbQsa6bB+Ase9OO4C5DrdATe
         HaDEQtlpf8yeHCG/b0jyTUq0Y2oY6aONS3XpjXzs7vSjSg6ZNbJBpUiP9U3pY+K99GC6
         yZc0YT39L7TJQVHKeU10V3cOnooaXEo15Q7eGmlrfW7auU8XqMNgRMi8FCFEmGMTqNA5
         aLDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ScMVJAOyawkvrX7iIA8mU1Xnsy9WDKPlw5OmEipfhD4=;
        b=fUtRfXrJ7dGIAYcCzSLoKBgPExh7G5iETyxqtnvU3ZInwyVA/BJpf7suTsoAHWmBJl
         w0/Kt1IGvnaYZY1DwYgaYTjJddCazPPeiSC1rUuG/uD6bjoRnmnk2zAYh1vxnqH2YydS
         S3fJgum8/PEMjOEjprAX+rCnGZns8I9jpNrjG783278xTMdUmx4pG9gpuW9C5Fkg+zDs
         ljk5LcEik5fjuYch8niTeyXNB0y6L6uSbmqmRPSQZGYYr4GCD+vn274uiJvCql2YXdyN
         yF2AINsZiG1HOg7lXRSIk7CkSTk/PMxXkejYihXzmjiIJFx1iT3x23+fV8xQNrh7/fto
         0osQ==
X-Gm-Message-State: AGi0PubBhKwTi6DlOqvuHDVnCKeF45BOy0Ex3P3wAJe09VhUMeyGuLsM
	SpmqVR8jwou5qpnb/WnaMcM=
X-Google-Smtp-Source: APiQypKcRBUQ0EWvV+2uxTuGQHyqzdtUu3fD4GDsvSergyzQAughqIiAeutxI1YlEF3v7XRt9uRQwA==
X-Received: by 2002:a17:90a:8815:: with SMTP id s21mr22719509pjn.154.1589200310879;
        Mon, 11 May 2020 05:31:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ca12:: with SMTP id x18ls16526410pjt.2.canary-gmail;
 Mon, 11 May 2020 05:31:50 -0700 (PDT)
X-Received: by 2002:a17:902:c193:: with SMTP id d19mr15339424pld.60.1589200310513;
        Mon, 11 May 2020 05:31:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589200310; cv=none;
        d=google.com; s=arc-20160816;
        b=zT65nwNIQFedYruHGmMC2H899Y+L96N8RPGT7PhXlGSMWc3TJ/vIIUhfxus+bAQUiE
         I3MXvwQZZ/XHIErPFQzv17Jw6YpTO2BFdRNMvV6HdENKVDPQEv5h4aSAHunadnfovYuR
         2x+pHcdQ9iKwlX1KN+Sd0Th3AGYnVWq8vD73S169TtU8HYVAPWJrAive7CnfFueagaRg
         GYaE6ouvgToDO77B23s6uZWVMPwCTbN2uZ+aHui1vDPE3Lb/faX2vWAaavOZrvNvjX4N
         SFjmbCZrWlezm/WbAdz0qYABXNM8p1ZjJ2ThxgcsItq/mQiFBpq5umLjMjxnG9QALnHD
         rG8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=x+HxYeL1lqwTBd9S2yxU8pNrVDCqS5KUpPIwISNSAbg=;
        b=DJL2UYOYojNi6tAaG6O+80GLCbv8Niq9a5g4v44P8y6PbKroY9sz7KHoxrU+o6J5qr
         xT/QaKKD87vzCpke1AbNw5coEQpI7zQWwYaZq+5AHlRXkJAesMUgUluhpQRgUr9DuhRs
         I5Fno/jZNgNTohqUFXvkLhqF4M3THefCNiguBrO6Xn4gh5geHCYxfN5oPgauOIS4uKi1
         UKs0Fyt0R5o9kZnUa4WFJRE/bySNDxpwEtZT9C+5d1gr/upsmiU6R6I6hyTWs4WE4x5I
         yQS4WJ06XFBc4JZubcMkcRoluQutcnyG79cW4tushukGY3pNsFfA8JYL/9IL5byPUQGt
         Uzlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="YtQ6H/Ia";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id bi9si689313plb.3.2020.05.11.05.31.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 May 2020 05:31:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id s186so7625735qkd.4
        for <kasan-dev@googlegroups.com>; Mon, 11 May 2020 05:31:50 -0700 (PDT)
X-Received: by 2002:a05:620a:990:: with SMTP id x16mr7641458qkx.256.1589200309364;
 Mon, 11 May 2020 05:31:49 -0700 (PDT)
MIME-Version: 1.0
References: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 May 2020 14:31:38 +0200
Message-ID: <CACT4Y+YWNwTSoheJhc3nMdQi9m719F3PzpGo3TfRY3zAg9EwuQ@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b="YtQ6H/Ia";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
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

Please move this to generic.c closer to kasan_set_free_info.
Unnecessary in the header.

> +#define KASAN_NR_RCU_CALL_STACKS 2

Since KASAN_NR_RCU_CALL_STACKS is only used once below, you could as
well use 2 instead of it.
Reduces level of indirection and cognitive load.

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYWNwTSoheJhc3nMdQi9m719F3PzpGo3TfRY3zAg9EwuQ%40mail.gmail.com.
