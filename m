Return-Path: <kasan-dev+bncBCMIZB7QWENRBN7E4T2QKGQEEFGGT3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id A5B5E1CD73D
	for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 13:08:40 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id cr5sf9278512qvb.14
        for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 04:08:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589195319; cv=pass;
        d=google.com; s=arc-20160816;
        b=tsQV6knwHk9z2wAxMH6xrXf5qaIVQMsugcrbbqMr0uIPXUU5XuusGVHsOEFBlVNUBY
         14ZXPrD5MkrfNN6hOCPJj1T6lHPZRhHqoSxr/hwyxRlvjRInyoKrnyGAXAjINOKVgxdE
         DEHhUuGOuQs/gGzZXJXG6USDoFhhtuUpEl0gCH+TqYg9ZCEBC6PnDwCgvulKMwpR5mdq
         3g6YsCLh6r61W4RErd/fCkcxwtb7O6Bd4fLUfqVu8ivvZdQvZMkNVUlBnTvasBy5HgWm
         bTL+EnBb0PGBglV+jHEBCA1EPvgfXcLwmfUpg6WEP+RMLDCCUN7Tfh/HZ/Y6V3t35vgL
         xcew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AeyRThgj6H3GmpKe5kjmiuqub5AnxYy8BtugWIaskjM=;
        b=PsTtYAevhrhCOvsykXVFudqVsAcPAP4k+4/ysiGcuKXzllIXH/3bqXgifxBH7a7mYC
         mVhjPMdU+IyDa60Fd7Ce3rZXv1hh+rm9XfIHzU0L3LNhEhchJtsc968dde38Z8M4icYB
         41LMoWCC7qqdbVPSzPPapQygzidPJ8uYdJAyFYIdDscPwcGdUT+THyu5sMuFQoJ1Xu95
         ixwa1TVlbSTyaVHZ9hatZaJ6ZQLB0ZHTFdwp58R7Ext4RizZ7s2gwn75n5L6ECznMgXJ
         /opX8ecVhYbRaaE3lunxvPLawy7921af4vUEoI3TtJ0YIJA6o1zNl/mBBZS5Y8nkhOev
         TtGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bPhme0DY;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AeyRThgj6H3GmpKe5kjmiuqub5AnxYy8BtugWIaskjM=;
        b=iZFKmFqsRRknrjEWVyTPLZ1IOWRmA2TSmZ07L0MlmgSsxvNGNHUpFO5RKAWvxshV02
         9Zgh8NWC6JDikmyCh6fhtGNIHl9+PQTaOPFDpp5TgT7WbW80yXRsJmqCHKgpiWKbPWDH
         AujUCNCY3uI2Jjc30xqpcYO+6/n9adE6kYWrHAQ5YhJ8v/7c/gyhLGx4RvqBtzMCeHVC
         1qbCMZSckxwB6ZVhhntBvRhd7sShuUq3NY2TUzNBGO+kForHdls10EPt4Vu5UfzOk+89
         6kNqi/mMe1j6Nej7JVM2OKTtMNghaVTAUep+eiLnA3MvjXW9XbUBM+32+ipDC4Dp5Srz
         ptrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AeyRThgj6H3GmpKe5kjmiuqub5AnxYy8BtugWIaskjM=;
        b=lfdyHx6dOxHVpWPvwrcQztDBEAdcrvaz+CBKrlzPlWQ36hC12zX5+sJZ/gMszzFqw0
         SlNEciRKNA/nzOAS04pAsoiou1aMrtR9j689g9weR62/jxVryvDcyn8/PKRC+5t2kj0R
         /WEG2ZNRJqSRtOim9mJ62JPu6kSrilm8rmkjkXz0iBQbwRmcrAGOteFWbxohmkwZ43md
         PcQDwRlmE30iivSg8M3Cees+b9jGziondxmrztvhyMKk9HOLoC4nJhX3MRVKJCCzSMGf
         s5f/Pgb+E3yE2WWI7qD0TmS7I8vvpjqpl+hMBJdsw3lgHy4Z6nUb5jpWD4kMSlBLBvV8
         4T9A==
X-Gm-Message-State: AGi0PubaoGgPIEuRflOfH9bC5Jbz33871MSVYXSsjyDNeGFrYIJ5r0HM
	YXvPeyox1v0trVmBXIrsF3c=
X-Google-Smtp-Source: APiQypIrn2MGCErdUQznbicG+kQd5mVWTeaG/FPXsgDC0NlAhpqbtkzkbwDHK9Pi8i+FDIzweCRjVw==
X-Received: by 2002:a37:8207:: with SMTP id e7mr15132561qkd.475.1589195319103;
        Mon, 11 May 2020 04:08:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:6c2c:: with SMTP id k12ls1602120qtu.2.gmail; Mon, 11 May
 2020 04:08:38 -0700 (PDT)
X-Received: by 2002:aed:2142:: with SMTP id 60mr15935417qtc.177.1589195318752;
        Mon, 11 May 2020 04:08:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589195318; cv=none;
        d=google.com; s=arc-20160816;
        b=CAOhT6BaGIdEBJ6h0EEFR+oSX40b9TUKoOhJMmkNZy5uG1oyg4Y+EWvVakmMM9WTzw
         /TD3ASmV855uKbAVFTkuNUqSLHlUOyCNPBL3uk5uXn1qjWHgynREH7aVJKDFV4fOqRPA
         /oizvoiNIDO476t7VuCtplpRDgM9gtIovYXrXLCzF5zgJPyIlzqGWtEhXKJVmPPpmcS6
         VwpKKBqXD+P9uTHabVm2LusGP9lYAvJIbOD9mqZl3V4uWx880gDDVys63kQeuPm3VuP2
         XN5GcsA6BNtEK0wW7szdi0aotjsuPt5TJxmk/nCktzjPxkzFP4VjpZhYdPQepGVEiugu
         rzJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UNMUTX3IVOdWGAHdZTtQUCk6o1GLMdtGOMtI+KbtqjM=;
        b=usaDJBvdooZ/hOxzN+0WtnFKYbwtmbga0rhA3UGQMb0ZeNDdYWo+ub66Ze2JC3nG1o
         AOEF2FzmyMq/rb9+A/KS2rvNyacFobZdxsbwfHIIrkQ5gwOK6+xouJwvWVEAz4YnBV9C
         13523S4UiY5XFECtEsp8vRL95dpN8RFyzl/nrIMue08bJgkR23u46ERjZ3RfHWO13TqD
         WI2j9dXqtawwsTXh5/CDzLAIuJ9HlJMYu2hUIdknxAvm3DxO6pOwCgRv9aQL38sAe3Rr
         mWV9rbIMCnF6/F574JDIqDY0eR/dtmx5bNuxkwXiJY60JxrQ9tGToql46YENj0GM6maa
         O26Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bPhme0DY;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id w66si612767qka.6.2020.05.11.04.08.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 May 2020 04:08:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id f13so8650294qkh.2
        for <kasan-dev@googlegroups.com>; Mon, 11 May 2020 04:08:38 -0700 (PDT)
X-Received: by 2002:ae9:ed05:: with SMTP id c5mr15323301qkg.250.1589195318085;
 Mon, 11 May 2020 04:08:38 -0700 (PDT)
MIME-Version: 1.0
References: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 May 2020 13:08:26 +0200
Message-ID: <CACT4Y+ZDaONL63_GdGQpgs+7dxG3GHRMGcNOVgfn9P88Kx7fig@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=bPhme0DY;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
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

This happens after we queued the object onto some queue and after some
return statements. I think this is wrong.
We need to do this somewhere at the very beginning of the function.

This is what I meant by "hard to review". This is completely invisible
in the diff.


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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZDaONL63_GdGQpgs%2B7dxG3GHRMGcNOVgfn9P88Kx7fig%40mail.gmail.com.
