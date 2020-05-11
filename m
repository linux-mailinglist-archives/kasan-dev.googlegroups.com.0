Return-Path: <kasan-dev+bncBCMIZB7QWENRBA564X2QKGQESN52POQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6714D1CDCEF
	for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 16:19:49 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id m5sf2567909ioq.19
        for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 07:19:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589206788; cv=pass;
        d=google.com; s=arc-20160816;
        b=oiyCAUHXtPLf2nvr8RmkOdWKGh0wZfH2aFiUb6M7brCyLYmZvq7PgbUBwuQB/Xjj/o
         GKt88aSLqPpqETgOVTRygmJdPU0yvKlcQe6l+OfG3yglL7zpPh9a3N0E9NXgs30UkKvf
         rYgq/4QgLZKeYbfbmah/SgkIAzUIAV6M1zONqCKJbgeZIL/dRXWxT6TtBJF28+iTPU55
         K45B679wXe8a69Qlk60a7BVRxRL8b7wVXg/Dxow6iZxWvcT1DiOQGJndrTKOjpvj0vV7
         SGlIHGe9ikJ97XRmT0UTDmmF6J8kKhz/0GkxzItnWH7j5Ev+6QrfzMxjuEfEzYlfPIH6
         xGXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5X6B5g/gSzsl4l55yBe59CFCWt3V4ERlNNn2iB9WFII=;
        b=zEM5YZgb7nOUNfY4X6yfbhTMqETE4qgvwmtyPvkXNNtxHvY0TpMxM5tb0LbH6tlYxy
         zc7+vk1n7zWpeBX6g3Jv33QgCDuCS3jhe4Q5spJJ+kAMWYJHWTEJ81etB8OAPNNSk51d
         z65gKSDaWdIvD4PdoCurXn97H1a1jalAdRW/Ni0srWeg+MXlwVUFHnanOZhaeXcXVMql
         IceZEydptu+XvgpQrP2azzr158nmfZpsxc2j43GXYJL/eq8jIC3yjtXvG/UoR14KJuAb
         xsZs/uxZTzQ6HuybRQonvMhVTPkev8P/tH6bCcdCjfEi75fhDK8kZujH8WB99uahme2M
         twYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FpIqnthq;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5X6B5g/gSzsl4l55yBe59CFCWt3V4ERlNNn2iB9WFII=;
        b=JV3cy+4WF2WjP6WDZyU2rPRXEygr1g1uzEbKsRrBnA3SBE6ACH5Nj85TGqmL9PbM3S
         UFYndLJdv2C94baYZLEqcnJEBUxkuM9LHlJ49wLVgd4LM5CafPnDdXfZvelaOHDx+lcw
         Ynlj+ByX0MIABCR9V8oxx1ZEz5i9dRcN1Klj9hIlQ3WHuHQk5MitRJtHERCmsT3KkfYB
         qxDEzGLZqGLX/WOcvZScQ/Ql3o1MHY73d5Q1igpH52+V8BZR6mswnhVaEXp8KEDxfcHS
         xGyIgQNPLUvvKHoQX4kZPkJ7ICtwCScY47372lkEMzLqTk+2usQwIUGnvsN4Qb6OLsWi
         L47w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5X6B5g/gSzsl4l55yBe59CFCWt3V4ERlNNn2iB9WFII=;
        b=jMS57uhxdTwrC9VGy94QhLcsIm5CxBjhBQwlxrO6+vDoLPCcmbxQKqHyFWYqScVV7z
         oxEILRykAUFrU0cxKi49Rc3MumKjqvri010spo1kI+yIck7Heyf1n9T6yrvS5Tu22pHq
         k35JqmDUoVpay7mr0R0fO4BcJBnQc223CDx7LRZEg8WOjLxRyNeyU7Sr3+0YLiaCHpzH
         BZ6plb0DhzEHt6ofd44XYCY1Z2xqq3T+WvpRBNcpxdyx5iZ4KurdOANG2tp9s/kd1+b/
         BBKyp3EkuMhqGh0sWcm0gc+DoubgvkshzNPkn4Ct1+STTnci+KT1W2oR0pAPwnl3HC9j
         5mlg==
X-Gm-Message-State: AGi0PubHlEh7iPYUD+R/F0p6txnrw3fwAlvRiKn0ekiVspCtkd5AzQDf
	b57yRP4nJni1M5LJBzYERYI=
X-Google-Smtp-Source: APiQypImlIwaN7XhBAHLIPwuPqRpdPogVRXJUJFc1Iq51I2/1670Ubnv3d2VEzg6QthiEvu7dZu5pg==
X-Received: by 2002:a05:6638:a1d:: with SMTP id 29mr16215547jan.21.1589206788045;
        Mon, 11 May 2020 07:19:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8582:: with SMTP id f2ls774608ioj.5.gmail; Mon, 11 May
 2020 07:19:47 -0700 (PDT)
X-Received: by 2002:a6b:6517:: with SMTP id z23mr15718697iob.48.1589206787599;
        Mon, 11 May 2020 07:19:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589206787; cv=none;
        d=google.com; s=arc-20160816;
        b=QSXvZYbr7kJKcf575MAfPH4QRNVsE9wvzwYaGVY4wSWNPPcHb859sM3kk4UCNyL4CD
         WF/IyWOGnQhR3+enfXLejZxc8NZYE/nrZUiVn20xo21eBrOLjS9cjMQu2IIE+vzsYK3J
         7s+wfgs6of89sQG5LLrnomAo6DpspAPAR0WUD0VweQppzf018wV1lIMaw99kMxQj0JlH
         HzPAf/cLB+WbRk2m7kx0f2qqGZRMay0+FCa540JXWFTiqIKHFStX4VcqgZjqhHyaFQNi
         BsPx5zwmwjyN65gWC/EdJm0QLws+TXEcB04hJ6z5spSokcy+MHKdy9AWx/03EZD/UH7e
         jdVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jwYtW81/ygzueOYMSAUrciWMI3nlvA3U3h7VebjOjDI=;
        b=X93PM3o8sY31gvCZ4WpmaBJwjgoh93PosyvdYzb6CGORKXxMPqFzc1AbtKOzAU0NJA
         ycD8Tbxg0LL1GTEAFxzalJilHG7hsShz4EZO8faNoy6hKQ9cScioFxvcar7M7VYFWABm
         Ci7ThtOWCkETuZR8VKFBHZ2xXkgKiygxjHhRcBW110ycmtLMfFJPFV3qRnnzUepKI3HA
         U8J6nc8XTg38M/UGs8q0yyhyccr8IEkCpLy7L82CPwHppii6rf9gvryxzinStAQKA3ZT
         CejHCrvNwCVm+FvllCWTjWOczGM69Kn4kirugv73G6mFDnqCaiEtTaswZasQXfxEsf33
         B64g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FpIqnthq;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id g5si721406ioq.3.2020.05.11.07.19.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 May 2020 07:19:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id g185so9846425qke.7
        for <kasan-dev@googlegroups.com>; Mon, 11 May 2020 07:19:47 -0700 (PDT)
X-Received: by 2002:ae9:f401:: with SMTP id y1mr16758561qkl.8.1589206786606;
 Mon, 11 May 2020 07:19:46 -0700 (PDT)
MIME-Version: 1.0
References: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
 <CACT4Y+YWNwTSoheJhc3nMdQi9m719F3PzpGo3TfRY3zAg9EwuQ@mail.gmail.com>
 <CACT4Y+bO1Zg_jgFHbOWgp7fLAADOQ_-AZmjEHz0WG7=oyOt4Gg@mail.gmail.com> <1589203771.21284.22.camel@mtksdccf07>
In-Reply-To: <1589203771.21284.22.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 May 2020 16:19:34 +0200
Message-ID: <CACT4Y+aOkuH6Dn+L+wv1qVOLgXyCY_Ck4hecAMw3DgyBgC9qHw@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] rcu/kasan: record and print call_rcu() call stack
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Josh Triplett <josh@joshtriplett.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FpIqnthq;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
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

On Mon, May 11, 2020 at 3:29 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > This feature will record first and last call_rcu() call stack and
> > > print two call_rcu() call stack in KASAN report.
> > >
> > > When call_rcu() is called, we store the call_rcu() call stack into
> > > slub alloc meta-data, so that KASAN report can print rcu stack.
> > >
> > > It doesn't increase the cost of memory consumption. Because we don't
> > > enlarge struct kasan_alloc_meta size.
> > > - add two call_rcu() call stack into kasan_alloc_meta, size is 8 bytes.
> > > - remove free track from kasan_alloc_meta, size is 8 bytes.
> > >
> > > [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> > > [2]https://groups.google.com/forum/#!searchin/kasan-dev/better$20stack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ
> > >
> > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > > Cc: Dmitry Vyukov <dvyukov@google.com>
> > > Cc: Alexander Potapenko <glider@google.com>
> > > Cc: Andrew Morton <akpm@linux-foundation.org>
> > > Cc: Paul E. McKenney <paulmck@kernel.org>
> > > Cc: Josh Triplett <josh@joshtriplett.org>
> > > Cc: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
> > > Cc: Lai Jiangshan <jiangshanlai@gmail.com>
> > > Cc: Joel Fernandes <joel@joelfernandes.org>
> > > ---
> > >  include/linux/kasan.h |  2 ++
> > >  kernel/rcu/tree.c     |  3 +++
> > >  lib/Kconfig.kasan     |  2 ++
> > >  mm/kasan/common.c     |  4 ++--
> > >  mm/kasan/generic.c    | 29 +++++++++++++++++++++++++++++
> > >  mm/kasan/kasan.h      | 19 +++++++++++++++++++
> > >  mm/kasan/report.c     | 21 +++++++++++++++++----
> > >  7 files changed, 74 insertions(+), 6 deletions(-)
> > >
> > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > index 31314ca7c635..23b7ee00572d 100644
> > > --- a/include/linux/kasan.h
> > > +++ b/include/linux/kasan.h
> > > @@ -174,11 +174,13 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> > >
> > >  void kasan_cache_shrink(struct kmem_cache *cache);
> > >  void kasan_cache_shutdown(struct kmem_cache *cache);
> > > +void kasan_record_aux_stack(void *ptr);
> > >
> > >  #else /* CONFIG_KASAN_GENERIC */
> > >
> > >  static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
> > >  static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
> > > +static inline void kasan_record_aux_stack(void *ptr) {}
> > >
> > >  #endif /* CONFIG_KASAN_GENERIC */
> > >
> > > diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> > > index 06548e2ebb72..de872b6cc261 100644
> > > --- a/kernel/rcu/tree.c
> > > +++ b/kernel/rcu/tree.c
> > > @@ -57,6 +57,7 @@
> > >  #include <linux/slab.h>
> > >  #include <linux/sched/isolation.h>
> > >  #include <linux/sched/clock.h>
> > > +#include <linux/kasan.h>
> > >  #include "../time/tick-internal.h"
> > >
> > >  #include "tree.h"
> > > @@ -2694,6 +2695,8 @@ __call_rcu(struct rcu_head *head, rcu_callback_t func)
> > >                 trace_rcu_callback(rcu_state.name, head,
> > >                                    rcu_segcblist_n_cbs(&rdp->cblist));
> > >
> > > +       kasan_record_aux_stack(head);
> > > +
> > >         /* Go handle any RCU core processing required. */
> > >         if (IS_ENABLED(CONFIG_RCU_NOCB_CPU) &&
> > >             unlikely(rcu_segcblist_is_offloaded(&rdp->cblist))) {
> > > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > > index 81f5464ea9e1..56a89291f1cc 100644
> > > --- a/lib/Kconfig.kasan
> > > +++ b/lib/Kconfig.kasan
> > > @@ -58,6 +58,8 @@ config KASAN_GENERIC
> > >           For better error detection enable CONFIG_STACKTRACE.
> > >           Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
> > >           (the resulting kernel does not boot).
> > > +         Currently CONFIG_KASAN_GENERIC will print first and last call_rcu()
> > > +         call stack. It doesn't increase the cost of memory consumption.
> > >
> > >  config KASAN_SW_TAGS
> > >         bool "Software tag-based mode"
> > > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > > index 2906358e42f0..8bc618289bb1 100644
> > > --- a/mm/kasan/common.c
> > > +++ b/mm/kasan/common.c
> > > @@ -41,7 +41,7 @@
> > >  #include "kasan.h"
> > >  #include "../slab.h"
> > >
> > > -static inline depot_stack_handle_t save_stack(gfp_t flags)
> > > +depot_stack_handle_t kasan_save_stack(gfp_t flags)
> > >  {
> > >         unsigned long entries[KASAN_STACK_DEPTH];
> > >         unsigned int nr_entries;
> > > @@ -54,7 +54,7 @@ static inline depot_stack_handle_t save_stack(gfp_t flags)
> > >  static inline void set_track(struct kasan_track *track, gfp_t flags)
> > >  {
> > >         track->pid = current->pid;
> > > -       track->stack = save_stack(flags);
> > > +       track->stack = kasan_save_stack(flags);
> > >  }
> > >
> > >  void kasan_enable_current(void)
> > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > index 56ff8885fe2e..b86880c338e2 100644
> > > --- a/mm/kasan/generic.c
> > > +++ b/mm/kasan/generic.c
> > > @@ -325,3 +325,32 @@ DEFINE_ASAN_SET_SHADOW(f2);
> > >  DEFINE_ASAN_SET_SHADOW(f3);
> > >  DEFINE_ASAN_SET_SHADOW(f5);
> > >  DEFINE_ASAN_SET_SHADOW(f8);
> > > +
> > > +void kasan_record_aux_stack(void *addr)
> > > +{
> > > +       struct page *page = kasan_addr_to_page(addr);
> > > +       struct kmem_cache *cache;
> > > +       struct kasan_alloc_meta *alloc_info;
> > > +       void *object;
> > > +
> > > +       if (!(page && PageSlab(page)))
> > > +               return;
> > > +
> > > +       cache = page->slab_cache;
> > > +       object = nearest_obj(cache, page, addr);
> > > +       alloc_info = get_alloc_info(cache, object);
> > > +
> > > +       if (!alloc_info->rcu_stack[0])
> > > +               /* record first call_rcu() call stack */
> > > +               alloc_info->rcu_stack[0] = kasan_save_stack(GFP_NOWAIT);
> > > +       else
> > > +               /* record last call_rcu() call stack */
> > > +               alloc_info->rcu_stack[1] = kasan_save_stack(GFP_NOWAIT);
> > > +}
> > > +
> > > +struct kasan_track *kasan_get_aux_stack(struct kasan_alloc_meta *alloc_info,
> > > +                                               u8 idx)
> > > +{
> > > +       return container_of(&alloc_info->rcu_stack[idx],
> > > +                                               struct kasan_track, stack);
> > > +}
> > > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > > index e8f37199d885..1cc1fb7b0de3 100644
> > > --- a/mm/kasan/kasan.h
> > > +++ b/mm/kasan/kasan.h
> > > @@ -96,15 +96,28 @@ struct kasan_track {
> > >         depot_stack_handle_t stack;
> > >  };
> > >
> > > +#ifdef CONFIG_KASAN_GENERIC
> > > +#define SIZEOF_PTR sizeof(void *)
> >
> > Please move this to generic.c closer to kasan_set_free_info.
> > Unnecessary in the header.
> >
> > > +#define KASAN_NR_RCU_CALL_STACKS 2
> >
> > Since KASAN_NR_RCU_CALL_STACKS is only used once below, you could as
> > well use 2 instead of it.
> > Reduces level of indirection and cognitive load.
> >
> > > +#else /* CONFIG_KASAN_GENERIC */
> > >  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > >  #define KASAN_NR_FREE_STACKS 5
> > >  #else
> > >  #define KASAN_NR_FREE_STACKS 1
> > >  #endif
> > > +#endif /* CONFIG_KASAN_GENERIC */
> > >
> > >  struct kasan_alloc_meta {
> > >         struct kasan_track alloc_track;
> > > +#ifdef CONFIG_KASAN_GENERIC
> > > +       /*
> > > +        * call_rcu() call stack is stored into struct kasan_alloc_meta.
> > > +        * The free stack is stored into freed object.
> > > +        */
> > > +       depot_stack_handle_t rcu_stack[KASAN_NR_RCU_CALL_STACKS];
> > > +#else
> > >         struct kasan_track free_track[KASAN_NR_FREE_STACKS];
> > > +#endif
> > >  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > >         u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
> > >         u8 free_track_idx;
> > > @@ -159,16 +172,22 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
> > >
> > >  struct page *kasan_addr_to_page(const void *addr);
> > >
> > > +depot_stack_handle_t kasan_save_stack(gfp_t flags);
> > > +
> > >  #if defined(CONFIG_KASAN_GENERIC) && \
> > >         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> > >  void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
> > >  void quarantine_reduce(void);
> > >  void quarantine_remove_cache(struct kmem_cache *cache);
> > > +struct kasan_track *kasan_get_aux_stack(struct kasan_alloc_meta *alloc_info,
> > > +                       u8 idx);
> > >  #else
> > >  static inline void quarantine_put(struct kasan_free_meta *info,
> > >                                 struct kmem_cache *cache) { }
> > >  static inline void quarantine_reduce(void) { }
> > >  static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
> > > +static inline struct kasan_track *kasan_get_aux_stack(
> > > +                       struct kasan_alloc_meta *alloc_info, u8 idx) { return NULL; }
> > >  #endif
> > >
> > >  #ifdef CONFIG_KASAN_SW_TAGS
> > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > index 80f23c9da6b0..f16a1a210815 100644
> > > --- a/mm/kasan/report.c
> > > +++ b/mm/kasan/report.c
> > > @@ -105,9 +105,13 @@ static void end_report(unsigned long *flags)
> > >         kasan_enable_current();
> > >  }
> > >
> > > -static void print_track(struct kasan_track *track, const char *prefix)
> > > +static void print_track(struct kasan_track *track, const char *prefix,
> > > +                                               bool is_callrcu)
> > >  {
> > > -       pr_err("%s by task %u:\n", prefix, track->pid);
> > > +       if (is_callrcu)
> > > +               pr_err("%s:\n", prefix);
> > > +       else
> > > +               pr_err("%s by task %u:\n", prefix, track->pid);
> > >         if (track->stack) {
> > >                 unsigned long *entries;
> > >                 unsigned int nr_entries;
> > > @@ -187,11 +191,20 @@ static void describe_object(struct kmem_cache *cache, void *object,
> > >         if (cache->flags & SLAB_KASAN) {
> > >                 struct kasan_track *free_track;
> > >
> > > -               print_track(&alloc_info->alloc_track, "Allocated");
> > > +               print_track(&alloc_info->alloc_track, "Allocated", false);
> > >                 pr_err("\n");
> > >                 free_track = kasan_get_free_track(cache, object, tag);
> > > -               print_track(free_track, "Freed");
> > > +               print_track(free_track, "Freed", false);
> > >                 pr_err("\n");
> > > +
> > > +               if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> > > +                       free_track = kasan_get_aux_stack(alloc_info, 0);
> > > +                       print_track(free_track, "First call_rcu() call stack", true);
> > > +                       pr_err("\n");
> > > +                       free_track = kasan_get_aux_stack(alloc_info, 1);
> > > +                       print_track(free_track, "Last call_rcu() call stack", true);
> > > +                       pr_err("\n");
> > > +               }
> > >         }
> > >
> > >         describe_object_addr(cache, object, addr);
>
> Some higher level comments.
>
> 1. I think we need to put the free track into kasan_free_meta as it
> was before. It looks like exactly the place for it. We have logic to
> properly place it and to do the casts.
>
>
> If the free track put kasan_free_meta, then it increase slab meta size?
> Our original goal does not enlarge it.

Are you sure it will increase object size?
I think we overlap kasan_free_meta with the object as well. The only
case we don't overlap kasan_free_meta with the object are
SLAB_TYPESAFE_BY_RCU || cache->ctor. But these are rare and it should
only affect small objects with small redzones.
And I think now we simply have a bug for these objects, we check
KASAN_KMALLOC_FREE and then assume object contains free stack, but for
objects with ctor, they still contain live object data, we don't store
free stack in them.
Such objects can be both free and still contain user data.


> 2. We need to zero aux stacks when we reallocate the object. Otherwise
> we print confusing garbage.
>
> My local has an UT about use-after-free and rcu, but it is hard to test the printing confusing garbage, because we may need to get the same object(old pointer and new pointer). In generic KASAN is not easy to get it.
>
> 3. __kasan_slab_free now contains a window of inconsistency when it
> marked the object as KASAN_KMALLOC_FREE, but did not store the free
> track yet. If another thread prints a report now, it will print random
> garbage.
>
>
> It is possible, but the window is so tiny. It sets free track immediately after write the KASAN_KMALLOC_FREE.

It is small. But (1) why do we want to allow it at all, (2) there is
actually a more serious problem. If we mark an object as
KASAN_KMALLOC_FREE, but don't do kasan_set_free_info (because object
has ctor), now we will treat live object data as free track. We need
to fix it anyway.




> 4. We need some tests. At least (2) should be visible on tests.
>
>
> Ok.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaOkuH6Dn%2BL%2Bwv1qVOLgXyCY_Ck4hecAMw3DgyBgC9qHw%40mail.gmail.com.
