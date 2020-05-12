Return-Path: <kasan-dev+bncBDGPTM5BQUDRBOUX5D2QKGQENONKGDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F81B1CEAE6
	for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 04:36:43 +0200 (CEST)
Received: by mail-vs1-xe40.google.com with SMTP id a4sf1910694vsp.8
        for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 19:36:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589251002; cv=pass;
        d=google.com; s=arc-20160816;
        b=hQe+VvHXVTDcBSNKNYL+U/2IA+qy5iGvCQJ0WKiFoj7o0R/gtIPD2HoOer6qGgTZZs
         U48GApmJ3/AoxyjRAVgY/1Z4ymio3V1ii6qBHA8GTrYsFVTaJ/hQ4plmEGxY3eNPY4FN
         jppSWXfY3Sz3DHlkq/JAQFClLXKGhDj/JDvPcQGVtO1eTrGOjMQcHlwLwOPCodPUTFVu
         4tY5rY98iCgSFUImP6iUb0IuQ+9Osohs+H5Gr7fdp/G5StWAIggeHdtmmMnrFU5A2taL
         TVLkhnscou7pWEOi06u/dasHof9jjGawxY8pBMPu+oB5NPEpcv71RXMCLH5nd5GKKS0e
         rdYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=dzUriT+nVk3OQ6R3vN8j1TjC/LIzevNMnlOLnz66+6A=;
        b=wqI1wu4lhHdj+7Vq7H1O/3PcEAsSeMrgpQtxY98aAMGp4foUON4Csc/UNaQIvih8b4
         XYCRyOXBYeykhrtQY7FC7ufnWLKZ6N+Xb5VawfW3Us8LNLjT1bloB+T3ZZbAOd1/kuKl
         GHSBrbR9jpf4kMWFLQ/AtZi8hJjwXFlzcVfgtMTu29og3EFKZb5U7ZjHFoSQE0n9EwCg
         sBFJf+mjHMfYo4gKo44EvqDsJYzzEg3ItbNH+1E47WsQE4JHNwvler8nFN7STTUKjEth
         X3lpChrmBbgMLNpE1wgudyKly6x7R5T4XkVPpIKnZnMBs4Kh6YY7azXQ81OQkAkyzYSz
         lg5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=NQkHlMbJ;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dzUriT+nVk3OQ6R3vN8j1TjC/LIzevNMnlOLnz66+6A=;
        b=lL3qwOojOGl05tQVyQSjdRO6RfXCJ9/0jUuWfqssJBrbFAO+6pfrn0EdBAHqQQeeyJ
         DDFKD0YVg0A0d1nP+6qxoht7TldA/FrBneD7wVUM7X/Dh5pzxNYgDFzVG0OpOmLpDnr3
         3alEiLFkOK9zjyGM8sqBZcuUZxWN/ybqzF1SY6qDzpfRKD5G93K5tmDxcD0AmB98rVRc
         tqlx0p98DrfJ9bk8Qdz9eIde4l9lciN864G0yLPIsKEr/vRVDLt10U14row3jW2FGOvW
         kUIljmd45wwxSARfNv6sw65XO2Er8313+4H0sLYlimozoKyiuqtr0v0UqH2mujo3sJQg
         GWIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dzUriT+nVk3OQ6R3vN8j1TjC/LIzevNMnlOLnz66+6A=;
        b=kgWtKtRVG/BwdxvFMN19yzN8OX1qcCJwMT7b3et4scGdTQaXKxCwj1Gg2/G00lGMBV
         VMsfSceVW2nv+fTUvOPeEACwxW2MYpw+KR1oZC2QLyO6106oLm3iYjGRiN5ZT3eD/4+F
         TNMXyGFQbW0GEh2Chzwnn9qquseUTfwl3QyKmahEC/DNHvH/Wk0cILvZpEoEwnwFpB/B
         yRJ/GCVvd6mJeW3M4s3HkSnQ7yKUl256E1WdfknfoiYkobjBneoKFQrP/DIIB6KsQmA7
         dtlCZYNq4MczAqS6i2Ic2senr34ZAt8YL4rDHDV0ypiwZTKjL+vkH+fK4JtL8abhnuEW
         wcIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuacGhbtKSKLbVxUkXMnTDtGTV+JfPhCTobZdGEwEolvmLn1S6WG
	UO5VgwgL4LwhomMLrMxEVRk=
X-Google-Smtp-Source: APiQypJhybA1R19aBVl6Nq/LfyQCZotfN7uF1uHayDDHz5XUORihuv1jw0ZarLhBYUT4eTQz2aBqnA==
X-Received: by 2002:a67:7c50:: with SMTP id x77mr15247380vsc.187.1589251002313;
        Mon, 11 May 2020 19:36:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:fc91:: with SMTP id x17ls235162vsp.10.gmail; Mon, 11 May
 2020 19:36:41 -0700 (PDT)
X-Received: by 2002:a67:1943:: with SMTP id 64mr14719384vsz.113.1589251001856;
        Mon, 11 May 2020 19:36:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589251001; cv=none;
        d=google.com; s=arc-20160816;
        b=JuBNoV5wXlOZZu13iJ1tMcx544K1IeuWtDVAMN5ZRAmHoCO/Gbuuu7bGYSJzPG7+vp
         URl0j9lUMJRNpxQXEatYHHLWMlTD4mQ1il5OoenMjBurwYjLnyCS2EZv/z0LZ5Jem+fb
         WH16yWNwYG1tdW+8OW3Na5ua8KjxxG6DEAfeZsWTNnD5uiXv6ymJQTyDVZ8wwJuyJuuJ
         DYKF13Kb3BML+0dBrRZ0ip4aPjDy8LL6kvDDIJsoSTgCTlrVX484uQbd+XouDaKOK6No
         6MBUizNa0A4hJSKTBhr9lt1lhQAW6TT5mdOR/ShrfjZgaAXubVxi8ExUbk6hIeiH3zjJ
         CgCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=FQ7XyHiA4cqNGdsuVZJtrzYx0SKzIOlxJaYrSNfV8VA=;
        b=v/ZpSxCgQe5A3Wa/3ONkUf4AToWAil65jia2mKt4g1vfL6RaGjUqIZu3Quxe5o6e26
         I5u/wPf1x8qxRTN1tlbVZz2IL96Ddw7dZlAw6dRQ8u9tCBIhoRglj1Elkrox5q/d94Ac
         xx3gvYobpZjL4d/2Ducssv1WO80SGSmBVYDgyzP4uEkEteHi6+mkf24m8CG8QBMo5ucr
         deaXtlA2jYegkMu8kF9NHypUjYJr+zIBQpauF4BHNjfi9p9oJF6ofWUatj0IfvKDPihG
         UMcCYWvxi+7+cqYYla2j6+fFciJUmjzy/iecA3SKa6pT71lx6Fm0P+H6QsBW1DSZHQqK
         9QTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=NQkHlMbJ;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id i26si167799vsk.0.2020.05.11.19.36.40
        for <kasan-dev@googlegroups.com>;
        Mon, 11 May 2020 19:36:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 1145165c29884c03831785316739ad91-20200512
X-UUID: 1145165c29884c03831785316739ad91-20200512
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1333453759; Tue, 12 May 2020 10:36:35 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 12 May 2020 10:36:29 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 12 May 2020 10:36:29 +0800
Message-ID: <1589250993.19238.22.camel@mtksdccf07>
Subject: Re: [PATCH v2 1/3] rcu/kasan: record and print call_rcu() call stack
From: Walter Wu <walter-zh.wu@mediatek.com>
To: <paulmck@kernel.org>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Josh Triplett <josh@joshtriplett.org>, "Mathieu
 Desnoyers" <mathieu.desnoyers@efficios.com>, Lai Jiangshan
	<jiangshanlai@gmail.com>, Joel Fernandes <joel@joelfernandes.org>, "Andrew
 Morton" <akpm@linux-foundation.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Tue, 12 May 2020 10:36:33 +0800
In-Reply-To: <20200511180527.GZ2869@paulmck-ThinkPad-P72>
References: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
	 <20200511180527.GZ2869@paulmck-ThinkPad-P72>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=NQkHlMbJ;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Mon, 2020-05-11 at 11:05 -0700, Paul E. McKenney wrote:
> On Mon, May 11, 2020 at 10:31:11AM +0800, Walter Wu wrote:
> > This feature will record first and last call_rcu() call stack and
> > print two call_rcu() call stack in KASAN report.
> 
> Suppose that a given rcu_head structure is passed to call_rcu(), then
> the grace period elapses, the callback is invoked, and the enclosing
> data structure is freed.  But then that same region of memory is
> immediately reallocated as the same type of structure and again
> passed to call_rcu(), and that this cycle repeats several times.
> 
> Would the first call stack forever be associated with the first
> call_rcu() in this series?  If so, wouldn't the last two usually
> be the most useful?  Or am I unclear on the use case?
> 

The first call stack doesn't forever associate with first call_rcu(),
if someone object freed and reallocated, then the first call stack will
replace with new object.

> > When call_rcu() is called, we store the call_rcu() call stack into
> > slub alloc meta-data, so that KASAN report can print rcu stack.
> > 
> > It doesn't increase the cost of memory consumption. Because we don't
> > enlarge struct kasan_alloc_meta size.
> > - add two call_rcu() call stack into kasan_alloc_meta, size is 8 bytes.
> > - remove free track from kasan_alloc_meta, size is 8 bytes.
> > 
> > [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> > [2]https://groups.google.com/forum/#!searchin/kasan-dev/better$20stack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ
> > 
> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > Cc: Paul E. McKenney <paulmck@kernel.org>
> > Cc: Josh Triplett <josh@joshtriplett.org>
> > Cc: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
> > Cc: Lai Jiangshan <jiangshanlai@gmail.com>
> > Cc: Joel Fernandes <joel@joelfernandes.org>
> > ---
> >  include/linux/kasan.h |  2 ++
> >  kernel/rcu/tree.c     |  3 +++
> >  lib/Kconfig.kasan     |  2 ++
> >  mm/kasan/common.c     |  4 ++--
> >  mm/kasan/generic.c    | 29 +++++++++++++++++++++++++++++
> >  mm/kasan/kasan.h      | 19 +++++++++++++++++++
> >  mm/kasan/report.c     | 21 +++++++++++++++++----
> >  7 files changed, 74 insertions(+), 6 deletions(-)
> > 
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 31314ca7c635..23b7ee00572d 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -174,11 +174,13 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> >  
> >  void kasan_cache_shrink(struct kmem_cache *cache);
> >  void kasan_cache_shutdown(struct kmem_cache *cache);
> > +void kasan_record_aux_stack(void *ptr);
> >  
> >  #else /* CONFIG_KASAN_GENERIC */
> >  
> >  static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
> >  static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
> > +static inline void kasan_record_aux_stack(void *ptr) {}
> >  
> >  #endif /* CONFIG_KASAN_GENERIC */
> >  
> > diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> > index 06548e2ebb72..de872b6cc261 100644
> > --- a/kernel/rcu/tree.c
> > +++ b/kernel/rcu/tree.c
> > @@ -57,6 +57,7 @@
> >  #include <linux/slab.h>
> >  #include <linux/sched/isolation.h>
> >  #include <linux/sched/clock.h>
> > +#include <linux/kasan.h>
> >  #include "../time/tick-internal.h"
> >  
> >  #include "tree.h"
> > @@ -2694,6 +2695,8 @@ __call_rcu(struct rcu_head *head, rcu_callback_t func)
> >  		trace_rcu_callback(rcu_state.name, head,
> >  				   rcu_segcblist_n_cbs(&rdp->cblist));
> >  
> > +	kasan_record_aux_stack(head);
> 
> Just for the record, at this point we have not yet queued the callback.
> We have also not yet disabled interrupts.  Which might be OK, but I
> figured I should call out the possibility of moving this down a few
> lines to follow the local_irq_save().
> 

We will intend to do it.

> If someone incorrectly invokes concurrently invokes call_rcu() on this
> same region of memory, possibly from an interrupt handler, we are OK
> corrupting the stack traces, right?
> 

Yes, and the wrong invoking call_rcu should be recorded.

> But what happens if a given structure has more than one rcu_head
> structure?  In that case, RCU would be just fine with it being
> concurrently passed to different call_rcu() invocations as long as the
> two invocations didn't both use the same rcu_head structure.  (In that
> case, they had best not be both freeing the object, and if even one of
> them is freeing the object, coordination is necessary.)
> 
> If this is a problem, one approach would be to move the
> kasan_record_aux_stack(head) call to kfree_rcu().  After all, it is
> definitely illegal to pass the same memory to a pair of kfree_rcu()
> invocations!  ;-)
> 

The function of kasan_record_aux_stack(head) is simple, it is only to
record call stack by the 'head' object.


Thanks.

> 							Thanx, Paul
> 
> > +
> >  	/* Go handle any RCU core processing required. */
> >  	if (IS_ENABLED(CONFIG_RCU_NOCB_CPU) &&
> >  	    unlikely(rcu_segcblist_is_offloaded(&rdp->cblist))) {
> > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > index 81f5464ea9e1..56a89291f1cc 100644
> > --- a/lib/Kconfig.kasan
> > +++ b/lib/Kconfig.kasan
> > @@ -58,6 +58,8 @@ config KASAN_GENERIC
> >  	  For better error detection enable CONFIG_STACKTRACE.
> >  	  Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
> >  	  (the resulting kernel does not boot).
> > +	  Currently CONFIG_KASAN_GENERIC will print first and last call_rcu()
> > +	  call stack. It doesn't increase the cost of memory consumption.
> >  
> >  config KASAN_SW_TAGS
> >  	bool "Software tag-based mode"
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 2906358e42f0..8bc618289bb1 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -41,7 +41,7 @@
> >  #include "kasan.h"
> >  #include "../slab.h"
> >  
> > -static inline depot_stack_handle_t save_stack(gfp_t flags)
> > +depot_stack_handle_t kasan_save_stack(gfp_t flags)
> >  {
> >  	unsigned long entries[KASAN_STACK_DEPTH];
> >  	unsigned int nr_entries;
> > @@ -54,7 +54,7 @@ static inline depot_stack_handle_t save_stack(gfp_t flags)
> >  static inline void set_track(struct kasan_track *track, gfp_t flags)
> >  {
> >  	track->pid = current->pid;
> > -	track->stack = save_stack(flags);
> > +	track->stack = kasan_save_stack(flags);
> >  }
> >  
> >  void kasan_enable_current(void)
> > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > index 56ff8885fe2e..b86880c338e2 100644
> > --- a/mm/kasan/generic.c
> > +++ b/mm/kasan/generic.c
> > @@ -325,3 +325,32 @@ DEFINE_ASAN_SET_SHADOW(f2);
> >  DEFINE_ASAN_SET_SHADOW(f3);
> >  DEFINE_ASAN_SET_SHADOW(f5);
> >  DEFINE_ASAN_SET_SHADOW(f8);
> > +
> > +void kasan_record_aux_stack(void *addr)
> > +{
> > +	struct page *page = kasan_addr_to_page(addr);
> > +	struct kmem_cache *cache;
> > +	struct kasan_alloc_meta *alloc_info;
> > +	void *object;
> > +
> > +	if (!(page && PageSlab(page)))
> > +		return;
> > +
> > +	cache = page->slab_cache;
> > +	object = nearest_obj(cache, page, addr);
> > +	alloc_info = get_alloc_info(cache, object);
> > +
> > +	if (!alloc_info->rcu_stack[0])
> > +		/* record first call_rcu() call stack */
> > +		alloc_info->rcu_stack[0] = kasan_save_stack(GFP_NOWAIT);
> > +	else
> > +		/* record last call_rcu() call stack */
> > +		alloc_info->rcu_stack[1] = kasan_save_stack(GFP_NOWAIT);
> > +}
> > +
> > +struct kasan_track *kasan_get_aux_stack(struct kasan_alloc_meta *alloc_info,
> > +						u8 idx)
> > +{
> > +	return container_of(&alloc_info->rcu_stack[idx],
> > +						struct kasan_track, stack);
> > +}
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index e8f37199d885..1cc1fb7b0de3 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -96,15 +96,28 @@ struct kasan_track {
> >  	depot_stack_handle_t stack;
> >  };
> >  
> > +#ifdef CONFIG_KASAN_GENERIC
> > +#define SIZEOF_PTR sizeof(void *)
> > +#define KASAN_NR_RCU_CALL_STACKS 2
> > +#else /* CONFIG_KASAN_GENERIC */
> >  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> >  #define KASAN_NR_FREE_STACKS 5
> >  #else
> >  #define KASAN_NR_FREE_STACKS 1
> >  #endif
> > +#endif /* CONFIG_KASAN_GENERIC */
> >  
> >  struct kasan_alloc_meta {
> >  	struct kasan_track alloc_track;
> > +#ifdef CONFIG_KASAN_GENERIC
> > +	/*
> > +	 * call_rcu() call stack is stored into struct kasan_alloc_meta.
> > +	 * The free stack is stored into freed object.
> > +	 */
> > +	depot_stack_handle_t rcu_stack[KASAN_NR_RCU_CALL_STACKS];
> > +#else
> >  	struct kasan_track free_track[KASAN_NR_FREE_STACKS];
> > +#endif
> >  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> >  	u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
> >  	u8 free_track_idx;
> > @@ -159,16 +172,22 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
> >  
> >  struct page *kasan_addr_to_page(const void *addr);
> >  
> > +depot_stack_handle_t kasan_save_stack(gfp_t flags);
> > +
> >  #if defined(CONFIG_KASAN_GENERIC) && \
> >  	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> >  void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
> >  void quarantine_reduce(void);
> >  void quarantine_remove_cache(struct kmem_cache *cache);
> > +struct kasan_track *kasan_get_aux_stack(struct kasan_alloc_meta *alloc_info,
> > +			u8 idx);
> >  #else
> >  static inline void quarantine_put(struct kasan_free_meta *info,
> >  				struct kmem_cache *cache) { }
> >  static inline void quarantine_reduce(void) { }
> >  static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
> > +static inline struct kasan_track *kasan_get_aux_stack(
> > +			struct kasan_alloc_meta *alloc_info, u8 idx) { return NULL; }
> >  #endif
> >  
> >  #ifdef CONFIG_KASAN_SW_TAGS
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 80f23c9da6b0..f16a1a210815 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -105,9 +105,13 @@ static void end_report(unsigned long *flags)
> >  	kasan_enable_current();
> >  }
> >  
> > -static void print_track(struct kasan_track *track, const char *prefix)
> > +static void print_track(struct kasan_track *track, const char *prefix,
> > +						bool is_callrcu)
> >  {
> > -	pr_err("%s by task %u:\n", prefix, track->pid);
> > +	if (is_callrcu)
> > +		pr_err("%s:\n", prefix);
> > +	else
> > +		pr_err("%s by task %u:\n", prefix, track->pid);
> >  	if (track->stack) {
> >  		unsigned long *entries;
> >  		unsigned int nr_entries;
> > @@ -187,11 +191,20 @@ static void describe_object(struct kmem_cache *cache, void *object,
> >  	if (cache->flags & SLAB_KASAN) {
> >  		struct kasan_track *free_track;
> >  
> > -		print_track(&alloc_info->alloc_track, "Allocated");
> > +		print_track(&alloc_info->alloc_track, "Allocated", false);
> >  		pr_err("\n");
> >  		free_track = kasan_get_free_track(cache, object, tag);
> > -		print_track(free_track, "Freed");
> > +		print_track(free_track, "Freed", false);
> >  		pr_err("\n");
> > +
> > +		if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> > +			free_track = kasan_get_aux_stack(alloc_info, 0);
> > +			print_track(free_track, "First call_rcu() call stack", true);
> > +			pr_err("\n");
> > +			free_track = kasan_get_aux_stack(alloc_info, 1);
> > +			print_track(free_track, "Last call_rcu() call stack", true);
> > +			pr_err("\n");
> > +		}
> >  	}
> >  
> >  	describe_object_addr(cache, object, addr);
> > -- 
> I> 2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1589250993.19238.22.camel%40mtksdccf07.
