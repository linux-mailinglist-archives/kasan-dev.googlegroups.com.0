Return-Path: <kasan-dev+bncBDGPTM5BQUDRBWVVSL3AKGQECCZM2QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BF261DA839
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 04:50:03 +0200 (CEST)
Received: by mail-ua1-x937.google.com with SMTP id j26sf631064uan.22
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 19:50:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589943002; cv=pass;
        d=google.com; s=arc-20160816;
        b=FrTFD4V84n1ZCF1pUZM3F9ZAHUQBI6r71gI6rAO58H2mf/85xUhKCVej4mgMKdCfx7
         tVjw7IclA5XXJwHElp2mZJEoML7hKrl5862bMvanxOPlFDSr4i51qO+YKpGx57E+jHmW
         KsWXREYoi8xiifnS5l7upaVutDc+uKZgDAACWmYAnOwpwmp+aaQ0v5ddywI60GdsCIDj
         eMdyDhJ1Rhc+9mxPAx2tStBZr8LDZJFV/zHR/tFLT+c9Z+QkJmitzzeYkYxliRzPgXK9
         h9z0uSEJ25uY5uuk8RE7j19PoBukmmIH70sp+Bg40Gj3+7Lw75H50KszhhTJRccXeQn+
         QiXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=fGkheNcLDpr2P3h2zkfby9OdV0coPaV5370AsaujhG0=;
        b=LSjdq2YXSpOY5xuP7BfzGQzU/Hd45YS89UI35sNGMkBC7WBIfcAMIdBTKcGo8LLJhZ
         T6iBuPRj73GYHV+9RvGf2dA5vq8f8Rml4Z79KLFnswJlBNcEUddSxD5aZD0rNem24lU2
         RGKY2KeGlMA+F6mBvv61ty8t8hLLHWyPVhce3vfI0cYyIwNAeJMIJ/yQmWdX8knbeJSs
         tral3Uxpww5ahgj0QfKL3GNsat+l0rLuX1qU/nVBm1UKWem7UaEmlUbwOwwEc/BHAAqN
         ERcDpleHlO7e+1W6ipsD4r4kaNbbfucSN2pTDwYN0qy85XIM6o0VmnVdvGLJXxPAOnhY
         +jHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=VNTQzhTh;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fGkheNcLDpr2P3h2zkfby9OdV0coPaV5370AsaujhG0=;
        b=DSu0lKvIMP4PFkYlviQ6DvKKSr0PfzsMpIh3Z4yFm3wfhDXGEkMPtEz5OsG5szvFGk
         iNh1XBbPeRX/cOhlIFTaqGxESSOUoL7C22ep7Qj4o0w83GrWJpOJyWFoExdYdUoiTqCF
         zJfNovAi/fqRVWc5nUVbzybarzs7Pu2bSAv0PShA1lg/RPFjvXl18FwIt7l1la2V9fzj
         4khBITa+OpPwrasI7SQ4fvHuDxQVKvvRmR2eIiCPy7PnYddDvt9N01uMvOIZ9SmBRCu1
         yAUHaFbHvAJxsvGDmUSAxsk8KiVejyuoMnZKwkFS60UU762/sNJjbJJT7QUvA1/6hqBd
         tCXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fGkheNcLDpr2P3h2zkfby9OdV0coPaV5370AsaujhG0=;
        b=RLdv7vd4Zn6iFoqnFhNfPIi8W+vRTRaxO3za/vfngum8l18rLgxKm0m2rHloN8aXE7
         nww2WiNx0t+8+n6feRXqth8tHyml8JQSBlIO1cIvnbeCbb2YsocsDkmdIlXIyI+OoHEX
         C5SpwmpgiurnZOY16+MXrF+c7AXu16ZxablxYsqP4e+KF2aGA0yKzFn2UkAYeakWTUIX
         u11vL/0pDTmjTaiked4ilm/3BFyLDYm3TKq4LC7ZsYrAc3zkCczM7zLNGTJgshDfUSl4
         xm08D+eLMRusEccrWcpB0AHYlCDgK4l44h2YgqyH/XjTr+17WqUHFGzifxeILq9p04/S
         B+nQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531dylw2tM3hQfLUhYsKUBScJE3NUOIB4vGYXhcwtVqnWkzYxCUj
	Arawc/J+cm/fyYn7dlKzv38=
X-Google-Smtp-Source: ABdhPJy1NDOHg+RIibxM05Vj3Vjm2tIs2x5SeLd/oRB/Y9keb/Yb5X9JGOhyPUtZTJ21nyDINBkE3w==
X-Received: by 2002:a67:fad8:: with SMTP id g24mr1872961vsq.204.1589943002176;
        Tue, 19 May 2020 19:50:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:3092:: with SMTP id w140ls153912vsw.1.gmail; Tue, 19 May
 2020 19:50:01 -0700 (PDT)
X-Received: by 2002:a05:6102:2123:: with SMTP id f3mr1825554vsg.141.1589943001791;
        Tue, 19 May 2020 19:50:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589943001; cv=none;
        d=google.com; s=arc-20160816;
        b=Sv/sNfzCh3nr4Af0VaWH6XIAyVeAk4qgzg1ccDfq5AD1GMjaJBBTZ9b2esonkr3Hzv
         9a8RPIXHBMNRhME+W7rGWxzSqlWc41fwQ3CvLQBJKiDZEHa3NDSPTmANuNrPYKR1AvWR
         5W5s7FX7mvPqjmpIf890f02esz5fplrWJ/QSGzJxBaqEAranwhWgKXg50rgy/Hjx8qTJ
         ECgZHSH5shRxhzZvtRY0ehzburImrPwObsORKaZhP51Iwg0vSy06EgI36szSQcln0UkJ
         9hFJfVNb/XGmGIThH1kD1qx/mbpTsiq4AMmpSWFIvhiLs4kOSM/c1F269rAtXR4/jnyT
         iRVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=DrIY2R3TOB8CSwrRNRIw6OHgkvC+BEhomkjBceqSmqE=;
        b=bx38kHTDEPfb0ytlfvkyCcfrbxNYWTHwca7B/aLDtIe6D0GK+M8in9BHgjSzwhfw8s
         wjuMA3Dm9Ik6dgt6ph55dOMLnRqKjVuxFbLt0MGefnIS2CohKJDG2FM5n0YzcF7+cPOh
         v3Xax8Vvl7hGaKE07zsDZUdSbfQtLOW3vGnp7xfY3DqylXx0lexyDwK74IiT6wvWahBu
         fUC7Ev1sQ3yxVzxKxi9PZa423DNbDw78ah/f31xQXHoSqojQ5RALNiwhZQxEg9RbmuN7
         ekkwwOytuLtCRyTClVdxpTE/DdEpIUQW6ay7nD0HzizAAN7s+v1byCd9dFqexVv5wGDp
         QvSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=VNTQzhTh;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id d24si155983vsk.2.2020.05.19.19.50.00
        for <kasan-dev@googlegroups.com>;
        Tue, 19 May 2020 19:50:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: d382b904b7c74f2698ee5dae33da4e05-20200520
X-UUID: d382b904b7c74f2698ee5dae33da4e05-20200520
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1382255477; Wed, 20 May 2020 10:49:57 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 20 May 2020 10:49:54 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 20 May 2020 10:49:50 +0800
Message-ID: <1589942995.29577.6.camel@mtksdccf07>
Subject: Re: [PATCH v4 1/4] rcu/kasan: record and print call_rcu() call stack
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
Date: Wed, 20 May 2020 10:49:55 +0800
In-Reply-To: <20200519154819.GJ2869@paulmck-ThinkPad-P72>
References: <20200519022359.24115-1-walter-zh.wu@mediatek.com>
	 <20200519154819.GJ2869@paulmck-ThinkPad-P72>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=VNTQzhTh;       spf=pass
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

On Tue, 2020-05-19 at 08:48 -0700, Paul E. McKenney wrote:
> On Tue, May 19, 2020 at 10:23:59AM +0800, Walter Wu wrote:
> > This feature will record the last two call_rcu() call stacks and
> > prints up to 2 call_rcu() call stacks in KASAN report.
> > 
> > When call_rcu() is called, we store the call_rcu() call stack into
> > slub alloc meta-data, so that the KASAN report can print rcu stack.
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
> 
> From an RCU perspective:
> 
> Acked-by: Paul E. McKenney <paulmck@kernel.org>
> 

Hi Paul,

Thank you for your suggestion and review.


Walter

> > ---
> >  include/linux/kasan.h |  2 ++
> >  kernel/rcu/tree.c     |  2 ++
> >  lib/Kconfig.kasan     |  2 ++
> >  mm/kasan/common.c     |  4 ++--
> >  mm/kasan/generic.c    | 19 +++++++++++++++++++
> >  mm/kasan/kasan.h      | 10 ++++++++++
> >  mm/kasan/report.c     | 24 ++++++++++++++++++++++++
> >  7 files changed, 61 insertions(+), 2 deletions(-)
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
> > index 06548e2ebb72..36a4ff7f320b 100644
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
> > @@ -2668,6 +2669,7 @@ __call_rcu(struct rcu_head *head, rcu_callback_t func)
> >  	head->func = func;
> >  	head->next = NULL;
> >  	local_irq_save(flags);
> > +	kasan_record_aux_stack(head);
> >  	rdp = this_cpu_ptr(&rcu_data);
> >  
> >  	/* Add the callback to our list. */
> > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > index 81f5464ea9e1..4e83cf6e3caa 100644
> > --- a/lib/Kconfig.kasan
> > +++ b/lib/Kconfig.kasan
> > @@ -58,6 +58,8 @@ config KASAN_GENERIC
> >  	  For better error detection enable CONFIG_STACKTRACE.
> >  	  Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
> >  	  (the resulting kernel does not boot).
> > +	  In generic mode KASAN prints the last two call_rcu() call stacks in
> > +	  reports.
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
> > index 56ff8885fe2e..3372bdcaf92a 100644
> > --- a/mm/kasan/generic.c
> > +++ b/mm/kasan/generic.c
> > @@ -325,3 +325,22 @@ DEFINE_ASAN_SET_SHADOW(f2);
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
> > +	/* record the last two call_rcu() call stacks */
> > +	alloc_info->aux_stack[1] = alloc_info->aux_stack[0];
> > +	alloc_info->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
> > +}
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index e8f37199d885..a7391bc83070 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -104,7 +104,15 @@ struct kasan_track {
> >  
> >  struct kasan_alloc_meta {
> >  	struct kasan_track alloc_track;
> > +#ifdef CONFIG_KASAN_GENERIC
> > +	/*
> > +	 * call_rcu() call stack is stored into struct kasan_alloc_meta.
> > +	 * The free stack is stored into struct kasan_free_meta.
> > +	 */
> > +	depot_stack_handle_t aux_stack[2];
> > +#else
> >  	struct kasan_track free_track[KASAN_NR_FREE_STACKS];
> > +#endif
> >  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> >  	u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
> >  	u8 free_track_idx;
> > @@ -159,6 +167,8 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
> >  
> >  struct page *kasan_addr_to_page(const void *addr);
> >  
> > +depot_stack_handle_t kasan_save_stack(gfp_t flags);
> > +
> >  #if defined(CONFIG_KASAN_GENERIC) && \
> >  	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> >  void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 80f23c9da6b0..6f8f2bf8f53b 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -179,6 +179,17 @@ static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> >  	return &alloc_meta->free_track[i];
> >  }
> >  
> > +#ifdef CONFIG_KASAN_GENERIC
> > +static void print_stack(depot_stack_handle_t stack)
> > +{
> > +	unsigned long *entries;
> > +	unsigned int nr_entries;
> > +
> > +	nr_entries = stack_depot_fetch(stack, &entries);
> > +	stack_trace_print(entries, nr_entries, 0);
> > +}
> > +#endif
> > +
> >  static void describe_object(struct kmem_cache *cache, void *object,
> >  				const void *addr, u8 tag)
> >  {
> > @@ -192,6 +203,19 @@ static void describe_object(struct kmem_cache *cache, void *object,
> >  		free_track = kasan_get_free_track(cache, object, tag);
> >  		print_track(free_track, "Freed");
> >  		pr_err("\n");
> > +
> > +#ifdef CONFIG_KASAN_GENERIC
> > +		if (alloc_info->aux_stack[0]) {
> > +			pr_err("Last one call_rcu() call stack:\n");
> > +			print_stack(alloc_info->aux_stack[0]);
> > +			pr_err("\n");
> > +		}
> > +		if (alloc_info->aux_stack[1]) {
> > +			pr_err("Second to last call_rcu() call stack:\n");
> > +			print_stack(alloc_info->aux_stack[1]);
> > +			pr_err("\n");
> > +		}
> > +#endif
> >  	}
> >  
> >  	describe_object_addr(cache, object, addr);
> > -- 
> > 2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1589942995.29577.6.camel%40mtksdccf07.
