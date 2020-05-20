Return-Path: <kasan-dev+bncBDGPTM5BQUDRBRNTSL3AKGQE3DORYKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 41E911DA82B
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 04:45:26 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id b82sf2258797qkg.22
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 19:45:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589942725; cv=pass;
        d=google.com; s=arc-20160816;
        b=K3mHK+7H3gHoVv3ghvEICOux8cGTbfYZXBh/WsUSGrJYygS5H/4DV31X6sno7vzg0F
         d3PL5CrV/6kB6sS2lquQdTBxicUcHKKv3A2tIHgCj4WHKjYtifEEJ5ezXdLPNnjkOeru
         3i83Aa5iTXkCr8EiWXgTb/XQz8/yuzdpvPs374CKbdAmT4aLupmuACbrbhqjg4hE2yXo
         pq4bT+WWZujAVCjdTgGacVwjvFqFOE9+GT920dOPWQ4Otb0YN5hE9NbdhnZipXnYEgkD
         VFJHWQRB3MFQeW2QqmQDUjdvFeOhPsg40pX0WEsELTDWRoqUSw330SXyC0S2yGWgWn9I
         Dw4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=98xoqSLXTdQtMljvAxRF+1/7X3PVN5T6OwqytO2IPYk=;
        b=tTcemUdcOJ6b9fdWDhpBtShSzCiAkssBUztrkmgleognoSp8dftcxDAEVC/FXvGb1i
         gj/feDAxpDJNjZhOeALmLLYVwK4HuyEPlfLOv3GITz7X4mXfWfHIkxmOEJ6F7+IxzXDG
         F/wB3T/uRHUcQLW+OA5ID0TlU29jGpnpsBI9jEsRmHL1E0kNJEKvZHVnQ6iBwirdAt+8
         4j49ANb2LMdLpA+oT0/4dlwdI2g50x8c+BsUPyHdiHYucbPNXbJEMM3XTboMUJPTfnkB
         w/Luj4/CBqyiQloObPvHwE7Nf2KyKXV9xgHda7R6Bbdbtixig8xOuXNu17lJrxo7lMIn
         AjGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=pprZAfHn;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=98xoqSLXTdQtMljvAxRF+1/7X3PVN5T6OwqytO2IPYk=;
        b=m/X5NiSBlMslNy5+Q2VksexI/29/KveY30kHSWZOezzJT0EIHhnTTNdXCWR0VE0EvX
         JCRwiMAQ9yeQfEN3HAFi4lgQP33yEfU0Qi+TJtRWfu6/cXA1WsbSo4pO5E67eiUWx4gG
         qD6SXo4pY20U4WyBQjTmdsnE5SiMkI6R/qbICzSAJD5+qQne8T0TKzaYTx6DQ3gWOqm+
         4uMPAl0ybSNQE7HK2Y4ipfTkMq3GLtv0TmYWJ4rH0KznugI7Gq9YHIztzcRhAQcrNTkL
         LEqShdPsGVRD3Ey3645zGO37V8UfKBzId/4qUnTatYtSomPPJtGXpEqRbth9OC+EypV1
         VsJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=98xoqSLXTdQtMljvAxRF+1/7X3PVN5T6OwqytO2IPYk=;
        b=bZTPOe94lwUISdG5CzLY3+cTf2iirS98BIj3RzoOs6CK+sLhnc7GTXfwfJeJabtX14
         zB3+IAWViD8Q8Pnt2ifYoeplSNgfarN4nErXwImVKFwN08oO0vuw8XYYgNJdZ3uwxtGE
         qf49i0+hi5s0ERh0WAVrzGacvsl/4xsCk+z1sVhNN5kRnbcaj1DI5WeXodr0/S6Sdu8x
         KGDfUV6OFlV3ou1LtsP/RRaPqf9d3MLpCLIDMRkOOjqJyYrRLPZi4ivfdfCQaOEnoSZp
         eoof8wHFWfRcyYI1UyYR6yjM30JqMCs7fb0SRz1ueM2FWYVbFK6p92JF9m0ovOFuGqUB
         lHgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533bnSbmLIwtyU8WQDL76LAVzEZuJOXUIkFKWhGotJOZM2BYl3pU
	0BL7NWIFU39NytKlEcMCZfQ=
X-Google-Smtp-Source: ABdhPJyRuH1CD7kI7eBYGTK3OHLDwG8GvsDW7wI/BnyiM/sRlxIdm6yzj12qWT0d7j6FUoRAODaxdw==
X-Received: by 2002:a37:b743:: with SMTP id h64mr2512020qkf.460.1589942725247;
        Tue, 19 May 2020 19:45:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:e001:: with SMTP id m1ls906288qkk.9.gmail; Tue, 19 May
 2020 19:45:24 -0700 (PDT)
X-Received: by 2002:a37:6384:: with SMTP id x126mr2629894qkb.355.1589942724899;
        Tue, 19 May 2020 19:45:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589942724; cv=none;
        d=google.com; s=arc-20160816;
        b=TQt8DMY9f/sdN8x8MTeERxOvEpFC8LiMPLh6Lrgce355rmootAnh/ePYg0C/vNEVY1
         OrHQx7nmmUSqLQG3Ehvt0c+xhUKcnFOSDq+ccvzJ9vhv/jP6xEcjQWAxC/ZzAjrC4+QK
         A9aSr9iiiOphXYlNU37t4qhsRDG5oDiMXdVXYCvpsAaWrs39I9Wcp4q9rYKL75RyzBSo
         pB/1Ep7r1daSfZbRtykU+66bImltj+tO0TYr4pdlKXc8UD95FyyWp5tWlI7L0+y/IEEH
         w5HX3RUYnxTTa9NVLIZFNNzhvEv+Qp5feyLsiqmH6kGvOdNrk0+/iRg6jXJ0bi++iovT
         gm9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=m3DuqKpgf4iRj54o8NbAF84k6JTIXvziVvcOSZRHoIg=;
        b=Kfvj7yQnaiCcZzHh9K+xpdPNG9+NIgJs77fcYSZ/nKezKOp8QwEhJuhjxzhlyi+YVr
         GoPhug85x1UNUiMzLtNh28paIqubP4cpkGnXq/UJvYVhY8QQHDbu2naiPROiihyWNp5Y
         dWwckC83lrKc9+yVK42+var4tACsUjz2dINcoqc1xuryr+538Ch3NBr9TRPFySdYwB0e
         B02fyJByEupQepgPq8n8X/EQrK7s8MP12/tTmMrAbyR+5HsfYRWQifHWvsVPtXgcVwL/
         OpBmCYMxEV920PfG8qCj4w4H+ZEWkZGzZbQ4eoDypOMOXnZudbCzogWITW4ZQ8kOTJwK
         AsVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=pprZAfHn;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id h15si104616qtr.4.2020.05.19.19.45.23
        for <kasan-dev@googlegroups.com>;
        Tue, 19 May 2020 19:45:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 490816c7f02349ceb88497402d494d3e-20200520
X-UUID: 490816c7f02349ceb88497402d494d3e-20200520
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1085158723; Wed, 20 May 2020 10:45:20 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 20 May 2020 10:45:16 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 20 May 2020 10:45:13 +0800
Message-ID: <1589942718.29577.3.camel@mtksdccf07>
Subject: Re: [PATCH v4 1/4] rcu/kasan: record and print call_rcu() call stack
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Konovalov <andreyknvl@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, "Paul E . McKenney" <paulmck@kernel.org>, "Josh
 Triplett" <josh@joshtriplett.org>, Mathieu Desnoyers
	<mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>,
	Joel Fernandes <joel@joelfernandes.org>, Andrew Morton
	<akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, "Linux
 Memory Management List" <linux-mm@kvack.org>, LKML
	<linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Wed, 20 May 2020 10:45:18 +0800
In-Reply-To: <CAAeHK+wHzVVxYkmqVuvg3PSJJMDAh_fNJrg6vULeYYo3063jYg@mail.gmail.com>
References: <20200519022359.24115-1-walter-zh.wu@mediatek.com>
	 <CAAeHK+wHzVVxYkmqVuvg3PSJJMDAh_fNJrg6vULeYYo3063jYg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: 6304041814EFF626743B3D340E4065BDC8A74CE1B689507D0DDD49A81C3153BD2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=pprZAfHn;       spf=pass
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

Hi Andrey,

On Tue, 2020-05-19 at 16:52 +0200, 'Andrey Konovalov' via kasan-dev
wrote:
> On Tue, May 19, 2020 at 4:24 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
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
> >         head->func = func;
> >         head->next = NULL;
> >         local_irq_save(flags);
> > +       kasan_record_aux_stack(head);
> >         rdp = this_cpu_ptr(&rcu_data);
> >
> >         /* Add the callback to our list. */
> > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > index 81f5464ea9e1..4e83cf6e3caa 100644
> > --- a/lib/Kconfig.kasan
> > +++ b/lib/Kconfig.kasan
> > @@ -58,6 +58,8 @@ config KASAN_GENERIC
> >           For better error detection enable CONFIG_STACKTRACE.
> >           Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
> >           (the resulting kernel does not boot).
> > +         In generic mode KASAN prints the last two call_rcu() call stacks in
> > +         reports.
> 
> I don't think we need this here, mentioning this in the documentation is fine.
> 

Ok, we will remove it. Only mention it in the documentation.

> 
> >
> >  config KASAN_SW_TAGS
> >         bool "Software tag-based mode"
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
> >         unsigned long entries[KASAN_STACK_DEPTH];
> >         unsigned int nr_entries;
> > @@ -54,7 +54,7 @@ static inline depot_stack_handle_t save_stack(gfp_t flags)
> >  static inline void set_track(struct kasan_track *track, gfp_t flags)
> >  {
> >         track->pid = current->pid;
> > -       track->stack = save_stack(flags);
> > +       track->stack = kasan_save_stack(flags);
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
> > +       struct page *page = kasan_addr_to_page(addr);
> > +       struct kmem_cache *cache;
> > +       struct kasan_alloc_meta *alloc_info;
> > +       void *object;
> > +
> > +       if (!(page && PageSlab(page)))
> > +               return;
> > +
> > +       cache = page->slab_cache;
> > +       object = nearest_obj(cache, page, addr);
> > +       alloc_info = get_alloc_info(cache, object);
> > +
> > +       /* record the last two call_rcu() call stacks */
> > +       alloc_info->aux_stack[1] = alloc_info->aux_stack[0];
> > +       alloc_info->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
> > +}
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index e8f37199d885..a7391bc83070 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -104,7 +104,15 @@ struct kasan_track {
> >
> >  struct kasan_alloc_meta {
> >         struct kasan_track alloc_track;
> > +#ifdef CONFIG_KASAN_GENERIC
> > +       /*
> > +        * call_rcu() call stack is stored into struct kasan_alloc_meta.
> > +        * The free stack is stored into struct kasan_free_meta.
> > +        */
> > +       depot_stack_handle_t aux_stack[2];
> > +#else
> >         struct kasan_track free_track[KASAN_NR_FREE_STACKS];
> > +#endif
> >  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> >         u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
> >         u8 free_track_idx;
> > @@ -159,6 +167,8 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
> >
> >  struct page *kasan_addr_to_page(const void *addr);
> >
> > +depot_stack_handle_t kasan_save_stack(gfp_t flags);
> > +
> >  #if defined(CONFIG_KASAN_GENERIC) && \
> >         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> >  void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 80f23c9da6b0..6f8f2bf8f53b 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -179,6 +179,17 @@ static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> >         return &alloc_meta->free_track[i];
> >  }
> >
> > +#ifdef CONFIG_KASAN_GENERIC
> > +static void print_stack(depot_stack_handle_t stack)
> 
> Let's put this function just before print_track() and reuse there.
> 

Ok.

> > +{
> > +       unsigned long *entries;
> > +       unsigned int nr_entries;
> > +
> > +       nr_entries = stack_depot_fetch(stack, &entries);
> > +       stack_trace_print(entries, nr_entries, 0);
> > +}
> > +#endif
> > +
> >  static void describe_object(struct kmem_cache *cache, void *object,
> >                                 const void *addr, u8 tag)
> >  {
> > @@ -192,6 +203,19 @@ static void describe_object(struct kmem_cache *cache, void *object,
> >                 free_track = kasan_get_free_track(cache, object, tag);
> >                 print_track(free_track, "Freed");
> >                 pr_err("\n");
> > +
> > +#ifdef CONFIG_KASAN_GENERIC
> > +               if (alloc_info->aux_stack[0]) {
> > +                       pr_err("Last one call_rcu() call stack:\n");
> 
> Could you change this to "Last call_rcu():\n",
> 
> > +                       print_stack(alloc_info->aux_stack[0]);
> > +                       pr_err("\n");
> > +               }
> > +               if (alloc_info->aux_stack[1]) {
> > +                       pr_err("Second to last call_rcu() call stack:\n");
> 
> and this to "Second to last call_rcu():\n"?
> 
> It's shorter, but provides the same info.
> 

We will change their name.

Thank you for your review.

> 
> 
> > +                       print_stack(alloc_info->aux_stack[1]);
> > +                       pr_err("\n");
> > +               }
> > +#endif
> >         }
> >
> >         describe_object_addr(cache, object, addr);
> > --
> > 2.18.0
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200519022359.24115-1-walter-zh.wu%40mediatek.com.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1589942718.29577.3.camel%40mtksdccf07.
