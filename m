Return-Path: <kasan-dev+bncBDGPTM5BQUDRBSFU5D2QKGQEQNZGVXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id EE7C61CEB97
	for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 05:38:49 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id r17sf7166646ioa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 20:38:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589254728; cv=pass;
        d=google.com; s=arc-20160816;
        b=mVq37EtDtINFoY7hu5Y1m8EolDOMxjRBprMvZHFjOY2bAox76bx3lpBdJB45Hs0G47
         IrjWtFb28PBWhfd3I/UrKDHDQCrlB1tbBhKQU9sl4hXjhC1tqtCwGCllCmA3lRarbVme
         RELP7JJvMr8TgrvDQnbayh4As8GzDReSvMebzVK3V2ZuuUK7NaCY0xKlnUqgMcm0GTk4
         wh4TUAfZX2r/IDYvw9oWhv3rU1GO/paqCehMoUxgjkDOvusPfGvNt2LOZP1vi7avVwxT
         RVa3uc3sPL95jmfiw4tqM1V/FPdwDZExCBOlJZO+KeEZ3nzqFMKTDGHLWGxSyB/7b3XB
         /3cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=1wXnnjJZtQP6HAfgrMRUel2RkA0nX7QqDh+Ri7Su4yM=;
        b=mL1jtH+LTrI0iOsTky5gseiakLNCS7WJD+L6GRKqRBjRELE1lhWpQFYo09USFYSLnu
         0BC/2ui3sxkf0C6VfVjDGKwQbwNrwsh8PskxjvB8rNRkVSjaiCLKISWVQdQqGKiF8jGz
         bhdokMWP9IoslKIZby89SXDTGDaPzwLfuLakfdGknvDNK2o+ri7B0jcs+G1rR2xMK6nq
         727griSwGUnR/v/gZ3z6r3SvjHl+6w6re8CZNOGVmH95+eNM9zu56Z3HiEOTUvrBZ5DW
         5OXf4adBP/YPXR+X4eLmcksttdOdgs+J1pe51/DD9Hc7X9mZ7tT8+5AwWtLahroWiV8i
         eaDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=fNNdZg1D;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1wXnnjJZtQP6HAfgrMRUel2RkA0nX7QqDh+Ri7Su4yM=;
        b=K8p09rWbc5jsjUuoZXcFmpogP8Sdn2xByBvPSPMCBLBFEu8KP2Z+1XkfSWTDFT1yoo
         G6GPNygVh9AJg83ykJD9nNj5MtvOj03T5jkAl5GwTJw9mUpwW9IROj5+bnOmLMvxHsIx
         VVRpmfm68RTNO47fsJUcgVoXffuttvC5ITYAPh21NVmuDL/jfP1gvV1ZHXbdOl8qNsgH
         N47Zz1zF0PRq30ajINVaQVNCudFwYDcelgmT/8XPspOCGbP1TJ6Uef0op4xJr7DEk9v1
         dhjaW4G9acGWNDKj/AwG7VZRLSCxzQIh4gDVmIgSt83eTf+og0lJruMsjKvmQjofsnZT
         ViNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1wXnnjJZtQP6HAfgrMRUel2RkA0nX7QqDh+Ri7Su4yM=;
        b=VwSiguj28sBwgjdJfVHKb5IeGG8QvCmY0XFG5zesspUXQ7apFQvZPawZvOaI2srA45
         Nv3X857Iz5yRbrYCrWQnn4IJtIMVF9dYeyqZg6cBkg1i9wI+nC1Cb+AAtblK7P8MUC+q
         v83vy6GFrhz/BU3o/W4Oyx6ndQG7YdXc3hv9SIGx5S71jrK1dgrSAAoM3pZPCx66MJuY
         gAQhqtgIINS3s+sBjsQwialO0D0kp5CwFrIyst1TSxuJAYQqm13JSqctMvR43a9zlb6T
         ekB/90NDCtylVQ6aFJHAbhrffzzYpYFgllC7KSZoksfjP8alZrVTHPOsG5u7UbK/wmpC
         NmOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZCZs6FYZKRGv4QpWqUN5PTNiYZbP7a/wNL7zm9qffwQnOzR5ur
	KYYtwH2/Wj+XHAMV6kq40h8=
X-Google-Smtp-Source: APiQypLEgkZa5VBthVQNuHeAOdRn0DpgzwjBOL6C6CmV+z8DLnz+MG87H8W9k9tfOuZ+Kd6jvGM9rg==
X-Received: by 2002:a05:6638:2ad:: with SMTP id d13mr10782540jaq.119.1589254728492;
        Mon, 11 May 2020 20:38:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:a612:: with SMTP id c18ls92635jam.0.gmail; Mon, 11 May
 2020 20:38:47 -0700 (PDT)
X-Received: by 2002:a02:a60f:: with SMTP id c15mr8272233jam.24.1589254727667;
        Mon, 11 May 2020 20:38:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589254727; cv=none;
        d=google.com; s=arc-20160816;
        b=aUNyS2SOEpyNVve06jxTR+PcHZnDPQwyAf3sCHUK+ZlTBRgiQ0r3Yu8l25GDWgF9GV
         DxPOvi21lgYq+yrGwUGJCbYTy08M/MQHlHvWxU522dKA32ressK+Oe7wb7cmPy1LLzuV
         rsCBXJynDGKp31TzN6MmrAmF4SIo3rLa3UXgJHOTIvdPNriDtrbTxtca3lxWdwUuSqUr
         qV3KZmhsFO4+SpNZq/tHJXaqUXr9pEwJmTLsgUiy0YvVC752mXiSFWiUxexsuTTKcg+G
         Njg+JonmQSB6oxmy5NmlulD+2tDuy5pl1jMkPH0dAwot26osNI47aQZY2VE/waWW0Iwu
         A3dQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=vldUPWrg6AE2Kp80nlemDtW3IillbEAbCq+PNbZ8Yh4=;
        b=NPRRUs83E/DlgSehZiBjIRljnposMA1C73deomq6SqxD6BvNSVfaDcWYqbBHHJVX6B
         kBqUWA7m1S/6tlyb+0GkGPvvc3IAuhwWaPm4aL5S10VSrzyA546hYbGsTrVWMuqjqOYF
         DGgTmKCh9BoBVOxr72r255GcZF5SyiS+pIalitqRNv9dX6spgVcFVUo+Ve0HwqU5z1h7
         oUVXzvFPLJwoBt1lqABxQpb+POtGRpRewIBauLWK99SLhl9KG1D4dinRRSCwVhoS1D/a
         DLtOaRkn4LtRJPcC/lJYdQCbgvu47t10hkuCoCSu47USmXjq4uOFvwEeJ6SWew1BXD6R
         hrIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=fNNdZg1D;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id m17si654739ioc.2.2020.05.11.20.38.47
        for <kasan-dev@googlegroups.com>;
        Mon, 11 May 2020 20:38:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 1a572e56f22248f989c8d511f4874b42-20200512
X-UUID: 1a572e56f22248f989c8d511f4874b42-20200512
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 2132765527; Tue, 12 May 2020 11:38:42 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs08n1.mediatek.inc (172.21.101.55) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 12 May 2020 11:38:40 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 12 May 2020 11:38:36 +0800
Message-ID: <1589254720.19238.36.camel@mtksdccf07>
Subject: Re: [PATCH v2 1/3] rcu/kasan: record and print call_rcu() call stack
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Paul E .
 McKenney" <paulmck@kernel.org>, Josh Triplett <josh@joshtriplett.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan
	<jiangshanlai@gmail.com>, Joel Fernandes <joel@joelfernandes.org>, "Andrew
 Morton" <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, "Linux
 ARM" <linux-arm-kernel@lists.infradead.org>
Date: Tue, 12 May 2020 11:38:40 +0800
In-Reply-To: <CACT4Y+aOkuH6Dn+L+wv1qVOLgXyCY_Ck4hecAMw3DgyBgC9qHw@mail.gmail.com>
References: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+YWNwTSoheJhc3nMdQi9m719F3PzpGo3TfRY3zAg9EwuQ@mail.gmail.com>
	 <CACT4Y+bO1Zg_jgFHbOWgp7fLAADOQ_-AZmjEHz0WG7=oyOt4Gg@mail.gmail.com>
	 <1589203771.21284.22.camel@mtksdccf07>
	 <CACT4Y+aOkuH6Dn+L+wv1qVOLgXyCY_Ck4hecAMw3DgyBgC9qHw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=fNNdZg1D;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
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

On Mon, 2020-05-11 at 16:19 +0200, Dmitry Vyukov wrote:
> On Mon, May 11, 2020 at 3:29 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > This feature will record first and last call_rcu() call stack and
> > > > print two call_rcu() call stack in KASAN report.
> > > >
> > > > When call_rcu() is called, we store the call_rcu() call stack into
> > > > slub alloc meta-data, so that KASAN report can print rcu stack.
> > > >
> > > > It doesn't increase the cost of memory consumption. Because we don't
> > > > enlarge struct kasan_alloc_meta size.
> > > > - add two call_rcu() call stack into kasan_alloc_meta, size is 8 bytes.
> > > > - remove free track from kasan_alloc_meta, size is 8 bytes.
> > > >
> > > > [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> > > > [2]https://groups.google.com/forum/#!searchin/kasan-dev/better$20stack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ
> > > >
> > > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > > > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > > > Cc: Dmitry Vyukov <dvyukov@google.com>
> > > > Cc: Alexander Potapenko <glider@google.com>
> > > > Cc: Andrew Morton <akpm@linux-foundation.org>
> > > > Cc: Paul E. McKenney <paulmck@kernel.org>
> > > > Cc: Josh Triplett <josh@joshtriplett.org>
> > > > Cc: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
> > > > Cc: Lai Jiangshan <jiangshanlai@gmail.com>
> > > > Cc: Joel Fernandes <joel@joelfernandes.org>
> > > > ---
> > > >  include/linux/kasan.h |  2 ++
> > > >  kernel/rcu/tree.c     |  3 +++
> > > >  lib/Kconfig.kasan     |  2 ++
> > > >  mm/kasan/common.c     |  4 ++--
> > > >  mm/kasan/generic.c    | 29 +++++++++++++++++++++++++++++
> > > >  mm/kasan/kasan.h      | 19 +++++++++++++++++++
> > > >  mm/kasan/report.c     | 21 +++++++++++++++++----
> > > >  7 files changed, 74 insertions(+), 6 deletions(-)
> > > >
> > > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > > index 31314ca7c635..23b7ee00572d 100644
> > > > --- a/include/linux/kasan.h
> > > > +++ b/include/linux/kasan.h
> > > > @@ -174,11 +174,13 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> > > >
> > > >  void kasan_cache_shrink(struct kmem_cache *cache);
> > > >  void kasan_cache_shutdown(struct kmem_cache *cache);
> > > > +void kasan_record_aux_stack(void *ptr);
> > > >
> > > >  #else /* CONFIG_KASAN_GENERIC */
> > > >
> > > >  static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
> > > >  static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
> > > > +static inline void kasan_record_aux_stack(void *ptr) {}
> > > >
> > > >  #endif /* CONFIG_KASAN_GENERIC */
> > > >
> > > > diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> > > > index 06548e2ebb72..de872b6cc261 100644
> > > > --- a/kernel/rcu/tree.c
> > > > +++ b/kernel/rcu/tree.c
> > > > @@ -57,6 +57,7 @@
> > > >  #include <linux/slab.h>
> > > >  #include <linux/sched/isolation.h>
> > > >  #include <linux/sched/clock.h>
> > > > +#include <linux/kasan.h>
> > > >  #include "../time/tick-internal.h"
> > > >
> > > >  #include "tree.h"
> > > > @@ -2694,6 +2695,8 @@ __call_rcu(struct rcu_head *head, rcu_callback_t func)
> > > >                 trace_rcu_callback(rcu_state.name, head,
> > > >                                    rcu_segcblist_n_cbs(&rdp->cblist));
> > > >
> > > > +       kasan_record_aux_stack(head);
> > > > +
> > > >         /* Go handle any RCU core processing required. */
> > > >         if (IS_ENABLED(CONFIG_RCU_NOCB_CPU) &&
> > > >             unlikely(rcu_segcblist_is_offloaded(&rdp->cblist))) {
> > > > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > > > index 81f5464ea9e1..56a89291f1cc 100644
> > > > --- a/lib/Kconfig.kasan
> > > > +++ b/lib/Kconfig.kasan
> > > > @@ -58,6 +58,8 @@ config KASAN_GENERIC
> > > >           For better error detection enable CONFIG_STACKTRACE.
> > > >           Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
> > > >           (the resulting kernel does not boot).
> > > > +         Currently CONFIG_KASAN_GENERIC will print first and last call_rcu()
> > > > +         call stack. It doesn't increase the cost of memory consumption.
> > > >
> > > >  config KASAN_SW_TAGS
> > > >         bool "Software tag-based mode"
> > > > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > > > index 2906358e42f0..8bc618289bb1 100644
> > > > --- a/mm/kasan/common.c
> > > > +++ b/mm/kasan/common.c
> > > > @@ -41,7 +41,7 @@
> > > >  #include "kasan.h"
> > > >  #include "../slab.h"
> > > >
> > > > -static inline depot_stack_handle_t save_stack(gfp_t flags)
> > > > +depot_stack_handle_t kasan_save_stack(gfp_t flags)
> > > >  {
> > > >         unsigned long entries[KASAN_STACK_DEPTH];
> > > >         unsigned int nr_entries;
> > > > @@ -54,7 +54,7 @@ static inline depot_stack_handle_t save_stack(gfp_t flags)
> > > >  static inline void set_track(struct kasan_track *track, gfp_t flags)
> > > >  {
> > > >         track->pid = current->pid;
> > > > -       track->stack = save_stack(flags);
> > > > +       track->stack = kasan_save_stack(flags);
> > > >  }
> > > >
> > > >  void kasan_enable_current(void)
> > > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > > index 56ff8885fe2e..b86880c338e2 100644
> > > > --- a/mm/kasan/generic.c
> > > > +++ b/mm/kasan/generic.c
> > > > @@ -325,3 +325,32 @@ DEFINE_ASAN_SET_SHADOW(f2);
> > > >  DEFINE_ASAN_SET_SHADOW(f3);
> > > >  DEFINE_ASAN_SET_SHADOW(f5);
> > > >  DEFINE_ASAN_SET_SHADOW(f8);
> > > > +
> > > > +void kasan_record_aux_stack(void *addr)
> > > > +{
> > > > +       struct page *page = kasan_addr_to_page(addr);
> > > > +       struct kmem_cache *cache;
> > > > +       struct kasan_alloc_meta *alloc_info;
> > > > +       void *object;
> > > > +
> > > > +       if (!(page && PageSlab(page)))
> > > > +               return;
> > > > +
> > > > +       cache = page->slab_cache;
> > > > +       object = nearest_obj(cache, page, addr);
> > > > +       alloc_info = get_alloc_info(cache, object);
> > > > +
> > > > +       if (!alloc_info->rcu_stack[0])
> > > > +               /* record first call_rcu() call stack */
> > > > +               alloc_info->rcu_stack[0] = kasan_save_stack(GFP_NOWAIT);
> > > > +       else
> > > > +               /* record last call_rcu() call stack */
> > > > +               alloc_info->rcu_stack[1] = kasan_save_stack(GFP_NOWAIT);
> > > > +}
> > > > +
> > > > +struct kasan_track *kasan_get_aux_stack(struct kasan_alloc_meta *alloc_info,
> > > > +                                               u8 idx)
> > > > +{
> > > > +       return container_of(&alloc_info->rcu_stack[idx],
> > > > +                                               struct kasan_track, stack);
> > > > +}
> > > > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > > > index e8f37199d885..1cc1fb7b0de3 100644
> > > > --- a/mm/kasan/kasan.h
> > > > +++ b/mm/kasan/kasan.h
> > > > @@ -96,15 +96,28 @@ struct kasan_track {
> > > >         depot_stack_handle_t stack;
> > > >  };
> > > >
> > > > +#ifdef CONFIG_KASAN_GENERIC
> > > > +#define SIZEOF_PTR sizeof(void *)
> > >
> > > Please move this to generic.c closer to kasan_set_free_info.
> > > Unnecessary in the header.
> > >
> > > > +#define KASAN_NR_RCU_CALL_STACKS 2
> > >
> > > Since KASAN_NR_RCU_CALL_STACKS is only used once below, you could as
> > > well use 2 instead of it.
> > > Reduces level of indirection and cognitive load.
> > >
> > > > +#else /* CONFIG_KASAN_GENERIC */
> > > >  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > >  #define KASAN_NR_FREE_STACKS 5
> > > >  #else
> > > >  #define KASAN_NR_FREE_STACKS 1
> > > >  #endif
> > > > +#endif /* CONFIG_KASAN_GENERIC */
> > > >
> > > >  struct kasan_alloc_meta {
> > > >         struct kasan_track alloc_track;
> > > > +#ifdef CONFIG_KASAN_GENERIC
> > > > +       /*
> > > > +        * call_rcu() call stack is stored into struct kasan_alloc_meta.
> > > > +        * The free stack is stored into freed object.
> > > > +        */
> > > > +       depot_stack_handle_t rcu_stack[KASAN_NR_RCU_CALL_STACKS];
> > > > +#else
> > > >         struct kasan_track free_track[KASAN_NR_FREE_STACKS];
> > > > +#endif
> > > >  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > >         u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
> > > >         u8 free_track_idx;
> > > > @@ -159,16 +172,22 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
> > > >
> > > >  struct page *kasan_addr_to_page(const void *addr);
> > > >
> > > > +depot_stack_handle_t kasan_save_stack(gfp_t flags);
> > > > +
> > > >  #if defined(CONFIG_KASAN_GENERIC) && \
> > > >         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> > > >  void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
> > > >  void quarantine_reduce(void);
> > > >  void quarantine_remove_cache(struct kmem_cache *cache);
> > > > +struct kasan_track *kasan_get_aux_stack(struct kasan_alloc_meta *alloc_info,
> > > > +                       u8 idx);
> > > >  #else
> > > >  static inline void quarantine_put(struct kasan_free_meta *info,
> > > >                                 struct kmem_cache *cache) { }
> > > >  static inline void quarantine_reduce(void) { }
> > > >  static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
> > > > +static inline struct kasan_track *kasan_get_aux_stack(
> > > > +                       struct kasan_alloc_meta *alloc_info, u8 idx) { return NULL; }
> > > >  #endif
> > > >
> > > >  #ifdef CONFIG_KASAN_SW_TAGS
> > > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > > index 80f23c9da6b0..f16a1a210815 100644
> > > > --- a/mm/kasan/report.c
> > > > +++ b/mm/kasan/report.c
> > > > @@ -105,9 +105,13 @@ static void end_report(unsigned long *flags)
> > > >         kasan_enable_current();
> > > >  }
> > > >
> > > > -static void print_track(struct kasan_track *track, const char *prefix)
> > > > +static void print_track(struct kasan_track *track, const char *prefix,
> > > > +                                               bool is_callrcu)
> > > >  {
> > > > -       pr_err("%s by task %u:\n", prefix, track->pid);
> > > > +       if (is_callrcu)
> > > > +               pr_err("%s:\n", prefix);
> > > > +       else
> > > > +               pr_err("%s by task %u:\n", prefix, track->pid);
> > > >         if (track->stack) {
> > > >                 unsigned long *entries;
> > > >                 unsigned int nr_entries;
> > > > @@ -187,11 +191,20 @@ static void describe_object(struct kmem_cache *cache, void *object,
> > > >         if (cache->flags & SLAB_KASAN) {
> > > >                 struct kasan_track *free_track;
> > > >
> > > > -               print_track(&alloc_info->alloc_track, "Allocated");
> > > > +               print_track(&alloc_info->alloc_track, "Allocated", false);
> > > >                 pr_err("\n");
> > > >                 free_track = kasan_get_free_track(cache, object, tag);
> > > > -               print_track(free_track, "Freed");
> > > > +               print_track(free_track, "Freed", false);
> > > >                 pr_err("\n");
> > > > +
> > > > +               if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> > > > +                       free_track = kasan_get_aux_stack(alloc_info, 0);
> > > > +                       print_track(free_track, "First call_rcu() call stack", true);
> > > > +                       pr_err("\n");
> > > > +                       free_track = kasan_get_aux_stack(alloc_info, 1);
> > > > +                       print_track(free_track, "Last call_rcu() call stack", true);
> > > > +                       pr_err("\n");
> > > > +               }
> > > >         }
> > > >
> > > >         describe_object_addr(cache, object, addr);
> >
> > Some higher level comments.
> >
> > 1. I think we need to put the free track into kasan_free_meta as it
> > was before. It looks like exactly the place for it. We have logic to
> > properly place it and to do the casts.
> >
> >
> > If the free track put kasan_free_meta, then it increase slab meta size?
> > Our original goal does not enlarge it.
> 
> Are you sure it will increase object size?
> I think we overlap kasan_free_meta with the object as well. The only
> case we don't overlap kasan_free_meta with the object are
> SLAB_TYPESAFE_BY_RCU || cache->ctor. But these are rare and it should
> only affect small objects with small redzones.
> And I think now we simply have a bug for these objects, we check
> KASAN_KMALLOC_FREE and then assume object contains free stack, but for
> objects with ctor, they still contain live object data, we don't store
> free stack in them.
> Such objects can be both free and still contain user data.
> 

Overlay kasan_free_meta. I see. but overlay it only when the object was
freed. kasan_free_meta will be used until free object.
1). When put object into quarantine, it need kasan_free_meta.
2). When the object exit from quarantine, it need kasan_free_meta

If we choose to overlay kasan_free_meta, then the free stack will be
stored very late. It may has no free stack in report.

> 
> > 2. We need to zero aux stacks when we reallocate the object. Otherwise
> > we print confusing garbage.
> >
> > My local has an UT about use-after-free and rcu, but it is hard to test the printing confusing garbage, because we may need to get the same object(old pointer and new pointer). In generic KASAN is not easy to get it.
> >
> > 3. __kasan_slab_free now contains a window of inconsistency when it
> > marked the object as KASAN_KMALLOC_FREE, but did not store the free
> > track yet. If another thread prints a report now, it will print random
> > garbage.
> >
> >
> > It is possible, but the window is so tiny. It sets free track immediately after write the KASAN_KMALLOC_FREE.
> 
> It is small. But (1) why do we want to allow it at all, (2) there is
> actually a more serious problem. If we mark an object as
> KASAN_KMALLOC_FREE, but don't do kasan_set_free_info (because object
> has ctor), now we will treat live object data as free track. We need
> to fix it anyway.
> 

I see.

> 
> 
> 
> > 4. We need some tests. At least (2) should be visible on tests.
> >
> >
> > Ok.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1589254720.19238.36.camel%40mtksdccf07.
