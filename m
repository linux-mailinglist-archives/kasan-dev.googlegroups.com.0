Return-Path: <kasan-dev+bncBDGPTM5BQUDRBNMK4X2QKGQEMJSRUMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe37.google.com (mail-vs1-xe37.google.com [IPv6:2607:f8b0:4864:20::e37])
	by mail.lfdr.de (Postfix) with ESMTPS id 9555D1CD9D0
	for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 14:29:42 +0200 (CEST)
Received: by mail-vs1-xe37.google.com with SMTP id u74sf1303914vsu.14
        for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 05:29:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589200181; cv=pass;
        d=google.com; s=arc-20160816;
        b=zcvr5zfSx2lP6yWR7KkTnjIcC6a4UIVDUYXh0FkByibP1hiszEmtpmitI+zsvTyBGq
         8X6n+Lhfa9KR9hD5Jm0yfu8A++1upjsclvv9t/UMts2YjiTLvKR8RCEtMvT+Vgwui7fW
         e3Wgk6JtA6sX9HU1yYJ68esVk79MY6f4uOm1QapjQcoOfbmouc9pC7RTrKt/id4bOPS5
         X73rvpBYiN4oH0vvGeO47Kuppxcx+zTE5+5NrYqGuO3wrfS9W0rYzCYTX02npx2iNbTS
         lP0fUFDoJPBiHSiU+VN3cBiO617TAZ9bHQuvcnpr4Lhuem0PFP4p2QWhHtRRRFcKsgWT
         XqhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=DkWkDBcvblCc5FFGdBik5zcAOTDa/F39RzS+VwN62i0=;
        b=IcmkCe7Ykt39uAWQ7RoFqrp2MUMjuDn8dkOmaWRPdgQjm1jUOK6tigYI4QzZ0FQJfE
         vfgKQy+hYmvQ2muE8ViPEXuLv0i+VzgdDV+i7GJq8fV3qYUurSNjm3mJj0HdEKPujcMg
         aVZBCv2jykaVHI2gpIZRRDPk2/uEiirGWRuLBNPpBYSVu+5iFm1DxbYeq/Pa08ELNSyX
         e9AH62A7T7HmuHTmCwJrct9msgskPlDMUmCm87cCPU3eNjiMCWB/CQP66zykZbUB42M9
         hCEquObBwVM1SZb4ld4ouFdbbymshMb1zi0ki+LTupxFQZuZ25YGD5RpPl8eMLmiTUgx
         K4OQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ddJ280M4;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DkWkDBcvblCc5FFGdBik5zcAOTDa/F39RzS+VwN62i0=;
        b=V6ae1vJB34/FvuCD3RRLZmT7M+xd44xa/Hv6r1L/axLx/s38Md70w9kgAy46h4R4NV
         B4nOJh0rK/u11B4fvfvpYw60X6nPlj622rQKGvwwUJhWrJOJhuWbf5gVlYf3V9IBmVfF
         D9ZFKxoM3/O/gAslMqtGzE0qf50H0S/YhvwpTyC+pCk9A/nK9vydHfAhBQsv1qquE6Pg
         zaBaj9aQK3x+kn5IfSrPjDi1/rB8qWV5RuRkx5MMJosK20l0351ZY8XfUH1284iA7UsJ
         5oew+Y90kxIrASKM9oV6+lWCxGFn1rGnRvyUCQy3e94I5YUYDN3U0pGikvATdFcu6G/B
         2GPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DkWkDBcvblCc5FFGdBik5zcAOTDa/F39RzS+VwN62i0=;
        b=cgtRZCP1plz0PjwnLpkPgAOsTdOW40f1CTAced9Bw+wIDwe1jy0P0/WNRh9LAjLsLJ
         Tifk7hTOqMXNVOvmgoQw4KQcR2lF7+NDvJJxxRlCfky7NHtVCBdSzPkZb9/QKJiuaUbA
         0x82eoTIqdiwkF+0YAHtZqOZxK4pCMlVq1TCSBZ9LQ6um5JEEMlhJLBAK59OUG3kX2m6
         R4IOOUnCQx1FrT29Dkq/7zUtJLr59Tiq2emy0PxUFRurrASOEc9RySmX+C6eacY7c8xM
         h5gnvelV0CwiXbjaGAR0Cl3Rz9JHCluM1n79b5VJDj4r2ggBH/HS4opf+owPbZOiAUih
         hB8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZrdFa8Xsz7ox5VfkCByxgVaHSpj0+zZygVSZYXXH97jr9euNd3
	qXTajW9mRjehmqaziL5KNHw=
X-Google-Smtp-Source: APiQypJa19qScbGTzQw/WnyfxE7O72n7zvtpUIzvlos0qa49A2BMhXUOHR0auLAu3Eif/yM0G3CbWw==
X-Received: by 2002:a67:ea4e:: with SMTP id r14mr11133553vso.205.1589200181303;
        Mon, 11 May 2020 05:29:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:5a87:: with SMTP id w7ls686200uae.6.gmail; Mon, 11 May
 2020 05:29:40 -0700 (PDT)
X-Received: by 2002:a9f:3e0d:: with SMTP id o13mr6267110uai.25.1589200180887;
        Mon, 11 May 2020 05:29:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589200180; cv=none;
        d=google.com; s=arc-20160816;
        b=BAGaIvw1x4eWFgIRHM3dCTnzXoExMEWsSrAhTD2v/6SvrZ85w3EHfL4oJAkzolnzmf
         SDp1+tzCWzyGAV0x2xFOg1A0btXb0ZW/GrPptNXItNwkqqAU+KWl38Zxspa6dV9dH+WT
         7STBCz4mUzYSrt/vT2tjS5TmZ/ArpbwBGfJktB8DNc1cZEuB/AVdXpM43xoKENcsY/Zx
         MmpUI978qYRtO4wGHJpf1LvVkJ3zMm9VUklf95YhzejKyxUdkgYHxr8F6ZzdHShd/Y39
         vrHpvUIdMquFepeRGNj2nbnkND/77coN1c9zSm6UbJkyiSxJag+pHid67qal7bZO3dBD
         fJdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=fFNjDq2ZBmlvzH9uW9bgKfkdmkMyI37zvLnnbgc/t24=;
        b=t0MZSVr01ZqH14nseckucQP3b8pDIFrLe7QceGvPb0IDgvHH+Ck0ZddxlCTF6iAR6F
         tvF3CuWtQv9XOThsAJ+dGk9mMspP/Gkn7FNk9OfNTyaBxfYBN1PwbQH0AgmX82lxh7wv
         e5Dhj+ushknu87fFfETHFPzC1LaRSZvJ84vsQXsReL/wS06aCXkC112D+w3Ozokpe2pq
         atKxxo/FyjZGRklVw57vBQXAI1YodevxHFKnzii09c7zghqpYsIK87vvb7kv69P65tUW
         Ij39bp0JqYZEtVDSLVv6zb3wtcCdaOMz0AdcJKWY3byCSJrY30pnJSM9BCerm4ccOPH9
         59Tg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ddJ280M4;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id i26si778308vsk.0.2020.05.11.05.29.39
        for <kasan-dev@googlegroups.com>;
        Mon, 11 May 2020 05:29:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 9a22b8426a6a46b0b2804b1fa68673bf-20200511
X-UUID: 9a22b8426a6a46b0b2804b1fa68673bf-20200511
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1986011982; Mon, 11 May 2020 20:29:35 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 11 May 2020 20:29:32 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 11 May 2020 20:29:31 +0800
Message-ID: <1589200174.12504.10.camel@mtksdccf07>
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
 ARM" <linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Mon, 11 May 2020 20:29:34 +0800
In-Reply-To: <CACT4Y+ZDaONL63_GdGQpgs+7dxG3GHRMGcNOVgfn9P88Kx7fig@mail.gmail.com>
References: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+ZDaONL63_GdGQpgs+7dxG3GHRMGcNOVgfn9P88Kx7fig@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: 8DD32CDD036DB2F2F9641C1F7DE50CFA035AD434F1066AEF4270F5F11B470D1A2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=ddJ280M4;       spf=pass
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

On Mon, 2020-05-11 at 13:08 +0200, Dmitry Vyukov wrote:
> On Mon, May 11, 2020 at 4:31 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > This feature will record first and last call_rcu() call stack and
> > print two call_rcu() call stack in KASAN report.
> >
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
> >                 trace_rcu_callback(rcu_state.name, head,
> >                                    rcu_segcblist_n_cbs(&rdp->cblist));
> >
> > +       kasan_record_aux_stack(head);
> 
> This happens after we queued the object onto some queue and after some
> return statements. I think this is wrong.
> We need to do this somewhere at the very beginning of the function.
> 

Yes, we should make sure that all recording are fully and correctly.

> This is what I meant by "hard to review". This is completely invisible
> in the diff.
> 

Thanks.

> 
> >         /* Go handle any RCU core processing required. */
> >         if (IS_ENABLED(CONFIG_RCU_NOCB_CPU) &&
> >             unlikely(rcu_segcblist_is_offloaded(&rdp->cblist))) {
> > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > index 81f5464ea9e1..56a89291f1cc 100644
> > --- a/lib/Kconfig.kasan
> > +++ b/lib/Kconfig.kasan
> > @@ -58,6 +58,8 @@ config KASAN_GENERIC
> >           For better error detection enable CONFIG_STACKTRACE.
> >           Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
> >           (the resulting kernel does not boot).
> > +         Currently CONFIG_KASAN_GENERIC will print first and last call_rcu()
> > +         call stack. It doesn't increase the cost of memory consumption.
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
> > +       if (!alloc_info->rcu_stack[0])
> > +               /* record first call_rcu() call stack */
> > +               alloc_info->rcu_stack[0] = kasan_save_stack(GFP_NOWAIT);
> > +       else
> > +               /* record last call_rcu() call stack */
> > +               alloc_info->rcu_stack[1] = kasan_save_stack(GFP_NOWAIT);
> > +}
> > +
> > +struct kasan_track *kasan_get_aux_stack(struct kasan_alloc_meta *alloc_info,
> > +                                               u8 idx)
> > +{
> > +       return container_of(&alloc_info->rcu_stack[idx],
> > +                                               struct kasan_track, stack);
> > +}
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index e8f37199d885..1cc1fb7b0de3 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -96,15 +96,28 @@ struct kasan_track {
> >         depot_stack_handle_t stack;
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
> >         struct kasan_track alloc_track;
> > +#ifdef CONFIG_KASAN_GENERIC
> > +       /*
> > +        * call_rcu() call stack is stored into struct kasan_alloc_meta.
> > +        * The free stack is stored into freed object.
> > +        */
> > +       depot_stack_handle_t rcu_stack[KASAN_NR_RCU_CALL_STACKS];
> > +#else
> >         struct kasan_track free_track[KASAN_NR_FREE_STACKS];
> > +#endif
> >  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> >         u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
> >         u8 free_track_idx;
> > @@ -159,16 +172,22 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
> >
> >  struct page *kasan_addr_to_page(const void *addr);
> >
> > +depot_stack_handle_t kasan_save_stack(gfp_t flags);
> > +
> >  #if defined(CONFIG_KASAN_GENERIC) && \
> >         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> >  void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
> >  void quarantine_reduce(void);
> >  void quarantine_remove_cache(struct kmem_cache *cache);
> > +struct kasan_track *kasan_get_aux_stack(struct kasan_alloc_meta *alloc_info,
> > +                       u8 idx);
> >  #else
> >  static inline void quarantine_put(struct kasan_free_meta *info,
> >                                 struct kmem_cache *cache) { }
> >  static inline void quarantine_reduce(void) { }
> >  static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
> > +static inline struct kasan_track *kasan_get_aux_stack(
> > +                       struct kasan_alloc_meta *alloc_info, u8 idx) { return NULL; }
> >  #endif
> >
> >  #ifdef CONFIG_KASAN_SW_TAGS
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 80f23c9da6b0..f16a1a210815 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -105,9 +105,13 @@ static void end_report(unsigned long *flags)
> >         kasan_enable_current();
> >  }
> >
> > -static void print_track(struct kasan_track *track, const char *prefix)
> > +static void print_track(struct kasan_track *track, const char *prefix,
> > +                                               bool is_callrcu)
> >  {
> > -       pr_err("%s by task %u:\n", prefix, track->pid);
> > +       if (is_callrcu)
> > +               pr_err("%s:\n", prefix);
> > +       else
> > +               pr_err("%s by task %u:\n", prefix, track->pid);
> >         if (track->stack) {
> >                 unsigned long *entries;
> >                 unsigned int nr_entries;
> > @@ -187,11 +191,20 @@ static void describe_object(struct kmem_cache *cache, void *object,
> >         if (cache->flags & SLAB_KASAN) {
> >                 struct kasan_track *free_track;
> >
> > -               print_track(&alloc_info->alloc_track, "Allocated");
> > +               print_track(&alloc_info->alloc_track, "Allocated", false);
> >                 pr_err("\n");
> >                 free_track = kasan_get_free_track(cache, object, tag);
> > -               print_track(free_track, "Freed");
> > +               print_track(free_track, "Freed", false);
> >                 pr_err("\n");
> > +
> > +               if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> > +                       free_track = kasan_get_aux_stack(alloc_info, 0);
> > +                       print_track(free_track, "First call_rcu() call stack", true);
> > +                       pr_err("\n");
> > +                       free_track = kasan_get_aux_stack(alloc_info, 1);
> > +                       print_track(free_track, "Last call_rcu() call stack", true);
> > +                       pr_err("\n");
> > +               }
> >         }
> >
> >         describe_object_addr(cache, object, addr);
> > --
> > 2.18.0
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200511023111.15310-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1589200174.12504.10.camel%40mtksdccf07.
