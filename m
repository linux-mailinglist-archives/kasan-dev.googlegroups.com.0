Return-Path: <kasan-dev+bncBCMIZB7QWENRB54Q4X2QKGQEUTOPJ5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 60BC31CDA51
	for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 14:43:36 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id z1sf4409002qvd.23
        for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 05:43:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589201015; cv=pass;
        d=google.com; s=arc-20160816;
        b=VAVoGNWI6ZIqk6mWaT0r1q6Ey0ogMj13oU1IH3lSgy3vjNiBu/syu5BQyq0gTs25zo
         Ajkj77zfZ/qOiMH51ypoAe0o4PG41kE/AgxjRT4Fpd8nQZJkWMQJRui9zMcBR3O9hPp+
         +RFXj4QKMxMb4aN6Pz0G9lVfoSGEa8ejDe81It93gAXuGGbQy8KUlmq+Ayugl4ki00hi
         oDHgws3/oul5/DCTkL71EtiIJorv/MOy35FxCcSeMwgj0pWgy8iymVsxKjwJ8pYvBvzc
         ChT2H0rzbBmf49KcpNERi3YJYHJOwFO0/EdYXSJ9jjKV4A8LeKHmbASglp+xmbe5wxj3
         cE9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=909ygh6a5bwX9qe5Zbi4erzhLxjnbfyGApVQS1aSA9M=;
        b=VquCKfZJbyyb1/iozSW9J6btGqdHq+5nAUSkR5EVcmcwxXD1i13i6x987bvCRe+6a+
         TTHjfG4qDcZNlXWLxXiGtcUVpohdQkUOBOm+Jx093yZisNaQ3/QhHtBH9Q5AaA/lYHf9
         Vi8IB9rKPXprN3Xkdumo542Fy8cIEKsI9PaNnrswNQ1mhMtZOIvitPAWKxJaumVeu5Us
         XZ5aDYyrA9Br+d0mEs+lKUoA5dS5BsTefMRRry9nfhydrZSXhvxAEqMFnpsdYGqII1iz
         QqhSgXCmdp2q/oGe3oJVywzav3iVP6bvFTZpDLdTxNinWPfWrsO08OoiYZoQbj4csKbU
         560g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iG294TZ8;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=909ygh6a5bwX9qe5Zbi4erzhLxjnbfyGApVQS1aSA9M=;
        b=D/aJzpWgkxLJzokzH6GC8p1dmb25O+I5Gqlxz846mS7A4V0rEL+BITP5dgw0VOdGRw
         i6V5BtUuqJ2ILOw6nhL/Xyzd5pOk8rTFVS3TWyTUhab/G/5UvTsKfYd6R0ozCWvXfTEL
         SMnIbVSvQ3Ygl2aM4LJPRPq0gKkHSeWDY3gBHnhCkVGnuAVt6AjBK43M7T3hjiXnHgCi
         0a/Lx6e2a7cDpXdPQQfgVcOUj0EvHNTv0Gxz9eYB+r56QZgVKHAzx+6HjjDH6USNsdUt
         GJ9cPaboHGUSYcCzjc3DMz1g3E9y9HksO8ELBDmiJ4kRMn5meTOPAqZVwpeTH82wAsC+
         zkrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=909ygh6a5bwX9qe5Zbi4erzhLxjnbfyGApVQS1aSA9M=;
        b=Nng1xydJkc8ouXugNxtzuuggzXHY5R6bkYkz0x0pqk2XftVbXBmRf0JCLaxSa6lCkB
         zfswnm0+NhG3oyX4p/FloJ2tYk9OA51edIjQzMBG1eAs7L+cY3oxAipmMXNpAncG0YFO
         99HF+NWLMz1FYZeUrLSk7dgwczBMHadxFoezAnYn/3TecN8g6m9A+E8Zz/FAfg+7UmN6
         LPAUm2SCsV+KqBRIl7T3lvJnOhsPXBalokuiwFBqpEQiRg4DORq4Xw+IK6086IOZa2q+
         sLAMv2taRTPGevwlGP4xy7FEl3LWA3M25+BU1o/f85kxg8vCdYJMgZcwVv/iWHZi8gNZ
         xmJg==
X-Gm-Message-State: AGi0PuYiFlI7bqN8zSgO3drQ/DFzfGRGBxYhSFJhSOvSJErXm1AtbrEK
	iLR/uPk4Ko+BjCk2pZ4MZ30=
X-Google-Smtp-Source: APiQypJuubBcVZoT7zTo/Ek3rBl8zYZG8WlDRn7z6k1eIx5pEd59uANq1OphSuqEHlLNgi3p1ikoOQ==
X-Received: by 2002:a05:620a:b0b:: with SMTP id t11mr15676391qkg.103.1589201015394;
        Mon, 11 May 2020 05:43:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:b245:: with SMTP id b66ls5324872qkf.7.gmail; Mon, 11 May
 2020 05:43:34 -0700 (PDT)
X-Received: by 2002:a37:4e81:: with SMTP id c123mr4777701qkb.467.1589201014832;
        Mon, 11 May 2020 05:43:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589201014; cv=none;
        d=google.com; s=arc-20160816;
        b=OsmldnsiHmSI9SuaYbe286KVCkFafvm86UTBgeuVQ1ULzn8MxmnIaDPiDjPd3Silxk
         7E42cXr0OF4pNISFi99la2SLVP3E/DopNRoPq7BDZEx9zlCDvAr+HrvicP2alaq2o60l
         Ix+oDMLrrzL/LCSwCVILzTGs14kCc1rLSuLfx4XfmiMLyyn2bpoGFIArgft2RmeN1D4y
         u+F+bH1QsRSpGCrdbZ0rWJdxfhosfMrUtGR34/ti0JvEi6K/k9VLoHe4XYSUxDkwfG/9
         PKSEbFskiYRJ+W45KH8f9GQjsz68ba9Ze6SWBMGovQJm5QcwMAjB4c8he4/gKR/T7vD/
         s2qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=o4SNxN2a4GN4w0hp5AlLi4G8AluIsrQ7+PBJOL3vihk=;
        b=u6m2xphJ/X/JVROwyjUL2GJAxlGwAaHchIqCJGpj1ldEyIQ12QQzdcgREraSBPWvyz
         qznDBvqakJoHWAfSPUwp0ccpm51e70u5KEOAP+H7FdLys45hjo/WsbpZcR4I8m8LEBN8
         abENc5fRIj3Mq4CMfZo4Pgxn3wPyNanIVioiETCCfqIt/bmpElJHoPZ/jqE54yXqF6xH
         LFekSged8W3vlBto8jIQBStyA3nyFdHYX03AwychC1g5wPsCsZWuKO+wwTdwSrwIRsrY
         TfV9v8dCAM5ag6erfX3WgTfzLAiMaJw1vlGYvzc0PsO2edvGQdfd1VbGWNVGM3TdRNUw
         kyiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iG294TZ8;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id 2si175463qtp.1.2020.05.11.05.43.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 May 2020 05:43:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id z90so7700277qtd.10
        for <kasan-dev@googlegroups.com>; Mon, 11 May 2020 05:43:34 -0700 (PDT)
X-Received: by 2002:ac8:6642:: with SMTP id j2mr16145758qtp.158.1589201014239;
 Mon, 11 May 2020 05:43:34 -0700 (PDT)
MIME-Version: 1.0
References: <20200511023111.15310-1-walter-zh.wu@mediatek.com> <CACT4Y+YWNwTSoheJhc3nMdQi9m719F3PzpGo3TfRY3zAg9EwuQ@mail.gmail.com>
In-Reply-To: <CACT4Y+YWNwTSoheJhc3nMdQi9m719F3PzpGo3TfRY3zAg9EwuQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 May 2020 14:43:22 +0200
Message-ID: <CACT4Y+bO1Zg_jgFHbOWgp7fLAADOQ_-AZmjEHz0WG7=oyOt4Gg@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=iG294TZ8;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
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

On Mon, May 11, 2020 at 2:31 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
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
> > +
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
>
> Please move this to generic.c closer to kasan_set_free_info.
> Unnecessary in the header.
>
> > +#define KASAN_NR_RCU_CALL_STACKS 2
>
> Since KASAN_NR_RCU_CALL_STACKS is only used once below, you could as
> well use 2 instead of it.
> Reduces level of indirection and cognitive load.
>
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

Some higher level comments.

1. I think we need to put the free track into kasan_free_meta as it
was before. It looks like exactly the place for it. We have logic to
properly place it and to do the casts.

2. We need to zero aux stacks when we reallocate the object. Otherwise
we print confusing garbage.

3. __kasan_slab_free now contains a window of inconsistency when it
marked the object as KASAN_KMALLOC_FREE, but did not store the free
track yet. If another thread prints a report now, it will print random
garbage.

4. We need some tests. At least (2) should be visible on tests.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbO1Zg_jgFHbOWgp7fLAADOQ_-AZmjEHz0WG7%3DoyOt4Gg%40mail.gmail.com.
