Return-Path: <kasan-dev+bncBDGPTM5BQUDRB5MV4X2QKGQEBMDKGNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FA8C1CDA83
	for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 14:54:14 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id u7sf7684311pga.8
        for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 05:54:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589201653; cv=pass;
        d=google.com; s=arc-20160816;
        b=l0ZHfoxjGU642kXT4qoPMRmA5sWp7sIs1bveyRisMZrDxc0/O9DjB38lRmiYV/UrDZ
         RjEJAICGYZt/qrdYQJZhhAIzIjdlWZuOmdMk66sX0OAZ9HkJgUO/8NzMuIasOhDcv6Cd
         aIRPGU6+lwTUa7vsF5jNU5ktSKzhiL/H2SdWfwvlILmWSBeAcD2xpc+7vN744svYOEOC
         bz/hYicRC2gugtpQj6ptOLjrKnTGW2IzoV3XOp0pRskrAQIw6YQjlttGkN5+xk77YM0X
         th5oQbs6QUb8eRmK9r0Tv5mMs1bYi0fgdvootNHzwGWWZL72pjqpISs1X/KSNnLsWZJR
         S2pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=MAIiNDQ1+lv/36RUs6gi2Gi5DjbxkWwLJjg/wzl68lM=;
        b=IpAM8znR3O/g1SalIo17vijRjcUKu2/USP1dX5oLalpTFCqttA/TuNsqkhxHQt4uiy
         X0T+8hlUEhDc0jYZVPdKEV4PkdvFj3VVU6gBztQ1AHUcARoWBMua03UGsXY56P5sh1lt
         l/JlzOcRY48CAy7gY7px1QAMAezSnzHXzEViPDPVN/Z5JkozI6IWsQGwUlClHuVo/fFN
         CYOGVGeCVsZp6twKGoqww76p2ENFgBB1vmdbzrqCfY1rkPyQvhlnhk6yYHH2RA0jWpT0
         HMU+PGWT3Ps1aN3RU4Ix54wZr0Gdv5a62ZAjdAJIyTtJs70VahrDmXk7drf+QuCO7pNN
         RcYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="U1/AQ1Xo";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MAIiNDQ1+lv/36RUs6gi2Gi5DjbxkWwLJjg/wzl68lM=;
        b=jWPe20lkm7fXeKTpdKkmRMjXjD034WjEK+9Obyy5TjgQDebvCYXH6z1kVkTwoYtZ2F
         nlYH3yJHoGHxzKfo+OKfw7vKGb+HFCB91T7CQGPH1SDLexWKnFITfD7hpXnpcoqiTMo2
         GvCQECFR1wTetYvatjXFIZZnc96m1gPp/OSc4Y4Q6y9GO5/Ggldo2619G+jWtovD0vug
         0uSKbegYtVzyb3aqB4nUD4/GSsyS3V4Fufu0it2tRfWogkO6Sb2Jhm1jRV4vBzvvN4Pv
         f4GfDQFKimW1hhXh1DJinhXX3JlTaLSRYFFyCvXF28/OxkLvGKEUBC2ln2NKqGB9bBd2
         TDsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MAIiNDQ1+lv/36RUs6gi2Gi5DjbxkWwLJjg/wzl68lM=;
        b=iLR8FeUV2GgRPLqgwaXP6hOnwOQhPAzHPcyCHGz5dMkDEjpKg1gIX9bpZVbiZQBYu8
         auzpoNFO33DC1Hxko9VzAAYDB0Zux0+i+qn/aVFC1FI15vuSSOm/sT4rjKXRmUT8IHqy
         6qnL1sArQ/eCHkd1puENcWfGQ0r5HM9XUByDKr2C4+3M+4d0+4g8mI4JrzpqbpHKou1/
         pu6MfoDfIkgihKvai7QIdeDEbt/8WBxNWBlUh5tkdab8ARQQUnNERMFavAGIVC4CSTI/
         X+qwfnfxH907NfzAuG3ukhunuZGQ3j+2MIH/E0sUgzTY6aMRI0IUvyKpSjmex7OwSPF1
         yF7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuaJSJwgoDHt68c8khglZ49lUWdTBPnwkpWa0CQKm9WHZfoK3TxN
	Mi7zSRFk7U+PTsddcz67jYk=
X-Google-Smtp-Source: APiQypJglQEovQ5YjkiqWB3ImlaPnC/8OB3Cy9YfntVm8I9t0Z0qXuBkLA5eUwf/mEN86EOuM13nrQ==
X-Received: by 2002:a17:902:82c1:: with SMTP id u1mr15421308plz.10.1589201653271;
        Mon, 11 May 2020 05:54:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1b0a:: with SMTP id b10ls3630611pgb.1.gmail; Mon, 11 May
 2020 05:54:12 -0700 (PDT)
X-Received: by 2002:a63:ef04:: with SMTP id u4mr14527826pgh.280.1589201652886;
        Mon, 11 May 2020 05:54:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589201652; cv=none;
        d=google.com; s=arc-20160816;
        b=qhc2v3cTd/J/9F/fCrWJ4bqBPC4BpYKzZ45LF7KjbdNsWiJXV8anFb2Cpq7r79TJuU
         n/EEI6ZOijZbJD2WuKmfszT4KFu8jgeYFOs1uKoYmL6gKeW0V617qpuPWrNrbROSYQ6f
         vc79Ltq5mdrYGwbgQFtvy5CWcL+1U3zZYSagjU5wkPMdxzSfJKs8MuepGmDeR/V+HOAb
         iE6ttA1YL3oPrskRNF11YjPrcFxMk5z61AC3dmwhmVxkmeXqTD9QdAdGWzw769SzejOJ
         QeFCB+HB//7Qfgv3DgZhhM4GtdXWM8j+bAdaKcC0asxIztm3YKO+S1zS3pjULMAHmTvA
         3BIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=rIZGhVrxXRjoXUn4E3hst+RuZALYvR1HEad0mjZszc0=;
        b=FnNoaxp2bW/Kgd1hSRh8NGSvE1vBwdWihUXbN6kiU/ZSTUn6x7rxw/seb+md9pMRlj
         WM7GdmWZ7XYQ0tQtVIYPYqJfYnyDM5LI2elxK8L4YiMzTMCmFoxzaOa/nx1j5FuHh3z/
         gnm/qUyf4S3M5c1nPQoVwNnG/i1KIySHwDQClPOmj19gSGPYR9QHiN85DJit9dbk0Pzj
         ig/Twp7TF5YKgnUcMLpiruc9hX5ApyQyPzJvNRV2YT8lr5TN5evKUjnN8UPoujTmg/eC
         PyKBUl6vfBX1kbEihLwkv3s6mmGf7GUKF39J7VO67ypNZ//knynSc17f8MKa7dZdT2ki
         jBsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="U1/AQ1Xo";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id a95si1274391pje.1.2020.05.11.05.54.12
        for <kasan-dev@googlegroups.com>;
        Mon, 11 May 2020 05:54:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 04be38007f5b4b80a0fb604a852b7f46-20200511
X-UUID: 04be38007f5b4b80a0fb604a852b7f46-20200511
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1080885132; Mon, 11 May 2020 20:54:07 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 11 May 2020 20:54:04 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 11 May 2020 20:53:58 +0800
Message-ID: <1589201640.21284.8.camel@mtksdccf07>
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
Date: Mon, 11 May 2020 20:54:00 +0800
In-Reply-To: <CACT4Y+beDTzGrDx9uWSjbr67j0encwBa_1PKpyQCejiddLhOxA@mail.gmail.com>
References: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+beDTzGrDx9uWSjbr67j0encwBa_1PKpyQCejiddLhOxA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b="U1/AQ1Xo";       spf=pass
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

On Mon, 2020-05-11 at 14:20 +0200, 'Dmitry Vyukov' via kasan-dev wrote:
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
> 
> This is not type safe, there is no kasan_track object. And we create a
> pointer to kasan_track just to carefully not treat it as valid
> kasan_track in print_track.
> 

Good catch.

> This adds an unnecessary if to print_track. And does not seem to be
> useful/nice to print:
> 
> First call_rcu() call stack:
> (stack is not available)
> 
> Last call_rcu() call stack:
> (stack is not available)
> 
> when no rcu stacks are memorized.
> Your intention seems to be to reuse 2 lines of code from print_track.
> I would factor them out into a function:
> 
> static void print_stack(depot_stack_handle_t stack)
> {
>         unsigned long *entries;
>         unsigned int nr_entries;
> 
>         nr_entries = stack_depot_fetch(stack, &entries);
>         stack_trace_print(entries, nr_entries, 0);
> }
> 
> And then this can expressed as:
> 
>         if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
>             stack = alloc_info->rcu_stack[0];
>             if (stack) {
>                 pr_err("First call_rcu() call stack:\n");
>                 print_stack(stack);
>                 pr_err("\n");
>             }
>             stack = alloc_info->rcu_stack[1];
>             if (stack) {
>                 pr_err("Last call_rcu() call stack:\n");
>                 print_stack(stack);
>                 pr_err("\n");
>             }
>         }
> 

rcu_stack doesn't exist at report.c, it need at generic.c,
otherwise it will have build error, unless add the #ifdef GENERIC_KASAN

Maybe we can make kasan_get_aux_stack() return NULL? then print_stack()
determine whether it will print aux stack.

> 
> Or with another helper function it becomes:
> 
>         if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
>             print_aux_stack(alloc_info->rcu_stack[0], "First");
>             print_aux_stack(alloc_info->rcu_stack[1], "Last");
>         }
> 
> 
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
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1589201640.21284.8.camel%40mtksdccf07.
