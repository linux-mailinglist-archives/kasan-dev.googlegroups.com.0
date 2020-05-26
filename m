Return-Path: <kasan-dev+bncBDGPTM5BQUDRBUXEWH3AKGQEFVGNJVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C3761E191D
	for <lists+kasan-dev@lfdr.de>; Tue, 26 May 2020 03:35:16 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id v194sf9817571ybv.5
        for <lists+kasan-dev@lfdr.de>; Mon, 25 May 2020 18:35:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590456915; cv=pass;
        d=google.com; s=arc-20160816;
        b=0jUwP0tblgPiA5wRK/A5oh1ATw75lSWSiZ8GswNtJdGMmL8Dqm8S8pHwqCiPdKvWqd
         /KO4AOGopueJqGjF3C6InaX6ppdX83YOyK8BpyJL2+fuJvQ/Mzfu+J1/WARo8kI6iFy1
         /uwo45WH8tlByFPQr3HUAftRcjKLE2nhbliKEVBn9vPK0m/zUWtsO+S7q6sb7cWtVjK9
         GkaX0+FMwJIBoM89ZR7dZ/kjiCiHXS+Gs4tPZ5ZI4ej5yUyQvkGeKKKCFe74jJ+hoUpp
         cpT0En2fFYqZUpaRC9eXBa8kpSFDs6wX8jBY87ZD3h6zIE8RRcIwn71iD5wZLfgDj2hu
         eDZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=fmmX/92SchIxoKLUS7AYR06H+mbPoz4Q1h0P/2RIEas=;
        b=dI8BcAMeehpAOHlZgX9xio5kGCCMcBLXbi+JclC454UbuZX1ifgGo1BuZP7da+Ytod
         KQtQZJQUxW3AXGWMnXgXD1JJxgJRFnmHPSxXUrinm0k/zF5nqQg8kGi7gYXnwIkrpAB7
         bHlA4AZxNbq9jmJi4YtPRdHTOmc648Wev46a8iFfhwCpnrP/z5/JcqUA7mxMnz0pFfYl
         uP8J3qAYzxeYw9SdS5XeGhRxfxcCxfWLe+0HFH/Lw6xJkDrjKanDaOe0SC25igf5+lS8
         2oJQ+tuDDxH17ypnbWi9sPQSJKeZi7OO5p316LYldjvEaX31jk52vaes2JNS1BWn/ZG1
         S6ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=AG81D6CA;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fmmX/92SchIxoKLUS7AYR06H+mbPoz4Q1h0P/2RIEas=;
        b=lWBucbKe/0XY4b20sYsvVmgoezgRk9GdbNsBPDeM3RNNEamtha2h4Gpn5svAx6Ai36
         TbjjY3/7A5ZOjcWzOnwAQSqulD9Hx/J4zkjygBJ/F8z7GjkDvngUgsp9DrNrAORegq91
         EfBPGYe9/IUlde+5MCjkYLMIpp0mo8ARCzP3KUiGNfOwdYn2k3OKlNnMxumeIkdySky/
         hFMSpjZzIcnvjGbjVEwwiGAIcxu6MRtySizXURu+d5GFN1+vQ/+X4A1+cbITUOwbL9I+
         qlrQAXSAP7KVSQH8w3PinOSMmNON7WgFeT+W4S7gH9xE/P7t7USgTUiuvQFztbPpfzEb
         fXBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fmmX/92SchIxoKLUS7AYR06H+mbPoz4Q1h0P/2RIEas=;
        b=Kunig8fYoRbQsBIa9vJVLp029MWa/P/atSN0K8b2VlpZkyDaoGshD9fRdBMyHPuEoC
         h6SbAW0bBZ1ndYE/4LxAHLrfBVPl+a/zU81GMEc/WmawJ/1l9N2l3hJ/C8K4Fjneu3Mt
         KMAr2HIgyZXKpe0hCA7rDOf8m2FpvLHz8ofHYxYkJlJB2UU6B777OBVz7h+jf0TLBtMm
         0SXXknL54tSKLrt8O+B7BhDxGM1kBFpoicEs+Z+y2qF2/3NiFVmy68o9noNzes3jGmuk
         82T8DMsF5TJZNOVk9lY5i7g4J+wcJ0VO++5zYSPQhku9/idoQW/hSS5M9S5EcsUdLlC8
         kbSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533xqXJvzFoddPCrYGj1xRyR4xDYUMN38Clv+klqONw3CI5qTOfX
	ltCZzRQTMQM5/iEb+D+tfck=
X-Google-Smtp-Source: ABdhPJweGimfhttAu6YHeFuzsYxhBytH2YFOkLNIY9MgcvlfLIRQAZD2sr/+dm0jL0GqYba980DRTw==
X-Received: by 2002:a25:cc87:: with SMTP id l129mr30336958ybf.18.1590456914807;
        Mon, 25 May 2020 18:35:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:be4d:: with SMTP id d13ls3584628ybm.2.gmail; Mon, 25 May
 2020 18:35:14 -0700 (PDT)
X-Received: by 2002:a25:7ec4:: with SMTP id z187mr36496830ybc.472.1590456914349;
        Mon, 25 May 2020 18:35:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590456914; cv=none;
        d=google.com; s=arc-20160816;
        b=zkjShv37kY7WDPslioZ9AjhF1/UHA4Yt5xoN9mXwqcSu3ilXctYX42U/JcMsBOUCUJ
         AlIKrYSzXGSpg8cZqJX1Qy67LBQTihl8KM/Z3Hay7wmlv8wweEqWDFivX2/ZsptSlyMQ
         Sgc3SL3WGWCrMDWfeV9PvdhmGHr6w4lmSAbim65GHfU+qoKP9VqfXcA7LdSNUv4dqyWm
         3yMmBBtoOC4z0oiFEUpDDgwoMI7JVHglsefKF5+P8jS5/S1SgFao8+f8+HNmahn6IQMS
         9KuAG5v95xNyWtj9KOirztjT0zEpcaLIKdIC2qq97Ca2H27UJ48CIGTX1PcO9TDB4Bdh
         Kbzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=ueSBcAd3PluSlVN5bpFI2LrWqNDxT0TcwE09/a4ZIpc=;
        b=FW2jzqN84xbjMvg7IDuef7qmXhFX2SCThTrhiUW+NUK6dVnk5B1N+4tDn9qgQ3bsgN
         Stc/v4fAcR9JYVWrBIaFw/lTnCyBqoAkHcIwuXKCKEGU2Jf1pcdjO4zSYQcdsqvvzd3b
         73APWoiXcrA7iF0zLh7mpWxTjbfQhBI4kqWTAVY+TmLy7hDlCXYLGuVj2ksfXyBHAKYb
         /SqSdeL+VaUWcHe8WlkMlN+4BGpVEZg7gemOzjEbu7gzXfGdJacRthbVZin1X9JXTyG+
         7I/w8PsBg9fP5s3A/cEMQVfGaiWhgcaR05R5KMmWSueqvZBe1fjnODjFWTfGxOH9nIp7
         /70w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=AG81D6CA;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id w190si1087908ybe.2.2020.05.25.18.35.13
        for <kasan-dev@googlegroups.com>;
        Mon, 25 May 2020 18:35:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: bf79214c38544007b56022499bd4d76b-20200526
X-UUID: bf79214c38544007b56022499bd4d76b-20200526
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1558043011; Tue, 26 May 2020 09:35:08 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 26 May 2020 09:34:55 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 26 May 2020 09:34:56 +0800
Message-ID: <1590456895.7226.11.camel@mtksdccf07>
Subject: Re: [PATCH v6 1/4] rcu/kasan: record and print call_rcu() call stack
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Paul E .
 McKenney" <paulmck@kernel.org>, Josh Triplett <josh@joshtriplett.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan
	<jiangshanlai@gmail.com>, Joel Fernandes <joel@joelfernandes.org>, "Andrew
 Morton" <akpm@linux-foundation.org>, Andrey Konovalov
	<andreyknvl@google.com>, kasan-dev <kasan-dev@googlegroups.com>, Linux-MM
	<linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Tue, 26 May 2020 09:34:55 +0800
In-Reply-To: <CACT4Y+Zn9eMAPwCMEo710NnsUEoXP+H7xge8a1essu2F9DeFRw@mail.gmail.com>
References: <20200522020059.22332-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+Zn9eMAPwCMEo710NnsUEoXP+H7xge8a1essu2F9DeFRw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=AG81D6CA;       spf=pass
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

On Mon, 2020-05-25 at 11:56 +0200, Dmitry Vyukov wrote:
> On Fri, May 22, 2020 at 4:01 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > This feature will record the last two call_rcu() call stacks and
> > prints up to 2 call_rcu() call stacks in KASAN report.
> >
> > When call_rcu() is called, we store the call_rcu() call stack into
> > slub alloc meta-data, so that the KASAN report can print rcu stack.
> >
> > [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> > [2]https://groups.google.com/forum/#!searchin/kasan-dev/better$20stack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ
> 
> Hi Walter,
> 
> The series look good to me. Thanks for bearing with me. I am eager to
> see this in syzbot reports.
> 
> Reviewed-and-tested-by: Dmitry Vyukov <dvyukov@google.com>
> 

Hi Dmitry,

I appreciate for your response. This patches make KASAN report more
better and let me learn a lot. Thank you for good suggestion and
detailed explanation.

Walter

> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > Acked-by: Paul E. McKenney <paulmck@kernel.org>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > Cc: Josh Triplett <josh@joshtriplett.org>
> > Cc: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
> > Cc: Lai Jiangshan <jiangshanlai@gmail.com>
> > Cc: Joel Fernandes <joel@joelfernandes.org>
> > Cc: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  include/linux/kasan.h |  2 ++
> >  kernel/rcu/tree.c     |  2 ++
> >  mm/kasan/common.c     |  4 ++--
> >  mm/kasan/generic.c    | 21 +++++++++++++++++++++
> >  mm/kasan/kasan.h      | 10 ++++++++++
> >  mm/kasan/report.c     | 28 +++++++++++++++++++++++-----
> >  6 files changed, 60 insertions(+), 7 deletions(-)
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
> > index 56ff8885fe2e..8acf48882ba2 100644
> > --- a/mm/kasan/generic.c
> > +++ b/mm/kasan/generic.c
> > @@ -325,3 +325,24 @@ DEFINE_ASAN_SET_SHADOW(f2);
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
> > +       /*
> > +        * record the last two call_rcu() call stacks.
> > +        */
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
> > index 80f23c9da6b0..2421a4bd9227 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -105,15 +105,20 @@ static void end_report(unsigned long *flags)
> >         kasan_enable_current();
> >  }
> >
> > +static void print_stack(depot_stack_handle_t stack)
> > +{
> > +       unsigned long *entries;
> > +       unsigned int nr_entries;
> > +
> > +       nr_entries = stack_depot_fetch(stack, &entries);
> > +       stack_trace_print(entries, nr_entries, 0);
> > +}
> > +
> >  static void print_track(struct kasan_track *track, const char *prefix)
> >  {
> >         pr_err("%s by task %u:\n", prefix, track->pid);
> >         if (track->stack) {
> > -               unsigned long *entries;
> > -               unsigned int nr_entries;
> > -
> > -               nr_entries = stack_depot_fetch(track->stack, &entries);
> > -               stack_trace_print(entries, nr_entries, 0);
> > +               print_stack(track->stack);
> >         } else {
> >                 pr_err("(stack is not available)\n");
> >         }
> > @@ -192,6 +197,19 @@ static void describe_object(struct kmem_cache *cache, void *object,
> >                 free_track = kasan_get_free_track(cache, object, tag);
> >                 print_track(free_track, "Freed");
> >                 pr_err("\n");
> > +
> > +#ifdef CONFIG_KASAN_GENERIC
> > +               if (alloc_info->aux_stack[0]) {
> > +                       pr_err("Last call_rcu():\n");
> > +                       print_stack(alloc_info->aux_stack[0]);
> > +                       pr_err("\n");
> > +               }
> > +               if (alloc_info->aux_stack[1]) {
> > +                       pr_err("Second to last call_rcu():\n");
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
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200522020059.22332-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1590456895.7226.11.camel%40mtksdccf07.
