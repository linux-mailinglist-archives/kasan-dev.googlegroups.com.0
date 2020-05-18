Return-Path: <kasan-dev+bncBDGPTM5BQUDRBLXFRH3AKGQEIMYWVQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id D49871D7734
	for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 13:34:07 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id o69sf8439792pfd.21
        for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 04:34:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589801646; cv=pass;
        d=google.com; s=arc-20160816;
        b=XoJ9tstpL2jyw/uIjAoSRw2fN433cgkRTigzmA06XA6j7F2MNc873pijJ9qPhE7fHk
         SNijBZa8DAcLiNwMOSOTuDTQ0kJgyEg7aX9oxan4wtrvqRxBkBh2HFZQVXGTkt/Qb5Eo
         PyJw2lLZBEa51nCmI6QeGdG12x7DLOp83hmLFwMXv30PYXygLmry5N26d+7stDOMmwyL
         fsNvcZZDXCNvvv01JgQ5Gg66Eki7UOpY2WdPi+fw3EV+FgEvsXMprTlHwFPLawJ0HsM6
         Q9garKNPYMqBqJDCX53Eal7Oq+LHdRdZKKEK4xDJG80NqJpM7gwSBMA/9IlR22ivb7Zj
         Vm5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=cUqOZwAnXjruJn4vABxcrmjQJZZq5TsS6WMcHzAf3QM=;
        b=mMr8LdYiy7dve8O82ooR5q2CCcV6dEb+6z+jYSnpmpP/Y9Hmcy/zMtX9xUYNWoneYo
         7knT+vManr78wNO79MDNJ1Zvahf1HJrE6PXr+kb2mvA8TYLtojYmQXnW3vNjJ8UyXVYl
         1iiCx4ZRePPLw2LKffvmHTWWl1pHPPS45/JSPyElab0nYjI8Qb4GYgURBkOwacicSr7z
         Md2NKjQW1/DYYt20QwFcA4ibzQdDFyOxS7Tahd/PfxH1lbQZRyj4W2tng+UumNLmyopb
         U5X44KHubf8oydxKCtnv7uIawg8mNQaex275wEAZ1ivE59CpK40NR79ALKqTLEQXRSlT
         VxKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=LUZgPjhz;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cUqOZwAnXjruJn4vABxcrmjQJZZq5TsS6WMcHzAf3QM=;
        b=N+3W+7PEBBxT8MpdohDC6YGqIhQGFtmPxVlNtZ5zeOF5j8EgJDUxCU1ezm+XfT/Gnc
         e7h/H4sSkIICSE45zj/7uWenlm3PLnEs8aVLRpUCDxuAn/NUkDhSGuh678sgv1gJu1Fk
         kLCQ5jrOMcpaFAvuE0DNM2zMBbB7aZNOFFqvgPUW2J7hVDFKISiLykzpUAILAhM2OqMZ
         VgwzMIPZeeSnIG5gF/KOptspb6+FJVZNktwSJVGyCoyanXMWcBXC9O376Yqf7EUGKD8j
         WRkFMaTJgndSZ93huvmMAY2RAcKRWK3Rn0YhuY1IZM+XTTx6EAhER1IYI3s5X+pcpu9B
         jKFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cUqOZwAnXjruJn4vABxcrmjQJZZq5TsS6WMcHzAf3QM=;
        b=YgoUM9bEjE+KjA1Rym0qktz6iw7nAIHC0gf7Ymwgs02C1/NDtMax0de+pCAlxFWkjr
         HHkpzJdPjJf5+TtnLIQHNi/L283WN7fFKtMntVijrErvur4V7dnJCBqIcA3IdmQdPW42
         eGjajvwVqBGJMCxuGWYrjAV3jiil9CDcWyC54YIdooBKWGVnPU/LKwQXr1H/tjheqS8n
         xoTckOkWF1Qg5Gb2AoDwlDTKzrkhREdVKZVvaInbey/3qd+R8BKi9bipi0UoAaxR5HO2
         4Su2GagrlTg/2E/U2O4shkMMBd0ttBFcIHFrMAtoNZI0cNWrg0MAwJEKKSKLOlLCfU0d
         FrQg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532U/QQ6E/7wIqPhIJL6+T9R48HqdjdfKT0Y5TeZswlPDz5Gn6+P
	hLbgaBS2n+y1TCgKh8znWhQ=
X-Google-Smtp-Source: ABdhPJwieM5mzUZztNnWq3bbOqTIa6thZyMYmL69q4+9LTwr8WkTF7iVXlCKklCcxr5dGSafrky8pw==
X-Received: by 2002:a17:90b:3717:: with SMTP id mg23mr19686255pjb.129.1589801646597;
        Mon, 18 May 2020 04:34:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4c02:: with SMTP id na2ls5156615pjb.0.gmail; Mon, 18
 May 2020 04:34:06 -0700 (PDT)
X-Received: by 2002:a17:902:7488:: with SMTP id h8mr16243708pll.128.1589801646142;
        Mon, 18 May 2020 04:34:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589801646; cv=none;
        d=google.com; s=arc-20160816;
        b=t93PAWc7n6mhAPjeTzn7mwIij1oaZwgM9Wi84vyQhXbUyuCElxhqRtLYtj1RUvV0j4
         aX8X5UpIjiutSFGQn9N0x0UlzX5akMWa+m3cR00nQ434LSilmsDmDYXBL59kpW1Dv4Bl
         yeAd6Z1OFpB43xLsPASdOGI3Mn8xk83n7WrgNlfeCyaUa47/V5gWeYkSe2/FoD6DJyT6
         HSgzLPzeJFs76ZxmjV2KqvmpSip9qNPHaOjmdtwjNBgRdPKydvdvhy6FzcBJwfd7qwvx
         kB2KMsSaO+8bQnOdaedXNl9/PXX/iWghb49xPQegS4MFftrmZURRfbCJ4oZwaYmVoHrv
         3fSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=b6TPxQu3uTXdGrIPN1uOW1C9cIPPPlIW83hXfyijCTY=;
        b=sgtrB7YDsjJE0vXv8iTi5E5wA51I/Jw+Xr/Ju5TjGcGobaQSqA/nPQDi9B+M6iCKD9
         3N23UJlMxP5ydo8mPCpfz5AtN4eeAPrKEIFGfNREdxWvEW1lTfGSZ6lMbQhGHI/hdm6/
         K32vNTShu19EKmhxUvZEqqpmOViTpMQHmUAyDgI3G5X7H7wBRRdmdFpa1Ruy/RtN2ojC
         ZQETMyXDtHbKe2f5yc+/54JlBbVU5UmnvQhC5/+uE7wXAcXYCCgpULGkJc7qM4pY7HM2
         NVpWS62wgwsii7TK0FpTeJPChvl6+kWH0WgU2YjWCE26w/aAs/m+Qp19u4a1nEySc8rN
         umPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=LUZgPjhz;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id s12si202572pfh.5.2020.05.18.04.34.05
        for <kasan-dev@googlegroups.com>;
        Mon, 18 May 2020 04:34:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 4eec50c4de2e4a13b9023ac3154334d9-20200518
X-UUID: 4eec50c4de2e4a13b9023ac3154334d9-20200518
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 972903765; Mon, 18 May 2020 19:34:04 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 18 May 2020 19:34:01 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 18 May 2020 19:34:01 +0800
Message-ID: <1589801642.16436.15.camel@mtksdccf07>
Subject: Re: [PATCH v3 1/4] rcu/kasan: record and print call_rcu() call stack
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
Date: Mon, 18 May 2020 19:34:02 +0800
In-Reply-To: <CACT4Y+aSmcoSeC7J7RgoVV8CanwCrEz=zNZYG=_8KX3U-57A5Q@mail.gmail.com>
References: <20200518062603.4570-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+aSmcoSeC7J7RgoVV8CanwCrEz=zNZYG=_8KX3U-57A5Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: E77F9617DB6389E914D0B76D0E0A18CFAD11FEE722E06AD465772D52125D2ED92000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=LUZgPjhz;       spf=pass
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

On Mon, 2020-05-18 at 12:21 +0200, 'Dmitry Vyukov' via kasan-dev wrote:
> On Mon, May 18, 2020 at 8:26 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > This feature will record the last two call_rcu() call stack and
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
> >  mm/kasan/generic.c    | 20 ++++++++++++++++++++
> >  mm/kasan/kasan.h      | 10 ++++++++++
> >  mm/kasan/report.c     | 24 ++++++++++++++++++++++++
> >  7 files changed, 62 insertions(+), 2 deletions(-)
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
> > index 56ff8885fe2e..78d8e0a75a8a 100644
> > --- a/mm/kasan/generic.c
> > +++ b/mm/kasan/generic.c
> > @@ -325,3 +325,23 @@ DEFINE_ASAN_SET_SHADOW(f2);
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
> > +       /* record last two call_rcu() call stacks */
> > +       if (alloc_info->rcu_stack[0])
> 
> Do we need this if?
> 
> If we do "alloc_info->rcu_stack[1] = alloc_info->rcu_stack[0]"
> unconditionally, then we will just move 0 from [0] to [1], which
> should be 0 at this point anyway.
> 

Yes, this if is redundant.

> I think it will be more reasonable to rename rcu_stack to aux_stack,
> the function that stores the stacks is kasan_record_aux_stack.
> 

ok, we will change it's name.

> > +               alloc_info->rcu_stack[1] = alloc_info->rcu_stack[0];
> > +       alloc_info->rcu_stack[0] = kasan_save_stack(GFP_NOWAIT);
> > +}
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index e8f37199d885..870c5dd07756 100644
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
> > +       depot_stack_handle_t rcu_stack[2];
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
> > index 80f23c9da6b0..5ee66cf7e27c 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -179,6 +179,17 @@ static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> >         return &alloc_meta->free_track[i];
> >  }
> >
> > +#ifdef CONFIG_KASAN_GENERIC
> > +static void print_stack(depot_stack_handle_t stack)
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
> > +               if (alloc_info->rcu_stack[0]) {
> > +                       pr_err("Last one call_rcu() call stack:\n");
> > +                       print_stack(alloc_info->rcu_stack[0]);
> > +                       pr_err("\n");
> > +               }
> > +               if (alloc_info->rcu_stack[1]) {
> > +                       pr_err("Second to last call_rcu() call stack:\n");
> > +                       print_stack(alloc_info->rcu_stack[1]);
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
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200518062603.4570-1-walter-zh.wu%40mediatek.com.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1589801642.16436.15.camel%40mtksdccf07.
