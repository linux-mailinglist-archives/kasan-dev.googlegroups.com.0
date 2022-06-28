Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB5M5SKQMGQEICYCQVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DFAB55E58B
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 16:54:01 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id 186-20020a3708c3000000b006af306eb272sf5616046qki.18
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 07:54:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656428040; cv=pass;
        d=google.com; s=arc-20160816;
        b=M8vmL/68CYfNWQJOT16One2+gmzwR89HwzaqXbswhcxmBDAN10sMtAA3jkGW7VA8rk
         jFlrhuGa4U9lZitYOCB7qHx6pyOYe/mGPcaG2E23XhSmpdrPPUTFFDEX39cixTp6D643
         J31C8pgFJiLeErS8SyGI6yzmjGPpM1WeQjYqfmhCMpkHJupBMai3DuMH23Pzeb7QRM84
         W3iX1K34faRoaRbI8KAm7Hp5li+ERlw+CfC+27BjidIlJu3xm/HLndY9uchnxCzFYGdg
         uTjPLp2KoBp5xbJeCqbFEUy6CKqFiFdIixZ49nC8g7bANe5LsM8pXlBSVWoLheucBiGA
         rzWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UiZKuFabJByHj7fWwEULFu1W8CJJDZV6G8iE4ixIHSo=;
        b=EQlxm6+B162Ct2+iQyTEvMR881oDq/vEy6/GrQS5ftsfUSvCboGWg9vxm71inXbXsv
         3W/fExuVH57GlXdquv7fJRP56wLxFUUI5+qeA2Z1xI2nE7FPNEPlkcgN8hu0Yggdsz1q
         jFYWw552Uds8brAPWPKMThqQ4Fc+Ce7uioQ1rexI4Fl7mNC5+ybK/pKRiptK+YEPxmIx
         chHINL2VjSC7jKTequo/sxcBN0VezHbmD7bOqQvYB8UGC0Gj4lKw8xUlTN51z8XLnGRq
         EXUfHCv9HKfeCESCj+AerI+Ct5/LdTZQSn16SWR3vxkZEutbbfNPbqv5y+nHaIXRUD0z
         qDfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hr+LOJOC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UiZKuFabJByHj7fWwEULFu1W8CJJDZV6G8iE4ixIHSo=;
        b=QYWYQQc1CtiMmcDwaE/JarnsORJLeT+XWCqm//VniVFsctuQ/bHgW+5EDs7cSw0tmT
         YcdZ+d4T5tuO3mKPOIR1czwVeOxjE+hLoB3h4U/r6DBw+0svefLKyb3O8CApFceWtes7
         xLEIp/iTEHmkJwRVHUvt/29n3C96Q3KdCPuQSpI240LF2TE7uJoRi9DFNJ/t6HV2sYpC
         nHp09dtdO/CvhGmigaX3SmUYccQEGBJittelIrVgE/xJHWQyWP+sfyfPMYxqstyPcKbO
         hdi4HLZNGuE/mjvWWAIbJOq7lyrA1pME++E5QSgMSwzUs7Go32M4387NEerVEZ6ENGpa
         EVMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UiZKuFabJByHj7fWwEULFu1W8CJJDZV6G8iE4ixIHSo=;
        b=i795ItGUEfsIj6zgLQZ6eFFKR+DouwZKMs4KD7+l73zxesaW9afBgsF76uGVnYtSs5
         dTbN673clRh0qpIIr6cK3uXwR8SBvoAA1KoiMY/f4aZdVBc6Ewvg6h8hw6XNxqETBa0q
         UGLYpdBTOoJYZS8X265kjsLwqcMl2uHZsg3VNoC2ap6h83F+moTicImK4K1jcd/tbXl0
         zfxUd9YvzRU0E+nRHkBGvCL+SQoz+3ntdJel5eJXuxRxp1xZ9rOqHmRdRmCeSut3/JC6
         nWLYBeM1M0mLZHlgiWwz2JBvTSDwseUDbZ5DIsyOgiqHN0cpACM3n1MVZEFM47qGIOx/
         D2oA==
X-Gm-Message-State: AJIora92Jk9IfsbPw7ppyPnV7YmClorWuNMIa3jDX7K0cXx15x2/TqF0
	FxzC4zQbiV/QFeqmTu0hWxE=
X-Google-Smtp-Source: AGRyM1vk07ojhO/znCrN7j/U6gS0FP6mu6rb+LAosNs0AnxOBYOyZ3OAsd46fTi7GVU0gPHt6hOFLA==
X-Received: by 2002:a05:620a:1b8f:b0:6af:337a:5067 with SMTP id dv15-20020a05620a1b8f00b006af337a5067mr5516204qkb.343.1656428040009;
        Tue, 28 Jun 2022 07:54:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:27cb:b0:6a7:63c0:980f with SMTP id
 i11-20020a05620a27cb00b006a763c0980fls19807002qkp.8.gmail; Tue, 28 Jun 2022
 07:53:59 -0700 (PDT)
X-Received: by 2002:a05:620a:c91:b0:6af:4b9:4c1b with SMTP id q17-20020a05620a0c9100b006af04b94c1bmr11670716qki.615.1656428039409;
        Tue, 28 Jun 2022 07:53:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656428039; cv=none;
        d=google.com; s=arc-20160816;
        b=BBaLhZmn3qgWxJL12jMaTAvp/NFPNblQIXHAoRyS2YZQkKvKIx13xB1Ikd9Jo8BC0i
         bJWj+bV7OOMRVozDpq5Jm9+v3946lL2lJLE/sVpmFSlM1tfAotSatS28IkJLxcb27zIj
         wOV0fwBi6R5ZrVPnpzPxfPzdFaOQo46cb4/R5iLf4DzRI2lHFdi/eGu8AtZ9lPaWdalF
         AX9xNf/2q3IZcgeOP4Wyx3hWL9+up5XJMLF7A5blyYvpQoTjtxwFpvw5H6dTY8KaLM8i
         fSjzimrOKQuag6m2IgULo66aY4Jg8EhPYrdsO3dKWZK0apYA6ERi3B5xFVzUyRDZ9Y4M
         bS8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vsLZ4itLb8yCme9zL9SXTWJXCTaMaHUvxCRr4pVmzPo=;
        b=Pz9UrSR0YOCOhwwBnF8IrRzENzWPz9NaTU36yd42I3rvzW8cGK1udJqpdbBXZQxmkQ
         ouayoFcQAi20Wc1ZFleBEl195Fne60bEa27v6khO0p07uEpANDwCsX7cgVI76+Fo4qVp
         c987iFQWUi5DB9CpkFg1opnd99+J5iuoacWP7n9f5baObAvUsrIL9lI2uMf3gGLZmFOx
         YedTcWOu+TQehtmaQdVED8oMI0TBGOwVEmdof7h6QXsx9fsZCSF+8uouhycYD0xlVdT1
         cwNvSA5eY6rIe3PzyRreDUNqJhvLxwn6nFKimYQhoitNZNq6y3/dhRuuoWgkNoEmjGd7
         6m2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hr+LOJOC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id a77-20020a376650000000b006a6ec16dd2csi710247qkc.1.2022.06.28.07.53.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 07:53:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id g4so11091578ybg.9
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 07:53:59 -0700 (PDT)
X-Received: by 2002:a5b:74e:0:b0:66c:df8d:12f6 with SMTP id
 s14-20020a5b074e000000b0066cdf8d12f6mr9546552ybq.609.1656428038960; Tue, 28
 Jun 2022 07:53:58 -0700 (PDT)
MIME-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com> <20220628095833.2579903-4-elver@google.com>
 <CACT4Y+bh06ZF5s4Mfq+CJ8RJ+Fm41NeXt=C8Kkx11t9hgABpYQ@mail.gmail.com>
In-Reply-To: <CACT4Y+bh06ZF5s4Mfq+CJ8RJ+Fm41NeXt=C8Kkx11t9hgABpYQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jun 2022 16:53:22 +0200
Message-ID: <CANpmjNOT=npm9Bu9QGNO=SgCJVB2fr8ojO4-u-Ffgw4gmRuSfw@mail.gmail.com>
Subject: Re: [PATCH v2 03/13] perf/hw_breakpoint: Optimize list of per-task breakpoints
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hr+LOJOC;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 28 Jun 2022 at 15:08, Dmitry Vyukov <dvyukov@google.com> wrote:
>
>  On Tue, 28 Jun 2022 at 11:59, Marco Elver <elver@google.com> wrote:
> >
> > On a machine with 256 CPUs, running the recently added perf breakpoint
> > benchmark results in:
> >
> >  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
> >  | # Running 'breakpoint/thread' benchmark:
> >  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
> >  |      Total time: 236.418 [sec]
> >  |
> >  |   123134.794271 usecs/op
> >  |  7880626.833333 usecs/op/cpu
> >
> > The benchmark tests inherited breakpoint perf events across many
> > threads.
> >
> > Looking at a perf profile, we can see that the majority of the time is
> > spent in various hw_breakpoint.c functions, which execute within the
> > 'nr_bp_mutex' critical sections which then results in contention on that
> > mutex as well:
> >
> >     37.27%  [kernel]       [k] osq_lock
> >     34.92%  [kernel]       [k] mutex_spin_on_owner
> >     12.15%  [kernel]       [k] toggle_bp_slot
> >     11.90%  [kernel]       [k] __reserve_bp_slot
> >
> > The culprit here is task_bp_pinned(), which has a runtime complexity of
> > O(#tasks) due to storing all task breakpoints in the same list and
> > iterating through that list looking for a matching task. Clearly, this
> > does not scale to thousands of tasks.
> >
> > Instead, make use of the "rhashtable" variant "rhltable" which stores
> > multiple items with the same key in a list. This results in average
> > runtime complexity of O(1) for task_bp_pinned().
> >
> > With the optimization, the benchmark shows:
> >
> >  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
> >  | # Running 'breakpoint/thread' benchmark:
> >  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
> >  |      Total time: 0.208 [sec]
> >  |
> >  |      108.422396 usecs/op
> >  |     6939.033333 usecs/op/cpu
> >
> > On this particular setup that's a speedup of ~1135x.
> >
> > While one option would be to make task_struct a breakpoint list node,
> > this would only further bloat task_struct for infrequently used data.
> > Furthermore, after all optimizations in this series, there's no evidence
> > it would result in better performance: later optimizations make the time
> > spent looking up entries in the hash table negligible (we'll reach the
> > theoretical ideal performance i.e. no constraints).
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > v2:
> > * Commit message tweaks.
> > ---
> >  include/linux/perf_event.h    |  3 +-
> >  kernel/events/hw_breakpoint.c | 56 ++++++++++++++++++++++-------------
> >  2 files changed, 37 insertions(+), 22 deletions(-)
> >
> > diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
> > index 01231f1d976c..e27360436dc6 100644
> > --- a/include/linux/perf_event.h
> > +++ b/include/linux/perf_event.h
> > @@ -36,6 +36,7 @@ struct perf_guest_info_callbacks {
> >  };
> >
> >  #ifdef CONFIG_HAVE_HW_BREAKPOINT
> > +#include <linux/rhashtable-types.h>
> >  #include <asm/hw_breakpoint.h>
> >  #endif
> >
> > @@ -178,7 +179,7 @@ struct hw_perf_event {
> >                          * creation and event initalization.
> >                          */
> >                         struct arch_hw_breakpoint       info;
> > -                       struct list_head                bp_list;
> > +                       struct rhlist_head              bp_list;
> >                 };
> >  #endif
> >                 struct { /* amd_iommu */
> > diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> > index 1b013968b395..add1b9c59631 100644
> > --- a/kernel/events/hw_breakpoint.c
> > +++ b/kernel/events/hw_breakpoint.c
> > @@ -26,10 +26,10 @@
> >  #include <linux/irqflags.h>
> >  #include <linux/kdebug.h>
> >  #include <linux/kernel.h>
> > -#include <linux/list.h>
> >  #include <linux/mutex.h>
> >  #include <linux/notifier.h>
> >  #include <linux/percpu.h>
> > +#include <linux/rhashtable.h>
> >  #include <linux/sched.h>
> >  #include <linux/slab.h>
> >
> > @@ -54,7 +54,13 @@ static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
> >  }
> >
> >  /* Keep track of the breakpoints attached to tasks */
> > -static LIST_HEAD(bp_task_head);
> > +static struct rhltable task_bps_ht;
> > +static const struct rhashtable_params task_bps_ht_params = {
> > +       .head_offset = offsetof(struct hw_perf_event, bp_list),
> > +       .key_offset = offsetof(struct hw_perf_event, target),
> > +       .key_len = sizeof_field(struct hw_perf_event, target),
> > +       .automatic_shrinking = true,
> > +};
> >
> >  static int constraints_initialized;
> >
> > @@ -103,17 +109,23 @@ static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
> >   */
> >  static int task_bp_pinned(int cpu, struct perf_event *bp, enum bp_type_idx type)
> >  {
> > -       struct task_struct *tsk = bp->hw.target;
> > +       struct rhlist_head *head, *pos;
> >         struct perf_event *iter;
> >         int count = 0;
> >
> > -       list_for_each_entry(iter, &bp_task_head, hw.bp_list) {
> > -               if (iter->hw.target == tsk &&
> > -                   find_slot_idx(iter->attr.bp_type) == type &&
> > +       rcu_read_lock();
> > +       head = rhltable_lookup(&task_bps_ht, &bp->hw.target, task_bps_ht_params);
> > +       if (!head)
> > +               goto out;
> > +
> > +       rhl_for_each_entry_rcu(iter, pos, head, hw.bp_list) {
> > +               if (find_slot_idx(iter->attr.bp_type) == type &&
> >                     (iter->cpu < 0 || cpu == iter->cpu))
> >                         count += hw_breakpoint_weight(iter);
> >         }
> >
> > +out:
> > +       rcu_read_unlock();
> >         return count;
> >  }
> >
> > @@ -186,7 +198,7 @@ static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
> >  /*
> >   * Add/remove the given breakpoint in our constraint table
> >   */
> > -static void
> > +static int
> >  toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
> >                int weight)
> >  {
> > @@ -199,7 +211,7 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
> >         /* Pinned counter cpu profiling */
> >         if (!bp->hw.target) {
> >                 get_bp_info(bp->cpu, type)->cpu_pinned += weight;
> > -               return;
> > +               return 0;
> >         }
> >
> >         /* Pinned counter task profiling */
> > @@ -207,9 +219,9 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
> >                 toggle_bp_task_slot(bp, cpu, type, weight);
> >
> >         if (enable)
> > -               list_add_tail(&bp->hw.bp_list, &bp_task_head);
> > +               return rhltable_insert(&task_bps_ht, &bp->hw.bp_list, task_bps_ht_params);
> >         else
> > -               list_del(&bp->hw.bp_list);
> > +               return rhltable_remove(&task_bps_ht, &bp->hw.bp_list, task_bps_ht_params);
> >  }
> >
> >  __weak int arch_reserve_bp_slot(struct perf_event *bp)
> > @@ -307,9 +319,7 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
> >         if (ret)
> >                 return ret;
> >
> > -       toggle_bp_slot(bp, true, type, weight);
> > -
> > -       return 0;
> > +       return toggle_bp_slot(bp, true, type, weight);
> >  }
> >
> >  int reserve_bp_slot(struct perf_event *bp)
> > @@ -334,7 +344,7 @@ static void __release_bp_slot(struct perf_event *bp, u64 bp_type)
> >
> >         type = find_slot_idx(bp_type);
> >         weight = hw_breakpoint_weight(bp);
> > -       toggle_bp_slot(bp, false, type, weight);
> > +       WARN_ON(toggle_bp_slot(bp, false, type, weight));
> >  }
> >
> >  void release_bp_slot(struct perf_event *bp)
> > @@ -678,7 +688,7 @@ static struct pmu perf_breakpoint = {
> >  int __init init_hw_breakpoint(void)
> >  {
> >         int cpu, err_cpu;
> > -       int i;
> > +       int i, ret;
> >
> >         for (i = 0; i < TYPE_MAX; i++)
> >                 nr_slots[i] = hw_breakpoint_slots(i);
> > @@ -689,18 +699,24 @@ int __init init_hw_breakpoint(void)
> >
> >                         info->tsk_pinned = kcalloc(nr_slots[i], sizeof(int),
> >                                                         GFP_KERNEL);
> > -                       if (!info->tsk_pinned)
> > -                               goto err_alloc;
> > +                       if (!info->tsk_pinned) {
> > +                               ret = -ENOMEM;
> > +                               goto err;
> > +                       }
> >                 }
> >         }
> >
> > +       ret = rhltable_init(&task_bps_ht, &task_bps_ht_params);
> > +       if (ret)
> > +               goto err;
> > +
> >         constraints_initialized = 1;
> >
> >         perf_pmu_register(&perf_breakpoint, "breakpoint", PERF_TYPE_BREAKPOINT);
> >
> >         return register_die_notifier(&hw_breakpoint_exceptions_nb);
>
> It seems there is a latent bug here:
> if register_die_notifier() fails we also need to execute the err: label code.

I think we should ignore it, because it's just a notifier when the
kernel dies. I'd rather have working breakpoints (which we have if we
made it to this point) when the kernel is live, and sacrifice some bad
behaviour when the kernel dies.

> Otherwise the patch looks good.
>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOT%3Dnpm9Bu9QGNO%3DSgCJVB2fr8ojO4-u-Ffgw4gmRuSfw%40mail.gmail.com.
