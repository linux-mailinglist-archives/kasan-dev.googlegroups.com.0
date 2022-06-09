Return-Path: <kasan-dev+bncBCMIZB7QWENRBY6PQ6KQMGQER5IRAZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id C1951544C01
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 14:30:28 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id k5-20020a2e6f05000000b002555a5d11e4sf4481219ljc.18
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 05:30:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654777828; cv=pass;
        d=google.com; s=arc-20160816;
        b=NbmH7is93jXEB5Orq7Hm1LuOox+W3yaR4s7w/q7lMberX+xWvUOGhsfdJ952kLOE6u
         oSNvguBUB+/cQAgDZXqa1RuPhG6GGEi+qAloC0KVdfOjqXMBWEj9U5oKp0F12J/U92mZ
         E1MRZRSy+jVXJHYsWa6trTNOD+AIZ/JgxQ1Pbgy73ZIRUKeenzuXvp6K4XFS/mKn37oE
         Ujhe+Ahae4LN6RHWZZvb3nTS0wEbhrfkzqTrsY1MtGfg+V4cf/g2Dws26x01doXtljcX
         hz8NJXLBiyk91pmgIn0snx4JtAGnWgb+B0zw0zWtz68b4V4iv8ZNNGLRLbvwAxRAR2jv
         rrwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nUo2DtVSRqZXjMlP7404IfTwFWWruK2F9Pl+Fe00KY8=;
        b=KZrglVabY/LVfbGqG5cFqSheZRiFfq7UbSih1iepVoUTrQaavcwylTkfomH+5u8F/I
         DEtgTkvkKve42VUi+ZnViQu+PlnUjDdIDV7tUu5wnfxKUV8wpoHfwe6dF3GVeGvoVvTA
         ycwH72od5dHjTaE8v/wmStZhlaA9AYNTqgEojJ8DUbIFJJqthHUNPc5+MrA7wPGC5V/E
         p26krp13/nR5lHm78uOhLd0Y7vpBJd0tpxwyVFLVBbFAsaUfsMhcqYHQVcsfsoraaglt
         0Pc1Zloq5HB8OkEhOhrEJc1td0Xb4aycZYp3YsNx594KQs6KrKAvxHAoK+/nbvjSWZQT
         rYLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=B6BHal5y;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nUo2DtVSRqZXjMlP7404IfTwFWWruK2F9Pl+Fe00KY8=;
        b=rV+g2FZ5w+GS7XiZeTu/Hq/H9VW0FDPSYYPjheXx/sklGTRc7MrxnWM4nzcaPNxQWD
         z12a6Rs3Pl+m+ZQ8CXUJiDYJNjI7l1/p7C/ChWEtEUQmXhXenNCRMm5bDBySNmPKyrpo
         HhLZsttj+VrwQDkFptaX1ys3NK2U4li9Mgv2z9jBCnSMKR0fXZAc5a/UygT0biP44l6i
         kWOJh10wdYUNJcbFGZPdSNyWQWuBhJQzXNJxIUdj0mUAlEhFCpRwUAGo6chEvtwycYzW
         ftc/59FyuksICEVVZGXDrDi/3txIXoc7rMCnZ5ROrxnF5ykv9N34JqLN/SrBk3pgzpzL
         8QOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nUo2DtVSRqZXjMlP7404IfTwFWWruK2F9Pl+Fe00KY8=;
        b=nvH8Rjc1WPSSlZYU6jk/fyfHVBHoeyY3IwK++NJb8ZxZxqId53LSuhXO+jafE9XGPg
         18V6W2ke0TQcks1Mo5ayvcUp1L10h0VeYdYrppB/EI6I4JWCeGs7QpE0UpQ/PXc13xyq
         Zt3kGLKzRKipzsApfoT6diCXccfVhBlZlIbZeE6mqoSvLU93Ueb5HEccucV/TNRj9j1R
         0e3lEU2KJPjBoPWuAxzKIHPrq0XhhKNUU0hOPf/ZbIMXnC9lwYSS89C/mjKj72+aUzPy
         Qd3UKmojhmQYKrnwvUynicRw/30EHQR88zsYsCxQCmJEVDeFKORt11Nu+o+70R4eWxp8
         c4yw==
X-Gm-Message-State: AOAM5303d2RueM4Ab4w+YdP3ihZtIH+Zk6invxquDIUuufi42pWK5bUG
	w1xLvm7KXu6cYVzFv/43jL8=
X-Google-Smtp-Source: ABdhPJyCg0ulePd+u5l8HStnyfxUgFzdecxuAKMubiJkXDt7QddA0cYAOV5XNd+qqVPii5qeApz7zQ==
X-Received: by 2002:a19:5e49:0:b0:47a:28a4:9667 with SMTP id z9-20020a195e49000000b0047a28a49667mr3912947lfi.65.1654777828082;
        Thu, 09 Jun 2022 05:30:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als93653lfa.2.gmail; Thu, 09 Jun 2022
 05:30:27 -0700 (PDT)
X-Received: by 2002:a05:6512:1398:b0:448:bda0:99f2 with SMTP id p24-20020a056512139800b00448bda099f2mr71206889lfa.681.1654777826898;
        Thu, 09 Jun 2022 05:30:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654777826; cv=none;
        d=google.com; s=arc-20160816;
        b=VG77AgcnUKPfxrTEDNhsklFGKBxW0XVZ5xyhW9W9ev3kg8vXDq+0NggKhx67pOkIK6
         3B6J6E19mTjKBa2je0Muuz5rJCOIcw18WN1eCrndvxJjdG2EMM1h+hXha+31AMEZwd+/
         SX1pS7tSY6m2x4hFcV0heVi5Go1PcWzAxn/zEPQroOs3SQ57OvRW9QBrfHhx+mqHp+Ez
         k6hYtYGMluQEguy1J4pPC1RoN4vjRliPnqMPHUU9pnw1PS79jsORBbkENq4R5ZJbQsNX
         cCiADMiwpda47x3e29eXWZdu5T+XbtmSFoOnlWYbm13xrRXWjtYIbEF7RXCUn3A2q8i1
         CSMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SqP5eMJEaejE2EE5ptLXYYiISpaJ8khY1mUkqMBz8rQ=;
        b=QeuheA0SS0NacauAJiYqP18gZPsRhLT5bAO3dMnLNUGqv7aazlBi3U1bLv9/ahxSOF
         0bcVS+MDCZ8UKGXNgsfkO6mQvjqd3WaBTnIQf8WZ+xlVxW191S93tfIYc5Nt1JKWn2g1
         HdrP/6vkVxP5CYrn4wh4rufwhaxOglosr/RUaM1HXJrBcfA6WZuB57+IfetAyYTI6LC1
         2mm3cdV5qlDBH/4yLY9Sh78gXTLcXsyWS+ltrgE9xlLCBILUU3usnR42JUCp/DL4JFEi
         Sq4/0cSC6YRc1EB/zqnzHOd1vJ2gNGTwMITfR/Pdh1NBPubiAZnu8eHwgl1qJMktDvi+
         PoDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=B6BHal5y;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12d.google.com (mail-lf1-x12d.google.com. [2a00:1450:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id k16-20020a0565123d9000b00478a62b07b8si450076lfv.5.2022.06.09.05.30.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 05:30:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12d as permitted sender) client-ip=2a00:1450:4864:20::12d;
Received: by mail-lf1-x12d.google.com with SMTP id c2so18315899lfk.0
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 05:30:26 -0700 (PDT)
X-Received: by 2002:a05:6512:3f13:b0:464:f55f:7806 with SMTP id
 y19-20020a0565123f1300b00464f55f7806mr25273629lfa.598.1654777826331; Thu, 09
 Jun 2022 05:30:26 -0700 (PDT)
MIME-Version: 1.0
References: <20220609113046.780504-1-elver@google.com> <20220609113046.780504-2-elver@google.com>
In-Reply-To: <20220609113046.780504-2-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jun 2022 14:30:14 +0200
Message-ID: <CACT4Y+ZfjLCj=wvPFhyUQLwxmcOXuK9G_a53SB=-niySExQdew@mail.gmail.com>
Subject: Re: [PATCH 1/8] perf/hw_breakpoint: Optimize list of per-task breakpoints
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, x86@kernel.org, 
	linux-sh@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=B6BHal5y;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12d
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

On Thu, 9 Jun 2022 at 13:31, Marco Elver <elver@google.com> wrote:
>
> On a machine with 256 CPUs, running the recently added perf breakpoint
> benchmark results in:
>
>  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
>  | # Running 'breakpoint/thread' benchmark:
>  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
>  |      Total time: 236.418 [sec]
>  |
>  |   123134.794271 usecs/op
>  |  7880626.833333 usecs/op/cpu
>
> The benchmark tests inherited breakpoint perf events across many
> threads.
>
> Looking at a perf profile, we can see that the majority of the time is
> spent in various hw_breakpoint.c functions, which execute within the
> 'nr_bp_mutex' critical sections which then results in contention on that
> mutex as well:
>
>     37.27%  [kernel]       [k] osq_lock
>     34.92%  [kernel]       [k] mutex_spin_on_owner
>     12.15%  [kernel]       [k] toggle_bp_slot
>     11.90%  [kernel]       [k] __reserve_bp_slot
>
> The culprit here is task_bp_pinned(), which has a runtime complexity of
> O(#tasks) due to storing all task breakpoints in the same list and
> iterating through that list looking for a matching task. Clearly, this
> does not scale to thousands of tasks.
>
> While one option would be to make task_struct a breakpoint list node,
> this would only further bloat task_struct for infrequently used data.
>
> Instead, make use of the "rhashtable" variant "rhltable" which stores
> multiple items with the same key in a list. This results in average
> runtime complexity of O(1) for task_bp_pinned().
>
> With the optimization, the benchmark shows:
>
>  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
>  | # Running 'breakpoint/thread' benchmark:
>  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
>  |      Total time: 0.208 [sec]
>  |
>  |      108.422396 usecs/op
>  |     6939.033333 usecs/op/cpu
>
> On this particular setup that's a speedup of ~1135x.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/linux/perf_event.h    |  3 +-
>  kernel/events/hw_breakpoint.c | 56 ++++++++++++++++++++++-------------
>  2 files changed, 37 insertions(+), 22 deletions(-)
>
> diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
> index 01231f1d976c..e27360436dc6 100644
> --- a/include/linux/perf_event.h
> +++ b/include/linux/perf_event.h
> @@ -36,6 +36,7 @@ struct perf_guest_info_callbacks {
>  };
>
>  #ifdef CONFIG_HAVE_HW_BREAKPOINT
> +#include <linux/rhashtable-types.h>
>  #include <asm/hw_breakpoint.h>
>  #endif
>
> @@ -178,7 +179,7 @@ struct hw_perf_event {
>                          * creation and event initalization.
>                          */
>                         struct arch_hw_breakpoint       info;
> -                       struct list_head                bp_list;
> +                       struct rhlist_head              bp_list;
>                 };
>  #endif
>                 struct { /* amd_iommu */
> diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> index f32320ac02fd..25c94c6e918d 100644
> --- a/kernel/events/hw_breakpoint.c
> +++ b/kernel/events/hw_breakpoint.c
> @@ -28,7 +28,7 @@
>  #include <linux/sched.h>
>  #include <linux/init.h>
>  #include <linux/slab.h>
> -#include <linux/list.h>
> +#include <linux/rhashtable.h>
>  #include <linux/cpu.h>
>  #include <linux/smp.h>
>  #include <linux/bug.h>
> @@ -55,7 +55,13 @@ static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
>  }
>
>  /* Keep track of the breakpoints attached to tasks */
> -static LIST_HEAD(bp_task_head);
> +static struct rhltable task_bps_ht;
> +static const struct rhashtable_params task_bps_ht_params = {
> +       .head_offset = offsetof(struct hw_perf_event, bp_list),
> +       .key_offset = offsetof(struct hw_perf_event, target),
> +       .key_len = sizeof_field(struct hw_perf_event, target),
> +       .automatic_shrinking = true,
> +};
>
>  static int constraints_initialized;
>
> @@ -104,17 +110,23 @@ static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
>   */
>  static int task_bp_pinned(int cpu, struct perf_event *bp, enum bp_type_idx type)
>  {
> -       struct task_struct *tsk = bp->hw.target;
> +       struct rhlist_head *head, *pos;
>         struct perf_event *iter;
>         int count = 0;
>
> -       list_for_each_entry(iter, &bp_task_head, hw.bp_list) {
> -               if (iter->hw.target == tsk &&
> -                   find_slot_idx(iter->attr.bp_type) == type &&
> +       rcu_read_lock();

Why do we need rcu_read_lock() here?
The patch does not change anything with respect to locking, so all
accesses to the container should still be protected by nr_bp_mutex.
Similarly for the rcu variant of for_each below.

Otherwise the change looks good to me.



> +       head = rhltable_lookup(&task_bps_ht, &bp->hw.target, task_bps_ht_params);
> +       if (!head)
> +               goto out;
> +
> +       rhl_for_each_entry_rcu(iter, pos, head, hw.bp_list) {
> +               if (find_slot_idx(iter->attr.bp_type) == type &&
>                     (iter->cpu < 0 || cpu == iter->cpu))
>                         count += hw_breakpoint_weight(iter);
>         }
>
> +out:
> +       rcu_read_unlock();
>         return count;
>  }
>
> @@ -187,7 +199,7 @@ static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
>  /*
>   * Add/remove the given breakpoint in our constraint table
>   */
> -static void
> +static int
>  toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
>                int weight)
>  {
> @@ -200,7 +212,7 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
>         /* Pinned counter cpu profiling */
>         if (!bp->hw.target) {
>                 get_bp_info(bp->cpu, type)->cpu_pinned += weight;
> -               return;
> +               return 0;
>         }
>
>         /* Pinned counter task profiling */
> @@ -208,9 +220,9 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
>                 toggle_bp_task_slot(bp, cpu, type, weight);
>
>         if (enable)
> -               list_add_tail(&bp->hw.bp_list, &bp_task_head);
> +               return rhltable_insert(&task_bps_ht, &bp->hw.bp_list, task_bps_ht_params);
>         else
> -               list_del(&bp->hw.bp_list);
> +               return rhltable_remove(&task_bps_ht, &bp->hw.bp_list, task_bps_ht_params);
>  }
>
>  __weak int arch_reserve_bp_slot(struct perf_event *bp)
> @@ -308,9 +320,7 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
>         if (ret)
>                 return ret;
>
> -       toggle_bp_slot(bp, true, type, weight);
> -
> -       return 0;
> +       return toggle_bp_slot(bp, true, type, weight);
>  }
>
>  int reserve_bp_slot(struct perf_event *bp)
> @@ -335,7 +345,7 @@ static void __release_bp_slot(struct perf_event *bp, u64 bp_type)
>
>         type = find_slot_idx(bp_type);
>         weight = hw_breakpoint_weight(bp);
> -       toggle_bp_slot(bp, false, type, weight);
> +       WARN_ON(toggle_bp_slot(bp, false, type, weight));
>  }
>
>  void release_bp_slot(struct perf_event *bp)
> @@ -679,7 +689,7 @@ static struct pmu perf_breakpoint = {
>  int __init init_hw_breakpoint(void)
>  {
>         int cpu, err_cpu;
> -       int i;
> +       int i, ret;
>
>         for (i = 0; i < TYPE_MAX; i++)
>                 nr_slots[i] = hw_breakpoint_slots(i);
> @@ -690,18 +700,24 @@ int __init init_hw_breakpoint(void)
>
>                         info->tsk_pinned = kcalloc(nr_slots[i], sizeof(int),
>                                                         GFP_KERNEL);
> -                       if (!info->tsk_pinned)
> -                               goto err_alloc;
> +                       if (!info->tsk_pinned) {
> +                               ret = -ENOMEM;
> +                               goto err;
> +                       }
>                 }
>         }
>
> +       ret = rhltable_init(&task_bps_ht, &task_bps_ht_params);
> +       if (ret)
> +               goto err;
> +
>         constraints_initialized = 1;
>
>         perf_pmu_register(&perf_breakpoint, "breakpoint", PERF_TYPE_BREAKPOINT);
>
>         return register_die_notifier(&hw_breakpoint_exceptions_nb);
>
> - err_alloc:
> +err:
>         for_each_possible_cpu(err_cpu) {
>                 for (i = 0; i < TYPE_MAX; i++)
>                         kfree(get_bp_info(err_cpu, i)->tsk_pinned);
> @@ -709,7 +725,5 @@ int __init init_hw_breakpoint(void)
>                         break;
>         }
>
> -       return -ENOMEM;
> +       return ret;
>  }
> -
> -
> --
> 2.36.1.255.ge46751e96f-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZfjLCj%3DwvPFhyUQLwxmcOXuK9G_a53SB%3D-niySExQdew%40mail.gmail.com.
