Return-Path: <kasan-dev+bncBCMIZB7QWENRBRP25OKQMGQEUWPUKTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AD9B55D0B7
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 15:08:22 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id g3-20020a2e9cc3000000b00253cc2b5ab5sf1639393ljj.19
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 06:08:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656421702; cv=pass;
        d=google.com; s=arc-20160816;
        b=pnDnwHdJXZG8LOTnDb9h6kUFKKk+F5/nZv2daY09UAK8KXQdUd7ry5fkyKoUdjmxxy
         KkQGir522MZVgek4HTImM+3Y4DxomJHUR7eqnSWmVZKI7nA1cZd90WW8nPfB1smAhs+Y
         550xmin4DkMqizwnhc4uaP5Um2RrhG2aORfaS6ZFJ2n55vsNcIxI3uq2rpu9HAdHC1Wm
         AcSoAlus4aTn8PvQwgFVhnWGHdnXmLyFSb75CvOCIFE8oOWu4cE1KafNsnIIkuNAitU7
         PlQJMJHR1cBxW0jvhsIJIp03v8AKsCfA4q8sm+BuqbnxJywXA3UI4hXvp/LZBY/JV6sg
         f+vQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=SbQrcJNY2HTSL6qzjDtkJNs6VTYFrZJtml8Bv/PPVZU=;
        b=jNbvSsy1gb6h5DW9hNme1qr0jGtgTX98r+nhCZnZmNAbCoZUbImKGEUjvN/845Xe+W
         JSioCz3DahYQxcRx80soCJ7UrAzY4y6GQXRiiL3sY6M/15AB3suHFEDzCZ/YfJnydDjT
         j+G3bl1bMO5mbTm4kQYZmQs3rjiUHS2EAApQZ77TOuqqnU8Pu08IMK/8Ar0rqAcsDIKY
         bF8Nx7qPZ0gJvvV0IF0QdhIh1pTEOUV52nLuU8shFHuVokqfjECjlRMb+cnHBMrHAYgF
         O3ABf2YWJsLbojlc0iqhD8E9RY+qIL20TW4sv5pI9d/yMTotMpClkwVcpRunZqnMgbjK
         M4ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Dyb0kRO5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SbQrcJNY2HTSL6qzjDtkJNs6VTYFrZJtml8Bv/PPVZU=;
        b=tZi7MMnvBeXYFWmoAmxdcOp+87rOdCAzLuFjPLmT8ux2WvU6eg3xk3x1rekQ+fghAo
         v0QY6sYXc20hJ12roUA8KLtzMjDr8WSr15b4iIyT9atma2OsGfwvGfbAlt1uc8aNU2mN
         kw7CquFS196Y4fj+Y66oeTlQZECFvQN83jtgNMqToLZO0yZadZoKVd4sWrkg56Nvw32K
         Y+DXhcm7kGFG883WTGiNsteYHqcq8kLTv4Php1saABHuQeVuBoynZsQb0mq8PCgKtWiQ
         HM1uY64Q1c/ZChIFIfJj0qDV638/QGPbDJzAHISgy7H2VyVimcYxSBtlbyFWp6cDRoj7
         YoqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SbQrcJNY2HTSL6qzjDtkJNs6VTYFrZJtml8Bv/PPVZU=;
        b=G5KjRjAYUWxeQ3+7tVSB24zC4LE5v/hw8oti2k65b4Fqy/+ijfnmoJjfgchIJax6o2
         5cFGBocgXMY5lVi3qAjcPMWIZi+nEy2w6PK9EMESL6I/vzlclOV9bXsAN3VsUfC2FSnh
         2gyyUD/MDgKK+X1Y0e+1DW+1pdRE4fcO2XGIOVJvqgToz6cz9juo533p9apOnXbMGa8f
         sLx8h9uWbKVldnSDxyATYxsFyImhYZsNiQKmgPIvNT+jtCkUju8L9xwx9de4ENA+IIE8
         OW0MRSEJuTA5FQjR1IZymNRh/MDBvIPc68jGs/F/bAdi5q9uqE9r1DpLXkD4SdIeJgh6
         s0dQ==
X-Gm-Message-State: AJIora9Xys45/Mi6nYtkWrNfHUmHGYLZIRSyGFMctEApAI+GUuHpMc1A
	PfuH04WqxXlFGmUPm+c6rus=
X-Google-Smtp-Source: AGRyM1v4iG3fcsT6T0T0HvIYy3fn/v4HrSM7lbNhr6HZQm0psfjXrxFCvxePgeQa6TMryXFEwfdxaQ==
X-Received: by 2002:a05:651c:a12:b0:25b:ce61:374e with SMTP id k18-20020a05651c0a1200b0025bce61374emr3152957ljq.165.1656421702164;
        Tue, 28 Jun 2022 06:08:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:81d1:0:b0:25b:c342:b0dd with SMTP id s17-20020a2e81d1000000b0025bc342b0ddls995410ljg.5.gmail;
 Tue, 28 Jun 2022 06:08:21 -0700 (PDT)
X-Received: by 2002:a05:651c:210f:b0:25a:8eec:1217 with SMTP id a15-20020a05651c210f00b0025a8eec1217mr9613735ljq.528.1656421700980;
        Tue, 28 Jun 2022 06:08:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656421700; cv=none;
        d=google.com; s=arc-20160816;
        b=AeJQYjRyxmloUPFc9NK5EfkyotLtgUlngZK8l/JGRRfxleiCZRUlBPNyUFJ68HLqSY
         Hwrnd+Rina1ai+OcDSRGp+muVJVX3rKht1k12vH4Zh6PPF3taHPh2IG+DyK353gL44uj
         kDVz7VTbyPaSQ8jXboB7eZSVex2DEsww8xwuM6vGUkExBZB4RJGLASnHQvVKwj6dUKTI
         iveJyf+Cu8TTS+sCyp+vzFkbBDVsgnacWZ0VROf2EdDyJynnIbIl4QZylnWTl+ulbvTL
         50rnREBcy95h5WYzjL91QRzqBHCQM9i5/UelLa1RDMD8+ueu+kfOVmIY/pTpFaw3IGqo
         tnjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aeUiRngewZvVOC/Ws+kiYpWX0PNqIg9bWynr1VvD7h0=;
        b=LS2LacJQDtPVH1JgJxUSIkujY+DjE8MIYhERvOzZsaSTniFAq/9hvoiyKvDL0d5/tj
         v6eLJpx1sIBDrePYaowxHJ+9ZNMM5+DUSLeNTi9IymsnHYIGA9oCqXwKwA6LoZsBt04v
         xONOV1XoWC65Qs5IyTMFdV76zKbPiLy47wZbTXcaECu+x0o4VoZfTGJtH2WP7JbtNsB7
         fmMkpEQfUOYsvbVpi1lKHhdlrfHaSt3+PHgJC52gf00ZHLvWAcviCpG3nLW9MRcjNpta
         7JEtmc5KIvxxa8zszvMSTmnjSvC06q2AapEtgBOATQiAJmpokIIO6QS2ia0tQMoxXvGr
         OFdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Dyb0kRO5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x232.google.com (mail-lj1-x232.google.com. [2a00:1450:4864:20::232])
        by gmr-mx.google.com with ESMTPS id p15-20020a2eb98f000000b0025a8d717b7dsi640419ljp.5.2022.06.28.06.08.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 06:08:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::232 as permitted sender) client-ip=2a00:1450:4864:20::232;
Received: by mail-lj1-x232.google.com with SMTP id bx13so6233581ljb.1
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 06:08:20 -0700 (PDT)
X-Received: by 2002:a2e:9f42:0:b0:25b:5649:1331 with SMTP id
 v2-20020a2e9f42000000b0025b56491331mr9293742ljk.268.1656421700299; Tue, 28
 Jun 2022 06:08:20 -0700 (PDT)
MIME-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com> <20220628095833.2579903-4-elver@google.com>
In-Reply-To: <20220628095833.2579903-4-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jun 2022 15:08:08 +0200
Message-ID: <CACT4Y+bh06ZF5s4Mfq+CJ8RJ+Fm41NeXt=C8Kkx11t9hgABpYQ@mail.gmail.com>
Subject: Re: [PATCH v2 03/13] perf/hw_breakpoint: Optimize list of per-task breakpoints
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Dyb0kRO5;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::232
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

 On Tue, 28 Jun 2022 at 11:59, Marco Elver <elver@google.com> wrote:
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
> While one option would be to make task_struct a breakpoint list node,
> this would only further bloat task_struct for infrequently used data.
> Furthermore, after all optimizations in this series, there's no evidence
> it would result in better performance: later optimizations make the time
> spent looking up entries in the hash table negligible (we'll reach the
> theoretical ideal performance i.e. no constraints).
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v2:
> * Commit message tweaks.
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
> index 1b013968b395..add1b9c59631 100644
> --- a/kernel/events/hw_breakpoint.c
> +++ b/kernel/events/hw_breakpoint.c
> @@ -26,10 +26,10 @@
>  #include <linux/irqflags.h>
>  #include <linux/kdebug.h>
>  #include <linux/kernel.h>
> -#include <linux/list.h>
>  #include <linux/mutex.h>
>  #include <linux/notifier.h>
>  #include <linux/percpu.h>
> +#include <linux/rhashtable.h>
>  #include <linux/sched.h>
>  #include <linux/slab.h>
>
> @@ -54,7 +54,13 @@ static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
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
> @@ -103,17 +109,23 @@ static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
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
> @@ -186,7 +198,7 @@ static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
>  /*
>   * Add/remove the given breakpoint in our constraint table
>   */
> -static void
> +static int
>  toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
>                int weight)
>  {
> @@ -199,7 +211,7 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
>         /* Pinned counter cpu profiling */
>         if (!bp->hw.target) {
>                 get_bp_info(bp->cpu, type)->cpu_pinned += weight;
> -               return;
> +               return 0;
>         }
>
>         /* Pinned counter task profiling */
> @@ -207,9 +219,9 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
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
> @@ -307,9 +319,7 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
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
> @@ -334,7 +344,7 @@ static void __release_bp_slot(struct perf_event *bp, u64 bp_type)
>
>         type = find_slot_idx(bp_type);
>         weight = hw_breakpoint_weight(bp);
> -       toggle_bp_slot(bp, false, type, weight);
> +       WARN_ON(toggle_bp_slot(bp, false, type, weight));
>  }
>
>  void release_bp_slot(struct perf_event *bp)
> @@ -678,7 +688,7 @@ static struct pmu perf_breakpoint = {
>  int __init init_hw_breakpoint(void)
>  {
>         int cpu, err_cpu;
> -       int i;
> +       int i, ret;
>
>         for (i = 0; i < TYPE_MAX; i++)
>                 nr_slots[i] = hw_breakpoint_slots(i);
> @@ -689,18 +699,24 @@ int __init init_hw_breakpoint(void)
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

It seems there is a latent bug here:
if register_die_notifier() fails we also need to execute the err: label code.

Otherwise the patch looks good.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> - err_alloc:
> +err:
>         for_each_possible_cpu(err_cpu) {
>                 for (i = 0; i < TYPE_MAX; i++)
>                         kfree(get_bp_info(err_cpu, i)->tsk_pinned);
> @@ -708,7 +724,5 @@ int __init init_hw_breakpoint(void)
>                         break;
>         }
>
> -       return -ENOMEM;
> +       return ret;
>  }
> -
> -
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bbh06ZF5s4Mfq%2BCJ8RJ%2BFm41NeXt%3DC8Kkx11t9hgABpYQ%40mail.gmail.com.
