Return-Path: <kasan-dev+bncBCMIZB7QWENRBO4HRCKQMGQEYBFZRSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F183544EF5
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 16:29:16 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id t14-20020a056402020e00b0042bd6f4467csf17084780edv.9
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 07:29:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654784955; cv=pass;
        d=google.com; s=arc-20160816;
        b=rylnx6b/pSOjWfshTrijqgZL0HrrbqUvXziYxRf5bexYwCGFab/3htE6/YXsh3Jz20
         28LDSDD80YXCks7CgwPAvaPRDnxLGz4WZJH3Og6w/nqCZ9E1nrn4IvfDiD4gx+dOvKI8
         /9dWwe+8+WWFVl8t5U1SJvIqD7K1aLuqexIs9Be58te5LDeXo33ZmSYBDiTXV1lX1AnV
         vbBH3t7FEGK32+TJHqNpDK3N30rnsmBWdR8E7VuGXgWyub+qTFRRVzWk5YMwuGY/OT7o
         mhgYXc9stEiJo9SZDYNtuftC8B8CmxJ93AThfJZs7lLVYD9V791Jyt9E5T8qvXwH8DIZ
         LNRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4jSlJI/zdL+n8UJfSS5GLknUMO4pO0FeFhLHRhs1r7w=;
        b=FumSaQwCR4GLw2i8vjn9uAE0NK61dsCr/FVr+5HuYbES1xNI3rkAkOFdp+AvvEgXUl
         qbelunvdoI4lApBgRoy54UdVziDr49h6vkcGStLUwcNtbsPKE7HKd0Nd0M8rwVb9vsaY
         Ngcwo4TBRVrj+u8MRPuogeFxl/8I/qmG03V9NdyFNpfmdGvJ+cgLxzgm9RDtNEyA3Vfx
         GVAPKe9rZsZk2+JdiMZbRuPZCdkzmvKdorqlUV5J9uiDQr9BScGPXhh22rsyzeG7U0Ae
         a1eixC3kN5vW5UiHkel5zz0hZFbb6QoxeCSISDOtUzgDBL7lgVwyLakfrPCLLOP11r+M
         WCTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=X9500eDv;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4jSlJI/zdL+n8UJfSS5GLknUMO4pO0FeFhLHRhs1r7w=;
        b=lJtwWO5AjpYOD5lsASx44yygJtDr1laF9nw51WVnrbQOY3P4iVwyhg1RW+4vUpkVsY
         AkAdZ4NqiP8US/FS0XsUVpZGNEwF9gGm2L+DUWtJ5FPjn9ZWGDjfPzL+HXaSULRMGjeh
         5q3qRdcvblfrWWyxXTxWZJeAECr4E5SIgifHFGbx2bnqclj7y5yarGp1YXIISkFdeRNi
         5Eg/LgvZRdOfWy9KLT7YvAul0FR1kk6JbNbKg8RJOQSRzSYK61eBdHwMuUXuDzVusn1X
         CdR+jatSjSABvoNq2F0o5ySczzQrKNJtALCJXbjFQXXIclSwk5HeMv8m2oZM/eYh1hYZ
         9UvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4jSlJI/zdL+n8UJfSS5GLknUMO4pO0FeFhLHRhs1r7w=;
        b=WyNu0098aEe4B9vNDYZrAULU6566TxR9QCGSE096o458aRld/H4cHyd0XJlVPUT91V
         QJzwuW67q77CnozM3PDn+9nz+vDHK4Rc0rms/oaKo4UmGjsuAVBParylkxF5RUj0jiBr
         yYaf9fww3lAce0fdUX2PkeDQgCWeidx8QA7rCIrZJhICQKuEQQzQdmfwgYTc3vF0vTTv
         P48vbf0UqimV1mysbl4WT8ljtxdaX+0Z3g9kivLq7ZU1gwX+BxW6qWnVSGTXMFE07IaE
         H0ywj6itrypuyduV5UMwJCiIJTtoV0IYpS3gYom5HA36eUMMFCgSmue3HnD96535/ROI
         pMJQ==
X-Gm-Message-State: AOAM531XibMBY69lBQTDpA5xyplJRaQMlayBc2GUKpVUyFV+TcgSRgkI
	9Jgik0dX4vudYjqjxkihO/4=
X-Google-Smtp-Source: ABdhPJz/qdyA4fv6y9wsN5OS632yjUO/6JwAaPjn3SxenhF4kQ9Len1fL5IVVvH8BG5lgSYOfbBglg==
X-Received: by 2002:a17:906:4784:b0:6ff:34ea:d824 with SMTP id cw4-20020a170906478400b006ff34ead824mr37446198ejc.526.1654784955680;
        Thu, 09 Jun 2022 07:29:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:424b:b0:433:426d:7e15 with SMTP id
 g11-20020a056402424b00b00433426d7e15ls1989878edb.0.gmail; Thu, 09 Jun 2022
 07:29:14 -0700 (PDT)
X-Received: by 2002:a05:6402:350e:b0:42f:b2c1:9393 with SMTP id b14-20020a056402350e00b0042fb2c19393mr35222825edd.11.1654784954353;
        Thu, 09 Jun 2022 07:29:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654784954; cv=none;
        d=google.com; s=arc-20160816;
        b=MDMIEiaa0lYguq8n9Wuyci4i/r3aqowW5GUGBAMhigKmNAl2wDm1ruWx9gx/F+ybKU
         vKWtHv8wpJm/fpBgxpvVjc6KGmLXav8ig98NfJm2TzLXoQufJRszsexFaLhQK+NJPq9Q
         +9c44WnXSo6KikDJz/9ibBFF/YF+WAuOOXUpmxucQv6en24s8hkSlYXmG8Hi8Oov+kpG
         QZ7+qtU+4CE34TJHT5o8PBmSTDu3eTQnFoZCIE6waCLq3P5xCMufB+Esb+YnX71df6SN
         Yj7eCprKF1dim+Ojy6vnveuKBCAk3bBS5IbkvfEBTkmsZTx9MOa43BTv2motkmeSvlec
         1Qwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=M9W9dRebSTBOmk3r6h+50xRRy5x7WHWQ6L9317Ru0kA=;
        b=h6WarnyL383ufAHFtTeia9FyOM0T7PvwuU4OMj+/0q+9xtFxTsuDn4cEAyZaPtB/Xt
         GDIkZbITPQb9ZFAzL2AGvIqJdIK7MzhY9VRSfZyYt/1bc/UF1OnugsAVusPNg16KpYzE
         6d5uLJE4RBsSnX07Chm6v7KO+6niX296jEU9EYOAzxskPtIBRlsOCya5bTSC6W/5M0KR
         wWcPk/kLXB38Vjh6mc2iPoZtir3aAvHGTmraPLspS+5lzWxRq3GY19VCBaXmnEji/Wf7
         SqxdSZmZEk0dC8ihwwhj8j12VpSPv8x7f1909JLiXOQ0W3fNZiPxKjuOsPiXWlI2SOh4
         YSEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=X9500eDv;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id b16-20020a0564021f1000b0042ddac8f86asi989654edb.2.2022.06.09.07.29.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 07:29:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id i29so21525331lfp.3
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 07:29:14 -0700 (PDT)
X-Received: by 2002:a05:6512:1085:b0:479:478b:d2cc with SMTP id
 j5-20020a056512108500b00479478bd2ccmr13054137lfg.540.1654784953738; Thu, 09
 Jun 2022 07:29:13 -0700 (PDT)
MIME-Version: 1.0
References: <20220609113046.780504-1-elver@google.com> <20220609113046.780504-2-elver@google.com>
In-Reply-To: <20220609113046.780504-2-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jun 2022 16:29:02 +0200
Message-ID: <CACT4Y+bOFmCyqfSgWS0b5xuwnPqP4V9v2ooJRmFCn0YAtOPmhQ@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=X9500eDv;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::133
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

task_struct already has:

#ifdef CONFIG_PERF_EVENTS
  struct perf_event_context *perf_event_ctxp[perf_nr_task_contexts];
  struct mutex perf_event_mutex;
  struct list_head perf_event_list;
#endif

Wonder if it's possible to use perf_event_mutex instead of the task_sharded_mtx?
And possibly perf_event_list instead of task_bps_ht? It will contain
other perf_event types, so we will need to test type as well, but on
the positive side, we don't need any management of the separate
container.




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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbOFmCyqfSgWS0b5xuwnPqP4V9v2ooJRmFCn0YAtOPmhQ%40mail.gmail.com.
