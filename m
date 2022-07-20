Return-Path: <kasan-dev+bncBDPPFIEASMFBB5F64CLAMGQEOB2ILKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 231F757B997
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 17:29:57 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 130-20020a1c0288000000b003a32b902668sf145507wmc.9
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 08:29:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658330996; cv=pass;
        d=google.com; s=arc-20160816;
        b=SNGajpc2UtBXsf8AX5zxYeK66FnnYVU8AGpx3H2NXDZlQS5sNzCpBRisIQIuBS15Yg
         s0KvP7XdFUnNoI7nw6uulgjkhYxfQyEKIz5SXm1TYGbGZcRfBz6taijQL2ciyc4xllC2
         D+MhorTTDtFYlLniBt8r+s58Kr1RwA4tY1cuvf0hecGAeDaRMSTJ7AWYtwO4dgwY5TH2
         z58PKftgqkcfQTK5/jdEzRV9r5JPhIARjXtvMRXP4AJQSftdRmrVwiVWKRWNj/99g+jN
         Cl7jqUkxygMqZnFO8IhvWeeQq4JvHluUtvGJVVd2A06y9zAr7hdijqbS3Mgo3ugtHn6h
         DO+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nGMZd9N4wgmfxh8zVWebLDZZYmA+7sNcMWTNMk7UTiE=;
        b=AX8DifAKG0X/7Y6f6TSA74IXXNc03F5qOQNgNe4GAJ/m5pjLPAnGvx4qNpYviokfld
         3X2+YejBOJL3kNqMbAIUQ8UfKQI6vf6Mx8g/VP8x3RbvVGpl2zhZLUsFfrLL2E+bOuuf
         +qhTetxWuTqde9n7s8fPrJIS8s8zBrHUQeovmySOWKEKvJkT1XBXmCQGm1vyApu4Xe1T
         WMfcoZqW8AsSKUujGQcfcxovWSrT1MX8EaLodCduzlPK15KvnTci+4HYRJKHeBzwCFko
         cu0S7KX6hLRiyP6b3p7Vc/SMzHtD5JKmJnXJUO+zxlsn2sLx8GDKDDNQbFO8Tj4hqimn
         Rt2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LGHNIngB;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nGMZd9N4wgmfxh8zVWebLDZZYmA+7sNcMWTNMk7UTiE=;
        b=Dgxms4JNsF21FxgkkXFkcEnRzYc5qFNC83iHdi6LBrUxCyAf4yaZXVPnJwp6oFBEZJ
         1d7QO/HlZKSkCS4g5f9DN2pDua1Z7bQPnWNCN30xUbyknJMIMeU25wfaKaSgXe/F0wg2
         sV2tEnm7phYW9crtYv5nnAj4FWIBuy55bn1Ed5Br3JS5ZpjTaCYatzVUu+YHsUv03ovL
         PEz4yHNyyE7MvuQQhlqPcWDA/RHt/O9r/VlW1qXnvkMqWrGlYlZE1HWg1/PjiT/9qW0T
         0aU8GY5c1N1MjghKxAG9wGdwwzgj59FLErU8ZmRExLjrU/kI1qYcVfCrYnODGfSz363u
         lzMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nGMZd9N4wgmfxh8zVWebLDZZYmA+7sNcMWTNMk7UTiE=;
        b=Ou+SaaNWWt6J+wzNHET1ZYO+mJjfh8xEt0eCtjKqZg8VvZR5bxV8MDDL+mrlToHeCX
         kGAGdcGCeMm0Ak6CQFvR/V54iXVfLWuzrQZ8a9ayv7XMrbQpTRWE9Z+Iak92EsQIoBTF
         yrG7M06nyx3qmiVuH8dVyM1q/GJYrgnVi0zVAh0OTc1ClX+cTFYDohc8GiJ+hsyN1D5o
         MvcvoLgNPNOj2lCHb63lF67DG9oZgutEPazL93TeN6K71X6m99lq3uwbXphiAWapZt6p
         FxeFuSOpEtQ+R157eZEnJwJ405GU3mLN0zY7VjNZdnYS5ePEF5g7DXVXTt54cyI+0ST8
         1InA==
X-Gm-Message-State: AJIora/ySFpTAmAKpgY4dw6sWJDsEUVyX81Lw2vujch4SIUHh6omiERF
	AUuxorruJXohhey1UfRqU1I=
X-Google-Smtp-Source: AGRyM1ujafH/b/M1ml1xbKv4tcmF/SJfQbRywZId+8IHzxZaVOFt5zgImPX3/5kmIdAsIFX7duGreA==
X-Received: by 2002:a05:600c:3b1e:b0:3a3:1ca2:c5e0 with SMTP id m30-20020a05600c3b1e00b003a31ca2c5e0mr4373206wms.69.1658330996699;
        Wed, 20 Jul 2022 08:29:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3641:b0:3a3:10d7:a7a7 with SMTP id
 y1-20020a05600c364100b003a310d7a7a7ls560446wmq.0.-pod-control-gmail; Wed, 20
 Jul 2022 08:29:55 -0700 (PDT)
X-Received: by 2002:a1c:ed14:0:b0:3a2:b91b:dce4 with SMTP id l20-20020a1ced14000000b003a2b91bdce4mr4459197wmh.22.1658330995577;
        Wed, 20 Jul 2022 08:29:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658330995; cv=none;
        d=google.com; s=arc-20160816;
        b=NxoBmekmcYhkdzyQb1jWXy53cAfZW/u9puNku6f9dzJaecpqeI0y4OzjlbHlBmKohN
         6/3+M5LJlO2g+lmm7CJPOpjpL1Pfkiasl+zv//bo5ZO+5EcyQRM03d1y1rm+oEascXyH
         Qyplj9k+j22AxrtZ/YcDTzhSJ2PTVJ9fEhuWcxj05rM3PRb2YMdQ2tnfA+DyyL/7smSn
         wwUhQinyoUvQ3Q7KFu5nfkgPxoIjseAU9hqyllhTUAJ4bEonyUMggaVnzvqpabyYGCJ/
         MeylFsrpkT2NO8iP1HcdPtOacoNf8S8IXl4InpFdgJ6UmVScmsRsI1a6mijz3P23QGt2
         a7Lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pOAyhEyNgA3ymBFdHh+7wY08TjYcdJ+OpPeDKrqApfc=;
        b=CTU8VJVo+RoIxFrIo8uWR45lDVj1/r+1UMsZfZSSrf1GdpYpPiVkgOGOZEofAg3QZQ
         lrgXpt9iZxMl/zwUyEj2sP5nG5MOm2K1E65CEM2TpmXAc+MGx8HsGov7YNuWZ+oBx3/w
         QU3anDNJ+60Ur0QgHlQpZF+oQg02GWGsTygio3L8UlR+ljaOu87cckzuhzUHmFSWmkEw
         5RKXA6wIaF822OKrnm3L84SsDQhpZzcNurAN1jshopqk4fr0mQFCuyRLc4Tx47efDtFw
         o3t7Yp7GcWjoac1PMtGBnffDdefg6XL8lrwqEaF3oLSg1if1eRpPi8wo6aE4H7a1GHlV
         n78g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LGHNIngB;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id ck7-20020a5d5e87000000b0021e41c2afbdsi195202wrb.7.2022.07.20.08.29.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Jul 2022 08:29:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id 8-20020a05600c024800b003a2fe343db1so1496361wmj.1
        for <kasan-dev@googlegroups.com>; Wed, 20 Jul 2022 08:29:55 -0700 (PDT)
X-Received: by 2002:a7b:c8d3:0:b0:3a2:fe0d:ba2e with SMTP id
 f19-20020a7bc8d3000000b003a2fe0dba2emr4492494wml.115.1658330995019; Wed, 20
 Jul 2022 08:29:55 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-5-elver@google.com>
In-Reply-To: <20220704150514.48816-5-elver@google.com>
From: "'Ian Rogers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Jul 2022 08:29:43 -0700
Message-ID: <CAP-5=fXgi_RUOzSvPZvxNh6A14OY0S_oCHgAD0==nSLXzWqFFQ@mail.gmail.com>
Subject: Re: [PATCH v3 04/14] perf/hw_breakpoint: Optimize list of per-task breakpoints
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: irogers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=LGHNIngB;       spf=pass
 (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::336
 as permitted sender) smtp.mailfrom=irogers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Ian Rogers <irogers@google.com>
Reply-To: Ian Rogers <irogers@google.com>
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

On Mon, Jul 4, 2022 at 8:06 AM Marco Elver <elver@google.com> wrote:
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
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
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

nit: perhaps it would be more intention revealing here to rename this
to bp_hashtable?

Acked-by: Ian Rogers <irogers@google.com>

Thanks,
Ian

>                 };
>  #endif
>                 struct { /* amd_iommu */
> diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> index 6076c6346291..6d09edc80d19 100644
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
> @@ -707,7 +717,7 @@ static struct pmu perf_breakpoint = {
>  int __init init_hw_breakpoint(void)
>  {
>         int cpu, err_cpu;
> -       int i;
> +       int i, ret;
>
>         for (i = 0; i < TYPE_MAX; i++)
>                 nr_slots[i] = hw_breakpoint_slots(i);
> @@ -718,18 +728,24 @@ int __init init_hw_breakpoint(void)
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
> @@ -737,7 +753,5 @@ int __init init_hw_breakpoint(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAP-5%3DfXgi_RUOzSvPZvxNh6A14OY0S_oCHgAD0%3D%3DnSLXzWqFFQ%40mail.gmail.com.
