Return-Path: <kasan-dev+bncBCMIZB7QWENRBJWE5SKQMGQEOZUX72I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id C07E055E5C6
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 17:45:42 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id s1-20020a5d69c1000000b0021b9f3abfebsf1899410wrw.2
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 08:45:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656431142; cv=pass;
        d=google.com; s=arc-20160816;
        b=JatReifnsBFgz3p+T/Vtg3XMCp1kxc+xqSridJQK2YYz3uduqOuKnfqN3DkymzZNba
         V7/YZNdzI55OP3kwkGvXt36AMazQZVvhrS1nngiCV2LxGvjn+Z+OnTrde6J7CYZWNGMw
         DUNWxdVlYdB/b70iWudKM5dfh4C7PU/VraWDFKc6X9RDgdx03cZWCtJAFJ6aEhOyOGIV
         R1rJM3BMJduDcD2UBztOdihofqeWLyZNkhHQwhkANGgZ1GBxVcg+mPfxZA7IH46n/+6s
         AWsP+lyHLQduYYxvHP0CAccp1YnTjw4oqOmmXGR9e7lFE2wuuCg+lYYC/mqOFpq4rQed
         IcBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3CTLIYA2AHVZ2Sjs3x8bKqN96aSNlXUblkSnkcQRq5I=;
        b=c1lARR0L+0YzgUJsxezSfcz4M9nyDGm1aC1rBpLY9XOCRW5uvGi0VksHq3Z7VA4n3v
         wNisPljkUGZsRTVbFkIZGvJQlUJLMErzUhiF6izTDA6lC4YZ83PwzgngjmXsvEzJ7NXg
         jkOivc7/4T8evlhgeKQZ0lrPHTFAQG/PNnEl+4NVoz9inzLU3P3TSd3aJnvcfzwGeln8
         AzqOsb18DJrvRia8pJJY3vecGxX1ls78W0VPhTuizN9dqLBKZe5xWDLqgy1iCgX3z46E
         O2Simhlkf+Wye5VXbZjSDdEOp6m5VT4KdlABn3zZR3ToWkzfaq3PjLpR2Fe13zDHdm4b
         06fA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IK9851jT;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3CTLIYA2AHVZ2Sjs3x8bKqN96aSNlXUblkSnkcQRq5I=;
        b=Zcmln5NbNbJh+HpSsxBLQHdDpEUZ+1uxuNBk37V1dWU2DM9iXyl4FuqQRSDJGjvYWX
         LH3/ouesRM1ICAnpb7vqM4Tikpzj+tbI9rXIXlf3m4vqkAAqtC0d2mkdFS8zxPpwwL4c
         f4S/aJGOCa/pknZ/MS4LCLpljPDkwligBPsf7nQcXafO0eRhDyzOBYcOqawvQuU/t5GZ
         /hO9QfMvJhW2IwPmoD+L3x+FkRIunYExqRo8sRO7VJC6rKeJ8RJpfHs1SAhMyffq2Gzq
         ZzH5XBYo+HlRiMcoFuqGvoI/7+ftgNpU4hkiGB0o8vJxdT1jJr0gHiq5B06HaaagP2zL
         BNKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3CTLIYA2AHVZ2Sjs3x8bKqN96aSNlXUblkSnkcQRq5I=;
        b=fqGgV/ofhew7p1z/SHWewsTBJ6jj1I6+iCM95AmbBeXrIHObqP0G/J7kQiMySDaRQ9
         pPVU5H+5AjRxvB8udxgxCuk83I4vDjXpTJwvK5hRjbPSQs4gOqL9m+i5yrEX4gxoIkJu
         IJDdAlq49100R9uOf+2ZSsIa89Xt+j2c5MuCQpwicWlKkYDZ0T0RPkp+axWFpUWRb8iM
         UMd8edCm85lt2O9HxGEjWmLN6GKsZAp54ZMmQMI/444coAJsCO1N2204s7fNYbdRJFB+
         0RvFBQHMnzYoYC5EBgLSnuorehCAzxeepJxzf8eYfQdV1G1o0udXTVsRYHStO6zqctkt
         vflA==
X-Gm-Message-State: AJIora+bqDnIHFFwjmXeIHtqCLPnFz1QWau8juE/AqDQfe7I0TMM6UwQ
	HS+qnuJpsYHVIcrksliPXr0=
X-Google-Smtp-Source: AGRyM1tAOhPZLR3EdIa3lNV6tqa1mIcDev3MLGXxAnnvEg1CmgDLvuLppfAvNqsdi670q3ZedTFz4Q==
X-Received: by 2002:a05:6000:1a8d:b0:21b:bc45:9c3e with SMTP id f13-20020a0560001a8d00b0021bbc459c3emr18280211wry.390.1656431142498;
        Tue, 28 Jun 2022 08:45:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b17:b0:3a0:2da0:3609 with SMTP id
 m23-20020a05600c3b1700b003a02da03609ls84791wms.1.gmail; Tue, 28 Jun 2022
 08:45:41 -0700 (PDT)
X-Received: by 2002:a1c:cc1a:0:b0:3a0:39b1:3408 with SMTP id h26-20020a1ccc1a000000b003a039b13408mr237568wmb.157.1656431141392;
        Tue, 28 Jun 2022 08:45:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656431141; cv=none;
        d=google.com; s=arc-20160816;
        b=LmUDLppl90g6Wa0YrRTxJaSBGsUCqxQCKdgTBF+VNEy6fPtOVZPN2O6Ubbsxg5NBP1
         k/t04V2RU8+blDOBtDcTtn2wdXXrKDdonoIww7+FGdGO3mgCpKfIWAQQnDoXWwNkh53Z
         rfkCC1ZHP/Q5kBgUmU8sRvQe0vsFeGngzp7+sdGvbfzfraWrBc+KQj5l+KJi8wOKMdd3
         V/oa2Luehs/032mg9cdId7o3hlM5+P+icwqHF5b8oXZaoPbeVocSZm1YbjjV2vCIpocv
         pfJj1PBUyrn3cjrl8eJkSQhDI5NIyMc8V2L06KUmAtk5Fp8+leC/sX1VwH4iAuGTnNNa
         9Duw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4W7G4HHn4e0MzSigkgQjmcxAYL0f3Ih5AyaRGznr2IM=;
        b=IW639uLsG9gHoRx6tzp1OfbFR0f9Ddhlt/1adwj9fmsaQ0tSvDVzwRNbHhOi3dz0yw
         luVHnOhIUXJxfejloOc0TVTeBhKC9DyOOGIPk0+jTnD3R6OxgYGIBuEOSLgO53rQ3eP6
         blwobhrqRAFbPv/7Wq/R2tha5KjMfaVMz01EEAi8GpJLBaJbPXIxQwFFd2BO6NG5CCsm
         68xViMbP2IoPmXHXSCbZEw8VPMUSRhwl+voSMntqXAOqlBEg3WffM7Xxq7IvUI6RJAPV
         Oibm8fNPH8YkEqC8FJ3CPSkoHjgpJdUblftVnhPwEP01e65RmnnsQbIiz/GtnYcANHZc
         4iSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IK9851jT;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id w15-20020adff9cf000000b0021b95bcfb2asi548611wrr.0.2022.06.28.08.45.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 08:45:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id a13so23010321lfr.10
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 08:45:41 -0700 (PDT)
X-Received: by 2002:a05:6512:39ce:b0:481:31e4:1e06 with SMTP id
 k14-20020a05651239ce00b0048131e41e06mr2237865lfu.376.1656431140732; Tue, 28
 Jun 2022 08:45:40 -0700 (PDT)
MIME-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com> <20220628095833.2579903-14-elver@google.com>
In-Reply-To: <20220628095833.2579903-14-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jun 2022 17:45:29 +0200
Message-ID: <CACT4Y+aJZzkYHc+YJRApOLG-NYe8zXMaqxpQgQQFAy5WY97Ttg@mail.gmail.com>
Subject: Re: [PATCH v2 13/13] perf/hw_breakpoint: Optimize toggle_bp_slot()
 for CPU-independent task targets
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
 header.i=@google.com header.s=20210112 header.b=IK9851jT;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134
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
> We can still see that a majority of the time is spent hashing task pointers:
>
>     ...
>     16.98%  [kernel]       [k] rhashtable_jhash2
>     ...
>
> Doing the bookkeeping in toggle_bp_slots() is currently O(#cpus),
> calling task_bp_pinned() for each CPU, even if task_bp_pinned() is
> CPU-independent. The reason for this is to update the per-CPU
> 'tsk_pinned' histogram.
>
> To optimize the CPU-independent case to O(1), keep a separate
> CPU-independent 'tsk_pinned_all' histogram.
>
> The major source of complexity are transitions between "all
> CPU-independent task breakpoints" and "mixed CPU-independent and
> CPU-dependent task breakpoints". The code comments list all cases that
> require handling.
>
> After this optimization:
>
>  | $> perf bench -r 100 breakpoint thread -b 4 -p 128 -t 512
>  |      Total time: 1.758 [sec]
>  |
>  |       34.336621 usecs/op
>  |     4395.087500 usecs/op/cpu
>
>     38.08%  [kernel]       [k] queued_spin_lock_slowpath
>     10.81%  [kernel]       [k] smp_cfm_core_cond
>      3.01%  [kernel]       [k] update_sg_lb_stats
>      2.58%  [kernel]       [k] osq_lock
>      2.57%  [kernel]       [k] llist_reverse_order
>      1.45%  [kernel]       [k] find_next_bit
>      1.21%  [kernel]       [k] flush_tlb_func_common
>      1.01%  [kernel]       [k] arch_install_hw_breakpoint
>
> Showing that the time spent hashing keys has become insignificant.
>
> With the given benchmark parameters, that's an improvement of 12%
> compared with the old O(#cpus) version.
>
> And finally, using the less aggressive parameters from the preceding
> changes, we now observe:
>
>  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
>  |      Total time: 0.067 [sec]
>  |
>  |       35.292187 usecs/op
>  |     2258.700000 usecs/op/cpu
>
> Which is an improvement of 12% compared to without the histogram
> optimizations (baseline is 40 usecs/op). This is now on par with the
> theoretical ideal (constraints disabled), and only 12% slower than no
> breakpoints at all.
>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

I don't see any bugs. But the code is quite complex. Does it make
sense to add some asserts to the histogram type? E.g. counters don't
underflow, weight is not negative (e.g. accidentally added -1 returned
from task_bp_pinned()). Not sure if it will be enough to catch all
types of bugs, though.
Could kunit tests check that histograms are all 0's at the end?

I am not just about the current code (which may be correct), but also
future modifications to this code.


> ---
> v2:
> * New patch.
> ---
>  kernel/events/hw_breakpoint.c | 152 +++++++++++++++++++++++++++-------
>  1 file changed, 121 insertions(+), 31 deletions(-)
>
> diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> index b5180a2ccfbf..31b24e42f2b5 100644
> --- a/kernel/events/hw_breakpoint.c
> +++ b/kernel/events/hw_breakpoint.c
> @@ -66,6 +66,8 @@ static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
>
>  /* Number of pinned CPU breakpoints globally. */
>  static struct bp_slots_histogram cpu_pinned[TYPE_MAX];
> +/* Number of pinned CPU-independent task breakpoints. */
> +static struct bp_slots_histogram tsk_pinned_all[TYPE_MAX];
>
>  /* Keep track of the breakpoints attached to tasks */
>  static struct rhltable task_bps_ht;
> @@ -200,6 +202,8 @@ static __init int init_breakpoint_slots(void)
>         for (i = 0; i < TYPE_MAX; i++) {
>                 if (!bp_slots_histogram_alloc(&cpu_pinned[i], i))
>                         goto err;
> +               if (!bp_slots_histogram_alloc(&tsk_pinned_all[i], i))
> +                       goto err;
>         }
>
>         return 0;
> @@ -210,8 +214,10 @@ static __init int init_breakpoint_slots(void)
>                 if (err_cpu == cpu)
>                         break;
>         }
> -       for (i = 0; i < TYPE_MAX; i++)
> +       for (i = 0; i < TYPE_MAX; i++) {
>                 bp_slots_histogram_free(&cpu_pinned[i]);
> +               bp_slots_histogram_free(&tsk_pinned_all[i]);
> +       }
>
>         return -ENOMEM;
>  }
> @@ -245,6 +251,26 @@ bp_slots_histogram_max(struct bp_slots_histogram *hist, enum bp_type_idx type)
>         return 0;
>  }
>
> +static int
> +bp_slots_histogram_max_merge(struct bp_slots_histogram *hist1, struct bp_slots_histogram *hist2,
> +                            enum bp_type_idx type)
> +{
> +       for (int i = hw_breakpoint_slots_cached(type) - 1; i >= 0; i--) {
> +               const int count1 = atomic_read(&hist1->count[i]);
> +               const int count2 = atomic_read(&hist2->count[i]);
> +
> +               /* Catch unexpected writers; we want a stable snapshot. */
> +               ASSERT_EXCLUSIVE_WRITER(hist1->count[i]);
> +               ASSERT_EXCLUSIVE_WRITER(hist2->count[i]);
> +               if (count1 + count2 > 0)
> +                       return i + 1;
> +               WARN(count1 < 0, "inconsistent breakpoint slots histogram");
> +               WARN(count2 < 0, "inconsistent breakpoint slots histogram");
> +       }
> +
> +       return 0;
> +}
> +
>  #ifndef hw_breakpoint_weight
>  static inline int hw_breakpoint_weight(struct perf_event *bp)
>  {
> @@ -273,7 +299,7 @@ static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
>          * toggle_bp_task_slot() to tsk_pinned, and we get a stable snapshot.
>          */
>         lockdep_assert_held_write(&bp_cpuinfo_sem);
> -       return bp_slots_histogram_max(tsk_pinned, type);
> +       return bp_slots_histogram_max_merge(tsk_pinned, &tsk_pinned_all[type], type);
>  }
>
>  /*
> @@ -366,40 +392,22 @@ max_bp_pinned_slots(struct perf_event *bp, enum bp_type_idx type)
>         return pinned_slots;
>  }
>
> -/*
> - * Add a pinned breakpoint for the given task in our constraint table
> - */
> -static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
> -                               enum bp_type_idx type, int weight)
> -{
> -       struct bp_slots_histogram *tsk_pinned = &get_bp_info(cpu, type)->tsk_pinned;
> -
> -       /*
> -        * If bp->hw.target, tsk_pinned is only modified, but not used
> -        * otherwise. We can permit concurrent updates as long as there are no
> -        * other uses: having acquired bp_cpuinfo_sem as a reader allows
> -        * concurrent updates here. Uses of tsk_pinned will require acquiring
> -        * bp_cpuinfo_sem as a writer to stabilize tsk_pinned's value.
> -        */
> -       lockdep_assert_held_read(&bp_cpuinfo_sem);
> -       bp_slots_histogram_add(tsk_pinned, task_bp_pinned(cpu, bp, type), weight);
> -}
> -
>  /*
>   * Add/remove the given breakpoint in our constraint table
>   */
>  static int
> -toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
> -              int weight)
> +toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type, int weight)
>  {
> -       const struct cpumask *cpumask = cpumask_of_bp(bp);
> -       int cpu;
> +       int cpu, next_tsk_pinned;
>
>         if (!enable)
>                 weight = -weight;
>
> -       /* Pinned counter cpu profiling */
>         if (!bp->hw.target) {
> +               /*
> +                * Update the pinned CPU slots, in per-CPU bp_cpuinfo and in the
> +                * global histogram.
> +                */
>                 struct bp_cpuinfo *info = get_bp_info(bp->cpu, type);
>
>                 lockdep_assert_held_write(&bp_cpuinfo_sem);
> @@ -408,9 +416,91 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
>                 return 0;
>         }
>
> -       /* Pinned counter task profiling */
> -       for_each_cpu(cpu, cpumask)
> -               toggle_bp_task_slot(bp, cpu, type, weight);
> +       /*
> +        * If bp->hw.target, tsk_pinned is only modified, but not used
> +        * otherwise. We can permit concurrent updates as long as there are no
> +        * other uses: having acquired bp_cpuinfo_sem as a reader allows
> +        * concurrent updates here. Uses of tsk_pinned will require acquiring
> +        * bp_cpuinfo_sem as a writer to stabilize tsk_pinned's value.
> +        */
> +       lockdep_assert_held_read(&bp_cpuinfo_sem);
> +
> +       /*
> +        * Update the pinned task slots, in per-CPU bp_cpuinfo and in the global
> +        * histogram. We need to take care of 5 cases:
> +        *
> +        *  1. This breakpoint targets all CPUs (cpu < 0), and there may only
> +        *     exist other task breakpoints targeting all CPUs. In this case we
> +        *     can simply update the global slots histogram.
> +        *
> +        *  2. This breakpoint targets a specific CPU (cpu >= 0), but there may
> +        *     only exist other task breakpoints targeting all CPUs.
> +        *
> +        *     a. On enable: remove the existing breakpoints from the global
> +        *        slots histogram and use the per-CPU histogram.
> +        *
> +        *     b. On disable: re-insert the existing breakpoints into the global
> +        *        slots histogram and remove from per-CPU histogram.
> +        *
> +        *  3. Some other existing task breakpoints target specific CPUs. Only
> +        *     update the per-CPU slots histogram.
> +        */
> +
> +       if (!enable) {
> +               /*
> +                * Remove before updating histograms so we can determine if this
> +                * was the last task breakpoint for a specific CPU.
> +                */
> +               int ret = rhltable_remove(&task_bps_ht, &bp->hw.bp_list, task_bps_ht_params);
> +
> +               if (ret)
> +                       return ret;
> +       }
> +       /*
> +        * Note: If !enable, next_tsk_pinned will not count the to-be-removed breakpoint.
> +        */
> +       next_tsk_pinned = task_bp_pinned(-1, bp, type);
> +
> +       if (next_tsk_pinned >= 0) {
> +               if (bp->cpu < 0) { /* Case 1: fast path */
> +                       if (!enable)
> +                               next_tsk_pinned += hw_breakpoint_weight(bp);
> +                       bp_slots_histogram_add(&tsk_pinned_all[type], next_tsk_pinned, weight);
> +               } else if (enable) { /* Case 2.a: slow path */
> +                       /* Add existing to per-CPU histograms. */
> +                       for_each_possible_cpu(cpu) {
> +                               bp_slots_histogram_add(&get_bp_info(cpu, type)->tsk_pinned,
> +                                                      0, next_tsk_pinned);
> +                       }
> +                       /* Add this first CPU-pinned task breakpoint. */
> +                       bp_slots_histogram_add(&get_bp_info(bp->cpu, type)->tsk_pinned,
> +                                              next_tsk_pinned, weight);
> +                       /* Rebalance global task pinned histogram. */
> +                       bp_slots_histogram_add(&tsk_pinned_all[type], next_tsk_pinned,
> +                                              -next_tsk_pinned);
> +               } else { /* Case 2.b: slow path */
> +                       /* Remove this last CPU-pinned task breakpoint. */
> +                       bp_slots_histogram_add(&get_bp_info(bp->cpu, type)->tsk_pinned,
> +                                              next_tsk_pinned + hw_breakpoint_weight(bp), weight);
> +                       /* Remove all from per-CPU histograms. */
> +                       for_each_possible_cpu(cpu) {
> +                               bp_slots_histogram_add(&get_bp_info(cpu, type)->tsk_pinned,
> +                                                      next_tsk_pinned, -next_tsk_pinned);
> +                       }
> +                       /* Rebalance global task pinned histogram. */
> +                       bp_slots_histogram_add(&tsk_pinned_all[type], 0, next_tsk_pinned);
> +               }
> +       } else { /* Case 3: slow path */
> +               const struct cpumask *cpumask = cpumask_of_bp(bp);
> +
> +               for_each_cpu(cpu, cpumask) {
> +                       next_tsk_pinned = task_bp_pinned(cpu, bp, type);
> +                       if (!enable)
> +                               next_tsk_pinned += hw_breakpoint_weight(bp);
> +                       bp_slots_histogram_add(&get_bp_info(cpu, type)->tsk_pinned,
> +                                              next_tsk_pinned, weight);
> +               }
> +       }
>
>         /*
>          * Readers want a stable snapshot of the per-task breakpoint list.
> @@ -419,8 +509,8 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
>
>         if (enable)
>                 return rhltable_insert(&task_bps_ht, &bp->hw.bp_list, task_bps_ht_params);
> -       else
> -               return rhltable_remove(&task_bps_ht, &bp->hw.bp_list, task_bps_ht_params);
> +
> +       return 0;
>  }
>
>  __weak int arch_reserve_bp_slot(struct perf_event *bp)
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaJZzkYHc%2BYJRApOLG-NYe8zXMaqxpQgQQFAy5WY97Ttg%40mail.gmail.com.
