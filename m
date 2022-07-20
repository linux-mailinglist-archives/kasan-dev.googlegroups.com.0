Return-Path: <kasan-dev+bncBDPPFIEASMFBBA6G4CLAMGQEPG73RPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 64E5C57BABC
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 17:45:08 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id b7-20020a056402350700b0043baadc4a58sf2232495edd.2
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 08:45:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658331908; cv=pass;
        d=google.com; s=arc-20160816;
        b=mHiYByxhm+RvjGn+btNOfZo5xycT4Ikbt685KyiiGrIeLpSTNjNhq3NzCUyiv2E1CN
         hJ9btgyqkxOQFx0Y/3QPFoxEFKEUzLhr5aNIB7W0FeHS27y30fNoAtgnz+vUpcCWGm4l
         /6u1aJOY0+MyTpJo4h6BXtXNBAw5B2DAotk266jP6wE4djyc0D4Up2kjg4nyeIJgdO3K
         WWO9KG4skApA7I+i8dKsYNuGQOCUQr4CBBmgB9AwPfAsN8OPcgv+wellRGrJO/lqWO/y
         WKoz+rTk5+D3hWjKLZYA9kmgbzQQFGluhSO3duWYctS5XEyTI1VbjFAjSroGMxjeiE9t
         HA1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=C/WwYjjWofpkcsWSss2urMC3hxPKsMceolPofdARPEE=;
        b=BxaGQdkFiTJqVQ7Sr2DbmEMwL0HRbOsXNc+il0cOYckdHb5o3gXlSW88IUhzAJ/Thy
         N62844eo68BdQlFnTN/xJH3PA45zneCeGtp+FOHMShiRFeTG3TG6bNs0tyTbH5ANo+PK
         Zh/OSO7DjxCDHtZxCEXTsNj9NQOhgZjzs6BIAGWykgYJ0JPdWR5Q/BNntI6JCwq7Rjsc
         Zsmwhng8zTgUaSfC5zxkq3WVdt/fvgKx7vn28olyVqifeN/mFxREwSkZNVFl2DoNk5a7
         zL1o+BL0PEyplHnAeZ+aFtsd0zKg3YgXHp84GLXIj/hJ0cjKUkUoCr/CT8/OYvTfE6cC
         uh4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jMjFel7O;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C/WwYjjWofpkcsWSss2urMC3hxPKsMceolPofdARPEE=;
        b=VrwQzXPtQSPFN16RoFi/CZTPPJt3Dbt9dfRYsI4aeqR2xXnsesFFPs8LNpFi+kcV2U
         LqJGweIPmqrquPN+T7pWSmv8kUySSKDDVehWFD2Eoh69upTve6szr9iGguBOIzuy9VOT
         udK6qZy033vOKaV+ZJJ14Zcl0RmOA9bMpZiPyrwNFcyf+k4AQwOx5iasgshYmiX2L2IE
         VvR+nZ3+KusJR2sUTqZ/qHM6vQWGjMhgEbRdezyBpypQfrBtFszj484gSFXebSxoon8I
         WROX9mcAgjgNu3rcen5T5gUgpA8vMCUXTBrI+mrKmfBcgnSZa0si5MF/ABQNYtQDDX+2
         4jEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C/WwYjjWofpkcsWSss2urMC3hxPKsMceolPofdARPEE=;
        b=UAImA0Q4H/HaQbejFX6p9KWvEOnEeD4VPzGeI83ff/PCU9NJFkSxs+e3K3gWgGa1D7
         pLgoUiO17H307DpRdzduB7gQd7e0DPA+EOjnRA0xNMho0p8MN9MvcYjs2+GSzL0Rvzna
         nYoJpSXj6TebuZ//Yq8pTWqa6tXuEtqKgs42AKq0C3Ygz1Grt739RFTW6dHyX3VtSZWo
         IuLoJiRdnXwlLY6cItO9QzxtjcEaTM3jtnIctAczCDhUnHzLYlB6IKcOzwkP23Y6qcDV
         mE9JDI21hYlOs84lVi605H+pm2hRVqFgcuR7+Fb6iPQrgJcWOLZrkx+RCIaPS4APn+vB
         GhSg==
X-Gm-Message-State: AJIora8vUSJwQwLMBKLkWm1XgnTpAl6IIfepjTanUcHncF7R0uwUji7A
	yWSFNNTme68UPMumiOlM/V0=
X-Google-Smtp-Source: AGRyM1tLSCqNS6Qopss8mi4shbheXhffoC+AsB93pb/ie3w9FXhgWXohFHPYkuxqgGrxSDvH55dBKw==
X-Received: by 2002:a17:906:478d:b0:72e:e902:587 with SMTP id cw13-20020a170906478d00b0072ee9020587mr27469236ejc.548.1658331907944;
        Wed, 20 Jul 2022 08:45:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:cb91:b0:726:d068:52af with SMTP id
 mf17-20020a170906cb9100b00726d06852afls322032ejb.1.-pod-prod-gmail; Wed, 20
 Jul 2022 08:45:07 -0700 (PDT)
X-Received: by 2002:a17:907:2856:b0:72b:8e8e:3d9 with SMTP id el22-20020a170907285600b0072b8e8e03d9mr36300788ejc.0.1658331907079;
        Wed, 20 Jul 2022 08:45:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658331907; cv=none;
        d=google.com; s=arc-20160816;
        b=LPbS6TjXEEWdWXTSPMAlIA4gZHSpNSXSp+aNnraTBnkE2cHuvBb49lBYW4EZjnSOQF
         mCfMWxNG9zIbtUoFmcKlwjnFttRO26RI1EVSIuU3NT5zFb8eCOrPMrre/GpiEKh2TN1u
         +6ECw8P1NoZBY3N36OEThJoLicK9GB3keSDI9Tv8aeYNDGOrcDWfqDROVkgb2jE1/Kig
         Rofu0G7+6JW8S8OypIwvTqvWyMJCbJhRWbRaV6g1HTsYUfIhiM+bZK9RijTejdyoV9s4
         EgWNcDgIz5MoJfbbU1NgCAb0ZbBwxw2ywyOISiBokWxNh/p89R7gBI3dChCO2Yhrwnij
         9trg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sTlwsce+j9b/yyK8fo/sWOEwGwuq8KzZalKUeFpjn/4=;
        b=aZWkzbIKgboXTtE7ILXCSECMyT40HMW2fLEvn2Cac/m3Eoy9WOUMFb9ILtrno3pvii
         zdXsmyf7It6mgY/4kw/hM4taDK34JfBU29u8BejfJ9W/A9jNbCy5yEsOYOruYey/E073
         jxxx9/td3Tk3h82m89j9ca2KAwwpManmB2F7X0qjwsPWWwzBKltz8u8v+ko1ls8B/XXz
         mJxundmAYPbwHdoEbr/QmuhVztz4uP0s4YS95LXoKPf/APLrYV9c7BtnkqKIZV9MqqHA
         VsBMLzmrGJFFRA1jgebjgiB67awzktKLFd083UJ+hl1uZeyB30u2UTtrPP66nyg52F+d
         pwvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jMjFel7O;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id d10-20020a50fe8a000000b0043a99ce7f64si590155edt.0.2022.07.20.08.45.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Jul 2022 08:45:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id b21-20020a05600c4e1500b003a32bc8612fso1027975wmq.3
        for <kasan-dev@googlegroups.com>; Wed, 20 Jul 2022 08:45:07 -0700 (PDT)
X-Received: by 2002:a05:600c:2854:b0:3a3:1551:d7d with SMTP id
 r20-20020a05600c285400b003a315510d7dmr4234783wmb.174.1658331906538; Wed, 20
 Jul 2022 08:45:06 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-15-elver@google.com>
In-Reply-To: <20220704150514.48816-15-elver@google.com>
From: "'Ian Rogers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Jul 2022 08:44:54 -0700
Message-ID: <CAP-5=fX1ayMVSSny8A3JtF2PELnt2wjCj-LPXXF+-Dji8qUNwg@mail.gmail.com>
Subject: Re: [PATCH v3 14/14] perf/hw_breakpoint: Optimize toggle_bp_slot()
 for CPU-independent task targets
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
 header.i=@google.com header.s=20210112 header.b=jMjFel7O;       spf=pass
 (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::329
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

On Mon, Jul 4, 2022 at 8:07 AM Marco Elver <elver@google.com> wrote:
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
>  | # Running 'breakpoint/thread' benchmark:
>  | # Created/joined 100 threads with 4 breakpoints and 128 parallelism
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
>  | # Running 'breakpoint/thread' benchmark:
>  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
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
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Acked-by: Ian Rogers <irogers@google.com>

Thanks,
Ian

> ---
> v3:
> * Fix typo "5 cases" -> "4 cases".
> * Update hw_breakpoint_is_used() to check tsk_pinned_all.
>
> v2:
> * New patch.
> ---
>  kernel/events/hw_breakpoint.c | 155 +++++++++++++++++++++++++++-------
>  1 file changed, 124 insertions(+), 31 deletions(-)
>
> diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> index a489f31fe147..7ef0e98d31e2 100644
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
> +        * histogram. We need to take care of 4 cases:
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
> @@ -850,6 +940,9 @@ bool hw_breakpoint_is_used(void)
>                          */
>                         if (WARN_ON(atomic_read(&cpu_pinned[type].count[slot])))
>                                 return true;
> +
> +                       if (atomic_read(&tsk_pinned_all[type].count[slot]))
> +                               return true;
>                 }
>         }
>
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAP-5%3DfX1ayMVSSny8A3JtF2PELnt2wjCj-LPXXF%2B-Dji8qUNwg%40mail.gmail.com.
