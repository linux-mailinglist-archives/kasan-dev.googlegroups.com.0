Return-Path: <kasan-dev+bncBDPPFIEASMFBB7OE4CLAMGQEAA5YUSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 58DC057BAAC
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 17:42:54 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id a12-20020a2e88cc000000b0025d67ee6ec4sf3125756ljk.3
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 08:42:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658331774; cv=pass;
        d=google.com; s=arc-20160816;
        b=0R4rm5MoKprkCbBzD9khLvz2t8wPeaTCNXBpvEm819r7r0Qq3XLJAKleXi7eVXg/6Z
         g+5NoEn88QHfn5Jxc2y48MtxQOnd7JINghb0n8sUjo11vQbzI5ldQkpFVwgoQNJQt8hJ
         cLdpgFgsrv/l/crf1/RpIuT1bkZBKjntEoTn3buOw+XL5g+XykK2ar4t+n5ynviZmRty
         eME8nzAXwRPx5cUkb2Q0WPtRuczy9va4/orES+oVuoR/5mZhWlomTV/VCQSn5QpTr65b
         bIg+Ot5eUUcexpyM/BX+Frec+Bt3vtYzBi28G9ujBf51WVmXWc8kd8yrM2v/V4Detc4h
         ILZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Tkm82WflK9qZsF0FNuCF8c5IxBedFxzU6XBONJ9NWz8=;
        b=gKo6OVPhcBL+XpVPTbDGcd+P+AGHJim1LdRzELNfDwMXuIeoCDGg6OEZ7YXsH3aF8C
         GAACamN1DDXf5QOlBZF7HIy56Udj+yFTtbx0a2n+CUXjOexfgOxd6GTUV1NT1EkZxyrB
         viiSShVfwksRRK7oUYtsSlVsqRMjD2CTYk9+opbCaK+FJHL5WvhKlaAFUwmx9e85iv3+
         6ZFjopek2hMERHYnbaauo/s+aqBqHlWJTMdyqxTvm4Dyir9j1W2pr4Juyp0CvFvW+yej
         YKxw8Xc6uwhxi6K/MGEj7cJfPeg5O9gyZRG48DMLy2aBfka6Byjb/XdjBhv41jZakH7A
         i2SA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iXpffLiJ;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tkm82WflK9qZsF0FNuCF8c5IxBedFxzU6XBONJ9NWz8=;
        b=mNqJ0DgHzOlNkHCxDnpDZaYWKhf3Ky5zMsUs+5x9NMaVMzsiCqPdsaLV+3dtjy3fAr
         XIAxRLUBBMIUq/ksyTN0b7msR84Xa1n1YgPZ9lJNdS6X2i6RJl8j6ipsAYyUxQ7cS6iz
         mHL/ec+6hBjXa1JaPocjWaFKKtRFaIDT4+9jzmxKQ2vOcaEhMXFenqqb20r5trfa2ro/
         XLS+cwlkSnMeTQ+buPHK6zGeOa0b/eWniVrl0035uguILEDk85SbK8OF1KAY7y0Ocnyi
         IKxlGskX5HnKRt1RBVC29HQz8Lc7RMb9Cev4A8Mh8Myj+VxQREURtAZB/E4wx2s9Qr5z
         1h+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tkm82WflK9qZsF0FNuCF8c5IxBedFxzU6XBONJ9NWz8=;
        b=n+2Fqy9YnORP9ZxGoEqKik20sWRmAgm6Wp62+hM42oZBsTgzmCK9JwvzKVWtRVXSo0
         dJtjzrb3+sJs5XfPMBT5HLB30a68nTg9D2LQeowNNUNCnLBPvfGJ0mXcTig1WfW3fTln
         FzhRS+7PsFngGxkqUqR8eiutCQhMBdvrnXlOkj2ToVz98ji11qMdo2rzHsIE5XiO8jg5
         lAvxpBwckVkqienALR7ECdCbOHVdWMrmQTg93kCIHmqyyiKJGPF4QREjYSz04Yx43G6e
         ikRxzxE0cS0Z2Akerk2DRR2/TZjp03PeEZVNdRjVQctn22upZeN3NumyDKA7Jr0KP5x5
         BDBg==
X-Gm-Message-State: AJIora9blaT6l+TbgrvN1XvVsbrmIVStFP8bcA7xKpHGEHKHev3FVGfj
	gQBYpMnMmIo39/TSWA9UyfQ=
X-Google-Smtp-Source: AGRyM1tsEVwMlpbuTE1HHjkfRzRfYrUefeVtfDtfXHTrPw9c2GaSJu0PBztqxHqmrxkUOVw37heuQg==
X-Received: by 2002:a05:6512:3996:b0:489:d526:93e5 with SMTP id j22-20020a056512399600b00489d52693e5mr20768786lfu.534.1658331773547;
        Wed, 20 Jul 2022 08:42:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2095:b0:489:cd40:7a25 with SMTP id
 t21-20020a056512209500b00489cd407a25ls101060lfr.3.-pod-prod-gmail; Wed, 20
 Jul 2022 08:42:52 -0700 (PDT)
X-Received: by 2002:a05:6512:c15:b0:489:e882:12c6 with SMTP id z21-20020a0565120c1500b00489e88212c6mr20784146lfu.530.1658331772423;
        Wed, 20 Jul 2022 08:42:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658331772; cv=none;
        d=google.com; s=arc-20160816;
        b=vxgU4J+e1HbE4Fppx+P0vC3kK4Cl39XTLpjbHIsM2qcoJ2+Wtfu8ydwbDQ2eEalyuS
         m4DZN9d/3aqFFPnhqxolrUcbTQka3/EkHYrEI9+88U6oRa7lQO2G5XWJ5OnT9Mkn3x55
         bMHyIcYhihXcBQ6JunrPQJob+qofrBRS5NTfcUWxu0yQLk8FlOb7ST+NaVamFFeet8TC
         akc2YDHalG3ei6OKComBh8XQJTFdOrLmVZKLBcrph9PV/CPN1Er2ma7uhHlub0WLxR2S
         1rKk70/4E9z3PbvooKCVWv2dlgczzfRawyWvokzrwqtlIQ5YVextAnJPo1DERFt/DniA
         oGkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iA6H9FbTpi/aYLA06konbtgAlr2/KT50OkDviEcMLbs=;
        b=AePj6931pbrs7kqaGp2p2nw+LbXGxXlkP6Vpy3ClhxBKH9rVWhWZ1RFKcZQJsrfP+x
         L/AcPKtxP2ofFHUmBfoSLQO2Mku+GtHP2mAiLvSv1N5HpIEkjY1Vi2zb7MrEN2EIPp33
         RGAmoGE0WOn8DCGUOIe8lWcgH4VBv1cmzuLHbU3DbJjDOKv3HebH3pdC0Bw/PatNzDV5
         fBOtJFnfnd31YVCS4QC578ICanacsaG1F4qxCDK5NQ51HBUTFPX/F1Skgeg4+50kzwRV
         m/GkUNuTzAAoFul90z+o7ZZEppK5rJ1EmuUxjlJK5R4pmBH6MvLpo3i7eY9ov2GaJ1vX
         meIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iXpffLiJ;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id v6-20020ac258e6000000b00489d438ad8bsi548546lfo.3.2022.07.20.08.42.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Jul 2022 08:42:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id j29-20020a05600c1c1d00b003a2fdafdefbso1527364wms.2
        for <kasan-dev@googlegroups.com>; Wed, 20 Jul 2022 08:42:52 -0700 (PDT)
X-Received: by 2002:a7b:c8d3:0:b0:3a2:fe0d:ba2e with SMTP id
 f19-20020a7bc8d3000000b003a2fe0dba2emr4552680wml.115.1658331771692; Wed, 20
 Jul 2022 08:42:51 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-14-elver@google.com>
In-Reply-To: <20220704150514.48816-14-elver@google.com>
From: "'Ian Rogers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Jul 2022 08:42:39 -0700
Message-ID: <CAP-5=fX3Ba8pOrnyehzJPfDBMEb-qf0ybj40na0nb4k_KyzeQA@mail.gmail.com>
Subject: Re: [PATCH v3 13/14] perf/hw_breakpoint: Optimize max_bp_pinned_slots()
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
 header.i=@google.com header.s=20210112 header.b=iXpffLiJ;       spf=pass
 (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::32d
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
> Running the perf benchmark with (note: more aggressive parameters vs.
> preceding changes, but same 256 CPUs host):
>
>  | $> perf bench -r 100 breakpoint thread -b 4 -p 128 -t 512
>  | # Running 'breakpoint/thread' benchmark:
>  | # Created/joined 100 threads with 4 breakpoints and 128 parallelism
>  |      Total time: 1.989 [sec]
>  |
>  |       38.854160 usecs/op
>  |     4973.332500 usecs/op/cpu
>
>     20.43%  [kernel]       [k] queued_spin_lock_slowpath
>     18.75%  [kernel]       [k] osq_lock
>     16.98%  [kernel]       [k] rhashtable_jhash2
>      8.34%  [kernel]       [k] task_bp_pinned
>      4.23%  [kernel]       [k] smp_cfm_core_cond
>      3.65%  [kernel]       [k] bcmp
>      2.83%  [kernel]       [k] toggle_bp_slot
>      1.87%  [kernel]       [k] find_next_bit
>      1.49%  [kernel]       [k] __reserve_bp_slot
>
> We can see that a majority of the time is now spent hashing task
> pointers to index into task_bps_ht in task_bp_pinned().
>
> Obtaining the max_bp_pinned_slots() for CPU-independent task targets
> currently is O(#cpus), and calls task_bp_pinned() for each CPU, even if
> the result of task_bp_pinned() is CPU-independent.
>
> The loop in max_bp_pinned_slots() wants to compute the maximum slots
> across all CPUs. If task_bp_pinned() is CPU-independent, we can do so by
> obtaining the max slots across all CPUs and adding task_bp_pinned().
>
> To do so in O(1), use a bp_slots_histogram for CPU-pinned slots.
>
> After this optimization:
>
>  | $> perf bench -r 100 breakpoint thread -b 4 -p 128 -t 512
>  | # Running 'breakpoint/thread' benchmark:
>  | # Created/joined 100 threads with 4 breakpoints and 128 parallelism
>  |      Total time: 1.930 [sec]
>  |
>  |       37.697832 usecs/op
>  |     4825.322500 usecs/op/cpu
>
>     19.13%  [kernel]       [k] queued_spin_lock_slowpath
>     18.21%  [kernel]       [k] rhashtable_jhash2
>     15.46%  [kernel]       [k] osq_lock
>      6.27%  [kernel]       [k] toggle_bp_slot
>      5.91%  [kernel]       [k] task_bp_pinned
>      5.05%  [kernel]       [k] smp_cfm_core_cond
>      1.78%  [kernel]       [k] update_sg_lb_stats
>      1.36%  [kernel]       [k] llist_reverse_order
>      1.34%  [kernel]       [k] find_next_bit
>      1.19%  [kernel]       [k] bcmp
>
> Suggesting that time spent in task_bp_pinned() has been reduced.
> However, we're still hashing too much, which will be addressed in the
> subsequent change.
>
> Signed-off-by: Marco Elver <elver@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Acked-by: Ian Rogers <irogers@google.com>

Thanks,
Ian

> ---
> v3:
> * Update hw_breakpoint_is_used() to include global cpu_pinned.
>
> v2:
> * New patch.
> ---
>  kernel/events/hw_breakpoint.c | 57 ++++++++++++++++++++++++++++++++---
>  1 file changed, 53 insertions(+), 4 deletions(-)
>
> diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> index 03ebecf048c0..a489f31fe147 100644
> --- a/kernel/events/hw_breakpoint.c
> +++ b/kernel/events/hw_breakpoint.c
> @@ -64,6 +64,9 @@ static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
>         return per_cpu_ptr(bp_cpuinfo + type, cpu);
>  }
>
> +/* Number of pinned CPU breakpoints globally. */
> +static struct bp_slots_histogram cpu_pinned[TYPE_MAX];
> +
>  /* Keep track of the breakpoints attached to tasks */
>  static struct rhltable task_bps_ht;
>  static const struct rhashtable_params task_bps_ht_params = {
> @@ -194,6 +197,10 @@ static __init int init_breakpoint_slots(void)
>                                 goto err;
>                 }
>         }
> +       for (i = 0; i < TYPE_MAX; i++) {
> +               if (!bp_slots_histogram_alloc(&cpu_pinned[i], i))
> +                       goto err;
> +       }
>
>         return 0;
>  err:
> @@ -203,6 +210,8 @@ static __init int init_breakpoint_slots(void)
>                 if (err_cpu == cpu)
>                         break;
>         }
> +       for (i = 0; i < TYPE_MAX; i++)
> +               bp_slots_histogram_free(&cpu_pinned[i]);
>
>         return -ENOMEM;
>  }
> @@ -270,6 +279,9 @@ static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
>  /*
>   * Count the number of breakpoints of the same type and same task.
>   * The given event must be not on the list.
> + *
> + * If @cpu is -1, but the result of task_bp_pinned() is not CPU-independent,
> + * returns a negative value.
>   */
>  static int task_bp_pinned(int cpu, struct perf_event *bp, enum bp_type_idx type)
>  {
> @@ -288,9 +300,18 @@ static int task_bp_pinned(int cpu, struct perf_event *bp, enum bp_type_idx type)
>                 goto out;
>
>         rhl_for_each_entry_rcu(iter, pos, head, hw.bp_list) {
> -               if (find_slot_idx(iter->attr.bp_type) == type &&
> -                   (iter->cpu < 0 || cpu == iter->cpu))
> -                       count += hw_breakpoint_weight(iter);
> +               if (find_slot_idx(iter->attr.bp_type) != type)
> +                       continue;
> +
> +               if (iter->cpu >= 0) {
> +                       if (cpu == -1) {
> +                               count = -1;
> +                               goto out;
> +                       } else if (cpu != iter->cpu)
> +                               continue;
> +               }
> +
> +               count += hw_breakpoint_weight(iter);
>         }
>
>  out:
> @@ -316,6 +337,19 @@ max_bp_pinned_slots(struct perf_event *bp, enum bp_type_idx type)
>         int pinned_slots = 0;
>         int cpu;
>
> +       if (bp->hw.target && bp->cpu < 0) {
> +               int max_pinned = task_bp_pinned(-1, bp, type);
> +
> +               if (max_pinned >= 0) {
> +                       /*
> +                        * Fast path: task_bp_pinned() is CPU-independent and
> +                        * returns the same value for any CPU.
> +                        */
> +                       max_pinned += bp_slots_histogram_max(&cpu_pinned[type], type);
> +                       return max_pinned;
> +               }
> +       }
> +
>         for_each_cpu(cpu, cpumask) {
>                 struct bp_cpuinfo *info = get_bp_info(cpu, type);
>                 int nr;
> @@ -366,8 +400,11 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
>
>         /* Pinned counter cpu profiling */
>         if (!bp->hw.target) {
> +               struct bp_cpuinfo *info = get_bp_info(bp->cpu, type);
> +
>                 lockdep_assert_held_write(&bp_cpuinfo_sem);
> -               get_bp_info(bp->cpu, type)->cpu_pinned += weight;
> +               bp_slots_histogram_add(&cpu_pinned[type], info->cpu_pinned, weight);
> +               info->cpu_pinned += weight;
>                 return 0;
>         }
>
> @@ -804,6 +841,18 @@ bool hw_breakpoint_is_used(void)
>                 }
>         }
>
> +       for (int type = 0; type < TYPE_MAX; ++type) {
> +               for (int slot = 0; slot < hw_breakpoint_slots_cached(type); ++slot) {
> +                       /*
> +                        * Warn, because if there are CPU pinned counters,
> +                        * should never get here; bp_cpuinfo::cpu_pinned should
> +                        * be consistent with the global cpu_pinned histogram.
> +                        */
> +                       if (WARN_ON(atomic_read(&cpu_pinned[type].count[slot])))
> +                               return true;
> +               }
> +       }
> +
>         return false;
>  }
>
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAP-5%3DfX3Ba8pOrnyehzJPfDBMEb-qf0ybj40na0nb4k_KyzeQA%40mail.gmail.com.
