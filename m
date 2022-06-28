Return-Path: <kasan-dev+bncBCMIZB7QWENRBNGC5SKQMGQEX3AESHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 47CC655E5BF
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 17:41:41 +0200 (CEST)
Received: by mail-ej1-x63c.google.com with SMTP id gr1-20020a170906e2c100b006fefea3ec0asf3801034ejb.14
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 08:41:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656430901; cv=pass;
        d=google.com; s=arc-20160816;
        b=QJwRu1bvDx9uoGFCSZ13SV8lhdBdFWqDZc1SuUxiSPthoRQIQm6KZaNzFQiYGpnZpz
         FVDG87s0JGW+HMWgEH9ANJWpXzeR0iLtpc18xXXE1gMRIdkvb2HbKMzPBfo0HfNfMrr2
         JaJJeel4ocNbZ6q5dDDLM3fG2KIhHklmgV+LU3d+oL0vPEJliFUFl1MgGVYq6lw8L0ax
         A5umJ/umsBMkba1qyOKN6+Kao2QoUSi95o9n3UzULlTGu/xr0dYFTKfKkax/W9cBgM6u
         SFRlXOM14Ou0xmpQTaxx2/gufAJfqcmI2IUhPMFzWKuEpZgYS2N31AaSq0h4+X25ej8B
         dEnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hzFqT3G58S8ZPbOMeikNbdCVdnpMOGWgrJLeKlXB3ww=;
        b=OPKEf/lBFRQT6XhgX7drSD9bSwCogxLFmkTDU3NuDdPuKnecFXOuLtcXueuroDrVly
         sqUhKUZENXG74L1rz1wjp6aFuRrbrCxHosdyo0h/sWFmgJOmdQJI/PC/Ow+PJfzENmDD
         zg4D9lnro03/U6NIOp5JJsYn+Op6dCVdUq2LozH8bLKJ3BPipAkz+ZudMTSojvqqDHY4
         uocR+FmWEbTJYY1BWuBSKY8QyblPPY+tU+XDe++KCbqoqnh6nyAz1Z9hFWbK/kkHPImR
         WQ5+w/btc6M1B1sJa5j7ooqWPSDNA/GSnL79LmsRRPr2MM10vz9B/J120E94yMNFP/q9
         5+VQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tixw4tZb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hzFqT3G58S8ZPbOMeikNbdCVdnpMOGWgrJLeKlXB3ww=;
        b=SH8WN94PQliNQ7xab6IFKfeGVNaoDjzsTuViBNBwYrM/PKrXApuy4co1di6HrKwK1k
         m4fyUDHuEwKMRYsi+L5ruP/3fEJ+cYZhttB9LEV402m3NpZtuW82vKOPBhPw0t/ChcdK
         8v8fUU8iyraAAOPkIW7fvs/C8iC5OlmqAH70cDf4GXK+HpxBtlAidpZKj8fLVdzyogJ6
         zhi8/YvyDds0NBmfZ4t7YD5NbCylwXdRPFxVtu7RUGSM9suIob8k4hzb0JNNThxj11d4
         wD51va40FBrEeQPTc9ZPkfBsv9l+lPvmY9YndWTqK6YKP8IllE2NOPihZrtExj9TqPyn
         J4yQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hzFqT3G58S8ZPbOMeikNbdCVdnpMOGWgrJLeKlXB3ww=;
        b=aoadXeU1uTyO0itT9IoyvNAdD8EoDjt1/AdVld1c9c1sKoFfSm7rSyV/vQb0mkcqlv
         eYYwPXK2PwbyyGAVHAKLch6IfKTDgoq+6c+qNqMCm2zGWy+kuHgm6SuBYiRd4CU0NcP2
         u3xIonSvVxmzn5+V47/sPa9WvWl1K7JEIxjko/0xn4W4Q3N46QUpCGCj/R34TKDVzh8y
         1Drjm/G10bxU2CGX6s9v5PLWiMoL9RTYTCVHAw5G+g8u1yiGc/RHDEW7VAPYZfP8uXCM
         jsMkRnhqyzUUNEUTdkv1MqWSZf9zyHXH1fBBN1T4RxqMuQeWbEl/c1nqPkTqolL9cXOa
         GBfw==
X-Gm-Message-State: AJIora+hnRZSbT4vcnlx5Iw//0uXtZ25+UjZU68Q00i/2Dk/GS9eYS2c
	VsI5KETHqoSpA00NEXwdjyM=
X-Google-Smtp-Source: AGRyM1vZ0Yh2a1fWCSgIOv43CXzeKsobrA+1O8wo3D2SW8M3u32tyN/9GMWj769h5nhLldFwcQBstw==
X-Received: by 2002:a17:907:94ca:b0:726:f4de:535b with SMTP id dn10-20020a17090794ca00b00726f4de535bmr824389ejc.590.1656430900887;
        Tue, 28 Jun 2022 08:41:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:16a7:b0:718:c04a:5161 with SMTP id
 hc39-20020a17090716a700b00718c04a5161ls490971ejc.11.gmail; Tue, 28 Jun 2022
 08:41:39 -0700 (PDT)
X-Received: by 2002:a17:906:478e:b0:722:fc31:aa13 with SMTP id cw14-20020a170906478e00b00722fc31aa13mr18595127ejc.84.1656430899887;
        Tue, 28 Jun 2022 08:41:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656430899; cv=none;
        d=google.com; s=arc-20160816;
        b=bqnw3JmiZAsBoJw99BgSY3C6+gbS1+cMbPoyZt+8NIm9kANgKtrZEryGWZbbCJWLNg
         kr3Bl1Hc8yKLHUaxTIpRx5EM84JN2EBgsDNmA/5WmoCoIewQrLSJ+Hpk4O3gVZw7UBmm
         gq/IVUH+PCiy+xOwxOsLODxIGCJylQAAW9hvN7KfJV8Ummu1KjP6cIxVNW3iRuRaK/o3
         Ig0zhuZPYxK54rfIIzNSwWZvOizvRxc7PQ8OhBQ1wD9wknzPgJwfKbjUwvPR4a6wHLnL
         IEnJeX48uRzHdfKvkG5PYTHqDu0yqdCEX+fQ22a8D/hQX5nC+SPKGQK3pIZLRyuyI9d1
         Pmyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=45OuMvop0l12Xy16UbND2bLY50+0LD4yzVw7v19VYg8=;
        b=DZ4G+eL+SLZHAHFhFEVVEwnfuBzIXoX2voTlLLWXkbVDa4c71JLEedr7Y5cj5erH+W
         wXckH8PJTUgOpy4re+uoJvingP9CBagS/RMSWeLzX6zSH/kB4oEYFh7pMn4lpi7qymwF
         lEhx5fFz4G7XHLtfXqry802Z9MrmieHW9yaQG4J/7fJ6LVRf2v5Jp72MmXbJNpsOmanV
         8lPkSiUt6OpgDk4puI3RyAdCYnpOfdLDp9Lpg+lxe8fPAI0dOjpXQAWoLO7hlYUUNeGM
         o5H4eR7hDySAht5O745Qq5fJL90dzTuk1d/smC2Lvu+8YfZrySetDPMoIdjJ5VBmZT+c
         2wRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tixw4tZb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x232.google.com (mail-lj1-x232.google.com. [2a00:1450:4864:20::232])
        by gmr-mx.google.com with ESMTPS id p11-20020a056402500b00b004359bd2b6c9si652602eda.3.2022.06.28.08.41.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 08:41:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::232 as permitted sender) client-ip=2a00:1450:4864:20::232;
Received: by mail-lj1-x232.google.com with SMTP id s14so15428049ljs.3
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 08:41:39 -0700 (PDT)
X-Received: by 2002:a2e:998c:0:b0:25b:b2ae:b2 with SMTP id w12-20020a2e998c000000b0025bb2ae00b2mr8470900lji.92.1656430899134;
 Tue, 28 Jun 2022 08:41:39 -0700 (PDT)
MIME-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com> <20220628095833.2579903-13-elver@google.com>
In-Reply-To: <20220628095833.2579903-13-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jun 2022 17:41:27 +0200
Message-ID: <CACT4Y+ZAjQa4rh-kq8h+wOmfaURvz+cV2LeU5SHj34OMtMMfow@mail.gmail.com>
Subject: Re: [PATCH v2 12/13] perf/hw_breakpoint: Optimize max_bp_pinned_slots()
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
 header.i=@google.com header.s=20210112 header.b=tixw4tZb;       spf=pass
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

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
> v2:
> * New patch.
> ---
>  kernel/events/hw_breakpoint.c | 45 +++++++++++++++++++++++++++++++----
>  1 file changed, 41 insertions(+), 4 deletions(-)
>
> diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> index 18886f115abc..b5180a2ccfbf 100644
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
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZAjQa4rh-kq8h%2BwOmfaURvz%2BcV2LeU5SHj34OMtMMfow%40mail.gmail.com.
