Return-Path: <kasan-dev+bncBDPPFIEASMFBBAWB4CLAMGQE7N7OR7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8036957BA15
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 17:34:26 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id r10-20020a05600c284a00b003a2ff6c9d6asf1409060wmb.4
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 08:34:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658331266; cv=pass;
        d=google.com; s=arc-20160816;
        b=e7oPypAg9Lqjc1Z9X7LMgCbVMSEgPPUKF3cJKQ2GPi8N53fU6CAfM4gcMvy65qjJN0
         Nz0T5BSucYWI2kDsxxww2LwF8U+nGqCoLqvxG218rGBa872DfPGeo87eqEveNSgW+pyJ
         1kuiHDUUObc3CgEyALR5ZFuDF264Jofm+hbF76pMplj/jjr9nowa8wVoJgWrpbcdTcXF
         k6KbKGgHLZsN6/fRBHVR4fd7G+fwXIEtrayfDF8gim81jap61qgso8iRARo+doFtYSPb
         i8X5lcDKDQVR7isxgPedMXimPks7Apq6EhOSMjIrpdc4O5NWm8eu31Dr3KMdvi+GnMqN
         9fNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=l10f60i/lyc//8jaTHQlHvuJlPY14Sfby4FuUvH8O+s=;
        b=JXAZ2XdiPpnDwLXZ4HIvkW+NCJcXqo5khYzTevHaVIYAhTiWjruO4g4/8TJW7ZKOrA
         BT19RjbOAWgYgGvZ7I2olrM9DcnOJCewsW1qYrmvoZELKVFel2iEjYm8CihF7OW8gTQQ
         ndFG09xtr2RN7Q661Vr59oFWAgsSzvxfYhKxPDGqcUCypb+CnfdKzkUHV2RGYcgzSNou
         TUm71AS97Tr3J/pysMqEZi2wcfqv+INDUFyWnh0R5Z/oUKMAgU6HjnToUvKZYcs3l927
         WitlmnRiDBovHs1yXbLR1t4s7DSd44opwDXeWn9We8APRkDcgypkhE6gEQ/L4+Kx8dqi
         nqWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qYpCF0yP;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l10f60i/lyc//8jaTHQlHvuJlPY14Sfby4FuUvH8O+s=;
        b=iCDih/wUedkOWDtHpa6AoWZGfxb+2RJeNLWy4v39imphonQCdyGIA6zatcNtFFhF7x
         +EeYxz7z9cB2D/u1A383kctaQ/rnwl/0ZCjx1g52eei4HF5cK5NB76aiv9HqX2cMCSx0
         gcISI2Zom2wHfgmRC2VNJwpMS78ZVSff1W32QXp59dzUp2WXtV6vTpKIKWXG8xhB4/hi
         NRzcc8hdpbBPww845HY5R3FYMFQztm95DFlTZsoW8KhBVIukJoN4dTefoGzFJcWW+Cnc
         anyUJWLEjs+b6LMwMGnp3KWItHxXw3pTDDgmdna+TDCz/HHGwm7l9yz8KWcEqg45KN7l
         zFHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l10f60i/lyc//8jaTHQlHvuJlPY14Sfby4FuUvH8O+s=;
        b=AVxRjgH0OOMrhDkKblbXJp20LSXshOHH2TjkLav+isPl4IhBLubYj7LLIBw2W7yKvG
         qk87uiEj2t0JB07JyK6eHilgkGrf+dExcDFkjnKL6ffZCxGWeK5Nd3JMGGQ3BYh5m280
         tIjs2gXGEUjCWjmmky6SkrsYUN4GvDwD9J55Ehn+7e4NS7o3X2kF+Q/YsVK0RYZp8z7a
         0Y6Cvv/dWyKt1d/hZ79tF4ckOr8xUzb9he/lwz8vzjF1RgBKde3GE/k3eC6aF1gN1NTp
         Zo0p1bKSEcW36GItoO1+SwV9J+YIulzE6ywSnc/nZ/34dvmTN8RUDwmw553+uDAXJIeL
         3kBw==
X-Gm-Message-State: AJIora8nvg4bEAfYJUYpaI82mqWpGh0+pqeMHWuVKF+/okc1eAMiFj3a
	+UBqSw/ProtS0W7O/ynSIO8=
X-Google-Smtp-Source: AGRyM1vaZXbyQSrITpgwZ8mZO3qa3uoAMfjcZJNuMdGBVRGQkln6K3ju1SpSnq8Gwbv1mjn9q1BQ9g==
X-Received: by 2002:a05:6000:1d1:b0:21d:6673:9894 with SMTP id t17-20020a05600001d100b0021d66739894mr31016167wrx.640.1658331266321;
        Wed, 20 Jul 2022 08:34:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cbc7:0:b0:3a3:19d9:6190 with SMTP id n7-20020a7bcbc7000000b003a319d96190ls562280wmi.3.-pod-prod-gmail;
 Wed, 20 Jul 2022 08:34:25 -0700 (PDT)
X-Received: by 2002:a05:600c:1d12:b0:3a3:297a:bb13 with SMTP id l18-20020a05600c1d1200b003a3297abb13mr3470198wms.136.1658331265383;
        Wed, 20 Jul 2022 08:34:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658331265; cv=none;
        d=google.com; s=arc-20160816;
        b=cEIq/intW1xCyA1MQ8HJCgyRNwvSPI7ON3Cqie0gEm/mQzVOonggQTotsBfeZm7p3h
         GN+FxIAJ3ncujG1CkqQ8gk71aUJw9ZW/63acxKmHsJDxe887IfhJPU+VG2ABrCOIdiqL
         XxZFSD3TTmYxFgL/QN/iup96u2E5PJouPvRpZKypbrLMuj8NKChsddrPeg/gFqfXH6WX
         vraEhF/HylOLItxoVg8Q1kjiRXXoVqYB86HwplGuJtKThVhV1WnwSsyJWudTIyc6EVyW
         BH8PrrmV4md+lF7hgwOzYgHmctFlX7YbNsShcXmF0QVjLQz2QzCz36tEsWzz8yTUDogl
         Kqvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ypDIzBcK+87vSvCQ9N63jBX4rrxFFdnrF6gevmMUAWM=;
        b=augk3v+XsO73cWCrA4CxZg8rdSIDVgZfTLauwn2gLRx0sOlHrza3lNwKS9Khk/wZVI
         2MuGT8WutBUFhXXkrnZT8x9U5OZTc+r4qaGPWHdrta1MQ3KtiLKFpqjJoheV0lI6O8Lo
         hkyWgAZ/ijRPD69DuLnQqxS1X4jT6VIOXJFNXQDV4vbXTgIU5ZEFOJVhKDsunyL5Md5A
         IsmRxoNkppW3wzybbeVP0YRVEOaSj51STT6EUbOQC1HYB+y5AhSTRuievizbxU2Gk1hf
         EI6xolHBEIEwS0KgC4p1Of9d7apW2KxNgr3A9tqqOZb2CWR8yfQVI9KID42BvC+xCMdx
         RweQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qYpCF0yP;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id k23-20020a5d5257000000b0021d2e06d2absi538592wrc.3.2022.07.20.08.34.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Jul 2022 08:34:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id b21-20020a05600c4e1500b003a32bc8612fso1007110wmq.3
        for <kasan-dev@googlegroups.com>; Wed, 20 Jul 2022 08:34:25 -0700 (PDT)
X-Received: by 2002:a7b:c8d3:0:b0:3a2:fe0d:ba2e with SMTP id
 f19-20020a7bc8d3000000b003a2fe0dba2emr4514304wml.115.1658331264903; Wed, 20
 Jul 2022 08:34:24 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-9-elver@google.com>
In-Reply-To: <20220704150514.48816-9-elver@google.com>
From: "'Ian Rogers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Jul 2022 08:34:13 -0700
Message-ID: <CAP-5=fVYaipBhx7hoq25E=tEUua1DNhhh9o5f3tPxoFtqpq4EQ@mail.gmail.com>
Subject: Re: [PATCH v3 08/14] perf/hw_breakpoint: Remove useless code related
 to flexible breakpoints
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
 header.i=@google.com header.s=20210112 header.b=qYpCF0yP;       spf=pass
 (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::333
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
> Flexible breakpoints have never been implemented, with
> bp_cpuinfo::flexible always being 0. Unfortunately, they still occupy 4
> bytes in each bp_cpuinfo and bp_busy_slots, as well as computing the max
> flexible count in fetch_bp_busy_slots().
>
> This again causes suboptimal code generation, when we always know that
> `!!slots.flexible` will be 0.
>
> Just get rid of the flexible "placeholder" and remove all real code
> related to it. Make a note in the comment related to the constraints
> algorithm but don't remove them from the algorithm, so that if in future
> flexible breakpoints need supporting, it should be trivial to revive
> them (along with reverting this change).
>
> Signed-off-by: Marco Elver <elver@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Acked-by: Ian Rogers <irogers@google.com>

Thanks,
Ian

> ---
> v2:
> * Also remove struct bp_busy_slots, and simplify functions.
> ---
>  kernel/events/hw_breakpoint.c | 57 +++++++++++------------------------
>  1 file changed, 17 insertions(+), 40 deletions(-)
>
> diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> index 9c9bf17666a5..8b40fca1a063 100644
> --- a/kernel/events/hw_breakpoint.c
> +++ b/kernel/events/hw_breakpoint.c
> @@ -45,8 +45,6 @@ struct bp_cpuinfo {
>  #else
>         unsigned int    *tsk_pinned;
>  #endif
> -       /* Number of non-pinned cpu/task breakpoints in a cpu */
> -       unsigned int    flexible; /* XXX: placeholder, see fetch_this_slot() */
>  };
>
>  static DEFINE_PER_CPU(struct bp_cpuinfo, bp_cpuinfo[TYPE_MAX]);
> @@ -67,12 +65,6 @@ static const struct rhashtable_params task_bps_ht_params = {
>
>  static bool constraints_initialized __ro_after_init;
>
> -/* Gather the number of total pinned and un-pinned bp in a cpuset */
> -struct bp_busy_slots {
> -       unsigned int pinned;
> -       unsigned int flexible;
> -};
> -
>  /* Serialize accesses to the above constraints */
>  static DEFINE_MUTEX(nr_bp_mutex);
>
> @@ -190,14 +182,14 @@ static const struct cpumask *cpumask_of_bp(struct perf_event *bp)
>  }
>
>  /*
> - * Report the number of pinned/un-pinned breakpoints we have in
> - * a given cpu (cpu > -1) or in all of them (cpu = -1).
> + * Returns the max pinned breakpoint slots in a given
> + * CPU (cpu > -1) or across all of them (cpu = -1).
>   */
> -static void
> -fetch_bp_busy_slots(struct bp_busy_slots *slots, struct perf_event *bp,
> -                   enum bp_type_idx type)
> +static int
> +max_bp_pinned_slots(struct perf_event *bp, enum bp_type_idx type)
>  {
>         const struct cpumask *cpumask = cpumask_of_bp(bp);
> +       int pinned_slots = 0;
>         int cpu;
>
>         for_each_cpu(cpu, cpumask) {
> @@ -210,24 +202,10 @@ fetch_bp_busy_slots(struct bp_busy_slots *slots, struct perf_event *bp,
>                 else
>                         nr += task_bp_pinned(cpu, bp, type);
>
> -               if (nr > slots->pinned)
> -                       slots->pinned = nr;
> -
> -               nr = info->flexible;
> -               if (nr > slots->flexible)
> -                       slots->flexible = nr;
> +               pinned_slots = max(nr, pinned_slots);
>         }
> -}
>
> -/*
> - * For now, continue to consider flexible as pinned, until we can
> - * ensure no flexible event can ever be scheduled before a pinned event
> - * in a same cpu.
> - */
> -static void
> -fetch_this_slot(struct bp_busy_slots *slots, int weight)
> -{
> -       slots->pinned += weight;
> +       return pinned_slots;
>  }
>
>  /*
> @@ -298,7 +276,12 @@ __weak void arch_unregister_hw_breakpoint(struct perf_event *bp)
>  }
>
>  /*
> - * Constraints to check before allowing this new breakpoint counter:
> + * Constraints to check before allowing this new breakpoint counter.
> + *
> + * Note: Flexible breakpoints are currently unimplemented, but outlined in the
> + * below algorithm for completeness.  The implementation treats flexible as
> + * pinned due to no guarantee that we currently always schedule flexible events
> + * before a pinned event in a same CPU.
>   *
>   *  == Non-pinned counter == (Considered as pinned for now)
>   *
> @@ -340,8 +323,8 @@ __weak void arch_unregister_hw_breakpoint(struct perf_event *bp)
>   */
>  static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
>  {
> -       struct bp_busy_slots slots = {0};
>         enum bp_type_idx type;
> +       int max_pinned_slots;
>         int weight;
>         int ret;
>
> @@ -357,15 +340,9 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
>         type = find_slot_idx(bp_type);
>         weight = hw_breakpoint_weight(bp);
>
> -       fetch_bp_busy_slots(&slots, bp, type);
> -       /*
> -        * Simulate the addition of this breakpoint to the constraints
> -        * and see the result.
> -        */
> -       fetch_this_slot(&slots, weight);
> -
> -       /* Flexible counters need to keep at least one slot */
> -       if (slots.pinned + (!!slots.flexible) > hw_breakpoint_slots_cached(type))
> +       /* Check if this new breakpoint can be satisfied across all CPUs. */
> +       max_pinned_slots = max_bp_pinned_slots(bp, type) + weight;
> +       if (max_pinned_slots > hw_breakpoint_slots_cached(type))
>                 return -ENOSPC;
>
>         ret = arch_reserve_bp_slot(bp);
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAP-5%3DfVYaipBhx7hoq25E%3DtEUua1DNhhh9o5f3tPxoFtqpq4EQ%40mail.gmail.com.
