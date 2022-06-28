Return-Path: <kasan-dev+bncBCMIZB7QWENRBU5L5SKQMGQE67T256I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 7891E55E587
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 16:53:08 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id y35-20020a0565123f2300b0047f70612402sf6347010lfa.12
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 07:53:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656427988; cv=pass;
        d=google.com; s=arc-20160816;
        b=SIGmiR8PxVVHl0rsaPcQdFSc5Bt98PUG8/sq1DlczIdr2FaJUlX/0gZ+3HHWcTnAH+
         j/niv/nLfiIY3Zy9DuqmJi7LN+U6964jhy5c9dCp2OuMIjq4FZLh/6ZbBpWrDXubcu8y
         w4jWhuh0dzBeRj7ctvNU+7O0HYRMBEM1QXcqn2CLPWWWAFFXe1399zJ8GCnMyp4NN9T/
         c+Qfy+ZK5eg8vxvgsehFyx6SFieGokVYeW4NDrJeoMW7WV9S5ghu5XO/tWe6jSG149uh
         EMBDSELSQQi/nU3Wd8ogQJ9e00vui62C2399aC61uF6mi2Dy6r6OfzW5y+oXM3aDtrQk
         z02g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9IEwQNaQwWgbzIINSkW4oy5+VGEfoPINkENjD5GWxt4=;
        b=XP10pkyvSQujJ0BWT9GHV86QS6VAiC07XlEtuWkOCUwr9WVpYVsWT3y6wW5f/L8JZ7
         m2+c1pF/KMHB5+zxcolax/98GMTKwDxwjcCvQjatPJpv0Ad6zvxQpZVmJE7ZkP3h19xl
         Urj3QfhyLfaScD0xXE21Fh0K4ZHscbntZy4Mi6dA4AGV6eFvAhZhLa24gRXr9OWAVRr0
         FTCQROL2jSdFHh17NrtKKUCnw8BDi8HcXMQfzdw+hx1Or7Z+wrex6B72pspIB0yf8RO8
         8N12dv9/S4fQkn5k7l10YZn11oSTNw6NEXUpFikHwxYBzGgD7NTWyMvExllvaebVa7kb
         HUgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CK+v3yJg;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9IEwQNaQwWgbzIINSkW4oy5+VGEfoPINkENjD5GWxt4=;
        b=RGlNLPlpcLIRxCFO0+IzZ/UVV+qjSvmC55etabvW8KVZ+YbsEN0tm0eEUzYGq2Ia3x
         RmB3JCtQZ6sJbNQqAKhsZtMjJ/nwBkycw3Z1i2Sq08hsXMWQrCTFWls11kis5xggaahS
         LPTGwEg0V1rSjOFD6fCB5p/yWKPzRTU1E/kuNVClMw+Ju3VK5/WVKyxMExIrEFEq6rVu
         /n+OcW+moMq9KoRYH6NpQcUh4LM26Wd2jy4LHOdXDMr8V8OHyYxq1erjftMy8Y1g37tD
         pFhc7Eqi9RO05Y5F1YIMfiI7GHhswHjXomYc23EPlFZ0tk3c9d23K6856t1/OhOZWK7e
         Es4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9IEwQNaQwWgbzIINSkW4oy5+VGEfoPINkENjD5GWxt4=;
        b=CSFlvwh8usJGjOaNuGntRne5a3NQf2j32wDzHnCOc7DC8ORCMyEjPoiHlkPhoEvRj4
         2yjYlQygLQrCDCJ/K86nxGOsFJzzmtghSj/M7aQVrhhkah3hXU926YBJ3BEutFQT7WQf
         WgvyDepTYo3tgtnr59X9rPVtkew5DuNA1XMJxLPeS+4oFhxBY+XNqkonJCZ3aWg2EyJw
         zO/nZw568ZH3bZuTuAM5UMDb+AmxJM//bXs0W5WtyWkkTDyPI+QucP2iJjDmFSxE/2vJ
         p+ASo8Q0ae3PQSGDp/1Aj6ljY4sEGhhxR/cx2WZ2tV4Y74otqzF128vCOhQXbDFZVpuf
         bZdg==
X-Gm-Message-State: AJIora+qz/pSXMb4ZI27oP0KBb7GtRt5oDgk9kt2Q8vHXWOGxbU57OlG
	m/8pxhua1C7I99bkh1qJ6Vg=
X-Google-Smtp-Source: AGRyM1sZIkS/7CU+xpUfOkyWcfEaexhy6So9VjcyYdewn3EQNeDglgf/eXMpvl979VpMPr4myHDrPQ==
X-Received: by 2002:ac2:4f03:0:b0:47e:53ff:7da with SMTP id k3-20020ac24f03000000b0047e53ff07damr11754702lfr.449.1656427987839;
        Tue, 28 Jun 2022 07:53:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0c:b0:47f:9907:2b50 with SMTP id
 f12-20020a0565123b0c00b0047f99072b50ls193527lfv.3.gmail; Tue, 28 Jun 2022
 07:53:06 -0700 (PDT)
X-Received: by 2002:a05:6512:151e:b0:481:348b:100a with SMTP id bq30-20020a056512151e00b00481348b100amr1664060lfb.253.1656427986425;
        Tue, 28 Jun 2022 07:53:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656427986; cv=none;
        d=google.com; s=arc-20160816;
        b=G/GtFWz16rcA6/7kmDeX5IK4m1hJkBBJvIjiCU4rpIfwdGvJ0PfHmxJXtn7w+48p/Q
         M93qJDLNuH92an0rOkUfc3B2DEWMmXlsKz0S+sU/kv9OtJ3Cs1rK8B9hxtCvtV/60g5e
         QVBkFwcDwV4Nd73a9c2+toJmxE+zcKsz9hSvqLCB0eMgVIpDkMUNdOyQo84aREx0kL7K
         F0N7XVkMeywFxKCXiGRtjai5+9iTa9ysOxNgiLMkgUswDhWaWZGFMY+yVOlkvrEF/Jg9
         PUgdvLT5BwbesRG/JnvJSfppIX0PrvoWyUvUsTOEaAS52/gL0ig98KNtld3R4Nn88l5J
         buoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YTlupDxR0VuIlLuxHDuN5QQVbAsill4fsciLPt4itQQ=;
        b=WW33nRJK3GMlZdU0vpc/1qlGIngpeZohjdv2YRLrNOgJZgI5JHaPsyiD1p+5L7+PGi
         fOqRcbamkL8SYfRw6mBK2sn/u47DJcBUmmVor/0uOzmI+QvvsJ0ilLtj2E9FueRoVDYT
         rvN3oLIGcWBsoSygsVDL6xer3cmVMyOEcoj4M07PMPgHCb5jopJNfflDXybhSkWZF1qi
         TpsAoqNiszraxYCCd2csTUpdZ4PCYpvEgbY3Aokr3PMFEAU9aIUpXXTIJaUHAhIpPS9C
         3RQU3GVu1yN6h1oa6j9Bl4dUn/oYpsYX3I/JP8Eoo34WRv+JKT2o42jrVT34FTVsSu/B
         SqIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CK+v3yJg;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x135.google.com (mail-lf1-x135.google.com. [2a00:1450:4864:20::135])
        by gmr-mx.google.com with ESMTPS id k16-20020a0565123d9000b0047c62295117si580339lfv.8.2022.06.28.07.53.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 07:53:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::135 as permitted sender) client-ip=2a00:1450:4864:20::135;
Received: by mail-lf1-x135.google.com with SMTP id x3so22783492lfd.2
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 07:53:06 -0700 (PDT)
X-Received: by 2002:a05:6512:39ce:b0:481:31e4:1e06 with SMTP id
 k14-20020a05651239ce00b0048131e41e06mr2071928lfu.376.1656427985930; Tue, 28
 Jun 2022 07:53:05 -0700 (PDT)
MIME-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com> <20220628095833.2579903-12-elver@google.com>
In-Reply-To: <20220628095833.2579903-12-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jun 2022 16:52:54 +0200
Message-ID: <CACT4Y+Y+NRKVbL3E8ctrgWh0H4hyHLoZryXN8V-qyB0bCfA1Xw@mail.gmail.com>
Subject: Re: [PATCH v2 11/13] perf/hw_breakpoint: Introduce bp_slots_histogram
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
 header.i=@google.com header.s=20210112 header.b=CK+v3yJg;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::135
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
> Factor out the existing `atomic_t count[N]` into its own struct called
> 'bp_slots_histogram', to generalize and make its intent clearer in
> preparation of reusing elsewhere. The basic idea of bucketing "total
> uses of N slots" resembles a histogram, so calling it such seems most
> intuitive.
>
> No functional change.
>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
> v2:
> * New patch.
> ---
>  kernel/events/hw_breakpoint.c | 94 +++++++++++++++++++++++------------
>  1 file changed, 62 insertions(+), 32 deletions(-)
>
> diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> index 128ba3429223..18886f115abc 100644
> --- a/kernel/events/hw_breakpoint.c
> +++ b/kernel/events/hw_breakpoint.c
> @@ -36,19 +36,27 @@
>  #include <linux/slab.h>
>
>  /*
> - * Constraints data
> + * Datastructure to track the total uses of N slots across tasks or CPUs;
> + * bp_slots_histogram::count[N] is the number of assigned N+1 breakpoint slots.
>   */
> -struct bp_cpuinfo {
> -       /* Number of pinned cpu breakpoints in a cpu */
> -       unsigned int    cpu_pinned;
> -       /* tsk_pinned[n] is the number of tasks having n+1 breakpoints */
> +struct bp_slots_histogram {
>  #ifdef hw_breakpoint_slots
> -       atomic_t        tsk_pinned[hw_breakpoint_slots(0)];
> +       atomic_t count[hw_breakpoint_slots(0)];
>  #else
> -       atomic_t        *tsk_pinned;
> +       atomic_t *count;
>  #endif
>  };
>
> +/*
> + * Per-CPU constraints data.
> + */
> +struct bp_cpuinfo {
> +       /* Number of pinned CPU breakpoints in a CPU. */
> +       unsigned int                    cpu_pinned;
> +       /* Histogram of pinned task breakpoints in a CPU. */
> +       struct bp_slots_histogram       tsk_pinned;
> +};
> +
>  static DEFINE_PER_CPU(struct bp_cpuinfo, bp_cpuinfo[TYPE_MAX]);
>
>  static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
> @@ -159,6 +167,18 @@ static inline int hw_breakpoint_slots_cached(int type)
>         return __nr_bp_slots[type];
>  }
>
> +static __init bool
> +bp_slots_histogram_alloc(struct bp_slots_histogram *hist, enum bp_type_idx type)
> +{
> +       hist->count = kcalloc(hw_breakpoint_slots_cached(type), sizeof(*hist->count), GFP_KERNEL);
> +       return hist->count;
> +}
> +
> +static __init void bp_slots_histogram_free(struct bp_slots_histogram *hist)
> +{
> +       kfree(hist->count);
> +}
> +
>  static __init int init_breakpoint_slots(void)
>  {
>         int i, cpu, err_cpu;
> @@ -170,8 +190,7 @@ static __init int init_breakpoint_slots(void)
>                 for (i = 0; i < TYPE_MAX; i++) {
>                         struct bp_cpuinfo *info = get_bp_info(cpu, i);
>
> -                       info->tsk_pinned = kcalloc(__nr_bp_slots[i], sizeof(atomic_t), GFP_KERNEL);
> -                       if (!info->tsk_pinned)
> +                       if (!bp_slots_histogram_alloc(&info->tsk_pinned, i))
>                                 goto err;
>                 }
>         }
> @@ -180,7 +199,7 @@ static __init int init_breakpoint_slots(void)
>  err:
>         for_each_possible_cpu(err_cpu) {
>                 for (i = 0; i < TYPE_MAX; i++)
> -                       kfree(get_bp_info(err_cpu, i)->tsk_pinned);
> +                       bp_slots_histogram_free(&get_bp_info(err_cpu, i)->tsk_pinned);
>                 if (err_cpu == cpu)
>                         break;
>         }
> @@ -189,6 +208,34 @@ static __init int init_breakpoint_slots(void)
>  }
>  #endif
>
> +static inline void
> +bp_slots_histogram_add(struct bp_slots_histogram *hist, int old, int val)
> +{
> +       const int old_idx = old - 1;
> +       const int new_idx = old_idx + val;
> +
> +       if (old_idx >= 0)
> +               atomic_dec(&hist->count[old_idx]);
> +       if (new_idx >= 0)
> +               atomic_inc(&hist->count[new_idx]);
> +}
> +
> +static int
> +bp_slots_histogram_max(struct bp_slots_histogram *hist, enum bp_type_idx type)
> +{
> +       for (int i = hw_breakpoint_slots_cached(type) - 1; i >= 0; i--) {
> +               const int count = atomic_read(&hist->count[i]);
> +
> +               /* Catch unexpected writers; we want a stable snapshot. */
> +               ASSERT_EXCLUSIVE_WRITER(hist->count[i]);
> +               if (count > 0)
> +                       return i + 1;
> +               WARN(count < 0, "inconsistent breakpoint slots histogram");
> +       }
> +
> +       return 0;
> +}
> +
>  #ifndef hw_breakpoint_weight
>  static inline int hw_breakpoint_weight(struct perf_event *bp)
>  {
> @@ -205,13 +252,11 @@ static inline enum bp_type_idx find_slot_idx(u64 bp_type)
>  }
>
>  /*
> - * Report the maximum number of pinned breakpoints a task
> - * have in this cpu
> + * Return the maximum number of pinned breakpoints a task has in this CPU.
>   */
>  static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
>  {
> -       atomic_t *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
> -       int i;
> +       struct bp_slots_histogram *tsk_pinned = &get_bp_info(cpu, type)->tsk_pinned;
>
>         /*
>          * At this point we want to have acquired the bp_cpuinfo_sem as a
> @@ -219,14 +264,7 @@ static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
>          * toggle_bp_task_slot() to tsk_pinned, and we get a stable snapshot.
>          */
>         lockdep_assert_held_write(&bp_cpuinfo_sem);
> -
> -       for (i = hw_breakpoint_slots_cached(type) - 1; i >= 0; i--) {
> -               ASSERT_EXCLUSIVE_WRITER(tsk_pinned[i]); /* Catch unexpected writers. */
> -               if (atomic_read(&tsk_pinned[i]) > 0)
> -                       return i + 1;
> -       }
> -
> -       return 0;
> +       return bp_slots_histogram_max(tsk_pinned, type);
>  }
>
>  /*
> @@ -300,8 +338,7 @@ max_bp_pinned_slots(struct perf_event *bp, enum bp_type_idx type)
>  static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
>                                 enum bp_type_idx type, int weight)
>  {
> -       atomic_t *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
> -       int old_idx, new_idx;
> +       struct bp_slots_histogram *tsk_pinned = &get_bp_info(cpu, type)->tsk_pinned;
>
>         /*
>          * If bp->hw.target, tsk_pinned is only modified, but not used
> @@ -311,14 +348,7 @@ static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
>          * bp_cpuinfo_sem as a writer to stabilize tsk_pinned's value.
>          */
>         lockdep_assert_held_read(&bp_cpuinfo_sem);
> -
> -       old_idx = task_bp_pinned(cpu, bp, type) - 1;
> -       new_idx = old_idx + weight;
> -
> -       if (old_idx >= 0)
> -               atomic_dec(&tsk_pinned[old_idx]);
> -       if (new_idx >= 0)
> -               atomic_inc(&tsk_pinned[new_idx]);
> +       bp_slots_histogram_add(tsk_pinned, task_bp_pinned(cpu, bp, type), weight);
>  }
>
>  /*
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY%2BNRKVbL3E8ctrgWh0H4hyHLoZryXN8V-qyB0bCfA1Xw%40mail.gmail.com.
