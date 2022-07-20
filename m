Return-Path: <kasan-dev+bncBDPPFIEASMFBB6574CLAMGQEWBEFRFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 7AF0B57B9AD
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 17:32:11 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id w13-20020a05640234cd00b0043a991fb3f3sf12257777edc.3
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 08:32:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658331131; cv=pass;
        d=google.com; s=arc-20160816;
        b=w9oaH57qGKSxhgBeQp0R3PFFFMYk7ERGtU7AEnwKOow47MatPNo02tHOmlU2YICEw3
         nndhkwt+RPvjEMlgPEqkApNCO37GljKDw0V/TeAZB6bl/D2e/M0/GfzR20cxQ+RLwdGb
         7HrAVHVsc/F1ZaH4gR9oZsbQBWsIWmJ0tussQk673vqiKiP2WC2Hlm0aEv2b8cEh5cUH
         iUaPzBrrSYRMIe41mYVogDKQjgKhYfI72jfVPVvOaibo9FcNJBPd/nwMrLQoAXDX+XMs
         q4TksjqoqUxBphBu+nP9dGYvuiP5UwkXBt3ZxmUpebDPGAZMPxYyKsPCniH+wxow87pe
         17Wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dpewG1kocPfiPi3cuyAfihkpModbsIpczWI8gfl8cMI=;
        b=mwtyION02phW5mKBu793txuSBnvr6HxIdufVDlGVpwXJPsgH9UE9xi1I2zK9mDI1XT
         PRR9S9E5R5OopFjsJDM11g1uTEd/blcgUWopY7cDAk5sFWQVRm9QVDaU2jRzls1LrlR0
         0CninxUdeFtjpko5P++NEULm6ahv1sq7iEsic/z+xZp/RqAp9IQMicXKFpa+F2LXxl2o
         Mx+mIVOGUs9KC+lH4tT0bEl6eKguuANVRgRk+Lq0EhCKSIx/t+SZO256Q8IJfummy0Mo
         4dCUzdWK6U2MnEXUL+hnvV9eodcKn2vTzU8u2KYe5UnUlH6kaGTOjrTO53KbVSZJcqJE
         rAvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dbCH1rMV;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dpewG1kocPfiPi3cuyAfihkpModbsIpczWI8gfl8cMI=;
        b=iw71xatJFSu6Z9uUSnyAXvO5VTcQ3oqd7HIazUqZooLw1mTlrkuQPLQIuj7N3AzECi
         nZRjeNnPGRtTJup9jMd7xQObDsMRpBuQtCzKq0YEXQ/qDcufbL/duVxuUIpR2tl2RH4i
         IMAuIhSODMDXfzSOut9kfU9JRy0tc8WvdXrHaB4RmKrsEXWFkZtG/qXm7fxzjRTnCnVD
         AFVhmpw2/h1XQjmtpKdb7xIPHSrl1cIT6AUOzpQX9WsWOsgy/hIOfDpu/8VKadPB30sW
         MHFTNMQCHwt1zmZUHr4VBJoMvMzr7Mrhnui3hZf7qeMeST5N7c7YONQEvXdsnIh5dU2B
         y8YA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dpewG1kocPfiPi3cuyAfihkpModbsIpczWI8gfl8cMI=;
        b=Yd0uQZ1uLpwHfi8if9WHjwK1fiZJkC9qCQk8VKp1JFmyB3vD+E6FmcjBaY5x7rvzqu
         1GCsiPPOe4/Pq2EgVW+oKim/+VntOmbhCGBBwqJIu1JrEjGtpG2LrcfKpXNP6Gooxp0P
         zQEC4JMkFbRfUAW5g7sPzzkz36DQQgEmqxoicgnqu+EGroGEyEJ47g5Cu6qtWJbswLoZ
         w9i/u2Eif7sE/7z9aXEn+/5CFCQrdjy5RBSqlqkWG+8DXdy4bpwy2EOKnXaKZKe6KOO7
         PyxGkvqQFBzZK6lkCJXWv3BDP/wKDjyPfnIIn8JAYdgmsS8bdksOkfVS/pEfSqDczS33
         OI0Q==
X-Gm-Message-State: AJIora/HB0v4ynIDd9kStYZGi5T5cAgXQVX9IbSfjDsbewZnHYU3hsV7
	ues8P/wDAuWjais/8+UUHhU=
X-Google-Smtp-Source: AGRyM1tbT7XIgncYRNyrGACA2TXngTMFHSEboguLbf4y9+Ckj7mc6bw468WC46K+K45Q5MMrKtJAYg==
X-Received: by 2002:a17:907:60c6:b0:72f:2e3b:ead6 with SMTP id hv6-20020a17090760c600b0072f2e3bead6mr15541440ejc.664.1658331131313;
        Wed, 20 Jul 2022 08:32:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:d0e:b0:425:ff69:1a2d with SMTP id
 eb14-20020a0564020d0e00b00425ff691a2dls97916edb.1.-pod-prod-gmail; Wed, 20
 Jul 2022 08:32:10 -0700 (PDT)
X-Received: by 2002:a05:6402:1d53:b0:43a:9ba7:315b with SMTP id dz19-20020a0564021d5300b0043a9ba7315bmr51975514edb.350.1658331130285;
        Wed, 20 Jul 2022 08:32:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658331130; cv=none;
        d=google.com; s=arc-20160816;
        b=Rx2SY2alHc0pUqUEZcGn6WWLQo22dhjlR7dv24iLKdJ5Xst4AwS66SzG1rg+VyUO35
         5yZhVTVz0AJ8J+jP7u9+V7yz5wOZ8MqLrkDx9gGr9YWSM8FLoE/Vqhw1sC7bq7lDfL53
         WGcSnIi+fpF1RUz1AxrXdsgsMsCoAO/bndHEB429lwmYtZCYZyAYcF1jvlOhNe/ZTOb/
         8Rs/SseGw7oyLFKDve/dK3GR4hQ+h3w9tAXknHGlVDiC+WMPKOb/sR9JiYjUdP/R3e2n
         q88RObOghFBz7XLEAASocpPxsQKyUcz9GJEzTb5LeNARUy/US1VE4vbYgzH47YyAjyEF
         4phQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MOe56Pal9wpMnCknu1sB4FBOOVOLYGu0YQCW9drNE6o=;
        b=Wmk7o00a7BvlENb0v6ECs0Rnxm01MLtJJxJXGMbmi5pw4+HZN8vasqPd8gI5jwC8o/
         xLPZye/Hd/FMnGHSMo5e8qA5Y/fRppt6uPGN7+lBRZh5px0VSrnwCzYqsCe+9+4SlzYk
         GbgcVHgTm7NlJJy05EkHufyt49DpyqVSH8MuO7lCKHxFe5Z8bBo1YodeAT5rT16wPW6B
         vvCZelzVvT6yij5mUQEd5qeT8azOda2xUaQBgDY67BiIlnqL+yhMKG28enspeLrRA3HN
         MehS15aE5o4RSRKEOkT+Bak/C3BarSINmp3p7AVXAvrwJqh5lLVX2Pnc6hR73XV2n7C2
         sxiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dbCH1rMV;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id n26-20020aa7c45a000000b004359bd2b6c9si539634edr.3.2022.07.20.08.32.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Jul 2022 08:32:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id h9so1569203wrm.0
        for <kasan-dev@googlegroups.com>; Wed, 20 Jul 2022 08:32:10 -0700 (PDT)
X-Received: by 2002:a05:6000:8e:b0:21d:7e97:67ed with SMTP id
 m14-20020a056000008e00b0021d7e9767edmr30049803wrx.343.1658331129763; Wed, 20
 Jul 2022 08:32:09 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-7-elver@google.com>
In-Reply-To: <20220704150514.48816-7-elver@google.com>
From: "'Ian Rogers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Jul 2022 08:31:57 -0700
Message-ID: <CAP-5=fV_maSd0k_WCzxgToN1SYG+XHg0KpTe1m2CTJTT9+KM+w@mail.gmail.com>
Subject: Re: [PATCH v3 06/14] perf/hw_breakpoint: Optimize constant number of
 breakpoint slots
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
 header.i=@google.com header.s=20210112 header.b=dbCH1rMV;       spf=pass
 (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::42d
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
> Optimize internal hw_breakpoint state if the architecture's number of
> breakpoint slots is constant. This avoids several kmalloc() calls and
> potentially unnecessary failures if the allocations fail, as well as
> subtly improves code generation and cache locality.
>
> The protocol is that if an architecture defines hw_breakpoint_slots via
> the preprocessor, it must be constant and the same for all types.
>
> Signed-off-by: Marco Elver <elver@google.com>
> Acked-by: Dmitry Vyukov <dvyukov@google.com>

Acked-by: Ian Rogers <irogers@google.com>

Thanks,
Ian

> ---
>  arch/sh/include/asm/hw_breakpoint.h  |  5 +-
>  arch/x86/include/asm/hw_breakpoint.h |  5 +-
>  kernel/events/hw_breakpoint.c        | 94 ++++++++++++++++++----------
>  3 files changed, 63 insertions(+), 41 deletions(-)
>
> diff --git a/arch/sh/include/asm/hw_breakpoint.h b/arch/sh/include/asm/hw_breakpoint.h
> index 199d17b765f2..361a0f57bdeb 100644
> --- a/arch/sh/include/asm/hw_breakpoint.h
> +++ b/arch/sh/include/asm/hw_breakpoint.h
> @@ -48,10 +48,7 @@ struct pmu;
>  /* Maximum number of UBC channels */
>  #define HBP_NUM                2
>
> -static inline int hw_breakpoint_slots(int type)
> -{
> -       return HBP_NUM;
> -}
> +#define hw_breakpoint_slots(type) (HBP_NUM)
>
>  /* arch/sh/kernel/hw_breakpoint.c */
>  extern int arch_check_bp_in_kernelspace(struct arch_hw_breakpoint *hw);
> diff --git a/arch/x86/include/asm/hw_breakpoint.h b/arch/x86/include/asm/hw_breakpoint.h
> index a1f0e90d0818..0bc931cd0698 100644
> --- a/arch/x86/include/asm/hw_breakpoint.h
> +++ b/arch/x86/include/asm/hw_breakpoint.h
> @@ -44,10 +44,7 @@ struct arch_hw_breakpoint {
>  /* Total number of available HW breakpoint registers */
>  #define HBP_NUM 4
>
> -static inline int hw_breakpoint_slots(int type)
> -{
> -       return HBP_NUM;
> -}
> +#define hw_breakpoint_slots(type) (HBP_NUM)
>
>  struct perf_event_attr;
>  struct perf_event;
> diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> index 7df46b276452..9fb66d358d81 100644
> --- a/kernel/events/hw_breakpoint.c
> +++ b/kernel/events/hw_breakpoint.c
> @@ -40,13 +40,16 @@ struct bp_cpuinfo {
>         /* Number of pinned cpu breakpoints in a cpu */
>         unsigned int    cpu_pinned;
>         /* tsk_pinned[n] is the number of tasks having n+1 breakpoints */
> +#ifdef hw_breakpoint_slots
> +       unsigned int    tsk_pinned[hw_breakpoint_slots(0)];
> +#else
>         unsigned int    *tsk_pinned;
> +#endif
>         /* Number of non-pinned cpu/task breakpoints in a cpu */
>         unsigned int    flexible; /* XXX: placeholder, see fetch_this_slot() */
>  };
>
>  static DEFINE_PER_CPU(struct bp_cpuinfo, bp_cpuinfo[TYPE_MAX]);
> -static int nr_slots[TYPE_MAX] __ro_after_init;
>
>  static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
>  {
> @@ -73,6 +76,54 @@ struct bp_busy_slots {
>  /* Serialize accesses to the above constraints */
>  static DEFINE_MUTEX(nr_bp_mutex);
>
> +#ifdef hw_breakpoint_slots
> +/*
> + * Number of breakpoint slots is constant, and the same for all types.
> + */
> +static_assert(hw_breakpoint_slots(TYPE_INST) == hw_breakpoint_slots(TYPE_DATA));
> +static inline int hw_breakpoint_slots_cached(int type) { return hw_breakpoint_slots(type); }
> +static inline int init_breakpoint_slots(void)          { return 0; }
> +#else
> +/*
> + * Dynamic number of breakpoint slots.
> + */
> +static int __nr_bp_slots[TYPE_MAX] __ro_after_init;
> +
> +static inline int hw_breakpoint_slots_cached(int type)
> +{
> +       return __nr_bp_slots[type];
> +}
> +
> +static __init int init_breakpoint_slots(void)
> +{
> +       int i, cpu, err_cpu;
> +
> +       for (i = 0; i < TYPE_MAX; i++)
> +               __nr_bp_slots[i] = hw_breakpoint_slots(i);
> +
> +       for_each_possible_cpu(cpu) {
> +               for (i = 0; i < TYPE_MAX; i++) {
> +                       struct bp_cpuinfo *info = get_bp_info(cpu, i);
> +
> +                       info->tsk_pinned = kcalloc(__nr_bp_slots[i], sizeof(int), GFP_KERNEL);
> +                       if (!info->tsk_pinned)
> +                               goto err;
> +               }
> +       }
> +
> +       return 0;
> +err:
> +       for_each_possible_cpu(err_cpu) {
> +               for (i = 0; i < TYPE_MAX; i++)
> +                       kfree(get_bp_info(err_cpu, i)->tsk_pinned);
> +               if (err_cpu == cpu)
> +                       break;
> +       }
> +
> +       return -ENOMEM;
> +}
> +#endif
> +
>  __weak int hw_breakpoint_weight(struct perf_event *bp)
>  {
>         return 1;
> @@ -95,7 +146,7 @@ static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
>         unsigned int *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
>         int i;
>
> -       for (i = nr_slots[type] - 1; i >= 0; i--) {
> +       for (i = hw_breakpoint_slots_cached(type) - 1; i >= 0; i--) {
>                 if (tsk_pinned[i] > 0)
>                         return i + 1;
>         }
> @@ -312,7 +363,7 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
>         fetch_this_slot(&slots, weight);
>
>         /* Flexible counters need to keep at least one slot */
> -       if (slots.pinned + (!!slots.flexible) > nr_slots[type])
> +       if (slots.pinned + (!!slots.flexible) > hw_breakpoint_slots_cached(type))
>                 return -ENOSPC;
>
>         ret = arch_reserve_bp_slot(bp);
> @@ -632,7 +683,7 @@ bool hw_breakpoint_is_used(void)
>                         if (info->cpu_pinned)
>                                 return true;
>
> -                       for (int slot = 0; slot < nr_slots[type]; ++slot) {
> +                       for (int slot = 0; slot < hw_breakpoint_slots_cached(type); ++slot) {
>                                 if (info->tsk_pinned[slot])
>                                         return true;
>                         }
> @@ -716,42 +767,19 @@ static struct pmu perf_breakpoint = {
>
>  int __init init_hw_breakpoint(void)
>  {
> -       int cpu, err_cpu;
> -       int i, ret;
> -
> -       for (i = 0; i < TYPE_MAX; i++)
> -               nr_slots[i] = hw_breakpoint_slots(i);
> -
> -       for_each_possible_cpu(cpu) {
> -               for (i = 0; i < TYPE_MAX; i++) {
> -                       struct bp_cpuinfo *info = get_bp_info(cpu, i);
> -
> -                       info->tsk_pinned = kcalloc(nr_slots[i], sizeof(int),
> -                                                       GFP_KERNEL);
> -                       if (!info->tsk_pinned) {
> -                               ret = -ENOMEM;
> -                               goto err;
> -                       }
> -               }
> -       }
> +       int ret;
>
>         ret = rhltable_init(&task_bps_ht, &task_bps_ht_params);
>         if (ret)
> -               goto err;
> +               return ret;
> +
> +       ret = init_breakpoint_slots();
> +       if (ret)
> +               return ret;
>
>         constraints_initialized = true;
>
>         perf_pmu_register(&perf_breakpoint, "breakpoint", PERF_TYPE_BREAKPOINT);
>
>         return register_die_notifier(&hw_breakpoint_exceptions_nb);
> -
> -err:
> -       for_each_possible_cpu(err_cpu) {
> -               for (i = 0; i < TYPE_MAX; i++)
> -                       kfree(get_bp_info(err_cpu, i)->tsk_pinned);
> -               if (err_cpu == cpu)
> -                       break;
> -       }
> -
> -       return ret;
>  }
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAP-5%3DfV_maSd0k_WCzxgToN1SYG%2BXHg0KpTe1m2CTJTT9%2BKM%2Bw%40mail.gmail.com.
