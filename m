Return-Path: <kasan-dev+bncBCMIZB7QWENRBWV7Q6KQMGQEG7IK3EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 826E0544B14
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 13:56:11 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id a17-20020a2eb171000000b002556cda407asf4414411ljm.9
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 04:56:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654775771; cv=pass;
        d=google.com; s=arc-20160816;
        b=LO0unYLkwyEJGPezsLoMM99A0bnaNW+gl6suoCUOpxnP0ZUDF4kyURC/K+HnewVXkO
         fGC/zS0FPBPLA18RTqx9XsJRi8Uxa2vZKz61t9cTMAXppcK4Jco3aphZZlueyUmX1o75
         770TYqlW5BtRgoNx/wFVO4jO6TgI/xr56Cyj4r+c/D5i276XLgnAd7ekcB4YRPf9RWWa
         csrGGHgQQpE6RDHC2VlOpvFz48oCS5INMkjXGZOe5OJE+vopy8HGhZiol/hYfwWy8aHU
         6WWd3c4HOEykEraEI7CuAFeX1cUfekjlekM5ymtJ8m+F7P/Q3MegwY7+GKMiknaopyvn
         /HIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=CpX1R4UmV2WPDXyP19j/ipqozJ5BYlDRZg3P9rRUf58=;
        b=kEDwGixXpdkHhsr6zqUDC4vQ+604JsrL/VoOUQ7fJn5Kg2VuyqE+GTBqhJgbrhmrW5
         aEUESprIzKgP3vW1+Z9cU6Sa1y7KtrkuQhzjYt24mSTOwvDG/ZI++EoO1oruroJUyE0b
         QQMqkOrHUNQB+gLYdulZy+H5ZciPuT3t2l/UM4Jwo8w+VdA6ouc0rLCyz29FdV7pgkIO
         VjcodgECB6zPql4rnLe0FX7hPXVAVulIX1L02jjo/mK4SRU98PQ2JBf+Yt03cWEL53kW
         3qaYtqkDpUuxgm0FzgzwXaEHbONzETBc8oaoyAgdJSUTCpi+zhAFqs/AtPh73OLzHy5g
         13AQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F2mY2Kyj;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CpX1R4UmV2WPDXyP19j/ipqozJ5BYlDRZg3P9rRUf58=;
        b=cOA5/MGY5XWNR2ZsE5w16xlwVnSjeipkimf7FChkk40wrAzd73DeNUNy+RkM50iP1x
         N4Va1rpU3rlLGYsQu9o06MZljLEUAdUYjky2AQG/TWQ/BtUtkY8MaYsoCkjgaD6wdM/f
         CONp1JmJfvoi5B9XLREWS8pUmFLKak8xYzEpYrH/hfwqwN2r3F79GWz3OplvffVj1PcR
         EdYgIcC1jABG+71ntTvtjzmnVLGF3OjDBIVqogFUyKvTNVAaEeHS1tXF5gFrt7os4tFs
         jo6Srzht8k0AgFJy3qUZLBE8O8Iyea/vORcmwV5+T0XF7lB5VG8+EAgIDRan+iKZyimv
         du8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CpX1R4UmV2WPDXyP19j/ipqozJ5BYlDRZg3P9rRUf58=;
        b=Q80sXT4sNXAKDBdBOK//ImmUne4QD8e3PCcyziGfD9OVuPLuSuDtPmWLJydpL21f0G
         M3VdVevDOdTliBTHqG91VaARUwIPtZMHsJpg6pI5HlkO9llbZK36ztc+xpsKfB/HskT9
         E8VhazNcEvol7WGgHtNYvfwlyE7KrNdVUFSTvG2KASyU27KvxOC/j68ciLcv3ZQhfoHH
         qW2+iVYdrBlY08rh7XpjFRxfNl7vXN51pbxWPMUV63QauyjuKRBBrlWJxpYpXlFZHsAK
         QntSLA7vLJ64KFO764OefhY7Dwm8l91/cTS4wBEOJKZFb83K9xCeRcUbOWHJ4YJjU3Tx
         fsOQ==
X-Gm-Message-State: AOAM531JcD7QT62DehOVsyAEboMvO0iTG831EK/y/rtoe8HBWEfY99kd
	IlQCYdvQGVgJw8/ezAWz8MA=
X-Google-Smtp-Source: ABdhPJwg7ErKAT6KaiQMKL/QA+S32o2R+moRNjzwxxVS6q8C0bkL18UtKD3k9yJHDBr3tjInMvOnwQ==
X-Received: by 2002:a05:6512:400a:b0:479:9ed:a71b with SMTP id br10-20020a056512400a00b0047909eda71bmr25495392lfb.488.1654775770993;
        Thu, 09 Jun 2022 04:56:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls4148lfu.0.gmail; Thu, 09 Jun 2022
 04:56:09 -0700 (PDT)
X-Received: by 2002:a05:6512:3130:b0:479:385f:e2ac with SMTP id p16-20020a056512313000b00479385fe2acmr14206815lfd.575.1654775769814;
        Thu, 09 Jun 2022 04:56:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654775769; cv=none;
        d=google.com; s=arc-20160816;
        b=LyonNmSZL36phqu8vyHARlwYXk5n9XUrNSC6VyBu+7JnSRoDa3Hgq20Uxf5ATGayH1
         j53PripdEIMphCNT5g8NvKOq93FvQOYJYoeMlPSKUvWSHYmA8sDTkTvyDX4Vv6t8h8Cz
         uEcKp4g1X3GmC6NGPDghn+HDA1p5P6K8TpwgvffLB7KN/V0kqE2NLRep4/rtIULFTbwW
         w68qy4uGbIh7NTvYnwy1jOTt5jNjx1+vT30rBHAsQwyhSuMl0djghNyQWGMcqX38ngfo
         pFZ4tuMJlhHb9QUMfXdA+OM5urv+ARSGrJ/kvg/wylL9D0PVuftbsMuxRM3AuE5RhVD6
         lsUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WY4HD3Pbrvr9rNcNT3QthTekyAgPVjpj/oQPb25t2us=;
        b=dgs160QFmQCGsXbu7qZp97MpGBlHHbahqFI7lboVpT9NDJMuHdXeOfNGztHjEYn+fD
         IHjd5O/PSldB8/mwXiYKZT9OC8fv6k5Z405MopeVOHog2BYwqqTGW4gPk9fCNMsEnbcO
         vKLsf52oxVc3KY+xMa7kz5hNxEznTqrYi6gEa9bwpVXFU7nQbhMSRvbtqR67z47BjEn/
         b6vEg3oau17pJr8aKaxfGycXhKbmCIn1kQ9Cw/T5Cq0WPyln9sI1dJLKxAFQoPlqbN1n
         rcv42qc1GgeYCH5o4thMivSdUjwJVJbsDhCNXnlTeFLCVoSVYa8Qk6XNBngGBp1OZ65R
         bvJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F2mY2Kyj;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x135.google.com (mail-lf1-x135.google.com. [2a00:1450:4864:20::135])
        by gmr-mx.google.com with ESMTPS id d31-20020a0565123d1f00b00479321d8077si712041lfv.3.2022.06.09.04.56.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 04:56:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::135 as permitted sender) client-ip=2a00:1450:4864:20::135;
Received: by mail-lf1-x135.google.com with SMTP id h23so37609111lfe.4
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 04:56:09 -0700 (PDT)
X-Received: by 2002:a05:6512:3d0:b0:478:9aca:4a06 with SMTP id
 w16-20020a05651203d000b004789aca4a06mr24033399lfp.410.1654775769284; Thu, 09
 Jun 2022 04:56:09 -0700 (PDT)
MIME-Version: 1.0
References: <20220609113046.780504-1-elver@google.com> <20220609113046.780504-4-elver@google.com>
In-Reply-To: <20220609113046.780504-4-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jun 2022 13:55:57 +0200
Message-ID: <CACT4Y+YhFT3wwtbjdjmBs5wKYjF3DOmH=AoP0Qq5bb6DAGHZxA@mail.gmail.com>
Subject: Re: [PATCH 3/8] perf/hw_breakpoint: Optimize constant number of
 breakpoint slots
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
 header.i=@google.com header.s=20210112 header.b=F2mY2Kyj;       spf=pass
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

On Thu, 9 Jun 2022 at 13:31, Marco Elver <elver@google.com> wrote:
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

Acked-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  arch/sh/include/asm/hw_breakpoint.h  |  5 +-
>  arch/x86/include/asm/hw_breakpoint.h |  5 +-
>  kernel/events/hw_breakpoint.c        | 92 ++++++++++++++++++----------
>  3 files changed, 62 insertions(+), 40 deletions(-)
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
> index 1f718745d569..8e939723f27d 100644
> --- a/kernel/events/hw_breakpoint.c
> +++ b/kernel/events/hw_breakpoint.c
> @@ -41,13 +41,16 @@ struct bp_cpuinfo {
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
> @@ -74,6 +77,54 @@ struct bp_busy_slots {
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
> @@ -96,7 +147,7 @@ static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
>         unsigned int *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
>         int i;
>
> -       for (i = nr_slots[type] - 1; i >= 0; i--) {
> +       for (i = hw_breakpoint_slots_cached(type) - 1; i >= 0; i--) {
>                 if (tsk_pinned[i] > 0)
>                         return i + 1;
>         }
> @@ -313,7 +364,7 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
>         fetch_this_slot(&slots, weight);
>
>         /* Flexible counters need to keep at least one slot */
> -       if (slots.pinned + (!!slots.flexible) > nr_slots[type])
> +       if (slots.pinned + (!!slots.flexible) > hw_breakpoint_slots_cached(type))
>                 return -ENOSPC;
>
>         ret = arch_reserve_bp_slot(bp);
> @@ -688,42 +739,19 @@ static struct pmu perf_breakpoint = {
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
> 2.36.1.255.ge46751e96f-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYhFT3wwtbjdjmBs5wKYjF3DOmH%3DAoP0Qq5bb6DAGHZxA%40mail.gmail.com.
