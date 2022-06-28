Return-Path: <kasan-dev+bncBCMIZB7QWENRBRX75OKQMGQEPY4C4UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D97855D7D3
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 15:19:03 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id e8-20020ac24e08000000b0047fad5770d2sf6255157lfr.17
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 06:19:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656422343; cv=pass;
        d=google.com; s=arc-20160816;
        b=LtXzsnk5SGrWIIG3/Kt+u4NOXieIQQoz9XExg9Y5ixLf1iAg15kew6tB9RFS/lLgqO
         P/pnTM8R2bwwmgEsfTQQhRy6mzsuOnY5nm8vZcyrN+5tbLvlk8F0oQaUtvqIudPMKpsB
         kn+Qtks6o6sxl3y6E0CsjnP3E0hFO+yINyxUvkUN2Cv1kZd0J7xfZCk+CV3r89OHNiHL
         fL0ZNnofcF9295EbofRKDenjcCtU5Fh086VEe1+uaLJ6R4IK3Ird/hPc4tfukflByjJV
         qvtk6uCFnwdsL2zULPhQjzmoy4b0XK7XChi4hnk6qzh1mwvd4MMrC6F5K+1VypDCP7Ht
         OL0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gi4Gou+QaO9smZv+npyd1IiVPsosPd4ojyxAlhu41nQ=;
        b=Y1efJcp3u6h/iwpS+JRoqCRxZRw0uv4s3cJviBmJIMmRFmjM3QXYFNWjzI7AW8i4yB
         B0u1sA/fg5p+UH3Q0gPU3yFqOIbZgRlmMRe0vFTPvsA/jrHnpawwsRVDxPUXTlrZJqUX
         kHwTYiOOLfa4QM3x1AbXrMXrjZWrjaisi9as9O2yWK7cVnMsDTcwrWygC8cj56Pcw8dK
         GQO2Biv+ubC/vRlXsz6ol1L+j8O/8AI52m9XTr5Gxxwri0RmxFJ6slLyKW8ju0v+zhd1
         13suaP4VtHsgvBakGhhfS1NB80729ZmW27kf5BvT+cZKExUpSCQHO4Bs4u8S594P+YL7
         EJkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=R8forfur;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gi4Gou+QaO9smZv+npyd1IiVPsosPd4ojyxAlhu41nQ=;
        b=UDpJ2sWkDIOQR6wy3IPY/cD23Oez6Y8nIAL67h/fw3lmt55uud8zdtOirvHm5rL1qR
         ZgqcERoIgw33xasThavDt1juARW0QlyiJE0b0OSCYIHFiv29N28XMnEfTDSV1G4NKa+Y
         cYJ0+7zkz2wosiuRr/ZVnCI/EtEHyzWUvDeSMm9LIDwr1AfbK3j0YZD5cLmYlSlvlhiG
         GLZG0c0jPBalQ2kPw6NRNVJ81g8NSk6GDNaNWSqF1XJTly5gvx/zKAMjn5R2ydiA+OxS
         LCMlH/pwdJb45g5yG40Gcu9q6XOBlXaryKOvDxE4/hQdq/Bi9SbE/HDSVOF8xUTsAyyu
         JmkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gi4Gou+QaO9smZv+npyd1IiVPsosPd4ojyxAlhu41nQ=;
        b=7BPQeG7zY/xDZC3i5FqtU6hpf7eDYNXaNIJSs1omdGywmG6W4yKGH9Y1lW1xnsNDQx
         tkiPr0RqF2A16sl9+fdFwuHRtDTEF6gbll84yRHJTyBii/8gX9+HTZSy7v/IDiI+GV45
         1i1ZMhtfxtbffk0ImeWsNlTvtCdA+FX4Npmnnt78xUL70k7ahduj5Won1lnl/q5xYYBo
         iNIATDzMe2tJV2SHvq21lkqkjafQuTWiv1d5Ltn4wpan3T/Jy3VtrKifvVpwDa94gq0j
         U34VH6Krl1i1nqu5iou9akLp/jpsYmSnlfJYp9PIGe4WeWw8rmzNtGwAPpfK78O6C2io
         z05A==
X-Gm-Message-State: AJIora/CS9PmK6P2eY7/9CqIrfYNck/WasSsLjDT2Fc/fNulQlyqlDvJ
	4dFqvl0R5jdM3ODhyZhSqkE=
X-Google-Smtp-Source: AGRyM1ux2hJWXFXFi8omIfhZ4PcDxNh0eEwsqSzkbU0k4aqfuH+Xr3GCECES/4FvNpQe2Vi+9VtL+g==
X-Received: by 2002:a05:6512:25a3:b0:481:25b8:51b5 with SMTP id bf35-20020a05651225a300b0048125b851b5mr3242528lfb.472.1656422343010;
        Tue, 28 Jun 2022 06:19:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0c:b0:47f:9907:2b50 with SMTP id
 f12-20020a0565123b0c00b0047f99072b50ls737108lfv.3.gmail; Tue, 28 Jun 2022
 06:19:02 -0700 (PDT)
X-Received: by 2002:a05:6512:1291:b0:47f:6ece:310e with SMTP id u17-20020a056512129100b0047f6ece310emr11595182lfs.389.1656422341909;
        Tue, 28 Jun 2022 06:19:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656422341; cv=none;
        d=google.com; s=arc-20160816;
        b=IlgX+ykjLpjDYzfbyrOftX/+uCrux7ugj1lcbBriE6QEVlI+GOdUxdfubo14okSjZ4
         aATB4Zdw+QQh8CFHa3wIpimOUFJXhTyCPKR0h/LNjO+UjgDywlaTj4Jg9dBF1r2z4NYK
         E3PE2Zh12YEjemwSY1CHPrsT7rahDwXyS5z3v17RJ9fB34ryWyfIytx1ZKnsdI5tqY/u
         Mg/G6gljH5l6Q41YrDU5/29olz7R8pcmYMmzV/W7kQY886lIFxu+xAQ/temPxS3WpoqQ
         rBpptyBT1IpMYWE1nvUOIfGGt1+tA/J1/qusVCZmZ8qLvAyibE4eJOiDr1nyhS1zXauH
         bIoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7CgIFPap6ypTTXSUzce/TyUpcucDj1PHP0T/IiacRoQ=;
        b=MjnSHnLLXjil6qeXbT/H3u1T0lC3MEDaPHcdOwUO60qiS5g49XiVRaF9papvxp8M5M
         WFWnBTrcwt9WLNpT0Fis4gXD5cJszYv4uWVpYPdWoRT9bbJe9CGk8SCt7FqQliIMo413
         /Jsg+2Lj5KwczYtFviTazUkki1w9lVbKCSyB73tcIie1GCKTxzoSgjkVCjCeYLDhScMe
         dM3FkGfAzlvebWcSWMTyHOMeRwrQCohJ//2uIzl3irgYfJE2Unnn98ZGTKXcdpnqpTmd
         wuL0JGRCjRklzA21rfV/7bgkh1nKom6770aAAJR4MLsa6+/0b2vqEn0EgZWKGuYozGam
         z6SQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=R8forfur;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x22c.google.com (mail-lj1-x22c.google.com. [2a00:1450:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id c38-20020a05651223a600b004811cb1ed75si232885lfv.13.2022.06.28.06.19.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 06:19:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22c as permitted sender) client-ip=2a00:1450:4864:20::22c;
Received: by mail-lj1-x22c.google.com with SMTP id b23so14858003ljh.7
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 06:19:01 -0700 (PDT)
X-Received: by 2002:a2e:9004:0:b0:25a:6dee:4ae2 with SMTP id
 h4-20020a2e9004000000b0025a6dee4ae2mr9881452ljg.33.1656422341451; Tue, 28 Jun
 2022 06:19:01 -0700 (PDT)
MIME-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com> <20220628095833.2579903-8-elver@google.com>
In-Reply-To: <20220628095833.2579903-8-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jun 2022 15:18:49 +0200
Message-ID: <CACT4Y+aqRgBpuah8Ab3E134cCBimAmW2kUpJ7rR-e95HpS4aFg@mail.gmail.com>
Subject: Re: [PATCH v2 07/13] perf/hw_breakpoint: Remove useless code related
 to flexible breakpoints
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
 header.i=@google.com header.s=20210112 header.b=R8forfur;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22c
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

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
> v2:
> * Also remove struct bp_busy_slots, and simplify functions.
> ---
>  kernel/events/hw_breakpoint.c | 57 +++++++++++------------------------
>  1 file changed, 17 insertions(+), 40 deletions(-)
>
> diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> index a124786e3ade..63e39dc836bd 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaqRgBpuah8Ab3E134cCBimAmW2kUpJ7rR-e95HpS4aFg%40mail.gmail.com.
