Return-Path: <kasan-dev+bncBDPPFIEASMFBBRWB4CLAMGQEH33ORLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C50457BA4F
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 17:35:34 +0200 (CEST)
Received: by mail-ej1-x63f.google.com with SMTP id ji2-20020a170907980200b0072b5b6d60c2sf4262266ejc.22
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 08:35:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658331334; cv=pass;
        d=google.com; s=arc-20160816;
        b=DCrR5L8+4s3YHVaJ01FRAd0zaO1hGZRuGCKqGIjnC4+Is6xLNTBgG0H9230zKIipBs
         f7YBfhMOPvj5fnXRJP9Nqj3AVPea5z2Lfdslml23o01R4ElYaDYGweZdlGujhj9Cr8I6
         0wd7tcYgz41pTdugKaue5jghB2+9RiFclBG2E5azaqyfXwdW12UcFsq2yJV42Po8H+NM
         gGHbnNctI6rVnfziQ8ZkZ6P5C1/ea5pnPBHWIKQeWec70GRwE/iQKtYHkz1lv/qOAZi7
         rCBI5alMoYInJV23DKu5nCeKN99AEjOuKiH0n74j2SOPuEqjol/1Fv5xT74pcx0+JRZZ
         dCaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=XsqftASK0G5puGwJhzEICddNqG2el5R6hZC2vQm4FYw=;
        b=W8TcH4JjCvHJdLvfKaLW84cDAUmnypEvxTnzSjlNDvZnnlCmSotLDPAXE99K0je6xB
         Z4J2upiKzGNr/flwfbXi01tx5ilojoEZZAP4r4iC3VDbbsbN0UQXkd50WX+lz5SoSsCC
         jllCR16aS0pj9JPE3IjWfzeWmSokH9No0fvYuwPbNrCjy7O/VikUvY1P2VFaqiT806M1
         gT1AhclZcDZ2a1AmChfJiQQE0PVx+zHb3+qATREn//IXnVITLxqUnPuaXu0DRJ6buwAT
         iCVbHTZ6fQnZwnnPQfijs6Nf5lNay0Fg9xSpIhqTtU01v3g2pMeKj0H1PAa+w8QTh9lD
         YnYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=f1+SWiW7;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XsqftASK0G5puGwJhzEICddNqG2el5R6hZC2vQm4FYw=;
        b=pkJGtyqEBa3RM2eVIF7oqgCzbTzfz1PfejVd/4IJ+bGFewkd7VgmlONeJkyvY1JQaY
         clZeHjmmLEsM5mysgrKyjWrCAzaUtrlf05D1EPhMZPVCKGMKkd63BGEqUU6tF4VpVan6
         UVs/0fDtZG+hF3RwezwRi0GQVHOkQFyyc5Sc/JhDEb3PpxyRUmGmkKnlKNcC3Z0P3JBq
         XjcyAs+JJ/17mFf2imUCjrYDSBtpQnsBjpoyAn/dnynt3Zbtgx/JKqmRKu5fP4Rdakbo
         K+egKjlqok3X0cIKw4E1/bHb8HjPo9JuWTvfvEUksUQpuNdOEM6XULlPnxzCUwVQZTDx
         3YxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XsqftASK0G5puGwJhzEICddNqG2el5R6hZC2vQm4FYw=;
        b=LlENbZOkaEdUejeeSfJVq9hsWG5XgcFR6GGiC1vdhgDnxwgz9A+NDDogho1CHmUZQO
         /vpYjvK2RTuZx3WmtACxQBxJD6zwi8KkOrPypZyQVmxrNXTHmr7doOFmogVmSJ7SlJV+
         +T0BfGhGF8T3fwV1/hfqWIRJusfybjm9HhCCLkfeteRVjSem52uSsAFOS+dxxr3yLKTw
         gPi1SWJT4yjBC9OtfTTz1VTIN6fPnSGQ4wR0waBBb1z+HXO8uV13V4McLGHCshFlx+f4
         j/fm+YjBuIA/sq8I0jQVS235abslxtA5QMBmwJcNEZoq+JOkAIlAuyKvUxcgj9iDom6F
         1akA==
X-Gm-Message-State: AJIora+1E/oG0e3ZpQcxmRZ94Ox/q/nb9otwefvpmuJtoIw+1CprCk1z
	NN0UXV6xHXATi55j4uEciz8=
X-Google-Smtp-Source: AGRyM1sHYEVRXHFo2FKIdVsBjBjLgtgibZZ1YuNcwP7dO1LgPCwRCGdNEKXaSJzKg2AAip81ybRbmg==
X-Received: by 2002:a05:6402:354b:b0:43b:bef0:5b67 with SMTP id f11-20020a056402354b00b0043bbef05b67mr728416edd.357.1658331334240;
        Wed, 20 Jul 2022 08:35:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4413:b0:43a:7c1c:8981 with SMTP id
 y19-20020a056402441300b0043a7c1c8981ls109445eda.0.-pod-prod-gmail; Wed, 20
 Jul 2022 08:35:33 -0700 (PDT)
X-Received: by 2002:a05:6402:1348:b0:43b:a1de:deef with SMTP id y8-20020a056402134800b0043ba1dedeefmr9461091edw.120.1658331333203;
        Wed, 20 Jul 2022 08:35:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658331333; cv=none;
        d=google.com; s=arc-20160816;
        b=ceYhgGxeavlKcsM9f/KakDeIPYao45bqQN249hm7A1FuH5kuB9lfKCGCED04Q77Y+z
         HaYtDk9QyunKV7hJgYxy37B8Oeg7bgyDchRq1D2rjgHNSWEnf4fShQ0FRbc6PzOWGWJS
         1i+dNEpPwgK3COwU37KRvOUNDP6oNlb3Y8/6bGRbBU/sxCzlSL+S4XqsCvt2bEvDy2UX
         LbB+D+tGG4Mwx0CS4lTbZWBpp+s3aVe1IBKsDD2S+J9I3hdkdIvhpgn2JAxzD563t4CR
         L8JzMzs7WIkvf1hNaq55KxBLhJTcsrD9ScBtV1WjXBbKuJvxUms2sBcmtmsKGLprhdKk
         GP9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=srzHwQjnGGGl03nd5STwWyJmD4z8xROiVMWo0kyoayo=;
        b=sq6viFXJBsWZhYltRVq2Sz6FBL27rSgxpy1ClNwjoLen7jk1FEtv7MGZR5u3lhZLLE
         IdZV7ZDh6w6JpX1uMEMfFKwV8gH7DudQpPTbpfRa0Fw+yaiBJi/GYZY11LaBL/q7jb2S
         HOrcOd4yChTthCq+br61hmI7dUdiI7CdKOlvh+oIJ617MY7MYV7G0y4T7FFTSSsCNhm8
         6hYWXvNscNC0b5n0/o3m/wEl1u6dst9Jx5Roc9R7LjVf4TxTSa+BB7KJk7V81UZqo7CM
         3PKZfAurbLZr2XY4TnfhvKOlSwtQNwJGY1a8kz9fez0yK4uQuW+Npa7fngVdYLYcIyh0
         Y27g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=f1+SWiW7;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id r18-20020aa7cfd2000000b0043bbb9ccb80si57064edy.2.2022.07.20.08.35.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Jul 2022 08:35:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id id17so4007875wmb.1
        for <kasan-dev@googlegroups.com>; Wed, 20 Jul 2022 08:35:33 -0700 (PDT)
X-Received: by 2002:a05:600c:19d2:b0:3a3:2cdb:cc02 with SMTP id
 u18-20020a05600c19d200b003a32cdbcc02mr1939558wmq.182.1658331332788; Wed, 20
 Jul 2022 08:35:32 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-10-elver@google.com>
In-Reply-To: <20220704150514.48816-10-elver@google.com>
From: "'Ian Rogers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Jul 2022 08:35:20 -0700
Message-ID: <CAP-5=fXevVEC9MFuArG7nLadwEDzzWRLeBBkCUqDdJz9X=Bvjg@mail.gmail.com>
Subject: Re: [PATCH v3 09/14] powerpc/hw_breakpoint: Avoid relying on caller synchronization
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
 header.i=@google.com header.s=20210112 header.b=f1+SWiW7;       spf=pass
 (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::32e
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
> Internal data structures (cpu_bps, task_bps) of powerpc's hw_breakpoint
> implementation have relied on nr_bp_mutex serializing access to them.
>
> Before overhauling synchronization of kernel/events/hw_breakpoint.c,
> introduce 2 spinlocks to synchronize cpu_bps and task_bps respectively,
> thus avoiding reliance on callers synchronizing powerpc's hw_breakpoint.
>
> Reported-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> Acked-by: Dmitry Vyukov <dvyukov@google.com>

Acked-by: Ian Rogers <irogers@google.com>

Thanks,
Ian

> ---
> v2:
> * New patch.
> ---
>  arch/powerpc/kernel/hw_breakpoint.c | 53 ++++++++++++++++++++++-------
>  1 file changed, 40 insertions(+), 13 deletions(-)
>
> diff --git a/arch/powerpc/kernel/hw_breakpoint.c b/arch/powerpc/kernel/hw_breakpoint.c
> index 2669f80b3a49..8db1a15d7acb 100644
> --- a/arch/powerpc/kernel/hw_breakpoint.c
> +++ b/arch/powerpc/kernel/hw_breakpoint.c
> @@ -15,6 +15,7 @@
>  #include <linux/kernel.h>
>  #include <linux/sched.h>
>  #include <linux/smp.h>
> +#include <linux/spinlock.h>
>  #include <linux/debugfs.h>
>  #include <linux/init.h>
>
> @@ -129,7 +130,14 @@ struct breakpoint {
>         bool ptrace_bp;
>  };
>
> +/*
> + * While kernel/events/hw_breakpoint.c does its own synchronization, we cannot
> + * rely on it safely synchronizing internals here; however, we can rely on it
> + * not requesting more breakpoints than available.
> + */
> +static DEFINE_SPINLOCK(cpu_bps_lock);
>  static DEFINE_PER_CPU(struct breakpoint *, cpu_bps[HBP_NUM_MAX]);
> +static DEFINE_SPINLOCK(task_bps_lock);
>  static LIST_HEAD(task_bps);
>
>  static struct breakpoint *alloc_breakpoint(struct perf_event *bp)
> @@ -174,7 +182,9 @@ static int task_bps_add(struct perf_event *bp)
>         if (IS_ERR(tmp))
>                 return PTR_ERR(tmp);
>
> +       spin_lock(&task_bps_lock);
>         list_add(&tmp->list, &task_bps);
> +       spin_unlock(&task_bps_lock);
>         return 0;
>  }
>
> @@ -182,6 +192,7 @@ static void task_bps_remove(struct perf_event *bp)
>  {
>         struct list_head *pos, *q;
>
> +       spin_lock(&task_bps_lock);
>         list_for_each_safe(pos, q, &task_bps) {
>                 struct breakpoint *tmp = list_entry(pos, struct breakpoint, list);
>
> @@ -191,6 +202,7 @@ static void task_bps_remove(struct perf_event *bp)
>                         break;
>                 }
>         }
> +       spin_unlock(&task_bps_lock);
>  }
>
>  /*
> @@ -200,12 +212,17 @@ static void task_bps_remove(struct perf_event *bp)
>  static bool all_task_bps_check(struct perf_event *bp)
>  {
>         struct breakpoint *tmp;
> +       bool ret = false;
>
> +       spin_lock(&task_bps_lock);
>         list_for_each_entry(tmp, &task_bps, list) {
> -               if (!can_co_exist(tmp, bp))
> -                       return true;
> +               if (!can_co_exist(tmp, bp)) {
> +                       ret = true;
> +                       break;
> +               }
>         }
> -       return false;
> +       spin_unlock(&task_bps_lock);
> +       return ret;
>  }
>
>  /*
> @@ -215,13 +232,18 @@ static bool all_task_bps_check(struct perf_event *bp)
>  static bool same_task_bps_check(struct perf_event *bp)
>  {
>         struct breakpoint *tmp;
> +       bool ret = false;
>
> +       spin_lock(&task_bps_lock);
>         list_for_each_entry(tmp, &task_bps, list) {
>                 if (tmp->bp->hw.target == bp->hw.target &&
> -                   !can_co_exist(tmp, bp))
> -                       return true;
> +                   !can_co_exist(tmp, bp)) {
> +                       ret = true;
> +                       break;
> +               }
>         }
> -       return false;
> +       spin_unlock(&task_bps_lock);
> +       return ret;
>  }
>
>  static int cpu_bps_add(struct perf_event *bp)
> @@ -234,6 +256,7 @@ static int cpu_bps_add(struct perf_event *bp)
>         if (IS_ERR(tmp))
>                 return PTR_ERR(tmp);
>
> +       spin_lock(&cpu_bps_lock);
>         cpu_bp = per_cpu_ptr(cpu_bps, bp->cpu);
>         for (i = 0; i < nr_wp_slots(); i++) {
>                 if (!cpu_bp[i]) {
> @@ -241,6 +264,7 @@ static int cpu_bps_add(struct perf_event *bp)
>                         break;
>                 }
>         }
> +       spin_unlock(&cpu_bps_lock);
>         return 0;
>  }
>
> @@ -249,6 +273,7 @@ static void cpu_bps_remove(struct perf_event *bp)
>         struct breakpoint **cpu_bp;
>         int i = 0;
>
> +       spin_lock(&cpu_bps_lock);
>         cpu_bp = per_cpu_ptr(cpu_bps, bp->cpu);
>         for (i = 0; i < nr_wp_slots(); i++) {
>                 if (!cpu_bp[i])
> @@ -260,19 +285,25 @@ static void cpu_bps_remove(struct perf_event *bp)
>                         break;
>                 }
>         }
> +       spin_unlock(&cpu_bps_lock);
>  }
>
>  static bool cpu_bps_check(int cpu, struct perf_event *bp)
>  {
>         struct breakpoint **cpu_bp;
> +       bool ret = false;
>         int i;
>
> +       spin_lock(&cpu_bps_lock);
>         cpu_bp = per_cpu_ptr(cpu_bps, cpu);
>         for (i = 0; i < nr_wp_slots(); i++) {
> -               if (cpu_bp[i] && !can_co_exist(cpu_bp[i], bp))
> -                       return true;
> +               if (cpu_bp[i] && !can_co_exist(cpu_bp[i], bp)) {
> +                       ret = true;
> +                       break;
> +               }
>         }
> -       return false;
> +       spin_unlock(&cpu_bps_lock);
> +       return ret;
>  }
>
>  static bool all_cpu_bps_check(struct perf_event *bp)
> @@ -286,10 +317,6 @@ static bool all_cpu_bps_check(struct perf_event *bp)
>         return false;
>  }
>
> -/*
> - * We don't use any locks to serialize accesses to cpu_bps or task_bps
> - * because are already inside nr_bp_mutex.
> - */
>  int arch_reserve_bp_slot(struct perf_event *bp)
>  {
>         int ret;
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAP-5%3DfXevVEC9MFuArG7nLadwEDzzWRLeBBkCUqDdJz9X%3DBvjg%40mail.gmail.com.
