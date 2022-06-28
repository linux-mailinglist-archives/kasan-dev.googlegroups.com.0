Return-Path: <kasan-dev+bncBCMIZB7QWENRB54A5SKQMGQEOL6XWBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D8B655D9D8
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 15:22:00 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id r28-20020ac25c1c000000b004809e9d21e5sf4968090lfp.18
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 06:22:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656422519; cv=pass;
        d=google.com; s=arc-20160816;
        b=kBBZVjPvObreKi0rgInyOLlo7bCQDPSu63eAtwfbyCE16vBEgu9czrvs41rv/Lwdn1
         W45NooHeLG5ubg7/CnPKHk5/vYpJxrNlwGadPxK1IFBANjUMHV0Q2yozcc3bYPP+2Xwm
         cBCs+VnA6JWD5K9KzMy6bmxLB7CEkjzyGnis9XxvSjMVBIb3RTmyZqlZcSp+3ORDSJ80
         P10NGPrCXpONCPHMC20wvXOAN/2MJnTaNzWCd61JCUYba34jd7zhwHVQbRKNIW0K+tEO
         5KLip1i31Go4yqIxBMiYgOFZD2I46YqU8wCiyJpiEVh59TWu4ELLSPzOC6gAtYQ9scQj
         SuRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tLE2p+g3dFIK6kOPhw2owZ7z6yfc7v2V3HLVY82CxLg=;
        b=D37/ihF/Gye6ilatb0qfzEElqGIM0XLGbeGQszXwZ93Z+7c1h7U4AIkO0MlDLuMxM5
         Iq5qw/nwwF5fXuxeQB8RVPkmSHCRi1zveE8ZOg7imCXrwJzfYn22JU7g0oi6Olls7IS+
         1R7WEBpcu7ywEhMzXoW1KSG+mkH0SWMghmrxcbLzC48QF/PNPpceBQm1IawAapml/LRB
         S+EpHtNLugjxcwYgjRaMcqc5lFa0AeUbtldFhQswoiyymY5NZLdyWQ2+xycXu5SA0ijO
         3jWj8TsfLSCzeBPDvg2n0TzQdFzVuhAqS4fQquztHfDrcUFmzIh+NIIW218TXvx0WER6
         fO8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="agU/nLOg";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tLE2p+g3dFIK6kOPhw2owZ7z6yfc7v2V3HLVY82CxLg=;
        b=VL3ykTqeV9Q7rnErfgcj2nvLyxxwdUnI2t8Sf0Btu6vJ/OlT3R0q0p0y/fTALQnX0M
         M4ChOof1Enug5+xyLj/EHjVUBj6IgrJ5jbXTBkCdG1KLAcwup2XXFmfyxzAsZ4RehE+r
         RiGQqmQjzIbI4gsJoNEmrd3rUtamxHUFXcNlnxXkzXMygmuMhmOLPID221IrSIrRLuGf
         9EV3PQtEUyIFBk3GleuJPbFZ4jGPRf1iL2RZrOI9IIidrjsLFDywnYY2wjbRaCiEX91B
         LHyLrw8NHWXpnWaab1knbpweEKVjdb9UCnEte97xfYmRN4JVigU+vi2xVE0f5+MfgDbH
         aU0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tLE2p+g3dFIK6kOPhw2owZ7z6yfc7v2V3HLVY82CxLg=;
        b=iCtI49eMbG1ael5sfDFtRUr93NywRYY/bLkqSDr97tqTSMvNc4p8vlitkyMd+pgQzc
         +lvwYD9/TwvEUgA83SbzrOB+htMl77egu5ocQELjMN0ahQU3fwuoOjA5/3XOCeYQgADC
         ijaLFGdTEmbe4TyQZMiQQf3S180Ak2W+Mq621xNKvOVvssbEhZ4p+YEf92y/lXKkGaI6
         F6loFoZ1jpEVsdcTjwDX9Ci2Lwv3yvPkze1FRMXxnKVZP7hdu+vEKL4D+yw/0P/J2XJ1
         FZB//rgebW91r19KMiohwErN2oOCqqpjkxfD/AKXkpQRynC5sb/9AuAUOPTZckg2SFUv
         LNOA==
X-Gm-Message-State: AJIora8x1AzFEMxTcxFTQ4YwWq/Oz0gqyC/gtqceFqLTMO3zbEMy5hfA
	riYzUVEOYSAJ0PjFva1Pzzo=
X-Google-Smtp-Source: AGRyM1tbpqhGoXxeTTfzRvMz3EH0DtG0CSro/8quZX2LJL+4lqneQ+kUg8LtcTT9A9hqjbco8N3AUw==
X-Received: by 2002:ac2:47ec:0:b0:47f:7e9a:ccf9 with SMTP id b12-20020ac247ec000000b0047f7e9accf9mr11632040lfp.385.1656422519584;
        Tue, 28 Jun 2022 06:21:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als750593lfa.2.gmail; Tue, 28 Jun 2022
 06:21:58 -0700 (PDT)
X-Received: by 2002:a05:6512:130c:b0:477:e2ea:396e with SMTP id x12-20020a056512130c00b00477e2ea396emr11923519lfu.489.1656422518487;
        Tue, 28 Jun 2022 06:21:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656422518; cv=none;
        d=google.com; s=arc-20160816;
        b=lv2cen8So0a9yCCqQtARXIwMGA5AD/7MoWq6UuM1Hz26ApImElOe676CHMwty1McWH
         NFG3j+0RaEVx0dam5e/euQcoxsqO+p0TCZUAurMAOzoKkb9RzlhOp8313tMJh5tkH0wV
         bIWm7u3lGaiGAJRg99JA4LY0lscgwN0kX/aBJF6hSWjkZ/e6zrf+IzjTZqCSyIoGM9vO
         79SbV/CQXnacWu5VWK28qkijFetS16Jxb/mXFnAVmXpffyRVRtVAEsYxjsASpJf+FdfP
         Inb4RdEFMcO9tRYGcCVxGh9EneM21G0pzC1sB4/peSfaFpwRJ7D8sM2NtnSUWukCIxgb
         vASA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3i9OmUcCYtxYmLpPV5EK9xnLGgU5ydCPjivPQxAxv/Y=;
        b=zFCXIBMRuSKjyO01ctEG4w/zbRAlc7eUtyvkf8yTiDuaa5+F5P7vUMgZw1FICqs98I
         FFFJPW83bLvaSAZLTg3/Zo3mBz7fZ3f/f0FWi98ih36k//7e4VQN/NyzAtoEAhP9qNWj
         9QwbGk/P1MJMCPnwCRVGnoLlEqV+EGIRi4vTJZzLzN2AdecZQUg+apMAm50HqWyfDLUH
         SA7C98AW1IL/zK9kiM7coG7zSuZrAQrIMTgDhyrESD9qkReGb3TLeaoo4vNScUs/MxB+
         tUcb++GNgx1vCRf9l7UiW4azGZCAv1Rh7zKvsxFCRA9KrucqQ8w71v9p6xXSpUVeep/L
         giTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="agU/nLOg";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x136.google.com (mail-lf1-x136.google.com. [2a00:1450:4864:20::136])
        by gmr-mx.google.com with ESMTPS id p15-20020a2eb98f000000b0025a8d717b7dsi642412ljp.5.2022.06.28.06.21.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 06:21:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) client-ip=2a00:1450:4864:20::136;
Received: by mail-lf1-x136.google.com with SMTP id z21so22214430lfb.12
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 06:21:58 -0700 (PDT)
X-Received: by 2002:ac2:4906:0:b0:47f:6c71:6de5 with SMTP id
 n6-20020ac24906000000b0047f6c716de5mr12443219lfi.137.1656422518034; Tue, 28
 Jun 2022 06:21:58 -0700 (PDT)
MIME-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com> <20220628095833.2579903-9-elver@google.com>
In-Reply-To: <20220628095833.2579903-9-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jun 2022 15:21:46 +0200
Message-ID: <CACT4Y+Z4W4CRO+pEvDjdmGwP+CX+MuQYE9bs2mPvUFm1Np83Dg@mail.gmail.com>
Subject: Re: [PATCH v2 08/13] powerpc/hw_breakpoint: Avoid relying on caller synchronization
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
 header.i=@google.com header.s=20210112 header.b="agU/nLOg";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136
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
> Internal data structures (cpu_bps, task_bps) of powerpc's hw_breakpoint
> implementation have relied on nr_bp_mutex serializing access to them.
>
> Before overhauling synchronization of kernel/events/hw_breakpoint.c,
> introduce 2 spinlocks to synchronize cpu_bps and task_bps respectively,
> thus avoiding reliance on callers synchronizing powerpc's hw_breakpoint.
>
> Reported-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Marco Elver <elver@google.com>

Acked-by: Dmitry Vyukov <dvyukov@google.com>

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ4W4CRO%2BpEvDjdmGwP%2BCX%2BMuQYE9bs2mPvUFm1Np83Dg%40mail.gmail.com.
