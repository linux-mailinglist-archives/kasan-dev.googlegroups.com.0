Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQMDQD4QKGQEYP7FIAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6780F2307FB
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jul 2020 12:45:22 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id o191sf11297451ila.3
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jul 2020 03:45:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595933121; cv=pass;
        d=google.com; s=arc-20160816;
        b=d7Ut1+mCZVZ1a0cz5AsvAX4t0juNfzwIiSAE3RsrYURuP4+RPoFQT1vbwNi5OD0Vz1
         VeQ6CosFGytCg05vKYr5IJPYN8jnvDENMwvcarl79ZpZbqS+Xao9rJgoYULHOYo1lqgq
         uljH+swg0Aa9zJKY9qEvlevC1zdxrp5+v8NAlfew25FjyD+54ShR/Rrj1HEGpMh3+cKd
         2WF3nyA7XGiC5VThPB2VpD5GWQ4ayoucglXHrBi/YxYm2K3kOnpO8dbtzDn46Cngawnm
         8dBjnFfghR34Gpgj475JM/+K0kWHr1mQ9dlgqnKOzXDzmcfpvRksjo5shhPQCwJfbSeW
         eqYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qQiJCZ0PoM0+D8dxoT+1a7gtEbmZpfFyvl9ziCVC8js=;
        b=hZUr7dcKrpU76E1ry884b36zFE0Rtv6ZHPVE4I62Tu/LUnQ0AokvvwFf06vFzAgYly
         6s7XakHc2nU0TsRoF1TdaqMip2nS621Re2m6Q98PXNQNOxwEWxJ84shgOtS2OWTj/Mqs
         /9mxdTmrFBV71RSbJhXWmnZh6DomWSNNzuS9s8rNtdVpZPl8CNkJ/soAPcA6zqJ5nwli
         fc3MJenfssfdgzUz7jJbm2RFZbOcK3KMsBbrEPG7sqF8sy3mzufe2tRGViq5qcVImxrB
         e1VA8gLZAiSyjgVxskcGT6OVaKMTeLxp4XezzqaS8afzgQ4znA6mxMfXrNjPxtu7x9km
         p/lQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=chyQVmXV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qQiJCZ0PoM0+D8dxoT+1a7gtEbmZpfFyvl9ziCVC8js=;
        b=b5owtT4tJNZYlxAmU+mZ4QXRu9anuDKq/451HrG7XMjXf1/+g1S1ftykIvQu6IPOgr
         IlDu8173Lj40yFnKv3ovt2SEWaTteLDGULuk8PzAGZZOc5neLqs0GeUg2zSJpAXEipSb
         okUkqwshLsUoxcUKCsI/0ltCj50rd09/Uywu0F7iDgZUpbpa4VJrhEk0v2jhNo/5CENa
         HAlY3wvCwKlPsMLEMuzP28wgUrZGWWuqqkM5yt33QmhWF5hQpS2LYnG5WFWZAae+0u+r
         UxYCgnWRXTPoooXnTxOdtvy0jtG3Y3B3k6QtPjTVTiRSkjTYIDMjkrIOuVL/soWnpVca
         W5mA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qQiJCZ0PoM0+D8dxoT+1a7gtEbmZpfFyvl9ziCVC8js=;
        b=R2gy7j5FfckLsIIzwWf7hQM45hcSNE7ftjMjKPznKtz+uFL7MVHRgcFr7NG4supT0S
         tS/7apQaPbRBGgzRDBEeEUMfRWtKcrxdf8EofwvWYCU6qF45kY7gpUdNx3SzhbBUPbZP
         mCO8LcuqTJIsdUWjjI2ItpWDt2k9LWwBSNZ3kSW0YvRrqHK3lY+nz0otCP+N7pcG2qX2
         hBkl2yrooRx2z5VLG0WBxbiw8ZAoTh8qyFbFM2PSTrTKPS8TtAPcDCaZUEL0DF7HpqYm
         xxcCwjZI67rll6547uhPeCnJMLxsXptviTOKGMtzP+wLs4wYKJ/tjV3oEAH/yDpPTdEA
         z40A==
X-Gm-Message-State: AOAM532u+EbQOHDViV4DJdKoik7L0rtHhyFLjf9kccamiAet6nWQvCyH
	zjbi7axrObGEUkaozvuKvZY=
X-Google-Smtp-Source: ABdhPJzx+XB+Kiusx3azsxUQTtNBPwphOO8WEWwXwhiJFu3GtJNmrOra5IKUU2Q885oBkU962OOUyA==
X-Received: by 2002:a92:c844:: with SMTP id b4mr8864664ilq.297.1595933121342;
        Tue, 28 Jul 2020 03:45:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:15c6:: with SMTP id 189ls3438423iov.8.gmail; Tue, 28 Jul
 2020 03:45:21 -0700 (PDT)
X-Received: by 2002:a05:6602:2cca:: with SMTP id j10mr28474059iow.22.1595933121000;
        Tue, 28 Jul 2020 03:45:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595933120; cv=none;
        d=google.com; s=arc-20160816;
        b=q3MsaKbtGiXffXhGDL6EgmEXPeqj0irn7tr6Ug2UxwUU+QVi+yjeXhflapQJDPnkIW
         QlnfoYiGgHuFCMq3QpcbvDlwh6BjzbN7YpTlvNw8XKWbfvS4zPaSaIIy8/Nxvvx17why
         YugjvfG/STCskJwDn43JJW2TpsmD8JUDCrX0J601XOqCWxe+/Kvulv9HlVTjJuo3oj69
         b2rvKBHGqDFN6kJaSXhGOLEQo4YxSxE0syu8FLUH5SMhHpOQBJPUp1PL4gNCWluteQ7l
         lxbrHixgycda7yyqddRPnMKq8uA9UO+OYeyTls7Ebpx1Ya+qljbxP2/5aDrqtKnO4/l9
         0rRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=P9qNMY+MaOU7/Uc+GSjibOeYutZuuvmea9JQdtNRlCc=;
        b=xUZqGFkkr6pw4lSwlVLOGeuyGSCQVcp8+eUvtWeJWkP/EpkRLWry1KU0jefeT0E4mi
         ql9QzxqkDwMVJYVa9AKhOf683mKrqIZkHibyEPyT95UlDH0+vR+LlXyGjeMhlUGQ9WAz
         gOtjtZCYrrZByBGx/SEhBvD56JMRFsHjUV1JRxepOG4Z5PkrtIGt3j6ax0wn6Ecw/xnx
         vNj2Ak6YZQ32/kKX8wGlKvukbyvcTxFpL53sUu2OdQdM9pEEL+Ki84h7EqNqvEMqdcjO
         pspGgaSRGkPeskxzlmPCG1h6wXfpkXn6fGKL6zVJ0HpEGg6mQsneiwTKp+fnK3zZnK6N
         2kQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=chyQVmXV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id k8si1126946ios.2.2020.07.28.03.45.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jul 2020 03:45:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id c25so14530476otf.7
        for <kasan-dev@googlegroups.com>; Tue, 28 Jul 2020 03:45:20 -0700 (PDT)
X-Received: by 2002:a05:6830:1612:: with SMTP id g18mr8111463otr.251.1595933120306;
 Tue, 28 Jul 2020 03:45:20 -0700 (PDT)
MIME-Version: 1.0
References: <20200720120348.2406588-1-elver@google.com>
In-Reply-To: <20200720120348.2406588-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jul 2020 12:45:08 +0200
Message-ID: <CANpmjNO7M2gm5=P9Z27_BgT3i=p6=KFBbEUaKm049wtqyBMQcA@mail.gmail.com>
Subject: Re: [PATCH tip/locking/core] kcsan: Improve IRQ state trace reporting
To: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>
Cc: Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=chyQVmXV;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 20 Jul 2020 at 14:03, Marco Elver <elver@google.com> wrote:
>
> To improve the general usefulness of the IRQ state trace information
> with KCSAN enabled, save and restore the trace information when entering
> and exiting the KCSAN runtime as well as when generating a KCSAN report.
>
> Without this, reporting the IRQ state trace (whether via a KCSAN report
> or outside of KCSAN via a lockdep report) is rather useless due to
> continuously being touched by KCSAN. This is because if KCSAN is
> enabled, every instrumented memory access causes changes to IRQ state
> tracking information (either by KCSAN disabling/enabling interrupts or
> taking report_lock when generating a report).
>
> Before "lockdep: Prepare for NMI IRQ state tracking", KCSAN avoided
> touching the IRQ state trace via raw_local_irq_save/restore() and
> lockdep_off/on().
>
> Fixes: 248591f5d257 ("kcsan: Make KCSAN compatible with new IRQ state tracking")
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>
>
> Hi, Peter,
>
> If this is reasonable, please take it into the branch that currently has
> the series around "lockdep: Prepare for NMI IRQ state tracking"
> (tip/locking/core?).

Just in case -- checking this one wasn't lost.

Many thanks,
-- Marco

> ---
>  include/linux/sched.h | 13 +++++++++++++
>  kernel/kcsan/core.c   | 39 +++++++++++++++++++++++++++++++++++++++
>  kernel/kcsan/kcsan.h  |  7 +++++++
>  kernel/kcsan/report.c |  3 +++
>  4 files changed, 62 insertions(+)
>
> diff --git a/include/linux/sched.h b/include/linux/sched.h
> index 692e327d7455..ca5324b1657c 100644
> --- a/include/linux/sched.h
> +++ b/include/linux/sched.h
> @@ -1199,6 +1199,19 @@ struct task_struct {
>  #endif
>  #ifdef CONFIG_KCSAN
>         struct kcsan_ctx                kcsan_ctx;
> +#ifdef CONFIG_TRACE_IRQFLAGS
> +       struct {
> +               unsigned int            irq_events;
> +               unsigned long           hardirq_enable_ip;
> +               unsigned long           hardirq_disable_ip;
> +               unsigned int            hardirq_enable_event;
> +               unsigned int            hardirq_disable_event;
> +               unsigned long           softirq_disable_ip;
> +               unsigned long           softirq_enable_ip;
> +               unsigned int            softirq_disable_event;
> +               unsigned int            softirq_enable_event;
> +       } kcsan_save_irqtrace;
> +#endif
>  #endif
>
>  #ifdef CONFIG_FUNCTION_GRAPH_TRACER
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 732623c30359..7e8347c14530 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -291,6 +291,36 @@ static inline unsigned int get_delay(void)
>                                 0);
>  }
>
> +void kcsan_save_irqtrace(struct task_struct *task)
> +{
> +#ifdef CONFIG_TRACE_IRQFLAGS
> +       task->kcsan_save_irqtrace.irq_events = task->irq_events;
> +       task->kcsan_save_irqtrace.hardirq_enable_ip = task->hardirq_enable_ip;
> +       task->kcsan_save_irqtrace.hardirq_disable_ip = task->hardirq_disable_ip;
> +       task->kcsan_save_irqtrace.hardirq_enable_event = task->hardirq_enable_event;
> +       task->kcsan_save_irqtrace.hardirq_disable_event = task->hardirq_disable_event;
> +       task->kcsan_save_irqtrace.softirq_disable_ip = task->softirq_disable_ip;
> +       task->kcsan_save_irqtrace.softirq_enable_ip = task->softirq_enable_ip;
> +       task->kcsan_save_irqtrace.softirq_disable_event = task->softirq_disable_event;
> +       task->kcsan_save_irqtrace.softirq_enable_event = task->softirq_enable_event;
> +#endif
> +}
> +
> +void kcsan_restore_irqtrace(struct task_struct *task)
> +{
> +#ifdef CONFIG_TRACE_IRQFLAGS
> +       task->irq_events = task->kcsan_save_irqtrace.irq_events;
> +       task->hardirq_enable_ip = task->kcsan_save_irqtrace.hardirq_enable_ip;
> +       task->hardirq_disable_ip = task->kcsan_save_irqtrace.hardirq_disable_ip;
> +       task->hardirq_enable_event = task->kcsan_save_irqtrace.hardirq_enable_event;
> +       task->hardirq_disable_event = task->kcsan_save_irqtrace.hardirq_disable_event;
> +       task->softirq_disable_ip = task->kcsan_save_irqtrace.softirq_disable_ip;
> +       task->softirq_enable_ip = task->kcsan_save_irqtrace.softirq_enable_ip;
> +       task->softirq_disable_event = task->kcsan_save_irqtrace.softirq_disable_event;
> +       task->softirq_enable_event = task->kcsan_save_irqtrace.softirq_enable_event;
> +#endif
> +}
> +
>  /*
>   * Pull everything together: check_access() below contains the performance
>   * critical operations; the fast-path (including check_access) functions should
> @@ -336,9 +366,11 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
>         flags = user_access_save();
>
>         if (consumed) {
> +               kcsan_save_irqtrace(current);
>                 kcsan_report(ptr, size, type, KCSAN_VALUE_CHANGE_MAYBE,
>                              KCSAN_REPORT_CONSUMED_WATCHPOINT,
>                              watchpoint - watchpoints);
> +               kcsan_restore_irqtrace(current);
>         } else {
>                 /*
>                  * The other thread may not print any diagnostics, as it has
> @@ -396,6 +428,12 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>                 goto out;
>         }
>
> +       /*
> +        * Save and restore the IRQ state trace touched by KCSAN, since KCSAN's
> +        * runtime is entered for every memory access, and potentially useful
> +        * information is lost if dirtied by KCSAN.
> +        */
> +       kcsan_save_irqtrace(current);
>         if (!kcsan_interrupt_watcher)
>                 local_irq_save(irq_flags);
>
> @@ -539,6 +577,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>  out_unlock:
>         if (!kcsan_interrupt_watcher)
>                 local_irq_restore(irq_flags);
> +       kcsan_restore_irqtrace(current);
>  out:
>         user_access_restore(ua_flags);
>  }
> diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
> index 763d6d08d94b..29480010dc30 100644
> --- a/kernel/kcsan/kcsan.h
> +++ b/kernel/kcsan/kcsan.h
> @@ -9,6 +9,7 @@
>  #define _KERNEL_KCSAN_KCSAN_H
>
>  #include <linux/kcsan.h>
> +#include <linux/sched.h>
>
>  /* The number of adjacent watchpoints to check. */
>  #define KCSAN_CHECK_ADJACENT 1
> @@ -22,6 +23,12 @@ extern unsigned int kcsan_udelay_interrupt;
>   */
>  extern bool kcsan_enabled;
>
> +/*
> + * Save/restore IRQ flags state trace dirtied by KCSAN.
> + */
> +void kcsan_save_irqtrace(struct task_struct *task);
> +void kcsan_restore_irqtrace(struct task_struct *task);
> +
>  /*
>   * Initialize debugfs file.
>   */
> diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> index 6b2fb1a6d8cd..9d07e175de0f 100644
> --- a/kernel/kcsan/report.c
> +++ b/kernel/kcsan/report.c
> @@ -308,6 +308,9 @@ static void print_verbose_info(struct task_struct *task)
>         if (!task)
>                 return;
>
> +       /* Restore IRQ state trace for printing. */
> +       kcsan_restore_irqtrace(task);
> +
>         pr_err("\n");
>         debug_show_held_locks(task);
>         print_irqtrace_events(task);
> --
> 2.28.0.rc0.105.gf9edc3c819-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO7M2gm5%3DP9Z27_BgT3i%3Dp6%3DKFBbEUaKm049wtqyBMQcA%40mail.gmail.com.
