Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOGHYHZAKGQEXYMUBII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3a.google.com (mail-yw1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 268AF168A43
	for <lists+kasan-dev@lfdr.de>; Sat, 22 Feb 2020 00:11:54 +0100 (CET)
Received: by mail-yw1-xc3a.google.com with SMTP id k129sf2940936ywe.13
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2020 15:11:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582326713; cv=pass;
        d=google.com; s=arc-20160816;
        b=BxOKTcXj97b2Eo7ZJXGrHpcZeMZZ7UtVJnTHUX/Z/MRths45au5XizGNEynFAaIHES
         Prv6lJhwDtwVcwdTk4I3DdT7+zTOr6T20mtmfHgpMeMsy5kr6QwEOq9gn29HZMldMHZI
         bfyoCegUyEWhC+zPGT0FHumSbmnVGnTDuHQufVfgEdM7CFIeQ6wtueiUj6tonqtCOpqt
         cdCgpiRu5AajY5hsPTYv1GJNEUGMJ6RRhAhb2/5hscH3dUvftfF2U1yADV5QA/I8h5iU
         gAUFkGQxuhA80lIUZNXwjv2dq9l+vGUxcSZ2DvcwBq/l9fElXG+3GqAYW+dopLkvX1uz
         ysiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Xhmwdy69FsgePm65Kam4vamkBI4fp48+mr4zoFLBZsk=;
        b=zHeqf+QJynulwu+sd+G/whwHF0ZHigjMDUhRrxItmpQoTpp3zB/pKFVpwONZTGo0o5
         BuPmn16AZ6vEBIldqaTmLTM9kUQ9YXlVl2aINDRHrORkuINwxbs+u9yvtjYcWRZszO/e
         j4q6z+P5AtUgBYfxPbSQdBqcI6dIqgt63nGAoqa1DI84nETfaVOqOcNOqlJnzrXnO1BK
         Rk2ZcAdFzkzWYqRR3j4otJotFUSPcm8RxBuEBtTK0VF1K/83xPQkVOuZ8/JPISan/jjQ
         Z4UO5F0KoNgOY2ATV+dkh+hAZg/cLupOnvIAu49vTEEgFEsZ9RrdCR1iCNobcT5eTfwK
         QNvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PR7FLPbQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xhmwdy69FsgePm65Kam4vamkBI4fp48+mr4zoFLBZsk=;
        b=ajKaHil5ysIc91y86K1iqBlekaeU29bBgk+oXWRLUfKCqjgoP8I9WdoeS7Chdo4bNW
         N+dfisqcAvCYu3LRUaT2hP19eIz9bjnrdKursJcVrigl7xtqjk8FPfSq3KkpwUy8uSio
         83Wmx99dQDpbs9uOOJg9mgpL1nNqWqLTUH2EcV355sPzz9hwCUtPN12TlCNFAgm4/2hW
         OZUGjKQJXP5eM/BmWsABerWD3cWnJjfOYuOOyrGY89yW7YfOOoDZYAngtIytrmG8G3Hx
         zIVxqQHSYurOjMtFxAViWzhtooFasX9gXBhITT6j6Ta8xembEoCgY0dxlbRlo7oL77LI
         5INA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xhmwdy69FsgePm65Kam4vamkBI4fp48+mr4zoFLBZsk=;
        b=fnxVTCaZ2p9EZnlLQ9DBtwvaFzr/FSHj7S8XV914IEDeTE+DysAHxObm/HoJZawmoY
         Ex6deTCOQHYa/HU36GtMkedH2ZZg6Qt3l5HnMvKdSWyepTXVHehHSisG632wfPzhVckV
         Ewfg9mPgCb6yy8v60VhGjGcxdck1vnmcrrdtY6JueC94TzAbIBRXU0YPdG7nIUtMkhK2
         T75Cy9evq2Wn1WGAHFlbfUHLSiYF6pAUvD25i/3ZSG52kPAi3rqWXyQjc1FW2QR6e7w1
         m9G73Vz1K+cbO+rTIwjTyw1UIxSOLBRQX+OrOTSBwn2fB51MlAHTCdGTXMewbZ7fWWC9
         fU3w==
X-Gm-Message-State: APjAAAUEUXvlrIARfbplK5bdf6N/nL0SFO0jJDTPrAcmKs+k7LCw43c3
	ifBh3aWa7CyVYsoMA3cfpG4=
X-Google-Smtp-Source: APXvYqx3JuYp64KNbok07Nk4UI3QWMBicAvrBVnZHSwHjVWI9y8VdsDALiazzd5/db4YSF/kdG6wnQ==
X-Received: by 2002:a0d:e2d1:: with SMTP id l200mr31670603ywe.122.1582326712991;
        Fri, 21 Feb 2020 15:11:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:df8b:: with SMTP id i133ls766964ywe.7.gmail; Fri, 21 Feb
 2020 15:11:52 -0800 (PST)
X-Received: by 2002:a0d:dd83:: with SMTP id g125mr35101478ywe.396.1582326712544;
        Fri, 21 Feb 2020 15:11:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582326712; cv=none;
        d=google.com; s=arc-20160816;
        b=MAXJ9vEUVXmy+LWoOEaSSrBeUU46vMNLVYG67lSPRv48vAL55i4gvi+ka8daZds6Gm
         dagUIOffpjJbPxXXdGLlsB6iuPpd6i/0mUcOLr0tCNyHq8mQXZhsexS0VrjHMRNUdmqI
         o066+OZuM9YK5FkBeyuRrK9KiVDe2fO/96KS6ESpXiI5bNK4QnZkvxneNnQkvkK1BQjA
         a8Lyldg4+6VNVan9H87n4pPkx4GUzx1Ol4PQu5snfbwTOQRjh5hZ1nOzbVBk+YzBK+8R
         5mkotAHLexeN4bBqtuadKJJ8znIvQBuMl3+5NgMgyQlYh6tAXRFXlr/Jt3284AZjwK/O
         q6SA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=47OgEQS9D9Mt9IKVwoke3+HqPkA9hvZv3pNIQJ9tJH4=;
        b=acq7R6EEoa+2oxB6dXdrxTENt41Qx/Uy+kPc9nJzDK+B3iuMkeo8r2QdH6LxemyKay
         q1bGACBm5gfz4EzUZ2X9V9N/TD5zlZIAlZzuRpE/3qeEKQyHhgiptUOsjwefqMncoQUV
         6jb0uIRJMUeSAeW/9NngOJpUHg6EyWRB0ukjwU8I/br6uOG0xq3/clXjl80eU+dJSrvR
         ityfTm5Ep1Ibz/EvWRZnZ2MUeRXLna/e4HTM+SJ5RJj7hgXEAT3rW1ZSXDvc/KBwMB2T
         e9qhDb+0Wxg5XdbFmvJreRNzmvQ991Vrk/B1o/h3BaCRRIHk57//n2/cvQ0d6rM46plf
         NnGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PR7FLPbQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id l1si77711ybt.2.2020.02.21.15.11.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Feb 2020 15:11:52 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id i1so3268429oie.8
        for <kasan-dev@googlegroups.com>; Fri, 21 Feb 2020 15:11:52 -0800 (PST)
X-Received: by 2002:aca:c7ca:: with SMTP id x193mr4065649oif.70.1582326711772;
 Fri, 21 Feb 2020 15:11:51 -0800 (PST)
MIME-Version: 1.0
References: <20200221225635.218857-1-elver@google.com>
In-Reply-To: <20200221225635.218857-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 22 Feb 2020 00:11:39 +0100
Message-ID: <CANpmjNNxtyQy2+-v85=PcjBAqGt=7dcqLi+WA3FS8U94nuVYnw@mail.gmail.com>
Subject: Re: [PATCH v2] kcsan: Add option for verbose reporting
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PR7FLPbQ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

Superseded by v3 due to typos:
http://lkml.kernel.org/r/20200221231027.230147-1-elver@google.com

Thanks,
-- Marco

On Fri, 21 Feb 2020 at 23:57, Marco Elver <elver@google.com> wrote:
>
> Adds CONFIG_KCSAN_VERBOSE to optionally enable more verbose reports.
> Currently information about the reporting task's held locks and IRQ
> trace events are shown, if they are enabled.
>
> Signed-off-by: Marco Elver <elver@google.com>
> Suggested-by: Qian Cai <cai@lca.pw>
> ---
> v2:
> * Rework obtaining 'current' for the "other thread" -- it now passes
>   'current' and ensures that we stall until the report was printed, so
>   that the lockdep information contained in 'current' is accurate. This
>   was non-trivial but testing so far leads me to conclude this now
>   reliably prints the held locks for the "other thread" (please test
>   more!).
> ---
>  kernel/kcsan/core.c   |   4 +-
>  kernel/kcsan/kcsan.h  |   3 ++
>  kernel/kcsan/report.c | 103 +++++++++++++++++++++++++++++++++++++++++-
>  lib/Kconfig.kcsan     |  13 ++++++
>  4 files changed, 120 insertions(+), 3 deletions(-)
>
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index e7387fec66795..065615df88eaa 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -18,8 +18,8 @@
>  #include "kcsan.h"
>
>  static bool kcsan_early_enable = IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE);
> -static unsigned int kcsan_udelay_task = CONFIG_KCSAN_UDELAY_TASK;
> -static unsigned int kcsan_udelay_interrupt = CONFIG_KCSAN_UDELAY_INTERRUPT;
> +unsigned int kcsan_udelay_task = CONFIG_KCSAN_UDELAY_TASK;
> +unsigned int kcsan_udelay_interrupt = CONFIG_KCSAN_UDELAY_INTERRUPT;
>  static long kcsan_skip_watch = CONFIG_KCSAN_SKIP_WATCH;
>  static bool kcsan_interrupt_watcher = IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER);
>
> diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
> index 892de5120c1b6..e282f8b5749e9 100644
> --- a/kernel/kcsan/kcsan.h
> +++ b/kernel/kcsan/kcsan.h
> @@ -13,6 +13,9 @@
>  /* The number of adjacent watchpoints to check. */
>  #define KCSAN_CHECK_ADJACENT 1
>
> +extern unsigned int kcsan_udelay_task;
> +extern unsigned int kcsan_udelay_interrupt;
> +
>  /*
>   * Globally enable and disable KCSAN.
>   */
> diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> index 11c791b886f3c..ee8f33d7405fb 100644
> --- a/kernel/kcsan/report.c
> +++ b/kernel/kcsan/report.c
> @@ -1,5 +1,7 @@
>  // SPDX-License-Identifier: GPL-2.0
>
> +#include <linux/debug_locks.h>
> +#include <linux/delay.h>
>  #include <linux/jiffies.h>
>  #include <linux/kernel.h>
>  #include <linux/lockdep.h>
> @@ -31,7 +33,26 @@ static struct {
>         int                     cpu_id;
>         unsigned long           stack_entries[NUM_STACK_ENTRIES];
>         int                     num_stack_entries;
> -} other_info = { .ptr = NULL };
> +
> +       /*
> +        * Optionally pass @current. Typically we do not need to pass @current
> +        * via @other_info since just @task_pid is sufficient. Passing @current
> +        * has additional overhead.
> +        *
> +        * To safely pass @current, we must either use get_task_struct/
> +        * put_task_struct, or stall the thread that populated @other_info.
> +        *
> +        * We cannot rely on get_task_struct/put_task_struct in case
> +        * release_report() races with a task being released, and would have to
> +        * free it in release_report(). This may result in deadlock if we want
> +        * to use KCSAN on the allocators.
> +        *
> +        * Since we also want to reliably print held locks for
> +        * CONFIG_KCSAN_VERBOSE, the current implementation stalls the thread
> +        * that populated @other_info until it has been consumed.
> +        */
> +       struct task_struct      *task;
> +} other_info;
>
>  /*
>   * Information about reported races; used to rate limit reporting.
> @@ -245,6 +266,16 @@ static int sym_strcmp(void *addr1, void *addr2)
>         return strncmp(buf1, buf2, sizeof(buf1));
>  }
>
> +static void print_verbose_info(struct task_struct *task)
> +{
> +       if (!task)
> +               return;
> +
> +       pr_err("\n");
> +       debug_show_held_locks(task);
> +       print_irqtrace_events(task);
> +}
> +
>  /*
>   * Returns true if a report was generated, false otherwise.
>   */
> @@ -319,6 +350,9 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
>                                   other_info.num_stack_entries - other_skipnr,
>                                   0);
>
> +               if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> +                   print_verbose_info(other_info.task);
> +
>                 pr_err("\n");
>                 pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
>                        get_access_type(access_type), ptr, size,
> @@ -340,6 +374,9 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
>         stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr,
>                           0);
>
> +       if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> +               print_verbose_info(current);
> +
>         /* Print report footer. */
>         pr_err("\n");
>         pr_err("Reported by Kernel Concurrency Sanitizer on:\n");
> @@ -357,6 +394,67 @@ static void release_report(unsigned long *flags, enum kcsan_report_type type)
>         spin_unlock_irqrestore(&report_lock, *flags);
>  }
>
> +/*
> + * Sets @other_info.task and awaits consumption of @other_info.
> + *
> + * Precondition: report_lock is held.
> + * Postcontiion: report_lock is held.
> + */
> +static void
> +set_other_info_task_blocking(unsigned long *flags, const volatile void *ptr)
> +{
> +       /*
> +        * We may be instrumenting a code-path where current->state is already
> +        * something other than TASK_RUNNING.
> +        */
> +       const bool is_running = current->state == TASK_RUNNING;
> +       /*
> +        * To avoid deadlock in case we are in an interrupt here and this is a
> +        * race with a task on the same CPU (KCSAN_INTERRUPT_WATCHER), provide a
> +        * timeout to ensure this works in all contexts.
> +        *
> +        * Await approximately the worst case delay of the reporting thread (if
> +        * we are not interrupted).
> +        */
> +       int timeout = max(kcsan_udelay_task, kcsan_udelay_interrupt);
> +
> +       other_info.task = current;
> +       do {
> +               if (is_running) {
> +                       /*
> +                        * Let lockdep know the real task is sleeping, to print
> +                        * the held locks (recall we turned lockdep off, so
> +                        * locking/unlocking @report_lock won't be recorded).
> +                        */
> +                       set_current_state(TASK_UNINTERRUPTIBLE);
> +               }
> +               spin_unlock_irqrestore(&report_lock, *flags);
> +               /*
> +                * We cannot call schedule() since we also cannot reliably
> +                * determine if sleeping here is permitted -- see in_atomic().
> +                */
> +
> +               udelay(1);
> +               spin_lock_irqsave(&report_lock, *flags);
> +               if (timeout-- < 0) {
> +                       /*
> +                        * Abort. Reset other_info.task to NULL, since it
> +                        * appears the other thread is still going to consume
> +                        * it. It will result in no verbose info printed for
> +                        * this task.
> +                        */
> +                       other_info.task = NULL;
> +                       break;
> +               }
> +               /*
> +                * If @ptr nor @current matches, then our information has been
> +                * consumed and we may continue. If not, retry.
> +                */
> +       } while (other_info.ptr == ptr && other_info.task == current);
> +       if (is_running)
> +               set_current_state(TASK_RUNNING);
> +}
> +
>  /*
>   * Depending on the report type either sets other_info and returns false, or
>   * acquires the matching other_info and returns true. If other_info is not
> @@ -388,6 +486,9 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
>                 other_info.cpu_id               = cpu_id;
>                 other_info.num_stack_entries    = stack_trace_save(other_info.stack_entries, NUM_STACK_ENTRIES, 1);
>
> +               if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> +                       set_other_info_task_blocking(flags, ptr);
> +
>                 spin_unlock_irqrestore(&report_lock, *flags);
>
>                 /*
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index 081ed2e1bf7b1..0f1447ff8f558 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -20,6 +20,19 @@ menuconfig KCSAN
>
>  if KCSAN
>
> +config KCSAN_VERBOSE
> +       bool "Show verbose reports with more information about system state"
> +       depends on PROVE_LOCKING
> +       help
> +         If enabled, reports show more information about the system state that
> +         may help better analyze and debug races. This includes held locks and
> +         IRQ trace events.
> +
> +         While this option should generally be benign, we call into more
> +         external functions on report generation; if a race report is
> +         generated from any one of them, system stability may suffer due to
> +         deadlocks or recursion.  If in doubt, say N.
> +
>  config KCSAN_DEBUG
>         bool "Debugging of KCSAN internals"
>
> --
> 2.25.0.265.gbab2e86ba0-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNxtyQy2%2B-v85%3DPcjBAqGt%3D7dcqLi%2BWA3FS8U94nuVYnw%40mail.gmail.com.
