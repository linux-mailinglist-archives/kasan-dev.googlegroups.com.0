Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLGC2DZAKGQE5KVXZEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C0C516B022
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Feb 2020 20:17:02 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id x16sf7268759pgg.5
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Feb 2020 11:17:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582571820; cv=pass;
        d=google.com; s=arc-20160816;
        b=cIpvvt1YiMwT1GlzkVQBzfUJ5U0/2BjfEHR1baN5D4vpApzhSnE3jb4qR70CtBBtNy
         Ud0bEXjN3n93JmIgrCc158pUa7EbTnh5htn3djLwkoptvM6uSJIuXTBsJaJfx3oR/kbA
         k7Hp266irLjTyAv1ffndAO1tgjfUhbHi1rIATdFDhU1qamBKwLLgQLnAyjQOV+pDGWCr
         CUSL2KcAZy8H8NyfRzREIRlh21B+Xq58LEOId6vuc36p5n7vDDLxR2wOYpR27TPmuxDN
         zXIc7Li5nWkhXCF7FaNct+R8AGE23MIvQHfJBu408AeJDSVzOfMvX0TAoWPX1uIanw3f
         GMZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=m99y985jg/x029M5hne7bEdZswztLYfH9+zpeNNkn0I=;
        b=lqP3aYleLRWJVSU+lkjbW4om76HAIH3uQqhdY9B9ZfgpSLfiVf5YNGJbjHkZsgeG4H
         cTFvKqQe7v45ZFFBLdXxg4WOykXkUDw7IaBl9hELQyzuOoN6BVn7xxydSQvm8kW4Zk/N
         rA+aMBOLGxqTXvCCfutYiHpOEVwZ+4+hGcpkogRBnIt/mKDrEv2Qvn9iaSdA1wCHokx7
         lkEFrpNOjxv/QzbTPbEv7syE3EPdisCXWSpXxb2iPJ+Tk3uuR58Eq9A9ChthVJBZ/ORi
         vAuIEDqmT6aP7d4c5IELLhZo3tCVWyXFsPvfE2TsldyCJO5epzq879fdHfiRYgIcjEM3
         YwRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=M1bBNyI8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m99y985jg/x029M5hne7bEdZswztLYfH9+zpeNNkn0I=;
        b=bTTetLTTcGIaYXwpVnLKPDp/zwjSHQkh5OiULf4yDrU4q7SN5v0R2DNsntHwRE/7pC
         0BT6JlxpKHZUgybXQ3YAfP7DogEz/2V2L9Ga9rEHeQ2jEhfOgQWl8aVDUN5RGMRvqYTV
         oOE7NrmwS0WY+gg1pXHCeLhlhqd7Rnefh12OKUeAN/mNaZi1MSWUcrdT/FKWu5tK1mhW
         WZ6GvGETSh0uYtIS3zwK9kVbC/TKUy4FVze1x5apo29mYvwYbgMoIgFswCwDvpLI4PJc
         ah/hb6ofHQpvpx33wU5H2Uw3iDJmylBMj+6CULZq8/2FkcgnMH75VlW/VBeO80hfHfZv
         NgzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m99y985jg/x029M5hne7bEdZswztLYfH9+zpeNNkn0I=;
        b=j+NlEPmwhleXyy6l6fyM6vcozEfldwhrCOM3OaqgsqDZQU6YPo1HXxvRdIx7T9cHAw
         TbazFbY2IrVqVViqPfQ1MdfOXdvGlSTqgJ5yb4dXvyI07PPS+fZiJQEZVN3ce6wI4CCu
         FquGowXpaf72OelCoFRX6UwP/RgUj2tgxCyYW/jDxU9DwtYUMX/W9yhLnRh8kTmw8z9O
         aRPtyamyp75yhuV42V6c6H4ZlPzMGtUiC02E75n+8f1WvFDEB0dGLWwV6EQRrmYFX22D
         L6rkEymnt5AX42z3VbYiKlzm/sj6HZrpclbaL8Jc7AI3slRAcnZlpv7KBghKESTI1Fwd
         9ahg==
X-Gm-Message-State: APjAAAVynwi06g8yM16c0Nxs1kg8yKov7lyHZ3cV5UraqqXKYBNrKFBR
	6gvGJeRkFkaz+Agi9dWdvaU=
X-Google-Smtp-Source: APXvYqxGd7Cz3cvd44G3hTvXpcJwr6bthWWFTioEfGg6lOjs+4yaerjY7Q2t+d3llgkCLlRUny36UQ==
X-Received: by 2002:a63:8c18:: with SMTP id m24mr56020026pgd.70.1582571820616;
        Mon, 24 Feb 2020 11:17:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7281:: with SMTP id d1ls3505866pll.1.gmail; Mon, 24
 Feb 2020 11:17:00 -0800 (PST)
X-Received: by 2002:a17:90a:9284:: with SMTP id n4mr624883pjo.69.1582571820085;
        Mon, 24 Feb 2020 11:17:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582571820; cv=none;
        d=google.com; s=arc-20160816;
        b=tMidqfsfIs5lAcG1g3Hjap755vtdWpMN3TdJqdz6+WCFdd+hMX3ai5I+UPSrznGtKw
         WwXCsawDRSKqruO9zbnLkwR70Y24T+SQldABRRFBYn28cAGs4g794vn+gHk2+V1yTIHy
         strE3U8u55XigZ2neBTPy04sjzRYWj7l+0JkP8/KXmAahcMINgqJ2TzggCke4NVIUDdm
         3j2WbAMjmIe2GaI3l/KckSnE2/22ODxeCOJrecR9fZfy2bWonQWHkXYQ84xBjYQI0Oqe
         NtkRiRcKI35syMvLjoF/XOOLwo50Nk+FupB1ixd800keHjBX2l+AIHNf2IRFMfIQve//
         xvtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qwV+u3WOm9LRc51C8OUh4HjW6YnKJQYbrX5gdSJFQPg=;
        b=vy571YXA/ptafPjt3yMGFTgQT0MW/86GHsanHbkdcp+w9dX3P7hEV9mw+srVBswinJ
         U9ERbhF7B3k0l0Zn6dC/izDviRytpX884mdG0wHrYVmg/EfbodVrGNbfsHtIuFTA7vSo
         8NbrV37LUF66zYdx6a8kJGUmggGY1rckxjbempTOBhZDtYCZxYEKsZ2F7Xr0c93bRldi
         wZibmqig8eiE87KV7z+28VTdi92OW4u2x9XchtCXfiqXwVFWlWKxcAGPFSpt7XEbhdm2
         7F73ZVuphTB42aotb4kYdAeN2rmXd2t5OFRuhSrdiDT/rZ010vBFucQzOUPdHRF4pcrh
         A3CQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=M1bBNyI8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id 12si723740pgx.4.2020.02.24.11.17.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Feb 2020 11:17:00 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id q84so10049299oic.4
        for <kasan-dev@googlegroups.com>; Mon, 24 Feb 2020 11:17:00 -0800 (PST)
X-Received: by 2002:aca:d4c1:: with SMTP id l184mr480740oig.172.1582571819031;
 Mon, 24 Feb 2020 11:16:59 -0800 (PST)
MIME-Version: 1.0
References: <20200221231027.230147-1-elver@google.com> <20200222013642.GQ2935@paulmck-ThinkPad-P72>
In-Reply-To: <20200222013642.GQ2935@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Feb 2020 20:16:47 +0100
Message-ID: <CANpmjNMVczXfr98LTTd4hYBXakq1uGZ14Wfs66pDB=e4JPGjwA@mail.gmail.com>
Subject: Re: [PATCH v3] kcsan: Add option for verbose reporting
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=M1bBNyI8;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Sat, 22 Feb 2020 at 02:36, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Sat, Feb 22, 2020 at 12:10:27AM +0100, Marco Elver wrote:
> > Adds CONFIG_KCSAN_VERBOSE to optionally enable more verbose reports.
> > Currently information about the reporting task's held locks and IRQ
> > trace events are shown, if they are enabled.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > Suggested-by: Qian Cai <cai@lca.pw>
>
> Applied in place of v1, thank you!  Please check -rcu's "dev" branch
> to make sure that I have correct ordering and versions.

(Missed this.) Checked, and all looks good. Thank you!

I hope the new version of this patch now does what you'd expect.

Thanks,
-- Marco

>
> > ---
> > v3:
> > * Typos
> > v2:
> > * Rework obtaining 'current' for the "other thread" -- it now passes
> >   'current' and ensures that we stall until the report was printed, so
> >   that the lockdep information contained in 'current' is accurate. This
> >   was non-trivial but testing so far leads me to conclude this now
> >   reliably prints the held locks for the "other thread" (please test
> >   more!).
> > ---
> >  kernel/kcsan/core.c   |   4 +-
> >  kernel/kcsan/kcsan.h  |   3 ++
> >  kernel/kcsan/report.c | 103 +++++++++++++++++++++++++++++++++++++++++-
> >  lib/Kconfig.kcsan     |  13 ++++++
> >  4 files changed, 120 insertions(+), 3 deletions(-)
> >
> > diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> > index e7387fec66795..065615df88eaa 100644
> > --- a/kernel/kcsan/core.c
> > +++ b/kernel/kcsan/core.c
> > @@ -18,8 +18,8 @@
> >  #include "kcsan.h"
> >
> >  static bool kcsan_early_enable = IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE);
> > -static unsigned int kcsan_udelay_task = CONFIG_KCSAN_UDELAY_TASK;
> > -static unsigned int kcsan_udelay_interrupt = CONFIG_KCSAN_UDELAY_INTERRUPT;
> > +unsigned int kcsan_udelay_task = CONFIG_KCSAN_UDELAY_TASK;
> > +unsigned int kcsan_udelay_interrupt = CONFIG_KCSAN_UDELAY_INTERRUPT;
> >  static long kcsan_skip_watch = CONFIG_KCSAN_SKIP_WATCH;
> >  static bool kcsan_interrupt_watcher = IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER);
> >
> > diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
> > index 892de5120c1b6..e282f8b5749e9 100644
> > --- a/kernel/kcsan/kcsan.h
> > +++ b/kernel/kcsan/kcsan.h
> > @@ -13,6 +13,9 @@
> >  /* The number of adjacent watchpoints to check. */
> >  #define KCSAN_CHECK_ADJACENT 1
> >
> > +extern unsigned int kcsan_udelay_task;
> > +extern unsigned int kcsan_udelay_interrupt;
> > +
> >  /*
> >   * Globally enable and disable KCSAN.
> >   */
> > diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> > index 11c791b886f3c..7bdb515e3662f 100644
> > --- a/kernel/kcsan/report.c
> > +++ b/kernel/kcsan/report.c
> > @@ -1,5 +1,7 @@
> >  // SPDX-License-Identifier: GPL-2.0
> >
> > +#include <linux/debug_locks.h>
> > +#include <linux/delay.h>
> >  #include <linux/jiffies.h>
> >  #include <linux/kernel.h>
> >  #include <linux/lockdep.h>
> > @@ -31,7 +33,26 @@ static struct {
> >       int                     cpu_id;
> >       unsigned long           stack_entries[NUM_STACK_ENTRIES];
> >       int                     num_stack_entries;
> > -} other_info = { .ptr = NULL };
> > +
> > +     /*
> > +      * Optionally pass @current. Typically we do not need to pass @current
> > +      * via @other_info since just @task_pid is sufficient. Passing @current
> > +      * has additional overhead.
> > +      *
> > +      * To safely pass @current, we must either use get_task_struct/
> > +      * put_task_struct, or stall the thread that populated @other_info.
> > +      *
> > +      * We cannot rely on get_task_struct/put_task_struct in case
> > +      * release_report() races with a task being released, and would have to
> > +      * free it in release_report(). This may result in deadlock if we want
> > +      * to use KCSAN on the allocators.
> > +      *
> > +      * Since we also want to reliably print held locks for
> > +      * CONFIG_KCSAN_VERBOSE, the current implementation stalls the thread
> > +      * that populated @other_info until it has been consumed.
> > +      */
> > +     struct task_struct      *task;
> > +} other_info;
> >
> >  /*
> >   * Information about reported races; used to rate limit reporting.
> > @@ -245,6 +266,16 @@ static int sym_strcmp(void *addr1, void *addr2)
> >       return strncmp(buf1, buf2, sizeof(buf1));
> >  }
> >
> > +static void print_verbose_info(struct task_struct *task)
> > +{
> > +     if (!task)
> > +             return;
> > +
> > +     pr_err("\n");
> > +     debug_show_held_locks(task);
> > +     print_irqtrace_events(task);
> > +}
> > +
> >  /*
> >   * Returns true if a report was generated, false otherwise.
> >   */
> > @@ -319,6 +350,9 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
> >                                 other_info.num_stack_entries - other_skipnr,
> >                                 0);
> >
> > +             if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> > +                 print_verbose_info(other_info.task);
> > +
> >               pr_err("\n");
> >               pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
> >                      get_access_type(access_type), ptr, size,
> > @@ -340,6 +374,9 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
> >       stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr,
> >                         0);
> >
> > +     if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> > +             print_verbose_info(current);
> > +
> >       /* Print report footer. */
> >       pr_err("\n");
> >       pr_err("Reported by Kernel Concurrency Sanitizer on:\n");
> > @@ -357,6 +394,67 @@ static void release_report(unsigned long *flags, enum kcsan_report_type type)
> >       spin_unlock_irqrestore(&report_lock, *flags);
> >  }
> >
> > +/*
> > + * Sets @other_info.task and awaits consumption of @other_info.
> > + *
> > + * Precondition: report_lock is held.
> > + * Postcondition: report_lock is held.
> > + */
> > +static void
> > +set_other_info_task_blocking(unsigned long *flags, const volatile void *ptr)
> > +{
> > +     /*
> > +      * We may be instrumenting a code-path where current->state is already
> > +      * something other than TASK_RUNNING.
> > +      */
> > +     const bool is_running = current->state == TASK_RUNNING;
> > +     /*
> > +      * To avoid deadlock in case we are in an interrupt here and this is a
> > +      * race with a task on the same CPU (KCSAN_INTERRUPT_WATCHER), provide a
> > +      * timeout to ensure this works in all contexts.
> > +      *
> > +      * Await approximately the worst case delay of the reporting thread (if
> > +      * we are not interrupted).
> > +      */
> > +     int timeout = max(kcsan_udelay_task, kcsan_udelay_interrupt);
> > +
> > +     other_info.task = current;
> > +     do {
> > +             if (is_running) {
> > +                     /*
> > +                      * Let lockdep know the real task is sleeping, to print
> > +                      * the held locks (recall we turned lockdep off, so
> > +                      * locking/unlocking @report_lock won't be recorded).
> > +                      */
> > +                     set_current_state(TASK_UNINTERRUPTIBLE);
> > +             }
> > +             spin_unlock_irqrestore(&report_lock, *flags);
> > +             /*
> > +              * We cannot call schedule() since we also cannot reliably
> > +              * determine if sleeping here is permitted -- see in_atomic().
> > +              */
> > +
> > +             udelay(1);
> > +             spin_lock_irqsave(&report_lock, *flags);
> > +             if (timeout-- < 0) {
> > +                     /*
> > +                      * Abort. Reset other_info.task to NULL, since it
> > +                      * appears the other thread is still going to consume
> > +                      * it. It will result in no verbose info printed for
> > +                      * this task.
> > +                      */
> > +                     other_info.task = NULL;
> > +                     break;
> > +             }
> > +             /*
> > +              * If @ptr nor @current matches, then our information has been
> > +              * consumed and we may continue. If not, retry.
> > +              */
> > +     } while (other_info.ptr == ptr && other_info.task == current);
> > +     if (is_running)
> > +             set_current_state(TASK_RUNNING);
> > +}
> > +
> >  /*
> >   * Depending on the report type either sets other_info and returns false, or
> >   * acquires the matching other_info and returns true. If other_info is not
> > @@ -388,6 +486,9 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
> >               other_info.cpu_id               = cpu_id;
> >               other_info.num_stack_entries    = stack_trace_save(other_info.stack_entries, NUM_STACK_ENTRIES, 1);
> >
> > +             if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> > +                     set_other_info_task_blocking(flags, ptr);
> > +
> >               spin_unlock_irqrestore(&report_lock, *flags);
> >
> >               /*
> > diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> > index 081ed2e1bf7b1..0f1447ff8f558 100644
> > --- a/lib/Kconfig.kcsan
> > +++ b/lib/Kconfig.kcsan
> > @@ -20,6 +20,19 @@ menuconfig KCSAN
> >
> >  if KCSAN
> >
> > +config KCSAN_VERBOSE
> > +     bool "Show verbose reports with more information about system state"
> > +     depends on PROVE_LOCKING
> > +     help
> > +       If enabled, reports show more information about the system state that
> > +       may help better analyze and debug races. This includes held locks and
> > +       IRQ trace events.
> > +
> > +       While this option should generally be benign, we call into more
> > +       external functions on report generation; if a race report is
> > +       generated from any one of them, system stability may suffer due to
> > +       deadlocks or recursion.  If in doubt, say N.
> > +
> >  config KCSAN_DEBUG
> >       bool "Debugging of KCSAN internals"
> >
> > --
> > 2.25.0.265.gbab2e86ba0-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMVczXfr98LTTd4hYBXakq1uGZ14Wfs66pDB%3De4JPGjwA%40mail.gmail.com.
