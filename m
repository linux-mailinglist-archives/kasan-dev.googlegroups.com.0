Return-Path: <kasan-dev+bncBAABBTEL6DZAKGQEGZI4YUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id DF4F3174F05
	for <lists+kasan-dev@lfdr.de>; Sun,  1 Mar 2020 19:58:21 +0100 (CET)
Received: by mail-vs1-xe3a.google.com with SMTP id 123sf1129217vsg.2
        for <lists+kasan-dev@lfdr.de>; Sun, 01 Mar 2020 10:58:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583089100; cv=pass;
        d=google.com; s=arc-20160816;
        b=sr37F7J1XkUoocaYTU+SlZ7Tt+BiBCScIJha1oktJGasCdfYpfMWgZTWlCvQg5hB4Y
         bvTwvqaDcQk9xpj7NuTGXisHezASdPvVAIhu0mlnzM54apNs+PA/zaao3zy5MdmnmpAb
         mtZSaR0hTUN/vwF8FQ7OJ+VZWD6b1/gAtTYvy7iuZNZWSPVwAu1kpRfg0brsIpjQUV52
         JJ0Qz3HSaecqmFdDXIN7EKkHoynlwD4yjFjW7nWqLbs5D6yy+uuLT9sZ5IhyScCIf79I
         el6EuJmyAZIDhsMm9C3mmdVGs+cwD3orZrzLNAYob8EK5QTGqfR6w+JdjJNk1ANAf171
         dCmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=W//5xuC9tJ3Bp2StMWjV34awtHVW8Hkut7Kcy2H7XHw=;
        b=sMh048sIKHTv3LGIOrm21p7cFpU64m1DaQT2WP+CprrjDozRS4HN65nWxPKbbdsU+P
         Ii1uoK3HdH+q9aKZJtD76SLK9oYk+KzFiRE+w7hXj+78k/7NeZMejmUkeKZ4enuMEZqf
         bsOncZSq97MkXxj78H+r/vRso6stFEfoEHcWVco4ePjuv0ph4joE7Xfr4dZqzIih9+8L
         2ibSU4hrrm0FOt15caQNa+2HMghHfO4OAx9CEIaLCBwFeQYdSL1JRYXyKZoPfhghAvjM
         4oHOffvVgT7qba6wDndWsNzaoLWnmHm+yeiDyNYmcnGYx30dfYxUsVqyQhpOgnwv75dh
         qH3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=j3FxICnE;
       spf=pass (google.com: domain of srs0=wqtx=4s=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=WqtX=4S=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W//5xuC9tJ3Bp2StMWjV34awtHVW8Hkut7Kcy2H7XHw=;
        b=EIW3BBK9QNDA7i9gYWSu/YrMP0xBeywhK/66cYJDg89Ow44f7Rj3oF6KeOCty2pnP4
         dO6FBPPOzV8X4+GPlgZaa9X7zkkVAoVboLtPWaHG2Neh5vgS7XTirA19O52+bs4Aptrf
         hKRzbcuE62FwgCF9LAGqKsP/SPuTKXHgvt7RcKbzfTkr+qy2FIf59K8ehjyCwwmeGDc9
         uWYJI9rswdPrV57RSx8KsT0X1e59W6u6eSlQFdF0JxUVpVxANfn36K4Vf/KbAKsVdrwG
         A4Bue6dwIs0c0TOKium28GG/JVCGP7+FmzK2p+pKbpBil7NAQ+r2AcZSd16f0zrUBxzt
         J99g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=W//5xuC9tJ3Bp2StMWjV34awtHVW8Hkut7Kcy2H7XHw=;
        b=HgtlclbSclm83Tnu1SQcnUgNkSdQPtB/fw3xKgjaXElnRWyMGg0cl5VMcwDJwwI7z0
         PT+iNv0irvlwMV1wIFMUc7S39plBclXbJ3h8KMKPzJcvujM7gt6QXBo4ng4I1FA/kpjR
         cOcoOL+ApRjWUtPfmS7ta/tttER1lQJxBAAGa1c35TlkAt5CmVDvWNXo2HBaUXquGNu8
         BERSPTwBsYxgfHkkYm9yg0TX1e5nUYXW4fB8+JWYCurl16L6vk1OOr90z3m/wBLOFmEJ
         BWSYveuXr6wsJBIXjK1ypPVIBgEEgCI1UseBSf+LXYlnMYLbA2/Azmyjc5W7hUPTbtwq
         Xx0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1bRe14aDvBFGiYD6HQGLg/QHQ00j8o3z8nQFdzwNBDrp3hDz4p
	9O81GyT3SBVeLfr//Bhpg0w=
X-Google-Smtp-Source: ADFU+vsWfwFY8Wf8lU3dAQFicOtHi8n3PByK4w3y85wIFg6ysvwJhD9gIXJtfjIEb35cQM9AIAq6tQ==
X-Received: by 2002:a67:eed3:: with SMTP id o19mr18459vsp.9.1583089100621;
        Sun, 01 Mar 2020 10:58:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ec03:: with SMTP id d3ls286737vso.3.gmail; Sun, 01 Mar
 2020 10:58:20 -0800 (PST)
X-Received: by 2002:a67:fbcb:: with SMTP id o11mr7680695vsr.109.1583089100222;
        Sun, 01 Mar 2020 10:58:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583089100; cv=none;
        d=google.com; s=arc-20160816;
        b=rgLp6q1JZfvoEqC7gBqirXrp6GtSjnurjK28cOkn9ms3d94mkJZ1oy9Jy9j6V1dle1
         nr1ildBaOPOBz/o8LcIYMbzqOUX+dm4gjwJ6No425NNR6rok94wLTqdG0jTZx59TtFW4
         icweo6Si5N1kAUiHgm9USqbgR+hgNEEGgb503yCB0iqH2QOpDEfBXyRFiyUdMtmTy2gB
         QBS4jhB7alj5q/W6tFKRatfYX5qAUAlI4Swyh/xuusyvkYvTT/VumH6t+Fjq8REloI7Z
         rMLfXjh/jIZn1nZgq4z9iWFeYmRzWoiyS3u8OWDDtb0JwxBNT+PIW24oOF9BicaVRNeR
         N/mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=8Tw2SYLl+1RlMMNQS5J57/kpzNKdW545URo2Ogoh2Bg=;
        b=IZgRb+GkBiBtqJjhPNNY6JFI4O/U6LYxdH9i924Sf/ra2wFMQp1GlO7tV4CiOaM/UJ
         6rHzlNHdOb8mrZVB3Ikc5YEX/lsIBD1boB04Sma/YoSzw/4qsc2FQ9GisPxYGeYguzK0
         VHiLO72A/gsXLj6QNiy3IpvkAXcwJ8TJlqjXjUJ1yYp7Q8Q62bsSxt54re5zENakKhEl
         YT5y/WtnASLRvIvwwk3xqEUauNlXUC58yo7Dd7SHy1rGsMrce8ZjvGShpsTGmjUdTtP2
         aJc3LRG6d5jhdP3OQPDcaulQGjco1iwuLy43Vwmg7Yo7MWTv1T579rtZdyzHDfrfGMUH
         Emsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=j3FxICnE;
       spf=pass (google.com: domain of srs0=wqtx=4s=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=WqtX=4S=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i27si615595uat.1.2020.03.01.10.58.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 01 Mar 2020 10:58:20 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=wqtx=4s=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 047E1246B6;
	Sun,  1 Mar 2020 18:58:19 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id C9D94352272F; Sun,  1 Mar 2020 10:58:18 -0800 (PST)
Date: Sun, 1 Mar 2020 10:58:18 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>, Qian Cai <cai@lca.pw>
Subject: Re: [PATCH v3] kcsan: Add option for verbose reporting
Message-ID: <20200301185818.GV2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200221231027.230147-1-elver@google.com>
 <20200222013642.GQ2935@paulmck-ThinkPad-P72>
 <CANpmjNMVczXfr98LTTd4hYBXakq1uGZ14Wfs66pDB=e4JPGjwA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMVczXfr98LTTd4hYBXakq1uGZ14Wfs66pDB=e4JPGjwA@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=j3FxICnE;       spf=pass
 (google.com: domain of srs0=wqtx=4s=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=WqtX=4S=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Feb 24, 2020 at 08:16:47PM +0100, Marco Elver wrote:
> On Sat, 22 Feb 2020 at 02:36, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On Sat, Feb 22, 2020 at 12:10:27AM +0100, Marco Elver wrote:
> > > Adds CONFIG_KCSAN_VERBOSE to optionally enable more verbose reports.
> > > Currently information about the reporting task's held locks and IRQ
> > > trace events are shown, if they are enabled.
> > >
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > Suggested-by: Qian Cai <cai@lca.pw>
> >
> > Applied in place of v1, thank you!  Please check -rcu's "dev" branch
> > to make sure that I have correct ordering and versions.
> 
> (Missed this.) Checked, and all looks good. Thank you!
> 
> I hope the new version of this patch now does what you'd expect.

Indeed it does!  Please see below for one example from an rcutorture
run.

							Thanx, Paul

------------------------------------------------------------------------

[    3.162466] ==================================================================
[    3.162989] BUG: KCSAN: data-race in mutex_spin_on_owner+0xc6/0x2b0
[    3.162989] 
[    3.162989] race at unknown origin, with read to 0xffff8e91dde0d838 of 4 bytes by task 156 on cpu 3:
[    3.162989]  mutex_spin_on_owner+0xc6/0x2b0
[    3.162989]  __mutex_lock+0x252/0xc70
[    3.162989]  mutex_lock_nested+0x27/0x30
[    3.162989]  ata_eh_acquire+0x32/0x80
[    3.162989]  ata_msleep+0x72/0xa0
[    3.162989]  sata_link_debounce+0xed/0x1e0
[    3.162989]  sata_link_resume+0x146/0x1b0
[    3.162989]  sata_link_hardreset+0x16c/0x290
[    3.162989]  ahci_do_hardreset+0x19b/0x220
[    3.162989]  ahci_hardreset+0x3e/0x70
[    3.168849] ata5: SATA link down (SStatus 0 SControl 300)
[    3.162989]  ata_do_reset+0x35/0xa0
[    3.162989]  ata_eh_reset+0x77b/0x1300
[    3.162989]  ata_eh_recover+0x433/0x2090
[    3.162989]  sata_pmp_error_handler+0x86a/0xef0
[    3.162989]  ahci_error_handler+0x7c/0xd0
[    3.162989]  ata_scsi_port_error_handler+0x3ef/0xb90
[    3.162989]  ata_scsi_error+0x185/0x1d0
[    3.162989]  scsi_error_handler+0x13f/0x710
[    3.172310] ata3.00: ATAPI: QEMU DVD-ROM, 2.5+, max UDMA/100
[    3.162989]  kthread+0x1c3/0x1e0
[    3.162989]  ret_from_fork+0x3a/0x50
[    3.162989] 
[    3.162989] 2 locks held by scsi_eh_3/156:
[    3.162989]  #0: ffff8e91ddef90d0 (&host->eh_mutex){+.+.}, at: ata_eh_acquire+0x32/0x80
[    3.162989]  #1: ffffffff86067ba0 (rcu_read_lock){....}, at: mutex_spin_on_owner+0x0/0x2b0

> Thanks,
> -- Marco
> 
> >
> > > ---
> > > v3:
> > > * Typos
> > > v2:
> > > * Rework obtaining 'current' for the "other thread" -- it now passes
> > >   'current' and ensures that we stall until the report was printed, so
> > >   that the lockdep information contained in 'current' is accurate. This
> > >   was non-trivial but testing so far leads me to conclude this now
> > >   reliably prints the held locks for the "other thread" (please test
> > >   more!).
> > > ---
> > >  kernel/kcsan/core.c   |   4 +-
> > >  kernel/kcsan/kcsan.h  |   3 ++
> > >  kernel/kcsan/report.c | 103 +++++++++++++++++++++++++++++++++++++++++-
> > >  lib/Kconfig.kcsan     |  13 ++++++
> > >  4 files changed, 120 insertions(+), 3 deletions(-)
> > >
> > > diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> > > index e7387fec66795..065615df88eaa 100644
> > > --- a/kernel/kcsan/core.c
> > > +++ b/kernel/kcsan/core.c
> > > @@ -18,8 +18,8 @@
> > >  #include "kcsan.h"
> > >
> > >  static bool kcsan_early_enable = IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE);
> > > -static unsigned int kcsan_udelay_task = CONFIG_KCSAN_UDELAY_TASK;
> > > -static unsigned int kcsan_udelay_interrupt = CONFIG_KCSAN_UDELAY_INTERRUPT;
> > > +unsigned int kcsan_udelay_task = CONFIG_KCSAN_UDELAY_TASK;
> > > +unsigned int kcsan_udelay_interrupt = CONFIG_KCSAN_UDELAY_INTERRUPT;
> > >  static long kcsan_skip_watch = CONFIG_KCSAN_SKIP_WATCH;
> > >  static bool kcsan_interrupt_watcher = IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER);
> > >
> > > diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
> > > index 892de5120c1b6..e282f8b5749e9 100644
> > > --- a/kernel/kcsan/kcsan.h
> > > +++ b/kernel/kcsan/kcsan.h
> > > @@ -13,6 +13,9 @@
> > >  /* The number of adjacent watchpoints to check. */
> > >  #define KCSAN_CHECK_ADJACENT 1
> > >
> > > +extern unsigned int kcsan_udelay_task;
> > > +extern unsigned int kcsan_udelay_interrupt;
> > > +
> > >  /*
> > >   * Globally enable and disable KCSAN.
> > >   */
> > > diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> > > index 11c791b886f3c..7bdb515e3662f 100644
> > > --- a/kernel/kcsan/report.c
> > > +++ b/kernel/kcsan/report.c
> > > @@ -1,5 +1,7 @@
> > >  // SPDX-License-Identifier: GPL-2.0
> > >
> > > +#include <linux/debug_locks.h>
> > > +#include <linux/delay.h>
> > >  #include <linux/jiffies.h>
> > >  #include <linux/kernel.h>
> > >  #include <linux/lockdep.h>
> > > @@ -31,7 +33,26 @@ static struct {
> > >       int                     cpu_id;
> > >       unsigned long           stack_entries[NUM_STACK_ENTRIES];
> > >       int                     num_stack_entries;
> > > -} other_info = { .ptr = NULL };
> > > +
> > > +     /*
> > > +      * Optionally pass @current. Typically we do not need to pass @current
> > > +      * via @other_info since just @task_pid is sufficient. Passing @current
> > > +      * has additional overhead.
> > > +      *
> > > +      * To safely pass @current, we must either use get_task_struct/
> > > +      * put_task_struct, or stall the thread that populated @other_info.
> > > +      *
> > > +      * We cannot rely on get_task_struct/put_task_struct in case
> > > +      * release_report() races with a task being released, and would have to
> > > +      * free it in release_report(). This may result in deadlock if we want
> > > +      * to use KCSAN on the allocators.
> > > +      *
> > > +      * Since we also want to reliably print held locks for
> > > +      * CONFIG_KCSAN_VERBOSE, the current implementation stalls the thread
> > > +      * that populated @other_info until it has been consumed.
> > > +      */
> > > +     struct task_struct      *task;
> > > +} other_info;
> > >
> > >  /*
> > >   * Information about reported races; used to rate limit reporting.
> > > @@ -245,6 +266,16 @@ static int sym_strcmp(void *addr1, void *addr2)
> > >       return strncmp(buf1, buf2, sizeof(buf1));
> > >  }
> > >
> > > +static void print_verbose_info(struct task_struct *task)
> > > +{
> > > +     if (!task)
> > > +             return;
> > > +
> > > +     pr_err("\n");
> > > +     debug_show_held_locks(task);
> > > +     print_irqtrace_events(task);
> > > +}
> > > +
> > >  /*
> > >   * Returns true if a report was generated, false otherwise.
> > >   */
> > > @@ -319,6 +350,9 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
> > >                                 other_info.num_stack_entries - other_skipnr,
> > >                                 0);
> > >
> > > +             if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> > > +                 print_verbose_info(other_info.task);
> > > +
> > >               pr_err("\n");
> > >               pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
> > >                      get_access_type(access_type), ptr, size,
> > > @@ -340,6 +374,9 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
> > >       stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr,
> > >                         0);
> > >
> > > +     if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> > > +             print_verbose_info(current);
> > > +
> > >       /* Print report footer. */
> > >       pr_err("\n");
> > >       pr_err("Reported by Kernel Concurrency Sanitizer on:\n");
> > > @@ -357,6 +394,67 @@ static void release_report(unsigned long *flags, enum kcsan_report_type type)
> > >       spin_unlock_irqrestore(&report_lock, *flags);
> > >  }
> > >
> > > +/*
> > > + * Sets @other_info.task and awaits consumption of @other_info.
> > > + *
> > > + * Precondition: report_lock is held.
> > > + * Postcondition: report_lock is held.
> > > + */
> > > +static void
> > > +set_other_info_task_blocking(unsigned long *flags, const volatile void *ptr)
> > > +{
> > > +     /*
> > > +      * We may be instrumenting a code-path where current->state is already
> > > +      * something other than TASK_RUNNING.
> > > +      */
> > > +     const bool is_running = current->state == TASK_RUNNING;
> > > +     /*
> > > +      * To avoid deadlock in case we are in an interrupt here and this is a
> > > +      * race with a task on the same CPU (KCSAN_INTERRUPT_WATCHER), provide a
> > > +      * timeout to ensure this works in all contexts.
> > > +      *
> > > +      * Await approximately the worst case delay of the reporting thread (if
> > > +      * we are not interrupted).
> > > +      */
> > > +     int timeout = max(kcsan_udelay_task, kcsan_udelay_interrupt);
> > > +
> > > +     other_info.task = current;
> > > +     do {
> > > +             if (is_running) {
> > > +                     /*
> > > +                      * Let lockdep know the real task is sleeping, to print
> > > +                      * the held locks (recall we turned lockdep off, so
> > > +                      * locking/unlocking @report_lock won't be recorded).
> > > +                      */
> > > +                     set_current_state(TASK_UNINTERRUPTIBLE);
> > > +             }
> > > +             spin_unlock_irqrestore(&report_lock, *flags);
> > > +             /*
> > > +              * We cannot call schedule() since we also cannot reliably
> > > +              * determine if sleeping here is permitted -- see in_atomic().
> > > +              */
> > > +
> > > +             udelay(1);
> > > +             spin_lock_irqsave(&report_lock, *flags);
> > > +             if (timeout-- < 0) {
> > > +                     /*
> > > +                      * Abort. Reset other_info.task to NULL, since it
> > > +                      * appears the other thread is still going to consume
> > > +                      * it. It will result in no verbose info printed for
> > > +                      * this task.
> > > +                      */
> > > +                     other_info.task = NULL;
> > > +                     break;
> > > +             }
> > > +             /*
> > > +              * If @ptr nor @current matches, then our information has been
> > > +              * consumed and we may continue. If not, retry.
> > > +              */
> > > +     } while (other_info.ptr == ptr && other_info.task == current);
> > > +     if (is_running)
> > > +             set_current_state(TASK_RUNNING);
> > > +}
> > > +
> > >  /*
> > >   * Depending on the report type either sets other_info and returns false, or
> > >   * acquires the matching other_info and returns true. If other_info is not
> > > @@ -388,6 +486,9 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
> > >               other_info.cpu_id               = cpu_id;
> > >               other_info.num_stack_entries    = stack_trace_save(other_info.stack_entries, NUM_STACK_ENTRIES, 1);
> > >
> > > +             if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> > > +                     set_other_info_task_blocking(flags, ptr);
> > > +
> > >               spin_unlock_irqrestore(&report_lock, *flags);
> > >
> > >               /*
> > > diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> > > index 081ed2e1bf7b1..0f1447ff8f558 100644
> > > --- a/lib/Kconfig.kcsan
> > > +++ b/lib/Kconfig.kcsan
> > > @@ -20,6 +20,19 @@ menuconfig KCSAN
> > >
> > >  if KCSAN
> > >
> > > +config KCSAN_VERBOSE
> > > +     bool "Show verbose reports with more information about system state"
> > > +     depends on PROVE_LOCKING
> > > +     help
> > > +       If enabled, reports show more information about the system state that
> > > +       may help better analyze and debug races. This includes held locks and
> > > +       IRQ trace events.
> > > +
> > > +       While this option should generally be benign, we call into more
> > > +       external functions on report generation; if a race report is
> > > +       generated from any one of them, system stability may suffer due to
> > > +       deadlocks or recursion.  If in doubt, say N.
> > > +
> > >  config KCSAN_DEBUG
> > >       bool "Debugging of KCSAN internals"
> > >
> > > --
> > > 2.25.0.265.gbab2e86ba0-goog
> > >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200301185818.GV2935%40paulmck-ThinkPad-P72.
