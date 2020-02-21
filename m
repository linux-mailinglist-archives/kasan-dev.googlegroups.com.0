Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWFUYDZAKGQEGLCPULA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 17CAB1685BD
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2020 18:58:50 +0100 (CET)
Received: by mail-vk1-xa3b.google.com with SMTP id h197sf1245413vka.5
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2020 09:58:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582307929; cv=pass;
        d=google.com; s=arc-20160816;
        b=nG/dqvzwky3NJ7BjT986XkAguGzWRMmKBOpIiqD5TONMv3sE7hwbXnnZpSY9tsH1aH
         Z0Q4LHT+EDf9F1wH4TdZvGRWzS/UzW34JAvpRLs4zEFgNK0pcBXwocJ9nQ14E3+iAjlL
         bz6/McOjCIgJs5RaqP31a+pAd4TB/CvB1/nKEuyky/6MKkGSY1mAM0bdK5MzgQZA/5Ut
         aQlin2lQPS/c0BBb423Bk5hlDz6nuYRyhfAr7NXLHNt705axjXPnu3ebNcIws4LA3BSL
         J9Xv9wyeYaDIiNPEkXic+To0xN+VxugRED8Gpa8Yw/sDPXjTrD1wDgIeTRTkciC4nxM9
         Ym+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=46K47k3PkkeB3ja/8pkwTAgYYZcZ8sDlJffP7bRgmno=;
        b=hreVVSlsq7urGPtFgMVeR9Q4NucMSqu3FLi/JJBG8mphre0jSdLdiIYyu2by4mnmAY
         RBzMyGW8Nml/cXYsTuB2AiWZOWq3Yf0TiTCETS9gVyFwmVMmzKQCqhrExPKeL884Vw2P
         AjcvyLjy4ji+aZRnSRZ31hbImzje1CRmv2iw+68NRnyd9RWCNNYgT7LK5sSXZdGsbmvd
         FIi5b5QNWMbnh856Q5drzCE2z7QPxe3/TUDBYIHOYQXOxwkjcvn0OGtL2HuOCZCeiNin
         YHldMVz8xxAWI7+MyUu0YbSTiOF83vgnHpGfabQnZIUCh8bt8hbSug7ui2ESkpuZfWrp
         x9Hg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Wsv50n8Q;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=46K47k3PkkeB3ja/8pkwTAgYYZcZ8sDlJffP7bRgmno=;
        b=LHtwP29aV18dtNRs4tIL9ZSnZRZr94d+vqLYMV+9jEwU/DpaA0BpPIm56ahAgsQgXg
         0FClM6Ynk24p3SK99N43Cyz8TdyDc96xUNZrnzro5PalHlFHGnGKYppCLRUuZkd+RB6E
         m5IIk9oEusijNBulk0N/1VuOHzCHQ8rTIf+ta5dTgtdrfdG3o0qsngZw2YKUThe0WBuQ
         tQIBiaLdrbzTSPFb38FFVMVuqJKEi4tDg+zMcWjOUub0Imj2EsDBwpR+bvZWtSSIC+wv
         qGh/Xesv0RJ0IwTR7gi180GNrT6wfUglefP6jr1h64bMOrZ+JWGwjVUyxEZru/aG3nyG
         v9IQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=46K47k3PkkeB3ja/8pkwTAgYYZcZ8sDlJffP7bRgmno=;
        b=P9Whmv9r9mF9r3CwXnXuxkXn1l/JzXPitm8hCbo6QV/vB5aUX0kK1vdDU3aau1ZLXI
         3pw0ExX5azk4/SdUFZHseniid8Ksfu3Y113zbX3MQZ+HSadjTHLLCU2oXivboeICLIED
         KgQwcbzyigZwRh5OCGyIL2YviiNB0McGThkGB3dcrghUSBGKa99QvlU46hSoPpNDQVKD
         S37Bjcg4KPbnKDj1v1OtcLB2kwkhtzaDQeCwDU4gYKLZ1oQZR2mre9jGY5W3VVKt6e/a
         NaLOPClizP94XpZJAh+6TlmI7j2QzEkLSluEOjpbycB10VNXEp/5bhQN+Vm01bAAPKGo
         IUEw==
X-Gm-Message-State: APjAAAXWh9kd0dM4cqokyHbECwG8EEiVM/aW9DR5w7r8dF33vN7SAoi6
	LizoZmf9Uhd3y1hcW4C3GuI=
X-Google-Smtp-Source: APXvYqzNCv54dr3Xv4Ox5HvAUsq5pUNILkrsyfoesNN5fs2Cb4Oa92V0HhraJ2plUNxXuFyIQdSXig==
X-Received: by 2002:ac5:c64c:: with SMTP id j12mr17904461vkl.11.1582307928864;
        Fri, 21 Feb 2020 09:58:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:2883:: with SMTP id d3ls217174uad.6.gmail; Fri, 21 Feb
 2020 09:58:48 -0800 (PST)
X-Received: by 2002:ab0:694d:: with SMTP id c13mr19042381uas.43.1582307928383;
        Fri, 21 Feb 2020 09:58:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582307928; cv=none;
        d=google.com; s=arc-20160816;
        b=g+bamssAvJ4wAYxd5r8SpEHPg+6TLrnczIgmdFsM0HHpZP8PwSERF9jEDLjITR1Ewd
         MBlkXVNrsvHmoEeGvJWEQ8yp+z4T00exrVs0oJPmTryBfKJIvp7qEvAAofVyMoENuUQC
         U3D6tNPqjpIZ3J4Glvy5RI4f2UAJu7GfBpDfcdE6l7qyirSz4WA/r8fyQU5tmSzv1RIg
         i4UBp+KK7x+ugbJB5X0hSwosgdaK1oKbfeLdgKWhYZP0Uuhlcm9BDLTK9J1w67QZqdx3
         UfdXaNlVebiSjz1KSxugIPI4p4qYfnOWZrEeYNwgd0TLee8sdv3dSS5PYYbG4morSJMN
         n8mQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=02nz5IY2LDSzsi6Uwi52GMpeaKEGb8jSNiWMvCCts+g=;
        b=EPPuWWB/L0puwmcDZwhOPEAQ9QzDcl12p9RLzRgtZIuQEP1l/wzfYP1zfzYk2wfSH3
         88Wrt0kYTfzDp0AhDsC3H60TQd+i4kQOQLEN1e0JI4QRP+j/z80F02UPd5uB9J9REsNS
         9Ql3Gplm0zuNJ73pMszQ82rMsnMcSwods0/FnIj4ILljSehj1DIVLtoQqWrGL9c3GmBn
         yRM4KCaQIJxmgK4tHcTwa1mfITSuerSaT8FKgH09n1SBk4OirvCNPLcgOsyGSw8Vt9Fu
         1aBmcJHKl7dxM/29zSgEmqPtAXkcprPulW1j8YxDhbFZFyfl3o5ANp52SnIBpA/8ni+Y
         yBtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Wsv50n8Q;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id h6si276937vkc.3.2020.02.21.09.58.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Feb 2020 09:58:48 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id i6so2771457otr.7
        for <kasan-dev@googlegroups.com>; Fri, 21 Feb 2020 09:58:48 -0800 (PST)
X-Received: by 2002:a05:6830:1d7b:: with SMTP id l27mr27496908oti.251.1582307927408;
 Fri, 21 Feb 2020 09:58:47 -0800 (PST)
MIME-Version: 1.0
References: <20200219151531.161515-1-elver@google.com> <1582305008.7365.111.camel@lca.pw>
In-Reply-To: <1582305008.7365.111.camel@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 21 Feb 2020 18:58:36 +0100
Message-ID: <CANpmjNMG4nZYLi+wFR-R_ifq1+u-YfC7b68iucCRWNd4M==vrw@mail.gmail.com>
Subject: Re: [PATCH] kcsan: Add option for verbose reporting
To: Qian Cai <cai@lca.pw>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Wsv50n8Q;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Fri, 21 Feb 2020 at 18:10, Qian Cai <cai@lca.pw> wrote:
>
> On Wed, 2020-02-19 at 16:15 +0100, Marco Elver wrote:
> > Adds CONFIG_KCSAN_VERBOSE to optionally enable more verbose reports.
> > Currently information about the reporting task's held locks and IRQ
> > trace events are shown, if they are enabled.
>
> Well, there is a report. I don't understand why it said there is no lock held in
> the writer, but clearly there is this right after in
> jbd2_journal_commit_transaction(),
>
>  spin_unlock(&jh->b_state_lock);

This is sort of expected right now.  In the comment that adds this
feature, it also has a comment for the "other thread" (in this case
the writer):

/*
* Showing held locks for a running task is unreliable, so just
* skip this. The printed locks are very likely inconsistent,
* since the stack trace was obtained when the actual race
* occurred and the task has since continued execution. Since we
* cannot display the below information from the racing thread,
* but must print it all from the watcher thread, bail out.
* Note: Even if the task is not running, there is a chance that
* the locks held may be inconsistent.
*/

Hmm, I suppose I could try harder and make this reliable by stalling
the other task if this option is on. Let me give that a try.

Thanks,
-- Marco


> [ 2268.021382][T25724] BUG: KCSAN: data-race in __jbd2_journal_refile_buffer
> [jbd2] / jbd2_write_access_granted [jbd2]
> [ 2268.031888][T25724]
> [ 2268.034099][T25724] write to 0xffff99f9b1bd0e30 of 8 bytes by task 25721 on
> cpu 70:
> [ 2268.041842][T25724]  __jbd2_journal_refile_buffer+0xdd/0x210 [jbd2]
> __jbd2_journal_refile_buffer at fs/jbd2/transaction.c:2569
> [ 2268.048181][T25724]  jbd2_journal_commit_transaction+0x2d15/0x3f20 [jbd2]
> (inlined by) jbd2_journal_commit_transaction at fs/jbd2/commit.c:1033
> [ 2268.055042][T25724]  kjournald2+0x13b/0x450 [jbd2]
> [ 2268.059876][T25724]  kthread+0x1cd/0x1f0
> [ 2268.063835][T25724]  ret_from_fork+0x27/0x50
> [ 2268.068143][T25724]
> [ 2268.070348][T25724] no locks held by jbd2/loop0-8/25721.
> [ 2268.075699][T25724] irq event stamp: 77604
> [ 2268.079830][T25724] hardirqs last  enabled at (77603): [<ffffffff986da853>]
> _raw_spin_unlock_irqrestore+0x53/0x60
> [ 2268.090166][T25724] hardirqs last disabled at (77604): [<ffffffff986d0841>]
> __schedule+0x181/0xa50
> [ 2268.099192][T25724] softirqs last  enabled at (76092): [<ffffffff98a0034c>]
> __do_softirq+0x34c/0x57c
> [ 2268.108392][T25724] softirqs last disabled at (76005): [<ffffffff97cc67a2>]
> irq_exit+0xa2/0xc0
> [ 2268.117062][T25724]
> [ 2268.119269][T25724] read to 0xffff99f9b1bd0e30 of 8 bytes by task 25724 on
> cpu 68:
> [ 2268.126916][T25724]  jbd2_write_access_granted+0x1b2/0x250 [jbd2]
> jbd2_write_access_granted at fs/jbd2/transaction.c:1155
> [ 2268.133086][T25724]  jbd2_journal_get_write_access+0x2c/0x60 [jbd2]
> [ 2268.139492][T25724]  __ext4_journal_get_write_access+0x50/0x90 [ext4]
> [ 2268.146076][T25724]  ext4_mb_mark_diskspace_used+0x158/0x620 [ext4]
> [ 2268.152507][T25724]  ext4_mb_new_blocks+0x54f/0xca0 [ext4]
> [ 2268.158125][T25724]  ext4_ind_map_blocks+0xc79/0x1b40 [ext4]
> [ 2268.163923][T25724]  ext4_map_blocks+0x3b4/0x950 [ext4]
> [ 2268.169284][T25724]  _ext4_get_block+0xfc/0x270 [ext4]
> [ 2268.174556][T25724]  ext4_get_block+0x3b/0x50 [ext4]
> [ 2268.179566][T25724]  __block_write_begin_int+0x22e/0xae0
> [ 2268.184921][T25724]  __block_write_begin+0x39/0x50
> [ 2268.189842][T25724]  ext4_write_begin+0x388/0xb50 [ext4]
> [ 2268.195195][T25724]  generic_perform_write+0x15d/0x290
> [ 2268.200467][T25724]  ext4_buffered_write_iter+0x11f/0x210 [ext4]
> [ 2268.206612][T25724]  ext4_file_write_iter+0xce/0x9e0 [ext4]
> [ 2268.212228][T25724]  new_sync_write+0x29c/0x3b0
> [ 2268.216794][T25724]  __vfs_write+0x92/0xa0
> [ 2268.220924][T25724]  vfs_write+0x103/0x260
> [ 2268.225052][T25724]  ksys_write+0x9d/0x130
> [ 2268.229182][T25724]  __x64_sys_write+0x4c/0x60
> [ 2268.233666][T25724]  do_syscall_64+0x91/0xb05
> [ 2268.238058][T25724]  entry_SYSCALL_64_after_hwframe+0x49/0xbe
> [ 2268.243846][T25724]
> [ 2268.246056][T25724] 5 locks held by fsync04/25724:
> [ 2268.250880][T25724]  #0: ffff99f9911093f8 (sb_writers#13){.+.+}, at:
> vfs_write+0x21c/0x260
> [ 2268.259211][T25724]  #1: ffff99f9db4c0348 (&sb->s_type-
> >i_mutex_key#15){+.+.}, at: ext4_buffered_write_iter+0x65/0x210 [ext4]
> [ 2268.270693][T25724]  #2: ffff99f5e7dfcf58 (jbd2_handle){++++}, at:
> start_this_handle+0x1c1/0x9d0 [jbd2]
> [ 2268.280180][T25724]  #3: ffff99f9db4c0168 (&ei->i_data_sem){++++}, at:
> ext4_map_blocks+0x176/0x950 [ext4]
> [ 2268.289913][T25724]  #4: ffffffff99086b40 (rcu_read_lock){....}, at:
> jbd2_write_access_granted+0x4e/0x250 [jbd2]
> [ 2268.300187][T25724] irq event stamp: 1407125
> [ 2268.304496][T25724] hardirqs last  enabled at (1407125): [<ffffffff980da9b7>]
> __find_get_block+0x107/0x790
> [ 2268.314218][T25724] hardirqs last disabled at (1407124): [<ffffffff980da8f9>]
> __find_get_block+0x49/0x790
> [ 2268.323856][T25724] softirqs last  enabled at (1405528): [<ffffffff98a0034c>]
> __do_softirq+0x34c/0x57c
> [ 2268.333229][T25724] softirqs last disabled at (1405521): [<ffffffff97cc67a2>]
> irq_exit+0xa2/0xc0
> [ 2268.342075][T25724]
> [ 2268.344282][T25724] Reported by Kernel Concurrency Sanitizer on:
> [ 2268.350339][T25724] CPU: 68 PID: 25724 Comm: fsync04 Tainted:
> G             L    5.6.0-rc2-next-20200221+ #7
> [ 2268.360234][T25724] Hardware name: HPE ProLiant DL385 Gen10/ProLiant DL385
> Gen10, BIOS A40 07/10/2019
>
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > Suggested-by: Qian Cai <cai@lca.pw>
> > ---
> >  kernel/kcsan/report.c | 48 +++++++++++++++++++++++++++++++++++++++++++
> >  lib/Kconfig.kcsan     | 13 ++++++++++++
> >  2 files changed, 61 insertions(+)
> >
> > diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> > index 11c791b886f3c..f14becb6f1537 100644
> > --- a/kernel/kcsan/report.c
> > +++ b/kernel/kcsan/report.c
> > @@ -1,10 +1,12 @@
> >  // SPDX-License-Identifier: GPL-2.0
> >
> > +#include <linux/debug_locks.h>
> >  #include <linux/jiffies.h>
> >  #include <linux/kernel.h>
> >  #include <linux/lockdep.h>
> >  #include <linux/preempt.h>
> >  #include <linux/printk.h>
> > +#include <linux/rcupdate.h>
> >  #include <linux/sched.h>
> >  #include <linux/spinlock.h>
> >  #include <linux/stacktrace.h>
> > @@ -245,6 +247,29 @@ static int sym_strcmp(void *addr1, void *addr2)
> >       return strncmp(buf1, buf2, sizeof(buf1));
> >  }
> >
> > +static void print_verbose_info(struct task_struct *task)
> > +{
> > +     if (!task)
> > +             return;
> > +
> > +     if (task != current && task->state == TASK_RUNNING)
> > +             /*
> > +              * Showing held locks for a running task is unreliable, so just
> > +              * skip this. The printed locks are very likely inconsistent,
> > +              * since the stack trace was obtained when the actual race
> > +              * occurred and the task has since continued execution. Since we
> > +              * cannot display the below information from the racing thread,
> > +              * but must print it all from the watcher thread, bail out.
> > +              * Note: Even if the task is not running, there is a chance that
> > +              * the locks held may be inconsistent.
> > +              */
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
> > @@ -319,6 +344,26 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
> >                                 other_info.num_stack_entries - other_skipnr,
> >                                 0);
> >
> > +             if (IS_ENABLED(CONFIG_KCSAN_VERBOSE) && other_info.task_pid != -1) {
> > +                     struct task_struct *other_task;
> > +
> > +                     /*
> > +                      * Rather than passing @current from the other task via
> > +                      * @other_info, obtain task_struct here. The problem
> > +                      * with passing @current via @other_info is that, we
> > +                      * would have to get_task_struct/put_task_struct, and if
> > +                      * we race with a task being released, we would have to
> > +                      * release it in release_report(). This may result in
> > +                      * deadlock if we want to use KCSAN on the allocators.
> > +                      * Instead, make this best-effort, and if the task was
> > +                      * already released, we just do not print anything here.
> > +                      */
> > +                     rcu_read_lock();
> > +                     other_task = find_task_by_pid_ns(other_info.task_pid, &init_pid_ns);
> > +                     print_verbose_info(other_task);
> > +                     rcu_read_unlock();
> > +             }
> > +
> >               pr_err("\n");
> >               pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
> >                      get_access_type(access_type), ptr, size,
> > @@ -340,6 +385,9 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
> >       stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr,
> >                         0);
> >
> > +     if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> > +             print_verbose_info(current);
> > +
> >       /* Print report footer. */
> >       pr_err("\n");
> >       pr_err("Reported by Kernel Concurrency Sanitizer on:\n");
> > diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> > index f0b791143c6ab..ba9268076cfbc 100644
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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMG4nZYLi%2BwFR-R_ifq1%2Bu-YfC7b68iucCRWNd4M%3D%3Dvrw%40mail.gmail.com.
