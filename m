Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLWCYHZAKGQEREAEYHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A659168A2E
	for <lists+kasan-dev@lfdr.de>; Sat, 22 Feb 2020 00:01:04 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id q1sf2160541pfg.2
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2020 15:01:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582326062; cv=pass;
        d=google.com; s=arc-20160816;
        b=brJIO6SqNJtgyZnmPO6mk91pqGftnYa+yYhPBV21Bpz5lW3CP6zeM4JmPDqwa1ReWg
         U1A3QiLmZWS/nZGNU8D0P23kuXfajN4tWe7ODDaopyvmNDPBGcZEUZgb4o1ju6VGJ+2S
         MKvSRNYOKeibuPFN0vEEwvktanBWl15mmo3mEbP/ERF7wYmVoLI8Dpj5g4YA6du06Pen
         o9HHqIYElfDQ+RvG7LFrhuNmC3cZEzjn+LRAsD00cMJjwYrxBf69FTxOX3kAiD8gt+G9
         TgwOHAfbMt5XvGnqWYYTnL+tlD3xhmTH5r33GT2H+Jf0kQZ3Et0KLtMNMphnPIG9CIcB
         /dPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QYfQ7wM1A3nkcc2OLyvAQqXEnKZURQgJK4/Fa+3jLh8=;
        b=ZKxABipTrlvBo7gPeVlRJRsXb2FSmyvrw8sxJJFeZgbpnHznE8DlP0lypfvSAheuRY
         rVS55mIEpBbWvMavRYkXVKTs3rvAhqugSMwrYMmVLFw4sBqdU5wslR+guHBJQEI7eAV9
         cLT7xVXyifCleS14CJrn7sXngBF2TsOllHP0GX7E6abHam7vB3SXEv7NLXq+DnmRZw0D
         1he8FFP5W9hw31LjZlyyDEuDKmVTY5eQ+tGTnFEcDsOtfMkgZRQyYsZvZPUT0ifGUMRG
         hx4XwNs8NfuAAmBD0WzIb+9yi5KEVweaooArzp/Uu4dT/2o5zmOe3StK0GSvV8dzzaGd
         ERlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N2HHyK+I;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QYfQ7wM1A3nkcc2OLyvAQqXEnKZURQgJK4/Fa+3jLh8=;
        b=rZqUe7Nqg0E1/qk0VBj7WtnSjSDI+EAsdSJSCx3XIlLqDx1w1Wwqao7CQtkSBsK/FT
         D4sWr2n6EjMP3UgI3RxIEraF6Om7C5+SLm5QcelkWEhED8iIoJ5xtBK56q6ehqUlNSs+
         LJZsVMUyDe3iif0RoRcFY3LwAIzgghh61JqnAPItWj90j668/b0oWbEnH4pbCvPJISK0
         pGax8bsVjU2FWdqBnX4xoBiE+lbqeu1lyLD1GNoceQpCJH6h0Ok56TMZv0EufQBI+hAg
         nO7qU+UyuB0uCU/amOMS2zB4UV+O/4SYllCcL/H/LWoJEvM+iGXJBXMCJDSOLfL4smhj
         7bjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QYfQ7wM1A3nkcc2OLyvAQqXEnKZURQgJK4/Fa+3jLh8=;
        b=acvyprWzKBrJ61/5pHaAy1UypQrtjlmekXLU1+fcy+9yfYGmVMfw4Fr5695ZRPzFTs
         IWinygPDXzbuSMRqVpuXdIG/B0gCctKmsKa/RHvon2+CIfcVJJfgmFuOC2eAjXP3bJjj
         kPFsbdRJs8BRlOn5DVh7jNYEh716ivn8lBSItETdsTHg/SPxpRd7BSQ1RCD0yOiBo4wG
         BMCCYAi/s32U4E/UNPBVNcsfbHGZ5p5OuoLBUcouzXpYeG4neQiP1Ih9qLhn/1AZFJh0
         /khSIweAKULUx1O4aT97s7SPEWCCjm20XV1SP+czDjxGxE+IpBAbGxjumTmaafibQ/C+
         58eA==
X-Gm-Message-State: APjAAAWKd1na+sI6orPEpsZaKgAgT7VIDNqaQLB5MvFkSz+F+hh7V1MA
	0Ff+heMJKv+SFoDRh4/aTco=
X-Google-Smtp-Source: APXvYqxEHafkE6P7hdY9Zl8O4vV7ND1D05fsl4eVapHNnab3zIZQ8NGTGTjAzwfZFJGmdMt5DAV6ug==
X-Received: by 2002:a63:5a11:: with SMTP id o17mr41143971pgb.60.1582326062707;
        Fri, 21 Feb 2020 15:01:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bb88:: with SMTP id m8ls1264728pls.6.gmail; Fri, 21
 Feb 2020 15:01:02 -0800 (PST)
X-Received: by 2002:a17:90b:4015:: with SMTP id ie21mr5749158pjb.1.1582326062085;
        Fri, 21 Feb 2020 15:01:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582326062; cv=none;
        d=google.com; s=arc-20160816;
        b=QZ8WPJluuwElH0b1VCJCbYVJnbSO53uEaTnyRuo9i3+kKf8Ym/gkN8cnV0AW5Tnyo/
         T1JmJwEgL9owZpYEXN/oiY2jpng7c+9oeIj9QKafqManllkSL+jZwKffOUInUsaIRk25
         QYylHLJurI3/Mq2aBTfWCejo7lqe/Amym1/3qxppaN9JZWt2XHfX0fGtKLl/IU3Mdghc
         htOiMwZs1Q2JdObs4mTSQyIP0LfwlfXHrau6/fHeDeciIG6dxpcWQi5tn7GwrUsYMwDn
         yMgQfPm1RELHW4+BaTTAxQ0ENr2PuvGy2npKaih9lstvfL759O60e+a0OhQ3b1Wal5eB
         1hJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rLFt3sbn+I+aKCOrpKD0K16I5LRQgevP/6DV21RziSU=;
        b=LMg8HvwaNL5hMcIIs85SKKbELdj72pNBCm9VFFCSNadfBSNpXg8mOhW6hCXyfS8iSb
         OrqL4oNkZSdgOMsv5GOCEehNC8hlr3DSDUuqEceQqnTCpHMw7OVhZsip8leuEVWwNBdC
         X/mamdrYEoTa565w4i8I5VKaqJXaiH4Czub/zWo8HQp5YWCcBEg/alMwoDK+6YIOxOqv
         XnLVwuXDcxvqxyJuuL3JMUSEC9WUiAE1E12dp88m+fqgUZzdkyzAbCZzvkkNKYdxjQxT
         GEYncS1j9Js+Crwql3NY2jYiWnJasrqw+SclA8ylfmBOAhjzGEieGCRiDyBda2CQzTXA
         49rQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N2HHyK+I;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id h2si494353pju.2.2020.02.21.15.01.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Feb 2020 15:01:02 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id h9so3516367otj.11
        for <kasan-dev@googlegroups.com>; Fri, 21 Feb 2020 15:01:02 -0800 (PST)
X-Received: by 2002:a9d:66d1:: with SMTP id t17mr31523013otm.233.1582326060978;
 Fri, 21 Feb 2020 15:01:00 -0800 (PST)
MIME-Version: 1.0
References: <20200219151531.161515-1-elver@google.com> <1582305008.7365.111.camel@lca.pw>
 <CANpmjNMG4nZYLi+wFR-R_ifq1+u-YfC7b68iucCRWNd4M==vrw@mail.gmail.com> <20200221180408.GI2935@paulmck-ThinkPad-P72>
In-Reply-To: <20200221180408.GI2935@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 22 Feb 2020 00:00:49 +0100
Message-ID: <CANpmjNMDMZPiDjAHxW0uXESg5ihY8L09jmx2ygaETCm-aVAU_Q@mail.gmail.com>
Subject: Re: [PATCH] kcsan: Add option for verbose reporting
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Qian Cai <cai@lca.pw>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=N2HHyK+I;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Fri, 21 Feb 2020 at 19:04, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Fri, Feb 21, 2020 at 06:58:36PM +0100, Marco Elver wrote:
> > On Fri, 21 Feb 2020 at 18:10, Qian Cai <cai@lca.pw> wrote:
> > >
> > > On Wed, 2020-02-19 at 16:15 +0100, Marco Elver wrote:
> > > > Adds CONFIG_KCSAN_VERBOSE to optionally enable more verbose reports.
> > > > Currently information about the reporting task's held locks and IRQ
> > > > trace events are shown, if they are enabled.
> > >
> > > Well, there is a report. I don't understand why it said there is no lock held in
> > > the writer, but clearly there is this right after in
> > > jbd2_journal_commit_transaction(),
> > >
> > >  spin_unlock(&jh->b_state_lock);
> >
> > This is sort of expected right now.  In the comment that adds this
> > feature, it also has a comment for the "other thread" (in this case
> > the writer):
> >
> > /*
> > * Showing held locks for a running task is unreliable, so just
> > * skip this. The printed locks are very likely inconsistent,
> > * since the stack trace was obtained when the actual race
> > * occurred and the task has since continued execution. Since we
> > * cannot display the below information from the racing thread,
> > * but must print it all from the watcher thread, bail out.
> > * Note: Even if the task is not running, there is a chance that
> > * the locks held may be inconsistent.
> > */
> >
> > Hmm, I suppose I could try harder and make this reliable by stalling
> > the other task if this option is on. Let me give that a try.
>
> And here I thought that I was just being unlucky when I never saw any
> locks held.  ;-)

Sent the new version:
http://lkml.kernel.org/r/20200221225635.218857-1-elver@google.com
It was fun to get this one right, so please test more. :-)

Thanks,
-- Marco

>                                                         Thanx, Paul
>
> > Thanks,
> > -- Marco
> >
> >
> > > [ 2268.021382][T25724] BUG: KCSAN: data-race in __jbd2_journal_refile_buffer
> > > [jbd2] / jbd2_write_access_granted [jbd2]
> > > [ 2268.031888][T25724]
> > > [ 2268.034099][T25724] write to 0xffff99f9b1bd0e30 of 8 bytes by task 25721 on
> > > cpu 70:
> > > [ 2268.041842][T25724]  __jbd2_journal_refile_buffer+0xdd/0x210 [jbd2]
> > > __jbd2_journal_refile_buffer at fs/jbd2/transaction.c:2569
> > > [ 2268.048181][T25724]  jbd2_journal_commit_transaction+0x2d15/0x3f20 [jbd2]
> > > (inlined by) jbd2_journal_commit_transaction at fs/jbd2/commit.c:1033
> > > [ 2268.055042][T25724]  kjournald2+0x13b/0x450 [jbd2]
> > > [ 2268.059876][T25724]  kthread+0x1cd/0x1f0
> > > [ 2268.063835][T25724]  ret_from_fork+0x27/0x50
> > > [ 2268.068143][T25724]
> > > [ 2268.070348][T25724] no locks held by jbd2/loop0-8/25721.
> > > [ 2268.075699][T25724] irq event stamp: 77604
> > > [ 2268.079830][T25724] hardirqs last  enabled at (77603): [<ffffffff986da853>]
> > > _raw_spin_unlock_irqrestore+0x53/0x60
> > > [ 2268.090166][T25724] hardirqs last disabled at (77604): [<ffffffff986d0841>]
> > > __schedule+0x181/0xa50
> > > [ 2268.099192][T25724] softirqs last  enabled at (76092): [<ffffffff98a0034c>]
> > > __do_softirq+0x34c/0x57c
> > > [ 2268.108392][T25724] softirqs last disabled at (76005): [<ffffffff97cc67a2>]
> > > irq_exit+0xa2/0xc0
> > > [ 2268.117062][T25724]
> > > [ 2268.119269][T25724] read to 0xffff99f9b1bd0e30 of 8 bytes by task 25724 on
> > > cpu 68:
> > > [ 2268.126916][T25724]  jbd2_write_access_granted+0x1b2/0x250 [jbd2]
> > > jbd2_write_access_granted at fs/jbd2/transaction.c:1155
> > > [ 2268.133086][T25724]  jbd2_journal_get_write_access+0x2c/0x60 [jbd2]
> > > [ 2268.139492][T25724]  __ext4_journal_get_write_access+0x50/0x90 [ext4]
> > > [ 2268.146076][T25724]  ext4_mb_mark_diskspace_used+0x158/0x620 [ext4]
> > > [ 2268.152507][T25724]  ext4_mb_new_blocks+0x54f/0xca0 [ext4]
> > > [ 2268.158125][T25724]  ext4_ind_map_blocks+0xc79/0x1b40 [ext4]
> > > [ 2268.163923][T25724]  ext4_map_blocks+0x3b4/0x950 [ext4]
> > > [ 2268.169284][T25724]  _ext4_get_block+0xfc/0x270 [ext4]
> > > [ 2268.174556][T25724]  ext4_get_block+0x3b/0x50 [ext4]
> > > [ 2268.179566][T25724]  __block_write_begin_int+0x22e/0xae0
> > > [ 2268.184921][T25724]  __block_write_begin+0x39/0x50
> > > [ 2268.189842][T25724]  ext4_write_begin+0x388/0xb50 [ext4]
> > > [ 2268.195195][T25724]  generic_perform_write+0x15d/0x290
> > > [ 2268.200467][T25724]  ext4_buffered_write_iter+0x11f/0x210 [ext4]
> > > [ 2268.206612][T25724]  ext4_file_write_iter+0xce/0x9e0 [ext4]
> > > [ 2268.212228][T25724]  new_sync_write+0x29c/0x3b0
> > > [ 2268.216794][T25724]  __vfs_write+0x92/0xa0
> > > [ 2268.220924][T25724]  vfs_write+0x103/0x260
> > > [ 2268.225052][T25724]  ksys_write+0x9d/0x130
> > > [ 2268.229182][T25724]  __x64_sys_write+0x4c/0x60
> > > [ 2268.233666][T25724]  do_syscall_64+0x91/0xb05
> > > [ 2268.238058][T25724]  entry_SYSCALL_64_after_hwframe+0x49/0xbe
> > > [ 2268.243846][T25724]
> > > [ 2268.246056][T25724] 5 locks held by fsync04/25724:
> > > [ 2268.250880][T25724]  #0: ffff99f9911093f8 (sb_writers#13){.+.+}, at:
> > > vfs_write+0x21c/0x260
> > > [ 2268.259211][T25724]  #1: ffff99f9db4c0348 (&sb->s_type-
> > > >i_mutex_key#15){+.+.}, at: ext4_buffered_write_iter+0x65/0x210 [ext4]
> > > [ 2268.270693][T25724]  #2: ffff99f5e7dfcf58 (jbd2_handle){++++}, at:
> > > start_this_handle+0x1c1/0x9d0 [jbd2]
> > > [ 2268.280180][T25724]  #3: ffff99f9db4c0168 (&ei->i_data_sem){++++}, at:
> > > ext4_map_blocks+0x176/0x950 [ext4]
> > > [ 2268.289913][T25724]  #4: ffffffff99086b40 (rcu_read_lock){....}, at:
> > > jbd2_write_access_granted+0x4e/0x250 [jbd2]
> > > [ 2268.300187][T25724] irq event stamp: 1407125
> > > [ 2268.304496][T25724] hardirqs last  enabled at (1407125): [<ffffffff980da9b7>]
> > > __find_get_block+0x107/0x790
> > > [ 2268.314218][T25724] hardirqs last disabled at (1407124): [<ffffffff980da8f9>]
> > > __find_get_block+0x49/0x790
> > > [ 2268.323856][T25724] softirqs last  enabled at (1405528): [<ffffffff98a0034c>]
> > > __do_softirq+0x34c/0x57c
> > > [ 2268.333229][T25724] softirqs last disabled at (1405521): [<ffffffff97cc67a2>]
> > > irq_exit+0xa2/0xc0
> > > [ 2268.342075][T25724]
> > > [ 2268.344282][T25724] Reported by Kernel Concurrency Sanitizer on:
> > > [ 2268.350339][T25724] CPU: 68 PID: 25724 Comm: fsync04 Tainted:
> > > G             L    5.6.0-rc2-next-20200221+ #7
> > > [ 2268.360234][T25724] Hardware name: HPE ProLiant DL385 Gen10/ProLiant DL385
> > > Gen10, BIOS A40 07/10/2019
> > >
> > > >
> > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > Suggested-by: Qian Cai <cai@lca.pw>
> > > > ---
> > > >  kernel/kcsan/report.c | 48 +++++++++++++++++++++++++++++++++++++++++++
> > > >  lib/Kconfig.kcsan     | 13 ++++++++++++
> > > >  2 files changed, 61 insertions(+)
> > > >
> > > > diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> > > > index 11c791b886f3c..f14becb6f1537 100644
> > > > --- a/kernel/kcsan/report.c
> > > > +++ b/kernel/kcsan/report.c
> > > > @@ -1,10 +1,12 @@
> > > >  // SPDX-License-Identifier: GPL-2.0
> > > >
> > > > +#include <linux/debug_locks.h>
> > > >  #include <linux/jiffies.h>
> > > >  #include <linux/kernel.h>
> > > >  #include <linux/lockdep.h>
> > > >  #include <linux/preempt.h>
> > > >  #include <linux/printk.h>
> > > > +#include <linux/rcupdate.h>
> > > >  #include <linux/sched.h>
> > > >  #include <linux/spinlock.h>
> > > >  #include <linux/stacktrace.h>
> > > > @@ -245,6 +247,29 @@ static int sym_strcmp(void *addr1, void *addr2)
> > > >       return strncmp(buf1, buf2, sizeof(buf1));
> > > >  }
> > > >
> > > > +static void print_verbose_info(struct task_struct *task)
> > > > +{
> > > > +     if (!task)
> > > > +             return;
> > > > +
> > > > +     if (task != current && task->state == TASK_RUNNING)
> > > > +             /*
> > > > +              * Showing held locks for a running task is unreliable, so just
> > > > +              * skip this. The printed locks are very likely inconsistent,
> > > > +              * since the stack trace was obtained when the actual race
> > > > +              * occurred and the task has since continued execution. Since we
> > > > +              * cannot display the below information from the racing thread,
> > > > +              * but must print it all from the watcher thread, bail out.
> > > > +              * Note: Even if the task is not running, there is a chance that
> > > > +              * the locks held may be inconsistent.
> > > > +              */
> > > > +             return;
> > > > +
> > > > +     pr_err("\n");
> > > > +     debug_show_held_locks(task);
> > > > +     print_irqtrace_events(task);
> > > > +}
> > > > +
> > > >  /*
> > > >   * Returns true if a report was generated, false otherwise.
> > > >   */
> > > > @@ -319,6 +344,26 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
> > > >                                 other_info.num_stack_entries - other_skipnr,
> > > >                                 0);
> > > >
> > > > +             if (IS_ENABLED(CONFIG_KCSAN_VERBOSE) && other_info.task_pid != -1) {
> > > > +                     struct task_struct *other_task;
> > > > +
> > > > +                     /*
> > > > +                      * Rather than passing @current from the other task via
> > > > +                      * @other_info, obtain task_struct here. The problem
> > > > +                      * with passing @current via @other_info is that, we
> > > > +                      * would have to get_task_struct/put_task_struct, and if
> > > > +                      * we race with a task being released, we would have to
> > > > +                      * release it in release_report(). This may result in
> > > > +                      * deadlock if we want to use KCSAN on the allocators.
> > > > +                      * Instead, make this best-effort, and if the task was
> > > > +                      * already released, we just do not print anything here.
> > > > +                      */
> > > > +                     rcu_read_lock();
> > > > +                     other_task = find_task_by_pid_ns(other_info.task_pid, &init_pid_ns);
> > > > +                     print_verbose_info(other_task);
> > > > +                     rcu_read_unlock();
> > > > +             }
> > > > +
> > > >               pr_err("\n");
> > > >               pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
> > > >                      get_access_type(access_type), ptr, size,
> > > > @@ -340,6 +385,9 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
> > > >       stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr,
> > > >                         0);
> > > >
> > > > +     if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> > > > +             print_verbose_info(current);
> > > > +
> > > >       /* Print report footer. */
> > > >       pr_err("\n");
> > > >       pr_err("Reported by Kernel Concurrency Sanitizer on:\n");
> > > > diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> > > > index f0b791143c6ab..ba9268076cfbc 100644
> > > > --- a/lib/Kconfig.kcsan
> > > > +++ b/lib/Kconfig.kcsan
> > > > @@ -20,6 +20,19 @@ menuconfig KCSAN
> > > >
> > > >  if KCSAN
> > > >
> > > > +config KCSAN_VERBOSE
> > > > +     bool "Show verbose reports with more information about system state"
> > > > +     depends on PROVE_LOCKING
> > > > +     help
> > > > +       If enabled, reports show more information about the system state that
> > > > +       may help better analyze and debug races. This includes held locks and
> > > > +       IRQ trace events.
> > > > +
> > > > +       While this option should generally be benign, we call into more
> > > > +       external functions on report generation; if a race report is
> > > > +       generated from any one of them, system stability may suffer due to
> > > > +       deadlocks or recursion.  If in doubt, say N.
> > > > +
> > > >  config KCSAN_DEBUG
> > > >       bool "Debugging of KCSAN internals"
> > > >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMDMZPiDjAHxW0uXESg5ihY8L09jmx2ygaETCm-aVAU_Q%40mail.gmail.com.
