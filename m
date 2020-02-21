Return-Path: <kasan-dev+bncBAABBGVXYDZAKGQEYL7MMZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 33BC3168605
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2020 19:04:11 +0100 (CET)
Received: by mail-vk1-xa3a.google.com with SMTP id y28sf1229933vkl.23
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2020 10:04:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582308250; cv=pass;
        d=google.com; s=arc-20160816;
        b=aScBiuE1sassgxZWW2aYCYdK8E8804DwTsAFgAk43dCmDDTgg2lVT+gkZvs5FMTXs8
         wY1k0VX/7STXb/BfKSjKw26GI8hHmEnEzaNmENoVcQzesX82n15J7ihK/JvTKoFSYZ8e
         okxayNmuiHE6O2z/WVTUnkx+tUrbDjIuoopOQnj8kFoEL1//DdEMXqqVOeGf5EkGjkM+
         6nJWOefmaT+HS2yM3I5XtNyJnOQ90DyGb9HaN1PsKDmsrfCniLvcgu6vLky0KUHuKmbI
         u1Q+3ojjYHBNb/8YWptkaPc0mgRJ5dmxN+WG1tC/bS20lwTVxGF6U1HPfsicqna9meVY
         psHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=uco5WfHs4fg2jfnNG8WiPtMFJnQRsAn3MZF2ttGErlU=;
        b=LX5QcFDQACPfNYNA4YufY2nN2PeUPu0QF2+OqA3/m68gX7ekFgHjyPalvI0chP/9YA
         7kb8WWxiLoYweiiCQnWYAlo4OvBnjNeiKNWP6JBdtv8kJNbRojm0Ng4LaEeqY1GW5T6V
         MYg/liphRMppgaDV93mVPAH+m2EnckuDbResIw0OMk1YHZY9EmtL+/zAoLCi3L3JKHqG
         CEAtPTyyw25PQF1LVlPJ25mtGZ9zXAYUPZTy1XgGHWpYokid2TC16gU4Nep/FVUOYS/t
         9xnlahB9arGfM4DslD61YcGpNkXcCMLD4fWzRtQkPoguVrZ0azFUNbKJ1j0enpeHBGmr
         Ud7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=e+l+jIv8;
       spf=pass (google.com: domain of srs0=ie8e=4j=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Ie8E=4J=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uco5WfHs4fg2jfnNG8WiPtMFJnQRsAn3MZF2ttGErlU=;
        b=DEFQJgtT53AKdLyc8pb4Ma1VMc8QwZ+MZXUS1gmew/SfjfYgec9MBAiYufsBNc1P8d
         BbvH0RtEsp9qpbw54HdzyO3MyGB4ddHkbbXckid32sHAxTiWH8NJfrmRmp7/ZVZzorBH
         0wnTS06001FpUzMLP2eMp1xKDdsY9brg/W9rlbJpT+vBr3YyhHtWsqySXxY44GQM024J
         sJ2NrOnud2ITNN7heZQCmPSxHGQU6CRkitb2im+EvWcvxnvyfClvJ4UnzD/Ii1ZBPXHq
         5IMd/qmlTIfrmSp4zsLsgzPlItWB6beL8GeK5YbRTbCmoSnv2qtDUjqZj5zm8VJ4GLRh
         kw9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uco5WfHs4fg2jfnNG8WiPtMFJnQRsAn3MZF2ttGErlU=;
        b=bIgor4CHIVktIADsjHBRdVz6iIrV2PvLQSBipwfizSENOa36fUDyf1hUE0BsrDBcVO
         dfNQX7af1+33ZWlJPFD3tYRqlyIA6VHJ2Xd0a98CX4KOwXwNEzkHPJjK/PXuHhU2B38W
         r0C87N5KQERoii84tHxgXTj7S+IfoaSaygiuLR6Y9HC/vXQ/4GeQ4MkakJKv3p7PRjef
         +ilrIsZDQKhvZWFcPbVQr3s1yh080Ikx5ZHVduPNWjuSmNrLAjVF7lFthtmanj50OTPw
         ZObSeLegYjRM43H+M2FELma1QzFsRuYyu/egUSLGlo9JoDxa4vZtmnQjOIONfO1dgVbt
         Eo/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWRX/X6dD79AK/rQpND/jbsJOjBK0+F/M25jrXBE/9pTjWVdisv
	TxevPqn7ZTaXOx+1MWaZmbc=
X-Google-Smtp-Source: APXvYqwyaWfumYJk+AiKfewK325FfOUcaEwlp2uB5W3ezMAPFq8hIICn+rrZjJ1RzH624vE2TdafjQ==
X-Received: by 2002:a1f:d904:: with SMTP id q4mr17529337vkg.13.1582308250206;
        Fri, 21 Feb 2020 10:04:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d38b:: with SMTP id b11ls336388vsj.9.gmail; Fri, 21 Feb
 2020 10:04:09 -0800 (PST)
X-Received: by 2002:a05:6102:72b:: with SMTP id u11mr22198970vsg.69.1582308249899;
        Fri, 21 Feb 2020 10:04:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582308249; cv=none;
        d=google.com; s=arc-20160816;
        b=kia/TnrlDvaZCz2z3HnkHUYuXvu/KT9kMQfk4dpdNlREcc3ZAOKl60ALdWJNzLc+/3
         LqnHdKB+rf7HkHkuAVEOlUg00ep8uAj19jSrdvGksneVXgoq47qW9rdkJJrRnBaaYScM
         Tcye2FhAb1+/7BYyi2GgOCifeNLuYGDsG97nIKRO1iqsvCKp1gt/WVU+/jM9C+3ZzA1t
         NvpVKSIgeV5nywLOtjl4Y1V2LUPXg+4HUJ9R8476Pdmpg7uAf1PAStuZnWblawD0aGOf
         hMHTYNlGcDTsmhWZ+lhl48WBjZZDGnpSK0VRE1zCN6gFbf3Wa37M5NjM5KhBfOJwpw91
         9N6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=hbA3V3w8OgDQK3XfqhZhlWkGgF908VQ3/sT5gcguYG4=;
        b=YbGdmSHlt/xQHalyl3yQC/ddvz9497Kmj0YYRBiThf7tBcnQh2/KSmHSlSaXAfjfus
         7y4lB4khDoOdQRKKTF+VbD6bO8Zytg8A6tb0Azu74kjO/CxpWNeH//BCbLdN0J+1P3Yj
         InWou1UB4EnobXOkzJhhjJH8B+3J3i8ccxbG4eUHAeZrtptzPS6yXDBN2YBbyk8e0ixD
         I9KS15YuOjIQDkimEui5DKrmdFI2DvpCqoRhfabvPiYqGg2ujbfgQHpB++6HcHQcVzVA
         7zCXJW50Rtnfo3J1fYsFSdgklpU1aC8+VjtAcDRqMwXsIpZPCeER7YGQyHjQO5xfgflw
         0tEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=e+l+jIv8;
       spf=pass (google.com: domain of srs0=ie8e=4j=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Ie8E=4J=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i27si196863uat.1.2020.02.21.10.04.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Feb 2020 10:04:09 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=ie8e=4j=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id BD48620722;
	Fri, 21 Feb 2020 18:04:08 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 9797B3521EAE; Fri, 21 Feb 2020 10:04:08 -0800 (PST)
Date: Fri, 21 Feb 2020 10:04:08 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Qian Cai <cai@lca.pw>, Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH] kcsan: Add option for verbose reporting
Message-ID: <20200221180408.GI2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200219151531.161515-1-elver@google.com>
 <1582305008.7365.111.camel@lca.pw>
 <CANpmjNMG4nZYLi+wFR-R_ifq1+u-YfC7b68iucCRWNd4M==vrw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMG4nZYLi+wFR-R_ifq1+u-YfC7b68iucCRWNd4M==vrw@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=e+l+jIv8;       spf=pass
 (google.com: domain of srs0=ie8e=4j=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Ie8E=4J=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Fri, Feb 21, 2020 at 06:58:36PM +0100, Marco Elver wrote:
> On Fri, 21 Feb 2020 at 18:10, Qian Cai <cai@lca.pw> wrote:
> >
> > On Wed, 2020-02-19 at 16:15 +0100, Marco Elver wrote:
> > > Adds CONFIG_KCSAN_VERBOSE to optionally enable more verbose reports.
> > > Currently information about the reporting task's held locks and IRQ
> > > trace events are shown, if they are enabled.
> >
> > Well, there is a report. I don't understand why it said there is no lock held in
> > the writer, but clearly there is this right after in
> > jbd2_journal_commit_transaction(),
> >
> >  spin_unlock(&jh->b_state_lock);
> 
> This is sort of expected right now.  In the comment that adds this
> feature, it also has a comment for the "other thread" (in this case
> the writer):
> 
> /*
> * Showing held locks for a running task is unreliable, so just
> * skip this. The printed locks are very likely inconsistent,
> * since the stack trace was obtained when the actual race
> * occurred and the task has since continued execution. Since we
> * cannot display the below information from the racing thread,
> * but must print it all from the watcher thread, bail out.
> * Note: Even if the task is not running, there is a chance that
> * the locks held may be inconsistent.
> */
> 
> Hmm, I suppose I could try harder and make this reliable by stalling
> the other task if this option is on. Let me give that a try.

And here I thought that I was just being unlucky when I never saw any
locks held.  ;-)

							Thanx, Paul

> Thanks,
> -- Marco
> 
> 
> > [ 2268.021382][T25724] BUG: KCSAN: data-race in __jbd2_journal_refile_buffer
> > [jbd2] / jbd2_write_access_granted [jbd2]
> > [ 2268.031888][T25724]
> > [ 2268.034099][T25724] write to 0xffff99f9b1bd0e30 of 8 bytes by task 25721 on
> > cpu 70:
> > [ 2268.041842][T25724]  __jbd2_journal_refile_buffer+0xdd/0x210 [jbd2]
> > __jbd2_journal_refile_buffer at fs/jbd2/transaction.c:2569
> > [ 2268.048181][T25724]  jbd2_journal_commit_transaction+0x2d15/0x3f20 [jbd2]
> > (inlined by) jbd2_journal_commit_transaction at fs/jbd2/commit.c:1033
> > [ 2268.055042][T25724]  kjournald2+0x13b/0x450 [jbd2]
> > [ 2268.059876][T25724]  kthread+0x1cd/0x1f0
> > [ 2268.063835][T25724]  ret_from_fork+0x27/0x50
> > [ 2268.068143][T25724]
> > [ 2268.070348][T25724] no locks held by jbd2/loop0-8/25721.
> > [ 2268.075699][T25724] irq event stamp: 77604
> > [ 2268.079830][T25724] hardirqs last  enabled at (77603): [<ffffffff986da853>]
> > _raw_spin_unlock_irqrestore+0x53/0x60
> > [ 2268.090166][T25724] hardirqs last disabled at (77604): [<ffffffff986d0841>]
> > __schedule+0x181/0xa50
> > [ 2268.099192][T25724] softirqs last  enabled at (76092): [<ffffffff98a0034c>]
> > __do_softirq+0x34c/0x57c
> > [ 2268.108392][T25724] softirqs last disabled at (76005): [<ffffffff97cc67a2>]
> > irq_exit+0xa2/0xc0
> > [ 2268.117062][T25724]
> > [ 2268.119269][T25724] read to 0xffff99f9b1bd0e30 of 8 bytes by task 25724 on
> > cpu 68:
> > [ 2268.126916][T25724]  jbd2_write_access_granted+0x1b2/0x250 [jbd2]
> > jbd2_write_access_granted at fs/jbd2/transaction.c:1155
> > [ 2268.133086][T25724]  jbd2_journal_get_write_access+0x2c/0x60 [jbd2]
> > [ 2268.139492][T25724]  __ext4_journal_get_write_access+0x50/0x90 [ext4]
> > [ 2268.146076][T25724]  ext4_mb_mark_diskspace_used+0x158/0x620 [ext4]
> > [ 2268.152507][T25724]  ext4_mb_new_blocks+0x54f/0xca0 [ext4]
> > [ 2268.158125][T25724]  ext4_ind_map_blocks+0xc79/0x1b40 [ext4]
> > [ 2268.163923][T25724]  ext4_map_blocks+0x3b4/0x950 [ext4]
> > [ 2268.169284][T25724]  _ext4_get_block+0xfc/0x270 [ext4]
> > [ 2268.174556][T25724]  ext4_get_block+0x3b/0x50 [ext4]
> > [ 2268.179566][T25724]  __block_write_begin_int+0x22e/0xae0
> > [ 2268.184921][T25724]  __block_write_begin+0x39/0x50
> > [ 2268.189842][T25724]  ext4_write_begin+0x388/0xb50 [ext4]
> > [ 2268.195195][T25724]  generic_perform_write+0x15d/0x290
> > [ 2268.200467][T25724]  ext4_buffered_write_iter+0x11f/0x210 [ext4]
> > [ 2268.206612][T25724]  ext4_file_write_iter+0xce/0x9e0 [ext4]
> > [ 2268.212228][T25724]  new_sync_write+0x29c/0x3b0
> > [ 2268.216794][T25724]  __vfs_write+0x92/0xa0
> > [ 2268.220924][T25724]  vfs_write+0x103/0x260
> > [ 2268.225052][T25724]  ksys_write+0x9d/0x130
> > [ 2268.229182][T25724]  __x64_sys_write+0x4c/0x60
> > [ 2268.233666][T25724]  do_syscall_64+0x91/0xb05
> > [ 2268.238058][T25724]  entry_SYSCALL_64_after_hwframe+0x49/0xbe
> > [ 2268.243846][T25724]
> > [ 2268.246056][T25724] 5 locks held by fsync04/25724:
> > [ 2268.250880][T25724]  #0: ffff99f9911093f8 (sb_writers#13){.+.+}, at:
> > vfs_write+0x21c/0x260
> > [ 2268.259211][T25724]  #1: ffff99f9db4c0348 (&sb->s_type-
> > >i_mutex_key#15){+.+.}, at: ext4_buffered_write_iter+0x65/0x210 [ext4]
> > [ 2268.270693][T25724]  #2: ffff99f5e7dfcf58 (jbd2_handle){++++}, at:
> > start_this_handle+0x1c1/0x9d0 [jbd2]
> > [ 2268.280180][T25724]  #3: ffff99f9db4c0168 (&ei->i_data_sem){++++}, at:
> > ext4_map_blocks+0x176/0x950 [ext4]
> > [ 2268.289913][T25724]  #4: ffffffff99086b40 (rcu_read_lock){....}, at:
> > jbd2_write_access_granted+0x4e/0x250 [jbd2]
> > [ 2268.300187][T25724] irq event stamp: 1407125
> > [ 2268.304496][T25724] hardirqs last  enabled at (1407125): [<ffffffff980da9b7>]
> > __find_get_block+0x107/0x790
> > [ 2268.314218][T25724] hardirqs last disabled at (1407124): [<ffffffff980da8f9>]
> > __find_get_block+0x49/0x790
> > [ 2268.323856][T25724] softirqs last  enabled at (1405528): [<ffffffff98a0034c>]
> > __do_softirq+0x34c/0x57c
> > [ 2268.333229][T25724] softirqs last disabled at (1405521): [<ffffffff97cc67a2>]
> > irq_exit+0xa2/0xc0
> > [ 2268.342075][T25724]
> > [ 2268.344282][T25724] Reported by Kernel Concurrency Sanitizer on:
> > [ 2268.350339][T25724] CPU: 68 PID: 25724 Comm: fsync04 Tainted:
> > G             L    5.6.0-rc2-next-20200221+ #7
> > [ 2268.360234][T25724] Hardware name: HPE ProLiant DL385 Gen10/ProLiant DL385
> > Gen10, BIOS A40 07/10/2019
> >
> > >
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > Suggested-by: Qian Cai <cai@lca.pw>
> > > ---
> > >  kernel/kcsan/report.c | 48 +++++++++++++++++++++++++++++++++++++++++++
> > >  lib/Kconfig.kcsan     | 13 ++++++++++++
> > >  2 files changed, 61 insertions(+)
> > >
> > > diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> > > index 11c791b886f3c..f14becb6f1537 100644
> > > --- a/kernel/kcsan/report.c
> > > +++ b/kernel/kcsan/report.c
> > > @@ -1,10 +1,12 @@
> > >  // SPDX-License-Identifier: GPL-2.0
> > >
> > > +#include <linux/debug_locks.h>
> > >  #include <linux/jiffies.h>
> > >  #include <linux/kernel.h>
> > >  #include <linux/lockdep.h>
> > >  #include <linux/preempt.h>
> > >  #include <linux/printk.h>
> > > +#include <linux/rcupdate.h>
> > >  #include <linux/sched.h>
> > >  #include <linux/spinlock.h>
> > >  #include <linux/stacktrace.h>
> > > @@ -245,6 +247,29 @@ static int sym_strcmp(void *addr1, void *addr2)
> > >       return strncmp(buf1, buf2, sizeof(buf1));
> > >  }
> > >
> > > +static void print_verbose_info(struct task_struct *task)
> > > +{
> > > +     if (!task)
> > > +             return;
> > > +
> > > +     if (task != current && task->state == TASK_RUNNING)
> > > +             /*
> > > +              * Showing held locks for a running task is unreliable, so just
> > > +              * skip this. The printed locks are very likely inconsistent,
> > > +              * since the stack trace was obtained when the actual race
> > > +              * occurred and the task has since continued execution. Since we
> > > +              * cannot display the below information from the racing thread,
> > > +              * but must print it all from the watcher thread, bail out.
> > > +              * Note: Even if the task is not running, there is a chance that
> > > +              * the locks held may be inconsistent.
> > > +              */
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
> > > @@ -319,6 +344,26 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
> > >                                 other_info.num_stack_entries - other_skipnr,
> > >                                 0);
> > >
> > > +             if (IS_ENABLED(CONFIG_KCSAN_VERBOSE) && other_info.task_pid != -1) {
> > > +                     struct task_struct *other_task;
> > > +
> > > +                     /*
> > > +                      * Rather than passing @current from the other task via
> > > +                      * @other_info, obtain task_struct here. The problem
> > > +                      * with passing @current via @other_info is that, we
> > > +                      * would have to get_task_struct/put_task_struct, and if
> > > +                      * we race with a task being released, we would have to
> > > +                      * release it in release_report(). This may result in
> > > +                      * deadlock if we want to use KCSAN on the allocators.
> > > +                      * Instead, make this best-effort, and if the task was
> > > +                      * already released, we just do not print anything here.
> > > +                      */
> > > +                     rcu_read_lock();
> > > +                     other_task = find_task_by_pid_ns(other_info.task_pid, &init_pid_ns);
> > > +                     print_verbose_info(other_task);
> > > +                     rcu_read_unlock();
> > > +             }
> > > +
> > >               pr_err("\n");
> > >               pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
> > >                      get_access_type(access_type), ptr, size,
> > > @@ -340,6 +385,9 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
> > >       stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr,
> > >                         0);
> > >
> > > +     if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> > > +             print_verbose_info(current);
> > > +
> > >       /* Print report footer. */
> > >       pr_err("\n");
> > >       pr_err("Reported by Kernel Concurrency Sanitizer on:\n");
> > > diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> > > index f0b791143c6ab..ba9268076cfbc 100644
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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200221180408.GI2935%40paulmck-ThinkPad-P72.
