Return-Path: <kasan-dev+bncBCD3NZ4T2IKRB445YDZAKGQE7MC63OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 498E2168472
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2020 18:10:13 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id 10sf2092373ybj.16
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2020 09:10:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582305012; cv=pass;
        d=google.com; s=arc-20160816;
        b=tJKCUjkuxsgVHdRWK+g/kULjKwYbEshcHrlSvzzCst85YSwlfhG/UV12Sy6d5qoJ/Y
         jf1uQywVDq0LcuLWG1A/HQ9A7D+/JfxoyrFb2KYlQbmi5jd7guBUux68BNcqQp5+v5An
         6hlgqWNUfMFUqXowVurwCwLP30yarzjs1bZ+9d3q0ALuJXmB99yfZZ2DpZs8C5Aass+X
         tag2YKFfFj38/vLozX9pfuJNlFeZDj5j4e+IFdK17NseYIa3312l0okk6wDe9G6iPZEh
         IQxTeiFUyFUoYVjSj6L9BQ18AnIoZXIawKkA2eE6ap4iKDCNdclQk+5pf/qRinV1SoqK
         HUzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=2QWCdM9tDhnYVG/MF3CFYPp6j8fv3abDYcywrrYoBmg=;
        b=wg5YbC4/v8kOYP/cwgzzvEKQfu5r2CzkKMnQoEGQUf7KIVeW4+y476un13AOI9M8OX
         XsRWMtOml1jI8EEF+a7pp6uJem928AfXiOj+TphmQAjY/BSMRni27L1YSDwxBUqU/spf
         WwYoR9auAaaLOk5emmDP7v/tbXVKSDCmzHIyaVc4Dvbj1NSxurQ57VZgTxpuSTcas/XQ
         NwKzUGvGXvUaSLYlcJpPFO/PBoPR7Mchr2hP79wKqzAfyoknqp/nO2CoDbSXFEOeSAv8
         drFvWe0ikf2iVsG5lkCpSbesiVXEwPlK7cNUiK/HDoG1Upse0Xp36Izf9hRg3z2Bo+uw
         MF+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=hQnbm4bv;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2QWCdM9tDhnYVG/MF3CFYPp6j8fv3abDYcywrrYoBmg=;
        b=GltPzYcrvDUhhAdu1+Z4aIQJK5g9L/qW79DcYtnh5H8RaUQEfDFODypPLw21MDfR08
         bvYMnWzIcta2z3ld/6Gm+ZGpnRa0Z8nyj3+/35kFmBg1TQ941FIULIHTjTyAbK9t2K4g
         u218qQ5FzcnppoTJi5ymTcX09eh9U+kBzZuo4c4jEPLb3GQbN1ogBCC1H0p3obk9Aq8j
         6ytJfu6fUDBcCqLGADrZvyauRAC7Nj47Qvhd9tb3AorIimCRWK0dmrqaYi4qHDpXQCUc
         5kQgbk6Le7COMEuqNb1et7TWfDI7pI11d0ggDmqgYTGol1tr82AUSPZ6DFkPTUCPHhFY
         iITA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2QWCdM9tDhnYVG/MF3CFYPp6j8fv3abDYcywrrYoBmg=;
        b=iXwjHbeovWuCVyWy+/DfZoDf8kr6LVhD9Q02F5aslaohgSnaltZ5oihz5l3CNL5FJi
         NfAL5D3StCMj8OebYUNsRSZsflZSgemoXlaCx9l+V+snTnEM4BqpLBwmk9wR5oScnQ1g
         VRUn8atEqrI4lQzn3Uy80ybfpr5XR3xcbgKAYv/STqB7ayjt9l7zf8fF8n0PImrDk8S0
         gowZtjuxtcVi3FS2a+InFPZd4XlJc2aJrD/Nvnunql94+cHAf+M71ENI0kM1Ftn+tS7X
         99Y2OT8/dmAIpYw1P0jz6uoPtKFdYQ4U/wVLS4l0MvLmesvRFuwCJ3pw5Bg/Jqo4nTUd
         3erg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV/Z9uQ26hlryvU4HNDuOKVA7qIIf2DGq5ATFNILCDszb83ibXB
	7+Gh8hLtxEZXnSOsRAKDWY8=
X-Google-Smtp-Source: APXvYqzLM55WrHtjn99D3ckdbBospMZ9rNVVYvLpP3WGfDdlAYaY7+yu9oXuR3r0lUtaNqIrZXdMgA==
X-Received: by 2002:a25:8745:: with SMTP id e5mr1966727ybn.30.1582305012029;
        Fri, 21 Feb 2020 09:10:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:1bc4:: with SMTP id b187ls543603ywb.10.gmail; Fri, 21
 Feb 2020 09:10:11 -0800 (PST)
X-Received: by 2002:a81:4fd5:: with SMTP id d204mr32964236ywb.232.1582305011510;
        Fri, 21 Feb 2020 09:10:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582305011; cv=none;
        d=google.com; s=arc-20160816;
        b=kk6wnLZEgKRHAWecAEfLgBwimOpo6/PTK65yzCxkEmuXaw93vzgpdVenq9aymCLo+2
         lWa5Puq6CnmqHbbbHPpELV6szrx/cz2Ucw8PFGbMgKbgXKJK+uGqCWPEn2uDySAGocx+
         IoBrHw6bhWR2QL4WSTOUYWCD5eEQK2DKd4W0MHtbQ8hucURa/HA8hRBMO4segHSNMSIJ
         TA8NjklzQQp8/rCkEO8/pA9ZTC1zfwlQx51F1HijZEgrNkLTPQ84PmQjDDh50MZel7GA
         t+7kkrlB/wl681YDNJ6tYUgwxaFlEcAALGPj8YFOiHJ4Byf+v7f88F1Hi9M8KTdWK3hF
         dVFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=gL/kI9VlGkNvzMfzmc7dKStrYuJZuzj9czJ6UkMUDSw=;
        b=iHVZ9+/onEMmIOZ5XMAubjarFRYHu888yI35KRIX7EPwA6qY2kJbgXVsKCjEEyvP69
         iKA4jBHZocByZiDsuIG68XwJUMEphetxBlPMn890vEjHhN05bExFaONVUK1k0FUBEMME
         bCWt0E+wUdilT+J6pemea0sZkMoSytn4l3BHo3CBLMnW+l5hpQGTBylla0lHf5cqqpfk
         n5ayyFaekBFMnf29qQvAZfyfkl/ciUQTmAPhgNOslALd4BmlxWlGpZ8Pd4QvzygaNQiL
         icscQdvEXI6BfBcvpPQf0OiXMkBLP5F8RFtVZNgUuh7eOQ9A7Pll+VU5sdZtEPoHawt+
         T4Iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=hQnbm4bv;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id t82si282744ywb.2.2020.02.21.09.10.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Feb 2020 09:10:11 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id 134so364107qkl.6
        for <kasan-dev@googlegroups.com>; Fri, 21 Feb 2020 09:10:11 -0800 (PST)
X-Received: by 2002:a37:4c81:: with SMTP id z123mr33909677qka.320.1582305010998;
        Fri, 21 Feb 2020 09:10:10 -0800 (PST)
Received: from dhcp-41-57.bos.redhat.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id 65sm1797385qtc.4.2020.02.21.09.10.09
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Feb 2020 09:10:10 -0800 (PST)
Message-ID: <1582305008.7365.111.camel@lca.pw>
Subject: Re: [PATCH] kcsan: Add option for verbose reporting
From: Qian Cai <cai@lca.pw>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
 dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Date: Fri, 21 Feb 2020 12:10:08 -0500
In-Reply-To: <20200219151531.161515-1-elver@google.com>
References: <20200219151531.161515-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.22.6 (3.22.6-10.el7)
Mime-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=hQnbm4bv;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Wed, 2020-02-19 at 16:15 +0100, Marco Elver wrote:
> Adds CONFIG_KCSAN_VERBOSE to optionally enable more verbose reports.
> Currently information about the reporting task's held locks and IRQ
> trace events are shown, if they are enabled.

Well, there is a report. I don't understand why it said there is no lock he=
ld in
the writer, but clearly there is this right after in
jbd2_journal_commit_transaction(),

=C2=A0spin_unlock(&jh->b_state_lock);

[ 2268.021382][T25724] BUG: KCSAN: data-race in __jbd2_journal_refile_buffe=
r
[jbd2] / jbd2_write_access_granted [jbd2]
[ 2268.031888][T25724]=C2=A0
[ 2268.034099][T25724] write to 0xffff99f9b1bd0e30 of 8 bytes by task 25721=
 on
cpu 70:
[ 2268.041842][T25724]=C2=A0=C2=A0__jbd2_journal_refile_buffer+0xdd/0x210 [=
jbd2]
__jbd2_journal_refile_buffer at fs/jbd2/transaction.c:2569
[ 2268.048181][T25724]=C2=A0=C2=A0jbd2_journal_commit_transaction+0x2d15/0x=
3f20 [jbd2]
(inlined by) jbd2_journal_commit_transaction at fs/jbd2/commit.c:1033
[ 2268.055042][T25724]=C2=A0=C2=A0kjournald2+0x13b/0x450 [jbd2]
[ 2268.059876][T25724]=C2=A0=C2=A0kthread+0x1cd/0x1f0
[ 2268.063835][T25724]=C2=A0=C2=A0ret_from_fork+0x27/0x50
[ 2268.068143][T25724]=C2=A0
[ 2268.070348][T25724] no locks held by jbd2/loop0-8/25721.
[ 2268.075699][T25724] irq event stamp: 77604
[ 2268.079830][T25724] hardirqs last=C2=A0=C2=A0enabled at (77603): [<fffff=
fff986da853>]
_raw_spin_unlock_irqrestore+0x53/0x60
[ 2268.090166][T25724] hardirqs last disabled at (77604): [<ffffffff986d084=
1>]
__schedule+0x181/0xa50
[ 2268.099192][T25724] softirqs last=C2=A0=C2=A0enabled at (76092): [<fffff=
fff98a0034c>]
__do_softirq+0x34c/0x57c
[ 2268.108392][T25724] softirqs last disabled at (76005): [<ffffffff97cc67a=
2>]
irq_exit+0xa2/0xc0
[ 2268.117062][T25724]=C2=A0
[ 2268.119269][T25724] read to 0xffff99f9b1bd0e30 of 8 bytes by task 25724 =
on
cpu 68:
[ 2268.126916][T25724]=C2=A0=C2=A0jbd2_write_access_granted+0x1b2/0x250 [jb=
d2]
jbd2_write_access_granted at fs/jbd2/transaction.c:1155
[ 2268.133086][T25724]=C2=A0=C2=A0jbd2_journal_get_write_access+0x2c/0x60 [=
jbd2]
[ 2268.139492][T25724]=C2=A0=C2=A0__ext4_journal_get_write_access+0x50/0x90=
 [ext4]
[ 2268.146076][T25724]=C2=A0=C2=A0ext4_mb_mark_diskspace_used+0x158/0x620 [=
ext4]
[ 2268.152507][T25724]=C2=A0=C2=A0ext4_mb_new_blocks+0x54f/0xca0 [ext4]
[ 2268.158125][T25724]=C2=A0=C2=A0ext4_ind_map_blocks+0xc79/0x1b40 [ext4]
[ 2268.163923][T25724]=C2=A0=C2=A0ext4_map_blocks+0x3b4/0x950 [ext4]
[ 2268.169284][T25724]=C2=A0=C2=A0_ext4_get_block+0xfc/0x270 [ext4]
[ 2268.174556][T25724]=C2=A0=C2=A0ext4_get_block+0x3b/0x50 [ext4]
[ 2268.179566][T25724]=C2=A0=C2=A0__block_write_begin_int+0x22e/0xae0
[ 2268.184921][T25724]=C2=A0=C2=A0__block_write_begin+0x39/0x50
[ 2268.189842][T25724]=C2=A0=C2=A0ext4_write_begin+0x388/0xb50 [ext4]
[ 2268.195195][T25724]=C2=A0=C2=A0generic_perform_write+0x15d/0x290
[ 2268.200467][T25724]=C2=A0=C2=A0ext4_buffered_write_iter+0x11f/0x210 [ext=
4]
[ 2268.206612][T25724]=C2=A0=C2=A0ext4_file_write_iter+0xce/0x9e0 [ext4]
[ 2268.212228][T25724]=C2=A0=C2=A0new_sync_write+0x29c/0x3b0
[ 2268.216794][T25724]=C2=A0=C2=A0__vfs_write+0x92/0xa0
[ 2268.220924][T25724]=C2=A0=C2=A0vfs_write+0x103/0x260
[ 2268.225052][T25724]=C2=A0=C2=A0ksys_write+0x9d/0x130
[ 2268.229182][T25724]=C2=A0=C2=A0__x64_sys_write+0x4c/0x60
[ 2268.233666][T25724]=C2=A0=C2=A0do_syscall_64+0x91/0xb05
[ 2268.238058][T25724]=C2=A0=C2=A0entry_SYSCALL_64_after_hwframe+0x49/0xbe
[ 2268.243846][T25724]=C2=A0
[ 2268.246056][T25724] 5 locks held by fsync04/25724:
[ 2268.250880][T25724]=C2=A0=C2=A0#0: ffff99f9911093f8 (sb_writers#13){.+.+=
}, at:
vfs_write+0x21c/0x260
[ 2268.259211][T25724]=C2=A0=C2=A0#1: ffff99f9db4c0348 (&sb->s_type-
>i_mutex_key#15){+.+.}, at: ext4_buffered_write_iter+0x65/0x210 [ext4]
[ 2268.270693][T25724]=C2=A0=C2=A0#2: ffff99f5e7dfcf58 (jbd2_handle){++++},=
 at:
start_this_handle+0x1c1/0x9d0 [jbd2]
[ 2268.280180][T25724]=C2=A0=C2=A0#3: ffff99f9db4c0168 (&ei->i_data_sem){++=
++}, at:
ext4_map_blocks+0x176/0x950 [ext4]
[ 2268.289913][T25724]=C2=A0=C2=A0#4: ffffffff99086b40 (rcu_read_lock){....=
}, at:
jbd2_write_access_granted+0x4e/0x250 [jbd2]
[ 2268.300187][T25724] irq event stamp: 1407125
[ 2268.304496][T25724] hardirqs last=C2=A0=C2=A0enabled at (1407125): [<fff=
fffff980da9b7>]
__find_get_block+0x107/0x790
[ 2268.314218][T25724] hardirqs last disabled at (1407124): [<ffffffff980da=
8f9>]
__find_get_block+0x49/0x790
[ 2268.323856][T25724] softirqs last=C2=A0=C2=A0enabled at (1405528): [<fff=
fffff98a0034c>]
__do_softirq+0x34c/0x57c
[ 2268.333229][T25724] softirqs last disabled at (1405521): [<ffffffff97cc6=
7a2>]
irq_exit+0xa2/0xc0
[ 2268.342075][T25724]=C2=A0
[ 2268.344282][T25724] Reported by Kernel Concurrency Sanitizer on:
[ 2268.350339][T25724] CPU: 68 PID: 25724 Comm: fsync04 Tainted:
G=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0L=C2=A0=C2=A0=C2=A0=C2=A05.6.0-rc2-next-20200221+ #7
[ 2268.360234][T25724] Hardware name: HPE ProLiant DL385 Gen10/ProLiant DL3=
85
Gen10, BIOS A40 07/10/2019

>=20
> Signed-off-by: Marco Elver <elver@google.com>
> Suggested-by: Qian Cai <cai@lca.pw>
> ---
>  kernel/kcsan/report.c | 48 +++++++++++++++++++++++++++++++++++++++++++
>  lib/Kconfig.kcsan     | 13 ++++++++++++
>  2 files changed, 61 insertions(+)
>=20
> diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> index 11c791b886f3c..f14becb6f1537 100644
> --- a/kernel/kcsan/report.c
> +++ b/kernel/kcsan/report.c
> @@ -1,10 +1,12 @@
>  // SPDX-License-Identifier: GPL-2.0
> =20
> +#include <linux/debug_locks.h>
>  #include <linux/jiffies.h>
>  #include <linux/kernel.h>
>  #include <linux/lockdep.h>
>  #include <linux/preempt.h>
>  #include <linux/printk.h>
> +#include <linux/rcupdate.h>
>  #include <linux/sched.h>
>  #include <linux/spinlock.h>
>  #include <linux/stacktrace.h>
> @@ -245,6 +247,29 @@ static int sym_strcmp(void *addr1, void *addr2)
>  	return strncmp(buf1, buf2, sizeof(buf1));
>  }
> =20
> +static void print_verbose_info(struct task_struct *task)
> +{
> +	if (!task)
> +		return;
> +
> +	if (task !=3D current && task->state =3D=3D TASK_RUNNING)
> +		/*
> +		 * Showing held locks for a running task is unreliable, so just
> +		 * skip this. The printed locks are very likely inconsistent,
> +		 * since the stack trace was obtained when the actual race
> +		 * occurred and the task has since continued execution. Since we
> +		 * cannot display the below information from the racing thread,
> +		 * but must print it all from the watcher thread, bail out.
> +		 * Note: Even if the task is not running, there is a chance that
> +		 * the locks held may be inconsistent.
> +		 */
> +		return;
> +
> +	pr_err("\n");
> +	debug_show_held_locks(task);
> +	print_irqtrace_events(task);
> +}
> +
>  /*
>   * Returns true if a report was generated, false otherwise.
>   */
> @@ -319,6 +344,26 @@ static bool print_report(const volatile void *ptr, s=
ize_t size, int access_type,
>  				  other_info.num_stack_entries - other_skipnr,
>  				  0);
> =20
> +		if (IS_ENABLED(CONFIG_KCSAN_VERBOSE) && other_info.task_pid !=3D -1) {
> +			struct task_struct *other_task;
> +
> +			/*
> +			 * Rather than passing @current from the other task via
> +			 * @other_info, obtain task_struct here. The problem
> +			 * with passing @current via @other_info is that, we
> +			 * would have to get_task_struct/put_task_struct, and if
> +			 * we race with a task being released, we would have to
> +			 * release it in release_report(). This may result in
> +			 * deadlock if we want to use KCSAN on the allocators.
> +			 * Instead, make this best-effort, and if the task was
> +			 * already released, we just do not print anything here.
> +			 */
> +			rcu_read_lock();
> +			other_task =3D find_task_by_pid_ns(other_info.task_pid, &init_pid_ns)=
;
> +			print_verbose_info(other_task);
> +			rcu_read_unlock();
> +		}
> +
>  		pr_err("\n");
>  		pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
>  		       get_access_type(access_type), ptr, size,
> @@ -340,6 +385,9 @@ static bool print_report(const volatile void *ptr, si=
ze_t size, int access_type,
>  	stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr,
>  			  0);
> =20
> +	if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> +		print_verbose_info(current);
> +
>  	/* Print report footer. */
>  	pr_err("\n");
>  	pr_err("Reported by Kernel Concurrency Sanitizer on:\n");
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index f0b791143c6ab..ba9268076cfbc 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -20,6 +20,19 @@ menuconfig KCSAN
> =20
>  if KCSAN
> =20
> +config KCSAN_VERBOSE
> +	bool "Show verbose reports with more information about system state"
> +	depends on PROVE_LOCKING
> +	help
> +	  If enabled, reports show more information about the system state that
> +	  may help better analyze and debug races. This includes held locks and
> +	  IRQ trace events.
> +
> +	  While this option should generally be benign, we call into more
> +	  external functions on report generation; if a race report is
> +	  generated from any one of them, system stability may suffer due to
> +	  deadlocks or recursion.  If in doubt, say N.
> +
>  config KCSAN_DEBUG
>  	bool "Debugging of KCSAN internals"
> =20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1582305008.7365.111.camel%40lca.pw.
