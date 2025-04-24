Return-Path: <kasan-dev+bncBCS4VDMYRUNBB242VPAAMGQEKXYQDAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 45A73A9BB79
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Apr 2025 01:46:54 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-229170fbe74sf13735135ad.2
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Apr 2025 16:46:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745538412; cv=pass;
        d=google.com; s=arc-20240605;
        b=A6Ymbe60jWE+h99q1tdcNGgXSmV/AtBHaH5YWuiNpeaz5Xj/K9mSyzHi02thJcepbc
         xvPBXkL95+lA0vcaou4qBhIIkbVXeQ+9szrU5FrjLN/WlLQSqyQ0GtR5i3hnv3IQpuvH
         RwEIcXQx9P9FJtJrS3niF9h+jGaIZ35YXr8EKDMx+MGxxQiQqMrGRVUgcQE0dfRu5YtZ
         FHmrcUAT5IxbFNGhDEWSVe52Ejf/8EsnuX9IzehxRtRtPuwxel7L8qSqdAjlmV2RB4lw
         5MRQ/IqlYnpcH4Tr65ySD+BYQSfqyI/wlwkakids7YbN9q9p0a4KBjQzSpCAR+Jy7rDv
         a/ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=BXq/cKSFgOnRR1yU3LaOfTvD55sJ83DoWxPqrHYvBT4=;
        fh=weKWIM8f8n6/kybTfhOL3cNKAeZvRIMDalG27IM9Ctg=;
        b=PWSEbQrZPobgsYB3TocMa44fUMt1G5+8zsU5agn4R8ZzPKYcU+WgMlbkXc1WODZjGp
         IV6hBORiz3GHFHUGKOmjSZpDH4A3OVYtevVvVbN3YJBAZH81U4l1d5vmyK0mk+4OUEFX
         xnklILOnitQ92nwBa2l5ItYXxOe7eJbdZOJ94NWbNmjoN9QRts0W34EjSCismPETUmuc
         RB5NEIMk9CznzaUPo78CMLWYgMWndaJKVpquCbkT2B2tblRw7++x/BFPBIOYfTs7Uu1J
         jJYu2hE41HdOVTU0dWkomoZtLVfvt6hYEbSDn7b0dJg3WPCoVZod/s6kCvPJv0LwVCtn
         aO9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mCMEX1vg;
       spf=pass (google.com: domain of srs0=hcaf=xk=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=HcaF=XK=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745538412; x=1746143212; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:reply-to
         :message-id:subject:cc:to:from:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BXq/cKSFgOnRR1yU3LaOfTvD55sJ83DoWxPqrHYvBT4=;
        b=xnoahrcppBbUgLuSJfupW/r2d1ZqhdMiPTe23I4Z+O26ipFyNs8ztVc8WXAU+ekC2j
         qvuLh4DrFEXLfOr8oLhHRlmYoCACtXWCyY6zyc3vbfb/4zKefC7ng486qP9zflCqhaMx
         ge/1QOYTCDYht2xJS26iiOez6WhIYga3qRZIbpK2DHj34DVIUQ93OfS72gePfJA2kZ7Q
         WwTMVIFrYiNbtabm67gzNqsCMRH2Am9LkUr4Ojo4DfsPuX6+o0oYHvelGzlVuZ4nFjCO
         ZyMP2KkYmov01JzM/Y6+XzoEL75fMQFkAl0dtJhIO9mr7TB5vXoZZFiPTh4p43hmgc94
         kEWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745538412; x=1746143212;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BXq/cKSFgOnRR1yU3LaOfTvD55sJ83DoWxPqrHYvBT4=;
        b=SJrGub5C3QSMoPTXjMHL56HiBVLe+Mqscy60bsdHMRfgTRPHQaM7ekQ9ZTjWz9LxHn
         0+OP5XHTSehowzku22Mtae2N30KICrPPhFe6hVnSeHQzrgmGJCyNE0n+1AXp/H4JZNfp
         gcaMzBMYtlVrIGe/uTY3suCu5QT35WGgpyK3NEqP3i8OA1f4FIjs8a/CwUUNcbY85+W0
         mGtoVfwePaCAZ5w6eSHiqDF8RKYm4yGMNHlhq9Xn2mdrZg9H46Eti29A3wONtKvcHdI7
         H62GRzjgyKffaz0R1HQj8nmqU5u9NcTtV13jtYnaJ6wRbmZQWB53oAtQAlrcTnd0YUTQ
         dibA==
X-Forwarded-Encrypted: i=2; AJvYcCVUmE9KTh4tGPmnmrXkMxvmOQ6ha+TamqRLqsyedYawMZmpA6G8x2UMoauGtmw42tAiRTI4BA==@lfdr.de
X-Gm-Message-State: AOJu0YzAoG2fo6B8nQwT6RAo2wAa+h7/eTLWdH1GfZt4uyUV/jQ7UlYj
	NmGhU7U7GwEjObj1CLf1NYUvLvBUvTPliavy5qUFCCTj+MIX/bCw
X-Google-Smtp-Source: AGHT+IFRPlfum8AX27aMKXQ30zUnkSJaV+BfY86eXYGgVCdsMYPLGb6FqFvv0pvp9/jiG9+Rff2L9Q==
X-Received: by 2002:a17:903:1b6d:b0:223:66bb:8993 with SMTP id d9443c01a7336-22dbf63a302mr2941525ad.43.1745538412196;
        Thu, 24 Apr 2025 16:46:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFNRO5v9PkaNVQ2xlkyCCIfvdGV/P9iQgoWBS8bzemDAA==
Received: by 2002:a17:903:3b53:b0:223:3b76:4e15 with SMTP id
 d9443c01a7336-22db161cc8als4519955ad.1.-pod-prod-09-us; Thu, 24 Apr 2025
 16:46:51 -0700 (PDT)
X-Received: by 2002:a17:903:24f:b0:224:826:279e with SMTP id d9443c01a7336-22dbf640322mr2696765ad.50.1745538410787;
        Thu, 24 Apr 2025 16:46:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745538410; cv=none;
        d=google.com; s=arc-20240605;
        b=FYTTelczJj4XkfTeXi+zeTJyYqCwPWpT/By9g0Atnmmsk8tlJU8I7VLfffGmraQpb5
         alSuaWLILmKqaN4jQ7BVQmY74G5Mx8vEz7k2RBxQLu6Daepkm8eNE4d1y1gDldv4uYtx
         f4IL3LQM/YsoiVjMU0jMQvpBZL7y5crPgyZc84cD1mdCykrLqvlpfFTJ2YsgAisr44jF
         x33Vgi+edU4Orcws6QLhufcPx4YCoLqFRbkj/KV2v42EX7Wcybqg18XdLLC4qkO9hdp3
         FnSx6vQ8l6wgEVZ3RZq8oFB1rREFJCI4yh9TdYI++oR5jzQTEMhnI+o+7MT+LlbRlzXM
         M49w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=BunHrG21Tma6amZJCEEBIAGCtrXzqE6OuRXE5lPuCwo=;
        fh=Ln3D5DioNyEYp1GSZPLgYmdfc49Oro0TrEUSYvV3U/8=;
        b=cPp5EI6VaYoiJ4pGzmvzkCjsWVrUAceiyjj4H/Ca42PnocZ8LQpLABqZ4/X1n9kkfY
         5Rie79MFsQesjT9I0J6rK1sz4GiquB5+QenxcFvY85BlwmLZtu6i/F+BKNzInbrygW72
         denJjDKRJPsrahOpQTt1DoCMoPIKcDVPDqooRMfZ8idx8SSj+kF7GPTJedmk6ek2p94Z
         RaG2/qfWIz/pNExe1mzrDFnkSy5slbPfWugb1XDHoSIauhuVbBe6N5MY4TIxYKPMTfZf
         y96N2qascfoNbLEXzlr7lcJmZMO5ZbPF2JjMCCp1jOv1/oNNXQ9Ov3tjUNeD+ypHrvVR
         +f0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mCMEX1vg;
       spf=pass (google.com: domain of srs0=hcaf=xk=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=HcaF=XK=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b15faded61dsi104501a12.4.2025.04.24.16.46.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 24 Apr 2025 16:46:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=hcaf=xk=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id E2530A403CF;
	Thu, 24 Apr 2025 23:41:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 90DDAC4CEE3;
	Thu, 24 Apr 2025 23:46:49 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 332E3CE191C; Thu, 24 Apr 2025 16:46:49 -0700 (PDT)
Date: Thu, 24 Apr 2025 16:46:49 -0700
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Cc: elver@google.com, dvyukov@google.com
Subject: Dazed and confused by KCSAN report (but I eventually figured it out)
Message-ID: <0dbb0354-9a89-438a-b009-5ac72e55efb1@paulmck-laptop>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mCMEX1vg;       spf=pass
 (google.com: domain of srs0=hcaf=xk=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom="SRS0=HcaF=XK=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Paul E. McKenney" <paulmck@kernel.org>
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

Hello!

OK, I *was* confused by the following KCSAN report.  It turned out that
the problem was that I did not realize that irq_work handlers do not run
with interrupts disabled.  Given that this particular irq_work handler is
not (very) performance sensitive, the fix is simply to disable interrupts,
as shown in the prototype patch shown at the end of this email.

I am including my initial confusion for your amusement.

So thank you all for KCSAN!  I am here to tell you that low-probability
bugs of this sort are a *real* pain to locate the hard way!  ;-)

							Thanx, Paul

------------------------------------------------------------------------

I am confused by this KCSAN report:

[  611.741857] BUG: KCSAN: data-race in rcu_preempt_deferred_qs_handler / rcu_read_unlock_special
[  611.741874] 
[  611.741877] read to 0xffff96b95f42d8d8 of 1 bytes by task 90 on cpu 8:
[  611.741883]  rcu_read_unlock_special+0x175/0x260
[  611.741895]  __rcu_read_unlock+0x92/0xa0
[  611.741905]  rt_spin_unlock+0x9b/0xc0
[  611.741914]  __local_bh_enable+0x10d/0x170
[  611.741925]  __local_bh_enable_ip+0xfb/0x150
[  611.741935]  rcu_do_batch+0x595/0xc40
[  611.741942]  rcu_cpu_kthread+0x4e9/0x830
[  611.741950]  smpboot_thread_fn+0x24d/0x3b0
[  611.741959]  kthread+0x3bd/0x410
[  611.741969]  ret_from_fork+0x35/0x40
[  611.741977]  ret_from_fork_asm+0x1a/0x30
[  611.741986]
[  611.741989] write to 0xffff96b95f42d8d8 of 1 bytes by task 88 on cpu 8:
[  611.741996]  rcu_preempt_deferred_qs_handler+0x1e/0x30
[  611.742006]  irq_work_single+0xaf/0x160
[  611.742013]  run_irq_workd+0x91/0xc0
[  611.742020]  smpboot_thread_fn+0x24d/0x3b0
[  611.742029]  kthread+0x3bd/0x410
[  611.742039]  ret_from_fork+0x35/0x40
[  611.742047]  ret_from_fork_asm+0x1a/0x30
[  611.742056]
[  611.742058] no locks held by irq_work/8/88.
[  611.742063] irq event stamp: 200272
[  611.742066] hardirqs last  enabled at (200272): [<ffffffffb0f56121>] finish_task_switch+0x131/0x320
[  611.742078] hardirqs last disabled at (200271): [<ffffffffb25c7859>] __schedule+0x129/0xd70
[  611.742089] softirqs last  enabled at (0): [<ffffffffb0ee093f>] copy_process+0x4df/0x1cc0
[  611.742112] softirqs last disabled at (0): [<0000000000000000>] 0x0
[  611.742119]
[  611.742142] Reported by Kernel Concurrency Sanitizer on:
[  611.742149] CPU: 8 UID: 0 PID: 88 Comm: irq_work/8 Not tainted 6.15.0-rc1-00063-g5e8a7c9a1a0a #2713 PREEMPT_{RT,(full)}
[  611.742154] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.14.0-0-g155821a1990b-prebuilt.qemu.org 04/01/2014

The rcu_preempt_deferred_qs_handler() IRQ-work handler's only memory
reference is the one-byte ->defer_qs_iw_pending field of the rcu_data
per-CPU structure.  This handler is scheduled using irq_work_queue_on(),
directed to the rcu_data structure's CPU.  All of the remaining references
are by rcu_read_unlock_special() with interrupts disabled, and with the
rcu_data structure selected for the current CPU.

I did add WARN_ON_ONCE() calls to verify that the code really was always
accessing a given CPU's ->defer_qs_iw_pending field from that CPU.
That WARN_ON_ONCE() never triggered, and KCSAN still flagged the
->defer_qs_iw_pending field as having a data race.

[ At which point I realized that I was not so sure that irq-work handlers
  had interrupts disabled.  It turns out that they do not, so an RCU
  read-side critical section in a real interrupt handler that interrupted
  rcu_preempt_deferred_qs_handler() could legitimately cause this KCSAN
  complaint.  Again, thank you all for KCSAN!!! ]

For completeness, the KCSAN Kconfig options are as follows:

CONFIG_HAVE_ARCH_KCSAN=y
CONFIG_HAVE_KCSAN_COMPILER=y
CONFIG_KCSAN=y
CONFIG_CC_HAS_TSAN_COMPOUND_READ_BEFORE_WRITE=y
CONFIG_KCSAN_VERBOSE=y
CONFIG_KCSAN_SELFTEST=y
CONFIG_KCSAN_EARLY_ENABLE=y
CONFIG_KCSAN_NUM_WATCHPOINTS=64
CONFIG_KCSAN_UDELAY_TASK=80
CONFIG_KCSAN_UDELAY_INTERRUPT=20
CONFIG_KCSAN_DELAY_RANDOMIZE=y
CONFIG_KCSAN_SKIP_WATCH=4000
CONFIG_KCSAN_SKIP_WATCH_RANDOMIZE=y
CONFIG_KCSAN_INTERRUPT_WATCHER=y
CONFIG_KCSAN_REPORT_ONCE_IN_MS=100000
CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN=y
CONFIG_KCSAN_STRICT=y
CONFIG_KCSAN_WEAK_MEMORY=y

------------------------------------------------------------------------

diff --git a/kernel/rcu/tree_plugin.h b/kernel/rcu/tree_plugin.h
index 3c0bbbbb686fe..003e549f65141 100644
--- a/kernel/rcu/tree_plugin.h
+++ b/kernel/rcu/tree_plugin.h
@@ -624,10 +624,13 @@ notrace void rcu_preempt_deferred_qs(struct task_struct *t)
  */
 static void rcu_preempt_deferred_qs_handler(struct irq_work *iwp)
 {
+	unsigned long flags;
 	struct rcu_data *rdp;
 
 	rdp = container_of(iwp, struct rcu_data, defer_qs_iw);
+	local_irq_save(flags);
 	rdp->defer_qs_iw_pending = false;
+	local_irq_restore(flags);
 }
 
 /*

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0dbb0354-9a89-438a-b009-5ac72e55efb1%40paulmck-laptop.
