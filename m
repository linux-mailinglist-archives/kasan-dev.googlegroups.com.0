Return-Path: <kasan-dev+bncBAABBGH43L6QKGQEUNII6RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id E20C52B9AE1
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Nov 2020 19:48:57 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id q5sf5635432ilc.13
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Nov 2020 10:48:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605811736; cv=pass;
        d=google.com; s=arc-20160816;
        b=ovCHJdO9iZGpJq6Tpw/qF/OdVLJiQXh5lkHWq9AGhXYCWy3Af1KKt6epVhmemZ2ZLM
         KlclBhK/T7yyFtVMlyGpZJ4NMVk2w9/pbd8S6TULY6wn1p/4DPFVlcThkYA1Tkuv7SXl
         6ukQlf/lnqRpWyUAJuNoOATOuPbQpcF2UOaWrL19bOsR1Ro+rmYyJIyfgd/5P9R0lmqq
         iH0P2ft2+yULCL7mNRBlhj4Mv1px63j4mAQg4uBI/Hj1GHjcJ44u0GucdxBhHwvo5E6G
         pX7kxahA6wFV3TPXoBacK189kV3Lv7t8ZlnnkayhWmByxc8seOOzgFLijQPnvLpdwdp7
         87eA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=VdLe06+/s8aL/R5T7Sqz+6dayHg+NPir4tTVkmuR5HU=;
        b=ZSYfyBuWEtHktrkOIVbWdWhlLZuHntp6aWtYHb3c/onKC464gLr0SCHDWB6AgJzPdU
         CL8GJAOx+izTKbiJQ6mnHKBH2Fxv4AeldypxM5Ljgn9jHn3TZS8x05tyQhrtFDFhpffk
         kusoxRQgK+q8trUguiigl2hcciaC+hqhmgVv+2X0Z9/L3HPAvJIzT8X8P2eXC9yu2nnn
         nCP84FOrD+rkyB7MPyloRbDYl8lSTqno4XxHNjNQDjX9Nr36DiCnNGpMONteRGzfVVDD
         K5VZveN3tkox2GCOnTpkLgE75nRhK6IKs+L+DZpHpUgWK3QTVNfVo32HvgMo+HpSCmiB
         p4Jw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=2G7HBzbX;
       spf=pass (google.com: domain of srs0=8ov6=ez=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8Ov6=EZ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VdLe06+/s8aL/R5T7Sqz+6dayHg+NPir4tTVkmuR5HU=;
        b=nqSxbCgpmlspZFgEnSMe4iAUZjEzZ1Bk4OWGt1iqTF5UeIZ6cnhOADtMGVimdNpZ9V
         iPfz6v6VqB3oB899c45XpL+hp47KKa8Qrpw9qGOR2XgKI0QYg1yC5heVBwrTAS8znGLd
         rANy1tOEWWDcEhAa1KpxJ0BtYaR10ye7aBW0EQoZDbDENiLtEngXydDD/vsahCYOnO2O
         k0OUqLllzKCQlKcz5gZRgvLS9sqQe70UObPgNi8Q+FgZojW6J9mngSnDuMgvRFtsVKfH
         o3D3eRR/G6WZDbJ+40Ha3KxWCevjVtThxSNhV7c51yB8oJMvG1XF7DgSFh7E5KiSvJGZ
         srKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VdLe06+/s8aL/R5T7Sqz+6dayHg+NPir4tTVkmuR5HU=;
        b=igLWSPczQteI+2pija+2uA5lPq/T4PnesWfJdCcUmzVadHqeylEmxqtBRFzIINHLsP
         8uUcTDBAodtQNGawRrW+MbLF12U+cGCCzrr/mZ54GXTfjERkp5Qnfe6Udu/rK/ZSAP6/
         u46eeD2wvb1oez8tjt5tJfDu6A6zEzDqfLJ51T1uy7x7oyJ9eKS2+5SyYQX+q/VjrRbM
         dgXjizOej7/4qGLmi08/hCp9+vH8rfDbaZpgAJ7mxLC03ywOW53ztJGumF7h0Qtr+mVV
         XhJOSi5moXO6yYxWHkSUbX3Iir++NPwxB1fzX2EzCTUeOSeAzzBdl//7BXpxG7bCsCCf
         X9SQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533YZqTd/Tdsf5IznO0awLHAV+61UdNVJboK+hXTyJLpA2ZWhV3c
	dbPcIV8pyNuPfxRyQyOruns=
X-Google-Smtp-Source: ABdhPJyQCbwKRGRlxcV1WNK1UDcw2p9rklN05CdPjaXmQl2WGd0HrnnmEN1MSQ0m8UJ8t0ZQ4aUB4g==
X-Received: by 2002:a02:16c3:: with SMTP id a186mr15453138jaa.49.1605811736464;
        Thu, 19 Nov 2020 10:48:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:a23:: with SMTP id 3ls578154jao.2.gmail; Thu, 19
 Nov 2020 10:48:56 -0800 (PST)
X-Received: by 2002:a02:c4d7:: with SMTP id h23mr6349664jaj.22.1605811736058;
        Thu, 19 Nov 2020 10:48:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605811736; cv=none;
        d=google.com; s=arc-20160816;
        b=iJJMfBlViGAzKhYB840ZCbSTQdYOHhkyN8NheDPo4C3fl2cCKPNLiNOUgRBf3YP37Z
         O6GBuQpFZVdw6fPBnJa2fIuw1N23fxCWWxMXjtLyC4CQPiVp2onwlFmhSUgmdLQRPkLe
         LJX5Z9KQUfBk1Zk5Kcjig4Hei8JpYnUIa8JyIhQJrqnwA75m/bXcNz9cCeCPmddLFXzo
         ZI9NymUAt17qvB32uUKfqrcmUCvpEDYoGMG5xdXAH+F+rPzi9rNKNAz8dPkzNR/7Tij9
         Z4a6VZKBVhNb8pzBsedKkNjlBS9sAaILSGHpUP5QNJx2PyJ4ocDd/bGL9fcGuU4XEClK
         DvAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=jevbpc8ynPDXtXinZRDW7141hPtqaSkpmjItkOmuYuE=;
        b=x8LO91WRvss97YF/TuZTEVHZdRD025kP36QisSrVm+8eu4VUe4RzWFLFOYs5hKulc3
         3VKxPx/mW1uDwDl/hSY+76/25zpIZelPqgrDl0vGA9zn9MhdVfvEGo1Oe283hIBMGs5j
         Q+iDHI/d+JQ+eMNSa4AkQW3jbyF94ljnCu0QGwYNFoIU1qa+UZUiID9nDgsBWr3z0m25
         P7Y6GemVDKrqYpD120nF2MkEq6P88KhUbyObpOB2S2rxuUm8EXm4Zl2tEaBi/2YnctBl
         76ET9/llpK826VFXxRxweF5lmbe5oC4r5O2b//+wdbSLXI1V9yjDpAeCQLvl9w0082zL
         Lp9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=2G7HBzbX;
       spf=pass (google.com: domain of srs0=8ov6=ez=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8Ov6=EZ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s11si37242iot.1.2020.11.19.10.48.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 Nov 2020 10:48:56 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=8ov6=ez=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1564824655;
	Thu, 19 Nov 2020 18:48:55 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id A9B5335225CF; Thu, 19 Nov 2020 10:48:54 -0800 (PST)
Date: Thu, 19 Nov 2020 10:48:54 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Steven Rostedt <rostedt@goodmis.org>,
	Anders Roxell <anders.roxell@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org,
	Peter Zijlstra <peterz@infradead.org>, Tejun Heo <tj@kernel.org>,
	Lai Jiangshan <jiangshanlai@gmail.com>
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without
 allocations
Message-ID: <20201119184854.GY1437@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201112161439.GA2989297@elver.google.com>
 <20201112175406.GF3249@paulmck-ThinkPad-P72>
 <20201113175754.GA6273@paulmck-ThinkPad-P72>
 <20201117105236.GA1964407@elver.google.com>
 <20201117182915.GM1437@paulmck-ThinkPad-P72>
 <20201118225621.GA1770130@elver.google.com>
 <20201118233841.GS1437@paulmck-ThinkPad-P72>
 <20201119125357.GA2084963@elver.google.com>
 <20201119151409.GU1437@paulmck-ThinkPad-P72>
 <20201119170259.GA2134472@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201119170259.GA2134472@elver.google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=2G7HBzbX;       spf=pass
 (google.com: domain of srs0=8ov6=ez=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8Ov6=EZ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Thu, Nov 19, 2020 at 06:02:59PM +0100, Marco Elver wrote:
> On Thu, Nov 19, 2020 at 07:14AM -0800, Paul E. McKenney wrote:
> > On Thu, Nov 19, 2020 at 01:53:57PM +0100, Marco Elver wrote:
> > > On Wed, Nov 18, 2020 at 03:38PM -0800, Paul E. McKenney wrote:
> > > > On Wed, Nov 18, 2020 at 11:56:21PM +0100, Marco Elver wrote:
> > > > > [...]
> > > > > I think I figured out one piece of the puzzle. Bisection keeps pointing
> > > > > me at some -rcu merge commit, which kept throwing me off. Nor did it
> > > > > help that reproduction is a bit flaky. However, I think there are 2
> > > > > independent problems, but the manifestation of 1 problem triggers the
> > > > > 2nd problem:
> > > > > 
> > > > > 1. problem: slowed forward progress (workqueue lockup / RCU stall reports)
> > > > > 
> > > > > 2. problem: DEADLOCK which causes complete system lockup
> > > > > 
> > > > > 	| ...
> > > > > 	|        CPU0
> > > > > 	|        ----
> > > > > 	|   lock(rcu_node_0);
> > > > > 	|   <Interrupt>
> > > > > 	|     lock(rcu_node_0);
> > > > > 	| 
> > > > > 	|  *** DEADLOCK ***
> > > > > 	| 
> > > > > 	| 1 lock held by event_benchmark/105:
> > > > > 	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: print_other_cpu_stall kernel/rcu/tree_stall.h:493 [inline]
> > > > > 	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: check_cpu_stall kernel/rcu/tree_stall.h:652 [inline]
> > > > > 	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: rcu_pending kernel/rcu/tree.c:3752 [inline]
> > > > > 	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x428/0xd40 kernel/rcu/tree.c:2581
> > > > > 	| ...
> > > > > 
> > > > > Problem 2 can with reasonable confidence (5 trials) be fixed by reverting:
> > > > > 
> > > > > 	rcu: Don't invoke try_invoke_on_locked_down_task() with irqs disabled
> > > > > 
> > > > > At which point the system always boots to user space -- albeit with a
> > > > > bunch of warnings still (attached). The supposed "good" version doesn't
> > > > > end up with all those warnings deterministically, so I couldn't say if
> > > > > the warnings are expected due to recent changes or not (Arm64 QEMU
> > > > > emulation, 1 CPU, and lots of debugging tools on).
> > > > > 
> > > > > Does any of that make sense?
> > > > 
> > > > Marco, it makes all too much sense!  :-/
> > > > 
> > > > Does the patch below help?
> > > > 
> > > > 							Thanx, Paul
> > > > 
> > > > ------------------------------------------------------------------------
> > > > 
> > > > commit 444ef3bbd0f243b912fdfd51f326704f8ee872bf
> > > > Author: Peter Zijlstra <peterz@infradead.org>
> > > > Date:   Sat Aug 29 10:22:24 2020 -0700
> > > > 
> > > >     sched/core: Allow try_invoke_on_locked_down_task() with irqs disabled
> > > 
> > > My assumption is that this is a replacement for "rcu: Don't invoke
> > > try_invoke_on_locked_down_task() with irqs disabled", right?
> > 
> > Hmmm...  It was actually intended to be in addition.
> > 
> > > That seems to have the same result (same test setup) as only reverting
> > > "rcu: Don't invoke..." does: still results in a bunch of workqueue
> > > lockup warnings and RCU stall warnings, but boots to user space. I
> > > attached a log. If the warnings are expected (are they?), then it looks
> > > fine to me.
> > 
> > No, they are not at all expected, but might be a different symptom
> > of the original problem.  Please see below.
> > 
> > > (And just in case: with "rcu: Don't invoke..." and "sched/core:
> > > Allow..." both applied I still get DEADLOCKs -- but that's probably
> > > expected.)
> > 
> > As noted earlier, it is a surprise.  Could you please send me the
> > console output?
>  
> I've attached the output of a run with both commits applied.

Got it, thank you!

> > > Testing all events: OK
> > > hrtimer: interrupt took 17120368 ns
> > > Running tests again, along with the function tracer
> > > Running tests on all trace events:
> > > Testing all events: 
> > > BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 12s!
> > > Showing busy workqueues and worker pools:
> > > workqueue events: flags=0x0
> > >   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
> > >     pending: vmstat_shepherd
> > > BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 17s!
> > > Showing busy workqueues and worker pools:
> > > workqueue events: flags=0x0
> > >   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
> > >     pending: vmstat_shepherd
> > > workqueue events_power_efficient: flags=0x82
> > >   pwq 2: cpus=0 flags=0x4 nice=0 active=1/256 refcnt=3
> > >     pending: neigh_periodic_work
> > > ------------[ cut here ]------------
> > > WARNING: CPU: 0 PID: 1 at kernel/rcu/tree_stall.h:758 rcu_check_gp_start_stall kernel/rcu/tree_stall.h:750 [inline]
> > > WARNING: CPU: 0 PID: 1 at kernel/rcu/tree_stall.h:758 rcu_check_gp_start_stall.isra.0+0x14c/0x210 kernel/rcu/tree_stall.h:711
> > 
> > I have different line numbering,
> 
> This is still using next-20201110. I'll rerun with latest -next as well.

No problem, as it looks like next-20201105 is a reasonable approximation.

> > but the only warning that I see in this
> > function is the one complaining that RCU has been ignoring a request to
> > start a grace period for too long.  This usually happens because the RCU
> > grace-period kthread (named "rcu_preempt" in your case, but can also be
> > named "rcu_sched") is being prevented from running, but can be caused
> > by other things as well.
> > 
> > > Modules linked in:
> > > CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.10.0-rc3-next-20201110-00003-g920304642405-dirty #30
> > > Hardware name: linux,dummy-virt (DT)
> > > pstate: 20000085 (nzCv daIf -PAN -UAO -TCO BTYPE=--)
> > > pc : rcu_check_gp_start_stall kernel/rcu/tree_stall.h:750 [inline]
> > > pc : rcu_check_gp_start_stall.isra.0+0x14c/0x210 kernel/rcu/tree_stall.h:711
> > > lr : __xchg_mb arch/arm64/include/asm/cmpxchg.h:88 [inline]
> > > lr : atomic_xchg include/asm-generic/atomic-instrumented.h:615 [inline]
> > > lr : rcu_check_gp_start_stall kernel/rcu/tree_stall.h:751 [inline]
> > > lr : rcu_check_gp_start_stall.isra.0+0x148/0x210 kernel/rcu/tree_stall.h:711
> > 
> > Two program counters and four link registers?  Awesome!  ;-)
> 
> Ah I'm using syzkaller's symbolizer, which duplicates lines if there was
> an inline function (remove all the "[inline]" and it should make sense,
> but the "[inline]" tell you the actual line). Obviously for things like
> this it's a bit unintuitive. :-)

Very useful, though, and a big THANK YOU to those who made it happen!

> > > sp : ffff800010003d20
> > > x29: ffff800010003d20 x28: ffff274ac3a10000 
> > > x27: 0000000000000000 x26: ffff274b3dbe72d8 
> > > x25: ffffbcb867722000 x24: 0000000000000000 
> > > x23: 0000000000000000 x22: ffffbcb8681d1260 
> > > x21: ffffbcb86735b000 x20: ffffbcb867404440 
> > > x19: ffffbcb867404440 x18: 0000000000000123 
> > > x17: ffffbcb865d400f0 x16: 0000000000000002 
> > > x15: 0000000000000002 x14: 0000000000000000 
> > > x13: 003d090000000000 x12: 00001e8480000000 
> > > x11: ffffbcb867958980 x10: ffff800010003cf0 
> > > x9 : ffffbcb864f4b7c8 x8 : 0000000000000080 
> > > x7 : 0000000000000026 x6 : ffffbcb86774e4c0 
> > > x5 : 0000000000000000 x4 : 00000000d4001f4b 
> > > x3 : 0000000000000000 x2 : 0000000000000000 
> > > x1 : 0000000000000001 x0 : 0000000000000000 
> > > Call trace:
> > >  rcu_check_gp_start_stall kernel/rcu/tree_stall.h:750 [inline]
> > >  rcu_check_gp_start_stall.isra.0+0x14c/0x210 kernel/rcu/tree_stall.h:711
> > >  rcu_core+0x168/0x9e0 kernel/rcu/tree.c:2719
> > >  rcu_core_si+0x18/0x28 kernel/rcu/tree.c:2737
> > 
> > The RCU_SOFTIRQ handler is causing this checking to occur, for whatever
> > that is worth.
> > 
> > >  __do_softirq+0x188/0x6b4 kernel/softirq.c:298
> > >  do_softirq_own_stack include/linux/interrupt.h:568 [inline]
> > >  invoke_softirq kernel/softirq.c:393 [inline]
> > >  __irq_exit_rcu kernel/softirq.c:423 [inline]
> > >  irq_exit+0x1cc/0x1e0 kernel/softirq.c:447
> > >  __handle_domain_irq+0xb4/0x130 kernel/irq/irqdesc.c:690
> > >  handle_domain_irq include/linux/irqdesc.h:170 [inline]
> > >  gic_handle_irq+0x70/0x108 drivers/irqchip/irq-gic.c:370
> > >  el1_irq+0xc0/0x180 arch/arm64/kernel/entry.S:651
> > >  arch_local_irq_restore+0x8/0x10 arch/arm64/include/asm/irqflags.h:124
> > >  release_probes kernel/tracepoint.c:113 [inline]
> > >  tracepoint_remove_func kernel/tracepoint.c:315 [inline]
> > >  tracepoint_probe_unregister+0x220/0x378 kernel/tracepoint.c:382
> > >  trace_event_reg+0x58/0x150 kernel/trace/trace_events.c:298
> > >  __ftrace_event_enable_disable+0x424/0x608 kernel/trace/trace_events.c:412
> > >  ftrace_event_enable_disable kernel/trace/trace_events.c:495 [inline]
> > >  __ftrace_set_clr_event_nolock+0x120/0x180 kernel/trace/trace_events.c:811
> > >  __ftrace_set_clr_event+0x60/0x90 kernel/trace/trace_events.c:833
> > >  event_trace_self_tests+0xd4/0x114 kernel/trace/trace_events.c:3661
> > >  event_trace_self_test_with_function kernel/trace/trace_events.c:3734 [inline]
> > >  event_trace_self_tests_init+0x88/0xa8 kernel/trace/trace_events.c:3747
> > >  do_one_initcall+0xa4/0x500 init/main.c:1212
> > >  do_initcall_level init/main.c:1285 [inline]
> > >  do_initcalls init/main.c:1301 [inline]
> > >  do_basic_setup init/main.c:1321 [inline]
> > >  kernel_init_freeable+0x344/0x3c4 init/main.c:1521
> > >  kernel_init+0x20/0x16c init/main.c:1410
> > >  ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:961
> > > irq event stamp: 3274113
> > > hardirqs last  enabled at (3274112): [<ffffbcb864f8aee4>] rcu_core+0x974/0x9e0 kernel/rcu/tree.c:2716
> > > hardirqs last disabled at (3274113): [<ffffbcb866233bf0>] __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:108 [inline]
> > > hardirqs last disabled at (3274113): [<ffffbcb866233bf0>] _raw_spin_lock_irqsave+0xb8/0x14c kernel/locking/spinlock.c:159
> > > softirqs last  enabled at (3272576): [<ffffbcb864e10b80>] __do_softirq+0x630/0x6b4 kernel/softirq.c:325
> > > softirqs last disabled at (3274101): [<ffffbcb864ec6c54>] do_softirq_own_stack include/linux/interrupt.h:568 [inline]
> > > softirqs last disabled at (3274101): [<ffffbcb864ec6c54>] invoke_softirq kernel/softirq.c:393 [inline]
> > > softirqs last disabled at (3274101): [<ffffbcb864ec6c54>] __irq_exit_rcu kernel/softirq.c:423 [inline]
> > > softirqs last disabled at (3274101): [<ffffbcb864ec6c54>] irq_exit+0x1cc/0x1e0 kernel/softirq.c:447
> > > ---[ end trace 902768efebf5a607 ]---
> > > rcu: rcu_preempt: wait state: RCU_GP_WAIT_GPS(1) ->state: 0x0 delta ->gp_activity 4452 ->gp_req_activity 3848 ->gp_wake_time 3848 ->gp_wake_seq 2696 ->gp_seq 2696 ->gp_seq_needed 2700 ->gp_flags 0x1
> > 
> > The last thing that RCU's grace-period kthread did was to go to sleep
> > waiting for a grace-period request (RCU_GP_WAIT_GPS).
> > 
> > > rcu: 	rcu_node 0:0 ->gp_seq 2696 ->gp_seq_needed 2700
> > > rcu: RCU callbacks invoked since boot: 2583
> > > rcu_tasks: RTGS_WAIT_CBS(11) since 567120 g:1 i:0/0 k. 
> > > rcu_tasks_rude: RTGS_WAIT_CBS(11) since 567155 g:1 i:0/1 k. 
> > > rcu_tasks_trace: RTGS_INIT(0) since 4295464549 g:0 i:0/0 k. N0 h:0/0/0
> > > rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
> > > 	(detected by 0, t=3752 jiffies, g=2705, q=8)
> > > rcu: All QSes seen, last rcu_preempt kthread activity 557 (4295471128-4295470571), jiffies_till_next_fqs=1, root ->qsmask 0x0
> > > rcu: rcu_preempt kthread starved for 557 jiffies! g2705 f0x2 RCU_GP_CLEANUP(7) ->state=0x0 ->cpu=0
> > 
> > And here we see that RCU's grace-period kthread has in fact been starved.
> > 
> > This kthread is now in RCU_GP_CLEANUP, perhaps because of the wakeup that is
> > sent in rcu_check_gp_kthread_starvation().
> > 
> > My current guess is that this is a consequence of the earlier failures,
> > but who knows?
>  
> I can try bisection again, or reverting some commits that might be
> suspicious? But we'd need some selection of suspicious commits.

The report claims that one of the rcu_node ->lock fields is held
with interrupts enabled, which would indeed be bad.  Except that all
of the stack traces that it shows have these locks held within the
scheduling-clock interrupt handler.  Now with the "rcu: Don't invoke
try_invoke_on_locked_down_task() with irqs disabled" but without the
"sched/core: Allow try_invoke_on_locked_down_task() with irqs disabled"
commit, I understand why.  With both, I don't see how this happens.

At this point, I am reduced to adding lockdep_assert_irqs_disabled()
calls at various points in that code, as shown in the patch below.

At this point, I would guess that your first priority would be the
initial bug rather than this following issue, but you never know, this
might well help diagnose the initial bug.

							Thanx, Paul

------------------------------------------------------------------------

commit ccedf00693ef60f7c06d23490fc41bb60dd43dc3
Author: Paul E. McKenney <paulmck@kernel.org>
Date:   Thu Nov 19 10:13:06 2020 -0800

    rcu: Add lockdep_assert_irqs_disabled() to rcu_sched_clock_irq() and callees
    
    This commit adds a number of lockdep_assert_irqs_disabled() calls
    to rcu_sched_clock_irq() and a number of the functions that it calls.
    The point of this is to help track down a situation where lockdep appears
    to be insisting that interrupts are enabled within these functions, which
    should only ever be invoked from the scheduling-clock interrupt handler.
    
    Link: https://lore.kernel.org/lkml/20201111133813.GA81547@elver.google.com/
    Signed-off-by: Paul E. McKenney <paulmck@kernel.org>

diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
index 2b3274c..1d956f9 100644
--- a/kernel/rcu/tree.c
+++ b/kernel/rcu/tree.c
@@ -2580,6 +2580,7 @@ static void rcu_do_batch(struct rcu_data *rdp)
 void rcu_sched_clock_irq(int user)
 {
 	trace_rcu_utilization(TPS("Start scheduler-tick"));
+	lockdep_assert_irqs_disabled();
 	raw_cpu_inc(rcu_data.ticks_this_gp);
 	/* The load-acquire pairs with the store-release setting to true. */
 	if (smp_load_acquire(this_cpu_ptr(&rcu_data.rcu_urgent_qs))) {
@@ -2593,6 +2594,7 @@ void rcu_sched_clock_irq(int user)
 	rcu_flavor_sched_clock_irq(user);
 	if (rcu_pending(user))
 		invoke_rcu_core();
+	lockdep_assert_irqs_disabled();
 
 	trace_rcu_utilization(TPS("End scheduler-tick"));
 }
@@ -3761,6 +3763,8 @@ static int rcu_pending(int user)
 	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
 	struct rcu_node *rnp = rdp->mynode;
 
+	lockdep_assert_irqs_disabled();
+
 	/* Check for CPU stalls, if enabled. */
 	check_cpu_stall(rdp);
 
diff --git a/kernel/rcu/tree_plugin.h b/kernel/rcu/tree_plugin.h
index 642ebd6..f7aa41c 100644
--- a/kernel/rcu/tree_plugin.h
+++ b/kernel/rcu/tree_plugin.h
@@ -682,6 +682,7 @@ static void rcu_flavor_sched_clock_irq(int user)
 {
 	struct task_struct *t = current;
 
+	lockdep_assert_irqs_disabled();
 	if (user || rcu_is_cpu_rrupt_from_idle()) {
 		rcu_note_voluntary_context_switch(current);
 	}
diff --git a/kernel/rcu/tree_stall.h b/kernel/rcu/tree_stall.h
index 4e3aecd..f276d8e 100644
--- a/kernel/rcu/tree_stall.h
+++ b/kernel/rcu/tree_stall.h
@@ -267,6 +267,7 @@ static int rcu_print_task_stall(struct rcu_node *rnp, unsigned long flags)
 	struct task_struct *t;
 	struct task_struct *ts[8];
 
+	lockdep_assert_irqs_disabled();
 	if (!rcu_preempt_blocked_readers_cgp(rnp))
 		return 0;
 	pr_err("\tTasks blocked on level-%d rcu_node (CPUs %d-%d):",
@@ -291,6 +292,7 @@ static int rcu_print_task_stall(struct rcu_node *rnp, unsigned long flags)
 				".q"[rscr.rs.b.need_qs],
 				".e"[rscr.rs.b.exp_hint],
 				".l"[rscr.on_blkd_list]);
+		lockdep_assert_irqs_disabled();
 		put_task_struct(t);
 		ndetected++;
 	}
@@ -527,6 +529,8 @@ static void print_other_cpu_stall(unsigned long gp_seq, unsigned long gps)
 	struct rcu_node *rnp;
 	long totqlen = 0;
 
+	lockdep_assert_irqs_disabled();
+
 	/* Kick and suppress, if so configured. */
 	rcu_stall_kick_kthreads();
 	if (rcu_stall_is_suppressed())
@@ -548,6 +552,7 @@ static void print_other_cpu_stall(unsigned long gp_seq, unsigned long gps)
 				}
 		}
 		ndetected += rcu_print_task_stall(rnp, flags); // Releases rnp->lock.
+		lockdep_assert_irqs_disabled();
 	}
 
 	for_each_possible_cpu(cpu)
@@ -594,6 +599,8 @@ static void print_cpu_stall(unsigned long gps)
 	struct rcu_node *rnp = rcu_get_root();
 	long totqlen = 0;
 
+	lockdep_assert_irqs_disabled();
+
 	/* Kick and suppress, if so configured. */
 	rcu_stall_kick_kthreads();
 	if (rcu_stall_is_suppressed())
@@ -649,6 +656,7 @@ static void check_cpu_stall(struct rcu_data *rdp)
 	unsigned long js;
 	struct rcu_node *rnp;
 
+	lockdep_assert_irqs_disabled();
 	if ((rcu_stall_is_suppressed() && !READ_ONCE(rcu_kick_kthreads)) ||
 	    !rcu_gp_in_progress())
 		return;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201119184854.GY1437%40paulmck-ThinkPad-P72.
