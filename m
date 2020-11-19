Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTGK3L6QKGQESQH3EMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B4A82B98CC
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Nov 2020 18:03:09 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id g19sf1465008ljl.23
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Nov 2020 09:03:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605805389; cv=pass;
        d=google.com; s=arc-20160816;
        b=hBSutVzYADWQb6hJcj2NSmBjsJspmi1o6SXtv9f20O/AK/Mpqh+IyjqNrp1nOldu3l
         kbCJA3Ci+FqalEDHcn2X5pgEcea/Gpo2MokLFpY3skp0vQD+GF00cz1S+kx2j3RAUZfj
         8+oeqZoqNhbzIaXgt6So4PbKixmODvLdPSWyELh+kTgmWgI4QzqXcg/48VysvTMjfSPT
         otl/BkTYm+oBStawU9VSM6pOUTdFaiRQVwxQwgYjBsGH+z4TQ/tDQAzKKcd1V2FoGdA+
         H12LzgMQ55VNxvP17UqW7uqhsas7L3trqAbUeyloBpu6VIwFor7NDNwsaSgo5fPcFHWt
         hZzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=bBlsLrdGHc++jWRdKrICWpb3Hl5Ac3nNg4SX/XTm6W0=;
        b=E35imLTXzjWjNm8Ok04kQVOvO4dZ2cqCHhRuOlK5rk0qWl5Jab0TjW+nGN8M32GEY8
         PwVGtw6WW4kBaAxwhixKi88/am2rYk3fnHyBlkgSmeHaPQikB9v1PIq9eG40K63tdVCw
         wQYQGU09VZLOcU9mBPay0VsmBDPBMfKOtodqhCSsg4wh0HrnLQzgf+GJhPgHdHcwHWIA
         orj7Xhzhe6xTovDitlElGXpB2oKnHWEgPD8+dKUEP3GbBHRue4jRwoAseRSbOu/9tB+Z
         PJfDfjSjrBGSh41cRdxpsUjgNgm74SF1Tp4+0fwoIBZ1Xst49MnQawjk+E/LEU+6vZba
         JK0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rPkuEZvM;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=bBlsLrdGHc++jWRdKrICWpb3Hl5Ac3nNg4SX/XTm6W0=;
        b=eVAG559kJthRiioZp2CLMELH6a+bPBOAZPE0nP2IPembA30zgmsGL3WNsRQ+bi9kxC
         GDd1UhI+UEjub5TJkTxLQvASikp/wJehbgWp+K1+LkdAyrpJNPAwrveBCy7bmSkOkR1o
         bR8mDnTth2iT33l/t3JlA0jETsI9CYoGQUYZ8eJ7XqtiMSlckQ7himL3jkMgIWyfTFeK
         VklTbtGck7z4lT7KSspzZFkx8PtMZm+G09UEh4SeqNnnj3kXDw+OZOMjZmczfboGzCwq
         TO5AiYw+xMmsYWJAcuPBbFWHYA5MIgRgGWlbi3deNdZaU/niaBbLvaUJJWYWDsCGIv0V
         vZfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bBlsLrdGHc++jWRdKrICWpb3Hl5Ac3nNg4SX/XTm6W0=;
        b=CZJwHJLUBgaoqEEpUv+eOq1VEp1ysOLE3/FKlxr4vbLsOOZImhE7npQsM8oMVNBgYL
         JmzS9p+ySEjkjWbF97JT0J9a6rfY0cEfj4v/Od64JTVRAzFD4Yalua0sPTm1c/q4PLP3
         Qs3piIMnOT4bv7YDKgn9QFw543Al8orN3yDHDZj21ofbstNumCXqS62SNCrXr1rH1Olj
         aotmhOq4jFgtHOgc/rg04Z2gNkLYMdr/ME0UnBhnz+PSxYR3rOuQzUQyLPIsc5eN8gLs
         Wase09xvdmMtPU/vD2WZuq1XCbyXo5XYwLGd0hJwHljb0CdcWSeg5XjUCOnNIFuo5gXW
         zFTA==
X-Gm-Message-State: AOAM533w2SgGJPIAooCGqnN6n2uv/HYbt5i2vxPuk+SZZNIRNkNGHC5C
	ZwweBEzX28SMl0RNIcBJX5k=
X-Google-Smtp-Source: ABdhPJzL4Vp07o6DC3rQ8HVTulbjSaF6FUoLOSODT53Y70MLeqdZQmJiWHlFkkbdR5BAlCnlutI1hQ==
X-Received: by 2002:ac2:46e1:: with SMTP id q1mr6821871lfo.212.1605805388967;
        Thu, 19 Nov 2020 09:03:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:480e:: with SMTP id v14ls968480lfa.2.gmail; Thu, 19 Nov
 2020 09:03:07 -0800 (PST)
X-Received: by 2002:ac2:4466:: with SMTP id y6mr5909341lfl.304.1605805387512;
        Thu, 19 Nov 2020 09:03:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605805387; cv=none;
        d=google.com; s=arc-20160816;
        b=YUdgJVqAlNu+3UtBgAnzPREpAjQnB6L4GfJIP0AGdVsGI4Sk4e/mGugESfNyeGVoSF
         dc7rrUptjBIFC38tKHBJOqwAUX8xXLG5K8UsHlanAJACRarATFthfyJZcG1d7kOGVE1E
         7z9cqiHRqvcL8PMBqG8PVmnGMRwtedZ3BlcdOcaKtl1OA0EMxeAfJPl6qtGh5xNOg6L7
         /Y/5ThR44BlUUOJb+AbqhfunW13RAEr/PJYNTfdlvBhh3whyZhxzkyWnpQl+Q5I0WB3J
         KFRITA+O77sj3dZg8GB76VIfM4t5vs05ikSgSeRSTDP9tg1BH9EC1Ds1IWQvC05IIlsf
         fjFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=z95GPwS+xvHGOD5r0CNYnBBj+LG8gXugvjHLF5gxxjE=;
        b=JM2DoVM990c/UHoxQN9x83vToeVF3NCdao3xNs0Vlczo5aq0FilZ11HX0tu4eeAP10
         b9lPVbUOOJVbJuKivlJJeOMHXQVWuvPEULVyuX43OIa9UeipkDBOyH7qhOMxyjsLlnU5
         t4xCmwhMLxraPmBN91H20f+pOCaEOyID/LnMflMB0zAoGS3zEZh7WCIyEGZi8ePgHqdH
         n7EV9kF1rlQDE4h0lE3iG4p4bmu3rgJ63vstuBVcqZAh6HiaC8hguAeTJFLzQmwg9MD0
         +POqt/3XS2m0HPzbZnVZ1e/BnOUYE6FgV86+PbjXygbweDmNek41pFRwVu9sO1GLyBHV
         prew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rPkuEZvM;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id x206si11595lfa.8.2020.11.19.09.03.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Nov 2020 09:03:07 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id a65so7406392wme.1
        for <kasan-dev@googlegroups.com>; Thu, 19 Nov 2020 09:03:07 -0800 (PST)
X-Received: by 2002:a1c:2d5:: with SMTP id 204mr5730900wmc.181.1605805386527;
        Thu, 19 Nov 2020 09:03:06 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id c2sm667848wrf.68.2020.11.19.09.03.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Nov 2020 09:03:05 -0800 (PST)
Date: Thu, 19 Nov 2020 18:02:59 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
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
Message-ID: <20201119170259.GA2134472@elver.google.com>
References: <CANpmjNNyZs6NrHPmomC4=9MPEvCy1bFA5R2pRsMhG7=c3LhL_Q@mail.gmail.com>
 <20201112161439.GA2989297@elver.google.com>
 <20201112175406.GF3249@paulmck-ThinkPad-P72>
 <20201113175754.GA6273@paulmck-ThinkPad-P72>
 <20201117105236.GA1964407@elver.google.com>
 <20201117182915.GM1437@paulmck-ThinkPad-P72>
 <20201118225621.GA1770130@elver.google.com>
 <20201118233841.GS1437@paulmck-ThinkPad-P72>
 <20201119125357.GA2084963@elver.google.com>
 <20201119151409.GU1437@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="jRHKVT23PllUwdXP"
Content-Disposition: inline
In-Reply-To: <20201119151409.GU1437@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rPkuEZvM;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as
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


--jRHKVT23PllUwdXP
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Thu, Nov 19, 2020 at 07:14AM -0800, Paul E. McKenney wrote:
> On Thu, Nov 19, 2020 at 01:53:57PM +0100, Marco Elver wrote:
> > On Wed, Nov 18, 2020 at 03:38PM -0800, Paul E. McKenney wrote:
> > > On Wed, Nov 18, 2020 at 11:56:21PM +0100, Marco Elver wrote:
> > > > [...]
> > > > I think I figured out one piece of the puzzle. Bisection keeps pointing
> > > > me at some -rcu merge commit, which kept throwing me off. Nor did it
> > > > help that reproduction is a bit flaky. However, I think there are 2
> > > > independent problems, but the manifestation of 1 problem triggers the
> > > > 2nd problem:
> > > > 
> > > > 1. problem: slowed forward progress (workqueue lockup / RCU stall reports)
> > > > 
> > > > 2. problem: DEADLOCK which causes complete system lockup
> > > > 
> > > > 	| ...
> > > > 	|        CPU0
> > > > 	|        ----
> > > > 	|   lock(rcu_node_0);
> > > > 	|   <Interrupt>
> > > > 	|     lock(rcu_node_0);
> > > > 	| 
> > > > 	|  *** DEADLOCK ***
> > > > 	| 
> > > > 	| 1 lock held by event_benchmark/105:
> > > > 	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: print_other_cpu_stall kernel/rcu/tree_stall.h:493 [inline]
> > > > 	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: check_cpu_stall kernel/rcu/tree_stall.h:652 [inline]
> > > > 	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: rcu_pending kernel/rcu/tree.c:3752 [inline]
> > > > 	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x428/0xd40 kernel/rcu/tree.c:2581
> > > > 	| ...
> > > > 
> > > > Problem 2 can with reasonable confidence (5 trials) be fixed by reverting:
> > > > 
> > > > 	rcu: Don't invoke try_invoke_on_locked_down_task() with irqs disabled
> > > > 
> > > > At which point the system always boots to user space -- albeit with a
> > > > bunch of warnings still (attached). The supposed "good" version doesn't
> > > > end up with all those warnings deterministically, so I couldn't say if
> > > > the warnings are expected due to recent changes or not (Arm64 QEMU
> > > > emulation, 1 CPU, and lots of debugging tools on).
> > > > 
> > > > Does any of that make sense?
> > > 
> > > Marco, it makes all too much sense!  :-/
> > > 
> > > Does the patch below help?
> > > 
> > > 							Thanx, Paul
> > > 
> > > ------------------------------------------------------------------------
> > > 
> > > commit 444ef3bbd0f243b912fdfd51f326704f8ee872bf
> > > Author: Peter Zijlstra <peterz@infradead.org>
> > > Date:   Sat Aug 29 10:22:24 2020 -0700
> > > 
> > >     sched/core: Allow try_invoke_on_locked_down_task() with irqs disabled
> > 
> > My assumption is that this is a replacement for "rcu: Don't invoke
> > try_invoke_on_locked_down_task() with irqs disabled", right?
> 
> Hmmm...  It was actually intended to be in addition.
> 
> > That seems to have the same result (same test setup) as only reverting
> > "rcu: Don't invoke..." does: still results in a bunch of workqueue
> > lockup warnings and RCU stall warnings, but boots to user space. I
> > attached a log. If the warnings are expected (are they?), then it looks
> > fine to me.
> 
> No, they are not at all expected, but might be a different symptom
> of the original problem.  Please see below.
> 
> > (And just in case: with "rcu: Don't invoke..." and "sched/core:
> > Allow..." both applied I still get DEADLOCKs -- but that's probably
> > expected.)
> 
> As noted earlier, it is a surprise.  Could you please send me the
> console output?
 
I've attached the output of a run with both commits applied.

> > Testing all events: OK
> > hrtimer: interrupt took 17120368 ns
> > Running tests again, along with the function tracer
> > Running tests on all trace events:
> > Testing all events: 
> > BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 12s!
> > Showing busy workqueues and worker pools:
> > workqueue events: flags=0x0
> >   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
> >     pending: vmstat_shepherd
> > BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 17s!
> > Showing busy workqueues and worker pools:
> > workqueue events: flags=0x0
> >   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
> >     pending: vmstat_shepherd
> > workqueue events_power_efficient: flags=0x82
> >   pwq 2: cpus=0 flags=0x4 nice=0 active=1/256 refcnt=3
> >     pending: neigh_periodic_work
> > ------------[ cut here ]------------
> > WARNING: CPU: 0 PID: 1 at kernel/rcu/tree_stall.h:758 rcu_check_gp_start_stall kernel/rcu/tree_stall.h:750 [inline]
> > WARNING: CPU: 0 PID: 1 at kernel/rcu/tree_stall.h:758 rcu_check_gp_start_stall.isra.0+0x14c/0x210 kernel/rcu/tree_stall.h:711
> 
> I have different line numbering,

This is still using next-20201110. I'll rerun with latest -next as well.

> but the only warning that I see in this
> function is the one complaining that RCU has been ignoring a request to
> start a grace period for too long.  This usually happens because the RCU
> grace-period kthread (named "rcu_preempt" in your case, but can also be
> named "rcu_sched") is being prevented from running, but can be caused
> by other things as well.
> 
> > Modules linked in:
> > CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.10.0-rc3-next-20201110-00003-g920304642405-dirty #30
> > Hardware name: linux,dummy-virt (DT)
> > pstate: 20000085 (nzCv daIf -PAN -UAO -TCO BTYPE=--)
> > pc : rcu_check_gp_start_stall kernel/rcu/tree_stall.h:750 [inline]
> > pc : rcu_check_gp_start_stall.isra.0+0x14c/0x210 kernel/rcu/tree_stall.h:711
> > lr : __xchg_mb arch/arm64/include/asm/cmpxchg.h:88 [inline]
> > lr : atomic_xchg include/asm-generic/atomic-instrumented.h:615 [inline]
> > lr : rcu_check_gp_start_stall kernel/rcu/tree_stall.h:751 [inline]
> > lr : rcu_check_gp_start_stall.isra.0+0x148/0x210 kernel/rcu/tree_stall.h:711
> 
> Two program counters and four link registers?  Awesome!  ;-)

Ah I'm using syzkaller's symbolizer, which duplicates lines if there was
an inline function (remove all the "[inline]" and it should make sense,
but the "[inline]" tell you the actual line). Obviously for things like
this it's a bit unintuitive. :-)
 
> > sp : ffff800010003d20
> > x29: ffff800010003d20 x28: ffff274ac3a10000 
> > x27: 0000000000000000 x26: ffff274b3dbe72d8 
> > x25: ffffbcb867722000 x24: 0000000000000000 
> > x23: 0000000000000000 x22: ffffbcb8681d1260 
> > x21: ffffbcb86735b000 x20: ffffbcb867404440 
> > x19: ffffbcb867404440 x18: 0000000000000123 
> > x17: ffffbcb865d400f0 x16: 0000000000000002 
> > x15: 0000000000000002 x14: 0000000000000000 
> > x13: 003d090000000000 x12: 00001e8480000000 
> > x11: ffffbcb867958980 x10: ffff800010003cf0 
> > x9 : ffffbcb864f4b7c8 x8 : 0000000000000080 
> > x7 : 0000000000000026 x6 : ffffbcb86774e4c0 
> > x5 : 0000000000000000 x4 : 00000000d4001f4b 
> > x3 : 0000000000000000 x2 : 0000000000000000 
> > x1 : 0000000000000001 x0 : 0000000000000000 
> > Call trace:
> >  rcu_check_gp_start_stall kernel/rcu/tree_stall.h:750 [inline]
> >  rcu_check_gp_start_stall.isra.0+0x14c/0x210 kernel/rcu/tree_stall.h:711
> >  rcu_core+0x168/0x9e0 kernel/rcu/tree.c:2719
> >  rcu_core_si+0x18/0x28 kernel/rcu/tree.c:2737
> 
> The RCU_SOFTIRQ handler is causing this checking to occur, for whatever
> that is worth.
> 
> >  __do_softirq+0x188/0x6b4 kernel/softirq.c:298
> >  do_softirq_own_stack include/linux/interrupt.h:568 [inline]
> >  invoke_softirq kernel/softirq.c:393 [inline]
> >  __irq_exit_rcu kernel/softirq.c:423 [inline]
> >  irq_exit+0x1cc/0x1e0 kernel/softirq.c:447
> >  __handle_domain_irq+0xb4/0x130 kernel/irq/irqdesc.c:690
> >  handle_domain_irq include/linux/irqdesc.h:170 [inline]
> >  gic_handle_irq+0x70/0x108 drivers/irqchip/irq-gic.c:370
> >  el1_irq+0xc0/0x180 arch/arm64/kernel/entry.S:651
> >  arch_local_irq_restore+0x8/0x10 arch/arm64/include/asm/irqflags.h:124
> >  release_probes kernel/tracepoint.c:113 [inline]
> >  tracepoint_remove_func kernel/tracepoint.c:315 [inline]
> >  tracepoint_probe_unregister+0x220/0x378 kernel/tracepoint.c:382
> >  trace_event_reg+0x58/0x150 kernel/trace/trace_events.c:298
> >  __ftrace_event_enable_disable+0x424/0x608 kernel/trace/trace_events.c:412
> >  ftrace_event_enable_disable kernel/trace/trace_events.c:495 [inline]
> >  __ftrace_set_clr_event_nolock+0x120/0x180 kernel/trace/trace_events.c:811
> >  __ftrace_set_clr_event+0x60/0x90 kernel/trace/trace_events.c:833
> >  event_trace_self_tests+0xd4/0x114 kernel/trace/trace_events.c:3661
> >  event_trace_self_test_with_function kernel/trace/trace_events.c:3734 [inline]
> >  event_trace_self_tests_init+0x88/0xa8 kernel/trace/trace_events.c:3747
> >  do_one_initcall+0xa4/0x500 init/main.c:1212
> >  do_initcall_level init/main.c:1285 [inline]
> >  do_initcalls init/main.c:1301 [inline]
> >  do_basic_setup init/main.c:1321 [inline]
> >  kernel_init_freeable+0x344/0x3c4 init/main.c:1521
> >  kernel_init+0x20/0x16c init/main.c:1410
> >  ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:961
> > irq event stamp: 3274113
> > hardirqs last  enabled at (3274112): [<ffffbcb864f8aee4>] rcu_core+0x974/0x9e0 kernel/rcu/tree.c:2716
> > hardirqs last disabled at (3274113): [<ffffbcb866233bf0>] __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:108 [inline]
> > hardirqs last disabled at (3274113): [<ffffbcb866233bf0>] _raw_spin_lock_irqsave+0xb8/0x14c kernel/locking/spinlock.c:159
> > softirqs last  enabled at (3272576): [<ffffbcb864e10b80>] __do_softirq+0x630/0x6b4 kernel/softirq.c:325
> > softirqs last disabled at (3274101): [<ffffbcb864ec6c54>] do_softirq_own_stack include/linux/interrupt.h:568 [inline]
> > softirqs last disabled at (3274101): [<ffffbcb864ec6c54>] invoke_softirq kernel/softirq.c:393 [inline]
> > softirqs last disabled at (3274101): [<ffffbcb864ec6c54>] __irq_exit_rcu kernel/softirq.c:423 [inline]
> > softirqs last disabled at (3274101): [<ffffbcb864ec6c54>] irq_exit+0x1cc/0x1e0 kernel/softirq.c:447
> > ---[ end trace 902768efebf5a607 ]---
> > rcu: rcu_preempt: wait state: RCU_GP_WAIT_GPS(1) ->state: 0x0 delta ->gp_activity 4452 ->gp_req_activity 3848 ->gp_wake_time 3848 ->gp_wake_seq 2696 ->gp_seq 2696 ->gp_seq_needed 2700 ->gp_flags 0x1
> 
> The last thing that RCU's grace-period kthread did was to go to sleep
> waiting for a grace-period request (RCU_GP_WAIT_GPS).
> 
> > rcu: 	rcu_node 0:0 ->gp_seq 2696 ->gp_seq_needed 2700
> > rcu: RCU callbacks invoked since boot: 2583
> > rcu_tasks: RTGS_WAIT_CBS(11) since 567120 g:1 i:0/0 k. 
> > rcu_tasks_rude: RTGS_WAIT_CBS(11) since 567155 g:1 i:0/1 k. 
> > rcu_tasks_trace: RTGS_INIT(0) since 4295464549 g:0 i:0/0 k. N0 h:0/0/0
> > rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
> > 	(detected by 0, t=3752 jiffies, g=2705, q=8)
> > rcu: All QSes seen, last rcu_preempt kthread activity 557 (4295471128-4295470571), jiffies_till_next_fqs=1, root ->qsmask 0x0
> > rcu: rcu_preempt kthread starved for 557 jiffies! g2705 f0x2 RCU_GP_CLEANUP(7) ->state=0x0 ->cpu=0
> 
> And here we see that RCU's grace-period kthread has in fact been starved.
> 
> This kthread is now in RCU_GP_CLEANUP, perhaps because of the wakeup that is
> sent in rcu_check_gp_kthread_starvation().
> 
> My current guess is that this is a consequence of the earlier failures,
> but who knows?
 
I can try bisection again, or reverting some commits that might be
suspicious? But we'd need some selection of suspicious commits.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201119170259.GA2134472%40elver.google.com.

--jRHKVT23PllUwdXP
Content-Type: text/plain; charset=us-ascii
Content-Disposition: attachment; filename=report

Testing all events: OK
Running tests again, along with the function tracer
Running tests on all trace events:
Testing all events: 
hrtimer: interrupt took 10901376 ns
BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 12s!
Showing busy workqueues and worker pools:
workqueue events: flags=0x0
  pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
    pending: vmstat_shepherd
workqueue events_power_efficient: flags=0x82
  pwq 2: cpus=0 flags=0x4 nice=0 active=1/256 refcnt=3
    pending: neigh_periodic_work
BUG: workqueue lockup - pool cpus=0 flags=0x5 nice=0 stuck for 11s!
Showing busy workqueues and worker pools:
workqueue events_power_efficient: flags=0x82
  pwq 2: cpus=0 flags=0x5 nice=0 active=3/256 refcnt=5
    in-flight: 99:check_lifetime
    pending: neigh_periodic_work, do_cache_clean
pool 2: cpus=0 flags=0x5 nice=0 hung=11s workers=2 manager: 61
BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 10s!
Showing busy workqueues and worker pools:
workqueue events: flags=0x0
  pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
    pending: vmstat_shepherd
workqueue events_power_efficient: flags=0x82
  pwq 2: cpus=0 flags=0x4 nice=0 active=1/256 refcnt=3
    in-flight: 107:check_lifetime
pool 2: cpus=0 flags=0x4 nice=0 hung=8s workers=4 idle: 99 106 61
BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 20s!
Showing busy workqueues and worker pools:
workqueue events: flags=0x0
  pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
    pending: vmstat_shepherd
workqueue events_power_efficient: flags=0x82
  pwq 2: cpus=0 flags=0x4 nice=0 active=1/256 refcnt=3
    in-flight: 107:check_lifetime
pool 2: cpus=0 flags=0x4 nice=0 hung=2s workers=4 idle: 99 106 61
rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
	(detected by 0, t=3752 jiffies, g=2501, q=1)
rcu: All QSes seen, last rcu_preempt kthread activity 3472 (4295298049-4295294577), jiffies_till_next_fqs=1, root ->qsmask 0x0
rcu: rcu_preempt kthread starved for 3472 jiffies! g2501 f0x2 RCU_GP_WAIT_FQS(5) ->state=0x402 ->cpu=0
rcu: 	Unless rcu_preempt kthread gets sufficient CPU time, OOM is now expected behavior.
rcu: RCU grace-period kthread stack dump:
task:rcu_preempt     state:I stack:    0 pid:   10 ppid:     2 flags:0x0000042a
Call trace:
 dump_backtrace+0x0/0x240 arch/arm64/kernel/stacktrace.c:100
 show_stack+0x34/0x88 arch/arm64/kernel/stacktrace.c:196
 sched_show_task kernel/sched/core.c:6444 [inline]
 sched_show_task+0x1fc/0x228 kernel/sched/core.c:6419
 rcu_check_gp_kthread_starvation+0xc8/0xe4 kernel/rcu/tree_stall.h:465
 print_other_cpu_stall kernel/rcu/tree_stall.h:532 [inline]
 check_cpu_stall kernel/rcu/tree_stall.h:652 [inline]
 rcu_pending kernel/rcu/tree.c:3752 [inline]
 rcu_sched_clock_irq+0xc2c/0xd40 kernel/rcu/tree.c:2581
 update_process_times+0x6c/0xb8 kernel/time/timer.c:1709
 tick_sched_handle.isra.0+0x58/0x88 kernel/time/tick-sched.c:176
 tick_sched_timer+0x68/0xe0 kernel/time/tick-sched.c:1328
 __run_hrtimer kernel/time/hrtimer.c:1519 [inline]
 __hrtimer_run_queues+0x288/0x730 kernel/time/hrtimer.c:1583
 hrtimer_interrupt+0x114/0x288 kernel/time/hrtimer.c:1645
 timer_handler drivers/clocksource/arm_arch_timer.c:647 [inline]
 arch_timer_handler_virt+0x50/0x70 drivers/clocksource/arm_arch_timer.c:658
 handle_percpu_devid_irq+0x104/0x4c0 kernel/irq/chip.c:930
 generic_handle_irq_desc include/linux/irqdesc.h:152 [inline]
 generic_handle_irq+0x54/0x78 kernel/irq/irqdesc.c:650
 __handle_domain_irq+0xac/0x130 kernel/irq/irqdesc.c:687
 handle_domain_irq include/linux/irqdesc.h:170 [inline]
 gic_handle_irq+0x70/0x108 drivers/irqchip/irq-gic.c:370
 el1_irq+0xc0/0x180 arch/arm64/kernel/entry.S:651
 arch_local_irq_restore arch/arm64/include/asm/irqflags.h:124 [inline]
 rcu_irq_enter_irqson+0x40/0x78 kernel/rcu/tree.c:1078
 trace_preempt_disable_rcuidle include/trace/events/preemptirq.h:51 [inline]
 trace_preempt_off+0x108/0x1f8 kernel/trace/trace_preemptirq.c:130
 preempt_latency_start kernel/sched/core.c:4163 [inline]
 preempt_latency_start kernel/sched/core.c:4156 [inline]
 preempt_schedule_common+0x170/0x1a8 kernel/sched/core.c:4679
 preempt_schedule+0x38/0x40 kernel/sched/core.c:4705
 __raw_spin_unlock_irqrestore include/linux/spinlock_api_smp.h:161 [inline]
 _raw_spin_unlock_irqrestore+0x90/0xa0 kernel/locking/spinlock.c:191
 prepare_to_swait_event+0x84/0xe8 kernel/sched/swait.c:120
 rcu_gp_fqs_loop kernel/rcu/tree.c:1942 [inline]
 rcu_gp_kthread+0x630/0x1bd8 kernel/rcu/tree.c:2115
 kthread+0x13c/0x188 kernel/kthread.c:292
 ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:961

================================
WARNING: inconsistent lock state
5.10.0-rc3-next-20201110-00003-g891a69a3957e #1 Not tainted
--------------------------------
inconsistent {IN-HARDIRQ-W} -> {HARDIRQ-ON-W} usage.
rcu_preempt/10 [HC0[0]:SC0[0]:HE0:SE1] takes:
ffffb80c721e4458 (rcu_node_0){?.-.}-{2:2}, at: print_other_cpu_stall kernel/rcu/tree_stall.h:493 [inline]
ffffb80c721e4458 (rcu_node_0){?.-.}-{2:2}, at: check_cpu_stall kernel/rcu/tree_stall.h:652 [inline]
ffffb80c721e4458 (rcu_node_0){?.-.}-{2:2}, at: rcu_pending kernel/rcu/tree.c:3752 [inline]
ffffb80c721e4458 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x428/0xd40 kernel/rcu/tree.c:2581
{IN-HARDIRQ-W} state was registered at:
  mark_lock kernel/locking/lockdep.c:4374 [inline]
  mark_usage kernel/locking/lockdep.c:4302 [inline]
  __lock_acquire+0xaa8/0x1a50 kernel/locking/lockdep.c:4785
  lock_acquire kernel/locking/lockdep.c:5436 [inline]
  lock_acquire+0x268/0x508 kernel/locking/lockdep.c:5401
  __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:110 [inline]
  _raw_spin_lock_irqsave+0x78/0x14c kernel/locking/spinlock.c:159
  print_other_cpu_stall kernel/rcu/tree_stall.h:493 [inline]
  check_cpu_stall kernel/rcu/tree_stall.h:652 [inline]
  rcu_pending kernel/rcu/tree.c:3752 [inline]
  rcu_sched_clock_irq+0x428/0xd40 kernel/rcu/tree.c:2581
  update_process_times+0x6c/0xb8 kernel/time/timer.c:1709
  tick_sched_handle.isra.0+0x58/0x88 kernel/time/tick-sched.c:176
  tick_sched_timer+0x68/0xe0 kernel/time/tick-sched.c:1328
  __run_hrtimer kernel/time/hrtimer.c:1519 [inline]
  __hrtimer_run_queues+0x288/0x730 kernel/time/hrtimer.c:1583
  hrtimer_interrupt+0x114/0x288 kernel/time/hrtimer.c:1645
  timer_handler drivers/clocksource/arm_arch_timer.c:647 [inline]
  arch_timer_handler_virt+0x50/0x70 drivers/clocksource/arm_arch_timer.c:658
  handle_percpu_devid_irq+0x104/0x4c0 kernel/irq/chip.c:930
  generic_handle_irq_desc include/linux/irqdesc.h:152 [inline]
  generic_handle_irq+0x54/0x78 kernel/irq/irqdesc.c:650
  __handle_domain_irq+0xac/0x130 kernel/irq/irqdesc.c:687
  handle_domain_irq include/linux/irqdesc.h:170 [inline]
  gic_handle_irq+0x70/0x108 drivers/irqchip/irq-gic.c:370
  el1_irq+0xc0/0x180 arch/arm64/kernel/entry.S:651
  arch_local_irq_restore arch/arm64/include/asm/irqflags.h:124 [inline]
  rcu_irq_enter_irqson+0x40/0x78 kernel/rcu/tree.c:1078
  trace_preempt_disable_rcuidle include/trace/events/preemptirq.h:51 [inline]
  trace_preempt_off+0x108/0x1f8 kernel/trace/trace_preemptirq.c:130
  preempt_latency_start kernel/sched/core.c:4163 [inline]
  preempt_latency_start kernel/sched/core.c:4156 [inline]
  preempt_schedule_common+0x170/0x1a8 kernel/sched/core.c:4679
  preempt_schedule+0x38/0x40 kernel/sched/core.c:4705
  __raw_spin_unlock_irqrestore include/linux/spinlock_api_smp.h:161 [inline]
  _raw_spin_unlock_irqrestore+0x90/0xa0 kernel/locking/spinlock.c:191
  prepare_to_swait_event+0x84/0xe8 kernel/sched/swait.c:120
  rcu_gp_fqs_loop kernel/rcu/tree.c:1942 [inline]
  rcu_gp_kthread+0x630/0x1bd8 kernel/rcu/tree.c:2115
  kthread+0x13c/0x188 kernel/kthread.c:292
  ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:961
irq event stamp: 43978
hardirqs last  enabled at (43977): [<ffffb80c6fd89db4>] rcu_irq_enter_irqson+0x64/0x78 kernel/rcu/tree.c:1078
hardirqs last disabled at (43978): [<ffffb80c6fc123c0>] el1_irq+0x80/0x180 arch/arm64/kernel/entry.S:648
softirqs last  enabled at (43682): [<ffffb80c6fc10b80>] __do_softirq+0x630/0x6b4 kernel/softirq.c:325
softirqs last disabled at (43673): [<ffffb80c6fcc61c4>] do_softirq_own_stack include/linux/interrupt.h:568 [inline]
softirqs last disabled at (43673): [<ffffb80c6fcc61c4>] invoke_softirq kernel/softirq.c:393 [inline]
softirqs last disabled at (43673): [<ffffb80c6fcc61c4>] __irq_exit_rcu kernel/softirq.c:423 [inline]
softirqs last disabled at (43673): [<ffffb80c6fcc61c4>] irq_exit+0x1cc/0x1e0 kernel/softirq.c:447

other info that might help us debug this:
 Possible unsafe locking scenario:

       CPU0
       ----
  lock(rcu_node_0);
  <Interrupt>
    lock(rcu_node_0);

 *** DEADLOCK ***

1 lock held by rcu_preempt/10:
 #0: ffffb80c721e4458 (rcu_node_0){?.-.}-{2:2}, at: print_other_cpu_stall kernel/rcu/tree_stall.h:493 [inline]
 #0: ffffb80c721e4458 (rcu_node_0){?.-.}-{2:2}, at: check_cpu_stall kernel/rcu/tree_stall.h:652 [inline]
 #0: ffffb80c721e4458 (rcu_node_0){?.-.}-{2:2}, at: rcu_pending kernel/rcu/tree.c:3752 [inline]
 #0: ffffb80c721e4458 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x428/0xd40 kernel/rcu/tree.c:2581

stack backtrace:
CPU: 0 PID: 10 Comm: rcu_preempt Not tainted 5.10.0-rc3-next-20201110-00003-g891a69a3957e #1
Hardware name: linux,dummy-virt (DT)
Call trace:
 dump_backtrace+0x0/0x240 arch/arm64/kernel/stacktrace.c:100
 show_stack+0x34/0x88 arch/arm64/kernel/stacktrace.c:196
 __dump_stack lib/dump_stack.c:77 [inline]
 dump_stack+0x140/0x1bc lib/dump_stack.c:118
 print_usage_bug kernel/locking/lockdep.c:3739 [inline]
 print_usage_bug+0x2a0/0x2f0 kernel/locking/lockdep.c:3706
 valid_state kernel/locking/lockdep.c:3750 [inline]
 mark_lock_irq kernel/locking/lockdep.c:3953 [inline]
 mark_lock.part.0+0x438/0x4e8 kernel/locking/lockdep.c:4410
 mark_lock kernel/locking/lockdep.c:4008 [inline]
 mark_held_locks+0x54/0x90 kernel/locking/lockdep.c:4011
 __trace_hardirqs_on_caller kernel/locking/lockdep.c:4029 [inline]
 lockdep_hardirqs_on_prepare+0xe0/0x290 kernel/locking/lockdep.c:4097
 trace_hardirqs_on+0x90/0x370 kernel/trace/trace_preemptirq.c:49
 el1_irq+0xdc/0x180 arch/arm64/kernel/entry.S:685
 arch_local_irq_restore arch/arm64/include/asm/irqflags.h:124 [inline]
 rcu_irq_enter_irqson+0x40/0x78 kernel/rcu/tree.c:1078
 trace_preempt_disable_rcuidle include/trace/events/preemptirq.h:51 [inline]
 trace_preempt_off+0x108/0x1f8 kernel/trace/trace_preemptirq.c:130
 preempt_latency_start kernel/sched/core.c:4163 [inline]
 preempt_latency_start kernel/sched/core.c:4156 [inline]
 preempt_schedule_common+0x170/0x1a8 kernel/sched/core.c:4679
 preempt_schedule+0x38/0x40 kernel/sched/core.c:4705
 __raw_spin_unlock_irqrestore include/linux/spinlock_api_smp.h:161 [inline]
 _raw_spin_unlock_irqrestore+0x90/0xa0 kernel/locking/spinlock.c:191
 prepare_to_swait_event+0x84/0xe8 kernel/sched/swait.c:120
 rcu_gp_fqs_loop kernel/rcu/tree.c:1942 [inline]
 rcu_gp_kthread+0x630/0x1bd8 kernel/rcu/tree.c:2115
 kthread+0x13c/0x188 kernel/kthread.c:292
 ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:961
BUG: scheduling while atomic: rcu_preempt/10/0x00000002
INFO: lockdep is turned off.
Modules linked in:
Preemption disabled at:
[<ffffb80c71009bf8>] preempt_schedule+0x38/0x40 kernel/sched/core.c:4705
CPU: 0 PID: 10 Comm: rcu_preempt Not tainted 5.10.0-rc3-next-20201110-00003-g891a69a3957e #1
Hardware name: linux,dummy-virt (DT)
Call trace:
 dump_backtrace+0x0/0x240 arch/arm64/kernel/stacktrace.c:100
 show_stack+0x34/0x88 arch/arm64/kernel/stacktrace.c:196
 __dump_stack lib/dump_stack.c:77 [inline]
 dump_stack+0x140/0x1bc lib/dump_stack.c:118
 __schedule_bug+0xcc/0xe0 kernel/sched/core.c:4261
 schedule_debug kernel/sched/core.c:4288 [inline]
 __schedule+0x888/0x970 kernel/sched/core.c:4416
 preempt_schedule_common+0x4c/0x1a8 kernel/sched/core.c:4680
 preempt_schedule+0x38/0x40 kernel/sched/core.c:4705
 __raw_spin_unlock_irqrestore include/linux/spinlock_api_smp.h:161 [inline]
 _raw_spin_unlock_irqrestore+0x90/0xa0 kernel/locking/spinlock.c:191
 prepare_to_swait_event+0x84/0xe8 kernel/sched/swait.c:120
 rcu_gp_fqs_loop kernel/rcu/tree.c:1942 [inline]
 rcu_gp_kthread+0x630/0x1bd8 kernel/rcu/tree.c:2115
 kthread+0x13c/0x188 kernel/kthread.c:292
 ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:961

--jRHKVT23PllUwdXP--
