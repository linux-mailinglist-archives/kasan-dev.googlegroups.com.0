Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNET3P6QKGQEQLOUF2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id E50312B9B8B
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Nov 2020 20:38:28 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id n20sf1577610ljj.16
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Nov 2020 11:38:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605814708; cv=pass;
        d=google.com; s=arc-20160816;
        b=iOt/RtXaVYCHC4BbdFrjeqLfycn+2HC6CqiHHmGf8Zjw/YZmQd6gfo6xjprOjwcosg
         N9uzJ8Z7iZWjbfb2E4JPz4+p1nCFMhCSosaLGdAkhum2bNq21IbSnJeafhL8uhoDaM1/
         JpWB+DvwUUKp4DmJnAxFNCkgKx0700KzFvh8M5+am/+2/pBm/ECpi+/XRMqZR7x6oloS
         01gUINhAXUOW5+2wkw64wmL4rPqBniYL3l1Na/ZFIfVaSWN2GK+bKqmYt66qzeU2mA+o
         nOT3jrogi2sYaXpiAG7eyb9c4nIeFDgsf5BP8iuka/46Vc17QYTPo3RnE6Mv7qJHQIOU
         l4YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=rT2qYpsDbtxWpiNjOSqSV6SPDEY2Jk5jO0mX+P4qhlU=;
        b=edSmeCHniULPxPp/hDVcP46v/cccP35ScmZZpNK6Kyrf0AYJ2eqdaZgcX6HZRmH5XH
         o9rSV8nmLEc1qCZ9+WQXLL7ni8FAeDkagl7T1zeduw3QZJXgH6VETVC9bKZYa8QfyQXd
         vggaBcqIgiELIEj35vywLV1wZiff+kC2ALOh0gHMKtntE/vner1nDmcuKRxL+2e+zeay
         Zgr3XQY/ea8xdCF2JHAC2+i2VSf4WJtzhYbH6do8/YtyOqqlVJvBb51ZsmkHZgrBUZez
         CEzDE3icpCw/BweRmFXy09R7/5/Me9LyVEyxgepmQcxijpDZG9pV7bZ6Kh4jgykBfhze
         ozAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ofcG2IAd;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=rT2qYpsDbtxWpiNjOSqSV6SPDEY2Jk5jO0mX+P4qhlU=;
        b=QYQcSw/Xv+++W/qAbAS0crqQ9mbMLTAyDojizE5h6wZIra3t0ZfqDZiSfsgy7xd9kI
         IKBC0Xn2pik5AlKLKOOuFilzGUbs74OocDWimCad0AsN5VZOE4KRSCNqtOsddz1rLI3G
         bRUa0958Xc5XpKI9qVNgtLv4/QPVSjK1yr6gSaXPt/Dvteb/VrEfQBYzTKzU5BOdU9K0
         HT9t760U1cE/rHqMP/vzy0zKt8+nOZEvHC3K/1SE9MR0U18JevQTScy28EDDYgTL7c89
         eTIwgholdCupOXsWtxLiW4jkMw+7VXaLc98bWsl+6pvMMon/5VY7lQ791YN/5q78D81G
         zZ3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rT2qYpsDbtxWpiNjOSqSV6SPDEY2Jk5jO0mX+P4qhlU=;
        b=PbykppA8VT+BcKmlva0DNudMa0XVWpIZ6PUCSNgBPcOknpPQeigXEoFBRY151X0+Bt
         SJuB52PEh7p1P9LZTUB6ckmGgy1fw0BLbQdz8FtzqzMbXfZQ0HdR6d2lk/VjUHsboR8T
         A0EHVh+ZQ9q+Y8dcSCSnu271JkSln/cNUr3LIynrQ9AVSLbVOidZDd8QZxcxA9RJYbLc
         XSstFnwcVfsGC4MJKEQ1IUYRzp5/9cDPcpwy5x1w30m04UzQnkzxj3z4nSiKakTi6hbr
         3h5nnvpfy5dHSOv51XWh6butU+qSS7RB6fTPE/9NdmJHnZnyLwUZpLfKy8R/b7mVY3bJ
         tkAA==
X-Gm-Message-State: AOAM533Wxl+SwzlyxAUXjkueDpFznkcI58uKTObfMZ2c13Z7LfrM4VWA
	Pq9lxcpb80O+qJDxSjWAOZM=
X-Google-Smtp-Source: ABdhPJxJVP+gVUf/0zJsURc90oUl7AeUsCb9zzBVkCxXaHBgsuiFML4oRFSXsu76uUVyKUrXbgnyQw==
X-Received: by 2002:ac2:5b88:: with SMTP id o8mr6533070lfn.265.1605814708404;
        Thu, 19 Nov 2020 11:38:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9b9a:: with SMTP id z26ls695035lji.7.gmail; Thu, 19 Nov
 2020 11:38:27 -0800 (PST)
X-Received: by 2002:a2e:9ad0:: with SMTP id p16mr7140306ljj.424.1605814707051;
        Thu, 19 Nov 2020 11:38:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605814707; cv=none;
        d=google.com; s=arc-20160816;
        b=sjcxbXGDrPRvtZXMR4XcIL0FQGF2IYD/q8a34RthvhKX9cBwvQyB+2XnvbGbZvo/OL
         NWDaCgxN+VtOe2kmgNY/nEP5gEUUwKzNq6Zu18rvfE8F3hKMnMO1inToQIXWPzKgLR2M
         uNP9klGQMYm2yXtHxUisyatZOqAMwJ1thxlJgTNl0EZLMsRBdXTlieMddjsVf+BvB0SZ
         nHZ+weDeLBBfKzekgczS4Q90x+V8pTc0c+E7P/5EUL9osU45nT1EQBm17S5GG1YmJMry
         l3E3DEfgRfDYOReUmmGV0fjjowbXw6GrayMPE593kyLfYDcEL+hYue0stKi4LumdoblN
         rxxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=63CVBq/T3f539Pn43bgVAE7mj44tLgbi2uoq3Bi9slE=;
        b=UuFWINOn0hxTwULUXuxDCfrwFCHTVUkS/eQ7TpGWFCN1BO3gmZMGx+QV+aVuUpXNl2
         VS8gWtFcPQAwb7oGAC+vltdhSIWTZ9K7c29fk+c5z2ZsXyjmHQZ0KcblRFerj/2Ykft3
         H7+DCIB7REUCU2vPquwx5EWY5g7ctvrXfCqgw/sGK2qhuTfxFolImbvwVGE/wH0Mhz9r
         JDLmtiOHoWRbG1tH2oX77POHV5MGAoW7Qo3+aPDL3FklXu65uPgaTfGEDBxB58OUltgk
         ymtobFAaXLYvhaW4VQiTI+TLGd8+UxsRnGyJWdCaTM/Z+f/YEJZfzRSkkbHzrqy2WNAU
         vGlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ofcG2IAd;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id v2si10825ljd.5.2020.11.19.11.38.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Nov 2020 11:38:27 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id a3so7777118wmb.5
        for <kasan-dev@googlegroups.com>; Thu, 19 Nov 2020 11:38:26 -0800 (PST)
X-Received: by 2002:a05:600c:14d4:: with SMTP id i20mr6470722wmh.118.1605814706180;
        Thu, 19 Nov 2020 11:38:26 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id e5sm1319054wrs.84.2020.11.19.11.38.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Nov 2020 11:38:24 -0800 (PST)
Date: Thu, 19 Nov 2020 20:38:19 +0100
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
	Lai Jiangshan <jiangshanlai@gmail.com>,
	linux-arm-kernel@lists.infradead.org
Subject: linux-next: stall warnings and deadlock on Arm64 (was: [PATCH]
 kfence: Avoid stalling...)
Message-ID: <20201119193819.GA2601289@elver.google.com>
References: <20201112175406.GF3249@paulmck-ThinkPad-P72>
 <20201113175754.GA6273@paulmck-ThinkPad-P72>
 <20201117105236.GA1964407@elver.google.com>
 <20201117182915.GM1437@paulmck-ThinkPad-P72>
 <20201118225621.GA1770130@elver.google.com>
 <20201118233841.GS1437@paulmck-ThinkPad-P72>
 <20201119125357.GA2084963@elver.google.com>
 <20201119151409.GU1437@paulmck-ThinkPad-P72>
 <20201119170259.GA2134472@elver.google.com>
 <20201119184854.GY1437@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="k+w/mQv8wyuph6w0"
Content-Disposition: inline
In-Reply-To: <20201119184854.GY1437@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ofcG2IAd;       spf=pass
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


--k+w/mQv8wyuph6w0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Thu, Nov 19, 2020 at 10:48AM -0800, Paul E. McKenney wrote:
> On Thu, Nov 19, 2020 at 06:02:59PM +0100, Marco Elver wrote:
> > On Thu, Nov 19, 2020 at 07:14AM -0800, Paul E. McKenney wrote:
> > > On Thu, Nov 19, 2020 at 01:53:57PM +0100, Marco Elver wrote:
> > > > On Wed, Nov 18, 2020 at 03:38PM -0800, Paul E. McKenney wrote:
> > > > > On Wed, Nov 18, 2020 at 11:56:21PM +0100, Marco Elver wrote:
> > > > > > [...]
> > > > > > I think I figured out one piece of the puzzle. Bisection keeps pointing
> > > > > > me at some -rcu merge commit, which kept throwing me off. Nor did it
> > > > > > help that reproduction is a bit flaky. However, I think there are 2
> > > > > > independent problems, but the manifestation of 1 problem triggers the
> > > > > > 2nd problem:
> > > > > > 
> > > > > > 1. problem: slowed forward progress (workqueue lockup / RCU stall reports)
> > > > > > 
> > > > > > 2. problem: DEADLOCK which causes complete system lockup
> > > > > > 
> > > > > > 	| ...
> > > > > > 	|        CPU0
> > > > > > 	|        ----
> > > > > > 	|   lock(rcu_node_0);
> > > > > > 	|   <Interrupt>
> > > > > > 	|     lock(rcu_node_0);
> > > > > > 	| 
> > > > > > 	|  *** DEADLOCK ***
> > > > > > 	| 
> > > > > > 	| 1 lock held by event_benchmark/105:
> > > > > > 	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: print_other_cpu_stall kernel/rcu/tree_stall.h:493 [inline]
> > > > > > 	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: check_cpu_stall kernel/rcu/tree_stall.h:652 [inline]
> > > > > > 	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: rcu_pending kernel/rcu/tree.c:3752 [inline]
> > > > > > 	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x428/0xd40 kernel/rcu/tree.c:2581
> > > > > > 	| ...
> > > > > > 
> > > > > > Problem 2 can with reasonable confidence (5 trials) be fixed by reverting:
> > > > > > 
> > > > > > 	rcu: Don't invoke try_invoke_on_locked_down_task() with irqs disabled
> > > > > > 
> > > > > > At which point the system always boots to user space -- albeit with a
> > > > > > bunch of warnings still (attached). The supposed "good" version doesn't
> > > > > > end up with all those warnings deterministically, so I couldn't say if
> > > > > > the warnings are expected due to recent changes or not (Arm64 QEMU
> > > > > > emulation, 1 CPU, and lots of debugging tools on).
> > > > > > 
> > > > > > Does any of that make sense?
> > > > > 
> > > > > Marco, it makes all too much sense!  :-/
> > > > > 
> > > > > Does the patch below help?
> > > > > 
> > > > > 							Thanx, Paul
> > > > > 
> > > > > ------------------------------------------------------------------------
> > > > > 
> > > > > commit 444ef3bbd0f243b912fdfd51f326704f8ee872bf
> > > > > Author: Peter Zijlstra <peterz@infradead.org>
> > > > > Date:   Sat Aug 29 10:22:24 2020 -0700
> > > > > 
> > > > >     sched/core: Allow try_invoke_on_locked_down_task() with irqs disabled
> > > > 
> > > > My assumption is that this is a replacement for "rcu: Don't invoke
> > > > try_invoke_on_locked_down_task() with irqs disabled", right?
> > > 
> > > Hmmm...  It was actually intended to be in addition.
> > > 
> > > > That seems to have the same result (same test setup) as only reverting
> > > > "rcu: Don't invoke..." does: still results in a bunch of workqueue
> > > > lockup warnings and RCU stall warnings, but boots to user space. I
> > > > attached a log. If the warnings are expected (are they?), then it looks
> > > > fine to me.
> > > 
> > > No, they are not at all expected, but might be a different symptom
> > > of the original problem.  Please see below.
> > > 
> > > > (And just in case: with "rcu: Don't invoke..." and "sched/core:
> > > > Allow..." both applied I still get DEADLOCKs -- but that's probably
> > > > expected.)
> > > 
> > > As noted earlier, it is a surprise.  Could you please send me the
> > > console output?
> >  
> > I've attached the output of a run with both commits applied.
> 
> Got it, thank you!
> 
> > > > Testing all events: OK
> > > > hrtimer: interrupt took 17120368 ns
> > > > Running tests again, along with the function tracer
> > > > Running tests on all trace events:
> > > > Testing all events: 
> > > > BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 12s!
> > > > Showing busy workqueues and worker pools:
> > > > workqueue events: flags=0x0
> > > >   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
> > > >     pending: vmstat_shepherd
> > > > BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 17s!
> > > > Showing busy workqueues and worker pools:
> > > > workqueue events: flags=0x0
> > > >   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
> > > >     pending: vmstat_shepherd
> > > > workqueue events_power_efficient: flags=0x82
> > > >   pwq 2: cpus=0 flags=0x4 nice=0 active=1/256 refcnt=3
> > > >     pending: neigh_periodic_work
> > > > ------------[ cut here ]------------
> > > > WARNING: CPU: 0 PID: 1 at kernel/rcu/tree_stall.h:758 rcu_check_gp_start_stall kernel/rcu/tree_stall.h:750 [inline]
> > > > WARNING: CPU: 0 PID: 1 at kernel/rcu/tree_stall.h:758 rcu_check_gp_start_stall.isra.0+0x14c/0x210 kernel/rcu/tree_stall.h:711
> > > 
> > > I have different line numbering,
> > 
> > This is still using next-20201110. I'll rerun with latest -next as well.
> 
> No problem, as it looks like next-20201105 is a reasonable approximation.
> 
> > > but the only warning that I see in this
> > > function is the one complaining that RCU has been ignoring a request to
> > > start a grace period for too long.  This usually happens because the RCU
> > > grace-period kthread (named "rcu_preempt" in your case, but can also be
> > > named "rcu_sched") is being prevented from running, but can be caused
> > > by other things as well.
> > > 
> > > > Modules linked in:
> > > > CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.10.0-rc3-next-20201110-00003-g920304642405-dirty #30
> > > > Hardware name: linux,dummy-virt (DT)
> > > > pstate: 20000085 (nzCv daIf -PAN -UAO -TCO BTYPE=--)
> > > > pc : rcu_check_gp_start_stall kernel/rcu/tree_stall.h:750 [inline]
> > > > pc : rcu_check_gp_start_stall.isra.0+0x14c/0x210 kernel/rcu/tree_stall.h:711
> > > > lr : __xchg_mb arch/arm64/include/asm/cmpxchg.h:88 [inline]
> > > > lr : atomic_xchg include/asm-generic/atomic-instrumented.h:615 [inline]
> > > > lr : rcu_check_gp_start_stall kernel/rcu/tree_stall.h:751 [inline]
> > > > lr : rcu_check_gp_start_stall.isra.0+0x148/0x210 kernel/rcu/tree_stall.h:711
> > > 
> > > Two program counters and four link registers?  Awesome!  ;-)
> > 
> > Ah I'm using syzkaller's symbolizer, which duplicates lines if there was
> > an inline function (remove all the "[inline]" and it should make sense,
> > but the "[inline]" tell you the actual line). Obviously for things like
> > this it's a bit unintuitive. :-)
> 
> Very useful, though, and a big THANK YOU to those who made it happen!
> 
> > > > sp : ffff800010003d20
> > > > x29: ffff800010003d20 x28: ffff274ac3a10000 
> > > > x27: 0000000000000000 x26: ffff274b3dbe72d8 
> > > > x25: ffffbcb867722000 x24: 0000000000000000 
> > > > x23: 0000000000000000 x22: ffffbcb8681d1260 
> > > > x21: ffffbcb86735b000 x20: ffffbcb867404440 
> > > > x19: ffffbcb867404440 x18: 0000000000000123 
> > > > x17: ffffbcb865d400f0 x16: 0000000000000002 
> > > > x15: 0000000000000002 x14: 0000000000000000 
> > > > x13: 003d090000000000 x12: 00001e8480000000 
> > > > x11: ffffbcb867958980 x10: ffff800010003cf0 
> > > > x9 : ffffbcb864f4b7c8 x8 : 0000000000000080 
> > > > x7 : 0000000000000026 x6 : ffffbcb86774e4c0 
> > > > x5 : 0000000000000000 x4 : 00000000d4001f4b 
> > > > x3 : 0000000000000000 x2 : 0000000000000000 
> > > > x1 : 0000000000000001 x0 : 0000000000000000 
> > > > Call trace:
> > > >  rcu_check_gp_start_stall kernel/rcu/tree_stall.h:750 [inline]
> > > >  rcu_check_gp_start_stall.isra.0+0x14c/0x210 kernel/rcu/tree_stall.h:711
> > > >  rcu_core+0x168/0x9e0 kernel/rcu/tree.c:2719
> > > >  rcu_core_si+0x18/0x28 kernel/rcu/tree.c:2737
> > > 
> > > The RCU_SOFTIRQ handler is causing this checking to occur, for whatever
> > > that is worth.
> > > 
> > > >  __do_softirq+0x188/0x6b4 kernel/softirq.c:298
> > > >  do_softirq_own_stack include/linux/interrupt.h:568 [inline]
> > > >  invoke_softirq kernel/softirq.c:393 [inline]
> > > >  __irq_exit_rcu kernel/softirq.c:423 [inline]
> > > >  irq_exit+0x1cc/0x1e0 kernel/softirq.c:447
> > > >  __handle_domain_irq+0xb4/0x130 kernel/irq/irqdesc.c:690
> > > >  handle_domain_irq include/linux/irqdesc.h:170 [inline]
> > > >  gic_handle_irq+0x70/0x108 drivers/irqchip/irq-gic.c:370
> > > >  el1_irq+0xc0/0x180 arch/arm64/kernel/entry.S:651
> > > >  arch_local_irq_restore+0x8/0x10 arch/arm64/include/asm/irqflags.h:124
> > > >  release_probes kernel/tracepoint.c:113 [inline]
> > > >  tracepoint_remove_func kernel/tracepoint.c:315 [inline]
> > > >  tracepoint_probe_unregister+0x220/0x378 kernel/tracepoint.c:382
> > > >  trace_event_reg+0x58/0x150 kernel/trace/trace_events.c:298
> > > >  __ftrace_event_enable_disable+0x424/0x608 kernel/trace/trace_events.c:412
> > > >  ftrace_event_enable_disable kernel/trace/trace_events.c:495 [inline]
> > > >  __ftrace_set_clr_event_nolock+0x120/0x180 kernel/trace/trace_events.c:811
> > > >  __ftrace_set_clr_event+0x60/0x90 kernel/trace/trace_events.c:833
> > > >  event_trace_self_tests+0xd4/0x114 kernel/trace/trace_events.c:3661
> > > >  event_trace_self_test_with_function kernel/trace/trace_events.c:3734 [inline]
> > > >  event_trace_self_tests_init+0x88/0xa8 kernel/trace/trace_events.c:3747
> > > >  do_one_initcall+0xa4/0x500 init/main.c:1212
> > > >  do_initcall_level init/main.c:1285 [inline]
> > > >  do_initcalls init/main.c:1301 [inline]
> > > >  do_basic_setup init/main.c:1321 [inline]
> > > >  kernel_init_freeable+0x344/0x3c4 init/main.c:1521
> > > >  kernel_init+0x20/0x16c init/main.c:1410
> > > >  ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:961
> > > > irq event stamp: 3274113
> > > > hardirqs last  enabled at (3274112): [<ffffbcb864f8aee4>] rcu_core+0x974/0x9e0 kernel/rcu/tree.c:2716
> > > > hardirqs last disabled at (3274113): [<ffffbcb866233bf0>] __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:108 [inline]
> > > > hardirqs last disabled at (3274113): [<ffffbcb866233bf0>] _raw_spin_lock_irqsave+0xb8/0x14c kernel/locking/spinlock.c:159
> > > > softirqs last  enabled at (3272576): [<ffffbcb864e10b80>] __do_softirq+0x630/0x6b4 kernel/softirq.c:325
> > > > softirqs last disabled at (3274101): [<ffffbcb864ec6c54>] do_softirq_own_stack include/linux/interrupt.h:568 [inline]
> > > > softirqs last disabled at (3274101): [<ffffbcb864ec6c54>] invoke_softirq kernel/softirq.c:393 [inline]
> > > > softirqs last disabled at (3274101): [<ffffbcb864ec6c54>] __irq_exit_rcu kernel/softirq.c:423 [inline]
> > > > softirqs last disabled at (3274101): [<ffffbcb864ec6c54>] irq_exit+0x1cc/0x1e0 kernel/softirq.c:447
> > > > ---[ end trace 902768efebf5a607 ]---
> > > > rcu: rcu_preempt: wait state: RCU_GP_WAIT_GPS(1) ->state: 0x0 delta ->gp_activity 4452 ->gp_req_activity 3848 ->gp_wake_time 3848 ->gp_wake_seq 2696 ->gp_seq 2696 ->gp_seq_needed 2700 ->gp_flags 0x1
> > > 
> > > The last thing that RCU's grace-period kthread did was to go to sleep
> > > waiting for a grace-period request (RCU_GP_WAIT_GPS).
> > > 
> > > > rcu: 	rcu_node 0:0 ->gp_seq 2696 ->gp_seq_needed 2700
> > > > rcu: RCU callbacks invoked since boot: 2583
> > > > rcu_tasks: RTGS_WAIT_CBS(11) since 567120 g:1 i:0/0 k. 
> > > > rcu_tasks_rude: RTGS_WAIT_CBS(11) since 567155 g:1 i:0/1 k. 
> > > > rcu_tasks_trace: RTGS_INIT(0) since 4295464549 g:0 i:0/0 k. N0 h:0/0/0
> > > > rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
> > > > 	(detected by 0, t=3752 jiffies, g=2705, q=8)
> > > > rcu: All QSes seen, last rcu_preempt kthread activity 557 (4295471128-4295470571), jiffies_till_next_fqs=1, root ->qsmask 0x0
> > > > rcu: rcu_preempt kthread starved for 557 jiffies! g2705 f0x2 RCU_GP_CLEANUP(7) ->state=0x0 ->cpu=0
> > > 
> > > And here we see that RCU's grace-period kthread has in fact been starved.
> > > 
> > > This kthread is now in RCU_GP_CLEANUP, perhaps because of the wakeup that is
> > > sent in rcu_check_gp_kthread_starvation().
> > > 
> > > My current guess is that this is a consequence of the earlier failures,
> > > but who knows?
> >  
> > I can try bisection again, or reverting some commits that might be
> > suspicious? But we'd need some selection of suspicious commits.
> 
> The report claims that one of the rcu_node ->lock fields is held
> with interrupts enabled, which would indeed be bad.  Except that all
> of the stack traces that it shows have these locks held within the
> scheduling-clock interrupt handler.  Now with the "rcu: Don't invoke
> try_invoke_on_locked_down_task() with irqs disabled" but without the
> "sched/core: Allow try_invoke_on_locked_down_task() with irqs disabled"
> commit, I understand why.  With both, I don't see how this happens.

I'm at a loss, but happy to keep bisecting and trying patches. I'm also
considering:

	Is it the compiler? Probably not, I tried 2 versions of GCC.

	Can we trust lockdep to precisely know IRQ state? I know there's
	been some recent work around this, but hopefully we're not
	affected here?

	Is QEMU buggy?

> At this point, I am reduced to adding lockdep_assert_irqs_disabled()
> calls at various points in that code, as shown in the patch below.
> 
> At this point, I would guess that your first priority would be the
> initial bug rather than this following issue, but you never know, this
> might well help diagnose the initial bug.

I don't mind either way. I'm worried deadlocking the whole system might
be worse.

> 							Thanx, Paul
> 
> ------------------------------------------------------------------------
> 
> commit ccedf00693ef60f7c06d23490fc41bb60dd43dc3
> Author: Paul E. McKenney <paulmck@kernel.org>
> Date:   Thu Nov 19 10:13:06 2020 -0800
> 
>     rcu: Add lockdep_assert_irqs_disabled() to rcu_sched_clock_irq() and callees

Applied that. See new log attached -- I don't see any of them have
fired.

I also upgraded to next-20201119 -- nothing has changed though, and the
warnings and deadlocks still appear.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201119193819.GA2601289%40elver.google.com.

--k+w/mQv8wyuph6w0
Content-Type: text/plain; charset=us-ascii
Content-Disposition: attachment; filename=log

Testing all events: OK
Running tests again, along with the function tracer
Running tests on all trace events:
Testing all events: 
hrtimer: interrupt took 11213232 ns
BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 11s!
Showing busy workqueues and worker pools:
workqueue events: flags=0x0
  pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
    pending: vmstat_shepherd
BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 13s!
Showing busy workqueues and worker pools:
workqueue events: flags=0x0
  pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
    pending: vmstat_shepherd
BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 10s!
Showing busy workqueues and worker pools:
workqueue events: flags=0x0
  pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
    pending: vmstat_shepherd
workqueue events_power_efficient: flags=0x82
  pwq 2: cpus=0 flags=0x4 nice=0 active=1/256 refcnt=3
    pending: neigh_periodic_work
BUG: workqueue lockup - pool cpus=0 flags=0x4 nice=0 stuck for 11s!
Showing busy workqueues and worker pools:
workqueue events: flags=0x0
  pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
    pending: vmstat_shepherd
workqueue events_power_efficient: flags=0x82
  pwq 2: cpus=0 flags=0x4 nice=0 active=1/256 refcnt=3
    pending: neigh_periodic_work
BUG: workqueue lockup - pool cpus=0 flags=0x4 nice=0 stuck for 21s!
Showing busy workqueues and worker pools:
workqueue events: flags=0x0
  pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
    in-flight: 15:vmstat_shepherd
workqueue events_power_efficient: flags=0x82
  pwq 2: cpus=0 flags=0x4 nice=0 active=1/256 refcnt=3
    pending: neigh_periodic_work
pool 0: cpus=0 node=0 flags=0x0 nice=0 hung=8s workers=2 idle: 5
BUG: workqueue lockup - pool cpus=0 flags=0x4 nice=0 stuck for 34s!
Showing busy workqueues and worker pools:
workqueue events: flags=0x0
  pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
    pending: vmstat_shepherd
workqueue events_power_efficient: flags=0x82
  pwq 2: cpus=0 flags=0x4 nice=0 active=2/256 refcnt=4
    pending: neigh_periodic_work, do_cache_clean
rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
	(detected by 0, t=3752 jiffies, g=2365, q=2)
rcu: All QSes seen, last rcu_preempt kthread activity 2599 (4295010564-4295007965), jiffies_till_next_fqs=1, root ->qsmask 0x0
rcu: rcu_preempt kthread starved for 2599 jiffies! g2365 f0x2 RCU_GP_WAIT_FQS(5) ->state=0x0 ->cpu=0
rcu: 	Unless rcu_preempt kthread gets sufficient CPU time, OOM is now expected behavior.
rcu: RCU grace-period kthread stack dump:
task:rcu_preempt     state:R  running task     stack:    0 pid:   10 ppid:     2 flags:0x00000428
Call trace:
 __switch_to+0x148/0x1f0 arch/arm64/kernel/process.c:577
 context_switch kernel/sched/core.c:4268 [inline]
 __schedule+0x2dc/0x9a8 kernel/sched/core.c:5018
 preempt_schedule_notrace+0x70/0x1c0 kernel/sched/core.c:5251
 __ftrace_ops_list_func kernel/trace/ftrace.c:6955 [inline]
 ftrace_ops_list_func+0x10c/0x218 kernel/trace/ftrace.c:6976
 ftrace_graph_call+0x0/0x4
 preempt_count_add+0x8/0x1a0 arch/arm64/include/asm/atomic.h:65
 schedule+0x44/0x100 kernel/sched/core.c:5096
 schedule_timeout+0x240/0x538 kernel/time/timer.c:1871
 rcu_gp_fqs_loop kernel/rcu/tree.c:1946 [inline]
 rcu_gp_kthread+0x618/0x1bd8 kernel/rcu/tree.c:2119
 kthread+0x13c/0x188 kernel/kthread.c:292
 ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:963
rcu: Stack dump where RCU GP kthread last ran:
Task dump for CPU 0:
task:khungtaskd      state:R  running task     stack:    0 pid:   23 ppid:     2 flags:0x0000042a
Call trace:
 dump_backtrace+0x0/0x240 arch/arm64/kernel/stacktrace.c:100
 show_stack+0x34/0x88 arch/arm64/kernel/stacktrace.c:196
 sched_show_task kernel/sched/core.c:6947 [inline]
 sched_show_task+0x208/0x230 kernel/sched/core.c:6921
 dump_cpu_task+0x4c/0x5c kernel/sched/core.c:8985
 rcu_check_gp_kthread_starvation+0x240/0x388 kernel/rcu/tree_stall.h:482
 print_other_cpu_stall kernel/rcu/tree_stall.h:556 [inline]
 check_cpu_stall kernel/rcu/tree_stall.h:679 [inline]
 rcu_pending kernel/rcu/tree.c:3764 [inline]
 rcu_sched_clock_irq+0x131c/0x1408 kernel/rcu/tree.c:2588
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
 arch_local_irq_enable arch/arm64/include/asm/irqflags.h:37 [inline]
 __raw_spin_unlock_irq include/linux/spinlock_api_smp.h:168 [inline]
 _raw_spin_unlock_irq+0x50/0x98 kernel/locking/spinlock.c:199
 finish_lock_switch kernel/sched/core.c:4046 [inline]
 finish_task_switch+0xb4/0x398 kernel/sched/core.c:4146
 context_switch kernel/sched/core.c:4271 [inline]
 __schedule+0x2e0/0x9a8 kernel/sched/core.c:5018
 preempt_schedule_irq+0x4c/0xa0 kernel/sched/core.c:5280
 arm64_preempt_schedule_irq+0xd0/0x118 arch/arm64/kernel/process.c:725
 el1_irq+0xd8/0x180 arch/arm64/kernel/entry.S:664
 check_hung_uninterruptible_tasks kernel/hung_task.c:231 [inline]
 watchdog+0x5d8/0xbe8 kernel/hung_task.c:338
 kthread+0x13c/0x188 kernel/kthread.c:292
 ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:963

================================
WARNING: inconsistent lock state
5.10.0-rc4-next-20201119-00003-gb88cbc8d31ee #4 Not tainted
--------------------------------
inconsistent {IN-HARDIRQ-W} -> {HARDIRQ-ON-W} usage.
khungtaskd/23 [HC0[0]:SC0[0]:HE0:SE1] takes:
ffffd1f0529f47d8 (rcu_node_0){?.-.}-{2:2}, at: print_other_cpu_stall kernel/rcu/tree_stall.h:516 [inline]
ffffd1f0529f47d8 (rcu_node_0){?.-.}-{2:2}, at: check_cpu_stall kernel/rcu/tree_stall.h:679 [inline]
ffffd1f0529f47d8 (rcu_node_0){?.-.}-{2:2}, at: rcu_pending kernel/rcu/tree.c:3764 [inline]
ffffd1f0529f47d8 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x7c8/0x1408 kernel/rcu/tree.c:2588
{IN-HARDIRQ-W} state was registered at:
  mark_lock kernel/locking/lockdep.c:4373 [inline]
  mark_usage kernel/locking/lockdep.c:4301 [inline]
  __lock_acquire+0xae8/0x1ac8 kernel/locking/lockdep.c:4784
  lock_acquire kernel/locking/lockdep.c:5435 [inline]
  lock_acquire+0x268/0x508 kernel/locking/lockdep.c:5400
  __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:110 [inline]
  _raw_spin_lock_irqsave+0x78/0x14c kernel/locking/spinlock.c:159
  print_other_cpu_stall kernel/rcu/tree_stall.h:516 [inline]
  check_cpu_stall kernel/rcu/tree_stall.h:679 [inline]
  rcu_pending kernel/rcu/tree.c:3764 [inline]
  rcu_sched_clock_irq+0x7c8/0x1408 kernel/rcu/tree.c:2588
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
  arch_local_irq_enable arch/arm64/include/asm/irqflags.h:37 [inline]
  __raw_spin_unlock_irq include/linux/spinlock_api_smp.h:168 [inline]
  _raw_spin_unlock_irq+0x50/0x98 kernel/locking/spinlock.c:199
  finish_lock_switch kernel/sched/core.c:4046 [inline]
  finish_task_switch+0xb4/0x398 kernel/sched/core.c:4146
  context_switch kernel/sched/core.c:4271 [inline]
  __schedule+0x2e0/0x9a8 kernel/sched/core.c:5018
  preempt_schedule_irq+0x4c/0xa0 kernel/sched/core.c:5280
  arm64_preempt_schedule_irq+0xd0/0x118 arch/arm64/kernel/process.c:725
  el1_irq+0xd8/0x180 arch/arm64/kernel/entry.S:664
  check_hung_uninterruptible_tasks kernel/hung_task.c:231 [inline]
  watchdog+0x5d8/0xbe8 kernel/hung_task.c:338
  kthread+0x13c/0x188 kernel/kthread.c:292
  ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:963
irq event stamp: 15198
hardirqs last  enabled at (15197): [<ffffd1f05041241c>] el1_irq+0xdc/0x180 arch/arm64/kernel/entry.S:685
hardirqs last disabled at (15198): [<ffffd1f0504123c0>] el1_irq+0x80/0x180 arch/arm64/kernel/entry.S:648
softirqs last  enabled at (14846): [<ffffd1f050410b80>] __do_softirq+0x630/0x6b4 kernel/softirq.c:325
softirqs last disabled at (14843): [<ffffd1f0504c623c>] do_softirq_own_stack include/linux/interrupt.h:568 [inline]
softirqs last disabled at (14843): [<ffffd1f0504c623c>] invoke_softirq kernel/softirq.c:393 [inline]
softirqs last disabled at (14843): [<ffffd1f0504c623c>] __irq_exit_rcu kernel/softirq.c:423 [inline]
softirqs last disabled at (14843): [<ffffd1f0504c623c>] irq_exit+0x1cc/0x1e0 kernel/softirq.c:447

other info that might help us debug this:
 Possible unsafe locking scenario:

       CPU0
       ----
  lock(rcu_node_0);
  <Interrupt>
    lock(rcu_node_0);

 *** DEADLOCK ***

2 locks held by khungtaskd/23:
 #0: ffffd1f0529f1420 (rcu_read_lock){....}-{1:2}, at: check_hung_uninterruptible_tasks kernel/hung_task.c:226 [inline]
 #0: ffffd1f0529f1420 (rcu_read_lock){....}-{1:2}, at: watchdog+0x15c/0xbe8 kernel/hung_task.c:338
 #1: ffffd1f0529f47d8 (rcu_node_0){?.-.}-{2:2}, at: print_other_cpu_stall kernel/rcu/tree_stall.h:516 [inline]
 #1: ffffd1f0529f47d8 (rcu_node_0){?.-.}-{2:2}, at: check_cpu_stall kernel/rcu/tree_stall.h:679 [inline]
 #1: ffffd1f0529f47d8 (rcu_node_0){?.-.}-{2:2}, at: rcu_pending kernel/rcu/tree.c:3764 [inline]
 #1: ffffd1f0529f47d8 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x7c8/0x1408 kernel/rcu/tree.c:2588

stack backtrace:
CPU: 0 PID: 23 Comm: khungtaskd Not tainted 5.10.0-rc4-next-20201119-00003-gb88cbc8d31ee #4
Hardware name: linux,dummy-virt (DT)
Call trace:
 dump_backtrace+0x0/0x240 arch/arm64/kernel/stacktrace.c:100
 show_stack+0x34/0x88 arch/arm64/kernel/stacktrace.c:196
 __dump_stack lib/dump_stack.c:79 [inline]
 dump_stack+0x140/0x1bc lib/dump_stack.c:120
 print_usage_bug kernel/locking/lockdep.c:3738 [inline]
 print_usage_bug+0x2a0/0x2f0 kernel/locking/lockdep.c:3705
 valid_state kernel/locking/lockdep.c:3749 [inline]
 mark_lock_irq kernel/locking/lockdep.c:3952 [inline]
 mark_lock.part.0+0x438/0x4e8 kernel/locking/lockdep.c:4409
 mark_lock kernel/locking/lockdep.c:4007 [inline]
 mark_held_locks+0x54/0x90 kernel/locking/lockdep.c:4010
 __trace_hardirqs_on_caller kernel/locking/lockdep.c:4028 [inline]
 lockdep_hardirqs_on_prepare+0xe0/0x290 kernel/locking/lockdep.c:4096
 trace_hardirqs_on+0x90/0x370 kernel/trace/trace_preemptirq.c:49
 el1_irq+0xdc/0x180 arch/arm64/kernel/entry.S:685
 arch_local_irq_enable arch/arm64/include/asm/irqflags.h:37 [inline]
 __raw_spin_unlock_irq include/linux/spinlock_api_smp.h:168 [inline]
 _raw_spin_unlock_irq+0x50/0x98 kernel/locking/spinlock.c:199
 finish_lock_switch kernel/sched/core.c:4046 [inline]
 finish_task_switch+0xb4/0x398 kernel/sched/core.c:4146
 context_switch kernel/sched/core.c:4271 [inline]
 __schedule+0x2e0/0x9a8 kernel/sched/core.c:5018
 preempt_schedule_irq+0x4c/0xa0 kernel/sched/core.c:5280
 arm64_preempt_schedule_irq+0xd0/0x118 arch/arm64/kernel/process.c:725
 el1_irq+0xd8/0x180 arch/arm64/kernel/entry.S:664
 check_hung_uninterruptible_tasks kernel/hung_task.c:231 [inline]
 watchdog+0x5d8/0xbe8 kernel/hung_task.c:338
 kthread+0x13c/0x188 kernel/kthread.c:292
 ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:963
BUG: scheduling while atomic: khungtaskd/23/0x00000002
INFO: lockdep is turned off.
Modules linked in:
Preemption disabled at:
[<ffffd1f05181ce7c>] preempt_schedule_irq+0x3c/0xa0 kernel/sched/core.c:5278
CPU: 0 PID: 23 Comm: khungtaskd Not tainted 5.10.0-rc4-next-20201119-00003-gb88cbc8d31ee #4
Hardware name: linux,dummy-virt (DT)
Call trace:
 dump_backtrace+0x0/0x240 arch/arm64/kernel/stacktrace.c:100
 show_stack+0x34/0x88 arch/arm64/kernel/stacktrace.c:196
 __dump_stack lib/dump_stack.c:79 [inline]
 dump_stack+0x140/0x1bc lib/dump_stack.c:120
 __schedule_bug+0xcc/0xe0 kernel/sched/core.c:4757
 schedule_debug kernel/sched/core.c:4784 [inline]
 __schedule+0x888/0x9a8 kernel/sched/core.c:4912
 preempt_schedule_irq+0x4c/0xa0 kernel/sched/core.c:5280
 arm64_preempt_schedule_irq+0xd0/0x118 arch/arm64/kernel/process.c:725
 el1_irq+0xd8/0x180 arch/arm64/kernel/entry.S:664
 check_hung_uninterruptible_tasks kernel/hung_task.c:231 [inline]
 watchdog+0x5d8/0xbe8 kernel/hung_task.c:338
 kthread+0x13c/0x188 kernel/kthread.c:292
 ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:963

--k+w/mQv8wyuph6w0--
