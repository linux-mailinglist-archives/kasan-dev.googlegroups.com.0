Return-Path: <kasan-dev+bncBC7OBJGL2MHBBH6N236QKGQEJ74XLXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id DD2232B87F3
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Nov 2020 23:56:31 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id f15sf891098ljm.20
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Nov 2020 14:56:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605740191; cv=pass;
        d=google.com; s=arc-20160816;
        b=khTv24WWNSSz6hitJblSl48dmR9mX2dZ9uW9dwdFn2wHo09PdomOS7dY4JCo+LIdEs
         SWzPcMXQz09+fQ0hmw6cU0SNk1FTvlxNdwn9zZSXTTxEuboh6RAqLHaFS0dqIgCxQk+B
         ma77KcwJW064A3rxxi/lO8lIY01Gr7a40JMm2MIea3EB/4N9etBC0HZEpjCpizfUKZHT
         usfI5ipwMWnMx0QcAFm8uRFbimS6Uzp8S0VwTg7WODV1JTX5AvX2JqSOFOBttJ7f+gcJ
         uzOxgXymeP+FBRRpMnUPmdNTj2KikGoxG0JwAGRmvuVYAZKoqTqv8OKBEP/rSF0Mt+bg
         wkUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=qi0JQAQKMM9ZClvdyFSgqNFsDZHLAGqtqe0i1m2t8lo=;
        b=ZPoE9QcLznbv8vtJTnLBI8lYPVzKhuuPZUy1Djdg8myebMKd1sW+Ky6aPN7X3rSPy+
         MogiBZQH25bRLVdlJ26odCoeN7iJQfbNGurapZBdLHuW27YAP2o/OLyeg2OXHOC9rn7B
         B4Z/WBY/h/gLnvXTRmUvSLZondKuWan1295r4/FoL2B1xkTkM4eBoQ9fJ7hBo/iy05KC
         weGIqtKG+81ICyB7wS197Zdymj1omKHiuv928Ge0y5TB/MPWJCmp7U6c77pUZwpvH9XE
         mnQ0f1gGyy0C9EM7wWTZYgH3eVOLmuypMPDmTxrjiL0ujX5bZ2KrqcMCRZYA7UY8Pmk7
         7twA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vox9ADdo;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=qi0JQAQKMM9ZClvdyFSgqNFsDZHLAGqtqe0i1m2t8lo=;
        b=QpNLFwrX4kJRqOtfGxphcWKVIz0jUroZVXRiJ6U+aiFLW3rImoNFqd3d07qKZpfe3y
         zMzf+YfUg8NAsQYOsBAVEEfGdwvQCaLccxhgHPoac8TcWJh10CMsoigpURZrjAgnFugP
         ZOnGjrtZXYEuHQ8sZduaIr1ZQ5iM+WNONyajV9AQ2u4eRMj7jHccWcNShKRrO3MPgf+y
         REQG4VCHAbeXfbSyfECznbY6JBUWd63s6F/SBiGPM7YeYgdHT5H2Et7NICOdoQg+BO1s
         do9oWWUQp5bbJAWLpFVuzAqNWgkNiOi1K7vsQab/MqNGDIIWANrJdUSK2d4R2pVZ7//q
         12eA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qi0JQAQKMM9ZClvdyFSgqNFsDZHLAGqtqe0i1m2t8lo=;
        b=kLu48hpw9oSjZUbDCmE9dpyHP49mhC8vx1MQEiXW6eXXESPgAZMh2pJq+yJA+q1rG0
         Fk4jWcXEqEHJUNYdGcjoluvHhzv4dsl+kbbCwCLTGVdJl+pu42Troa2LODBvIcJF3cZ9
         NKrgyDmWHlZ3j+rJXb7Qe5R0TdBZTQyOQL1zD7FF7EzZCDjsR4zr0NW59GOOO80VU43/
         KpLTmkWp288di595tCAQKFpo9K/NT/jTBDrRykGM1COf/MOvxpyuresrv45U5F+oewdV
         omWpR0253oZORt2uUau7QuaDHlTM9vKGiRXPo/DUbcNFkFkm21w7RpyLW3s4e/2guXQz
         kcjw==
X-Gm-Message-State: AOAM53006V1uE2/FKhK8pYiruuk37ykRq8vfiWGglMIoq1LRZ7x1UjQj
	l4GsiuVzGJlqT6qytDbojic=
X-Google-Smtp-Source: ABdhPJwimrBYt9U4R9EMstxiZDJbHfDLoC3Nis3pkRr+aLfdD4f9L9vzyvMWpJ7MyD31sAuH97BvlQ==
X-Received: by 2002:a19:ad06:: with SMTP id t6mr4953500lfc.222.1605740191412;
        Wed, 18 Nov 2020 14:56:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:ccc2:: with SMTP id c185ls600755lfg.3.gmail; Wed, 18 Nov
 2020 14:56:30 -0800 (PST)
X-Received: by 2002:ac2:5e23:: with SMTP id o3mr4455969lfg.159.1605740190184;
        Wed, 18 Nov 2020 14:56:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605740190; cv=none;
        d=google.com; s=arc-20160816;
        b=Yh5Js0KL4JOKVlP418YltNUyw7ERvPQFLCsaWtJWsTAcyw+FiMamfPc/kn+NQ9zMZo
         Oyoa2J4uXFp/BBJ/wCTMxJTT9VIr7b0iyEahJ8iqJZfk37n0tS23cnvVrIY+E92IzOu2
         Z7AwyMu9GBGTQiboop8KY9XKPEGeJXHCNGGNDXLrc0f7btw5MCKVTJ5ZMwaKcYRsMNmj
         xFPFmC8PyQmYixnfNIQ/napb4UKvao1P0Oe4gBD68CXPPFmndbixA25NS5y/WpZg64Cz
         IRGOyYYF87EUspejEZEZOopplp6WSvOuOmkI2ssG16hFPRao6AUOoi7/gKqyKF48uhKl
         qjUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=1seX92mFsrfx7vZyLIxprFubCVzfCSOLsu/hjAP+vTs=;
        b=npmYUETxe5z5KoaUp3s1FFmSskhat7ZDLrg4Yb7WIRH38rMNsMW5sj6+NRDQUgPlKG
         aNqeGG2UNd0+TQKceeo1hDAF/Qibej+6xEI4Ip6AVwT2BAlQPw0HqPET5yjbNO2RCdzr
         Dx1IzH2/gDn7YEHWLPrNzWLL2vR0fyjurJqy0pA6B/kndMSbwzJAeLuRq0T/a0P5QkEs
         gQvbmWxmX2QOKpqGPpCgtncPHd4W15iy1lL9WXeOHxakEbgp+zSdGEdfRhl6zI2++CJt
         QoKRf8em8pMNVAcLY7ycs1MLAxvCh5yQyNmfminkb4HtZ3LUNSlPH2+WJWTetMwr0uIH
         N/KQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vox9ADdo;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id o185si820755lfa.12.2020.11.18.14.56.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Nov 2020 14:56:30 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id a65so4602783wme.1
        for <kasan-dev@googlegroups.com>; Wed, 18 Nov 2020 14:56:30 -0800 (PST)
X-Received: by 2002:a7b:cc84:: with SMTP id p4mr1406309wma.86.1605740189466;
        Wed, 18 Nov 2020 14:56:29 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id p4sm35980145wrm.51.2020.11.18.14.56.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Nov 2020 14:56:27 -0800 (PST)
Date: Wed, 18 Nov 2020 23:56:21 +0100
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
Message-ID: <20201118225621.GA1770130@elver.google.com>
References: <20201111183430.GN517454@elver.google.com>
 <20201111192123.GB3249@paulmck-ThinkPad-P72>
 <20201111202153.GT517454@elver.google.com>
 <20201112001129.GD3249@paulmck-ThinkPad-P72>
 <CANpmjNNyZs6NrHPmomC4=9MPEvCy1bFA5R2pRsMhG7=c3LhL_Q@mail.gmail.com>
 <20201112161439.GA2989297@elver.google.com>
 <20201112175406.GF3249@paulmck-ThinkPad-P72>
 <20201113175754.GA6273@paulmck-ThinkPad-P72>
 <20201117105236.GA1964407@elver.google.com>
 <20201117182915.GM1437@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="0OAP2g/MAC+5xKAE"
Content-Disposition: inline
In-Reply-To: <20201117182915.GM1437@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vox9ADdo;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as
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


--0OAP2g/MAC+5xKAE
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Tue, Nov 17, 2020 at 10:29AM -0800, Paul E. McKenney wrote:
[...] 
> But it would be good to get the kcompactd() people to look at this (not
> immediately seeing who they are in MAINTAINERS).  Perhaps preemption is
> disabled somehow and I am failing to see it.
> 
> Failing that, maybe someone knows of a way to check for overly long
> timeout handlers.

I think I figured out one piece of the puzzle. Bisection keeps pointing
me at some -rcu merge commit, which kept throwing me off. Nor did it
help that reproduction is a bit flaky. However, I think there are 2
independent problems, but the manifestation of 1 problem triggers the
2nd problem:

1. problem: slowed forward progress (workqueue lockup / RCU stall reports)

2. problem: DEADLOCK which causes complete system lockup

	| ...
	|        CPU0
	|        ----
	|   lock(rcu_node_0);
	|   <Interrupt>
	|     lock(rcu_node_0);
	| 
	|  *** DEADLOCK ***
	| 
	| 1 lock held by event_benchmark/105:
	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: print_other_cpu_stall kernel/rcu/tree_stall.h:493 [inline]
	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: check_cpu_stall kernel/rcu/tree_stall.h:652 [inline]
	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: rcu_pending kernel/rcu/tree.c:3752 [inline]
	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x428/0xd40 kernel/rcu/tree.c:2581
	| ...

Problem 2 can with reasonable confidence (5 trials) be fixed by reverting:

	rcu: Don't invoke try_invoke_on_locked_down_task() with irqs disabled

At which point the system always boots to user space -- albeit with a
bunch of warnings still (attached). The supposed "good" version doesn't
end up with all those warnings deterministically, so I couldn't say if
the warnings are expected due to recent changes or not (Arm64 QEMU
emulation, 1 CPU, and lots of debugging tools on).

Does any of that make sense?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201118225621.GA1770130%40elver.google.com.

--0OAP2g/MAC+5xKAE
Content-Type: text/plain; charset=us-ascii
Content-Disposition: attachment; filename=log

Testing all events: OK
Running tests again, along with the function tracer
Running tests on all trace events:
Testing all events: 
hrtimer: interrupt took 10156432 ns
rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
	(detected by 0, t=3752 jiffies, g=2785, q=6)
rcu: All QSes seen, last rcu_preempt kthread activity 3752 (4295396561-4295392809), jiffies_till_next_fqs=1, root ->qsmask 0x0
rcu: rcu_preempt kthread starved for 3752 jiffies! g2785 f0x0 RCU_GP_ONOFF(3) ->state=0x0 ->cpu=0
rcu: 	Unless rcu_preempt kthread gets sufficient CPU time, OOM is now expected behavior.
rcu: RCU grace-period kthread stack dump:
task:rcu_preempt     state:R  running task     stack:    0 pid:   10 ppid:     2 flags:0x00000428
Call trace:
 __switch_to+0x10c/0x200 arch/arm64/kernel/process.c:578
 context_switch kernel/sched/core.c:3773 [inline]
 __schedule+0x2d8/0x980 kernel/sched/core.c:4522
 preempt_schedule_common+0x4c/0x1a8 kernel/sched/core.c:4681
 preempt_schedule+0x38/0x40 kernel/sched/core.c:4706
 __raw_spin_unlock include/linux/spinlock_api_smp.h:152 [inline]
 _raw_spin_unlock+0x94/0xa8 kernel/locking/spinlock.c:183
 rcu_gp_init kernel/rcu/tree.c:1820 [inline]
 rcu_gp_kthread+0x34c/0x1bd8 kernel/rcu/tree.c:2105
 kthread+0x13c/0x188 kernel/kthread.c:292
 ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:961
rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
	(detected by 0, t=3752 jiffies, g=2817, q=6)
rcu: All QSes seen, last rcu_preempt kthread activity 856 (4295412565-4295411709), jiffies_till_next_fqs=1, root ->qsmask 0x0
rcu: rcu_preempt kthread starved for 856 jiffies! g2817 f0x2 RCU_GP_CLEANUP(7) ->state=0x0 ->cpu=0
rcu: 	Unless rcu_preempt kthread gets sufficient CPU time, OOM is now expected behavior.
rcu: RCU grace-period kthread stack dump:
task:rcu_preempt     state:R  running task     stack:    0 pid:   10 ppid:     2 flags:0x00000428
Call trace:
 __switch_to+0x10c/0x200 arch/arm64/kernel/process.c:578
 context_switch kernel/sched/core.c:3773 [inline]
 __schedule+0x2d8/0x980 kernel/sched/core.c:4522
 preempt_schedule_common+0x4c/0x1a8 kernel/sched/core.c:4681
 preempt_schedule+0x38/0x40 kernel/sched/core.c:4706
 __raw_spin_unlock_irq include/linux/spinlock_api_smp.h:169 [inline]
 _raw_spin_unlock_irq+0x84/0x98 kernel/locking/spinlock.c:199
 rcu_gp_cleanup kernel/rcu/tree.c:2015 [inline]
 rcu_gp_kthread+0x1038/0x1bd8 kernel/rcu/tree.c:2119
 kthread+0x13c/0x188 kernel/kthread.c:292
 ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:961
BUG: workqueue lockup - pool cpus=0 flags=0x4 nice=0 stuck for 16s!
Showing busy workqueues and worker pools:
workqueue events: flags=0x0
  pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
    pending: vmstat_shepherd
workqueue events_power_efficient: flags=0x82
  pwq 2: cpus=0 flags=0x4 nice=0 active=2/256 refcnt=4
    pending: neigh_periodic_work, do_cache_clean
workqueue rcu_gp: flags=0x8
  pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
    in-flight: 15:srcu_invoke_callbacks
pool 0: cpus=0 node=0 flags=0x0 nice=0 hung=0s workers=3 idle: 111 5
rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
	(detected by 0, t=3752 jiffies, g=2829, q=6)
rcu: All QSes seen, last rcu_preempt kthread activity 1522 (4295422970-4295421448), jiffies_till_next_fqs=1, root ->qsmask 0x0
rcu: rcu_preempt kthread starved for 1522 jiffies! g2829 f0x2 RCU_GP_CLEANUP(7) ->state=0x0 ->cpu=0
rcu: 	Unless rcu_preempt kthread gets sufficient CPU time, OOM is now expected behavior.
rcu: RCU grace-period kthread stack dump:
task:rcu_preempt     state:R  running task     stack:    0 pid:   10 ppid:     2 flags:0x00000428
Call trace:
 dump_backtrace+0x0/0x240 arch/arm64/kernel/stacktrace.c:100
 show_stack+0x34/0x88 arch/arm64/kernel/stacktrace.c:196
 sched_show_task kernel/sched/core.c:6445 [inline]
 sched_show_task+0x1fc/0x228 kernel/sched/core.c:6420
 rcu_check_gp_kthread_starvation+0xc8/0xe4 kernel/rcu/tree_stall.h:452
 print_other_cpu_stall kernel/rcu/tree_stall.h:520 [inline]
 check_cpu_stall kernel/rcu/tree_stall.h:640 [inline]
 rcu_pending kernel/rcu/tree.c:3752 [inline]
 rcu_sched_clock_irq+0xb34/0xc48 kernel/rcu/tree.c:2581
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
 finish_lock_switch kernel/sched/core.c:3513 [inline]
 finish_task_switch+0xa8/0x290 kernel/sched/core.c:3613
 context_switch kernel/sched/core.c:3776 [inline]
 __schedule+0x2dc/0x980 kernel/sched/core.c:4522
 preempt_schedule_common+0x4c/0x1a8 kernel/sched/core.c:4681
 preempt_schedule+0x38/0x40 kernel/sched/core.c:4706
 __raw_spin_unlock_irq include/linux/spinlock_api_smp.h:169 [inline]
 _raw_spin_unlock_irq+0x84/0x98 kernel/locking/spinlock.c:199
 rcu_gp_cleanup kernel/rcu/tree.c:2046 [inline]
 rcu_gp_kthread+0x1144/0x1bd8 kernel/rcu/tree.c:2119
 kthread+0x13c/0x188 kernel/kthread.c:292
 ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:961
rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
	(detected by 0, t=3752 jiffies, g=2845, q=6)
rcu: All QSes seen, last rcu_preempt kthread activity 2796 (4295435367-4295432571), jiffies_till_next_fqs=1, root ->qsmask 0x0
rcu: rcu_preempt kthread starved for 2796 jiffies! g2845 f0x2 RCU_GP_WAIT_FQS(5) ->state=0x0 ->cpu=0
rcu: 	Unless rcu_preempt kthread gets sufficient CPU time, OOM is now expected behavior.
rcu: RCU grace-period kthread stack dump:
task:rcu_preempt     state:R  running task     stack:    0 pid:   10 ppid:     2 flags:0x0000042a
Call trace:
 dump_backtrace+0x0/0x240 arch/arm64/kernel/stacktrace.c:100
 show_stack+0x34/0x88 arch/arm64/kernel/stacktrace.c:196
 sched_show_task kernel/sched/core.c:6445 [inline]
 sched_show_task+0x1fc/0x228 kernel/sched/core.c:6420
 rcu_check_gp_kthread_starvation+0xc8/0xe4 kernel/rcu/tree_stall.h:452
 print_other_cpu_stall kernel/rcu/tree_stall.h:520 [inline]
 check_cpu_stall kernel/rcu/tree_stall.h:640 [inline]
 rcu_pending kernel/rcu/tree.c:3752 [inline]
 rcu_sched_clock_irq+0xb34/0xc48 kernel/rcu/tree.c:2581
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
 preempt_latency_start kernel/sched/core.c:4164 [inline]
 preempt_latency_start kernel/sched/core.c:4157 [inline]
 preempt_schedule_notrace+0x170/0x1c0 kernel/sched/core.c:4747
 __ftrace_ops_list_func kernel/trace/ftrace.c:6956 [inline]
 ftrace_ops_list_func+0x108/0x230 kernel/trace/ftrace.c:6977
 ftrace_graph_call+0x0/0x4
 preempt_count_add+0x8/0x1a0 arch/arm64/include/asm/atomic.h:65
 schedule+0x44/0x100 kernel/sched/core.c:4599
 schedule_timeout+0x240/0x538 kernel/time/timer.c:1871
 rcu_gp_fqs_loop kernel/rcu/tree.c:1942 [inline]
 rcu_gp_kthread+0x618/0x1bd8 kernel/rcu/tree.c:2115
 kthread+0x13c/0x188 kernel/kthread.c:292
 ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:961
OK

--0OAP2g/MAC+5xKAE--
