Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7GWZ36QKGQECT3BRSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id E9BB92B5D43
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 11:52:44 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id q17sf1364413wmc.1
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 02:52:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605610364; cv=pass;
        d=google.com; s=arc-20160816;
        b=GCEbUPX9/NqyVw5u9YGqKkyXsW/CWXI2BObeclGD5Vf2/+5NKXqQjtbf89NjWL/vnv
         Hvp+dRDyQ3ciKpqSO3nErvcATwbbe7VhOGhJ7Z8ge8MrdpeY8ExOKxiUCTGKaKw6vCbU
         tcq34pSOZw+VS13QUhaodS97j1ZT6ftdh7oz7GfwB+YUErvSGZbuzzlLT+2VF3OPuNuu
         Uq8/Sn7yQp/JSJCqSpYeSvjQCUZ8nsZPjYpTl5LIngDpbHCUnMn0dWxpzvtizQTnWgLq
         miO5bOo4ObdJ2i6uXxbgC7l7foiicoCw4zWBpKuqAl1b5MtDbOIUPGRlKStBBGFL1LJv
         4jDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ctII/LCaWNTdZZymsLy4kbmmZ7H9k6FGkCAUowpOkVE=;
        b=caLMYe0As6j16aQtnxi6yoh6ji8AvEZb3A79q5nbJNKtwRzH7BFqMbjR3ale+b3yuA
         PpQVYR6m921y3pHW6fg2hG/KUB68AWMNQONXHOMwxdmFXAj9jV35gdlRKDXFd6q2uhfQ
         27gMNZQlK16L/2JsIKXoBmOGPfZ6cBP9BTn8+kyCfe3pyFtF6tgL3wj2v77RVB2A6FJE
         EKYqpOKrMGlgRnSc63ZiXyawIj7zLkoPrjiUr4ZTQCUxqKQmSk1GOSu/eg6uApWPyubN
         XC6vuwCMjE1kwHlKWl7XBUZTzvOj9Hp9naBivOOBYaNjSOPsXFcdN/Mz9eWlU2sepcVz
         tjtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AqYtGjDg;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ctII/LCaWNTdZZymsLy4kbmmZ7H9k6FGkCAUowpOkVE=;
        b=qSjO17YZLfWBuDtx9jKHdFF6KWZAvdpOrtv4Pnv8NYxKsnUkwtbEc1Zq3LjSac/fr6
         d3PEi4Q9viZ2e7zwAywJrE12SRJ9iQ6S0skCwPXQhRRdGsGvVLFqTsRazpg2oMRFZNzB
         NGyZdnzwTlc6TZ3s/pRYzUyWtnxxMmKtmfdhiVjgFysRTqvxMqCy7RRSJONer0/TWwtH
         lv/XwGuidGJQuuQVeH1FAz0MUQmsjaDmHm3kL6nxdxQpP1gjsqT3RSLge7FvjQrAQQWA
         KyTkWYAFymWM34kW/uV/Ux/C3iki6S6Lc7LXkreYofZMCTkmdZ8gNOAIQdnBlPPt4zgM
         S8jA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ctII/LCaWNTdZZymsLy4kbmmZ7H9k6FGkCAUowpOkVE=;
        b=ON5jjqgmm+T4cOK31+tk2vnbzr4Fl1rPuGHfDWDaz5oFP8DpuhH8tzRTVymlDAdgWV
         u5mewlwiyMtEpnWeAwVBtLoisiDYtkd2BudhyM7qNcinbVg/u38sCpEJzwNpYwKP5Nfl
         ts+JvOrpXQQ7abLgkUSuyvRbTUYyCcdlX4FVFaumfcfVGvbMDFJlPyldCkcutY1tfw/R
         96SMPMALByqIhHz5TpmE/DEPcuzuqOBvQ8gArwQQc14Nl+GLEAqKIQfCoibywlj5BkGB
         S40D1ddwUfQm00hEYmEZ+6eD7ID+ZV1SGtbBimqu6aMI0lc96JwaUQiKwF2kKUJo4re4
         1I/w==
X-Gm-Message-State: AOAM533lmPsDiUdKKx0nTj2Y+5MCmOoW6gmPoJHYa2o6NSmfWYfdSEpn
	HO+u9A4tkZVHwr/BVM9VGiY=
X-Google-Smtp-Source: ABdhPJx15KejG82sZdbbWs2oZi0Hh4eQgTHyYvaE7msrQFVAmvMQ4h6cZuMcHFbrosPDTa53NxI6Zg==
X-Received: by 2002:adf:a1c2:: with SMTP id v2mr25394637wrv.95.1605610364672;
        Tue, 17 Nov 2020 02:52:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2348:: with SMTP id j69ls984379wmj.0.gmail; Tue, 17 Nov
 2020 02:52:43 -0800 (PST)
X-Received: by 2002:a1c:7f90:: with SMTP id a138mr3724409wmd.61.1605610363666;
        Tue, 17 Nov 2020 02:52:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605610363; cv=none;
        d=google.com; s=arc-20160816;
        b=vDghsCl06sFjGxbOKSu4MGD+GKJOKxjNLzJMy4REPWlzxL9PplvP1Az7TwsIqzrB+2
         ETiyJqma3SnAD82Vi6hEFavaLCzvMeLajNdThcbDITgfKN6Hz6N6bpAkN0dYoa+pyUvC
         6qKLWLJkxI7rST43aDUdaRm9JiCzctFS+2ENkIWu6oea3GNGMPg9AhApquJSJrdjbG5X
         +b9wk6tLnhrWW3kemAd22Dlgr9GUPBeGh6d5MS5OZZSvwqRJb9UrGY/8srb/czPLvajU
         uHtl6TV03SRdpqm9bnoV1zMMW5Dv4nneHPeZxXYvbIFT0S4to1Flj0UyuuxtxR9y+4Rt
         6o2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=QQROMh+9BnCoDz5knPZBApc3aEl7baqeK6HQ68ZBd3E=;
        b=nx9A0WObWiIkdoZmsorVYUBVbgaEI4nn7t+3v7uVADAz3tBhcW6kW3w55MamVPRnTh
         xQYvMExJucXv8KjokqwAeZKhDmgT2yhAAiGBvdNmSzrhrKi7kuCtxrpD0D949PflcUGE
         UvsBV+D9NpJqB8p+RB6Shdv4Tg/8FpeED/zs5vZzR4HNlpqoL5il+QVnRY6AYOpTrK2r
         vecMIakNHZwv5iD2uOKZnHJ9nat61LckJ/2t45rvp+SubnJgYjPSWYjuN23NRqINlH9d
         nMX/wGgEbjy/ON9ki7uu9ENdReLeRFB9lD8vgliImG/pzsyCfkGSfZbExdBt+fTBzRji
         NY+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AqYtGjDg;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id j199si85025wmj.0.2020.11.17.02.52.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Nov 2020 02:52:43 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id d12so22650743wrr.13
        for <kasan-dev@googlegroups.com>; Tue, 17 Nov 2020 02:52:43 -0800 (PST)
X-Received: by 2002:adf:9d44:: with SMTP id o4mr25847113wre.229.1605610362994;
        Tue, 17 Nov 2020 02:52:42 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id f19sm2895675wml.21.2020.11.17.02.52.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Nov 2020 02:52:42 -0800 (PST)
Date: Tue, 17 Nov 2020 11:52:36 +0100
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
Message-ID: <20201117105236.GA1964407@elver.google.com>
References: <20201111130543.27d29462@gandalf.local.home>
 <20201111182333.GA3249@paulmck-ThinkPad-P72>
 <20201111183430.GN517454@elver.google.com>
 <20201111192123.GB3249@paulmck-ThinkPad-P72>
 <20201111202153.GT517454@elver.google.com>
 <20201112001129.GD3249@paulmck-ThinkPad-P72>
 <CANpmjNNyZs6NrHPmomC4=9MPEvCy1bFA5R2pRsMhG7=c3LhL_Q@mail.gmail.com>
 <20201112161439.GA2989297@elver.google.com>
 <20201112175406.GF3249@paulmck-ThinkPad-P72>
 <20201113175754.GA6273@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201113175754.GA6273@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=AqYtGjDg;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as
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

On Fri, Nov 13, 2020 at 09:57AM -0800, Paul E. McKenney wrote:
> On Thu, Nov 12, 2020 at 09:54:06AM -0800, Paul E. McKenney wrote:
> > On Thu, Nov 12, 2020 at 05:14:39PM +0100, Marco Elver wrote:
> 
> [ . . . ]
> 
> > > | [  334.160218] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 15s!
> > 
> > It might be instructive to cause this code to provoke a backtrace.
> > I suggest adding something like "trigger_single_cpu_backtrace(cpu)"
> > in kernel/workqueue.c's function named wq_watchdog_timer_fn()
> > somewhere within its "if" statement that is preceded with the "did we
> > stall?" comment.  Or just search for "BUG: workqueue lockup - pool"
> > within kernel/workqueue.c.
> 
> And I did get a small but unexpected gift of time, so here is an
> (untested) patch.
> 
> 							Thanx, Paul
> 
> ------------------------------------------------------------------------
> 
> diff --git a/kernel/workqueue.c b/kernel/workqueue.c
> index 437935e..f3d4ff7 100644
> --- a/kernel/workqueue.c
> +++ b/kernel/workqueue.c
> @@ -5792,6 +5792,7 @@ static void wq_watchdog_timer_fn(struct timer_list *unused)
>  			pr_cont_pool_info(pool);
>  			pr_cont(" stuck for %us!\n",
>  				jiffies_to_msecs(jiffies - pool_ts) / 1000);
> +			trigger_single_cpu_backtrace(cpu);
>  		}
>  	}
>  

That didn't quite work, although the system this is running on only has
1 CPU, so dump_stack() should give us the information we want (see
below). Not sure if that helps though.

Thanks,
-- Marco

------ >8 ------

| Testing all events: OK
| Running tests again, along with the function tracer
| Running tests on all trace events:
| Testing all events: 
| hrtimer: interrupt took 10322624 ns
| BUG: workqueue lockup - pool cpus=0 flags=0x4 nice=0 stuck for 19s!
| CPU: 0 PID: 26 Comm: kcompactd0 Not tainted 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #2
| Hardware name: linux,dummy-virt (DT)
| Call trace:
|  dump_backtrace+0x0/0x240 arch/arm64/kernel/stacktrace.c:100
|  show_stack+0x34/0x88 arch/arm64/kernel/stacktrace.c:196
|  __dump_stack lib/dump_stack.c:77 [inline]
|  dump_stack+0x140/0x1bc lib/dump_stack.c:118
|  wq_watchdog_timer_fn+0x338/0x340 kernel/workqueue.c:5796
|  call_timer_fn+0xe8/0x480 kernel/time/timer.c:1410
|  expire_timers kernel/time/timer.c:1455 [inline]
|  __run_timers.part.0+0x2e8/0x470 kernel/time/timer.c:1747
|  __run_timers kernel/time/timer.c:1728 [inline]
|  run_timer_softirq+0x90/0xa8 kernel/time/timer.c:1762
|  __do_softirq+0x188/0x6b4 kernel/softirq.c:298
|  do_softirq_own_stack include/linux/interrupt.h:568 [inline]
|  invoke_softirq kernel/softirq.c:393 [inline]
|  __irq_exit_rcu kernel/softirq.c:423 [inline]
|  irq_exit+0x1cc/0x1e0 kernel/softirq.c:447
|  __handle_domain_irq+0xb4/0x130 kernel/irq/irqdesc.c:690
|  handle_domain_irq include/linux/irqdesc.h:170 [inline]
|  gic_handle_irq+0x70/0x108 drivers/irqchip/irq-gic.c:370
|  el1_irq+0xc0/0x180 arch/arm64/kernel/entry.S:651
|  arch_local_irq_restore arch/arm64/include/asm/irqflags.h:124 [inline]
|  rcu_irq_exit_irqson+0x40/0x78 kernel/rcu/tree.c:832
|  trace_preempt_enable_rcuidle include/trace/events/preemptirq.h:55 [inline]
|  trace_preempt_on+0x144/0x1a0 kernel/trace/trace_preemptirq.c:123
|  preempt_latency_stop kernel/sched/core.c:4197 [inline]
|  preempt_latency_stop kernel/sched/core.c:4194 [inline]
|  preempt_schedule_common+0xf8/0x1a8 kernel/sched/core.c:4682
|  preempt_schedule+0x38/0x40 kernel/sched/core.c:4706
|  __raw_spin_unlock_irqrestore include/linux/spinlock_api_smp.h:161 [inline]
|  _raw_spin_unlock_irqrestore+0x90/0xa0 kernel/locking/spinlock.c:191
|  spin_unlock_irqrestore include/linux/spinlock.h:409 [inline]
|  finish_wait+0x78/0xa0 kernel/sched/wait.c:382
|  kcompactd+0x3a0/0x4b8 mm/compaction.c:2817
|  kthread+0x13c/0x188 kernel/kthread.c:292
|  ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:961
| Showing busy workqueues and worker pools:
| workqueue events: flags=0x0
|   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
|     pending: vmstat_shepherd
| workqueue events_power_efficient: flags=0x82
|   pwq 2: cpus=0 flags=0x4 nice=0 active=3/256 refcnt=5
|     in-flight: 7:check_lifetime
|     pending: do_cache_clean, neigh_periodic_work
| pool 2: cpus=0 flags=0x4 nice=0 hung=19s workers=2 idle: 61
| rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
| 	(detected by 0, t=3752 jiffies, g=2501, q=1)
| rcu: All QSes seen, last rcu_preempt kthread activity 2981 (4295017301-4295014320), jiffies_till_next_fqs=1, root ->qsmask 0x0
| rcu: rcu_preempt kthread starved for 2981 jiffies! g2501 f0x2 RCU_GP_WAIT_FQS(5) ->state=0x0 ->cpu=0
| rcu: 	Unless rcu_preempt kthread gets sufficient CPU time, OOM is now expected behavior.
| rcu: RCU grace-period kthread stack dump:
| task:rcu_preempt     state:R  running task     stack:    0 pid:   10 ppid:     2 flags:0x00000428
| Call trace:
|  __switch_to+0x10c/0x200 arch/arm64/kernel/process.c:578
|  context_switch kernel/sched/core.c:3773 [inline]
|  __schedule+0x2d8/0x980 kernel/sched/core.c:4522
|  preempt_schedule_notrace+0x70/0x1c0 kernel/sched/core.c:4754
|  __ftrace_ops_list_func kernel/trace/ftrace.c:6956 [inline]
|  ftrace_ops_list_func+0x108/0x230 kernel/trace/ftrace.c:6977
|  ftrace_graph_call+0x0/0x4
|  preempt_count_add+0x8/0x1a0 arch/arm64/include/asm/atomic.h:65
|  schedule+0x44/0x100 kernel/sched/core.c:4599
|  schedule_timeout+0x240/0x538 kernel/time/timer.c:1871
|  rcu_gp_fqs_loop kernel/rcu/tree.c:1942 [inline]
|  rcu_gp_kthread+0x618/0x1bd8 kernel/rcu/tree.c:2115
|  kthread+0x13c/0x188 kernel/kthread.c:292
|  ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:961
| 
| ================================
| WARNING: inconsistent lock state
| 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #2 Not tainted
| --------------------------------
| inconsistent {IN-HARDIRQ-W} -> {HARDIRQ-ON-W} usage.
| event_benchmark/105 [HC0[0]:SC0[0]:HE0:SE1] takes:
| ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: print_other_cpu_stall kernel/rcu/tree_stall.h:493 [inline]
| ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: check_cpu_stall kernel/rcu/tree_stall.h:652 [inline]
| ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: rcu_pending kernel/rcu/tree.c:3752 [inline]
| ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x428/0xd40 kernel/rcu/tree.c:2581
| {IN-HARDIRQ-W} state was registered at:
|   mark_lock kernel/locking/lockdep.c:4374 [inline]
|   mark_usage kernel/locking/lockdep.c:4302 [inline]
|   __lock_acquire+0xab8/0x1a50 kernel/locking/lockdep.c:4785
|   lock_acquire kernel/locking/lockdep.c:5436 [inline]
|   lock_acquire+0x268/0x508 kernel/locking/lockdep.c:5401
|   __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:110 [inline]
|   _raw_spin_lock_irqsave+0x78/0x14c kernel/locking/spinlock.c:159
|   print_other_cpu_stall kernel/rcu/tree_stall.h:493 [inline]
|   check_cpu_stall kernel/rcu/tree_stall.h:652 [inline]
|   rcu_pending kernel/rcu/tree.c:3752 [inline]
|   rcu_sched_clock_irq+0x428/0xd40 kernel/rcu/tree.c:2581
|   update_process_times+0x6c/0xb8 kernel/time/timer.c:1709
|   tick_sched_handle.isra.0+0x58/0x88 kernel/time/tick-sched.c:176
|   tick_sched_timer+0x68/0xe0 kernel/time/tick-sched.c:1328
|   __run_hrtimer kernel/time/hrtimer.c:1519 [inline]
|   __hrtimer_run_queues+0x288/0x730 kernel/time/hrtimer.c:1583
|   hrtimer_interrupt+0x114/0x288 kernel/time/hrtimer.c:1645
|   timer_handler drivers/clocksource/arm_arch_timer.c:647 [inline]
|   arch_timer_handler_virt+0x50/0x70 drivers/clocksource/arm_arch_timer.c:658
|   handle_percpu_devid_irq+0x104/0x4c0 kernel/irq/chip.c:930
|   generic_handle_irq_desc include/linux/irqdesc.h:152 [inline]
|   generic_handle_irq+0x54/0x78 kernel/irq/irqdesc.c:650
|   __handle_domain_irq+0xac/0x130 kernel/irq/irqdesc.c:687
|   handle_domain_irq include/linux/irqdesc.h:170 [inline]
|   gic_handle_irq+0x70/0x108 drivers/irqchip/irq-gic.c:370
|   el1_irq+0xc0/0x180 arch/arm64/kernel/entry.S:651
|   arch_local_irq_enable arch/arm64/include/asm/irqflags.h:37 [inline]
|   preempt_schedule_irq+0x44/0xa0 kernel/sched/core.c:4782
|   arm64_preempt_schedule_irq+0xd0/0x118 arch/arm64/kernel/process.c:726
|   el1_irq+0xd8/0x180 arch/arm64/kernel/entry.S:664
|   arch_local_irq_enable arch/arm64/include/asm/irqflags.h:37 [inline]
|   trace_do_benchmark kernel/trace/trace_benchmark.c:56 [inline]
|   benchmark_event_kthread+0x144/0x4b0 kernel/trace/trace_benchmark.c:154
|   kthread+0x13c/0x188 kernel/kthread.c:292
|   ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:961
| irq event stamp: 12978
| hardirqs last  enabled at (12977): [<ffffbb6e0a62ea50>] preempt_schedule_irq+0x40/0xa0 kernel/sched/core.c:4782
| hardirqs last disabled at (12978): [<ffffbb6e092123c0>] el1_irq+0x80/0x180 arch/arm64/kernel/entry.S:648
| softirqs last  enabled at (8540): [<ffffbb6e09210b80>] __do_softirq+0x630/0x6b4 kernel/softirq.c:325
| softirqs last disabled at (8531): [<ffffbb6e092c6c54>] do_softirq_own_stack include/linux/interrupt.h:568 [inline]
| softirqs last disabled at (8531): [<ffffbb6e092c6c54>] invoke_softirq kernel/softirq.c:393 [inline]
| softirqs last disabled at (8531): [<ffffbb6e092c6c54>] __irq_exit_rcu kernel/softirq.c:423 [inline]
| softirqs last disabled at (8531): [<ffffbb6e092c6c54>] irq_exit+0x1cc/0x1e0 kernel/softirq.c:447
| 
| other info that might help us debug this:
|  Possible unsafe locking scenario:
| 
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
| 
| stack backtrace:
| CPU: 0 PID: 105 Comm: event_benchmark Not tainted 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #2
| Hardware name: linux,dummy-virt (DT)
| Call trace:
|  dump_backtrace+0x0/0x240 arch/arm64/kernel/stacktrace.c:100
|  show_stack+0x34/0x88 arch/arm64/kernel/stacktrace.c:196
|  __dump_stack lib/dump_stack.c:77 [inline]
|  dump_stack+0x140/0x1bc lib/dump_stack.c:118
|  print_usage_bug kernel/locking/lockdep.c:3739 [inline]
|  print_usage_bug+0x2a0/0x2f0 kernel/locking/lockdep.c:3706
|  valid_state kernel/locking/lockdep.c:3750 [inline]
|  mark_lock_irq kernel/locking/lockdep.c:3953 [inline]
|  mark_lock.part.0+0x438/0x4e8 kernel/locking/lockdep.c:4410
|  mark_lock kernel/locking/lockdep.c:4008 [inline]
|  mark_held_locks+0x54/0x90 kernel/locking/lockdep.c:4011
|  __trace_hardirqs_on_caller kernel/locking/lockdep.c:4029 [inline]
|  lockdep_hardirqs_on_prepare+0xe0/0x290 kernel/locking/lockdep.c:4097
|  trace_hardirqs_on+0x90/0x370 kernel/trace/trace_preemptirq.c:49
|  el1_irq+0xdc/0x180 arch/arm64/kernel/entry.S:685
|  arch_local_irq_enable arch/arm64/include/asm/irqflags.h:37 [inline]
|  preempt_schedule_irq+0x44/0xa0 kernel/sched/core.c:4782
|  arm64_preempt_schedule_irq+0xd0/0x118 arch/arm64/kernel/process.c:726
|  el1_irq+0xd8/0x180 arch/arm64/kernel/entry.S:664
|  arch_local_irq_enable arch/arm64/include/asm/irqflags.h:37 [inline]
|  trace_do_benchmark kernel/trace/trace_benchmark.c:56 [inline]
|  benchmark_event_kthread+0x144/0x4b0 kernel/trace/trace_benchmark.c:154
|  kthread+0x13c/0x188 kernel/kthread.c:292
|  ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:961
| BUG: scheduling while atomic: event_benchmark/105/0x00000002
| INFO: lockdep is turned off.
| Modules linked in:
| Preemption disabled at:
| [<ffffbb6e0a62ea4c>] preempt_schedule_irq+0x3c/0xa0 kernel/sched/core.c:4781
| CPU: 0 PID: 105 Comm: event_benchmark Not tainted 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #2
| Hardware name: linux,dummy-virt (DT)
| Call trace:
|  dump_backtrace+0x0/0x240 arch/arm64/kernel/stacktrace.c:100
|  show_stack+0x34/0x88 arch/arm64/kernel/stacktrace.c:196
|  __dump_stack lib/dump_stack.c:77 [inline]
|  dump_stack+0x140/0x1bc lib/dump_stack.c:118
|  __schedule_bug+0xcc/0xe0 kernel/sched/core.c:4262
|  schedule_debug kernel/sched/core.c:4289 [inline]
|  __schedule+0x878/0x980 kernel/sched/core.c:4417
|  preempt_schedule_irq+0x4c/0xa0 kernel/sched/core.c:4783
|  arm64_preempt_schedule_irq+0xd0/0x118 arch/arm64/kernel/process.c:726
|  el1_irq+0xd8/0x180 arch/arm64/kernel/entry.S:664
|  arch_local_irq_enable arch/arm64/include/asm/irqflags.h:37 [inline]
|  trace_do_benchmark kernel/trace/trace_benchmark.c:56 [inline]
|  benchmark_event_kthread+0x144/0x4b0 kernel/trace/trace_benchmark.c:154
|  kthread+0x13c/0x188 kernel/kthread.c:292
|  ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:961

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201117105236.GA1964407%40elver.google.com.
