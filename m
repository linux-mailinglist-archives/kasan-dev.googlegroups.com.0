Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3OV3H6QKGQEWE7LXPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E11F2B92D2
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Nov 2020 13:54:06 +0100 (CET)
Received: by mail-ej1-x639.google.com with SMTP id f21sf2110226ejf.11
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Nov 2020 04:54:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605790446; cv=pass;
        d=google.com; s=arc-20160816;
        b=rKjwBJT8r3acLOndn9nN3NzfWsvXRhrlRMo24ZE8B9z86mnS/5DR4plcBKvXwYHt59
         o3RuwTyyQXEtpqDZPZp42rynNu+sXUC4xDuhh52sri/esSD8EgrUIJcLoV5Jm55+66xu
         T90cYWQdIZaWlfnviWsFTUkB12adX/fq4osfmQlGpLwu/c3DWXIsI+tMEonchu6vr8IR
         RNKTDKn4iLXwjVzxxCvS3H9zImSyoJ2aWRTOIAVw+u8BFwEXRpoqqIKssCjW/4jX67wI
         xe6teqGL9fPsKbzlHY890Htw2WmueYTtUJ7EdY76nTKEt5C1RPunXtTlr1M62RqBgClY
         HKHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Ak/lkDLHn//viSoszxrR+b5saLHxIkZOKfhiVcOgM18=;
        b=ka/+pTht3Bb5t0L2bIVUu4qJ590/KXk9lXARL1f8/uq5pl2vzOV8woaS1Tjo5D1d9M
         6DCIXHRsPe23h1DivpjTZ76klSC2wdGoet98gNTTy17RkFl8Fx+JrsEhP73urwmSVCQq
         EM6EBpPA9GnT5ccyybudtUknvu+nTurtkHAfejTCjLoW5PqlNXRb5y3fOK/OLCLn5aBc
         np1xbxwpG3Jaqi6pGFtCbs0u2XSQp2JlGsgc0aX51WaZ0sK16QoTjx4+o9v0KCtKjx4G
         ulwdOI0Xp1qId0rob7tYw/RhbmD6XuQX65YcAPD/6clnv8azOAHURj4kewtFYlFoBa6b
         02Gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ot1pMPmx;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Ak/lkDLHn//viSoszxrR+b5saLHxIkZOKfhiVcOgM18=;
        b=CeaLv/wkTQgSHqw3y0vOLgfibBJ1n/fuIODkjy93jycIhIgB5sXD5l8VmQXgkTuB/m
         ExVktZcZ9l6P5+ql5zfE8JqjpD8Q3C0WdL0lVypIUQAOmswbky+eM+/94zJrqrsoiGj1
         L/e3LotTDhIPC/c5VQjfBFjmMR+VCnJq+XU8fZzQUd+FMdPRBeNW7Py04TqNOhOpTjaM
         1ye7KAO8jQV8/WwP6dbZIoqq62ZpM9mP/QcGMMaDPPpjIFsZ98vfQVMK4kGm6Acu7UZu
         I7I2hpqo/BqsXrqoztDoq9EdFB1y6Fy7JwaJU7BMya5lw6F9qvmxCTZDBkCW2mgDzVXT
         AH1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ak/lkDLHn//viSoszxrR+b5saLHxIkZOKfhiVcOgM18=;
        b=tsUoNX2C+tBbuRXfyj7BcGo8OcoahK4waxdh1wdi2oO0DOKy1sqv069B4HVrycc17v
         i31Z1n+AgC4hIdgHSS8GvVwiwKsGUaoE4JIIAMUhwj4RPZcW9Jrd1SafTGnyxgGhrRGg
         d1FUiT6fLiSpYLWWs+SKZ6Fc41vuteFm+Pw0opDgAw5dmDRQ1lO5FoZszJ8CppT4fjtq
         vG4j8jwtg1c7hMqX9bQW2lNyY6I9LS1ocKW0m/1RRYr16sF2GHYOj5kTN43lfKqKECEI
         Miopp/IkBgxaffM2DbpBDp1MgLVBBpLhHDd5nEEy4eSsBI6Umtcy+SE04mLaposUbNUH
         a2IA==
X-Gm-Message-State: AOAM530YWxvRX/zSGv4Hf14qb7Sj6P3WNLUdG16Ef0DIv2VXn0x3g475
	WnVUJOfQ74SlXrQth3tCuSc=
X-Google-Smtp-Source: ABdhPJwO8zMu1CitLRmaX4tWMi3h+EevmZTsFos6QTM+LWH08Ur8yZ9xxukRRmQvAZf79w1RdvxNhQ==
X-Received: by 2002:a50:eb96:: with SMTP id y22mr31292229edr.116.1605790446080;
        Thu, 19 Nov 2020 04:54:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:c04:: with SMTP id co4ls2570617edb.0.gmail; Thu, 19
 Nov 2020 04:54:05 -0800 (PST)
X-Received: by 2002:aa7:c50e:: with SMTP id o14mr30374038edq.80.1605790445005;
        Thu, 19 Nov 2020 04:54:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605790445; cv=none;
        d=google.com; s=arc-20160816;
        b=PelnOMpYpJTyz23LZe/T+qyiVZ6MYTZCAvSVTEuEQ8H6jITW+8mpXG1zPSxGJmFgTi
         aGElkp4x7RmICKxiZbAo6q4zUtWi6D1bC04Xp29l6KRGI9V1JC0bzoIwSQLqix0VLb6z
         X3kEjahQyfgNGUkXq9cH5GV6UcTdvJ+Bv+KwfpZLBRs/syuw34ZKKuSpGJkqXCqlfiEg
         oYVpezdGtemxqIGGLaajnH8WUwDJ7bBlRIx6dOfv+WQvrgppXxxsA342+Id6NYq0EI4m
         4UsU6lsKeVmOnKk+9Ryt0XDZSWM4kLVGrOc4K4pPob/2nGyRFAdvEobKVKfxbtwwUlsW
         nhKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=sJ12RXZ5BrbHa4QRvWDENN8f77BW3hgJOfvxlD6uU/0=;
        b=UsCnwI1x1lcpg+T5fXwg9XBVQpsXYVp+9jse5/jEa00Av547//DFs3ImqCtbnxBWmA
         3MoPN2aGODS0qqmnTLWD9taSauahVrSfekw7FdMEkhJF5lR4FLkRfQQkVA3tmIJApGzV
         w/gQ5AzvhbzSf9FFBZYCzGy6dJmyxjuWYwVWOtaOAjQc/hURX18qWm+0rhgDOmh3xCfy
         r5/25JhDs1mOKjiEKyPOLSovofj1zZfiZRhmkZb2jWXFkTyjp61r5GP6s0TZVPZj09Fv
         B+Q3AD9eY2FBFyTyDSdBc6o/5uvroXdUk3occnNXs2FCPOzLhHA9NJ1Vu+0t+YlBC6EH
         tdZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ot1pMPmx;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id h5si158769ejl.1.2020.11.19.04.54.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Nov 2020 04:54:04 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id l1so6287179wrb.9
        for <kasan-dev@googlegroups.com>; Thu, 19 Nov 2020 04:54:04 -0800 (PST)
X-Received: by 2002:adf:f9c5:: with SMTP id w5mr9658853wrr.69.1605790444553;
        Thu, 19 Nov 2020 04:54:04 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id f23sm9043046wmb.43.2020.11.19.04.54.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Nov 2020 04:54:02 -0800 (PST)
Date: Thu, 19 Nov 2020 13:53:57 +0100
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
Message-ID: <20201119125357.GA2084963@elver.google.com>
References: <20201111202153.GT517454@elver.google.com>
 <20201112001129.GD3249@paulmck-ThinkPad-P72>
 <CANpmjNNyZs6NrHPmomC4=9MPEvCy1bFA5R2pRsMhG7=c3LhL_Q@mail.gmail.com>
 <20201112161439.GA2989297@elver.google.com>
 <20201112175406.GF3249@paulmck-ThinkPad-P72>
 <20201113175754.GA6273@paulmck-ThinkPad-P72>
 <20201117105236.GA1964407@elver.google.com>
 <20201117182915.GM1437@paulmck-ThinkPad-P72>
 <20201118225621.GA1770130@elver.google.com>
 <20201118233841.GS1437@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="T4sUOijqQbZv57TR"
Content-Disposition: inline
In-Reply-To: <20201118233841.GS1437@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ot1pMPmx;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as
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


--T4sUOijqQbZv57TR
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Wed, Nov 18, 2020 at 03:38PM -0800, Paul E. McKenney wrote:
> On Wed, Nov 18, 2020 at 11:56:21PM +0100, Marco Elver wrote:
> > [...]
> > I think I figured out one piece of the puzzle. Bisection keeps pointing
> > me at some -rcu merge commit, which kept throwing me off. Nor did it
> > help that reproduction is a bit flaky. However, I think there are 2
> > independent problems, but the manifestation of 1 problem triggers the
> > 2nd problem:
> > 
> > 1. problem: slowed forward progress (workqueue lockup / RCU stall reports)
> > 
> > 2. problem: DEADLOCK which causes complete system lockup
> > 
> > 	| ...
> > 	|        CPU0
> > 	|        ----
> > 	|   lock(rcu_node_0);
> > 	|   <Interrupt>
> > 	|     lock(rcu_node_0);
> > 	| 
> > 	|  *** DEADLOCK ***
> > 	| 
> > 	| 1 lock held by event_benchmark/105:
> > 	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: print_other_cpu_stall kernel/rcu/tree_stall.h:493 [inline]
> > 	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: check_cpu_stall kernel/rcu/tree_stall.h:652 [inline]
> > 	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: rcu_pending kernel/rcu/tree.c:3752 [inline]
> > 	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x428/0xd40 kernel/rcu/tree.c:2581
> > 	| ...
> > 
> > Problem 2 can with reasonable confidence (5 trials) be fixed by reverting:
> > 
> > 	rcu: Don't invoke try_invoke_on_locked_down_task() with irqs disabled
> > 
> > At which point the system always boots to user space -- albeit with a
> > bunch of warnings still (attached). The supposed "good" version doesn't
> > end up with all those warnings deterministically, so I couldn't say if
> > the warnings are expected due to recent changes or not (Arm64 QEMU
> > emulation, 1 CPU, and lots of debugging tools on).
> > 
> > Does any of that make sense?
> 
> Marco, it makes all too much sense!  :-/
> 
> Does the patch below help?
> 
> 							Thanx, Paul
> 
> ------------------------------------------------------------------------
> 
> commit 444ef3bbd0f243b912fdfd51f326704f8ee872bf
> Author: Peter Zijlstra <peterz@infradead.org>
> Date:   Sat Aug 29 10:22:24 2020 -0700
> 
>     sched/core: Allow try_invoke_on_locked_down_task() with irqs disabled

My assumption is that this is a replacement for "rcu: Don't invoke
try_invoke_on_locked_down_task() with irqs disabled", right?

That seems to have the same result (same test setup) as only reverting
"rcu: Don't invoke..." does: still results in a bunch of workqueue
lockup warnings and RCU stall warnings, but boots to user space. I
attached a log. If the warnings are expected (are they?), then it looks
fine to me.

(And just in case: with "rcu: Don't invoke..." and "sched/core:
Allow..." both applied I still get DEADLOCKs -- but that's probably
expected.)

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201119125357.GA2084963%40elver.google.com.

--T4sUOijqQbZv57TR
Content-Type: text/plain; charset=us-ascii
Content-Disposition: attachment; filename=log

Testing all events: OK
hrtimer: interrupt took 17120368 ns
Running tests again, along with the function tracer
Running tests on all trace events:
Testing all events: 
BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 12s!
Showing busy workqueues and worker pools:
workqueue events: flags=0x0
  pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
    pending: vmstat_shepherd
BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 17s!
Showing busy workqueues and worker pools:
workqueue events: flags=0x0
  pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
    pending: vmstat_shepherd
workqueue events_power_efficient: flags=0x82
  pwq 2: cpus=0 flags=0x4 nice=0 active=1/256 refcnt=3
    pending: neigh_periodic_work
------------[ cut here ]------------
WARNING: CPU: 0 PID: 1 at kernel/rcu/tree_stall.h:758 rcu_check_gp_start_stall kernel/rcu/tree_stall.h:750 [inline]
WARNING: CPU: 0 PID: 1 at kernel/rcu/tree_stall.h:758 rcu_check_gp_start_stall.isra.0+0x14c/0x210 kernel/rcu/tree_stall.h:711
Modules linked in:
CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.10.0-rc3-next-20201110-00003-g920304642405-dirty #30
Hardware name: linux,dummy-virt (DT)
pstate: 20000085 (nzCv daIf -PAN -UAO -TCO BTYPE=--)
pc : rcu_check_gp_start_stall kernel/rcu/tree_stall.h:750 [inline]
pc : rcu_check_gp_start_stall.isra.0+0x14c/0x210 kernel/rcu/tree_stall.h:711
lr : __xchg_mb arch/arm64/include/asm/cmpxchg.h:88 [inline]
lr : atomic_xchg include/asm-generic/atomic-instrumented.h:615 [inline]
lr : rcu_check_gp_start_stall kernel/rcu/tree_stall.h:751 [inline]
lr : rcu_check_gp_start_stall.isra.0+0x148/0x210 kernel/rcu/tree_stall.h:711
sp : ffff800010003d20
x29: ffff800010003d20 x28: ffff274ac3a10000 
x27: 0000000000000000 x26: ffff274b3dbe72d8 
x25: ffffbcb867722000 x24: 0000000000000000 
x23: 0000000000000000 x22: ffffbcb8681d1260 
x21: ffffbcb86735b000 x20: ffffbcb867404440 
x19: ffffbcb867404440 x18: 0000000000000123 
x17: ffffbcb865d400f0 x16: 0000000000000002 
x15: 0000000000000002 x14: 0000000000000000 
x13: 003d090000000000 x12: 00001e8480000000 
x11: ffffbcb867958980 x10: ffff800010003cf0 
x9 : ffffbcb864f4b7c8 x8 : 0000000000000080 
x7 : 0000000000000026 x6 : ffffbcb86774e4c0 
x5 : 0000000000000000 x4 : 00000000d4001f4b 
x3 : 0000000000000000 x2 : 0000000000000000 
x1 : 0000000000000001 x0 : 0000000000000000 
Call trace:
 rcu_check_gp_start_stall kernel/rcu/tree_stall.h:750 [inline]
 rcu_check_gp_start_stall.isra.0+0x14c/0x210 kernel/rcu/tree_stall.h:711
 rcu_core+0x168/0x9e0 kernel/rcu/tree.c:2719
 rcu_core_si+0x18/0x28 kernel/rcu/tree.c:2737
 __do_softirq+0x188/0x6b4 kernel/softirq.c:298
 do_softirq_own_stack include/linux/interrupt.h:568 [inline]
 invoke_softirq kernel/softirq.c:393 [inline]
 __irq_exit_rcu kernel/softirq.c:423 [inline]
 irq_exit+0x1cc/0x1e0 kernel/softirq.c:447
 __handle_domain_irq+0xb4/0x130 kernel/irq/irqdesc.c:690
 handle_domain_irq include/linux/irqdesc.h:170 [inline]
 gic_handle_irq+0x70/0x108 drivers/irqchip/irq-gic.c:370
 el1_irq+0xc0/0x180 arch/arm64/kernel/entry.S:651
 arch_local_irq_restore+0x8/0x10 arch/arm64/include/asm/irqflags.h:124
 release_probes kernel/tracepoint.c:113 [inline]
 tracepoint_remove_func kernel/tracepoint.c:315 [inline]
 tracepoint_probe_unregister+0x220/0x378 kernel/tracepoint.c:382
 trace_event_reg+0x58/0x150 kernel/trace/trace_events.c:298
 __ftrace_event_enable_disable+0x424/0x608 kernel/trace/trace_events.c:412
 ftrace_event_enable_disable kernel/trace/trace_events.c:495 [inline]
 __ftrace_set_clr_event_nolock+0x120/0x180 kernel/trace/trace_events.c:811
 __ftrace_set_clr_event+0x60/0x90 kernel/trace/trace_events.c:833
 event_trace_self_tests+0xd4/0x114 kernel/trace/trace_events.c:3661
 event_trace_self_test_with_function kernel/trace/trace_events.c:3734 [inline]
 event_trace_self_tests_init+0x88/0xa8 kernel/trace/trace_events.c:3747
 do_one_initcall+0xa4/0x500 init/main.c:1212
 do_initcall_level init/main.c:1285 [inline]
 do_initcalls init/main.c:1301 [inline]
 do_basic_setup init/main.c:1321 [inline]
 kernel_init_freeable+0x344/0x3c4 init/main.c:1521
 kernel_init+0x20/0x16c init/main.c:1410
 ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:961
irq event stamp: 3274113
hardirqs last  enabled at (3274112): [<ffffbcb864f8aee4>] rcu_core+0x974/0x9e0 kernel/rcu/tree.c:2716
hardirqs last disabled at (3274113): [<ffffbcb866233bf0>] __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:108 [inline]
hardirqs last disabled at (3274113): [<ffffbcb866233bf0>] _raw_spin_lock_irqsave+0xb8/0x14c kernel/locking/spinlock.c:159
softirqs last  enabled at (3272576): [<ffffbcb864e10b80>] __do_softirq+0x630/0x6b4 kernel/softirq.c:325
softirqs last disabled at (3274101): [<ffffbcb864ec6c54>] do_softirq_own_stack include/linux/interrupt.h:568 [inline]
softirqs last disabled at (3274101): [<ffffbcb864ec6c54>] invoke_softirq kernel/softirq.c:393 [inline]
softirqs last disabled at (3274101): [<ffffbcb864ec6c54>] __irq_exit_rcu kernel/softirq.c:423 [inline]
softirqs last disabled at (3274101): [<ffffbcb864ec6c54>] irq_exit+0x1cc/0x1e0 kernel/softirq.c:447
---[ end trace 902768efebf5a607 ]---
rcu: rcu_preempt: wait state: RCU_GP_WAIT_GPS(1) ->state: 0x0 delta ->gp_activity 4452 ->gp_req_activity 3848 ->gp_wake_time 3848 ->gp_wake_seq 2696 ->gp_seq 2696 ->gp_seq_needed 2700 ->gp_flags 0x1
rcu: 	rcu_node 0:0 ->gp_seq 2696 ->gp_seq_needed 2700
rcu: RCU callbacks invoked since boot: 2583
rcu_tasks: RTGS_WAIT_CBS(11) since 567120 g:1 i:0/0 k. 
rcu_tasks_rude: RTGS_WAIT_CBS(11) since 567155 g:1 i:0/1 k. 
rcu_tasks_trace: RTGS_INIT(0) since 4295464549 g:0 i:0/0 k. N0 h:0/0/0
rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
	(detected by 0, t=3752 jiffies, g=2705, q=8)
rcu: All QSes seen, last rcu_preempt kthread activity 557 (4295471128-4295470571), jiffies_till_next_fqs=1, root ->qsmask 0x0
rcu: rcu_preempt kthread starved for 557 jiffies! g2705 f0x2 RCU_GP_CLEANUP(7) ->state=0x0 ->cpu=0
rcu: 	Unless rcu_preempt kthread gets sufficient CPU time, OOM is now expected behavior.
rcu: RCU grace-period kthread stack dump:
task:rcu_preempt     state:R  running task     stack:    0 pid:   10 ppid:     2 flags:0x00000428
Call trace:
 __switch_to+0x10c/0x200 arch/arm64/kernel/process.c:578
 context_switch kernel/sched/core.c:3772 [inline]
 __schedule+0x2d8/0x980 kernel/sched/core.c:4521
 preempt_schedule_common+0x4c/0x1a8 kernel/sched/core.c:4680
 preempt_schedule+0x38/0x40 kernel/sched/core.c:4705
 __raw_spin_unlock_irq include/linux/spinlock_api_smp.h:169 [inline]
 _raw_spin_unlock_irq+0x84/0x98 kernel/locking/spinlock.c:199
 rcu_gp_cleanup kernel/rcu/tree.c:2015 [inline]
 rcu_gp_kthread+0x1038/0x1bd8 kernel/rcu/tree.c:2119
 kthread+0x13c/0x188 kernel/kthread.c:292
 ret_from_fork+0x10/0x34 arch/arm64/kernel/entry.S:961
OK
Testing ftrace filter: OK
Loading compiled-in X.509 certificates
input: gpio-keys as /devices/platform/gpio-keys/input/input0
ALSA device list:
  No soundcards found.
TAP version 14
1..0
uart-pl011 9000000.pl011: no DMA platform data
EXT4-fs (sda): mounting ext3 file system using the ext4 subsystem
EXT4-fs (sda): mounted filesystem with ordered data mode. Opts: (null)
VFS: Mounted root (ext3 filesystem) readonly on device 8:0.
devtmpfs: mounted
Freeing unused kernel memory: 8832K
Run /sbin/init as init process

--T4sUOijqQbZv57TR--
