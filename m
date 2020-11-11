Return-Path: <kasan-dev+bncBAABBJWYWD6QKGQEWD6GTVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 064622AF7D8
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 19:23:36 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id g19sf1202888oib.6
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 10:23:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605119015; cv=pass;
        d=google.com; s=arc-20160816;
        b=axgZukScO+ostE/pNquuwz5+5mCKWyi+Awm22Fs5jirBo+nXVAEfqIWjOmI9xkDD0x
         vqaM7fW7JXx+GTeA3x2BoDJiyQzz+sxbWHC1tHn4Fk8hprOwVBjPPEogCdI5OUpXCHT3
         83n1jiHost+ID6STx/DGLR3VTITXt8DlsAWrfwYvpRi6PfzsxQjagCWIDDi1YmKXaUWr
         Fiz62XAE2IbgdO9al10oLpX3s5F49IrjbVR0gngz0wlcCDfQGtQ7VsMfWAcfcWtHLq9e
         mlPo/8+YehXgavrRBR5uiM90BOuYg8W5nq/L/oz+tkWJFMb/Rz0PU9osftV/NT4MNS7u
         aInw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=zFxflPALzmTklL+dZdXOdh+KwXjewL0VP3vPEQZVoOU=;
        b=wKhNlzkcg9WEgpg0lwr4jEjo9hB/oQqSTCe99ANdalcBvDMrriatXjE4OvUCR2QI9N
         wI7hW+QkFrCaypVD98/9QGM8/Zjw9S7VWpcXGW5UX08m9Km46eZCGpOL7fabaq63vgCM
         iP259ZKbpLTaBatGVHX+AxkcPxfCNNlzSZtlONVLl7zdqr/qQBCNTFs5OvbuGSfg5MXt
         YJqLKah1po1Lo5hNo/ChidJKUcizSnqijt/Xl90m7NIV6neRhEgkqV7VBXmsixh5PVS6
         3ffJK7E85E0nG15a3a+U9XJNrYYg+vs0cEDobES+ZjPIroozPHSmnClNJUE6pwAxwcvX
         4qOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=hMelV46A;
       spf=pass (google.com: domain of srs0=nwwe=er=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=nwWE=ER=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zFxflPALzmTklL+dZdXOdh+KwXjewL0VP3vPEQZVoOU=;
        b=Y2vj1OWWmE0uKvnwYmqsLn370Zxc1FjdTCBODskYPzfRMB8rTogqaD7tff5rnmwzZ5
         ArJFKHyRffbK9kclK4K30kf4lma6v3dCsxVLsfpThuFGmf//Qr2P8DfzL3yfUwFjo1Z2
         BjKTzz3fi5ujXQE0WC13VDwiWUf9BAg45n0b0mLhhMOAMEy+HjkaeVJO7tziVVSlxjbp
         VMxjfohhSZavsbfZ2UP3OPzwgXMot5RXGqJLzDfU9FUVqs1R9tShFGSwaDqPH0QsPhWd
         TuWiuCFmjTuDPPgsPHxPfZDEBfZCmfIz7szhbBI641JaxS/txZq/+gprbYCLm853RIae
         BgJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zFxflPALzmTklL+dZdXOdh+KwXjewL0VP3vPEQZVoOU=;
        b=loA0QZZOh0d3FKLY46uLlpuanZueWSrGwRPHeul+9O9MMOXK4ticaDfiCMihbnVXEX
         GCeL1rKNPhCGs21qwWjPzL0WEA6fOpfrOFSPCGCuY4sWdawYJneEZHWIY+Y9X6REr3Ko
         7WSvNtP4s1QKR1UUtbOVdNfB9qd8SF7FnL3/zeXreOrhFVBnSvPjk9ZAD6cSQ1lPtP3x
         rd1+TnB2kcb2IxQeLen4En0wJmMw466fKAURKW15n6VoXkUph+gk8Rq/PwzRb7Fj0ivU
         MHmCkTJZ6g7MiTE2upYVOhm2kzuqgLMVshgtVtfHzpuo5XDJZRJ9LjprECh5ojma4Rdu
         +NTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530tbCmU7Fsa3OXQCFD/KB4efqtS7rnQd8t6fcGjgWMbIRrvVn2W
	QHZLhQpqbwSV0R5LMwi/p9A=
X-Google-Smtp-Source: ABdhPJx3jfg+pNLKMawOqv9+JgQcLtJTom72GFWP1vSFs3G/RdTjIXbUGhhrvBY+7hw2vWcGl0p9Cg==
X-Received: by 2002:aca:3542:: with SMTP id c63mr2983849oia.61.1605119014923;
        Wed, 11 Nov 2020 10:23:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5214:: with SMTP id g20ls77687oib.9.gmail; Wed, 11 Nov
 2020 10:23:34 -0800 (PST)
X-Received: by 2002:aca:3605:: with SMTP id d5mr3083309oia.45.1605119014558;
        Wed, 11 Nov 2020 10:23:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605119014; cv=none;
        d=google.com; s=arc-20160816;
        b=lmqkU7UxzFwZlH+DE050xzvchMZJT0fP0HWVfHAY2/1xg53qhaVenLOz9Ug5UpbF+p
         0fm6Lyu3j09yXX6OdCBozrfUmRiaDWPM6bJC6PaFZ+VG0UZtzwfI5Se15/SWq9Wj6hQ9
         DXZJslaNMfUPPkfx0dgcPA7VgHsVU8hF/8OgUdr0Cx3FEzu0aPNiulq3d1YW7SQDH8WB
         4xx+mLj+Oml5ktvInIaR249/Z/vNDbnJAqLDlBdS9UJ8JjrBvQ42A79Eh2kJUXQD6uGN
         JKFmTDYlqciN47zRXTcS354RKAZSWtCGM0I9j3uBUyZeQzRJkQ8xSld44jGDj5YDGapH
         HgGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=goD5QNas3mbKkKcN6CtqHHWT46Q5LsEvGryqFHG1Xh0=;
        b=LeIaqa9vo4ziThdbFJW82vjXuWbDgMO7S/oR0084I74+z2UuhuoENxZTwdBKicS5sT
         kvdbdtKHixdZ5HRh6S+HkIiYpPtOrpsuatTI12dlfJ59LeVSBCQ5SXKdH9Bgg51dE9wI
         LUk9iV5HrzNKRkUwieHUgqEol96/V0CDRFomnIXGjXvSLjJCfvR03Z4x2TZmfUaheWhf
         DINQiCJUV+z45NTHZXLwdkk6n08wfrjXs8UftKne+men3hfK67ksVTayF8mQFJVbHQyI
         picObeXCFRvy2yCIMsRD4I2ZrppaE1vpzznP68z8kFRTy15SMc8zgjWJ8ABncNfCTpkm
         f3CA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=hMelV46A;
       spf=pass (google.com: domain of srs0=nwwe=er=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=nwWE=ER=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e206si257384oob.2.2020.11.11.10.23.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Nov 2020 10:23:34 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=nwwe=er=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 91F3E2076E;
	Wed, 11 Nov 2020 18:23:33 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 2AF3E35225D6; Wed, 11 Nov 2020 10:23:33 -0800 (PST)
Date: Wed, 11 Nov 2020 10:23:33 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Marco Elver <elver@google.com>,
	Anders Roxell <anders.roxell@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org,
	peterz@infradead.org
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without
 allocations
Message-ID: <20201111182333.GA3249@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201110135320.3309507-1-elver@google.com>
 <CADYN=9+=-ApMi_eEdAeHU6TyuQ7ZJSTQ8F-FCSD33kZH8HR+xg@mail.gmail.com>
 <CANpmjNM8MZphvkTSo=KgCBXQ6fNY4qo6NZD5SBHjNse_L9i5FQ@mail.gmail.com>
 <20201111133813.GA81547@elver.google.com>
 <20201111130543.27d29462@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201111130543.27d29462@gandalf.local.home>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=hMelV46A;       spf=pass
 (google.com: domain of srs0=nwwe=er=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=nwWE=ER=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Nov 11, 2020 at 01:05:43PM -0500, Steven Rostedt wrote:
> On Wed, 11 Nov 2020 14:38:13 +0100
> Marco Elver <elver@google.com> wrote:
> 
> > [+Cc folks who can maybe help figure out what's going on, since I get
> >   warnings even without KFENCE on next-20201110.]
> > 
> > On Wed, Nov 11, 2020 at 09:29AM +0100, Marco Elver wrote:
> > > On Wed, 11 Nov 2020 at 00:23, Anders Roxell <anders.roxell@linaro.org> wrote:
> > > [...]
> > > > I gave them a spin on next-20201105 [1] and on next-20201110 [2].
> > > >
> > > > I eventually got to a prompt on next-20201105.
> > > > However, I got to this kernel panic on the next-20201110:
> > > >
> > > > [...]
> > > > [ 1514.089966][    T1] Testing event system initcall: OK
> > > > [ 1514.806232][    T1] Running tests on all trace events:
> > > > [ 1514.857835][    T1] Testing all events:
> > > > [ 1525.503262][    C0] hrtimer: interrupt took 10902600 ns
> > > > [ 1623.861452][    C0] BUG: workqueue lockup - pool cpus=0 node=0
> > > > flags=0x0 nice=0 stuck for 65s!
> > > > [...]
> 
> OK, so this blows up when you enable all events?
> 
> Note, it could just be adding overhead (which is exasperated with other
> debug options enabled), which could open up a race window.
>  
> 
> > > > [ 7823.104349][   T28]       Tainted: G        W
> > > > 5.10.0-rc3-next-20201110-00008-g8dc06700529d #3
> > > > [ 7833.206491][   T28] "echo 0 >
> > > > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
> > > > [ 7840.750700][   T28] task:kworker/0:1     state:D stack:26640 pid:
> > > > 1872 ppid:     2 flags:0x00000428
> > > > [ 7875.642531][   T28] Workqueue: events toggle_allocation_gate
> > > > [ 7889.178334][   T28] Call trace:
> > > > [ 7897.066649][   T28]  __switch_to+0x1cc/0x1e0
> > > > [ 7905.326856][   T28]  0xffff00000f7077b0
> > > > [ 7928.354644][   T28] INFO: lockdep is turned off.
> > > > [ 7934.022572][   T28] Kernel panic - not syncing: hung_task: blocked tasks
> > > > [ 7934.032039][   T28] CPU: 0 PID: 28 Comm: khungtaskd Tainted: G
> > > >   W         5.10.0-rc3-next-20201110-00008-g8dc06700529d #3
> > > > [ 7934.045586][   T28] Hardware name: linux,dummy-virt (DT)
> > > > [ 7934.053677][   T28] Call trace:
> > > > [ 7934.060276][   T28]  dump_backtrace+0x0/0x420
> > > > [ 7934.067635][   T28]  show_stack+0x38/0xa0
> > > > [ 7934.091277][   T28]  dump_stack+0x1d4/0x278
> > > > [ 7934.098878][   T28]  panic+0x304/0x5d8
> > > > [ 7934.114923][   T28]  check_hung_uninterruptible_tasks+0x5e4/0x640
> > > > [ 7934.123823][   T28]  watchdog+0x138/0x160
> > > > [ 7934.131561][   T28]  kthread+0x23c/0x260
> > > > [ 7934.138590][   T28]  ret_from_fork+0x10/0x18
> > > > [ 7934.146631][   T28] Kernel Offset: disabled
> > > > [ 7934.153749][   T28] CPU features: 0x0240002,20002004
> > > > [ 7934.161476][   T28] Memory Limit: none
> > > > [ 7934.171272][   T28] ---[ end Kernel panic - not syncing: hung_task:
> > > > blocked tasks ]---
> > > >
> > > > Cheers,
> > > > Anders
> > > > [1] https://people.linaro.org/~anders.roxell/output-next-20201105-test.log
> > > > [2] https://people.linaro.org/~anders.roxell/output-next-20201110-test.log
> > > 
> > > Thanks for testing. The fact that it passes on next-20201105 but not
> > > on 20201110 is strange. If you boot with KFENCE disabled (boot param
> > > kfence.sample_interval=0), does it boot?
> > [...]
> > 
> > Right, so I think this is no longer KFENCE's fault. This looks like
> > something scheduler/RCU/ftrace related?! I notice that there have been
> > scheduler changes between next-20201105 and next-20201110.
> 
> I'm not sure any of that would cause this.
> 
> > 
> > I get this with KFENCE disabled:
> > 
> > | Running tests on all trace events:
> > | Testing all events: 
> > | BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 32s!
> > | Showing busy workqueues and worker pools:
> > | workqueue events: flags=0x0
> > |   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
> > |     pending: vmstat_shepherd
> > | workqueue events_power_efficient: flags=0x82
> > |   pwq 2: cpus=0 flags=0x5 nice=0 active=2/256 refcnt=4
> > |     in-flight: 107:neigh_periodic_work
> > |     pending: do_cache_clean
> > | pool 2: cpus=0 flags=0x5 nice=0 hung=3s workers=2 manager: 7
> > | rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
> > | 	(detected by 0, t=6502 jiffies, g=2885, q=4)
> > | rcu: All QSes seen, last rcu_preempt kthread activity 5174 (4295523265-4295518091), jiffies_till_next_fqs=1, root ->qsmask 0x0
> > | rcu: rcu_preempt kthread starved for 5174 jiffies! g2885 f0x2 RCU_GP_WAIT_FQS(5) ->state=0x0 ->cpu=0
> > | rcu: 	Unless rcu_preempt kthread gets sufficient CPU time, OOM is now expected behavior.
> > | rcu: RCU grace-period kthread stack dump:
> > | task:rcu_preempt     state:R  running task     stack:    0 pid:   10 ppid:     2 flags:0x00000428
> > | Call trace:
> > |  __switch_to+0x100/0x1e0
> > |  __schedule+0x2d0/0x890
> > |  preempt_schedule_notrace+0x70/0x1c0
> > |  ftrace_ops_no_ops+0x174/0x250
> > |  ftrace_graph_call+0x0/0xc
> 
> Note, just because ftrace is called here, the blocked task was preempted
> when the ftrace code called preempt_enable_notrace().
> 
> 
> > |  preempt_count_add+0x1c/0x180
> > |  schedule+0x44/0x108
> > |  schedule_timeout+0x394/0x530
> > |  rcu_gp_kthread+0x76c/0x19a8
> > |  kthread+0x174/0x188
> > |  ret_from_fork+0x10/0x18
> > | 
> > | ================================
> > | WARNING: inconsistent lock state
> > | 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #18 Not tainted
> > | --------------------------------
> > | inconsistent {IN-HARDIRQ-W} -> {HARDIRQ-ON-W} usage.
> > | kcompactd0/26 [HC0[0]:SC0[0]:HE0:SE1] takes:
> > | ffffae32e6bd4358 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x4a0/0xd18
> > | {IN-HARDIRQ-W} state was registered at:
> 
> I did some digging here and it looks like the rcu_node lock could be taken
> without interrupts enabled when it does a stall print. That probably should
> be fixed, but it's a symptom of the underlining bug and not the cause.

Does this patch (in -next) help?

							Thanx, Paul

------------------------------------------------------------------------

commit c583bcb8f5edd48c1798798e341f78afb9bf4f6f
Author: Paul E. McKenney <paulmck@kernel.org>
Date:   Thu Sep 24 15:11:55 2020 -0700

    rcu: Don't invoke try_invoke_on_locked_down_task() with irqs disabled
    
    The try_invoke_on_locked_down_task() function requires that
    interrupts be enabled, but it is called with interrupts disabled from
    rcu_print_task_stall(), resulting in an "IRQs not enabled as expected"
    diagnostic.  This commit therefore updates rcu_print_task_stall()
    to accumulate a list of the first few tasks while holding the current
    leaf rcu_node structure's ->lock, then releases that lock and only then
    uses try_invoke_on_locked_down_task() to attempt to obtain per-task
    detailed information.  Of course, as soon as ->lock is released, the
    task might exit, so the get_task_struct() function is used to prevent
    the task structure from going away in the meantime.
    
    Link: https://lore.kernel.org/lkml/000000000000903d5805ab908fc4@google.com/
    Fixes: 5bef8da66a9c ("rcu: Add per-task state to RCU CPU stall warnings")
    Reported-by: syzbot+cb3b69ae80afd6535b0e@syzkaller.appspotmail.com
    Reported-by: syzbot+f04854e1c5c9e913cc27@syzkaller.appspotmail.com
    Tested-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
    Signed-off-by: Paul E. McKenney <paulmck@kernel.org>

diff --git a/kernel/rcu/tree_stall.h b/kernel/rcu/tree_stall.h
index 0fde39b..ca21d28 100644
--- a/kernel/rcu/tree_stall.h
+++ b/kernel/rcu/tree_stall.h
@@ -249,13 +249,16 @@ static bool check_slow_task(struct task_struct *t, void *arg)
 
 /*
  * Scan the current list of tasks blocked within RCU read-side critical
- * sections, printing out the tid of each.
+ * sections, printing out the tid of each of the first few of them.
  */
-static int rcu_print_task_stall(struct rcu_node *rnp)
+static int rcu_print_task_stall(struct rcu_node *rnp, unsigned long flags)
+	__releases(rnp->lock)
 {
+	int i = 0;
 	int ndetected = 0;
 	struct rcu_stall_chk_rdr rscr;
 	struct task_struct *t;
+	struct task_struct *ts[8];
 
 	if (!rcu_preempt_blocked_readers_cgp(rnp))
 		return 0;
@@ -264,6 +267,14 @@ static int rcu_print_task_stall(struct rcu_node *rnp)
 	t = list_entry(rnp->gp_tasks->prev,
 		       struct task_struct, rcu_node_entry);
 	list_for_each_entry_continue(t, &rnp->blkd_tasks, rcu_node_entry) {
+		get_task_struct(t);
+		ts[i++] = t;
+		if (i >= ARRAY_SIZE(ts))
+			break;
+	}
+	raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
+	for (i--; i; i--) {
+		t = ts[i];
 		if (!try_invoke_on_locked_down_task(t, check_slow_task, &rscr))
 			pr_cont(" P%d", t->pid);
 		else
@@ -273,6 +284,7 @@ static int rcu_print_task_stall(struct rcu_node *rnp)
 				".q"[rscr.rs.b.need_qs],
 				".e"[rscr.rs.b.exp_hint],
 				".l"[rscr.on_blkd_list]);
+		put_task_struct(t);
 		ndetected++;
 	}
 	pr_cont("\n");
@@ -293,8 +305,9 @@ static void rcu_print_detail_task_stall_rnp(struct rcu_node *rnp)
  * Because preemptible RCU does not exist, we never have to check for
  * tasks blocked within RCU read-side critical sections.
  */
-static int rcu_print_task_stall(struct rcu_node *rnp)
+static int rcu_print_task_stall(struct rcu_node *rnp, unsigned long flags)
 {
+	raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
 	return 0;
 }
 #endif /* #else #ifdef CONFIG_PREEMPT_RCU */
@@ -472,7 +485,6 @@ static void print_other_cpu_stall(unsigned long gp_seq, unsigned long gps)
 	pr_err("INFO: %s detected stalls on CPUs/tasks:\n", rcu_state.name);
 	rcu_for_each_leaf_node(rnp) {
 		raw_spin_lock_irqsave_rcu_node(rnp, flags);
-		ndetected += rcu_print_task_stall(rnp);
 		if (rnp->qsmask != 0) {
 			for_each_leaf_node_possible_cpu(rnp, cpu)
 				if (rnp->qsmask & leaf_node_cpu_bit(rnp, cpu)) {
@@ -480,7 +492,7 @@ static void print_other_cpu_stall(unsigned long gp_seq, unsigned long gps)
 					ndetected++;
 				}
 		}
-		raw_spin_unlock_irqrestore_rcu_node(rnp, flags);
+		ndetected += rcu_print_task_stall(rnp, flags); // Releases rnp->lock.
 	}
 
 	for_each_possible_cpu(cpu)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111182333.GA3249%40paulmck-ThinkPad-P72.
