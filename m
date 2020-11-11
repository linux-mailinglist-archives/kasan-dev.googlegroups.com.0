Return-Path: <kasan-dev+bncBCU73AEHRQBBB7GPWD6QKGQEOTPDIEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 22E4A2AF7AE
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 19:05:50 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id w123sf1166636oie.20
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 10:05:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605117949; cv=pass;
        d=google.com; s=arc-20160816;
        b=kP2aOryupc+rvEMPVgxLJ3jfD5OYWKmFhHQI+ZowY0Ltknbfyzc/kkfU+rvQjyYxmx
         jUKg4Sd6wEp13Ex7prg4NUtPXU11ZY9CvrpdxRceRX39IOl9hG3Yom5STyfsI71DVPsL
         S+5G+q/IzAZfdiMceXYPYVncdUrribZ7TVr90Vs3oRQxRoDHUOIPvltp/yjN5rU3qQL3
         GKRX6aSVdFE9EJYYFkDVmDivkrI1h9KB/wcSyeDk8QwkouPGFoOYR+e7FqxlxScIW+CN
         qjUERHFVXNF3e49izj9seXF1Ij3jqiIj48YG3M+/tVWoXlT7lEvEIwll/sCKcQBS2o2Z
         BRoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=pbogiJkx5sMH9nuCAxqWPKUdISM6F+QiK7otyl8XDBc=;
        b=bmWHmNr+5s7jYkqTOnyBkBz+XICO3k9IH7enWQBbbxCtEqjysx/vt/CovyDfbPYxnK
         3cLG/LiBGLQGtQXfpMohd4co9014j6Wvfb0RXe3Uzm3DiQsK3bR0asehSrx2Yi2QKlPq
         YMto9wCRAhkO83D9XD68B5wUgkwcBv56K+ue7VdPaOa0Iaa9C55Au+ng2ON0vl8kHZlS
         D+EselOxp34c/KqT5rLBEfbH54037B13ez/nVSZIqBAzqOQzRYrUr00Z5N6syB8jkynP
         wZWN3JTGCNLsWvIvij7RrNPT4R+c39zTcqgNBLJ4EPFoeCqkip63ayf6N3PhNAW1gn2e
         iC2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=aevy=er=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=AEVy=ER=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pbogiJkx5sMH9nuCAxqWPKUdISM6F+QiK7otyl8XDBc=;
        b=aB+MpbIqr7EuRSPXRIBrek4161niHst4MM4fJ1pU7gikhiX+JCFdaS+mBexX3mgjio
         pi/ADL+N7hl5sNeXYE3F3OCQZJWNw5OkA47hdkRQFxQ58/UOhLB7MeLcUBGTc9E31/my
         8gYHXdIi9QjAsfZVw344uB7M2v5J/iHIDIx+52hB7ATYifZlyxQGFJBhg9MosMyb/MYK
         bhjquzl1OVUL1FvFDZeFcf4J2KRaEr8/ZIhS89bH8bbh50esvX2PeOBY0DTlKrdhHnGa
         Vnfu+7cR5q4IsWLKPzlMXchPqpS6RWf5dlnPzd4S81JUHup/bQ5q6oxesekpwwQSxIMR
         PnHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pbogiJkx5sMH9nuCAxqWPKUdISM6F+QiK7otyl8XDBc=;
        b=l6vl3EyGnog9PCwc5RKv+zqiE5hMKfwSx6kIH8jeVoXIxU8F7Opz/tMHydvzRN6UDl
         3lY9E3B9sHMqTVLGkcKUeRHD7UVhmHNd4xOjBU6SXvegpiEFsEwAbyBtCI/HKcn8335F
         17keXrBdRvpzSdIO3h79us3mFqIA3WCqyyUIlNOaqUjeRxSQd1aPfVEhTbeI2aj6BgkN
         W5zq/1QB1WofLkgrzjJTdTsGbjb6rpIIEHc6N4h6bYm49wCqmZKG4U6A10nq7ahcKKsf
         +3X42SS042FssPm7sztKVmBkVF3gsX1THhU8RQB0Ri+NCXq8hhm1J5hOWrNj+aZtL0km
         4VpQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532i45gtu8QDolQ1zGhZKF/ngRMGQ4F4RmqUMpvGWn/JnvL2CDxh
	wGg2CSX/5PdxFVUohZkH6Ag=
X-Google-Smtp-Source: ABdhPJyqPzesFhsomNmN8bgNBcknquB/RM0kXkENzfo0x4dEStLgJMg0frs8dKPI+DySaOSQiQhz8w==
X-Received: by 2002:a9d:590e:: with SMTP id t14mr19450684oth.230.1605117948865;
        Wed, 11 Nov 2020 10:05:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1f59:: with SMTP id u25ls95201oth.1.gmail; Wed, 11
 Nov 2020 10:05:48 -0800 (PST)
X-Received: by 2002:a9d:58c6:: with SMTP id s6mr18906794oth.67.1605117948441;
        Wed, 11 Nov 2020 10:05:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605117948; cv=none;
        d=google.com; s=arc-20160816;
        b=k0lAS3mbPoJHeLw8ykPXw+hMh6vb7Svlj62mV256HOeY+oMzX4FCRW0VGq3QbpWVr1
         MBDS2IXb9N8el2eKhp6P+ADVu2wBHkF98FFph12j3TQG0pPE88ngJ63VjzMK8/NtG4b+
         UlRxGcW3jSmEfhT5TUSP4SRGEBUd5IBy1i/okeVXcpWDiQwPTxYvj86lnVVyKDakGMtU
         aB8Wv45wrD8prsiOUumRhRB7gPSY3rlxYXKceaNfzmqiqYOqbqAONnqk/n3pbwKJ+8pV
         JExtyFFBARvHN+gmVGX216zlozcM2wXIyXh2SJE+rAC33jGUV/fWFRmAmcWFyHqNXBSh
         tq8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=+OWqbwh2Ef57FLGg0OqlIxGf+/j8oPpOUSbQoXtMBp0=;
        b=OSchMdivzEZI8uShDUEnpBEK6/E84m797V2YiN4NpS/JeGyv44fGqH08tuZzVr71RX
         esSA3DfmGypReoTWfyyi60Ay5AKNaeWAoNGuQsm5LUxMk7qflMnB1ha+KOeNtTMVmsk8
         hojtOKvpyCqX5ZA9+ZhExWo2OLmInCRPBwZx4jjScTC6kV5o1jNz/UyACq7EXuds5w4I
         R2BJUQRCorcwODYJRQLEXL1bP/RlJoFFkzVrsz8OHLGJ/Dwaje+dWlYsF++J2gY3M5k4
         U5+yZ3bdwkjjDxZG7YcZFUaHBphfyg+KUhyhg/N9A2WYW2bvISfK/8hAQg4OPySMyNGE
         EOoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=aevy=er=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=AEVy=ER=goodmis.org=rostedt@kernel.org"
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o23si214982oic.4.2020.11.11.10.05.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Nov 2020 10:05:48 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=aevy=er=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gandalf.local.home (cpe-66-24-58-225.stny.res.rr.com [66.24.58.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id D42422076E;
	Wed, 11 Nov 2020 18:05:45 +0000 (UTC)
Date: Wed, 11 Nov 2020 13:05:43 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Marco Elver <elver@google.com>
Cc: Anders Roxell <anders.roxell@linaro.org>, Andrew Morton
 <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, Mark
 Rutland <mark.rutland@arm.com>, Linux Kernel Mailing List
 <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, kasan-dev
 <kasan-dev@googlegroups.com>, rcu@vger.kernel.org, paulmck@kernel.org,
 peterz@infradead.org
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without
 allocations
Message-ID: <20201111130543.27d29462@gandalf.local.home>
In-Reply-To: <20201111133813.GA81547@elver.google.com>
References: <20201110135320.3309507-1-elver@google.com>
	<CADYN=9+=-ApMi_eEdAeHU6TyuQ7ZJSTQ8F-FCSD33kZH8HR+xg@mail.gmail.com>
	<CANpmjNM8MZphvkTSo=KgCBXQ6fNY4qo6NZD5SBHjNse_L9i5FQ@mail.gmail.com>
	<20201111133813.GA81547@elver.google.com>
X-Mailer: Claws Mail 3.17.3 (GTK+ 2.24.32; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=aevy=er=goodmis.org=rostedt@kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=AEVy=ER=goodmis.org=rostedt@kernel.org"
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

On Wed, 11 Nov 2020 14:38:13 +0100
Marco Elver <elver@google.com> wrote:

> [+Cc folks who can maybe help figure out what's going on, since I get
>   warnings even without KFENCE on next-20201110.]
> 
> On Wed, Nov 11, 2020 at 09:29AM +0100, Marco Elver wrote:
> > On Wed, 11 Nov 2020 at 00:23, Anders Roxell <anders.roxell@linaro.org> wrote:
> > [...]
> > > I gave them a spin on next-20201105 [1] and on next-20201110 [2].
> > >
> > > I eventually got to a prompt on next-20201105.
> > > However, I got to this kernel panic on the next-20201110:
> > >
> > > [...]
> > > [ 1514.089966][    T1] Testing event system initcall: OK
> > > [ 1514.806232][    T1] Running tests on all trace events:
> > > [ 1514.857835][    T1] Testing all events:
> > > [ 1525.503262][    C0] hrtimer: interrupt took 10902600 ns
> > > [ 1623.861452][    C0] BUG: workqueue lockup - pool cpus=0 node=0
> > > flags=0x0 nice=0 stuck for 65s!
> > > [...]

OK, so this blows up when you enable all events?

Note, it could just be adding overhead (which is exasperated with other
debug options enabled), which could open up a race window.
 

> > > [ 7823.104349][   T28]       Tainted: G        W
> > > 5.10.0-rc3-next-20201110-00008-g8dc06700529d #3
> > > [ 7833.206491][   T28] "echo 0 >
> > > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
> > > [ 7840.750700][   T28] task:kworker/0:1     state:D stack:26640 pid:
> > > 1872 ppid:     2 flags:0x00000428
> > > [ 7875.642531][   T28] Workqueue: events toggle_allocation_gate
> > > [ 7889.178334][   T28] Call trace:
> > > [ 7897.066649][   T28]  __switch_to+0x1cc/0x1e0
> > > [ 7905.326856][   T28]  0xffff00000f7077b0
> > > [ 7928.354644][   T28] INFO: lockdep is turned off.
> > > [ 7934.022572][   T28] Kernel panic - not syncing: hung_task: blocked tasks
> > > [ 7934.032039][   T28] CPU: 0 PID: 28 Comm: khungtaskd Tainted: G
> > >   W         5.10.0-rc3-next-20201110-00008-g8dc06700529d #3
> > > [ 7934.045586][   T28] Hardware name: linux,dummy-virt (DT)
> > > [ 7934.053677][   T28] Call trace:
> > > [ 7934.060276][   T28]  dump_backtrace+0x0/0x420
> > > [ 7934.067635][   T28]  show_stack+0x38/0xa0
> > > [ 7934.091277][   T28]  dump_stack+0x1d4/0x278
> > > [ 7934.098878][   T28]  panic+0x304/0x5d8
> > > [ 7934.114923][   T28]  check_hung_uninterruptible_tasks+0x5e4/0x640
> > > [ 7934.123823][   T28]  watchdog+0x138/0x160
> > > [ 7934.131561][   T28]  kthread+0x23c/0x260
> > > [ 7934.138590][   T28]  ret_from_fork+0x10/0x18
> > > [ 7934.146631][   T28] Kernel Offset: disabled
> > > [ 7934.153749][   T28] CPU features: 0x0240002,20002004
> > > [ 7934.161476][   T28] Memory Limit: none
> > > [ 7934.171272][   T28] ---[ end Kernel panic - not syncing: hung_task:
> > > blocked tasks ]---
> > >
> > > Cheers,
> > > Anders
> > > [1] https://people.linaro.org/~anders.roxell/output-next-20201105-test.log
> > > [2] https://people.linaro.org/~anders.roxell/output-next-20201110-test.log
> > 
> > Thanks for testing. The fact that it passes on next-20201105 but not
> > on 20201110 is strange. If you boot with KFENCE disabled (boot param
> > kfence.sample_interval=0), does it boot?
> [...]
> 
> Right, so I think this is no longer KFENCE's fault. This looks like
> something scheduler/RCU/ftrace related?! I notice that there have been
> scheduler changes between next-20201105 and next-20201110.

I'm not sure any of that would cause this.

> 
> I get this with KFENCE disabled:
> 
> | Running tests on all trace events:
> | Testing all events: 
> | BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 32s!
> | Showing busy workqueues and worker pools:
> | workqueue events: flags=0x0
> |   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
> |     pending: vmstat_shepherd
> | workqueue events_power_efficient: flags=0x82
> |   pwq 2: cpus=0 flags=0x5 nice=0 active=2/256 refcnt=4
> |     in-flight: 107:neigh_periodic_work
> |     pending: do_cache_clean
> | pool 2: cpus=0 flags=0x5 nice=0 hung=3s workers=2 manager: 7
> | rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
> | 	(detected by 0, t=6502 jiffies, g=2885, q=4)
> | rcu: All QSes seen, last rcu_preempt kthread activity 5174 (4295523265-4295518091), jiffies_till_next_fqs=1, root ->qsmask 0x0
> | rcu: rcu_preempt kthread starved for 5174 jiffies! g2885 f0x2 RCU_GP_WAIT_FQS(5) ->state=0x0 ->cpu=0
> | rcu: 	Unless rcu_preempt kthread gets sufficient CPU time, OOM is now expected behavior.
> | rcu: RCU grace-period kthread stack dump:
> | task:rcu_preempt     state:R  running task     stack:    0 pid:   10 ppid:     2 flags:0x00000428
> | Call trace:
> |  __switch_to+0x100/0x1e0
> |  __schedule+0x2d0/0x890
> |  preempt_schedule_notrace+0x70/0x1c0
> |  ftrace_ops_no_ops+0x174/0x250
> |  ftrace_graph_call+0x0/0xc

Note, just because ftrace is called here, the blocked task was preempted
when the ftrace code called preempt_enable_notrace().


> |  preempt_count_add+0x1c/0x180
> |  schedule+0x44/0x108
> |  schedule_timeout+0x394/0x530
> |  rcu_gp_kthread+0x76c/0x19a8
> |  kthread+0x174/0x188
> |  ret_from_fork+0x10/0x18
> | 
> | ================================
> | WARNING: inconsistent lock state
> | 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #18 Not tainted
> | --------------------------------
> | inconsistent {IN-HARDIRQ-W} -> {HARDIRQ-ON-W} usage.
> | kcompactd0/26 [HC0[0]:SC0[0]:HE0:SE1] takes:
> | ffffae32e6bd4358 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x4a0/0xd18
> | {IN-HARDIRQ-W} state was registered at:

I did some digging here and it looks like the rcu_node lock could be taken
without interrupts enabled when it does a stall print. That probably should
be fixed, but it's a symptom of the underlining bug and not the cause.

-- Steve


> |   __lock_acquire+0x7bc/0x15b8
> |   lock_acquire+0x244/0x498
> |   _raw_spin_lock_irqsave+0x78/0x144
> |   rcu_sched_clock_irq+0x4a0/0xd18
> |   update_process_times+0x68/0x98
> |   tick_sched_handle.isra.16+0x54/0x80
> |   tick_sched_timer+0x64/0xd8
> |   __hrtimer_run_queues+0x2a4/0x750
> | [...]
> | irq event stamp: 270278
> | hardirqs last  enabled at (270277): [<ffffae32e5a0bff8>] _raw_spin_unlock_irq+0x48/0x90
> | hardirqs last disabled at (270278): [<ffffae32e46122bc>] el1_irq+0x7c/0x180
> | softirqs last  enabled at (268786): [<ffffae32e4610b58>] __do_softirq+0x650/0x6a4
> | softirqs last disabled at (268783): [<ffffae32e46c0b80>] irq_exit+0x1a8/0x1b0
> | 
> | other info that might help us debug this:
> |  Possible unsafe locking scenario:
> | 
> |        CPU0
> |        ----
> |   lock(rcu_node_0);
> |   <Interrupt>
> |     lock(rcu_node_0);
> | 
> |  *** DEADLOCK ***
> | 
> | 1 lock held by kcompactd0/26:
> |  #0: ffffae32e6bd4358 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x4a0/0xd18
> | [...]
> 
> Full log and config attached. Also, I can provoke this quicker with the
> attached diff.
> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111130543.27d29462%40gandalf.local.home.
