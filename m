Return-Path: <kasan-dev+bncBAABBFWXWD6QKGQEVAMQUMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 271BE2AF7D1
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 19:21:12 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id f66sf1932707ilh.17
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 10:21:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605118871; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fiw+VqFrH7a/gzWGXfGA0CmOCJEuLB21X3YbMRbYxgKEM92rDFwFx2Nh8ayMuq6dW5
         yyR8gvCRP1C9zdKhxIniCaoWW6SpvokyMgNnJn2eedqHLP4WN8tjuqe7TTOUCTnOR1/z
         ElKCt8Y9wLMIjJWssaBv5cY67V291vz04HHzq0anIWhMO54yoiL3KVnmi9Di241gnDTD
         ezkEROZ91cGxxm484F4otkLKpZ73UU/NfC0f48SYFIL8QM0aLhwwz1YKXzJCyRu1bHwE
         6vz5jMbCmHDgdEKVJF/AAXXicGyfrg5t7FkACyQLTzRlnN2xQsQ5JC6NXtjxvaCedE8W
         5h1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=1oHgZ8UmHyMDH0sbQvkq/R79Wagu0AEPVyhaveLfL7s=;
        b=BZwZe3TrT0KwhYmRRTof01aJxFrAxKGRbm0Wt9jYDgumPbIMBUCJhkHc0Ze9XjeYHS
         fen3lJSFLdY6y/0DNMBcLxAo/iLnBMIOHNao8uuR23kQAVD9OToRScnQ5VhPY3tVzpOt
         5tNr0x0qV1IajMAViGMRXx9NOIAcvBh5veEK39QNRvw38AWvBFS2U3FbKU8gqLz+R8OY
         xTHJclbqtGmrpFMe8P9/Mmgw7LgwxjGP7Y2j2uB9Qfk/tQ0q9k9pC2VQirA6ViVOm7v1
         /xuFZnjvrdFzvVm194WOqpES6P1SKrkIb9qn4hx6kiQsWWNX5uT5ekBJY8gcB1D9HXZh
         NkzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=E9VXTIyx;
       spf=pass (google.com: domain of srs0=nwwe=er=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=nwWE=ER=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1oHgZ8UmHyMDH0sbQvkq/R79Wagu0AEPVyhaveLfL7s=;
        b=SF/RHZqB8dp34v58PSicnciDGyoYIIZRwmRluyKcuB9ZvKak1/2YXzW4XAX3s/9U/s
         V8Z7AYTzmECRFSqfrlLQWR/3jyPPlzoMz97Tki+wM8bVtomVofZNGxTGUm5Z60hbttY/
         pGIeJ3HSfwGodknOrRWF+nPSHGgmpHSPKifhexm6iASng3wFXHQYaCf9Hw9VAtFiPhhZ
         EcJ5onWrn21e2qKONLNSSta7J9cTXNsU5mMmUBl//4c+g/riWPcTzMUQUmK4j7cpYNlB
         gU+mY0lN2XSvGj7DqKAJZh4JwbO3EtuIyv67ts6lF93a4kx4qBjrEEZCpmAC/uY71JG+
         g+zA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1oHgZ8UmHyMDH0sbQvkq/R79Wagu0AEPVyhaveLfL7s=;
        b=saXMw8NmW1SpKRPWOJ0HePg6rsD4lAzIS+oNr5DbgaOZX1z8NuHN1g6hh7+DtjDJMO
         viMeqWLDPjqhonok554vez5EXv6XQTI+VGc7U7NDrI9s12ussR6k/Mw2hMGhC1UMbHIv
         FlhGP4mwPOWBsUXFMo6hg2nEHqyg4bpwEbSJ14OTGusj7Kqo88obRV2/oeOojNhDoPQz
         xuNQpI4yuZPhyM57faHmSiRhn3nJ07/am9o25u1I9rSw4OwI+E3Fba3eq6PhoAYmJJ18
         IVlGNoZ8G2o8G58oEMeg8+UQtYbbr+UNRtY7KA6tmLTjs4Il7g3XFnWGCxcwoN0cfOZe
         8bcA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530dNQSmji1PybOgzZkZhFyjLnUjnjHKhySGZGnabCyQKk/VXJqv
	gc9+0vYGOHaJgxsRj923rxM=
X-Google-Smtp-Source: ABdhPJycndo5uPYbUGul8//+arVq6jyWP+AHh0SnseiVBw34e68HdatObf1c/O0Id3mI8tazzPDtog==
X-Received: by 2002:a05:6e02:12ab:: with SMTP id f11mr19125650ilr.89.1605118870613;
        Wed, 11 Nov 2020 10:21:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:99d1:: with SMTP id t78ls160844ilk.7.gmail; Wed, 11 Nov
 2020 10:21:10 -0800 (PST)
X-Received: by 2002:a92:c6c6:: with SMTP id v6mr2802566ilm.119.1605118869936;
        Wed, 11 Nov 2020 10:21:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605118869; cv=none;
        d=google.com; s=arc-20160816;
        b=PNrF5S5aESs8OEsTgQgorCXOysAFYLxA9MFQNSrsB70Bjf/pKCdBsH3w4nlMJLPX9i
         gXMI122hXb+iJBKEDWTElY2fBlSXmS2W6qdhIoeG/yxh8PCOYpaAw041j/jVfaAnywhB
         BKsPVs1oLtqsVhd0lcarQMVSnycY1186Wyou2lyVcflD2a0NWIdB1/o+29k8Rp1c1uBw
         x5IOOG+TvGAzixdt63tIEf8KEwlhAZyqm9pEJ+cIMWHqAkCRla9j+htLdDfIkDQqYz3W
         k6Foxsmzf2sLppm5hXjDSCmz2vI67PguxIZ1DYxY59J1utPhtFqESfBXjmevZyLiEzeu
         GXYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=rX6S4asFn7sqqAJ2hUKx1MoYe5+bjMlmUvmazHZTPzM=;
        b=0GC76t4oD6eG7k+qQ3DgDy0mX40YKKXGNi0TiIGrup0ZPHo/84o9r047VSPC3iWs9f
         cua2rq3cCCOI037XrKihVZbNImNjvkKooxD9H3AOFcL+EkMQpN9qqwBADTDYBsSmRBHE
         5ZEIDwlzKKOyV0k4n0KiXHCr07P4XY5EZ4VezWszi1Z+c5i6UZ6hy4T5qdPNROR1tLT5
         JMSNwCHGebgDYZUfF615pk41MXvo31fda8fOtNSo8q+BLdVZp+2v5uSJ3Bbiwlfacc7y
         ZxicMsNxqk+SojQBJejhE3AaHjtFK7L+sl8UVqFp5bc50wu6aTJCnx46GwZbijCSXeL8
         EKqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=E9VXTIyx;
       spf=pass (google.com: domain of srs0=nwwe=er=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=nwWE=ER=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d25si192878ioz.2.2020.11.11.10.21.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Nov 2020 10:21:09 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=nwwe=er=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 6D2E72076E;
	Wed, 11 Nov 2020 18:21:08 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 0D14635225D6; Wed, 11 Nov 2020 10:21:08 -0800 (PST)
Date: Wed, 11 Nov 2020 10:21:08 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Anders Roxell <anders.roxell@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org,
	peterz@infradead.org, rostedt@goodmis.org
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without
 allocations
Message-ID: <20201111182108.GZ3249@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201110135320.3309507-1-elver@google.com>
 <CADYN=9+=-ApMi_eEdAeHU6TyuQ7ZJSTQ8F-FCSD33kZH8HR+xg@mail.gmail.com>
 <CANpmjNM8MZphvkTSo=KgCBXQ6fNY4qo6NZD5SBHjNse_L9i5FQ@mail.gmail.com>
 <20201111133813.GA81547@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201111133813.GA81547@elver.google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=E9VXTIyx;       spf=pass
 (google.com: domain of srs0=nwwe=er=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=nwWE=ER=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Content-Transfer-Encoding: quoted-printable
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

On Wed, Nov 11, 2020 at 02:38:13PM +0100, Marco Elver wrote:
> [+Cc folks who can maybe help figure out what's going on, since I get
>   warnings even without KFENCE on next-20201110.]

That is quite the gallery of warning messages...

> On Wed, Nov 11, 2020 at 09:29AM +0100, Marco Elver wrote:
> > On Wed, 11 Nov 2020 at 00:23, Anders Roxell <anders.roxell@linaro.org> =
wrote:
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
> > > [ 1623.861452][    C0] BUG: workqueue lockup - pool cpus=3D0 node=3D0
> > > flags=3D0x0 nice=3D0 stuck for 65s!
> > > [...]
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
> > > [ 7934.022572][   T28] Kernel panic - not syncing: hung_task: blocked=
 tasks
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
> > > [ 7934.171272][   T28] ---[ end Kernel panic - not syncing: hung_task=
:
> > > blocked tasks ]---
> > >
> > > Cheers,
> > > Anders
> > > [1] https://people.linaro.org/~anders.roxell/output-next-20201105-tes=
t.log
> > > [2] https://people.linaro.org/~anders.roxell/output-next-20201110-tes=
t.log
> >=20
> > Thanks for testing. The fact that it passes on next-20201105 but not
> > on 20201110 is strange. If you boot with KFENCE disabled (boot param
> > kfence.sample_interval=3D0), does it boot?
> [...]
>=20
> Right, so I think this is no longer KFENCE's fault. This looks like
> something scheduler/RCU/ftrace related?! I notice that there have been
> scheduler changes between next-20201105 and next-20201110.
>=20
> I get this with KFENCE disabled:
>=20
> | Running tests on all trace events:
> | Testing all events:=20
> | BUG: workqueue lockup - pool cpus=3D0 node=3D0 flags=3D0x0 nice=3D0 stu=
ck for 32s!
> | Showing busy workqueues and worker pools:
> | workqueue events: flags=3D0x0
> |   pwq 0: cpus=3D0 node=3D0 flags=3D0x0 nice=3D0 active=3D1/256 refcnt=
=3D2
> |     pending: vmstat_shepherd
> | workqueue events_power_efficient: flags=3D0x82
> |   pwq 2: cpus=3D0 flags=3D0x5 nice=3D0 active=3D2/256 refcnt=3D4
> |     in-flight: 107:neigh_periodic_work
> |     pending: do_cache_clean
> | pool 2: cpus=3D0 flags=3D0x5 nice=3D0 hung=3D3s workers=3D2 manager: 7

I don't know the workqueue code all that well, but this looks like
workqueues isn't getting any CPU time on CPU 0.

> | rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
> | 	(detected by 0, t=3D6502 jiffies, g=3D2885, q=3D4)
> | rcu: All QSes seen, last rcu_preempt kthread activity 5174 (4295523265-=
4295518091), jiffies_till_next_fqs=3D1, root ->qsmask 0x0
> | rcu: rcu_preempt kthread starved for 5174 jiffies! g2885 f0x2 RCU_GP_WA=
IT_FQS(5) ->state=3D0x0 ->cpu=3D0
> | rcu: 	Unless rcu_preempt kthread gets sufficient CPU time, OOM is now e=
xpected behavior.

The above line says it all from an RCU viewpoint.  The rcu_preempt
kthread tried to wait for a few jiffies (as in three or fewer), and
more than 5000 jiffies later has failed to make any useful forward
progress.  And this kthread also was last running on CPU 0.

> | rcu: RCU grace-period kthread stack dump:
> | task:rcu_preempt     state:R  running task     stack:    0 pid:   10 pp=
id:     2 flags:0x00000428

And the timer subsystem did deliver the wakeup, hence the "state:R" above.
Which corroborates the "->state=3D0x0" in the "OOM is now expected behavior=
"
line above.

> | Call trace:
> |  __switch_to+0x100/0x1e0
> |  __schedule+0x2d0/0x890
> |  preempt_schedule_notrace+0x70/0x1c0
> |  ftrace_ops_no_ops+0x174/0x250
> |  ftrace_graph_call+0x0/0xc
> |  preempt_count_add+0x1c/0x180
> |  schedule+0x44/0x108
> |  schedule_timeout+0x394/0x530
> |  rcu_gp_kthread+0x76c/0x19a8
> |  kthread+0x174/0x188
> |  ret_from_fork+0x10/0x18
> |=20
> | =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D
> | WARNING: inconsistent lock state
> | 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #18 Not tainted
> | --------------------------------
> | inconsistent {IN-HARDIRQ-W} -> {HARDIRQ-ON-W} usage.
> | kcompactd0/26 [HC0[0]:SC0[0]:HE0:SE1] takes:
> | ffffae32e6bd4358 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x4a=
0/0xd18
> | {IN-HARDIRQ-W} state was registered at:
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
> | hardirqs last  enabled at (270277): [<ffffae32e5a0bff8>] _raw_spin_unlo=
ck_irq+0x48/0x90
> | hardirqs last disabled at (270278): [<ffffae32e46122bc>] el1_irq+0x7c/0=
x180
> | softirqs last  enabled at (268786): [<ffffae32e4610b58>] __do_softirq+0=
x650/0x6a4
> | softirqs last disabled at (268783): [<ffffae32e46c0b80>] irq_exit+0x1a8=
/0x1b0
> |=20
> | other info that might help us debug this:
> |  Possible unsafe locking scenario:
> |=20
> |        CPU0
> |        ----
> |   lock(rcu_node_0);
> |   <Interrupt>
> |     lock(rcu_node_0);
> |=20
> |  *** DEADLOCK ***
> |=20
> | 1 lock held by kcompactd0/26:
> |  #0: ffffae32e6bd4358 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq=
+0x4a0/0xd18

And this would explain nobody getting time on CPU 0, if we have a
self-deadlock.  Though in that case I would have expected to get the
lockdep warning first.

The fact that _raw_spin_lcok_irq() last enabled interrupts might mean
that RCU is invoking something that used to be OK with having interrupts
disabled, but now expects them to be enabled, and thus blindly re-enables
them.

Or Steven is right, and I should look at the RCU CPU stall-warning code.

Still, something bad happened before we got here.

							Thanx, Paul

> | [...]
>=20
> Full log and config attached. Also, I can provoke this quicker with the
> attached diff.
>=20
> Thanks,
> -- Marco

> [    0.000000] Booting Linux on physical CPU 0x0000000000 [0x411fd070]
> [    0.000000] Linux version 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5=
-dirty (elver@elver.muc.corp.google.com) (aarch64-linux-gnu-gcc (Linaro GCC=
 7.4-2019.02) 7.4.1 20181213 [linaro-7.4-2019.02 revision 56ec6f6b99cc167ff=
0c2f8e1a2eed33b1edc85d4], GNU ld (Linaro_Binutils-2019.02) 2.28.2.20170706)=
 #18 SMP PREEMPT Wed Nov 11 12:13:12 CET 2020
> [    0.000000] Machine model: linux,dummy-virt
> [    0.000000] efi: UEFI not found.
> [    0.000000] cma: Reserved 32 MiB at 0x00000000be000000
> [    0.000000] earlycon: pl11 at MMIO 0x0000000009000000 (options '')
> [    0.000000] printk: bootconsole [pl11] enabled
> [    0.000000] NUMA: No NUMA configuration found
> [    0.000000] NUMA: Faking a node at [mem 0x0000000040000000-0x00000000b=
fffffff]
> [    0.000000] NUMA: NODE_DATA [mem 0xbdbf8000-0xbdbf9fff]
> [    0.000000] Zone ranges:
> [    0.000000]   DMA      [mem 0x0000000040000000-0x00000000bfffffff]
> [    0.000000]   DMA32    empty
> [    0.000000]   Normal   empty
> [    0.000000] Movable zone start for each node
> [    0.000000] Early memory node ranges
> [    0.000000]   node   0: [mem 0x0000000040000000-0x00000000bfffffff]
> [    0.000000] Initmem setup node 0 [mem 0x0000000040000000-0x00000000bff=
fffff]
> [    0.000000] On node 0 totalpages: 524288
> [    0.000000]   DMA zone: 8192 pages used for memmap
> [    0.000000]   DMA zone: 0 pages reserved
> [    0.000000]   DMA zone: 524288 pages, LIFO batch:63
> [    0.000000] psci: probing for conduit method from DT.
> [    0.000000] psci: PSCIv0.2 detected in firmware.
> [    0.000000] psci: Using standard PSCI v0.2 function IDs
> [    0.000000] psci: Trusted OS migration not required
> [    0.000000] percpu: Embedded 49 pages/cpu s161936 r8192 d30576 u200704
> [    0.000000] pcpu-alloc: s161936 r8192 d30576 u200704 alloc=3D49*4096
> [    0.000000] pcpu-alloc: [0] 0=20
> [    0.000000] Detected PIPT I-cache on CPU0
> [    0.000000] CPU features: detected: ARM erratum 832075
> [    0.000000] CPU features: detected: ARM erratum 834220
> [    0.000000] CPU features: detected: EL2 vector hardening
> [    0.000000] CPU features: kernel page table isolation forced ON by KAS=
LR
> [    0.000000] CPU features: detected: Kernel page table isolation (KPTI)
> [    0.000000] CPU features: detected: Spectre-v2
> [    0.000000] CPU features: detected: Spectre-v4
> [    0.000000] CPU features: detected: ARM errata 1165522, 1319367, or 15=
30923
> [    0.000000] Built 1 zonelists, mobility grouping on.  Total pages: 516=
096
> [    0.000000] Policy zone: DMA
> [    0.000000] Kernel command line: console=3DttyAMA0 root=3D/dev/sda deb=
ug earlycon earlyprintk=3Dserial slub_debug=3DUZ slub_debug=3D- kfence.samp=
le_interval=3D0
> [    0.000000] Dentry cache hash table entries: 262144 (order: 9, 2097152=
 bytes, linear)
> [    0.000000] Inode-cache hash table entries: 131072 (order: 8, 1048576 =
bytes, linear)
> [    0.000000] mem auto-init: stack:off, heap alloc:off, heap free:off
> [    0.000000] Memory: 1969304K/2097152K available (20544K kernel code, 4=
020K rwdata, 8504K rodata, 8832K init, 11817K bss, 95080K reserved, 32768K =
cma-reserved)
> [    0.000000] SLUB: HWalign=3D64, Order=3D0-3, MinObjects=3D0, CPUs=3D1,=
 Nodes=3D1
> [    0.000000] ftrace: allocating 56112 entries in 220 pages
> [    0.000000] ftrace: allocated 220 pages with 5 groups
> [    0.000000] Running RCU self tests
> [    0.000000] rcu: Preemptible hierarchical RCU implementation.
> [    0.000000] rcu: 	RCU event tracing is enabled.
> [    0.000000] rcu: 	RCU lockdep checking is enabled.
> [    0.000000] rcu: 	RCU restricting CPUs from NR_CPUS=3D256 to nr_cpu_id=
s=3D1.
> [    0.000000] 	Trampoline variant of Tasks RCU enabled.
> [    0.000000] 	Rude variant of Tasks RCU enabled.
> [    0.000000] 	Tracing variant of Tasks RCU enabled.
> [    0.000000] rcu: RCU calculated value of scheduler-enlistment delay is=
 25 jiffies.
> [    0.000000] rcu: Adjusting geometry for rcu_fanout_leaf=3D16, nr_cpu_i=
ds=3D1
> [    0.000000] NR_IRQS: 64, nr_irqs: 64, preallocated irqs: 0
> [    0.000000] GICv2m: range[mem 0x08020000-0x08020fff], SPI[80:143]
> [    0.000000] random: get_random_bytes called from start_kernel+0x428/0x=
5e8 with crng_init=3D0
> [    0.000000] arch_timer: cp15 timer(s) running at 62.50MHz (virt).
> [    0.000000] clocksource: arch_sys_counter: mask: 0xffffffffffffff max_=
cycles: 0x1cd42e208c, max_idle_ns: 881590405314 ns
> [    0.000233] sched_clock: 56 bits at 62MHz, resolution 16ns, wraps ever=
y 4398046511096ns
> [    0.011426] Console: colour dummy device 80x25
> [    0.012862] Lock dependency validator: Copyright (c) 2006 Red Hat, Inc=
., Ingo Molnar
> [    0.013209] ... MAX_LOCKDEP_SUBCLASSES:  8
> [    0.013469] ... MAX_LOCK_DEPTH:          48
> [    0.013728] ... MAX_LOCKDEP_KEYS:        8192
> [    0.013992] ... CLASSHASH_SIZE:          4096
> [    0.014251] ... MAX_LOCKDEP_ENTRIES:     32768
> [    0.014511] ... MAX_LOCKDEP_CHAINS:      65536
> [    0.014770] ... CHAINHASH_SIZE:          32768
> [    0.015031]  memory used by lock dependency info: 6365 kB
> [    0.015306]  memory used for stack traces: 4224 kB
> [    0.015573]  per task-struct memory footprint: 1920 bytes
> [    0.018216] Calibrating delay loop (skipped), value calculated using t=
imer frequency.. 125.00 BogoMIPS (lpj=3D250000)
> [    0.018900] pid_max: default: 32768 minimum: 301
> [    0.022123] LSM: Security Framework initializing
> [    0.024372] Mount-cache hash table entries: 4096 (order: 3, 32768 byte=
s, linear)
> [    0.025621] Mountpoint-cache hash table entries: 4096 (order: 3, 32768=
 bytes, linear)
> [    0.113947] rcu: Hierarchical SRCU implementation.
> [    0.133436] EFI services will not be available.
> [    0.137866] smp: Bringing up secondary CPUs ...
> [    0.138333] smp: Brought up 1 node, 1 CPU
> [    0.138982] SMP: Total of 1 processors activated.
> [    0.139442] CPU features: detected: 32-bit EL0 Support
> [    0.139873] CPU features: detected: CRC32 instructions
> [    0.140211] CPU features: detected: 32-bit EL1 Support
> [    0.533739] CPU: All CPU(s) started at EL1
> [    0.534735] alternatives: patching kernel code
> [    0.597327] devtmpfs: initialized
> [    0.671951] KASLR enabled
> [    0.702419] clocksource: jiffies: mask: 0xffffffff max_cycles: 0xfffff=
fff, max_idle_ns: 7645041785100000 ns
> [    0.703467] futex hash table entries: 256 (order: 3, 32768 bytes, line=
ar)
> [    0.705355] Running postponed tracer tests:
> [    0.709250] Testing tracer function: PASSED
> [    8.480905] Testing dynamic ftrace: PASSED
> [    9.425085] Testing dynamic ftrace ops #1:=20
> [   12.011706] (1 0 1 0 0)=20
> [   12.012472] (1 1 2 0 0)=20
> [   19.421411] (2 1 3 0 1101335)=20
> [   19.423966] (2 2 4 0 1101760) PASSED
> [   23.382135] Testing dynamic ftrace ops #2:=20
> [   32.872265] (1 0 1 1082126 0)=20
> [   32.873599] (1 1 2 1082338 0)=20
> [   32.924413] (2 1 3 1 2103)=20
> [   32.925559] (2 2 4 200 2302) PASSED
> [   36.124900] Testing ftrace recursion: PASSED
> [   36.859157] Testing ftrace recursion safe: PASSED
> [   37.594606] Testing ftrace regs(no arch support): PASSED
> [   38.333537] Testing tracer nop: PASSED
> [   38.337880] Testing tracer irqsoff: PASSED
> [   46.271584] Testing tracer preemptoff: PASSED
> [   54.135978] Testing tracer preemptirqsoff: PASSED
> [   62.043008] Testing tracer wakeup:=20
> [   67.158358] sched: DL replenish lagged too much
> [   69.851230] PASSED
> [   69.859014] Testing tracer wakeup_rt: PASSED
> [   77.691853] Testing tracer wakeup_dl: PASSED
> [   85.583156] Testing tracer function_graph: PASSED
> [   93.250201] pinctrl core: initialized pinctrl subsystem
> [   93.297588] DMI not present or invalid.
> [   93.317875] NET: Registered protocol family 16
> [   93.384841] DMA: preallocated 256 KiB GFP_KERNEL pool for atomic alloc=
ations
> [   93.385798] DMA: preallocated 256 KiB GFP_KERNEL|GFP_DMA pool for atom=
ic allocations
> [   93.388668] DMA: preallocated 256 KiB GFP_KERNEL|GFP_DMA32 pool for at=
omic allocations
> [   93.390895] audit: initializing netlink subsys (disabled)
> [   93.402708] audit: type=3D2000 audit(81.888:1): state=3Dinitialized au=
dit_enabled=3D0 res=3D1
> [   93.438512] thermal_sys: Registered thermal governor 'step_wise'
> [   93.438744] thermal_sys: Registered thermal governor 'power_allocator'
> [   93.442047] cpuidle: using governor menu
> [   93.447969] hw-breakpoint: found 6 breakpoint and 4 watchpoint registe=
rs.
> [   93.449661] ASID allocator initialised with 32768 entries
> [   93.485107] Serial: AMBA PL011 UART driver
> [   94.434483] 9000000.pl011: ttyAMA0 at MMIO 0x9000000 (irq =3D 47, base=
_baud =3D 0) is a PL011 rev1
> [   94.438214] printk: console [ttyAMA0] enabled
> [   94.438214] printk: console [ttyAMA0] enabled
> [   94.439358] printk: bootconsole [pl11] disabled
> [   94.439358] printk: bootconsole [pl11] disabled
> [   94.922239] HugeTLB registered 1.00 GiB page size, pre-allocated 0 pag=
es
> [   94.922762] HugeTLB registered 32.0 MiB page size, pre-allocated 0 pag=
es
> [   94.923519] HugeTLB registered 2.00 MiB page size, pre-allocated 0 pag=
es
> [   94.923960] HugeTLB registered 64.0 KiB page size, pre-allocated 0 pag=
es
> [   94.995847] cryptd: max_cpu_qlen set to 1000
> [   95.132486] ACPI: Interpreter disabled.
> [   95.198275] iommu: Default domain type: Translated=20
> [   95.207497] vgaarb: loaded
> [   95.219386] SCSI subsystem initialized
> [   95.224642] libata version 3.00 loaded.
> [   95.233901] usbcore: registered new interface driver usbfs
> [   95.235586] usbcore: registered new interface driver hub
> [   95.237847] usbcore: registered new device driver usb
> [   95.262747] pps_core: LinuxPPS API ver. 1 registered
> [   95.263152] pps_core: Software ver. 5.3.6 - Copyright 2005-2007 Rodolf=
o Giometti <giometti@linux.it>
> [   95.263966] PTP clock support registered
> [   95.269799] EDAC MC: Ver: 3.0.0
> [   95.324422] FPGA manager framework
> [   95.328570] Advanced Linux Sound Architecture Driver Initialized.
> [   95.361928] clocksource: Switched to clocksource arch_sys_counter
> [  111.416735] VFS: Disk quotas dquot_6.6.0
> [  111.418925] VFS: Dquot-cache hash table entries: 512 (order 0, 4096 by=
tes)
> [  111.428393] pnp: PnP ACPI: disabled
> [  111.666757] NET: Registered protocol family 2
> [  111.690777] tcp_listen_portaddr_hash hash table entries: 1024 (order: =
4, 81920 bytes, linear)
> [  111.691885] TCP established hash table entries: 16384 (order: 5, 13107=
2 bytes, linear)
> [  111.701171] TCP bind hash table entries: 16384 (order: 8, 1179648 byte=
s, linear)
> [  111.708874] TCP: Hash tables configured (established 16384 bind 16384)
> [  111.713132] UDP hash table entries: 1024 (order: 5, 163840 bytes, line=
ar)
> [  111.716578] UDP-Lite hash table entries: 1024 (order: 5, 163840 bytes,=
 linear)
> [  111.722527] NET: Registered protocol family 1
> [  111.740889] RPC: Registered named UNIX socket transport module.
> [  111.741847] RPC: Registered udp transport module.
> [  111.742250] RPC: Registered tcp transport module.
> [  111.742627] RPC: Registered tcp NFSv4.1 backchannel transport module.
> [  111.743235] PCI: CLS 0 bytes, default 64
> [  111.773814] hw perfevents: enabled with armv8_pmuv3 PMU driver, 5 coun=
ters available
> [  111.775981] kvm [1]: HYP mode not available
> [  112.002354] Initialise system trusted keyrings
> [  112.008369] workingset: timestamp_bits=3D44 max_order=3D19 bucket_orde=
r=3D0
> [  112.315870] squashfs: version 4.0 (2009/01/31) Phillip Lougher
> [  112.336509] NFS: Registering the id_resolver key type
> [  112.337956] Key type id_resolver registered
> [  112.338516] Key type id_legacy registered
> [  112.342326] nfs4filelayout_init: NFSv4 File Layout Driver Registering.=
..
> [  112.350262] 9p: Installing v9fs 9p2000 file system support
> [  112.445768] Key type asymmetric registered
> [  112.446387] Asymmetric key parser 'x509' registered
> [  112.447763] Block layer SCSI generic (bsg) driver version 0.4 loaded (=
major 245)
> [  112.448420] io scheduler mq-deadline registered
> [  112.448928] io scheduler kyber registered
> [  112.832673] pl061_gpio 9030000.pl061: PL061 GPIO chip registered
> [  112.892911] pci-host-generic 4010000000.pcie: host bridge /pcie@100000=
00 ranges:
> [  112.895334] pci-host-generic 4010000000.pcie:       IO 0x003eff0000..0=
x003effffff -> 0x0000000000
> [  112.897242] pci-host-generic 4010000000.pcie:      MEM 0x0010000000..0=
x003efeffff -> 0x0010000000
> [  112.898516] pci-host-generic 4010000000.pcie:      MEM 0x8000000000..0=
xffffffffff -> 0x8000000000
> [  112.901413] pci-host-generic 4010000000.pcie: ECAM at [mem 0x401000000=
0-0x401fffffff] for [bus 00-ff]
> [  112.906977] pci-host-generic 4010000000.pcie: PCI host bridge to bus 0=
000:00
> [  112.907704] pci_bus 0000:00: root bus resource [bus 00-ff]
> [  112.908246] pci_bus 0000:00: root bus resource [io  0x0000-0xffff]
> [  112.908735] pci_bus 0000:00: root bus resource [mem 0x10000000-0x3efef=
fff]
> [  112.909295] pci_bus 0000:00: root bus resource [mem 0x8000000000-0xfff=
fffffff]
> [  112.912394] pci 0000:00:00.0: [1b36:0008] type 00 class 0x060000
> [  112.924053] pci 0000:00:01.0: [1af4:1009] type 00 class 0x000200
> [  112.925272] pci 0000:00:01.0: reg 0x10: [io  0x0000-0x003f]
> [  112.926292] pci 0000:00:01.0: reg 0x14: [mem 0x00000000-0x00000fff]
> [  112.927523] pci 0000:00:01.0: reg 0x20: [mem 0x00000000-0x00003fff 64b=
it pref]
> [  112.935594] pci 0000:00:02.0: [1af4:1009] type 00 class 0x000200
> [  112.936480] pci 0000:00:02.0: reg 0x10: [io  0x0000-0x003f]
> [  112.937116] pci 0000:00:02.0: reg 0x14: [mem 0x00000000-0x00000fff]
> [  112.938606] pci 0000:00:02.0: reg 0x20: [mem 0x00000000-0x00003fff 64b=
it pref]
> [  112.946673] pci 0000:00:03.0: [1af4:1000] type 00 class 0x020000
> [  112.947572] pci 0000:00:03.0: reg 0x10: [io  0x0000-0x001f]
> [  112.948199] pci 0000:00:03.0: reg 0x14: [mem 0x00000000-0x00000fff]
> [  112.949374] pci 0000:00:03.0: reg 0x20: [mem 0x00000000-0x00003fff 64b=
it pref]
> [  112.950357] pci 0000:00:03.0: reg 0x30: [mem 0x00000000-0x0003ffff pre=
f]
> [  112.958217] pci 0000:00:04.0: [1af4:1004] type 00 class 0x010000
> [  112.959101] pci 0000:00:04.0: reg 0x10: [io  0x0000-0x003f]
> [  112.959728] pci 0000:00:04.0: reg 0x14: [mem 0x00000000-0x00000fff]
> [  112.960876] pci 0000:00:04.0: reg 0x20: [mem 0x00000000-0x00003fff 64b=
it pref]
> [  112.974853] pci 0000:00:03.0: BAR 6: assigned [mem 0x10000000-0x1003ff=
ff pref]
> [  112.975676] pci 0000:00:01.0: BAR 4: assigned [mem 0x8000000000-0x8000=
003fff 64bit pref]
> [  112.976651] pci 0000:00:02.0: BAR 4: assigned [mem 0x8000004000-0x8000=
007fff 64bit pref]
> [  112.977889] pci 0000:00:03.0: BAR 4: assigned [mem 0x8000008000-0x8000=
00bfff 64bit pref]
> [  112.978725] pci 0000:00:04.0: BAR 4: assigned [mem 0x800000c000-0x8000=
00ffff 64bit pref]
> [  112.979501] pci 0000:00:01.0: BAR 1: assigned [mem 0x10040000-0x10040f=
ff]
> [  112.980096] pci 0000:00:02.0: BAR 1: assigned [mem 0x10041000-0x10041f=
ff]
> [  112.980678] pci 0000:00:03.0: BAR 1: assigned [mem 0x10042000-0x10042f=
ff]
> [  112.981246] pci 0000:00:04.0: BAR 1: assigned [mem 0x10043000-0x10043f=
ff]
> [  112.982177] pci 0000:00:01.0: BAR 0: assigned [io  0x1000-0x103f]
> [  112.982760] pci 0000:00:02.0: BAR 0: assigned [io  0x1040-0x107f]
> [  112.983316] pci 0000:00:04.0: BAR 0: assigned [io  0x1080-0x10bf]
> [  112.983869] pci 0000:00:03.0: BAR 0: assigned [io  0x10c0-0x10df]
> [  113.057252] EINJ: ACPI disabled.
> [  113.556321] virtio-pci 0000:00:01.0: enabling device (0000 -> 0003)
> [  113.571711] virtio-pci 0000:00:02.0: enabling device (0000 -> 0003)
> [  113.584925] virtio-pci 0000:00:03.0: enabling device (0000 -> 0003)
> [  113.596020] virtio-pci 0000:00:04.0: enabling device (0000 -> 0003)
> [  113.787453] Serial: 8250/16550 driver, 4 ports, IRQ sharing enabled
> [  113.882178] SuperH (H)SCI(F) driver initialized
> [  113.901072] msm_serial: driver initialized
> [  113.952925] cacheinfo: Unable to detect cache hierarchy for CPU 0
> [  114.230176] loop: module loaded
> [  114.262318] megasas: 07.714.04.00-rc1
> [  114.302236] scsi host0: Virtio SCSI HBA
> [  114.336019] scsi 0:0:0:0: Direct-Access     QEMU     QEMU HARDDISK    =
2.5+ PQ: 0 ANSI: 5
> [  117.142680] random: fast init done
> [  117.213261] sd 0:0:0:0: Power-on or device reset occurred
> [  117.238425] sd 0:0:0:0: [sda] 524288 512-byte logical blocks: (268 MB/=
256 MiB)
> [  117.240745] sd 0:0:0:0: [sda] Write Protect is off
> [  117.241797] sd 0:0:0:0: [sda] Mode Sense: 63 00 00 08
> [  117.245029] sd 0:0:0:0: [sda] Write cache: enabled, read cache: enable=
d, doesn't support DPO or FUA
> [  117.363810] physmap-flash 0.flash: physmap platform flash device: [mem=
 0x00000000-0x03ffffff]
> [  117.370560] 0.flash: Found 2 x16 devices at 0x0 in 32-bit bank. Manufa=
cturer ID 0x000000 Chip ID 0x000000
> [  117.371615] Intel/Sharp Extended Query Table at 0x0031
> [  117.372904] Using buffer write method
> [  117.378232] erase region 0: offset=3D0x0,size=3D0x40000,blocks=3D256
> [  117.379270] physmap-flash 0.flash: physmap platform flash device: [mem=
 0x04000000-0x07ffffff]
> [  117.386159] 0.flash: Found 2 x16 devices at 0x0 in 32-bit bank. Manufa=
cturer ID 0x000000 Chip ID 0x000000
> [  117.386764] Intel/Sharp Extended Query Table at 0x0031
> [  117.387780] Using buffer write method
> [  117.388252] erase region 0: offset=3D0x0,size=3D0x40000,blocks=3D256
> [  117.388744] Concatenating MTD devices:
> [  117.389145] (0): "0.flash"
> [  117.394228] (1): "0.flash"
> [  117.394599] into device "0.flash"
> [  117.431485] sd 0:0:0:0: [sda] Attached SCSI disk
> [  117.647630] libphy: Fixed MDIO Bus: probed
> [  117.695782] tun: Universal TUN/TAP device driver, 1.6
> [  117.753377] thunder_xcv, ver 1.0
> [  117.755546] thunder_bgx, ver 1.0
> [  117.757381] nicpf, ver 1.0
> [  117.802859] hclge is initializing
> [  117.804122] hns3: Hisilicon Ethernet Network Driver for Hip08 Family -=
 version
> [  117.804571] hns3: Copyright (c) 2017 Huawei Corporation.
> [  117.807038] e1000: Intel(R) PRO/1000 Network Driver
> [  117.807436] e1000: Copyright (c) 1999-2006 Intel Corporation.
> [  117.809232] e1000e: Intel(R) PRO/1000 Network Driver
> [  117.809943] e1000e: Copyright(c) 1999 - 2015 Intel Corporation.
> [  117.811895] igb: Intel(R) Gigabit Ethernet Network Driver
> [  117.812296] igb: Copyright (c) 2007-2014 Intel Corporation.
> [  117.814130] igbvf: Intel(R) Gigabit Virtual Function Network Driver
> [  117.814551] igbvf: Copyright (c) 2009 - 2012 Intel Corporation.
> [  117.828957] sky2: driver version 1.30
> [  117.865333] VFIO - User Level meta-driver version: 0.3
> [  117.930121] ehci_hcd: USB 2.0 'Enhanced' Host Controller (EHCI) Driver
> [  117.930624] ehci-pci: EHCI PCI platform driver
> [  117.932133] ehci-platform: EHCI generic platform driver
> [  117.936936] ehci-orion: EHCI orion driver
> [  117.941876] ehci-exynos: EHCI Exynos driver
> [  117.946441] ohci_hcd: USB 1.1 'Open' Host Controller (OHCI) Driver
> [  117.947298] ohci-pci: OHCI PCI platform driver
> [  117.948921] ohci-platform: OHCI generic platform driver
> [  117.954091] ohci-exynos: OHCI Exynos driver
> [  117.970958] usbcore: registered new interface driver usb-storage
> [  118.086591] rtc-pl031 9010000.pl031: registered as rtc0
> [  118.088263] rtc-pl031 9010000.pl031: setting system clock to 2020-11-1=
1T11:15:44 UTC (1605093344)
> [  118.112352] i2c /dev entries driver
> [  118.359637] sdhci: Secure Digital Host Controller Interface driver
> [  118.360055] sdhci: Copyright(c) Pierre Ossman
> [  118.376774] Synopsys Designware Multimedia Card Interface Driver
> [  118.417048] sdhci-pltfm: SDHCI platform and OF driver helper
> [  118.473048] ledtrig-cpu: registered to indicate activity on CPUs
> [  118.541154] usbcore: registered new interface driver usbhid
> [  118.541908] usbhid: USB HID core driver
> [  118.726391] drop_monitor: Initializing network drop monitor service
> [  118.729987] NET: Registered protocol family 17
> [  118.736719] 9pnet: Installing 9P2000 support
> [  118.755745] Key type dns_resolver registered
> [  118.763199] registered taskstats version 1
> [  118.764943] Running tests on all trace events:
> [  118.765319] Testing all events: OK
> [  154.077275] hrtimer: interrupt took 21125232 ns
> [  176.049337] Running tests again, along with the function tracer
> [  176.068194] Running tests on all trace events:
> [  176.078196] Testing all events:=20
> [ 1320.629571] BUG: workqueue lockup - pool cpus=3D0 node=3D0 flags=3D0x0=
 nice=3D0 stuck for 32s!
> [ 1320.785660] Showing busy workqueues and worker pools:
> [ 1320.825476] workqueue events: flags=3D0x0
> [ 1320.861955]   pwq 0: cpus=3D0 node=3D0 flags=3D0x0 nice=3D0 active=3D1=
/256 refcnt=3D2
> [ 1320.873397]     pending: vmstat_shepherd
> [ 1320.885467] workqueue events_power_efficient: flags=3D0x82
> [ 1320.921575]   pwq 2: cpus=3D0 flags=3D0x5 nice=3D0 active=3D2/256 refc=
nt=3D4
> [ 1320.931385]     in-flight: 107:neigh_periodic_work
> [ 1320.938581]     pending: do_cache_clean
> [ 1320.960212] pool 2: cpus=3D0 flags=3D0x5 nice=3D0 hung=3D3s workers=3D=
2 manager: 7
> [ 2535.539509] rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
> [ 2535.545633] 	(detected by 0, t=3D6502 jiffies, g=3D2885, q=3D4)
> [ 2535.547634] rcu: All QSes seen, last rcu_preempt kthread activity 5174=
 (4295523265-4295518091), jiffies_till_next_fqs=3D1, root ->qsmask 0x0
> [ 2535.558720] rcu: rcu_preempt kthread starved for 5174 jiffies! g2885 f=
0x2 RCU_GP_WAIT_FQS(5) ->state=3D0x0 ->cpu=3D0
> [ 2535.564713] rcu: 	Unless rcu_preempt kthread gets sufficient CPU time,=
 OOM is now expected behavior.
> [ 2535.570363] rcu: RCU grace-period kthread stack dump:
> [ 2535.574930] task:rcu_preempt     state:R  running task     stack:    0=
 pid:   10 ppid:     2 flags:0x00000428
> [ 2535.584170] Call trace:
> [ 2535.588004]  __switch_to+0x100/0x1e0
> [ 2535.592125]  __schedule+0x2d0/0x890
> [ 2535.596252]  preempt_schedule_notrace+0x70/0x1c0
> [ 2535.600745]  ftrace_ops_no_ops+0x174/0x250
> [ 2535.605047]  ftrace_graph_call+0x0/0xc
> [ 2535.609205]  preempt_count_add+0x1c/0x180
> [ 2535.613451]  schedule+0x44/0x108
> [ 2535.617464]  schedule_timeout+0x394/0x530
> [ 2535.621741]  rcu_gp_kthread+0x76c/0x19a8
> [ 2535.625972]  kthread+0x174/0x188
> [ 2535.630006]  ret_from_fork+0x10/0x18
> [ 2535.643477]=20
> [ 2535.645825] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [ 2535.648864] WARNING: inconsistent lock state
> [ 2535.652090] 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #18 Not=
 tainted
> [ 2535.656024] --------------------------------
> [ 2535.659086] inconsistent {IN-HARDIRQ-W} -> {HARDIRQ-ON-W} usage.
> [ 2535.662702] kcompactd0/26 [HC0[0]:SC0[0]:HE0:SE1] takes:
> [ 2535.666132] ffffae32e6bd4358 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_c=
lock_irq+0x4a0/0xd18
> [ 2535.674157] {IN-HARDIRQ-W} state was registered at:
> [ 2535.677571]   __lock_acquire+0x7bc/0x15b8
> [ 2535.680656]   lock_acquire+0x244/0x498
> [ 2535.683628]   _raw_spin_lock_irqsave+0x78/0x144
> [ 2535.686822]   rcu_sched_clock_irq+0x4a0/0xd18
> [ 2535.689963]   update_process_times+0x68/0x98
> [ 2535.693072]   tick_sched_handle.isra.16+0x54/0x80
> [ 2535.696314]   tick_sched_timer+0x64/0xd8
> [ 2535.699352]   __hrtimer_run_queues+0x2a4/0x750
> [ 2535.702522]   hrtimer_interrupt+0xf4/0x2a0
> [ 2535.705620]   arch_timer_handler_virt+0x44/0x70
> [ 2535.708845]   handle_percpu_devid_irq+0xfc/0x4d0
> [ 2535.712056]   generic_handle_irq+0x50/0x70
> [ 2535.715127]   __handle_domain_irq+0x9c/0x120
> [ 2535.718233]   gic_handle_irq+0xcc/0x108
> [ 2535.721261]   el1_irq+0xbc/0x180
> [ 2535.724080]   _raw_spin_unlock_irq+0x50/0x90
> [ 2535.727203]   finish_task_switch+0xa4/0x2a8
> [ 2535.730289]   __schedule+0x2d4/0x890
> [ 2535.733211]   preempt_schedule_notrace+0x70/0x1c0
> [ 2535.736450]   ftrace_ops_no_ops+0x174/0x250
> [ 2535.739535]   ftrace_graph_call+0x0/0xc
> [ 2535.742555]   preempt_count_add+0x1c/0x180
> [ 2535.745621]   schedule+0x44/0x108
> [ 2535.748470]   schedule_timeout+0x394/0x530
> [ 2535.751548]   kcompactd+0x340/0x498
> [ 2535.754446]   kthread+0x174/0x188
> [ 2535.757308]   ret_from_fork+0x10/0x18
> [ 2535.760211] irq event stamp: 270278
> [ 2535.763168] hardirqs last  enabled at (270277): [<ffffae32e5a0bff8>] _=
raw_spin_unlock_irq+0x48/0x90
> [ 2535.767704] hardirqs last disabled at (270278): [<ffffae32e46122bc>] e=
l1_irq+0x7c/0x180
> [ 2535.771957] softirqs last  enabled at (268786): [<ffffae32e4610b58>] _=
_do_softirq+0x650/0x6a4
> [ 2535.776321] softirqs last disabled at (268783): [<ffffae32e46c0b80>] i=
rq_exit+0x1a8/0x1b0
> [ 2535.780515]=20
> [ 2535.780515] other info that might help us debug this:
> [ 2535.784227]  Possible unsafe locking scenario:
> [ 2535.784227]=20
> [ 2535.787754]        CPU0
> [ 2535.790268]        ----
> [ 2535.792772]   lock(rcu_node_0);
> [ 2535.797232]   <Interrupt>
> [ 2535.799765]     lock(rcu_node_0);
> [ 2535.804266]=20
> [ 2535.804266]  *** DEADLOCK ***
> [ 2535.804266]=20
> [ 2535.807836] 1 lock held by kcompactd0/26:
> [ 2535.810840]  #0: ffffae32e6bd4358 (rcu_node_0){?.-.}-{2:2}, at: rcu_sc=
hed_clock_irq+0x4a0/0xd18
> [ 2535.819708]=20
> [ 2535.819708] stack backtrace:
> [ 2535.823059] CPU: 0 PID: 26 Comm: kcompactd0 Not tainted 5.10.0-rc3-nex=
t-20201110-00001-gc07b306d7fa5-dirty #18
> [ 2535.827790] Hardware name: linux,dummy-virt (DT)
> [ 2535.831009] Call trace:
> [ 2535.833607]  dump_backtrace+0x0/0x278
> [ 2535.836537]  show_stack+0x30/0x80
> [ 2535.839386]  dump_stack+0x138/0x1b0
> [ 2535.842278]  print_usage_bug+0x2d8/0x2f8
> [ 2535.845301]  mark_lock.part.46+0x370/0x480
> [ 2535.848366]  mark_held_locks+0x58/0x90
> [ 2535.851340]  lockdep_hardirqs_on_prepare+0xdc/0x298
> [ 2535.854655]  trace_hardirqs_on+0x90/0x388
> [ 2535.857693]  el1_irq+0xd8/0x180
> [ 2535.860494]  _raw_spin_unlock_irq+0x50/0x90
> [ 2535.863583]  finish_task_switch+0xa4/0x2a8
> [ 2535.866656]  __schedule+0x2d4/0x890
> [ 2535.869575]  preempt_schedule_notrace+0x70/0x1c0
> [ 2535.872811]  ftrace_ops_no_ops+0x174/0x250
> [ 2535.875885]  ftrace_graph_call+0x0/0xc
> [ 2535.878865]  preempt_count_add+0x1c/0x180
> [ 2535.881901]  schedule+0x44/0x108
> [ 2535.884719]  schedule_timeout+0x394/0x530
> [ 2535.887747]  kcompactd+0x340/0x498
> [ 2535.890630]  kthread+0x174/0x188
> [ 2535.893441]  ret_from_fork+0x10/0x18
> [ 2535.900455] BUG: scheduling while atomic: kcompactd0/26/0x00000002
> [ 2535.908864] INFO: lockdep is turned off.
> [ 2535.917408] Modules linked in:
> [ 2535.930517] Preemption disabled at:
> [ 2535.932175] [<ffffae32e4819ca4>] ftrace_ops_no_ops+0x174/0x250
> [ 2535.945072] CPU: 0 PID: 26 Comm: kcompactd0 Not tainted 5.10.0-rc3-nex=
t-20201110-00001-gc07b306d7fa5-dirty #18
> [ 2535.949821] Hardware name: linux,dummy-virt (DT)
> [ 2535.952991] Call trace:
> [ 2535.955591]  dump_backtrace+0x0/0x278
> [ 2535.958529]  show_stack+0x30/0x80
> [ 2535.961385]  dump_stack+0x138/0x1b0
> [ 2535.964320]  __schedule_bug+0x8c/0xe8
> [ 2535.967292]  __schedule+0x7e8/0x890
> [ 2535.970204]  preempt_schedule_notrace+0x70/0x1c0
> [ 2535.973465]  ftrace_ops_no_ops+0x174/0x250
> [ 2535.976547]  ftrace_graph_call+0x0/0xc
> [ 2535.979553]  preempt_count_add+0x1c/0x180
> [ 2535.982597]  schedule+0x44/0x108
> [ 2535.985411]  schedule_timeout+0x394/0x530
> [ 2535.988445]  kcompactd+0x340/0x498
> [ 2535.991330]  kthread+0x174/0x188
> [ 2535.994150]  ret_from_fork+0x10/0x18
> qemu-system-aarch64: terminating on signal 15 from pid 4135918 ()

> diff --git a/kernel/trace/trace_events.c b/kernel/trace/trace_events.c
> index 47a71f96e5bc..2fbe0637e053 100644
> --- a/kernel/trace/trace_events.c
> +++ b/kernel/trace/trace_events.c
> @@ -3568,6 +3568,7 @@ static __init void event_trace_self_tests(void)
>  	if (!tr)
>  		return;
> =20
> +#if 0
>  	pr_info("Running tests on trace events:\n");
> =20
>  	list_for_each_entry(file, &tr->events, list) {
> @@ -3641,6 +3642,7 @@ static __init void event_trace_self_tests(void)
> =20
>  		pr_cont("OK\n");
>  	}
> +#endif
> =20
>  	/* Test with all events enabled */
> =20

> #
> # Automatically generated file; DO NOT EDIT.
> # Linux/arm64 5.10.0-rc3 Kernel Configuration
> #
> CONFIG_CC_VERSION_TEXT=3D"aarch64-linux-gnu-gcc (Linaro GCC 7.4-2019.02) =
7.4.1 20181213 [linaro-7.4-2019.02 revision 56ec6f6b99cc167ff0c2f8e1a2eed33=
b1edc85d4]"
> CONFIG_CC_IS_GCC=3Dy
> CONFIG_GCC_VERSION=3D70401
> CONFIG_LD_VERSION=3D228020000
> CONFIG_CLANG_VERSION=3D0
> CONFIG_CC_CAN_LINK=3Dy
> CONFIG_CC_CAN_LINK_STATIC=3Dy
> CONFIG_CC_HAS_ASM_GOTO=3Dy
> CONFIG_IRQ_WORK=3Dy
> CONFIG_BUILDTIME_TABLE_SORT=3Dy
> CONFIG_THREAD_INFO_IN_TASK=3Dy
>=20
> #
> # General setup
> #
> CONFIG_INIT_ENV_ARG_LIMIT=3D32
> # CONFIG_COMPILE_TEST is not set
> CONFIG_LOCALVERSION=3D""
> CONFIG_LOCALVERSION_AUTO=3Dy
> CONFIG_BUILD_SALT=3D""
> CONFIG_DEFAULT_INIT=3D""
> CONFIG_DEFAULT_HOSTNAME=3D"(none)"
> CONFIG_SWAP=3Dy
> CONFIG_SYSVIPC=3Dy
> CONFIG_SYSVIPC_SYSCTL=3Dy
> CONFIG_POSIX_MQUEUE=3Dy
> CONFIG_POSIX_MQUEUE_SYSCTL=3Dy
> # CONFIG_WATCH_QUEUE is not set
> CONFIG_CROSS_MEMORY_ATTACH=3Dy
> # CONFIG_USELIB is not set
> CONFIG_AUDIT=3Dy
> CONFIG_HAVE_ARCH_AUDITSYSCALL=3Dy
> CONFIG_AUDITSYSCALL=3Dy
>=20
> #
> # IRQ subsystem
> #
> CONFIG_GENERIC_IRQ_PROBE=3Dy
> CONFIG_GENERIC_IRQ_SHOW=3Dy
> CONFIG_GENERIC_IRQ_SHOW_LEVEL=3Dy
> CONFIG_GENERIC_IRQ_EFFECTIVE_AFF_MASK=3Dy
> CONFIG_GENERIC_IRQ_MIGRATION=3Dy
> CONFIG_HARDIRQS_SW_RESEND=3Dy
> CONFIG_GENERIC_IRQ_CHIP=3Dy
> CONFIG_IRQ_DOMAIN=3Dy
> CONFIG_IRQ_DOMAIN_HIERARCHY=3Dy
> CONFIG_IRQ_FASTEOI_HIERARCHY_HANDLERS=3Dy
> CONFIG_GENERIC_IRQ_IPI=3Dy
> CONFIG_GENERIC_MSI_IRQ=3Dy
> CONFIG_GENERIC_MSI_IRQ_DOMAIN=3Dy
> CONFIG_IRQ_MSI_IOMMU=3Dy
> CONFIG_HANDLE_DOMAIN_IRQ=3Dy
> CONFIG_IRQ_FORCED_THREADING=3Dy
> CONFIG_SPARSE_IRQ=3Dy
> # CONFIG_GENERIC_IRQ_DEBUGFS is not set
> # end of IRQ subsystem
>=20
> CONFIG_GENERIC_IRQ_MULTI_HANDLER=3Dy
> CONFIG_GENERIC_TIME_VSYSCALL=3Dy
> CONFIG_GENERIC_CLOCKEVENTS=3Dy
> CONFIG_ARCH_HAS_TICK_BROADCAST=3Dy
> CONFIG_GENERIC_CLOCKEVENTS_BROADCAST=3Dy
>=20
> #
> # Timers subsystem
> #
> CONFIG_TICK_ONESHOT=3Dy
> CONFIG_NO_HZ_COMMON=3Dy
> # CONFIG_HZ_PERIODIC is not set
> CONFIG_NO_HZ_IDLE=3Dy
> # CONFIG_NO_HZ_FULL is not set
> # CONFIG_NO_HZ is not set
> CONFIG_HIGH_RES_TIMERS=3Dy
> # end of Timers subsystem
>=20
> # CONFIG_PREEMPT_NONE is not set
> # CONFIG_PREEMPT_VOLUNTARY is not set
> CONFIG_PREEMPT=3Dy
> CONFIG_PREEMPTION=3Dy
>=20
> #
> # CPU/Task time and stats accounting
> #
> CONFIG_TICK_CPU_ACCOUNTING=3Dy
> # CONFIG_VIRT_CPU_ACCOUNTING_GEN is not set
> CONFIG_IRQ_TIME_ACCOUNTING=3Dy
> CONFIG_HAVE_SCHED_AVG_IRQ=3Dy
> CONFIG_SCHED_THERMAL_PRESSURE=3Dy
> CONFIG_BSD_PROCESS_ACCT=3Dy
> CONFIG_BSD_PROCESS_ACCT_V3=3Dy
> CONFIG_TASKSTATS=3Dy
> CONFIG_TASK_DELAY_ACCT=3Dy
> CONFIG_TASK_XACCT=3Dy
> CONFIG_TASK_IO_ACCOUNTING=3Dy
> # CONFIG_PSI is not set
> # end of CPU/Task time and stats accounting
>=20
> CONFIG_CPU_ISOLATION=3Dy
>=20
> #
> # RCU Subsystem
> #
> CONFIG_TREE_RCU=3Dy
> CONFIG_PREEMPT_RCU=3Dy
> # CONFIG_RCU_EXPERT is not set
> CONFIG_SRCU=3Dy
> CONFIG_TREE_SRCU=3Dy
> CONFIG_TASKS_RCU_GENERIC=3Dy
> CONFIG_TASKS_RCU=3Dy
> CONFIG_TASKS_RUDE_RCU=3Dy
> CONFIG_TASKS_TRACE_RCU=3Dy
> CONFIG_RCU_STALL_COMMON=3Dy
> CONFIG_RCU_NEED_SEGCBLIST=3Dy
> # end of RCU Subsystem
>=20
> CONFIG_IKCONFIG=3Dy
> CONFIG_IKCONFIG_PROC=3Dy
> # CONFIG_IKHEADERS is not set
> CONFIG_LOG_BUF_SHIFT=3D17
> CONFIG_LOG_CPU_MAX_BUF_SHIFT=3D12
> CONFIG_PRINTK_SAFE_LOG_BUF_SHIFT=3D13
> CONFIG_GENERIC_SCHED_CLOCK=3Dy
>=20
> #
> # Scheduler features
> #
> # CONFIG_UCLAMP_TASK is not set
> # end of Scheduler features
>=20
> CONFIG_ARCH_SUPPORTS_NUMA_BALANCING=3Dy
> CONFIG_CC_HAS_INT128=3Dy
> CONFIG_ARCH_SUPPORTS_INT128=3Dy
> CONFIG_NUMA_BALANCING=3Dy
> CONFIG_NUMA_BALANCING_DEFAULT_ENABLED=3Dy
> CONFIG_CGROUPS=3Dy
> CONFIG_PAGE_COUNTER=3Dy
> CONFIG_MEMCG=3Dy
> CONFIG_MEMCG_SWAP=3Dy
> CONFIG_MEMCG_KMEM=3Dy
> CONFIG_BLK_CGROUP=3Dy
> CONFIG_CGROUP_WRITEBACK=3Dy
> CONFIG_CGROUP_SCHED=3Dy
> CONFIG_FAIR_GROUP_SCHED=3Dy
> # CONFIG_CFS_BANDWIDTH is not set
> # CONFIG_RT_GROUP_SCHED is not set
> CONFIG_CGROUP_PIDS=3Dy
> # CONFIG_CGROUP_RDMA is not set
> # CONFIG_CGROUP_FREEZER is not set
> CONFIG_CGROUP_HUGETLB=3Dy
> CONFIG_CPUSETS=3Dy
> CONFIG_PROC_PID_CPUSET=3Dy
> CONFIG_CGROUP_DEVICE=3Dy
> CONFIG_CGROUP_CPUACCT=3Dy
> CONFIG_CGROUP_PERF=3Dy
> # CONFIG_CGROUP_DEBUG is not set
> CONFIG_NAMESPACES=3Dy
> CONFIG_UTS_NS=3Dy
> CONFIG_TIME_NS=3Dy
> CONFIG_IPC_NS=3Dy
> CONFIG_USER_NS=3Dy
> CONFIG_PID_NS=3Dy
> CONFIG_NET_NS=3Dy
> # CONFIG_CHECKPOINT_RESTORE is not set
> CONFIG_SCHED_AUTOGROUP=3Dy
> # CONFIG_SYSFS_DEPRECATED is not set
> CONFIG_RELAY=3Dy
> CONFIG_BLK_DEV_INITRD=3Dy
> CONFIG_INITRAMFS_SOURCE=3D""
> CONFIG_RD_GZIP=3Dy
> CONFIG_RD_BZIP2=3Dy
> CONFIG_RD_LZMA=3Dy
> CONFIG_RD_XZ=3Dy
> CONFIG_RD_LZO=3Dy
> CONFIG_RD_LZ4=3Dy
> CONFIG_RD_ZSTD=3Dy
> # CONFIG_BOOT_CONFIG is not set
> CONFIG_CC_OPTIMIZE_FOR_PERFORMANCE=3Dy
> # CONFIG_CC_OPTIMIZE_FOR_SIZE is not set
> CONFIG_SYSCTL=3Dy
> CONFIG_HAVE_UID16=3Dy
> CONFIG_SYSCTL_EXCEPTION_TRACE=3Dy
> CONFIG_BPF=3Dy
> # CONFIG_EXPERT is not set
> CONFIG_UID16=3Dy
> CONFIG_MULTIUSER=3Dy
> CONFIG_SYSFS_SYSCALL=3Dy
> CONFIG_FHANDLE=3Dy
> CONFIG_POSIX_TIMERS=3Dy
> CONFIG_PRINTK=3Dy
> CONFIG_PRINTK_NMI=3Dy
> CONFIG_BUG=3Dy
> CONFIG_ELF_CORE=3Dy
> CONFIG_BASE_FULL=3Dy
> CONFIG_FUTEX=3Dy
> CONFIG_FUTEX_PI=3Dy
> CONFIG_HAVE_FUTEX_CMPXCHG=3Dy
> CONFIG_EPOLL=3Dy
> CONFIG_SIGNALFD=3Dy
> CONFIG_TIMERFD=3Dy
> CONFIG_EVENTFD=3Dy
> CONFIG_SHMEM=3Dy
> CONFIG_AIO=3Dy
> CONFIG_IO_URING=3Dy
> CONFIG_ADVISE_SYSCALLS=3Dy
> CONFIG_MEMBARRIER=3Dy
> CONFIG_KALLSYMS=3Dy
> CONFIG_KALLSYMS_ALL=3Dy
> CONFIG_KALLSYMS_BASE_RELATIVE=3Dy
> # CONFIG_BPF_SYSCALL is not set
> CONFIG_ARCH_WANT_DEFAULT_BPF_JIT=3Dy
> CONFIG_BPF_JIT_DEFAULT_ON=3Dy
> # CONFIG_USERFAULTFD is not set
> CONFIG_ARCH_HAS_MEMBARRIER_SYNC_CORE=3Dy
> CONFIG_RSEQ=3Dy
> # CONFIG_EMBEDDED is not set
> CONFIG_HAVE_PERF_EVENTS=3Dy
>=20
> #
> # Kernel Performance Events And Counters
> #
> CONFIG_PERF_EVENTS=3Dy
> # CONFIG_DEBUG_PERF_USE_VMALLOC is not set
> # end of Kernel Performance Events And Counters
>=20
> CONFIG_VM_EVENT_COUNTERS=3Dy
> CONFIG_SLUB_DEBUG=3Dy
> # CONFIG_COMPAT_BRK is not set
> # CONFIG_SLAB is not set
> CONFIG_SLUB=3Dy
> CONFIG_SLAB_MERGE_DEFAULT=3Dy
> # CONFIG_SLAB_FREELIST_RANDOM is not set
> # CONFIG_SLAB_FREELIST_HARDENED is not set
> # CONFIG_SHUFFLE_PAGE_ALLOCATOR is not set
> CONFIG_SLUB_CPU_PARTIAL=3Dy
> CONFIG_SYSTEM_DATA_VERIFICATION=3Dy
> CONFIG_PROFILING=3Dy
> CONFIG_TRACEPOINTS=3Dy
> # end of General setup
>=20
> CONFIG_ARM64=3Dy
> CONFIG_64BIT=3Dy
> CONFIG_MMU=3Dy
> CONFIG_ARM64_PAGE_SHIFT=3D12
> CONFIG_ARM64_CONT_PTE_SHIFT=3D4
> CONFIG_ARM64_CONT_PMD_SHIFT=3D4
> CONFIG_ARCH_MMAP_RND_BITS_MIN=3D18
> CONFIG_ARCH_MMAP_RND_BITS_MAX=3D33
> CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MIN=3D11
> CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX=3D16
> CONFIG_STACKTRACE_SUPPORT=3Dy
> CONFIG_ILLEGAL_POINTER_VALUE=3D0xdead000000000000
> CONFIG_LOCKDEP_SUPPORT=3Dy
> CONFIG_TRACE_IRQFLAGS_SUPPORT=3Dy
> CONFIG_GENERIC_BUG=3Dy
> CONFIG_GENERIC_BUG_RELATIVE_POINTERS=3Dy
> CONFIG_GENERIC_HWEIGHT=3Dy
> CONFIG_GENERIC_CSUM=3Dy
> CONFIG_GENERIC_CALIBRATE_DELAY=3Dy
> CONFIG_ZONE_DMA=3Dy
> CONFIG_ZONE_DMA32=3Dy
> CONFIG_ARCH_ENABLE_MEMORY_HOTPLUG=3Dy
> CONFIG_ARCH_ENABLE_MEMORY_HOTREMOVE=3Dy
> CONFIG_SMP=3Dy
> CONFIG_KERNEL_MODE_NEON=3Dy
> CONFIG_FIX_EARLYCON_MEM=3Dy
> CONFIG_PGTABLE_LEVELS=3D4
> CONFIG_ARCH_SUPPORTS_UPROBES=3Dy
> CONFIG_ARCH_PROC_KCORE_TEXT=3Dy
>=20
> #
> # Platform selection
> #
> CONFIG_ARCH_ACTIONS=3Dy
> CONFIG_ARCH_AGILEX=3Dy
> CONFIG_ARCH_SUNXI=3Dy
> CONFIG_ARCH_ALPINE=3Dy
> CONFIG_ARCH_BCM2835=3Dy
> CONFIG_ARCH_BCM_IPROC=3Dy
> CONFIG_ARCH_BERLIN=3Dy
> # CONFIG_ARCH_BITMAIN is not set
> CONFIG_ARCH_BRCMSTB=3Dy
> CONFIG_ARCH_EXYNOS=3Dy
> # CONFIG_ARCH_SPARX5 is not set
> CONFIG_ARCH_K3=3Dy
> CONFIG_ARCH_LAYERSCAPE=3Dy
> CONFIG_ARCH_LG1K=3Dy
> CONFIG_ARCH_HISI=3Dy
> # CONFIG_ARCH_KEEMBAY is not set
> CONFIG_ARCH_MEDIATEK=3Dy
> CONFIG_ARCH_MESON=3Dy
> CONFIG_ARCH_MVEBU=3Dy
> CONFIG_ARCH_MXC=3Dy
> CONFIG_ARCH_QCOM=3Dy
> # CONFIG_ARCH_REALTEK is not set
> CONFIG_ARCH_RENESAS=3Dy
> CONFIG_ARCH_ROCKCHIP=3Dy
> CONFIG_ARCH_S32=3Dy
> CONFIG_ARCH_SEATTLE=3Dy
> CONFIG_ARCH_STRATIX10=3Dy
> CONFIG_ARCH_SYNQUACER=3Dy
> CONFIG_ARCH_TEGRA=3Dy
> CONFIG_ARCH_SPRD=3Dy
> CONFIG_ARCH_THUNDER=3Dy
> CONFIG_ARCH_THUNDER2=3Dy
> CONFIG_ARCH_UNIPHIER=3Dy
> CONFIG_ARCH_VEXPRESS=3Dy
> # CONFIG_ARCH_VISCONTI is not set
> CONFIG_ARCH_XGENE=3Dy
> CONFIG_ARCH_ZX=3Dy
> CONFIG_ARCH_ZYNQMP=3Dy
> # end of Platform selection
>=20
> #
> # Kernel Features
> #
>=20
> #
> # ARM errata workarounds via the alternatives framework
> #
> CONFIG_ARM64_WORKAROUND_CLEAN_CACHE=3Dy
> CONFIG_ARM64_ERRATUM_826319=3Dy
> CONFIG_ARM64_ERRATUM_827319=3Dy
> CONFIG_ARM64_ERRATUM_824069=3Dy
> CONFIG_ARM64_ERRATUM_819472=3Dy
> CONFIG_ARM64_ERRATUM_832075=3Dy
> CONFIG_ARM64_ERRATUM_834220=3Dy
> CONFIG_ARM64_ERRATUM_845719=3Dy
> CONFIG_ARM64_ERRATUM_843419=3Dy
> CONFIG_ARM64_ERRATUM_1024718=3Dy
> CONFIG_ARM64_ERRATUM_1418040=3Dy
> CONFIG_ARM64_WORKAROUND_SPECULATIVE_AT=3Dy
> CONFIG_ARM64_ERRATUM_1165522=3Dy
> CONFIG_ARM64_ERRATUM_1319367=3Dy
> CONFIG_ARM64_ERRATUM_1530923=3Dy
> CONFIG_ARM64_WORKAROUND_REPEAT_TLBI=3Dy
> CONFIG_ARM64_ERRATUM_1286807=3Dy
> CONFIG_ARM64_ERRATUM_1463225=3Dy
> CONFIG_ARM64_ERRATUM_1542419=3Dy
> CONFIG_ARM64_ERRATUM_1508412=3Dy
> CONFIG_CAVIUM_ERRATUM_22375=3Dy
> CONFIG_CAVIUM_ERRATUM_23144=3Dy
> CONFIG_CAVIUM_ERRATUM_23154=3Dy
> CONFIG_CAVIUM_ERRATUM_27456=3Dy
> CONFIG_CAVIUM_ERRATUM_30115=3Dy
> CONFIG_CAVIUM_TX2_ERRATUM_219=3Dy
> CONFIG_FUJITSU_ERRATUM_010001=3Dy
> CONFIG_HISILICON_ERRATUM_161600802=3Dy
> CONFIG_QCOM_FALKOR_ERRATUM_1003=3Dy
> CONFIG_QCOM_FALKOR_ERRATUM_1009=3Dy
> CONFIG_QCOM_QDF2400_ERRATUM_0065=3Dy
> CONFIG_QCOM_FALKOR_ERRATUM_E1041=3Dy
> CONFIG_SOCIONEXT_SYNQUACER_PREITS=3Dy
> # end of ARM errata workarounds via the alternatives framework
>=20
> CONFIG_ARM64_4K_PAGES=3Dy
> # CONFIG_ARM64_16K_PAGES is not set
> # CONFIG_ARM64_64K_PAGES is not set
> # CONFIG_ARM64_VA_BITS_39 is not set
> CONFIG_ARM64_VA_BITS_48=3Dy
> CONFIG_ARM64_VA_BITS=3D48
> CONFIG_ARM64_PA_BITS_48=3Dy
> CONFIG_ARM64_PA_BITS=3D48
> # CONFIG_CPU_BIG_ENDIAN is not set
> CONFIG_CPU_LITTLE_ENDIAN=3Dy
> CONFIG_SCHED_MC=3Dy
> CONFIG_SCHED_SMT=3Dy
> CONFIG_NR_CPUS=3D256
> CONFIG_HOTPLUG_CPU=3Dy
> CONFIG_NUMA=3Dy
> CONFIG_NODES_SHIFT=3D2
> CONFIG_USE_PERCPU_NUMA_NODE_ID=3Dy
> CONFIG_HAVE_SETUP_PER_CPU_AREA=3Dy
> CONFIG_NEED_PER_CPU_EMBED_FIRST_CHUNK=3Dy
> CONFIG_HOLES_IN_ZONE=3Dy
> # CONFIG_HZ_100 is not set
> CONFIG_HZ_250=3Dy
> # CONFIG_HZ_300 is not set
> # CONFIG_HZ_1000 is not set
> CONFIG_HZ=3D250
> CONFIG_SCHED_HRTICK=3Dy
> CONFIG_ARCH_SPARSEMEM_ENABLE=3Dy
> CONFIG_ARCH_SPARSEMEM_DEFAULT=3Dy
> CONFIG_ARCH_SELECT_MEMORY_MODEL=3Dy
> CONFIG_HW_PERF_EVENTS=3Dy
> CONFIG_SYS_SUPPORTS_HUGETLBFS=3Dy
> CONFIG_ARCH_WANT_HUGE_PMD_SHARE=3Dy
> CONFIG_ARCH_HAS_CACHE_LINE_SIZE=3Dy
> CONFIG_ARCH_ENABLE_SPLIT_PMD_PTLOCK=3Dy
> CONFIG_PARAVIRT=3Dy
> # CONFIG_PARAVIRT_TIME_ACCOUNTING is not set
> CONFIG_KEXEC=3Dy
> # CONFIG_KEXEC_FILE is not set
> CONFIG_CRASH_DUMP=3Dy
> CONFIG_XEN_DOM0=3Dy
> CONFIG_XEN=3Dy
> CONFIG_FORCE_MAX_ZONEORDER=3D11
> CONFIG_UNMAP_KERNEL_AT_EL0=3Dy
> CONFIG_RODATA_FULL_DEFAULT_ENABLED=3Dy
> # CONFIG_ARM64_SW_TTBR0_PAN is not set
> CONFIG_ARM64_TAGGED_ADDR_ABI=3Dy
> CONFIG_COMPAT=3Dy
> CONFIG_KUSER_HELPERS=3Dy
> # CONFIG_ARMV8_DEPRECATED is not set
>=20
> #
> # ARMv8.1 architectural features
> #
> CONFIG_ARM64_HW_AFDBM=3Dy
> CONFIG_ARM64_PAN=3Dy
> CONFIG_ARM64_LSE_ATOMICS=3Dy
> CONFIG_ARM64_USE_LSE_ATOMICS=3Dy
> CONFIG_ARM64_VHE=3Dy
> # end of ARMv8.1 architectural features
>=20
> #
> # ARMv8.2 architectural features
> #
> CONFIG_ARM64_UAO=3Dy
> # CONFIG_ARM64_PMEM is not set
> CONFIG_ARM64_RAS_EXTN=3Dy
> CONFIG_ARM64_CNP=3Dy
> # end of ARMv8.2 architectural features
>=20
> #
> # ARMv8.3 architectural features
> #
> CONFIG_CC_HAS_SIGN_RETURN_ADDRESS=3Dy
> CONFIG_AS_HAS_PAC=3Dy
> # end of ARMv8.3 architectural features
>=20
> #
> # ARMv8.4 architectural features
> #
> CONFIG_ARM64_AMU_EXTN=3Dy
> # end of ARMv8.4 architectural features
>=20
> #
> # ARMv8.5 architectural features
> #
> CONFIG_ARM64_BTI=3Dy
> CONFIG_ARM64_E0PD=3Dy
> CONFIG_ARCH_RANDOM=3Dy
> # end of ARMv8.5 architectural features
>=20
> CONFIG_ARM64_SVE=3Dy
> CONFIG_ARM64_MODULE_PLTS=3Dy
> # CONFIG_ARM64_PSEUDO_NMI is not set
> CONFIG_RELOCATABLE=3Dy
> CONFIG_RANDOMIZE_BASE=3Dy
> CONFIG_RANDOMIZE_MODULE_REGION_FULL=3Dy
> # end of Kernel Features
>=20
> #
> # Boot options
> #
> # CONFIG_ARM64_ACPI_PARKING_PROTOCOL is not set
> CONFIG_CMDLINE=3D""
> CONFIG_EFI_STUB=3Dy
> CONFIG_EFI=3Dy
> CONFIG_DMI=3Dy
> # end of Boot options
>=20
> CONFIG_SYSVIPC_COMPAT=3Dy
> CONFIG_ARCH_ENABLE_HUGEPAGE_MIGRATION=3Dy
> CONFIG_ARCH_ENABLE_THP_MIGRATION=3Dy
>=20
> #
> # Power management options
> #
> CONFIG_SUSPEND=3Dy
> CONFIG_SUSPEND_FREEZER=3Dy
> CONFIG_HIBERNATE_CALLBACKS=3Dy
> CONFIG_HIBERNATION=3Dy
> CONFIG_HIBERNATION_SNAPSHOT_DEV=3Dy
> CONFIG_PM_STD_PARTITION=3D""
> CONFIG_PM_SLEEP=3Dy
> CONFIG_PM_SLEEP_SMP=3Dy
> # CONFIG_PM_AUTOSLEEP is not set
> # CONFIG_PM_WAKELOCKS is not set
> CONFIG_PM=3Dy
> # CONFIG_PM_DEBUG is not set
> CONFIG_PM_CLK=3Dy
> CONFIG_PM_GENERIC_DOMAINS=3Dy
> CONFIG_WQ_POWER_EFFICIENT_DEFAULT=3Dy
> CONFIG_PM_GENERIC_DOMAINS_SLEEP=3Dy
> CONFIG_PM_GENERIC_DOMAINS_OF=3Dy
> CONFIG_CPU_PM=3Dy
> CONFIG_ENERGY_MODEL=3Dy
> CONFIG_ARCH_HIBERNATION_POSSIBLE=3Dy
> CONFIG_ARCH_HIBERNATION_HEADER=3Dy
> CONFIG_ARCH_SUSPEND_POSSIBLE=3Dy
> # end of Power management options
>=20
> #
> # CPU Power Management
> #
>=20
> #
> # CPU Idle
> #
> CONFIG_CPU_IDLE=3Dy
> CONFIG_CPU_IDLE_MULTIPLE_DRIVERS=3Dy
> # CONFIG_CPU_IDLE_GOV_LADDER is not set
> CONFIG_CPU_IDLE_GOV_MENU=3Dy
> # CONFIG_CPU_IDLE_GOV_TEO is not set
> CONFIG_DT_IDLE_STATES=3Dy
>=20
> #
> # ARM CPU Idle Drivers
> #
> CONFIG_ARM_CPUIDLE=3Dy
> CONFIG_ARM_PSCI_CPUIDLE=3Dy
> CONFIG_ARM_PSCI_CPUIDLE_DOMAIN=3Dy
> # end of ARM CPU Idle Drivers
> # end of CPU Idle
>=20
> #
> # CPU Frequency scaling
> #
> CONFIG_CPU_FREQ=3Dy
> CONFIG_CPU_FREQ_GOV_ATTR_SET=3Dy
> CONFIG_CPU_FREQ_GOV_COMMON=3Dy
> CONFIG_CPU_FREQ_STAT=3Dy
> CONFIG_CPU_FREQ_DEFAULT_GOV_PERFORMANCE=3Dy
> # CONFIG_CPU_FREQ_DEFAULT_GOV_POWERSAVE is not set
> # CONFIG_CPU_FREQ_DEFAULT_GOV_USERSPACE is not set
> # CONFIG_CPU_FREQ_DEFAULT_GOV_ONDEMAND is not set
> # CONFIG_CPU_FREQ_DEFAULT_GOV_CONSERVATIVE is not set
> # CONFIG_CPU_FREQ_DEFAULT_GOV_SCHEDUTIL is not set
> CONFIG_CPU_FREQ_GOV_PERFORMANCE=3Dy
> CONFIG_CPU_FREQ_GOV_POWERSAVE=3Dm
> CONFIG_CPU_FREQ_GOV_USERSPACE=3Dy
> CONFIG_CPU_FREQ_GOV_ONDEMAND=3Dy
> CONFIG_CPU_FREQ_GOV_CONSERVATIVE=3Dm
> CONFIG_CPU_FREQ_GOV_SCHEDUTIL=3Dy
>=20
> #
> # CPU frequency scaling drivers
> #
> CONFIG_CPUFREQ_DT=3Dy
> CONFIG_CPUFREQ_DT_PLATDEV=3Dy
> CONFIG_ACPI_CPPC_CPUFREQ=3Dm
> CONFIG_ARM_ALLWINNER_SUN50I_CPUFREQ_NVMEM=3Dm
> CONFIG_ARM_ARMADA_37XX_CPUFREQ=3Dy
> # CONFIG_ARM_ARMADA_8K_CPUFREQ is not set
> CONFIG_ARM_SCPI_CPUFREQ=3Dy
> CONFIG_ARM_BRCMSTB_AVS_CPUFREQ=3Dy
> CONFIG_ARM_IMX_CPUFREQ_DT=3Dm
> # CONFIG_ARM_MEDIATEK_CPUFREQ is not set
> CONFIG_ARM_QCOM_CPUFREQ_NVMEM=3Dy
> CONFIG_ARM_QCOM_CPUFREQ_HW=3Dy
> CONFIG_ARM_RASPBERRYPI_CPUFREQ=3Dm
> CONFIG_ARM_TEGRA20_CPUFREQ=3Dy
> CONFIG_ARM_TEGRA124_CPUFREQ=3Dy
> CONFIG_ARM_TEGRA186_CPUFREQ=3Dy
> CONFIG_ARM_TEGRA194_CPUFREQ=3Dy
> CONFIG_QORIQ_CPUFREQ=3Dy
> # end of CPU Frequency scaling
> # end of CPU Power Management
>=20
> #
> # Firmware Drivers
> #
> # CONFIG_ARM_SCMI_PROTOCOL is not set
> CONFIG_ARM_SCPI_PROTOCOL=3Dy
> CONFIG_ARM_SCPI_POWER_DOMAIN=3Dy
> # CONFIG_ARM_SDE_INTERFACE is not set
> CONFIG_DMIID=3Dy
> # CONFIG_DMI_SYSFS is not set
> # CONFIG_ISCSI_IBFT is not set
> CONFIG_RASPBERRYPI_FIRMWARE=3Dy
> # CONFIG_FW_CFG_SYSFS is not set
> CONFIG_INTEL_STRATIX10_SERVICE=3Dy
> CONFIG_INTEL_STRATIX10_RSU=3Dm
> CONFIG_QCOM_SCM=3Dy
> # CONFIG_QCOM_SCM_DOWNLOAD_MODE_DEFAULT is not set
> CONFIG_TI_SCI_PROTOCOL=3Dy
> # CONFIG_TURRIS_MOX_RWTM is not set
> CONFIG_TEE_BNXT_FW=3Dy
> # CONFIG_GOOGLE_FIRMWARE is not set
>=20
> #
> # EFI (Extensible Firmware Interface) Support
> #
> CONFIG_EFI_ESRT=3Dy
> CONFIG_EFI_VARS_PSTORE=3Dy
> # CONFIG_EFI_VARS_PSTORE_DEFAULT_DISABLE is not set
> CONFIG_EFI_PARAMS_FROM_FDT=3Dy
> CONFIG_EFI_RUNTIME_WRAPPERS=3Dy
> CONFIG_EFI_GENERIC_STUB=3Dy
> CONFIG_EFI_ARMSTUB_DTB_LOADER=3Dy
> CONFIG_EFI_GENERIC_STUB_INITRD_CMDLINE_LOADER=3Dy
> # CONFIG_EFI_BOOTLOADER_CONTROL is not set
> CONFIG_EFI_CAPSULE_LOADER=3Dy
> # CONFIG_EFI_TEST is not set
> # CONFIG_RESET_ATTACK_MITIGATION is not set
> # CONFIG_EFI_DISABLE_PCI_DMA is not set
> # end of EFI (Extensible Firmware Interface) Support
>=20
> CONFIG_UEFI_CPER=3Dy
> CONFIG_UEFI_CPER_ARM=3Dy
> CONFIG_EFI_EARLYCON=3Dy
> CONFIG_EFI_CUSTOM_SSDT_OVERLAYS=3Dy
> # CONFIG_IMX_DSP is not set
> CONFIG_IMX_SCU=3Dy
> CONFIG_IMX_SCU_PD=3Dy
> CONFIG_MESON_SM=3Dy
> CONFIG_ARM_PSCI_FW=3Dy
> # CONFIG_ARM_PSCI_CHECKER is not set
> CONFIG_HAVE_ARM_SMCCC=3Dy
> CONFIG_HAVE_ARM_SMCCC_DISCOVERY=3Dy
> CONFIG_ARM_SMCCC_SOC_ID=3Dy
>=20
> #
> # Tegra firmware driver
> #
> CONFIG_TEGRA_IVC=3Dy
> CONFIG_TEGRA_BPMP=3Dy
> # end of Tegra firmware driver
>=20
> #
> # Zynq MPSoC Firmware Drivers
> #
> CONFIG_ZYNQMP_FIRMWARE=3Dy
> # CONFIG_ZYNQMP_FIRMWARE_DEBUG is not set
> # end of Zynq MPSoC Firmware Drivers
> # end of Firmware Drivers
>=20
> CONFIG_ARCH_SUPPORTS_ACPI=3Dy
> CONFIG_ACPI=3Dy
> CONFIG_ACPI_GENERIC_GSI=3Dy
> CONFIG_ACPI_CCA_REQUIRED=3Dy
> # CONFIG_ACPI_DEBUGGER is not set
> CONFIG_ACPI_SPCR_TABLE=3Dy
> # CONFIG_ACPI_EC_DEBUGFS is not set
> CONFIG_ACPI_AC=3Dy
> CONFIG_ACPI_BATTERY=3Dy
> CONFIG_ACPI_BUTTON=3Dy
> CONFIG_ACPI_FAN=3Dy
> # CONFIG_ACPI_TAD is not set
> # CONFIG_ACPI_DOCK is not set
> CONFIG_ACPI_PROCESSOR_IDLE=3Dy
> CONFIG_ACPI_MCFG=3Dy
> CONFIG_ACPI_CPPC_LIB=3Dy
> CONFIG_ACPI_PROCESSOR=3Dy
> # CONFIG_ACPI_IPMI is not set
> CONFIG_ACPI_HOTPLUG_CPU=3Dy
> CONFIG_ACPI_THERMAL=3Dy
> CONFIG_ARCH_HAS_ACPI_TABLE_UPGRADE=3Dy
> CONFIG_ACPI_TABLE_UPGRADE=3Dy
> # CONFIG_ACPI_DEBUG is not set
> # CONFIG_ACPI_PCI_SLOT is not set
> CONFIG_ACPI_CONTAINER=3Dy
> CONFIG_ACPI_HED=3Dy
> # CONFIG_ACPI_CUSTOM_METHOD is not set
> # CONFIG_ACPI_BGRT is not set
> CONFIG_ACPI_REDUCED_HARDWARE_ONLY=3Dy
> CONFIG_ACPI_NUMA=3Dy
> # CONFIG_ACPI_HMAT is not set
> CONFIG_HAVE_ACPI_APEI=3Dy
> CONFIG_ACPI_APEI=3Dy
> CONFIG_ACPI_APEI_GHES=3Dy
> CONFIG_ACPI_APEI_SEA=3Dy
> CONFIG_ACPI_APEI_MEMORY_FAILURE=3Dy
> CONFIG_ACPI_APEI_EINJ=3Dy
> # CONFIG_ACPI_APEI_ERST_DEBUG is not set
> # CONFIG_ACPI_CONFIGFS is not set
> CONFIG_ACPI_IORT=3Dy
> CONFIG_ACPI_GTDT=3Dy
> CONFIG_ACPI_PPTT=3Dy
> # CONFIG_PMIC_OPREGION is not set
> CONFIG_IRQ_BYPASS_MANAGER=3Dy
> CONFIG_VIRTUALIZATION=3Dy
> CONFIG_KVM=3Dy
> CONFIG_HAVE_KVM_IRQCHIP=3Dy
> CONFIG_HAVE_KVM_IRQFD=3Dy
> CONFIG_HAVE_KVM_IRQ_ROUTING=3Dy
> CONFIG_HAVE_KVM_EVENTFD=3Dy
> CONFIG_KVM_MMIO=3Dy
> CONFIG_HAVE_KVM_MSI=3Dy
> CONFIG_HAVE_KVM_CPU_RELAX_INTERCEPT=3Dy
> CONFIG_KVM_VFIO=3Dy
> CONFIG_HAVE_KVM_ARCH_TLB_FLUSH_ALL=3Dy
> CONFIG_KVM_GENERIC_DIRTYLOG_READ_PROTECT=3Dy
> CONFIG_HAVE_KVM_IRQ_BYPASS=3Dy
> CONFIG_HAVE_KVM_VCPU_RUN_PID_CHANGE=3Dy
> CONFIG_KVM_ARM_PMU=3Dy
> CONFIG_ARM64_CRYPTO=3Dy
> CONFIG_CRYPTO_SHA256_ARM64=3Dy
> CONFIG_CRYPTO_SHA512_ARM64=3Dm
> CONFIG_CRYPTO_SHA1_ARM64_CE=3Dy
> CONFIG_CRYPTO_SHA2_ARM64_CE=3Dy
> CONFIG_CRYPTO_SHA512_ARM64_CE=3Dm
> CONFIG_CRYPTO_SHA3_ARM64=3Dm
> CONFIG_CRYPTO_SM3_ARM64_CE=3Dm
> # CONFIG_CRYPTO_SM4_ARM64_CE is not set
> CONFIG_CRYPTO_GHASH_ARM64_CE=3Dy
> CONFIG_CRYPTO_CRCT10DIF_ARM64_CE=3Dm
> CONFIG_CRYPTO_AES_ARM64=3Dy
> CONFIG_CRYPTO_AES_ARM64_CE=3Dy
> CONFIG_CRYPTO_AES_ARM64_CE_CCM=3Dy
> CONFIG_CRYPTO_AES_ARM64_CE_BLK=3Dy
> CONFIG_CRYPTO_AES_ARM64_NEON_BLK=3Dm
> CONFIG_CRYPTO_CHACHA20_NEON=3Dm
> # CONFIG_CRYPTO_POLY1305_NEON is not set
> # CONFIG_CRYPTO_NHPOLY1305_NEON is not set
> CONFIG_CRYPTO_AES_ARM64_BS=3Dm
>=20
> #
> # General architecture-dependent options
> #
> CONFIG_CRASH_CORE=3Dy
> CONFIG_KEXEC_CORE=3Dy
> CONFIG_SET_FS=3Dy
> # CONFIG_KPROBES is not set
> CONFIG_JUMP_LABEL=3Dy
> # CONFIG_STATIC_KEYS_SELFTEST is not set
> CONFIG_UPROBES=3Dy
> CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=3Dy
> CONFIG_HAVE_KPROBES=3Dy
> CONFIG_HAVE_KRETPROBES=3Dy
> CONFIG_HAVE_FUNCTION_ERROR_INJECTION=3Dy
> CONFIG_HAVE_NMI=3Dy
> CONFIG_HAVE_ARCH_TRACEHOOK=3Dy
> CONFIG_HAVE_DMA_CONTIGUOUS=3Dy
> CONFIG_GENERIC_SMP_IDLE_THREAD=3Dy
> CONFIG_GENERIC_IDLE_POLL_SETUP=3Dy
> CONFIG_ARCH_HAS_FORTIFY_SOURCE=3Dy
> CONFIG_ARCH_HAS_KEEPINITRD=3Dy
> CONFIG_ARCH_HAS_SET_MEMORY=3Dy
> CONFIG_ARCH_HAS_SET_DIRECT_MAP=3Dy
> CONFIG_HAVE_ARCH_THREAD_STRUCT_WHITELIST=3Dy
> CONFIG_HAVE_ASM_MODVERSIONS=3Dy
> CONFIG_HAVE_REGS_AND_STACK_ACCESS_API=3Dy
> CONFIG_HAVE_RSEQ=3Dy
> CONFIG_HAVE_FUNCTION_ARG_ACCESS_API=3Dy
> CONFIG_HAVE_HW_BREAKPOINT=3Dy
> CONFIG_HAVE_PERF_REGS=3Dy
> CONFIG_HAVE_PERF_USER_STACK_DUMP=3Dy
> CONFIG_HAVE_ARCH_JUMP_LABEL=3Dy
> CONFIG_HAVE_ARCH_JUMP_LABEL_RELATIVE=3Dy
> CONFIG_MMU_GATHER_TABLE_FREE=3Dy
> CONFIG_MMU_GATHER_RCU_TABLE_FREE=3Dy
> CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG=3Dy
> CONFIG_HAVE_ALIGNED_STRUCT_PAGE=3Dy
> CONFIG_HAVE_CMPXCHG_LOCAL=3Dy
> CONFIG_HAVE_CMPXCHG_DOUBLE=3Dy
> CONFIG_ARCH_WANT_COMPAT_IPC_PARSE_VERSION=3Dy
> CONFIG_HAVE_ARCH_SECCOMP=3Dy
> CONFIG_HAVE_ARCH_SECCOMP_FILTER=3Dy
> CONFIG_SECCOMP=3Dy
> CONFIG_SECCOMP_FILTER=3Dy
> CONFIG_HAVE_ARCH_STACKLEAK=3Dy
> CONFIG_HAVE_STACKPROTECTOR=3Dy
> CONFIG_STACKPROTECTOR=3Dy
> CONFIG_STACKPROTECTOR_STRONG=3Dy
> CONFIG_HAVE_CONTEXT_TRACKING=3Dy
> CONFIG_HAVE_VIRT_CPU_ACCOUNTING_GEN=3Dy
> CONFIG_HAVE_IRQ_TIME_ACCOUNTING=3Dy
> CONFIG_HAVE_MOVE_PUD=3Dy
> CONFIG_HAVE_MOVE_PMD=3Dy
> CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE=3Dy
> CONFIG_HAVE_ARCH_HUGE_VMAP=3Dy
> CONFIG_HAVE_MOD_ARCH_SPECIFIC=3Dy
> CONFIG_MODULES_USE_ELF_RELA=3Dy
> CONFIG_ARCH_HAS_ELF_RANDOMIZE=3Dy
> CONFIG_HAVE_ARCH_MMAP_RND_BITS=3Dy
> CONFIG_ARCH_MMAP_RND_BITS=3D18
> CONFIG_HAVE_ARCH_MMAP_RND_COMPAT_BITS=3Dy
> CONFIG_ARCH_MMAP_RND_COMPAT_BITS=3D11
> CONFIG_ARCH_WANT_DEFAULT_TOPDOWN_MMAP_LAYOUT=3Dy
> CONFIG_CLONE_BACKWARDS=3Dy
> CONFIG_OLD_SIGSUSPEND3=3Dy
> CONFIG_COMPAT_OLD_SIGACTION=3Dy
> CONFIG_COMPAT_32BIT_TIME=3Dy
> CONFIG_HAVE_ARCH_VMAP_STACK=3Dy
> CONFIG_VMAP_STACK=3Dy
> CONFIG_ARCH_HAS_STRICT_KERNEL_RWX=3Dy
> CONFIG_STRICT_KERNEL_RWX=3Dy
> CONFIG_ARCH_HAS_STRICT_MODULE_RWX=3Dy
> CONFIG_STRICT_MODULE_RWX=3Dy
> CONFIG_HAVE_ARCH_COMPILER_H=3Dy
> CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=3Dy
> CONFIG_ARCH_USE_MEMREMAP_PROT=3Dy
> # CONFIG_LOCK_EVENT_COUNTS is not set
> CONFIG_ARCH_HAS_RELR=3Dy
> CONFIG_ARCH_SUPPORTS_DEBUG_PAGEALLOC=3Dy
> CONFIG_HAVE_ARCH_PFN_VALID=3Dy
>=20
> #
> # GCOV-based kernel profiling
> #
> # CONFIG_GCOV_KERNEL is not set
> CONFIG_ARCH_HAS_GCOV_PROFILE_ALL=3Dy
> # end of GCOV-based kernel profiling
>=20
> CONFIG_HAVE_GCC_PLUGINS=3Dy
> CONFIG_GCC_PLUGINS=3Dy
> # CONFIG_GCC_PLUGIN_LATENT_ENTROPY is not set
> # CONFIG_GCC_PLUGIN_RANDSTRUCT is not set
> # end of General architecture-dependent options
>=20
> CONFIG_RT_MUTEXES=3Dy
> CONFIG_BASE_SMALL=3D0
> CONFIG_MODULES=3Dy
> # CONFIG_MODULE_FORCE_LOAD is not set
> CONFIG_MODULE_UNLOAD=3Dy
> # CONFIG_MODULE_FORCE_UNLOAD is not set
> # CONFIG_MODVERSIONS is not set
> # CONFIG_MODULE_SRCVERSION_ALL is not set
> # CONFIG_MODULE_SIG is not set
> # CONFIG_MODULE_COMPRESS is not set
> # CONFIG_MODULE_ALLOW_MISSING_NAMESPACE_IMPORTS is not set
> # CONFIG_UNUSED_SYMBOLS is not set
> # CONFIG_TRIM_UNUSED_KSYMS is not set
> CONFIG_MODULES_TREE_LOOKUP=3Dy
> CONFIG_BLOCK=3Dy
> CONFIG_BLK_SCSI_REQUEST=3Dy
> CONFIG_BLK_DEV_BSG=3Dy
> CONFIG_BLK_DEV_BSGLIB=3Dy
> CONFIG_BLK_DEV_INTEGRITY=3Dy
> CONFIG_BLK_DEV_INTEGRITY_T10=3Dy
> # CONFIG_BLK_DEV_ZONED is not set
> # CONFIG_BLK_DEV_THROTTLING is not set
> # CONFIG_BLK_CMDLINE_PARSER is not set
> # CONFIG_BLK_WBT is not set
> # CONFIG_BLK_CGROUP_IOLATENCY is not set
> # CONFIG_BLK_CGROUP_IOCOST is not set
> CONFIG_BLK_DEBUG_FS=3Dy
> # CONFIG_BLK_SED_OPAL is not set
> # CONFIG_BLK_INLINE_ENCRYPTION is not set
>=20
> #
> # Partition Types
> #
> # CONFIG_PARTITION_ADVANCED is not set
> CONFIG_MSDOS_PARTITION=3Dy
> CONFIG_EFI_PARTITION=3Dy
> # end of Partition Types
>=20
> CONFIG_BLOCK_COMPAT=3Dy
> CONFIG_BLK_MQ_PCI=3Dy
> CONFIG_BLK_MQ_VIRTIO=3Dy
> CONFIG_BLK_PM=3Dy
>=20
> #
> # IO Schedulers
> #
> CONFIG_MQ_IOSCHED_DEADLINE=3Dy
> CONFIG_MQ_IOSCHED_KYBER=3Dy
> # CONFIG_IOSCHED_BFQ is not set
> # end of IO Schedulers
>=20
> CONFIG_PREEMPT_NOTIFIERS=3Dy
> CONFIG_ASN1=3Dy
> CONFIG_UNINLINE_SPIN_UNLOCK=3Dy
> CONFIG_ARCH_SUPPORTS_ATOMIC_RMW=3Dy
> CONFIG_MUTEX_SPIN_ON_OWNER=3Dy
> CONFIG_RWSEM_SPIN_ON_OWNER=3Dy
> CONFIG_LOCK_SPIN_ON_OWNER=3Dy
> CONFIG_ARCH_USE_QUEUED_SPINLOCKS=3Dy
> CONFIG_QUEUED_SPINLOCKS=3Dy
> CONFIG_ARCH_USE_QUEUED_RWLOCKS=3Dy
> CONFIG_QUEUED_RWLOCKS=3Dy
> CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE=3Dy
> CONFIG_ARCH_HAS_SYSCALL_WRAPPER=3Dy
> CONFIG_FREEZER=3Dy
>=20
> #
> # Executable file formats
> #
> CONFIG_BINFMT_ELF=3Dy
> CONFIG_COMPAT_BINFMT_ELF=3Dy
> CONFIG_ARCH_BINFMT_ELF_STATE=3Dy
> CONFIG_ARCH_HAVE_ELF_PROT=3Dy
> CONFIG_ARCH_USE_GNU_PROPERTY=3Dy
> CONFIG_ELFCORE=3Dy
> # CONFIG_CORE_DUMP_DEFAULT_ELF_HEADERS is not set
> CONFIG_BINFMT_SCRIPT=3Dy
> # CONFIG_BINFMT_MISC is not set
> CONFIG_COREDUMP=3Dy
> # end of Executable file formats
>=20
> #
> # Memory Management options
> #
> CONFIG_SELECT_MEMORY_MODEL=3Dy
> CONFIG_SPARSEMEM_MANUAL=3Dy
> CONFIG_SPARSEMEM=3Dy
> CONFIG_NEED_MULTIPLE_NODES=3Dy
> CONFIG_SPARSEMEM_EXTREME=3Dy
> CONFIG_SPARSEMEM_VMEMMAP_ENABLE=3Dy
> CONFIG_SPARSEMEM_VMEMMAP=3Dy
> CONFIG_HAVE_FAST_GUP=3Dy
> CONFIG_ARCH_KEEP_MEMBLOCK=3Dy
> CONFIG_MEMORY_ISOLATION=3Dy
> # CONFIG_MEMORY_HOTPLUG is not set
> CONFIG_SPLIT_PTLOCK_CPUS=3D4
> CONFIG_MEMORY_BALLOON=3Dy
> CONFIG_BALLOON_COMPACTION=3Dy
> CONFIG_COMPACTION=3Dy
> CONFIG_PAGE_REPORTING=3Dy
> CONFIG_MIGRATION=3Dy
> CONFIG_CONTIG_ALLOC=3Dy
> CONFIG_PHYS_ADDR_T_64BIT=3Dy
> CONFIG_BOUNCE=3Dy
> CONFIG_MMU_NOTIFIER=3Dy
> CONFIG_KSM=3Dy
> CONFIG_DEFAULT_MMAP_MIN_ADDR=3D4096
> CONFIG_ARCH_SUPPORTS_MEMORY_FAILURE=3Dy
> CONFIG_MEMORY_FAILURE=3Dy
> # CONFIG_HWPOISON_INJECT is not set
> CONFIG_TRANSPARENT_HUGEPAGE=3Dy
> CONFIG_TRANSPARENT_HUGEPAGE_ALWAYS=3Dy
> # CONFIG_TRANSPARENT_HUGEPAGE_MADVISE is not set
> # CONFIG_CLEANCACHE is not set
> # CONFIG_FRONTSWAP is not set
> CONFIG_CMA=3Dy
> # CONFIG_CMA_DEBUG is not set
> # CONFIG_CMA_DEBUGFS is not set
> CONFIG_CMA_AREAS=3D7
> # CONFIG_ZPOOL is not set
> # CONFIG_ZBUD is not set
> # CONFIG_ZSMALLOC is not set
> CONFIG_GENERIC_EARLY_IOREMAP=3Dy
> # CONFIG_DEFERRED_STRUCT_PAGE_INIT is not set
> # CONFIG_IDLE_PAGE_TRACKING is not set
> CONFIG_ARCH_HAS_PTE_DEVMAP=3Dy
> CONFIG_FRAME_VECTOR=3Dy
> # CONFIG_PERCPU_STATS is not set
> # CONFIG_GUP_TEST is not set
> # CONFIG_READ_ONLY_THP_FOR_FS is not set
> CONFIG_ARCH_HAS_PTE_SPECIAL=3Dy
> # end of Memory Management options
>=20
> CONFIG_NET=3Dy
> CONFIG_NET_INGRESS=3Dy
> CONFIG_SKB_EXTENSIONS=3Dy
>=20
> #
> # Networking options
> #
> CONFIG_PACKET=3Dy
> # CONFIG_PACKET_DIAG is not set
> CONFIG_UNIX=3Dy
> CONFIG_UNIX_SCM=3Dy
> # CONFIG_UNIX_DIAG is not set
> # CONFIG_TLS is not set
> # CONFIG_XFRM_USER is not set
> # CONFIG_NET_KEY is not set
> CONFIG_INET=3Dy
> CONFIG_IP_MULTICAST=3Dy
> # CONFIG_IP_ADVANCED_ROUTER is not set
> CONFIG_IP_PNP=3Dy
> CONFIG_IP_PNP_DHCP=3Dy
> CONFIG_IP_PNP_BOOTP=3Dy
> # CONFIG_IP_PNP_RARP is not set
> # CONFIG_NET_IPIP is not set
> # CONFIG_NET_IPGRE_DEMUX is not set
> CONFIG_NET_IP_TUNNEL=3Dm
> # CONFIG_IP_MROUTE is not set
> # CONFIG_SYN_COOKIES is not set
> # CONFIG_NET_IPVTI is not set
> # CONFIG_NET_FOU is not set
> # CONFIG_NET_FOU_IP_TUNNELS is not set
> # CONFIG_INET_AH is not set
> # CONFIG_INET_ESP is not set
> # CONFIG_INET_IPCOMP is not set
> CONFIG_INET_TUNNEL=3Dm
> CONFIG_INET_DIAG=3Dy
> CONFIG_INET_TCP_DIAG=3Dy
> # CONFIG_INET_UDP_DIAG is not set
> # CONFIG_INET_RAW_DIAG is not set
> # CONFIG_INET_DIAG_DESTROY is not set
> # CONFIG_TCP_CONG_ADVANCED is not set
> CONFIG_TCP_CONG_CUBIC=3Dy
> CONFIG_DEFAULT_TCP_CONG=3D"cubic"
> # CONFIG_TCP_MD5SIG is not set
> CONFIG_IPV6=3Dm
> # CONFIG_IPV6_ROUTER_PREF is not set
> # CONFIG_IPV6_OPTIMISTIC_DAD is not set
> # CONFIG_INET6_AH is not set
> # CONFIG_INET6_ESP is not set
> # CONFIG_INET6_IPCOMP is not set
> # CONFIG_IPV6_MIP6 is not set
> # CONFIG_IPV6_ILA is not set
> # CONFIG_IPV6_VTI is not set
> CONFIG_IPV6_SIT=3Dm
> # CONFIG_IPV6_SIT_6RD is not set
> CONFIG_IPV6_NDISC_NODETYPE=3Dy
> # CONFIG_IPV6_TUNNEL is not set
> # CONFIG_IPV6_MULTIPLE_TABLES is not set
> # CONFIG_IPV6_MROUTE is not set
> # CONFIG_IPV6_SEG6_LWTUNNEL is not set
> # CONFIG_IPV6_SEG6_HMAC is not set
> # CONFIG_IPV6_RPL_LWTUNNEL is not set
> # CONFIG_NETLABEL is not set
> # CONFIG_MPTCP is not set
> # CONFIG_NETWORK_SECMARK is not set
> CONFIG_NET_PTP_CLASSIFY=3Dy
> # CONFIG_NETWORK_PHY_TIMESTAMPING is not set
> CONFIG_NETFILTER=3Dy
> CONFIG_NETFILTER_ADVANCED=3Dy
> # CONFIG_BRIDGE_NETFILTER is not set
>=20
> #
> # Core Netfilter Configuration
> #
> CONFIG_NETFILTER_INGRESS=3Dy
> CONFIG_NETFILTER_NETLINK=3Dm
> # CONFIG_NETFILTER_NETLINK_ACCT is not set
> # CONFIG_NETFILTER_NETLINK_QUEUE is not set
> # CONFIG_NETFILTER_NETLINK_LOG is not set
> # CONFIG_NETFILTER_NETLINK_OSF is not set
> CONFIG_NF_CONNTRACK=3Dm
> CONFIG_NF_LOG_COMMON=3Dm
> # CONFIG_NF_LOG_NETDEV is not set
> # CONFIG_NF_CONNTRACK_MARK is not set
> # CONFIG_NF_CONNTRACK_ZONES is not set
> CONFIG_NF_CONNTRACK_PROCFS=3Dy
> CONFIG_NF_CONNTRACK_EVENTS=3Dy
> CONFIG_NF_CONNTRACK_TIMEOUT=3Dy
> # CONFIG_NF_CONNTRACK_TIMESTAMP is not set
> # CONFIG_NF_CONNTRACK_LABELS is not set
> CONFIG_NF_CT_PROTO_DCCP=3Dy
> CONFIG_NF_CT_PROTO_SCTP=3Dy
> CONFIG_NF_CT_PROTO_UDPLITE=3Dy
> # CONFIG_NF_CONNTRACK_AMANDA is not set
> # CONFIG_NF_CONNTRACK_FTP is not set
> # CONFIG_NF_CONNTRACK_H323 is not set
> # CONFIG_NF_CONNTRACK_IRC is not set
> # CONFIG_NF_CONNTRACK_NETBIOS_NS is not set
> # CONFIG_NF_CONNTRACK_SNMP is not set
> # CONFIG_NF_CONNTRACK_PPTP is not set
> # CONFIG_NF_CONNTRACK_SANE is not set
> # CONFIG_NF_CONNTRACK_SIP is not set
> # CONFIG_NF_CONNTRACK_TFTP is not set
> # CONFIG_NF_CT_NETLINK is not set
> CONFIG_NF_CT_NETLINK_TIMEOUT=3Dm
> CONFIG_NF_NAT=3Dm
> CONFIG_NF_NAT_MASQUERADE=3Dy
> # CONFIG_NF_TABLES is not set
> CONFIG_NETFILTER_XTABLES=3Dm
>=20
> #
> # Xtables combined modules
> #
> # CONFIG_NETFILTER_XT_MARK is not set
> # CONFIG_NETFILTER_XT_CONNMARK is not set
>=20
> #
> # Xtables targets
> #
> # CONFIG_NETFILTER_XT_TARGET_AUDIT is not set
> CONFIG_NETFILTER_XT_TARGET_CHECKSUM=3Dm
> # CONFIG_NETFILTER_XT_TARGET_CLASSIFY is not set
> # CONFIG_NETFILTER_XT_TARGET_CONNMARK is not set
> # CONFIG_NETFILTER_XT_TARGET_DSCP is not set
> # CONFIG_NETFILTER_XT_TARGET_HL is not set
> # CONFIG_NETFILTER_XT_TARGET_HMARK is not set
> # CONFIG_NETFILTER_XT_TARGET_IDLETIMER is not set
> # CONFIG_NETFILTER_XT_TARGET_LED is not set
> CONFIG_NETFILTER_XT_TARGET_LOG=3Dm
> # CONFIG_NETFILTER_XT_TARGET_MARK is not set
> CONFIG_NETFILTER_XT_NAT=3Dm
> # CONFIG_NETFILTER_XT_TARGET_NETMAP is not set
> # CONFIG_NETFILTER_XT_TARGET_NFLOG is not set
> # CONFIG_NETFILTER_XT_TARGET_NFQUEUE is not set
> # CONFIG_NETFILTER_XT_TARGET_RATEEST is not set
> # CONFIG_NETFILTER_XT_TARGET_REDIRECT is not set
> CONFIG_NETFILTER_XT_TARGET_MASQUERADE=3Dm
> # CONFIG_NETFILTER_XT_TARGET_TEE is not set
> # CONFIG_NETFILTER_XT_TARGET_TPROXY is not set
> # CONFIG_NETFILTER_XT_TARGET_TCPMSS is not set
> # CONFIG_NETFILTER_XT_TARGET_TCPOPTSTRIP is not set
>=20
> #
> # Xtables matches
> #
> CONFIG_NETFILTER_XT_MATCH_ADDRTYPE=3Dm
> # CONFIG_NETFILTER_XT_MATCH_BPF is not set
> # CONFIG_NETFILTER_XT_MATCH_CGROUP is not set
> # CONFIG_NETFILTER_XT_MATCH_CLUSTER is not set
> # CONFIG_NETFILTER_XT_MATCH_COMMENT is not set
> # CONFIG_NETFILTER_XT_MATCH_CONNBYTES is not set
> # CONFIG_NETFILTER_XT_MATCH_CONNLABEL is not set
> # CONFIG_NETFILTER_XT_MATCH_CONNLIMIT is not set
> # CONFIG_NETFILTER_XT_MATCH_CONNMARK is not set
> CONFIG_NETFILTER_XT_MATCH_CONNTRACK=3Dm
> # CONFIG_NETFILTER_XT_MATCH_CPU is not set
> # CONFIG_NETFILTER_XT_MATCH_DCCP is not set
> # CONFIG_NETFILTER_XT_MATCH_DEVGROUP is not set
> # CONFIG_NETFILTER_XT_MATCH_DSCP is not set
> # CONFIG_NETFILTER_XT_MATCH_ECN is not set
> # CONFIG_NETFILTER_XT_MATCH_ESP is not set
> # CONFIG_NETFILTER_XT_MATCH_HASHLIMIT is not set
> # CONFIG_NETFILTER_XT_MATCH_HELPER is not set
> # CONFIG_NETFILTER_XT_MATCH_HL is not set
> # CONFIG_NETFILTER_XT_MATCH_IPCOMP is not set
> # CONFIG_NETFILTER_XT_MATCH_IPRANGE is not set
> # CONFIG_NETFILTER_XT_MATCH_L2TP is not set
> # CONFIG_NETFILTER_XT_MATCH_LENGTH is not set
> # CONFIG_NETFILTER_XT_MATCH_LIMIT is not set
> # CONFIG_NETFILTER_XT_MATCH_MAC is not set
> # CONFIG_NETFILTER_XT_MATCH_MARK is not set
> # CONFIG_NETFILTER_XT_MATCH_MULTIPORT is not set
> # CONFIG_NETFILTER_XT_MATCH_NFACCT is not set
> # CONFIG_NETFILTER_XT_MATCH_OSF is not set
> # CONFIG_NETFILTER_XT_MATCH_OWNER is not set
> # CONFIG_NETFILTER_XT_MATCH_PKTTYPE is not set
> # CONFIG_NETFILTER_XT_MATCH_QUOTA is not set
> # CONFIG_NETFILTER_XT_MATCH_RATEEST is not set
> # CONFIG_NETFILTER_XT_MATCH_REALM is not set
> # CONFIG_NETFILTER_XT_MATCH_RECENT is not set
> # CONFIG_NETFILTER_XT_MATCH_SCTP is not set
> # CONFIG_NETFILTER_XT_MATCH_SOCKET is not set
> # CONFIG_NETFILTER_XT_MATCH_STATE is not set
> # CONFIG_NETFILTER_XT_MATCH_STATISTIC is not set
> # CONFIG_NETFILTER_XT_MATCH_STRING is not set
> # CONFIG_NETFILTER_XT_MATCH_TCPMSS is not set
> # CONFIG_NETFILTER_XT_MATCH_TIME is not set
> # CONFIG_NETFILTER_XT_MATCH_U32 is not set
> # end of Core Netfilter Configuration
>=20
> # CONFIG_IP_SET is not set
> # CONFIG_IP_VS is not set
>=20
> #
> # IP: Netfilter Configuration
> #
> CONFIG_NF_DEFRAG_IPV4=3Dm
> # CONFIG_NF_SOCKET_IPV4 is not set
> # CONFIG_NF_TPROXY_IPV4 is not set
> # CONFIG_NF_DUP_IPV4 is not set
> # CONFIG_NF_LOG_ARP is not set
> CONFIG_NF_LOG_IPV4=3Dm
> CONFIG_NF_REJECT_IPV4=3Dm
> CONFIG_IP_NF_IPTABLES=3Dm
> # CONFIG_IP_NF_MATCH_AH is not set
> # CONFIG_IP_NF_MATCH_ECN is not set
> # CONFIG_IP_NF_MATCH_RPFILTER is not set
> # CONFIG_IP_NF_MATCH_TTL is not set
> CONFIG_IP_NF_FILTER=3Dm
> CONFIG_IP_NF_TARGET_REJECT=3Dm
> # CONFIG_IP_NF_TARGET_SYNPROXY is not set
> CONFIG_IP_NF_NAT=3Dm
> CONFIG_IP_NF_TARGET_MASQUERADE=3Dm
> # CONFIG_IP_NF_TARGET_NETMAP is not set
> # CONFIG_IP_NF_TARGET_REDIRECT is not set
> CONFIG_IP_NF_MANGLE=3Dm
> # CONFIG_IP_NF_TARGET_CLUSTERIP is not set
> # CONFIG_IP_NF_TARGET_ECN is not set
> # CONFIG_IP_NF_TARGET_TTL is not set
> # CONFIG_IP_NF_RAW is not set
> # CONFIG_IP_NF_SECURITY is not set
> # CONFIG_IP_NF_ARPTABLES is not set
> # end of IP: Netfilter Configuration
>=20
> #
> # IPv6: Netfilter Configuration
> #
> # CONFIG_NF_SOCKET_IPV6 is not set
> # CONFIG_NF_TPROXY_IPV6 is not set
> # CONFIG_NF_DUP_IPV6 is not set
> CONFIG_NF_REJECT_IPV6=3Dm
> CONFIG_NF_LOG_IPV6=3Dm
> CONFIG_IP6_NF_IPTABLES=3Dm
> # CONFIG_IP6_NF_MATCH_AH is not set
> # CONFIG_IP6_NF_MATCH_EUI64 is not set
> # CONFIG_IP6_NF_MATCH_FRAG is not set
> # CONFIG_IP6_NF_MATCH_OPTS is not set
> # CONFIG_IP6_NF_MATCH_HL is not set
> # CONFIG_IP6_NF_MATCH_IPV6HEADER is not set
> # CONFIG_IP6_NF_MATCH_MH is not set
> # CONFIG_IP6_NF_MATCH_RPFILTER is not set
> # CONFIG_IP6_NF_MATCH_RT is not set
> # CONFIG_IP6_NF_MATCH_SRH is not set
> # CONFIG_IP6_NF_TARGET_HL is not set
> CONFIG_IP6_NF_FILTER=3Dm
> CONFIG_IP6_NF_TARGET_REJECT=3Dm
> # CONFIG_IP6_NF_TARGET_SYNPROXY is not set
> CONFIG_IP6_NF_MANGLE=3Dm
> # CONFIG_IP6_NF_RAW is not set
> # CONFIG_IP6_NF_SECURITY is not set
> CONFIG_IP6_NF_NAT=3Dm
> CONFIG_IP6_NF_TARGET_MASQUERADE=3Dm
> # CONFIG_IP6_NF_TARGET_NPT is not set
> # end of IPv6: Netfilter Configuration
>=20
> CONFIG_NF_DEFRAG_IPV6=3Dm
> # CONFIG_NF_CONNTRACK_BRIDGE is not set
> # CONFIG_BRIDGE_NF_EBTABLES is not set
> # CONFIG_BPFILTER is not set
> # CONFIG_IP_DCCP is not set
> # CONFIG_IP_SCTP is not set
> # CONFIG_RDS is not set
> # CONFIG_TIPC is not set
> # CONFIG_ATM is not set
> # CONFIG_L2TP is not set
> CONFIG_STP=3Dm
> CONFIG_GARP=3Dm
> CONFIG_MRP=3Dm
> CONFIG_BRIDGE=3Dm
> CONFIG_BRIDGE_IGMP_SNOOPING=3Dy
> CONFIG_BRIDGE_VLAN_FILTERING=3Dy
> # CONFIG_BRIDGE_MRP is not set
> # CONFIG_BRIDGE_CFM is not set
> CONFIG_HAVE_NET_DSA=3Dy
> CONFIG_NET_DSA=3Dm
> # CONFIG_NET_DSA_TAG_AR9331 is not set
> # CONFIG_NET_DSA_TAG_BRCM is not set
> # CONFIG_NET_DSA_TAG_BRCM_PREPEND is not set
> # CONFIG_NET_DSA_TAG_HELLCREEK is not set
> # CONFIG_NET_DSA_TAG_GSWIP is not set
> # CONFIG_NET_DSA_TAG_DSA is not set
> # CONFIG_NET_DSA_TAG_EDSA is not set
> # CONFIG_NET_DSA_TAG_MTK is not set
> # CONFIG_NET_DSA_TAG_KSZ is not set
> # CONFIG_NET_DSA_TAG_RTL4_A is not set
> CONFIG_NET_DSA_TAG_OCELOT=3Dm
> # CONFIG_NET_DSA_TAG_QCA is not set
> # CONFIG_NET_DSA_TAG_LAN9303 is not set
> # CONFIG_NET_DSA_TAG_SJA1105 is not set
> # CONFIG_NET_DSA_TAG_TRAILER is not set
> CONFIG_VLAN_8021Q=3Dm
> CONFIG_VLAN_8021Q_GVRP=3Dy
> CONFIG_VLAN_8021Q_MVRP=3Dy
> # CONFIG_DECNET is not set
> CONFIG_LLC=3Dm
> # CONFIG_LLC2 is not set
> # CONFIG_ATALK is not set
> # CONFIG_X25 is not set
> # CONFIG_LAPB is not set
> # CONFIG_PHONET is not set
> # CONFIG_6LOWPAN is not set
> # CONFIG_IEEE802154 is not set
> # CONFIG_NET_SCHED is not set
> # CONFIG_DCB is not set
> CONFIG_DNS_RESOLVER=3Dy
> # CONFIG_BATMAN_ADV is not set
> # CONFIG_OPENVSWITCH is not set
> # CONFIG_VSOCKETS is not set
> # CONFIG_NETLINK_DIAG is not set
> # CONFIG_MPLS is not set
> # CONFIG_NET_NSH is not set
> # CONFIG_HSR is not set
> CONFIG_NET_SWITCHDEV=3Dy
> # CONFIG_NET_L3_MASTER_DEV is not set
> CONFIG_QRTR=3Dm
> CONFIG_QRTR_SMD=3Dm
> CONFIG_QRTR_TUN=3Dm
> # CONFIG_NET_NCSI is not set
> CONFIG_RPS=3Dy
> CONFIG_RFS_ACCEL=3Dy
> CONFIG_XPS=3Dy
> # CONFIG_CGROUP_NET_PRIO is not set
> # CONFIG_CGROUP_NET_CLASSID is not set
> CONFIG_NET_RX_BUSY_POLL=3Dy
> CONFIG_BQL=3Dy
> CONFIG_BPF_JIT=3Dy
> CONFIG_NET_FLOW_LIMIT=3Dy
>=20
> #
> # Network testing
> #
> # CONFIG_NET_PKTGEN is not set
> CONFIG_NET_DROP_MONITOR=3Dy
> # end of Network testing
> # end of Networking options
>=20
> # CONFIG_HAMRADIO is not set
> CONFIG_CAN=3Dm
> CONFIG_CAN_RAW=3Dm
> CONFIG_CAN_BCM=3Dm
> CONFIG_CAN_GW=3Dm
> # CONFIG_CAN_J1939 is not set
> # CONFIG_CAN_ISOTP is not set
>=20
> #
> # CAN Device Drivers
> #
> # CONFIG_CAN_VCAN is not set
> # CONFIG_CAN_VXCAN is not set
> # CONFIG_CAN_SLCAN is not set
> CONFIG_CAN_DEV=3Dm
> CONFIG_CAN_CALC_BITTIMING=3Dy
> CONFIG_CAN_FLEXCAN=3Dm
> # CONFIG_CAN_GRCAN is not set
> # CONFIG_CAN_KVASER_PCIEFD is not set
> # CONFIG_CAN_XILINXCAN is not set
> # CONFIG_CAN_C_CAN is not set
> # CONFIG_CAN_CC770 is not set
> # CONFIG_CAN_IFI_CANFD is not set
> # CONFIG_CAN_M_CAN is not set
> # CONFIG_CAN_PEAK_PCIEFD is not set
> CONFIG_CAN_RCAR=3Dm
> CONFIG_CAN_RCAR_CANFD=3Dm
> # CONFIG_CAN_SJA1000 is not set
> # CONFIG_CAN_SOFTING is not set
>=20
> #
> # CAN SPI interfaces
> #
> # CONFIG_CAN_HI311X is not set
> # CONFIG_CAN_MCP251X is not set
> # CONFIG_CAN_MCP251XFD is not set
> # end of CAN SPI interfaces
>=20
> #
> # CAN USB interfaces
> #
> # CONFIG_CAN_8DEV_USB is not set
> # CONFIG_CAN_EMS_USB is not set
> # CONFIG_CAN_ESD_USB2 is not set
> # CONFIG_CAN_GS_USB is not set
> # CONFIG_CAN_KVASER_USB is not set
> # CONFIG_CAN_MCBA_USB is not set
> # CONFIG_CAN_PEAK_USB is not set
> # CONFIG_CAN_UCAN is not set
> # end of CAN USB interfaces
>=20
> # CONFIG_CAN_DEBUG_DEVICES is not set
> # end of CAN Device Drivers
>=20
> CONFIG_BT=3Dm
> CONFIG_BT_BREDR=3Dy
> # CONFIG_BT_RFCOMM is not set
> # CONFIG_BT_BNEP is not set
> CONFIG_BT_HIDP=3Dm
> # CONFIG_BT_HS is not set
> # CONFIG_BT_LE is not set
> CONFIG_BT_LEDS=3Dy
> # CONFIG_BT_MSFTEXT is not set
> # CONFIG_BT_DEBUGFS is not set
> # CONFIG_BT_SELFTEST is not set
> # CONFIG_BT_FEATURE_DEBUG is not set
>=20
> #
> # Bluetooth device drivers
> #
> CONFIG_BT_INTEL=3Dm
> CONFIG_BT_BCM=3Dm
> CONFIG_BT_RTL=3Dm
> CONFIG_BT_QCA=3Dm
> CONFIG_BT_HCIBTUSB=3Dm
> # CONFIG_BT_HCIBTUSB_AUTOSUSPEND is not set
> CONFIG_BT_HCIBTUSB_BCM=3Dy
> # CONFIG_BT_HCIBTUSB_MTK is not set
> CONFIG_BT_HCIBTUSB_RTL=3Dy
> # CONFIG_BT_HCIBTSDIO is not set
> CONFIG_BT_HCIUART=3Dm
> CONFIG_BT_HCIUART_SERDEV=3Dy
> CONFIG_BT_HCIUART_H4=3Dy
> # CONFIG_BT_HCIUART_NOKIA is not set
> # CONFIG_BT_HCIUART_BCSP is not set
> # CONFIG_BT_HCIUART_ATH3K is not set
> CONFIG_BT_HCIUART_LL=3Dy
> # CONFIG_BT_HCIUART_3WIRE is not set
> # CONFIG_BT_HCIUART_INTEL is not set
> CONFIG_BT_HCIUART_BCM=3Dy
> # CONFIG_BT_HCIUART_RTL is not set
> CONFIG_BT_HCIUART_QCA=3Dy
> # CONFIG_BT_HCIUART_AG6XX is not set
> # CONFIG_BT_HCIUART_MRVL is not set
> # CONFIG_BT_HCIBCM203X is not set
> # CONFIG_BT_HCIBPA10X is not set
> # CONFIG_BT_HCIBFUSB is not set
> # CONFIG_BT_HCIVHCI is not set
> # CONFIG_BT_MRVL is not set
> # CONFIG_BT_ATH3K is not set
> # CONFIG_BT_MTKSDIO is not set
> # CONFIG_BT_MTKUART is not set
> # end of Bluetooth device drivers
>=20
> # CONFIG_AF_RXRPC is not set
> # CONFIG_AF_KCM is not set
> CONFIG_WIRELESS=3Dy
> CONFIG_CFG80211=3Dm
> # CONFIG_NL80211_TESTMODE is not set
> # CONFIG_CFG80211_DEVELOPER_WARNINGS is not set
> CONFIG_CFG80211_REQUIRE_SIGNED_REGDB=3Dy
> CONFIG_CFG80211_USE_KERNEL_REGDB_KEYS=3Dy
> CONFIG_CFG80211_DEFAULT_PS=3Dy
> # CONFIG_CFG80211_DEBUGFS is not set
> CONFIG_CFG80211_CRDA_SUPPORT=3Dy
> # CONFIG_CFG80211_WEXT is not set
> CONFIG_MAC80211=3Dm
> CONFIG_MAC80211_HAS_RC=3Dy
> CONFIG_MAC80211_RC_MINSTREL=3Dy
> CONFIG_MAC80211_RC_DEFAULT_MINSTREL=3Dy
> CONFIG_MAC80211_RC_DEFAULT=3D"minstrel_ht"
> # CONFIG_MAC80211_MESH is not set
> CONFIG_MAC80211_LEDS=3Dy
> # CONFIG_MAC80211_DEBUGFS is not set
> # CONFIG_MAC80211_MESSAGE_TRACING is not set
> # CONFIG_MAC80211_DEBUG_MENU is not set
> CONFIG_MAC80211_STA_HASH_MAX_SIZE=3D0
> CONFIG_RFKILL=3Dm
> CONFIG_RFKILL_LEDS=3Dy
> CONFIG_RFKILL_INPUT=3Dy
> # CONFIG_RFKILL_GPIO is not set
> CONFIG_NET_9P=3Dy
> CONFIG_NET_9P_VIRTIO=3Dy
> # CONFIG_NET_9P_XEN is not set
> # CONFIG_NET_9P_DEBUG is not set
> # CONFIG_CAIF is not set
> # CONFIG_CEPH_LIB is not set
> # CONFIG_NFC is not set
> # CONFIG_PSAMPLE is not set
> # CONFIG_NET_IFE is not set
> # CONFIG_LWTUNNEL is not set
> CONFIG_DST_CACHE=3Dy
> CONFIG_GRO_CELLS=3Dy
> CONFIG_NET_DEVLINK=3Dy
> CONFIG_PAGE_POOL=3Dy
> CONFIG_FAILOVER=3Dy
> CONFIG_ETHTOOL_NETLINK=3Dy
> CONFIG_HAVE_EBPF_JIT=3Dy
>=20
> #
> # Device Drivers
> #
> CONFIG_ARM_AMBA=3Dy
> CONFIG_TEGRA_AHB=3Dy
> CONFIG_HAVE_PCI=3Dy
> CONFIG_PCI=3Dy
> CONFIG_PCI_DOMAINS=3Dy
> CONFIG_PCI_DOMAINS_GENERIC=3Dy
> CONFIG_PCI_SYSCALL=3Dy
> CONFIG_PCIEPORTBUS=3Dy
> # CONFIG_HOTPLUG_PCI_PCIE is not set
> # CONFIG_PCIEAER is not set
> CONFIG_PCIEASPM=3Dy
> CONFIG_PCIEASPM_DEFAULT=3Dy
> # CONFIG_PCIEASPM_POWERSAVE is not set
> # CONFIG_PCIEASPM_POWER_SUPERSAVE is not set
> # CONFIG_PCIEASPM_PERFORMANCE is not set
> CONFIG_PCIE_PME=3Dy
> # CONFIG_PCIE_PTM is not set
> # CONFIG_PCIE_BW is not set
> CONFIG_PCI_MSI=3Dy
> CONFIG_PCI_MSI_IRQ_DOMAIN=3Dy
> CONFIG_PCI_MSI_ARCH_FALLBACKS=3Dy
> CONFIG_PCI_QUIRKS=3Dy
> # CONFIG_PCI_DEBUG is not set
> # CONFIG_PCI_REALLOC_ENABLE_AUTO is not set
> # CONFIG_PCI_STUB is not set
> # CONFIG_PCI_PF_STUB is not set
> CONFIG_PCI_ATS=3Dy
> CONFIG_PCI_ECAM=3Dy
> CONFIG_PCI_BRIDGE_EMUL=3Dy
> CONFIG_PCI_IOV=3Dy
> # CONFIG_PCI_PRI is not set
> CONFIG_PCI_PASID=3Dy
> CONFIG_PCI_LABEL=3Dy
> CONFIG_HOTPLUG_PCI=3Dy
> CONFIG_HOTPLUG_PCI_ACPI=3Dy
> # CONFIG_HOTPLUG_PCI_ACPI_IBM is not set
> # CONFIG_HOTPLUG_PCI_CPCI is not set
> # CONFIG_HOTPLUG_PCI_SHPC is not set
>=20
> #
> # PCI controller drivers
> #
> CONFIG_PCI_AARDVARK=3Dy
> # CONFIG_PCIE_XILINX_NWL is not set
> # CONFIG_PCI_FTPCI100 is not set
> CONFIG_PCI_TEGRA=3Dy
> # CONFIG_PCIE_RCAR is not set
> CONFIG_PCIE_RCAR_HOST=3Dy
> CONFIG_PCI_HOST_COMMON=3Dy
> CONFIG_PCI_HOST_GENERIC=3Dy
> # CONFIG_PCIE_XILINX is not set
> # CONFIG_PCIE_XILINX_CPM is not set
> CONFIG_PCI_XGENE=3Dy
> CONFIG_PCI_XGENE_MSI=3Dy
> CONFIG_PCIE_IPROC=3Dy
> CONFIG_PCIE_IPROC_PLATFORM=3Dy
> CONFIG_PCIE_IPROC_MSI=3Dy
> CONFIG_PCIE_ALTERA=3Dy
> CONFIG_PCIE_ALTERA_MSI=3Dy
> CONFIG_PCI_HOST_THUNDER_PEM=3Dy
> CONFIG_PCI_HOST_THUNDER_ECAM=3Dy
> CONFIG_PCIE_ROCKCHIP=3Dy
> CONFIG_PCIE_ROCKCHIP_HOST=3Dm
> # CONFIG_PCIE_MEDIATEK is not set
> CONFIG_PCIE_BRCMSTB=3Dm
> # CONFIG_PCIE_HISI_ERR is not set
>=20
> #
> # DesignWare PCI Core Support
> #
> CONFIG_PCIE_DW=3Dy
> CONFIG_PCIE_DW_HOST=3Dy
> # CONFIG_PCIE_DW_PLAT_HOST is not set
> # CONFIG_PCI_IMX6 is not set
> # CONFIG_PCI_KEYSTONE_HOST is not set
> CONFIG_PCI_LAYERSCAPE=3Dy
> CONFIG_PCI_HISI=3Dy
> CONFIG_PCIE_QCOM=3Dy
> CONFIG_PCIE_ARMADA_8K=3Dy
> CONFIG_PCIE_KIRIN=3Dy
> CONFIG_PCIE_HISI_STB=3Dy
> # CONFIG_PCI_MESON is not set
> CONFIG_PCIE_TEGRA194=3Dm
> CONFIG_PCIE_TEGRA194_HOST=3Dm
> # CONFIG_PCIE_UNIPHIER is not set
> # CONFIG_PCIE_AL is not set
> # end of DesignWare PCI Core Support
>=20
> #
> # Mobiveil PCIe Core Support
> #
> CONFIG_PCIE_MOBIVEIL=3Dy
> CONFIG_PCIE_MOBIVEIL_HOST=3Dy
> # CONFIG_PCIE_MOBIVEIL_PLAT is not set
> CONFIG_PCIE_LAYERSCAPE_GEN4=3Dy
> # end of Mobiveil PCIe Core Support
>=20
> #
> # Cadence PCIe controllers support
> #
> # CONFIG_PCIE_CADENCE_PLAT_HOST is not set
> # CONFIG_PCI_J721E_HOST is not set
> # end of Cadence PCIe controllers support
> # end of PCI controller drivers
>=20
> #
> # PCI Endpoint
> #
> # CONFIG_PCI_ENDPOINT is not set
> # end of PCI Endpoint
>=20
> #
> # PCI switch controller drivers
> #
> # CONFIG_PCI_SW_SWITCHTEC is not set
> # end of PCI switch controller drivers
>=20
> # CONFIG_PCCARD is not set
> # CONFIG_RAPIDIO is not set
>=20
> #
> # Generic Driver Options
> #
> # CONFIG_UEVENT_HELPER is not set
> CONFIG_DEVTMPFS=3Dy
> CONFIG_DEVTMPFS_MOUNT=3Dy
> CONFIG_STANDALONE=3Dy
> CONFIG_PREVENT_FIRMWARE_BUILD=3Dy
>=20
> #
> # Firmware loader
> #
> CONFIG_FW_LOADER=3Dy
> CONFIG_FW_LOADER_PAGED_BUF=3Dy
> CONFIG_EXTRA_FIRMWARE=3D""
> CONFIG_FW_LOADER_USER_HELPER=3Dy
> CONFIG_FW_LOADER_USER_HELPER_FALLBACK=3Dy
> # CONFIG_FW_LOADER_COMPRESS is not set
> CONFIG_FW_CACHE=3Dy
> # end of Firmware loader
>=20
> CONFIG_WANT_DEV_COREDUMP=3Dy
> CONFIG_ALLOW_DEV_COREDUMP=3Dy
> CONFIG_DEV_COREDUMP=3Dy
> # CONFIG_DEBUG_DRIVER is not set
> # CONFIG_DEBUG_DEVRES is not set
> # CONFIG_DEBUG_TEST_DRIVER_REMOVE is not set
> # CONFIG_PM_QOS_KUNIT_TEST is not set
> CONFIG_TEST_ASYNC_DRIVER_PROBE=3Dm
> # CONFIG_KUNIT_DRIVER_PE_TEST is not set
> CONFIG_SYS_HYPERVISOR=3Dy
> CONFIG_GENERIC_CPU_AUTOPROBE=3Dy
> CONFIG_GENERIC_CPU_VULNERABILITIES=3Dy
> CONFIG_SOC_BUS=3Dy
> CONFIG_REGMAP=3Dy
> CONFIG_REGMAP_I2C=3Dy
> CONFIG_REGMAP_SLIMBUS=3Dm
> CONFIG_REGMAP_SPI=3Dy
> CONFIG_REGMAP_SPMI=3Dy
> CONFIG_REGMAP_MMIO=3Dy
> CONFIG_REGMAP_IRQ=3Dy
> CONFIG_REGMAP_SOUNDWIRE=3Dm
> CONFIG_DMA_SHARED_BUFFER=3Dy
> CONFIG_DMA_FENCE_TRACE=3Dy
> CONFIG_GENERIC_ARCH_TOPOLOGY=3Dy
> # end of Generic Driver Options
>=20
> #
> # Bus devices
> #
> CONFIG_BRCMSTB_GISB_ARB=3Dy
> # CONFIG_MOXTET is not set
> CONFIG_HISILICON_LPC=3Dy
> # CONFIG_IMX_WEIM is not set
> CONFIG_QCOM_EBI2=3Dy
> CONFIG_SIMPLE_PM_BUS=3Dy
> CONFIG_SUN50I_DE2_BUS=3Dy
> CONFIG_SUNXI_RSB=3Dy
> # CONFIG_TEGRA_ACONNECT is not set
> # CONFIG_TEGRA_GMI is not set
> CONFIG_UNIPHIER_SYSTEM_BUS=3Dy
> CONFIG_VEXPRESS_CONFIG=3Dy
> CONFIG_FSL_MC_BUS=3Dy
> # CONFIG_MHI_BUS is not set
> # end of Bus devices
>=20
> # CONFIG_CONNECTOR is not set
> # CONFIG_GNSS is not set
> CONFIG_MTD=3Dy
> # CONFIG_MTD_TESTS is not set
>=20
> #
> # Partition parsers
> #
> # CONFIG_MTD_AR7_PARTS is not set
> # CONFIG_MTD_CMDLINE_PARTS is not set
> CONFIG_MTD_OF_PARTS=3Dy
> # CONFIG_MTD_AFS_PARTS is not set
> # CONFIG_MTD_REDBOOT_PARTS is not set
> # end of Partition parsers
>=20
> #
> # User Modules And Translation Layers
> #
> CONFIG_MTD_BLKDEVS=3Dy
> CONFIG_MTD_BLOCK=3Dy
> # CONFIG_FTL is not set
> # CONFIG_NFTL is not set
> # CONFIG_INFTL is not set
> # CONFIG_RFD_FTL is not set
> # CONFIG_SSFDC is not set
> # CONFIG_SM_FTL is not set
> # CONFIG_MTD_OOPS is not set
> # CONFIG_MTD_SWAP is not set
> # CONFIG_MTD_PARTITIONED_MASTER is not set
>=20
> #
> # RAM/ROM/Flash chip drivers
> #
> CONFIG_MTD_CFI=3Dy
> # CONFIG_MTD_JEDECPROBE is not set
> CONFIG_MTD_GEN_PROBE=3Dy
> CONFIG_MTD_CFI_ADV_OPTIONS=3Dy
> CONFIG_MTD_CFI_NOSWAP=3Dy
> # CONFIG_MTD_CFI_BE_BYTE_SWAP is not set
> # CONFIG_MTD_CFI_LE_BYTE_SWAP is not set
> # CONFIG_MTD_CFI_GEOMETRY is not set
> CONFIG_MTD_MAP_BANK_WIDTH_1=3Dy
> CONFIG_MTD_MAP_BANK_WIDTH_2=3Dy
> CONFIG_MTD_MAP_BANK_WIDTH_4=3Dy
> CONFIG_MTD_CFI_I1=3Dy
> CONFIG_MTD_CFI_I2=3Dy
> # CONFIG_MTD_OTP is not set
> CONFIG_MTD_CFI_INTELEXT=3Dy
> CONFIG_MTD_CFI_AMDSTD=3Dy
> CONFIG_MTD_CFI_STAA=3Dy
> CONFIG_MTD_CFI_UTIL=3Dy
> # CONFIG_MTD_RAM is not set
> # CONFIG_MTD_ROM is not set
> # CONFIG_MTD_ABSENT is not set
> # end of RAM/ROM/Flash chip drivers
>=20
> #
> # Mapping drivers for chip access
> #
> # CONFIG_MTD_COMPLEX_MAPPINGS is not set
> CONFIG_MTD_PHYSMAP=3Dy
> # CONFIG_MTD_PHYSMAP_COMPAT is not set
> CONFIG_MTD_PHYSMAP_OF=3Dy
> # CONFIG_MTD_PHYSMAP_VERSATILE is not set
> # CONFIG_MTD_PHYSMAP_GEMINI is not set
> # CONFIG_MTD_INTEL_VR_NOR is not set
> # CONFIG_MTD_PLATRAM is not set
> # end of Mapping drivers for chip access
>=20
> #
> # Self-contained MTD device drivers
> #
> # CONFIG_MTD_PMC551 is not set
> CONFIG_MTD_DATAFLASH=3Dy
> # CONFIG_MTD_DATAFLASH_WRITE_VERIFY is not set
> # CONFIG_MTD_DATAFLASH_OTP is not set
> # CONFIG_MTD_MCHP23K256 is not set
> CONFIG_MTD_SST25L=3Dy
> # CONFIG_MTD_SLRAM is not set
> # CONFIG_MTD_PHRAM is not set
> # CONFIG_MTD_MTDRAM is not set
> # CONFIG_MTD_BLOCK2MTD is not set
>=20
> #
> # Disk-On-Chip Device Drivers
> #
> # CONFIG_MTD_DOCG3 is not set
> # end of Self-contained MTD device drivers
>=20
> #
> # NAND
> #
> CONFIG_MTD_NAND_CORE=3Dy
> # CONFIG_MTD_ONENAND is not set
> CONFIG_MTD_RAW_NAND=3Dy
>=20
> #
> # Raw/parallel NAND flash controllers
> #
> CONFIG_MTD_NAND_DENALI=3Dy
> # CONFIG_MTD_NAND_DENALI_PCI is not set
> CONFIG_MTD_NAND_DENALI_DT=3Dy
> # CONFIG_MTD_NAND_CAFE is not set
> CONFIG_MTD_NAND_MARVELL=3Dy
> # CONFIG_MTD_NAND_BRCMNAND is not set
> CONFIG_MTD_NAND_FSL_IFC=3Dy
> # CONFIG_MTD_NAND_MXC is not set
> # CONFIG_MTD_NAND_SUNXI is not set
> # CONFIG_MTD_NAND_HISI504 is not set
> CONFIG_MTD_NAND_QCOM=3Dy
> # CONFIG_MTD_NAND_MTK is not set
> # CONFIG_MTD_NAND_MXIC is not set
> # CONFIG_MTD_NAND_TEGRA is not set
> # CONFIG_MTD_NAND_MESON is not set
> # CONFIG_MTD_NAND_GPIO is not set
> # CONFIG_MTD_NAND_PLATFORM is not set
> # CONFIG_MTD_NAND_CADENCE is not set
> # CONFIG_MTD_NAND_ARASAN is not set
>=20
> #
> # Misc
> #
> # CONFIG_MTD_NAND_NANDSIM is not set
> # CONFIG_MTD_NAND_RICOH is not set
> # CONFIG_MTD_NAND_DISKONCHIP is not set
> # CONFIG_MTD_SPI_NAND is not set
>=20
> #
> # ECC engine support
> #
> CONFIG_MTD_NAND_ECC=3Dy
> CONFIG_MTD_NAND_ECC_SW_HAMMING=3Dy
> # CONFIG_MTD_NAND_ECC_SW_HAMMING_SMC is not set
> # CONFIG_MTD_NAND_ECC_SW_BCH is not set
> # end of ECC engine support
> # end of NAND
>=20
> #
> # LPDDR & LPDDR2 PCM memory drivers
> #
> # CONFIG_MTD_LPDDR is not set
> # end of LPDDR & LPDDR2 PCM memory drivers
>=20
> CONFIG_MTD_SPI_NOR=3Dy
> CONFIG_MTD_SPI_NOR_USE_4K_SECTORS=3Dy
> # CONFIG_SPI_HISI_SFC is not set
> # CONFIG_MTD_UBI is not set
> # CONFIG_MTD_HYPERBUS is not set
> CONFIG_DTC=3Dy
> CONFIG_OF=3Dy
> # CONFIG_OF_UNITTEST is not set
> CONFIG_OF_FLATTREE=3Dy
> CONFIG_OF_EARLY_FLATTREE=3Dy
> CONFIG_OF_KOBJ=3Dy
> CONFIG_OF_DYNAMIC=3Dy
> CONFIG_OF_ADDRESS=3Dy
> CONFIG_OF_IRQ=3Dy
> CONFIG_OF_NET=3Dy
> CONFIG_OF_RESERVED_MEM=3Dy
> CONFIG_OF_RESOLVE=3Dy
> CONFIG_OF_OVERLAY=3Dy
> CONFIG_OF_NUMA=3Dy
> # CONFIG_PARPORT is not set
> CONFIG_PNP=3Dy
> CONFIG_PNP_DEBUG_MESSAGES=3Dy
>=20
> #
> # Protocols
> #
> CONFIG_PNPACPI=3Dy
> CONFIG_BLK_DEV=3Dy
> # CONFIG_BLK_DEV_NULL_BLK is not set
> # CONFIG_BLK_DEV_PCIESSD_MTIP32XX is not set
> # CONFIG_BLK_DEV_UMEM is not set
> CONFIG_BLK_DEV_LOOP=3Dy
> CONFIG_BLK_DEV_LOOP_MIN_COUNT=3D8
> # CONFIG_BLK_DEV_CRYPTOLOOP is not set
> # CONFIG_BLK_DEV_DRBD is not set
> CONFIG_BLK_DEV_NBD=3Dm
> # CONFIG_BLK_DEV_SKD is not set
> # CONFIG_BLK_DEV_SX8 is not set
> # CONFIG_BLK_DEV_RAM is not set
> # CONFIG_CDROM_PKTCDVD is not set
> # CONFIG_ATA_OVER_ETH is not set
> CONFIG_XEN_BLKDEV_FRONTEND=3Dy
> # CONFIG_XEN_BLKDEV_BACKEND is not set
> CONFIG_VIRTIO_BLK=3Dy
> # CONFIG_BLK_DEV_RBD is not set
> # CONFIG_BLK_DEV_RSXX is not set
>=20
> #
> # NVME Support
> #
> CONFIG_NVME_CORE=3Dm
> CONFIG_BLK_DEV_NVME=3Dm
> # CONFIG_NVME_MULTIPATH is not set
> # CONFIG_NVME_HWMON is not set
> # CONFIG_NVME_FC is not set
> # CONFIG_NVME_TCP is not set
> # CONFIG_NVME_TARGET is not set
> # end of NVME Support
>=20
> #
> # Misc devices
> #
> # CONFIG_AD525X_DPOT is not set
> # CONFIG_DUMMY_IRQ is not set
> # CONFIG_PHANTOM is not set
> # CONFIG_TIFM_CORE is not set
> # CONFIG_ICS932S401 is not set
> # CONFIG_ENCLOSURE_SERVICES is not set
> # CONFIG_HP_ILO is not set
> # CONFIG_QCOM_COINCELL is not set
> # CONFIG_QCOM_FASTRPC is not set
> # CONFIG_APDS9802ALS is not set
> # CONFIG_ISL29003 is not set
> # CONFIG_ISL29020 is not set
> # CONFIG_SENSORS_TSL2550 is not set
> # CONFIG_SENSORS_BH1770 is not set
> # CONFIG_SENSORS_APDS990X is not set
> # CONFIG_HMC6352 is not set
> # CONFIG_DS1682 is not set
> # CONFIG_LATTICE_ECP3_CONFIG is not set
> CONFIG_SRAM=3Dy
> # CONFIG_PCI_ENDPOINT_TEST is not set
> # CONFIG_XILINX_SDFEC is not set
> # CONFIG_PVPANIC is not set
> # CONFIG_HISI_HIKEY_USB is not set
> # CONFIG_C2PORT is not set
>=20
> #
> # EEPROM support
> #
> CONFIG_EEPROM_AT24=3Dm
> CONFIG_EEPROM_AT25=3Dm
> # CONFIG_EEPROM_LEGACY is not set
> # CONFIG_EEPROM_MAX6875 is not set
> # CONFIG_EEPROM_93CX6 is not set
> # CONFIG_EEPROM_93XX46 is not set
> # CONFIG_EEPROM_IDT_89HPESX is not set
> # CONFIG_EEPROM_EE1004 is not set
> # end of EEPROM support
>=20
> # CONFIG_CB710_CORE is not set
>=20
> #
> # Texas Instruments shared transport line discipline
> #
> # CONFIG_TI_ST is not set
> # end of Texas Instruments shared transport line discipline
>=20
> # CONFIG_SENSORS_LIS3_I2C is not set
> # CONFIG_ALTERA_STAPL is not set
> # CONFIG_GENWQE is not set
> # CONFIG_ECHO is not set
> # CONFIG_MISC_ALCOR_PCI is not set
> # CONFIG_MISC_RTSX_PCI is not set
> # CONFIG_MISC_RTSX_USB is not set
> # CONFIG_HABANA_AI is not set
> CONFIG_UACCE=3Dm
> # end of Misc devices
>=20
> #
> # SCSI device support
> #
> CONFIG_SCSI_MOD=3Dy
> CONFIG_RAID_ATTRS=3Dm
> CONFIG_SCSI=3Dy
> CONFIG_SCSI_DMA=3Dy
> # CONFIG_SCSI_PROC_FS is not set
>=20
> #
> # SCSI support type (disk, tape, CD-ROM)
> #
> CONFIG_BLK_DEV_SD=3Dy
> # CONFIG_CHR_DEV_ST is not set
> # CONFIG_BLK_DEV_SR is not set
> # CONFIG_CHR_DEV_SG is not set
> # CONFIG_CHR_DEV_SCH is not set
> # CONFIG_SCSI_CONSTANTS is not set
> # CONFIG_SCSI_LOGGING is not set
> # CONFIG_SCSI_SCAN_ASYNC is not set
>=20
> #
> # SCSI Transports
> #
> # CONFIG_SCSI_SPI_ATTRS is not set
> # CONFIG_SCSI_FC_ATTRS is not set
> # CONFIG_SCSI_ISCSI_ATTRS is not set
> CONFIG_SCSI_SAS_ATTRS=3Dy
> CONFIG_SCSI_SAS_LIBSAS=3Dy
> CONFIG_SCSI_SAS_ATA=3Dy
> CONFIG_SCSI_SAS_HOST_SMP=3Dy
> # CONFIG_SCSI_SRP_ATTRS is not set
> # end of SCSI Transports
>=20
> CONFIG_SCSI_LOWLEVEL=3Dy
> # CONFIG_ISCSI_TCP is not set
> # CONFIG_ISCSI_BOOT_SYSFS is not set
> # CONFIG_SCSI_CXGB3_ISCSI is not set
> # CONFIG_SCSI_CXGB4_ISCSI is not set
> # CONFIG_SCSI_BNX2_ISCSI is not set
> # CONFIG_BE2ISCSI is not set
> # CONFIG_BLK_DEV_3W_XXXX_RAID is not set
> # CONFIG_SCSI_HPSA is not set
> # CONFIG_SCSI_3W_9XXX is not set
> # CONFIG_SCSI_3W_SAS is not set
> # CONFIG_SCSI_ACARD is not set
> # CONFIG_SCSI_AACRAID is not set
> # CONFIG_SCSI_AIC7XXX is not set
> # CONFIG_SCSI_AIC79XX is not set
> # CONFIG_SCSI_AIC94XX is not set
> CONFIG_SCSI_HISI_SAS=3Dy
> CONFIG_SCSI_HISI_SAS_PCI=3Dy
> # CONFIG_SCSI_MVSAS is not set
> # CONFIG_SCSI_MVUMI is not set
> # CONFIG_SCSI_ADVANSYS is not set
> # CONFIG_SCSI_ARCMSR is not set
> # CONFIG_SCSI_ESAS2R is not set
> # CONFIG_MEGARAID_NEWGEN is not set
> # CONFIG_MEGARAID_LEGACY is not set
> CONFIG_MEGARAID_SAS=3Dy
> CONFIG_SCSI_MPT3SAS=3Dm
> CONFIG_SCSI_MPT2SAS_MAX_SGE=3D128
> CONFIG_SCSI_MPT3SAS_MAX_SGE=3D128
> # CONFIG_SCSI_MPT2SAS is not set
> # CONFIG_SCSI_SMARTPQI is not set
> CONFIG_SCSI_UFSHCD=3Dy
> # CONFIG_SCSI_UFSHCD_PCI is not set
> CONFIG_SCSI_UFSHCD_PLATFORM=3Dy
> # CONFIG_SCSI_UFS_CDNS_PLATFORM is not set
> # CONFIG_SCSI_UFS_DWC_TC_PLATFORM is not set
> CONFIG_SCSI_UFS_QCOM=3Dm
> # CONFIG_SCSI_UFS_MEDIATEK is not set
> CONFIG_SCSI_UFS_HISI=3Dy
> # CONFIG_SCSI_UFS_TI_J721E is not set
> # CONFIG_SCSI_UFS_BSG is not set
> # CONFIG_SCSI_UFS_EXYNOS is not set
> # CONFIG_SCSI_HPTIOP is not set
> # CONFIG_SCSI_MYRB is not set
> # CONFIG_SCSI_MYRS is not set
> # CONFIG_XEN_SCSI_FRONTEND is not set
> # CONFIG_SCSI_SNIC is not set
> # CONFIG_SCSI_DMX3191D is not set
> # CONFIG_SCSI_FDOMAIN_PCI is not set
> # CONFIG_SCSI_GDTH is not set
> # CONFIG_SCSI_IPS is not set
> # CONFIG_SCSI_INITIO is not set
> # CONFIG_SCSI_INIA100 is not set
> # CONFIG_SCSI_STEX is not set
> # CONFIG_SCSI_SYM53C8XX_2 is not set
> # CONFIG_SCSI_IPR is not set
> # CONFIG_SCSI_QLOGIC_1280 is not set
> # CONFIG_SCSI_QLA_ISCSI is not set
> # CONFIG_SCSI_DC395x is not set
> # CONFIG_SCSI_AM53C974 is not set
> # CONFIG_SCSI_WD719X is not set
> # CONFIG_SCSI_DEBUG is not set
> # CONFIG_SCSI_PMCRAID is not set
> # CONFIG_SCSI_PM8001 is not set
> CONFIG_SCSI_VIRTIO=3Dy
> # CONFIG_SCSI_DH is not set
> # end of SCSI device support
>=20
> CONFIG_HAVE_PATA_PLATFORM=3Dy
> CONFIG_ATA=3Dy
> CONFIG_SATA_HOST=3Dy
> CONFIG_PATA_TIMINGS=3Dy
> CONFIG_ATA_VERBOSE_ERROR=3Dy
> CONFIG_ATA_FORCE=3Dy
> CONFIG_ATA_ACPI=3Dy
> # CONFIG_SATA_ZPODD is not set
> CONFIG_SATA_PMP=3Dy
>=20
> #
> # Controllers with non-SFF native interface
> #
> CONFIG_SATA_AHCI=3Dy
> CONFIG_SATA_MOBILE_LPM_POLICY=3D0
> CONFIG_SATA_AHCI_PLATFORM=3Dy
> # CONFIG_AHCI_BRCM is not set
> # CONFIG_AHCI_IMX is not set
> CONFIG_AHCI_CEVA=3Dy
> # CONFIG_AHCI_MTK is not set
> CONFIG_AHCI_MVEBU=3Dy
> # CONFIG_AHCI_SUNXI is not set
> # CONFIG_AHCI_TEGRA is not set
> CONFIG_AHCI_XGENE=3Dy
> CONFIG_AHCI_QORIQ=3Dy
> # CONFIG_SATA_AHCI_SEATTLE is not set
> # CONFIG_SATA_INIC162X is not set
> # CONFIG_SATA_ACARD_AHCI is not set
> CONFIG_SATA_SIL24=3Dy
> CONFIG_ATA_SFF=3Dy
>=20
> #
> # SFF controllers with custom DMA interface
> #
> # CONFIG_PDC_ADMA is not set
> # CONFIG_SATA_QSTOR is not set
> # CONFIG_SATA_SX4 is not set
> CONFIG_ATA_BMDMA=3Dy
>=20
> #
> # SATA SFF controllers with BMDMA
> #
> # CONFIG_ATA_PIIX is not set
> # CONFIG_SATA_DWC is not set
> # CONFIG_SATA_MV is not set
> # CONFIG_SATA_NV is not set
> # CONFIG_SATA_PROMISE is not set
> CONFIG_SATA_RCAR=3Dy
> # CONFIG_SATA_SIL is not set
> # CONFIG_SATA_SIS is not set
> # CONFIG_SATA_SVW is not set
> # CONFIG_SATA_ULI is not set
> # CONFIG_SATA_VIA is not set
> # CONFIG_SATA_VITESSE is not set
>=20
> #
> # PATA SFF controllers with BMDMA
> #
> # CONFIG_PATA_ALI is not set
> # CONFIG_PATA_AMD is not set
> # CONFIG_PATA_ARTOP is not set
> # CONFIG_PATA_ATIIXP is not set
> # CONFIG_PATA_ATP867X is not set
> # CONFIG_PATA_CMD64X is not set
> # CONFIG_PATA_CYPRESS is not set
> # CONFIG_PATA_EFAR is not set
> # CONFIG_PATA_HPT366 is not set
> # CONFIG_PATA_HPT37X is not set
> # CONFIG_PATA_HPT3X2N is not set
> # CONFIG_PATA_HPT3X3 is not set
> # CONFIG_PATA_IMX is not set
> # CONFIG_PATA_IT8213 is not set
> # CONFIG_PATA_IT821X is not set
> # CONFIG_PATA_JMICRON is not set
> # CONFIG_PATA_MARVELL is not set
> # CONFIG_PATA_NETCELL is not set
> # CONFIG_PATA_NINJA32 is not set
> # CONFIG_PATA_NS87415 is not set
> # CONFIG_PATA_OLDPIIX is not set
> # CONFIG_PATA_OPTIDMA is not set
> # CONFIG_PATA_PDC2027X is not set
> # CONFIG_PATA_PDC_OLD is not set
> # CONFIG_PATA_RADISYS is not set
> # CONFIG_PATA_RDC is not set
> # CONFIG_PATA_SCH is not set
> # CONFIG_PATA_SERVERWORKS is not set
> # CONFIG_PATA_SIL680 is not set
> # CONFIG_PATA_SIS is not set
> # CONFIG_PATA_TOSHIBA is not set
> # CONFIG_PATA_TRIFLEX is not set
> # CONFIG_PATA_VIA is not set
> # CONFIG_PATA_WINBOND is not set
>=20
> #
> # PIO-only SFF controllers
> #
> # CONFIG_PATA_CMD640_PCI is not set
> # CONFIG_PATA_MPIIX is not set
> # CONFIG_PATA_NS87410 is not set
> # CONFIG_PATA_OPTI is not set
> CONFIG_PATA_PLATFORM=3Dy
> CONFIG_PATA_OF_PLATFORM=3Dy
> # CONFIG_PATA_RZ1000 is not set
>=20
> #
> # Generic fallback / legacy drivers
> #
> # CONFIG_PATA_ACPI is not set
> # CONFIG_ATA_GENERIC is not set
> # CONFIG_PATA_LEGACY is not set
> CONFIG_MD=3Dy
> CONFIG_BLK_DEV_MD=3Dm
> # CONFIG_MD_LINEAR is not set
> # CONFIG_MD_RAID0 is not set
> # CONFIG_MD_RAID1 is not set
> # CONFIG_MD_RAID10 is not set
> # CONFIG_MD_RAID456 is not set
> # CONFIG_MD_MULTIPATH is not set
> # CONFIG_MD_FAULTY is not set
> # CONFIG_BCACHE is not set
> CONFIG_BLK_DEV_DM_BUILTIN=3Dy
> CONFIG_BLK_DEV_DM=3Dm
> # CONFIG_DM_DEBUG is not set
> # CONFIG_DM_UNSTRIPED is not set
> # CONFIG_DM_CRYPT is not set
> # CONFIG_DM_SNAPSHOT is not set
> # CONFIG_DM_THIN_PROVISIONING is not set
> # CONFIG_DM_CACHE is not set
> # CONFIG_DM_WRITECACHE is not set
> # CONFIG_DM_EBS is not set
> # CONFIG_DM_ERA is not set
> # CONFIG_DM_CLONE is not set
> CONFIG_DM_MIRROR=3Dm
> # CONFIG_DM_LOG_USERSPACE is not set
> # CONFIG_DM_RAID is not set
> CONFIG_DM_ZERO=3Dm
> # CONFIG_DM_MULTIPATH is not set
> # CONFIG_DM_DELAY is not set
> # CONFIG_DM_DUST is not set
> # CONFIG_DM_UEVENT is not set
> # CONFIG_DM_FLAKEY is not set
> # CONFIG_DM_VERITY is not set
> # CONFIG_DM_SWITCH is not set
> # CONFIG_DM_LOG_WRITES is not set
> # CONFIG_DM_INTEGRITY is not set
> # CONFIG_TARGET_CORE is not set
> # CONFIG_FUSION is not set
>=20
> #
> # IEEE 1394 (FireWire) support
> #
> # CONFIG_FIREWIRE is not set
> # CONFIG_FIREWIRE_NOSY is not set
> # end of IEEE 1394 (FireWire) support
>=20
> CONFIG_NETDEVICES=3Dy
> CONFIG_MII=3Dy
> CONFIG_NET_CORE=3Dy
> # CONFIG_BONDING is not set
> # CONFIG_DUMMY is not set
> # CONFIG_WIREGUARD is not set
> # CONFIG_EQUALIZER is not set
> # CONFIG_NET_FC is not set
> # CONFIG_NET_TEAM is not set
> CONFIG_MACVLAN=3Dm
> CONFIG_MACVTAP=3Dm
> # CONFIG_IPVLAN is not set
> # CONFIG_VXLAN is not set
> # CONFIG_GENEVE is not set
> # CONFIG_BAREUDP is not set
> # CONFIG_GTP is not set
> # CONFIG_MACSEC is not set
> # CONFIG_NETCONSOLE is not set
> CONFIG_TUN=3Dy
> CONFIG_TAP=3Dm
> # CONFIG_TUN_VNET_CROSS_LE is not set
> CONFIG_VETH=3Dm
> CONFIG_VIRTIO_NET=3Dy
> # CONFIG_NLMON is not set
> # CONFIG_ARCNET is not set
>=20
> #
> # Distributed Switch Architecture drivers
> #
> # CONFIG_B53 is not set
> # CONFIG_NET_DSA_BCM_SF2 is not set
> # CONFIG_NET_DSA_LOOP is not set
> # CONFIG_NET_DSA_HIRSCHMANN_HELLCREEK is not set
> # CONFIG_NET_DSA_LANTIQ_GSWIP is not set
> # CONFIG_NET_DSA_MT7530 is not set
> # CONFIG_NET_DSA_MV88E6060 is not set
> # CONFIG_NET_DSA_MICROCHIP_KSZ9477 is not set
> # CONFIG_NET_DSA_MICROCHIP_KSZ8795 is not set
> # CONFIG_NET_DSA_MV88E6XXX is not set
> CONFIG_NET_DSA_MSCC_FELIX=3Dm
> # CONFIG_NET_DSA_MSCC_SEVILLE is not set
> # CONFIG_NET_DSA_AR9331 is not set
> # CONFIG_NET_DSA_SJA1105 is not set
> # CONFIG_NET_DSA_QCA8K is not set
> # CONFIG_NET_DSA_REALTEK_SMI is not set
> # CONFIG_NET_DSA_SMSC_LAN9303_I2C is not set
> # CONFIG_NET_DSA_SMSC_LAN9303_MDIO is not set
> # CONFIG_NET_DSA_VITESSE_VSC73XX_SPI is not set
> # CONFIG_NET_DSA_VITESSE_VSC73XX_PLATFORM is not set
> # end of Distributed Switch Architecture drivers
>=20
> CONFIG_ETHERNET=3Dy
> CONFIG_MDIO=3Dm
> CONFIG_NET_VENDOR_3COM=3Dy
> # CONFIG_VORTEX is not set
> # CONFIG_TYPHOON is not set
> CONFIG_NET_VENDOR_ADAPTEC=3Dy
> # CONFIG_ADAPTEC_STARFIRE is not set
> CONFIG_NET_VENDOR_AGERE=3Dy
> # CONFIG_ET131X is not set
> CONFIG_NET_VENDOR_ALACRITECH=3Dy
> # CONFIG_SLICOSS is not set
> CONFIG_NET_VENDOR_ALLWINNER=3Dy
> # CONFIG_SUN4I_EMAC is not set
> CONFIG_NET_VENDOR_ALTEON=3Dy
> # CONFIG_ACENIC is not set
> # CONFIG_ALTERA_TSE is not set
> CONFIG_NET_VENDOR_AMAZON=3Dy
> # CONFIG_ENA_ETHERNET is not set
> CONFIG_NET_VENDOR_AMD=3Dy
> # CONFIG_AMD8111_ETH is not set
> # CONFIG_PCNET32 is not set
> CONFIG_AMD_XGBE=3Dy
> CONFIG_NET_XGENE=3Dy
> # CONFIG_NET_XGENE_V2 is not set
> CONFIG_NET_VENDOR_AQUANTIA=3Dy
> # CONFIG_AQTION is not set
> CONFIG_NET_VENDOR_ARC=3Dy
> # CONFIG_EMAC_ROCKCHIP is not set
> CONFIG_NET_VENDOR_ATHEROS=3Dy
> # CONFIG_ATL2 is not set
> # CONFIG_ATL1 is not set
> # CONFIG_ATL1E is not set
> CONFIG_ATL1C=3Dm
> # CONFIG_ALX is not set
> CONFIG_NET_VENDOR_AURORA=3Dy
> # CONFIG_AURORA_NB8800 is not set
> CONFIG_NET_VENDOR_BROADCOM=3Dy
> # CONFIG_B44 is not set
> CONFIG_BCMGENET=3Dm
> # CONFIG_BNX2 is not set
> # CONFIG_CNIC is not set
> # CONFIG_TIGON3 is not set
> CONFIG_BNX2X=3Dm
> CONFIG_BNX2X_SRIOV=3Dy
> CONFIG_BGMAC=3Dy
> CONFIG_BGMAC_PLATFORM=3Dy
> # CONFIG_SYSTEMPORT is not set
> # CONFIG_BNXT is not set
> CONFIG_NET_VENDOR_BROCADE=3Dy
> # CONFIG_BNA is not set
> CONFIG_NET_VENDOR_CADENCE=3Dy
> CONFIG_MACB=3Dy
> CONFIG_MACB_USE_HWSTAMP=3Dy
> # CONFIG_MACB_PCI is not set
> CONFIG_NET_VENDOR_CAVIUM=3Dy
> CONFIG_THUNDER_NIC_PF=3Dy
> # CONFIG_THUNDER_NIC_VF is not set
> CONFIG_THUNDER_NIC_BGX=3Dy
> CONFIG_THUNDER_NIC_RGX=3Dy
> # CONFIG_CAVIUM_PTP is not set
> # CONFIG_LIQUIDIO is not set
> # CONFIG_LIQUIDIO_VF is not set
> CONFIG_NET_VENDOR_CHELSIO=3Dy
> # CONFIG_CHELSIO_T1 is not set
> # CONFIG_CHELSIO_T3 is not set
> # CONFIG_CHELSIO_T4 is not set
> # CONFIG_CHELSIO_T4VF is not set
> CONFIG_NET_VENDOR_CISCO=3Dy
> # CONFIG_ENIC is not set
> CONFIG_NET_VENDOR_CORTINA=3Dy
> # CONFIG_GEMINI_ETHERNET is not set
> # CONFIG_DNET is not set
> CONFIG_NET_VENDOR_DEC=3Dy
> # CONFIG_NET_TULIP is not set
> CONFIG_NET_VENDOR_DLINK=3Dy
> # CONFIG_DL2K is not set
> # CONFIG_SUNDANCE is not set
> CONFIG_NET_VENDOR_EMULEX=3Dy
> # CONFIG_BE2NET is not set
> CONFIG_NET_VENDOR_EZCHIP=3Dy
> # CONFIG_EZCHIP_NPS_MANAGEMENT_ENET is not set
> CONFIG_NET_VENDOR_FREESCALE=3Dy
> CONFIG_FEC=3Dy
> CONFIG_FSL_FMAN=3Dy
> CONFIG_DPAA_ERRATUM_A050385=3Dy
> # CONFIG_FSL_PQ_MDIO is not set
> # CONFIG_FSL_XGMAC_MDIO is not set
> # CONFIG_GIANFAR is not set
> CONFIG_FSL_DPAA_ETH=3Dy
> CONFIG_FSL_DPAA2_ETH=3Dy
> CONFIG_FSL_DPAA2_PTP_CLOCK=3Dy
> CONFIG_FSL_ENETC=3Dy
> CONFIG_FSL_ENETC_VF=3Dy
> CONFIG_FSL_ENETC_MDIO=3Dy
> CONFIG_FSL_ENETC_PTP_CLOCK=3Dy
> CONFIG_NET_VENDOR_GOOGLE=3Dy
> # CONFIG_GVE is not set
> CONFIG_NET_VENDOR_HISILICON=3Dy
> CONFIG_HIX5HD2_GMAC=3Dy
> # CONFIG_HISI_FEMAC is not set
> # CONFIG_HIP04_ETH is not set
> CONFIG_HNS_MDIO=3Dy
> CONFIG_HNS=3Dy
> CONFIG_HNS_DSAF=3Dy
> CONFIG_HNS_ENET=3Dy
> CONFIG_HNS3=3Dy
> CONFIG_HNS3_HCLGE=3Dy
> # CONFIG_HNS3_HCLGEVF is not set
> CONFIG_HNS3_ENET=3Dy
> CONFIG_NET_VENDOR_HUAWEI=3Dy
> # CONFIG_HINIC is not set
> CONFIG_NET_VENDOR_I825XX=3Dy
> CONFIG_NET_VENDOR_INTEL=3Dy
> # CONFIG_E100 is not set
> CONFIG_E1000=3Dy
> CONFIG_E1000E=3Dy
> CONFIG_IGB=3Dy
> CONFIG_IGB_HWMON=3Dy
> CONFIG_IGBVF=3Dy
> # CONFIG_IXGB is not set
> # CONFIG_IXGBE is not set
> # CONFIG_IXGBEVF is not set
> # CONFIG_I40E is not set
> # CONFIG_I40EVF is not set
> # CONFIG_ICE is not set
> # CONFIG_FM10K is not set
> # CONFIG_IGC is not set
> # CONFIG_JME is not set
> CONFIG_NET_VENDOR_MARVELL=3Dy
> CONFIG_MVMDIO=3Dy
> CONFIG_MVNETA=3Dy
> CONFIG_MVPP2=3Dy
> # CONFIG_PXA168_ETH is not set
> # CONFIG_SKGE is not set
> CONFIG_SKY2=3Dy
> # CONFIG_SKY2_DEBUG is not set
> # CONFIG_OCTEONTX2_AF is not set
> # CONFIG_OCTEONTX2_PF is not set
> # CONFIG_PRESTERA is not set
> # CONFIG_NET_VENDOR_MEDIATEK is not set
> CONFIG_NET_VENDOR_MELLANOX=3Dy
> CONFIG_MLX4_EN=3Dm
> CONFIG_MLX4_CORE=3Dm
> CONFIG_MLX4_DEBUG=3Dy
> CONFIG_MLX4_CORE_GEN2=3Dy
> CONFIG_MLX5_CORE=3Dm
> # CONFIG_MLX5_FPGA is not set
> CONFIG_MLX5_CORE_EN=3Dy
> CONFIG_MLX5_EN_ARFS=3Dy
> CONFIG_MLX5_EN_RXNFC=3Dy
> CONFIG_MLX5_MPFS=3Dy
> CONFIG_MLX5_ESWITCH=3Dy
> # CONFIG_MLX5_CORE_IPOIB is not set
> CONFIG_MLX5_SW_STEERING=3Dy
> # CONFIG_MLXSW_CORE is not set
> # CONFIG_MLXFW is not set
> CONFIG_NET_VENDOR_MICREL=3Dy
> # CONFIG_KS8842 is not set
> # CONFIG_KS8851 is not set
> # CONFIG_KS8851_MLL is not set
> # CONFIG_KSZ884X_PCI is not set
> CONFIG_NET_VENDOR_MICROCHIP=3Dy
> # CONFIG_ENC28J60 is not set
> # CONFIG_ENCX24J600 is not set
> # CONFIG_LAN743X is not set
> CONFIG_NET_VENDOR_MICROSEMI=3Dy
> CONFIG_MSCC_OCELOT_SWITCH_LIB=3Dm
> CONFIG_MSCC_OCELOT_SWITCH=3Dm
> CONFIG_NET_VENDOR_MYRI=3Dy
> # CONFIG_MYRI10GE is not set
> # CONFIG_FEALNX is not set
> CONFIG_NET_VENDOR_NATSEMI=3Dy
> # CONFIG_NATSEMI is not set
> # CONFIG_NS83820 is not set
> CONFIG_NET_VENDOR_NETERION=3Dy
> # CONFIG_S2IO is not set
> # CONFIG_VXGE is not set
> CONFIG_NET_VENDOR_NETRONOME=3Dy
> # CONFIG_NFP is not set
> CONFIG_NET_VENDOR_NI=3Dy
> # CONFIG_NI_XGE_MANAGEMENT_ENET is not set
> CONFIG_NET_VENDOR_8390=3Dy
> # CONFIG_NE2K_PCI is not set
> CONFIG_NET_VENDOR_NVIDIA=3Dy
> # CONFIG_FORCEDETH is not set
> CONFIG_NET_VENDOR_OKI=3Dy
> # CONFIG_ETHOC is not set
> CONFIG_NET_VENDOR_PACKET_ENGINES=3Dy
> # CONFIG_HAMACHI is not set
> # CONFIG_YELLOWFIN is not set
> CONFIG_NET_VENDOR_PENSANDO=3Dy
> # CONFIG_IONIC is not set
> CONFIG_NET_VENDOR_QLOGIC=3Dy
> # CONFIG_QLA3XXX is not set
> # CONFIG_QLCNIC is not set
> # CONFIG_NETXEN_NIC is not set
> # CONFIG_QED is not set
> CONFIG_NET_VENDOR_QUALCOMM=3Dy
> # CONFIG_QCA7000_SPI is not set
> # CONFIG_QCA7000_UART is not set
> CONFIG_QCOM_EMAC=3Dm
> CONFIG_RMNET=3Dm
> CONFIG_NET_VENDOR_RDC=3Dy
> # CONFIG_R6040 is not set
> CONFIG_NET_VENDOR_REALTEK=3Dy
> # CONFIG_8139CP is not set
> # CONFIG_8139TOO is not set
> # CONFIG_R8169 is not set
> CONFIG_NET_VENDOR_RENESAS=3Dy
> # CONFIG_SH_ETH is not set
> CONFIG_RAVB=3Dy
> CONFIG_NET_VENDOR_ROCKER=3Dy
> # CONFIG_ROCKER is not set
> CONFIG_NET_VENDOR_SAMSUNG=3Dy
> # CONFIG_SXGBE_ETH is not set
> CONFIG_NET_VENDOR_SEEQ=3Dy
> CONFIG_NET_VENDOR_SOLARFLARE=3Dy
> # CONFIG_SFC is not set
> # CONFIG_SFC_FALCON is not set
> CONFIG_NET_VENDOR_SILAN=3Dy
> # CONFIG_SC92031 is not set
> CONFIG_NET_VENDOR_SIS=3Dy
> # CONFIG_SIS900 is not set
> # CONFIG_SIS190 is not set
> CONFIG_NET_VENDOR_SMSC=3Dy
> CONFIG_SMC91X=3Dy
> # CONFIG_EPIC100 is not set
> CONFIG_SMSC911X=3Dy
> # CONFIG_SMSC9420 is not set
> CONFIG_NET_VENDOR_SOCIONEXT=3Dy
> CONFIG_SNI_AVE=3Dy
> CONFIG_SNI_NETSEC=3Dy
> CONFIG_NET_VENDOR_STMICRO=3Dy
> CONFIG_STMMAC_ETH=3Dm
> # CONFIG_STMMAC_SELFTESTS is not set
> CONFIG_STMMAC_PLATFORM=3Dm
> # CONFIG_DWMAC_DWC_QOS_ETH is not set
> CONFIG_DWMAC_GENERIC=3Dm
> CONFIG_DWMAC_IPQ806X=3Dm
> # CONFIG_DWMAC_MEDIATEK is not set
> CONFIG_DWMAC_MESON=3Dm
> CONFIG_DWMAC_QCOM_ETHQOS=3Dm
> CONFIG_DWMAC_ROCKCHIP=3Dm
> CONFIG_DWMAC_SOCFPGA=3Dm
> CONFIG_DWMAC_SUNXI=3Dm
> CONFIG_DWMAC_SUN8I=3Dm
> CONFIG_DWMAC_IMX8=3Dm
> # CONFIG_DWMAC_INTEL_PLAT is not set
> # CONFIG_STMMAC_PCI is not set
> CONFIG_NET_VENDOR_SUN=3Dy
> # CONFIG_HAPPYMEAL is not set
> # CONFIG_SUNGEM is not set
> # CONFIG_CASSINI is not set
> # CONFIG_NIU is not set
> CONFIG_NET_VENDOR_SYNOPSYS=3Dy
> # CONFIG_DWC_XLGMAC is not set
> CONFIG_NET_VENDOR_TEHUTI=3Dy
> # CONFIG_TEHUTI is not set
> CONFIG_NET_VENDOR_TI=3Dy
> CONFIG_TI_DAVINCI_MDIO=3Dy
> # CONFIG_TI_CPSW_PHY_SEL is not set
> CONFIG_TI_K3_AM65_CPSW_NUSS=3Dy
> # CONFIG_TI_K3_AM65_CPTS is not set
> # CONFIG_TLAN is not set
> CONFIG_NET_VENDOR_VIA=3Dy
> # CONFIG_VIA_RHINE is not set
> # CONFIG_VIA_VELOCITY is not set
> CONFIG_NET_VENDOR_WIZNET=3Dy
> # CONFIG_WIZNET_W5100 is not set
> # CONFIG_WIZNET_W5300 is not set
> CONFIG_NET_VENDOR_XILINX=3Dy
> # CONFIG_XILINX_AXI_EMAC is not set
> # CONFIG_XILINX_LL_TEMAC is not set
> # CONFIG_FDDI is not set
> # CONFIG_HIPPI is not set
> CONFIG_QCOM_IPA=3Dm
> # CONFIG_NET_SB1000 is not set
> CONFIG_PHYLINK=3Dy
> CONFIG_PHYLIB=3Dy
> CONFIG_SWPHY=3Dy
> # CONFIG_LED_TRIGGER_PHY is not set
> CONFIG_FIXED_PHY=3Dy
> # CONFIG_SFP is not set
>=20
> #
> # MII PHY device drivers
> #
> # CONFIG_AMD_PHY is not set
> CONFIG_MESON_GXL_PHY=3Dm
> # CONFIG_ADIN_PHY is not set
> CONFIG_AQUANTIA_PHY=3Dy
> # CONFIG_AX88796B_PHY is not set
> CONFIG_BROADCOM_PHY=3Dm
> # CONFIG_BCM54140_PHY is not set
> CONFIG_BCM7XXX_PHY=3Dm
> # CONFIG_BCM84881_PHY is not set
> # CONFIG_BCM87XX_PHY is not set
> # CONFIG_BCM_CYGNUS_PHY is not set
> CONFIG_BCM_NET_PHYLIB=3Dm
> # CONFIG_CICADA_PHY is not set
> # CONFIG_CORTINA_PHY is not set
> # CONFIG_DAVICOM_PHY is not set
> # CONFIG_ICPLUS_PHY is not set
> # CONFIG_LXT_PHY is not set
> # CONFIG_INTEL_XWAY_PHY is not set
> # CONFIG_LSI_ET1011C_PHY is not set
> CONFIG_MARVELL_PHY=3Dm
> CONFIG_MARVELL_10G_PHY=3Dm
> CONFIG_MICREL_PHY=3Dy
> CONFIG_MICROCHIP_PHY=3Dm
> # CONFIG_MICROCHIP_T1_PHY is not set
> CONFIG_MICROSEMI_PHY=3Dy
> # CONFIG_NATIONAL_PHY is not set
> # CONFIG_NXP_TJA11XX_PHY is not set
> CONFIG_AT803X_PHY=3Dy
> # CONFIG_QSEMI_PHY is not set
> CONFIG_REALTEK_PHY=3Dm
> # CONFIG_RENESAS_PHY is not set
> CONFIG_ROCKCHIP_PHY=3Dy
> CONFIG_SMSC_PHY=3Dm
> # CONFIG_STE10XP is not set
> # CONFIG_TERANETICS_PHY is not set
> # CONFIG_DP83822_PHY is not set
> # CONFIG_DP83TC811_PHY is not set
> # CONFIG_DP83848_PHY is not set
> # CONFIG_DP83867_PHY is not set
> # CONFIG_DP83869_PHY is not set
> CONFIG_VITESSE_PHY=3Dy
> # CONFIG_XILINX_GMII2RGMII is not set
> # CONFIG_MICREL_KS8995MA is not set
> CONFIG_MDIO_DEVICE=3Dy
> CONFIG_MDIO_BUS=3Dy
> CONFIG_OF_MDIO=3Dy
> CONFIG_MDIO_DEVRES=3Dy
> # CONFIG_MDIO_SUN4I is not set
> CONFIG_MDIO_XGENE=3Dy
> CONFIG_MDIO_BITBANG=3Dy
> CONFIG_MDIO_BCM_IPROC=3Dy
> CONFIG_MDIO_BCM_UNIMAC=3Dm
> CONFIG_MDIO_CAVIUM=3Dy
> # CONFIG_MDIO_GPIO is not set
> # CONFIG_MDIO_HISI_FEMAC is not set
> # CONFIG_MDIO_MVUSB is not set
> # CONFIG_MDIO_MSCC_MIIM is not set
> # CONFIG_MDIO_OCTEON is not set
> # CONFIG_MDIO_IPQ4019 is not set
> # CONFIG_MDIO_IPQ8064 is not set
> CONFIG_MDIO_THUNDER=3Dy
>=20
> #
> # MDIO Multiplexers
> #
> CONFIG_MDIO_BUS_MUX=3Dy
> CONFIG_MDIO_BUS_MUX_MESON_G12A=3Dm
> CONFIG_MDIO_BUS_MUX_BCM_IPROC=3Dy
> # CONFIG_MDIO_BUS_MUX_GPIO is not set
> CONFIG_MDIO_BUS_MUX_MULTIPLEXER=3Dy
> CONFIG_MDIO_BUS_MUX_MMIOREG=3Dy
>=20
> #
> # PCS device drivers
> #
> CONFIG_PCS_XPCS=3Dm
> CONFIG_PCS_LYNX=3Dy
> # end of PCS device drivers
>=20
> # CONFIG_PPP is not set
> # CONFIG_SLIP is not set
> CONFIG_USB_NET_DRIVERS=3Dy
> # CONFIG_USB_CATC is not set
> # CONFIG_USB_KAWETH is not set
> CONFIG_USB_PEGASUS=3Dm
> CONFIG_USB_RTL8150=3Dm
> CONFIG_USB_RTL8152=3Dm
> CONFIG_USB_LAN78XX=3Dm
> CONFIG_USB_USBNET=3Dm
> CONFIG_USB_NET_AX8817X=3Dm
> CONFIG_USB_NET_AX88179_178A=3Dm
> CONFIG_USB_NET_CDCETHER=3Dm
> # CONFIG_USB_NET_CDC_EEM is not set
> CONFIG_USB_NET_CDC_NCM=3Dm
> # CONFIG_USB_NET_HUAWEI_CDC_NCM is not set
> # CONFIG_USB_NET_CDC_MBIM is not set
> CONFIG_USB_NET_DM9601=3Dm
> # CONFIG_USB_NET_SR9700 is not set
> CONFIG_USB_NET_SR9800=3Dm
> CONFIG_USB_NET_SMSC75XX=3Dm
> CONFIG_USB_NET_SMSC95XX=3Dm
> # CONFIG_USB_NET_GL620A is not set
> CONFIG_USB_NET_NET1080=3Dm
> CONFIG_USB_NET_PLUSB=3Dm
> CONFIG_USB_NET_MCS7830=3Dm
> # CONFIG_USB_NET_RNDIS_HOST is not set
> CONFIG_USB_NET_CDC_SUBSET_ENABLE=3Dm
> CONFIG_USB_NET_CDC_SUBSET=3Dm
> # CONFIG_USB_ALI_M5632 is not set
> # CONFIG_USB_AN2720 is not set
> CONFIG_USB_BELKIN=3Dy
> CONFIG_USB_ARMLINUX=3Dy
> # CONFIG_USB_EPSON2888 is not set
> # CONFIG_USB_KC2190 is not set
> CONFIG_USB_NET_ZAURUS=3Dm
> # CONFIG_USB_NET_CX82310_ETH is not set
> # CONFIG_USB_NET_KALMIA is not set
> # CONFIG_USB_NET_QMI_WWAN is not set
> # CONFIG_USB_HSO is not set
> # CONFIG_USB_NET_INT51X1 is not set
> # CONFIG_USB_IPHETH is not set
> # CONFIG_USB_SIERRA_NET is not set
> # CONFIG_USB_VL600 is not set
> # CONFIG_USB_NET_CH9200 is not set
> # CONFIG_USB_NET_AQC111 is not set
> CONFIG_WLAN=3Dy
> CONFIG_WLAN_VENDOR_ADMTEK=3Dy
> # CONFIG_ADM8211 is not set
> CONFIG_ATH_COMMON=3Dm
> CONFIG_WLAN_VENDOR_ATH=3Dy
> # CONFIG_ATH_DEBUG is not set
> # CONFIG_ATH5K is not set
> # CONFIG_ATH5K_PCI is not set
> # CONFIG_ATH9K is not set
> # CONFIG_ATH9K_HTC is not set
> # CONFIG_CARL9170 is not set
> # CONFIG_ATH6KL is not set
> # CONFIG_AR5523 is not set
> # CONFIG_WIL6210 is not set
> CONFIG_ATH10K=3Dm
> CONFIG_ATH10K_CE=3Dy
> CONFIG_ATH10K_PCI=3Dm
> # CONFIG_ATH10K_AHB is not set
> # CONFIG_ATH10K_SDIO is not set
> # CONFIG_ATH10K_USB is not set
> CONFIG_ATH10K_SNOC=3Dm
> # CONFIG_ATH10K_DEBUG is not set
> # CONFIG_ATH10K_DEBUGFS is not set
> # CONFIG_ATH10K_TRACING is not set
> # CONFIG_WCN36XX is not set
> CONFIG_WLAN_VENDOR_ATMEL=3Dy
> # CONFIG_ATMEL is not set
> # CONFIG_AT76C50X_USB is not set
> CONFIG_WLAN_VENDOR_BROADCOM=3Dy
> # CONFIG_B43 is not set
> # CONFIG_B43LEGACY is not set
> CONFIG_BRCMUTIL=3Dm
> # CONFIG_BRCMSMAC is not set
> CONFIG_BRCMFMAC=3Dm
> CONFIG_BRCMFMAC_PROTO_BCDC=3Dy
> CONFIG_BRCMFMAC_SDIO=3Dy
> # CONFIG_BRCMFMAC_USB is not set
> # CONFIG_BRCMFMAC_PCIE is not set
> # CONFIG_BRCM_TRACING is not set
> # CONFIG_BRCMDBG is not set
> CONFIG_WLAN_VENDOR_CISCO=3Dy
> CONFIG_WLAN_VENDOR_INTEL=3Dy
> # CONFIG_IPW2100 is not set
> # CONFIG_IPW2200 is not set
> # CONFIG_IWL4965 is not set
> # CONFIG_IWL3945 is not set
> # CONFIG_IWLWIFI is not set
> CONFIG_WLAN_VENDOR_INTERSIL=3Dy
> # CONFIG_HOSTAP is not set
> # CONFIG_HERMES is not set
> # CONFIG_P54_COMMON is not set
> # CONFIG_PRISM54 is not set
> CONFIG_WLAN_VENDOR_MARVELL=3Dy
> # CONFIG_LIBERTAS is not set
> # CONFIG_LIBERTAS_THINFIRM is not set
> CONFIG_MWIFIEX=3Dm
> # CONFIG_MWIFIEX_SDIO is not set
> CONFIG_MWIFIEX_PCIE=3Dm
> # CONFIG_MWIFIEX_USB is not set
> # CONFIG_MWL8K is not set
> CONFIG_WLAN_VENDOR_MEDIATEK=3Dy
> # CONFIG_MT7601U is not set
> # CONFIG_MT76x0U is not set
> # CONFIG_MT76x0E is not set
> # CONFIG_MT76x2E is not set
> # CONFIG_MT76x2U is not set
> # CONFIG_MT7603E is not set
> # CONFIG_MT7615E is not set
> # CONFIG_MT7663U is not set
> # CONFIG_MT7663S is not set
> # CONFIG_MT7915E is not set
> CONFIG_WLAN_VENDOR_MICROCHIP=3Dy
> # CONFIG_WILC1000_SDIO is not set
> # CONFIG_WILC1000_SPI is not set
> CONFIG_WLAN_VENDOR_RALINK=3Dy
> # CONFIG_RT2X00 is not set
> CONFIG_WLAN_VENDOR_REALTEK=3Dy
> # CONFIG_RTL8180 is not set
> # CONFIG_RTL8187 is not set
> CONFIG_RTL_CARDS=3Dm
> # CONFIG_RTL8192CE is not set
> # CONFIG_RTL8192SE is not set
> # CONFIG_RTL8192DE is not set
> # CONFIG_RTL8723AE is not set
> # CONFIG_RTL8723BE is not set
> # CONFIG_RTL8188EE is not set
> # CONFIG_RTL8192EE is not set
> # CONFIG_RTL8821AE is not set
> # CONFIG_RTL8192CU is not set
> # CONFIG_RTL8XXXU is not set
> # CONFIG_RTW88 is not set
> CONFIG_WLAN_VENDOR_RSI=3Dy
> # CONFIG_RSI_91X is not set
> CONFIG_WLAN_VENDOR_ST=3Dy
> # CONFIG_CW1200 is not set
> CONFIG_WLAN_VENDOR_TI=3Dy
> # CONFIG_WL1251 is not set
> # CONFIG_WL12XX is not set
> CONFIG_WL18XX=3Dm
> CONFIG_WLCORE=3Dm
> # CONFIG_WLCORE_SPI is not set
> CONFIG_WLCORE_SDIO=3Dm
> CONFIG_WILINK_PLATFORM_DATA=3Dy
> CONFIG_WLAN_VENDOR_ZYDAS=3Dy
> # CONFIG_USB_ZD1201 is not set
> # CONFIG_ZD1211RW is not set
> CONFIG_WLAN_VENDOR_QUANTENNA=3Dy
> # CONFIG_QTNFMAC_PCIE is not set
> # CONFIG_MAC80211_HWSIM is not set
> # CONFIG_USB_NET_RNDIS_WLAN is not set
> # CONFIG_VIRT_WIFI is not set
> # CONFIG_WAN is not set
> CONFIG_XEN_NETDEV_FRONTEND=3Dy
> # CONFIG_XEN_NETDEV_BACKEND is not set
> # CONFIG_VMXNET3 is not set
> # CONFIG_FUJITSU_ES is not set
> # CONFIG_NETDEVSIM is not set
> CONFIG_NET_FAILOVER=3Dy
> # CONFIG_ISDN is not set
> # CONFIG_NVM is not set
>=20
> #
> # Input device support
> #
> CONFIG_INPUT=3Dy
> CONFIG_INPUT_LEDS=3Dy
> CONFIG_INPUT_FF_MEMLESS=3Dy
> # CONFIG_INPUT_POLLDEV is not set
> # CONFIG_INPUT_SPARSEKMAP is not set
> CONFIG_INPUT_MATRIXKMAP=3Dy
>=20
> #
> # Userland interfaces
> #
> # CONFIG_INPUT_MOUSEDEV is not set
> # CONFIG_INPUT_JOYDEV is not set
> CONFIG_INPUT_EVDEV=3Dy
> # CONFIG_INPUT_EVBUG is not set
>=20
> #
> # Input Device Drivers
> #
> CONFIG_INPUT_KEYBOARD=3Dy
> CONFIG_KEYBOARD_ADC=3Dm
> # CONFIG_KEYBOARD_ADP5588 is not set
> # CONFIG_KEYBOARD_ADP5589 is not set
> CONFIG_KEYBOARD_ATKBD=3Dy
> # CONFIG_KEYBOARD_QT1050 is not set
> # CONFIG_KEYBOARD_QT1070 is not set
> # CONFIG_KEYBOARD_QT2160 is not set
> # CONFIG_KEYBOARD_DLINK_DIR685 is not set
> # CONFIG_KEYBOARD_LKKBD is not set
> CONFIG_KEYBOARD_GPIO=3Dy
> # CONFIG_KEYBOARD_GPIO_POLLED is not set
> # CONFIG_KEYBOARD_TCA6416 is not set
> # CONFIG_KEYBOARD_TCA8418 is not set
> # CONFIG_KEYBOARD_MATRIX is not set
> # CONFIG_KEYBOARD_LM8323 is not set
> # CONFIG_KEYBOARD_LM8333 is not set
> # CONFIG_KEYBOARD_MAX7359 is not set
> # CONFIG_KEYBOARD_MCS is not set
> # CONFIG_KEYBOARD_MPR121 is not set
> CONFIG_KEYBOARD_SNVS_PWRKEY=3Dm
> # CONFIG_KEYBOARD_IMX is not set
> CONFIG_KEYBOARD_IMX_SC_KEY=3Dm
> # CONFIG_KEYBOARD_NEWTON is not set
> # CONFIG_KEYBOARD_TEGRA is not set
> # CONFIG_KEYBOARD_OPENCORES is not set
> # CONFIG_KEYBOARD_SAMSUNG is not set
> # CONFIG_KEYBOARD_STOWAWAY is not set
> # CONFIG_KEYBOARD_SUNKBD is not set
> # CONFIG_KEYBOARD_SUN4I_LRADC is not set
> # CONFIG_KEYBOARD_OMAP4 is not set
> # CONFIG_KEYBOARD_TM2_TOUCHKEY is not set
> # CONFIG_KEYBOARD_XTKBD is not set
> CONFIG_KEYBOARD_CROS_EC=3Dy
> # CONFIG_KEYBOARD_CAP11XX is not set
> # CONFIG_KEYBOARD_BCM is not set
> CONFIG_INPUT_MOUSE=3Dy
> CONFIG_MOUSE_PS2=3Dy
> CONFIG_MOUSE_PS2_ALPS=3Dy
> CONFIG_MOUSE_PS2_BYD=3Dy
> CONFIG_MOUSE_PS2_LOGIPS2PP=3Dy
> CONFIG_MOUSE_PS2_SYNAPTICS=3Dy
> CONFIG_MOUSE_PS2_SYNAPTICS_SMBUS=3Dy
> CONFIG_MOUSE_PS2_CYPRESS=3Dy
> CONFIG_MOUSE_PS2_TRACKPOINT=3Dy
> # CONFIG_MOUSE_PS2_ELANTECH is not set
> # CONFIG_MOUSE_PS2_SENTELIC is not set
> # CONFIG_MOUSE_PS2_TOUCHKIT is not set
> CONFIG_MOUSE_PS2_FOCALTECH=3Dy
> CONFIG_MOUSE_PS2_SMBUS=3Dy
> # CONFIG_MOUSE_SERIAL is not set
> # CONFIG_MOUSE_APPLETOUCH is not set
> # CONFIG_MOUSE_BCM5974 is not set
> # CONFIG_MOUSE_CYAPA is not set
> # CONFIG_MOUSE_ELAN_I2C is not set
> # CONFIG_MOUSE_VSXXXAA is not set
> # CONFIG_MOUSE_GPIO is not set
> # CONFIG_MOUSE_SYNAPTICS_I2C is not set
> # CONFIG_MOUSE_SYNAPTICS_USB is not set
> # CONFIG_INPUT_JOYSTICK is not set
> # CONFIG_INPUT_TABLET is not set
> CONFIG_INPUT_TOUCHSCREEN=3Dy
> CONFIG_TOUCHSCREEN_PROPERTIES=3Dy
> # CONFIG_TOUCHSCREEN_ADS7846 is not set
> # CONFIG_TOUCHSCREEN_AD7877 is not set
> # CONFIG_TOUCHSCREEN_AD7879 is not set
> # CONFIG_TOUCHSCREEN_ADC is not set
> # CONFIG_TOUCHSCREEN_AR1021_I2C is not set
> CONFIG_TOUCHSCREEN_ATMEL_MXT=3Dm
> # CONFIG_TOUCHSCREEN_ATMEL_MXT_T37 is not set
> # CONFIG_TOUCHSCREEN_AUO_PIXCIR is not set
> # CONFIG_TOUCHSCREEN_BU21013 is not set
> # CONFIG_TOUCHSCREEN_BU21029 is not set
> # CONFIG_TOUCHSCREEN_CHIPONE_ICN8318 is not set
> # CONFIG_TOUCHSCREEN_CHIPONE_ICN8505 is not set
> # CONFIG_TOUCHSCREEN_CY8CTMA140 is not set
> # CONFIG_TOUCHSCREEN_CY8CTMG110 is not set
> # CONFIG_TOUCHSCREEN_CYTTSP_CORE is not set
> # CONFIG_TOUCHSCREEN_CYTTSP4_CORE is not set
> # CONFIG_TOUCHSCREEN_DYNAPRO is not set
> # CONFIG_TOUCHSCREEN_HAMPSHIRE is not set
> # CONFIG_TOUCHSCREEN_EETI is not set
> # CONFIG_TOUCHSCREEN_EGALAX is not set
> # CONFIG_TOUCHSCREEN_EGALAX_SERIAL is not set
> # CONFIG_TOUCHSCREEN_EXC3000 is not set
> # CONFIG_TOUCHSCREEN_FUJITSU is not set
> # CONFIG_TOUCHSCREEN_GOODIX is not set
> # CONFIG_TOUCHSCREEN_HIDEEP is not set
> # CONFIG_TOUCHSCREEN_ILI210X is not set
> # CONFIG_TOUCHSCREEN_IPROC is not set
> # CONFIG_TOUCHSCREEN_S6SY761 is not set
> # CONFIG_TOUCHSCREEN_GUNZE is not set
> # CONFIG_TOUCHSCREEN_EKTF2127 is not set
> # CONFIG_TOUCHSCREEN_ELAN is not set
> # CONFIG_TOUCHSCREEN_ELO is not set
> # CONFIG_TOUCHSCREEN_WACOM_W8001 is not set
> # CONFIG_TOUCHSCREEN_WACOM_I2C is not set
> # CONFIG_TOUCHSCREEN_MAX11801 is not set
> # CONFIG_TOUCHSCREEN_MCS5000 is not set
> # CONFIG_TOUCHSCREEN_MMS114 is not set
> # CONFIG_TOUCHSCREEN_MELFAS_MIP4 is not set
> # CONFIG_TOUCHSCREEN_MTOUCH is not set
> # CONFIG_TOUCHSCREEN_IMX6UL_TSC is not set
> # CONFIG_TOUCHSCREEN_INEXIO is not set
> # CONFIG_TOUCHSCREEN_MK712 is not set
> # CONFIG_TOUCHSCREEN_PENMOUNT is not set
> # CONFIG_TOUCHSCREEN_EDT_FT5X06 is not set
> # CONFIG_TOUCHSCREEN_RASPBERRYPI_FW is not set
> # CONFIG_TOUCHSCREEN_TOUCHRIGHT is not set
> # CONFIG_TOUCHSCREEN_TOUCHWIN is not set
> # CONFIG_TOUCHSCREEN_PIXCIR is not set
> # CONFIG_TOUCHSCREEN_WDT87XX_I2C is not set
> # CONFIG_TOUCHSCREEN_USB_COMPOSITE is not set
> # CONFIG_TOUCHSCREEN_TOUCHIT213 is not set
> # CONFIG_TOUCHSCREEN_TSC_SERIO is not set
> # CONFIG_TOUCHSCREEN_TSC2004 is not set
> # CONFIG_TOUCHSCREEN_TSC2005 is not set
> # CONFIG_TOUCHSCREEN_TSC2007 is not set
> # CONFIG_TOUCHSCREEN_RM_TS is not set
> # CONFIG_TOUCHSCREEN_SILEAD is not set
> # CONFIG_TOUCHSCREEN_SIS_I2C is not set
> # CONFIG_TOUCHSCREEN_ST1232 is not set
> # CONFIG_TOUCHSCREEN_STMFTS is not set
> # CONFIG_TOUCHSCREEN_SUN4I is not set
> # CONFIG_TOUCHSCREEN_SUR40 is not set
> # CONFIG_TOUCHSCREEN_SURFACE3_SPI is not set
> # CONFIG_TOUCHSCREEN_SX8654 is not set
> # CONFIG_TOUCHSCREEN_TPS6507X is not set
> # CONFIG_TOUCHSCREEN_ZET6223 is not set
> # CONFIG_TOUCHSCREEN_ZFORCE is not set
> # CONFIG_TOUCHSCREEN_ROHM_BU21023 is not set
> # CONFIG_TOUCHSCREEN_IQS5XX is not set
> # CONFIG_TOUCHSCREEN_ZINITIX is not set
> CONFIG_INPUT_MISC=3Dy
> # CONFIG_INPUT_AD714X is not set
> # CONFIG_INPUT_ATMEL_CAPTOUCH is not set
> # CONFIG_INPUT_BMA150 is not set
> # CONFIG_INPUT_E3X0_BUTTON is not set
> CONFIG_INPUT_PM8941_PWRKEY=3Dy
> CONFIG_INPUT_PM8XXX_VIBRATOR=3Dm
> # CONFIG_INPUT_MMA8450 is not set
> # CONFIG_INPUT_GPIO_BEEPER is not set
> # CONFIG_INPUT_GPIO_DECODER is not set
> # CONFIG_INPUT_GPIO_VIBRA is not set
> # CONFIG_INPUT_ATI_REMOTE2 is not set
> # CONFIG_INPUT_KEYSPAN_REMOTE is not set
> # CONFIG_INPUT_KXTJ9 is not set
> # CONFIG_INPUT_POWERMATE is not set
> # CONFIG_INPUT_YEALINK is not set
> # CONFIG_INPUT_CM109 is not set
> # CONFIG_INPUT_REGULATOR_HAPTIC is not set
> # CONFIG_INPUT_AXP20X_PEK is not set
> # CONFIG_INPUT_UINPUT is not set
> # CONFIG_INPUT_PCF8574 is not set
> # CONFIG_INPUT_PWM_BEEPER is not set
> # CONFIG_INPUT_PWM_VIBRA is not set
> # CONFIG_INPUT_RK805_PWRKEY is not set
> # CONFIG_INPUT_GPIO_ROTARY_ENCODER is not set
> # CONFIG_INPUT_ADXL34X is not set
> # CONFIG_INPUT_IMS_PCU is not set
> # CONFIG_INPUT_IQS269A is not set
> # CONFIG_INPUT_CMA3000 is not set
> CONFIG_INPUT_XEN_KBDDEV_FRONTEND=3Dy
> # CONFIG_INPUT_SOC_BUTTON_ARRAY is not set
> # CONFIG_INPUT_DRV260X_HAPTICS is not set
> # CONFIG_INPUT_DRV2665_HAPTICS is not set
> # CONFIG_INPUT_DRV2667_HAPTICS is not set
> CONFIG_INPUT_HISI_POWERKEY=3Dy
> # CONFIG_RMI4_CORE is not set
>=20
> #
> # Hardware I/O ports
> #
> CONFIG_SERIO=3Dy
> # CONFIG_SERIO_SERPORT is not set
> CONFIG_SERIO_AMBAKMI=3Dy
> # CONFIG_SERIO_PCIPS2 is not set
> CONFIG_SERIO_LIBPS2=3Dy
> # CONFIG_SERIO_RAW is not set
> # CONFIG_SERIO_ALTERA_PS2 is not set
> # CONFIG_SERIO_PS2MULT is not set
> # CONFIG_SERIO_ARC_PS2 is not set
> # CONFIG_SERIO_APBPS2 is not set
> # CONFIG_SERIO_SUN4I_PS2 is not set
> # CONFIG_SERIO_GPIO_PS2 is not set
> # CONFIG_USERIO is not set
> # CONFIG_GAMEPORT is not set
> # end of Hardware I/O ports
> # end of Input device support
>=20
> #
> # Character devices
> #
> CONFIG_TTY=3Dy
> CONFIG_VT=3Dy
> CONFIG_CONSOLE_TRANSLATIONS=3Dy
> CONFIG_VT_CONSOLE=3Dy
> CONFIG_VT_CONSOLE_SLEEP=3Dy
> CONFIG_HW_CONSOLE=3Dy
> CONFIG_VT_HW_CONSOLE_BINDING=3Dy
> CONFIG_UNIX98_PTYS=3Dy
> CONFIG_LEGACY_PTYS=3Dy
> CONFIG_LEGACY_PTY_COUNT=3D16
> CONFIG_LDISC_AUTOLOAD=3Dy
>=20
> #
> # Serial drivers
> #
> CONFIG_SERIAL_EARLYCON=3Dy
> CONFIG_SERIAL_8250=3Dy
> CONFIG_SERIAL_8250_DEPRECATED_OPTIONS=3Dy
> CONFIG_SERIAL_8250_PNP=3Dy
> CONFIG_SERIAL_8250_16550A_VARIANTS=3Dy
> # CONFIG_SERIAL_8250_FINTEK is not set
> CONFIG_SERIAL_8250_CONSOLE=3Dy
> CONFIG_SERIAL_8250_DMA=3Dy
> CONFIG_SERIAL_8250_PCI=3Dy
> CONFIG_SERIAL_8250_EXAR=3Dy
> CONFIG_SERIAL_8250_NR_UARTS=3D4
> CONFIG_SERIAL_8250_RUNTIME_UARTS=3D4
> CONFIG_SERIAL_8250_EXTENDED=3Dy
> # CONFIG_SERIAL_8250_MANY_PORTS is not set
> # CONFIG_SERIAL_8250_ASPEED_VUART is not set
> CONFIG_SERIAL_8250_SHARE_IRQ=3Dy
> # CONFIG_SERIAL_8250_DETECT_IRQ is not set
> # CONFIG_SERIAL_8250_RSA is not set
> CONFIG_SERIAL_8250_DWLIB=3Dy
> CONFIG_SERIAL_8250_BCM2835AUX=3Dy
> CONFIG_SERIAL_8250_FSL=3Dy
> CONFIG_SERIAL_8250_DW=3Dy
> # CONFIG_SERIAL_8250_RT288X is not set
> CONFIG_SERIAL_8250_OMAP=3Dy
> CONFIG_SERIAL_8250_OMAP_TTYO_FIXUP=3Dy
> CONFIG_SERIAL_8250_MT6577=3Dy
> CONFIG_SERIAL_8250_UNIPHIER=3Dy
> CONFIG_SERIAL_8250_TEGRA=3Dy
> CONFIG_SERIAL_OF_PLATFORM=3Dy
>=20
> #
> # Non-8250 serial port support
> #
> # CONFIG_SERIAL_AMBA_PL010 is not set
> CONFIG_SERIAL_AMBA_PL011=3Dy
> CONFIG_SERIAL_AMBA_PL011_CONSOLE=3Dy
> # CONFIG_SERIAL_EARLYCON_ARM_SEMIHOST is not set
> CONFIG_SERIAL_MESON=3Dy
> CONFIG_SERIAL_MESON_CONSOLE=3Dy
> CONFIG_SERIAL_SAMSUNG=3Dy
> CONFIG_SERIAL_SAMSUNG_UARTS_4=3Dy
> CONFIG_SERIAL_SAMSUNG_UARTS=3D4
> CONFIG_SERIAL_SAMSUNG_CONSOLE=3Dy
> CONFIG_SERIAL_TEGRA=3Dy
> CONFIG_SERIAL_TEGRA_TCU=3Dy
> CONFIG_SERIAL_TEGRA_TCU_CONSOLE=3Dy
> # CONFIG_SERIAL_MAX3100 is not set
> # CONFIG_SERIAL_MAX310X is not set
> CONFIG_SERIAL_IMX=3Dy
> CONFIG_SERIAL_IMX_CONSOLE=3Dy
> # CONFIG_SERIAL_IMX_EARLYCON is not set
> # CONFIG_SERIAL_UARTLITE is not set
> CONFIG_SERIAL_SH_SCI=3Dy
> CONFIG_SERIAL_SH_SCI_NR_UARTS=3D18
> CONFIG_SERIAL_SH_SCI_CONSOLE=3Dy
> CONFIG_SERIAL_SH_SCI_EARLYCON=3Dy
> CONFIG_SERIAL_SH_SCI_DMA=3Dy
> CONFIG_SERIAL_CORE=3Dy
> CONFIG_SERIAL_CORE_CONSOLE=3Dy
> # CONFIG_SERIAL_JSM is not set
> CONFIG_SERIAL_MSM=3Dy
> CONFIG_SERIAL_MSM_CONSOLE=3Dy
> CONFIG_SERIAL_QCOM_GENI=3Dy
> CONFIG_SERIAL_QCOM_GENI_CONSOLE=3Dy
> # CONFIG_SERIAL_SIFIVE is not set
> # CONFIG_SERIAL_SCCNXP is not set
> # CONFIG_SERIAL_SC16IS7XX is not set
> # CONFIG_SERIAL_ALTERA_JTAGUART is not set
> # CONFIG_SERIAL_ALTERA_UART is not set
> # CONFIG_SERIAL_IFX6X60 is not set
> CONFIG_SERIAL_XILINX_PS_UART=3Dy
> CONFIG_SERIAL_XILINX_PS_UART_CONSOLE=3Dy
> # CONFIG_SERIAL_ARC is not set
> # CONFIG_SERIAL_RP2 is not set
> CONFIG_SERIAL_FSL_LPUART=3Dy
> CONFIG_SERIAL_FSL_LPUART_CONSOLE=3Dy
> CONFIG_SERIAL_FSL_LINFLEXUART=3Dy
> CONFIG_SERIAL_FSL_LINFLEXUART_CONSOLE=3Dy
> # CONFIG_SERIAL_CONEXANT_DIGICOLOR is not set
> # CONFIG_SERIAL_SPRD is not set
> CONFIG_SERIAL_MVEBU_UART=3Dy
> CONFIG_SERIAL_MVEBU_CONSOLE=3Dy
> CONFIG_SERIAL_OWL=3Dy
> CONFIG_SERIAL_OWL_CONSOLE=3Dy
> # end of Serial drivers
>=20
> CONFIG_SERIAL_MCTRL_GPIO=3Dy
> # CONFIG_SERIAL_NONSTANDARD is not set
> # CONFIG_N_GSM is not set
> # CONFIG_NOZOMI is not set
> # CONFIG_NULL_TTY is not set
> CONFIG_TRACE_ROUTER=3Dm
> CONFIG_TRACE_SINK=3Dm
> CONFIG_HVC_DRIVER=3Dy
> CONFIG_HVC_IRQ=3Dy
> CONFIG_HVC_XEN=3Dy
> CONFIG_HVC_XEN_FRONTEND=3Dy
> # CONFIG_HVC_DCC is not set
> CONFIG_SERIAL_DEV_BUS=3Dy
> CONFIG_SERIAL_DEV_CTRL_TTYPORT=3Dy
> CONFIG_VIRTIO_CONSOLE=3Dy
> CONFIG_IPMI_HANDLER=3Dm
> CONFIG_IPMI_DMI_DECODE=3Dy
> CONFIG_IPMI_PLAT_DATA=3Dy
> # CONFIG_IPMI_PANIC_EVENT is not set
> CONFIG_IPMI_DEVICE_INTERFACE=3Dm
> CONFIG_IPMI_SI=3Dm
> # CONFIG_IPMI_SSIF is not set
> CONFIG_IPMI_WATCHDOG=3Dm
> # CONFIG_IPMI_POWEROFF is not set
> # CONFIG_IPMB_DEVICE_INTERFACE is not set
> CONFIG_HW_RANDOM=3Dm
> # CONFIG_HW_RANDOM_TIMERIOMEM is not set
> # CONFIG_HW_RANDOM_BA431 is not set
> CONFIG_HW_RANDOM_BCM2835=3Dm
> CONFIG_HW_RANDOM_IPROC_RNG200=3Dm
> CONFIG_HW_RANDOM_OMAP=3Dm
> # CONFIG_HW_RANDOM_VIRTIO is not set
> CONFIG_HW_RANDOM_HISI=3Dm
> CONFIG_HW_RANDOM_HISI_V2=3Dm
> CONFIG_HW_RANDOM_XGENE=3Dm
> CONFIG_HW_RANDOM_MESON=3Dm
> CONFIG_HW_RANDOM_CAVIUM=3Dm
> CONFIG_HW_RANDOM_MTK=3Dm
> CONFIG_HW_RANDOM_EXYNOS=3Dm
> CONFIG_HW_RANDOM_OPTEE=3Dm
> # CONFIG_HW_RANDOM_CCTRNG is not set
> # CONFIG_HW_RANDOM_XIPHERA is not set
> # CONFIG_APPLICOM is not set
> CONFIG_DEVMEM=3Dy
> # CONFIG_RAW_DRIVER is not set
> CONFIG_DEVPORT=3Dy
> CONFIG_TCG_TPM=3Dy
> # CONFIG_TCG_TIS is not set
> # CONFIG_TCG_TIS_SPI is not set
> # CONFIG_TCG_TIS_SYNQUACER is not set
> # CONFIG_TCG_TIS_I2C_ATMEL is not set
> CONFIG_TCG_TIS_I2C_INFINEON=3Dy
> # CONFIG_TCG_TIS_I2C_NUVOTON is not set
> # CONFIG_TCG_ATMEL is not set
> # CONFIG_TCG_INFINEON is not set
> # CONFIG_TCG_XEN is not set
> # CONFIG_TCG_CRB is not set
> # CONFIG_TCG_VTPM_PROXY is not set
> # CONFIG_TCG_FTPM_TEE is not set
> # CONFIG_TCG_TIS_ST33ZP24_I2C is not set
> # CONFIG_TCG_TIS_ST33ZP24_SPI is not set
> # CONFIG_XILLYBUS is not set
> # end of Character devices
>=20
> # CONFIG_RANDOM_TRUST_CPU is not set
> # CONFIG_RANDOM_TRUST_BOOTLOADER is not set
>=20
> #
> # I2C support
> #
> CONFIG_I2C=3Dy
> CONFIG_ACPI_I2C_OPREGION=3Dy
> CONFIG_I2C_BOARDINFO=3Dy
> CONFIG_I2C_COMPAT=3Dy
> CONFIG_I2C_CHARDEV=3Dy
> CONFIG_I2C_MUX=3Dy
>=20
> #
> # Multiplexer I2C Chip support
> #
> # CONFIG_I2C_ARB_GPIO_CHALLENGE is not set
> # CONFIG_I2C_MUX_GPIO is not set
> # CONFIG_I2C_MUX_GPMUX is not set
> # CONFIG_I2C_MUX_LTC4306 is not set
> # CONFIG_I2C_MUX_PCA9541 is not set
> CONFIG_I2C_MUX_PCA954x=3Dy
> # CONFIG_I2C_MUX_PINCTRL is not set
> # CONFIG_I2C_MUX_REG is not set
> # CONFIG_I2C_DEMUX_PINCTRL is not set
> # CONFIG_I2C_MUX_MLXCPLD is not set
> # end of Multiplexer I2C Chip support
>=20
> CONFIG_I2C_HELPER_AUTO=3Dy
> CONFIG_I2C_SMBUS=3Dy
> CONFIG_I2C_ALGOBIT=3Dy
>=20
> #
> # I2C Hardware Bus support
> #
>=20
> #
> # PC SMBus host controller drivers
> #
> # CONFIG_I2C_ALI1535 is not set
> # CONFIG_I2C_ALI1563 is not set
> # CONFIG_I2C_ALI15X3 is not set
> # CONFIG_I2C_AMD756 is not set
> # CONFIG_I2C_AMD8111 is not set
> # CONFIG_I2C_AMD_MP2 is not set
> # CONFIG_I2C_HIX5HD2 is not set
> # CONFIG_I2C_I801 is not set
> # CONFIG_I2C_ISCH is not set
> # CONFIG_I2C_PIIX4 is not set
> # CONFIG_I2C_NFORCE2 is not set
> # CONFIG_I2C_NVIDIA_GPU is not set
> # CONFIG_I2C_SIS5595 is not set
> # CONFIG_I2C_SIS630 is not set
> # CONFIG_I2C_SIS96X is not set
> # CONFIG_I2C_VIA is not set
> # CONFIG_I2C_VIAPRO is not set
>=20
> #
> # ACPI drivers
> #
> # CONFIG_I2C_SCMI is not set
>=20
> #
> # I2C system bus drivers (mostly embedded / system-on-chip)
> #
> CONFIG_I2C_BCM2835=3Dm
> CONFIG_I2C_BCM_IPROC=3Dy
> CONFIG_I2C_BRCMSTB=3Dy
> # CONFIG_I2C_CADENCE is not set
> # CONFIG_I2C_CBUS_GPIO is not set
> CONFIG_I2C_DESIGNWARE_CORE=3Dy
> # CONFIG_I2C_DESIGNWARE_SLAVE is not set
> CONFIG_I2C_DESIGNWARE_PLATFORM=3Dy
> # CONFIG_I2C_DESIGNWARE_PCI is not set
> # CONFIG_I2C_EMEV2 is not set
> CONFIG_I2C_EXYNOS5=3Dy
> CONFIG_I2C_GPIO=3Dm
> # CONFIG_I2C_GPIO_FAULT_INJECTOR is not set
> CONFIG_I2C_IMX=3Dy
> CONFIG_I2C_IMX_LPI2C=3Dy
> CONFIG_I2C_MESON=3Dy
> # CONFIG_I2C_MT65XX is not set
> CONFIG_I2C_MV64XXX=3Dy
> # CONFIG_I2C_NOMADIK is not set
> # CONFIG_I2C_OCORES is not set
> # CONFIG_I2C_OMAP is not set
> CONFIG_I2C_OWL=3Dy
> # CONFIG_I2C_PCA_PLATFORM is not set
> CONFIG_I2C_PXA=3Dy
> # CONFIG_I2C_PXA_SLAVE is not set
> CONFIG_I2C_QCOM_CCI=3Dm
> CONFIG_I2C_QCOM_GENI=3Dm
> CONFIG_I2C_QUP=3Dy
> # CONFIG_I2C_RIIC is not set
> CONFIG_I2C_RK3X=3Dy
> CONFIG_I2C_SH_MOBILE=3Dy
> # CONFIG_I2C_SIMTEC is not set
> # CONFIG_I2C_SPRD is not set
> # CONFIG_I2C_SYNQUACER is not set
> CONFIG_I2C_TEGRA=3Dy
> CONFIG_I2C_TEGRA_BPMP=3Dy
> # CONFIG_I2C_UNIPHIER is not set
> CONFIG_I2C_UNIPHIER_F=3Dy
> # CONFIG_I2C_VERSATILE is not set
> # CONFIG_I2C_THUNDERX is not set
> # CONFIG_I2C_XILINX is not set
> # CONFIG_I2C_XLP9XX is not set
> CONFIG_I2C_RCAR=3Dy
>=20
> #
> # External I2C/SMBus adapter drivers
> #
> # CONFIG_I2C_DIOLAN_U2C is not set
> # CONFIG_I2C_ROBOTFUZZ_OSIF is not set
> # CONFIG_I2C_TAOS_EVM is not set
> # CONFIG_I2C_TINY_USB is not set
>=20
> #
> # Other I2C/SMBus bus drivers
> #
> CONFIG_I2C_CROS_EC_TUNNEL=3Dy
> # CONFIG_I2C_XGENE_SLIMPRO is not set
> CONFIG_I2C_ZX2967=3Dy
> # end of I2C Hardware Bus support
>=20
> # CONFIG_I2C_STUB is not set
> CONFIG_I2C_SLAVE=3Dy
> # CONFIG_I2C_SLAVE_EEPROM is not set
> # CONFIG_I2C_SLAVE_TESTUNIT is not set
> # CONFIG_I2C_DEBUG_CORE is not set
> # CONFIG_I2C_DEBUG_ALGO is not set
> # CONFIG_I2C_DEBUG_BUS is not set
> # end of I2C support
>=20
> # CONFIG_I3C is not set
> CONFIG_SPI=3Dy
> # CONFIG_SPI_DEBUG is not set
> CONFIG_SPI_MASTER=3Dy
> CONFIG_SPI_MEM=3Dy
>=20
> #
> # SPI Master Controller Drivers
> #
> # CONFIG_SPI_ALTERA is not set
> CONFIG_SPI_ARMADA_3700=3Dy
> # CONFIG_SPI_AXI_SPI_ENGINE is not set
> CONFIG_SPI_BCM2835=3Dm
> CONFIG_SPI_BCM2835AUX=3Dm
> CONFIG_SPI_BCM_QSPI=3Dy
> CONFIG_SPI_BITBANG=3Dm
> # CONFIG_SPI_CADENCE is not set
> CONFIG_SPI_CADENCE_QUADSPI=3Dy
> # CONFIG_SPI_DESIGNWARE is not set
> CONFIG_SPI_FSL_LPSPI=3Dy
> CONFIG_SPI_FSL_QUADSPI=3Dy
> # CONFIG_SPI_HISI_SFC_V3XX is not set
> CONFIG_SPI_NXP_FLEXSPI=3Dy
> # CONFIG_SPI_GPIO is not set
> CONFIG_SPI_IMX=3Dm
> # CONFIG_SPI_FSL_SPI is not set
> CONFIG_SPI_FSL_DSPI=3Dy
> CONFIG_SPI_MESON_SPICC=3Dm
> CONFIG_SPI_MESON_SPIFC=3Dm
> # CONFIG_SPI_MT65XX is not set
> # CONFIG_SPI_MTK_NOR is not set
> # CONFIG_SPI_OC_TINY is not set
> # CONFIG_SPI_OMAP24XX is not set
> CONFIG_SPI_ORION=3Dy
> CONFIG_SPI_PL022=3Dy
> # CONFIG_SPI_PXA2XX is not set
> CONFIG_SPI_ROCKCHIP=3Dy
> # CONFIG_SPI_RSPI is not set
> CONFIG_SPI_QCOM_QSPI=3Dm
> CONFIG_SPI_QUP=3Dy
> CONFIG_SPI_QCOM_GENI=3Dm
> CONFIG_SPI_S3C64XX=3Dy
> # CONFIG_SPI_SC18IS602 is not set
> CONFIG_SPI_SH_MSIOF=3Dm
> # CONFIG_SPI_SH_HSPI is not set
> # CONFIG_SPI_SIFIVE is not set
> # CONFIG_SPI_SPRD is not set
> # CONFIG_SPI_SPRD_ADI is not set
> # CONFIG_SPI_SUN4I is not set
> CONFIG_SPI_SUN6I=3Dy
> # CONFIG_SPI_SYNQUACER is not set
> # CONFIG_SPI_MXIC is not set
> # CONFIG_SPI_TEGRA114 is not set
> # CONFIG_SPI_TEGRA20_SFLASH is not set
> # CONFIG_SPI_TEGRA20_SLINK is not set
> # CONFIG_SPI_THUNDERX is not set
> # CONFIG_SPI_UNIPHIER is not set
> # CONFIG_SPI_XCOMM is not set
> # CONFIG_SPI_XILINX is not set
> # CONFIG_SPI_XLP is not set
> # CONFIG_SPI_ZYNQMP_GQSPI is not set
> # CONFIG_SPI_AMD is not set
>=20
> #
> # SPI Multiplexer support
> #
> # CONFIG_SPI_MUX is not set
>=20
> #
> # SPI Protocol Masters
> #
> CONFIG_SPI_SPIDEV=3Dm
> # CONFIG_SPI_LOOPBACK_TEST is not set
> # CONFIG_SPI_TLE62X0 is not set
> # CONFIG_SPI_SLAVE is not set
> CONFIG_SPI_DYNAMIC=3Dy
> CONFIG_SPMI=3Dy
> CONFIG_SPMI_MSM_PMIC_ARB=3Dy
> # CONFIG_HSI is not set
> CONFIG_PPS=3Dy
> # CONFIG_PPS_DEBUG is not set
>=20
> #
> # PPS clients support
> #
> # CONFIG_PPS_CLIENT_KTIMER is not set
> # CONFIG_PPS_CLIENT_LDISC is not set
> # CONFIG_PPS_CLIENT_GPIO is not set
>=20
> #
> # PPS generators support
> #
>=20
> #
> # PTP clock support
> #
> CONFIG_PTP_1588_CLOCK=3Dy
> CONFIG_PTP_1588_CLOCK_DTE=3Dy
> CONFIG_PTP_1588_CLOCK_QORIQ=3Dy
>=20
> #
> # Enable PHYLIB and NETWORK_PHY_TIMESTAMPING to see the additional clocks=
.
> #
> # CONFIG_PTP_1588_CLOCK_IDT82P33 is not set
> # CONFIG_PTP_1588_CLOCK_IDTCM is not set
> # end of PTP clock support
>=20
> CONFIG_PINCTRL=3Dy
> CONFIG_GENERIC_PINCTRL_GROUPS=3Dy
> CONFIG_PINMUX=3Dy
> CONFIG_GENERIC_PINMUX_FUNCTIONS=3Dy
> CONFIG_PINCONF=3Dy
> CONFIG_GENERIC_PINCONF=3Dy
> # CONFIG_DEBUG_PINCTRL is not set
> # CONFIG_PINCTRL_AXP209 is not set
> # CONFIG_PINCTRL_AMD is not set
> # CONFIG_PINCTRL_MCP23S08 is not set
> CONFIG_PINCTRL_ROCKCHIP=3Dy
> CONFIG_PINCTRL_SINGLE=3Dy
> # CONFIG_PINCTRL_SX150X is not set
> # CONFIG_PINCTRL_STMFX is not set
> CONFIG_PINCTRL_MAX77620=3Dy
> # CONFIG_PINCTRL_RK805 is not set
> # CONFIG_PINCTRL_OCELOT is not set
> CONFIG_PINCTRL_OWL=3Dy
> # CONFIG_PINCTRL_S500 is not set
> CONFIG_PINCTRL_S700=3Dy
> CONFIG_PINCTRL_S900=3Dy
> CONFIG_PINCTRL_BCM2835=3Dy
> CONFIG_PINCTRL_IPROC_GPIO=3Dy
> CONFIG_PINCTRL_NS2_MUX=3Dy
> # CONFIG_PINCTRL_AS370 is not set
> # CONFIG_PINCTRL_BERLIN_BG4CT is not set
> CONFIG_PINCTRL_IMX=3Dy
> CONFIG_PINCTRL_IMX_SCU=3Dy
> CONFIG_PINCTRL_IMX8MM=3Dy
> CONFIG_PINCTRL_IMX8MN=3Dy
> CONFIG_PINCTRL_IMX8MP=3Dy
> CONFIG_PINCTRL_IMX8MQ=3Dy
> # CONFIG_PINCTRL_IMX8QM is not set
> CONFIG_PINCTRL_IMX8QXP=3Dy
> CONFIG_PINCTRL_IMX8DXL=3Dy
> CONFIG_PINCTRL_MVEBU=3Dy
> CONFIG_PINCTRL_ARMADA_AP806=3Dy
> CONFIG_PINCTRL_ARMADA_CP110=3Dy
> CONFIG_PINCTRL_ARMADA_37XX=3Dy
> CONFIG_PINCTRL_MSM=3Dy
> # CONFIG_PINCTRL_APQ8064 is not set
> # CONFIG_PINCTRL_APQ8084 is not set
> # CONFIG_PINCTRL_IPQ4019 is not set
> # CONFIG_PINCTRL_IPQ8064 is not set
> CONFIG_PINCTRL_IPQ8074=3Dy
> CONFIG_PINCTRL_IPQ6018=3Dy
> # CONFIG_PINCTRL_MSM8226 is not set
> # CONFIG_PINCTRL_MSM8660 is not set
> # CONFIG_PINCTRL_MSM8960 is not set
> # CONFIG_PINCTRL_MDM9615 is not set
> # CONFIG_PINCTRL_MSM8X74 is not set
> CONFIG_PINCTRL_MSM8916=3Dy
> # CONFIG_PINCTRL_MSM8953 is not set
> # CONFIG_PINCTRL_MSM8976 is not set
> CONFIG_PINCTRL_MSM8994=3Dy
> CONFIG_PINCTRL_MSM8996=3Dy
> CONFIG_PINCTRL_MSM8998=3Dy
> CONFIG_PINCTRL_QCS404=3Dy
> CONFIG_PINCTRL_QDF2XXX=3Dy
> CONFIG_PINCTRL_QCOM_SPMI_PMIC=3Dy
> # CONFIG_PINCTRL_QCOM_SSBI_PMIC is not set
> CONFIG_PINCTRL_SC7180=3Dy
> # CONFIG_PINCTRL_SDM660 is not set
> CONFIG_PINCTRL_SDM845=3Dy
> CONFIG_PINCTRL_SM8150=3Dy
> # CONFIG_PINCTRL_SM8250 is not set
>=20
> #
> # Renesas pinctrl drivers
> #
> CONFIG_PINCTRL_RENESAS=3Dy
> CONFIG_PINCTRL_SH_PFC=3Dy
> CONFIG_PINCTRL_PFC_R8A77995=3Dy
> CONFIG_PINCTRL_PFC_R8A77990=3Dy
> CONFIG_PINCTRL_PFC_R8A77950=3Dy
> CONFIG_PINCTRL_PFC_R8A77951=3Dy
> CONFIG_PINCTRL_PFC_R8A77965=3Dy
> CONFIG_PINCTRL_PFC_R8A77960=3Dy
> CONFIG_PINCTRL_PFC_R8A77961=3Dy
> CONFIG_PINCTRL_PFC_R8A77980=3Dy
> CONFIG_PINCTRL_PFC_R8A77970=3Dy
> CONFIG_PINCTRL_PFC_R8A774C0=3Dy
> CONFIG_PINCTRL_PFC_R8A774A1=3Dy
> CONFIG_PINCTRL_PFC_R8A774B1=3Dy
> # end of Renesas pinctrl drivers
>=20
> CONFIG_PINCTRL_SAMSUNG=3Dy
> CONFIG_PINCTRL_EXYNOS=3Dy
> CONFIG_PINCTRL_EXYNOS_ARM64=3Dy
> # CONFIG_PINCTRL_SPRD_SC9860 is not set
> CONFIG_PINCTRL_SUNXI=3Dy
> # CONFIG_PINCTRL_SUN4I_A10 is not set
> # CONFIG_PINCTRL_SUN5I is not set
> # CONFIG_PINCTRL_SUN6I_A31 is not set
> # CONFIG_PINCTRL_SUN6I_A31_R is not set
> # CONFIG_PINCTRL_SUN8I_A23 is not set
> # CONFIG_PINCTRL_SUN8I_A33 is not set
> # CONFIG_PINCTRL_SUN8I_A83T is not set
> # CONFIG_PINCTRL_SUN8I_A83T_R is not set
> # CONFIG_PINCTRL_SUN8I_A23_R is not set
> # CONFIG_PINCTRL_SUN8I_H3 is not set
> CONFIG_PINCTRL_SUN8I_H3_R=3Dy
> # CONFIG_PINCTRL_SUN8I_V3S is not set
> # CONFIG_PINCTRL_SUN9I_A80 is not set
> # CONFIG_PINCTRL_SUN9I_A80_R is not set
> CONFIG_PINCTRL_SUN50I_A64=3Dy
> CONFIG_PINCTRL_SUN50I_A64_R=3Dy
> CONFIG_PINCTRL_SUN50I_A100=3Dy
> CONFIG_PINCTRL_SUN50I_A100_R=3Dy
> CONFIG_PINCTRL_SUN50I_H5=3Dy
> CONFIG_PINCTRL_SUN50I_H6=3Dy
> CONFIG_PINCTRL_SUN50I_H6_R=3Dy
> CONFIG_PINCTRL_TEGRA=3Dy
> CONFIG_PINCTRL_TEGRA124=3Dy
> CONFIG_PINCTRL_TEGRA210=3Dy
> CONFIG_PINCTRL_TEGRA194=3Dy
> CONFIG_PINCTRL_TEGRA_XUSB=3Dy
> CONFIG_PINCTRL_UNIPHIER=3Dy
> # CONFIG_PINCTRL_UNIPHIER_LD4 is not set
> # CONFIG_PINCTRL_UNIPHIER_PRO4 is not set
> # CONFIG_PINCTRL_UNIPHIER_SLD8 is not set
> # CONFIG_PINCTRL_UNIPHIER_PRO5 is not set
> # CONFIG_PINCTRL_UNIPHIER_PXS2 is not set
> # CONFIG_PINCTRL_UNIPHIER_LD6B is not set
> CONFIG_PINCTRL_UNIPHIER_LD11=3Dy
> CONFIG_PINCTRL_UNIPHIER_LD20=3Dy
> CONFIG_PINCTRL_UNIPHIER_PXS3=3Dy
>=20
> #
> # MediaTek pinctrl drivers
> #
> CONFIG_EINT_MTK=3Dy
> CONFIG_PINCTRL_MTK=3Dy
> CONFIG_PINCTRL_MTK_V2=3Dy
> CONFIG_PINCTRL_MTK_MOORE=3Dy
> CONFIG_PINCTRL_MTK_PARIS=3Dy
> CONFIG_PINCTRL_MT2712=3Dy
> CONFIG_PINCTRL_MT6765=3Dy
> CONFIG_PINCTRL_MT6779=3Dy
> CONFIG_PINCTRL_MT6797=3Dy
> CONFIG_PINCTRL_MT7622=3Dy
> CONFIG_PINCTRL_MT8167=3Dy
> CONFIG_PINCTRL_MT8173=3Dy
> CONFIG_PINCTRL_MT8183=3Dy
> CONFIG_PINCTRL_MT8192=3Dy
> CONFIG_PINCTRL_MT8516=3Dy
> # end of MediaTek pinctrl drivers
>=20
> # CONFIG_PINCTRL_ZX296718 is not set
> CONFIG_PINCTRL_MESON=3Dy
> CONFIG_PINCTRL_MESON_GXBB=3Dy
> CONFIG_PINCTRL_MESON_GXL=3Dy
> CONFIG_PINCTRL_MESON8_PMX=3Dy
> CONFIG_PINCTRL_MESON_AXG=3Dy
> CONFIG_PINCTRL_MESON_AXG_PMX=3Dy
> CONFIG_PINCTRL_MESON_G12A=3Dy
> CONFIG_PINCTRL_MESON_A1=3Dy
> CONFIG_GPIOLIB=3Dy
> CONFIG_GPIOLIB_FASTPATH_LIMIT=3D512
> CONFIG_OF_GPIO=3Dy
> CONFIG_GPIO_ACPI=3Dy
> CONFIG_GPIOLIB_IRQCHIP=3Dy
> # CONFIG_DEBUG_GPIO is not set
> # CONFIG_GPIO_SYSFS is not set
> CONFIG_GPIO_CDEV=3Dy
> CONFIG_GPIO_CDEV_V1=3Dy
> CONFIG_GPIO_GENERIC=3Dy
>=20
> #
> # Memory mapped GPIO drivers
> #
> # CONFIG_GPIO_74XX_MMIO is not set
> CONFIG_GPIO_ALTERA=3Dm
> # CONFIG_GPIO_AMDPT is not set
> CONFIG_GPIO_RASPBERRYPI_EXP=3Dy
> CONFIG_GPIO_BCM_XGS_IPROC=3Dy
> CONFIG_GPIO_BRCMSTB=3Dy
> # CONFIG_GPIO_CADENCE is not set
> # CONFIG_GPIO_DAVINCI is not set
> CONFIG_GPIO_DWAPB=3Dy
> # CONFIG_GPIO_EIC_SPRD is not set
> # CONFIG_GPIO_EXAR is not set
> # CONFIG_GPIO_FTGPIO010 is not set
> CONFIG_GPIO_GENERIC_PLATFORM=3Dy
> # CONFIG_GPIO_GRGPIO is not set
> # CONFIG_GPIO_HLWD is not set
> # CONFIG_GPIO_LOGICVC is not set
> CONFIG_GPIO_MB86S7X=3Dy
> CONFIG_GPIO_MPC8XXX=3Dy
> CONFIG_GPIO_MVEBU=3Dy
> CONFIG_GPIO_MXC=3Dy
> CONFIG_GPIO_PL061=3Dy
> CONFIG_GPIO_RCAR=3Dy
> # CONFIG_GPIO_SAMA5D2_PIOBU is not set
> # CONFIG_GPIO_SIFIVE is not set
> # CONFIG_GPIO_SPRD is not set
> # CONFIG_GPIO_SYSCON is not set
> CONFIG_GPIO_TEGRA=3Dy
> CONFIG_GPIO_TEGRA186=3Dy
> # CONFIG_GPIO_THUNDERX is not set
> CONFIG_GPIO_UNIPHIER=3Dy
> CONFIG_GPIO_WCD934X=3Dm
> CONFIG_GPIO_XGENE=3Dy
> CONFIG_GPIO_XGENE_SB=3Dy
> # CONFIG_GPIO_XILINX is not set
> # CONFIG_GPIO_XLP is not set
> # CONFIG_GPIO_ZYNQ is not set
> # CONFIG_GPIO_ZX is not set
> # CONFIG_GPIO_AMD_FCH is not set
> # end of Memory mapped GPIO drivers
>=20
> #
> # I2C GPIO expanders
> #
> # CONFIG_GPIO_ADP5588 is not set
> # CONFIG_GPIO_ADNP is not set
> # CONFIG_GPIO_GW_PLD is not set
> # CONFIG_GPIO_MAX7300 is not set
> CONFIG_GPIO_MAX732X=3Dy
> # CONFIG_GPIO_MAX732X_IRQ is not set
> CONFIG_GPIO_PCA953X=3Dy
> CONFIG_GPIO_PCA953X_IRQ=3Dy
> # CONFIG_GPIO_PCA9570 is not set
> # CONFIG_GPIO_PCF857X is not set
> # CONFIG_GPIO_TPIC2810 is not set
> # end of I2C GPIO expanders
>=20
> #
> # MFD GPIO expanders
> #
> CONFIG_GPIO_BD9571MWV=3Dm
> CONFIG_GPIO_MAX77620=3Dy
> # end of MFD GPIO expanders
>=20
> #
> # PCI GPIO expanders
> #
> # CONFIG_GPIO_BT8XX is not set
> # CONFIG_GPIO_PCI_IDIO_16 is not set
> # CONFIG_GPIO_PCIE_IDIO_24 is not set
> # CONFIG_GPIO_RDC321X is not set
> # end of PCI GPIO expanders
>=20
> #
> # SPI GPIO expanders
> #
> # CONFIG_GPIO_74X164 is not set
> # CONFIG_GPIO_MAX3191X is not set
> # CONFIG_GPIO_MAX7301 is not set
> # CONFIG_GPIO_MC33880 is not set
> # CONFIG_GPIO_PISOSR is not set
> # CONFIG_GPIO_XRA1403 is not set
> # end of SPI GPIO expanders
>=20
> #
> # USB GPIO expanders
> #
> # end of USB GPIO expanders
>=20
> # CONFIG_GPIO_AGGREGATOR is not set
> # CONFIG_GPIO_MOCKUP is not set
> # CONFIG_W1 is not set
> CONFIG_POWER_RESET=3Dy
> CONFIG_POWER_RESET_BRCMSTB=3Dy
> # CONFIG_POWER_RESET_GPIO is not set
> # CONFIG_POWER_RESET_GPIO_RESTART is not set
> # CONFIG_POWER_RESET_HISI is not set
> # CONFIG_POWER_RESET_LINKSTATION is not set
> CONFIG_POWER_RESET_MSM=3Dy
> # CONFIG_POWER_RESET_QCOM_PON is not set
> # CONFIG_POWER_RESET_LTC2952 is not set
> # CONFIG_POWER_RESET_RESTART is not set
> # CONFIG_POWER_RESET_VEXPRESS is not set
> CONFIG_POWER_RESET_XGENE=3Dy
> CONFIG_POWER_RESET_SYSCON=3Dy
> # CONFIG_POWER_RESET_SYSCON_POWEROFF is not set
> # CONFIG_POWER_RESET_ZX is not set
> CONFIG_REBOOT_MODE=3Dy
> CONFIG_SYSCON_REBOOT_MODE=3Dy
> # CONFIG_NVMEM_REBOOT_MODE is not set
> CONFIG_POWER_SUPPLY=3Dy
> # CONFIG_POWER_SUPPLY_DEBUG is not set
> CONFIG_POWER_SUPPLY_HWMON=3Dy
> # CONFIG_PDA_POWER is not set
> # CONFIG_GENERIC_ADC_BATTERY is not set
> CONFIG_TEST_POWER=3Dm
> # CONFIG_CHARGER_ADP5061 is not set
> # CONFIG_BATTERY_CW2015 is not set
> # CONFIG_BATTERY_DS2780 is not set
> # CONFIG_BATTERY_DS2781 is not set
> # CONFIG_BATTERY_DS2782 is not set
> CONFIG_BATTERY_SBS=3Dm
> # CONFIG_CHARGER_SBS is not set
> # CONFIG_MANAGER_SBS is not set
> CONFIG_BATTERY_BQ27XXX=3Dy
> CONFIG_BATTERY_BQ27XXX_I2C=3Dy
> # CONFIG_BATTERY_BQ27XXX_DT_UPDATES_NVM is not set
> # CONFIG_AXP20X_POWER is not set
> # CONFIG_AXP288_FUEL_GAUGE is not set
> # CONFIG_BATTERY_MAX17040 is not set
> # CONFIG_BATTERY_MAX17042 is not set
> # CONFIG_CHARGER_ISP1704 is not set
> # CONFIG_CHARGER_MAX8903 is not set
> # CONFIG_CHARGER_LP8727 is not set
> # CONFIG_CHARGER_GPIO is not set
> # CONFIG_CHARGER_MANAGER is not set
> # CONFIG_CHARGER_LT3651 is not set
> # CONFIG_CHARGER_DETECTOR_MAX14656 is not set
> # CONFIG_CHARGER_QCOM_SMBB is not set
> # CONFIG_CHARGER_BQ2415X is not set
> # CONFIG_CHARGER_BQ24190 is not set
> # CONFIG_CHARGER_BQ24257 is not set
> # CONFIG_CHARGER_BQ24735 is not set
> # CONFIG_CHARGER_BQ2515X is not set
> # CONFIG_CHARGER_BQ25890 is not set
> # CONFIG_CHARGER_BQ25980 is not set
> # CONFIG_CHARGER_SMB347 is not set
> # CONFIG_BATTERY_GAUGE_LTC2941 is not set
> # CONFIG_CHARGER_RT9455 is not set
> # CONFIG_CHARGER_CROS_USBPD is not set
> # CONFIG_CHARGER_UCS1002 is not set
> # CONFIG_CHARGER_BD99954 is not set
> CONFIG_HWMON=3Dy
> # CONFIG_HWMON_DEBUG_CHIP is not set
>=20
> #
> # Native drivers
> #
> # CONFIG_SENSORS_AD7314 is not set
> # CONFIG_SENSORS_AD7414 is not set
> # CONFIG_SENSORS_AD7418 is not set
> # CONFIG_SENSORS_ADM1021 is not set
> # CONFIG_SENSORS_ADM1025 is not set
> # CONFIG_SENSORS_ADM1026 is not set
> # CONFIG_SENSORS_ADM1029 is not set
> # CONFIG_SENSORS_ADM1031 is not set
> # CONFIG_SENSORS_ADM1177 is not set
> # CONFIG_SENSORS_ADM9240 is not set
> # CONFIG_SENSORS_ADT7310 is not set
> # CONFIG_SENSORS_ADT7410 is not set
> # CONFIG_SENSORS_ADT7411 is not set
> # CONFIG_SENSORS_ADT7462 is not set
> # CONFIG_SENSORS_ADT7470 is not set
> # CONFIG_SENSORS_ADT7475 is not set
> # CONFIG_SENSORS_AS370 is not set
> # CONFIG_SENSORS_ASC7621 is not set
> # CONFIG_SENSORS_AXI_FAN_CONTROL is not set
> CONFIG_SENSORS_ARM_SCPI=3Dy
> # CONFIG_SENSORS_ASPEED is not set
> # CONFIG_SENSORS_ATXP1 is not set
> # CONFIG_SENSORS_CORSAIR_CPRO is not set
> # CONFIG_SENSORS_CORSAIR_PSU is not set
> # CONFIG_SENSORS_DRIVETEMP is not set
> # CONFIG_SENSORS_DS620 is not set
> # CONFIG_SENSORS_DS1621 is not set
> # CONFIG_SENSORS_I5K_AMB is not set
> # CONFIG_SENSORS_F71805F is not set
> # CONFIG_SENSORS_F71882FG is not set
> # CONFIG_SENSORS_F75375S is not set
> # CONFIG_SENSORS_FTSTEUTATES is not set
> # CONFIG_SENSORS_GL518SM is not set
> # CONFIG_SENSORS_GL520SM is not set
> # CONFIG_SENSORS_G760A is not set
> # CONFIG_SENSORS_G762 is not set
> # CONFIG_SENSORS_GPIO_FAN is not set
> # CONFIG_SENSORS_HIH6130 is not set
> # CONFIG_SENSORS_IBMAEM is not set
> # CONFIG_SENSORS_IBMPEX is not set
> # CONFIG_SENSORS_IIO_HWMON is not set
> # CONFIG_SENSORS_IT87 is not set
> # CONFIG_SENSORS_JC42 is not set
> # CONFIG_SENSORS_POWR1220 is not set
> # CONFIG_SENSORS_LINEAGE is not set
> # CONFIG_SENSORS_LTC2945 is not set
> # CONFIG_SENSORS_LTC2947_I2C is not set
> # CONFIG_SENSORS_LTC2947_SPI is not set
> # CONFIG_SENSORS_LTC2990 is not set
> # CONFIG_SENSORS_LTC4151 is not set
> # CONFIG_SENSORS_LTC4215 is not set
> # CONFIG_SENSORS_LTC4222 is not set
> # CONFIG_SENSORS_LTC4245 is not set
> # CONFIG_SENSORS_LTC4260 is not set
> # CONFIG_SENSORS_LTC4261 is not set
> # CONFIG_SENSORS_MAX1111 is not set
> # CONFIG_SENSORS_MAX16065 is not set
> # CONFIG_SENSORS_MAX1619 is not set
> # CONFIG_SENSORS_MAX1668 is not set
> # CONFIG_SENSORS_MAX197 is not set
> # CONFIG_SENSORS_MAX31722 is not set
> # CONFIG_SENSORS_MAX31730 is not set
> # CONFIG_SENSORS_MAX6621 is not set
> # CONFIG_SENSORS_MAX6639 is not set
> # CONFIG_SENSORS_MAX6642 is not set
> # CONFIG_SENSORS_MAX6650 is not set
> # CONFIG_SENSORS_MAX6697 is not set
> # CONFIG_SENSORS_MAX31790 is not set
> # CONFIG_SENSORS_MCP3021 is not set
> # CONFIG_SENSORS_TC654 is not set
> # CONFIG_SENSORS_MR75203 is not set
> # CONFIG_SENSORS_ADCXX is not set
> # CONFIG_SENSORS_LM63 is not set
> # CONFIG_SENSORS_LM70 is not set
> # CONFIG_SENSORS_LM73 is not set
> # CONFIG_SENSORS_LM75 is not set
> # CONFIG_SENSORS_LM77 is not set
> # CONFIG_SENSORS_LM78 is not set
> # CONFIG_SENSORS_LM80 is not set
> # CONFIG_SENSORS_LM83 is not set
> # CONFIG_SENSORS_LM85 is not set
> # CONFIG_SENSORS_LM87 is not set
> CONFIG_SENSORS_LM90=3Dm
> # CONFIG_SENSORS_LM92 is not set
> # CONFIG_SENSORS_LM93 is not set
> # CONFIG_SENSORS_LM95234 is not set
> # CONFIG_SENSORS_LM95241 is not set
> # CONFIG_SENSORS_LM95245 is not set
> # CONFIG_SENSORS_PC87360 is not set
> # CONFIG_SENSORS_PC87427 is not set
> # CONFIG_SENSORS_NTC_THERMISTOR is not set
> # CONFIG_SENSORS_NCT6683 is not set
> # CONFIG_SENSORS_NCT6775 is not set
> # CONFIG_SENSORS_NCT7802 is not set
> # CONFIG_SENSORS_NCT7904 is not set
> # CONFIG_SENSORS_NPCM7XX is not set
> # CONFIG_SENSORS_OCC_P8_I2C is not set
> # CONFIG_SENSORS_PCF8591 is not set
> # CONFIG_PMBUS is not set
> CONFIG_SENSORS_PWM_FAN=3Dm
> CONFIG_SENSORS_RASPBERRYPI_HWMON=3Dm
> # CONFIG_SENSORS_SHT15 is not set
> # CONFIG_SENSORS_SHT21 is not set
> # CONFIG_SENSORS_SHT3x is not set
> # CONFIG_SENSORS_SHTC1 is not set
> # CONFIG_SENSORS_SIS5595 is not set
> # CONFIG_SENSORS_DME1737 is not set
> # CONFIG_SENSORS_EMC1403 is not set
> # CONFIG_SENSORS_EMC2103 is not set
> # CONFIG_SENSORS_EMC6W201 is not set
> # CONFIG_SENSORS_SMSC47M1 is not set
> # CONFIG_SENSORS_SMSC47M192 is not set
> # CONFIG_SENSORS_SMSC47B397 is not set
> # CONFIG_SENSORS_SCH5627 is not set
> # CONFIG_SENSORS_SCH5636 is not set
> # CONFIG_SENSORS_STTS751 is not set
> # CONFIG_SENSORS_SMM665 is not set
> # CONFIG_SENSORS_ADC128D818 is not set
> # CONFIG_SENSORS_ADS7828 is not set
> # CONFIG_SENSORS_ADS7871 is not set
> # CONFIG_SENSORS_AMC6821 is not set
> # CONFIG_SENSORS_INA209 is not set
> CONFIG_SENSORS_INA2XX=3Dm
> CONFIG_SENSORS_INA3221=3Dm
> # CONFIG_SENSORS_TC74 is not set
> # CONFIG_SENSORS_THMC50 is not set
> # CONFIG_SENSORS_TMP102 is not set
> # CONFIG_SENSORS_TMP103 is not set
> # CONFIG_SENSORS_TMP108 is not set
> # CONFIG_SENSORS_TMP401 is not set
> # CONFIG_SENSORS_TMP421 is not set
> # CONFIG_SENSORS_TMP513 is not set
> # CONFIG_SENSORS_VEXPRESS is not set
> # CONFIG_SENSORS_VIA686A is not set
> # CONFIG_SENSORS_VT1211 is not set
> # CONFIG_SENSORS_VT8231 is not set
> # CONFIG_SENSORS_W83773G is not set
> # CONFIG_SENSORS_W83781D is not set
> # CONFIG_SENSORS_W83791D is not set
> # CONFIG_SENSORS_W83792D is not set
> # CONFIG_SENSORS_W83793 is not set
> # CONFIG_SENSORS_W83795 is not set
> # CONFIG_SENSORS_W83L785TS is not set
> # CONFIG_SENSORS_W83L786NG is not set
> # CONFIG_SENSORS_W83627HF is not set
> # CONFIG_SENSORS_W83627EHF is not set
> # CONFIG_SENSORS_XGENE is not set
>=20
> #
> # ACPI drivers
> #
> # CONFIG_SENSORS_ACPI_POWER is not set
> CONFIG_THERMAL=3Dy
> # CONFIG_THERMAL_NETLINK is not set
> # CONFIG_THERMAL_STATISTICS is not set
> CONFIG_THERMAL_EMERGENCY_POWEROFF_DELAY_MS=3D0
> CONFIG_THERMAL_HWMON=3Dy
> CONFIG_THERMAL_OF=3Dy
> # CONFIG_THERMAL_WRITABLE_TRIPS is not set
> CONFIG_THERMAL_DEFAULT_GOV_STEP_WISE=3Dy
> # CONFIG_THERMAL_DEFAULT_GOV_FAIR_SHARE is not set
> # CONFIG_THERMAL_DEFAULT_GOV_USER_SPACE is not set
> # CONFIG_THERMAL_DEFAULT_GOV_POWER_ALLOCATOR is not set
> # CONFIG_THERMAL_GOV_FAIR_SHARE is not set
> CONFIG_THERMAL_GOV_STEP_WISE=3Dy
> # CONFIG_THERMAL_GOV_BANG_BANG is not set
> # CONFIG_THERMAL_GOV_USER_SPACE is not set
> CONFIG_THERMAL_GOV_POWER_ALLOCATOR=3Dy
> CONFIG_CPU_THERMAL=3Dy
> CONFIG_CPU_FREQ_THERMAL=3Dy
> # CONFIG_DEVFREQ_THERMAL is not set
> CONFIG_THERMAL_EMULATION=3Dy
> # CONFIG_THERMAL_MMIO is not set
> CONFIG_HISI_THERMAL=3Dy
> # CONFIG_IMX_THERMAL is not set
> CONFIG_IMX_SC_THERMAL=3Dm
> CONFIG_IMX8MM_THERMAL=3Dm
> # CONFIG_K3_THERMAL is not set
> # CONFIG_MAX77620_THERMAL is not set
> CONFIG_QORIQ_THERMAL=3Dm
> CONFIG_SUN8I_THERMAL=3Dy
> CONFIG_ROCKCHIP_THERMAL=3Dm
> CONFIG_RCAR_THERMAL=3Dy
> CONFIG_RCAR_GEN3_THERMAL=3Dy
> CONFIG_ARMADA_THERMAL=3Dy
> CONFIG_MTK_THERMAL=3Dy
> CONFIG_AMLOGIC_THERMAL=3Dy
>=20
> #
> # Broadcom thermal drivers
> #
> CONFIG_BCM2711_THERMAL=3Dm
> CONFIG_BCM2835_THERMAL=3Dm
> CONFIG_BRCMSTB_THERMAL=3Dm
> CONFIG_BCM_NS_THERMAL=3Dy
> CONFIG_BCM_SR_THERMAL=3Dy
> # end of Broadcom thermal drivers
>=20
> #
> # Samsung thermal drivers
> #
> CONFIG_EXYNOS_THERMAL=3Dy
> # end of Samsung thermal drivers
>=20
> #
> # NVIDIA Tegra thermal drivers
> #
> # CONFIG_TEGRA_SOCTHERM is not set
> CONFIG_TEGRA_BPMP_THERMAL=3Dm
> # end of NVIDIA Tegra thermal drivers
>=20
> # CONFIG_GENERIC_ADC_THERMAL is not set
>=20
> #
> # Qualcomm thermal drivers
> #
> CONFIG_QCOM_TSENS=3Dy
> CONFIG_QCOM_SPMI_TEMP_ALARM=3Dm
> # end of Qualcomm thermal drivers
>=20
> # CONFIG_ZX2967_THERMAL is not set
> CONFIG_UNIPHIER_THERMAL=3Dy
> # CONFIG_SPRD_THERMAL is not set
> CONFIG_WATCHDOG=3Dy
> CONFIG_WATCHDOG_CORE=3Dy
> CONFIG_WATCHDOG_NOWAYOUT=3Dy
> CONFIG_WATCHDOG_HANDLE_BOOT_ENABLED=3Dy
> CONFIG_WATCHDOG_OPEN_TIMEOUT=3D0
> CONFIG_WATCHDOG_SYSFS=3Dy
>=20
> #
> # Watchdog Pretimeout Governors
> #
> CONFIG_WATCHDOG_PRETIMEOUT_GOV=3Dy
> CONFIG_WATCHDOG_PRETIMEOUT_GOV_SEL=3Dm
> CONFIG_WATCHDOG_PRETIMEOUT_GOV_NOOP=3Dm
> CONFIG_WATCHDOG_PRETIMEOUT_GOV_PANIC=3Dm
> # CONFIG_WATCHDOG_PRETIMEOUT_DEFAULT_GOV_NOOP is not set
> CONFIG_WATCHDOG_PRETIMEOUT_DEFAULT_GOV_PANIC=3Dy
>=20
> #
> # Watchdog Device Drivers
> #
> CONFIG_SOFT_WATCHDOG=3Dm
> CONFIG_SOFT_WATCHDOG_PRETIMEOUT=3Dy
> CONFIG_GPIO_WATCHDOG=3Dm
> # CONFIG_WDAT_WDT is not set
> CONFIG_XILINX_WATCHDOG=3Dm
> CONFIG_ZIIRAVE_WATCHDOG=3Dm
> CONFIG_ARM_SP805_WATCHDOG=3Dy
> CONFIG_ARM_SBSA_WATCHDOG=3Dy
> CONFIG_ARMADA_37XX_WATCHDOG=3Dm
> CONFIG_CADENCE_WATCHDOG=3Dm
> CONFIG_S3C2410_WATCHDOG=3Dy
> CONFIG_DW_WATCHDOG=3Dy
> CONFIG_K3_RTI_WATCHDOG=3Dm
> CONFIG_SUNXI_WATCHDOG=3Dm
> CONFIG_MAX63XX_WATCHDOG=3Dm
> CONFIG_MAX77620_WATCHDOG=3Dm
> CONFIG_IMX2_WDT=3Dy
> CONFIG_IMX_SC_WDT=3Dm
> # CONFIG_IMX7ULP_WDT is not set
> CONFIG_TEGRA_WATCHDOG=3Dm
> CONFIG_QCOM_WDT=3Dm
> CONFIG_MESON_GXBB_WATCHDOG=3Dm
> CONFIG_MESON_WATCHDOG=3Dm
> CONFIG_MEDIATEK_WATCHDOG=3Dm
> CONFIG_ARM_SMC_WATCHDOG=3Dy
> CONFIG_RENESAS_WDT=3Dy
> # CONFIG_RENESAS_RZAWDT is not set
> CONFIG_ZX2967_WATCHDOG=3Dm
> CONFIG_UNIPHIER_WATCHDOG=3Dy
> CONFIG_SPRD_WATCHDOG=3Dm
> CONFIG_PM8916_WATCHDOG=3Dm
> # CONFIG_ALIM7101_WDT is not set
> # CONFIG_I6300ESB_WDT is not set
> CONFIG_BCM2835_WDT=3Dy
> # CONFIG_BCM7038_WDT is not set
> # CONFIG_MEN_A21_WDT is not set
> # CONFIG_XEN_WDT is not set
>=20
> #
> # PCI-based Watchdog Cards
> #
> CONFIG_PCIPCWATCHDOG=3Dm
> # CONFIG_WDTPCI is not set
>=20
> #
> # USB-based Watchdog Cards
> #
> CONFIG_USBPCWATCHDOG=3Dm
> CONFIG_SSB_POSSIBLE=3Dy
> # CONFIG_SSB is not set
> CONFIG_BCMA_POSSIBLE=3Dy
> # CONFIG_BCMA is not set
>=20
> #
> # Multifunction device drivers
> #
> CONFIG_MFD_CORE=3Dy
> CONFIG_MFD_ALTERA_SYSMGR=3Dy
> # CONFIG_MFD_ACT8945A is not set
> # CONFIG_MFD_SUN4I_GPADC is not set
> # CONFIG_MFD_AS3711 is not set
> # CONFIG_MFD_AS3722 is not set
> # CONFIG_PMIC_ADP5520 is not set
> # CONFIG_MFD_AAT2870_CORE is not set
> # CONFIG_MFD_ATMEL_FLEXCOM is not set
> # CONFIG_MFD_ATMEL_HLCDC is not set
> # CONFIG_MFD_BCM590XX is not set
> CONFIG_MFD_BD9571MWV=3Dy
> # CONFIG_MFD_AC100 is not set
> CONFIG_MFD_AXP20X=3Dy
> CONFIG_MFD_AXP20X_I2C=3Dy
> CONFIG_MFD_AXP20X_RSB=3Dy
> CONFIG_MFD_CROS_EC_DEV=3Dy
> # CONFIG_MFD_MADERA is not set
> # CONFIG_PMIC_DA903X is not set
> # CONFIG_MFD_DA9052_SPI is not set
> # CONFIG_MFD_DA9052_I2C is not set
> # CONFIG_MFD_DA9055 is not set
> # CONFIG_MFD_DA9062 is not set
> # CONFIG_MFD_DA9063 is not set
> # CONFIG_MFD_DA9150 is not set
> # CONFIG_MFD_DLN2 is not set
> CONFIG_MFD_EXYNOS_LPASS=3Dm
> # CONFIG_MFD_GATEWORKS_GSC is not set
> # CONFIG_MFD_MC13XXX_SPI is not set
> # CONFIG_MFD_MC13XXX_I2C is not set
> # CONFIG_MFD_MP2629 is not set
> CONFIG_MFD_HI6421_PMIC=3Dy
> CONFIG_MFD_HI655X_PMIC=3Dy
> # CONFIG_HTC_PASIC3 is not set
> # CONFIG_HTC_I2CPLD is not set
> # CONFIG_LPC_ICH is not set
> # CONFIG_LPC_SCH is not set
> # CONFIG_MFD_INTEL_PMT is not set
> # CONFIG_MFD_IQS62X is not set
> # CONFIG_MFD_JANZ_CMODIO is not set
> # CONFIG_MFD_KEMPLD is not set
> # CONFIG_MFD_88PM800 is not set
> # CONFIG_MFD_88PM805 is not set
> # CONFIG_MFD_88PM860X is not set
> # CONFIG_MFD_MAX14577 is not set
> CONFIG_MFD_MAX77620=3Dy
> # CONFIG_MFD_MAX77650 is not set
> # CONFIG_MFD_MAX77686 is not set
> # CONFIG_MFD_MAX77693 is not set
> # CONFIG_MFD_MAX77843 is not set
> # CONFIG_MFD_MAX8907 is not set
> # CONFIG_MFD_MAX8925 is not set
> # CONFIG_MFD_MAX8997 is not set
> # CONFIG_MFD_MAX8998 is not set
> # CONFIG_MFD_MT6360 is not set
> # CONFIG_MFD_MT6397 is not set
> # CONFIG_MFD_MENF21BMC is not set
> # CONFIG_EZX_PCAP is not set
> # CONFIG_MFD_CPCAP is not set
> # CONFIG_MFD_VIPERBOARD is not set
> # CONFIG_MFD_RETU is not set
> # CONFIG_MFD_PCF50633 is not set
> # CONFIG_MFD_QCOM_RPM is not set
> CONFIG_MFD_SPMI_PMIC=3Dy
> # CONFIG_MFD_RDC321X is not set
> # CONFIG_MFD_RT5033 is not set
> # CONFIG_MFD_RC5T583 is not set
> CONFIG_MFD_RK808=3Dy
> # CONFIG_MFD_RN5T618 is not set
> CONFIG_MFD_SEC_CORE=3Dy
> # CONFIG_MFD_SI476X_CORE is not set
> # CONFIG_MFD_SL28CPLD is not set
> # CONFIG_MFD_SM501 is not set
> # CONFIG_MFD_SKY81452 is not set
> # CONFIG_MFD_SC27XX_PMIC is not set
> # CONFIG_ABX500_CORE is not set
> # CONFIG_MFD_STMPE is not set
> CONFIG_MFD_SUN6I_PRCM=3Dy
> CONFIG_MFD_SYSCON=3Dy
> # CONFIG_MFD_TI_AM335X_TSCADC is not set
> # CONFIG_MFD_LP3943 is not set
> # CONFIG_MFD_LP8788 is not set
> # CONFIG_MFD_TI_LMU is not set
> # CONFIG_MFD_PALMAS is not set
> # CONFIG_TPS6105X is not set
> # CONFIG_TPS65010 is not set
> # CONFIG_TPS6507X is not set
> # CONFIG_MFD_TPS65086 is not set
> # CONFIG_MFD_TPS65090 is not set
> # CONFIG_MFD_TPS65217 is not set
> # CONFIG_MFD_TPS68470 is not set
> # CONFIG_MFD_TI_LP873X is not set
> # CONFIG_MFD_TI_LP87565 is not set
> # CONFIG_MFD_TPS65218 is not set
> # CONFIG_MFD_TPS6586X is not set
> # CONFIG_MFD_TPS65910 is not set
> # CONFIG_MFD_TPS65912_I2C is not set
> # CONFIG_MFD_TPS65912_SPI is not set
> # CONFIG_MFD_TPS80031 is not set
> # CONFIG_TWL4030_CORE is not set
> # CONFIG_TWL6040_CORE is not set
> # CONFIG_MFD_WL1273_CORE is not set
> # CONFIG_MFD_LM3533 is not set
> # CONFIG_MFD_TC3589X is not set
> # CONFIG_MFD_TQMX86 is not set
> # CONFIG_MFD_VX855 is not set
> # CONFIG_MFD_LOCHNAGAR is not set
> # CONFIG_MFD_ARIZONA_I2C is not set
> # CONFIG_MFD_ARIZONA_SPI is not set
> # CONFIG_MFD_WM8400 is not set
> # CONFIG_MFD_WM831X_I2C is not set
> # CONFIG_MFD_WM831X_SPI is not set
> # CONFIG_MFD_WM8350_I2C is not set
> # CONFIG_MFD_WM8994 is not set
> CONFIG_MFD_ROHM_BD718XX=3Dy
> # CONFIG_MFD_ROHM_BD70528 is not set
> # CONFIG_MFD_ROHM_BD71828 is not set
> # CONFIG_MFD_STPMIC1 is not set
> # CONFIG_MFD_STMFX is not set
> CONFIG_MFD_WCD934X=3Dm
> # CONFIG_MFD_KHADAS_MCU is not set
> CONFIG_MFD_VEXPRESS_SYSREG=3Dy
> # CONFIG_RAVE_SP_CORE is not set
> # CONFIG_MFD_INTEL_M10_BMC is not set
> # end of Multifunction device drivers
>=20
> CONFIG_REGULATOR=3Dy
> # CONFIG_REGULATOR_DEBUG is not set
> CONFIG_REGULATOR_FIXED_VOLTAGE=3Dy
> # CONFIG_REGULATOR_VIRTUAL_CONSUMER is not set
> # CONFIG_REGULATOR_USERSPACE_CONSUMER is not set
> # CONFIG_REGULATOR_88PG86X is not set
> # CONFIG_REGULATOR_ACT8865 is not set
> # CONFIG_REGULATOR_AD5398 is not set
> # CONFIG_REGULATOR_ANATOP is not set
> CONFIG_REGULATOR_AXP20X=3Dy
> CONFIG_REGULATOR_BD718XX=3Dy
> CONFIG_REGULATOR_BD9571MWV=3Dy
> # CONFIG_REGULATOR_CROS_EC is not set
> # CONFIG_REGULATOR_DA9121 is not set
> # CONFIG_REGULATOR_DA9210 is not set
> # CONFIG_REGULATOR_DA9211 is not set
> CONFIG_REGULATOR_FAN53555=3Dy
> # CONFIG_REGULATOR_FAN53880 is not set
> CONFIG_REGULATOR_GPIO=3Dy
> # CONFIG_REGULATOR_HI6421 is not set
> CONFIG_REGULATOR_HI6421V530=3Dy
> CONFIG_REGULATOR_HI655X=3Dy
> # CONFIG_REGULATOR_ISL9305 is not set
> # CONFIG_REGULATOR_ISL6271A is not set
> # CONFIG_REGULATOR_LP3971 is not set
> # CONFIG_REGULATOR_LP3972 is not set
> # CONFIG_REGULATOR_LP872X is not set
> # CONFIG_REGULATOR_LP8755 is not set
> # CONFIG_REGULATOR_LTC3589 is not set
> # CONFIG_REGULATOR_LTC3676 is not set
> # CONFIG_REGULATOR_MAX1586 is not set
> CONFIG_REGULATOR_MAX77620=3Dy
> # CONFIG_REGULATOR_MAX8649 is not set
> # CONFIG_REGULATOR_MAX8660 is not set
> # CONFIG_REGULATOR_MAX8952 is not set
> CONFIG_REGULATOR_MAX8973=3Dy
> # CONFIG_REGULATOR_MAX77826 is not set
> # CONFIG_REGULATOR_MCP16502 is not set
> # CONFIG_REGULATOR_MP5416 is not set
> # CONFIG_REGULATOR_MP8859 is not set
> # CONFIG_REGULATOR_MP886X is not set
> # CONFIG_REGULATOR_MPQ7920 is not set
> # CONFIG_REGULATOR_MT6311 is not set
> # CONFIG_REGULATOR_PCA9450 is not set
> CONFIG_REGULATOR_PFUZE100=3Dy
> # CONFIG_REGULATOR_PV88060 is not set
> # CONFIG_REGULATOR_PV88080 is not set
> # CONFIG_REGULATOR_PV88090 is not set
> CONFIG_REGULATOR_PWM=3Dy
> CONFIG_REGULATOR_QCOM_RPMH=3Dy
> CONFIG_REGULATOR_QCOM_SMD_RPM=3Dy
> CONFIG_REGULATOR_QCOM_SPMI=3Dy
> # CONFIG_REGULATOR_QCOM_USB_VBUS is not set
> # CONFIG_REGULATOR_RASPBERRYPI_TOUCHSCREEN_ATTINY is not set
> CONFIG_REGULATOR_RK808=3Dy
> CONFIG_REGULATOR_ROHM=3Dy
> # CONFIG_REGULATOR_RT4801 is not set
> # CONFIG_REGULATOR_RTMV20 is not set
> # CONFIG_REGULATOR_S2MPA01 is not set
> CONFIG_REGULATOR_S2MPS11=3Dy
> # CONFIG_REGULATOR_S5M8767 is not set
> # CONFIG_REGULATOR_SLG51000 is not set
> # CONFIG_REGULATOR_SY8106A is not set
> # CONFIG_REGULATOR_SY8824X is not set
> # CONFIG_REGULATOR_SY8827N is not set
> # CONFIG_REGULATOR_TPS51632 is not set
> # CONFIG_REGULATOR_TPS62360 is not set
> # CONFIG_REGULATOR_TPS65023 is not set
> # CONFIG_REGULATOR_TPS6507X is not set
> # CONFIG_REGULATOR_TPS65132 is not set
> # CONFIG_REGULATOR_TPS6524X is not set
> CONFIG_REGULATOR_UNIPHIER=3Dy
> CONFIG_REGULATOR_VCTRL=3Dm
> # CONFIG_REGULATOR_VEXPRESS is not set
> # CONFIG_REGULATOR_VQMMC_IPQ4019 is not set
> # CONFIG_REGULATOR_QCOM_LABIBB is not set
> CONFIG_RC_CORE=3Dm
> CONFIG_RC_MAP=3Dm
> # CONFIG_LIRC is not set
> CONFIG_RC_DECODERS=3Dy
> # CONFIG_IR_NEC_DECODER is not set
> # CONFIG_IR_RC5_DECODER is not set
> # CONFIG_IR_RC6_DECODER is not set
> # CONFIG_IR_JVC_DECODER is not set
> # CONFIG_IR_SONY_DECODER is not set
> # CONFIG_IR_SANYO_DECODER is not set
> # CONFIG_IR_SHARP_DECODER is not set
> # CONFIG_IR_MCE_KBD_DECODER is not set
> # CONFIG_IR_XMP_DECODER is not set
> # CONFIG_IR_IMON_DECODER is not set
> # CONFIG_IR_RCMM_DECODER is not set
> CONFIG_RC_DEVICES=3Dy
> # CONFIG_RC_ATI_REMOTE is not set
> # CONFIG_IR_ENE is not set
> # CONFIG_IR_HIX5HD2 is not set
> # CONFIG_IR_IMON is not set
> # CONFIG_IR_IMON_RAW is not set
> # CONFIG_IR_MCEUSB is not set
> # CONFIG_IR_ITE_CIR is not set
> # CONFIG_IR_FINTEK is not set
> CONFIG_IR_MESON=3Dm
> # CONFIG_IR_MTK is not set
> # CONFIG_IR_NUVOTON is not set
> # CONFIG_IR_REDRAT3 is not set
> # CONFIG_IR_STREAMZAP is not set
> # CONFIG_IR_IGORPLUGUSB is not set
> # CONFIG_IR_IGUANA is not set
> # CONFIG_IR_TTUSBIR is not set
> # CONFIG_RC_LOOPBACK is not set
> # CONFIG_IR_GPIO_CIR is not set
> CONFIG_IR_SUNXI=3Dm
> # CONFIG_IR_SERIAL is not set
> # CONFIG_IR_SIR is not set
> # CONFIG_RC_XBOX_DVD is not set
> # CONFIG_IR_ZX is not set
> # CONFIG_IR_TOY is not set
> CONFIG_CEC_CORE=3Dm
> CONFIG_CEC_NOTIFIER=3Dy
> # CONFIG_MEDIA_CEC_RC is not set
> # CONFIG_MEDIA_CEC_SUPPORT is not set
> CONFIG_MEDIA_SUPPORT=3Dm
> CONFIG_MEDIA_SUPPORT_FILTER=3Dy
> CONFIG_MEDIA_SUBDRV_AUTOSELECT=3Dy
>=20
> #
> # Media device types
> #
> CONFIG_MEDIA_CAMERA_SUPPORT=3Dy
> CONFIG_MEDIA_ANALOG_TV_SUPPORT=3Dy
> CONFIG_MEDIA_DIGITAL_TV_SUPPORT=3Dy
> # CONFIG_MEDIA_RADIO_SUPPORT is not set
> CONFIG_MEDIA_SDR_SUPPORT=3Dy
> CONFIG_MEDIA_PLATFORM_SUPPORT=3Dy
> # CONFIG_MEDIA_TEST_SUPPORT is not set
> # end of Media device types
>=20
> CONFIG_VIDEO_DEV=3Dm
> CONFIG_MEDIA_CONTROLLER=3Dy
> CONFIG_DVB_CORE=3Dm
>=20
> #
> # Video4Linux options
> #
> CONFIG_VIDEO_V4L2=3Dm
> CONFIG_VIDEO_V4L2_I2C=3Dy
> CONFIG_VIDEO_V4L2_SUBDEV_API=3Dy
> # CONFIG_VIDEO_ADV_DEBUG is not set
> # CONFIG_VIDEO_FIXED_MINOR_RANGES is not set
> CONFIG_V4L2_MEM2MEM_DEV=3Dm
> CONFIG_V4L2_FWNODE=3Dm
> # end of Video4Linux options
>=20
> #
> # Media controller options
> #
> # CONFIG_MEDIA_CONTROLLER_DVB is not set
> # end of Media controller options
>=20
> #
> # Digital TV options
> #
> # CONFIG_DVB_MMAP is not set
> # CONFIG_DVB_NET is not set
> CONFIG_DVB_MAX_ADAPTERS=3D16
> CONFIG_DVB_DYNAMIC_MINORS=3Dy
> # CONFIG_DVB_DEMUX_SECTION_LOSS_LOG is not set
> # CONFIG_DVB_ULE_DEBUG is not set
> # end of Digital TV options
>=20
> #
> # Media drivers
> #
>=20
> #
> # Drivers filtered as selected at 'Filter media drivers'
> #
> CONFIG_MEDIA_USB_SUPPORT=3Dy
>=20
> #
> # Webcam devices
> #
> CONFIG_USB_VIDEO_CLASS=3Dm
> CONFIG_USB_VIDEO_CLASS_INPUT_EVDEV=3Dy
> CONFIG_USB_GSPCA=3Dm
> # CONFIG_USB_M5602 is not set
> # CONFIG_USB_STV06XX is not set
> # CONFIG_USB_GL860 is not set
> # CONFIG_USB_GSPCA_BENQ is not set
> # CONFIG_USB_GSPCA_CONEX is not set
> # CONFIG_USB_GSPCA_CPIA1 is not set
> # CONFIG_USB_GSPCA_DTCS033 is not set
> # CONFIG_USB_GSPCA_ETOMS is not set
> # CONFIG_USB_GSPCA_FINEPIX is not set
> # CONFIG_USB_GSPCA_JEILINJ is not set
> # CONFIG_USB_GSPCA_JL2005BCD is not set
> # CONFIG_USB_GSPCA_KINECT is not set
> # CONFIG_USB_GSPCA_KONICA is not set
> # CONFIG_USB_GSPCA_MARS is not set
> # CONFIG_USB_GSPCA_MR97310A is not set
> # CONFIG_USB_GSPCA_NW80X is not set
> # CONFIG_USB_GSPCA_OV519 is not set
> # CONFIG_USB_GSPCA_OV534 is not set
> # CONFIG_USB_GSPCA_OV534_9 is not set
> # CONFIG_USB_GSPCA_PAC207 is not set
> # CONFIG_USB_GSPCA_PAC7302 is not set
> # CONFIG_USB_GSPCA_PAC7311 is not set
> # CONFIG_USB_GSPCA_SE401 is not set
> # CONFIG_USB_GSPCA_SN9C2028 is not set
> # CONFIG_USB_GSPCA_SN9C20X is not set
> # CONFIG_USB_GSPCA_SONIXB is not set
> # CONFIG_USB_GSPCA_SONIXJ is not set
> # CONFIG_USB_GSPCA_SPCA500 is not set
> # CONFIG_USB_GSPCA_SPCA501 is not set
> # CONFIG_USB_GSPCA_SPCA505 is not set
> # CONFIG_USB_GSPCA_SPCA506 is not set
> # CONFIG_USB_GSPCA_SPCA508 is not set
> # CONFIG_USB_GSPCA_SPCA561 is not set
> # CONFIG_USB_GSPCA_SPCA1528 is not set
> # CONFIG_USB_GSPCA_SQ905 is not set
> # CONFIG_USB_GSPCA_SQ905C is not set
> # CONFIG_USB_GSPCA_SQ930X is not set
> # CONFIG_USB_GSPCA_STK014 is not set
> # CONFIG_USB_GSPCA_STK1135 is not set
> # CONFIG_USB_GSPCA_STV0680 is not set
> # CONFIG_USB_GSPCA_SUNPLUS is not set
> # CONFIG_USB_GSPCA_T613 is not set
> # CONFIG_USB_GSPCA_TOPRO is not set
> # CONFIG_USB_GSPCA_TOUPTEK is not set
> # CONFIG_USB_GSPCA_TV8532 is not set
> # CONFIG_USB_GSPCA_VC032X is not set
> # CONFIG_USB_GSPCA_VICAM is not set
> # CONFIG_USB_GSPCA_XIRLINK_CIT is not set
> # CONFIG_USB_GSPCA_ZC3XX is not set
> # CONFIG_USB_PWC is not set
> # CONFIG_VIDEO_CPIA2 is not set
> # CONFIG_USB_ZR364XX is not set
> # CONFIG_USB_STKWEBCAM is not set
> # CONFIG_USB_S2255 is not set
> # CONFIG_VIDEO_USBTV is not set
>=20
> #
> # Analog TV USB devices
> #
> # CONFIG_VIDEO_PVRUSB2 is not set
> # CONFIG_VIDEO_HDPVR is not set
> # CONFIG_VIDEO_STK1160_COMMON is not set
> # CONFIG_VIDEO_GO7007 is not set
>=20
> #
> # Analog/digital TV USB devices
> #
> # CONFIG_VIDEO_AU0828 is not set
> # CONFIG_VIDEO_CX231XX is not set
> # CONFIG_VIDEO_TM6000 is not set
>=20
> #
> # Digital TV USB devices
> #
> # CONFIG_DVB_USB is not set
> # CONFIG_DVB_USB_V2 is not set
> # CONFIG_DVB_TTUSB_BUDGET is not set
> # CONFIG_DVB_TTUSB_DEC is not set
> # CONFIG_SMS_USB_DRV is not set
> # CONFIG_DVB_B2C2_FLEXCOP_USB is not set
> # CONFIG_DVB_AS102 is not set
>=20
> #
> # Webcam, TV (analog/digital) USB devices
> #
> # CONFIG_VIDEO_EM28XX is not set
>=20
> #
> # Software defined radio USB devices
> #
> # CONFIG_USB_AIRSPY is not set
> # CONFIG_USB_HACKRF is not set
> # CONFIG_USB_MSI2500 is not set
> # CONFIG_MEDIA_PCI_SUPPORT is not set
> CONFIG_VIDEOBUF2_CORE=3Dm
> CONFIG_VIDEOBUF2_V4L2=3Dm
> CONFIG_VIDEOBUF2_MEMOPS=3Dm
> CONFIG_VIDEOBUF2_DMA_CONTIG=3Dm
> CONFIG_VIDEOBUF2_VMALLOC=3Dm
> CONFIG_VIDEOBUF2_DMA_SG=3Dm
> CONFIG_V4L_PLATFORM_DRIVERS=3Dy
> # CONFIG_VIDEO_CAFE_CCIC is not set
> # CONFIG_VIDEO_CADENCE is not set
> # CONFIG_VIDEO_ASPEED is not set
> # CONFIG_VIDEO_MUX is not set
> CONFIG_VIDEO_QCOM_CAMSS=3Dm
> # CONFIG_VIDEO_SAMSUNG_EXYNOS4_IS is not set
> # CONFIG_VIDEO_XILINX is not set
> CONFIG_VIDEO_RCAR_CSI2=3Dm
> CONFIG_VIDEO_RCAR_VIN=3Dm
> # CONFIG_VIDEO_SUN4I_CSI is not set
> CONFIG_VIDEO_SUN6I_CSI=3Dm
> # CONFIG_VIDEO_TI_CAL is not set
> CONFIG_V4L_MEM2MEM_DRIVERS=3Dy
> # CONFIG_VIDEO_CODA is not set
> # CONFIG_VIDEO_IMX_PXP is not set
> # CONFIG_VIDEO_MEDIATEK_VPU is not set
> # CONFIG_VIDEO_MEM2MEM_DEINTERLACE is not set
> # CONFIG_VIDEO_SAMSUNG_S5P_G2D is not set
> CONFIG_VIDEO_SAMSUNG_S5P_JPEG=3Dm
> CONFIG_VIDEO_SAMSUNG_S5P_MFC=3Dm
> CONFIG_VIDEO_SAMSUNG_EXYNOS_GSC=3Dm
> CONFIG_VIDEO_RENESAS_FDP1=3Dm
> # CONFIG_VIDEO_RENESAS_JPU is not set
> CONFIG_VIDEO_RENESAS_FCP=3Dm
> CONFIG_VIDEO_RENESAS_VSP1=3Dm
> # CONFIG_VIDEO_ROCKCHIP_RGA is not set
> # CONFIG_VIDEO_QCOM_VENUS is not set
> # CONFIG_VIDEO_SUN8I_DEINTERLACE is not set
> # CONFIG_VIDEO_SUN8I_ROTATE is not set
> # CONFIG_DVB_PLATFORM_DRIVERS is not set
> CONFIG_SDR_PLATFORM_DRIVERS=3Dy
> CONFIG_VIDEO_RCAR_DRIF=3Dm
>=20
> #
> # MMC/SDIO DVB adapters
> #
> # CONFIG_SMS_SDIO_DRV is not set
> # end of Media drivers
>=20
> CONFIG_MEDIA_HIDE_ANCILLARY_SUBDRV=3Dy
>=20
> #
> # Media ancillary drivers
> #
> CONFIG_MEDIA_ATTACH=3Dy
>=20
> #
> # IR I2C driver auto-selected by 'Autoselect ancillary drivers'
> #
> CONFIG_VIDEO_IR_I2C=3Dm
>=20
> #
> # audio, video and radio I2C drivers auto-selected by 'Autoselect ancilla=
ry drivers'
> #
>=20
> #
> # Video and audio decoders
> #
>=20
> #
> # Camera sensor devices
> #
> # CONFIG_VIDEO_HI556 is not set
> # CONFIG_VIDEO_IMX214 is not set
> # CONFIG_VIDEO_IMX219 is not set
> # CONFIG_VIDEO_IMX258 is not set
> # CONFIG_VIDEO_IMX274 is not set
> # CONFIG_VIDEO_IMX290 is not set
> # CONFIG_VIDEO_IMX319 is not set
> # CONFIG_VIDEO_IMX355 is not set
> # CONFIG_VIDEO_OV2640 is not set
> # CONFIG_VIDEO_OV2659 is not set
> # CONFIG_VIDEO_OV2680 is not set
> # CONFIG_VIDEO_OV2685 is not set
> # CONFIG_VIDEO_OV2740 is not set
> # CONFIG_VIDEO_OV5640 is not set
> # CONFIG_VIDEO_OV5645 is not set
> # CONFIG_VIDEO_OV5647 is not set
> # CONFIG_VIDEO_OV6650 is not set
> # CONFIG_VIDEO_OV5670 is not set
> # CONFIG_VIDEO_OV5675 is not set
> # CONFIG_VIDEO_OV5695 is not set
> # CONFIG_VIDEO_OV7251 is not set
> # CONFIG_VIDEO_OV772X is not set
> # CONFIG_VIDEO_OV7640 is not set
> # CONFIG_VIDEO_OV7670 is not set
> # CONFIG_VIDEO_OV7740 is not set
> # CONFIG_VIDEO_OV8856 is not set
> # CONFIG_VIDEO_OV9640 is not set
> # CONFIG_VIDEO_OV9650 is not set
> # CONFIG_VIDEO_OV13858 is not set
> # CONFIG_VIDEO_VS6624 is not set
> # CONFIG_VIDEO_MT9M001 is not set
> # CONFIG_VIDEO_MT9M032 is not set
> # CONFIG_VIDEO_MT9M111 is not set
> # CONFIG_VIDEO_MT9P031 is not set
> # CONFIG_VIDEO_MT9T001 is not set
> # CONFIG_VIDEO_MT9T112 is not set
> # CONFIG_VIDEO_MT9V011 is not set
> # CONFIG_VIDEO_MT9V032 is not set
> # CONFIG_VIDEO_MT9V111 is not set
> # CONFIG_VIDEO_SR030PC30 is not set
> # CONFIG_VIDEO_NOON010PC30 is not set
> # CONFIG_VIDEO_M5MOLS is not set
> # CONFIG_VIDEO_RDACM20 is not set
> # CONFIG_VIDEO_RJ54N1 is not set
> # CONFIG_VIDEO_S5K6AA is not set
> # CONFIG_VIDEO_S5K6A3 is not set
> # CONFIG_VIDEO_S5K4ECGX is not set
> # CONFIG_VIDEO_S5K5BAF is not set
> # CONFIG_VIDEO_SMIAPP is not set
> # CONFIG_VIDEO_ET8EK8 is not set
> # CONFIG_VIDEO_S5C73M3 is not set
> # end of Camera sensor devices
>=20
> #
> # Lens drivers
> #
> # CONFIG_VIDEO_AD5820 is not set
> # CONFIG_VIDEO_AK7375 is not set
> # CONFIG_VIDEO_DW9714 is not set
> # CONFIG_VIDEO_DW9768 is not set
> # CONFIG_VIDEO_DW9807_VCM is not set
> # end of Lens drivers
>=20
> #
> # Flash devices
> #
> # CONFIG_VIDEO_ADP1653 is not set
> # CONFIG_VIDEO_LM3560 is not set
> # CONFIG_VIDEO_LM3646 is not set
> # end of Flash devices
>=20
> #
> # SPI I2C drivers auto-selected by 'Autoselect ancillary drivers'
> #
>=20
> #
> # Media SPI Adapters
> #
> # CONFIG_CXD2880_SPI_DRV is not set
> # end of Media SPI Adapters
>=20
> CONFIG_MEDIA_TUNER=3Dm
>=20
> #
> # Tuner drivers auto-selected by 'Autoselect ancillary drivers'
> #
> CONFIG_MEDIA_TUNER_SIMPLE=3Dm
> CONFIG_MEDIA_TUNER_TDA8290=3Dm
> CONFIG_MEDIA_TUNER_TDA827X=3Dm
> CONFIG_MEDIA_TUNER_TDA18271=3Dm
> CONFIG_MEDIA_TUNER_TDA9887=3Dm
> CONFIG_MEDIA_TUNER_MT20XX=3Dm
> CONFIG_MEDIA_TUNER_XC2028=3Dm
> CONFIG_MEDIA_TUNER_XC5000=3Dm
> CONFIG_MEDIA_TUNER_XC4000=3Dm
> CONFIG_MEDIA_TUNER_MC44S803=3Dm
>=20
> #
> # DVB Frontend drivers auto-selected by 'Autoselect ancillary drivers'
> #
>=20
> #
> # Multistandard (satellite) frontends
> #
>=20
> #
> # Multistandard (cable + terrestrial) frontends
> #
>=20
> #
> # DVB-S (satellite) frontends
> #
>=20
> #
> # DVB-T (terrestrial) frontends
> #
>=20
> #
> # DVB-C (cable) frontends
> #
>=20
> #
> # ATSC (North American/Korean Terrestrial/Cable DTV) frontends
> #
>=20
> #
> # ISDB-T (terrestrial) frontends
> #
>=20
> #
> # ISDB-S (satellite) & ISDB-T (terrestrial) frontends
> #
>=20
> #
> # Digital terrestrial only tuners/PLL
> #
>=20
> #
> # SEC control devices for DVB-S
> #
>=20
> #
> # Common Interface (EN50221) controller drivers
> #
> # end of Media ancillary drivers
>=20
> #
> # Graphics support
> #
> CONFIG_VGA_ARB=3Dy
> CONFIG_VGA_ARB_MAX_GPUS=3D16
> CONFIG_TEGRA_HOST1X=3Dm
> CONFIG_TEGRA_HOST1X_FIREWALL=3Dy
> CONFIG_DRM=3Dm
> CONFIG_DRM_MIPI_DSI=3Dy
> # CONFIG_DRM_DP_AUX_CHARDEV is not set
> # CONFIG_DRM_DEBUG_SELFTEST is not set
> CONFIG_DRM_KMS_HELPER=3Dm
> CONFIG_DRM_KMS_FB_HELPER=3Dy
> CONFIG_DRM_FBDEV_EMULATION=3Dy
> CONFIG_DRM_FBDEV_OVERALLOC=3D100
> # CONFIG_DRM_LOAD_EDID_FIRMWARE is not set
> # CONFIG_DRM_DP_CEC is not set
> CONFIG_DRM_TTM=3Dm
> CONFIG_DRM_VRAM_HELPER=3Dm
> CONFIG_DRM_TTM_HELPER=3Dm
> CONFIG_DRM_GEM_CMA_HELPER=3Dy
> CONFIG_DRM_KMS_CMA_HELPER=3Dy
> CONFIG_DRM_GEM_SHMEM_HELPER=3Dy
> CONFIG_DRM_VM=3Dy
> CONFIG_DRM_SCHED=3Dm
>=20
> #
> # I2C encoder or helper chips
> #
> CONFIG_DRM_I2C_CH7006=3Dm
> CONFIG_DRM_I2C_SIL164=3Dm
> CONFIG_DRM_I2C_NXP_TDA998X=3Dm
> # CONFIG_DRM_I2C_NXP_TDA9950 is not set
> # end of I2C encoder or helper chips
>=20
> #
> # ARM devices
> #
> # CONFIG_DRM_HDLCD is not set
> CONFIG_DRM_MALI_DISPLAY=3Dm
> # CONFIG_DRM_KOMEDA is not set
> # end of ARM devices
>=20
> # CONFIG_DRM_RADEON is not set
> # CONFIG_DRM_AMDGPU is not set
> CONFIG_DRM_NOUVEAU=3Dm
> CONFIG_NOUVEAU_LEGACY_CTX_SUPPORT=3Dy
> CONFIG_NOUVEAU_PLATFORM_DRIVER=3Dy
> CONFIG_NOUVEAU_DEBUG=3D5
> CONFIG_NOUVEAU_DEBUG_DEFAULT=3D3
> # CONFIG_NOUVEAU_DEBUG_MMU is not set
> # CONFIG_NOUVEAU_DEBUG_PUSH is not set
> CONFIG_DRM_NOUVEAU_BACKLIGHT=3Dy
> # CONFIG_DRM_KMB_DISPLAY is not set
> # CONFIG_DRM_VGEM is not set
> # CONFIG_DRM_VKMS is not set
> CONFIG_DRM_EXYNOS=3Dm
>=20
> #
> # CRTCs
> #
> # CONFIG_DRM_EXYNOS_FIMD is not set
> CONFIG_DRM_EXYNOS5433_DECON=3Dy
> CONFIG_DRM_EXYNOS7_DECON=3Dy
> # CONFIG_DRM_EXYNOS_MIXER is not set
> # CONFIG_DRM_EXYNOS_VIDI is not set
>=20
> #
> # Encoders and Bridges
> #
> CONFIG_DRM_EXYNOS_DSI=3Dy
> # CONFIG_DRM_EXYNOS_DP is not set
> CONFIG_DRM_EXYNOS_HDMI=3Dy
> CONFIG_DRM_EXYNOS_MIC=3Dy
>=20
> #
> # Sub-drivers
> #
> # CONFIG_DRM_EXYNOS_G2D is not set
> # CONFIG_DRM_EXYNOS_FIMC is not set
> # CONFIG_DRM_EXYNOS_ROTATOR is not set
> # CONFIG_DRM_EXYNOS_SCALER is not set
> CONFIG_DRM_ROCKCHIP=3Dm
> CONFIG_ROCKCHIP_ANALOGIX_DP=3Dy
> CONFIG_ROCKCHIP_CDN_DP=3Dy
> CONFIG_ROCKCHIP_DW_HDMI=3Dy
> CONFIG_ROCKCHIP_DW_MIPI_DSI=3Dy
> CONFIG_ROCKCHIP_INNO_HDMI=3Dy
> # CONFIG_ROCKCHIP_LVDS is not set
> # CONFIG_ROCKCHIP_RGB is not set
> # CONFIG_ROCKCHIP_RK3066_HDMI is not set
> # CONFIG_DRM_UDL is not set
> # CONFIG_DRM_AST is not set
> # CONFIG_DRM_MGAG200 is not set
> CONFIG_DRM_RCAR_DU=3Dm
> CONFIG_DRM_RCAR_CMM=3Dm
> CONFIG_DRM_RCAR_DW_HDMI=3Dm
> CONFIG_DRM_RCAR_LVDS=3Dm
> CONFIG_DRM_RCAR_VSP=3Dy
> CONFIG_DRM_RCAR_WRITEBACK=3Dy
> CONFIG_DRM_SUN4I=3Dm
> CONFIG_DRM_SUN4I_HDMI=3Dm
> # CONFIG_DRM_SUN4I_HDMI_CEC is not set
> CONFIG_DRM_SUN4I_BACKEND=3Dm
> CONFIG_DRM_SUN6I_DSI=3Dm
> CONFIG_DRM_SUN8I_DW_HDMI=3Dm
> CONFIG_DRM_SUN8I_MIXER=3Dm
> CONFIG_DRM_SUN8I_TCON_TOP=3Dm
> # CONFIG_DRM_QXL is not set
> # CONFIG_DRM_BOCHS is not set
> CONFIG_DRM_VIRTIO_GPU=3Dm
> CONFIG_DRM_TEGRA=3Dm
> # CONFIG_DRM_TEGRA_DEBUG is not set
> CONFIG_DRM_PANEL=3Dy
>=20
> #
> # Display Panels
> #
> # CONFIG_DRM_PANEL_ARM_VERSATILE is not set
> # CONFIG_DRM_PANEL_ASUS_Z00T_TM5P5_NT35596 is not set
> # CONFIG_DRM_PANEL_BOE_HIMAX8279D is not set
> # CONFIG_DRM_PANEL_BOE_TV101WUM_NL6 is not set
> CONFIG_DRM_PANEL_LVDS=3Dm
> CONFIG_DRM_PANEL_SIMPLE=3Dm
> # CONFIG_DRM_PANEL_ELIDA_KD35T133 is not set
> # CONFIG_DRM_PANEL_FEIXIN_K101_IM2BA02 is not set
> # CONFIG_DRM_PANEL_FEIYANG_FY07024DI26A30D is not set
> # CONFIG_DRM_PANEL_ILITEK_IL9322 is not set
> # CONFIG_DRM_PANEL_ILITEK_ILI9881C is not set
> # CONFIG_DRM_PANEL_INNOLUX_P079ZCA is not set
> # CONFIG_DRM_PANEL_JDI_LT070ME05000 is not set
> # CONFIG_DRM_PANEL_KINGDISPLAY_KD097D04 is not set
> # CONFIG_DRM_PANEL_LEADTEK_LTK050H3146W is not set
> # CONFIG_DRM_PANEL_LEADTEK_LTK500HD1829 is not set
> # CONFIG_DRM_PANEL_SAMSUNG_LD9040 is not set
> # CONFIG_DRM_PANEL_LG_LB035Q02 is not set
> # CONFIG_DRM_PANEL_LG_LG4573 is not set
> # CONFIG_DRM_PANEL_NEC_NL8048HL11 is not set
> # CONFIG_DRM_PANEL_NOVATEK_NT35510 is not set
> # CONFIG_DRM_PANEL_NOVATEK_NT36672A is not set
> # CONFIG_DRM_PANEL_NOVATEK_NT39016 is not set
> # CONFIG_DRM_PANEL_MANTIX_MLAF057WE51 is not set
> # CONFIG_DRM_PANEL_OLIMEX_LCD_OLINUXINO is not set
> # CONFIG_DRM_PANEL_ORISETECH_OTM8009A is not set
> # CONFIG_DRM_PANEL_OSD_OSD101T2587_53TS is not set
> # CONFIG_DRM_PANEL_PANASONIC_VVX10F034N00 is not set
> # CONFIG_DRM_PANEL_RASPBERRYPI_TOUCHSCREEN is not set
> # CONFIG_DRM_PANEL_RAYDIUM_RM67191 is not set
> # CONFIG_DRM_PANEL_RAYDIUM_RM68200 is not set
> # CONFIG_DRM_PANEL_RONBO_RB070D30 is not set
> # CONFIG_DRM_PANEL_SAMSUNG_S6D16D0 is not set
> # CONFIG_DRM_PANEL_SAMSUNG_S6E3HA2 is not set
> # CONFIG_DRM_PANEL_SAMSUNG_S6E63J0X03 is not set
> # CONFIG_DRM_PANEL_SAMSUNG_S6E63M0 is not set
> # CONFIG_DRM_PANEL_SAMSUNG_S6E88A0_AMS452EF01 is not set
> # CONFIG_DRM_PANEL_SAMSUNG_S6E8AA0 is not set
> # CONFIG_DRM_PANEL_SEIKO_43WVF1G is not set
> # CONFIG_DRM_PANEL_SHARP_LQ101R1SX01 is not set
> # CONFIG_DRM_PANEL_SHARP_LS037V7DW01 is not set
> # CONFIG_DRM_PANEL_SHARP_LS043T1LE01 is not set
> # CONFIG_DRM_PANEL_SITRONIX_ST7701 is not set
> # CONFIG_DRM_PANEL_SITRONIX_ST7703 is not set
> # CONFIG_DRM_PANEL_SITRONIX_ST7789V is not set
> # CONFIG_DRM_PANEL_SONY_ACX424AKP is not set
> # CONFIG_DRM_PANEL_SONY_ACX565AKM is not set
> # CONFIG_DRM_PANEL_TDO_TL070WSH30 is not set
> # CONFIG_DRM_PANEL_TPO_TD028TTEC1 is not set
> # CONFIG_DRM_PANEL_TPO_TD043MTEA1 is not set
> # CONFIG_DRM_PANEL_TPO_TPG110 is not set
> CONFIG_DRM_PANEL_TRULY_NT35597_WQXGA=3Dm
> # CONFIG_DRM_PANEL_VISIONOX_RM69299 is not set
> # CONFIG_DRM_PANEL_XINPENG_XPP055C272 is not set
> # end of Display Panels
>=20
> CONFIG_DRM_BRIDGE=3Dy
> CONFIG_DRM_PANEL_BRIDGE=3Dy
>=20
> #
> # Display Interface Bridges
> #
> # CONFIG_DRM_CDNS_DSI is not set
> # CONFIG_DRM_CHRONTEL_CH7033 is not set
> CONFIG_DRM_DISPLAY_CONNECTOR=3Dm
> # CONFIG_DRM_LONTIUM_LT9611 is not set
> # CONFIG_DRM_LONTIUM_LT9611UXC is not set
> # CONFIG_DRM_LVDS_CODEC is not set
> # CONFIG_DRM_MEGACHIPS_STDPXXXX_GE_B850V3_FW is not set
> # CONFIG_DRM_NWL_MIPI_DSI is not set
> # CONFIG_DRM_NXP_PTN3460 is not set
> # CONFIG_DRM_PARADE_PS8622 is not set
> # CONFIG_DRM_PARADE_PS8640 is not set
> # CONFIG_DRM_SIL_SII8620 is not set
> CONFIG_DRM_SII902X=3Dm
> # CONFIG_DRM_SII9234 is not set
> CONFIG_DRM_SIMPLE_BRIDGE=3Dm
> CONFIG_DRM_THINE_THC63LVD1024=3Dm
> # CONFIG_DRM_TOSHIBA_TC358762 is not set
> # CONFIG_DRM_TOSHIBA_TC358764 is not set
> # CONFIG_DRM_TOSHIBA_TC358767 is not set
> # CONFIG_DRM_TOSHIBA_TC358768 is not set
> # CONFIG_DRM_TOSHIBA_TC358775 is not set
> # CONFIG_DRM_TI_TFP410 is not set
> CONFIG_DRM_TI_SN65DSI86=3Dm
> # CONFIG_DRM_TI_TPD12S015 is not set
> # CONFIG_DRM_ANALOGIX_ANX6345 is not set
> # CONFIG_DRM_ANALOGIX_ANX78XX is not set
> CONFIG_DRM_ANALOGIX_DP=3Dm
> # CONFIG_DRM_ANALOGIX_ANX7625 is not set
> CONFIG_DRM_I2C_ADV7511=3Dm
> # CONFIG_DRM_I2C_ADV7511_AUDIO is not set
> CONFIG_DRM_I2C_ADV7511_CEC=3Dy
> # CONFIG_DRM_CDNS_MHDP8546 is not set
> CONFIG_DRM_DW_HDMI=3Dm
> CONFIG_DRM_DW_HDMI_AHB_AUDIO=3Dm
> CONFIG_DRM_DW_HDMI_I2S_AUDIO=3Dm
> CONFIG_DRM_DW_HDMI_CEC=3Dm
> CONFIG_DRM_DW_MIPI_DSI=3Dm
> # end of Display Interface Bridges
>=20
> # CONFIG_DRM_IMX_DCSS is not set
> CONFIG_DRM_VC4=3Dm
> # CONFIG_DRM_VC4_HDMI_CEC is not set
> CONFIG_DRM_ETNAVIV=3Dm
> CONFIG_DRM_ETNAVIV_THERMAL=3Dy
> # CONFIG_DRM_ARCPGU is not set
> CONFIG_DRM_HISI_HIBMC=3Dm
> CONFIG_DRM_HISI_KIRIN=3Dm
> # CONFIG_DRM_MEDIATEK is not set
> # CONFIG_DRM_ZTE is not set
> # CONFIG_DRM_MXSFB is not set
> CONFIG_DRM_MESON=3Dm
> CONFIG_DRM_MESON_DW_HDMI=3Dm
> # CONFIG_DRM_CIRRUS_QEMU is not set
> # CONFIG_DRM_GM12U320 is not set
> # CONFIG_TINYDRM_HX8357D is not set
> # CONFIG_TINYDRM_ILI9225 is not set
> # CONFIG_TINYDRM_ILI9341 is not set
> # CONFIG_TINYDRM_ILI9486 is not set
> # CONFIG_TINYDRM_MI0283QT is not set
> # CONFIG_TINYDRM_REPAPER is not set
> # CONFIG_TINYDRM_ST7586 is not set
> # CONFIG_TINYDRM_ST7735R is not set
> CONFIG_DRM_PL111=3Dm
> # CONFIG_DRM_XEN is not set
> CONFIG_DRM_LIMA=3Dm
> CONFIG_DRM_PANFROST=3Dm
> # CONFIG_DRM_TIDSS is not set
> # CONFIG_DRM_ZYNQMP_DPSUB is not set
> CONFIG_DRM_LEGACY=3Dy
> # CONFIG_DRM_TDFX is not set
> # CONFIG_DRM_R128 is not set
> # CONFIG_DRM_MGA is not set
> # CONFIG_DRM_VIA is not set
> # CONFIG_DRM_SAVAGE is not set
> CONFIG_DRM_PANEL_ORIENTATION_QUIRKS=3Dy
>=20
> #
> # Frame buffer Devices
> #
> CONFIG_FB_CMDLINE=3Dy
> CONFIG_FB_NOTIFY=3Dy
> CONFIG_FB=3Dy
> # CONFIG_FIRMWARE_EDID is not set
> CONFIG_FB_CFB_FILLRECT=3Dy
> CONFIG_FB_CFB_COPYAREA=3Dy
> CONFIG_FB_CFB_IMAGEBLIT=3Dy
> CONFIG_FB_SYS_FILLRECT=3Dy
> CONFIG_FB_SYS_COPYAREA=3Dy
> CONFIG_FB_SYS_IMAGEBLIT=3Dy
> # CONFIG_FB_FOREIGN_ENDIAN is not set
> CONFIG_FB_SYS_FOPS=3Dy
> CONFIG_FB_DEFERRED_IO=3Dy
> CONFIG_FB_MODE_HELPERS=3Dy
> # CONFIG_FB_TILEBLITTING is not set
>=20
> #
> # Frame buffer hardware drivers
> #
> # CONFIG_FB_CIRRUS is not set
> # CONFIG_FB_PM2 is not set
> # CONFIG_FB_ARMCLCD is not set
> # CONFIG_FB_IMX is not set
> # CONFIG_FB_CYBER2000 is not set
> # CONFIG_FB_ASILIANT is not set
> # CONFIG_FB_IMSTT is not set
> CONFIG_FB_EFI=3Dy
> # CONFIG_FB_OPENCORES is not set
> # CONFIG_FB_S1D13XXX is not set
> # CONFIG_FB_NVIDIA is not set
> # CONFIG_FB_RIVA is not set
> # CONFIG_FB_I740 is not set
> # CONFIG_FB_MATROX is not set
> # CONFIG_FB_RADEON is not set
> # CONFIG_FB_ATY128 is not set
> # CONFIG_FB_ATY is not set
> # CONFIG_FB_S3 is not set
> # CONFIG_FB_SAVAGE is not set
> # CONFIG_FB_SIS is not set
> # CONFIG_FB_NEOMAGIC is not set
> # CONFIG_FB_KYRO is not set
> # CONFIG_FB_3DFX is not set
> # CONFIG_FB_VOODOO1 is not set
> # CONFIG_FB_VT8623 is not set
> # CONFIG_FB_TRIDENT is not set
> # CONFIG_FB_ARK is not set
> # CONFIG_FB_PM3 is not set
> # CONFIG_FB_CARMINE is not set
> # CONFIG_FB_SH_MOBILE_LCDC is not set
> # CONFIG_FB_SMSCUFX is not set
> # CONFIG_FB_UDL is not set
> # CONFIG_FB_IBM_GXT4500 is not set
> # CONFIG_FB_XILINX is not set
> # CONFIG_FB_VIRTUAL is not set
> CONFIG_XEN_FBDEV_FRONTEND=3Dy
> # CONFIG_FB_METRONOME is not set
> # CONFIG_FB_MB862XX is not set
> CONFIG_FB_MX3=3Dy
> # CONFIG_FB_SIMPLE is not set
> # CONFIG_FB_SSD1307 is not set
> # CONFIG_FB_SM712 is not set
> # end of Frame buffer Devices
>=20
> #
> # Backlight & LCD device support
> #
> # CONFIG_LCD_CLASS_DEVICE is not set
> CONFIG_BACKLIGHT_CLASS_DEVICE=3Dy
> # CONFIG_BACKLIGHT_KTD253 is not set
> CONFIG_BACKLIGHT_PWM=3Dm
> # CONFIG_BACKLIGHT_QCOM_WLED is not set
> # CONFIG_BACKLIGHT_ADP8860 is not set
> # CONFIG_BACKLIGHT_ADP8870 is not set
> # CONFIG_BACKLIGHT_LM3630A is not set
> # CONFIG_BACKLIGHT_LM3639 is not set
> CONFIG_BACKLIGHT_LP855X=3Dm
> # CONFIG_BACKLIGHT_GPIO is not set
> # CONFIG_BACKLIGHT_LV5207LP is not set
> # CONFIG_BACKLIGHT_BD6107 is not set
> # CONFIG_BACKLIGHT_ARCXCNN is not set
> # CONFIG_BACKLIGHT_LED is not set
> # end of Backlight & LCD device support
>=20
> CONFIG_VIDEOMODE_HELPERS=3Dy
> CONFIG_HDMI=3Dy
>=20
> #
> # Console display driver support
> #
> CONFIG_DUMMY_CONSOLE=3Dy
> CONFIG_DUMMY_CONSOLE_COLUMNS=3D80
> CONFIG_DUMMY_CONSOLE_ROWS=3D25
> CONFIG_FRAMEBUFFER_CONSOLE=3Dy
> CONFIG_FRAMEBUFFER_CONSOLE_DETECT_PRIMARY=3Dy
> # CONFIG_FRAMEBUFFER_CONSOLE_ROTATION is not set
> # CONFIG_FRAMEBUFFER_CONSOLE_DEFERRED_TAKEOVER is not set
> # end of Console display driver support
>=20
> CONFIG_LOGO=3Dy
> # CONFIG_LOGO_LINUX_MONO is not set
> # CONFIG_LOGO_LINUX_VGA16 is not set
> CONFIG_LOGO_LINUX_CLUT224=3Dy
> # end of Graphics support
>=20
> CONFIG_SOUND=3Dy
> CONFIG_SND=3Dy
> CONFIG_SND_TIMER=3Dy
> CONFIG_SND_PCM=3Dy
> CONFIG_SND_PCM_ELD=3Dy
> CONFIG_SND_PCM_IEC958=3Dy
> CONFIG_SND_DMAENGINE_PCM=3Dy
> CONFIG_SND_JACK=3Dy
> CONFIG_SND_JACK_INPUT_DEV=3Dy
> # CONFIG_SND_OSSEMUL is not set
> CONFIG_SND_PCM_TIMER=3Dy
> # CONFIG_SND_HRTIMER is not set
> CONFIG_SND_DYNAMIC_MINORS=3Dy
> CONFIG_SND_MAX_CARDS=3D32
> CONFIG_SND_SUPPORT_OLD_API=3Dy
> CONFIG_SND_PROC_FS=3Dy
> CONFIG_SND_VERBOSE_PROCFS=3Dy
> # CONFIG_SND_VERBOSE_PRINTK is not set
> # CONFIG_SND_DEBUG is not set
> CONFIG_SND_VMASTER=3Dy
> # CONFIG_SND_SEQUENCER is not set
> CONFIG_SND_DRIVERS=3Dy
> # CONFIG_SND_DUMMY is not set
> # CONFIG_SND_ALOOP is not set
> # CONFIG_SND_MTPAV is not set
> # CONFIG_SND_SERIAL_U16550 is not set
> # CONFIG_SND_MPU401 is not set
> CONFIG_SND_PCI=3Dy
> # CONFIG_SND_AD1889 is not set
> # CONFIG_SND_ALS300 is not set
> # CONFIG_SND_ALI5451 is not set
> # CONFIG_SND_ATIIXP is not set
> # CONFIG_SND_ATIIXP_MODEM is not set
> # CONFIG_SND_AU8810 is not set
> # CONFIG_SND_AU8820 is not set
> # CONFIG_SND_AU8830 is not set
> # CONFIG_SND_AW2 is not set
> # CONFIG_SND_AZT3328 is not set
> # CONFIG_SND_BT87X is not set
> # CONFIG_SND_CA0106 is not set
> # CONFIG_SND_CMIPCI is not set
> # CONFIG_SND_OXYGEN is not set
> # CONFIG_SND_CS4281 is not set
> # CONFIG_SND_CS46XX is not set
> # CONFIG_SND_CTXFI is not set
> # CONFIG_SND_DARLA20 is not set
> # CONFIG_SND_GINA20 is not set
> # CONFIG_SND_LAYLA20 is not set
> # CONFIG_SND_DARLA24 is not set
> # CONFIG_SND_GINA24 is not set
> # CONFIG_SND_LAYLA24 is not set
> # CONFIG_SND_MONA is not set
> # CONFIG_SND_MIA is not set
> # CONFIG_SND_ECHO3G is not set
> # CONFIG_SND_INDIGO is not set
> # CONFIG_SND_INDIGOIO is not set
> # CONFIG_SND_INDIGODJ is not set
> # CONFIG_SND_INDIGOIOX is not set
> # CONFIG_SND_INDIGODJX is not set
> # CONFIG_SND_EMU10K1 is not set
> # CONFIG_SND_EMU10K1X is not set
> # CONFIG_SND_ENS1370 is not set
> # CONFIG_SND_ENS1371 is not set
> # CONFIG_SND_ES1938 is not set
> # CONFIG_SND_ES1968 is not set
> # CONFIG_SND_FM801 is not set
> # CONFIG_SND_HDSP is not set
> # CONFIG_SND_HDSPM is not set
> # CONFIG_SND_ICE1712 is not set
> # CONFIG_SND_ICE1724 is not set
> # CONFIG_SND_INTEL8X0 is not set
> # CONFIG_SND_INTEL8X0M is not set
> # CONFIG_SND_KORG1212 is not set
> # CONFIG_SND_LOLA is not set
> # CONFIG_SND_LX6464ES is not set
> # CONFIG_SND_MAESTRO3 is not set
> # CONFIG_SND_MIXART is not set
> # CONFIG_SND_NM256 is not set
> # CONFIG_SND_PCXHR is not set
> # CONFIG_SND_RIPTIDE is not set
> # CONFIG_SND_RME32 is not set
> # CONFIG_SND_RME96 is not set
> # CONFIG_SND_RME9652 is not set
> # CONFIG_SND_SE6X is not set
> # CONFIG_SND_SONICVIBES is not set
> # CONFIG_SND_TRIDENT is not set
> # CONFIG_SND_VIA82XX is not set
> # CONFIG_SND_VIA82XX_MODEM is not set
> # CONFIG_SND_VIRTUOSO is not set
> # CONFIG_SND_VX222 is not set
> # CONFIG_SND_YMFPCI is not set
>=20
> #
> # HD-Audio
> #
> CONFIG_SND_HDA=3Dm
> # CONFIG_SND_HDA_INTEL is not set
> CONFIG_SND_HDA_TEGRA=3Dm
> # CONFIG_SND_HDA_HWDEP is not set
> # CONFIG_SND_HDA_RECONFIG is not set
> # CONFIG_SND_HDA_INPUT_BEEP is not set
> # CONFIG_SND_HDA_PATCH_LOADER is not set
> # CONFIG_SND_HDA_CODEC_REALTEK is not set
> # CONFIG_SND_HDA_CODEC_ANALOG is not set
> # CONFIG_SND_HDA_CODEC_SIGMATEL is not set
> # CONFIG_SND_HDA_CODEC_VIA is not set
> CONFIG_SND_HDA_CODEC_HDMI=3Dm
> # CONFIG_SND_HDA_CODEC_CIRRUS is not set
> # CONFIG_SND_HDA_CODEC_CONEXANT is not set
> # CONFIG_SND_HDA_CODEC_CA0110 is not set
> # CONFIG_SND_HDA_CODEC_CA0132 is not set
> # CONFIG_SND_HDA_CODEC_CMEDIA is not set
> # CONFIG_SND_HDA_CODEC_SI3054 is not set
> # CONFIG_SND_HDA_GENERIC is not set
> CONFIG_SND_HDA_POWER_SAVE_DEFAULT=3D0
> # end of HD-Audio
>=20
> CONFIG_SND_HDA_CORE=3Dm
> CONFIG_SND_HDA_ALIGNED_MMIO=3Dy
> CONFIG_SND_HDA_COMPONENT=3Dy
> CONFIG_SND_HDA_PREALLOC_SIZE=3D64
> CONFIG_SND_SPI=3Dy
> CONFIG_SND_USB=3Dy
> # CONFIG_SND_USB_AUDIO is not set
> # CONFIG_SND_USB_UA101 is not set
> # CONFIG_SND_USB_CAIAQ is not set
> # CONFIG_SND_USB_6FIRE is not set
> # CONFIG_SND_USB_HIFACE is not set
> # CONFIG_SND_BCD2000 is not set
> # CONFIG_SND_USB_POD is not set
> # CONFIG_SND_USB_PODHD is not set
> # CONFIG_SND_USB_TONEPORT is not set
> # CONFIG_SND_USB_VARIAX is not set
> CONFIG_SND_SOC=3Dy
> CONFIG_SND_SOC_GENERIC_DMAENGINE_PCM=3Dy
> # CONFIG_SND_SOC_AMD_ACP is not set
> # CONFIG_SND_ATMEL_SOC is not set
> CONFIG_SND_BCM2835_SOC_I2S=3Dm
> # CONFIG_SND_BCM63XX_I2S_WHISTLER is not set
> # CONFIG_SND_DESIGNWARE_I2S is not set
>=20
> #
> # SoC Audio for Freescale CPUs
> #
>=20
> #
> # Common SoC Audio options for Freescale CPUs:
> #
> # CONFIG_SND_SOC_FSL_ASRC is not set
> # CONFIG_SND_SOC_FSL_SAI is not set
> # CONFIG_SND_SOC_FSL_AUDMIX is not set
> # CONFIG_SND_SOC_FSL_SSI is not set
> # CONFIG_SND_SOC_FSL_SPDIF is not set
> # CONFIG_SND_SOC_FSL_ESAI is not set
> # CONFIG_SND_SOC_FSL_MICFIL is not set
> # CONFIG_SND_SOC_FSL_XCVR is not set
> # CONFIG_SND_SOC_FSL_AUD2HTX is not set
> # CONFIG_SND_SOC_IMX_AUDMUX is not set
> # CONFIG_SND_IMX_SOC is not set
> # end of SoC Audio for Freescale CPUs
>=20
> # CONFIG_SND_I2S_HI6210_I2S is not set
> # CONFIG_SND_KIRKWOOD_SOC is not set
> # CONFIG_SND_SOC_IMG is not set
> # CONFIG_SND_SOC_INTEL_KEEMBAY is not set
> # CONFIG_SND_SOC_MT2701 is not set
> # CONFIG_SND_SOC_MT6797 is not set
> # CONFIG_SND_SOC_MT8173 is not set
> # CONFIG_SND_SOC_MT8183 is not set
> # CONFIG_SND_SOC_MTK_BTCVSD is not set
> # CONFIG_SND_SOC_MT8192 is not set
>=20
> #
> # ASoC support for Amlogic platforms
> #
> CONFIG_SND_MESON_AIU=3Dm
> CONFIG_SND_MESON_AXG_FIFO=3Dm
> CONFIG_SND_MESON_AXG_FRDDR=3Dm
> CONFIG_SND_MESON_AXG_TODDR=3Dm
> CONFIG_SND_MESON_AXG_TDM_FORMATTER=3Dm
> CONFIG_SND_MESON_AXG_TDM_INTERFACE=3Dm
> CONFIG_SND_MESON_AXG_TDMIN=3Dm
> CONFIG_SND_MESON_AXG_TDMOUT=3Dm
> CONFIG_SND_MESON_AXG_SOUND_CARD=3Dm
> CONFIG_SND_MESON_AXG_SPDIFOUT=3Dm
> CONFIG_SND_MESON_AXG_SPDIFIN=3Dm
> CONFIG_SND_MESON_AXG_PDM=3Dm
> CONFIG_SND_MESON_CARD_UTILS=3Dm
> CONFIG_SND_MESON_CODEC_GLUE=3Dm
> CONFIG_SND_MESON_GX_SOUND_CARD=3Dm
> # CONFIG_SND_MESON_G12A_TOACODEC is not set
> CONFIG_SND_MESON_G12A_TOHDMITX=3Dm
> CONFIG_SND_SOC_MESON_T9015=3Dm
> # end of ASoC support for Amlogic platforms
>=20
> # CONFIG_SND_SOC_QCOM is not set
> CONFIG_SND_SOC_ROCKCHIP=3Dm
> CONFIG_SND_SOC_ROCKCHIP_I2S=3Dm
> # CONFIG_SND_SOC_ROCKCHIP_PDM is not set
> CONFIG_SND_SOC_ROCKCHIP_SPDIF=3Dm
> # CONFIG_SND_SOC_ROCKCHIP_MAX98090 is not set
> CONFIG_SND_SOC_ROCKCHIP_RT5645=3Dm
> # CONFIG_SND_SOC_RK3288_HDMI_ANALOG is not set
> CONFIG_SND_SOC_RK3399_GRU_SOUND=3Dm
> CONFIG_SND_SOC_SAMSUNG=3Dy
> # CONFIG_SND_SAMSUNG_PCM is not set
> # CONFIG_SND_SAMSUNG_SPDIF is not set
> # CONFIG_SND_SAMSUNG_I2S is not set
> # CONFIG_SND_SOC_SAMSUNG_SMDK_WM8994 is not set
> # CONFIG_SND_SOC_SAMSUNG_SMDK_SPDIF is not set
> # CONFIG_SND_SOC_SMDK_WM8994_PCM is not set
> # CONFIG_SND_SOC_SNOW is not set
> # CONFIG_SND_SOC_ODROID is not set
> # CONFIG_SND_SOC_ARNDALE is not set
> # CONFIG_SND_SOC_SAMSUNG_MIDAS_WM1811 is not set
>=20
> #
> # SoC Audio support for Renesas SoCs
> #
> # CONFIG_SND_SOC_SH4_FSI is not set
> CONFIG_SND_SOC_RCAR=3Dm
> # end of SoC Audio support for Renesas SoCs
>=20
> # CONFIG_SND_SOC_SOF_TOPLEVEL is not set
> # CONFIG_SND_SOC_SPRD is not set
>=20
> #
> # STMicroelectronics STM32 SOC audio support
> #
> # end of STMicroelectronics STM32 SOC audio support
>=20
> #
> # Allwinner SoC Audio support
> #
> # CONFIG_SND_SUN4I_CODEC is not set
> # CONFIG_SND_SUN8I_CODEC is not set
> # CONFIG_SND_SUN8I_CODEC_ANALOG is not set
> # CONFIG_SND_SUN50I_CODEC_ANALOG is not set
> # CONFIG_SND_SUN4I_I2S is not set
> CONFIG_SND_SUN4I_SPDIF=3Dm
> # end of Allwinner SoC Audio support
>=20
> # CONFIG_SND_SOC_TEGRA is not set
>=20
> #
> # Audio support for Texas Instruments SoCs
> #
>=20
> #
> # Texas Instruments DAI support for:
> #
> # CONFIG_SND_SOC_DAVINCI_MCASP is not set
>=20
> #
> # Audio support for boards with Texas Instruments SoCs
> #
> # CONFIG_SND_SOC_J721E_EVM is not set
> # end of Audio support for Texas Instruments SoCs
>=20
> # CONFIG_SND_SOC_UNIPHIER is not set
> # CONFIG_SND_SOC_XILINX_I2S is not set
> # CONFIG_SND_SOC_XILINX_AUDIO_FORMATTER is not set
> # CONFIG_SND_SOC_XILINX_SPDIF is not set
> # CONFIG_SND_SOC_XTFPGA_I2S is not set
> # CONFIG_ZX_SPDIF is not set
> # CONFIG_ZX_I2S is not set
> # CONFIG_ZX_TDM is not set
> CONFIG_SND_SOC_I2C_AND_SPI=3Dy
>=20
> #
> # CODEC drivers
> #
> # CONFIG_SND_SOC_AC97_CODEC is not set
> # CONFIG_SND_SOC_ADAU1701 is not set
> # CONFIG_SND_SOC_ADAU1761_I2C is not set
> # CONFIG_SND_SOC_ADAU1761_SPI is not set
> # CONFIG_SND_SOC_ADAU7002 is not set
> # CONFIG_SND_SOC_ADAU7118_HW is not set
> # CONFIG_SND_SOC_ADAU7118_I2C is not set
> # CONFIG_SND_SOC_AK4104 is not set
> # CONFIG_SND_SOC_AK4118 is not set
> # CONFIG_SND_SOC_AK4458 is not set
> # CONFIG_SND_SOC_AK4554 is not set
> CONFIG_SND_SOC_AK4613=3Dm
> # CONFIG_SND_SOC_AK4642 is not set
> # CONFIG_SND_SOC_AK5386 is not set
> # CONFIG_SND_SOC_AK5558 is not set
> # CONFIG_SND_SOC_ALC5623 is not set
> # CONFIG_SND_SOC_BD28623 is not set
> # CONFIG_SND_SOC_BT_SCO is not set
> CONFIG_SND_SOC_CROS_EC_CODEC=3Dm
> # CONFIG_SND_SOC_CS35L32 is not set
> # CONFIG_SND_SOC_CS35L33 is not set
> # CONFIG_SND_SOC_CS35L34 is not set
> # CONFIG_SND_SOC_CS35L35 is not set
> # CONFIG_SND_SOC_CS35L36 is not set
> # CONFIG_SND_SOC_CS42L42 is not set
> # CONFIG_SND_SOC_CS42L51_I2C is not set
> # CONFIG_SND_SOC_CS42L52 is not set
> # CONFIG_SND_SOC_CS42L56 is not set
> # CONFIG_SND_SOC_CS42L73 is not set
> # CONFIG_SND_SOC_CS4234 is not set
> # CONFIG_SND_SOC_CS4265 is not set
> # CONFIG_SND_SOC_CS4270 is not set
> # CONFIG_SND_SOC_CS4271_I2C is not set
> # CONFIG_SND_SOC_CS4271_SPI is not set
> # CONFIG_SND_SOC_CS42XX8_I2C is not set
> # CONFIG_SND_SOC_CS43130 is not set
> # CONFIG_SND_SOC_CS4341 is not set
> # CONFIG_SND_SOC_CS4349 is not set
> # CONFIG_SND_SOC_CS53L30 is not set
> # CONFIG_SND_SOC_CX2072X is not set
> # CONFIG_SND_SOC_DA7213 is not set
> CONFIG_SND_SOC_DA7219=3Dm
> CONFIG_SND_SOC_DMIC=3Dm
> CONFIG_SND_SOC_HDMI_CODEC=3Dm
> CONFIG_SND_SOC_ES7134=3Dm
> CONFIG_SND_SOC_ES7241=3Dm
> # CONFIG_SND_SOC_ES8316 is not set
> # CONFIG_SND_SOC_ES8328_I2C is not set
> # CONFIG_SND_SOC_ES8328_SPI is not set
> # CONFIG_SND_SOC_GTM601 is not set
> # CONFIG_SND_SOC_INNO_RK3036 is not set
> # CONFIG_SND_SOC_MAX98088 is not set
> CONFIG_SND_SOC_MAX98357A=3Dm
> # CONFIG_SND_SOC_MAX98504 is not set
> # CONFIG_SND_SOC_MAX9867 is not set
> CONFIG_SND_SOC_MAX98927=3Dm
> # CONFIG_SND_SOC_MAX98373_I2C is not set
> # CONFIG_SND_SOC_MAX98373_SDW is not set
> # CONFIG_SND_SOC_MAX98390 is not set
> # CONFIG_SND_SOC_MAX9860 is not set
> # CONFIG_SND_SOC_MSM8916_WCD_ANALOG is not set
> # CONFIG_SND_SOC_MSM8916_WCD_DIGITAL is not set
> # CONFIG_SND_SOC_PCM1681 is not set
> # CONFIG_SND_SOC_PCM1789_I2C is not set
> # CONFIG_SND_SOC_PCM179X_I2C is not set
> # CONFIG_SND_SOC_PCM179X_SPI is not set
> # CONFIG_SND_SOC_PCM186X_I2C is not set
> # CONFIG_SND_SOC_PCM186X_SPI is not set
> # CONFIG_SND_SOC_PCM3060_I2C is not set
> # CONFIG_SND_SOC_PCM3060_SPI is not set
> CONFIG_SND_SOC_PCM3168A=3Dm
> CONFIG_SND_SOC_PCM3168A_I2C=3Dm
> # CONFIG_SND_SOC_PCM3168A_SPI is not set
> # CONFIG_SND_SOC_PCM5102A is not set
> # CONFIG_SND_SOC_PCM512x_I2C is not set
> # CONFIG_SND_SOC_PCM512x_SPI is not set
> # CONFIG_SND_SOC_RK3328 is not set
> CONFIG_SND_SOC_RL6231=3Dm
> # CONFIG_SND_SOC_RT1308_SDW is not set
> CONFIG_SND_SOC_RT5514=3Dm
> CONFIG_SND_SOC_RT5514_SPI=3Dm
> # CONFIG_SND_SOC_RT5616 is not set
> # CONFIG_SND_SOC_RT5631 is not set
> CONFIG_SND_SOC_RT5645=3Dm
> # CONFIG_SND_SOC_RT5682_SDW is not set
> # CONFIG_SND_SOC_RT700_SDW is not set
> # CONFIG_SND_SOC_RT711_SDW is not set
> # CONFIG_SND_SOC_RT715_SDW is not set
> # CONFIG_SND_SOC_SGTL5000 is not set
> CONFIG_SND_SOC_SIMPLE_AMPLIFIER=3Dm
> # CONFIG_SND_SOC_SIRF_AUDIO_CODEC is not set
> CONFIG_SND_SOC_SPDIF=3Dm
> # CONFIG_SND_SOC_SSM2305 is not set
> # CONFIG_SND_SOC_SSM2602_SPI is not set
> # CONFIG_SND_SOC_SSM2602_I2C is not set
> # CONFIG_SND_SOC_SSM4567 is not set
> # CONFIG_SND_SOC_STA32X is not set
> # CONFIG_SND_SOC_STA350 is not set
> # CONFIG_SND_SOC_STI_SAS is not set
> # CONFIG_SND_SOC_TAS2552 is not set
> # CONFIG_SND_SOC_TAS2562 is not set
> # CONFIG_SND_SOC_TAS2764 is not set
> # CONFIG_SND_SOC_TAS2770 is not set
> # CONFIG_SND_SOC_TAS5086 is not set
> CONFIG_SND_SOC_TAS571X=3Dm
> # CONFIG_SND_SOC_TAS5720 is not set
> # CONFIG_SND_SOC_TAS6424 is not set
> # CONFIG_SND_SOC_TDA7419 is not set
> # CONFIG_SND_SOC_TFA9879 is not set
> # CONFIG_SND_SOC_TLV320AIC23_I2C is not set
> # CONFIG_SND_SOC_TLV320AIC23_SPI is not set
> # CONFIG_SND_SOC_TLV320AIC31XX is not set
> # CONFIG_SND_SOC_TLV320AIC32X4_I2C is not set
> # CONFIG_SND_SOC_TLV320AIC32X4_SPI is not set
> # CONFIG_SND_SOC_TLV320AIC3X is not set
> # CONFIG_SND_SOC_TLV320ADCX140 is not set
> # CONFIG_SND_SOC_TS3A227E is not set
> # CONFIG_SND_SOC_TSCS42XX is not set
> # CONFIG_SND_SOC_TSCS454 is not set
> # CONFIG_SND_SOC_UDA1334 is not set
> # CONFIG_SND_SOC_WCD9335 is not set
> CONFIG_SND_SOC_WCD934X=3Dm
> # CONFIG_SND_SOC_WM8510 is not set
> # CONFIG_SND_SOC_WM8523 is not set
> # CONFIG_SND_SOC_WM8524 is not set
> # CONFIG_SND_SOC_WM8580 is not set
> # CONFIG_SND_SOC_WM8711 is not set
> # CONFIG_SND_SOC_WM8728 is not set
> # CONFIG_SND_SOC_WM8731 is not set
> # CONFIG_SND_SOC_WM8737 is not set
> # CONFIG_SND_SOC_WM8741 is not set
> # CONFIG_SND_SOC_WM8750 is not set
> # CONFIG_SND_SOC_WM8753 is not set
> # CONFIG_SND_SOC_WM8770 is not set
> # CONFIG_SND_SOC_WM8776 is not set
> # CONFIG_SND_SOC_WM8782 is not set
> # CONFIG_SND_SOC_WM8804_I2C is not set
> # CONFIG_SND_SOC_WM8804_SPI is not set
> # CONFIG_SND_SOC_WM8903 is not set
> # CONFIG_SND_SOC_WM8904 is not set
> # CONFIG_SND_SOC_WM8960 is not set
> # CONFIG_SND_SOC_WM8962 is not set
> # CONFIG_SND_SOC_WM8974 is not set
> # CONFIG_SND_SOC_WM8978 is not set
> # CONFIG_SND_SOC_WM8985 is not set
> CONFIG_SND_SOC_WSA881X=3Dm
> # CONFIG_SND_SOC_ZL38060 is not set
> # CONFIG_SND_SOC_ZX_AUD96P22 is not set
> # CONFIG_SND_SOC_MAX9759 is not set
> # CONFIG_SND_SOC_MT6351 is not set
> # CONFIG_SND_SOC_MT6358 is not set
> # CONFIG_SND_SOC_MT6660 is not set
> # CONFIG_SND_SOC_NAU8540 is not set
> # CONFIG_SND_SOC_NAU8810 is not set
> # CONFIG_SND_SOC_NAU8822 is not set
> # CONFIG_SND_SOC_NAU8824 is not set
> # CONFIG_SND_SOC_TPA6130A2 is not set
> # end of CODEC drivers
>=20
> CONFIG_SND_SIMPLE_CARD_UTILS=3Dm
> CONFIG_SND_SIMPLE_CARD=3Dm
> CONFIG_SND_AUDIO_GRAPH_CARD=3Dm
> # CONFIG_SND_XEN_FRONTEND is not set
>=20
> #
> # HID support
> #
> CONFIG_HID=3Dy
> # CONFIG_HID_BATTERY_STRENGTH is not set
> # CONFIG_HIDRAW is not set
> # CONFIG_UHID is not set
> CONFIG_HID_GENERIC=3Dy
>=20
> #
> # Special HID drivers
> #
> CONFIG_HID_A4TECH=3Dy
> # CONFIG_HID_ACCUTOUCH is not set
> # CONFIG_HID_ACRUX is not set
> CONFIG_HID_APPLE=3Dy
> # CONFIG_HID_APPLEIR is not set
> # CONFIG_HID_ASUS is not set
> # CONFIG_HID_AUREAL is not set
> CONFIG_HID_BELKIN=3Dy
> # CONFIG_HID_BETOP_FF is not set
> # CONFIG_HID_BIGBEN_FF is not set
> CONFIG_HID_CHERRY=3Dy
> CONFIG_HID_CHICONY=3Dy
> # CONFIG_HID_CORSAIR is not set
> # CONFIG_HID_COUGAR is not set
> # CONFIG_HID_MACALLY is not set
> # CONFIG_HID_PRODIKEYS is not set
> # CONFIG_HID_CMEDIA is not set
> # CONFIG_HID_CREATIVE_SB0540 is not set
> CONFIG_HID_CYPRESS=3Dy
> # CONFIG_HID_DRAGONRISE is not set
> # CONFIG_HID_EMS_FF is not set
> # CONFIG_HID_ELAN is not set
> # CONFIG_HID_ELECOM is not set
> # CONFIG_HID_ELO is not set
> CONFIG_HID_EZKEY=3Dy
> # CONFIG_HID_GEMBIRD is not set
> # CONFIG_HID_GFRM is not set
> # CONFIG_HID_GLORIOUS is not set
> # CONFIG_HID_HOLTEK is not set
> # CONFIG_HID_GOOGLE_HAMMER is not set
> # CONFIG_HID_VIVALDI is not set
> # CONFIG_HID_GT683R is not set
> # CONFIG_HID_KEYTOUCH is not set
> # CONFIG_HID_KYE is not set
> # CONFIG_HID_UCLOGIC is not set
> # CONFIG_HID_WALTOP is not set
> # CONFIG_HID_VIEWSONIC is not set
> # CONFIG_HID_GYRATION is not set
> # CONFIG_HID_ICADE is not set
> CONFIG_HID_ITE=3Dy
> # CONFIG_HID_JABRA is not set
> # CONFIG_HID_TWINHAN is not set
> CONFIG_HID_KENSINGTON=3Dy
> # CONFIG_HID_LCPOWER is not set
> # CONFIG_HID_LED is not set
> # CONFIG_HID_LENOVO is not set
> CONFIG_HID_LOGITECH=3Dy
> # CONFIG_HID_LOGITECH_HIDPP is not set
> # CONFIG_LOGITECH_FF is not set
> # CONFIG_LOGIRUMBLEPAD2_FF is not set
> # CONFIG_LOGIG940_FF is not set
> # CONFIG_LOGIWHEELS_FF is not set
> # CONFIG_HID_MAGICMOUSE is not set
> # CONFIG_HID_MALTRON is not set
> # CONFIG_HID_MAYFLASH is not set
> CONFIG_HID_REDRAGON=3Dy
> CONFIG_HID_MICROSOFT=3Dy
> CONFIG_HID_MONTEREY=3Dy
> # CONFIG_HID_MULTITOUCH is not set
> # CONFIG_HID_NTI is not set
> # CONFIG_HID_NTRIG is not set
> # CONFIG_HID_ORTEK is not set
> # CONFIG_HID_PANTHERLORD is not set
> # CONFIG_HID_PENMOUNT is not set
> # CONFIG_HID_PETALYNX is not set
> # CONFIG_HID_PICOLCD is not set
> # CONFIG_HID_PLANTRONICS is not set
> # CONFIG_HID_PRIMAX is not set
> # CONFIG_HID_RETRODE is not set
> # CONFIG_HID_ROCCAT is not set
> # CONFIG_HID_SAITEK is not set
> # CONFIG_HID_SAMSUNG is not set
> # CONFIG_HID_SONY is not set
> # CONFIG_HID_SPEEDLINK is not set
> # CONFIG_HID_STEAM is not set
> # CONFIG_HID_STEELSERIES is not set
> # CONFIG_HID_SUNPLUS is not set
> # CONFIG_HID_RMI is not set
> # CONFIG_HID_GREENASIA is not set
> # CONFIG_HID_SMARTJOYPLUS is not set
> # CONFIG_HID_TIVO is not set
> # CONFIG_HID_TOPSEED is not set
> # CONFIG_HID_THINGM is not set
> # CONFIG_HID_THRUSTMASTER is not set
> # CONFIG_HID_UDRAW_PS3 is not set
> # CONFIG_HID_U2FZERO is not set
> # CONFIG_HID_WACOM is not set
> # CONFIG_HID_WIIMOTE is not set
> # CONFIG_HID_XINMO is not set
> # CONFIG_HID_ZEROPLUS is not set
> # CONFIG_HID_ZYDACRON is not set
> # CONFIG_HID_SENSOR_HUB is not set
> # CONFIG_HID_ALPS is not set
> # CONFIG_HID_MCP2221 is not set
> # end of Special HID drivers
>=20
> #
> # USB HID support
> #
> CONFIG_USB_HID=3Dy
> # CONFIG_HID_PID is not set
> # CONFIG_USB_HIDDEV is not set
> # end of USB HID support
>=20
> #
> # I2C HID support
> #
> CONFIG_I2C_HID=3Dm
> # end of I2C HID support
> # end of HID support
>=20
> CONFIG_USB_OHCI_LITTLE_ENDIAN=3Dy
> CONFIG_USB_SUPPORT=3Dy
> CONFIG_USB_COMMON=3Dy
> # CONFIG_USB_LED_TRIG is not set
> CONFIG_USB_ULPI_BUS=3Dy
> CONFIG_USB_CONN_GPIO=3Dy
> CONFIG_USB_ARCH_HAS_HCD=3Dy
> CONFIG_USB=3Dy
> CONFIG_USB_PCI=3Dy
> # CONFIG_USB_ANNOUNCE_NEW_DEVICES is not set
>=20
> #
> # Miscellaneous USB options
> #
> CONFIG_USB_DEFAULT_PERSIST=3Dy
> # CONFIG_USB_FEW_INIT_RETRIES is not set
> # CONFIG_USB_DYNAMIC_MINORS is not set
> CONFIG_USB_OTG=3Dy
> # CONFIG_USB_OTG_PRODUCTLIST is not set
> # CONFIG_USB_OTG_DISABLE_EXTERNAL_HUB is not set
> # CONFIG_USB_OTG_FSM is not set
> # CONFIG_USB_LEDS_TRIGGER_USBPORT is not set
> CONFIG_USB_AUTOSUSPEND_DELAY=3D2
> # CONFIG_USB_MON is not set
>=20
> #
> # USB Host Controller Drivers
> #
> # CONFIG_USB_C67X00_HCD is not set
> CONFIG_USB_XHCI_HCD=3Dy
> # CONFIG_USB_XHCI_DBGCAP is not set
> CONFIG_USB_XHCI_PCI=3Dy
> # CONFIG_USB_XHCI_PCI_RENESAS is not set
> CONFIG_USB_XHCI_PLATFORM=3Dy
> # CONFIG_USB_XHCI_HISTB is not set
> # CONFIG_USB_XHCI_MTK is not set
> # CONFIG_USB_XHCI_MVEBU is not set
> CONFIG_USB_XHCI_RCAR=3Dy
> CONFIG_USB_XHCI_TEGRA=3Dy
> # CONFIG_USB_BRCMSTB is not set
> CONFIG_USB_EHCI_HCD=3Dy
> CONFIG_USB_EHCI_ROOT_HUB_TT=3Dy
> CONFIG_USB_EHCI_TT_NEWSCHED=3Dy
> CONFIG_USB_EHCI_PCI=3Dy
> # CONFIG_USB_EHCI_FSL is not set
> # CONFIG_USB_EHCI_MXC is not set
> CONFIG_USB_EHCI_HCD_ORION=3Dy
> # CONFIG_USB_EHCI_TEGRA is not set
> CONFIG_USB_EHCI_EXYNOS=3Dy
> CONFIG_USB_EHCI_HCD_PLATFORM=3Dy
> # CONFIG_USB_OXU210HP_HCD is not set
> # CONFIG_USB_ISP116X_HCD is not set
> # CONFIG_USB_FOTG210_HCD is not set
> # CONFIG_USB_MAX3421_HCD is not set
> CONFIG_USB_OHCI_HCD=3Dy
> CONFIG_USB_OHCI_HCD_PCI=3Dy
> CONFIG_USB_OHCI_EXYNOS=3Dy
> CONFIG_USB_OHCI_HCD_PLATFORM=3Dy
> # CONFIG_USB_UHCI_HCD is not set
> # CONFIG_USB_SL811_HCD is not set
> # CONFIG_USB_R8A66597_HCD is not set
> CONFIG_USB_RENESAS_USBHS_HCD=3Dm
> # CONFIG_USB_HCD_TEST_MODE is not set
> CONFIG_USB_RENESAS_USBHS=3Dm
>=20
> #
> # USB Device Class drivers
> #
> # CONFIG_USB_ACM is not set
> # CONFIG_USB_PRINTER is not set
> # CONFIG_USB_WDM is not set
> # CONFIG_USB_TMC is not set
>=20
> #
> # NOTE: USB_STORAGE depends on SCSI but BLK_DEV_SD may
> #
>=20
> #
> # also be needed; see USB_STORAGE Help for more info
> #
> CONFIG_USB_STORAGE=3Dy
> # CONFIG_USB_STORAGE_DEBUG is not set
> # CONFIG_USB_STORAGE_REALTEK is not set
> # CONFIG_USB_STORAGE_DATAFAB is not set
> # CONFIG_USB_STORAGE_FREECOM is not set
> # CONFIG_USB_STORAGE_ISD200 is not set
> # CONFIG_USB_STORAGE_USBAT is not set
> # CONFIG_USB_STORAGE_SDDR09 is not set
> # CONFIG_USB_STORAGE_SDDR55 is not set
> # CONFIG_USB_STORAGE_JUMPSHOT is not set
> # CONFIG_USB_STORAGE_ALAUDA is not set
> # CONFIG_USB_STORAGE_ONETOUCH is not set
> # CONFIG_USB_STORAGE_KARMA is not set
> # CONFIG_USB_STORAGE_CYPRESS_ATACB is not set
> # CONFIG_USB_STORAGE_ENE_UB6250 is not set
> # CONFIG_USB_UAS is not set
>=20
> #
> # USB Imaging devices
> #
> # CONFIG_USB_MDC800 is not set
> # CONFIG_USB_MICROTEK is not set
> # CONFIG_USBIP_CORE is not set
> # CONFIG_USB_CDNS3 is not set
> # CONFIG_USB_MTU3 is not set
> CONFIG_USB_MUSB_HDRC=3Dy
> # CONFIG_USB_MUSB_HOST is not set
> # CONFIG_USB_MUSB_GADGET is not set
> CONFIG_USB_MUSB_DUAL_ROLE=3Dy
>=20
> #
> # Platform Glue Layer
> #
> CONFIG_USB_MUSB_SUNXI=3Dy
> # CONFIG_USB_MUSB_MEDIATEK is not set
>=20
> #
> # MUSB DMA mode
> #
> # CONFIG_MUSB_PIO_ONLY is not set
> CONFIG_USB_DWC3=3Dy
> # CONFIG_USB_DWC3_ULPI is not set
> # CONFIG_USB_DWC3_HOST is not set
> # CONFIG_USB_DWC3_GADGET is not set
> CONFIG_USB_DWC3_DUAL_ROLE=3Dy
>=20
> #
> # Platform Glue Driver Support
> #
> CONFIG_USB_DWC3_EXYNOS=3Dy
> CONFIG_USB_DWC3_PCI=3Dy
> CONFIG_USB_DWC3_HAPS=3Dy
> CONFIG_USB_DWC3_KEYSTONE=3Dy
> CONFIG_USB_DWC3_MESON_G12A=3Dy
> CONFIG_USB_DWC3_OF_SIMPLE=3Dy
> CONFIG_USB_DWC3_QCOM=3Dy
> CONFIG_USB_DWC2=3Dy
> # CONFIG_USB_DWC2_HOST is not set
>=20
> #
> # Gadget/Dual-role mode requires USB Gadget support to be enabled
> #
> # CONFIG_USB_DWC2_PERIPHERAL is not set
> CONFIG_USB_DWC2_DUAL_ROLE=3Dy
> # CONFIG_USB_DWC2_PCI is not set
> # CONFIG_USB_DWC2_DEBUG is not set
> # CONFIG_USB_DWC2_TRACK_MISSED_SOFS is not set
> CONFIG_USB_CHIPIDEA=3Dy
> CONFIG_USB_CHIPIDEA_UDC=3Dy
> CONFIG_USB_CHIPIDEA_HOST=3Dy
> CONFIG_USB_CHIPIDEA_PCI=3Dy
> CONFIG_USB_CHIPIDEA_MSM=3Dy
> CONFIG_USB_CHIPIDEA_IMX=3Dy
> CONFIG_USB_CHIPIDEA_GENERIC=3Dy
> CONFIG_USB_CHIPIDEA_TEGRA=3Dy
> CONFIG_USB_ISP1760=3Dy
> CONFIG_USB_ISP1760_HCD=3Dy
> CONFIG_USB_ISP1761_UDC=3Dy
> # CONFIG_USB_ISP1760_HOST_ROLE is not set
> # CONFIG_USB_ISP1760_GADGET_ROLE is not set
> CONFIG_USB_ISP1760_DUAL_ROLE=3Dy
>=20
> #
> # USB port drivers
> #
> # CONFIG_USB_SERIAL is not set
>=20
> #
> # USB Miscellaneous drivers
> #
> # CONFIG_USB_EMI62 is not set
> # CONFIG_USB_EMI26 is not set
> # CONFIG_USB_ADUTUX is not set
> # CONFIG_USB_SEVSEG is not set
> # CONFIG_USB_LEGOTOWER is not set
> # CONFIG_USB_LCD is not set
> # CONFIG_USB_CYPRESS_CY7C63 is not set
> # CONFIG_USB_CYTHERM is not set
> # CONFIG_USB_IDMOUSE is not set
> # CONFIG_USB_FTDI_ELAN is not set
> # CONFIG_USB_APPLEDISPLAY is not set
> # CONFIG_APPLE_MFI_FASTCHARGE is not set
> # CONFIG_USB_SISUSBVGA is not set
> # CONFIG_USB_LD is not set
> # CONFIG_USB_TRANCEVIBRATOR is not set
> # CONFIG_USB_IOWARRIOR is not set
> # CONFIG_USB_TEST is not set
> # CONFIG_USB_EHSET_TEST_FIXTURE is not set
> # CONFIG_USB_ISIGHTFW is not set
> # CONFIG_USB_YUREX is not set
> # CONFIG_USB_EZUSB_FX2 is not set
> # CONFIG_USB_HUB_USB251XB is not set
> CONFIG_USB_HSIC_USB3503=3Dy
> # CONFIG_USB_HSIC_USB4604 is not set
> # CONFIG_USB_LINK_LAYER_TEST is not set
> # CONFIG_USB_CHAOSKEY is not set
> CONFIG_BRCM_USB_PINMAP=3Dy
>=20
> #
> # USB Physical Layer drivers
> #
> CONFIG_USB_PHY=3Dy
> CONFIG_NOP_USB_XCEIV=3Dy
> # CONFIG_USB_GPIO_VBUS is not set
> # CONFIG_USB_ISP1301 is not set
> # CONFIG_USB_MXS_PHY is not set
> CONFIG_USB_TEGRA_PHY=3Dy
> CONFIG_USB_ULPI=3Dy
> CONFIG_USB_ULPI_VIEWPORT=3Dy
> # end of USB Physical Layer drivers
>=20
> CONFIG_USB_GADGET=3Dy
> # CONFIG_USB_GADGET_DEBUG is not set
> # CONFIG_USB_GADGET_DEBUG_FILES is not set
> # CONFIG_USB_GADGET_DEBUG_FS is not set
> CONFIG_USB_GADGET_VBUS_DRAW=3D2
> CONFIG_USB_GADGET_STORAGE_NUM_BUFFERS=3D2
>=20
> #
> # USB Peripheral Controller
> #
> # CONFIG_USB_FSL_USB2 is not set
> # CONFIG_USB_FOTG210_UDC is not set
> # CONFIG_USB_GR_UDC is not set
> # CONFIG_USB_R8A66597 is not set
> CONFIG_USB_RENESAS_USBHS_UDC=3Dm
> CONFIG_USB_RENESAS_USB3=3Dm
> # CONFIG_USB_PXA27X is not set
> # CONFIG_USB_MV_UDC is not set
> # CONFIG_USB_MV_U3D is not set
> CONFIG_USB_SNP_CORE=3Dy
> CONFIG_USB_SNP_UDC_PLAT=3Dy
> # CONFIG_USB_M66592 is not set
> CONFIG_USB_BDC_UDC=3Dy
>=20
> #
> # Platform Support
> #
> CONFIG_USB_BDC_PCI=3Dy
> # CONFIG_USB_AMD5536UDC is not set
> # CONFIG_USB_NET2272 is not set
> # CONFIG_USB_NET2280 is not set
> # CONFIG_USB_GOKU is not set
> # CONFIG_USB_EG20T is not set
> # CONFIG_USB_GADGET_XILINX is not set
> # CONFIG_USB_MAX3420_UDC is not set
> CONFIG_USB_TEGRA_XUDC=3Dm
> # CONFIG_USB_DUMMY_HCD is not set
> # end of USB Peripheral Controller
>=20
> # CONFIG_USB_CONFIGFS is not set
>=20
> #
> # USB Gadget precomposed configurations
> #
> # CONFIG_USB_ZERO is not set
> # CONFIG_USB_AUDIO is not set
> # CONFIG_USB_ETH is not set
> # CONFIG_USB_G_NCM is not set
> # CONFIG_USB_GADGETFS is not set
> # CONFIG_USB_FUNCTIONFS is not set
> # CONFIG_USB_MASS_STORAGE is not set
> # CONFIG_USB_G_SERIAL is not set
> # CONFIG_USB_MIDI_GADGET is not set
> # CONFIG_USB_G_PRINTER is not set
> # CONFIG_USB_CDC_COMPOSITE is not set
> # CONFIG_USB_G_ACM_MS is not set
> # CONFIG_USB_G_MULTI is not set
> # CONFIG_USB_G_HID is not set
> # CONFIG_USB_G_DBGP is not set
> # CONFIG_USB_G_WEBCAM is not set
> # CONFIG_USB_RAW_GADGET is not set
> # end of USB Gadget precomposed configurations
>=20
> CONFIG_TYPEC=3Dm
> CONFIG_TYPEC_TCPM=3Dm
> # CONFIG_TYPEC_TCPCI is not set
> CONFIG_TYPEC_FUSB302=3Dm
> # CONFIG_TYPEC_UCSI is not set
> CONFIG_TYPEC_HD3SS3220=3Dm
> # CONFIG_TYPEC_TPS6598X is not set
> # CONFIG_TYPEC_STUSB160X is not set
> # CONFIG_TYPEC_QCOM_PMIC is not set
>=20
> #
> # USB Type-C Multiplexer/DeMultiplexer Switch support
> #
> # CONFIG_TYPEC_MUX_PI3USB30532 is not set
> # end of USB Type-C Multiplexer/DeMultiplexer Switch support
>=20
> #
> # USB Type-C Alternate Mode drivers
> #
> # CONFIG_TYPEC_DP_ALTMODE is not set
> # end of USB Type-C Alternate Mode drivers
>=20
> CONFIG_USB_ROLE_SWITCH=3Dy
> CONFIG_MMC=3Dy
> CONFIG_PWRSEQ_EMMC=3Dy
> # CONFIG_PWRSEQ_SD8787 is not set
> CONFIG_PWRSEQ_SIMPLE=3Dy
> CONFIG_MMC_BLOCK=3Dy
> CONFIG_MMC_BLOCK_MINORS=3D32
> # CONFIG_SDIO_UART is not set
> # CONFIG_MMC_TEST is not set
>=20
> #
> # MMC/SD/SDIO Host Controller Drivers
> #
> # CONFIG_MMC_DEBUG is not set
> CONFIG_MMC_ARMMMCI=3Dy
> CONFIG_MMC_QCOM_DML=3Dy
> CONFIG_MMC_STM32_SDMMC=3Dy
> CONFIG_MMC_SDHCI=3Dy
> CONFIG_MMC_SDHCI_IO_ACCESSORS=3Dy
> # CONFIG_MMC_SDHCI_PCI is not set
> CONFIG_MMC_SDHCI_ACPI=3Dy
> CONFIG_MMC_SDHCI_PLTFM=3Dy
> CONFIG_MMC_SDHCI_OF_ARASAN=3Dy
> # CONFIG_MMC_SDHCI_OF_ASPEED is not set
> # CONFIG_MMC_SDHCI_OF_AT91 is not set
> CONFIG_MMC_SDHCI_OF_ESDHC=3Dy
> # CONFIG_MMC_SDHCI_OF_DWCMSHC is not set
> CONFIG_MMC_SDHCI_CADENCE=3Dy
> CONFIG_MMC_SDHCI_ESDHC_IMX=3Dy
> CONFIG_MMC_SDHCI_TEGRA=3Dy
> # CONFIG_MMC_SDHCI_S3C is not set
> # CONFIG_MMC_SDHCI_PXAV3 is not set
> CONFIG_MMC_SDHCI_F_SDH30=3Dy
> # CONFIG_MMC_SDHCI_MILBEAUT is not set
> CONFIG_MMC_SDHCI_IPROC=3Dy
> CONFIG_MMC_MESON_GX=3Dy
> # CONFIG_MMC_MESON_MX_SDIO is not set
> CONFIG_MMC_SDHCI_MSM=3Dy
> # CONFIG_MMC_MXC is not set
> # CONFIG_MMC_TIFM_SD is not set
> CONFIG_MMC_SPI=3Dy
> # CONFIG_MMC_SDHCI_SPRD is not set
> CONFIG_MMC_TMIO_CORE=3Dy
> CONFIG_MMC_SDHI=3Dy
> # CONFIG_MMC_SDHI_SYS_DMAC is not set
> CONFIG_MMC_SDHI_INTERNAL_DMAC=3Dy
> CONFIG_MMC_UNIPHIER=3Dy
> # CONFIG_MMC_CB710 is not set
> # CONFIG_MMC_VIA_SDMMC is not set
> CONFIG_MMC_DW=3Dy
> CONFIG_MMC_DW_PLTFM=3Dy
> # CONFIG_MMC_DW_BLUEFIELD is not set
> CONFIG_MMC_DW_EXYNOS=3Dy
> CONFIG_MMC_DW_HI3798CV200=3Dy
> CONFIG_MMC_DW_K3=3Dy
> # CONFIG_MMC_DW_PCI is not set
> CONFIG_MMC_DW_ROCKCHIP=3Dy
> # CONFIG_MMC_DW_ZX is not set
> # CONFIG_MMC_SH_MMCIF is not set
> # CONFIG_MMC_VUB300 is not set
> # CONFIG_MMC_USHC is not set
> # CONFIG_MMC_USDHI6ROL0 is not set
> CONFIG_MMC_SUNXI=3Dy
> CONFIG_MMC_CQHCI=3Dy
> # CONFIG_MMC_HSQ is not set
> # CONFIG_MMC_TOSHIBA_PCI is not set
> CONFIG_MMC_BCM2835=3Dy
> # CONFIG_MMC_MTK is not set
> CONFIG_MMC_SDHCI_BRCMSTB=3Dy
> CONFIG_MMC_SDHCI_XENON=3Dy
> # CONFIG_MMC_SDHCI_OMAP is not set
> # CONFIG_MMC_SDHCI_AM654 is not set
> CONFIG_MMC_OWL=3Dy
> # CONFIG_MEMSTICK is not set
> CONFIG_NEW_LEDS=3Dy
> CONFIG_LEDS_CLASS=3Dy
> # CONFIG_LEDS_CLASS_FLASH is not set
> # CONFIG_LEDS_CLASS_MULTICOLOR is not set
> # CONFIG_LEDS_BRIGHTNESS_HW_CHANGED is not set
>=20
> #
> # LED drivers
> #
> # CONFIG_LEDS_AN30259A is not set
> # CONFIG_LEDS_AW2013 is not set
> # CONFIG_LEDS_BCM6328 is not set
> # CONFIG_LEDS_BCM6358 is not set
> # CONFIG_LEDS_CR0014114 is not set
> # CONFIG_LEDS_EL15203000 is not set
> # CONFIG_LEDS_LM3530 is not set
> # CONFIG_LEDS_LM3532 is not set
> # CONFIG_LEDS_LM3642 is not set
> # CONFIG_LEDS_LM3692X is not set
> # CONFIG_LEDS_PCA9532 is not set
> CONFIG_LEDS_GPIO=3Dy
> # CONFIG_LEDS_LP3944 is not set
> # CONFIG_LEDS_LP3952 is not set
> # CONFIG_LEDS_LP50XX is not set
> # CONFIG_LEDS_LP55XX_COMMON is not set
> # CONFIG_LEDS_LP8860 is not set
> # CONFIG_LEDS_PCA955X is not set
> # CONFIG_LEDS_PCA963X is not set
> # CONFIG_LEDS_DAC124S085 is not set
> CONFIG_LEDS_PWM=3Dy
> # CONFIG_LEDS_REGULATOR is not set
> # CONFIG_LEDS_BD2802 is not set
> # CONFIG_LEDS_LT3593 is not set
> # CONFIG_LEDS_TCA6507 is not set
> # CONFIG_LEDS_TLC591XX is not set
> # CONFIG_LEDS_LM355x is not set
> # CONFIG_LEDS_IS31FL319X is not set
> # CONFIG_LEDS_IS31FL32XX is not set
>=20
> #
> # LED driver for blink(1) USB RGB LED is under Special HID drivers (HID_T=
HINGM)
> #
> # CONFIG_LEDS_BLINKM is not set
> CONFIG_LEDS_SYSCON=3Dy
> # CONFIG_LEDS_MLXREG is not set
> # CONFIG_LEDS_USER is not set
> # CONFIG_LEDS_SPI_BYTE is not set
> # CONFIG_LEDS_TI_LMU_COMMON is not set
>=20
> #
> # LED Triggers
> #
> CONFIG_LEDS_TRIGGERS=3Dy
> CONFIG_LEDS_TRIGGER_TIMER=3Dy
> # CONFIG_LEDS_TRIGGER_ONESHOT is not set
> CONFIG_LEDS_TRIGGER_DISK=3Dy
> # CONFIG_LEDS_TRIGGER_MTD is not set
> CONFIG_LEDS_TRIGGER_HEARTBEAT=3Dy
> # CONFIG_LEDS_TRIGGER_BACKLIGHT is not set
> CONFIG_LEDS_TRIGGER_CPU=3Dy
> # CONFIG_LEDS_TRIGGER_ACTIVITY is not set
> # CONFIG_LEDS_TRIGGER_GPIO is not set
> CONFIG_LEDS_TRIGGER_DEFAULT_ON=3Dy
>=20
> #
> # iptables trigger is under Netfilter config (LED target)
> #
> # CONFIG_LEDS_TRIGGER_TRANSIENT is not set
> # CONFIG_LEDS_TRIGGER_CAMERA is not set
> CONFIG_LEDS_TRIGGER_PANIC=3Dy
> # CONFIG_LEDS_TRIGGER_NETDEV is not set
> # CONFIG_LEDS_TRIGGER_PATTERN is not set
> # CONFIG_LEDS_TRIGGER_AUDIO is not set
> # CONFIG_ACCESSIBILITY is not set
> # CONFIG_INFINIBAND is not set
> CONFIG_EDAC_SUPPORT=3Dy
> CONFIG_EDAC=3Dy
> CONFIG_EDAC_LEGACY_SYSFS=3Dy
> # CONFIG_EDAC_DEBUG is not set
> CONFIG_EDAC_GHES=3Dy
> # CONFIG_EDAC_AL_MC is not set
> # CONFIG_EDAC_LAYERSCAPE is not set
> # CONFIG_EDAC_THUNDERX is not set
> # CONFIG_EDAC_ALTERA is not set
> # CONFIG_EDAC_SYNOPSYS is not set
> # CONFIG_EDAC_XGENE is not set
> # CONFIG_EDAC_DMC520 is not set
> CONFIG_RTC_LIB=3Dy
> CONFIG_RTC_CLASS=3Dy
> CONFIG_RTC_HCTOSYS=3Dy
> CONFIG_RTC_HCTOSYS_DEVICE=3D"rtc0"
> CONFIG_RTC_SYSTOHC=3Dy
> CONFIG_RTC_SYSTOHC_DEVICE=3D"rtc0"
> # CONFIG_RTC_DEBUG is not set
> CONFIG_RTC_NVMEM=3Dy
>=20
> #
> # RTC interfaces
> #
> CONFIG_RTC_INTF_SYSFS=3Dy
> CONFIG_RTC_INTF_PROC=3Dy
> CONFIG_RTC_INTF_DEV=3Dy
> # CONFIG_RTC_INTF_DEV_UIE_EMUL is not set
> # CONFIG_RTC_DRV_TEST is not set
>=20
> #
> # I2C RTC drivers
> #
> # CONFIG_RTC_DRV_ABB5ZES3 is not set
> # CONFIG_RTC_DRV_ABEOZ9 is not set
> # CONFIG_RTC_DRV_ABX80X is not set
> CONFIG_RTC_DRV_BRCMSTB=3Dy
> CONFIG_RTC_DRV_DS1307=3Dm
> # CONFIG_RTC_DRV_DS1307_CENTURY is not set
> # CONFIG_RTC_DRV_DS1374 is not set
> # CONFIG_RTC_DRV_DS1672 is not set
> # CONFIG_RTC_DRV_HYM8563 is not set
> # CONFIG_RTC_DRV_MAX6900 is not set
> CONFIG_RTC_DRV_MAX77686=3Dy
> CONFIG_RTC_DRV_RK808=3Dm
> # CONFIG_RTC_DRV_RS5C372 is not set
> # CONFIG_RTC_DRV_ISL1208 is not set
> # CONFIG_RTC_DRV_ISL12022 is not set
> # CONFIG_RTC_DRV_ISL12026 is not set
> # CONFIG_RTC_DRV_X1205 is not set
> # CONFIG_RTC_DRV_PCF8523 is not set
> # CONFIG_RTC_DRV_PCF85063 is not set
> CONFIG_RTC_DRV_PCF85363=3Dm
> # CONFIG_RTC_DRV_PCF8563 is not set
> # CONFIG_RTC_DRV_PCF8583 is not set
> # CONFIG_RTC_DRV_M41T80 is not set
> # CONFIG_RTC_DRV_BQ32K is not set
> # CONFIG_RTC_DRV_S35390A is not set
> # CONFIG_RTC_DRV_FM3130 is not set
> # CONFIG_RTC_DRV_RX8010 is not set
> CONFIG_RTC_DRV_RX8581=3Dm
> # CONFIG_RTC_DRV_RX8025 is not set
> # CONFIG_RTC_DRV_EM3027 is not set
> # CONFIG_RTC_DRV_RV3028 is not set
> # CONFIG_RTC_DRV_RV3032 is not set
> # CONFIG_RTC_DRV_RV8803 is not set
> CONFIG_RTC_DRV_S5M=3Dy
> # CONFIG_RTC_DRV_SD3078 is not set
>=20
> #
> # SPI RTC drivers
> #
> # CONFIG_RTC_DRV_M41T93 is not set
> # CONFIG_RTC_DRV_M41T94 is not set
> # CONFIG_RTC_DRV_DS1302 is not set
> # CONFIG_RTC_DRV_DS1305 is not set
> # CONFIG_RTC_DRV_DS1343 is not set
> # CONFIG_RTC_DRV_DS1347 is not set
> # CONFIG_RTC_DRV_DS1390 is not set
> # CONFIG_RTC_DRV_MAX6916 is not set
> # CONFIG_RTC_DRV_R9701 is not set
> # CONFIG_RTC_DRV_RX4581 is not set
> # CONFIG_RTC_DRV_RX6110 is not set
> # CONFIG_RTC_DRV_RS5C348 is not set
> # CONFIG_RTC_DRV_MAX6902 is not set
> # CONFIG_RTC_DRV_PCF2123 is not set
> # CONFIG_RTC_DRV_MCP795 is not set
> CONFIG_RTC_I2C_AND_SPI=3Dy
>=20
> #
> # SPI and I2C RTC drivers
> #
> CONFIG_RTC_DRV_DS3232=3Dy
> CONFIG_RTC_DRV_DS3232_HWMON=3Dy
> CONFIG_RTC_DRV_PCF2127=3Dm
> # CONFIG_RTC_DRV_RV3029C2 is not set
>=20
> #
> # Platform RTC drivers
> #
> # CONFIG_RTC_DRV_DS1286 is not set
> # CONFIG_RTC_DRV_DS1511 is not set
> # CONFIG_RTC_DRV_DS1553 is not set
> # CONFIG_RTC_DRV_DS1685_FAMILY is not set
> # CONFIG_RTC_DRV_DS1742 is not set
> # CONFIG_RTC_DRV_DS2404 is not set
> CONFIG_RTC_DRV_EFI=3Dy
> # CONFIG_RTC_DRV_STK17TA8 is not set
> # CONFIG_RTC_DRV_M48T86 is not set
> # CONFIG_RTC_DRV_M48T35 is not set
> # CONFIG_RTC_DRV_M48T59 is not set
> # CONFIG_RTC_DRV_MSM6242 is not set
> # CONFIG_RTC_DRV_BQ4802 is not set
> # CONFIG_RTC_DRV_RP5C01 is not set
> # CONFIG_RTC_DRV_V3020 is not set
> # CONFIG_RTC_DRV_ZYNQMP is not set
> CONFIG_RTC_DRV_CROS_EC=3Dy
>=20
> #
> # on-CPU RTC drivers
> #
> # CONFIG_RTC_DRV_IMXDI is not set
> # CONFIG_RTC_DRV_FSL_FTM_ALARM is not set
> CONFIG_RTC_DRV_MESON_VRTC=3Dm
> CONFIG_HAVE_S3C_RTC=3Dy
> CONFIG_RTC_DRV_S3C=3Dy
> # CONFIG_RTC_DRV_SH is not set
> # CONFIG_RTC_DRV_PL030 is not set
> CONFIG_RTC_DRV_PL031=3Dy
> CONFIG_RTC_DRV_SUN6I=3Dy
> # CONFIG_RTC_DRV_MV is not set
> CONFIG_RTC_DRV_ARMADA38X=3Dy
> # CONFIG_RTC_DRV_CADENCE is not set
> # CONFIG_RTC_DRV_FTRTC010 is not set
> # CONFIG_RTC_DRV_PM8XXX is not set
> CONFIG_RTC_DRV_TEGRA=3Dy
> # CONFIG_RTC_DRV_MXC is not set
> # CONFIG_RTC_DRV_MXC_V2 is not set
> CONFIG_RTC_DRV_SNVS=3Dm
> CONFIG_RTC_DRV_IMX_SC=3Dm
> # CONFIG_RTC_DRV_MT2712 is not set
> # CONFIG_RTC_DRV_MT7622 is not set
> CONFIG_RTC_DRV_XGENE=3Dy
> # CONFIG_RTC_DRV_R7301 is not set
>=20
> #
> # HID Sensor RTC drivers
> #
> CONFIG_DMADEVICES=3Dy
> # CONFIG_DMADEVICES_DEBUG is not set
>=20
> #
> # DMA Devices
> #
> CONFIG_ASYNC_TX_ENABLE_CHANNEL_SWITCH=3Dy
> CONFIG_DMA_ENGINE=3Dy
> CONFIG_DMA_VIRTUAL_CHANNELS=3Dy
> CONFIG_DMA_ACPI=3Dy
> CONFIG_DMA_OF=3Dy
> # CONFIG_ALTERA_MSGDMA is not set
> # CONFIG_AMBA_PL08X is not set
> # CONFIG_AXI_DMAC is not set
> CONFIG_BCM_SBA_RAID=3Dm
> CONFIG_DMA_BCM2835=3Dy
> CONFIG_DMA_SUN6I=3Dm
> # CONFIG_DW_AXI_DMAC is not set
> CONFIG_FSL_EDMA=3Dy
> # CONFIG_FSL_QDMA is not set
> # CONFIG_HISI_DMA is not set
> # CONFIG_IMX_DMA is not set
> CONFIG_IMX_SDMA=3Dy
> # CONFIG_INTEL_IDMA64 is not set
> CONFIG_K3_DMA=3Dy
> CONFIG_MV_XOR=3Dy
> CONFIG_MV_XOR_V2=3Dy
> # CONFIG_MXS_DMA is not set
> CONFIG_MX3_IPU=3Dy
> CONFIG_MX3_IPU_IRQS=3D4
> CONFIG_OWL_DMA=3Dy
> CONFIG_PL330_DMA=3Dy
> # CONFIG_PLX_DMA is not set
> # CONFIG_SPRD_DMA is not set
> CONFIG_TEGRA20_APB_DMA=3Dy
> # CONFIG_TEGRA210_ADMA is not set
> # CONFIG_UNIPHIER_MDMAC is not set
> # CONFIG_UNIPHIER_XDMAC is not set
> # CONFIG_XGENE_DMA is not set
> # CONFIG_XILINX_DMA is not set
> # CONFIG_XILINX_ZYNQMP_DMA is not set
> # CONFIG_XILINX_ZYNQMP_DPDMA is not set
> # CONFIG_ZX_DMA is not set
> # CONFIG_MTK_HSDMA is not set
> # CONFIG_MTK_CQDMA is not set
> # CONFIG_MTK_UART_APDMA is not set
> CONFIG_QCOM_BAM_DMA=3Dy
> CONFIG_QCOM_HIDMA_MGMT=3Dy
> CONFIG_QCOM_HIDMA=3Dy
> # CONFIG_DW_DMAC is not set
> # CONFIG_DW_DMAC_PCI is not set
> # CONFIG_DW_EDMA is not set
> # CONFIG_DW_EDMA_PCIE is not set
> # CONFIG_SF_PDMA is not set
> CONFIG_RENESAS_DMA=3Dy
> CONFIG_RCAR_DMAC=3Dy
> CONFIG_RENESAS_USB_DMAC=3Dm
> CONFIG_TI_K3_UDMA=3Dy
> CONFIG_TI_K3_UDMA_GLUE_LAYER=3Dy
> CONFIG_TI_K3_PSIL=3Dy
> # CONFIG_FSL_DPAA2_QDMA is not set
>=20
> #
> # DMA Clients
> #
> # CONFIG_ASYNC_TX_DMA is not set
> # CONFIG_DMATEST is not set
> CONFIG_DMA_ENGINE_RAID=3Dy
>=20
> #
> # DMABUF options
> #
> CONFIG_SYNC_FILE=3Dy
> # CONFIG_SW_SYNC is not set
> # CONFIG_UDMABUF is not set
> # CONFIG_DMABUF_MOVE_NOTIFY is not set
> # CONFIG_DMABUF_SELFTESTS is not set
> # CONFIG_DMABUF_HEAPS is not set
> # end of DMABUF options
>=20
> # CONFIG_AUXDISPLAY is not set
> # CONFIG_UIO is not set
> CONFIG_VFIO_IOMMU_TYPE1=3Dy
> CONFIG_VFIO_VIRQFD=3Dy
> CONFIG_VFIO=3Dy
> # CONFIG_VFIO_NOIOMMU is not set
> CONFIG_VFIO_PCI=3Dy
> CONFIG_VFIO_PCI_MMAP=3Dy
> CONFIG_VFIO_PCI_INTX=3Dy
> # CONFIG_VFIO_PLATFORM is not set
> # CONFIG_VFIO_MDEV is not set
> # CONFIG_VFIO_FSL_MC is not set
> # CONFIG_VIRT_DRIVERS is not set
> CONFIG_VIRTIO=3Dy
> CONFIG_VIRTIO_MENU=3Dy
> CONFIG_VIRTIO_PCI=3Dy
> CONFIG_VIRTIO_PCI_LEGACY=3Dy
> CONFIG_VIRTIO_BALLOON=3Dy
> CONFIG_VIRTIO_INPUT=3Dy
> CONFIG_VIRTIO_MMIO=3Dy
> # CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES is not set
> CONFIG_VIRTIO_DMA_SHARED_BUFFER=3Dm
> # CONFIG_VDPA is not set
> CONFIG_VHOST_MENU=3Dy
> # CONFIG_VHOST_NET is not set
> # CONFIG_VHOST_CROSS_ENDIAN_LEGACY is not set
>=20
> #
> # Microsoft Hyper-V guest support
> #
> # end of Microsoft Hyper-V guest support
>=20
> #
> # Xen driver support
> #
> CONFIG_XEN_BALLOON=3Dy
> CONFIG_XEN_SCRUB_PAGES_DEFAULT=3Dy
> CONFIG_XEN_DEV_EVTCHN=3Dy
> CONFIG_XEN_BACKEND=3Dy
> CONFIG_XENFS=3Dy
> CONFIG_XEN_COMPAT_XENFS=3Dy
> CONFIG_XEN_SYS_HYPERVISOR=3Dy
> CONFIG_XEN_XENBUS_FRONTEND=3Dy
> CONFIG_XEN_GNTDEV=3Dy
> CONFIG_XEN_GRANT_DEV_ALLOC=3Dy
> # CONFIG_XEN_GRANT_DMA_ALLOC is not set
> CONFIG_SWIOTLB_XEN=3Dy
> # CONFIG_XEN_PVCALLS_FRONTEND is not set
> # CONFIG_XEN_PVCALLS_BACKEND is not set
> CONFIG_XEN_PRIVCMD=3Dy
> CONFIG_XEN_EFI=3Dy
> CONFIG_XEN_AUTO_XLATE=3Dy
> # end of Xen driver support
>=20
> # CONFIG_GREYBUS is not set
> # CONFIG_STAGING is not set
> # CONFIG_GOLDFISH is not set
> CONFIG_CHROME_PLATFORMS=3Dy
> # CONFIG_CHROMEOS_TBMC is not set
> CONFIG_CROS_EC=3Dy
> CONFIG_CROS_EC_I2C=3Dy
> # CONFIG_CROS_EC_RPMSG is not set
> CONFIG_CROS_EC_SPI=3Dy
> CONFIG_CROS_EC_PROTO=3Dy
> # CONFIG_CROS_KBD_LED_BACKLIGHT is not set
> CONFIG_CROS_EC_CHARDEV=3Dy
> CONFIG_CROS_EC_LIGHTBAR=3Dy
> CONFIG_CROS_EC_VBC=3Dy
> CONFIG_CROS_EC_DEBUGFS=3Dy
> CONFIG_CROS_EC_SENSORHUB=3Dy
> CONFIG_CROS_EC_SYSFS=3Dy
> CONFIG_CROS_EC_TYPEC=3Dm
> CONFIG_CROS_USBPD_NOTIFY=3Dy
> # CONFIG_MELLANOX_PLATFORM is not set
> CONFIG_SURFACE_PLATFORMS=3Dy
> # CONFIG_SURFACE_3_BUTTON is not set
> # CONFIG_SURFACE_3_POWER_OPREGION is not set
> # CONFIG_SURFACE_PRO3_BUTTON is not set
> CONFIG_HAVE_CLK=3Dy
> CONFIG_CLKDEV_LOOKUP=3Dy
> CONFIG_HAVE_CLK_PREPARE=3Dy
> CONFIG_COMMON_CLK=3Dy
>=20
> #
> # Clock driver for ARM Reference designs
> #
> # CONFIG_ICST is not set
> # CONFIG_CLK_SP810 is not set
> CONFIG_CLK_VEXPRESS_OSC=3Dy
> # end of Clock driver for ARM Reference designs
>=20
> # CONFIG_COMMON_CLK_MAX77686 is not set
> # CONFIG_COMMON_CLK_MAX9485 is not set
> CONFIG_COMMON_CLK_RK808=3Dy
> CONFIG_COMMON_CLK_HI655X=3Dy
> CONFIG_COMMON_CLK_SCPI=3Dy
> # CONFIG_COMMON_CLK_SI5341 is not set
> # CONFIG_COMMON_CLK_SI5351 is not set
> # CONFIG_COMMON_CLK_SI514 is not set
> # CONFIG_COMMON_CLK_SI544 is not set
> # CONFIG_COMMON_CLK_SI570 is not set
> # CONFIG_COMMON_CLK_CDCE706 is not set
> # CONFIG_COMMON_CLK_CDCE925 is not set
> CONFIG_COMMON_CLK_CS2000_CP=3Dy
> # CONFIG_COMMON_CLK_FSL_SAI is not set
> CONFIG_COMMON_CLK_S2MPS11=3Dy
> CONFIG_CLK_QORIQ=3Dy
> CONFIG_CLK_LS1028A_PLLDIG=3Dy
> CONFIG_COMMON_CLK_XGENE=3Dy
> CONFIG_COMMON_CLK_PWM=3Dy
> CONFIG_COMMON_CLK_VC5=3Dy
> # CONFIG_COMMON_CLK_BD718XX is not set
> # CONFIG_COMMON_CLK_FIXED_MMIO is not set
> CONFIG_CLK_ACTIONS=3Dy
> CONFIG_CLK_OWL_S500=3Dy
> CONFIG_CLK_OWL_S700=3Dy
> CONFIG_CLK_OWL_S900=3Dy
> CONFIG_CLK_BCM2711_DVP=3Dy
> CONFIG_CLK_BCM2835=3Dy
> CONFIG_COMMON_CLK_IPROC=3Dy
> CONFIG_CLK_BCM_NS2=3Dy
> CONFIG_CLK_BCM_SR=3Dy
> CONFIG_CLK_RASPBERRYPI=3Dm
> CONFIG_COMMON_CLK_HI3516CV300=3Dy
> CONFIG_COMMON_CLK_HI3519=3Dy
> CONFIG_COMMON_CLK_HI3660=3Dy
> CONFIG_COMMON_CLK_HI3670=3Dy
> CONFIG_COMMON_CLK_HI3798CV200=3Dy
> CONFIG_COMMON_CLK_HI6220=3Dy
> CONFIG_RESET_HISI=3Dy
> CONFIG_STUB_CLK_HI6220=3Dy
> CONFIG_STUB_CLK_HI3660=3Dy
> CONFIG_MXC_CLK=3Dy
> CONFIG_MXC_CLK_SCU=3Dy
> CONFIG_CLK_IMX8MM=3Dy
> CONFIG_CLK_IMX8MN=3Dy
> CONFIG_CLK_IMX8MP=3Dy
> CONFIG_CLK_IMX8MQ=3Dy
> CONFIG_CLK_IMX8QXP=3Dy
> CONFIG_TI_SCI_CLK=3Dy
> # CONFIG_TI_SCI_CLK_PROBE_FROM_FW is not set
> CONFIG_TI_SYSCON_CLK=3Dy
>=20
> #
> # Clock driver for MediaTek SoC
> #
> CONFIG_COMMON_CLK_MEDIATEK=3Dy
> CONFIG_COMMON_CLK_MT2712=3Dy
> # CONFIG_COMMON_CLK_MT2712_BDPSYS is not set
> # CONFIG_COMMON_CLK_MT2712_IMGSYS is not set
> # CONFIG_COMMON_CLK_MT2712_JPGDECSYS is not set
> # CONFIG_COMMON_CLK_MT2712_MFGCFG is not set
> # CONFIG_COMMON_CLK_MT2712_MMSYS is not set
> # CONFIG_COMMON_CLK_MT2712_VDECSYS is not set
> # CONFIG_COMMON_CLK_MT2712_VENCSYS is not set
> CONFIG_COMMON_CLK_MT6765=3Dy
> # CONFIG_COMMON_CLK_MT6765_AUDIOSYS is not set
> # CONFIG_COMMON_CLK_MT6765_CAMSYS is not set
> # CONFIG_COMMON_CLK_MT6765_GCESYS is not set
> # CONFIG_COMMON_CLK_MT6765_MMSYS is not set
> # CONFIG_COMMON_CLK_MT6765_IMGSYS is not set
> # CONFIG_COMMON_CLK_MT6765_VCODECSYS is not set
> # CONFIG_COMMON_CLK_MT6765_MFGSYS is not set
> # CONFIG_COMMON_CLK_MT6765_MIPI0ASYS is not set
> # CONFIG_COMMON_CLK_MT6765_MIPI0BSYS is not set
> # CONFIG_COMMON_CLK_MT6765_MIPI1ASYS is not set
> # CONFIG_COMMON_CLK_MT6765_MIPI1BSYS is not set
> # CONFIG_COMMON_CLK_MT6765_MIPI2ASYS is not set
> # CONFIG_COMMON_CLK_MT6765_MIPI2BSYS is not set
> CONFIG_COMMON_CLK_MT6779=3Dy
> # CONFIG_COMMON_CLK_MT6779_MMSYS is not set
> # CONFIG_COMMON_CLK_MT6779_IMGSYS is not set
> # CONFIG_COMMON_CLK_MT6779_IPESYS is not set
> # CONFIG_COMMON_CLK_MT6779_CAMSYS is not set
> # CONFIG_COMMON_CLK_MT6779_VDECSYS is not set
> # CONFIG_COMMON_CLK_MT6779_VENCSYS is not set
> # CONFIG_COMMON_CLK_MT6779_MFGCFG is not set
> # CONFIG_COMMON_CLK_MT6779_AUDSYS is not set
> CONFIG_COMMON_CLK_MT6797=3Dy
> # CONFIG_COMMON_CLK_MT6797_MMSYS is not set
> # CONFIG_COMMON_CLK_MT6797_IMGSYS is not set
> # CONFIG_COMMON_CLK_MT6797_VDECSYS is not set
> # CONFIG_COMMON_CLK_MT6797_VENCSYS is not set
> CONFIG_COMMON_CLK_MT7622=3Dy
> # CONFIG_COMMON_CLK_MT7622_ETHSYS is not set
> # CONFIG_COMMON_CLK_MT7622_HIFSYS is not set
> # CONFIG_COMMON_CLK_MT7622_AUDSYS is not set
> CONFIG_COMMON_CLK_MT8167=3Dy
> CONFIG_COMMON_CLK_MT8167_AUDSYS=3Dy
> CONFIG_COMMON_CLK_MT8167_IMGSYS=3Dy
> CONFIG_COMMON_CLK_MT8167_MFGCFG=3Dy
> CONFIG_COMMON_CLK_MT8167_MMSYS=3Dy
> CONFIG_COMMON_CLK_MT8167_VDECSYS=3Dy
> CONFIG_COMMON_CLK_MT8173=3Dy
> CONFIG_COMMON_CLK_MT8173_MMSYS=3Dy
> CONFIG_COMMON_CLK_MT8183=3Dy
> # CONFIG_COMMON_CLK_MT8183_AUDIOSYS is not set
> # CONFIG_COMMON_CLK_MT8183_CAMSYS is not set
> # CONFIG_COMMON_CLK_MT8183_IMGSYS is not set
> # CONFIG_COMMON_CLK_MT8183_IPU_CORE0 is not set
> # CONFIG_COMMON_CLK_MT8183_IPU_CORE1 is not set
> # CONFIG_COMMON_CLK_MT8183_IPU_ADL is not set
> # CONFIG_COMMON_CLK_MT8183_IPU_CONN is not set
> # CONFIG_COMMON_CLK_MT8183_MFGCFG is not set
> # CONFIG_COMMON_CLK_MT8183_MMSYS is not set
> # CONFIG_COMMON_CLK_MT8183_VDECSYS is not set
> # CONFIG_COMMON_CLK_MT8183_VENCSYS is not set
> CONFIG_COMMON_CLK_MT8516=3Dy
> # CONFIG_COMMON_CLK_MT8516_AUDSYS is not set
> # end of Clock driver for MediaTek SoC
>=20
> #
> # Clock support for Amlogic platforms
> #
> CONFIG_COMMON_CLK_MESON_REGMAP=3Dy
> CONFIG_COMMON_CLK_MESON_DUALDIV=3Dy
> CONFIG_COMMON_CLK_MESON_MPLL=3Dy
> CONFIG_COMMON_CLK_MESON_PHASE=3Dm
> CONFIG_COMMON_CLK_MESON_PLL=3Dy
> CONFIG_COMMON_CLK_MESON_SCLK_DIV=3Dm
> CONFIG_COMMON_CLK_MESON_VID_PLL_DIV=3Dy
> CONFIG_COMMON_CLK_MESON_AO_CLKC=3Dy
> CONFIG_COMMON_CLK_MESON_EE_CLKC=3Dy
> CONFIG_COMMON_CLK_MESON_CPU_DYNDIV=3Dy
> CONFIG_COMMON_CLK_GXBB=3Dy
> CONFIG_COMMON_CLK_AXG=3Dy
> CONFIG_COMMON_CLK_AXG_AUDIO=3Dm
> CONFIG_COMMON_CLK_G12A=3Dy
> # end of Clock support for Amlogic platforms
>=20
> CONFIG_ARMADA_AP_CP_HELPER=3Dy
> CONFIG_ARMADA_37XX_CLK=3Dy
> CONFIG_ARMADA_AP806_SYSCON=3Dy
> CONFIG_ARMADA_CP110_SYSCON=3Dy
> CONFIG_QCOM_GDSC=3Dy
> CONFIG_QCOM_RPMCC=3Dy
> CONFIG_COMMON_CLK_QCOM=3Dy
> CONFIG_QCOM_A53PLL=3Dy
> CONFIG_QCOM_CLK_APCS_MSM8916=3Dy
> # CONFIG_QCOM_CLK_APCC_MSM8996 is not set
> CONFIG_QCOM_CLK_SMD_RPM=3Dy
> CONFIG_QCOM_CLK_RPMH=3Dy
> # CONFIG_APQ_GCC_8084 is not set
> # CONFIG_APQ_MMCC_8084 is not set
> # CONFIG_IPQ_APSS_PLL is not set
> # CONFIG_IPQ_APSS_6018 is not set
> # CONFIG_IPQ_GCC_4019 is not set
> CONFIG_IPQ_GCC_6018=3Dy
> # CONFIG_IPQ_GCC_806X is not set
> # CONFIG_IPQ_LCC_806X is not set
> CONFIG_IPQ_GCC_8074=3Dy
> # CONFIG_MSM_GCC_8660 is not set
> CONFIG_MSM_GCC_8916=3Dy
> # CONFIG_MSM_GCC_8939 is not set
> # CONFIG_MSM_GCC_8960 is not set
> # CONFIG_MSM_LCC_8960 is not set
> # CONFIG_MDM_GCC_9615 is not set
> # CONFIG_MDM_LCC_9615 is not set
> # CONFIG_MSM_MMCC_8960 is not set
> # CONFIG_MSM_GCC_8974 is not set
> # CONFIG_MSM_MMCC_8974 is not set
> CONFIG_MSM_GCC_8994=3Dy
> CONFIG_MSM_GCC_8996=3Dy
> CONFIG_MSM_MMCC_8996=3Dy
> CONFIG_MSM_GCC_8998=3Dy
> # CONFIG_MSM_GPUCC_8998 is not set
> # CONFIG_MSM_MMCC_8998 is not set
> CONFIG_QCS_GCC_404=3Dy
> # CONFIG_SC_CAMCC_7180 is not set
> # CONFIG_SC_DISPCC_7180 is not set
> CONFIG_SC_GCC_7180=3Dy
> # CONFIG_SC_LPASS_CORECC_7180 is not set
> # CONFIG_SC_GPUCC_7180 is not set
> # CONFIG_SC_MSS_7180 is not set
> # CONFIG_SC_VIDEOCC_7180 is not set
> CONFIG_SDM_CAMCC_845=3Dm
> # CONFIG_SDM_GCC_660 is not set
> # CONFIG_QCS_TURING_404 is not set
> # CONFIG_QCS_Q6SSTOP_404 is not set
> CONFIG_SDM_GCC_845=3Dy
> CONFIG_SDM_GPUCC_845=3Dy
> # CONFIG_SDM_VIDEOCC_845 is not set
> CONFIG_SDM_DISPCC_845=3Dy
> # CONFIG_SDM_LPASSCC_845 is not set
> # CONFIG_SM_DISPCC_8250 is not set
> CONFIG_SM_GCC_8150=3Dy
> CONFIG_SM_GCC_8250=3Dy
> # CONFIG_SM_GPUCC_8150 is not set
> # CONFIG_SM_GPUCC_8250 is not set
> # CONFIG_SM_VIDEOCC_8150 is not set
> # CONFIG_SM_VIDEOCC_8250 is not set
> # CONFIG_SPMI_PMIC_CLKDIV is not set
> CONFIG_QCOM_HFPLL=3Dy
> # CONFIG_KPSS_XCC is not set
> # CONFIG_CLK_GFM_LPASS_SM8250 is not set
> CONFIG_CLK_RENESAS=3Dy
> CONFIG_CLK_R8A774A1=3Dy
> CONFIG_CLK_R8A774B1=3Dy
> CONFIG_CLK_R8A774C0=3Dy
> CONFIG_CLK_R8A7795=3Dy
> CONFIG_CLK_R8A77960=3Dy
> CONFIG_CLK_R8A77961=3Dy
> CONFIG_CLK_R8A77965=3Dy
> CONFIG_CLK_R8A77970=3Dy
> CONFIG_CLK_R8A77980=3Dy
> CONFIG_CLK_R8A77990=3Dy
> CONFIG_CLK_R8A77995=3Dy
> # CONFIG_CLK_R9A06G032 is not set
> CONFIG_CLK_RCAR_GEN3_CPG=3Dy
> # CONFIG_CLK_RCAR_USB2_CLOCK_SEL is not set
> CONFIG_CLK_RENESAS_CPG_MSSR=3Dy
> CONFIG_CLK_RENESAS_DIV6=3Dy
> CONFIG_COMMON_CLK_ROCKCHIP=3Dy
> CONFIG_CLK_PX30=3Dy
> CONFIG_CLK_RK3308=3Dy
> CONFIG_CLK_RK3328=3Dy
> CONFIG_CLK_RK3368=3Dy
> CONFIG_CLK_RK3399=3Dy
> CONFIG_COMMON_CLK_SAMSUNG=3Dy
> CONFIG_EXYNOS_ARM64_COMMON_CLK=3Dy
> CONFIG_EXYNOS_AUDSS_CLK_CON=3Dy
> CONFIG_SPRD_COMMON_CLK=3Dy
> CONFIG_SPRD_SC9860_CLK=3Dy
> CONFIG_SPRD_SC9863A_CLK=3Dy
> CONFIG_CLK_SUNXI=3Dy
> CONFIG_CLK_SUNXI_CLOCKS=3Dy
> CONFIG_CLK_SUNXI_PRCM_SUN6I=3Dy
> CONFIG_CLK_SUNXI_PRCM_SUN8I=3Dy
> CONFIG_CLK_SUNXI_PRCM_SUN9I=3Dy
> CONFIG_SUNXI_CCU=3Dy
> CONFIG_SUN50I_A64_CCU=3Dy
> CONFIG_SUN50I_A100_CCU=3Dy
> CONFIG_SUN50I_A100_R_CCU=3Dy
> CONFIG_SUN50I_H6_CCU=3Dy
> CONFIG_SUN50I_H6_R_CCU=3Dy
> # CONFIG_SUN8I_A83T_CCU is not set
> CONFIG_SUN8I_H3_CCU=3Dy
> CONFIG_SUN8I_DE2_CCU=3Dy
> CONFIG_SUN8I_R_CCU=3Dy
> CONFIG_CLK_TEGRA_BPMP=3Dy
> CONFIG_TEGRA_CLK_DFLL=3Dy
> CONFIG_CLK_UNIPHIER=3Dy
> # CONFIG_COMMON_CLK_ZYNQMP is not set
> CONFIG_HWSPINLOCK=3Dy
> # CONFIG_HWSPINLOCK_OMAP is not set
> CONFIG_HWSPINLOCK_QCOM=3Dy
> # CONFIG_HWSPINLOCK_SPRD is not set
>=20
> #
> # Clock Source drivers
> #
> CONFIG_TIMER_OF=3Dy
> CONFIG_TIMER_ACPI=3Dy
> CONFIG_TIMER_PROBE=3Dy
> CONFIG_CLKSRC_MMIO=3Dy
> CONFIG_DW_APB_TIMER=3Dy
> CONFIG_DW_APB_TIMER_OF=3Dy
> CONFIG_ROCKCHIP_TIMER=3Dy
> CONFIG_OWL_TIMER=3Dy
> CONFIG_TEGRA_TIMER=3Dy
> CONFIG_ARM_ARCH_TIMER=3Dy
> CONFIG_ARM_ARCH_TIMER_EVTSTREAM=3Dy
> CONFIG_ARM_ARCH_TIMER_OOL_WORKAROUND=3Dy
> CONFIG_FSL_ERRATUM_A008585=3Dy
> CONFIG_HISILICON_ERRATUM_161010101=3Dy
> CONFIG_ARM64_ERRATUM_858921=3Dy
> CONFIG_SUN50I_ERRATUM_UNKNOWN1=3Dy
> CONFIG_ARM_TIMER_SP804=3Dy
> CONFIG_SYS_SUPPORTS_SH_CMT=3Dy
> CONFIG_MTK_TIMER=3Dy
> CONFIG_SPRD_TIMER=3Dy
> CONFIG_SYS_SUPPORTS_SH_TMU=3Dy
> CONFIG_SH_TIMER_CMT=3Dy
> CONFIG_SH_TIMER_TMU=3Dy
> CONFIG_TIMER_IMX_SYS_CTR=3Dy
> # CONFIG_MICROCHIP_PIT64B is not set
> # end of Clock Source drivers
>=20
> CONFIG_MAILBOX=3Dy
> CONFIG_ARM_MHU=3Dy
> CONFIG_IMX_MBOX=3Dy
> CONFIG_PLATFORM_MHU=3Dy
> # CONFIG_PL320_MBOX is not set
> # CONFIG_ARMADA_37XX_RWTM_MBOX is not set
> # CONFIG_OMAP2PLUS_MBOX is not set
> # CONFIG_ROCKCHIP_MBOX is not set
> CONFIG_PCC=3Dy
> # CONFIG_ALTERA_MBOX is not set
> CONFIG_BCM2835_MBOX=3Dy
> CONFIG_TI_MESSAGE_MANAGER=3Dy
> CONFIG_HI3660_MBOX=3Dy
> CONFIG_HI6220_MBOX=3Dy
> # CONFIG_MAILBOX_TEST is not set
> CONFIG_QCOM_APCS_IPC=3Dy
> CONFIG_TEGRA_HSP_MBOX=3Dy
> # CONFIG_XGENE_SLIMPRO_MBOX is not set
> # CONFIG_BCM_PDC_MBOX is not set
> CONFIG_BCM_FLEXRM_MBOX=3Dm
> # CONFIG_MTK_CMDQ_MBOX is not set
> CONFIG_ZYNQMP_IPI_MBOX=3Dy
> CONFIG_SUN6I_MSGBOX=3Dy
> # CONFIG_SPRD_MBOX is not set
> # CONFIG_QCOM_IPCC is not set
> CONFIG_IOMMU_IOVA=3Dy
> CONFIG_IOMMU_API=3Dy
> CONFIG_IOMMU_SUPPORT=3Dy
>=20
> #
> # Generic IOMMU Pagetable Support
> #
> CONFIG_IOMMU_IO_PGTABLE=3Dy
> CONFIG_IOMMU_IO_PGTABLE_LPAE=3Dy
> # CONFIG_IOMMU_IO_PGTABLE_LPAE_SELFTEST is not set
> # CONFIG_IOMMU_IO_PGTABLE_ARMV7S is not set
> # end of Generic IOMMU Pagetable Support
>=20
> # CONFIG_IOMMU_DEBUGFS is not set
> # CONFIG_IOMMU_DEFAULT_PASSTHROUGH is not set
> CONFIG_OF_IOMMU=3Dy
> CONFIG_IOMMU_DMA=3Dy
> CONFIG_ROCKCHIP_IOMMU=3Dy
> # CONFIG_SUN50I_IOMMU is not set
> CONFIG_TEGRA_IOMMU_SMMU=3Dy
> # CONFIG_EXYNOS_IOMMU is not set
> # CONFIG_IPMMU_VMSA is not set
> CONFIG_ARM_SMMU=3Dy
> # CONFIG_ARM_SMMU_LEGACY_DT_BINDINGS is not set
> CONFIG_ARM_SMMU_DISABLE_BYPASS_BY_DEFAULT=3Dy
> CONFIG_ARM_SMMU_V3=3Dy
> # CONFIG_ARM_SMMU_V3_SVA is not set
> # CONFIG_MTK_IOMMU is not set
> CONFIG_QCOM_IOMMU=3Dy
> # CONFIG_VIRTIO_IOMMU is not set
>=20
> #
> # Remoteproc drivers
> #
> CONFIG_REMOTEPROC=3Dy
> # CONFIG_REMOTEPROC_CDEV is not set
> # CONFIG_IMX_REMOTEPROC is not set
> # CONFIG_MTK_SCP is not set
> CONFIG_QCOM_PIL_INFO=3Dm
> CONFIG_QCOM_RPROC_COMMON=3Dm
> CONFIG_QCOM_Q6V5_COMMON=3Dm
> # CONFIG_QCOM_Q6V5_ADSP is not set
> CONFIG_QCOM_Q6V5_MSS=3Dm
> CONFIG_QCOM_Q6V5_PAS=3Dm
> # CONFIG_QCOM_Q6V5_WCSS is not set
> CONFIG_QCOM_SYSMON=3Dm
> # CONFIG_QCOM_WCNSS_PIL is not set
> # CONFIG_TI_K3_DSP_REMOTEPROC is not set
> # CONFIG_TI_K3_R5_REMOTEPROC is not set
> # end of Remoteproc drivers
>=20
> #
> # Rpmsg drivers
> #
> CONFIG_RPMSG=3Dy
> # CONFIG_RPMSG_CHAR is not set
> CONFIG_RPMSG_QCOM_GLINK=3Dy
> CONFIG_RPMSG_QCOM_GLINK_RPM=3Dy
> CONFIG_RPMSG_QCOM_GLINK_SMEM=3Dm
> CONFIG_RPMSG_QCOM_SMD=3Dy
> # CONFIG_RPMSG_VIRTIO is not set
> # end of Rpmsg drivers
>=20
> CONFIG_SOUNDWIRE=3Dm
>=20
> #
> # SoundWire Devices
> #
> # CONFIG_SOUNDWIRE_INTEL is not set
> CONFIG_SOUNDWIRE_QCOM=3Dm
>=20
> #
> # SOC (System On Chip) specific Drivers
> #
> CONFIG_OWL_PM_DOMAINS_HELPER=3Dy
> CONFIG_OWL_PM_DOMAINS=3Dy
>=20
> #
> # Amlogic SoC drivers
> #
> CONFIG_MESON_CANVAS=3Dm
> CONFIG_MESON_CLK_MEASURE=3Dy
> CONFIG_MESON_GX_SOCINFO=3Dy
> CONFIG_MESON_GX_PM_DOMAINS=3Dy
> CONFIG_MESON_EE_PM_DOMAINS=3Dy
> CONFIG_MESON_SECURE_PM_DOMAINS=3Dy
> # end of Amlogic SoC drivers
>=20
> #
> # Broadcom SoC drivers
> #
> CONFIG_BCM2835_POWER=3Dy
> CONFIG_RASPBERRYPI_POWER=3Dy
> CONFIG_SOC_BRCMSTB=3Dy
> CONFIG_BRCMSTB_PM=3Dy
> # end of Broadcom SoC drivers
>=20
> #
> # NXP/Freescale QorIQ SoC drivers
> #
> CONFIG_FSL_DPAA=3Dy
> # CONFIG_FSL_DPAA_CHECKING is not set
> # CONFIG_FSL_BMAN_TEST is not set
> # CONFIG_FSL_QMAN_TEST is not set
> # CONFIG_QUICC_ENGINE is not set
> CONFIG_FSL_GUTS=3Dy
> CONFIG_FSL_MC_DPIO=3Dy
> CONFIG_DPAA2_CONSOLE=3Dy
> # CONFIG_FSL_RCPM is not set
> # end of NXP/Freescale QorIQ SoC drivers
>=20
> #
> # i.MX SoC drivers
> #
> CONFIG_IMX_GPCV2_PM_DOMAINS=3Dy
> CONFIG_SOC_IMX8M=3Dy
> # end of i.MX SoC drivers
>=20
> #
> # Enable LiteX SoC Builder specific drivers
> #
> # CONFIG_LITEX_SOC_CONTROLLER is not set
> # end of Enable LiteX SoC Builder specific drivers
>=20
> #
> # MediaTek SoC drivers
> #
> # CONFIG_MTK_CMDQ is not set
> CONFIG_MTK_INFRACFG=3Dy
> # CONFIG_MTK_PMIC_WRAP is not set
> CONFIG_MTK_SCPSYS=3Dy
> CONFIG_MTK_MMSYS=3Dy
> # end of MediaTek SoC drivers
>=20
> #
> # Qualcomm SoC drivers
> #
> CONFIG_QCOM_AOSS_QMP=3Dy
> CONFIG_QCOM_COMMAND_DB=3Dy
> CONFIG_QCOM_CPR=3Dy
> CONFIG_QCOM_GENI_SE=3Dy
> # CONFIG_QCOM_GSBI is not set
> # CONFIG_QCOM_LLCC is not set
> CONFIG_QCOM_KRYO_L2_ACCESSORS=3Dy
> CONFIG_QCOM_MDT_LOADER=3Dm
> # CONFIG_QCOM_OCMEM is not set
> CONFIG_QCOM_PDR_HELPERS=3Dm
> CONFIG_QCOM_QMI_HELPERS=3Dm
> CONFIG_QCOM_RMTFS_MEM=3Dm
> CONFIG_QCOM_RPMH=3Dy
> CONFIG_QCOM_RPMHPD=3Dy
> # CONFIG_QCOM_RPMPD is not set
> CONFIG_QCOM_SMEM=3Dy
> CONFIG_QCOM_SMD_RPM=3Dy
> CONFIG_QCOM_SMEM_STATE=3Dy
> CONFIG_QCOM_SMP2P=3Dy
> CONFIG_QCOM_SMSM=3Dy
> CONFIG_QCOM_SOCINFO=3Dm
> # CONFIG_QCOM_WCNSS_CTRL is not set
> CONFIG_QCOM_APR=3Dm
> # end of Qualcomm SoC drivers
>=20
> CONFIG_SOC_RENESAS=3Dy
> CONFIG_ARCH_RCAR_GEN3=3Dy
> CONFIG_ARCH_R8A77995=3Dy
> CONFIG_ARCH_R8A77990=3Dy
> CONFIG_ARCH_R8A77950=3Dy
> CONFIG_ARCH_R8A77951=3Dy
> CONFIG_ARCH_R8A77965=3Dy
> CONFIG_ARCH_R8A77960=3Dy
> CONFIG_ARCH_R8A77961=3Dy
> CONFIG_ARCH_R8A77980=3Dy
> CONFIG_ARCH_R8A77970=3Dy
> # CONFIG_ARCH_R8A779A0 is not set
> CONFIG_ARCH_R8A774C0=3Dy
> # CONFIG_ARCH_R8A774E1 is not set
> CONFIG_ARCH_R8A774A1=3Dy
> CONFIG_ARCH_R8A774B1=3Dy
> CONFIG_RST_RCAR=3Dy
> CONFIG_SYSC_RCAR=3Dy
> CONFIG_SYSC_R8A77995=3Dy
> CONFIG_SYSC_R8A77990=3Dy
> CONFIG_SYSC_R8A7795=3Dy
> CONFIG_SYSC_R8A77965=3Dy
> CONFIG_SYSC_R8A77960=3Dy
> CONFIG_SYSC_R8A77961=3Dy
> CONFIG_SYSC_R8A77980=3Dy
> CONFIG_SYSC_R8A77970=3Dy
> CONFIG_SYSC_R8A774C0=3Dy
> CONFIG_SYSC_R8A774A1=3Dy
> CONFIG_SYSC_R8A774B1=3Dy
> CONFIG_ROCKCHIP_GRF=3Dy
> CONFIG_ROCKCHIP_IODOMAIN=3Dy
> CONFIG_ROCKCHIP_PM_DOMAINS=3Dy
> CONFIG_SOC_SAMSUNG=3Dy
> CONFIG_EXYNOS_CHIPID=3Dy
> CONFIG_EXYNOS_PMU=3Dy
> CONFIG_EXYNOS_PM_DOMAINS=3Dy
> CONFIG_SUNXI_SRAM=3Dy
> CONFIG_ARCH_TEGRA_132_SOC=3Dy
> CONFIG_ARCH_TEGRA_210_SOC=3Dy
> CONFIG_ARCH_TEGRA_186_SOC=3Dy
> CONFIG_ARCH_TEGRA_194_SOC=3Dy
> # CONFIG_ARCH_TEGRA_234_SOC is not set
> CONFIG_SOC_TEGRA_FUSE=3Dy
> CONFIG_SOC_TEGRA_FLOWCTRL=3Dy
> CONFIG_SOC_TEGRA_PMC=3Dy
> CONFIG_SOC_TEGRA_POWERGATE_BPMP=3Dy
> CONFIG_ARCH_K3_AM6_SOC=3Dy
> CONFIG_ARCH_K3_J721E_SOC=3Dy
> CONFIG_SOC_TI=3Dy
> CONFIG_TI_SCI_PM_DOMAINS=3Dy
> CONFIG_TI_K3_RINGACC=3Dy
> CONFIG_TI_K3_SOCINFO=3Dy
> # CONFIG_TI_PRUSS is not set
> CONFIG_TI_SCI_INTA_MSI_DOMAIN=3Dy
>=20
> #
> # Xilinx SoC drivers
> #
> # CONFIG_XILINX_VCU is not set
> CONFIG_ZYNQMP_POWER=3Dy
> CONFIG_ZYNQMP_PM_DOMAINS=3Dy
> # end of Xilinx SoC drivers
>=20
> # CONFIG_SOC_ZTE is not set
> # end of SOC (System On Chip) specific Drivers
>=20
> CONFIG_PM_DEVFREQ=3Dy
>=20
> #
> # DEVFREQ Governors
> #
> CONFIG_DEVFREQ_GOV_SIMPLE_ONDEMAND=3Dy
> # CONFIG_DEVFREQ_GOV_PERFORMANCE is not set
> # CONFIG_DEVFREQ_GOV_POWERSAVE is not set
> # CONFIG_DEVFREQ_GOV_USERSPACE is not set
> # CONFIG_DEVFREQ_GOV_PASSIVE is not set
>=20
> #
> # DEVFREQ Drivers
> #
> # CONFIG_ARM_EXYNOS_BUS_DEVFREQ is not set
> # CONFIG_ARM_IMX_BUS_DEVFREQ is not set
> # CONFIG_ARM_IMX8M_DDRC_DEVFREQ is not set
> # CONFIG_ARM_TEGRA_DEVFREQ is not set
> # CONFIG_ARM_RK3399_DMC_DEVFREQ is not set
> # CONFIG_PM_DEVFREQ_EVENT is not set
> CONFIG_EXTCON=3Dy
>=20
> #
> # Extcon Device Drivers
> #
> # CONFIG_EXTCON_ADC_JACK is not set
> # CONFIG_EXTCON_FSA9480 is not set
> # CONFIG_EXTCON_GPIO is not set
> # CONFIG_EXTCON_MAX3355 is not set
> # CONFIG_EXTCON_PTN5150 is not set
> # CONFIG_EXTCON_QCOM_SPMI_MISC is not set
> # CONFIG_EXTCON_RT8973A is not set
> # CONFIG_EXTCON_SM5502 is not set
> CONFIG_EXTCON_USB_GPIO=3Dy
> CONFIG_EXTCON_USBC_CROS_EC=3Dy
> # CONFIG_EXTCON_USBC_TUSB320 is not set
> CONFIG_MEMORY=3Dy
> # CONFIG_ARM_PL172_MPMC is not set
> CONFIG_BRCMSTB_DPFE=3Dy
> CONFIG_FSL_IFC=3Dy
> # CONFIG_RENESAS_RPCIF is not set
> CONFIG_TEGRA_MC=3Dy
> # CONFIG_TEGRA210_EMC is not set
> CONFIG_IIO=3Dy
> CONFIG_IIO_BUFFER=3Dy
> # CONFIG_IIO_BUFFER_CB is not set
> # CONFIG_IIO_BUFFER_DMA is not set
> # CONFIG_IIO_BUFFER_DMAENGINE is not set
> # CONFIG_IIO_BUFFER_HW_CONSUMER is not set
> CONFIG_IIO_KFIFO_BUF=3Dm
> CONFIG_IIO_TRIGGERED_BUFFER=3Dm
> # CONFIG_IIO_CONFIGFS is not set
> CONFIG_IIO_TRIGGER=3Dy
> CONFIG_IIO_CONSUMERS_PER_TRIGGER=3D2
> # CONFIG_IIO_SW_DEVICE is not set
> # CONFIG_IIO_SW_TRIGGER is not set
> # CONFIG_IIO_TRIGGERED_EVENT is not set
>=20
> #
> # Accelerometers
> #
> # CONFIG_ADIS16201 is not set
> # CONFIG_ADIS16209 is not set
> # CONFIG_ADXL345_I2C is not set
> # CONFIG_ADXL345_SPI is not set
> # CONFIG_ADXL372_SPI is not set
> # CONFIG_ADXL372_I2C is not set
> # CONFIG_BMA180 is not set
> # CONFIG_BMA220 is not set
> # CONFIG_BMA400 is not set
> # CONFIG_BMC150_ACCEL is not set
> # CONFIG_DA280 is not set
> # CONFIG_DA311 is not set
> # CONFIG_DMARD06 is not set
> # CONFIG_DMARD09 is not set
> # CONFIG_DMARD10 is not set
> # CONFIG_IIO_CROS_EC_ACCEL_LEGACY is not set
> # CONFIG_IIO_ST_ACCEL_3AXIS is not set
> # CONFIG_KXSD9 is not set
> # CONFIG_KXCJK1013 is not set
> # CONFIG_MC3230 is not set
> # CONFIG_MMA7455_I2C is not set
> # CONFIG_MMA7455_SPI is not set
> # CONFIG_MMA7660 is not set
> # CONFIG_MMA8452 is not set
> # CONFIG_MMA9551 is not set
> # CONFIG_MMA9553 is not set
> # CONFIG_MXC4005 is not set
> # CONFIG_MXC6255 is not set
> # CONFIG_SCA3000 is not set
> # CONFIG_STK8312 is not set
> # CONFIG_STK8BA50 is not set
> # end of Accelerometers
>=20
> #
> # Analog to digital converters
> #
> # CONFIG_AD7091R5 is not set
> # CONFIG_AD7124 is not set
> # CONFIG_AD7192 is not set
> # CONFIG_AD7266 is not set
> # CONFIG_AD7291 is not set
> # CONFIG_AD7292 is not set
> # CONFIG_AD7298 is not set
> # CONFIG_AD7476 is not set
> # CONFIG_AD7606_IFACE_PARALLEL is not set
> # CONFIG_AD7606_IFACE_SPI is not set
> # CONFIG_AD7766 is not set
> # CONFIG_AD7768_1 is not set
> # CONFIG_AD7780 is not set
> # CONFIG_AD7791 is not set
> # CONFIG_AD7793 is not set
> # CONFIG_AD7887 is not set
> # CONFIG_AD7923 is not set
> # CONFIG_AD7949 is not set
> # CONFIG_AD799X is not set
> # CONFIG_AD9467 is not set
> # CONFIG_ADI_AXI_ADC is not set
> # CONFIG_AXP20X_ADC is not set
> # CONFIG_AXP288_ADC is not set
> # CONFIG_BCM_IPROC_ADC is not set
> # CONFIG_BERLIN2_ADC is not set
> # CONFIG_CC10001_ADC is not set
> # CONFIG_ENVELOPE_DETECTOR is not set
> CONFIG_EXYNOS_ADC=3Dy
> # CONFIG_HI8435 is not set
> # CONFIG_HX711 is not set
> # CONFIG_INA2XX_ADC is not set
> # CONFIG_IMX7D_ADC is not set
> # CONFIG_LTC2471 is not set
> # CONFIG_LTC2485 is not set
> # CONFIG_LTC2496 is not set
> # CONFIG_LTC2497 is not set
> # CONFIG_MAX1027 is not set
> # CONFIG_MAX11100 is not set
> # CONFIG_MAX1118 is not set
> # CONFIG_MAX1241 is not set
> # CONFIG_MAX1363 is not set
> CONFIG_MAX9611=3Dm
> # CONFIG_MCP320X is not set
> # CONFIG_MCP3422 is not set
> # CONFIG_MCP3911 is not set
> # CONFIG_MEDIATEK_MT6577_AUXADC is not set
> CONFIG_MESON_SARADC=3Dy
> # CONFIG_NAU7802 is not set
> CONFIG_QCOM_VADC_COMMON=3Dm
> # CONFIG_QCOM_SPMI_IADC is not set
> # CONFIG_QCOM_SPMI_VADC is not set
> CONFIG_QCOM_SPMI_ADC5=3Dm
> CONFIG_ROCKCHIP_SARADC=3Dm
> # CONFIG_SD_ADC_MODULATOR is not set
> # CONFIG_TI_ADC081C is not set
> # CONFIG_TI_ADC0832 is not set
> # CONFIG_TI_ADC084S021 is not set
> # CONFIG_TI_ADC12138 is not set
> # CONFIG_TI_ADC108S102 is not set
> # CONFIG_TI_ADC128S052 is not set
> # CONFIG_TI_ADC161S626 is not set
> # CONFIG_TI_ADS1015 is not set
> # CONFIG_TI_ADS7950 is not set
> # CONFIG_TI_ADS8344 is not set
> # CONFIG_TI_ADS8688 is not set
> # CONFIG_TI_ADS124S08 is not set
> # CONFIG_TI_TLC4541 is not set
> # CONFIG_VF610_ADC is not set
> # CONFIG_XILINX_XADC is not set
> # end of Analog to digital converters
>=20
> #
> # Analog Front Ends
> #
> # CONFIG_IIO_RESCALE is not set
> # end of Analog Front Ends
>=20
> #
> # Amplifiers
> #
> # CONFIG_AD8366 is not set
> # CONFIG_HMC425 is not set
> # end of Amplifiers
>=20
> #
> # Chemical Sensors
> #
> # CONFIG_ATLAS_PH_SENSOR is not set
> # CONFIG_ATLAS_EZO_SENSOR is not set
> # CONFIG_BME680 is not set
> # CONFIG_CCS811 is not set
> # CONFIG_IAQCORE is not set
> # CONFIG_PMS7003 is not set
> # CONFIG_SCD30_CORE is not set
> # CONFIG_SENSIRION_SGP30 is not set
> # CONFIG_SPS30 is not set
> # CONFIG_VZ89X is not set
> # end of Chemical Sensors
>=20
> CONFIG_IIO_CROS_EC_SENSORS_CORE=3Dm
> CONFIG_IIO_CROS_EC_SENSORS=3Dm
> # CONFIG_IIO_CROS_EC_SENSORS_LID_ANGLE is not set
>=20
> #
> # Hid Sensor IIO Common
> #
> # end of Hid Sensor IIO Common
>=20
> #
> # SSP Sensor Common
> #
> # CONFIG_IIO_SSP_SENSORHUB is not set
> # end of SSP Sensor Common
>=20
> #
> # Digital to analog converters
> #
> # CONFIG_AD5064 is not set
> # CONFIG_AD5360 is not set
> # CONFIG_AD5380 is not set
> # CONFIG_AD5421 is not set
> # CONFIG_AD5446 is not set
> # CONFIG_AD5449 is not set
> # CONFIG_AD5592R is not set
> # CONFIG_AD5593R is not set
> # CONFIG_AD5504 is not set
> # CONFIG_AD5624R_SPI is not set
> # CONFIG_AD5686_SPI is not set
> # CONFIG_AD5696_I2C is not set
> # CONFIG_AD5755 is not set
> # CONFIG_AD5758 is not set
> # CONFIG_AD5761 is not set
> # CONFIG_AD5764 is not set
> # CONFIG_AD5770R is not set
> # CONFIG_AD5791 is not set
> # CONFIG_AD7303 is not set
> # CONFIG_AD8801 is not set
> # CONFIG_DPOT_DAC is not set
> # CONFIG_DS4424 is not set
> # CONFIG_LTC1660 is not set
> # CONFIG_LTC2632 is not set
> # CONFIG_M62332 is not set
> # CONFIG_MAX517 is not set
> # CONFIG_MAX5821 is not set
> # CONFIG_MCP4725 is not set
> # CONFIG_MCP4922 is not set
> # CONFIG_TI_DAC082S085 is not set
> # CONFIG_TI_DAC5571 is not set
> # CONFIG_TI_DAC7311 is not set
> # CONFIG_TI_DAC7612 is not set
> # CONFIG_VF610_DAC is not set
> # end of Digital to analog converters
>=20
> #
> # IIO dummy driver
> #
> # end of IIO dummy driver
>=20
> #
> # Frequency Synthesizers DDS/PLL
> #
>=20
> #
> # Clock Generator/Distribution
> #
> # CONFIG_AD9523 is not set
> # end of Clock Generator/Distribution
>=20
> #
> # Phase-Locked Loop (PLL) frequency synthesizers
> #
> # CONFIG_ADF4350 is not set
> # CONFIG_ADF4371 is not set
> # end of Phase-Locked Loop (PLL) frequency synthesizers
> # end of Frequency Synthesizers DDS/PLL
>=20
> #
> # Digital gyroscope sensors
> #
> # CONFIG_ADIS16080 is not set
> # CONFIG_ADIS16130 is not set
> # CONFIG_ADIS16136 is not set
> # CONFIG_ADIS16260 is not set
> # CONFIG_ADXRS290 is not set
> # CONFIG_ADXRS450 is not set
> # CONFIG_BMG160 is not set
> # CONFIG_FXAS21002C is not set
> # CONFIG_MPU3050_I2C is not set
> # CONFIG_IIO_ST_GYRO_3AXIS is not set
> # CONFIG_ITG3200 is not set
> # end of Digital gyroscope sensors
>=20
> #
> # Health Sensors
> #
>=20
> #
> # Heart Rate Monitors
> #
> # CONFIG_AFE4403 is not set
> # CONFIG_AFE4404 is not set
> # CONFIG_MAX30100 is not set
> # CONFIG_MAX30102 is not set
> # end of Heart Rate Monitors
> # end of Health Sensors
>=20
> #
> # Humidity sensors
> #
> # CONFIG_AM2315 is not set
> # CONFIG_DHT11 is not set
> # CONFIG_HDC100X is not set
> # CONFIG_HDC2010 is not set
> # CONFIG_HTS221 is not set
> # CONFIG_HTU21 is not set
> # CONFIG_SI7005 is not set
> # CONFIG_SI7020 is not set
> # end of Humidity sensors
>=20
> #
> # Inertial measurement units
> #
> # CONFIG_ADIS16400 is not set
> # CONFIG_ADIS16460 is not set
> # CONFIG_ADIS16475 is not set
> # CONFIG_ADIS16480 is not set
> # CONFIG_BMI160_I2C is not set
> # CONFIG_BMI160_SPI is not set
> # CONFIG_FXOS8700_I2C is not set
> # CONFIG_FXOS8700_SPI is not set
> # CONFIG_KMX61 is not set
> # CONFIG_INV_ICM42600_I2C is not set
> # CONFIG_INV_ICM42600_SPI is not set
> # CONFIG_INV_MPU6050_I2C is not set
> # CONFIG_INV_MPU6050_SPI is not set
> # CONFIG_IIO_ST_LSM6DSX is not set
> # end of Inertial measurement units
>=20
> #
> # Light sensors
> #
> # CONFIG_ACPI_ALS is not set
> # CONFIG_ADJD_S311 is not set
> # CONFIG_ADUX1020 is not set
> # CONFIG_AL3010 is not set
> # CONFIG_AL3320A is not set
> # CONFIG_APDS9300 is not set
> # CONFIG_APDS9960 is not set
> # CONFIG_AS73211 is not set
> # CONFIG_BH1750 is not set
> # CONFIG_BH1780 is not set
> # CONFIG_CM32181 is not set
> # CONFIG_CM3232 is not set
> # CONFIG_CM3323 is not set
> # CONFIG_CM3605 is not set
> # CONFIG_CM36651 is not set
> CONFIG_IIO_CROS_EC_LIGHT_PROX=3Dm
> # CONFIG_GP2AP002 is not set
> # CONFIG_GP2AP020A00F is not set
> CONFIG_SENSORS_ISL29018=3Dm
> # CONFIG_SENSORS_ISL29028 is not set
> # CONFIG_ISL29125 is not set
> # CONFIG_JSA1212 is not set
> # CONFIG_RPR0521 is not set
> # CONFIG_LTR501 is not set
> # CONFIG_LV0104CS is not set
> # CONFIG_MAX44000 is not set
> # CONFIG_MAX44009 is not set
> # CONFIG_NOA1305 is not set
> # CONFIG_OPT3001 is not set
> # CONFIG_PA12203001 is not set
> # CONFIG_SI1133 is not set
> # CONFIG_SI1145 is not set
> # CONFIG_STK3310 is not set
> # CONFIG_ST_UVIS25 is not set
> # CONFIG_TCS3414 is not set
> # CONFIG_TCS3472 is not set
> # CONFIG_SENSORS_TSL2563 is not set
> # CONFIG_TSL2583 is not set
> # CONFIG_TSL2772 is not set
> # CONFIG_TSL4531 is not set
> # CONFIG_US5182D is not set
> # CONFIG_VCNL4000 is not set
> # CONFIG_VCNL4035 is not set
> # CONFIG_VEML6030 is not set
> # CONFIG_VEML6070 is not set
> # CONFIG_VL6180 is not set
> # CONFIG_ZOPT2201 is not set
> # end of Light sensors
>=20
> #
> # Magnetometer sensors
> #
> # CONFIG_AK8974 is not set
> # CONFIG_AK8975 is not set
> # CONFIG_AK09911 is not set
> # CONFIG_BMC150_MAGN_I2C is not set
> # CONFIG_BMC150_MAGN_SPI is not set
> # CONFIG_MAG3110 is not set
> # CONFIG_MMC35240 is not set
> # CONFIG_IIO_ST_MAGN_3AXIS is not set
> # CONFIG_SENSORS_HMC5843_I2C is not set
> # CONFIG_SENSORS_HMC5843_SPI is not set
> # CONFIG_SENSORS_RM3100_I2C is not set
> # CONFIG_SENSORS_RM3100_SPI is not set
> # end of Magnetometer sensors
>=20
> #
> # Multiplexers
> #
> # CONFIG_IIO_MUX is not set
> # end of Multiplexers
>=20
> #
> # Inclinometer sensors
> #
> # end of Inclinometer sensors
>=20
> #
> # Triggers - standalone
> #
> # CONFIG_IIO_INTERRUPT_TRIGGER is not set
> # CONFIG_IIO_SYSFS_TRIGGER is not set
> # end of Triggers - standalone
>=20
> #
> # Linear and angular position sensors
> #
> # end of Linear and angular position sensors
>=20
> #
> # Digital potentiometers
> #
> # CONFIG_AD5272 is not set
> # CONFIG_DS1803 is not set
> # CONFIG_MAX5432 is not set
> # CONFIG_MAX5481 is not set
> # CONFIG_MAX5487 is not set
> # CONFIG_MCP4018 is not set
> # CONFIG_MCP4131 is not set
> # CONFIG_MCP4531 is not set
> # CONFIG_MCP41010 is not set
> # CONFIG_TPL0102 is not set
> # end of Digital potentiometers
>=20
> #
> # Digital potentiostats
> #
> # CONFIG_LMP91000 is not set
> # end of Digital potentiostats
>=20
> #
> # Pressure sensors
> #
> # CONFIG_ABP060MG is not set
> # CONFIG_BMP280 is not set
> CONFIG_IIO_CROS_EC_BARO=3Dm
> # CONFIG_DLHL60D is not set
> # CONFIG_DPS310 is not set
> # CONFIG_HP03 is not set
> # CONFIG_ICP10100 is not set
> # CONFIG_MPL115_I2C is not set
> # CONFIG_MPL115_SPI is not set
> CONFIG_MPL3115=3Dm
> # CONFIG_MS5611 is not set
> # CONFIG_MS5637 is not set
> # CONFIG_IIO_ST_PRESS is not set
> # CONFIG_T5403 is not set
> # CONFIG_HP206C is not set
> # CONFIG_ZPA2326 is not set
> # end of Pressure sensors
>=20
> #
> # Lightning sensors
> #
> # CONFIG_AS3935 is not set
> # end of Lightning sensors
>=20
> #
> # Proximity and distance sensors
> #
> # CONFIG_ISL29501 is not set
> # CONFIG_LIDAR_LITE_V2 is not set
> # CONFIG_MB1232 is not set
> # CONFIG_PING is not set
> # CONFIG_RFD77402 is not set
> # CONFIG_SRF04 is not set
> # CONFIG_SX9310 is not set
> # CONFIG_SX9500 is not set
> # CONFIG_SRF08 is not set
> # CONFIG_VCNL3020 is not set
> # CONFIG_VL53L0X_I2C is not set
> # end of Proximity and distance sensors
>=20
> #
> # Resolver to digital converters
> #
> # CONFIG_AD2S90 is not set
> # CONFIG_AD2S1200 is not set
> # end of Resolver to digital converters
>=20
> #
> # Temperature sensors
> #
> # CONFIG_LTC2983 is not set
> # CONFIG_MAXIM_THERMOCOUPLE is not set
> # CONFIG_MLX90614 is not set
> # CONFIG_MLX90632 is not set
> # CONFIG_TMP006 is not set
> # CONFIG_TMP007 is not set
> # CONFIG_TSYS01 is not set
> # CONFIG_TSYS02D is not set
> # CONFIG_MAX31856 is not set
> # end of Temperature sensors
>=20
> # CONFIG_NTB is not set
> # CONFIG_VME_BUS is not set
> CONFIG_PWM=3Dy
> CONFIG_PWM_SYSFS=3Dy
> # CONFIG_PWM_DEBUG is not set
> CONFIG_PWM_BCM_IPROC=3Dy
> CONFIG_PWM_BCM2835=3Dm
> # CONFIG_PWM_BERLIN is not set
> # CONFIG_PWM_BRCMSTB is not set
> CONFIG_PWM_CROS_EC=3Dm
> # CONFIG_PWM_FSL_FTM is not set
> # CONFIG_PWM_HIBVT is not set
> # CONFIG_PWM_IMX1 is not set
> # CONFIG_PWM_IMX27 is not set
> # CONFIG_PWM_IMX_TPM is not set
> CONFIG_PWM_MESON=3Dm
> # CONFIG_PWM_MTK_DISP is not set
> # CONFIG_PWM_MEDIATEK is not set
> # CONFIG_PWM_PCA9685 is not set
> CONFIG_PWM_RCAR=3Dm
> # CONFIG_PWM_RENESAS_TPU is not set
> CONFIG_PWM_ROCKCHIP=3Dy
> CONFIG_PWM_SAMSUNG=3Dy
> # CONFIG_PWM_SPRD is not set
> CONFIG_PWM_SUN4I=3Dm
> CONFIG_PWM_TEGRA=3Dm
> # CONFIG_PWM_TIECAP is not set
> # CONFIG_PWM_TIEHRPWM is not set
> # CONFIG_PWM_ZX is not set
>=20
> #
> # IRQ chip support
> #
> CONFIG_IRQCHIP=3Dy
> CONFIG_ARM_GIC=3Dy
> CONFIG_ARM_GIC_PM=3Dy
> CONFIG_ARM_GIC_MAX_NR=3D1
> CONFIG_ARM_GIC_V2M=3Dy
> CONFIG_ARM_GIC_V3=3Dy
> CONFIG_ARM_GIC_V3_ITS=3Dy
> CONFIG_ARM_GIC_V3_ITS_PCI=3Dy
> CONFIG_ARM_GIC_V3_ITS_FSL_MC=3Dy
> CONFIG_ALPINE_MSI=3Dy
> # CONFIG_AL_FIC is not set
> CONFIG_BCM7038_L1_IRQ=3Dy
> CONFIG_BRCMSTB_L2_IRQ=3Dy
> CONFIG_DW_APB_ICTL=3Dy
> CONFIG_HISILICON_IRQ_MBIGEN=3Dy
> CONFIG_RENESAS_IRQC=3Dy
> CONFIG_IMX_GPCV2=3Dy
> CONFIG_MVEBU_GICP=3Dy
> CONFIG_MVEBU_ICU=3Dy
> CONFIG_MVEBU_ODMI=3Dy
> CONFIG_MVEBU_PIC=3Dy
> CONFIG_MVEBU_SEI=3Dy
> CONFIG_LS_EXTIRQ=3Dy
> CONFIG_LS_SCFG_MSI=3Dy
> CONFIG_PARTITION_PERCPU=3Dy
> CONFIG_QCOM_IRQ_COMBINER=3Dy
> CONFIG_IRQ_UNIPHIER_AIDET=3Dy
> CONFIG_MESON_IRQ_GPIO=3Dy
> CONFIG_QCOM_PDC=3Dy
> CONFIG_IMX_IRQSTEER=3Dy
> CONFIG_IMX_INTMUX=3Dy
> CONFIG_TI_SCI_INTR_IRQCHIP=3Dy
> CONFIG_TI_SCI_INTA_IRQCHIP=3Dy
> # CONFIG_TI_PRUSS_INTC is not set
> CONFIG_MST_IRQ=3Dy
> # end of IRQ chip support
>=20
> # CONFIG_IPACK_BUS is not set
> CONFIG_ARCH_HAS_RESET_CONTROLLER=3Dy
> CONFIG_RESET_CONTROLLER=3Dy
> CONFIG_RESET_BERLIN=3Dy
> CONFIG_RESET_BRCMSTB=3Dy
> CONFIG_RESET_BRCMSTB_RESCAL=3Dy
> CONFIG_RESET_IMX7=3Dy
> # CONFIG_RESET_INTEL_GW is not set
> CONFIG_RESET_MESON=3Dy
> CONFIG_RESET_MESON_AUDIO_ARB=3Dm
> CONFIG_RESET_QCOM_AOSS=3Dy
> CONFIG_RESET_QCOM_PDC=3Dm
> CONFIG_RESET_RASPBERRYPI=3Dy
> CONFIG_RESET_SIMPLE=3Dy
> CONFIG_RESET_SUNXI=3Dy
> CONFIG_RESET_TI_SCI=3Dy
> # CONFIG_RESET_TI_SYSCON is not set
> CONFIG_RESET_UNIPHIER=3Dy
> CONFIG_RESET_UNIPHIER_GLUE=3Dy
> CONFIG_COMMON_RESET_HI3660=3Dy
> CONFIG_COMMON_RESET_HI6220=3Dy
> CONFIG_RESET_TEGRA_BPMP=3Dy
>=20
> #
> # PHY Subsystem
> #
> CONFIG_GENERIC_PHY=3Dy
> CONFIG_GENERIC_PHY_MIPI_DPHY=3Dy
> CONFIG_PHY_XGENE=3Dy
> # CONFIG_USB_LGM_PHY is not set
> CONFIG_PHY_SUN4I_USB=3Dy
> CONFIG_PHY_SUN6I_MIPI_DPHY=3Dm
> # CONFIG_PHY_SUN9I_USB is not set
> # CONFIG_PHY_SUN50I_USB3 is not set
> CONFIG_PHY_MESON8B_USB2=3Dy
> CONFIG_PHY_MESON_GXL_USB2=3Dy
> CONFIG_PHY_MESON_G12A_USB2=3Dy
> CONFIG_PHY_MESON_G12A_USB3_PCIE=3Dy
> CONFIG_PHY_MESON_AXG_PCIE=3Dy
> CONFIG_PHY_MESON_AXG_MIPI_PCIE_ANALOG=3Dy
> CONFIG_PHY_BCM_SR_USB=3Dy
> # CONFIG_BCM_KONA_USB2_PHY is not set
> # CONFIG_PHY_BCM_NS_USB2 is not set
> # CONFIG_PHY_BCM_NS_USB3 is not set
> CONFIG_PHY_NS2_PCIE=3Dy
> CONFIG_PHY_NS2_USB_DRD=3Dy
> CONFIG_PHY_BRCM_SATA=3Dy
> CONFIG_PHY_BRCM_USB=3Dy
> CONFIG_PHY_BCM_SR_PCIE=3Dy
> # CONFIG_PHY_CADENCE_TORRENT is not set
> # CONFIG_PHY_CADENCE_DPHY is not set
> # CONFIG_PHY_CADENCE_SIERRA is not set
> # CONFIG_PHY_CADENCE_SALVO is not set
> CONFIG_PHY_FSL_IMX8MQ_USB=3Dy
> # CONFIG_PHY_MIXEL_MIPI_DPHY is not set
> CONFIG_PHY_HI6220_USB=3Dy
> # CONFIG_PHY_HI3660_USB is not set
> CONFIG_PHY_HISTB_COMBPHY=3Dy
> CONFIG_PHY_HISI_INNO_USB2=3Dy
> # CONFIG_PHY_BERLIN_SATA is not set
> # CONFIG_PHY_BERLIN_USB is not set
> CONFIG_PHY_MVEBU_A3700_COMPHY=3Dy
> CONFIG_PHY_MVEBU_A3700_UTMI=3Dy
> # CONFIG_PHY_MVEBU_A38X_COMPHY is not set
> CONFIG_PHY_MVEBU_CP110_COMPHY=3Dy
> # CONFIG_PHY_PXA_28NM_HSIC is not set
> # CONFIG_PHY_PXA_28NM_USB2 is not set
> # CONFIG_PHY_MTK_TPHY is not set
> # CONFIG_PHY_MTK_UFS is not set
> # CONFIG_PHY_MTK_XSPHY is not set
> # CONFIG_PHY_MTK_HDMI is not set
> # CONFIG_PHY_CPCAP_USB is not set
> # CONFIG_PHY_MAPPHONE_MDM6600 is not set
> # CONFIG_PHY_OCELOT_SERDES is not set
> # CONFIG_PHY_QCOM_APQ8064_SATA is not set
> # CONFIG_PHY_QCOM_IPQ4019_USB is not set
> # CONFIG_PHY_QCOM_IPQ806X_SATA is not set
> # CONFIG_PHY_QCOM_PCIE2 is not set
> CONFIG_PHY_QCOM_QMP=3Dm
> CONFIG_PHY_QCOM_QUSB2=3Dm
> CONFIG_PHY_QCOM_USB_HS=3Dy
> # CONFIG_PHY_QCOM_USB_SNPS_FEMTO_V2 is not set
> # CONFIG_PHY_QCOM_USB_HSIC is not set
> # CONFIG_PHY_QCOM_USB_HS_28NM is not set
> # CONFIG_PHY_QCOM_USB_SS is not set
> # CONFIG_PHY_QCOM_IPQ806X_USB is not set
> # CONFIG_PHY_RCAR_GEN2 is not set
> CONFIG_PHY_RCAR_GEN3_PCIE=3Dy
> CONFIG_PHY_RCAR_GEN3_USB2=3Dy
> CONFIG_PHY_RCAR_GEN3_USB3=3Dm
> # CONFIG_PHY_ROCKCHIP_DP is not set
> # CONFIG_PHY_ROCKCHIP_DPHY_RX0 is not set
> CONFIG_PHY_ROCKCHIP_EMMC=3Dy
> CONFIG_PHY_ROCKCHIP_INNO_HDMI=3Dm
> CONFIG_PHY_ROCKCHIP_INNO_USB2=3Dy
> # CONFIG_PHY_ROCKCHIP_INNO_DSIDPHY is not set
> CONFIG_PHY_ROCKCHIP_PCIE=3Dm
> CONFIG_PHY_ROCKCHIP_TYPEC=3Dy
> # CONFIG_PHY_ROCKCHIP_USB is not set
> CONFIG_PHY_EXYNOS_DP_VIDEO=3Dy
> CONFIG_PHY_EXYNOS_MIPI_VIDEO=3Dy
> # CONFIG_PHY_EXYNOS_PCIE is not set
> # CONFIG_PHY_SAMSUNG_UFS is not set
> CONFIG_PHY_SAMSUNG_USB2=3Dy
> CONFIG_PHY_EXYNOS5_USBDRD=3Dy
> CONFIG_PHY_UNIPHIER_USB2=3Dy
> CONFIG_PHY_UNIPHIER_USB3=3Dy
> # CONFIG_PHY_UNIPHIER_PCIE is not set
> CONFIG_PHY_UNIPHIER_AHCI=3Dy
> CONFIG_PHY_TEGRA_XUSB=3Dy
> CONFIG_PHY_TEGRA194_P2U=3Dm
> # CONFIG_PHY_AM654_SERDES is not set
> # CONFIG_PHY_J721E_WIZ is not set
> # CONFIG_OMAP_USB2 is not set
> # CONFIG_PHY_TUSB1210 is not set
> CONFIG_PHY_TI_GMII_SEL=3Dy
> # CONFIG_PHY_INTEL_KEEMBAY_EMMC is not set
> # CONFIG_PHY_XILINX_ZYNQMP is not set
> # end of PHY Subsystem
>=20
> # CONFIG_POWERCAP is not set
> # CONFIG_MCB is not set
>=20
> #
> # Performance monitor support
> #
> # CONFIG_ARM_CCI_PMU is not set
> # CONFIG_ARM_CCN is not set
> # CONFIG_ARM_CMN is not set
> CONFIG_ARM_PMU=3Dy
> CONFIG_ARM_PMU_ACPI=3Dy
> CONFIG_ARM_SMMU_V3_PMU=3Dm
> # CONFIG_ARM_DSU_PMU is not set
> CONFIG_FSL_IMX8_DDR_PMU=3Dm
> CONFIG_QCOM_L2_PMU=3Dy
> CONFIG_QCOM_L3_PMU=3Dy
> CONFIG_THUNDERX2_PMU=3Dm
> # CONFIG_XGENE_PMU is not set
> # CONFIG_ARM_SPE_PMU is not set
> CONFIG_HISI_PMU=3Dy
> # end of Performance monitor support
>=20
> CONFIG_RAS=3Dy
> # CONFIG_USB4 is not set
>=20
> #
> # Android
> #
> # CONFIG_ANDROID is not set
> # end of Android
>=20
> # CONFIG_LIBNVDIMM is not set
> # CONFIG_DAX is not set
> CONFIG_NVMEM=3Dy
> CONFIG_NVMEM_SYSFS=3Dy
> # CONFIG_NVMEM_IMX_IIM is not set
> CONFIG_NVMEM_IMX_OCOTP=3Dy
> CONFIG_NVMEM_IMX_OCOTP_SCU=3Dy
> # CONFIG_MTK_EFUSE is not set
> CONFIG_QCOM_QFPROM=3Dy
> # CONFIG_NVMEM_SPMI_SDAM is not set
> CONFIG_ROCKCHIP_EFUSE=3Dy
> # CONFIG_ROCKCHIP_OTP is not set
> CONFIG_NVMEM_BCM_OCOTP=3Dy
> CONFIG_NVMEM_SUNXI_SID=3Dy
> CONFIG_UNIPHIER_EFUSE=3Dy
> CONFIG_MESON_EFUSE=3Dm
> # CONFIG_MESON_MX_EFUSE is not set
> # CONFIG_NVMEM_SNVS_LPGPR is not set
> # CONFIG_NVMEM_ZYNQMP is not set
> # CONFIG_SPRD_EFUSE is not set
>=20
> #
> # HW tracing support
> #
> # CONFIG_STM is not set
> # CONFIG_INTEL_TH is not set
> # end of HW tracing support
>=20
> CONFIG_FPGA=3Dy
> # CONFIG_ALTERA_PR_IP_CORE is not set
> # CONFIG_FPGA_MGR_ALTERA_PS_SPI is not set
> # CONFIG_FPGA_MGR_ALTERA_CVP is not set
> CONFIG_FPGA_MGR_STRATIX10_SOC=3Dm
> # CONFIG_FPGA_MGR_XILINX_SPI is not set
> # CONFIG_FPGA_MGR_ICE40_SPI is not set
> # CONFIG_FPGA_MGR_MACHXO2_SPI is not set
> CONFIG_FPGA_BRIDGE=3Dm
> CONFIG_ALTERA_FREEZE_BRIDGE=3Dm
> # CONFIG_XILINX_PR_DECOUPLER is not set
> CONFIG_FPGA_REGION=3Dm
> CONFIG_OF_FPGA_REGION=3Dm
> # CONFIG_FPGA_DFL is not set
> # CONFIG_FPGA_MGR_ZYNQMP_FPGA is not set
> # CONFIG_FSI is not set
> CONFIG_TEE=3Dy
>=20
> #
> # TEE drivers
> #
> CONFIG_OPTEE=3Dy
> CONFIG_OPTEE_SHM_NUM_PRIV_PAGES=3D1
> # end of TEE drivers
>=20
> CONFIG_MULTIPLEXER=3Dy
>=20
> #
> # Multiplexer drivers
> #
> # CONFIG_MUX_ADG792A is not set
> # CONFIG_MUX_ADGS1408 is not set
> # CONFIG_MUX_GPIO is not set
> CONFIG_MUX_MMIO=3Dy
> # end of Multiplexer drivers
>=20
> CONFIG_PM_OPP=3Dy
> # CONFIG_SIOX is not set
> CONFIG_SLIMBUS=3Dm
> CONFIG_SLIM_QCOM_CTRL=3Dm
> CONFIG_SLIM_QCOM_NGD_CTRL=3Dm
> CONFIG_INTERCONNECT=3Dy
> # CONFIG_INTERCONNECT_IMX is not set
> # CONFIG_INTERCONNECT_QCOM is not set
> # CONFIG_COUNTER is not set
> # CONFIG_MOST is not set
> # end of Device Drivers
>=20
> #
> # File systems
> #
> CONFIG_DCACHE_WORD_ACCESS=3Dy
> # CONFIG_VALIDATE_FS_PARSER is not set
> CONFIG_FS_IOMAP=3Dy
> CONFIG_EXT2_FS=3Dy
> # CONFIG_EXT2_FS_XATTR is not set
> CONFIG_EXT3_FS=3Dy
> # CONFIG_EXT3_FS_POSIX_ACL is not set
> # CONFIG_EXT3_FS_SECURITY is not set
> CONFIG_EXT4_FS=3Dy
> CONFIG_EXT4_FS_POSIX_ACL=3Dy
> # CONFIG_EXT4_FS_SECURITY is not set
> # CONFIG_EXT4_DEBUG is not set
> # CONFIG_EXT4_KUNIT_TESTS is not set
> CONFIG_JBD2=3Dy
> # CONFIG_JBD2_DEBUG is not set
> CONFIG_FS_MBCACHE=3Dy
> # CONFIG_REISERFS_FS is not set
> # CONFIG_JFS_FS is not set
> CONFIG_XFS_FS=3Dm
> CONFIG_XFS_SUPPORT_V4=3Dy
> # CONFIG_XFS_QUOTA is not set
> # CONFIG_XFS_POSIX_ACL is not set
> # CONFIG_XFS_RT is not set
> # CONFIG_XFS_ONLINE_SCRUB is not set
> # CONFIG_XFS_WARN is not set
> # CONFIG_XFS_DEBUG is not set
> # CONFIG_GFS2_FS is not set
> # CONFIG_OCFS2_FS is not set
> CONFIG_BTRFS_FS=3Dm
> CONFIG_BTRFS_FS_POSIX_ACL=3Dy
> # CONFIG_BTRFS_FS_CHECK_INTEGRITY is not set
> # CONFIG_BTRFS_FS_RUN_SANITY_TESTS is not set
> # CONFIG_BTRFS_DEBUG is not set
> # CONFIG_BTRFS_ASSERT is not set
> # CONFIG_BTRFS_FS_REF_VERIFY is not set
> # CONFIG_NILFS2_FS is not set
> # CONFIG_F2FS_FS is not set
> # CONFIG_FS_DAX is not set
> CONFIG_FS_POSIX_ACL=3Dy
> CONFIG_EXPORTFS=3Dy
> # CONFIG_EXPORTFS_BLOCK_OPS is not set
> CONFIG_FILE_LOCKING=3Dy
> CONFIG_MANDATORY_FILE_LOCKING=3Dy
> # CONFIG_FS_ENCRYPTION is not set
> # CONFIG_FS_VERITY is not set
> CONFIG_FSNOTIFY=3Dy
> CONFIG_DNOTIFY=3Dy
> CONFIG_INOTIFY_USER=3Dy
> CONFIG_FANOTIFY=3Dy
> CONFIG_FANOTIFY_ACCESS_PERMISSIONS=3Dy
> # CONFIG_MOUNT_NOTIFICATIONS is not set
> CONFIG_QUOTA=3Dy
> # CONFIG_QUOTA_NETLINK_INTERFACE is not set
> CONFIG_PRINT_QUOTA_WARNING=3Dy
> # CONFIG_QUOTA_DEBUG is not set
> # CONFIG_QFMT_V1 is not set
> # CONFIG_QFMT_V2 is not set
> CONFIG_QUOTACTL=3Dy
> CONFIG_AUTOFS4_FS=3Dy
> CONFIG_AUTOFS_FS=3Dy
> CONFIG_FUSE_FS=3Dm
> CONFIG_CUSE=3Dm
> # CONFIG_VIRTIO_FS is not set
> CONFIG_OVERLAY_FS=3Dy
> # CONFIG_OVERLAY_FS_REDIRECT_DIR is not set
> CONFIG_OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW=3Dy
> # CONFIG_OVERLAY_FS_INDEX is not set
> # CONFIG_OVERLAY_FS_XINO_AUTO is not set
> # CONFIG_OVERLAY_FS_METACOPY is not set
>=20
> #
> # Caches
> #
> # CONFIG_FSCACHE is not set
> # end of Caches
>=20
> #
> # CD-ROM/DVD Filesystems
> #
> # CONFIG_ISO9660_FS is not set
> # CONFIG_UDF_FS is not set
> # end of CD-ROM/DVD Filesystems
>=20
> #
> # DOS/FAT/EXFAT/NT Filesystems
> #
> CONFIG_FAT_FS=3Dy
> # CONFIG_MSDOS_FS is not set
> CONFIG_VFAT_FS=3Dy
> CONFIG_FAT_DEFAULT_CODEPAGE=3D437
> CONFIG_FAT_DEFAULT_IOCHARSET=3D"iso8859-1"
> # CONFIG_FAT_DEFAULT_UTF8 is not set
> # CONFIG_EXFAT_FS is not set
> # CONFIG_NTFS_FS is not set
> # end of DOS/FAT/EXFAT/NT Filesystems
>=20
> #
> # Pseudo filesystems
> #
> CONFIG_PROC_FS=3Dy
> # CONFIG_PROC_KCORE is not set
> CONFIG_PROC_VMCORE=3Dy
> # CONFIG_PROC_VMCORE_DEVICE_DUMP is not set
> CONFIG_PROC_SYSCTL=3Dy
> CONFIG_PROC_PAGE_MONITOR=3Dy
> # CONFIG_PROC_CHILDREN is not set
> CONFIG_KERNFS=3Dy
> CONFIG_SYSFS=3Dy
> CONFIG_TMPFS=3Dy
> # CONFIG_TMPFS_POSIX_ACL is not set
> # CONFIG_TMPFS_XATTR is not set
> # CONFIG_TMPFS_INODE64 is not set
> CONFIG_HUGETLBFS=3Dy
> CONFIG_HUGETLB_PAGE=3Dy
> CONFIG_MEMFD_CREATE=3Dy
> CONFIG_ARCH_HAS_GIGANTIC_PAGE=3Dy
> CONFIG_CONFIGFS_FS=3Dy
> CONFIG_EFIVAR_FS=3Dy
> # end of Pseudo filesystems
>=20
> CONFIG_MISC_FILESYSTEMS=3Dy
> # CONFIG_ORANGEFS_FS is not set
> # CONFIG_ADFS_FS is not set
> # CONFIG_AFFS_FS is not set
> # CONFIG_ECRYPT_FS is not set
> # CONFIG_HFS_FS is not set
> # CONFIG_HFSPLUS_FS is not set
> # CONFIG_BEFS_FS is not set
> # CONFIG_BFS_FS is not set
> # CONFIG_EFS_FS is not set
> # CONFIG_JFFS2_FS is not set
> # CONFIG_CRAMFS is not set
> CONFIG_SQUASHFS=3Dy
> CONFIG_SQUASHFS_FILE_CACHE=3Dy
> # CONFIG_SQUASHFS_FILE_DIRECT is not set
> CONFIG_SQUASHFS_DECOMP_SINGLE=3Dy
> # CONFIG_SQUASHFS_DECOMP_MULTI is not set
> # CONFIG_SQUASHFS_DECOMP_MULTI_PERCPU is not set
> # CONFIG_SQUASHFS_XATTR is not set
> CONFIG_SQUASHFS_ZLIB=3Dy
> # CONFIG_SQUASHFS_LZ4 is not set
> # CONFIG_SQUASHFS_LZO is not set
> # CONFIG_SQUASHFS_XZ is not set
> # CONFIG_SQUASHFS_ZSTD is not set
> # CONFIG_SQUASHFS_4K_DEVBLK_SIZE is not set
> # CONFIG_SQUASHFS_EMBEDDED is not set
> CONFIG_SQUASHFS_FRAGMENT_CACHE_SIZE=3D3
> # CONFIG_VXFS_FS is not set
> # CONFIG_MINIX_FS is not set
> # CONFIG_OMFS_FS is not set
> # CONFIG_HPFS_FS is not set
> # CONFIG_QNX4FS_FS is not set
> # CONFIG_QNX6FS_FS is not set
> # CONFIG_ROMFS_FS is not set
> CONFIG_PSTORE=3Dy
> CONFIG_PSTORE_DEFLATE_COMPRESS=3Dy
> # CONFIG_PSTORE_LZO_COMPRESS is not set
> # CONFIG_PSTORE_LZ4_COMPRESS is not set
> # CONFIG_PSTORE_LZ4HC_COMPRESS is not set
> # CONFIG_PSTORE_842_COMPRESS is not set
> # CONFIG_PSTORE_ZSTD_COMPRESS is not set
> CONFIG_PSTORE_COMPRESS=3Dy
> CONFIG_PSTORE_DEFLATE_COMPRESS_DEFAULT=3Dy
> CONFIG_PSTORE_COMPRESS_DEFAULT=3D"deflate"
> # CONFIG_PSTORE_CONSOLE is not set
> # CONFIG_PSTORE_PMSG is not set
> CONFIG_PSTORE_FTRACE=3Dy
> # CONFIG_PSTORE_RAM is not set
> # CONFIG_PSTORE_BLK is not set
> # CONFIG_SYSV_FS is not set
> # CONFIG_UFS_FS is not set
> # CONFIG_EROFS_FS is not set
> CONFIG_NETWORK_FILESYSTEMS=3Dy
> CONFIG_NFS_FS=3Dy
> CONFIG_NFS_V2=3Dy
> CONFIG_NFS_V3=3Dy
> # CONFIG_NFS_V3_ACL is not set
> CONFIG_NFS_V4=3Dy
> # CONFIG_NFS_SWAP is not set
> CONFIG_NFS_V4_1=3Dy
> CONFIG_NFS_V4_2=3Dy
> CONFIG_PNFS_FILE_LAYOUT=3Dy
> CONFIG_PNFS_BLOCK=3Dm
> CONFIG_PNFS_FLEXFILE_LAYOUT=3Dm
> CONFIG_NFS_V4_1_IMPLEMENTATION_ID_DOMAIN=3D"kernel.org"
> # CONFIG_NFS_V4_1_MIGRATION is not set
> CONFIG_NFS_V4_SECURITY_LABEL=3Dy
> CONFIG_ROOT_NFS=3Dy
> # CONFIG_NFS_USE_LEGACY_DNS is not set
> CONFIG_NFS_USE_KERNEL_DNS=3Dy
> CONFIG_NFS_DISABLE_UDP_SUPPORT=3Dy
> # CONFIG_NFSD is not set
> CONFIG_GRACE_PERIOD=3Dy
> CONFIG_LOCKD=3Dy
> CONFIG_LOCKD_V4=3Dy
> CONFIG_NFS_COMMON=3Dy
> CONFIG_SUNRPC=3Dy
> CONFIG_SUNRPC_GSS=3Dy
> CONFIG_SUNRPC_BACKCHANNEL=3Dy
> # CONFIG_SUNRPC_DEBUG is not set
> # CONFIG_CEPH_FS is not set
> # CONFIG_CIFS is not set
> # CONFIG_CODA_FS is not set
> # CONFIG_AFS_FS is not set
> CONFIG_9P_FS=3Dy
> # CONFIG_9P_FS_POSIX_ACL is not set
> # CONFIG_9P_FS_SECURITY is not set
> CONFIG_NLS=3Dy
> CONFIG_NLS_DEFAULT=3D"iso8859-1"
> CONFIG_NLS_CODEPAGE_437=3Dy
> # CONFIG_NLS_CODEPAGE_737 is not set
> # CONFIG_NLS_CODEPAGE_775 is not set
> # CONFIG_NLS_CODEPAGE_850 is not set
> # CONFIG_NLS_CODEPAGE_852 is not set
> # CONFIG_NLS_CODEPAGE_855 is not set
> # CONFIG_NLS_CODEPAGE_857 is not set
> # CONFIG_NLS_CODEPAGE_860 is not set
> # CONFIG_NLS_CODEPAGE_861 is not set
> # CONFIG_NLS_CODEPAGE_862 is not set
> # CONFIG_NLS_CODEPAGE_863 is not set
> # CONFIG_NLS_CODEPAGE_864 is not set
> # CONFIG_NLS_CODEPAGE_865 is not set
> # CONFIG_NLS_CODEPAGE_866 is not set
> # CONFIG_NLS_CODEPAGE_869 is not set
> # CONFIG_NLS_CODEPAGE_936 is not set
> # CONFIG_NLS_CODEPAGE_950 is not set
> # CONFIG_NLS_CODEPAGE_932 is not set
> # CONFIG_NLS_CODEPAGE_949 is not set
> # CONFIG_NLS_CODEPAGE_874 is not set
> # CONFIG_NLS_ISO8859_8 is not set
> # CONFIG_NLS_CODEPAGE_1250 is not set
> # CONFIG_NLS_CODEPAGE_1251 is not set
> # CONFIG_NLS_ASCII is not set
> CONFIG_NLS_ISO8859_1=3Dy
> # CONFIG_NLS_ISO8859_2 is not set
> # CONFIG_NLS_ISO8859_3 is not set
> # CONFIG_NLS_ISO8859_4 is not set
> # CONFIG_NLS_ISO8859_5 is not set
> # CONFIG_NLS_ISO8859_6 is not set
> # CONFIG_NLS_ISO8859_7 is not set
> # CONFIG_NLS_ISO8859_9 is not set
> # CONFIG_NLS_ISO8859_13 is not set
> # CONFIG_NLS_ISO8859_14 is not set
> # CONFIG_NLS_ISO8859_15 is not set
> # CONFIG_NLS_KOI8_R is not set
> # CONFIG_NLS_KOI8_U is not set
> # CONFIG_NLS_MAC_ROMAN is not set
> # CONFIG_NLS_MAC_CELTIC is not set
> # CONFIG_NLS_MAC_CENTEURO is not set
> # CONFIG_NLS_MAC_CROATIAN is not set
> # CONFIG_NLS_MAC_CYRILLIC is not set
> # CONFIG_NLS_MAC_GAELIC is not set
> # CONFIG_NLS_MAC_GREEK is not set
> # CONFIG_NLS_MAC_ICELAND is not set
> # CONFIG_NLS_MAC_INUIT is not set
> # CONFIG_NLS_MAC_ROMANIAN is not set
> # CONFIG_NLS_MAC_TURKISH is not set
> # CONFIG_NLS_UTF8 is not set
> # CONFIG_DLM is not set
> # CONFIG_UNICODE is not set
> CONFIG_IO_WQ=3Dy
> # end of File systems
>=20
> #
> # Security options
> #
> CONFIG_KEYS=3Dy
> # CONFIG_KEYS_REQUEST_CACHE is not set
> # CONFIG_PERSISTENT_KEYRINGS is not set
> # CONFIG_TRUSTED_KEYS is not set
> # CONFIG_ENCRYPTED_KEYS is not set
> # CONFIG_KEY_DH_OPERATIONS is not set
> # CONFIG_SECURITY_DMESG_RESTRICT is not set
> CONFIG_SECURITY=3Dy
> CONFIG_SECURITYFS=3Dy
> # CONFIG_SECURITY_NETWORK is not set
> # CONFIG_SECURITY_PATH is not set
> CONFIG_HAVE_HARDENED_USERCOPY_ALLOCATOR=3Dy
> # CONFIG_HARDENED_USERCOPY is not set
> # CONFIG_FORTIFY_SOURCE is not set
> # CONFIG_STATIC_USERMODEHELPER is not set
> # CONFIG_SECURITY_SMACK is not set
> # CONFIG_SECURITY_TOMOYO is not set
> # CONFIG_SECURITY_APPARMOR is not set
> # CONFIG_SECURITY_LOADPIN is not set
> # CONFIG_SECURITY_YAMA is not set
> # CONFIG_SECURITY_SAFESETID is not set
> # CONFIG_SECURITY_LOCKDOWN_LSM is not set
> CONFIG_INTEGRITY=3Dy
> # CONFIG_INTEGRITY_SIGNATURE is not set
> CONFIG_INTEGRITY_AUDIT=3Dy
> # CONFIG_IMA is not set
> # CONFIG_EVM is not set
> CONFIG_DEFAULT_SECURITY_DAC=3Dy
> CONFIG_LSM=3D"lockdown,yama,loadpin,safesetid,integrity,bpf"
>=20
> #
> # Kernel hardening options
> #
>=20
> #
> # Memory initialization
> #
> CONFIG_INIT_STACK_NONE=3Dy
> # CONFIG_GCC_PLUGIN_STRUCTLEAK_USER is not set
> # CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF is not set
> # CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL is not set
> # CONFIG_GCC_PLUGIN_STACKLEAK is not set
> # CONFIG_INIT_ON_ALLOC_DEFAULT_ON is not set
> # CONFIG_INIT_ON_FREE_DEFAULT_ON is not set
> # end of Memory initialization
> # end of Kernel hardening options
> # end of Security options
>=20
> CONFIG_XOR_BLOCKS=3Dm
> CONFIG_ASYNC_TX_DISABLE_PQ_VAL_DMA=3Dy
> CONFIG_ASYNC_TX_DISABLE_XOR_VAL_DMA=3Dy
> CONFIG_CRYPTO=3Dy
>=20
> #
> # Crypto core or helper
> #
> CONFIG_CRYPTO_ALGAPI=3Dy
> CONFIG_CRYPTO_ALGAPI2=3Dy
> CONFIG_CRYPTO_AEAD=3Dy
> CONFIG_CRYPTO_AEAD2=3Dy
> CONFIG_CRYPTO_SKCIPHER=3Dy
> CONFIG_CRYPTO_SKCIPHER2=3Dy
> CONFIG_CRYPTO_HASH=3Dy
> CONFIG_CRYPTO_HASH2=3Dy
> CONFIG_CRYPTO_RNG=3Dy
> CONFIG_CRYPTO_RNG2=3Dy
> CONFIG_CRYPTO_RNG_DEFAULT=3Dy
> CONFIG_CRYPTO_AKCIPHER2=3Dy
> CONFIG_CRYPTO_AKCIPHER=3Dy
> CONFIG_CRYPTO_KPP2=3Dy
> CONFIG_CRYPTO_KPP=3Dm
> CONFIG_CRYPTO_ACOMP2=3Dy
> CONFIG_CRYPTO_MANAGER=3Dy
> CONFIG_CRYPTO_MANAGER2=3Dy
> # CONFIG_CRYPTO_USER is not set
> CONFIG_CRYPTO_MANAGER_DISABLE_TESTS=3Dy
> CONFIG_CRYPTO_GF128MUL=3Dy
> CONFIG_CRYPTO_NULL=3Dy
> CONFIG_CRYPTO_NULL2=3Dy
> # CONFIG_CRYPTO_PCRYPT is not set
> CONFIG_CRYPTO_CRYPTD=3Dy
> CONFIG_CRYPTO_AUTHENC=3Dm
> # CONFIG_CRYPTO_TEST is not set
> CONFIG_CRYPTO_SIMD=3Dy
> CONFIG_CRYPTO_ENGINE=3Dy
>=20
> #
> # Public-key cryptography
> #
> CONFIG_CRYPTO_RSA=3Dy
> CONFIG_CRYPTO_DH=3Dm
> CONFIG_CRYPTO_ECC=3Dm
> CONFIG_CRYPTO_ECDH=3Dm
> # CONFIG_CRYPTO_ECRDSA is not set
> # CONFIG_CRYPTO_SM2 is not set
> # CONFIG_CRYPTO_CURVE25519 is not set
>=20
> #
> # Authenticated Encryption with Associated Data
> #
> CONFIG_CRYPTO_CCM=3Dm
> CONFIG_CRYPTO_GCM=3Dm
> # CONFIG_CRYPTO_CHACHA20POLY1305 is not set
> # CONFIG_CRYPTO_AEGIS128 is not set
> # CONFIG_CRYPTO_SEQIV is not set
> CONFIG_CRYPTO_ECHAINIV=3Dy
>=20
> #
> # Block modes
> #
> CONFIG_CRYPTO_CBC=3Dy
> # CONFIG_CRYPTO_CFB is not set
> CONFIG_CRYPTO_CTR=3Dm
> # CONFIG_CRYPTO_CTS is not set
> CONFIG_CRYPTO_ECB=3Dy
> # CONFIG_CRYPTO_LRW is not set
> # CONFIG_CRYPTO_OFB is not set
> # CONFIG_CRYPTO_PCBC is not set
> CONFIG_CRYPTO_XTS=3Dm
> # CONFIG_CRYPTO_KEYWRAP is not set
> # CONFIG_CRYPTO_ADIANTUM is not set
> # CONFIG_CRYPTO_ESSIV is not set
>=20
> #
> # Hash modes
> #
> CONFIG_CRYPTO_CMAC=3Dm
> CONFIG_CRYPTO_HMAC=3Dy
> # CONFIG_CRYPTO_XCBC is not set
> # CONFIG_CRYPTO_VMAC is not set
>=20
> #
> # Digest
> #
> CONFIG_CRYPTO_CRC32C=3Dy
> # CONFIG_CRYPTO_CRC32 is not set
> CONFIG_CRYPTO_XXHASH=3Dm
> CONFIG_CRYPTO_BLAKE2B=3Dm
> # CONFIG_CRYPTO_BLAKE2S is not set
> CONFIG_CRYPTO_CRCT10DIF=3Dy
> CONFIG_CRYPTO_GHASH=3Dm
> # CONFIG_CRYPTO_POLY1305 is not set
> # CONFIG_CRYPTO_MD4 is not set
> CONFIG_CRYPTO_MD5=3Dm
> # CONFIG_CRYPTO_MICHAEL_MIC is not set
> # CONFIG_CRYPTO_RMD128 is not set
> # CONFIG_CRYPTO_RMD160 is not set
> # CONFIG_CRYPTO_RMD256 is not set
> # CONFIG_CRYPTO_RMD320 is not set
> CONFIG_CRYPTO_SHA1=3Dy
> CONFIG_CRYPTO_SHA256=3Dy
> CONFIG_CRYPTO_SHA512=3Dm
> CONFIG_CRYPTO_SHA3=3Dm
> CONFIG_CRYPTO_SM3=3Dm
> # CONFIG_CRYPTO_STREEBOG is not set
> # CONFIG_CRYPTO_TGR192 is not set
> # CONFIG_CRYPTO_WP512 is not set
>=20
> #
> # Ciphers
> #
> CONFIG_CRYPTO_AES=3Dy
> # CONFIG_CRYPTO_AES_TI is not set
> # CONFIG_CRYPTO_ANUBIS is not set
> # CONFIG_CRYPTO_ARC4 is not set
> # CONFIG_CRYPTO_BLOWFISH is not set
> # CONFIG_CRYPTO_CAMELLIA is not set
> # CONFIG_CRYPTO_CAST5 is not set
> # CONFIG_CRYPTO_CAST6 is not set
> CONFIG_CRYPTO_DES=3Dm
> # CONFIG_CRYPTO_FCRYPT is not set
> # CONFIG_CRYPTO_KHAZAD is not set
> # CONFIG_CRYPTO_SALSA20 is not set
> # CONFIG_CRYPTO_CHACHA20 is not set
> # CONFIG_CRYPTO_SEED is not set
> # CONFIG_CRYPTO_SERPENT is not set
> CONFIG_CRYPTO_SM4=3Dm
> # CONFIG_CRYPTO_TEA is not set
> # CONFIG_CRYPTO_TWOFISH is not set
>=20
> #
> # Compression
> #
> CONFIG_CRYPTO_DEFLATE=3Dy
> # CONFIG_CRYPTO_LZO is not set
> # CONFIG_CRYPTO_842 is not set
> # CONFIG_CRYPTO_LZ4 is not set
> # CONFIG_CRYPTO_LZ4HC is not set
> # CONFIG_CRYPTO_ZSTD is not set
>=20
> #
> # Random Number Generation
> #
> CONFIG_CRYPTO_ANSI_CPRNG=3Dy
> CONFIG_CRYPTO_DRBG_MENU=3Dy
> CONFIG_CRYPTO_DRBG_HMAC=3Dy
> # CONFIG_CRYPTO_DRBG_HASH is not set
> # CONFIG_CRYPTO_DRBG_CTR is not set
> CONFIG_CRYPTO_DRBG=3Dy
> CONFIG_CRYPTO_JITTERENTROPY=3Dy
> CONFIG_CRYPTO_USER_API=3Dm
> # CONFIG_CRYPTO_USER_API_HASH is not set
> # CONFIG_CRYPTO_USER_API_SKCIPHER is not set
> CONFIG_CRYPTO_USER_API_RNG=3Dm
> # CONFIG_CRYPTO_USER_API_RNG_CAVP is not set
> # CONFIG_CRYPTO_USER_API_AEAD is not set
> CONFIG_CRYPTO_USER_API_ENABLE_OBSOLETE=3Dy
> CONFIG_CRYPTO_HASH_INFO=3Dy
>=20
> #
> # Crypto library routines
> #
> CONFIG_CRYPTO_LIB_AES=3Dy
> CONFIG_CRYPTO_LIB_ARC4=3Dm
> # CONFIG_CRYPTO_LIB_BLAKE2S is not set
> CONFIG_CRYPTO_ARCH_HAVE_LIB_CHACHA=3Dm
> CONFIG_CRYPTO_LIB_CHACHA_GENERIC=3Dm
> # CONFIG_CRYPTO_LIB_CHACHA is not set
> # CONFIG_CRYPTO_LIB_CURVE25519 is not set
> CONFIG_CRYPTO_LIB_DES=3Dm
> CONFIG_CRYPTO_LIB_POLY1305_RSIZE=3D9
> # CONFIG_CRYPTO_LIB_POLY1305 is not set
> # CONFIG_CRYPTO_LIB_CHACHA20POLY1305 is not set
> CONFIG_CRYPTO_LIB_SHA256=3Dy
> CONFIG_CRYPTO_HW=3Dy
> CONFIG_CRYPTO_DEV_ALLWINNER=3Dy
> # CONFIG_CRYPTO_DEV_SUN4I_SS is not set
> CONFIG_CRYPTO_DEV_SUN8I_CE=3Dm
> # CONFIG_CRYPTO_DEV_SUN8I_CE_DEBUG is not set
> # CONFIG_CRYPTO_DEV_SUN8I_CE_HASH is not set
> # CONFIG_CRYPTO_DEV_SUN8I_CE_PRNG is not set
> # CONFIG_CRYPTO_DEV_SUN8I_CE_TRNG is not set
> # CONFIG_CRYPTO_DEV_SUN8I_SS is not set
> CONFIG_CRYPTO_DEV_FSL_CAAM_COMMON=3Dm
> CONFIG_CRYPTO_DEV_FSL_CAAM_CRYPTO_API_DESC=3Dm
> CONFIG_CRYPTO_DEV_FSL_CAAM_AHASH_API_DESC=3Dm
> CONFIG_CRYPTO_DEV_FSL_CAAM=3Dm
> # CONFIG_CRYPTO_DEV_FSL_CAAM_DEBUG is not set
> CONFIG_CRYPTO_DEV_FSL_CAAM_JR=3Dm
> CONFIG_CRYPTO_DEV_FSL_CAAM_RINGSIZE=3D9
> # CONFIG_CRYPTO_DEV_FSL_CAAM_INTC is not set
> CONFIG_CRYPTO_DEV_FSL_CAAM_CRYPTO_API=3Dy
> CONFIG_CRYPTO_DEV_FSL_CAAM_CRYPTO_API_QI=3Dy
> CONFIG_CRYPTO_DEV_FSL_CAAM_AHASH_API=3Dy
> CONFIG_CRYPTO_DEV_FSL_CAAM_PKC_API=3Dy
> CONFIG_CRYPTO_DEV_FSL_CAAM_RNG_API=3Dy
> CONFIG_CRYPTO_DEV_FSL_DPAA2_CAAM=3Dm
> # CONFIG_CRYPTO_DEV_SAHARA is not set
> # CONFIG_CRYPTO_DEV_EXYNOS_RNG is not set
> # CONFIG_CRYPTO_DEV_S5P is not set
> # CONFIG_CRYPTO_DEV_ATMEL_ECC is not set
> # CONFIG_CRYPTO_DEV_ATMEL_SHA204A is not set
> # CONFIG_CRYPTO_DEV_CCP is not set
> # CONFIG_CRYPTO_DEV_MXS_DCP is not set
> # CONFIG_CAVIUM_CPT is not set
> # CONFIG_CRYPTO_DEV_NITROX_CNN55XX is not set
> # CONFIG_CRYPTO_DEV_MARVELL_CESA is not set
> # CONFIG_CRYPTO_DEV_OCTEONTX_CPT is not set
> # CONFIG_CRYPTO_DEV_CAVIUM_ZIP is not set
> # CONFIG_CRYPTO_DEV_QCE is not set
> CONFIG_CRYPTO_DEV_QCOM_RNG=3Dm
> # CONFIG_CRYPTO_DEV_ROCKCHIP is not set
> # CONFIG_CRYPTO_DEV_ZYNQMP_AES is not set
> CONFIG_CRYPTO_DEV_VIRTIO=3Dm
> CONFIG_CRYPTO_DEV_BCM_SPU=3Dm
> # CONFIG_CRYPTO_DEV_SAFEXCEL is not set
> CONFIG_CRYPTO_DEV_CCREE=3Dm
> # CONFIG_CRYPTO_DEV_HISI_SEC is not set
> CONFIG_CRYPTO_DEV_HISI_SEC2=3Dm
> CONFIG_CRYPTO_DEV_HISI_QM=3Dm
> CONFIG_CRYPTO_DEV_HISI_ZIP=3Dm
> CONFIG_CRYPTO_DEV_HISI_HPRE=3Dm
> CONFIG_CRYPTO_DEV_AMLOGIC_GXL=3Dy
> # CONFIG_CRYPTO_DEV_AMLOGIC_GXL_DEBUG is not set
> # CONFIG_CRYPTO_DEV_SA2UL is not set
> CONFIG_ASYMMETRIC_KEY_TYPE=3Dy
> CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=3Dy
> CONFIG_X509_CERTIFICATE_PARSER=3Dy
> # CONFIG_PKCS8_PRIVATE_KEY_PARSER is not set
> CONFIG_PKCS7_MESSAGE_PARSER=3Dy
> # CONFIG_PKCS7_TEST_KEY is not set
> # CONFIG_SIGNED_PE_FILE_VERIFICATION is not set
>=20
> #
> # Certificates for signature checking
> #
> CONFIG_SYSTEM_TRUSTED_KEYRING=3Dy
> CONFIG_SYSTEM_TRUSTED_KEYS=3D""
> # CONFIG_SYSTEM_EXTRA_CERTIFICATE is not set
> # CONFIG_SECONDARY_TRUSTED_KEYRING is not set
> # CONFIG_SYSTEM_BLACKLIST_KEYRING is not set
> # end of Certificates for signature checking
>=20
> CONFIG_BINARY_PRINTF=3Dy
>=20
> #
> # Library routines
> #
> CONFIG_RAID6_PQ=3Dm
> CONFIG_RAID6_PQ_BENCHMARK=3Dy
> CONFIG_LINEAR_RANGES=3Dy
> CONFIG_PACKING=3Dy
> CONFIG_BITREVERSE=3Dy
> CONFIG_HAVE_ARCH_BITREVERSE=3Dy
> CONFIG_GENERIC_STRNCPY_FROM_USER=3Dy
> CONFIG_GENERIC_STRNLEN_USER=3Dy
> CONFIG_GENERIC_NET_UTILS=3Dy
> # CONFIG_CORDIC is not set
> # CONFIG_PRIME_NUMBERS is not set
> CONFIG_RATIONAL=3Dy
> CONFIG_GENERIC_PCI_IOMAP=3Dy
> CONFIG_ARCH_USE_CMPXCHG_LOCKREF=3Dy
> CONFIG_ARCH_HAS_FAST_MULTIPLIER=3Dy
> CONFIG_ARCH_USE_SYM_ANNOTATIONS=3Dy
> CONFIG_INDIRECT_PIO=3Dy
> CONFIG_CRC_CCITT=3Dm
> CONFIG_CRC16=3Dy
> CONFIG_CRC_T10DIF=3Dy
> CONFIG_CRC_ITU_T=3Dy
> CONFIG_CRC32=3Dy
> # CONFIG_CRC32_SELFTEST is not set
> CONFIG_CRC32_SLICEBY8=3Dy
> # CONFIG_CRC32_SLICEBY4 is not set
> # CONFIG_CRC32_SARWATE is not set
> # CONFIG_CRC32_BIT is not set
> # CONFIG_CRC64 is not set
> # CONFIG_CRC4 is not set
> CONFIG_CRC7=3Dy
> CONFIG_LIBCRC32C=3Dm
> # CONFIG_CRC8 is not set
> CONFIG_XXHASH=3Dy
> CONFIG_AUDIT_GENERIC=3Dy
> CONFIG_AUDIT_ARCH_COMPAT_GENERIC=3Dy
> CONFIG_AUDIT_COMPAT_GENERIC=3Dy
> # CONFIG_RANDOM32_SELFTEST is not set
> CONFIG_ZLIB_INFLATE=3Dy
> CONFIG_ZLIB_DEFLATE=3Dy
> CONFIG_LZO_COMPRESS=3Dy
> CONFIG_LZO_DECOMPRESS=3Dy
> CONFIG_LZ4_DECOMPRESS=3Dy
> CONFIG_ZSTD_COMPRESS=3Dm
> CONFIG_ZSTD_DECOMPRESS=3Dy
> CONFIG_XZ_DEC=3Dy
> CONFIG_XZ_DEC_X86=3Dy
> CONFIG_XZ_DEC_POWERPC=3Dy
> CONFIG_XZ_DEC_IA64=3Dy
> CONFIG_XZ_DEC_ARM=3Dy
> CONFIG_XZ_DEC_ARMTHUMB=3Dy
> CONFIG_XZ_DEC_SPARC=3Dy
> CONFIG_XZ_DEC_BCJ=3Dy
> # CONFIG_XZ_DEC_TEST is not set
> CONFIG_DECOMPRESS_GZIP=3Dy
> CONFIG_DECOMPRESS_BZIP2=3Dy
> CONFIG_DECOMPRESS_LZMA=3Dy
> CONFIG_DECOMPRESS_XZ=3Dy
> CONFIG_DECOMPRESS_LZO=3Dy
> CONFIG_DECOMPRESS_LZ4=3Dy
> CONFIG_DECOMPRESS_ZSTD=3Dy
> CONFIG_GENERIC_ALLOCATOR=3Dy
> CONFIG_INTERVAL_TREE=3Dy
> CONFIG_XARRAY_MULTI=3Dy
> CONFIG_ASSOCIATIVE_ARRAY=3Dy
> CONFIG_HAS_IOMEM=3Dy
> CONFIG_HAS_IOPORT_MAP=3Dy
> CONFIG_HAS_DMA=3Dy
> CONFIG_DMA_OPS=3Dy
> CONFIG_NEED_SG_DMA_LENGTH=3Dy
> CONFIG_NEED_DMA_MAP_STATE=3Dy
> CONFIG_ARCH_DMA_ADDR_T_64BIT=3Dy
> CONFIG_DMA_DECLARE_COHERENT=3Dy
> CONFIG_ARCH_HAS_SETUP_DMA_OPS=3Dy
> CONFIG_ARCH_HAS_TEARDOWN_DMA_OPS=3Dy
> CONFIG_ARCH_HAS_SYNC_DMA_FOR_DEVICE=3Dy
> CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU=3Dy
> CONFIG_ARCH_HAS_DMA_PREP_COHERENT=3Dy
> CONFIG_SWIOTLB=3Dy
> CONFIG_DMA_NONCOHERENT_MMAP=3Dy
> CONFIG_DMA_COHERENT_POOL=3Dy
> CONFIG_DMA_REMAP=3Dy
> CONFIG_DMA_DIRECT_REMAP=3Dy
> CONFIG_DMA_CMA=3Dy
> CONFIG_DMA_PERNUMA_CMA=3Dy
>=20
> #
> # Default contiguous memory area size:
> #
> CONFIG_CMA_SIZE_MBYTES=3D32
> CONFIG_CMA_SIZE_SEL_MBYTES=3Dy
> # CONFIG_CMA_SIZE_SEL_PERCENTAGE is not set
> # CONFIG_CMA_SIZE_SEL_MIN is not set
> # CONFIG_CMA_SIZE_SEL_MAX is not set
> CONFIG_CMA_ALIGNMENT=3D8
> # CONFIG_DMA_API_DEBUG is not set
> CONFIG_SGL_ALLOC=3Dy
> CONFIG_CPU_RMAP=3Dy
> CONFIG_DQL=3Dy
> CONFIG_GLOB=3Dy
> # CONFIG_GLOB_SELFTEST is not set
> CONFIG_NLATTR=3Dy
> CONFIG_CLZ_TAB=3Dy
> CONFIG_IRQ_POLL=3Dy
> CONFIG_MPILIB=3Dy
> CONFIG_DIMLIB=3Dy
> CONFIG_LIBFDT=3Dy
> CONFIG_OID_REGISTRY=3Dy
> CONFIG_UCS2_STRING=3Dy
> CONFIG_HAVE_GENERIC_VDSO=3Dy
> CONFIG_GENERIC_GETTIMEOFDAY=3Dy
> CONFIG_GENERIC_VDSO_TIME_NS=3Dy
> CONFIG_FONT_SUPPORT=3Dy
> # CONFIG_FONTS is not set
> CONFIG_FONT_8x8=3Dy
> CONFIG_FONT_8x16=3Dy
> CONFIG_SG_POOL=3Dy
> CONFIG_ARCH_STACKWALK=3Dy
> CONFIG_SBITMAP=3Dy
> # CONFIG_STRING_SELFTEST is not set
> # end of Library routines
>=20
> #
> # Kernel hacking
> #
>=20
> #
> # printk and dmesg options
> #
> CONFIG_PRINTK_TIME=3Dy
> # CONFIG_PRINTK_CALLER is not set
> CONFIG_CONSOLE_LOGLEVEL_DEFAULT=3D7
> CONFIG_CONSOLE_LOGLEVEL_QUIET=3D4
> CONFIG_MESSAGE_LOGLEVEL_DEFAULT=3D4
> # CONFIG_BOOT_PRINTK_DELAY is not set
> # CONFIG_DYNAMIC_DEBUG is not set
> # CONFIG_DYNAMIC_DEBUG_CORE is not set
> CONFIG_SYMBOLIC_ERRNAME=3Dy
> CONFIG_DEBUG_BUGVERBOSE=3Dy
> # end of printk and dmesg options
>=20
> #
> # Compile-time checks and compiler options
> #
> CONFIG_DEBUG_INFO=3Dy
> # CONFIG_DEBUG_INFO_REDUCED is not set
> # CONFIG_DEBUG_INFO_COMPRESSED is not set
> # CONFIG_DEBUG_INFO_SPLIT is not set
> # CONFIG_DEBUG_INFO_DWARF4 is not set
> # CONFIG_DEBUG_INFO_BTF is not set
> CONFIG_GDB_SCRIPTS=3Dy
> CONFIG_ENABLE_MUST_CHECK=3Dy
> CONFIG_FRAME_WARN=3D2048
> # CONFIG_STRIP_ASM_SYMS is not set
> # CONFIG_READABLE_ASM is not set
> # CONFIG_HEADERS_INSTALL is not set
> # CONFIG_DEBUG_SECTION_MISMATCH is not set
> CONFIG_SECTION_MISMATCH_WARN_ONLY=3Dy
> CONFIG_ARCH_WANT_FRAME_POINTERS=3Dy
> CONFIG_FRAME_POINTER=3Dy
> # CONFIG_DEBUG_FORCE_WEAK_PER_CPU is not set
> # end of Compile-time checks and compiler options
>=20
> #
> # Generic Kernel Debugging Instruments
> #
> CONFIG_MAGIC_SYSRQ=3Dy
> CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE=3D0x1
> CONFIG_MAGIC_SYSRQ_SERIAL=3Dy
> CONFIG_MAGIC_SYSRQ_SERIAL_SEQUENCE=3D""
> CONFIG_DEBUG_FS=3Dy
> CONFIG_DEBUG_FS_ALLOW_ALL=3Dy
> # CONFIG_DEBUG_FS_DISALLOW_MOUNT is not set
> # CONFIG_DEBUG_FS_ALLOW_NONE is not set
> CONFIG_HAVE_ARCH_KGDB=3Dy
> # CONFIG_KGDB is not set
> CONFIG_ARCH_HAS_UBSAN_SANITIZE_ALL=3Dy
> # CONFIG_UBSAN is not set
> # end of Generic Kernel Debugging Instruments
>=20
> CONFIG_DEBUG_KERNEL=3Dy
> CONFIG_DEBUG_MISC=3Dy
>=20
> #
> # Memory Debugging
> #
> # CONFIG_PAGE_EXTENSION is not set
> # CONFIG_DEBUG_PAGEALLOC is not set
> # CONFIG_PAGE_OWNER is not set
> # CONFIG_PAGE_POISONING is not set
> # CONFIG_DEBUG_PAGE_REF is not set
> # CONFIG_DEBUG_RODATA_TEST is not set
> CONFIG_ARCH_HAS_DEBUG_WX=3Dy
> # CONFIG_DEBUG_WX is not set
> CONFIG_GENERIC_PTDUMP=3Dy
> # CONFIG_PTDUMP_DEBUGFS is not set
> # CONFIG_DEBUG_OBJECTS is not set
> # CONFIG_SLUB_DEBUG_ON is not set
> # CONFIG_SLUB_STATS is not set
> CONFIG_HAVE_DEBUG_KMEMLEAK=3Dy
> # CONFIG_DEBUG_KMEMLEAK is not set
> # CONFIG_DEBUG_STACK_USAGE is not set
> # CONFIG_SCHED_STACK_END_CHECK is not set
> CONFIG_ARCH_HAS_DEBUG_VM_PGTABLE=3Dy
> # CONFIG_DEBUG_VM is not set
> # CONFIG_DEBUG_VM_PGTABLE is not set
> CONFIG_ARCH_HAS_DEBUG_VIRTUAL=3Dy
> CONFIG_DEBUG_VIRTUAL=3Dy
> CONFIG_DEBUG_MEMORY_INIT=3Dy
> # CONFIG_DEBUG_PER_CPU_MAPS is not set
> CONFIG_HAVE_ARCH_KASAN=3Dy
> CONFIG_HAVE_ARCH_KASAN_SW_TAGS=3Dy
> CONFIG_CC_HAS_KASAN_GENERIC=3Dy
> CONFIG_HAVE_ARCH_KFENCE=3Dy
> # CONFIG_KFENCE is not set
> # end of Memory Debugging
>=20
> # CONFIG_DEBUG_SHIRQ is not set
>=20
> #
> # Debug Oops, Lockups and Hangs
> #
> # CONFIG_PANIC_ON_OOPS is not set
> CONFIG_PANIC_ON_OOPS_VALUE=3D0
> CONFIG_PANIC_TIMEOUT=3D0
> # CONFIG_SOFTLOCKUP_DETECTOR is not set
> CONFIG_DETECT_HUNG_TASK=3Dy
> CONFIG_DEFAULT_HUNG_TASK_TIMEOUT=3D10
> CONFIG_BOOTPARAM_HUNG_TASK_PANIC=3Dy
> CONFIG_BOOTPARAM_HUNG_TASK_PANIC_VALUE=3D1
> CONFIG_WQ_WATCHDOG=3Dy
> # CONFIG_TEST_LOCKUP is not set
> # end of Debug Oops, Lockups and Hangs
>=20
> #
> # Scheduler Debugging
> #
> # CONFIG_SCHED_DEBUG is not set
> CONFIG_SCHED_INFO=3Dy
> # CONFIG_SCHEDSTATS is not set
> # end of Scheduler Debugging
>=20
> # CONFIG_DEBUG_TIMEKEEPING is not set
> CONFIG_DEBUG_PREEMPT=3Dy
>=20
> #
> # Lock Debugging (spinlocks, mutexes, etc...)
> #
> CONFIG_LOCK_DEBUGGING_SUPPORT=3Dy
> CONFIG_PROVE_LOCKING=3Dy
> # CONFIG_PROVE_RAW_LOCK_NESTING is not set
> # CONFIG_LOCK_STAT is not set
> CONFIG_DEBUG_RT_MUTEXES=3Dy
> CONFIG_DEBUG_SPINLOCK=3Dy
> CONFIG_DEBUG_MUTEXES=3Dy
> CONFIG_DEBUG_WW_MUTEX_SLOWPATH=3Dy
> CONFIG_DEBUG_RWSEMS=3Dy
> CONFIG_DEBUG_LOCK_ALLOC=3Dy
> CONFIG_LOCKDEP=3Dy
> CONFIG_DEBUG_LOCKDEP=3Dy
> # CONFIG_DEBUG_ATOMIC_SLEEP is not set
> # CONFIG_DEBUG_LOCKING_API_SELFTESTS is not set
> CONFIG_LOCK_TORTURE_TEST=3Dm
> # CONFIG_WW_MUTEX_SELFTEST is not set
> # CONFIG_SCF_TORTURE_TEST is not set
> # CONFIG_CSD_LOCK_WAIT_DEBUG is not set
> # end of Lock Debugging (spinlocks, mutexes, etc...)
>=20
> CONFIG_TRACE_IRQFLAGS=3Dy
> CONFIG_STACKTRACE=3Dy
> # CONFIG_WARN_ALL_UNSEEDED_RANDOM is not set
> # CONFIG_DEBUG_KOBJECT is not set
> CONFIG_HAVE_DEBUG_BUGVERBOSE=3Dy
>=20
> #
> # Debug kernel data structures
> #
> CONFIG_DEBUG_LIST=3Dy
> # CONFIG_DEBUG_PLIST is not set
> # CONFIG_DEBUG_SG is not set
> # CONFIG_DEBUG_NOTIFIERS is not set
> # CONFIG_BUG_ON_DATA_CORRUPTION is not set
> # end of Debug kernel data structures
>=20
> # CONFIG_DEBUG_CREDENTIALS is not set
>=20
> #
> # RCU Debugging
> #
> CONFIG_PROVE_RCU=3Dy
> CONFIG_TORTURE_TEST=3Dm
> # CONFIG_RCU_SCALE_TEST is not set
> CONFIG_RCU_TORTURE_TEST=3Dm
> # CONFIG_RCU_REF_SCALE_TEST is not set
> CONFIG_RCU_CPU_STALL_TIMEOUT=3D21
> CONFIG_RCU_TRACE=3Dy
> # CONFIG_RCU_EQS_DEBUG is not set
> # end of RCU Debugging
>=20
> # CONFIG_DEBUG_WQ_FORCE_RR_CPU is not set
> # CONFIG_DEBUG_BLOCK_EXT_DEVT is not set
> # CONFIG_CPU_HOTPLUG_STATE_CONTROL is not set
> # CONFIG_LATENCYTOP is not set
> CONFIG_NOP_TRACER=3Dy
> CONFIG_HAVE_FUNCTION_TRACER=3Dy
> CONFIG_HAVE_FUNCTION_GRAPH_TRACER=3Dy
> CONFIG_HAVE_DYNAMIC_FTRACE=3Dy
> CONFIG_HAVE_FTRACE_MCOUNT_RECORD=3Dy
> CONFIG_HAVE_SYSCALL_TRACEPOINTS=3Dy
> CONFIG_HAVE_C_RECORDMCOUNT=3Dy
> CONFIG_TRACER_MAX_TRACE=3Dy
> CONFIG_TRACE_CLOCK=3Dy
> CONFIG_RING_BUFFER=3Dy
> CONFIG_EVENT_TRACING=3Dy
> CONFIG_CONTEXT_SWITCH_TRACER=3Dy
> CONFIG_RING_BUFFER_ALLOW_SWAP=3Dy
> CONFIG_PREEMPTIRQ_TRACEPOINTS=3Dy
> CONFIG_TRACING=3Dy
> CONFIG_GENERIC_TRACER=3Dy
> CONFIG_TRACING_SUPPORT=3Dy
> CONFIG_FTRACE=3Dy
> # CONFIG_BOOTTIME_TRACING is not set
> CONFIG_FUNCTION_TRACER=3Dy
> CONFIG_FUNCTION_GRAPH_TRACER=3Dy
> CONFIG_DYNAMIC_FTRACE=3Dy
> # CONFIG_FUNCTION_PROFILER is not set
> CONFIG_STACK_TRACER=3Dy
> CONFIG_TRACE_PREEMPT_TOGGLE=3Dy
> CONFIG_IRQSOFF_TRACER=3Dy
> CONFIG_PREEMPT_TRACER=3Dy
> CONFIG_SCHED_TRACER=3Dy
> CONFIG_HWLAT_TRACER=3Dy
> CONFIG_FTRACE_SYSCALLS=3Dy
> CONFIG_TRACER_SNAPSHOT=3Dy
> CONFIG_TRACER_SNAPSHOT_PER_CPU_SWAP=3Dy
> CONFIG_BRANCH_PROFILE_NONE=3Dy
> # CONFIG_PROFILE_ANNOTATED_BRANCHES is not set
> # CONFIG_PROFILE_ALL_BRANCHES is not set
> CONFIG_BLK_DEV_IO_TRACE=3Dy
> CONFIG_UPROBE_EVENTS=3Dy
> CONFIG_DYNAMIC_EVENTS=3Dy
> CONFIG_PROBE_EVENTS=3Dy
> CONFIG_FTRACE_MCOUNT_RECORD=3Dy
> # CONFIG_SYNTH_EVENTS is not set
> # CONFIG_HIST_TRIGGERS is not set
> CONFIG_TRACE_EVENT_INJECT=3Dy
> CONFIG_TRACEPOINT_BENCHMARK=3Dy
> # CONFIG_RING_BUFFER_BENCHMARK is not set
> CONFIG_TRACE_EVAL_MAP_FILE=3Dy
> CONFIG_FTRACE_SELFTEST=3Dy
> CONFIG_FTRACE_STARTUP_TEST=3Dy
> CONFIG_EVENT_TRACE_STARTUP_TEST=3Dy
> CONFIG_EVENT_TRACE_TEST_SYSCALLS=3Dy
> # CONFIG_RING_BUFFER_STARTUP_TEST is not set
> CONFIG_PREEMPTIRQ_DELAY_TEST=3Dm
> # CONFIG_SAMPLES is not set
> CONFIG_ARCH_HAS_DEVMEM_IS_ALLOWED=3Dy
> CONFIG_STRICT_DEVMEM=3Dy
> # CONFIG_IO_STRICT_DEVMEM is not set
>=20
> #
> # arm64 Debugging
> #
> # CONFIG_DEBUG_AID_FOR_SYZBOT is not set
> # CONFIG_PID_IN_CONTEXTIDR is not set
> # CONFIG_DEBUG_EFI is not set
> # CONFIG_ARM64_RELOC_TEST is not set
> # CONFIG_CORESIGHT is not set
> # end of arm64 Debugging
>=20
> #
> # Kernel Testing and Coverage
> #
> CONFIG_KUNIT=3Dy
> CONFIG_KUNIT_DEBUGFS=3Dy
> # CONFIG_KUNIT_TEST is not set
> # CONFIG_KUNIT_EXAMPLE_TEST is not set
> # CONFIG_KUNIT_ALL_TESTS is not set
> # CONFIG_NOTIFIER_ERROR_INJECTION is not set
> # CONFIG_FAULT_INJECTION is not set
> CONFIG_ARCH_HAS_KCOV=3Dy
> CONFIG_CC_HAS_SANCOV_TRACE_PC=3Dy
> CONFIG_KCOV=3Dy
> CONFIG_KCOV_INSTRUMENT_ALL=3Dy
> CONFIG_KCOV_IRQ_AREA_SIZE=3D0x40000
> CONFIG_RUNTIME_TESTING_MENU=3Dy
> CONFIG_LKDTM=3Dm
> CONFIG_TEST_LIST_SORT=3Dm
> # CONFIG_TEST_MIN_HEAP is not set
> CONFIG_TEST_SORT=3Dm
> CONFIG_BACKTRACE_SELF_TEST=3Dm
> # CONFIG_RBTREE_TEST is not set
> # CONFIG_REED_SOLOMON_TEST is not set
> # CONFIG_INTERVAL_TREE_TEST is not set
> # CONFIG_PERCPU_TEST is not set
> # CONFIG_ATOMIC64_SELFTEST is not set
> CONFIG_TEST_HEXDUMP=3Dm
> CONFIG_TEST_STRING_HELPERS=3Dm
> CONFIG_TEST_STRSCPY=3Dm
> CONFIG_TEST_KSTRTOX=3Dm
> CONFIG_TEST_PRINTF=3Dm
> CONFIG_TEST_BITMAP=3Dm
> CONFIG_TEST_UUID=3Dm
> CONFIG_TEST_XARRAY=3Dm
> CONFIG_TEST_OVERFLOW=3Dm
> CONFIG_TEST_RHASHTABLE=3Dm
> CONFIG_TEST_HASH=3Dm
> CONFIG_TEST_IDA=3Dm
> CONFIG_TEST_LKM=3Dm
> # CONFIG_TEST_BITOPS is not set
> CONFIG_TEST_VMALLOC=3Dm
> CONFIG_TEST_USER_COPY=3Dm
> CONFIG_TEST_BPF=3Dm
> # CONFIG_TEST_BLACKHOLE_DEV is not set
> # CONFIG_FIND_BIT_BENCHMARK is not set
> CONFIG_TEST_FIRMWARE=3Dm
> CONFIG_TEST_SYSCTL=3Dm
> # CONFIG_BITFIELD_KUNIT is not set
> # CONFIG_SYSCTL_KUNIT_TEST is not set
> # CONFIG_LIST_KUNIT_TEST is not set
> # CONFIG_LINEAR_RANGES_TEST is not set
> # CONFIG_BITS_TEST is not set
> CONFIG_TEST_UDELAY=3Dm
> CONFIG_TEST_STATIC_KEYS=3Dm
> CONFIG_TEST_KMOD=3Dm
> # CONFIG_TEST_DEBUG_VIRTUAL is not set
> CONFIG_TEST_MEMCAT_P=3Dm
> CONFIG_TEST_STACKINIT=3Dm
> # CONFIG_TEST_MEMINIT is not set
> # CONFIG_TEST_FREE_PAGES is not set
> CONFIG_MEMTEST=3Dy
> # end of Kernel Testing and Coverage
> # end of Kernel hacking

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201111182108.GZ3249%40paulmck-ThinkPad-P72.
