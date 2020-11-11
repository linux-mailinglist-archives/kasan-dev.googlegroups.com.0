Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPW5WD6QKGQE66AAOLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 475872AF7FE
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 19:34:39 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id dj19sf1198217edb.13
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 10:34:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605119679; cv=pass;
        d=google.com; s=arc-20160816;
        b=t9xuxCCi8bIX3VxeBUyE2zDtIivCb1dVVPBdhzUL7CoBrpX5FP7lhX85286Vp6Dn4n
         HNaOyRmaVu+gCOujEnUWfSvjxRPYd7E/O98PS/x8d38T+R9mhl+79SRzCHI/8WDlL1q0
         W7opY1xhcrYS9x9+w0Mxra83EmLrtLGuBGHJHz6nytU4yOPTVKjvx6vlPI0Pk8bBHzds
         AS/CPIjKoqYworP3/yheMYldhW2AHeHK6Oap1FtBtSj81dUW0Y09Ab2ZXQKXtBWfDhCz
         4ugpu76LlOILsm6mftdvNgepAyDh2PEsFqit7+0wpLOFjbKrlA66xAsFwlSyLhMvyCTO
         /t1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=AmpdmhL2WFShn32OoowEaWpAav0+91wdGbj7l3WXFhw=;
        b=T42X+BkaHn7aNF6cBVKFe3cjqdrD6CZu12SohZiseFkWZRHXfCPsCjdCTsBOKIWrKq
         3/4YoQc/nUCbXHI1UbIhq35AbHfhD1i8exD7MHVF/zg3H7ZYd3Sygg7AV/m96whjt88N
         msIjAeXC13JQ+hMwKvp3DoASy9LAEU8BlLui+yVxTyqRaeJlqkW5xE2G7FuoH1HVcny4
         X/0zvpTmcbfXXoN6/N6FNRrjZoHrE23qylQqw+o/X9kf6TMi6CpHzoJZsKTS1sVfKdNf
         yRg+HK72qXOqug3QIxg/krHgNfdS7p/4UinLPU8diaosoSPFeztRGYg6SKhhcjUZKCq/
         Or8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rj5UMYIW;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=AmpdmhL2WFShn32OoowEaWpAav0+91wdGbj7l3WXFhw=;
        b=BR+ISlNE+KC8lUDv5WfnZdMhRZ4wUnpT1ns5FIpzilHwvq6TPaBQ/Ya9L/JlX86IAz
         WNQ4/n8IuUMdDgQVXRIHQ8bN9t4y/pQJngPgyM3upiaBpnzsTQD7ItELnVDGRmG26egd
         3NwS1FRDZ4akqBqZtmwY9BWj/wPweSQX0o7+1MyIOuMcZ6uU0wuXltY6WrcuB6b+Kslr
         iQUxddX5laqNPC7otkaXKhOoFQxFIxYcQNQAcuMu2hrYHmBtobKJ2pITcoBqK9HLS70I
         57gaWMs1YZ/HVwYcMeWOeWRptx/GfxFGd/EktUaM0gGn26I0YPe7jl8OeYMw4401lCeh
         PMVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AmpdmhL2WFShn32OoowEaWpAav0+91wdGbj7l3WXFhw=;
        b=ojzpvTlD1Rd4u3yTk5HCRm91umUE/El+pRygBEqlPYQc68GplXLoJCykFidYdGhI5d
         9DELG647g4ptP22LEijEkqvYXva5/1G/bjuMGe2VhmZPgYDdX+ZnPD1OIDuZlRa5Sh84
         xHV9GtFj8974au7ikk53dQtMAx2B6bIsjGS1TGmttM0hb4GkOsbtpsQHCPzhLFkNk7It
         +N6/gpUUFN37+m85BT+UWSy/LJ+a72pHpjVfuMxqLx9/cdnM0AEhvK/01whkiNjINBy8
         hs+Y3pUGQxFBwQU+SQ82ZfMaC4LCDGKFsYPoT7UszAv7MhZ3SHcUAgI7JcNkq/QFiO1b
         /6fg==
X-Gm-Message-State: AOAM532tvlMmu13uC5sFnKfis9vF+B7PaywXn3o5AQH7cGYJZnpZNuKU
	WBrFJKDMtk7ZPTeYPBZ2LKw=
X-Google-Smtp-Source: ABdhPJxFruX0LOb6ii5wI7Esi5MCLXgruLXKyEmeppWOOsIMxgrDQb277wA9nyuLLw4Grs8i717Tww==
X-Received: by 2002:a50:b584:: with SMTP id a4mr860540ede.301.1605119678976;
        Wed, 11 Nov 2020 10:34:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:b246:: with SMTP id o64ls645678edd.2.gmail; Wed, 11 Nov
 2020 10:34:37 -0800 (PST)
X-Received: by 2002:a50:ec1a:: with SMTP id g26mr945929edr.10.1605119677923;
        Wed, 11 Nov 2020 10:34:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605119677; cv=none;
        d=google.com; s=arc-20160816;
        b=Ayc8M8I2hKzwJKsQ4Nk9UNy4zOMiopRwqficms2J1kz3oxJDKlC0O/+x/UHYDtqTeW
         TJ5eOn4vN1i/6V73EQlWsFtEXzqtJWZKXH3D7Gu/FGtSss3y4URMIXFnh9W6hBNLtJgI
         Cyq80vNUYcLGUiZP7h8BtHB4SB8RhfnKVaDAFyPSJLb+hWADObnjKDoZwYE1zBVysege
         Yf+bSLtqzVIOFFZSD7u0Jik4GJ3dbWItk9l35ADd3IWyxc64tynkuLglqxGq/ODbU8di
         6zZ9cFUUDhiXEpidwc0GAwh8SPdPz4zM3/xLbpD56AgJvDRFGqmLE5AB+YPsdDNvyv7S
         MjDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=vxcKoesuuR8pDNQg4uNFcBd05UOqaWNnyX6PLwZNx7M=;
        b=tV6QAp8UiiyJ577hFBEveou9ZGC1vkPe29J4RWS3/DvJm63C+sax3WmfQAAuA6QwMQ
         oEa8oQyTr3j1+cjI8Gx4I/+Qq/GdgdvBG2zsD2nx7w3XHttAdMAau3c8h7qWOIzyGwJg
         higmS+XLipf4P3a8Dpo1UEthCr8+VEv2j0ilGwGBhhD4ELiqkDr49rUBmjHea2ecY1Ab
         ztGT28zsbY/9FDznNodm7m+7/YCtFv3uYxByQyT0kK60GmvX4g/Gri93YdxN79N+u1hu
         J3Q4vPbHDMN5TC029pa+bhbihxImMETCnRWU+/P7ZIz1GNmSfjYZ99dQ3edmrwrIZnd4
         BrWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rj5UMYIW;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id ss24si50573ejb.1.2020.11.11.10.34.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 10:34:37 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id d12so3458161wrr.13
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 10:34:37 -0800 (PST)
X-Received: by 2002:adf:92e7:: with SMTP id 94mr33490175wrn.271.1605119677378;
        Wed, 11 Nov 2020 10:34:37 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id f19sm3364561wml.21.2020.11.11.10.34.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Nov 2020 10:34:36 -0800 (PST)
Date: Wed, 11 Nov 2020 19:34:30 +0100
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
	peterz@infradead.org
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without
 allocations
Message-ID: <20201111183430.GN517454@elver.google.com>
References: <20201110135320.3309507-1-elver@google.com>
 <CADYN=9+=-ApMi_eEdAeHU6TyuQ7ZJSTQ8F-FCSD33kZH8HR+xg@mail.gmail.com>
 <CANpmjNM8MZphvkTSo=KgCBXQ6fNY4qo6NZD5SBHjNse_L9i5FQ@mail.gmail.com>
 <20201111133813.GA81547@elver.google.com>
 <20201111130543.27d29462@gandalf.local.home>
 <20201111182333.GA3249@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201111182333.GA3249@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rj5UMYIW;       spf=pass
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

On Wed, Nov 11, 2020 at 10:23AM -0800, Paul E. McKenney wrote:
> On Wed, Nov 11, 2020 at 01:05:43PM -0500, Steven Rostedt wrote:
> > On Wed, 11 Nov 2020 14:38:13 +0100
> > Marco Elver <elver@google.com> wrote:
> > 
> > > [+Cc folks who can maybe help figure out what's going on, since I get
> > >   warnings even without KFENCE on next-20201110.]
> > > 
> > > On Wed, Nov 11, 2020 at 09:29AM +0100, Marco Elver wrote:
> > > > On Wed, 11 Nov 2020 at 00:23, Anders Roxell <anders.roxell@linaro.org> wrote:
> > > > [...]
> > > > > I gave them a spin on next-20201105 [1] and on next-20201110 [2].
> > > > >
> > > > > I eventually got to a prompt on next-20201105.
> > > > > However, I got to this kernel panic on the next-20201110:
> > > > >
> > > > > [...]
> > > > > [ 1514.089966][    T1] Testing event system initcall: OK
> > > > > [ 1514.806232][    T1] Running tests on all trace events:
> > > > > [ 1514.857835][    T1] Testing all events:
> > > > > [ 1525.503262][    C0] hrtimer: interrupt took 10902600 ns
> > > > > [ 1623.861452][    C0] BUG: workqueue lockup - pool cpus=0 node=0
> > > > > flags=0x0 nice=0 stuck for 65s!
> > > > > [...]
> > 
> > OK, so this blows up when you enable all events?
> > 
> > Note, it could just be adding overhead (which is exasperated with other
> > debug options enabled), which could open up a race window.
> >  
> > 
> > > > > [ 7823.104349][   T28]       Tainted: G        W
> > > > > 5.10.0-rc3-next-20201110-00008-g8dc06700529d #3
> > > > > [ 7833.206491][   T28] "echo 0 >
> > > > > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
> > > > > [ 7840.750700][   T28] task:kworker/0:1     state:D stack:26640 pid:
> > > > > 1872 ppid:     2 flags:0x00000428
> > > > > [ 7875.642531][   T28] Workqueue: events toggle_allocation_gate
> > > > > [ 7889.178334][   T28] Call trace:
> > > > > [ 7897.066649][   T28]  __switch_to+0x1cc/0x1e0
> > > > > [ 7905.326856][   T28]  0xffff00000f7077b0
> > > > > [ 7928.354644][   T28] INFO: lockdep is turned off.
> > > > > [ 7934.022572][   T28] Kernel panic - not syncing: hung_task: blocked tasks
> > > > > [ 7934.032039][   T28] CPU: 0 PID: 28 Comm: khungtaskd Tainted: G
> > > > >   W         5.10.0-rc3-next-20201110-00008-g8dc06700529d #3
> > > > > [ 7934.045586][   T28] Hardware name: linux,dummy-virt (DT)
> > > > > [ 7934.053677][   T28] Call trace:
> > > > > [ 7934.060276][   T28]  dump_backtrace+0x0/0x420
> > > > > [ 7934.067635][   T28]  show_stack+0x38/0xa0
> > > > > [ 7934.091277][   T28]  dump_stack+0x1d4/0x278
> > > > > [ 7934.098878][   T28]  panic+0x304/0x5d8
> > > > > [ 7934.114923][   T28]  check_hung_uninterruptible_tasks+0x5e4/0x640
> > > > > [ 7934.123823][   T28]  watchdog+0x138/0x160
> > > > > [ 7934.131561][   T28]  kthread+0x23c/0x260
> > > > > [ 7934.138590][   T28]  ret_from_fork+0x10/0x18
> > > > > [ 7934.146631][   T28] Kernel Offset: disabled
> > > > > [ 7934.153749][   T28] CPU features: 0x0240002,20002004
> > > > > [ 7934.161476][   T28] Memory Limit: none
> > > > > [ 7934.171272][   T28] ---[ end Kernel panic - not syncing: hung_task:
> > > > > blocked tasks ]---
> > > > >
> > > > > Cheers,
> > > > > Anders
> > > > > [1] https://people.linaro.org/~anders.roxell/output-next-20201105-test.log
> > > > > [2] https://people.linaro.org/~anders.roxell/output-next-20201110-test.log
> > > > 
> > > > Thanks for testing. The fact that it passes on next-20201105 but not
> > > > on 20201110 is strange. If you boot with KFENCE disabled (boot param
> > > > kfence.sample_interval=0), does it boot?
> > > [...]
> > > 
> > > Right, so I think this is no longer KFENCE's fault. This looks like
> > > something scheduler/RCU/ftrace related?! I notice that there have been
> > > scheduler changes between next-20201105 and next-20201110.
> > 
> > I'm not sure any of that would cause this.
> > 
> > > 
> > > I get this with KFENCE disabled:
> > > 
> > > | Running tests on all trace events:
> > > | Testing all events: 
> > > | BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 32s!
> > > | Showing busy workqueues and worker pools:
> > > | workqueue events: flags=0x0
> > > |   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
> > > |     pending: vmstat_shepherd
> > > | workqueue events_power_efficient: flags=0x82
> > > |   pwq 2: cpus=0 flags=0x5 nice=0 active=2/256 refcnt=4
> > > |     in-flight: 107:neigh_periodic_work
> > > |     pending: do_cache_clean
> > > | pool 2: cpus=0 flags=0x5 nice=0 hung=3s workers=2 manager: 7
> > > | rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
> > > | 	(detected by 0, t=6502 jiffies, g=2885, q=4)
> > > | rcu: All QSes seen, last rcu_preempt kthread activity 5174 (4295523265-4295518091), jiffies_till_next_fqs=1, root ->qsmask 0x0
> > > | rcu: rcu_preempt kthread starved for 5174 jiffies! g2885 f0x2 RCU_GP_WAIT_FQS(5) ->state=0x0 ->cpu=0
> > > | rcu: 	Unless rcu_preempt kthread gets sufficient CPU time, OOM is now expected behavior.
> > > | rcu: RCU grace-period kthread stack dump:
> > > | task:rcu_preempt     state:R  running task     stack:    0 pid:   10 ppid:     2 flags:0x00000428
> > > | Call trace:
> > > |  __switch_to+0x100/0x1e0
> > > |  __schedule+0x2d0/0x890
> > > |  preempt_schedule_notrace+0x70/0x1c0
> > > |  ftrace_ops_no_ops+0x174/0x250
> > > |  ftrace_graph_call+0x0/0xc
> > 
> > Note, just because ftrace is called here, the blocked task was preempted
> > when the ftrace code called preempt_enable_notrace().
> > 
> > 
> > > |  preempt_count_add+0x1c/0x180
> > > |  schedule+0x44/0x108
> > > |  schedule_timeout+0x394/0x530
> > > |  rcu_gp_kthread+0x76c/0x19a8
> > > |  kthread+0x174/0x188
> > > |  ret_from_fork+0x10/0x18
> > > | 
> > > | ================================
> > > | WARNING: inconsistent lock state
> > > | 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #18 Not tainted
> > > | --------------------------------
> > > | inconsistent {IN-HARDIRQ-W} -> {HARDIRQ-ON-W} usage.
> > > | kcompactd0/26 [HC0[0]:SC0[0]:HE0:SE1] takes:
> > > | ffffae32e6bd4358 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x4a0/0xd18
> > > | {IN-HARDIRQ-W} state was registered at:
> > 
> > I did some digging here and it looks like the rcu_node lock could be taken
> > without interrupts enabled when it does a stall print. That probably should
> > be fixed, but it's a symptom of the underlining bug and not the cause.
> 
> Does this patch (in -next) help?
> 
> 							Thanx, Paul
 
>     rcu: Don't invoke try_invoke_on_locked_down_task() with irqs disabled

Sadly, no, next-20201110 already included that one, and that's what I
tested and got me all those warnings above.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111183430.GN517454%40elver.google.com.
