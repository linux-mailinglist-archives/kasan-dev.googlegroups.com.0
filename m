Return-Path: <kasan-dev+bncBAABBNHTWD6QKGQE2UHTOXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C1B32AF8E1
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 20:21:26 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id y7sf1841133pgg.12
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 11:21:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605122484; cv=pass;
        d=google.com; s=arc-20160816;
        b=zQ5/IK1pHegFMdzTO8D/q9rKUty4HfiIjbmBcZ85GTLPbUhZgeuCaLG9fl8va3uAT3
         GNue62CpeJ/uqyg6VbgfEUATZbpBEk0RFnbfRinbFgNpDwttxQIUEAULtTzdN/3723iY
         JZoF94rW8RPa0DfqzZ46MElANW/5NBXNfVz9UUJ9bAg7Tj/9/yxb/zsPUG04Vu4/stDW
         yT9wz9H/7se82nYgaf17Qegr0YuFH+lAR98Se+of7i5/eyUlBkp30a1upZplWLqghewQ
         eOjgFOhEXwZmFPHNItJfhbj/j7GlC1xc5w8/cHkzJHK5twznB9+OfD+p+79W8WKhG2kd
         K0uQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=vWL7kWfPjkbOdS970q5u2jhLwD2u+JCmBLo4eepXUFM=;
        b=JuZnS47wkf0m5ModGAdZh4s9PtAfx1XDZt9JiiFp53JVq7m7I1OeOnzcNWi1SEWdUG
         M3uZX/IKCLI6U+sQnbK3xBMOwJC+F+P7SPWSVvriVnUB7ssAVZbp83uS61q40C6uT0uZ
         lNBenAhZ+CdVNrspaQvUYDB1orU2uBGTMSgj6JZ2Rlc0ZJIo1nHk7b77rbj+7V7LpumX
         OfCmOsHYSid+4IuKoHNEpUiGmbzmukTKZazGxJRnMIUlLDtZ7+iqNczb6Jajpz4lfnlm
         SURqAsVabwnHzM81AS3nOTk77UI8u0MSZROj6HseMJJDYjF0YoAsqpHJJx4FfzzjT/A3
         VYtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=AqZT3O24;
       spf=pass (google.com: domain of srs0=nwwe=er=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=nwWE=ER=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vWL7kWfPjkbOdS970q5u2jhLwD2u+JCmBLo4eepXUFM=;
        b=ZJ/g2nJTElSj5uEsiSPNmJjzJxClb4htxG8fBuYUA7kNnUoO4jCKqRjJK6cm15L4eZ
         +fNuWwZDB08dr69sbY5LzAHmCqhP5sI+j5VaMdiHzcBHS04voTLzthiue3lL1N4Tm6kd
         DughM6glloifgFMKVgYXfcjMv5OlODVRcCWYRnnhK0Yl2vKPL3ZF7SaNvSb44gF4IN/P
         HaZs1gX1oP7JJtCHEf4AI4xITldst+Cz7H0IYkg31xK2cFOVTiTBwbIcXyEOXNeoVZId
         icD+ZM7PP72nKzfy4btWWAXnVSS8ib1iCXTyvbyJqBLilUIdKO8vKzjokT4NXPEU5js5
         h5/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vWL7kWfPjkbOdS970q5u2jhLwD2u+JCmBLo4eepXUFM=;
        b=j4n1j02Bd7b3GWNEGU5a3zGQpS+nq1zhbw4TdVmKBrBRTSsw02pnDiQC/9WlsvEpNt
         ZXNOqCQq8aJckTSVYuZ33Aca3q8nP1cbcOYi0GYWJ5wqYMSurJL/CqxRR4hkIfyLj7oX
         Xaz4e9nS9ix9ysHufHyRRBrBjmMGOYnlnIa3wq8swSXktqbTvdglWJcsEnFyTIFdp7SW
         C9klyM8v2Gz+OYmuNbXgafRftbwNaUOjl/Yo9SwQopHXMU2YkwEExMQMXfvEcQ200Njz
         NtChkKWCouiu1ZltR8ZQMop2iN4E3/puUVbpQkeQQgV2dUMr0qLjRONTZJvN2wpUOs7h
         csCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530HSwRIro480PUH94diXsmu/7xthnOitf5feJ/wlur6VBTZzc8O
	mfCGZHnQUghcEAqUhvtUhkQ=
X-Google-Smtp-Source: ABdhPJzBkCllS9wTjv/lPM6EZqsdcl/R85ibOKJADW3J3fERjfNUO2mFivIsUo+XUSFtlJXGugqfnw==
X-Received: by 2002:a62:2b88:0:b029:163:c6fb:f2a with SMTP id r130-20020a622b880000b0290163c6fb0f2amr23808081pfr.7.1605122484748;
        Wed, 11 Nov 2020 11:21:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:b56:: with SMTP id a22ls217439pgl.6.gmail; Wed, 11 Nov
 2020 11:21:24 -0800 (PST)
X-Received: by 2002:aa7:8a97:0:b029:160:c0b:671a with SMTP id a23-20020aa78a970000b02901600c0b671amr23924251pfc.16.1605122484180;
        Wed, 11 Nov 2020 11:21:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605122484; cv=none;
        d=google.com; s=arc-20160816;
        b=ZLWFqqYmnR3TJXIMJozYhj3CV0xtvMw2/ugad3vUBnZinoyOp4B4hu1KtM+LUjUa50
         sJoq0Q/mc8AfsCWz8EnmbFN7dBVP3ycSNzNRRh5XEGq22/Uh1MppI1Hk8ScE0A/JLc4y
         TD08JCnw8rpRJirVyMl4t4Jz0wsnVcGO6/QTiNA6h/NJuxcsRiQhGptFzC4GCkA096FJ
         nW0E4ip/AglafmWdoOjK+uRuVMIE6LDTae3uQ/Gf8lWSQp0/xRoWuztQd/ttqA14h0bg
         BphqWalh+dSmdXeg5qMj+aRKPgqYayAYHRncb1wEuemr+GeAtwO1yxGpavAtC2OFbXAl
         /Fcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=7z/XnopT/tCtrYwfzkBaH3rsW+0rQwvCJ39uVx+3HcU=;
        b=n5Jbh6wWEBO6byom2pjxCrKv449ngO8X4IbQSFnxwGn+CLZpy1m9557B44rjA85JZJ
         C63yqZLXNsRJ8+lYzHopeOeeQjuobs95rBMUDQaNzPbyYCPoG2QpffwF8Ejl4nXQNCAF
         WKksuwF7I2WW324Lda6088/c1/0AyXNfXpaOlhvlAUOA4IWanKl1zLov9QJm0rPoJiPk
         a/Bd9Biu/4MR6O0W29XmJOR6ApV0X9/IVjC58+wGdo+dmNG7mQhBeV/m9Jz/ge0Gvw+w
         6zy4h7IZMddXOSFPNzdFAFrRdUTrsoYsoUM+5nqd6fDHP8C6Aw42oaaQxe9LK9Bt/uP3
         aVAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=AqZT3O24;
       spf=pass (google.com: domain of srs0=nwwe=er=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=nwWE=ER=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x24si184000pll.5.2020.11.11.11.21.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Nov 2020 11:21:24 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=nwwe=er=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9D5AC20658;
	Wed, 11 Nov 2020 19:21:23 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 3899535225D6; Wed, 11 Nov 2020 11:21:23 -0800 (PST)
Date: Wed, 11 Nov 2020 11:21:23 -0800
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
	peterz@infradead.org
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without
 allocations
Message-ID: <20201111192123.GB3249@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201110135320.3309507-1-elver@google.com>
 <CADYN=9+=-ApMi_eEdAeHU6TyuQ7ZJSTQ8F-FCSD33kZH8HR+xg@mail.gmail.com>
 <CANpmjNM8MZphvkTSo=KgCBXQ6fNY4qo6NZD5SBHjNse_L9i5FQ@mail.gmail.com>
 <20201111133813.GA81547@elver.google.com>
 <20201111130543.27d29462@gandalf.local.home>
 <20201111182333.GA3249@paulmck-ThinkPad-P72>
 <20201111183430.GN517454@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201111183430.GN517454@elver.google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=AqZT3O24;       spf=pass
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

On Wed, Nov 11, 2020 at 07:34:30PM +0100, Marco Elver wrote:
> On Wed, Nov 11, 2020 at 10:23AM -0800, Paul E. McKenney wrote:
> > On Wed, Nov 11, 2020 at 01:05:43PM -0500, Steven Rostedt wrote:
> > > On Wed, 11 Nov 2020 14:38:13 +0100
> > > Marco Elver <elver@google.com> wrote:
> > > 
> > > > [+Cc folks who can maybe help figure out what's going on, since I get
> > > >   warnings even without KFENCE on next-20201110.]
> > > > 
> > > > On Wed, Nov 11, 2020 at 09:29AM +0100, Marco Elver wrote:
> > > > > On Wed, 11 Nov 2020 at 00:23, Anders Roxell <anders.roxell@linaro.org> wrote:
> > > > > [...]
> > > > > > I gave them a spin on next-20201105 [1] and on next-20201110 [2].
> > > > > >
> > > > > > I eventually got to a prompt on next-20201105.
> > > > > > However, I got to this kernel panic on the next-20201110:
> > > > > >
> > > > > > [...]
> > > > > > [ 1514.089966][    T1] Testing event system initcall: OK
> > > > > > [ 1514.806232][    T1] Running tests on all trace events:
> > > > > > [ 1514.857835][    T1] Testing all events:
> > > > > > [ 1525.503262][    C0] hrtimer: interrupt took 10902600 ns
> > > > > > [ 1623.861452][    C0] BUG: workqueue lockup - pool cpus=0 node=0
> > > > > > flags=0x0 nice=0 stuck for 65s!
> > > > > > [...]
> > > 
> > > OK, so this blows up when you enable all events?
> > > 
> > > Note, it could just be adding overhead (which is exasperated with other
> > > debug options enabled), which could open up a race window.
> > >  
> > > 
> > > > > > [ 7823.104349][   T28]       Tainted: G        W
> > > > > > 5.10.0-rc3-next-20201110-00008-g8dc06700529d #3
> > > > > > [ 7833.206491][   T28] "echo 0 >
> > > > > > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
> > > > > > [ 7840.750700][   T28] task:kworker/0:1     state:D stack:26640 pid:
> > > > > > 1872 ppid:     2 flags:0x00000428
> > > > > > [ 7875.642531][   T28] Workqueue: events toggle_allocation_gate
> > > > > > [ 7889.178334][   T28] Call trace:
> > > > > > [ 7897.066649][   T28]  __switch_to+0x1cc/0x1e0
> > > > > > [ 7905.326856][   T28]  0xffff00000f7077b0
> > > > > > [ 7928.354644][   T28] INFO: lockdep is turned off.
> > > > > > [ 7934.022572][   T28] Kernel panic - not syncing: hung_task: blocked tasks
> > > > > > [ 7934.032039][   T28] CPU: 0 PID: 28 Comm: khungtaskd Tainted: G
> > > > > >   W         5.10.0-rc3-next-20201110-00008-g8dc06700529d #3
> > > > > > [ 7934.045586][   T28] Hardware name: linux,dummy-virt (DT)
> > > > > > [ 7934.053677][   T28] Call trace:
> > > > > > [ 7934.060276][   T28]  dump_backtrace+0x0/0x420
> > > > > > [ 7934.067635][   T28]  show_stack+0x38/0xa0
> > > > > > [ 7934.091277][   T28]  dump_stack+0x1d4/0x278
> > > > > > [ 7934.098878][   T28]  panic+0x304/0x5d8
> > > > > > [ 7934.114923][   T28]  check_hung_uninterruptible_tasks+0x5e4/0x640
> > > > > > [ 7934.123823][   T28]  watchdog+0x138/0x160
> > > > > > [ 7934.131561][   T28]  kthread+0x23c/0x260
> > > > > > [ 7934.138590][   T28]  ret_from_fork+0x10/0x18
> > > > > > [ 7934.146631][   T28] Kernel Offset: disabled
> > > > > > [ 7934.153749][   T28] CPU features: 0x0240002,20002004
> > > > > > [ 7934.161476][   T28] Memory Limit: none
> > > > > > [ 7934.171272][   T28] ---[ end Kernel panic - not syncing: hung_task:
> > > > > > blocked tasks ]---
> > > > > >
> > > > > > Cheers,
> > > > > > Anders
> > > > > > [1] https://people.linaro.org/~anders.roxell/output-next-20201105-test.log
> > > > > > [2] https://people.linaro.org/~anders.roxell/output-next-20201110-test.log
> > > > > 
> > > > > Thanks for testing. The fact that it passes on next-20201105 but not
> > > > > on 20201110 is strange. If you boot with KFENCE disabled (boot param
> > > > > kfence.sample_interval=0), does it boot?
> > > > [...]
> > > > 
> > > > Right, so I think this is no longer KFENCE's fault. This looks like
> > > > something scheduler/RCU/ftrace related?! I notice that there have been
> > > > scheduler changes between next-20201105 and next-20201110.
> > > 
> > > I'm not sure any of that would cause this.
> > > 
> > > > 
> > > > I get this with KFENCE disabled:
> > > > 
> > > > | Running tests on all trace events:
> > > > | Testing all events: 
> > > > | BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 32s!
> > > > | Showing busy workqueues and worker pools:
> > > > | workqueue events: flags=0x0
> > > > |   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
> > > > |     pending: vmstat_shepherd
> > > > | workqueue events_power_efficient: flags=0x82
> > > > |   pwq 2: cpus=0 flags=0x5 nice=0 active=2/256 refcnt=4
> > > > |     in-flight: 107:neigh_periodic_work
> > > > |     pending: do_cache_clean
> > > > | pool 2: cpus=0 flags=0x5 nice=0 hung=3s workers=2 manager: 7
> > > > | rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
> > > > | 	(detected by 0, t=6502 jiffies, g=2885, q=4)
> > > > | rcu: All QSes seen, last rcu_preempt kthread activity 5174 (4295523265-4295518091), jiffies_till_next_fqs=1, root ->qsmask 0x0
> > > > | rcu: rcu_preempt kthread starved for 5174 jiffies! g2885 f0x2 RCU_GP_WAIT_FQS(5) ->state=0x0 ->cpu=0
> > > > | rcu: 	Unless rcu_preempt kthread gets sufficient CPU time, OOM is now expected behavior.
> > > > | rcu: RCU grace-period kthread stack dump:
> > > > | task:rcu_preempt     state:R  running task     stack:    0 pid:   10 ppid:     2 flags:0x00000428
> > > > | Call trace:
> > > > |  __switch_to+0x100/0x1e0
> > > > |  __schedule+0x2d0/0x890
> > > > |  preempt_schedule_notrace+0x70/0x1c0
> > > > |  ftrace_ops_no_ops+0x174/0x250
> > > > |  ftrace_graph_call+0x0/0xc
> > > 
> > > Note, just because ftrace is called here, the blocked task was preempted
> > > when the ftrace code called preempt_enable_notrace().
> > > 
> > > 
> > > > |  preempt_count_add+0x1c/0x180
> > > > |  schedule+0x44/0x108
> > > > |  schedule_timeout+0x394/0x530
> > > > |  rcu_gp_kthread+0x76c/0x19a8
> > > > |  kthread+0x174/0x188
> > > > |  ret_from_fork+0x10/0x18
> > > > | 
> > > > | ================================
> > > > | WARNING: inconsistent lock state
> > > > | 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #18 Not tainted
> > > > | --------------------------------
> > > > | inconsistent {IN-HARDIRQ-W} -> {HARDIRQ-ON-W} usage.
> > > > | kcompactd0/26 [HC0[0]:SC0[0]:HE0:SE1] takes:
> > > > | ffffae32e6bd4358 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x4a0/0xd18
> > > > | {IN-HARDIRQ-W} state was registered at:
> > > 
> > > I did some digging here and it looks like the rcu_node lock could be taken
> > > without interrupts enabled when it does a stall print. That probably should
> > > be fixed, but it's a symptom of the underlining bug and not the cause.
> > 
> > Does this patch (in -next) help?
> > 
> > 							Thanx, Paul
>  
> >     rcu: Don't invoke try_invoke_on_locked_down_task() with irqs disabled
> 
> Sadly, no, next-20201110 already included that one, and that's what I
> tested and got me all those warnings above.

Hey, I had to ask!  The only uncertainty I seee is the acquisition of
the lock in rcu_iw_handler(), for which I add a lockdep check in the
(untested) patch below.  The other thing I could do is sprinkle such
checks through the stall-warning code on the assumption that something
RCU is calling is enabling interrupts.

Other thoughts?

							Thanx, Paul

------------------------------------------------------------------------

diff --git a/kernel/rcu/tree_stall.h b/kernel/rcu/tree_stall.h
index 70d48c5..3d67650 100644
--- a/kernel/rcu/tree_stall.h
+++ b/kernel/rcu/tree_stall.h
@@ -189,6 +189,7 @@ static void rcu_iw_handler(struct irq_work *iwp)
 
 	rdp = container_of(iwp, struct rcu_data, rcu_iw);
 	rnp = rdp->mynode;
+	lockdep_assert_irqs_disabled();
 	raw_spin_lock_rcu_node(rnp);
 	if (!WARN_ON_ONCE(!rdp->rcu_iw_pending)) {
 		rdp->rcu_iw_gp_seq = rnp->gp_seq;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111192123.GB3249%40paulmck-ThinkPad-P72.
