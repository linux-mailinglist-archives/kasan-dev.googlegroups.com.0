Return-Path: <kasan-dev+bncBCU73AEHRQBBBGEF6D6QKGQEWWL3YTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 661252C134E
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 19:42:33 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id t7sf7278067oog.7
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 10:42:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606156952; cv=pass;
        d=google.com; s=arc-20160816;
        b=gdlA3WT6VFvomO/zV1M5V6G6TJPSH1wDmk/f7MbWkyIUMc16xe305gdCRKCTII+u4R
         X/Z8nEE7wU6ohOPp/VAQ7VX7r1SkFq8+Vk628vrNYnQ7PhdTAOKm4EzsSQ+tCNpHdvZz
         HUxlV9kRumr6EfkYOPgTQQUxC/KOSVBvDo5JIlT7cw/9gUul9swbeOWkrtil2VfHt1Yn
         qBa1MdYDHmk4cFTwvhVRsahDseAcfASsTe9BrsK5QgDjKOH34gUtSSCsdCAf7Ek7JsL1
         3gt359kq+1rmezindO4hYpDtj0ZP85tpkx4gnoiwt6Xfr1jQalSZ7bOzUOVZvn4Gim7r
         432g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=fIhrN0sS6UtywBwpNcng0tp9h3brO12Z2DykrB4crOo=;
        b=SAp4GiHlo6CX6Mu04k/RlKismFtdkx/uPkygT8Iyjc7NQQCwsgNWBjbUkawxWdrFom
         eo7fA5Eygyy4zmE+puunp0vBfvpxSTGDIBhKZOSUifdF4pWd75Ke50KEwOmHVgw5CCpE
         XNMmFbcKJv4kFuWN0L3Sk/09ehZ6U8IQ/tY1QbfJkFzrceW7g/SKhzVzDIzjUxFhkxQI
         SZXLMsY90Q31miFGR3FDcjpMIo2xymlQQ2NGXPsc0X2qry49p1xGngtTZbgfQ74wMtP6
         u2sI6XLXTEAWsuh5eRxFdyveGcS69r+45I2A1BzapeGtuNQjV2O7TAIivSYtDZeA3nSz
         6KGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=epz8=e5=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=EPZ8=E5=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fIhrN0sS6UtywBwpNcng0tp9h3brO12Z2DykrB4crOo=;
        b=OnntTSeyFya/60aTcmnXOvZkXUDk9DSQw6bkYog50cerEWOYMxSFC+H2IEo8bhQ5my
         6j82srvHgXdrVam10+/ESAPE83xNgrsDShs7fvHvHkblT2/mj/fUhTf6+cvLve1hCKe+
         bn9mygANq+pEvc/ES6NlrM1Egt2ObA6iGllI7YwcZyswRV+iOIzRjahwBt2eW6ajg8UY
         OxDzGNZY0+wNeJJ55TFhxlvZMoaWAeymzE7XNUCA1ueJ/qvHom1gvuF99Kkewd3jUcXV
         Q4bZ8ztjdea+IroeYTxtIYeft18+ebldtYuk24Ng4mBsV8ZYBpfg67g2tMAj9M4BJw9m
         oIvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fIhrN0sS6UtywBwpNcng0tp9h3brO12Z2DykrB4crOo=;
        b=hhfQOvWLO02Pcbd0KsXyaNMRxpq9qfIMmGKNDZWgggypmO1QLcdvPwahXyWCpqLa3r
         WhOrez9/BYm785EYY47+YZY7FObJImjcT1oJaugO1q1yJ7syzVcJCsPbW+vx95RbDtc8
         JLNpQRvnk1zFPUmXBgkd6P6mcMgoJVJZ7PzeaGHnEURnXVLzC2qS4WWfBtBPsi0NDV2e
         8nfn+fXPSIT56lL0/RXHX5kGfE0c+f0SANDxj0ioYZ6ONV0PCcxuEzHD9HVqye04j64k
         GSP5PHuhIlEmtnHDbAc2TieNjuAptdybAzbQ1OI651zjb5cvTO19q6P+mIWAJaqCMznS
         Ykog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531xz4GdToiB4DT8TXEe9H1xevVDqTcgpTA/JXpVA226kkQi5+wD
	yBf4VR1MHmQxZt1bdwQBnJ8=
X-Google-Smtp-Source: ABdhPJygD8WOab8CBoPIxGx0q1rUNgwCx2zpjvy6OZ4XiFK7lSK7uF34PyN7hgqCAcOtmq8K+f2BDA==
X-Received: by 2002:a05:6830:17c4:: with SMTP id p4mr515204ota.246.1606156952219;
        Mon, 23 Nov 2020 10:42:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:39c9:: with SMTP id y67ls977199otb.7.gmail; Mon, 23 Nov
 2020 10:42:31 -0800 (PST)
X-Received: by 2002:a9d:5d15:: with SMTP id b21mr580247oti.244.1606156951800;
        Mon, 23 Nov 2020 10:42:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606156951; cv=none;
        d=google.com; s=arc-20160816;
        b=jxKIDuA1d0MhyeGktP0gOCh0mztT9Rg/YtvPCl34J3jHqWMpp0a6etstnOGXhm1tWA
         vay+nONJLvIptrtGhDMDWmsspiwpO7Di/5PVuoS66ezrEFsTfd2N86+Txtc63GF9piWA
         3DYsUeDC4BbdK7YkY8jpu90HgNbiUD0wKzutBTZYnbyYmvSMKUWLT8c9s/Tpr93FAqVv
         KslJf2tty9FOL/L0CjcEMgErOjMNgWGYVxcUyTlCu7N8kmBSv+27J7uR0JlgGC4HHrtQ
         am8L5i3dhn9JhkkiUjqmARZf+m4awlt0kYix8HDSGe5S/RVfSqaKQgrdixelUttXamnB
         pEnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=KM2ydoKX86qYoUww7R71iUlnpmxT+YE4pdMEz1Cw/Uw=;
        b=EERr686GjR5FZoX25aRlv0xdCXoXVbU23nm2MR/a2Wafuci3tpLCF5XFQAtPNKuCJP
         tFqpDme1bReAJtqepyTpDaqVjkovO1AbDIwx3IsvXdQdZWIdtO5KMkaNGDFwBooIfa66
         gQFCo9QE0Jk67KqgSM65MMwoEl+JNcht551kr3HmBG5/rk2VcxxNQko7j9WCS6kAC9Ya
         egOfRJSQy4jpWrYk36yTFzsatR0anFgfMpHH0lERWhtpw/bsCNBTeR1TyMPHe2urMTXB
         TX/coHey6NeJs6q1VgyawTGeEX8AqFgo7+QQyswWJ56dB72J6PZXMg3Z4TfAj52h/68b
         wXSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=epz8=e5=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=EPZ8=E5=goodmis.org=rostedt@kernel.org"
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l23si806356oil.2.2020.11.23.10.42.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 23 Nov 2020 10:42:31 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=epz8=e5=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gandalf.local.home (cpe-66-24-58-225.stny.res.rr.com [66.24.58.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 3745320658;
	Mon, 23 Nov 2020 18:42:29 +0000 (UTC)
Date: Mon, 23 Nov 2020 13:42:27 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Anders Roxell
 <anders.roxell@linaro.org>, Andrew Morton <akpm@linux-foundation.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Jann Horn <jannh@google.com>, Mark Rutland
 <mark.rutland@arm.com>, Linux Kernel Mailing List
 <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, kasan-dev
 <kasan-dev@googlegroups.com>, rcu@vger.kernel.org, Peter Zijlstra
 <peterz@infradead.org>, Tejun Heo <tj@kernel.org>, Lai Jiangshan
 <jiangshanlai@gmail.com>, Thomas Gleixner <tglx@linutronix.de>
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without
 allocations
Message-ID: <20201123134227.6df443db@gandalf.local.home>
In-Reply-To: <20201123112812.19e918b3@gandalf.local.home>
References: <CANpmjNNyZs6NrHPmomC4=9MPEvCy1bFA5R2pRsMhG7=c3LhL_Q@mail.gmail.com>
	<20201112161439.GA2989297@elver.google.com>
	<20201112175406.GF3249@paulmck-ThinkPad-P72>
	<20201113175754.GA6273@paulmck-ThinkPad-P72>
	<20201117105236.GA1964407@elver.google.com>
	<20201117182915.GM1437@paulmck-ThinkPad-P72>
	<20201118225621.GA1770130@elver.google.com>
	<20201118233841.GS1437@paulmck-ThinkPad-P72>
	<20201119125357.GA2084963@elver.google.com>
	<20201120142734.75af5cd6@gandalf.local.home>
	<20201123152720.GA2177956@elver.google.com>
	<20201123112812.19e918b3@gandalf.local.home>
X-Mailer: Claws Mail 3.17.3 (GTK+ 2.24.32; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=epz8=e5=goodmis.org=rostedt@kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=EPZ8=E5=goodmis.org=rostedt@kernel.org"
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

On Mon, 23 Nov 2020 11:28:12 -0500
Steven Rostedt <rostedt@goodmis.org> wrote:

> I noticed:
> 
> 
> [  237.650900] enabling event benchmark_event
> 
> In both traces. Could you disable CONFIG_TRACEPOINT_BENCHMARK and see if
> the issue goes away. That event kicks off a thread that spins in a tight
> loop for some time and could possibly cause some issues.
> 
> It still shouldn't break things, we can narrow it down if it is the culprit.

[ Added Thomas  ]

And that's just one issue. I don't think that has anything to do with the
other one:

[ 1614.162007] rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
[ 1614.168625]  (detected by 0, t=3752 jiffies, g=3529, q=1)
[ 1614.170825] rcu: All QSes seen, last rcu_preempt kthread activity 242 (4295293115-4295292873), jiffies_till_next_fqs=1, root ->qsmask 0x0
[ 1614.194272] 
[ 1614.196673] ================================
[ 1614.199738] WARNING: inconsistent lock state
[ 1614.203056] 5.10.0-rc4-next-20201119-00004-g77838ee21ff6-dirty #21 Not tainted
[ 1614.207012] --------------------------------
[ 1614.210125] inconsistent {IN-HARDIRQ-W} -> {HARDIRQ-ON-W} usage.
[ 1614.213832] swapper/0/1 [HC0[0]:SC0[0]:HE0:SE1] takes:
[ 1614.217288] ffffd942547f47d8 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x7c0/0x17a0
[ 1614.225496] {IN-HARDIRQ-W} state was registered at:
[ 1614.229031]   __lock_acquire+0xae8/0x1ac8
[ 1614.232203]   lock_acquire+0x268/0x508
[ 1614.235254]   _raw_spin_lock_irqsave+0x78/0x14c
[ 1614.238547]   rcu_sched_clock_irq+0x7c0/0x17a0
[ 1614.241757]   update_process_times+0x6c/0xb8
[ 1614.244950]   tick_sched_handle.isra.0+0x58/0x88
[ 1614.248225]   tick_sched_timer+0x68/0xe0
[ 1614.251304]   __hrtimer_run_queues+0x288/0x730
[ 1614.254516]   hrtimer_interrupt+0x114/0x288
[ 1614.257650]   arch_timer_handler_virt+0x50/0x70
[ 1614.260922]   handle_percpu_devid_irq+0x104/0x4c0
[ 1614.264236]   generic_handle_irq+0x54/0x78
[ 1614.267385]   __handle_domain_irq+0xac/0x130
[ 1614.270585]   gic_handle_irq+0x70/0x108
[ 1614.273633]   el1_irq+0xc0/0x180
[ 1614.276526]   rcu_irq_exit_irqson+0x40/0x78
[ 1614.279704]   trace_preempt_on+0x144/0x1a0
[ 1614.282834]   preempt_schedule_common+0xf8/0x1a8
[ 1614.286126]   preempt_schedule+0x38/0x40
[ 1614.289240]   __mutex_lock+0x608/0x8e8
[ 1614.292302]   mutex_lock_nested+0x3c/0x58
[ 1614.295450]   static_key_enable_cpuslocked+0x7c/0xf8
[ 1614.298828]   static_key_enable+0x2c/0x40
[ 1614.301961]   tracepoint_probe_register_prio+0x284/0x3a0
[ 1614.305464]   tracepoint_probe_register+0x40/0x58
[ 1614.308776]   trace_event_reg+0xe8/0x150
[ 1614.311852]   __ftrace_event_enable_disable+0x2e8/0x608
[ 1614.315351]   __ftrace_set_clr_event_nolock+0x160/0x1d8
[ 1614.318809]   __ftrace_set_clr_event+0x60/0x90
[ 1614.322061]   event_trace_self_tests+0x64/0x12c
[ 1614.325335]   event_trace_self_tests_init+0x88/0xa8
[ 1614.328758]   do_one_initcall+0xa4/0x500
[ 1614.331860]   kernel_init_freeable+0x344/0x3c4
[ 1614.335110]   kernel_init+0x20/0x16c
[ 1614.338102]   ret_from_fork+0x10/0x34
[ 1614.341057] irq event stamp: 3206302
[ 1614.344123] hardirqs last  enabled at (3206301): [<ffffd9425238da04>] rcu_irq_exit_irqson+0x64/0x78
[ 1614.348697] hardirqs last disabled at (3206302): [<ffffd942522123c0>] el1_irq+0x80/0x180
[ 1614.353013] softirqs last  enabled at (3204216): [<ffffd94252210b80>] __do_softirq+0x630/0x6b4
[ 1614.357509] softirqs last disabled at (3204191): [<ffffd942522c623c>] irq_exit+0x1cc/0x1e0
[ 1614.361737] 
[ 1614.361737] other info that might help us debug this:
[ 1614.365566]  Possible unsafe locking scenario:
[ 1614.365566] 
[ 1614.369128]        CPU0
[ 1614.371747]        ----
[ 1614.374282]   lock(rcu_node_0);
[ 1614.378818]   <Interrupt>
[ 1614.381394]     lock(rcu_node_0);
[ 1614.385997] 
[ 1614.385997]  *** DEADLOCK ***
[ 1614.385997] 
[ 1614.389613] 5 locks held by swapper/0/1:
[ 1614.392655]  #0: ffffd9425480e940 (event_mutex){+.+.}-{3:3}, at: __ftrace_set_clr_event+0x48/0x90
[ 1614.401701]  #1: ffffd9425480a530 (tracepoints_mutex){+.+.}-{3:3}, at: tracepoint_probe_register_prio+0x48/0x3a0
[ 1614.410973]  #2: ffffd9425476abf0 (cpu_hotplug_lock){++++}-{0:0}, at: static_key_enable+0x24/0x40
[ 1614.419858]  #3: ffffd94254816348 (jump_label_mutex){+.+.}-{3:3}, at: static_key_enable_cpuslocked+0x7c/0xf8
[ 1614.429049]  #4: ffffd942547f47d8 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x7c0/0x17a0
[ 1614.438029] 
[ 1614.438029] stack backtrace:
[ 1614.441436] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.10.0-rc4-next-20201119-00004-g77838ee21ff6-dirty #21
[ 1614.446149] Hardware name: linux,dummy-virt (DT)
[ 1614.449621] Call trace:
[ 1614.452337]  dump_backtrace+0x0/0x240
[ 1614.455372]  show_stack+0x34/0x88
[ 1614.458306]  dump_stack+0x140/0x1bc
[ 1614.461258]  print_usage_bug+0x2a0/0x2f0
[ 1614.464399]  mark_lock.part.0+0x438/0x4e8
[ 1614.467528]  mark_held_locks+0x54/0x90
[ 1614.470576]  lockdep_hardirqs_on_prepare+0xe0/0x290
[ 1614.473935]  trace_hardirqs_on+0x90/0x370
[ 1614.477045]  el1_irq+0xdc/0x180
[ 1614.479934]  rcu_irq_exit_irqson+0x40/0x78
[ 1614.483093]  trace_preempt_on+0x144/0x1a0
[ 1614.486211]  preempt_schedule_common+0xf8/0x1a8
[ 1614.489479]  preempt_schedule+0x38/0x40
[ 1614.492544]  __mutex_lock+0x608/0x8e8


The above has:

 preempt_schedule_common() {
   trace_preempt_on() {
     <interrupt>
	el1_irq:
	   handle_arch_irq {
	      irq_enter();
	      [..]
	      irq_exit();
	   }
	   bl trace_hardirqs_on


I wonder if the lockdep logic got confused on ARM64 by the rework done to
lockdep and tracing with respect to irq entry / exit.

Or maybe there's an rcu_node leak lock that happened somewhere?

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201123134227.6df443db%40gandalf.local.home.
