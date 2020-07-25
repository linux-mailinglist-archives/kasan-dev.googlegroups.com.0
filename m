Return-Path: <kasan-dev+bncBAABBGEQ6H4AKGQELVBN6MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FF5722D845
	for <lists+kasan-dev@lfdr.de>; Sat, 25 Jul 2020 16:56:26 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id y73sf8489313pfb.8
        for <lists+kasan-dev@lfdr.de>; Sat, 25 Jul 2020 07:56:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595688984; cv=pass;
        d=google.com; s=arc-20160816;
        b=uaCDWcCj+LOxxEwM8htYzvSVbw+E26GDQGh22nH5TtxWCnqdPtVkplYGdxRP09a8LN
         rxXnVdlorFFlNYibv1g2C13bKJk0Cp2SKmt9ElRYmhmxqXHt+Iild2ZGKpa0gjvW4tiH
         Ox0TvxAXlG0aTCha6Y3x0KnpMZwRF6WOLVDRfVfow3yy+OljfeOLqh6yRdz9wiIz7IfN
         FYne/UF+Jwk8Yv/CwJxNho9Y75QS8dooX3JUu3oLz4pkvVpWrcXgsbfr8M6I5zon7TWO
         uMR3f80Mqgb9uB9KsDjU+WLYsy3vUH4BLBOSJOJlZwO1uo066D1bTzw9Qg2peDul0FbO
         xbWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=yks7LypfbWdSWtrN32DQv16q0HI40ocUOWIdsrg71vQ=;
        b=wDC+RiUGRoGrMDZp49ezcjR7CKoltZDrcpi2kr4YdJv/OTMeafr9LTU6PjVGuiCrMF
         zI2PyJ0zcLqRpVGpKxKVTnFGbF7JYzM/bUVXzK2oI2HdQAI0M3X+bHtcOF6QCgRUN1Te
         vs7NSDqnx1viuh3lMmpugG2BsLrwjlOZxLxy8fB0RjOFtFyL8lE28fe9QNapkLQwz4Ch
         mZ+bC6N/rze7yU3tPqhDDalI03XS5+C92wOGkwbQgTHp4jOX/qOZGpP5A1BAI5fSqrx1
         XNeSG7R0vcm0qxpms0pkF9+RTt9PYb4gZv+tcLo1/0yEae5UgyDNqArmOFYaazZwy0ng
         0Hfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=TDzsALth;
       spf=pass (google.com: domain of srs0=ej9m=be=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=eJ9M=BE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yks7LypfbWdSWtrN32DQv16q0HI40ocUOWIdsrg71vQ=;
        b=QDXQx9Q087/Wn4X4wYXfbEHfCtL2z+/hlZ7DMdmSVThkZTX+YARfh/UJG6SXIvJ39/
         Z/fC4+hyhD6HDWKw4/LWIm6QC42DH4cUE7cMhR66NwiP5jJU/L98VeWI8ehUXTzFDJcS
         Kwp79vv8VCHlk0sJjVfk2cbp9LtGGy8vX34VccEzwtQ0oPyfGIS2BZu+yeZ67tSE2MYZ
         0UPfc/fHbkduYxeIMaAeIC31vazoy79GukfSLyYpYPt0yJVvNmOrstuyjLq74ql9nuyL
         JIwJeOjXG/H0DIN1+2+Uhsz8c8/dSgmTOF3UAdIMfblpJ+En8O40zNviDNaazfsg7MB/
         7psg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yks7LypfbWdSWtrN32DQv16q0HI40ocUOWIdsrg71vQ=;
        b=TcR+fWiTvLz/6568tAxjSX8dvEs/wMt5MfqskJjuVCD6hisuJSU5zlhclKyubhkKLx
         exyOU0+bl6ZXQeaXcM/UVCie6v5YX4MB08n30rjj7EFPINje0uh0AdkqYxRJ5H5u+sZ/
         /QtjiJM2qLSHPCJ7d25nz80SzFy9UbNdRdZ71xOprAc/k+mGHHSH8vbyxkHiDVTWutzG
         B+FIzcF8phizIG2cujjNS830gD59alwuSZ9tuBoiHjPanP3eOSeTcBi3AdbD7UXokshp
         2v7C5NEBZbsmw+K8vTni9wyKWJZnzkCZ1rUFsipGGacUZNAmXKrCJJiTHo5YOghXAqNX
         PEoA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530WcBsVaxBHemilP+cye09Z6xIPEp1MRPS/lM28D7fSM3wwTJ7l
	JTZrN3Hy7Xb3AnpkUFvFR14=
X-Google-Smtp-Source: ABdhPJxWbmvT/emKTGcW3l7r2eD/y42snN412FVwuk07b6yq2zoRdybX1ZopkuOUrcPXdvfDjZGqOw==
X-Received: by 2002:a17:90a:ce02:: with SMTP id f2mr10937061pju.159.1595688984496;
        Sat, 25 Jul 2020 07:56:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b288:: with SMTP id u8ls4629221plr.4.gmail; Sat, 25
 Jul 2020 07:56:24 -0700 (PDT)
X-Received: by 2002:a17:90b:f16:: with SMTP id br22mr10944684pjb.170.1595688984198;
        Sat, 25 Jul 2020 07:56:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595688984; cv=none;
        d=google.com; s=arc-20160816;
        b=JBx7AV9N5DC/Ou7KgjrfZZ1KtckGU1qLMqu0TRVchtpmFTTQbrUBX1RQciJq4yieva
         8sGRYG8dqJ941alRaS6x/3sckTnztXaZtku3h0fq3SOImVSYOtLNvrdx5etojneNoivU
         gEnX8Y4OpBYEzZEa40SIRzTLPuOu2+k3/AxfZThjsTXKJOSIpbTmfJORhGjNUON08EyQ
         +YNcViw/FkhB7kFbFhZ26aPw0E1ebsGchbeZYKMoFbZcGKeDS2KaiFnKuhboSnryjOZ+
         YnT3l2QHhJr7kL3LW2hy9MSWk9efa+dzqtiJ5kckGdlF3zvaqXeAukQBGWueaQZOutpx
         iV4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=xaq/+lgSk5dJ7mqIwGGQO37bBMTE4iDpn7wRghHwWCQ=;
        b=k2dmptQdTTB7Nk8PBDAY7KdSbx6C0sJH2vbN28v5xn1reyReo13WK61ydyIw7x1aZp
         mnBBDxqe6C/NBoHnkNRxHNcpoFcDAJ6SYvtMFhZRCtyGbu+fiIfun+eCv7YvJsxVSQvk
         wu7PjmK3+epJY/fgUWcskk/2IjJKl/tWPxiU+tNvoFePd9UIXkjCRG9f0rDgPs/NRmib
         aq1H3g7F8WVI41O0YLuoqsyFBbaC4Qw3fB25tfRmigmZxxTyvsI1tQUdVPHc73697Gzq
         RmCFzKNoGESj3OzO30ZURHSXI0cdBeZL2by5fhWeguMspj+vtvV+9mmcN8aBE+5SjnCo
         Vc5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=TDzsALth;
       spf=pass (google.com: domain of srs0=ej9m=be=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=eJ9M=BE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n60si539056pjb.1.2020.07.25.07.56.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 25 Jul 2020 07:56:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ej9m=be=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-111-31.bvtn.or.frontiernet.net [50.39.111.31])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id E047D20674;
	Sat, 25 Jul 2020 14:56:23 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id C8AE93522767; Sat, 25 Jul 2020 07:56:23 -0700 (PDT)
Date: Sat, 25 Jul 2020 07:56:23 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kcsan: Add option to allow watcher interruptions
Message-ID: <20200725145623.GZ9247@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200220141551.166537-1-elver@google.com>
 <20200220185855.GY2935@paulmck-ThinkPad-P72>
 <20200220213317.GA35033@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200220213317.GA35033@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=TDzsALth;       spf=pass
 (google.com: domain of srs0=ej9m=be=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=eJ9M=BE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Thu, Feb 20, 2020 at 10:33:17PM +0100, Marco Elver wrote:
> On Thu, 20 Feb 2020, Paul E. McKenney wrote:

I am clearly not keeping up...  :-/

> > On Thu, Feb 20, 2020 at 03:15:51PM +0100, Marco Elver wrote:
> > > Add option to allow interrupts while a watchpoint is set up. This can be
> > > enabled either via CONFIG_KCSAN_INTERRUPT_WATCHER or via the boot
> > > parameter 'kcsan.interrupt_watcher=1'.
> > > 
> > > Note that, currently not all safe per-CPU access primitives and patterns
> > > are accounted for, which could result in false positives. For example,
> > > asm-generic/percpu.h uses plain operations, which by default are
> > > instrumented. On interrupts and subsequent accesses to the same
> > > variable, KCSAN would currently report a data race with this option.
> > > 
> > > Therefore, this option should currently remain disabled by default, but
> > > may be enabled for specific test scenarios.
> > > 
> > > Signed-off-by: Marco Elver <elver@google.com>
> > 
> > Queued for review and testing, thank you!
> > 
> > > ---
> > > 
> > > As an example, the first data race that this found:
> > > 
> > > write to 0xffff88806b3324b8 of 4 bytes by interrupt on cpu 0:
> > >  rcu_preempt_read_enter kernel/rcu/tree_plugin.h:353 [inline]
> > >  __rcu_read_lock+0x3c/0x50 kernel/rcu/tree_plugin.h:373
> > >  rcu_read_lock include/linux/rcupdate.h:599 [inline]
> > >  cpuacct_charge+0x36/0x80 kernel/sched/cpuacct.c:347
> > >  cgroup_account_cputime include/linux/cgroup.h:773 [inline]
> > >  update_curr+0xe2/0x1d0 kernel/sched/fair.c:860
> > >  enqueue_entity+0x130/0x5d0 kernel/sched/fair.c:4005
> > >  enqueue_task_fair+0xb0/0x420 kernel/sched/fair.c:5260
> > >  enqueue_task kernel/sched/core.c:1302 [inline]
> > >  activate_task+0x6d/0x110 kernel/sched/core.c:1324
> > >  ttwu_do_activate.isra.0+0x40/0x60 kernel/sched/core.c:2266
> > >  ttwu_queue kernel/sched/core.c:2411 [inline]
> > >  try_to_wake_up+0x3be/0x6c0 kernel/sched/core.c:2645
> > >  wake_up_process+0x10/0x20 kernel/sched/core.c:2669
> > >  hrtimer_wakeup+0x4c/0x60 kernel/time/hrtimer.c:1769
> > >  __run_hrtimer kernel/time/hrtimer.c:1517 [inline]
> > >  __hrtimer_run_queues+0x274/0x5f0 kernel/time/hrtimer.c:1579
> > >  hrtimer_interrupt+0x22d/0x490 kernel/time/hrtimer.c:1641
> > >  local_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1119 [inline]
> > >  smp_apic_timer_interrupt+0xdc/0x280 arch/x86/kernel/apic/apic.c:1144
> > >  apic_timer_interrupt+0xf/0x20 arch/x86/entry/entry_64.S:829
> > >  delay_tsc+0x38/0xc0 arch/x86/lib/delay.c:68                   <--- interrupt while delayed
> > >  __delay arch/x86/lib/delay.c:161 [inline]
> > >  __const_udelay+0x33/0x40 arch/x86/lib/delay.c:175
> > >  __udelay+0x10/0x20 arch/x86/lib/delay.c:181
> > >  kcsan_setup_watchpoint+0x17f/0x400 kernel/kcsan/core.c:428
> > >  check_access kernel/kcsan/core.c:550 [inline]
> > >  __tsan_read4+0xc6/0x100 kernel/kcsan/core.c:685               <--- Enter KCSAN runtime
> > >  rcu_preempt_read_enter kernel/rcu/tree_plugin.h:353 [inline]  <---+
> > >  __rcu_read_lock+0x2a/0x50 kernel/rcu/tree_plugin.h:373            |
> > >  rcu_read_lock include/linux/rcupdate.h:599 [inline]               |
> > >  lock_page_memcg+0x31/0x110 mm/memcontrol.c:1972                   |
> > >                                                                    |
> > > read to 0xffff88806b3324b8 of 4 bytes by task 6131 on cpu 0:       |
> > >  rcu_preempt_read_enter kernel/rcu/tree_plugin.h:353 [inline]  ----+
> > >  __rcu_read_lock+0x2a/0x50 kernel/rcu/tree_plugin.h:373
> > >  rcu_read_lock include/linux/rcupdate.h:599 [inline]
> > >  lock_page_memcg+0x31/0x110 mm/memcontrol.c:1972
> > > 
> > > The writer is doing 'current->rcu_read_lock_nesting++'. The read is as
> > > vulnerable to compiler optimizations and would therefore conclude this
> > > is a valid data race.
> > 
> > Heh!  That one is a fun one!  It is on a very hot fastpath.  READ_ONCE()
> > and WRITE_ONCE() are likely to be measurable at the system level.
> > 
> > Thoughts on other options?
> 
> Would this be a use-case for local_t? Don't think this_cpu ops work
> here.
> 
> See below idea. This would avoid the data race (KCSAN stopped
> complaining) and seems to generate reasonable code.
> 
> Version before:
> 
>  <__rcu_read_lock>:
>      130	mov    %gs:0x0,%rax
>      137
>      139	addl   $0x1,0x370(%rax)
>      140	retq   
>      141	data16 nopw %cs:0x0(%rax,%rax,1)
>      148
>      14c	nopl   0x0(%rax)
> 
> Version after:
> 
>  <__rcu_read_lock>:
>      130	mov    %gs:0x0,%rax
>      137
>      139	incq   0x370(%rax)
>      140	retq   
>      141	data16 nopw %cs:0x0(%rax,%rax,1)
>      148
>      14c	nopl   0x0(%rax)
> 
> I haven't checked the other places where it is used, though.
> (Can send it as a patch if you think this might work.)
> 
> Thanks,
> -- Marco
> 
> diff --git a/include/linux/rcupdate.h b/include/linux/rcupdate.h
> index 2678a37c31696..3d8586ee7ae64 100644
> --- a/include/linux/rcupdate.h
> +++ b/include/linux/rcupdate.h
> @@ -50,7 +50,7 @@ void __rcu_read_unlock(void);
>   * nesting depth, but makes sense only if CONFIG_PREEMPT_RCU -- in other
>   * types of kernel builds, the rcu_read_lock() nesting depth is unknowable.
>   */
> -#define rcu_preempt_depth() (current->rcu_read_lock_nesting)
> +#define rcu_preempt_depth() local_read(&current->rcu_read_lock_nesting)
>  
>  #else /* #ifdef CONFIG_PREEMPT_RCU */
>  
> diff --git a/include/linux/sched.h b/include/linux/sched.h
> index 0918904c939d2..70d7e3257feed 100644
> --- a/include/linux/sched.h
> +++ b/include/linux/sched.h
> @@ -10,6 +10,7 @@
>  #include <uapi/linux/sched.h>
>  
>  #include <asm/current.h>
> +#include <asm/local.h>
>  
>  #include <linux/pid.h>
>  #include <linux/sem.h>
> @@ -708,7 +709,7 @@ struct task_struct {
>  	cpumask_t			cpus_mask;
>  
>  #ifdef CONFIG_PREEMPT_RCU
> -	int				rcu_read_lock_nesting;
> +	local_t				rcu_read_lock_nesting;
>  	union rcu_special		rcu_read_unlock_special;
>  	struct list_head		rcu_node_entry;
>  	struct rcu_node			*rcu_blocked_node;
> diff --git a/init/init_task.c b/init/init_task.c
> index 096191d177d5c..941777fce11e5 100644
> --- a/init/init_task.c
> +++ b/init/init_task.c
> @@ -130,7 +130,7 @@ struct task_struct init_task
>  	.perf_event_list = LIST_HEAD_INIT(init_task.perf_event_list),
>  #endif
>  #ifdef CONFIG_PREEMPT_RCU
> -	.rcu_read_lock_nesting = 0,
> +	.rcu_read_lock_nesting = LOCAL_INIT(0),
>  	.rcu_read_unlock_special.s = 0,
>  	.rcu_node_entry = LIST_HEAD_INIT(init_task.rcu_node_entry),
>  	.rcu_blocked_node = NULL,
> diff --git a/kernel/fork.c b/kernel/fork.c
> index 60a1295f43843..43af326081b06 100644
> --- a/kernel/fork.c
> +++ b/kernel/fork.c
> @@ -1669,7 +1669,7 @@ init_task_pid(struct task_struct *task, enum pid_type type, struct pid *pid)
>  static inline void rcu_copy_process(struct task_struct *p)
>  {
>  #ifdef CONFIG_PREEMPT_RCU
> -	p->rcu_read_lock_nesting = 0;
> +	local_set(&p->rcu_read_lock_nesting, 0);
>  	p->rcu_read_unlock_special.s = 0;
>  	p->rcu_blocked_node = NULL;
>  	INIT_LIST_HEAD(&p->rcu_node_entry);
> diff --git a/kernel/rcu/tree_plugin.h b/kernel/rcu/tree_plugin.h
> index c6ea81cd41890..e0595abd50c0f 100644
> --- a/kernel/rcu/tree_plugin.h
> +++ b/kernel/rcu/tree_plugin.h
> @@ -350,17 +350,17 @@ static int rcu_preempt_blocked_readers_cgp(struct rcu_node *rnp)
>  
>  static void rcu_preempt_read_enter(void)
>  {
> -	current->rcu_read_lock_nesting++;
> +	local_inc(&current->rcu_read_lock_nesting);
>  }
>  
>  static void rcu_preempt_read_exit(void)
>  {
> -	current->rcu_read_lock_nesting--;
> +	local_dec(&current->rcu_read_lock_nesting);
>  }
>  
>  static void rcu_preempt_depth_set(int val)
>  {
> -	current->rcu_read_lock_nesting = val;
> +	local_set(&current->rcu_read_lock_nesting, val);

I agree that this removes the data races, and that the code for x86 is
quite nice, but aren't rcu_read_lock() and rcu_read_unlock() going to
have heavyweight atomic operations on many CPUs?

Maybe I am stuck with arch-specific code in rcu_read_lock() and
rcu_preempt_read_exit().  I suppose worse things could happen.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200725145623.GZ9247%40paulmck-ThinkPad-P72.
