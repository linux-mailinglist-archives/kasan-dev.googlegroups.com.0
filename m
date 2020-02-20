Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJXWXPZAKGQEUCZ2IHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3438E1669E0
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2020 22:33:27 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id t6sf460068ljh.11
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2020 13:33:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582234406; cv=pass;
        d=google.com; s=arc-20160816;
        b=OKbY8kXa/bZx0kTxc5RyMg0SUpT7cMPFChkXrJaGsGMP43XWTUXdwVfkGReZXcgNS7
         5NQ9VIpUH8G0+P+lJ1FjNbrOhOUp3kQDCYZRUx8Ou3yL73a5KigNYzsTv4txQh2xkiXQ
         nsjfHqtvjy5gcwG5MIBp8IXUp44V9whgH+dF7vnHgVIL3SIKkO/e4UgVqHOi5TziIrt0
         6m6h9P/YIoeCJz7yT2CS9WUqLDxr4c54YOgHMTyaUTfu/q5CawF8a3RCWoE6W03zf0mz
         aKiT661OjXjWnP1IrPX60Ij7KLu47Mqn77uvm3sHLnhbTvcbrtQghxmBO68Eu0hIdEY3
         XiXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=D+X37S0ifO6gk1rJAICLmyix06pcvLXvJNubwOiUJnA=;
        b=ZY0uUdZ3qZ4OYkHrqKlF0gHai7bmE4WpaBZU5xnThrLlxN27/1h9yXWm2IpJxl9MCN
         neVhyh2LZvyvzrZsOJwYuqkccn/bSvSnMbwF79RbJIoFEYxGwFTqpzw95VRkS5kyxelV
         41xCu+9v7n2P4njQYVO4RQeA8aedi9kqY4i6FlVwezVtZLFhF96F36p9WxtjG+t7YFqP
         CBI/s7SueHu7Kjh98pvMCOLg/OIb0EcJQ6y8ZXuJQCroveoN8nTd4plpF99n7/iAXBBs
         RULwZ+CqopSCU0WWIbXF7YA55gSi/EHN72XZhSbwT6xQXBImc9PWooq0uf1CadLbEzin
         DSNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hrM22W3W;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=D+X37S0ifO6gk1rJAICLmyix06pcvLXvJNubwOiUJnA=;
        b=S9avDjH1WabnU3mLNnQTW8HCvEmXJwqyBnRdELJ+uPkIGPyWFc3F+DHdOIpuk+bQ9W
         wZVNUJRO+OCH3LBu3txL/hEYcfnY+DOa+PcifUPA8QnsXbvzsoDFGwqSeaWIzo1JF72Q
         maQz3nOcg76q/jnYnMJUL+OlUAWsjnwk6Mm6Y9Lj7/BjWNhrXoAsQIGMC2bCli9UymzF
         GGMIhe3aMYTcjbULGxlulNTSu0Xx1P0ANPzx7CyigqIbYSLGNksDy/yh9Ut2DgZj3fqU
         obi8WVQi61ipwBaLtry7v2ad3MxsEslxDKRgdo4yuMYnRMGA/KTuD+s271JscR/I7Yd4
         sRwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=D+X37S0ifO6gk1rJAICLmyix06pcvLXvJNubwOiUJnA=;
        b=G8WEaIc5eWRBtMjHMlU3Pjk1yNAjBYP1rMvIe3kp9+sAjDqockPJVWyfLdEPWX98Xf
         JVIf2xv8OaBWB2ARYcU8/4Qw1qoH0ztIjMG1N8bAMgRUNI9Wgw49M6Kx2/2e9lMBNgZi
         gqnPZ2bG4T/aUmi3pypYlw49V5MwZPSSxJ/cuRnTdSKBXADkW1NlNRCJRLikVHzrPuF1
         eRJmUd32jDMNgc1X23ETDqi9GEfSUpvaj3hDEzSCOFO896y7uciS/c7CbO5JWXmgxbl5
         mLlNpIrt2M+L/DINUL3hIQ/fTaqVMN9BHfUaPlBF0Q+hriNfh/KV6+BxzEFLPpmsGsMN
         tEIQ==
X-Gm-Message-State: APjAAAX7GZ2GxCuekA9ehcAk/H3CD/aghXZCbCweL+6s+6Yzt1o8sg2T
	Apx2AdwMsX4XbjWKlGxXTCY=
X-Google-Smtp-Source: APXvYqylErnkgNwx3nQhqdFARRRLw4BRle+NGRQulLBSygzv1VEN4+CY4+NxBc/06ke9wsczfkQuMw==
X-Received: by 2002:a2e:98c6:: with SMTP id s6mr20134909ljj.14.1582234406546;
        Thu, 20 Feb 2020 13:33:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:518f:: with SMTP id u15ls3086968lfi.3.gmail; Thu, 20 Feb
 2020 13:33:25 -0800 (PST)
X-Received: by 2002:a05:6512:31ca:: with SMTP id j10mr6120849lfe.110.1582234405739;
        Thu, 20 Feb 2020 13:33:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582234405; cv=none;
        d=google.com; s=arc-20160816;
        b=YkccoM1uit4ofRd8NFJlPkzsQWcCDhrpZAN0wM4846gboWqZkdQv2Vm02/8Y/R+z7r
         ifj5L9Qpiek1jrCA7pYR+oH9NlfU9+GFN1ISp5LIQO7LmquQmTnreGO4B/6agzp9+Ldc
         g/B/FRSxYbrdlOeqVHJ240Bg2UytYtQGKYo/GMm3zrFjVNtgEXdDKvXgc0J2oHA8CgGF
         AIxz9ldOFIXwn0v/pnh0CEvmJCZOR79ubcUzxzBSEmq6xLZn1N/SxrBaQc8tBj/ETHGY
         VY/El/aGhHfBZDALFLUjSmk5gDADmljl7BgIMv2ozObmk1A8TwtptKwTLn+UU3Fw20SD
         wfIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=h/6mqJ7J0kdf9iYU8k/XIKFGrRZibfs8BWFcrfPQu2E=;
        b=D+KSFRj0Am0EyIwdv0Ddk/0db33DNlie1TSabFR5h3hja2VDRGHPzd391ygoFzgfW5
         WOs9kAfkvoWB7De+Vf90RLKU3i/p/0OaIKVRDahxzECk1BRN7kcNWKD+pgz8DcTbNEJ7
         pmzDez3yu+SVCxPAKtj9ZMcuvVtSl7sEHKW5iHNfx4dJSZDXi9VXeC5eL8kOSvePgi6H
         fn565YIwspiQmhfhIQh8jpdNpFBaR/W7NWs3RDoYWiZfeL2w8EHkELbCDkGm2aosrxpD
         IyvHgFM9nTqhHuM+KdcTSwNqn82GEIOc3tCB5m1yGMN+A3zNiQndpfOKcVDwD66SyZWL
         /a0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hrM22W3W;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id j30si33798lfp.5.2020.02.20.13.33.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Feb 2020 13:33:25 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id g3so6214918wrs.12
        for <kasan-dev@googlegroups.com>; Thu, 20 Feb 2020 13:33:25 -0800 (PST)
X-Received: by 2002:adf:aadb:: with SMTP id i27mr46656435wrc.105.1582234404712;
        Thu, 20 Feb 2020 13:33:24 -0800 (PST)
Received: from google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id c15sm1082670wrt.1.2020.02.20.13.33.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 20 Feb 2020 13:33:23 -0800 (PST)
Date: Thu, 20 Feb 2020 22:33:17 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kcsan: Add option to allow watcher interruptions
Message-ID: <20200220213317.GA35033@google.com>
References: <20200220141551.166537-1-elver@google.com>
 <20200220185855.GY2935@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200220185855.GY2935@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=hrM22W3W;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as
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



On Thu, 20 Feb 2020, Paul E. McKenney wrote:

> On Thu, Feb 20, 2020 at 03:15:51PM +0100, Marco Elver wrote:
> > Add option to allow interrupts while a watchpoint is set up. This can be
> > enabled either via CONFIG_KCSAN_INTERRUPT_WATCHER or via the boot
> > parameter 'kcsan.interrupt_watcher=1'.
> > 
> > Note that, currently not all safe per-CPU access primitives and patterns
> > are accounted for, which could result in false positives. For example,
> > asm-generic/percpu.h uses plain operations, which by default are
> > instrumented. On interrupts and subsequent accesses to the same
> > variable, KCSAN would currently report a data race with this option.
> > 
> > Therefore, this option should currently remain disabled by default, but
> > may be enabled for specific test scenarios.
> > 
> > Signed-off-by: Marco Elver <elver@google.com>
> 
> Queued for review and testing, thank you!
> 
> > ---
> > 
> > As an example, the first data race that this found:
> > 
> > write to 0xffff88806b3324b8 of 4 bytes by interrupt on cpu 0:
> >  rcu_preempt_read_enter kernel/rcu/tree_plugin.h:353 [inline]
> >  __rcu_read_lock+0x3c/0x50 kernel/rcu/tree_plugin.h:373
> >  rcu_read_lock include/linux/rcupdate.h:599 [inline]
> >  cpuacct_charge+0x36/0x80 kernel/sched/cpuacct.c:347
> >  cgroup_account_cputime include/linux/cgroup.h:773 [inline]
> >  update_curr+0xe2/0x1d0 kernel/sched/fair.c:860
> >  enqueue_entity+0x130/0x5d0 kernel/sched/fair.c:4005
> >  enqueue_task_fair+0xb0/0x420 kernel/sched/fair.c:5260
> >  enqueue_task kernel/sched/core.c:1302 [inline]
> >  activate_task+0x6d/0x110 kernel/sched/core.c:1324
> >  ttwu_do_activate.isra.0+0x40/0x60 kernel/sched/core.c:2266
> >  ttwu_queue kernel/sched/core.c:2411 [inline]
> >  try_to_wake_up+0x3be/0x6c0 kernel/sched/core.c:2645
> >  wake_up_process+0x10/0x20 kernel/sched/core.c:2669
> >  hrtimer_wakeup+0x4c/0x60 kernel/time/hrtimer.c:1769
> >  __run_hrtimer kernel/time/hrtimer.c:1517 [inline]
> >  __hrtimer_run_queues+0x274/0x5f0 kernel/time/hrtimer.c:1579
> >  hrtimer_interrupt+0x22d/0x490 kernel/time/hrtimer.c:1641
> >  local_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1119 [inline]
> >  smp_apic_timer_interrupt+0xdc/0x280 arch/x86/kernel/apic/apic.c:1144
> >  apic_timer_interrupt+0xf/0x20 arch/x86/entry/entry_64.S:829
> >  delay_tsc+0x38/0xc0 arch/x86/lib/delay.c:68                   <--- interrupt while delayed
> >  __delay arch/x86/lib/delay.c:161 [inline]
> >  __const_udelay+0x33/0x40 arch/x86/lib/delay.c:175
> >  __udelay+0x10/0x20 arch/x86/lib/delay.c:181
> >  kcsan_setup_watchpoint+0x17f/0x400 kernel/kcsan/core.c:428
> >  check_access kernel/kcsan/core.c:550 [inline]
> >  __tsan_read4+0xc6/0x100 kernel/kcsan/core.c:685               <--- Enter KCSAN runtime
> >  rcu_preempt_read_enter kernel/rcu/tree_plugin.h:353 [inline]  <---+
> >  __rcu_read_lock+0x2a/0x50 kernel/rcu/tree_plugin.h:373            |
> >  rcu_read_lock include/linux/rcupdate.h:599 [inline]               |
> >  lock_page_memcg+0x31/0x110 mm/memcontrol.c:1972                   |
> >                                                                    |
> > read to 0xffff88806b3324b8 of 4 bytes by task 6131 on cpu 0:       |
> >  rcu_preempt_read_enter kernel/rcu/tree_plugin.h:353 [inline]  ----+
> >  __rcu_read_lock+0x2a/0x50 kernel/rcu/tree_plugin.h:373
> >  rcu_read_lock include/linux/rcupdate.h:599 [inline]
> >  lock_page_memcg+0x31/0x110 mm/memcontrol.c:1972
> > 
> > The writer is doing 'current->rcu_read_lock_nesting++'. The read is as
> > vulnerable to compiler optimizations and would therefore conclude this
> > is a valid data race.
> 
> Heh!  That one is a fun one!  It is on a very hot fastpath.  READ_ONCE()
> and WRITE_ONCE() are likely to be measurable at the system level.
> 
> Thoughts on other options?

Would this be a use-case for local_t? Don't think this_cpu ops work
here.

See below idea. This would avoid the data race (KCSAN stopped
complaining) and seems to generate reasonable code.

Version before:

 <__rcu_read_lock>:
     130	mov    %gs:0x0,%rax
     137
     139	addl   $0x1,0x370(%rax)
     140	retq   
     141	data16 nopw %cs:0x0(%rax,%rax,1)
     148
     14c	nopl   0x0(%rax)

Version after:

 <__rcu_read_lock>:
     130	mov    %gs:0x0,%rax
     137
     139	incq   0x370(%rax)
     140	retq   
     141	data16 nopw %cs:0x0(%rax,%rax,1)
     148
     14c	nopl   0x0(%rax)

I haven't checked the other places where it is used, though.
(Can send it as a patch if you think this might work.)

Thanks,
-- Marco

diff --git a/include/linux/rcupdate.h b/include/linux/rcupdate.h
index 2678a37c31696..3d8586ee7ae64 100644
--- a/include/linux/rcupdate.h
+++ b/include/linux/rcupdate.h
@@ -50,7 +50,7 @@ void __rcu_read_unlock(void);
  * nesting depth, but makes sense only if CONFIG_PREEMPT_RCU -- in other
  * types of kernel builds, the rcu_read_lock() nesting depth is unknowable.
  */
-#define rcu_preempt_depth() (current->rcu_read_lock_nesting)
+#define rcu_preempt_depth() local_read(&current->rcu_read_lock_nesting)
 
 #else /* #ifdef CONFIG_PREEMPT_RCU */
 
diff --git a/include/linux/sched.h b/include/linux/sched.h
index 0918904c939d2..70d7e3257feed 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -10,6 +10,7 @@
 #include <uapi/linux/sched.h>
 
 #include <asm/current.h>
+#include <asm/local.h>
 
 #include <linux/pid.h>
 #include <linux/sem.h>
@@ -708,7 +709,7 @@ struct task_struct {
 	cpumask_t			cpus_mask;
 
 #ifdef CONFIG_PREEMPT_RCU
-	int				rcu_read_lock_nesting;
+	local_t				rcu_read_lock_nesting;
 	union rcu_special		rcu_read_unlock_special;
 	struct list_head		rcu_node_entry;
 	struct rcu_node			*rcu_blocked_node;
diff --git a/init/init_task.c b/init/init_task.c
index 096191d177d5c..941777fce11e5 100644
--- a/init/init_task.c
+++ b/init/init_task.c
@@ -130,7 +130,7 @@ struct task_struct init_task
 	.perf_event_list = LIST_HEAD_INIT(init_task.perf_event_list),
 #endif
 #ifdef CONFIG_PREEMPT_RCU
-	.rcu_read_lock_nesting = 0,
+	.rcu_read_lock_nesting = LOCAL_INIT(0),
 	.rcu_read_unlock_special.s = 0,
 	.rcu_node_entry = LIST_HEAD_INIT(init_task.rcu_node_entry),
 	.rcu_blocked_node = NULL,
diff --git a/kernel/fork.c b/kernel/fork.c
index 60a1295f43843..43af326081b06 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -1669,7 +1669,7 @@ init_task_pid(struct task_struct *task, enum pid_type type, struct pid *pid)
 static inline void rcu_copy_process(struct task_struct *p)
 {
 #ifdef CONFIG_PREEMPT_RCU
-	p->rcu_read_lock_nesting = 0;
+	local_set(&p->rcu_read_lock_nesting, 0);
 	p->rcu_read_unlock_special.s = 0;
 	p->rcu_blocked_node = NULL;
 	INIT_LIST_HEAD(&p->rcu_node_entry);
diff --git a/kernel/rcu/tree_plugin.h b/kernel/rcu/tree_plugin.h
index c6ea81cd41890..e0595abd50c0f 100644
--- a/kernel/rcu/tree_plugin.h
+++ b/kernel/rcu/tree_plugin.h
@@ -350,17 +350,17 @@ static int rcu_preempt_blocked_readers_cgp(struct rcu_node *rnp)
 
 static void rcu_preempt_read_enter(void)
 {
-	current->rcu_read_lock_nesting++;
+	local_inc(&current->rcu_read_lock_nesting);
 }
 
 static void rcu_preempt_read_exit(void)
 {
-	current->rcu_read_lock_nesting--;
+	local_dec(&current->rcu_read_lock_nesting);
 }
 
 static void rcu_preempt_depth_set(int val)
 {
-	current->rcu_read_lock_nesting = val;
+	local_set(&current->rcu_read_lock_nesting, val);
 }
 
 /*

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200220213317.GA35033%40google.com.
