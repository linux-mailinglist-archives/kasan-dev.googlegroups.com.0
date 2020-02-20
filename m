Return-Path: <kasan-dev+bncBAABB4FNXPZAKGQEZUSNAPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 791041666BB
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2020 19:58:58 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id h8sf2680509plr.11
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2020 10:58:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582225136; cv=pass;
        d=google.com; s=arc-20160816;
        b=ISBDXysZpCDxXuweBeCwlVlD/KEXJwlShR1xP076QoNNA4+VjEQleY4hA/mzSk9k2V
         rcPQmeo2+Cq87s1ENU2g6VE77hFzZTKYlv1ao4W7/kwDlsIZdfiSyQoMVMV5HtCmgl35
         9ryFMn7zCX4CqhxSWJCS/UrltnOchQ1bOxHf2xMcmLBosdohYVxEmk/Wyf9+AlvcXkAF
         7dz4Jg16Do2+PStsMhnfVtZaeT77BJHllBlzFKFzCu21nPUE/0NLd+T2xgQBtEI3gd4b
         PS5x97nlVoV6sQmWEU/R1tCRLL6SJ4HD/XBBb6Pqy0AhunxtPa6uBpm3QDvoG/hCKmmw
         0m/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=2R/lyBEIekeXKAk0adD/2s6ceQtbETXIvoEigtJMxJQ=;
        b=ct9Um7jPcRUpw7f3B2XQ8FVXSj27VIPAqlEszhxmq2wNCGk4WrwfB93rfVBMSf0pn5
         eYrOExRGUdDCTiarcdRG8cwgX/FIbBaV/tI1V68vGdxep2drjE/tDxOlQh28tLOGnOWG
         xopBGisgDYmEXRSnxoSvP8FpD/9fne+5aIRG9ItEE537spjLqz+CQ8EfGKd5noCRrm6K
         /SuxJMnfiipXA4YTVRnsqsjIcJuqAE57tKndzlq0QHRawBJ/z92eCsgpzu9K4Rn9/3QG
         yn6s36qL2VAiR3oR7q0cpvafcnPvJXOpHzHDW6b8kZAaDNgx8h6g0ea/QLyf6g2OF1Ws
         i+Bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=gBqcqMbN;
       spf=pass (google.com: domain of srs0=ji+1=4i=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ji+1=4I=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2R/lyBEIekeXKAk0adD/2s6ceQtbETXIvoEigtJMxJQ=;
        b=sCpkM0gHxjniY2Kh3ryJ8FR/P6YCTHshjPR3k6wB0EXtTGzqw/2Decruxbiq25kP4t
         x7eMQyuIZLARiA3W8jIJx6O5hMg98/JBE/2X5WVDrexKxOrmAzV3rkgAGS//MBu14/nI
         DtZ3a701BAFPNniJLv6zWnsd5UnDqyRRLNGMu1JtqF6Mq/JXs2GWIv3dI0H4LCj9zJ2R
         TqFwuhyewxwyAYt2VUaoy2xx9wd6cfBp4QViVPB4RSNYTxwKpEEa6hEprU6g3qNdCsFH
         KugzZa/gB+qOsevxMD6uEH7ETQQ1MOe5GQJB+LDopPg0zvhKN6mjpITwJMqqDBfMElQU
         AHEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2R/lyBEIekeXKAk0adD/2s6ceQtbETXIvoEigtJMxJQ=;
        b=s07nXfvTJIp33un94FZiPLHqpXlJB0UVdFUVzioYFCuZBr4/R2Hv9auZEMS9g0tj9L
         Zv7vsczDu+GD8f/JdWY+pr1LkW3KFMcddVfdK9DN0J7kx0CdRtwg49rBZDRcSld7eqv4
         rxssvxuXw/hGPHkMdWMjFfSFC2xTjtMKcE4/CvO7TYXou+IBHARDnVvfluhL0MaVKCHb
         CdGprMbiRzCtED2IWkg1pNimqIsTU3Lr45pNoonSA9zRbpGZD/wPhYA4VFeGqvV4n99I
         SmfNCScqGCub8g9MSQ7sFJDoORcoG7Lxz3QGkJkDokFom7/506zfP3Vh5nuo0j/62E1S
         luBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXLtu8Sj7agemhwMew1UQIxillaTds5qQ8UHPPvezalb3lxWww6
	swd0aMDkNqXN1LmRGt9+B4M=
X-Google-Smtp-Source: APXvYqyP5SlQmKYJNem9ApyqzichWv7kOhH+1tQ8Hk7kArqYBBa7TBt9fERn3PSasnCglj7PYJv0iA==
X-Received: by 2002:a62:1a97:: with SMTP id a145mr34830241pfa.244.1582225136667;
        Thu, 20 Feb 2020 10:58:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b601:: with SMTP id b1ls9114472pls.3.gmail; Thu, 20
 Feb 2020 10:58:56 -0800 (PST)
X-Received: by 2002:a17:902:8f8a:: with SMTP id z10mr33302871plo.169.1582225136214;
        Thu, 20 Feb 2020 10:58:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582225136; cv=none;
        d=google.com; s=arc-20160816;
        b=s+KBU4MHuEHSWFXp12ERoq5awXHmkBV93BOWbte93EatQS7ueSkMtbsMrplhH3ONY7
         i8E7z6nM0+PtxRmlVt9lAFcHMdVT2oRuMtvyscghDx9CBfD0bB9ODxQFgzf9rsBobXHm
         7T1Emn+uhFejKDiD4zAdZi+LZBBw/T2/NFwOekeS5R2yClatQTHQ4ujRpaI4d6oepOS5
         mCGOYS+h0VFH2f2NRHYHblHq5znEPequkSrO0088bevvFK3Q6VY2Y7rDr9tosNL2Ha8z
         eWUP2PvJJa2xB6pUzjS2mcGZ+F8n1xRKS2bmyfdjK2VUxbuQlYCvDGp3j2od9kvqwxvV
         4Fbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=oxwc4ccAVLohJvfuBUaOV/wQB9jaA8FiblyzrOOkGjs=;
        b=bdfoxW0owIsuFtDPX5DnIa0EYnTKSjm8qHH5vRD4OGtVIdxz65tA4M2AY6OUUvYaax
         BYrzwOWM8ikYwe92JQQtcfEhbvbAtEz1+OX0xU/DzgipzFHnT0D2D7nTzenQ3yjXQkx6
         f3GeNTtL9ApBNs7hDbfnA1AnfQZcrZOQmlb1VPuTopiUeWidbjzJgRNlgnA7qMTvbzUg
         V4xgp1tk+/TuGb5qDMzjNVrN4/0SWxY/glD78yXIyuukliXySklLayOe+r/sk/1nKMjm
         vFDdxJWpmN7tIy8R3LKlS05JNCkRUkVhNo5sIttYNZviHlbVCXW0UcJi8ZojpypV1Ize
         A74g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=gBqcqMbN;
       spf=pass (google.com: domain of srs0=ji+1=4i=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ji+1=4I=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r18si18687pfc.2.2020.02.20.10.58.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Feb 2020 10:58:56 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=ji+1=4i=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id E29C92467A;
	Thu, 20 Feb 2020 18:58:55 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id BADBF352034E; Thu, 20 Feb 2020 10:58:55 -0800 (PST)
Date: Thu, 20 Feb 2020 10:58:55 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kcsan: Add option to allow watcher interruptions
Message-ID: <20200220185855.GY2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200220141551.166537-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200220141551.166537-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=gBqcqMbN;       spf=pass
 (google.com: domain of srs0=ji+1=4i=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ji+1=4I=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Thu, Feb 20, 2020 at 03:15:51PM +0100, Marco Elver wrote:
> Add option to allow interrupts while a watchpoint is set up. This can be
> enabled either via CONFIG_KCSAN_INTERRUPT_WATCHER or via the boot
> parameter 'kcsan.interrupt_watcher=1'.
> 
> Note that, currently not all safe per-CPU access primitives and patterns
> are accounted for, which could result in false positives. For example,
> asm-generic/percpu.h uses plain operations, which by default are
> instrumented. On interrupts and subsequent accesses to the same
> variable, KCSAN would currently report a data race with this option.
> 
> Therefore, this option should currently remain disabled by default, but
> may be enabled for specific test scenarios.
> 
> Signed-off-by: Marco Elver <elver@google.com>

Queued for review and testing, thank you!

> ---
> 
> As an example, the first data race that this found:
> 
> write to 0xffff88806b3324b8 of 4 bytes by interrupt on cpu 0:
>  rcu_preempt_read_enter kernel/rcu/tree_plugin.h:353 [inline]
>  __rcu_read_lock+0x3c/0x50 kernel/rcu/tree_plugin.h:373
>  rcu_read_lock include/linux/rcupdate.h:599 [inline]
>  cpuacct_charge+0x36/0x80 kernel/sched/cpuacct.c:347
>  cgroup_account_cputime include/linux/cgroup.h:773 [inline]
>  update_curr+0xe2/0x1d0 kernel/sched/fair.c:860
>  enqueue_entity+0x130/0x5d0 kernel/sched/fair.c:4005
>  enqueue_task_fair+0xb0/0x420 kernel/sched/fair.c:5260
>  enqueue_task kernel/sched/core.c:1302 [inline]
>  activate_task+0x6d/0x110 kernel/sched/core.c:1324
>  ttwu_do_activate.isra.0+0x40/0x60 kernel/sched/core.c:2266
>  ttwu_queue kernel/sched/core.c:2411 [inline]
>  try_to_wake_up+0x3be/0x6c0 kernel/sched/core.c:2645
>  wake_up_process+0x10/0x20 kernel/sched/core.c:2669
>  hrtimer_wakeup+0x4c/0x60 kernel/time/hrtimer.c:1769
>  __run_hrtimer kernel/time/hrtimer.c:1517 [inline]
>  __hrtimer_run_queues+0x274/0x5f0 kernel/time/hrtimer.c:1579
>  hrtimer_interrupt+0x22d/0x490 kernel/time/hrtimer.c:1641
>  local_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1119 [inline]
>  smp_apic_timer_interrupt+0xdc/0x280 arch/x86/kernel/apic/apic.c:1144
>  apic_timer_interrupt+0xf/0x20 arch/x86/entry/entry_64.S:829
>  delay_tsc+0x38/0xc0 arch/x86/lib/delay.c:68                   <--- interrupt while delayed
>  __delay arch/x86/lib/delay.c:161 [inline]
>  __const_udelay+0x33/0x40 arch/x86/lib/delay.c:175
>  __udelay+0x10/0x20 arch/x86/lib/delay.c:181
>  kcsan_setup_watchpoint+0x17f/0x400 kernel/kcsan/core.c:428
>  check_access kernel/kcsan/core.c:550 [inline]
>  __tsan_read4+0xc6/0x100 kernel/kcsan/core.c:685               <--- Enter KCSAN runtime
>  rcu_preempt_read_enter kernel/rcu/tree_plugin.h:353 [inline]  <---+
>  __rcu_read_lock+0x2a/0x50 kernel/rcu/tree_plugin.h:373            |
>  rcu_read_lock include/linux/rcupdate.h:599 [inline]               |
>  lock_page_memcg+0x31/0x110 mm/memcontrol.c:1972                   |
>                                                                    |
> read to 0xffff88806b3324b8 of 4 bytes by task 6131 on cpu 0:       |
>  rcu_preempt_read_enter kernel/rcu/tree_plugin.h:353 [inline]  ----+
>  __rcu_read_lock+0x2a/0x50 kernel/rcu/tree_plugin.h:373
>  rcu_read_lock include/linux/rcupdate.h:599 [inline]
>  lock_page_memcg+0x31/0x110 mm/memcontrol.c:1972
> 
> The writer is doing 'current->rcu_read_lock_nesting++'. The read is as
> vulnerable to compiler optimizations and would therefore conclude this
> is a valid data race.

Heh!  That one is a fun one!  It is on a very hot fastpath.  READ_ONCE()
and WRITE_ONCE() are likely to be measurable at the system level.

Thoughts on other options?

							Thanx, Paul

> ---
>  kernel/kcsan/core.c | 30 ++++++++----------------------
>  lib/Kconfig.kcsan   | 11 +++++++++++
>  2 files changed, 19 insertions(+), 22 deletions(-)
> 
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 589b1e7f0f253..43eb5f850c68e 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -21,6 +21,7 @@ static bool kcsan_early_enable = IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE);
>  static unsigned int kcsan_udelay_task = CONFIG_KCSAN_UDELAY_TASK;
>  static unsigned int kcsan_udelay_interrupt = CONFIG_KCSAN_UDELAY_INTERRUPT;
>  static long kcsan_skip_watch = CONFIG_KCSAN_SKIP_WATCH;
> +static bool kcsan_interrupt_watcher = IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER);
>  
>  #ifdef MODULE_PARAM_PREFIX
>  #undef MODULE_PARAM_PREFIX
> @@ -30,6 +31,7 @@ module_param_named(early_enable, kcsan_early_enable, bool, 0);
>  module_param_named(udelay_task, kcsan_udelay_task, uint, 0644);
>  module_param_named(udelay_interrupt, kcsan_udelay_interrupt, uint, 0644);
>  module_param_named(skip_watch, kcsan_skip_watch, long, 0644);
> +module_param_named(interrupt_watcher, kcsan_interrupt_watcher, bool, 0444);
>  
>  bool kcsan_enabled;
>  
> @@ -354,7 +356,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>  	unsigned long access_mask;
>  	enum kcsan_value_change value_change = KCSAN_VALUE_CHANGE_MAYBE;
>  	unsigned long ua_flags = user_access_save();
> -	unsigned long irq_flags;
> +	unsigned long irq_flags = 0;
>  
>  	/*
>  	 * Always reset kcsan_skip counter in slow-path to avoid underflow; see
> @@ -370,26 +372,9 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>  		goto out;
>  	}
>  
> -	/*
> -	 * Disable interrupts & preemptions to avoid another thread on the same
> -	 * CPU accessing memory locations for the set up watchpoint; this is to
> -	 * avoid reporting races to e.g. CPU-local data.
> -	 *
> -	 * An alternative would be adding the source CPU to the watchpoint
> -	 * encoding, and checking that watchpoint-CPU != this-CPU. There are
> -	 * several problems with this:
> -	 *   1. we should avoid stealing more bits from the watchpoint encoding
> -	 *      as it would affect accuracy, as well as increase performance
> -	 *      overhead in the fast-path;
> -	 *   2. if we are preempted, but there *is* a genuine data race, we
> -	 *      would *not* report it -- since this is the common case (vs.
> -	 *      CPU-local data accesses), it makes more sense (from a data race
> -	 *      detection point of view) to simply disable preemptions to ensure
> -	 *      as many tasks as possible run on other CPUs.
> -	 *
> -	 * Use raw versions, to avoid lockdep recursion via IRQ flags tracing.
> -	 */
> -	raw_local_irq_save(irq_flags);
> +	if (!kcsan_interrupt_watcher)
> +		/* Use raw to avoid lockdep recursion via IRQ flags tracing. */
> +		raw_local_irq_save(irq_flags);
>  
>  	watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
>  	if (watchpoint == NULL) {
> @@ -524,7 +509,8 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>  
>  	kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
>  out_unlock:
> -	raw_local_irq_restore(irq_flags);
> +	if (!kcsan_interrupt_watcher)
> +		raw_local_irq_restore(irq_flags);
>  out:
>  	user_access_restore(ua_flags);
>  }
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index ba9268076cfbc..0f1447ff8f558 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -101,6 +101,17 @@ config KCSAN_SKIP_WATCH_RANDOMIZE
>  	  KCSAN_WATCH_SKIP. If false, the chosen value is always
>  	  KCSAN_WATCH_SKIP.
>  
> +config KCSAN_INTERRUPT_WATCHER
> +	bool "Interruptible watchers"
> +	help
> +	  If enabled, a task that set up a watchpoint may be interrupted while
> +	  delayed. This option will allow KCSAN to detect races between
> +	  interrupted tasks and other threads of execution on the same CPU.
> +
> +	  Currently disabled by default, because not all safe per-CPU access
> +	  primitives and patterns may be accounted for, and therefore could
> +	  result in false positives.
> +
>  config KCSAN_REPORT_ONCE_IN_MS
>  	int "Duration in milliseconds, in which any given race is only reported once"
>  	default 3000
> -- 
> 2.25.0.265.gbab2e86ba0-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200220185855.GY2935%40paulmck-ThinkPad-P72.
