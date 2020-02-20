Return-Path: <kasan-dev+bncBC7OBJGL2MHBBINJXLZAKGQEKQHLYUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 99C41165F89
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2020 15:16:01 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id m21sf2784468edp.14
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2020 06:16:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582208161; cv=pass;
        d=google.com; s=arc-20160816;
        b=Dst5yMQOAt0pqhmsrc9vPtJe5p6YfQTgG0p9xZj8wc5vTheBIc2mk1xgrfltxuK5bX
         78q+W/9eH+lMTgEk7v2vzeC/GvfVQDNrAIO6+do4Fo94M/5BhOG6rQJnva0vZVGazNXv
         ZMixZhALhnZRRvQDc3AdbABayJGyBroIIFErneQbx8xmfxfj1gkByCKATMdyK7Z7jdCB
         xpSm5oZtwr2ROsTjO23Q7U2FzSNgsL9blTX7jx3iaN5PuNztsQzdETpG9ARKqYKldbKp
         uwmUX5hHNHRziQ/kJc+CyV6hELvh3aunkNhFYZ5p68eYL7oQIF1K0l1rsP2oVYyt9zqe
         Es8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=s6AphT4KH59eaCGRBCGg8yywo8yslUkDKx0x/wSYfX4=;
        b=BvCfmfGmLeDLLam6jW9mXj1J0nmm1GXfX2kGIDV3tfOz/zAiaM4qiw3COYvoNi5DKn
         NMFCZnk304MCvaNQw0dKrXHmzlJfriTyuDVLYW5H96R7kYYjlrgvUMG5jviSfpz3Dw+H
         ujq+wBbPQUQfOh/b9yJ6ifA67cLMy5lF7Yk+Dmm69cmqxSdIogsWeKF+Fio179MCKLmZ
         lmXkfap12mzXs6Kr8OLb50DFCB3Ar9BkgofdLXuk2sXkkIhVwv0Pd18idAuE9Mu4VTq/
         GAU672eCzVB0psTwZNm9wt1LcZMs/Hx+8kDLAZvbMS89+LVIfKljZsZgDCCRnD4QjwXH
         N+Yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Dn4hLPZz;
       spf=pass (google.com: domain of 3n5roxgukcfognxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3n5ROXgUKCfognxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=s6AphT4KH59eaCGRBCGg8yywo8yslUkDKx0x/wSYfX4=;
        b=CZX/rH+hIqMtBmjBZzDOFCAsOtotgA74ZQHv968TvIVfwXWvKtV85l2UVfSD5kXMfL
         gdQsRYXyti7WOk+zr4kYQZA61Jd7jgUvwI5RpAvPc7dvrICbXH8lHYzHb0YMs/90IrF1
         aI5a2Ch6OxRuJFv8iARxGIwOQ7/PW3yzOH+torrbPkybdaR33lqfKvBm7uVJyxVNafjt
         6T3kN4iTaEUXc/Vdadbs+BsRT+Ipgrmlfw6mL4RTwYDtejtl0D6zx1qLcuhIJdwEJAWU
         WjEArJlQ/GxXTDzdFAN2Aonp7+i0f32zzol/sz67wS3pjHjwv1788lNATEbytKEdJewm
         C1Eg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=s6AphT4KH59eaCGRBCGg8yywo8yslUkDKx0x/wSYfX4=;
        b=YqyL0Fvcx2MNz9RwcaFWJEJrgaTZvxRdvbN44vHUlUgejq6ZaOh0E0fDv3D77xR1xV
         UbfSMbdEukL/TC6/O7peCSRkm4Fuf/5p5/hWSQjrwi3Vc9nSqr6uwc6SMa/hA2b4OwYA
         L3gwX2+DuiMA3KEdNa++FSIjQ+USexyDguV6+yPv/LuKTnIdwYq8Vgl8ISOM85ssS52j
         8aDrA602wXnwYUSkP9sJWj1xMcSA2GJk7CDzAVX/KANdQ0wljcH+6ZtH6lylXxAmh45R
         vygFq0VHi0Az5IG6I8XRtuaXui6ZyUegsN7VDhQRr+Wyd5/kPqkLcyWpXG6Ez/6E614m
         uhaA==
X-Gm-Message-State: APjAAAUs8KR9Hfe9N72kGebxoWA5W8n+K1sQY1pdDg0xBi6QcCT4+dmq
	cKEXekVUx9z5/i2bKyRmLhQ=
X-Google-Smtp-Source: APXvYqx/Ys4AgQab6bv/kyodOINm6yT6G5mA3ZtLELW2P8dLUMe8LgMFGcttF2+mhzkSKe1ICrV94Q==
X-Received: by 2002:aa7:d1d0:: with SMTP id g16mr29046710edp.56.1582208161330;
        Thu, 20 Feb 2020 06:16:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c0d1:: with SMTP id j17ls10194452edp.4.gmail; Thu, 20
 Feb 2020 06:16:00 -0800 (PST)
X-Received: by 2002:a50:f70d:: with SMTP id g13mr28964724edn.80.1582208160363;
        Thu, 20 Feb 2020 06:16:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582208160; cv=none;
        d=google.com; s=arc-20160816;
        b=D/8yxOsS+IfPfaPYEzqxU7yN7MMMn4XPtAm0rUcSXgSk6ceC+ByCjkcM5lEUiAwLJ8
         rRRHnb7vLHE5BrFO3qpebUuibjBOt9tvOVNQtBY0TNVduN61TSC6W0WFwbYo6XAYc0+4
         /+cw9YOcU3vQ7b0vHqTV40YmqFgpZ0yFRUQiRyPDDfh7otqINKjYbf1AWhUZ2jpqsVg+
         dr1MUzR+nDbqntNMAkxgzxmWl0KLLXWa2KN/D63Ighvq52eicFhrQ9NNogyWjmw26W0c
         /eKEzu8bcS37TBJK1/DNs5hTYFYJC00g454QsV8BkPwpHBcAV+IJZP2KvmgX0LIV2b2O
         8RSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=KvrVRvnTainfLUNEVicj5vB+FMWhRD8P5T9JfeiRjxw=;
        b=SgRTmZ8lNwVpOJKSGsRlwry1chpuhkF51p4K7M6T0bygvrLNSF8xU+hhMN7aCskNbs
         Ogk3hjIVa0H21E+e6ogVYd1H5hZKBf7cWkCpWTcDkE23q0XuvWHwQcAmkHpLCYvLBco5
         boMhBrJMLgm8QG9kmh8EomNiUH7XfCxENackeoLZs1kbttYcFbgp5QbraMMvZKcCIQ5T
         fQ6CDX2wHfryyYOYKEezo/qTttMeM3UUYn9+ObTaIpKc7SwRMC5OtmQJi1DgFlYufhG1
         S1M+7um3+ANpFyCEcUh5O/huh8yS0wNZs7aAhKCkW/KlDZk4XQvQfFTKLCzT89XglMc6
         8yzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Dn4hLPZz;
       spf=pass (google.com: domain of 3n5roxgukcfognxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3n5ROXgUKCfognxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id z20si140015ejx.1.2020.02.20.06.16.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Feb 2020 06:16:00 -0800 (PST)
Received-SPF: pass (google.com: domain of 3n5roxgukcfognxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id a12so1789494wrn.19
        for <kasan-dev@googlegroups.com>; Thu, 20 Feb 2020 06:16:00 -0800 (PST)
X-Received: by 2002:adf:ef92:: with SMTP id d18mr40898485wro.234.1582208159510;
 Thu, 20 Feb 2020 06:15:59 -0800 (PST)
Date: Thu, 20 Feb 2020 15:15:51 +0100
Message-Id: <20200220141551.166537-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.265.gbab2e86ba0-goog
Subject: [PATCH] kcsan: Add option to allow watcher interruptions
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Dn4hLPZz;       spf=pass
 (google.com: domain of 3n5roxgukcfognxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3n5ROXgUKCfognxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

Add option to allow interrupts while a watchpoint is set up. This can be
enabled either via CONFIG_KCSAN_INTERRUPT_WATCHER or via the boot
parameter 'kcsan.interrupt_watcher=1'.

Note that, currently not all safe per-CPU access primitives and patterns
are accounted for, which could result in false positives. For example,
asm-generic/percpu.h uses plain operations, which by default are
instrumented. On interrupts and subsequent accesses to the same
variable, KCSAN would currently report a data race with this option.

Therefore, this option should currently remain disabled by default, but
may be enabled for specific test scenarios.

Signed-off-by: Marco Elver <elver@google.com>
---

As an example, the first data race that this found:

write to 0xffff88806b3324b8 of 4 bytes by interrupt on cpu 0:
 rcu_preempt_read_enter kernel/rcu/tree_plugin.h:353 [inline]
 __rcu_read_lock+0x3c/0x50 kernel/rcu/tree_plugin.h:373
 rcu_read_lock include/linux/rcupdate.h:599 [inline]
 cpuacct_charge+0x36/0x80 kernel/sched/cpuacct.c:347
 cgroup_account_cputime include/linux/cgroup.h:773 [inline]
 update_curr+0xe2/0x1d0 kernel/sched/fair.c:860
 enqueue_entity+0x130/0x5d0 kernel/sched/fair.c:4005
 enqueue_task_fair+0xb0/0x420 kernel/sched/fair.c:5260
 enqueue_task kernel/sched/core.c:1302 [inline]
 activate_task+0x6d/0x110 kernel/sched/core.c:1324
 ttwu_do_activate.isra.0+0x40/0x60 kernel/sched/core.c:2266
 ttwu_queue kernel/sched/core.c:2411 [inline]
 try_to_wake_up+0x3be/0x6c0 kernel/sched/core.c:2645
 wake_up_process+0x10/0x20 kernel/sched/core.c:2669
 hrtimer_wakeup+0x4c/0x60 kernel/time/hrtimer.c:1769
 __run_hrtimer kernel/time/hrtimer.c:1517 [inline]
 __hrtimer_run_queues+0x274/0x5f0 kernel/time/hrtimer.c:1579
 hrtimer_interrupt+0x22d/0x490 kernel/time/hrtimer.c:1641
 local_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1119 [inline]
 smp_apic_timer_interrupt+0xdc/0x280 arch/x86/kernel/apic/apic.c:1144
 apic_timer_interrupt+0xf/0x20 arch/x86/entry/entry_64.S:829
 delay_tsc+0x38/0xc0 arch/x86/lib/delay.c:68                   <--- interrupt while delayed
 __delay arch/x86/lib/delay.c:161 [inline]
 __const_udelay+0x33/0x40 arch/x86/lib/delay.c:175
 __udelay+0x10/0x20 arch/x86/lib/delay.c:181
 kcsan_setup_watchpoint+0x17f/0x400 kernel/kcsan/core.c:428
 check_access kernel/kcsan/core.c:550 [inline]
 __tsan_read4+0xc6/0x100 kernel/kcsan/core.c:685               <--- Enter KCSAN runtime
 rcu_preempt_read_enter kernel/rcu/tree_plugin.h:353 [inline]  <---+
 __rcu_read_lock+0x2a/0x50 kernel/rcu/tree_plugin.h:373            |
 rcu_read_lock include/linux/rcupdate.h:599 [inline]               |
 lock_page_memcg+0x31/0x110 mm/memcontrol.c:1972                   |
                                                                   |
read to 0xffff88806b3324b8 of 4 bytes by task 6131 on cpu 0:       |
 rcu_preempt_read_enter kernel/rcu/tree_plugin.h:353 [inline]  ----+
 __rcu_read_lock+0x2a/0x50 kernel/rcu/tree_plugin.h:373
 rcu_read_lock include/linux/rcupdate.h:599 [inline]
 lock_page_memcg+0x31/0x110 mm/memcontrol.c:1972

The writer is doing 'current->rcu_read_lock_nesting++'. The read is as
vulnerable to compiler optimizations and would therefore conclude this
is a valid data race.
---
 kernel/kcsan/core.c | 30 ++++++++----------------------
 lib/Kconfig.kcsan   | 11 +++++++++++
 2 files changed, 19 insertions(+), 22 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 589b1e7f0f253..43eb5f850c68e 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -21,6 +21,7 @@ static bool kcsan_early_enable = IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE);
 static unsigned int kcsan_udelay_task = CONFIG_KCSAN_UDELAY_TASK;
 static unsigned int kcsan_udelay_interrupt = CONFIG_KCSAN_UDELAY_INTERRUPT;
 static long kcsan_skip_watch = CONFIG_KCSAN_SKIP_WATCH;
+static bool kcsan_interrupt_watcher = IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER);
 
 #ifdef MODULE_PARAM_PREFIX
 #undef MODULE_PARAM_PREFIX
@@ -30,6 +31,7 @@ module_param_named(early_enable, kcsan_early_enable, bool, 0);
 module_param_named(udelay_task, kcsan_udelay_task, uint, 0644);
 module_param_named(udelay_interrupt, kcsan_udelay_interrupt, uint, 0644);
 module_param_named(skip_watch, kcsan_skip_watch, long, 0644);
+module_param_named(interrupt_watcher, kcsan_interrupt_watcher, bool, 0444);
 
 bool kcsan_enabled;
 
@@ -354,7 +356,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	unsigned long access_mask;
 	enum kcsan_value_change value_change = KCSAN_VALUE_CHANGE_MAYBE;
 	unsigned long ua_flags = user_access_save();
-	unsigned long irq_flags;
+	unsigned long irq_flags = 0;
 
 	/*
 	 * Always reset kcsan_skip counter in slow-path to avoid underflow; see
@@ -370,26 +372,9 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		goto out;
 	}
 
-	/*
-	 * Disable interrupts & preemptions to avoid another thread on the same
-	 * CPU accessing memory locations for the set up watchpoint; this is to
-	 * avoid reporting races to e.g. CPU-local data.
-	 *
-	 * An alternative would be adding the source CPU to the watchpoint
-	 * encoding, and checking that watchpoint-CPU != this-CPU. There are
-	 * several problems with this:
-	 *   1. we should avoid stealing more bits from the watchpoint encoding
-	 *      as it would affect accuracy, as well as increase performance
-	 *      overhead in the fast-path;
-	 *   2. if we are preempted, but there *is* a genuine data race, we
-	 *      would *not* report it -- since this is the common case (vs.
-	 *      CPU-local data accesses), it makes more sense (from a data race
-	 *      detection point of view) to simply disable preemptions to ensure
-	 *      as many tasks as possible run on other CPUs.
-	 *
-	 * Use raw versions, to avoid lockdep recursion via IRQ flags tracing.
-	 */
-	raw_local_irq_save(irq_flags);
+	if (!kcsan_interrupt_watcher)
+		/* Use raw to avoid lockdep recursion via IRQ flags tracing. */
+		raw_local_irq_save(irq_flags);
 
 	watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
 	if (watchpoint == NULL) {
@@ -524,7 +509,8 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 
 	kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
 out_unlock:
-	raw_local_irq_restore(irq_flags);
+	if (!kcsan_interrupt_watcher)
+		raw_local_irq_restore(irq_flags);
 out:
 	user_access_restore(ua_flags);
 }
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index ba9268076cfbc..0f1447ff8f558 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -101,6 +101,17 @@ config KCSAN_SKIP_WATCH_RANDOMIZE
 	  KCSAN_WATCH_SKIP. If false, the chosen value is always
 	  KCSAN_WATCH_SKIP.
 
+config KCSAN_INTERRUPT_WATCHER
+	bool "Interruptible watchers"
+	help
+	  If enabled, a task that set up a watchpoint may be interrupted while
+	  delayed. This option will allow KCSAN to detect races between
+	  interrupted tasks and other threads of execution on the same CPU.
+
+	  Currently disabled by default, because not all safe per-CPU access
+	  primitives and patterns may be accounted for, and therefore could
+	  result in false positives.
+
 config KCSAN_REPORT_ONCE_IN_MS
 	int "Duration in milliseconds, in which any given race is only reported once"
 	default 3000
-- 
2.25.0.265.gbab2e86ba0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200220141551.166537-1-elver%40google.com.
