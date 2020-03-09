Return-Path: <kasan-dev+bncBAABBOFGTLZQKGQE5Y7FWLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id BBB1017E7C8
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:25 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id t16sf7135143otc.3
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780664; cv=pass;
        d=google.com; s=arc-20160816;
        b=tolCLH9EAxLtaHwetUpqw8da4bed63auFqKolGesnQi2syJbRjqWxtTo8ZD1VQ6Bf1
         +IydCbrz1qNGMq22Qy45wqvxd0xx6v8QTR06It0+NV8/vkWgAJEif+8xvJwtHakmEcek
         T39df7vDFKFjkdy8jwtVL++Qe3w187WqWERdW1TG73m/ZoG07yA4GYmf9kjAdmjbEmUr
         lShDImukQgW+mfZXSP3eF0O5M2+2Qz6NHExCi7xDjBlG09/9lTOKc2lu/DKVfM2V1fgc
         1ZoneQOiFFf3RcMiExreoi8A5U5e3cJPWn+afy2n2bExoXNmPV3ItuFu4/IPLLh1zi+4
         3fnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=6KyAFQ5I7v19xgqkoTCzK/sTY5OI/8aWDQPgoog13oQ=;
        b=IhAVlTKHMoDcko6pC358+vaBkfMtYRxOwTlA+DCoG4o71OhlZT+3fegh6Kj1yYwmPU
         4P/AzYimul/N2rpyuM8AilWb9mxcfgBh6uTTKhBXmLOwrOR2LOKDvE/kjL6ya7vrGBua
         jpa9k181FHpNwlJCeq52KPFPgYiPtjXpxNpW0IQT+ceNaesD9A43KavZLtuSfHSoinTw
         NnQWQ8xso0obIxzIqEzTYWtbL7gwVWgKjuuo04VtlldHqfaWBtoZIeiek3jcdD6C+2ku
         bYHBO3H5wXl//hB9mP16aO2CZEhwnRItXxz+5rX65vGO9hg9FuIDwcvgDEDzMh83fOvc
         XCPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=n1FhMvHw;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6KyAFQ5I7v19xgqkoTCzK/sTY5OI/8aWDQPgoog13oQ=;
        b=FHbMJfdf0vMMkUuyY4LtRlAKEv2vH1M63glQKL8o4aI/yYa5BrhHvJk6Fe3MzeuXVZ
         Q3UczY0M4z26AW1FzTVbrXpWLxmITrDzNtzK/rkzjWsLtRjEmjKcKF3tFnsQ/wiKGWXE
         iPk0TMUNNXuIi89XOqKSDdjh9RMXdaODChQywPfMFutrb5C+wivVmlwzBfefRZmU8n6w
         0kmYU7WugHNTciBdqhGU9vNDSShhJ/c5lDjElOet4gOD8zYS7C+nGCWAey1O62KG/ZW3
         O6UZh98g46/J12UGbHsbe1hi8LiN0nxnGWFG7JUTknQ8z3i3DCY0nK81ScFfzGJn18Un
         zwSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6KyAFQ5I7v19xgqkoTCzK/sTY5OI/8aWDQPgoog13oQ=;
        b=PPn6UAV/1IU4EgYSgPMV2F/G8BFnbJev3Gr1fD9a3PQe2IbkinV90E/N6dFynZ8IQ9
         D47L/umECY2NPvNxJbRX4ZMCQEDTm1963Gx4LObKzqlWmbPvGuBghnd9cOKZSWG/H72C
         pfw/3fXC7Z9xNIULsvMqhCa0u4PKObDa1BC/r9g0fRYcow4YbXvsoovWKihqE6vxyfw6
         QDssnxb3Q8LFRKOhxwT6WHOkigm4C25WSpMxV2W/VFDwWFlValmZXOXlhy5uaVsBlkjv
         S7YwSG3a70pvP2pPXCyVGUN5UZD5RG/DE60PrOllCD0z2QczHs3Pf/mDL6ZeFqmB5LLj
         W4Pg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ2wuJ1zMvb3R4O/nxjtmPXe4FYeTyhaqAz+PODnZc4+aEXsj9F2
	9FMIPho0qAj2av5uy6NY5QY=
X-Google-Smtp-Source: ADFU+vvoGjxVnrTpOwVU0g/B6tZuUzyiGZmuX21HGUs3nhZx7BJlf7K9DbULE58jMHTA3/TU6J13IQ==
X-Received: by 2002:a9d:6c58:: with SMTP id g24mr4044871otq.106.1583780664468;
        Mon, 09 Mar 2020 12:04:24 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6759:: with SMTP id w25ls1740339otm.10.gmail; Mon, 09
 Mar 2020 12:04:24 -0700 (PDT)
X-Received: by 2002:a9d:64cd:: with SMTP id n13mr14209909otl.274.1583780663970;
        Mon, 09 Mar 2020 12:04:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780663; cv=none;
        d=google.com; s=arc-20160816;
        b=YIGRlzj4bUnpLuBH9aUtzsbJkbzz3+ZUvZIFFJ+ALiJ3CPliK93mVFDfiaVSRHuYk4
         0aRbVz8/VV5YtTRYBEpgxsdAv27jh8vhrQIHXl22JD+YPQ7z8FZS0lW3KQlGclX1oVCz
         EZzkjZvWIefN15LQJowD/XrY82YnPUdFKlUiHi1tZZpsirXDipUgrFvj5CYVwmbbDqnQ
         YWMcfBPRJ6HwwJmxJEPzvDxP49hc/4Ss+7YDGB+RQF0M6JcrvKUBicY+T58Q773AC1TZ
         op9XcX9SpVN1Jgb2ljB5uV44QwwjSrrRu4P93c+cSPHZFLl/G54O9M2/DiWXoX5ejh8L
         Moew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=c5D4ljJmBqCSgA4t2dCT7MImX7WFaLbZ9rmjyQ+qx2E=;
        b=GDKImt4CRRvKhsEMYz7vH/2j+niHNkEj1LQliZdP9Ou9p3nbNFPY7bEJeM9ICxH3hc
         rxNP15OXb6SH7uXc/yhfGKSUdeo5b9orT2pvg4hr45s/aHfDrVIU7K7XL9ZK4tuBpRyY
         jKdyjqFvkInIPwzuxfGMiK20bkNDfc+tKqJFkCMTJsTAJ5gL/hIUmPBekIZK4k1qD+gU
         avYjQexNYsjJO4mlJ6VdTUd6KIwpxS7fRSM+zQD5TJoyWB3GbMCIvH3jMG/2520oHsxX
         B7g9dUyx8Vjv3KF3ukPj+WXX3tgaGlBxQIPRgznm5LJvpT/GfnLDq5KuXcZ63SqCPCc4
         Gi3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=n1FhMvHw;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d11si235170otk.5.2020.03.09.12.04.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id E3A0A227BF;
	Mon,  9 Mar 2020 19:04:22 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 04/32] kcsan: Make KCSAN compatible with lockdep
Date: Mon,  9 Mar 2020 12:03:52 -0700
Message-Id: <20200309190420.6100-4-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=n1FhMvHw;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

From: Marco Elver <elver@google.com>

We must avoid any recursion into lockdep if KCSAN is enabled on utilities
used by lockdep. One manifestation of this is corruption of lockdep's
IRQ trace state (if TRACE_IRQFLAGS), resulting in spurious warnings
(see below).  This commit fixes this by:

1. Using raw_local_irq{save,restore} in kcsan_setup_watchpoint().
2. Disabling lockdep in kcsan_report().

Tested with:

  CONFIG_LOCKDEP=y
  CONFIG_DEBUG_LOCKDEP=y
  CONFIG_TRACE_IRQFLAGS=y

This fix eliminates spurious warnings such as the following one:

    WARNING: CPU: 0 PID: 2 at kernel/locking/lockdep.c:4406 check_flags.part.0+0x101/0x220
    Modules linked in:
    CPU: 0 PID: 2 Comm: kthreadd Not tainted 5.5.0-rc1+ #11
    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.12.0-1 04/01/2014
    RIP: 0010:check_flags.part.0+0x101/0x220
    <snip>
    Call Trace:
     lock_is_held_type+0x69/0x150
     freezer_fork+0x20b/0x370
     cgroup_post_fork+0x2c9/0x5c0
     copy_process+0x2675/0x3b40
     _do_fork+0xbe/0xa30
     ? _raw_spin_unlock_irqrestore+0x40/0x50
     ? match_held_lock+0x56/0x250
     ? kthread_park+0xf0/0xf0
     kernel_thread+0xa6/0xd0
     ? kthread_park+0xf0/0xf0
     kthreadd+0x321/0x3d0
     ? kthread_create_on_cpu+0x130/0x130
     ret_from_fork+0x3a/0x50
    irq event stamp: 64
    hardirqs last  enabled at (63): [<ffffffff9a7995d0>] _raw_spin_unlock_irqrestore+0x40/0x50
    hardirqs last disabled at (64): [<ffffffff992a96d2>] kcsan_setup_watchpoint+0x92/0x460
    softirqs last  enabled at (32): [<ffffffff990489b8>] fpu__copy+0xe8/0x470
    softirqs last disabled at (30): [<ffffffff99048939>] fpu__copy+0x69/0x470

Reported-by: Qian Cai <cai@lca.pw>
Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Alexander Potapenko <glider@google.com>
Tested-by: Qian Cai <cai@lca.pw>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c     |  6 ++++--
 kernel/kcsan/report.c   | 11 +++++++++++
 kernel/locking/Makefile |  3 +++
 3 files changed, 18 insertions(+), 2 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 87bf857..64b30f7 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -336,8 +336,10 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	 *      CPU-local data accesses), it makes more sense (from a data race
 	 *      detection point of view) to simply disable preemptions to ensure
 	 *      as many tasks as possible run on other CPUs.
+	 *
+	 * Use raw versions, to avoid lockdep recursion via IRQ flags tracing.
 	 */
-	local_irq_save(irq_flags);
+	raw_local_irq_save(irq_flags);
 
 	watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
 	if (watchpoint == NULL) {
@@ -429,7 +431,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 
 	kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
 out_unlock:
-	local_irq_restore(irq_flags);
+	raw_local_irq_restore(irq_flags);
 out:
 	user_access_restore(ua_flags);
 }
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index b5b4fee..33bdf8b 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -2,6 +2,7 @@
 
 #include <linux/jiffies.h>
 #include <linux/kernel.h>
+#include <linux/lockdep.h>
 #include <linux/preempt.h>
 #include <linux/printk.h>
 #include <linux/sched.h>
@@ -410,6 +411,14 @@ void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 {
 	unsigned long flags = 0;
 
+	/*
+	 * With TRACE_IRQFLAGS, lockdep's IRQ trace state becomes corrupted if
+	 * we do not turn off lockdep here; this could happen due to recursion
+	 * into lockdep via KCSAN if we detect a data race in utilities used by
+	 * lockdep.
+	 */
+	lockdep_off();
+
 	kcsan_disable_current();
 	if (prepare_report(&flags, ptr, size, access_type, cpu_id, type)) {
 		if (print_report(ptr, size, access_type, value_change, cpu_id, type) && panic_on_warn)
@@ -418,4 +427,6 @@ void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 		release_report(&flags, type);
 	}
 	kcsan_enable_current();
+
+	lockdep_on();
 }
diff --git a/kernel/locking/Makefile b/kernel/locking/Makefile
index 45452fa..6d11cfb 100644
--- a/kernel/locking/Makefile
+++ b/kernel/locking/Makefile
@@ -5,6 +5,9 @@ KCOV_INSTRUMENT		:= n
 
 obj-y += mutex.o semaphore.o rwsem.o percpu-rwsem.o
 
+# Avoid recursion lockdep -> KCSAN -> ... -> lockdep.
+KCSAN_SANITIZE_lockdep.o := n
+
 ifdef CONFIG_FUNCTION_TRACER
 CFLAGS_REMOVE_lockdep.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_lockdep_proc.o = $(CC_FLAGS_FTRACE)
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-4-paulmck%40kernel.org.
