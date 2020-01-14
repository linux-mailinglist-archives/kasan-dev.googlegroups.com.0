Return-Path: <kasan-dev+bncBC7OBJGL2MHBBW7R63YAKGQEJTAO7LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id B476313A9A7
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 13:49:33 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id c8sf8335405pgl.15
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 04:49:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579006172; cv=pass;
        d=google.com; s=arc-20160816;
        b=nGLs/bXTSvUIzHzdO9rLUwZPVY6GCvhMGq8bwQ4U78ewtFkNVKRP1zR77GHZOPuxrg
         jKl6fwyFsMPLAqYay2xT1C/aWG+Q9quVP0TC4zQDSrg+ESCzfavf+5kVR/V2Rib7TObx
         rp6cUC928MQhpCdTXrcuFDjhqxMaooQ5c2cc9mui0z+OB8oGR+gXThaUb35q53YkUYIQ
         TFt1RqBaHzI40/IomWg7YuT2pYihdgDUswiA5ZkaNdaO6/fPxOzdwOpbSbn3FqQJyOe7
         4EKdNK63yHNgwdFTqIykWm0R1+5uwziOde7/9twLEsuo5xTYRiqScBBz0JEkphBCa1vB
         CfDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=F0dnbya6zU3WlbXAW1pMx6DD8zZkitwC8IZLNnlf0YU=;
        b=slAji9cihl+H19kYfgqqqB+3y4RVRmyMFzcjuthEX28CULjzLiDSd42jRAXjs7rgO3
         W28F+ATxtioTzTxM27Z37pxqtINhLoR1QWGuvHfSYi3OkvAmHPJycHxS52irzwji3ogg
         R3vwUfC4K5+VvKARseSxGU043lYajolREojX5U7kIodPgjez6ckBlXxiRaz3zdZQpOxS
         7BdkFcOdViQM7vRHh5WhgSC4MiCc2LBWlhvij01FxPgi3Au9c2OP7Zgq1eQFVlnaWjFr
         eQt4SRfwXCQ5kWen9AK45+2J9m7txgZu2eGTPmbHt1zhDYh7Yfz+n70oPw3kuBaRN9aB
         DITg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XeCJbWOq;
       spf=pass (google.com: domain of 32rgdxgukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::949 as permitted sender) smtp.mailfrom=32rgdXgUKCbkdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=F0dnbya6zU3WlbXAW1pMx6DD8zZkitwC8IZLNnlf0YU=;
        b=jxAy45axkL+mbngfm146oWNhPTKD5QsYF4JioyaLgcGGZJ4+S6UDSzMQEjvYTpvUCV
         8dRmb0zkYoYCovhyYNEa8KyctFmPDsoQoVaJDo8StiuvgHeeOZiEYOzJoNaAN4UrHqif
         tYaDx6cmfWqv0AERN0yUn7Z0rCcaVMBC508R/1B4ZPSjdRgMRYWUCIsCm0BzYIpo6fQ8
         thBTcFtW7E7LGAqQU0pvtWlu/2FuKBnxaVYSaP1Y83+OHGUYo+7/du8YWHLFzXJBOzNJ
         IZmm89HtO49R+VXVaeiuCxAxnVw8VYNJlo0NzAL5899SHTleirfedLPPhsLUb0zsItkg
         TvWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=F0dnbya6zU3WlbXAW1pMx6DD8zZkitwC8IZLNnlf0YU=;
        b=Qin3yWH7QXfYSc3htrgBgFt12FcDfv95tjen1Z3ZWwyaJj7FGfYUvDSXH90F/afL7n
         5wzm7Xgrw1zd/DHC4hkLOA+Nh49tKX1Dg1pC64MsYuLx4eTNteeBlQxQEc+64x1sJt79
         pElQjBca9D6OxEIxNA5/YowXVuTF8/f6m1CLK4YqVm0dOf1pWBLvBi2LI3jcpbCC4umh
         4qVNSEM50JQO2ZNIuNYYhBsQCnWzAA/765MziN5LAlUHrEz6nDSutRCQOrCRE69u47Uv
         PSepmm7Jg4uBBcBaoTSasHkSFCAr51oDHbgB1FjmeojHKHP0vRkgHW7Y7oD/PC/gqjJ8
         /3og==
X-Gm-Message-State: APjAAAXGfn8otS8/WqcdmIijwyY9FwB9app8S/tB8a7bl0iApuLyoWc+
	y0FSMEMuV2B3Z0d88kn4O9U=
X-Google-Smtp-Source: APXvYqx2qPqFYKwqRzrprC77O+BA5rOWD7NBjlkoAOz4SxM585FoNV9xXbAU5gvWcARNOrws+r7fKA==
X-Received: by 2002:a17:902:c693:: with SMTP id r19mr20823435plx.25.1579006171659;
        Tue, 14 Jan 2020 04:49:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8c94:: with SMTP id b20ls882338pjo.0.gmail; Tue, 14
 Jan 2020 04:49:31 -0800 (PST)
X-Received: by 2002:a17:902:6904:: with SMTP id j4mr3475270plk.88.1579006171147;
        Tue, 14 Jan 2020 04:49:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579006171; cv=none;
        d=google.com; s=arc-20160816;
        b=WrV3olmYkbhvB+J4wWjnVz2BUBXOhBhXXm2wKjNGuLP2vsKfkHunbdCkRWHQ6mFfg1
         p4WZP1Vu6CAYg12OtYnafJ3r++fIKFo9hGpqB+3o6XXsoADMXVGkuF4uGVdRoM1gxXqS
         8cVZj4qGQ/CjMPbi2Unk9haPJERrirzszUIMqrjyXOvP3VkGAPetJ974cAvUmhMnLaNN
         gpEQhQ+ATHVEiCzEisX98bA8W7yYFm4Z+eWY8Ua1VN7qureLUVfdd/4HvgrP6gHphltc
         SsI37PKpyPCliHCa1For8cpf8PQc5kPtjYYyOYljdsL6Apb/7hOWq8Ejo3EB2qiCIvtF
         U3Jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=sVzqQ6fMFKvf6/qthqEQJR/jG26iiS1B70RE5p8wL2Q=;
        b=jZbpxIhFRujsVmyk/9iWqJmN3Itlck/Zt340rC7DAqOsy+k8j0S8vUoGzj+ovf/T9p
         pV4Pxc4dxcxjBs9ciGUl99M38L3MwUiU/DlsPIducQAwYmicls9b8SHVVTInvn/hp2ye
         hEUWCjOaInzpRFaJ4XvbImiknQ305WIlsY6cK4Ti/lwUI4nUyDy1uxOxI05pUMej5hfN
         5zCTsrkqqSHSLojQNiffEX6UpLIosQ6cEiLmzMTTMQeGA9T++gMB2PcjI1zSBgtw8bKt
         x5Wv6dvY5snx8zXT8gRK8N+uZs6alQKJSudRYlVbPBpIIIEVLsv3xIBG0mEJZviek0h9
         U5PQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XeCJbWOq;
       spf=pass (google.com: domain of 32rgdxgukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::949 as permitted sender) smtp.mailfrom=32rgdXgUKCbkdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x949.google.com (mail-ua1-x949.google.com. [2607:f8b0:4864:20::949])
        by gmr-mx.google.com with ESMTPS id o9si766182pfp.0.2020.01.14.04.49.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Jan 2020 04:49:31 -0800 (PST)
Received-SPF: pass (google.com: domain of 32rgdxgukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::949 as permitted sender) client-ip=2607:f8b0:4864:20::949;
Received: by mail-ua1-x949.google.com with SMTP id i12so2086307uak.21
        for <kasan-dev@googlegroups.com>; Tue, 14 Jan 2020 04:49:31 -0800 (PST)
X-Received: by 2002:a67:1447:: with SMTP id 68mr1189159vsu.76.1579006170515;
 Tue, 14 Jan 2020 04:49:30 -0800 (PST)
Date: Tue, 14 Jan 2020 13:49:19 +0100
Message-Id: <20200114124919.11891-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.rc1.283.g88dfdc4193-goog
Subject: [PATCH -rcu] kcsan: Make KCSAN compatible with lockdep
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	peterz@infradead.org, mingo@redhat.com, will@kernel.org, 
	Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XeCJbWOq;       spf=pass
 (google.com: domain of 32rgdxgukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::949 as permitted sender) smtp.mailfrom=32rgdXgUKCbkdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
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

To avoid unexpected reentry into lockdep's IRQ tracing code via KCSAN
(if TRACE_IRQFLAGS is enabled), (1) use raw versions of
local_irq_{save,restore} in kcsan_setup_watchpoint(), and (2) disable
lockdep in kcsan_report() to avoid IRQ flags tracing upon generating the
report.

Tested with:

  CONFIG_LOCKDEP=y
  CONFIG_DEBUG_LOCKDEP=y

Where previously, the following warning (and variants with different
stack traces) was consistently generated, with the fix introduced in
this patch, the warning cannot be reproduced.

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
---
 kernel/kcsan/core.c     |  4 ++--
 kernel/kcsan/report.c   | 11 +++++++++++
 kernel/locking/Makefile |  3 +++
 3 files changed, 16 insertions(+), 2 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 87bf857c8893..e75f3dbf627e 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -337,7 +337,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	 *      detection point of view) to simply disable preemptions to ensure
 	 *      as many tasks as possible run on other CPUs.
 	 */
-	local_irq_save(irq_flags);
+	raw_local_irq_save(irq_flags);
 
 	watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
 	if (watchpoint == NULL) {
@@ -429,7 +429,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 
 	kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
 out_unlock:
-	local_irq_restore(irq_flags);
+	raw_local_irq_restore(irq_flags);
 out:
 	user_access_restore(ua_flags);
 }
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index b5b4feea49de..57ab7ef9786c 100644
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
+	 * With TRACE_IRQFLAGS, lockdep's internal IRQ flags state becomes
+	 * corrupted if we do not turn off lockdep. The likely cause is
+	 * unexpected reentry into IRQ tracing code via KCSAN if we detect a
+	 * data race.
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
index 45452facff3b..6d11cfb9b41f 100644
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
2.25.0.rc1.283.g88dfdc4193-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200114124919.11891-1-elver%40google.com.
