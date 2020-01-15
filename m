Return-Path: <kasan-dev+bncBC7OBJGL2MHBB57Z7TYAKGQEZ7G7VVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id A79B513C930
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 17:25:28 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id g11sf11768689edu.10
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 08:25:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579105528; cv=pass;
        d=google.com; s=arc-20160816;
        b=EnIvFyg35qtDfl/7Nr5R+yySud/Pt/l9BcGnLlX/FUu/b1dK9t1rHYRKXQKTR/mxqW
         b2QTCgPuoVZFyzr+z58qi9WO72u8rfjNh9NRZDKjF2qRqEHOkwq0F8aMqbcJtkMydtFC
         1oNZKsIcJkqvV9CNtAXfZweolY1tQC1nZ8VuOjk3Ly5obNb9OxcxbX87QtBOCy/bMSm8
         y2ESqT2IG2yLslDakdPnmTizXBHIMJdbAGUE4Z4IL2jY6cDNbNNRz6GVWbSZT0+1SAU0
         sQ1XjxeKAnncWGiv3NwcbPYbcYkQclOxqvGuvM06YfJ9YwAl7JLrNyKmmGg/1sc76Zsn
         Y4Rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=jEnuaNPY4GFQcy+anrnYXF/fQKCKmSefxN7GOW6osgk=;
        b=gA2u0YAUAP5PuuNzgF4d8dZ+7vHZG1JUf2uPV6ElpP6KPexSSNHsktk3RKF1A4rf8G
         DdTowOt5ANC/yPmLD/8gEqEoToHfVc1XNksaa/3DwMy+/FNWYVi2H/khgfRxOw3QUOLl
         owx25aS4KPLGaXQpPtsrOXNXZB2jlhrg4vVoR6LVCpfb33ESygWWMXu5Tv/0b+YwswZu
         S0BBI8D7wvqxBFizrmmYVesovAvsnBQwKjk/LPZNIKaJiV0snrXq1riHVnVolUR2OPVF
         E23Ia6DeqByCpYoa6HLs9hVY+G3hVosJrqGwZt3ptsJGe+QXCPmmxKOno3/iTZC5DT5X
         SOmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r0T9BBio;
       spf=pass (google.com: domain of 39jwfxgukcemjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39jwfXgUKCeMJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=jEnuaNPY4GFQcy+anrnYXF/fQKCKmSefxN7GOW6osgk=;
        b=Y/1A7V7FkhEzNrbQBXmapNenMhh1DX2JUdh3C8oSUqZ7yA4R82bCy/ftM64Ve0lvAo
         ltY5EvjhLVA8k9dKdKQqE/TbnB9m95b/MBmoLKEIC22n6y4PiWNbRG8EuizLSMaAzunw
         +1nbC2u7g5pqOXfX9ZuIcB54J1yHz/hQl5eDe7nZWHXyOa5hipx1WCcV+XHLtCa8N/nj
         vnvy80QGFDD8Aw5bHmE7NbRDZCf7nGtKof9Z+ZY6avQtTicCIFDKSD/WOAtYxasgnW+7
         xJ8YGMxPPKDwDF+owOcPTubVYB8aErCCctgGPVxi0WUt/+Kzdf6HJWy1TLEfeSBlmdk5
         4fkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jEnuaNPY4GFQcy+anrnYXF/fQKCKmSefxN7GOW6osgk=;
        b=LtjxQCAxDgzQ2cduYBD/2VhI1RIYHZa8eeIbGkQJiXy8meKk7zT2JHSMiyTnojFVqy
         4Dzycl4PaiVBpJSGZ9HepgInhHTRIivmpeOfzXvmsAcsso0HOXQCZnQSjeHc2kzIeRfA
         qJWxJC3DU8DK/KU4/hsLHYVom+1AAMjalEjuXPWzP84UVhtLZRHa/ZK1Pfco5gnE2BzT
         dYFSKe/6KiqiZApuA/I77on4eRdL1rj9qQVgAi4cfeLJCSynOCxGWnOVXoRKtPg7VZ+7
         YJqUoFbkpLTpNQn+2Q7pERtF8IQsDdkjHneXOSB+qAUD6Z8XpBrzj58O8hCz4Unh1CDa
         lzfg==
X-Gm-Message-State: APjAAAUfV+bW99UWfpYtegjQlqJ+aaizjoRAFwzsr83lFLugnl44CxQm
	AacEEc18yUr2ObY+BxU03ks=
X-Google-Smtp-Source: APXvYqwCdwMQo067Ad0Trzyc7caQ/Fd/5twwX5cXWrGpssoqUBioQUhYU6NImz2dq0HHygelSNbE2A==
X-Received: by 2002:a17:906:c28b:: with SMTP id r11mr28608439ejz.291.1579105528092;
        Wed, 15 Jan 2020 08:25:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1f97:: with SMTP id t23ls5476772ejr.11.gmail; Wed,
 15 Jan 2020 08:25:27 -0800 (PST)
X-Received: by 2002:a17:906:52d7:: with SMTP id w23mr28824925ejn.74.1579105527355;
        Wed, 15 Jan 2020 08:25:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579105527; cv=none;
        d=google.com; s=arc-20160816;
        b=YyjidaoH2Sqbvi7YNZnUofjZRs87oP96eYMISzlZmd5bZQuPd8PzFouatZkdm8U6M4
         dakh3o9J6HQtFZT/G5CCJIG6OxCEGjRCAPsK7xVyXbmREM7mIEkIffhn0Zi6OKEtYkTN
         OCX3IVVWw782gkiuupeV/8vnEhwMJ7QA1SQdn05jf1AReI7sKMSZunwlAqKk97CPeebX
         CD4uUWAgkLue67xLusuoZact9zUanv+tTc2oeDuANeqE565WEode7ACsuc56ZH6Wl3zP
         KJ5HKNPkQHo5st1/nyrACI6CVYJ5AYUzj2FjZU2WNFFMNe6WhQWBKHCYwunEfvbpfs9Z
         LggQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=tWWTYC00Bevk0nm3TMQwKmrrXXB+slBnVDIOhwQFpv4=;
        b=mL2SFQnyeJwxkEayqTeFJcwMpipMDTSq34Ogo13onvPOHXFg6TDS08WdahdNBzNQKD
         ExTGzY272P+nzW+97iyL1X3x2rKTnSwXcAqID62UaH/W/5nLl5ZYMM498DNHhsp2C5nU
         Czfoy6a/NrRjalJkNiHZbaI7+6L30S7frBa2CrOIG6Df4SWuYCZpaoZ1/mWMiADa+6Br
         bgLzVXTW+gb0RizHX109DDEQU0Q7qR7jjJPi/d/YgDrTbvXTobIe1u9LIpL/U0qFf8nO
         e3P5DC4aOanxZR+/i8Xctb92gMn/I5AUfgE4S1s7luiw8+rsTWGfelGDUnv1SRKGXWwH
         ESow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r0T9BBio;
       spf=pass (google.com: domain of 39jwfxgukcemjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39jwfXgUKCeMJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id cc24si840405edb.5.2020.01.15.08.25.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 08:25:27 -0800 (PST)
Received-SPF: pass (google.com: domain of 39jwfxgukcemjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id t4so145465wmf.2
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 08:25:27 -0800 (PST)
X-Received: by 2002:a5d:45c4:: with SMTP id b4mr31874609wrs.303.1579105526489;
 Wed, 15 Jan 2020 08:25:26 -0800 (PST)
Date: Wed, 15 Jan 2020 17:25:12 +0100
Message-Id: <20200115162512.70807-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.rc1.283.g88dfdc4193-goog
Subject: [PATCH -rcu v2] kcsan: Make KCSAN compatible with lockdep
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	peterz@infradead.org, mingo@redhat.com, will@kernel.org, 
	Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=r0T9BBio;       spf=pass
 (google.com: domain of 39jwfxgukcemjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39jwfXgUKCeMJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
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

We must avoid any recursion into lockdep if KCSAN is enabled on
utilities used by lockdep. One manifestation of this is corrupting
lockdep's IRQ trace state (if TRACE_IRQFLAGS). Fix this by:

1. Using raw_local_irq{save,restore} in kcsan_setup_watchpoint().
2. Disabling lockdep in kcsan_report().

Tested with:

  CONFIG_LOCKDEP=y
  CONFIG_DEBUG_LOCKDEP=y
  CONFIG_TRACE_IRQFLAGS=y

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
v2:
* Update comments.
---
 kernel/kcsan/core.c     |  6 ++++--
 kernel/kcsan/report.c   | 11 +++++++++++
 kernel/locking/Makefile |  3 +++
 3 files changed, 18 insertions(+), 2 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 87bf857c8893..64b30f7716a1 100644
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
index b5b4feea49de..33bdf8b229b5 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200115162512.70807-1-elver%40google.com.
