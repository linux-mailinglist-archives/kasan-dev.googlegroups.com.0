Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB4AYT4QKGQEV4FQ26A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D5D4240325
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 10:06:32 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id r14sf3914835wrq.3
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 01:06:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597046792; cv=pass;
        d=google.com; s=arc-20160816;
        b=TEe34LD5TFxpLBZbIHlr/QUtGdyp5Kg0klhpx1mG7hQZOKumkHqIq/Lx/pf6D4BNi0
         chUaOq5MUD2OHYjvgV1lCQAk+VksinIt2Q+tpyObDJcZBucEpqgQM0+Lq8UWxPRIwgLh
         XSX0xpCMFveetF/JuoRH8bijr/RGo5DqSEF46guUJ6kuA15xZz7yqOoKbdYNmGOsEZfo
         X4m47NeDWRONi26OB8bMPNXwCcDC9KPMObTro6P2cK6qbljHr/Iv82WpLy1TFVVY7Kt5
         iYkK82dnWIxATuF5wcTEKuZ3DHilEW4HrzPqgnQDyoilNaTF/w9lwnL2pmat/tDcRPjY
         OguA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=ikHSyIICMgVr7FeNiwG8ZVCB9R8VGx2CMjn4YUnvmUg=;
        b=PybX262y423UVR3Rf/AhFThtKC33gtDh5Ck+jJPY2NcefmW9MlecLtsXBUfhZqXp4U
         C50YHR0XFIpdZqmWUZyIS8/VAJ5P2WmZ2uQNahvXyjqykksOPYtbTx32xDIw/3tpURY7
         daln+Sa05DPl6HF/TMa3LPol0NzO5o5bcqG3r4BciWw2ZKojoRMBYqP197ry06PRuvgC
         POcpTwTN1fIkr1axYn+aZuNutqjS5qXrOP+R61mFU4k1UzsKbkbEpYuiOIkF6Zkl03/j
         xZuBJMZIkgEWZciIpaSEn9/BjYtFB2a8mYcr3pfMy7TGu0ncrSgR6wX8oQ2qlJFH5dxl
         5gQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lWDXFnBx;
       spf=pass (google.com: domain of 3bgaxxwukcckt0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3BgAxXwUKCckt0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ikHSyIICMgVr7FeNiwG8ZVCB9R8VGx2CMjn4YUnvmUg=;
        b=N0yyjpW5QYx/U43oHfArWWU0AElbOzz4sRIlAl/FMgIywLHJsq0a9hN/6FYf42DMvG
         jjN1h0mA5kl1l21biVtbQU/RYkdIagYeKBbvbsiQ8H0bj2f8Opf+D66dvUVv6B0srxJO
         +OcLYpOpgXQikr1z9dlBTgoVvR8JWGMbVZuu55VYZ9UhKI8viXOXH2jKnWSi9dBnyJGD
         lbjSlGfE4sM1+7AoFc0KYZZfEqaynBmFkgHjpaV8QjjlJGvieB43i/tgG20p5v57tAf2
         LsC43AzhfBmZ+wEALT5HvEFUPm1ew0v79ykyAuvAisijicqh7Tv2mqSr/dYxl/XZA3QK
         wp3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ikHSyIICMgVr7FeNiwG8ZVCB9R8VGx2CMjn4YUnvmUg=;
        b=RsPRDhURp/zpDxTUwuhfiVomKNlFnKztAEULVpYu/5xo+XMs8cT28dz7uZy93bMaFB
         /1Vy3S6c7HKH3K2f432LPVw2J+GerWZwd/9+mZ3VD7bir0SrWOm/pgS+rqm95YAiLPaP
         mtkKtLYhKh7iKgtxFAJXZTS+X7mEKB705TlRW/MrKP647Q13Br/6idufdhfq6EnkbBzm
         UyPdLxeY6V0jsLNyRLYh3m5rhhkm1TsjwHSbPl78/KqFd2yYGmM3ov38yma5ticMjJ9/
         mbJYzEHnLxnfbh6scU8Y+v+o4dujzDNtYAJbn/0Qp8zEHHWwfPq6cTN6ikl8xVf6YVqz
         ybjw==
X-Gm-Message-State: AOAM533SIT1oypFptrTYJM47iroDbXtQGJB3OML2gFBVdBkYOyXodQFZ
	nEIwye0qrjlOpYwkDPio47E=
X-Google-Smtp-Source: ABdhPJx3cpFFcR1Tj7MI9o8zbzLB2oUbzNSNN/srfLAOKdzfgo/oipW7Jqosy0qCLeP/s+fDTlBbpA==
X-Received: by 2002:a1c:7e44:: with SMTP id z65mr25627147wmc.13.1597046791879;
        Mon, 10 Aug 2020 01:06:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:a50e:: with SMTP id o14ls1379011wme.3.gmail; Mon, 10 Aug
 2020 01:06:31 -0700 (PDT)
X-Received: by 2002:a7b:c002:: with SMTP id c2mr25645605wmb.51.1597046791285;
        Mon, 10 Aug 2020 01:06:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597046791; cv=none;
        d=google.com; s=arc-20160816;
        b=lphPGJbvua4bJdOb70PsjyaY0UrN1guF9upwG+XX5PYp2l4L1RqaObIIHF6jafjlj4
         Dd0XtNQSns+iIjj1o3Z2JeSdb6rZjH2iOTH/foqOo6omi7EebC2fcUmWUzIl6yEF2TWY
         hZniRiqXaxNEcpGMPtyfnP/RyYeX/Tx2YPSThGA855xF6XDQws7DEPDOHsh40SDQrDM4
         +9x35Cg+/6Ch9UFfbTfdxwm6hfRI+MfJedinQPVl+8g9WfKSJXMIKu3/Y1xErpuiFMzO
         GOsXh7NwZlJts6Pk8EVWnNxgn7nYW7S6Is3cjbaKF/ZL/J+7OVNqBDw8CfEt6BVgf1eg
         YuMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=GRkzPey+vf5ZdYTLVvZRABQWI4Soo5smNIo1Ur+XGto=;
        b=xG++oaqb8afwwPJddzaa2OLiFioMZ5Uqz7l6HWtNDxbnduZ1uXWFWJC9vQ8B1XgoF7
         aVWbgcq2O0589u/rdT5dKljUEmMptbCQwZY4xPvGmwdzyUuuTqzRij1T3PbfCkyPv5sv
         C565JQvzLay/Z+7tWVvJIxhB7T1hGcSP+X5CiEQbM1Ht3zT+0f7n2LvmEYcCfILYxpGp
         FtycQ1hQPpO/8LU2M6jESCJ5mKmtxp3JlmfHtRaH/Vnpyhb1NrwTxA/C3tDFU4zBWcGQ
         r//Mcdrq/T3BVrVtsXomwD7Q0z0xdSrXHyhqPNV4khUnkxuhH79biGg0SkRdSW2v69rg
         IDkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lWDXFnBx;
       spf=pass (google.com: domain of 3bgaxxwukcckt0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3BgAxXwUKCckt0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id f23si865962wml.3.2020.08.10.01.06.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Aug 2020 01:06:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bgaxxwukcckt0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id k11so3888958wrv.1
        for <kasan-dev@googlegroups.com>; Mon, 10 Aug 2020 01:06:31 -0700 (PDT)
X-Received: by 2002:a1c:6555:: with SMTP id z82mr24640106wmb.67.1597046790842;
 Mon, 10 Aug 2020 01:06:30 -0700 (PDT)
Date: Mon, 10 Aug 2020 10:06:25 +0200
Message-Id: <20200810080625.1428045-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.236.gb10cc79966-goog
Subject: [PATCH] kcsan: Optimize debugfs stats counters
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lWDXFnBx;       spf=pass
 (google.com: domain of 3bgaxxwukcckt0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3BgAxXwUKCckt0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
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

Remove kcsan_counter_inc/dec() functions, as they perform no other
logic, and are no longer needed.

This avoids several calls in kcsan_setup_watchpoint() and
kcsan_found_watchpoint(), as well as lets the compiler warn us about
potential out-of-bounds accesses as the array's size is known at all
usage sites at compile-time.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/core.c    | 22 +++++++++++-----------
 kernel/kcsan/debugfs.c | 21 +++++----------------
 kernel/kcsan/kcsan.h   | 12 ++++++------
 kernel/kcsan/report.c  |  2 +-
 4 files changed, 23 insertions(+), 34 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 23d0c4e4cd3a..c3b19e4a089a 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -351,13 +351,13 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
 		 * already removed the watchpoint, or another thread consumed
 		 * the watchpoint before this thread.
 		 */
-		kcsan_counter_inc(KCSAN_COUNTER_REPORT_RACES);
+		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_REPORT_RACES]);
 	}
 
 	if ((type & KCSAN_ACCESS_ASSERT) != 0)
-		kcsan_counter_inc(KCSAN_COUNTER_ASSERT_FAILURES);
+		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_ASSERT_FAILURES]);
 	else
-		kcsan_counter_inc(KCSAN_COUNTER_DATA_RACES);
+		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_DATA_RACES]);
 
 	user_access_restore(flags);
 }
@@ -398,7 +398,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		goto out;
 
 	if (!check_encodable((unsigned long)ptr, size)) {
-		kcsan_counter_inc(KCSAN_COUNTER_UNENCODABLE_ACCESSES);
+		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_UNENCODABLE_ACCESSES]);
 		goto out;
 	}
 
@@ -413,12 +413,12 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		 * with which should_watch() returns true should be tweaked so
 		 * that this case happens very rarely.
 		 */
-		kcsan_counter_inc(KCSAN_COUNTER_NO_CAPACITY);
+		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_NO_CAPACITY]);
 		goto out_unlock;
 	}
 
-	kcsan_counter_inc(KCSAN_COUNTER_SETUP_WATCHPOINTS);
-	kcsan_counter_inc(KCSAN_COUNTER_USED_WATCHPOINTS);
+	atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_SETUP_WATCHPOINTS]);
+	atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_USED_WATCHPOINTS]);
 
 	/*
 	 * Read the current value, to later check and infer a race if the data
@@ -520,16 +520,16 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		 * increment this counter.
 		 */
 		if (is_assert && value_change == KCSAN_VALUE_CHANGE_TRUE)
-			kcsan_counter_inc(KCSAN_COUNTER_ASSERT_FAILURES);
+			atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_ASSERT_FAILURES]);
 
 		kcsan_report(ptr, size, type, value_change, KCSAN_REPORT_RACE_SIGNAL,
 			     watchpoint - watchpoints);
 	} else if (value_change == KCSAN_VALUE_CHANGE_TRUE) {
 		/* Inferring a race, since the value should not have changed. */
 
-		kcsan_counter_inc(KCSAN_COUNTER_RACES_UNKNOWN_ORIGIN);
+		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_RACES_UNKNOWN_ORIGIN]);
 		if (is_assert)
-			kcsan_counter_inc(KCSAN_COUNTER_ASSERT_FAILURES);
+			atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_ASSERT_FAILURES]);
 
 		if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN) || is_assert)
 			kcsan_report(ptr, size, type, KCSAN_VALUE_CHANGE_TRUE,
@@ -542,7 +542,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	 * reused after this point.
 	 */
 	remove_watchpoint(watchpoint);
-	kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
+	atomic_long_dec(&kcsan_counters[KCSAN_COUNTER_USED_WATCHPOINTS]);
 out_unlock:
 	if (!kcsan_interrupt_watcher)
 		raw_local_irq_restore(irq_flags);
diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 6c4914fa2fad..3c8093a371b1 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -17,10 +17,7 @@
 
 #include "kcsan.h"
 
-/*
- * Statistics counters.
- */
-static atomic_long_t counters[KCSAN_COUNTER_COUNT];
+atomic_long_t kcsan_counters[KCSAN_COUNTER_COUNT];
 static const char *const counter_names[] = {
 	[KCSAN_COUNTER_USED_WATCHPOINTS]		= "used_watchpoints",
 	[KCSAN_COUNTER_SETUP_WATCHPOINTS]		= "setup_watchpoints",
@@ -53,16 +50,6 @@ static struct {
 };
 static DEFINE_SPINLOCK(report_filterlist_lock);
 
-void kcsan_counter_inc(enum kcsan_counter_id id)
-{
-	atomic_long_inc(&counters[id]);
-}
-
-void kcsan_counter_dec(enum kcsan_counter_id id)
-{
-	atomic_long_dec(&counters[id]);
-}
-
 /*
  * The microbenchmark allows benchmarking KCSAN core runtime only. To run
  * multiple threads, pipe 'microbench=<iters>' from multiple tasks into the
@@ -206,8 +193,10 @@ static int show_info(struct seq_file *file, void *v)
 
 	/* show stats */
 	seq_printf(file, "enabled: %i\n", READ_ONCE(kcsan_enabled));
-	for (i = 0; i < KCSAN_COUNTER_COUNT; ++i)
-		seq_printf(file, "%s: %ld\n", counter_names[i], atomic_long_read(&counters[i]));
+	for (i = 0; i < KCSAN_COUNTER_COUNT; ++i) {
+		seq_printf(file, "%s: %ld\n", counter_names[i],
+			   atomic_long_read(&kcsan_counters[i]));
+	}
 
 	/* show filter functions, and filter type */
 	spin_lock_irqsave(&report_filterlist_lock, flags);
diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
index 763d6d08d94b..7619c245e080 100644
--- a/kernel/kcsan/kcsan.h
+++ b/kernel/kcsan/kcsan.h
@@ -8,6 +8,7 @@
 #ifndef _KERNEL_KCSAN_KCSAN_H
 #define _KERNEL_KCSAN_KCSAN_H
 
+#include <linux/atomic.h>
 #include <linux/kcsan.h>
 
 /* The number of adjacent watchpoints to check. */
@@ -27,6 +28,10 @@ extern bool kcsan_enabled;
  */
 void kcsan_debugfs_init(void);
 
+/*
+ * Statistics counters displayed via debugfs; should only be modified in
+ * slow-paths.
+ */
 enum kcsan_counter_id {
 	/*
 	 * Number of watchpoints currently in use.
@@ -79,12 +84,7 @@ enum kcsan_counter_id {
 
 	KCSAN_COUNTER_COUNT, /* number of counters */
 };
-
-/*
- * Increment/decrement counter with given id; avoid calling these in fast-path.
- */
-extern void kcsan_counter_inc(enum kcsan_counter_id id);
-extern void kcsan_counter_dec(enum kcsan_counter_id id);
+extern atomic_long_t kcsan_counters[KCSAN_COUNTER_COUNT];
 
 /*
  * Returns true if data races in the function symbol that maps to func_addr
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 15add93ff12e..3add0d9b252c 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -556,7 +556,7 @@ static bool prepare_report_consumer(unsigned long *flags,
 		 * If the actual accesses to not match, this was a false
 		 * positive due to watchpoint encoding.
 		 */
-		kcsan_counter_inc(KCSAN_COUNTER_ENCODING_FALSE_POSITIVES);
+		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_ENCODING_FALSE_POSITIVES]);
 		goto discard;
 	}
 
-- 
2.28.0.236.gb10cc79966-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200810080625.1428045-1-elver%40google.com.
