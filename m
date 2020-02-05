Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJWS5TYQKGQESWUDJNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id A86AF1539B3
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Feb 2020 21:44:22 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id m18sf1558208wmc.4
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Feb 2020 12:44:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580935462; cv=pass;
        d=google.com; s=arc-20160816;
        b=ovUqupWHEfsDcRlKdI2deUbBYN9l1lvXMJIJZOsQg2FgCN1L/UJWYmyoBuJvozzcNQ
         D7YtRi1c09Kl/AUisjY9lKjuJyCLYgGg6onzszfL6LHOFFepC1LX3sr2EeWFt4iGXTAp
         lmag0XTI2E2h23tuoW8z7tf9AqhA0Lr/9R4m1lWmkv9vaDO3ej41J2Wk0/Txa4MgMhxj
         nbBCC73sD2iI7AvBvl5HOX5SStiI3VfyYhpbPVr7kPiu8v9UT2I7/e4tEAlSGVGpMcKh
         +8Jcwrhg4/tbO8OkATWu7LsBpsSape/YLfWJrGlcAcLpV07uxzPf3uAeRKNh3RpAEEuK
         ySGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=9srLh5ttTBi7uwV/YGFJX3dWLcnlccevFMPRAaReKqI=;
        b=wl3Sx1nKVuz/kSX92YJKQqNzvGRXN5mdAwWFPvepasXP00Qnp8OH/TDMYraFkdQCDz
         TL9jDOf+XHm8HzHxga+slG1KATrDw5uB4BVLyr2wANMGCsYsg9IWit+3raIWOVvuI/bS
         Cto1hGAsCO+GfxXMlBSSkgBQksb77bM9M6AeiALnzALG6GajrK7+3D1Wa+LPHu8BMjR5
         IDnSpnFsTqeMH9dEhtMHeWkH0qNSpBs0DId8KQJ3+BbMv+C8OUjOWVZy+tUJD8a9OQAt
         D652OP/W8j5dGfV8jlRJyMoZZ7NVJu3yPJHQdJFc3OCf3sp04f53trikHGAK9OS/XTLb
         jCsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Qc/9JiZY";
       spf=pass (google.com: domain of 3jsk7xgukcvw8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3JSk7XgUKCVw8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9srLh5ttTBi7uwV/YGFJX3dWLcnlccevFMPRAaReKqI=;
        b=T5/gqDTEjmHEmyvLWNJviEIFFyJd8d31WmgUj4/xF2veXF3VsXhFTYuWJX5E7eM4V5
         McYfSIj+4j809ThKXAV8nqLAYLX4z76tg+Vm47ZiQc0AwBKtguLXFxPiaLZU9opX+C82
         DWQVAWJfCwiYzoSTlobtz2v7Np308BevAN4nhnjI1mPpmCOzN7ZUl9/eIP7zM7wjtr2e
         bHcRSN7MndxBnE37f2nsgrmYx8uvFYg6P+Aiiv9KWDLa9NRn0DXiPmQzWvRzVRkG+xBh
         12mHgSm/+gRLgMUkw9okGzZNf1NLJ7lqJglSfYO2c2vQn/heMkZVO4oxUHGSybfKQBKF
         tWGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9srLh5ttTBi7uwV/YGFJX3dWLcnlccevFMPRAaReKqI=;
        b=ZERP8ZoSJcZBsDJQ6UpjrtVZPwW14vRs1csrIOIKukVEJeF6uobk8hoi+CczxNBZS9
         WHSHYmdx3w0S7HZi15AKOH0p/2Mfd6qNdvUNLbaXIBNDMfN9k33rvLPDm3pxNF+x1lOz
         Ia5gZkeZNpp3Gt+HapJXLNxKD3522gmC9RYZpD8LMQp4U1CO/IsfF72RU2cNk83PaO+B
         WIt/3of6UffxLjLLSthDUuOafY5rtiMGN7DtiCoj1MlP+KYX6cznYtfT7k/yo3pXHkBc
         b1Iuna9lWoV39tICTvcX/IMI8ZQp/rHDNzd6xvaDa+W2PZUUGcGNzYtKKRbywprc4vdo
         MqCw==
X-Gm-Message-State: APjAAAU9o2hI4VkY+j0kec8BY7/QkhBlkWCoFCCeahVyfDBOCYfBZlLc
	ZxSBxLr6wdey97ORJ55mLys=
X-Google-Smtp-Source: APXvYqx1sHmrmuVDciV5aPNC2tgC0RrIy5yRPCjiH8AnT7HfWA6RWh2sdoG6j4BC3jLrpEG94r72AQ==
X-Received: by 2002:a5d:4e0a:: with SMTP id p10mr372175wrt.229.1580935462357;
        Wed, 05 Feb 2020 12:44:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c0d9:: with SMTP id s25ls2935530wmh.0.gmail; Wed, 05 Feb
 2020 12:44:21 -0800 (PST)
X-Received: by 2002:a1c:a947:: with SMTP id s68mr7869530wme.61.1580935461616;
        Wed, 05 Feb 2020 12:44:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580935461; cv=none;
        d=google.com; s=arc-20160816;
        b=Z0GALoUz+1N7C1pV+AkEF2m5wuOeLVExVStVDYNqcaaUvLtZkYxX/TOcMzMppSyuAh
         /YOq5AOb4iySkec5X2Xi5GSlQWmZk2+r6UtmWLYmwUcQDkGahZtGTko1qo3cAz+mMNTe
         S9XIgHfZ0XHbT/khU1nmTGGBoVruCZdhxY8kJqBZn3wEGeH8XqBF+xDqKSUuTJ9YeBZP
         IU+zWubh0vJcfJNikLDIKvrZJJ+edGbVgkgonDSBN74gBWZCCr2JMpbj6SlR343wCGHn
         oDsJlBaW4VkKbSIL3B6qsg2P1Sd64HBPFUlFYECs9RrthCcbHeFKo92i4iVQfkDN105w
         8zJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Sd30aiJo7Ul/w6KJx1kKYsloupmct0RdFlLDgIoc8Tw=;
        b=CmrHDhE36zsEMEHTo1MxRfvTHUmD7+x9VMVEUAGDywUqURPf3ildDZEXweE+k8VJep
         c2SB5QFC9wIzbgXQ3GfOoTRVFSMwTpU0qUvKi18Z85EUhQ1HTnrxxuQrTDhxt+/k+gKt
         sLpACjjRSjp/Ds0lyEy/ya+4Yai7aHe7/FnzrVfw0GyKBvoE7AnQlJPeFMMAntaDX37D
         6X8az9E8Wqk/xndWGJOYmf6SlhJFmgHmo4So1TlMjrlvBL7BHdWAHI6O/pH9FCrRss60
         GlLnY/YNkKiSkgLZwAc/mA4Dyyer9iF0RjBkTWsPuu34U096tLlxktzsJ7TVzhJg2mkk
         l+SA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Qc/9JiZY";
       spf=pass (google.com: domain of 3jsk7xgukcvw8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3JSk7XgUKCVw8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id i18si52341wrn.0.2020.02.05.12.44.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Feb 2020 12:44:21 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jsk7xgukcvw8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id s13so2066855wrb.21
        for <kasan-dev@googlegroups.com>; Wed, 05 Feb 2020 12:44:21 -0800 (PST)
X-Received: by 2002:a5d:68cf:: with SMTP id p15mr345787wrw.31.1580935461105;
 Wed, 05 Feb 2020 12:44:21 -0800 (PST)
Date: Wed,  5 Feb 2020 21:43:33 +0100
In-Reply-To: <20200205204333.30953-1-elver@google.com>
Message-Id: <20200205204333.30953-3-elver@google.com>
Mime-Version: 1.0
References: <20200205204333.30953-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH 3/3] kcsan: Add test to generate conflicts via debugfs
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Qc/9JiZY";       spf=pass
 (google.com: domain of 3jsk7xgukcvw8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3JSk7XgUKCVw8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
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

Add 'test=<iters>' option to KCSAN's debugfs interface to invoke KCSAN
checks on a dummy variable. By writing 'test=<iters>' to the debugfs
file from multiple tasks, we can generate real conflicts, and trigger
data race reports.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/debugfs.c | 51 +++++++++++++++++++++++++++++++++++++-----
 1 file changed, 46 insertions(+), 5 deletions(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index bec42dab32ee8..5733f51a6e2c7 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -6,6 +6,7 @@
 #include <linux/debugfs.h>
 #include <linux/init.h>
 #include <linux/kallsyms.h>
+#include <linux/sched.h>
 #include <linux/seq_file.h>
 #include <linux/slab.h>
 #include <linux/sort.h>
@@ -68,9 +69,9 @@ void kcsan_counter_dec(enum kcsan_counter_id id)
 /*
  * The microbenchmark allows benchmarking KCSAN core runtime only. To run
  * multiple threads, pipe 'microbench=<iters>' from multiple tasks into the
- * debugfs file.
+ * debugfs file. This will not generate any conflicts, and tests fast-path only.
  */
-static void microbenchmark(unsigned long iters)
+static noinline void microbenchmark(unsigned long iters)
 {
 	cycles_t cycles;
 
@@ -80,18 +81,52 @@ static void microbenchmark(unsigned long iters)
 	while (iters--) {
 		/*
 		 * We can run this benchmark from multiple tasks; this address
-		 * calculation increases likelyhood of some accesses overlapping
-		 * (they still won't conflict because all are reads).
+		 * calculation increases likelyhood of some accesses
+		 * overlapping. Make the access type an atomic read, to never
+		 * set up watchpoints and test the fast-path only.
 		 */
 		unsigned long addr =
 			iters % (CONFIG_KCSAN_NUM_WATCHPOINTS * PAGE_SIZE);
-		__kcsan_check_read((void *)addr, sizeof(long));
+		__kcsan_check_access((void *)addr, sizeof(long), KCSAN_ACCESS_ATOMIC);
 	}
 	cycles = get_cycles() - cycles;
 
 	pr_info("KCSAN: %s end   | cycles: %llu\n", __func__, cycles);
 }
 
+/*
+ * Simple test to create conflicting accesses. Write 'test=<iters>' to KCSAN's
+ * debugfs file from multiple tasks to generate real conflicts and show reports.
+ */
+static long test_dummy;
+static noinline void test_thread(unsigned long iters)
+{
+	const struct kcsan_ctx ctx_save = current->kcsan_ctx;
+	cycles_t cycles;
+
+	/* We may have been called from an atomic region; reset context. */
+	memset(&current->kcsan_ctx, 0, sizeof(current->kcsan_ctx));
+
+	pr_info("KCSAN: %s begin | iters: %lu\n", __func__, iters);
+
+	cycles = get_cycles();
+	while (iters--) {
+		__kcsan_check_read(&test_dummy, sizeof(test_dummy));
+		__kcsan_check_write(&test_dummy, sizeof(test_dummy));
+		ASSERT_EXCLUSIVE_WRITER(test_dummy);
+		ASSERT_EXCLUSIVE_ACCESS(test_dummy);
+
+		/* not actually instrumented */
+		WRITE_ONCE(test_dummy, iters);  /* to observe value-change */
+	}
+	cycles = get_cycles() - cycles;
+
+	pr_info("KCSAN: %s end   | cycles: %llu\n", __func__, cycles);
+
+	/* restore context */
+	current->kcsan_ctx = ctx_save;
+}
+
 static int cmp_filterlist_addrs(const void *rhs, const void *lhs)
 {
 	const unsigned long a = *(const unsigned long *)rhs;
@@ -241,6 +276,12 @@ debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *o
 		if (kstrtoul(&arg[sizeof("microbench=") - 1], 0, &iters))
 			return -EINVAL;
 		microbenchmark(iters);
+	} else if (!strncmp(arg, "test=", sizeof("test=") - 1)) {
+		unsigned long iters;
+
+		if (kstrtoul(&arg[sizeof("test=") - 1], 0, &iters))
+			return -EINVAL;
+		test_thread(iters);
 	} else if (!strcmp(arg, "whitelist")) {
 		set_report_filterlist_whitelist(true);
 	} else if (!strcmp(arg, "blacklist")) {
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200205204333.30953-3-elver%40google.com.
