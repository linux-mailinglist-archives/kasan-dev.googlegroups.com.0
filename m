Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHVCWXZAKGQET5QHT6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id BE98C16481F
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Feb 2020 16:15:42 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id b8sf248365wmj.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Feb 2020 07:15:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582125342; cv=pass;
        d=google.com; s=arc-20160816;
        b=BjF0k52e6VNdriXn/DnYSVuOvQ1drR9/yA2ub6UViitAJQiXEBDgTHGD7cWQ86TPos
         0tgVUDfc81j4ydjNbgyY/9oz+nZrIbTeThwT/bGtWGlgpUaI/34w/CoDmVJavk/6dMUY
         3kGacyT91nqNHbXh+ixv7Okf9UcbSgVVz8kGQQ5q+QZHcvHXd8P3Fjlpb/tz2nuq6s9D
         n9qqh8PcgVibV4J5HAMv1fTLwVdkn5aNOc4dVd8XaBD1QYmFSiCi8a9mTZQcCx7gRZn/
         5NK59+7Q8TKTsMnztoxrdPv9uXtURQ8KDr9KTSgVKXWfFz3bltrJ26cQGhwOibTF/03t
         20Bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=jWjZVPRBHJeYyQN9DSBpmO1+t2J1yNY7/0Te3an34ac=;
        b=Bj+JW9bd2KP2b0c7PVw/jR+K31fcYbBW3CQGwALkrWt4l5h/aoH0AzORiC3b3CPzoz
         V3fSCFA1OwtPpI/BedPDJ6mtSwb39lLIS5cBb+mXerGGB1iYD5gVU5gs3KGJN6kHZBjN
         n/iRJvstrwbAFRVv/a9K7p+pO5b6WuGiIipwRAbNpfwIjr83q2qQK+TgWmvwAJY44SZq
         XgeYj/LS1ycqIs/Woz9ea1h+RMF/854BU5Q/qfs27fBXiEt+XLx1U6fH0PS9QDgjtqqb
         N51Wkt5bJvBwbPVCrzhrzQUaIDHGHR/4DdK7fJGBu/678LkSUvToD5wgV2GF8IRkntdz
         fdZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cW2cAcBP;
       spf=pass (google.com: domain of 3hffnxgukcesryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HFFNXgUKCesRYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=jWjZVPRBHJeYyQN9DSBpmO1+t2J1yNY7/0Te3an34ac=;
        b=BPF8j1EF6QSzdiY5cCFL6NNvSwU3DllUA6iS4a4CMV9hNIGKANepmtPCL/pAmWUeck
         Q3hBN0V0FSiUrkyCXlBWe+GKDm1Qv7blHjZfhQAl1CyWkI0JQPoZ0PKY86jRjF1VwEbT
         RXzpCoxWq1J0IfpViYicKPvm3eVJHVVilKMVukTrSwGzUBtauI2rEd1p76vZJEpPbbOl
         amIgb2bOn8n6XqolROSOjdnFx80xi3Egke3kyY6AM8MQZw6GVwtnR4GfpqoufqiWSsvt
         cxeZFhTInKxJVf/Oc5BhRrPjY420Ev+J6Ty/Em2D2kvmlb94EspZ3c38/7h2C8kkyWvY
         tkLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jWjZVPRBHJeYyQN9DSBpmO1+t2J1yNY7/0Te3an34ac=;
        b=Rycj6Dcj7DEV0AAJEFTTouUjZe21RLlU3WVGFW75z1DYCnSHGNkgETI7OecpraTfb3
         30eJWiUZP+8/HhxDp4q2y1NpnpjQYc2XBRIJfMzhch61OVElDA37SL3I8AE232i5TIr/
         5Ep7/3ton106LIesppoQv0U2pSfSk+NztWmcUZyuBapCTqNmvlDXt9voe/Z40UYooYWI
         iARdkEutQkiqlSo88EL7dJYCUbHhjv8+Bw03ODHlbFgDLwdrWp5LTEbEXbqCAxsi6+e6
         7UHIkc3bN5ak6mVwP1rPBcgNwuCcbX4daLV23TH5fQ0I0d7w2glDq/xPf26jsjxpHO0w
         djrA==
X-Gm-Message-State: APjAAAUH5jHxQ7Dz3ICtduypelt3yiogMeXmDRPCIj4BVg2OCqUJFGJD
	g7VIXdxe6k8li98u0iEwRvQ=
X-Google-Smtp-Source: APXvYqy7s24RpcHEQjbg2EnJdNOeAOuKtoOi1lrEWMnmcusxEkDZY4dmAaErBDyou/tCxxaE4xydTg==
X-Received: by 2002:a7b:c847:: with SMTP id c7mr10229853wml.3.1582125342474;
        Wed, 19 Feb 2020 07:15:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6a8f:: with SMTP id s15ls9774114wru.7.gmail; Wed, 19 Feb
 2020 07:15:41 -0800 (PST)
X-Received: by 2002:adf:93c1:: with SMTP id 59mr37225458wrp.399.1582125341577;
        Wed, 19 Feb 2020 07:15:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582125341; cv=none;
        d=google.com; s=arc-20160816;
        b=KgJVFxghkVbpEsfmsZtSHJxpgFdmNMZ41BOMhpnBTuQQjjbtFbXahrmhvhgcNaX+JS
         j9ZY6Fr5Dncbke2wqSzhH6Hg/ZsL/auW4RNUt1cFXh9QTtLbheIqSg2/hMNJTBn41WQP
         ASIJcopNHbc95fZpudlIK5++o9eK3C3aW3HHA58NZFv1nNrpLdY/NyW7BYd0SZjJ+j7q
         tZd8sL9q34s3lVbmvHfCEwrBO/HkhGp8vmJ009xNNgP7ojb1AGqChIrX5wuBXeIAXOJQ
         rQzxMHUr9Shr/h4abeLjaWUkbQ6P1/tiI1Lwdk13G2hCFuAjZg7hFfdg5okF1jftX17V
         s81Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=Byu8soxgkprIbakxZbQOBFe9yLNNMXZxXhnHj/Q3XIE=;
        b=sTykfAzRgKMbSZDOkUTlwX+mRDHXurjvA0uK9hCnv9Ib+gB5sHQZepPmEAA9ENwLYM
         Ec/PHqRZ5hRfqWs+EEu9RKnV8Xj3LgJ8Sk0dhnD5N295yX0OLFJXzD8hJPjNd5jtIyCu
         aitZD/4PZiyKQSAeyRcwNTY2VrUbthPPyNu2VCd5NkY6BFSv7pkED7wslMhlm/BhNc/U
         DTn4vF6zG/4pjQHkJDjtrmzb0uRYmLJxSfbyhmpEIPSR9OL9cP1VmVrASh0yH5MykXfo
         RzNjHfFrxeAxxTvTSL/hrNJvYKuMYZwIelKyYR+7cLT15SI8olQqUYMYem1QgSiWZ3Eh
         3w9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cW2cAcBP;
       spf=pass (google.com: domain of 3hffnxgukcesryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HFFNXgUKCesRYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id t83si230737wmb.4.2020.02.19.07.15.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Feb 2020 07:15:41 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hffnxgukcesryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id p2so326373wmi.8
        for <kasan-dev@googlegroups.com>; Wed, 19 Feb 2020 07:15:41 -0800 (PST)
X-Received: by 2002:a5d:6404:: with SMTP id z4mr9741809wru.262.1582125340973;
 Wed, 19 Feb 2020 07:15:40 -0800 (PST)
Date: Wed, 19 Feb 2020 16:15:31 +0100
Message-Id: <20200219151531.161515-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.265.gbab2e86ba0-goog
Subject: [PATCH] kcsan: Add option for verbose reporting
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cW2cAcBP;       spf=pass
 (google.com: domain of 3hffnxgukcesryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HFFNXgUKCesRYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
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

Adds CONFIG_KCSAN_VERBOSE to optionally enable more verbose reports.
Currently information about the reporting task's held locks and IRQ
trace events are shown, if they are enabled.

Signed-off-by: Marco Elver <elver@google.com>
Suggested-by: Qian Cai <cai@lca.pw>
---
 kernel/kcsan/report.c | 48 +++++++++++++++++++++++++++++++++++++++++++
 lib/Kconfig.kcsan     | 13 ++++++++++++
 2 files changed, 61 insertions(+)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 11c791b886f3c..f14becb6f1537 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -1,10 +1,12 @@
 // SPDX-License-Identifier: GPL-2.0
 
+#include <linux/debug_locks.h>
 #include <linux/jiffies.h>
 #include <linux/kernel.h>
 #include <linux/lockdep.h>
 #include <linux/preempt.h>
 #include <linux/printk.h>
+#include <linux/rcupdate.h>
 #include <linux/sched.h>
 #include <linux/spinlock.h>
 #include <linux/stacktrace.h>
@@ -245,6 +247,29 @@ static int sym_strcmp(void *addr1, void *addr2)
 	return strncmp(buf1, buf2, sizeof(buf1));
 }
 
+static void print_verbose_info(struct task_struct *task)
+{
+	if (!task)
+		return;
+
+	if (task != current && task->state == TASK_RUNNING)
+		/*
+		 * Showing held locks for a running task is unreliable, so just
+		 * skip this. The printed locks are very likely inconsistent,
+		 * since the stack trace was obtained when the actual race
+		 * occurred and the task has since continued execution. Since we
+		 * cannot display the below information from the racing thread,
+		 * but must print it all from the watcher thread, bail out.
+		 * Note: Even if the task is not running, there is a chance that
+		 * the locks held may be inconsistent.
+		 */
+		return;
+
+	pr_err("\n");
+	debug_show_held_locks(task);
+	print_irqtrace_events(task);
+}
+
 /*
  * Returns true if a report was generated, false otherwise.
  */
@@ -319,6 +344,26 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
 				  other_info.num_stack_entries - other_skipnr,
 				  0);
 
+		if (IS_ENABLED(CONFIG_KCSAN_VERBOSE) && other_info.task_pid != -1) {
+			struct task_struct *other_task;
+
+			/*
+			 * Rather than passing @current from the other task via
+			 * @other_info, obtain task_struct here. The problem
+			 * with passing @current via @other_info is that, we
+			 * would have to get_task_struct/put_task_struct, and if
+			 * we race with a task being released, we would have to
+			 * release it in release_report(). This may result in
+			 * deadlock if we want to use KCSAN on the allocators.
+			 * Instead, make this best-effort, and if the task was
+			 * already released, we just do not print anything here.
+			 */
+			rcu_read_lock();
+			other_task = find_task_by_pid_ns(other_info.task_pid, &init_pid_ns);
+			print_verbose_info(other_task);
+			rcu_read_unlock();
+		}
+
 		pr_err("\n");
 		pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
 		       get_access_type(access_type), ptr, size,
@@ -340,6 +385,9 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
 	stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr,
 			  0);
 
+	if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
+		print_verbose_info(current);
+
 	/* Print report footer. */
 	pr_err("\n");
 	pr_err("Reported by Kernel Concurrency Sanitizer on:\n");
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index f0b791143c6ab..ba9268076cfbc 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -20,6 +20,19 @@ menuconfig KCSAN
 
 if KCSAN
 
+config KCSAN_VERBOSE
+	bool "Show verbose reports with more information about system state"
+	depends on PROVE_LOCKING
+	help
+	  If enabled, reports show more information about the system state that
+	  may help better analyze and debug races. This includes held locks and
+	  IRQ trace events.
+
+	  While this option should generally be benign, we call into more
+	  external functions on report generation; if a race report is
+	  generated from any one of them, system stability may suffer due to
+	  deadlocks or recursion.  If in doubt, say N.
+
 config KCSAN_DEBUG
 	bool "Debugging of KCSAN internals"
 
-- 
2.25.0.265.gbab2e86ba0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200219151531.161515-1-elver%40google.com.
