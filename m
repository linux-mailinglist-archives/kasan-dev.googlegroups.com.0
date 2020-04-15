Return-Path: <kasan-dev+bncBAABBJVH3X2AKGQE7SJYMLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 68EE51AB0C4
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 20:34:15 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id c4sf6108923ilf.11
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 11:34:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586975654; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZriY0Wb88mtt4sTdmeBG+UD8ez/8nleNBVFdBhaeF23CJbcAmn5MG66uk9iOx+mI6n
         AWcBPGqyND6hK2wldbjNVVH/NcnzxGmJUVc8N+MVkM+p2Hdw/QIw0+aYMQxBc/1WEzl2
         3CHiinn9CQML254byciLu9fRZLB6QdLJ4HTYwFZK7D6nH7gdBY1X4mfwEhnB8wJvYVO1
         psXb2CW+YD0kT/GKAZtnKcPYDZDO4tJT/NjDGGbJmDD3aSsIbDnGL0z7QlYQvuE4RjTT
         UWEoF0hQCc3oPibRFY52Yo1rfRJcvIBQZRgmE6uxz7AaTMuivJrrgeNyGNKOOI+qBm/S
         Avdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=wfSBP3AyR5XbY46k7/OlpN5iCnLRJ5+YoZTCu+6o4NM=;
        b=himb0Zmk1CXvnTqkzQYaEn0VC8k2iYKVr++LlLSGWQjTNCLXN8BWiWkv5XVmKy4lJA
         SS0cs7+Co//fy0HqTBcn3R4PO9gps15PKkSkGCbzSxQR0Pa8joBJ0Ur5cl8i+INeeKBO
         KDALB1SdjkmqyVMmPCWs+v74Adcw5TeS1YM8yAxlgFlEzMM+pHWucQH5LwXoM/g0o4oc
         hZNGyy3p2lC75leshemBcWTERWJ6N5Sz4/pZOg+KgXkCeIzV5XLLebR0Dlg7Kyz8FVem
         pkkH4b60smHJsgpm+z4GAUVn4zsVSLk7fziciR33P7igBz+s5/n/DNcMO0sXwHrnEsyY
         qLog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=iNrFmMYv;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wfSBP3AyR5XbY46k7/OlpN5iCnLRJ5+YoZTCu+6o4NM=;
        b=f6gJ2OMvQnqkPpNQ4TK33EYwXUVui6NY0+rnqweivjnS+Z3oFRTO65PU32bBPgrv5f
         q5UUY2CloT5gIpN76ESPevPwo7LsDtFDrdPENjRNMh1JuI6gNFq+KRbhyw4walLWp/t8
         9OdYos9zq4LQ450XUts7eG7fMqpBwRDI82LlKE+Dw9lH3G4z0kuirfq8MYeukhbBg+vZ
         S73a6lUJqIbhA4jK8a1EgHDtT+Em7h5yt9nPRG7NY0jINz/QO0Jf1cBcSBl3sU2UYslt
         mApRJhlu48Y2Rfbkf4/igG6X3/DKbIFS3VXil+heBj91oK3MsPDxwdNK1ndGmpoY6RAQ
         F1wA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wfSBP3AyR5XbY46k7/OlpN5iCnLRJ5+YoZTCu+6o4NM=;
        b=KKK3WI4oaggGBeJXtHcAjbFtnbIJae0ODKzLQc1bbsvFUy4MMA+1sarUMm6MXj+XBO
         DMSSJDx7KLr/SsYd/CwK3t546fDW/AxUNFrGcjaW0323cTbm9oeTEKJUGuYvxUjnP8+X
         aZF9ylfhTZsJ/H+JfH2FlfORIlI84flwPldxnGfqThN1vV3GZHQgcwwqTMbEkOWyduDi
         JQnqnUIfg8TUqzHJWvGZ7NhybvDGoL9xkZuuee9PBi4ieS5p7DKHlXxjEI40kSVZ/oWZ
         hkKfYKY9s3fqHq0uBnmhcI1CbSnottqpH76flCqmsGOc3CE3ek6EvPYermlOoQH0k7/Z
         XcEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZ8E3rUU19L5PD5LtaVvUXi06pujNQhXzxYRrLZDzOOmi5yBVt+
	LM1gnChjXYmPU0gZ51lH7vU=
X-Google-Smtp-Source: APiQypJ9lUqijjKPGstLyF+Hzw204gI6YZKmRRUp7UGba/uEyv7ilIoVZXL2i5KF+hYaSAeI7CFoYw==
X-Received: by 2002:a6b:b547:: with SMTP id e68mr24548481iof.173.1586975654439;
        Wed, 15 Apr 2020 11:34:14 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:878c:: with SMTP id f12ls2413419ion.1.gmail; Wed, 15 Apr
 2020 11:34:14 -0700 (PDT)
X-Received: by 2002:a05:6602:1214:: with SMTP id y20mr27985544iot.106.1586975654194;
        Wed, 15 Apr 2020 11:34:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586975654; cv=none;
        d=google.com; s=arc-20160816;
        b=O2nDyUme64jqObc9cIxarTBQ63w/W3aGtUuA/aITXWyZbMv6hayz4B0ZdahDTm7dIx
         wwIo5Z83l5zRVRpGWQyUJ1TTXc+mQlwrMReJ/Pv9WnguM4e503/fS5KKM7HstxgkWVud
         WHyGM+IixvHo5oUCgxRKOUZ2hCLFudQfBzLHKDvCNAYg6b1zZp95xLZAfZqbpQvT6JUE
         yF+/V7rQxCqQrTj6fELwAO80mLnTLwYJXdUb5GUnB66PxRt3KW/PfD/mLVuR9VsDYP8u
         E97ZpSmsVOD7DZU3Yj7iWh/PvF5qQg2THK7qMjhuMMaX6CDaH2gffnpUdFYg5ULxqY8/
         3a1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=7OFfAHGGG3rVXY6J2TaubDU4Xao31vVX//rjqI60xkA=;
        b=KGcKEg38r+WAf0MM7DJtnKhjUQbblqU1eSWyQtG+kCJLzWd2MkLfGxEwAtbqkgdPcM
         N9WE/UkwZfneFoplq4wFap1RvapcBJQaY9IBvs3ZIpSUuIqv0B0aFYL7l0njEzhPCiez
         +Htt5Fo1PrPPWdHNg+8SSedb5+4pDW/zcoZAj8w9xT+wNf+S3wmgti8bZlc59M9UVvAv
         4pRZ+Xn+b4rW3tuH4AyCvmAiHcPFBIe8bgPRWZFwSI2KdXCwG38RnOfJen2yEZY+t6Sp
         vU5BqfvjuL8WR2TkX4kK1UDUpz7FhJWrqnRy7i/H3kpLo/OpUju2kVOCB+3lSYCtWOXD
         NyGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=iNrFmMYv;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r8si488458ilj.3.2020.04.15.11.34.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Apr 2020 11:34:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 5E4C721582;
	Wed, 15 Apr 2020 18:34:13 +0000 (UTC)
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
Subject: [PATCH v4 tip/core/rcu 02/15] kcsan: Add option for verbose reporting
Date: Wed, 15 Apr 2020 11:33:58 -0700
Message-Id: <20200415183411.12368-2-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200415183343.GA12265@paulmck-ThinkPad-P72>
References: <20200415183343.GA12265@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=iNrFmMYv;       spf=pass
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

Adds CONFIG_KCSAN_VERBOSE to optionally enable more verbose reports.
Currently information about the reporting task's held locks and IRQ
trace events are shown, if they are enabled.

Signed-off-by: Marco Elver <elver@google.com>
Suggested-by: Qian Cai <cai@lca.pw>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c   |   4 +-
 kernel/kcsan/kcsan.h  |   3 ++
 kernel/kcsan/report.c | 103 +++++++++++++++++++++++++++++++++++++++++++++++++-
 lib/Kconfig.kcsan     |  13 +++++++
 4 files changed, 120 insertions(+), 3 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index e7387fe..065615d 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -18,8 +18,8 @@
 #include "kcsan.h"
 
 static bool kcsan_early_enable = IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE);
-static unsigned int kcsan_udelay_task = CONFIG_KCSAN_UDELAY_TASK;
-static unsigned int kcsan_udelay_interrupt = CONFIG_KCSAN_UDELAY_INTERRUPT;
+unsigned int kcsan_udelay_task = CONFIG_KCSAN_UDELAY_TASK;
+unsigned int kcsan_udelay_interrupt = CONFIG_KCSAN_UDELAY_INTERRUPT;
 static long kcsan_skip_watch = CONFIG_KCSAN_SKIP_WATCH;
 static bool kcsan_interrupt_watcher = IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER);
 
diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
index 892de51..e282f8b 100644
--- a/kernel/kcsan/kcsan.h
+++ b/kernel/kcsan/kcsan.h
@@ -13,6 +13,9 @@
 /* The number of adjacent watchpoints to check. */
 #define KCSAN_CHECK_ADJACENT 1
 
+extern unsigned int kcsan_udelay_task;
+extern unsigned int kcsan_udelay_interrupt;
+
 /*
  * Globally enable and disable KCSAN.
  */
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 11c791b..18f9d3b 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -1,5 +1,7 @@
 // SPDX-License-Identifier: GPL-2.0
 
+#include <linux/debug_locks.h>
+#include <linux/delay.h>
 #include <linux/jiffies.h>
 #include <linux/kernel.h>
 #include <linux/lockdep.h>
@@ -31,7 +33,26 @@ static struct {
 	int			cpu_id;
 	unsigned long		stack_entries[NUM_STACK_ENTRIES];
 	int			num_stack_entries;
-} other_info = { .ptr = NULL };
+
+	/*
+	 * Optionally pass @current. Typically we do not need to pass @current
+	 * via @other_info since just @task_pid is sufficient. Passing @current
+	 * has additional overhead.
+	 *
+	 * To safely pass @current, we must either use get_task_struct/
+	 * put_task_struct, or stall the thread that populated @other_info.
+	 *
+	 * We cannot rely on get_task_struct/put_task_struct in case
+	 * release_report() races with a task being released, and would have to
+	 * free it in release_report(). This may result in deadlock if we want
+	 * to use KCSAN on the allocators.
+	 *
+	 * Since we also want to reliably print held locks for
+	 * CONFIG_KCSAN_VERBOSE, the current implementation stalls the thread
+	 * that populated @other_info until it has been consumed.
+	 */
+	struct task_struct	*task;
+} other_info;
 
 /*
  * Information about reported races; used to rate limit reporting.
@@ -245,6 +266,16 @@ static int sym_strcmp(void *addr1, void *addr2)
 	return strncmp(buf1, buf2, sizeof(buf1));
 }
 
+static void print_verbose_info(struct task_struct *task)
+{
+	if (!task)
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
@@ -319,6 +350,9 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
 				  other_info.num_stack_entries - other_skipnr,
 				  0);
 
+		if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
+			print_verbose_info(other_info.task);
+
 		pr_err("\n");
 		pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
 		       get_access_type(access_type), ptr, size,
@@ -340,6 +374,9 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
 	stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr,
 			  0);
 
+	if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
+		print_verbose_info(current);
+
 	/* Print report footer. */
 	pr_err("\n");
 	pr_err("Reported by Kernel Concurrency Sanitizer on:\n");
@@ -358,6 +395,67 @@ static void release_report(unsigned long *flags, enum kcsan_report_type type)
 }
 
 /*
+ * Sets @other_info.task and awaits consumption of @other_info.
+ *
+ * Precondition: report_lock is held.
+ * Postcondition: report_lock is held.
+ */
+static void
+set_other_info_task_blocking(unsigned long *flags, const volatile void *ptr)
+{
+	/*
+	 * We may be instrumenting a code-path where current->state is already
+	 * something other than TASK_RUNNING.
+	 */
+	const bool is_running = current->state == TASK_RUNNING;
+	/*
+	 * To avoid deadlock in case we are in an interrupt here and this is a
+	 * race with a task on the same CPU (KCSAN_INTERRUPT_WATCHER), provide a
+	 * timeout to ensure this works in all contexts.
+	 *
+	 * Await approximately the worst case delay of the reporting thread (if
+	 * we are not interrupted).
+	 */
+	int timeout = max(kcsan_udelay_task, kcsan_udelay_interrupt);
+
+	other_info.task = current;
+	do {
+		if (is_running) {
+			/*
+			 * Let lockdep know the real task is sleeping, to print
+			 * the held locks (recall we turned lockdep off, so
+			 * locking/unlocking @report_lock won't be recorded).
+			 */
+			set_current_state(TASK_UNINTERRUPTIBLE);
+		}
+		spin_unlock_irqrestore(&report_lock, *flags);
+		/*
+		 * We cannot call schedule() since we also cannot reliably
+		 * determine if sleeping here is permitted -- see in_atomic().
+		 */
+
+		udelay(1);
+		spin_lock_irqsave(&report_lock, *flags);
+		if (timeout-- < 0) {
+			/*
+			 * Abort. Reset other_info.task to NULL, since it
+			 * appears the other thread is still going to consume
+			 * it. It will result in no verbose info printed for
+			 * this task.
+			 */
+			other_info.task = NULL;
+			break;
+		}
+		/*
+		 * If @ptr nor @current matches, then our information has been
+		 * consumed and we may continue. If not, retry.
+		 */
+	} while (other_info.ptr == ptr && other_info.task == current);
+	if (is_running)
+		set_current_state(TASK_RUNNING);
+}
+
+/*
  * Depending on the report type either sets other_info and returns false, or
  * acquires the matching other_info and returns true. If other_info is not
  * required for the report type, simply acquires report_lock and returns true.
@@ -388,6 +486,9 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
 		other_info.cpu_id		= cpu_id;
 		other_info.num_stack_entries	= stack_trace_save(other_info.stack_entries, NUM_STACK_ENTRIES, 1);
 
+		if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
+			set_other_info_task_blocking(flags, ptr);
+
 		spin_unlock_irqrestore(&report_lock, *flags);
 
 		/*
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 081ed2e..0f1447f 100644
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
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200415183411.12368-2-paulmck%40kernel.org.
