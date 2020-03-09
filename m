Return-Path: <kasan-dev+bncBAABBPVGTLZQKGQE2HH7G7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E8EF117E7E2
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:31 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id v3sf7374369qve.11
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780671; cv=pass;
        d=google.com; s=arc-20160816;
        b=DCrbOdyi9zZ5tbPfUceRfncgh4vpYxcUPS9d4h28HZY7JRaKed/SWYXlk6UpnU5dqM
         er7L3qvdzo4L+jWJu6ogX+ah3N3zJISIAxf70Gwk2kEljS0pEGW6nZH0n+GAcHMvnzoU
         v1bcilcGaehakiWtd/QviYG4Ej5knla6uSgwnTAIC1ZscEMrVGl8SZ7ZvYIwq9ANn8oA
         NaoPRNKRL4ulveS666VxccztL8WmetFvSD0pXbOcCEOMqdyJEmW6jwuLvgh0eTTskMyJ
         mvgWDPJrXOeu0KOFmH5DSpgRhe9giHsvTogYuKLy9fKSmhtcpQ3anI7Wfbjc+pas5jVz
         wXfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=z3vL/bsA+SaC609XJzaQGwkgUJH4qJGB7HDDdGwIc6k=;
        b=y11sOxutS9dMe8gPYK/pP56ZsQkIPaCT6MfkLeY/6/tPsTxwVmMM/DSiaxmMoq8qh/
         VtQBwm9jrMEKrFwRPhJmpS3gJchV2qWYv4CgMJv1gZzUS3GlDeGJIupuv8n+CwdjLKdm
         CyrBkIequnhb1wJfRv057F2s2Rr4VGlVX+LT+ZzzbTqY+mrQHW6bfGnMeb03McrHYWbf
         g8zrMx879pI19gIm81wmSuDj+JPawKZPqUGn69SqlRoy4jUXmWx2pLw3Xj4aHfQnFmsZ
         +t6R43BXU2TPm1CMDJTStpCMSt3xxs21Wm6tYNnt9hfuxjNxcDJ2rqiVepfqw2WI2uaw
         U27g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=QzyY5YC4;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z3vL/bsA+SaC609XJzaQGwkgUJH4qJGB7HDDdGwIc6k=;
        b=Z4UfbrM+mLZoAkOojAMl1UL4k2SjRdQKSx9AzZ39h1xY8+jV7su1LN0BmND1V7anHf
         Z/1xgtuLZdOmYv3zrFPrHoRNLfDZxGcEkxkHpLuApVqM2x85L5hS75fsBfqMGw9558Pq
         jpAi+M+FV6mX823mm2C5nJ6GkkWt064bBbJFVNlysaZJOpHFraxL9TsvNHirX1KCqQpk
         POicP0ChAT/mm+opywTqeJ2UB+2imdDa1fnJMJRiWNLvzUDKtquqVUWpmI4b29Tc0FBs
         hkOIWcNjWW5kih5J46np9Q8KqB3OodrPBm+qGRvFxGOnCVFyCGiisWd5qvnSkXO/P0Wx
         neSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z3vL/bsA+SaC609XJzaQGwkgUJH4qJGB7HDDdGwIc6k=;
        b=K3rpD4k5n+f4S8xhTzsKCAqN5OMQtF49odxMyfzHlzeghRK2VZA86emWxyQe1CEMPl
         YMbSwWeQmW59cztmOcg+zJUnxhk+AT0xQ2Y/QWfm72+Ap3s9GWuw9c916+hgZFWoXaxB
         rq12gQePYzQqEKRs82wxKXSasYfx86jXe0Ij1MFEUvEApcZsrw5SJDt95usbu8piroC8
         BcwgB13hDZSI4ipjvXVXYerwmTt9K+OdnMNMHRMIdvw24NGhQ1xOliHvZ4KnFiSwDLWF
         wjXSZKyVd+SbckEvDvxg/+BN9PXHqQkrAsnkD13r9fgP3VhyCZ92L1NG3/T1NAQmXpaj
         LFBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ2RWB2M6nzoOIPuFW0KJXfeB5+Cts46HO6OHdiDFbnlCsAdyPz0
	NO9q6Wbb60HE2Rw3ZYHsw28=
X-Google-Smtp-Source: ADFU+vtE7xEsrYlUjoCcmV2TLZuTnrc8vWm7npXgysV/WzsempE6ElgmJ2ju2zKkUjmaIXJuCYbFXw==
X-Received: by 2002:a0c:a281:: with SMTP id g1mr15810312qva.168.1583780670913;
        Mon, 09 Mar 2020 12:04:30 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7358:: with SMTP id q24ls3571622qtp.4.gmail; Mon, 09 Mar
 2020 12:04:30 -0700 (PDT)
X-Received: by 2002:ac8:775a:: with SMTP id g26mr15557655qtu.125.1583780670330;
        Mon, 09 Mar 2020 12:04:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780670; cv=none;
        d=google.com; s=arc-20160816;
        b=OslNtU9sRQepjbaCbSZWDjk+ORjgQqV1AG2kzFCr+Y3rjUl/RfjGb2c34/swz1f169
         jt2cwRHqsOnzYF/8K1Nb0KgSwhn4zATvUO9IGXUlx0dPaVjK6NA3g1HI63I5/3m0IezW
         wx2J5UJUTR2sHsJMtw1HT2+dNwHbZhFWrWt4Rhc005ffa8pCi2k1Cibo2AyfJE5fHhCB
         KDi8oC+/fvCg4jVkTFds6zOnCgauDXWbXGSiY1Cp0JAdrrDxzovzy1Afj8pRKCCL94B9
         wvH69+jON85thZrVeutMbmM6j/L4v+aRNikvcpMZJVlkEO817hccl3is3U8NHd5afmah
         cqeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=vhZinSdZ088Ar7xW4Ox+eBs+vfEi/9GxC/xQX81u2jA=;
        b=g7NlFIuz1n0kvPJQEzRNwDJd0M1yHH0ecjqkLxv2Kr7ov+inLwPawr7O51zHMXsPCF
         2R0V/ylVQG3bsSCqsemmR04AIHw8jEHQGzSDv0WXOTEM/OIPoG9wtxzrZ1oSka+fbkPU
         UENKgoL5pNnFwEmehIdlfvn2Eq5K09+glfFlrHhyt0yRMBVMPZRAB1BhxrP4prcFZd2P
         5o05Nq75RXZned98kSGMG6VxTc6cRtUuz5b3eNpJSYezBTjdmA9NmC1cFZ33WRn37Vpx
         0XkQGd7MelTRlOM04A0njEvinmS/8RaebCWV2Ym4OuAuB9vZHBSh4Y4TVuOSz39OYs2C
         bRwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=QzyY5YC4;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r32si749476qtb.2.2020.03.09.12.04.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 2366824679;
	Mon,  9 Mar 2020 19:04:29 +0000 (UTC)
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
Subject: [PATCH kcsan 28/32] kcsan: Add option for verbose reporting
Date: Mon,  9 Mar 2020 12:04:16 -0700
Message-Id: <20200309190420.6100-28-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=QzyY5YC4;       spf=pass
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
index 11c791b..7bdb515 100644
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
+		    print_verbose_info(other_info.task);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-28-paulmck%40kernel.org.
