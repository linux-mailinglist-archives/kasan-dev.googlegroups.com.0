Return-Path: <kasan-dev+bncBC7OBJGL2MHBB26GYHZAKGQEKTDPJ2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id B3852168A40
	for <lists+kasan-dev@lfdr.de>; Sat, 22 Feb 2020 00:10:35 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id r14sf500221ljc.18
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2020 15:10:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582326635; cv=pass;
        d=google.com; s=arc-20160816;
        b=FeDeLX9+nZk77B+dM15lR27j1j0p9xZd6jmlLOgHxZtVKIcSNLuS63wBDudHEvZiJ+
         rOdNGcK9Dh7PSJOeZ1MvZ1IT6YFZxVXbQhE31QG1HLnCuy5hGbiYpiVyP4g/2RZCwwA9
         rpCo0VQogosAysKzVB1Q18lS7HvY/Ul2JXRjkjvnaLLkXxm3lwgw/QZkNekcXW/JdXPr
         kHlGtph6ehDsfJTeV8jJ01z+DOJ95coBPWg6BM1g4a2qglwHKhIm5RdWLXwZRmb2XPaz
         CZDvv6gnninvho/6VWLbq2Zm64Z3bNuXBxfBgrV2suYdvLfQnq+BZ/5b8LHXd/07vPG4
         evOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=nYlTCS2A5QoekmLfotO1GNzpVrzb3zlZsU5Bu24FKe4=;
        b=eo20kZ54oADupwBcrSHWAzXIli0812FuWvEWZZzRIUJdgIEsv48klVl5fBXOJTU33Z
         22B4+UHLzbzplR/KYPbgqjmPTeE/ZmXLjyAJTGlvIuY1mV5MP42bc+Im42kAhSXLHZMb
         xci6ITpDXvEhJ6ZyZxmBArOMuPS8B545SqwB7Vd92XE7uyFjp1v/EFiAnQ2lFw71wuo+
         63p8HiEfgdEjD1Pcc7KldnaRGSlw+hoC326jqZpqkVkS2IktvOF88fFR4l4t2CI5SlYV
         2zI6mlXgJ8ka0uY/ZxlOZo1/S38R9eKsTfuoviIUUFbnNXPNU2u7WIXnSJI0areCkjs4
         jeLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nUZ4jtYu;
       spf=pass (google.com: domain of 3awnqxgukcwomtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3aWNQXgUKCWoMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=nYlTCS2A5QoekmLfotO1GNzpVrzb3zlZsU5Bu24FKe4=;
        b=Sn+1x990pQgCSHEaWJgrzJoMUnrGDRqC/h9Pzbp8IeXv6ogGfu3JM4rq7qQeeepPw6
         +Od+D2k5qYk8na5jjQb2xd4SEfbj52tvz747BPxJNmGWrdf/FkvxlYzIf1wCLe+S4O95
         WD3bk0xp1BZt6tIjjmkvPhYVLPVaC/Ph9vT9+/foUFeP1pdPKklrVff1vd9j3dW9CGIa
         CSTGeTX4C/pH+HhrIuxHje/Ui9TvV1D0pCyQY64pmmz4c2CIrX4DaDtNsB/rmCbTz7eH
         PohHBadW7r9cpE8CwCQAVRu4ijJg3rTljHVdGRtKKy3zBvoFTEgH7ibw/KPKzOkfEByx
         49zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nYlTCS2A5QoekmLfotO1GNzpVrzb3zlZsU5Bu24FKe4=;
        b=mkBNr63SlfSRabi5nJfAfer0s0tGPtSJqIY2hj9d09JLVahdAibOuoXwsPylx4S6pv
         VbHvLtwDnFFvRT3nCMWyLPZ/YXCAO3q5opJ2yPIGcwbeVfCKwkrGfXQWn8zvlqEdVdw2
         fDmrxPwc8FpK2s276/OvzpC8YozUTEWwx3v4JOtiARpPVE2OSA6aNDxse73whzNNGOKB
         hIC6AfNOiC36QNkM3RQ5/iLHWxq67X23VJ0hekyPHxifNUfQ2wl6+8Zq7eMj9COYPbOl
         a3S9lcFrvzDo39sQTF4BroemCu/XjdWHn3DmeMCaI5j2/S6nLCUK5CnFea1M36Rn1YtT
         Rvhg==
X-Gm-Message-State: APjAAAUTfAKKY5dxvu910U9zVlh0cFZ2/71IqZIgz7X7BcebVmixTSi1
	zHZM0LfDdrBecQBHUrbV0YI=
X-Google-Smtp-Source: APXvYqxkQ6iwNmzj589Y++YmTlbVwmqAJJ0YYZ2s3QbsievsHftpIm3opL7ETy5fUwYFEcuR3PeKlg==
X-Received: by 2002:a2e:810d:: with SMTP id d13mr23506829ljg.113.1582326635189;
        Fri, 21 Feb 2020 15:10:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:3f0b:: with SMTP id m11ls440608lfa.0.gmail; Fri, 21 Feb
 2020 15:10:34 -0800 (PST)
X-Received: by 2002:a19:691e:: with SMTP id e30mr2335274lfc.104.1582326634403;
        Fri, 21 Feb 2020 15:10:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582326634; cv=none;
        d=google.com; s=arc-20160816;
        b=dciTptDKJNRw4JLmYht0/MCD2ebc972l0+37sCy9N3jAOta2cl3Pygs/5pxzlSxatt
         eRonkFNgW7zQYyOs1qK06V+QrSqCUiDX2p03w4cCbtYLor+8fxKfjqLu/2UoA6esX0GS
         82n6mZsSI123ujC+QUfL5RfgvaNqJT38QfNK5ZlU1cWoUwcQkCks/875OxO4Gt2Xi3PA
         cE8FfcsFB3/NGzjmYSi02Uw9VOenJjhLzTHDSKrLX64BUkchQYjl+fT0UJpkzZox5VLt
         MoULaaerVY62K2ffo5xr+xuANBewuB1heTRWaovuNfPENSrhRCylXOKoOuPmOtRag2se
         yLrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=Jn6Uxzj8UrrWQ3MFOKJO4gCOCt/S0XlKGs1U1eQelhE=;
        b=fV8iW/5QBWXzy8qio5d+zZTtOFlr7yOAKfQCDi7SyYMlJ6hrbjp01SL+Vsk1CZ3gsy
         mECQiduVhV7fgD1NUdsNoAZgujMzDDePzg8IKwd4aYIXmtQ2hatZaWRvMab16CuQVIXJ
         EtuE6eadhQOohCjJDHUNMUpnXKi7g44ColcGhGeW/6RcJmqLBup0XyMrJ+vs+IAtK4ls
         1E9j6rv5G2aO/gZG8SKC5mBsoc4r3DEIv6XInSdnN7ja0diaRYa0ywAxcPCCPsHMuxBv
         pH0rYDyH9NkRfaQ7bJC91/ZifGG/TJBHVBE6JoxxeDsP1CSH3CvqfSocuIWBDR9N1kqd
         7AOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nUZ4jtYu;
       spf=pass (google.com: domain of 3awnqxgukcwomtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3aWNQXgUKCWoMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id b10si268508lfi.1.2020.02.21.15.10.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Feb 2020 15:10:34 -0800 (PST)
Received-SPF: pass (google.com: domain of 3awnqxgukcwomtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id d7so1692737wrx.9
        for <kasan-dev@googlegroups.com>; Fri, 21 Feb 2020 15:10:34 -0800 (PST)
X-Received: by 2002:a5d:614a:: with SMTP id y10mr53068523wrt.73.1582326633667;
 Fri, 21 Feb 2020 15:10:33 -0800 (PST)
Date: Sat, 22 Feb 2020 00:10:27 +0100
Message-Id: <20200221231027.230147-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.265.gbab2e86ba0-goog
Subject: [PATCH v3] kcsan: Add option for verbose reporting
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nUZ4jtYu;       spf=pass
 (google.com: domain of 3awnqxgukcwomtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3aWNQXgUKCWoMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
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
v3:
* Typos
v2:
* Rework obtaining 'current' for the "other thread" -- it now passes
  'current' and ensures that we stall until the report was printed, so
  that the lockdep information contained in 'current' is accurate. This
  was non-trivial but testing so far leads me to conclude this now
  reliably prints the held locks for the "other thread" (please test
  more!).
---
 kernel/kcsan/core.c   |   4 +-
 kernel/kcsan/kcsan.h  |   3 ++
 kernel/kcsan/report.c | 103 +++++++++++++++++++++++++++++++++++++++++-
 lib/Kconfig.kcsan     |  13 ++++++
 4 files changed, 120 insertions(+), 3 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index e7387fec66795..065615df88eaa 100644
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
index 892de5120c1b6..e282f8b5749e9 100644
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
index 11c791b886f3c..7bdb515e3662f 100644
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
@@ -357,6 +394,67 @@ static void release_report(unsigned long *flags, enum kcsan_report_type type)
 	spin_unlock_irqrestore(&report_lock, *flags);
 }
 
+/*
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
 /*
  * Depending on the report type either sets other_info and returns false, or
  * acquires the matching other_info and returns true. If other_info is not
@@ -388,6 +486,9 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
 		other_info.cpu_id		= cpu_id;
 		other_info.num_stack_entries	= stack_trace_save(other_info.stack_entries, NUM_STACK_ENTRIES, 1);
 
+		if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
+			set_other_info_task_blocking(flags, ptr);
+
 		spin_unlock_irqrestore(&report_lock, *flags);
 
 		/*
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 081ed2e1bf7b1..0f1447ff8f558 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200221231027.230147-1-elver%40google.com.
