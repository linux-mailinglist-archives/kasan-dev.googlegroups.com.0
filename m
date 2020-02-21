Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSWAYHZAKGQEFKBY5KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id E0DEC168A20
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2020 23:57:14 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id f25sf2579240eds.22
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2020 14:57:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582325834; cv=pass;
        d=google.com; s=arc-20160816;
        b=nXvHAkqLSBJwTw3V0WZQO1yPRuy63fXWXrUbS91HThnY99LhnNy5VfZcX0qFOx68Xx
         Qsmt+2wV8DRiPAVsnlQnPieR/jArO9/9z+zrZN8AwWoEIwdhgGP7t7sL27VKRXyCjqw8
         nrZDFhQnruWOXJETWrljGGZWbuOmPXfUUyJETP8/XIGIUTQXDoDyrFQK184P+m4XXmMs
         OMB7ZpG/HHwq3CFt8HfUCVOZn8opShJFLs5aq+yA63NsoczOEOx/okNj1r1+l78Jw/mg
         qvUbRSdmqwBqIiRSBctwI2UhKVfyI3zMVses4eymYEIwjQi+GF+d/OxGrdWoXOiMCiCp
         SV7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=YwkMtnPzM+gDebksCIFcSwFDkuera3nPh69EeD8eBdc=;
        b=NJ+iReuwkHy5x1RmWu9fcpsO/KR1uLxw0Gba2Vipzu/YLp5858iyFNQL/vaS70uDWh
         eVvke6b4XNLqJilDU1s+nlgo7WfsLMFMSkD644anQDBP7pERLOI//p5TmmIrdJBowgCk
         fiHrRhoVM8BIuEllArcxl/acIffRrG5MzzKYo6v5uZ8lEz3NopjhLT4SsXoomfnNbrGr
         1OovNwxcdmVydzZtCfUxYxK+t0lh63f3uS78tXx1kCRFBCkrd3+y9s0muFJAkPGG873b
         u6On38MeWrEQHjOJzlXOf/tbU1DnA/KMbDhL83MuUFC/ndPjitHIlvCTrbwBz21X41v6
         w14w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VvT2SFdt;
       spf=pass (google.com: domain of 3swbqxgukcuqkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3SWBQXgUKCUQkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=YwkMtnPzM+gDebksCIFcSwFDkuera3nPh69EeD8eBdc=;
        b=Njcun8658zJJVD6is4buxbeHw3YvUOilpLUnZ+rGJZUPgAsPM5KFlWKQdZuQZbslWV
         jt8rnLQywnuzYe8biwPCTffvDdt1s5lz+cJDZzuBkIxdKBpmNYuVTLtrE5rSV8s5OB6n
         2gPiXPZCYj1sbJNlory+AJ02MtdCNafiV18Qb93QRMbfy1fOG1ftNW2XGdMUmO6BSPgs
         m77G0fzuTUKnk50jvZwS8d72IXR8uAAmL/0TDKNL91jFmYxKCicAOZV2ftvwdtd1H1hw
         xhYvcOuHP9iRD/15j3jdLUljw2m14HuJQ6uZCKAhTBjo4RwauuRWgxgERNklFnx93LF+
         ehiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YwkMtnPzM+gDebksCIFcSwFDkuera3nPh69EeD8eBdc=;
        b=Oeb5Fi+7lz+T4BLoQcaFC2YJ+2Btq9F8VOK5XmrrtyWeiBgkgYSkKSRTCoikSA0024
         Zf1vy8+7UsEmPesdRInB5e94qgZhw4ENIejlybpkHzL61CeylcpWARaPrMq0j9Rw9M9V
         nxFZJJ1KXjXWdpywxtY6x2hpgQPt70PHoL8KFDx1RzjtBZu/IN8UqUv1p9Vd0SgJ/+oZ
         w9GQp9vgQnOlH5YH1/awv2dEp+Wg7zYXs9Yv6G/5bVhU0gbKXvK/ZCYtYZyjxNgXvI1T
         cwsZJKqPKcj2DnhxfGcDXprWPy0O+ItdoRhCzYnlcZygXxfFGsWMxHsYRcQhxampBUV/
         g50Q==
X-Gm-Message-State: APjAAAWCCUllmo7OIoS55CINXqvqiOnPQIPiQ/p4hkOikWL/BGVHDyeS
	vnH8kTEGWAnjDKInaLTUe9A=
X-Google-Smtp-Source: APXvYqypBwajfOM0TCiI7Q6GxbCe6iEOgvsapEJFdbN+K1JlDHFsWBbPwFC5UFcb82ctzWw4qqB7WA==
X-Received: by 2002:aa7:c751:: with SMTP id c17mr36466368eds.293.1582325834584;
        Fri, 21 Feb 2020 14:57:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:bfe7:: with SMTP id vr7ls1521193ejb.1.gmail; Fri, 21
 Feb 2020 14:57:13 -0800 (PST)
X-Received: by 2002:a17:906:1181:: with SMTP id n1mr37018873eja.218.1582325833914;
        Fri, 21 Feb 2020 14:57:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582325833; cv=none;
        d=google.com; s=arc-20160816;
        b=zJQygfuyps+pg/3BXdDWeaECWSPZK2mY5TnY826lP3o2OfGzRvy6+6OsSH4y9UYDUU
         tSYwMpetf8boPsxcDNwq+1mHs0ghaaTECsVYCZL+r244h8t9sBXdZPII4osE0FqAN7ir
         DOUtf+WyVjRX7dbJwV5ijMpo222/bLC/kygh/kBNPkTJMBTK49LznM5F0pobL5nPNF+f
         eMcly50G/YW3eKw7YY2xY/mb0wVWNBRK+rNdmHB1c+XPCq549RnmNATe41bmFhdODUTF
         Xv2zRRO/EIzl1YIAXSsx8mlj9h++BZsaPYK8fyQ5l/PD+gS7bVHBvQR8QUtZBX6qhLCz
         d9Gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=sP6Z7L3V8E82h2fwZqPlTVXoifzxjcYRadJI4ND9o7w=;
        b=CnaZxGmvqlnIsLO1Qao4U23hx+Xmqkw35onNcrQWqfoaYC7tGMz0uDXV7khpXOCQtX
         dDCu2nlryfxr9bXEZKsUMKSE1HfqpMcYJbLTi68bCfo/Pe5k3i8KPFupLFZE//niNdNT
         TQavVpiO0ypJ7X6OjEJYtMUjCxDEw9cSbgoA3nkBaT0zkhHoU1RZwU1OX/us9dxP7jY3
         VZGKVDEXeOZE6xAnxi2zpzHOXc5gRVsKzL9+APPiHOVGFAdvmtjez2C197KYWfc2Mp7b
         F7qbnkZFb+jC3zfTeeLa+irTUDChPjOcWa6DyuafUg6GBVvufbp3BqAsT1eSR1yuAhZ8
         Dyug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VvT2SFdt;
       spf=pass (google.com: domain of 3swbqxgukcuqkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3SWBQXgUKCUQkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id d29si203374edj.0.2020.02.21.14.57.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Feb 2020 14:57:13 -0800 (PST)
Received-SPF: pass (google.com: domain of 3swbqxgukcuqkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id 90so1676977wrq.6
        for <kasan-dev@googlegroups.com>; Fri, 21 Feb 2020 14:57:13 -0800 (PST)
X-Received: by 2002:adf:f850:: with SMTP id d16mr49653895wrq.161.1582325833291;
 Fri, 21 Feb 2020 14:57:13 -0800 (PST)
Date: Fri, 21 Feb 2020 23:56:35 +0100
Message-Id: <20200221225635.218857-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.265.gbab2e86ba0-goog
Subject: [PATCH v2] kcsan: Add option for verbose reporting
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VvT2SFdt;       spf=pass
 (google.com: domain of 3swbqxgukcuqkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3SWBQXgUKCUQkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
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
index 11c791b886f3c..ee8f33d7405fb 100644
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
+ * Postcontiion: report_lock is held.
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200221225635.218857-1-elver%40google.com.
