Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLG3TP2QKGQE5PEMFNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 692E01BA685
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Apr 2020 16:35:26 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id z13sf15900362iog.16
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Apr 2020 07:35:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587998125; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ijg6TzfBd6YAzXUODs1lc80FA6Yq6rwp3Og/9kbCJhuGRJKJyqZWGUVNoxL8iVI0aS
         piyU7IkDYvLXX1Na9wZNhO7m/N04nVi5/w3XN+pSMo4taSUevYxUtzIQ6mBDZ3YHtuPm
         Mu5dkSTSptdsld0tiXwq6qMBeU7D1vKndcLvIoxCkYf7mKmfusj0WNy7brjnbkjPPDO5
         v+hVTA6MnqTlwacty2H2tO/ChhyIzi/+1L9t0fmUoB6ZzrWRrf9x+MdZD9uV5xsdwoYu
         Kqiivt4NphKA3FoZCw0/r5m2Cp75+7HMTUu8MIX8phODQJgL4Xiy3F3JTq35WeXGioxl
         JidA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=cC5nip3oWLEL7hZvv1GsYjiUbstPWBhg0ZL7JhSkRY8=;
        b=mk92lNb/8nU8ry3wzeZJ9/jRLaES1Bg7QRvRfpT7YzebAbmwHqc0UYjhIJlbDI+leR
         DGt2PVJ3DdLaE2LwcuwzKtXSK5JbX2ikR6vI1xtBxZOBgmCT+1XMUO61jNHcZLqJiA+t
         x3otMHbyt1byyL3EKn4d+JxfQd3Inj8Tw0KzBeYmc4D1H6ynx92NrI1JTvPhUsS/FcKW
         PTZrqeLL5A+xp4oHyEAGuCXsBcmyG0a0cRbVp1nQNtcjzAu6Zl3eEVh7kyOHuyljjvdu
         B36eET3rnDLUtISaGDysu2puRPb4WsAMYvivlq9S+mR5yJbLf+Ysrx60N3BQehK0sZPa
         t2Kw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ucPBOu2A;
       spf=pass (google.com: domain of 3q-2mxgukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3q-2mXgUKCR48FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=cC5nip3oWLEL7hZvv1GsYjiUbstPWBhg0ZL7JhSkRY8=;
        b=Y5myYwFUXfLvAHXpGv2o5W9RSk/tdvQ/LaNp8pDFQuKCvckoVzCZxp1X7foiPwe0UM
         9YdsdXWSE6rrTCiMpKDcyhRgUi7TfgLRtddeiCpA65TXCT0jFfZ6o6NnWNv1EooHXgtF
         x6XTjnexcWBF9Bj/nQNQOlwG2Vvp2CDdNBaE0UUoqvV15lH0eZmzQN5Gu3aHQua7Wm2D
         tNYoXYvc8jei3YsWF6re2hNaNiAdw5eZitp9DJYpyI6PkoqROxgdKYgze/QumXTOjf7B
         dvcoedsZ41KveNW9LGzAh2g8/s3FQoa0mH8oA8p9dwTA4Xs/0obn8RhzQ4PAL1E2hj3P
         zSMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cC5nip3oWLEL7hZvv1GsYjiUbstPWBhg0ZL7JhSkRY8=;
        b=IUauDrIv240HrkdCAtrRRtXcl1pYu332gazH81/er1TT0Uw+xxrunVlerQuZY0SmNo
         M6qPY42dma8uCiQhH9RkInUuSo00ps0jZGrgMmE7zD1cliUCj+W2tJX7uzyEte7hH8XA
         k5npOfL5pY1NCxbprnZSkxk6xuKUTgKLNZ7RcS/CHv9wAgxrTID1YieQNx/yzAqspsjO
         XyVL0wGwkUFmOIFkGJBPIANjshv/X0zrvHQt0tNaNM4rh9aROm1Hd3dCZqnq9Ur73K27
         D8Oy+dO64NzWiNWeSDbjN3C0ZU3XJtUeIN0GeC7HdvtvXduAT+9EVcWgqHZVAdhpSm8w
         gfaA==
X-Gm-Message-State: AGi0Pub3JD6u41GXQ1ludkahc33ueASt4q9oovPWohxVYXFR6JDX5tJw
	BOqQFoY6RyDkgBw4ouYJanE=
X-Google-Smtp-Source: APiQypKv96Kz21++eG/Lo7pmHjDyDMIsdyDdK1K4UuCpfir1q1+laWHRr2UC45M8/iMWypE4vmbqdQ==
X-Received: by 2002:a92:bb01:: with SMTP id w1mr22047954ili.233.1587998124903;
        Mon, 27 Apr 2020 07:35:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:d516:: with SMTP id e22ls1049053iom.3.gmail; Mon, 27 Apr
 2020 07:35:24 -0700 (PDT)
X-Received: by 2002:a5d:8b89:: with SMTP id p9mr20840758iol.107.1587998123940;
        Mon, 27 Apr 2020 07:35:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587998123; cv=none;
        d=google.com; s=arc-20160816;
        b=Ye/wxYqu10krsauKSkUfcU2IS5D9eNYHeHTJSwiAgqdtJjvqgevea69kRPzLfgr01y
         ME8dhqrEMNlhhn3QrvD0TH9cpyOc326nlpxWZ+hqzWMrCuYM2pS8tcVl41T+fmLn2L2f
         xiRseQBMKj5vZzAcaX/unZ9XfzdJg0qb5pjq1OyqUN69BfCybJr9f825gpZCxSHkQpmR
         xgJSti9dylABYDfhCFTOlmeyfJyv3EzSTnOBjJoBsiUriX1WZpL8wgcxeIvMLaKoR1U4
         ozRkYFVgc4AEhJnC443EbqsMwfDZKcmXyiccjqlO7eZg0usTlDSSRrzydHN8qbpZ1E1c
         bROg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=Iuqs6FYQTgn2aRBU4Q/NgOjJDVFpS/by4jmjezytMJU=;
        b=nyH60oTdOmk+d1d4USbAFjSZSKYiaS59OT71qbcUWEkUA2V+UC0CvdsZby0blOWwnt
         NaijZ881IDz2EVk/PvYTW6NM+Z4BvnpfyAN/iCpaFohTlp5icP9LkqA9n6megsmgMuEC
         Orm8yl9BtXOA7Ze4eqsGwnMp9/Pz2+vn2D3U+S/UQG4q6M4mc5c5rQtbGLJfZf+QmJqK
         hsvPZy6eRMH0WDjHaPecMYvfj5GUAa0TZ3G0WXC6DcjpzpHwy+3gszVY1R7Bl2N9RZQe
         Yn0u2sikbo6TXE6419kvD/bmWF4kK1QAA4J8J9WLqg/w+34qAEoClX8JhSIQx+COcrcv
         Stpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ucPBOu2A;
       spf=pass (google.com: domain of 3q-2mxgukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3q-2mXgUKCR48FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id o6si21090ilo.4.2020.04.27.07.35.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Apr 2020 07:35:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3q-2mxgukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id o18so18922427qvu.8
        for <kasan-dev@googlegroups.com>; Mon, 27 Apr 2020 07:35:23 -0700 (PDT)
X-Received: by 2002:a05:6214:9b3:: with SMTP id du19mr22220068qvb.167.1587998123294;
 Mon, 27 Apr 2020 07:35:23 -0700 (PDT)
Date: Mon, 27 Apr 2020 16:35:07 +0200
Message-Id: <20200427143507.49654-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.26.2.303.gf8c07b1a785-goog
Subject: [PATCH] kcsan: Add test suite
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ucPBOu2A;       spf=pass
 (google.com: domain of 3q-2mxgukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3q-2mXgUKCR48FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
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

This adds KCSAN test focusing on behaviour of the integrated runtime.
Tests various race scenarios, and verifies the reports generated to
console. Makes use of KUnit for test organization, and the Torture
framework for test thread control.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/Makefile     |    3 +
 kernel/kcsan/kcsan-test.c | 1067 +++++++++++++++++++++++++++++++++++++
 lib/Kconfig.kcsan         |   23 +-
 3 files changed, 1092 insertions(+), 1 deletion(-)
 create mode 100644 kernel/kcsan/kcsan-test.c

diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
index d4999b38d1be..14533cf24bc3 100644
--- a/kernel/kcsan/Makefile
+++ b/kernel/kcsan/Makefile
@@ -12,3 +12,6 @@ CFLAGS_core.o := $(call cc-option,-fno-conserve-stack,) \
 
 obj-y := core.o debugfs.o report.o
 obj-$(CONFIG_KCSAN_SELFTEST) += test.o
+
+CFLAGS_kcsan-test.o := $(CFLAGS_KCSAN) -g -fno-omit-frame-pointer
+obj-$(CONFIG_KCSAN_TEST) += kcsan-test.o
diff --git a/kernel/kcsan/kcsan-test.c b/kernel/kcsan/kcsan-test.c
new file mode 100644
index 000000000000..04326cd5a4b2
--- /dev/null
+++ b/kernel/kcsan/kcsan-test.c
@@ -0,0 +1,1067 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * KCSAN test with various race scenarious to test runtime behaviour. Since the
+ * interface with which KCSAN's reports are obtained is via the console, this is
+ * the output we should verify. For each test case checks the presence (or
+ * absence) of generated reports. Relies on 'console' tracepoint to capture
+ * reports as they appear in the kernel log.
+ *
+ * Makes use of KUnit for test organization, and the Torture framework for test
+ * thread control.
+ *
+ * Copyright (C) 2020, Google LLC.
+ * Author: Marco Elver <elver@google.com>
+ */
+
+#include <kunit/test.h>
+#include <linux/jiffies.h>
+#include <linux/kcsan-checks.h>
+#include <linux/kernel.h>
+#include <linux/sched.h>
+#include <linux/seqlock.h>
+#include <linux/spinlock.h>
+#include <linux/string.h>
+#include <linux/timer.h>
+#include <linux/torture.h>
+#include <linux/tracepoint.h>
+#include <linux/types.h>
+#include <trace/events/printk.h>
+
+/* Points to current test-case memory access "kernels". */
+static void (*access_kernels[2])(void);
+
+static struct task_struct **threads; /* Lists of threads. */
+static unsigned long end_time;       /* End time of test. */
+
+/* Report as observed from console. */
+static struct {
+	spinlock_t lock;
+	int nlines;
+	char lines[3][512];
+} observed = {
+	.lock = __SPIN_LOCK_UNLOCKED(observed.lock),
+};
+
+/* Setup test checking loop. */
+static __no_kcsan_or_inline void
+begin_test_checks(void (*func1)(void), void (*func2)(void))
+{
+	kcsan_disable_current();
+
+	/*
+	 * Require at least as long as KCSAN_REPORT_ONCE_IN_MS, to ensure at
+	 * least one race is reported.
+	 */
+	end_time = jiffies + msecs_to_jiffies(CONFIG_KCSAN_REPORT_ONCE_IN_MS + 300);
+
+	/* Signal start; release potential initialization of shared data. */
+	smp_store_release(&access_kernels[0], func1);
+	smp_store_release(&access_kernels[1], func2);
+}
+
+/* End test checking loop. */
+static __no_kcsan_or_inline bool
+end_test_checks(bool stop)
+{
+	if (!stop && time_before(jiffies, end_time)) {
+		/* Continue checking */
+		return false;
+	}
+
+	kcsan_enable_current();
+	return true;
+}
+
+/*
+ * Probe for console output: checks if a race was reported, and obtains observed
+ * lines of interest.
+ */
+__no_kcsan
+static void probe_console(void *ignore, const char *buf, size_t len)
+{
+	unsigned long flags;
+	int nlines;
+
+	/*
+	 * Note that KCSAN reports under a global lock, so we do not risk the
+	 * possibility of having multiple reports interleaved. If that were the
+	 * case, we'd expect tests to fail.
+	 */
+
+	spin_lock_irqsave(&observed.lock, flags);
+	nlines = observed.nlines;
+
+	if (strnstr(buf, "BUG: KCSAN: ", len) && strnstr(buf, "test_", len)) {
+		/*
+		 * KCSAN report and related to the test.
+		 *
+		 * The provided @buf is not NUL-terminated; copy no more than
+		 * @len bytes and let strscpy() add the missing NUL-terminator.
+		 */
+		strscpy(observed.lines[0], buf, min(len + 1, sizeof(observed.lines[0])));
+		nlines = 1;
+	} else if ((nlines == 1 || nlines == 2) && strnstr(buf, "bytes by", len)) {
+		strscpy(observed.lines[nlines++], buf, min(len + 1, sizeof(observed.lines[0])));
+
+		if (strnstr(buf, "race at unknown origin", len)) {
+			if (WARN_ON(nlines != 2))
+				goto out;
+
+			/* No second line of interest. */
+			strcpy(observed.lines[nlines++], "<none>");
+		}
+	}
+
+out:
+	WRITE_ONCE(observed.nlines, nlines); /* Publish new nlines. */
+	spin_unlock_irqrestore(&observed.lock, flags);
+}
+
+/* Check if a report related to the test exists. */
+__no_kcsan
+static bool report_available(void)
+{
+	return READ_ONCE(observed.nlines) == ARRAY_SIZE(observed.lines);
+}
+
+/* Report information we expect in a report. */
+struct expect_report {
+	/* Access information of both accesses. */
+	struct {
+		void *fn;    /* Function pointer to expected function of top frame. */
+		void *addr;  /* Address of access; unchecked if NULL. */
+		size_t size; /* Size of access; unchecked if @addr is NULL. */
+		int type;    /* Access type, see KCSAN_ACCESS definitions. */
+	} access[2];
+};
+
+/* Check observed report matches information in @r. */
+__no_kcsan
+static bool report_matches(const struct expect_report *r)
+{
+	const bool is_assert = (r->access[0].type | r->access[1].type) & KCSAN_ACCESS_ASSERT;
+	bool ret = false;
+	unsigned long flags;
+	typeof(observed.lines) expect;
+	const char *end;
+	char *cur;
+	int i;
+
+	/* Doubled-checked locking. */
+	if (!report_available())
+		return false;
+
+	/* Generate expected report contents. */
+
+	/* Title */
+	cur = expect[0];
+	end = &expect[0][sizeof(expect[0]) - 1];
+	cur += scnprintf(cur, end - cur, "BUG: KCSAN: %s in ",
+			 is_assert ? "assert: race" : "data-race");
+	if (r->access[1].fn) {
+		char tmp[2][64];
+		int cmp;
+
+		/* Expect lexographically sorted function names in title. */
+		scnprintf(tmp[0], sizeof(tmp[0]), "%pS", r->access[0].fn);
+		scnprintf(tmp[1], sizeof(tmp[1]), "%pS", r->access[1].fn);
+		cmp = strcmp(tmp[0], tmp[1]);
+		cur += scnprintf(cur, end - cur, "%ps / %ps",
+				 cmp < 0 ? r->access[0].fn : r->access[1].fn,
+				 cmp < 0 ? r->access[1].fn : r->access[0].fn);
+	} else {
+		scnprintf(cur, end - cur, "%pS", r->access[0].fn);
+		/* The exact offset won't match, remove it. */
+		cur = strchr(expect[0], '+');
+		if (cur)
+			*cur = '\0';
+	}
+
+	/* Access 1 */
+	cur = expect[1];
+	end = &expect[1][sizeof(expect[1]) - 1];
+	if (!r->access[1].fn)
+		cur += scnprintf(cur, end - cur, "race at unknown origin, with ");
+
+	/* Access 1 & 2 */
+	for (i = 0; i < 2; ++i) {
+		const char *const access_type =
+			(r->access[i].type & KCSAN_ACCESS_ASSERT) ?
+				((r->access[i].type & KCSAN_ACCESS_WRITE) ?
+					 "assert no accesses" :
+					 "assert no writes") :
+				((r->access[i].type & KCSAN_ACCESS_WRITE) ?
+					 "write" :
+					 "read");
+		const char *const access_type_aux =
+			(r->access[i].type & KCSAN_ACCESS_ATOMIC) ?
+				" (marked)" :
+				((r->access[i].type & KCSAN_ACCESS_SCOPED) ?
+					 " (scoped)" :
+					 "");
+
+		if (i == 1) {
+			/* Access 2 */
+			cur = expect[2];
+			end = &expect[2][sizeof(expect[2]) - 1];
+
+			if (!r->access[1].fn) {
+				/* Dummy string if no second access is available. */
+				strcpy(cur, "<none>");
+				break;
+			}
+		}
+
+		cur += scnprintf(cur, end - cur, "%s%s to ", access_type,
+				 access_type_aux);
+
+		if (r->access[i].addr) /* Address is optional. */
+			cur += scnprintf(cur, end - cur, "0x%px of %zu bytes",
+					 r->access[i].addr, r->access[i].size);
+	}
+
+	spin_lock_irqsave(&observed.lock, flags);
+	if (!report_available())
+		goto out; /* A new report is being captured. */
+
+	/* Finally match expected output to what we actually observed. */
+	ret = strstr(observed.lines[0], expect[0]) &&
+	      /* Access info may appear in any order. */
+	      ((strstr(observed.lines[1], expect[1]) &&
+		strstr(observed.lines[2], expect[2])) ||
+	       (strstr(observed.lines[1], expect[2]) &&
+		strstr(observed.lines[2], expect[1])));
+out:
+	spin_unlock_irqrestore(&observed.lock, flags);
+	return ret;
+}
+
+/* ===== Test kernels ===== */
+
+static long test_sink;
+static long test_var;
+/* @test_array should be large enough to fall into multiple watchpoint slots. */
+static long test_array[3 * PAGE_SIZE / sizeof(long)];
+static struct {
+	long val[8];
+} test_struct;
+static DEFINE_SEQLOCK(test_seqlock);
+
+/*
+ * Helper to avoid compiler optimizing out reads, and to generate source values
+ * for writes.
+ */
+__no_kcsan
+static noinline void sink_value(long v) { WRITE_ONCE(test_sink, v); }
+
+static noinline void test_kernel_read(void) { sink_value(test_var); }
+
+static noinline void test_kernel_write(void)
+{
+	test_var = READ_ONCE_NOCHECK(test_sink) + 1;
+}
+
+static noinline void test_kernel_write_nochange(void) { test_var = 42; }
+
+/* Suffixed by value-change exception filter. */
+static noinline void test_kernel_write_nochange_rcu(void) { test_var = 42; }
+
+static noinline void test_kernel_read_atomic(void)
+{
+	sink_value(READ_ONCE(test_var));
+}
+
+static noinline void test_kernel_write_atomic(void)
+{
+	WRITE_ONCE(test_var, READ_ONCE_NOCHECK(test_sink) + 1);
+}
+
+__no_kcsan
+static noinline void test_kernel_write_uninstrumented(void) { test_var++; }
+
+static noinline void test_kernel_data_race(void) { data_race(test_var++); }
+
+static noinline void test_kernel_assert_writer(void)
+{
+	ASSERT_EXCLUSIVE_WRITER(test_var);
+}
+
+static noinline void test_kernel_assert_access(void)
+{
+	ASSERT_EXCLUSIVE_ACCESS(test_var);
+}
+
+#define TEST_CHANGE_BITS 0xff00ff00
+
+static noinline void test_kernel_change_bits(void)
+{
+	if (IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {
+		/*
+		 * Avoid race of unknown origin for this test, just pretend they
+		 * are atomic.
+		 */
+		kcsan_nestable_atomic_begin();
+		test_var ^= TEST_CHANGE_BITS;
+		kcsan_nestable_atomic_end();
+	} else
+		WRITE_ONCE(test_var, READ_ONCE(test_var) ^ TEST_CHANGE_BITS);
+}
+
+static noinline void test_kernel_assert_bits_change(void)
+{
+	ASSERT_EXCLUSIVE_BITS(test_var, TEST_CHANGE_BITS);
+}
+
+static noinline void test_kernel_assert_bits_nochange(void)
+{
+	ASSERT_EXCLUSIVE_BITS(test_var, ~TEST_CHANGE_BITS);
+}
+
+/* To check that scoped assertions do trigger anywhere in scope. */
+static noinline void test_enter_scope(void)
+{
+	int x = 0;
+
+	/* Unrelated accesses to scoped assert. */
+	READ_ONCE(test_sink);
+	kcsan_check_read(&x, sizeof(x));
+}
+
+static noinline void test_kernel_assert_writer_scoped(void)
+{
+	ASSERT_EXCLUSIVE_WRITER_SCOPED(test_var);
+	test_enter_scope();
+}
+
+static noinline void test_kernel_assert_access_scoped(void)
+{
+	ASSERT_EXCLUSIVE_ACCESS_SCOPED(test_var);
+	test_enter_scope();
+}
+
+static noinline void test_kernel_rmw_array(void)
+{
+	int i;
+
+	for (i = 0; i < ARRAY_SIZE(test_array); ++i)
+		test_array[i]++;
+}
+
+static noinline void test_kernel_write_struct(void)
+{
+	kcsan_check_write(&test_struct, sizeof(test_struct));
+	kcsan_disable_current();
+	test_struct.val[3]++; /* induce value change */
+	kcsan_enable_current();
+}
+
+static noinline void test_kernel_write_struct_part(void)
+{
+	test_struct.val[3] = 42;
+}
+
+static noinline void test_kernel_read_struct_zero_size(void)
+{
+	kcsan_check_read(&test_struct.val[3], 0);
+}
+
+static noinline void test_kernel_seqlock_reader(void)
+{
+	unsigned int seq;
+
+	do {
+		seq = read_seqbegin(&test_seqlock);
+		sink_value(test_var);
+	} while (read_seqretry(&test_seqlock, seq));
+}
+
+static noinline void test_kernel_seqlock_writer(void)
+{
+	unsigned long flags;
+
+	write_seqlock_irqsave(&test_seqlock, flags);
+	test_var++;
+	write_sequnlock_irqrestore(&test_seqlock, flags);
+}
+
+/* ===== Test cases ===== */
+
+/* Simple test with normal data race. */
+__no_kcsan
+static void test_basic(struct kunit *test)
+{
+	const struct expect_report expect = {
+		.access = {
+			{ test_kernel_write, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
+			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
+		},
+	};
+	static const struct expect_report never = {
+		.access = {
+			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
+			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
+		},
+	};
+	bool match_expect = false;
+	bool match_never = false;
+
+	begin_test_checks(test_kernel_write, test_kernel_read);
+	do {
+		match_expect |= report_matches(&expect);
+		match_never = report_matches(&never);
+	} while (!end_test_checks(match_never));
+	KUNIT_EXPECT_TRUE(test, match_expect);
+	KUNIT_EXPECT_FALSE(test, match_never);
+}
+
+/*
+ * Stress KCSAN with lots of concurrent races on different addresses until
+ * timeout.
+ */
+__no_kcsan
+static void test_concurrent_races(struct kunit *test)
+{
+	const struct expect_report expect = {
+		.access = {
+			/* NULL will match any address. */
+			{ test_kernel_rmw_array, NULL, 0, KCSAN_ACCESS_WRITE },
+			{ test_kernel_rmw_array, NULL, 0, 0 },
+		},
+	};
+	static const struct expect_report never = {
+		.access = {
+			{ test_kernel_rmw_array, NULL, 0, 0 },
+			{ test_kernel_rmw_array, NULL, 0, 0 },
+		},
+	};
+	bool match_expect = false;
+	bool match_never = false;
+
+	begin_test_checks(test_kernel_rmw_array, test_kernel_rmw_array);
+	do {
+		match_expect |= report_matches(&expect);
+		match_never |= report_matches(&never);
+	} while (!end_test_checks(false));
+	KUNIT_EXPECT_TRUE(test, match_expect); /* Sanity check matches exist. */
+	KUNIT_EXPECT_FALSE(test, match_never);
+}
+
+/* Test the KCSAN_REPORT_VALUE_CHANGE_ONLY option. */
+__no_kcsan
+static void test_novalue_change(struct kunit *test)
+{
+	const struct expect_report expect = {
+		.access = {
+			{ test_kernel_write_nochange, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
+			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
+		},
+	};
+	bool match_expect = false;
+
+	begin_test_checks(test_kernel_write_nochange, test_kernel_read);
+	do {
+		match_expect = report_matches(&expect);
+	} while (!end_test_checks(match_expect));
+	if (IS_ENABLED(CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY))
+		KUNIT_EXPECT_FALSE(test, match_expect);
+	else
+		KUNIT_EXPECT_TRUE(test, match_expect);
+}
+
+/*
+ * Test that the rules where the KCSAN_REPORT_VALUE_CHANGE_ONLY option should
+ * never apply work.
+ */
+__no_kcsan
+static void test_novalue_change_exception(struct kunit *test)
+{
+	const struct expect_report expect = {
+		.access = {
+			{ test_kernel_write_nochange_rcu, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
+			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
+		},
+	};
+	bool match_expect = false;
+
+	begin_test_checks(test_kernel_write_nochange_rcu, test_kernel_read);
+	do {
+		match_expect = report_matches(&expect);
+	} while (!end_test_checks(match_expect));
+	KUNIT_EXPECT_TRUE(test, match_expect);
+}
+
+/* Test that data races of unknown origin are reported. */
+__no_kcsan
+static void test_unknown_origin(struct kunit *test)
+{
+	const struct expect_report expect = {
+		.access = {
+			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
+			{ NULL },
+		},
+	};
+	bool match_expect = false;
+
+	begin_test_checks(test_kernel_write_uninstrumented, test_kernel_read);
+	do {
+		match_expect = report_matches(&expect);
+	} while (!end_test_checks(match_expect));
+	if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN))
+		KUNIT_EXPECT_TRUE(test, match_expect);
+	else
+		KUNIT_EXPECT_FALSE(test, match_expect);
+}
+
+/* Test KCSAN_ASSUME_PLAIN_WRITES_ATOMIC if it is selected. */
+__no_kcsan
+static void test_write_write_assume_atomic(struct kunit *test)
+{
+	const struct expect_report expect = {
+		.access = {
+			{ test_kernel_write, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
+			{ test_kernel_write, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
+		},
+	};
+	bool match_expect = false;
+
+	begin_test_checks(test_kernel_write, test_kernel_write);
+	do {
+		sink_value(READ_ONCE(test_var)); /* induce value-change */
+		match_expect = report_matches(&expect);
+	} while (!end_test_checks(match_expect));
+	if (IS_ENABLED(CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC))
+		KUNIT_EXPECT_FALSE(test, match_expect);
+	else
+		KUNIT_EXPECT_TRUE(test, match_expect);
+}
+
+/*
+ * Test that data races with writes larger than word-size are always reported,
+ * even if KCSAN_ASSUME_PLAIN_WRITES_ATOMIC is selected.
+ */
+__no_kcsan
+static void test_write_write_struct(struct kunit *test)
+{
+	const struct expect_report expect = {
+		.access = {
+			{ test_kernel_write_struct, &test_struct, sizeof(test_struct), KCSAN_ACCESS_WRITE },
+			{ test_kernel_write_struct, &test_struct, sizeof(test_struct), KCSAN_ACCESS_WRITE },
+		},
+	};
+	bool match_expect = false;
+
+	begin_test_checks(test_kernel_write_struct, test_kernel_write_struct);
+	do {
+		match_expect = report_matches(&expect);
+	} while (!end_test_checks(match_expect));
+	KUNIT_EXPECT_TRUE(test, match_expect);
+}
+
+/*
+ * Test that data races where only one write is larger than word-size are always
+ * reported, even if KCSAN_ASSUME_PLAIN_WRITES_ATOMIC is selected.
+ */
+__no_kcsan
+static void test_write_write_struct_part(struct kunit *test)
+{
+	const struct expect_report expect = {
+		.access = {
+			{ test_kernel_write_struct, &test_struct, sizeof(test_struct), KCSAN_ACCESS_WRITE },
+			{ test_kernel_write_struct_part, &test_struct.val[3], sizeof(test_struct.val[3]), KCSAN_ACCESS_WRITE },
+		},
+	};
+	bool match_expect = false;
+
+	begin_test_checks(test_kernel_write_struct, test_kernel_write_struct_part);
+	do {
+		match_expect = report_matches(&expect);
+	} while (!end_test_checks(match_expect));
+	KUNIT_EXPECT_TRUE(test, match_expect);
+}
+
+/* Test that races with atomic accesses never result in reports. */
+__no_kcsan
+static void test_read_atomic_write_atomic(struct kunit *test)
+{
+	bool match_never = false;
+
+	begin_test_checks(test_kernel_read_atomic, test_kernel_write_atomic);
+	do {
+		match_never = report_available();
+	} while (!end_test_checks(match_never));
+	KUNIT_EXPECT_FALSE(test, match_never);
+}
+
+/* Test that a race with an atomic and plain access result in reports. */
+__no_kcsan
+static void test_read_plain_atomic_write(struct kunit *test)
+{
+	const struct expect_report expect = {
+		.access = {
+			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
+			{ test_kernel_write_atomic, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC },
+		},
+	};
+	bool match_expect = false;
+
+	if (IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS))
+		return;
+
+	begin_test_checks(test_kernel_read, test_kernel_write_atomic);
+	do {
+		match_expect = report_matches(&expect);
+	} while (!end_test_checks(match_expect));
+	KUNIT_EXPECT_TRUE(test, match_expect);
+}
+
+/* Zero-sized accesses should never cause data race reports. */
+__no_kcsan
+static void test_zero_size_access(struct kunit *test)
+{
+	const struct expect_report expect = {
+		.access = {
+			{ test_kernel_write_struct, &test_struct, sizeof(test_struct), KCSAN_ACCESS_WRITE },
+			{ test_kernel_write_struct, &test_struct, sizeof(test_struct), KCSAN_ACCESS_WRITE },
+		},
+	};
+	const struct expect_report never = {
+		.access = {
+			{ test_kernel_write_struct, &test_struct, sizeof(test_struct), KCSAN_ACCESS_WRITE },
+			{ test_kernel_read_struct_zero_size, &test_struct.val[3], 0, 0 },
+		},
+	};
+	bool match_expect = false;
+	bool match_never = false;
+
+	begin_test_checks(test_kernel_write_struct, test_kernel_read_struct_zero_size);
+	do {
+		match_expect |= report_matches(&expect);
+		match_never = report_matches(&never);
+	} while (!end_test_checks(match_never));
+	KUNIT_EXPECT_TRUE(test, match_expect); /* Sanity check. */
+	KUNIT_EXPECT_FALSE(test, match_never);
+}
+
+/* Test the data_race() macro. */
+__no_kcsan
+static void test_data_race(struct kunit *test)
+{
+	bool match_never = false;
+
+	begin_test_checks(test_kernel_data_race, test_kernel_data_race);
+	do {
+		match_never = report_available();
+	} while (!end_test_checks(match_never));
+	KUNIT_EXPECT_FALSE(test, match_never);
+}
+
+__no_kcsan
+static void test_assert_exclusive_writer(struct kunit *test)
+{
+	const struct expect_report expect = {
+		.access = {
+			{ test_kernel_assert_writer, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT },
+			{ test_kernel_write_nochange, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
+		},
+	};
+	bool match_expect = false;
+
+	begin_test_checks(test_kernel_assert_writer, test_kernel_write_nochange);
+	do {
+		match_expect = report_matches(&expect);
+	} while (!end_test_checks(match_expect));
+	KUNIT_EXPECT_TRUE(test, match_expect);
+}
+
+__no_kcsan
+static void test_assert_exclusive_access(struct kunit *test)
+{
+	const struct expect_report expect = {
+		.access = {
+			{ test_kernel_assert_access, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_WRITE },
+			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
+		},
+	};
+	bool match_expect = false;
+
+	begin_test_checks(test_kernel_assert_access, test_kernel_read);
+	do {
+		match_expect = report_matches(&expect);
+	} while (!end_test_checks(match_expect));
+	KUNIT_EXPECT_TRUE(test, match_expect);
+}
+
+__no_kcsan
+static void test_assert_exclusive_access_writer(struct kunit *test)
+{
+	const struct expect_report expect_access_writer = {
+		.access = {
+			{ test_kernel_assert_access, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_WRITE },
+			{ test_kernel_assert_writer, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT },
+		},
+	};
+	const struct expect_report expect_access_access = {
+		.access = {
+			{ test_kernel_assert_access, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_WRITE },
+			{ test_kernel_assert_access, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_WRITE },
+		},
+	};
+	const struct expect_report never = {
+		.access = {
+			{ test_kernel_assert_writer, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT },
+			{ test_kernel_assert_writer, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT },
+		},
+	};
+	bool match_expect_access_writer = false;
+	bool match_expect_access_access = false;
+	bool match_never = false;
+
+	begin_test_checks(test_kernel_assert_access, test_kernel_assert_writer);
+	do {
+		match_expect_access_writer |= report_matches(&expect_access_writer);
+		match_expect_access_access |= report_matches(&expect_access_access);
+		match_never |= report_matches(&never);
+	} while (!end_test_checks(match_never));
+	KUNIT_EXPECT_TRUE(test, match_expect_access_writer);
+	KUNIT_EXPECT_TRUE(test, match_expect_access_access);
+	KUNIT_EXPECT_FALSE(test, match_never);
+}
+
+__no_kcsan
+static void test_assert_exclusive_bits_change(struct kunit *test)
+{
+	const struct expect_report expect = {
+		.access = {
+			{ test_kernel_assert_bits_change, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT },
+			{ test_kernel_change_bits, &test_var, sizeof(test_var),
+				KCSAN_ACCESS_WRITE | (IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS) ? 0 : KCSAN_ACCESS_ATOMIC) },
+		},
+	};
+	bool match_expect = false;
+
+	begin_test_checks(test_kernel_assert_bits_change, test_kernel_change_bits);
+	do {
+		match_expect = report_matches(&expect);
+	} while (!end_test_checks(match_expect));
+	KUNIT_EXPECT_TRUE(test, match_expect);
+}
+
+__no_kcsan
+static void test_assert_exclusive_bits_nochange(struct kunit *test)
+{
+	bool match_never = false;
+
+	begin_test_checks(test_kernel_assert_bits_nochange, test_kernel_change_bits);
+	do {
+		match_never = report_available();
+	} while (!end_test_checks(match_never));
+	KUNIT_EXPECT_FALSE(test, match_never);
+}
+
+__no_kcsan
+static void test_assert_exclusive_writer_scoped(struct kunit *test)
+{
+	const struct expect_report expect_start = {
+		.access = {
+			{ test_kernel_assert_writer_scoped, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_SCOPED },
+			{ test_kernel_write_nochange, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
+		},
+	};
+	const struct expect_report expect_anywhere = {
+		.access = {
+			{ test_enter_scope, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_SCOPED },
+			{ test_kernel_write_nochange, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
+		},
+	};
+	bool match_expect_start = false;
+	bool match_expect_anywhere = false;
+
+	begin_test_checks(test_kernel_assert_writer_scoped, test_kernel_write_nochange);
+	do {
+		match_expect_start |= report_matches(&expect_start);
+		match_expect_anywhere |= report_matches(&expect_anywhere);
+	} while (!end_test_checks(match_expect_start && match_expect_anywhere));
+	KUNIT_EXPECT_TRUE(test, match_expect_start);
+	KUNIT_EXPECT_TRUE(test, match_expect_anywhere);
+}
+
+__no_kcsan
+static void test_assert_exclusive_access_scoped(struct kunit *test)
+{
+	const struct expect_report expect_start1 = {
+		.access = {
+			{ test_kernel_assert_access_scoped, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_SCOPED },
+			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
+		},
+	};
+	const struct expect_report expect_start2 = {
+		.access = { expect_start1.access[0], expect_start1.access[0] },
+	};
+	const struct expect_report expect_inscope = {
+		.access = {
+			{ test_enter_scope, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_SCOPED },
+			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
+		},
+	};
+	bool match_expect_start = false;
+	bool match_expect_inscope = false;
+
+	begin_test_checks(test_kernel_assert_access_scoped, test_kernel_read);
+	end_time += msecs_to_jiffies(1000); /* This test requires a bit more time. */
+	do {
+		match_expect_start |= report_matches(&expect_start1) || report_matches(&expect_start2);
+		match_expect_inscope |= report_matches(&expect_inscope);
+	} while (!end_test_checks(match_expect_start && match_expect_inscope));
+	KUNIT_EXPECT_TRUE(test, match_expect_start);
+	KUNIT_EXPECT_TRUE(test, match_expect_inscope);
+}
+
+/* Test that racing accesses in seqlock critical sections are not reported. */
+__no_kcsan
+static void test_seqlock_noreport(struct kunit *test)
+{
+	bool match_never = false;
+
+	begin_test_checks(test_kernel_seqlock_reader, test_kernel_seqlock_writer);
+	do {
+		match_never = report_available();
+	} while (!end_test_checks(match_never));
+	KUNIT_EXPECT_FALSE(test, match_never);
+}
+
+/*
+ * Each test case is run with different numbers of threads. Until KUnit supports
+ * passing arguments for each test case, we encode #threads in the test case
+ * name (read by get_num_threads()). [The '-' was chosen as a stylistic
+ * preference to separate test name and #threads.]
+ *
+ * The thread counts are chosen to cover potentially interesting boundaries and
+ * corner cases (range 2-5), and then stress the system with larger counts.
+ */
+#define KCSAN_KUNIT_CASE(test_name)                                            \
+	{ .run_case = test_name, .name = #test_name "-02" },                   \
+	{ .run_case = test_name, .name = #test_name "-03" },                   \
+	{ .run_case = test_name, .name = #test_name "-04" },                   \
+	{ .run_case = test_name, .name = #test_name "-05" },                   \
+	{ .run_case = test_name, .name = #test_name "-08" },                   \
+	{ .run_case = test_name, .name = #test_name "-16" }
+
+static struct kunit_case kcsan_test_cases[] = {
+	KCSAN_KUNIT_CASE(test_basic),
+	KCSAN_KUNIT_CASE(test_concurrent_races),
+	KCSAN_KUNIT_CASE(test_novalue_change),
+	KCSAN_KUNIT_CASE(test_novalue_change_exception),
+	KCSAN_KUNIT_CASE(test_unknown_origin),
+	KCSAN_KUNIT_CASE(test_write_write_assume_atomic),
+	KCSAN_KUNIT_CASE(test_write_write_struct),
+	KCSAN_KUNIT_CASE(test_write_write_struct_part),
+	KCSAN_KUNIT_CASE(test_read_atomic_write_atomic),
+	KCSAN_KUNIT_CASE(test_read_plain_atomic_write),
+	KCSAN_KUNIT_CASE(test_zero_size_access),
+	KCSAN_KUNIT_CASE(test_data_race),
+	KCSAN_KUNIT_CASE(test_assert_exclusive_writer),
+	KCSAN_KUNIT_CASE(test_assert_exclusive_access),
+	KCSAN_KUNIT_CASE(test_assert_exclusive_access_writer),
+	KCSAN_KUNIT_CASE(test_assert_exclusive_bits_change),
+	KCSAN_KUNIT_CASE(test_assert_exclusive_bits_nochange),
+	KCSAN_KUNIT_CASE(test_assert_exclusive_writer_scoped),
+	KCSAN_KUNIT_CASE(test_assert_exclusive_access_scoped),
+	KCSAN_KUNIT_CASE(test_seqlock_noreport),
+	{},
+};
+
+/* ===== End test cases ===== */
+
+/* Get number of threads encoded in test name. */
+static bool __no_kcsan
+get_num_threads(const char *test, int *nthreads)
+{
+	int len = strlen(test);
+
+	if (WARN_ON(len < 3))
+		return false;
+
+	*nthreads = test[len - 1] - '0';
+	*nthreads += (test[len - 2] - '0') * 10;
+
+	if (WARN_ON(*nthreads < 0))
+		return false;
+
+	return true;
+}
+
+/* Concurrent accesses from interrupts. */
+__no_kcsan
+static void access_thread_timer(struct timer_list *timer)
+{
+	static atomic_t cnt = ATOMIC_INIT(0);
+	unsigned int idx;
+	void (*func)(void);
+
+	idx = (unsigned int)atomic_inc_return(&cnt) % ARRAY_SIZE(access_kernels);
+	/* Acquire potential initialization. */
+	func = smp_load_acquire(&access_kernels[idx]);
+	if (func)
+		func();
+}
+
+/* The main loop for each thread. */
+__no_kcsan
+static int access_thread(void *arg)
+{
+	struct timer_list timer;
+	unsigned int cnt = 0;
+	unsigned int idx;
+	void (*func)(void);
+
+	timer_setup_on_stack(&timer, access_thread_timer, 0);
+	do {
+		if (!timer_pending(&timer))
+			mod_timer(&timer, jiffies + 1);
+		else {
+			/* Iterate through all kernels. */
+			idx = cnt++ % ARRAY_SIZE(access_kernels);
+			/* Acquire potential initialization. */
+			func = smp_load_acquire(&access_kernels[idx]);
+			if (func)
+				func();
+		}
+	} while (!torture_must_stop());
+	del_timer_sync(&timer);
+	destroy_timer_on_stack(&timer);
+
+	torture_kthread_stopping("access_thread");
+	return 0;
+}
+
+__no_kcsan
+static int test_init(struct kunit *test)
+{
+	unsigned long flags;
+	int nthreads;
+	int i;
+
+	spin_lock_irqsave(&observed.lock, flags);
+	for (i = 0; i < ARRAY_SIZE(observed.lines); ++i)
+		observed.lines[i][0] = '\0';
+	observed.nlines = 0;
+	spin_unlock_irqrestore(&observed.lock, flags);
+
+	if (!torture_init_begin((char *)test->name, 1))
+		return -EBUSY;
+
+	if (!get_num_threads(test->name, &nthreads))
+		goto err;
+
+	if (WARN_ON(threads))
+		goto err;
+
+	for (i = 0; i < ARRAY_SIZE(access_kernels); ++i) {
+		if (WARN_ON(access_kernels[i]))
+			goto err;
+	}
+
+	if (!IS_ENABLED(CONFIG_PREEMPT) && nthreads > num_online_cpus() - 2) {
+		nthreads = num_online_cpus() - 2;
+		pr_info("%s: limiting number of threads to %d\n", test->name,
+			nthreads);
+	}
+
+	if (nthreads) {
+		threads = kcalloc(nthreads + 1, sizeof(struct task_struct *),
+				  GFP_KERNEL);
+		if (WARN_ON(!threads))
+			goto err;
+
+		threads[nthreads] = NULL;
+		for (i = 0; i < nthreads; ++i) {
+			if (torture_create_kthread(access_thread, NULL,
+						   threads[i]))
+				goto err;
+		}
+	}
+
+	torture_init_end();
+
+	return 0;
+
+err:
+	kfree(threads);
+	threads = NULL;
+	torture_init_end();
+	return -EINVAL;
+}
+
+__no_kcsan
+static void test_exit(struct kunit *test)
+{
+	struct task_struct **stop_thread;
+	int i;
+
+	if (torture_cleanup_begin())
+		return;
+
+	for (i = 0; i < ARRAY_SIZE(access_kernels); ++i)
+		WRITE_ONCE(access_kernels[i], NULL);
+
+	if (threads) {
+		for (stop_thread = threads; *stop_thread; stop_thread++)
+			torture_stop_kthread(reader_thread, *stop_thread);
+
+		kfree(threads);
+		threads = NULL;
+	}
+
+	torture_cleanup_end();
+}
+
+static struct kunit_suite kcsan_test_suite = {
+	.name = "kcsan-test",
+	.test_cases = kcsan_test_cases,
+	.init = test_init,
+	.exit = test_exit,
+};
+static struct kunit_suite *kcsan_test_suites[] = { &kcsan_test_suite, NULL };
+
+__no_kcsan
+static void register_tracepoints(struct tracepoint *tp, void *ignore)
+{
+	check_trace_callback_type_console(probe_console);
+	if (!strcmp(tp->name, "console"))
+		WARN_ON(tracepoint_probe_register(tp, probe_console, NULL));
+}
+
+__no_kcsan
+static void unregister_tracepoints(struct tracepoint *tp, void *ignore)
+{
+	if (!strcmp(tp->name, "console"))
+		tracepoint_probe_unregister(tp, probe_console, NULL);
+}
+
+/*
+ * We only want to do tracepoints setup and teardown once, therefore we have to
+ * customize the init and exit functions and cannot rely on kunit_test_suite().
+ */
+static int __init kcsan_test_init(void)
+{
+	/*
+	 * Because we want to be able to build the test as a module, we need to
+	 * iterate through all known tracepoints, since the static registration
+	 * won't work here.
+	 */
+	for_each_kernel_tracepoint(register_tracepoints, NULL);
+	return __kunit_test_suites_init(kcsan_test_suites);
+}
+
+static void kcsan_test_exit(void)
+{
+	__kunit_test_suites_exit(kcsan_test_suites);
+	for_each_kernel_tracepoint(unregister_tracepoints, NULL);
+	tracepoint_synchronize_unregister();
+}
+
+late_initcall(kcsan_test_init);
+module_exit(kcsan_test_exit);
+
+MODULE_LICENSE("GPL v2");
+MODULE_AUTHOR("Marco Elver <elver@google.com>");
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 689b6b81f272..ea28245c6c1d 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -41,7 +41,28 @@ config KCSAN_SELFTEST
 	bool "Perform short selftests on boot"
 	default y
 	help
-	  Run KCSAN selftests on boot. On test failure, causes the kernel to panic.
+	  Run KCSAN selftests on boot. On test failure, causes the kernel to
+	  panic. Recommended to be enabled, ensuring critical functionality
+	  works as intended.
+
+config KCSAN_TEST
+	tristate "KCSAN test for integrated runtime behaviour"
+	depends on TRACEPOINTS && KUNIT
+	select TORTURE_TEST
+	help
+	  KCSAN test focusing on behaviour of the integrated runtime. Tests
+	  various race scenarios, and verifies the reports generated to
+	  console. Makes use of KUnit for test organization, and the Torture
+	  framework for test thread control.
+
+	  Each test case may run at least up to KCSAN_REPORT_ONCE_IN_MS
+	  milliseconds. Test run duration may be optimized by building the
+	  kernel and KCSAN test with KCSAN_REPORT_ONCE_IN_MS set to a lower
+	  than default value.
+
+	  Say Y here if you want the test to be built into the kernel and run
+	  during boot; say M if you want the test to build as a module; say N
+	  if you are unsure.
 
 config KCSAN_EARLY_ENABLE
 	bool "Early enable during boot"
-- 
2.26.2.303.gf8c07b1a785-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200427143507.49654-1-elver%40google.com.
