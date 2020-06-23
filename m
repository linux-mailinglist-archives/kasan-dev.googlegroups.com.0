Return-Path: <kasan-dev+bncBAABBONAYX3QKGQENUM4KHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id A52142045FF
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 02:43:38 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id g6sf1746830qtr.0
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jun 2020 17:43:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592873017; cv=pass;
        d=google.com; s=arc-20160816;
        b=otetmoOK0x2KvLSjy69Q8ykNG6ohsACzRKKLM+nZ+F0uKmXH5VCiwXzfsKF7bJkZR8
         sONTN22CXvCx3SCdeYEMvE8xbwmqHW4jJSkzQv1pP0ZB6SHK+a+pOf7oKIDNQHJ9epxt
         CoYr9em/574bdlJ7qrKCMB+fSFpXvVsvCDB35jEPbH0zITyW1NXCNmS4R0NfIKpX2d2K
         iIpPcLAqPY6x2BUlIWDJYnvlzjcSPBZuoJsNOWyi9WcB7N64PHw6jXPEy1F94ZfFaiR1
         jf9uxCYKbyvbsqlMKF4d0WZC33MwCUT++XF1J9S7qOLkeV/XL0/0/JmqAcglJi1OEgn4
         JOHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=r3liVAiqg3HgrpVPMj/O42w60duqljBfv97QGATRa+s=;
        b=qzsdExlGjxii7K04F44JwwtOwXzjSfs5uQPrcQeTYCyIM0OAPuEPSwg+h4WpeK6yw+
         IvttfvdB4sTWjAs/bYDgRfCEMHWlFRGn0KUfkEidvt/SW+hN2mqxwIAuODNJi2Tzf0rk
         g9AcrrZJ/kt2DT+I+/5r9+Jp+B3gBWTipcq3XKKPddCgmSorClQYjUgAHd6vwIXzAmAK
         yhbD/gfH630+vXitKTy5jNftwDRA+wN2V7a1ijPl4K1rOiwKr4929acmyqljj8w1/s01
         CFm/Kh/5E8cN4I83rvj+CHSGU1hlCVkQiylmKsW0PG5A7pFTk8UGk7JdHLvEmPX4VONl
         YY0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=BRIhYOTm;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r3liVAiqg3HgrpVPMj/O42w60duqljBfv97QGATRa+s=;
        b=jB/kFirMV4W4PxwCzBoH0cpupEvemuhw5R/ITWwYSxZACiKJ/nGNjm7dMRSOIITfjx
         7LXOHS224zDSNi6eTBGig6T7xcd68yE0DXstNB/oEB8R5sfFQ1VBI2n6GQOuJnLrTeys
         bpyFpa1Vt+iUasr6vW1QKAe40VfnmlVhl2XqzpbGUjAMW78kz/SUA0oRqmnn05bEPywZ
         WWEnoBV69ADMQ/bTiMcJuS8/2AALaLqPCmqzQPqXjkXcleG7MKFbFpWWAaDtxdJexYZ/
         /Xpf9i4tefj5hGo8CaMr0xeVYJ8ME33YPmb7ILqhwCwiug41j1ylgpJ+CjdnJ7/oRFt0
         B53Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r3liVAiqg3HgrpVPMj/O42w60duqljBfv97QGATRa+s=;
        b=CJ+bow98q88G0ZwLUKsS69TdLwkDZ97CeVMDOEWxDVNqMIPO+s1ekGpbOnZgTqTX1Q
         8ugVGOTXWHlYMSio7oeSEvPZlJvZJeWiTQPFLrBRUhLSKdmGLoRcDorOfFOEPeUqWJra
         adtir/3drHKkChYYd2zdRT55rx+opB9keWcP7oyM5eEEx0lofaDqqgda7nYqqAE26Ayl
         /Z3G5sWZddBAakGThxJdwZk4rg6rVKoxmepPBdBVUlGGIjTT0uF+0gcDUy9jEryKCQ1d
         m+cZ0H1yBEBaPawGpVk5niB+wssX7yzk4mf9rYNbM8EWs2X9uR92xFXRuKVVy9CwUFfL
         Ty1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531y9ZGquyj8an77UDXp29HlNi3z+9cS5dn+pVYYXFGmuHlQvQ4x
	NffhguXHS+lumRpHK/pTOS4=
X-Google-Smtp-Source: ABdhPJwhVd3daZ5B86gdMew+Ur2cXkPenaHtDxWueBHZZTzEpaphNZEx9WGFmEY6yzgOFYhY1ZxtgA==
X-Received: by 2002:ac8:346e:: with SMTP id v43mr17994339qtb.265.1592873017316;
        Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9ece:: with SMTP id h197ls2052384qke.7.gmail; Mon, 22
 Jun 2020 17:43:37 -0700 (PDT)
X-Received: by 2002:a37:9046:: with SMTP id s67mr3187870qkd.275.1592873016926;
        Mon, 22 Jun 2020 17:43:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592873016; cv=none;
        d=google.com; s=arc-20160816;
        b=cESvTgY6eOvD7aUshN4BmEUwlqN7dlyT9NBnxNHLkIp6VaAcuYs1F6OgDHN9W4ByMy
         5kw7kKsN+8UGYBjVrAehXLmPts2Y/WbLSGfrcLa8q3MBz4muWJ8ZZnLTOHTxnILhNHV1
         bdzOrThTTc4e2v+82NemGmDo51rrwLqLduo7uXtkKbT1x4KKdnJhG0p9vK2+QjvwK7Af
         u3Orv4NKPvErnXS+w/wzP6kjDaIfg6FcVpZdZlCKrgdfvWM6/pprczzGsM8m2XW3vP+V
         fFVfA9H30E5lhtV5i5Vjy6LQTCJW2voiktPJ//qMpXaKzZsHA3QR6mNQS0KYwcmZOqkE
         HFWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=K8w0jrCnXhWO3racO9BBUMFavrpphAd7JHe5ZovT8F8=;
        b=OuHuH1Z70+76+OG3DditmI3ylEKdvIwU7AjpK0ApV7LJaDbL6Dk0n1ge1Nx7KYJAij
         Angc35VHwUlz+B3CDILlk5D/7oF2GejDjfze6za9RHYZfopU3ty9F6c6ad1lCn2/LdAH
         cX3FPhgltbSDipAq0+JmcgbyzDolfdShPX2jqST/B5mVzdS1r3+iiXH+MUdk0LtH4Ehe
         JtfdqU24RoOfcaCMbXqlScTxO2zAEiuA/XxwV4xWHPlqE7MNiH6gzVNiqzRdAvHLzI36
         kUTezvicABRCN9rV5o2JU8+H8oh9QKq0RBU0n0Wr0OEdEnx3TaFmH59COfAbcC4RxTYo
         ys/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=BRIhYOTm;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m1si1181514qki.3.2020.06.22.17.43.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Jun 2020 17:43:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id DD5D620842;
	Tue, 23 Jun 2020 00:43:35 +0000 (UTC)
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
Subject: [PATCH tip/core/rcu 04/10] kcsan: Add test suite
Date: Mon, 22 Jun 2020 17:43:27 -0700
Message-Id: <20200623004333.27227-4-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200623003731.GA26717@paulmck-ThinkPad-P72>
References: <20200623003731.GA26717@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=BRIhYOTm;       spf=pass
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

This adds KCSAN test focusing on behaviour of the integrated runtime.
Tests various race scenarios, and verifies the reports generated to
console. Makes use of KUnit for test organization, and the Torture
framework for test thread control.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/Makefile     |    3 +
 kernel/kcsan/kcsan-test.c | 1084 +++++++++++++++++++++++++++++++++++++++++++++
 lib/Kconfig.kcsan         |   23 +-
 3 files changed, 1109 insertions(+), 1 deletion(-)
 create mode 100644 kernel/kcsan/kcsan-test.c

diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
index d4999b3..14533cf 100644
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
index 0000000..a8c1150
--- /dev/null
+++ b/kernel/kcsan/kcsan-test.c
@@ -0,0 +1,1084 @@
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
+	end_time = jiffies + msecs_to_jiffies(CONFIG_KCSAN_REPORT_ONCE_IN_MS + 500);
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
+		might_sleep();
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
+		might_sleep();
+
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
+	if (!IS_ENABLED(CONFIG_PREEMPT) || !IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER)) {
+		/*
+		 * Without any preemption, keep 2 CPUs free for other tasks, one
+		 * of which is the main test case function checking for
+		 * completion or failure.
+		 */
+		const int min_unused_cpus = IS_ENABLED(CONFIG_PREEMPT_NONE) ? 2 : 0;
+		const int min_required_cpus = 2 + min_unused_cpus;
+
+		if (num_online_cpus() < min_required_cpus) {
+			pr_err("%s: too few online CPUs (%u < %d) for test",
+			       test->name, num_online_cpus(), min_required_cpus);
+			goto err;
+		} else if (nthreads > num_online_cpus() - min_unused_cpus) {
+			nthreads = num_online_cpus() - min_unused_cpus;
+			pr_warn("%s: limiting number of threads to %d\n",
+				test->name, nthreads);
+		}
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
index 5ee88e5..3f3b5bc 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -59,7 +59,28 @@ config KCSAN_SELFTEST
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
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200623004333.27227-4-paulmck%40kernel.org.
