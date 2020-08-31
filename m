Return-Path: <kasan-dev+bncBAABBYH5WT5AKGQEXAV6IBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B65F72580A2
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 20:18:09 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id y9sf10066146ybp.8
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598897888; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZjkMPn6woFa9RxTPvSTC3PApBSsfF6OKc8A7yhDTOFJWCV9BE3zrU+Lfax8i2P2VYg
         oVvPrEsekc5R//AOQBD6HgHKB2oUvuawe53KvNOgUMX+AzzfjjS/jSjYSrYzUKcec8F6
         2ry12lRD2HYtsJfbJyQ7NjZ5NQb8dW8+z+uxo6okUWuA7LonhxtrvXAm5JcTBWwLxUBN
         9Jjl9IF9bmU67V6vD5E4vNhusaJfLiT15Zr0Gy+1rVeyC48r0IhRSpRUvX63IInWjEmY
         6RHsFBIVapyG1693HGUGkYDn+LmPaHFJBwea3SULK8ei30zAeim5lnbe2Lloa6IpJOhj
         YWTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=UK4AqCjZTfq7wKOR/8pekfdFuW5m9VhRNk25VFacjL8=;
        b=IWBx8XdGAhBtdMiyF2wPAL1wDCP6gaCJ97nLVsu9WqOqhnzNWisyb/TRbQfEvxGZ1k
         5GZ4ImJm/iCRFw5dxn9fIXUzcUuOxZgjk9DP4aqWE4UFMETC1coZ3lkEzxZQowtrclU5
         vG+2ACvha9mOUA+nELeSkmdPIxN3N3Svg2gQ9R5YDf+V91LXvEx4EypUtHSURiwZAMPf
         3CGtItecAVVJZUcCOQhg7h/Vm+AZvH4Djw2v5z84r3NX0KH7LMsGhzAkHaDpAo8jqE5Z
         ML0xyrIt3XUUcXrw1D+snN5C3TQ/RNK7wGCg7RjEbl8k4T66XgPIRVLzCaH2+81UJNiv
         eFBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Wvc088uw;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UK4AqCjZTfq7wKOR/8pekfdFuW5m9VhRNk25VFacjL8=;
        b=icRMk28LHbBOP1EccrhKEeI/7s7SnNg2BIkvXImVhqTunk9m94nmY052oQBgimY+IY
         SwNVt15l0Vbe6OrhNtObSrBZg+Xv9XrVT5hVswQc3L7wk7xADbTrcVf7F70rUsJc5Ncj
         PGnO+94pxpNcwQSzVD09xRB4431lCj6LTjfHG5pDXDtlICzJShS8IOIdhSkch7QMsurK
         cmc4F0myIYaXYHZBMOSwtBv30lLmGyz0WWbuGsGt9omGjWbF0r637afwNqjGwYZo5qvW
         4Y3FBUK1yez7OMr+VUvNbr4MOHL05RzrX24/UNJdtIiEudIHGIb+TCc1tBLBngsaGjZX
         h9OQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UK4AqCjZTfq7wKOR/8pekfdFuW5m9VhRNk25VFacjL8=;
        b=REbwfzOlmC5GZl47RLNu8B5jcLAccUKUDc38hMg18kchWBN7NqvTu/Z8RwDykFzHia
         jJ/rarfoK3eH24A+MmXKdM2O5cGSlBm/eaJOexN6zhynnoK9w4sQpq+RM3z2eru9rFlm
         k544mRfCZDAmc4PaV7nBGzF9c7U7xrconThKUwe6iwmPrbggU8TLYMwGuRRRG6HkGwtH
         9YSY8M++tgxJlKhOFgIkUcLtWMmSy/o/MHIuQ+w+FeKrs+0r+Y8E9gFEbvh9RP5Wi0ne
         /k/+HzaPoc5yrUMwvCxNBlflRsz9WpR84rIgVIpxvgMjXu+U+FMoLyxLDLMnA0ChGfMU
         B1gw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53095PwzArmp3gPBdi2dzj8EZOGLldb3k9w6mbhF3toIAoEYprIs
	JVbK76MhCxJw5fz02azES1s=
X-Google-Smtp-Source: ABdhPJxew4v5yYI0S9ckIR+OyZ/NFVMUTqmWcT3fKSaw/mjwp7T9yxiiMZehy544mHubWWO1BK39lA==
X-Received: by 2002:a25:aaf3:: with SMTP id t106mr3734295ybi.56.1598897888555;
        Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:70d:: with SMTP id k13ls3429264ybt.9.gmail; Mon, 31
 Aug 2020 11:18:08 -0700 (PDT)
X-Received: by 2002:a25:a081:: with SMTP id y1mr4110639ybh.370.1598897888278;
        Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598897888; cv=none;
        d=google.com; s=arc-20160816;
        b=hDXzKYQS0vf4btcY9GgDVqnFrVsQJJFX1ENcKEuQcJi+Uafeoygfv8eWMW45rSUP/q
         uhzdOm6fU5DBpKijkwqm9l4d6gI88+5s2n3/AwrSnrS1pgsCCbPANMAR6mMEg+iYse+N
         ZKrClt8ZcMcqJX4A97L3TN8lX8n3lqyH+V0CpexmSak4I7i45XRIsCqP5KFx42jJYVHO
         DcSsYyeJSUhp1xd4id7TbfBsPtJNDeLmhfAfFnSUFyd/MPCkQZiJAI/klvFeRMJiUbRz
         pZVPBEg3EdLkMuwI17xUSBgnGoGWAq6gsrvpn/rOFebWSxMFYcrG9CZ+efLF110gOSrp
         ijeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=4xZVSm/TW+P4Tm0gNrwt/UfJ0S4uCIgQhoQysUX7Hls=;
        b=A7VIiTMwt6ICDGMa12hgAK/tloDI+WToY3TY4sWHcb+E/5gMoDzqFhCp2X7T5Gdss+
         yqtXYNnNLaxguq76O7N3Drglb0Qb4JhWkAl18UrhdAr5BEWfQxFQfaZ+2WArquVAkrXd
         FlJaaBFiSOrIBsKqjxo4IGmZNR5QzW8VYBzkK75+HQs/qFIjGHGlcMklt0RK3Y4G3bxa
         qjYVe8To5VRDzMK0wFlgeiY9gHVlktU5zmxtm+oOqw/s3qW95owt5EhfwbA/0zHKUMLD
         mPFlvxGJMx0lr4LuzL9hozS9SHEmIkiBIhZfRHdQZOxYZZEULm7gwNcZHDe7HvjUozqX
         P3Uw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Wvc088uw;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o14si420643ybm.5.2020.08.31.11.18.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 7328221534;
	Mon, 31 Aug 2020 18:18:07 +0000 (UTC)
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
Subject: [PATCH kcsan 08/19] kcsan: Test support for compound instrumentation
Date: Mon, 31 Aug 2020 11:17:54 -0700
Message-Id: <20200831181805.1833-8-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200831181715.GA1530@paulmck-ThinkPad-P72>
References: <20200831181715.GA1530@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=Wvc088uw;       spf=pass
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

Changes kcsan-test module to support checking reports that include
compound instrumentation. Since we should not fail the test if this
support is unavailable, we have to add a config variable that the test
can use to decide what to check for.

Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/kcsan-test.c | 65 +++++++++++++++++++++++++++++++++++++----------
 lib/Kconfig.kcsan         |  5 ++++
 2 files changed, 56 insertions(+), 14 deletions(-)

diff --git a/kernel/kcsan/kcsan-test.c b/kernel/kcsan/kcsan-test.c
index 721180c..ebe7fd2 100644
--- a/kernel/kcsan/kcsan-test.c
+++ b/kernel/kcsan/kcsan-test.c
@@ -27,6 +27,12 @@
 #include <linux/types.h>
 #include <trace/events/printk.h>
 
+#ifdef CONFIG_CC_HAS_TSAN_COMPOUND_READ_BEFORE_WRITE
+#define __KCSAN_ACCESS_RW(alt) (KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE)
+#else
+#define __KCSAN_ACCESS_RW(alt) (alt)
+#endif
+
 /* Points to current test-case memory access "kernels". */
 static void (*access_kernels[2])(void);
 
@@ -186,20 +192,21 @@ static bool report_matches(const struct expect_report *r)
 
 	/* Access 1 & 2 */
 	for (i = 0; i < 2; ++i) {
+		const int ty = r->access[i].type;
 		const char *const access_type =
-			(r->access[i].type & KCSAN_ACCESS_ASSERT) ?
-				((r->access[i].type & KCSAN_ACCESS_WRITE) ?
-					 "assert no accesses" :
-					 "assert no writes") :
-				((r->access[i].type & KCSAN_ACCESS_WRITE) ?
-					 "write" :
-					 "read");
+			(ty & KCSAN_ACCESS_ASSERT) ?
+				      ((ty & KCSAN_ACCESS_WRITE) ?
+					       "assert no accesses" :
+					       "assert no writes") :
+				      ((ty & KCSAN_ACCESS_WRITE) ?
+					       ((ty & KCSAN_ACCESS_COMPOUND) ?
+							"read-write" :
+							"write") :
+					       "read");
 		const char *const access_type_aux =
-			(r->access[i].type & KCSAN_ACCESS_ATOMIC) ?
-				" (marked)" :
-				((r->access[i].type & KCSAN_ACCESS_SCOPED) ?
-					 " (scoped)" :
-					 "");
+			(ty & KCSAN_ACCESS_ATOMIC) ?
+				      " (marked)" :
+				      ((ty & KCSAN_ACCESS_SCOPED) ? " (scoped)" : "");
 
 		if (i == 1) {
 			/* Access 2 */
@@ -277,6 +284,12 @@ static noinline void test_kernel_write_atomic(void)
 	WRITE_ONCE(test_var, READ_ONCE_NOCHECK(test_sink) + 1);
 }
 
+static noinline void test_kernel_atomic_rmw(void)
+{
+	/* Use builtin, so we can set up the "bad" atomic/non-atomic scenario. */
+	__atomic_fetch_add(&test_var, 1, __ATOMIC_RELAXED);
+}
+
 __no_kcsan
 static noinline void test_kernel_write_uninstrumented(void) { test_var++; }
 
@@ -439,8 +452,8 @@ static void test_concurrent_races(struct kunit *test)
 	const struct expect_report expect = {
 		.access = {
 			/* NULL will match any address. */
-			{ test_kernel_rmw_array, NULL, 0, KCSAN_ACCESS_WRITE },
-			{ test_kernel_rmw_array, NULL, 0, 0 },
+			{ test_kernel_rmw_array, NULL, 0, __KCSAN_ACCESS_RW(KCSAN_ACCESS_WRITE) },
+			{ test_kernel_rmw_array, NULL, 0, __KCSAN_ACCESS_RW(0) },
 		},
 	};
 	static const struct expect_report never = {
@@ -629,6 +642,29 @@ static void test_read_plain_atomic_write(struct kunit *test)
 	KUNIT_EXPECT_TRUE(test, match_expect);
 }
 
+/* Test that atomic RMWs generate correct report. */
+__no_kcsan
+static void test_read_plain_atomic_rmw(struct kunit *test)
+{
+	const struct expect_report expect = {
+		.access = {
+			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
+			{ test_kernel_atomic_rmw, &test_var, sizeof(test_var),
+				KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC },
+		},
+	};
+	bool match_expect = false;
+
+	if (IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS))
+		return;
+
+	begin_test_checks(test_kernel_read, test_kernel_atomic_rmw);
+	do {
+		match_expect = report_matches(&expect);
+	} while (!end_test_checks(match_expect));
+	KUNIT_EXPECT_TRUE(test, match_expect);
+}
+
 /* Zero-sized accesses should never cause data race reports. */
 __no_kcsan
 static void test_zero_size_access(struct kunit *test)
@@ -942,6 +978,7 @@ static struct kunit_case kcsan_test_cases[] = {
 	KCSAN_KUNIT_CASE(test_write_write_struct_part),
 	KCSAN_KUNIT_CASE(test_read_atomic_write_atomic),
 	KCSAN_KUNIT_CASE(test_read_plain_atomic_write),
+	KCSAN_KUNIT_CASE(test_read_plain_atomic_rmw),
 	KCSAN_KUNIT_CASE(test_zero_size_access),
 	KCSAN_KUNIT_CASE(test_data_race),
 	KCSAN_KUNIT_CASE(test_assert_exclusive_writer),
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 3d282d5..f271ff5 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -40,6 +40,11 @@ menuconfig KCSAN
 
 if KCSAN
 
+# Compiler capabilities that should not fail the test if they are unavailable.
+config CC_HAS_TSAN_COMPOUND_READ_BEFORE_WRITE
+	def_bool (CC_IS_CLANG && $(cc-option,-fsanitize=thread -mllvm -tsan-compound-read-before-write=1)) || \
+		 (CC_IS_GCC && $(cc-option,-fsanitize=thread --param tsan-compound-read-before-write=1))
+
 config KCSAN_VERBOSE
 	bool "Show verbose reports with more information about system state"
 	depends on PROVE_LOCKING
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200831181805.1833-8-paulmck%40kernel.org.
