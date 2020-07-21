Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU4H3P4AKGQEJWXPDBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id D1D24227D05
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 12:30:43 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id t18sf8424498lfe.7
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 03:30:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595327443; cv=pass;
        d=google.com; s=arc-20160816;
        b=CdCDA1cYT1sHgWsINKT3vaa82Vuxqn78eoDC6f6tx6YDcM9oGie8M8+b2iJ2PggwF0
         EGgL+1PcYrMUfyBoEYQ5wysMmA/oteyu3GYHC546Zu8HlU2SpaTTAvAWg1DrPUa2r5Ie
         rNAN2zgaZIRK9lb2oYJPS/ADnGVA9EIhsr6vDdclt1X3hn5cuDBXLyyKyLPXNy+CfTlh
         FfP7evM57OiGO8ObqbAcdBxrn0wYswKlHa2gsRMBg3/cqyeXDCdhWYM4sN27Pt5IJ0zG
         Zqsm617etyZSAYYCrbrIXRE47DDDGfJ4K+IbX48BvtezMROBvexjn8tNZNV4RqIN9kco
         2/Rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=V+TVx0ybDPe4RDcSuUB6eCrjLTDEjl9H0uQVuZNe0+0=;
        b=z3QLTh/lsuBFLBO7R6vxn9hVADNJq6Utt8uSJ7hR20FmxqSkuvYguSA++UwGfKm1uw
         gz5dJkfovBDHxk719YNahjVE9r6zDq+WGJYGFznnqGAkD2gcYnJX9VKzSkmLRGUfEJV5
         5zDz1mopMpURQWdXL14gb8AGB13selefRX5NIqI910Q5WvmDFZyUjDP5xPpJBoxbj2S5
         gYDxmzYJdOLcR9PNzzmG2NCy1KqLgCsrmuCdZSmuL4SGJ2+ugIpm5UyMM9tjbcHrU+bp
         vO7fujfVf14W7ln9EypHcb50ZcH1s463gbQOn6TaJ7v0mCt2Hq2vdzNTLfkxQk0uP2rJ
         txGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XzNICzMl;
       spf=pass (google.com: domain of 30smwxwukcbmxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=30sMWXwUKCbMXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V+TVx0ybDPe4RDcSuUB6eCrjLTDEjl9H0uQVuZNe0+0=;
        b=Ei9XkEnIcL1p4S8trqDrRBYse8P5LOk5cSF1ByveT2YlUt+C9Jutdxe7dVrZ9/LEeX
         hv9uUdptiNAXjbOX5+9a1P6m4Y/xn6pbowZzxPPhmkB7B05xg/wtxfGk2MfE2lgD/E7H
         F4LmYpkcEA3vbdMWgqkFYM0VQnozkQM8U1mC6EROhlissupNtNJYLttBp87k+UaZ7y6E
         Lco/BVRkKUBdTP6xAaKAbEMzE2XF/ImPJ0WWInfyltDv2nXc18eSaULRQZrYZK6bq+nP
         J92PjBVO7xO8Xr4wQwBVaGvLc8S/nX8JQSo+KhPBYCQwJQaSVyIbU2sLq0A6Fz1zgDhb
         5J3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V+TVx0ybDPe4RDcSuUB6eCrjLTDEjl9H0uQVuZNe0+0=;
        b=pnyMO6dpA8YJ288QrTyAGkqmeTGy51IlKWk/Ndvlex2RpvtVF6eX9gXM/YrrzKkwht
         7PVZpevIXQfDN70gmQGwuJVS2yAna6SW1nt3GqDiIKel26novBcxWn9pRmRkfu2IgHH9
         F/NxovrSVReiCNRo5WAVoi1T/gVuDP6OjwVMBzqo24QFiiuzou3PU7FuyOcRbPlzHxvR
         6KXu2PakVRBMvexWyZR8CinW4Okay22J6aVMef+7qeRufYkrN9QlBxySdcyf5gliGC44
         bNQYo2cJivUJHE7Gwk93yBCHnmhTKt8fQMSGixDbnb6j0wrKGwG3nBux9ZJCnHA1UUrr
         uDfA==
X-Gm-Message-State: AOAM531M2wL4nA2lFH6JaBZLVmGFHjpRcGqi94vhWW/10doHpS7dtx3Y
	6I3lN4w/VKqaxCV76qumklg=
X-Google-Smtp-Source: ABdhPJw0ZqH5xOCrsGIbO0v7G8RoDrRSN4i5s5oays2q0pe9sqNzBprU01I7NcV6YwMTUi2FQW4w+w==
X-Received: by 2002:a2e:91da:: with SMTP id u26mr12899839ljg.311.1595327443399;
        Tue, 21 Jul 2020 03:30:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5e33:: with SMTP id o19ls2937247lfg.1.gmail; Tue, 21 Jul
 2020 03:30:42 -0700 (PDT)
X-Received: by 2002:ac2:4158:: with SMTP id c24mr13132532lfi.109.1595327442701;
        Tue, 21 Jul 2020 03:30:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595327442; cv=none;
        d=google.com; s=arc-20160816;
        b=TntsbsPeCygG9klxXW+6lOnxfQL6u7NA6zKLV7fvW9GFcE7894I6q9kISr/gTx2NS+
         cipN7QtTUMHvwMMPp0yAWogNnhcoOwMoPqg/9aow23WLeziaPoEEgaiVTD0x3edTeFe4
         u7ZTP3I79fF8iS63YX0M2qQVm2nVRYfP9NCJGIITth8AyjavF84CPastM6xHxZydSPHL
         9TrAfhjBqedMQeBgvEaNipnMsxcYiiIzGZsBBmMXm+F1OJbrSrx2gDluc4RK6r7qDLob
         j3Z42pYCTxY5KntjgzlMvWT91IXXLSb2sUkKepho4SIPwaQEutKGB0rsVLLPm/wevus3
         otBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=lzumWwjBCjoWvyaVpmfup+Sfq7jvpdMDLzihovn9kHY=;
        b=uuwbE4PME8yU4ePAE8L2IbNhD3zUSpZ45k4A7srbVPgQk/OrYvgSJy7TtdeJLO/ZMX
         kRhPrAW45qLPzdUTHRZSFEFq7/qqLOV2bbVM6ebjq70OXBFx4/SjEmJjZPOA6HyWerGi
         JW11p+qB76EdZOw1NxzK1kn5mrIJ0maE5Av4AmASwY7ZK8iZKyrMU4qBODgC9UaD+24M
         mElSVwl3c0Kc1pLV19ws2QeM6XLGnn9rFt8d8wbCYnN31j2BiFR7AEwvzMX6BdDHPvNh
         TnqzlM2hRRUHV4waFT51WyEkNmp6tvzDnvV4Qn42YU6EoYWimsFE17rrHtAAXxmKIz7a
         f5Ow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XzNICzMl;
       spf=pass (google.com: domain of 30smwxwukcbmxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=30sMWXwUKCbMXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id k10si1179171lji.2.2020.07.21.03.30.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jul 2020 03:30:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30smwxwukcbmxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id s12so833583wmc.5
        for <kasan-dev@googlegroups.com>; Tue, 21 Jul 2020 03:30:42 -0700 (PDT)
X-Received: by 2002:a1c:984d:: with SMTP id a74mr3644277wme.140.1595327442395;
 Tue, 21 Jul 2020 03:30:42 -0700 (PDT)
Date: Tue, 21 Jul 2020 12:30:13 +0200
In-Reply-To: <20200721103016.3287832-1-elver@google.com>
Message-Id: <20200721103016.3287832-6-elver@google.com>
Mime-Version: 1.0
References: <20200721103016.3287832-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.rc0.105.gf9edc3c819-goog
Subject: [PATCH 5/8] kcsan: Test support for compound instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, arnd@arndb.de, mark.rutland@arm.com, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XzNICzMl;       spf=pass
 (google.com: domain of 30smwxwukcbmxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=30sMWXwUKCbMXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
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

Changes kcsan-test module to support checking reports that include
compound instrumentation. Since we should not fail the test if this
support is unavailable, we have to add a config variable that the test
can use to decide what to check for.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/kcsan-test.c | 65 ++++++++++++++++++++++++++++++---------
 lib/Kconfig.kcsan         |  5 +++
 2 files changed, 56 insertions(+), 14 deletions(-)

diff --git a/kernel/kcsan/kcsan-test.c b/kernel/kcsan/kcsan-test.c
index 721180cbbab1..ebe7fd245104 100644
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
index 3d282d51849b..cde5b62b0a01 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -40,6 +40,11 @@ menuconfig KCSAN
 
 if KCSAN
 
+# Compiler capabilities that should not fail the test if they are unavailable.
+config CC_HAS_TSAN_COMPOUND_READ_BEFORE_WRITE
+	def_bool (CC_IS_CLANG && $(cc-option,-fsanitize=thread -mllvm -tsan-compound-read-before-write=1)) || \
+		 (CC_IS_GCC && $(cc-option,-fsanitize=thread --param -tsan-compound-read-before-write=1))
+
 config KCSAN_VERBOSE
 	bool "Show verbose reports with more information about system state"
 	depends on PROVE_LOCKING
-- 
2.28.0.rc0.105.gf9edc3c819-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200721103016.3287832-6-elver%40google.com.
