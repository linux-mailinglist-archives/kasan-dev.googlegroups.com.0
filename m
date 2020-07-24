Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE4O5L4AKGQEJBPWCHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id D297322BE6F
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jul 2020 09:00:35 +0200 (CEST)
Received: by mail-ej1-x63f.google.com with SMTP id a26sf3300340ejr.7
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jul 2020 00:00:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595574035; cv=pass;
        d=google.com; s=arc-20160816;
        b=aQnREElt1DbH1+oK5WW2xiwQmopnwGYGuTlgJ8pz1bzd75AXJ6VGrBsesm46iwY6sV
         DVFAroaBlt9kp45j6jqjXZN6h/L5mSrgs7UTRC+E5663jPxHGq/0FyiRQzzxLGHUNuvp
         hS7Db/1dP6AdTrG8usnngCdqkl58UtvdcApFodRngt3XvhkKgAXQT8tNEr88lpTyepWP
         +Mmp9ZFMlw/SQ0PWNdi+MfQsj73kqflzGANwSxC1BBPey/FevoK4nK9HG6LjZ7uLW+6+
         ALH112n25QkQL4cgcl2XM6QHnqQMYTnENpVzuWy4ILfG5VuKOwVxqJzgFZBMmfBijj3Z
         T9ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=fB9xuI4a/kuAlgwz1LZfwuCsyLwijwHvHTkfv8NHd+o=;
        b=HUfV/eeAlaVYxlujINt3fu3kFIzHVc7JMxuoelnpcuTM3vr4kmsZTQ4s4BCu76GFHf
         Gui50s+0QV0rgxoUGNItI/jjMgZYD2KGXtJCCa6zO4VsW+AVfjIdJ4/Q7QqyoqZKGPWS
         TqhJ2ir6POsLUzmL4Sse3pjI6mEpHxBBBYk6TFmbxSHs2gPRKl+16hzpTLJmusQ9pjL7
         fHz4cBXwJSrmXUSra4KlauKRBEtBZOUEvLpE9pkjoBZ2P9Ea1P+COpW65dLLO5UEYty9
         1kB48D43h7xyPpIo+BQiq2evqiIw72lGq3ITRX00WSJhRpmKT8BLnfDVGbnaAdLgtxM1
         i/CA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mu+faoc3;
       spf=pass (google.com: domain of 3eocaxwukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3EocaXwUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fB9xuI4a/kuAlgwz1LZfwuCsyLwijwHvHTkfv8NHd+o=;
        b=TnewCgOxetLzdfkNGtY3dqRxccvzWPvF3glsmvGwLGH4yXAXahNlVxegFfRQt4uk9G
         tiwaJaeE5D1eRjPcFts3WoUbo2yW6tWNhwJ8ruUJ4JCj9Dw0P//CL9pCEYiG6occWNOq
         tHa2eVPeyYP78za3A/EK6+NKb8arbv8UXXABF8zWhc/1MrxIKbzqzHniJIU4Q124mPNt
         vzBUrUYDqHptFOXWtOT8mIWsrfVrtC6S/gJ5aM/fUdAFsefDSuBTXkopeRfkw4pOuE/a
         tQJryZSbLOv34hnXEb6dMc4VqFxJ9m4xKmlluJp9aw4M1H+AbvIGumpeM8ZijHYHtHe9
         ouiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fB9xuI4a/kuAlgwz1LZfwuCsyLwijwHvHTkfv8NHd+o=;
        b=F/VN0UAThzGGQfO96aVGYd9uprkn+nYyMBW2TcSmkuWZKIqDWqs93gOt01cpiWypUa
         DIki7rHD+n0gWRr/BGx/A5NCwWgOi3rA5oRoREV7jzk9zi4wwluwPJs/F+1n1syV4VyC
         5sd0dIJh+2IohjiSgKAjjXbuHdKMXxb1DUWPfIPBVffjkMs2qBS7+A9bXOb/stZZXr19
         ViqB9RiGueVhEZiWdopUoEZPCmYK/YjyD4JcTXRYCK+1FCHOESy46ropc1uMLHH2i+tY
         Xmxy6jlgl/IJdlqVdtZV6HCvtK+yAmSRgppK9PV5tscwq2/feZKdZP6C6Zar20n7Wa2N
         /ZDw==
X-Gm-Message-State: AOAM531yPk5T2BJT2uepgl+PSRWO6cNyhVkr0OdT0Xt0c9jovVnch5oq
	yVNEnJzsKb0I2XJyvucrZ4I=
X-Google-Smtp-Source: ABdhPJzcQrqiYDt1+xwfB8TLnhz6BLPdumKXXv/NIZ2FjKuRDr9rPVbr17jCaIjBrg8gMS1o3+p4Uw==
X-Received: by 2002:a50:c3c3:: with SMTP id i3mr2238253edf.78.1595574035532;
        Fri, 24 Jul 2020 00:00:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1d37:: with SMTP id dh23ls5922597edb.1.gmail; Fri,
 24 Jul 2020 00:00:34 -0700 (PDT)
X-Received: by 2002:aa7:d650:: with SMTP id v16mr7556243edr.361.1595574034874;
        Fri, 24 Jul 2020 00:00:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595574034; cv=none;
        d=google.com; s=arc-20160816;
        b=XUX9AKjoRtRbyreNOUaJYl4qmsCuYTHI0cs601t2q8+8jNZsdlPWKUPQ2F8CvHL3/o
         EePkwI/JleLSSD8Usj5+Om9ofVmkcGOhPipEiNOHMl8p1g5EfIxQb68Y9pgDx65Ye321
         SOylhNfoTLaAylvMd9sppqWEQ0uGRfno56SZ2nFAZ2469dGDx2w9zdshaHzQCav4gndU
         HCmK4+GrXkWe0IjbXOhpaGfCUWUHy2AajwQPLDXNNcWuha4G/yQijPcEv/0L/WgHbenW
         XpApqaYdCMNJTKlGQr+yHkMGUUak0oDn0BSu75WOFKDZdUH3kw2St86vdWkwy1qtrMg2
         9olg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ZaqDMwLk6PPGhSBflviL3tpxd3/gyTDsl7bIZ5aTHls=;
        b=HhmCYNUbAeY5SH+3Y7x1Kf7OdGLbIO/Y/aV4pBA9arRcb5PfOGZJWOhiZ7Yzg8sYEH
         APTbAQ59QWvlxi32mwS8ZeCH4quRsZgnUR67Ir9DB9oenTt+XwyEiHH+ANJ/2pVCIc/5
         5oGzCwzLGW9ppkkUxdDXBqREKW9Ry7JBMefoflgXYS+6nhEIl4bjmLPsV4yKhusz+O7M
         cmJRWMb4R5NzABoyOzppWDSQpAcmNjQTU3MPYTR0jLAv1JOEdDDAprhsoNNmw3RT0o9S
         KhL0UxqZl93PVBxKK5du+LteRCgKV7OSiTg/pTF2RH3inrpJRg3M0E/I1whzKbDTIV2i
         4gEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mu+faoc3;
       spf=pass (google.com: domain of 3eocaxwukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3EocaXwUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x149.google.com (mail-lf1-x149.google.com. [2a00:1450:4864:20::149])
        by gmr-mx.google.com with ESMTPS id o23si5145edq.5.2020.07.24.00.00.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Jul 2020 00:00:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3eocaxwukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) client-ip=2a00:1450:4864:20::149;
Received: by mail-lf1-x149.google.com with SMTP id m13so1951980lfr.18
        for <kasan-dev@googlegroups.com>; Fri, 24 Jul 2020 00:00:34 -0700 (PDT)
X-Received: by 2002:a2e:8618:: with SMTP id a24mr3774032lji.302.1595574034152;
 Fri, 24 Jul 2020 00:00:34 -0700 (PDT)
Date: Fri, 24 Jul 2020 09:00:05 +0200
In-Reply-To: <20200724070008.1389205-1-elver@google.com>
Message-Id: <20200724070008.1389205-6-elver@google.com>
Mime-Version: 1.0
References: <20200724070008.1389205-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.rc0.142.g3c755180ce-goog
Subject: [PATCH v2 5/8] kcsan: Test support for compound instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, arnd@arndb.de, mark.rutland@arm.com, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mu+faoc3;       spf=pass
 (google.com: domain of 3eocaxwukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3EocaXwUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
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
v2:
* Fix CC_HAS_TSAN_COMPOUND_READ_BEFORE_WRITE: s/--param -tsan/--param tsan/
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
index 3d282d51849b..f271ff5fbb5a 100644
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
2.28.0.rc0.142.g3c755180ce-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200724070008.1389205-6-elver%40google.com.
