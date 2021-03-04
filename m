Return-Path: <kasan-dev+bncBCJZRXGY5YJBBC6ZQCBAMGQEWBULI2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id DD20F32C3A9
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 01:40:44 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id o23sf6548774oop.9
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 16:40:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614818444; cv=pass;
        d=google.com; s=arc-20160816;
        b=kPHipQ3npTkzN8azgLFkPAgsS7as9bypNlIHJQJ2SOJniZigS1fqaGGBjVjptsZoqo
         7MVJmLkOmKL9RNu5mvM6aVbuQM/nyDom7HtnmSaGcHKi/pED4KKb4iVHq2La7rfFt0GM
         d+DUGvrVWQhHFdDKdnZGaN6V+isHSgAX3R5Llvp3AXNltIAxkvlS9aYJYKXTIQ+Rnnll
         VdeUfV1eB3RhwjY1uRdupZHDJLcpNYKDK5yrtl/eFoshcEyYw1XspRAv8gyH0T7cL6bM
         YgOpbuTI5dYqtBYyokSKHVJ1G0OqYrk96e1pM3dReu0XFDFMV0SpvPpJA9NR2ySflF/a
         lr8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=EiE5kFmoHMk/Qi9x9ROgrGAza3goMbs5s2NMlFIWpwc=;
        b=MivI6Xn4A9+LFpnr+SP4za5HyHZkPxb6tBPWNy/YGua/ypZLSc4eJDtbMORUVl31g/
         2UBFriS5uhxezxODKTJXldAK1Hwb9bwHdIvKs0y6YRy5lpLHkiUkyJQdkfhb0Pktoeu0
         OED6wTls4Cs0bZuQHYK8m05zq1dLX2uagUNXdytgqCUPO48M5cNUo8Za2ziP/QqLPCqp
         QfD8iebcucCtvON3w5N6bxunVaUdwHWlMplhb7N8DY2TWwSIKBoo+ySYz8kCHzo1w0AK
         JTZQGXXL9/G7Y/riPXFfT6o4gXQb+UzejMNqXkU6Y6TicN6aYM0DuDMGTe7QyRZjI8cP
         dfuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rlF81TFn;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EiE5kFmoHMk/Qi9x9ROgrGAza3goMbs5s2NMlFIWpwc=;
        b=EvaUJLGAFCqbP4kYaygYT7IsMNNtth2zI2FcMMNFK+FmaKa6CZu89+wpvjDEgj/BOe
         4Q7auOw6x2ybj6W5fzWhVWqRMvQeLAVDH8MTeObzf7QlfeSsn0qH7ozGy5mB++8uYQqm
         DXP6bep4Kp6PIzQ54xYivq4nIF4NjD/Du0XcqSxxPApvrA/ci92zDiplJr7j3DbiGp9V
         lruk6u2XVZmdjFXUIgYraem2zoonQ7KlaPsGsoZAf8Xv9zqD0eUGdkadqIp+KBmWZoJg
         b4G00pIDmYZ3iVnXkSBGKgVCGNgW4PukXNUZvhpEg2NM7D+4Llgbt10ySQt8TfWRzxDk
         6HZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EiE5kFmoHMk/Qi9x9ROgrGAza3goMbs5s2NMlFIWpwc=;
        b=RS+KQ+YBM0NjXM7y6RV7qYjZoOqo+povuEFeRgm49ucLGuOXM3uTnbp7sfQfPVuKb6
         fqcHoKfB66ffOVxXGGGaKrbnJUriNGIvnbcndxratnq5KIcplNNyvwjdQjEng4697cDY
         x95ju2EsCy3lvfbH3+q28qWYkwUg9/aezYeQ2EMWVJeCa5AIDKsFXZl3AaKG0LiY2ONt
         me8L4sZo0Pqr01ZZTz0yc8hKS822tJaIuCDLQxpl96+ZJb3nNtXWFc4wTJA/JPfhN+LA
         hEQARHARcdBebPIXl+D/VvfjUXyYyjbE0fTLUMx81WKobfgIWi6Q6SzzLKgPJObBg9kJ
         cOMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Q5Nb5mG6gn6YAddmleLnNvsPaPiw1SkzNzcCkZsiGS1GFVzFh
	rxuztPB7oy7iDutud2e7m3s=
X-Google-Smtp-Source: ABdhPJyp8/kgwhCFy85NVcsaxZSEleD7V0D5RAoU4/isY6do2ksqRXuJnmyHJc74syxs2Z5NWsAOJw==
X-Received: by 2002:a05:6830:16d8:: with SMTP id l24mr1492404otr.200.1614818443917;
        Wed, 03 Mar 2021 16:40:43 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1553:: with SMTP id l19ls1115433otp.4.gmail; Wed,
 03 Mar 2021 16:40:43 -0800 (PST)
X-Received: by 2002:a05:6830:1352:: with SMTP id r18mr1474177otq.283.1614818443497;
        Wed, 03 Mar 2021 16:40:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614818443; cv=none;
        d=google.com; s=arc-20160816;
        b=Tf88B/tuco08xO5lavsB+GYuBOdbHccxwYLSt9NqF0GMMgaIHgdEWuIFxI1TtIHyLk
         WORmtCXKPNcfjUXxmsbfpKXDKsF4aNOFTSstn8dPolmAKaAWVMZfydcsuO8u1gI1j50i
         vw7nTc8x3ZL4hGu/jK1FvDBkeAPt3TClSkYviWG1UsfVkmysf7DUCoU0hyzatMP8VOQf
         lrY6J5NiavjE3CYx95UghwaKSmCr+NFlsWCLDm8AtdSI3npKpYa9U/f7pn2/5B2ZYwRy
         P93Ie72MuFKx0MZJQQK5Qc7Hi6RaM92IYXQMbHK2fYJK3SuOwzfCuK0wQc6FCHddYU0K
         AvhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=GzHKrNxQqIQBhIMd95/inH5ir0C2mbYhCBLz6U8Bab8=;
        b=k6hJkQf7N3iSpd1HZwAlvltl8XiacxkrPmGYtmL2LGj2h4qMa/a4QOgvLmw3iMdOS/
         eWkVmObsVulTRfZ7dVojRIIxqJFcF6lhLilbI2RYuF2LpsF+1r47EpBGzC+f4BU+0nXm
         M+wpw6Q9OMtZvfoQ5qNT4KEuCnMOdZCQj/Az3z7VbNBgA+e4m8kIEPiESDXD7t8Dl157
         PmiK1m0ukJcbc8kyP60qoYAi3s3HUG0fuPQiXNqS10BauVplDHFRMpXwkQjJM1tRlQhH
         PTFKudyBuW+LnMFoBoX2x3n4w8HVf9D48SRUMrkaq25lkbR0mv/Vu3U391/k4LkonhpH
         SW9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rlF81TFn;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q10si1621952oon.2.2021.03.03.16.40.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Mar 2021 16:40:43 -0800 (PST)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id A32DA64F02;
	Thu,  4 Mar 2021 00:40:42 +0000 (UTC)
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
Subject: [PATCH kcsan 3/4] kcsan: Switch to KUNIT_CASE_PARAM for parameterized tests
Date: Wed,  3 Mar 2021 16:40:39 -0800
Message-Id: <20210304004040.25074-3-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20210304003750.GA24696@paulmck-ThinkPad-P72>
References: <20210304003750.GA24696@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rlF81TFn;       spf=pass
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

Since KUnit now support parameterized tests via KUNIT_CASE_PARAM, update
KCSAN's test to switch to it for parameterized tests. This simplifies
parameterized tests and gets rid of the "parameters in case name"
workaround (hack).

At the same time, we can increase the maximum number of threads used,
because on systems with too few CPUs, KUnit allows us to now stop at the
maximum useful threads and not unnecessarily execute redundant test
cases with (the same) limited threads as had been the case before.

Reviewed-by: David Gow <davidgow@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/kcsan_test.c | 116 +++++++++++++++++++++-------------------------
 1 file changed, 54 insertions(+), 62 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index f16f632..b71751f 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -13,6 +13,8 @@
  * Author: Marco Elver <elver@google.com>
  */
 
+#define pr_fmt(fmt) "kcsan_test: " fmt
+
 #include <kunit/test.h>
 #include <linux/jiffies.h>
 #include <linux/kcsan-checks.h>
@@ -951,22 +953,53 @@ static void test_atomic_builtins(struct kunit *test)
 }
 
 /*
- * Each test case is run with different numbers of threads. Until KUnit supports
- * passing arguments for each test case, we encode #threads in the test case
- * name (read by get_num_threads()). [The '-' was chosen as a stylistic
- * preference to separate test name and #threads.]
+ * Generate thread counts for all test cases. Values generated are in interval
+ * [2, 5] followed by exponentially increasing thread counts from 8 to 32.
  *
  * The thread counts are chosen to cover potentially interesting boundaries and
- * corner cases (range 2-5), and then stress the system with larger counts.
+ * corner cases (2 to 5), and then stress the system with larger counts.
  */
-#define KCSAN_KUNIT_CASE(test_name)                                            \
-	{ .run_case = test_name, .name = #test_name "-02" },                   \
-	{ .run_case = test_name, .name = #test_name "-03" },                   \
-	{ .run_case = test_name, .name = #test_name "-04" },                   \
-	{ .run_case = test_name, .name = #test_name "-05" },                   \
-	{ .run_case = test_name, .name = #test_name "-08" },                   \
-	{ .run_case = test_name, .name = #test_name "-16" }
+static const void *nthreads_gen_params(const void *prev, char *desc)
+{
+	long nthreads = (long)prev;
+
+	if (nthreads < 0 || nthreads >= 32)
+		nthreads = 0; /* stop */
+	else if (!nthreads)
+		nthreads = 2; /* initial value */
+	else if (nthreads < 5)
+		nthreads++;
+	else if (nthreads == 5)
+		nthreads = 8;
+	else
+		nthreads *= 2;
 
+	if (!IS_ENABLED(CONFIG_PREEMPT) || !IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER)) {
+		/*
+		 * Without any preemption, keep 2 CPUs free for other tasks, one
+		 * of which is the main test case function checking for
+		 * completion or failure.
+		 */
+		const long min_unused_cpus = IS_ENABLED(CONFIG_PREEMPT_NONE) ? 2 : 0;
+		const long min_required_cpus = 2 + min_unused_cpus;
+
+		if (num_online_cpus() < min_required_cpus) {
+			pr_err_once("Too few online CPUs (%u < %d) for test\n",
+				    num_online_cpus(), min_required_cpus);
+			nthreads = 0;
+		} else if (nthreads >= num_online_cpus() - min_unused_cpus) {
+			/* Use negative value to indicate last param. */
+			nthreads = -(num_online_cpus() - min_unused_cpus);
+			pr_warn_once("Limiting number of threads to %ld (only %d online CPUs)\n",
+				     -nthreads, num_online_cpus());
+		}
+	}
+
+	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "threads=%ld", abs(nthreads));
+	return (void *)nthreads;
+}
+
+#define KCSAN_KUNIT_CASE(test_name) KUNIT_CASE_PARAM(test_name, nthreads_gen_params)
 static struct kunit_case kcsan_test_cases[] = {
 	KCSAN_KUNIT_CASE(test_basic),
 	KCSAN_KUNIT_CASE(test_concurrent_races),
@@ -996,24 +1029,6 @@ static struct kunit_case kcsan_test_cases[] = {
 
 /* ===== End test cases ===== */
 
-/* Get number of threads encoded in test name. */
-static bool __no_kcsan
-get_num_threads(const char *test, int *nthreads)
-{
-	int len = strlen(test);
-
-	if (WARN_ON(len < 3))
-		return false;
-
-	*nthreads = test[len - 1] - '0';
-	*nthreads += (test[len - 2] - '0') * 10;
-
-	if (WARN_ON(*nthreads < 0))
-		return false;
-
-	return true;
-}
-
 /* Concurrent accesses from interrupts. */
 __no_kcsan
 static void access_thread_timer(struct timer_list *timer)
@@ -1076,9 +1091,6 @@ static int test_init(struct kunit *test)
 	if (!torture_init_begin((char *)test->name, 1))
 		return -EBUSY;
 
-	if (!get_num_threads(test->name, &nthreads))
-		goto err;
-
 	if (WARN_ON(threads))
 		goto err;
 
@@ -1087,38 +1099,18 @@ static int test_init(struct kunit *test)
 			goto err;
 	}
 
-	if (!IS_ENABLED(CONFIG_PREEMPT) || !IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER)) {
-		/*
-		 * Without any preemption, keep 2 CPUs free for other tasks, one
-		 * of which is the main test case function checking for
-		 * completion or failure.
-		 */
-		const int min_unused_cpus = IS_ENABLED(CONFIG_PREEMPT_NONE) ? 2 : 0;
-		const int min_required_cpus = 2 + min_unused_cpus;
+	nthreads = abs((long)test->param_value);
+	if (WARN_ON(!nthreads))
+		goto err;
 
-		if (num_online_cpus() < min_required_cpus) {
-			pr_err("%s: too few online CPUs (%u < %d) for test",
-			       test->name, num_online_cpus(), min_required_cpus);
-			goto err;
-		} else if (nthreads > num_online_cpus() - min_unused_cpus) {
-			nthreads = num_online_cpus() - min_unused_cpus;
-			pr_warn("%s: limiting number of threads to %d\n",
-				test->name, nthreads);
-		}
-	}
+	threads = kcalloc(nthreads + 1, sizeof(struct task_struct *), GFP_KERNEL);
+	if (WARN_ON(!threads))
+		goto err;
 
-	if (nthreads) {
-		threads = kcalloc(nthreads + 1, sizeof(struct task_struct *),
-				  GFP_KERNEL);
-		if (WARN_ON(!threads))
+	threads[nthreads] = NULL;
+	for (i = 0; i < nthreads; ++i) {
+		if (torture_create_kthread(access_thread, NULL, threads[i]))
 			goto err;
-
-		threads[nthreads] = NULL;
-		for (i = 0; i < nthreads; ++i) {
-			if (torture_create_kthread(access_thread, NULL,
-						   threads[i]))
-				goto err;
-		}
 	}
 
 	torture_init_end();
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210304004040.25074-3-paulmck%40kernel.org.
