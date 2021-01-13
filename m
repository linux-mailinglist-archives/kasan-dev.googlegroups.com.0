Return-Path: <kasan-dev+bncBC7OBJGL2MHBB65U7T7QKGQEZGRMQUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id BC7132F4F75
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:06:20 +0100 (CET)
Received: by mail-qk1-x73e.google.com with SMTP id w204sf1660247qka.18
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:06:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610553979; cv=pass;
        d=google.com; s=arc-20160816;
        b=lULLsj2Oh6mL7YBGV1JGicDB4whvxYz/VVc5wuzciGfgk6v7iziY05OAfBCMKD+rQw
         kG9KPy1nXMVFM4GraHwkIuaeBRrbRAbPmb/w4uZP1wcGM5wk79+Nayat8PHRmetjDuDI
         sVhmeQok+cc1udNauwKHIxI/tf/LAVUuN+g9OZf8LQXDA5LILSmRB+TWx/x9lgVSPLgG
         Q30iK28BsL3yEmVfEW5TLdJTXVQy5ZX8FOo18v8caAD1IalBODp+Z/j3KPmzvTHha/lk
         22JB5RAAtZG3eb//C4d2e0CX4am+/0WXnoiJ92uX8qbK9DsYLgsdUCk86QNMv2D6a2hD
         pj+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=tqjz6MZlBQ0c3JIz5w+iLTDXOtUR3Ywxi6+DWqnrUpY=;
        b=TexQlTxWFPWsU3SITKF4zkTKLOX0umXiZcDOZb8aB7ugcrYBiqIEy04GBRngz6lVgK
         ObvSIUVBfULRXwiKygg+c7IJg7svmbVPwFfC01GCMcBYNuyDbKJSy+oGzMc2WSXcRRfr
         Wmq7A3wzYzjy5W4j/sgIV2vdZHWJoKTyvWStvenXONjhL4aMDSC14osSUrLMHF/6Sk0X
         3G776NM781nSUXKdSmbdFlmQxy11q67vf3e9VqbsuOqI6vLR0dhNiVWiQgSpgqPjKfSS
         dSMx34+HBpKlFNh6sCzcEIs46MYwCvK0aEA2ih6xjruGSG+HLpaZuUHPgnZ/tqL0FpKL
         LhlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=q3+44RYz;
       spf=pass (google.com: domain of 3ehr_xwukcbevcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3ehr_XwUKCbEVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tqjz6MZlBQ0c3JIz5w+iLTDXOtUR3Ywxi6+DWqnrUpY=;
        b=mJuLg9Lp1FdNbZRX3fm1L0Ix1bbWqAFh2vxfX0lT7ks9ShMnqV+ritoZ5a1z5Qa31i
         l9WdFmy1O6xZ26qz/7Qzml8rK9J2YtWjoKUUFjkYw2f/KZoic5hUGCpNyyoN5XWCp7Ko
         JwBDzV4SvYeV5SUYGNdK3nIQbzg/hIqRegW77xek3ezxiZwYEKs5uzGxgCadbU3NpfnN
         I23UEW1vT4u0G8nGshjKaGp0W3QzjJhGGZ8lzyPwJHZnsEYGFi6OXje/QGPMdQsNAspn
         Qo1U9mtYrfhoth5KB4aHCU2UWgG33ZlbYqZxtJJzwFqq3vJUlFSGIa8Wh1pwTkDQfmrb
         17gA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tqjz6MZlBQ0c3JIz5w+iLTDXOtUR3Ywxi6+DWqnrUpY=;
        b=SbckA6ZS6qcl6Bkk/KJZhEANqsmCu+KLscuLoQQq0uwelVXnnf8VOwyIfiGJZU05lO
         nsjtRHNw2m+s6QMpILabOOcIcay5G0NylsyR8b5e6GyKWPSjyOQ+vj1qhyDGpm3JNecy
         XbunJ2/aZpqfJp0H3zBiMXfnhLbZXKWiMvr6v5TMh4RkgbCrcpgO465xfJbdLwx501b3
         A2uwt04xdmhBuRqM1xSNnT4LN6tpL2X9hoqGs4Wr43zXXEUQtR5JVfg2KhTM13URs5DT
         9KPgyi1IYN7Y1TuFxj3ISoC6ORh41y2H2hPUKfZ0Lov3DDOo3hKXqyzlt4UtbXPgQ7Gi
         nm/Q==
X-Gm-Message-State: AOAM531uR++8pbQze+M/wgVHrOTmtHz5iyNh1jQ84TYmFIc9wWLFAu8y
	iqbug7G4M/4uNQRGA5B51Tw=
X-Google-Smtp-Source: ABdhPJyp8vdCOSwzynaz6tx/3yQv2htu92hfr5ZhIAA6z/d0I8j/UeSXqnA7PgR2hkFkdGYMK8x8Cw==
X-Received: by 2002:a25:6405:: with SMTP id y5mr4434103ybb.328.1610553979571;
        Wed, 13 Jan 2021 08:06:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ff19:: with SMTP id c25ls1199251ybe.2.gmail; Wed, 13 Jan
 2021 08:06:19 -0800 (PST)
X-Received: by 2002:a5b:b0f:: with SMTP id z15mr4326704ybp.296.1610553979064;
        Wed, 13 Jan 2021 08:06:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610553979; cv=none;
        d=google.com; s=arc-20160816;
        b=pCXjVNBuZ1lPjihoMqtM6vwPLBIvOfyGo/UDEWcVPSiK3mrLd6r7TR/S5megCIRUHs
         KiTxALZFvQvrsiuTsWvUbwCylFtOPFURN2rAJvhWn8ARIOg2xXhafCVpdGGWQ0JmIONI
         smChxEC4viIGDeSFtIRgUfoBXxksmbGp6umyrjWt1dYpDLKT0yiVB7yXVAq7rr3ePSF/
         8IC5yoDOxtI0pG6wrTiBlSbyy/rZI4uRqe4wNg3Kd49D7HGIcuW/MT9ZH6HHPhEDpZPB
         9ivWsHrO77xFE0V6HLVSN+f5obHZVbzBH8z9Yvkm6AlFPCFLTn3yq45zTMQcAoUBYZtg
         ptnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=JSaOZgBM+NKre49h7oSv83dotWqimUT6GB75MwXSDhM=;
        b=PXAeKUy0vI5g0oTiqRkfrSCO5qWZIjatoLMSNBXyDbkRwTVWxZGHML0MmwvbRncDJj
         tEmxBOF4JOlGQA2mLHEFabFgfTQtku3DjV1gIk07TRxjcOBFsT/2NYMECOaaN4i0ZKMe
         dXo4dxlfj7taEHblZ7Tiyi4X6XL1FyNggD2TXHqGeJevbQMWX2Xd6GGZ7iIjez3KW7ZM
         UNie5SHiKORwW31uuJOR9hbLtMKnGMbc4FlRRlfRzXnvh+viJWWiirV/V5EV8hEyIMYp
         tPEbtEE776TF/8h/3cx67WHJJHuDytqOAz254sqvD4AN7GX2N2zmHMLpGy6Yu30Z2jgM
         5+Pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=q3+44RYz;
       spf=pass (google.com: domain of 3ehr_xwukcbevcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3ehr_XwUKCbEVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id s187si192593ybc.2.2021.01.13.08.06.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:06:19 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ehr_xwukcbevcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id k12so1663686qth.23
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:06:19 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:ad4:4c50:: with SMTP id cs16mr3080778qvb.33.1610553978623;
 Wed, 13 Jan 2021 08:06:18 -0800 (PST)
Date: Wed, 13 Jan 2021 17:05:57 +0100
In-Reply-To: <20210113160557.1801480-1-elver@google.com>
Message-Id: <20210113160557.1801480-2-elver@google.com>
Mime-Version: 1.0
References: <20210113160557.1801480-1-elver@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH 2/2] kcsan: Switch to KUNIT_CASE_PARAM for parameterized tests
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: dvyukov@google.com, boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=q3+44RYz;       spf=pass
 (google.com: domain of 3ehr_xwukcbevcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3ehr_XwUKCbEVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
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

Since KUnit now support parameterized tests via KUNIT_CASE_PARAM, update
KCSAN's test to switch to it for parameterized tests. This simplifies
parameterized tests and gets rid of the "parameters in case name"
workaround (hack).

At the same time, we can increase the maximum number of threads used,
because on systems with too few CPUs, KUnit allows us to now stop at the
maximum useful threads and not unnecessarily execute redundant test
cases with (the same) limited threads as had been the case before.

Cc: David Gow <davidgow@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/kcsan_test.c | 116 ++++++++++++++++++--------------------
 1 file changed, 54 insertions(+), 62 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index f16f632eb416..b71751fc9f4f 100644
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
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210113160557.1801480-2-elver%40google.com.
