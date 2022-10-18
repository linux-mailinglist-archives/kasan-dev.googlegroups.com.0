Return-Path: <kasan-dev+bncBAABBFV7XONAMGQEJXMATJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A8CD603169
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 19:17:11 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id v125-20020a1cac83000000b003bd44dc5242sf11513498wme.7
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 10:17:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666113430; cv=pass;
        d=google.com; s=arc-20160816;
        b=p2oR0z+LZ89U47c77f0iXhYaZhXncHF9ozW9kQG/mRicFvVEKoUGv4u5n5/wo6rz2g
         AZeRloUcc6yP/ArltRCrVF6ZrM7a5/c+0p6m3RvAc0olls3n8SydmelQVJ7M9P3Ul/y3
         VhsyO92zmn53vMYdXzUmfjJUqZIplfsMXjsKm44qQx4Wky+jRxMoprFW6vBbcvQKqMYx
         lFxwtEpZ5NZiEbhZZ+pB4DyaPhrvLRdSkZD7qVHkzPoLXZxOh+hrPYG9hDOPtECaZIFz
         bOqK9B7Q3Pgerps1HWHCvmzb0RedElfcpV0fjuz70Uqj/btWfAhCT/uj5vHOJXrji6wF
         qn8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=E3XzH9tBf2AS1t2THv+1l+8kdPmg/0p/6hG39lIKWX8=;
        b=ZYhP5SW7+jGdj+7tIdg7d6DCu7JG9wxXT6P5XpmcUV4BmhMU4l2M5ZPSpwHOXe0rYK
         vgzp/Bu6lyUQVvwOd8pDnqdPYFDEeVWE8Sg8QFGigNZhseVP2+0Bl+91eRr7ZOTnKQD6
         mXOHuLBoi0+CBkciRGFTQT1LOmfxX0FA6rg1P2Rnuj+93QtjbDh/Ssc/szSOb6xvIiei
         6bLHLYEtn98tq7pDzDiNkf0zTteDrsl7A15vZ2cVP9pVqGCXRQubq33eFF17k/7t8Ocb
         Y67fYx4LsJdtcQFsPAdbpSypMTiJn5G+sD7ZZe4NRzBpm2XiMzlvU8bSpS3BPwnIEz4j
         jdEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="guGKFGP/";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=E3XzH9tBf2AS1t2THv+1l+8kdPmg/0p/6hG39lIKWX8=;
        b=pxYeamR0Raof+t7DSzBV4Igti/eYjn7egcb6bPpEIr9IZ7ca9yWzPhjIw2wWntThv9
         GFtAWqj3Tj77QcJnv3D7q0NuJRevWU1gxb1y6jW57YBlaoRs3NZUCLw1FN0YfFxn45uv
         sKGQcgVQ+KByAxAS1ShFbYARMOb7seigQ4q9n37Jq6LzMUnrRJvHpBSCAZJbIUpch+1d
         HwMt7P+vfc0bGjMjRQ92Y849yTy8EfjukC3KRyOXofuEf7O4PhTsobSathxtAHOJInDs
         oO+5Hw9hDCdm/K8s3R+EUT2xsO6jeSdRDrcn/Zz49OwSoIU/8V1wPHwwankZdaQ0OCQ3
         cznA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=E3XzH9tBf2AS1t2THv+1l+8kdPmg/0p/6hG39lIKWX8=;
        b=35mvDxNrFAAL/AZU4ZPG8nRKBTAtElObn98d3XJdlqdSZsZ/3i7VEv6F8tyO2h8W7t
         0Hx1Ll2Bc7X9lcyMS5L5Udwg53Y/6n5qP1QSw3ZNJu95jGl4r38nXMfWiU4UOP3QrATn
         BqFj1xh77KL16ahXmP20FVcVlIpfhR0zdT6pWoVyIx7TLeRIHm+at5w1GTypCmDc1FiW
         r3gZMzZNk0IPdsOTCbaofbc01AS0G4qlv01cAk/hQzbldV4AZp8Xw8VLjp3ubMpkK/Gb
         Q4WjgrZLe4/tuUEjLdePEq/K4BFaWpIyu4foiLItKFb3IBU7mImwkonFDZWjzhc5zWCv
         Rgdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2G/TVx5HoalPdVZ3yMe83zGoi4UErBnGUAR8OAtXiuoA1LyQMo
	TLyfGa8Iykrq7Dchq43UNpA=
X-Google-Smtp-Source: AMsMyM6u4Zo3IfDLFBOo3tEVJBkl1TW0C/PTqK46QPUW44ZSr2Y5/2mXfZKXb+/G7ux8vTFQ0EYZOQ==
X-Received: by 2002:adf:f00b:0:b0:22e:3439:cff2 with SMTP id j11-20020adff00b000000b0022e3439cff2mr2723340wro.719.1666113430461;
        Tue, 18 Oct 2022 10:17:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:2:b0:3c5:a439:23df with SMTP id g2-20020a05600c000200b003c5a43923dfls9786577wmc.0.-pod-canary-gmail;
 Tue, 18 Oct 2022 10:17:09 -0700 (PDT)
X-Received: by 2002:a05:600c:5388:b0:3c5:4c1:a1f6 with SMTP id hg8-20020a05600c538800b003c504c1a1f6mr2826178wmb.11.1666113429672;
        Tue, 18 Oct 2022 10:17:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666113429; cv=none;
        d=google.com; s=arc-20160816;
        b=cdKcS9UrwESnQrJtG74SyfNNUQUzRfdURK+ShTpE9YYk4eyva5i0XcK0l8sfZVXG/f
         1vjNd83zrrxZYd3UmBU819Z8F0+urq7N1+F70vUaf2145tjrluwBFE5qnBmp4YZqROj0
         apBJ4eUJ4nR+WKN56VPwYxbJeKsCKASQ8kzLpzEGBaG7csKJf/mkz/Jq2K4vaXlhC0iC
         jzwpF3QQr68+QAei3XbGSOz3tw5IaeyVaiJwNRhv5o5S5DZmIFYhpfPXe/sRX+cuASCA
         LnVIDqRDIib534nBMi7PunDxDrc2CLHxfvQsKVghYGXy2IBLqIW6PBcB0qV82zK+qrEa
         m+VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=5qXG9FN8q1BZCzLXn/AJyCLf0ifsZsE4nXpgEgyO44I=;
        b=FfGEJEN0b18yLVlNcfee8e0v+MZ4tIPxUCxHGnA+SuUp+bzd21f1csqYr+m2r1O1mQ
         D+G18Y07mKdhrpOUH94e+xIzoNkPpgC10MtzAMOjV5PzTffD7Aw/fvsGFT4B5e8L3Aqj
         OqekBzzH6kB+kGr1zJHGK5nfj0PwFM19FcCMvZMITjCSjKu/62tGuaqxwejm/ekOVT2g
         lKdOtY8sTufaVMJkzm7ALmxHh/EnMMzIWE1dSK2eyTKCnw4jqyVgdIueEDLKvrNK6anA
         RYrkTNdjR32KaARmZiw9wO6qIR69CVqsNpB0lZOLTTVrt5uXs8FkCx7eV5SJ3K5G/sAP
         W+hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="guGKFGP/";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id az27-20020adfe19b000000b0022f74ffaae6si480917wrb.8.2022.10.18.10.17.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 18 Oct 2022 10:17:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3 1/3] kasan: switch kunit tests to console tracepoints
Date: Tue, 18 Oct 2022 19:17:04 +0200
Message-Id: <ebf96ea600050f00ed567e80505ae8f242633640.1666113393.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="guGKFGP/";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Switch KUnit-compatible KASAN tests from using per-task KUnit resources
to console tracepoints.

This allows for two things:

1. Migrating tests that trigger a KASAN report in the context of a task
   other than current to KUnit framework.
   This is implemented in the patches that follow.

2. Parsing and matching the contents of KASAN reports.
   This is not yet implemented.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changed v2->v3:
- Rebased onto 6.1-rc1

Changes v1->v2:
- Remove kunit_kasan_status struct definition.
---
 lib/Kconfig.kasan     |  2 +-
 mm/kasan/kasan.h      |  8 ----
 mm/kasan/kasan_test.c | 85 +++++++++++++++++++++++++++++++------------
 mm/kasan/report.c     | 31 ----------------
 4 files changed, 63 insertions(+), 63 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index ca09b1cf8ee9..ba5b27962c34 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -181,7 +181,7 @@ config KASAN_VMALLOC
 
 config KASAN_KUNIT_TEST
 	tristate "KUnit-compatible tests of KASAN bug detection capabilities" if !KUNIT_ALL_TESTS
-	depends on KASAN && KUNIT
+	depends on KASAN && KUNIT && TRACEPOINTS
 	default KUNIT_ALL_TESTS
 	help
 	  A KUnit-based KASAN test suite. Triggers different kinds of
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index abbcc1b0eec5..a84491bc4867 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -261,14 +261,6 @@ struct kasan_stack_ring {
 
 #endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
-#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
-/* Used in KUnit-compatible KASAN tests. */
-struct kunit_kasan_status {
-	bool report_found;
-	bool sync_fault;
-};
-#endif
-
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 0d59098f0876..0ff20bfa3376 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -5,8 +5,12 @@
  * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
  */
 
+#define pr_fmt(fmt) "kasan_test: " fmt
+
+#include <kunit/test.h>
 #include <linux/bitops.h>
 #include <linux/delay.h>
+#include <linux/io.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
 #include <linux/mm.h>
@@ -14,21 +18,28 @@
 #include <linux/module.h>
 #include <linux/printk.h>
 #include <linux/random.h>
+#include <linux/set_memory.h>
 #include <linux/slab.h>
 #include <linux/string.h>
+#include <linux/tracepoint.h>
 #include <linux/uaccess.h>
-#include <linux/io.h>
 #include <linux/vmalloc.h>
-#include <linux/set_memory.h>
+#include <trace/events/printk.h>
 
 #include <asm/page.h>
 
-#include <kunit/test.h>
-
 #include "kasan.h"
 
 #define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANULE_SIZE)
 
+static bool multishot;
+
+/* Fields set based on lines observed in the console. */
+static struct {
+	bool report_found;
+	bool async_fault;
+} test_status;
+
 /*
  * Some tests use these global variables to store return values from function
  * calls that could otherwise be eliminated by the compiler as dead code.
@@ -36,35 +47,61 @@
 void *kasan_ptr_result;
 int kasan_int_result;
 
-static struct kunit_resource resource;
-static struct kunit_kasan_status test_status;
-static bool multishot;
+/* Probe for console output: obtains test_status lines of interest. */
+static void probe_console(void *ignore, const char *buf, size_t len)
+{
+	if (strnstr(buf, "BUG: KASAN: ", len))
+		WRITE_ONCE(test_status.report_found, true);
+	else if (strnstr(buf, "Asynchronous fault: ", len))
+		WRITE_ONCE(test_status.async_fault, true);
+}
 
-/*
- * Temporarily enable multi-shot mode. Otherwise, KASAN would only report the
- * first detected bug and panic the kernel if panic_on_warn is enabled. For
- * hardware tag-based KASAN also allow tag checking to be reenabled for each
- * test, see the comment for KUNIT_EXPECT_KASAN_FAIL().
- */
-static int kasan_test_init(struct kunit *test)
+static void register_tracepoints(struct tracepoint *tp, void *ignore)
+{
+	check_trace_callback_type_console(probe_console);
+	if (!strcmp(tp->name, "console"))
+		WARN_ON(tracepoint_probe_register(tp, probe_console, NULL));
+}
+
+static void unregister_tracepoints(struct tracepoint *tp, void *ignore)
+{
+	if (!strcmp(tp->name, "console"))
+		tracepoint_probe_unregister(tp, probe_console, NULL);
+}
+
+static int kasan_suite_init(struct kunit_suite *suite)
 {
 	if (!kasan_enabled()) {
-		kunit_err(test, "can't run KASAN tests with KASAN disabled");
+		pr_err("Can't run KASAN tests with KASAN disabled");
 		return -1;
 	}
 
+	/*
+	 * Temporarily enable multi-shot mode. Otherwise, KASAN would only
+	 * report the first detected bug and panic the kernel if panic_on_warn
+	 * is enabled.
+	 */
 	multishot = kasan_save_enable_multi_shot();
-	test_status.report_found = false;
-	test_status.sync_fault = false;
-	kunit_add_named_resource(test, NULL, NULL, &resource,
-					"kasan_status", &test_status);
+
+	/*
+	 * Because we want to be able to build the test as a module, we need to
+	 * iterate through all known tracepoints, since the static registration
+	 * won't work here.
+	 */
+	for_each_kernel_tracepoint(register_tracepoints, NULL);
 	return 0;
 }
 
-static void kasan_test_exit(struct kunit *test)
+static void kasan_suite_exit(struct kunit_suite *suite)
 {
 	kasan_restore_multi_shot(multishot);
-	KUNIT_EXPECT_FALSE(test, test_status.report_found);
+	for_each_kernel_tracepoint(unregister_tracepoints, NULL);
+	tracepoint_synchronize_unregister();
+}
+
+static void kasan_test_exit(struct kunit *test)
+{
+	KUNIT_EXPECT_FALSE(test, READ_ONCE(test_status.report_found));
 }
 
 /**
@@ -106,11 +143,12 @@ static void kasan_test_exit(struct kunit *test)
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&				\
 	    kasan_sync_fault_possible()) {				\
 		if (READ_ONCE(test_status.report_found) &&		\
-		    READ_ONCE(test_status.sync_fault))			\
+		    !READ_ONCE(test_status.async_fault))		\
 			kasan_enable_tagging();				\
 		migrate_enable();					\
 	}								\
 	WRITE_ONCE(test_status.report_found, false);			\
+	WRITE_ONCE(test_status.async_fault, false);			\
 } while (0)
 
 #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {			\
@@ -1447,9 +1485,10 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 
 static struct kunit_suite kasan_kunit_test_suite = {
 	.name = "kasan",
-	.init = kasan_test_init,
 	.test_cases = kasan_kunit_test_cases,
 	.exit = kasan_test_exit,
+	.suite_init = kasan_suite_init,
+	.suite_exit = kasan_suite_exit,
 };
 
 kunit_test_suite(kasan_kunit_test_suite);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index df3602062bfd..31355851a5ec 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -30,8 +30,6 @@
 
 #include <asm/sections.h>
 
-#include <kunit/test.h>
-
 #include "kasan.h"
 #include "../slab.h"
 
@@ -114,41 +112,12 @@ EXPORT_SYMBOL_GPL(kasan_restore_multi_shot);
 
 #endif
 
-#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
-static void update_kunit_status(bool sync)
-{
-	struct kunit *test;
-	struct kunit_resource *resource;
-	struct kunit_kasan_status *status;
-
-	test = current->kunit_test;
-	if (!test)
-		return;
-
-	resource = kunit_find_named_resource(test, "kasan_status");
-	if (!resource) {
-		kunit_set_failure(test);
-		return;
-	}
-
-	status = (struct kunit_kasan_status *)resource->data;
-	WRITE_ONCE(status->report_found, true);
-	WRITE_ONCE(status->sync_fault, sync);
-
-	kunit_put_resource(resource);
-}
-#else
-static void update_kunit_status(bool sync) { }
-#endif
-
 static DEFINE_SPINLOCK(report_lock);
 
 static void start_report(unsigned long *flags, bool sync)
 {
 	/* Respect the /proc/sys/kernel/traceoff_on_warning interface. */
 	disable_trace_on_warning();
-	/* Update status of the currently running KASAN test. */
-	update_kunit_status(sync);
 	/* Do not allow LOCKDEP mangling KASAN reports. */
 	lockdep_off();
 	/* Make sure we don't end up in loop. */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ebf96ea600050f00ed567e80505ae8f242633640.1666113393.git.andreyknvl%40google.com.
