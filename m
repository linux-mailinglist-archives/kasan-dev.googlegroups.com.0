Return-Path: <kasan-dev+bncBAABBEHOWSIAMGQEN4FV7FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id F15934B8F56
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 18:40:32 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id c7-20020a1c3507000000b0034a0dfc86aasf3176288wma.6
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 09:40:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645033232; cv=pass;
        d=google.com; s=arc-20160816;
        b=x2jZAiH5Q24bS68YyrPKjv670q5+GEN4nxb1354gxBd2xOsS9Qwmr7CZMmPrUd2VGm
         i1ul0f1+9QlBPuq6hl01ulXdmv0XidcjONhZs6fhAGe/RkrXK6VihZtuASavNaqQk9Fo
         kCTQER1Qy+214+5lJdsIlNt8ttSrJMjwnktuTHGnUWmr2k5WtFpTwgC3mwh29k44P/KF
         4Al/WW5Enq9/BnA+bNsfDeeTYtbwfidMDuV3IjSqaMt3iFG2D9Ud7t893R2JaumYycBX
         PsVErbVrq1j8m0kIVCCJesCjZ97QyM6hhF3KN6ZOXm9+lAPzJIr2WSVlMkVxaDXQT9oh
         j59w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=NcaMkl1O/CidKUI0bDQjMH/cZUHtdQtyEK0tj6AULnE=;
        b=Mc1h16HKTioa4aCn8AaIYNRnPU/Q8tR+mgI1RogFMJyj8AVrbk+4IRXgze3JkkMqNb
         Jx7QRnIGIyE3I6SsFNIM+8s4hC9lFeNH+aUsAB1yjRx45b9Tc5CcW2TLYdJ5PHuIyByA
         u++vViaduGqTmnTgGOGFaopJMm9KPMFS8HMgZVp4iA6Q3Nz6SyiLLPtEgpgyn9rbpOum
         LTpMA310HqIMwHrcpI/x7I/Te/EcLWxzoL9aeanyxw1Z0XU/jzbQUjzJN+cF/l5uxcnX
         ro8dzOV2m5TPvQ+KM99JmCAojYoK7Uxv6hhvRKVN/FKSotqLQ1aH7fYTRZhSZVH4/YiJ
         QLow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KFIxhOys;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NcaMkl1O/CidKUI0bDQjMH/cZUHtdQtyEK0tj6AULnE=;
        b=lTgG3Edf781BrZ3mYyJg52XPV5pKvgi3GZ/d+n8oSHZWJBu/HFxPWHoWj5U/mWgV0W
         Qz8ivkfIA7iRCYmvRNX4dXE/inwUlpvjMNzXJDYRysXGQFm0vzhda5vy0wCrf7Tmropj
         LdSNbbuO9Unh/OdDedgVIZKGLD7ndvg0UBJj71rWu1ZRZp5/sRSA5kC73Y8MZQnU6c4t
         5lrqQunk84iPwJRVwcMCBLu4XqHelz7QCcjN36SoEdfxVFPiLQVM2v5LJEosjI4qIHgr
         c5NNrbdCs8Lk4sSzkZdwRzVEhQmO8uG5XTDT0oPZw5O3s3DjNw1KQ1oKFouY+U8QGZq+
         XWJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NcaMkl1O/CidKUI0bDQjMH/cZUHtdQtyEK0tj6AULnE=;
        b=K/Ate/7MRe0XKILOGQj6KiZ5uA0Aq/vnQZoSrOaOI06FqKvoy3w0Bdnic1ySe9PYol
         SYKOWuWc4E5c5BuTUKgm6W/1BZKlB3e4RntZRtwf7xXHn33a2JU7omvckqmo0pgix++g
         2HYe18Dbfa3aDVd7OkbHy7cOEnVYzIzhOllYzlLEkodxpxc+smDMgP/iruFOi7D/TClR
         YRXnn/yjTfM74zZYVYb+JFvFYt3nQlapV545C5+0LHdiEMaErJKF6aAQFHcLl4dVkN+u
         6CSYOhILBGGHvMeXq4h4dpIGfhals3BFGpkVsfZ4uFHzXFi2bSjkBq+OXgMxEWtm95dn
         r1ig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533/dfSkKjauqqyE+mYKepYFk3uVwO1fVQszR6JaPbskm4ScYuQA
	ZGyGV2WnGaYLvrr6Ei8ULIU=
X-Google-Smtp-Source: ABdhPJzajp3GRMN6PNyl33+8rTOYwAYeykNRguwuNxnxrW9TFqryhVZhSEnxOVSDR0rFoGO2LMU8cA==
X-Received: by 2002:a05:600c:4ed1:b0:37b:bb72:9ecd with SMTP id g17-20020a05600c4ed100b0037bbb729ecdmr2534846wmq.177.1645033232572;
        Wed, 16 Feb 2022 09:40:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3d9a:b0:37b:f94b:3486 with SMTP id
 bi26-20020a05600c3d9a00b0037bf94b3486ls1811wmb.0.experimental-gmail; Wed, 16
 Feb 2022 09:40:31 -0800 (PST)
X-Received: by 2002:a05:600c:4888:b0:37b:c7ea:4cbd with SMTP id j8-20020a05600c488800b0037bc7ea4cbdmr2694671wmp.51.1645033231739;
        Wed, 16 Feb 2022 09:40:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645033231; cv=none;
        d=google.com; s=arc-20160816;
        b=VR3INLD0qjQFNOBA4sCDKqN7Ch30cRfqq4eDggq1ItMUGih65uxFAbhj0ODFfPzrKG
         f8H2npuVHILqvcw1BhxBjcBihtmdvokqsYgC2y71gdFh24HTBLjgkDMb96yfVbni4IHE
         zU8V788S7wNshgax+0+SnMOP1xCzEktTwyQmRmU9HNjz7O+sjcpUaf4mNMJhjrVaTPNI
         PqqAk3AlZNK/Jk6dWNE27YTgxRZPywe+Opg4ZANILLfpM0AG3j8y8uT1qBK9nRwOUYZL
         EIUMRUeocMS85Kdvfl84F//vjX8IMBYEBquraz/L+ioHKmYqE4VFjCB0TeKFJxkVH6J8
         EC2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=m4631CfCFoYR3Tqcbex/s0GntKYxT5FXEjdyP0a17Xs=;
        b=EU2NehTST0sJ3ff09zE0fZaAn7Rd5j/qYYwkcCR0hAXC0620eO3hbLHEHMH1s1550E
         86dbt95SzPjpSKY7swXtXzWb43KSYcKMj7VG0oBfN1i7PP7fnw4zqfMa71JqRlcUdc55
         mVynb/p9ODg2sSK+2Uw59O1GNCD66d12tV8pjFeaVKldH5AlZmRniM9qs9xHy/i9f8Cc
         2DQdF3ywE8BfV8LZ0SPt/AWl7KNhlQxo+d1pf2S4HbYD7AvAuuipfUni2PTaIlVk6KST
         D+oV9UkIoFE9OhhtsOpJkXEbOUcPcM8+GGUFGPJsPfRLfBwVMe7ifb9JybgOvs+vj/rV
         qWgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KFIxhOys;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id h81si1159545wmh.2.2022.02.16.09.40.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 16 Feb 2022 09:40:31 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2] kasan: test: support async (again) and asymm modes for HW_TAGS
Date: Wed, 16 Feb 2022 18:40:27 +0100
Message-Id: <133970562ccacc93ba19d754012c562351d4a8c8.1645033139.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=KFIxhOys;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Async mode support has already been implemented in commit
e80a76aa1a91 ("kasan, arm64: tests supports for HW_TAGS async mode")
but then got accidentally broken in
commit 99734b535d9b ("kasan: detect false-positives in tests").

Restore the changes removed by the latter patch and adapt them for
asymm mode: add a sync_fault flag to kunit_kasan_expectation that
only get set if the MTE fault was synchronous, and reenable MTE
on such faults in tests.

Also rename kunit_kasan_expectation to kunit_kasan_status and move its
definition to mm/kasan/kasan.h from include/linux/kasan.h, as this
structure is only internally used by KASAN. Also put the structure
definition under IS_ENABLED(CONFIG_KUNIT).

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Use CONFIG_KUNIT check for kunit_kasan_status instead of
  CONFIG_KASAN_KUNIT_TEST.
---
 include/linux/kasan.h |  5 -----
 lib/test_kasan.c      | 39 ++++++++++++++++++++++-----------------
 mm/kasan/hw_tags.c    | 18 +++++++++---------
 mm/kasan/kasan.h      | 14 ++++++++++++--
 mm/kasan/report.c     | 17 +++++++++--------
 5 files changed, 52 insertions(+), 41 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 3593c95d1fa5..562bf36fd6ec 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -18,11 +18,6 @@ struct task_struct;
 #include <linux/linkage.h>
 #include <asm/kasan.h>
 
-/* kasan_data struct is used in KUnit tests for KASAN expected failures */
-struct kunit_kasan_expectation {
-	bool report_found;
-};
-
 #endif
 
 typedef unsigned int __bitwise kasan_vmalloc_flags_t;
diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index ef99d81fe8b3..8416161d5177 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -37,7 +37,7 @@ void *kasan_ptr_result;
 int kasan_int_result;
 
 static struct kunit_resource resource;
-static struct kunit_kasan_expectation fail_data;
+static struct kunit_kasan_status test_status;
 static bool multishot;
 
 /*
@@ -54,58 +54,63 @@ static int kasan_test_init(struct kunit *test)
 	}
 
 	multishot = kasan_save_enable_multi_shot();
-	fail_data.report_found = false;
+	test_status.report_found = false;
+	test_status.sync_fault = false;
 	kunit_add_named_resource(test, NULL, NULL, &resource,
-					"kasan_data", &fail_data);
+					"kasan_status", &test_status);
 	return 0;
 }
 
 static void kasan_test_exit(struct kunit *test)
 {
 	kasan_restore_multi_shot(multishot);
-	KUNIT_EXPECT_FALSE(test, fail_data.report_found);
+	KUNIT_EXPECT_FALSE(test, test_status.report_found);
 }
 
 /**
  * KUNIT_EXPECT_KASAN_FAIL() - check that the executed expression produces a
  * KASAN report; causes a test failure otherwise. This relies on a KUnit
- * resource named "kasan_data". Do not use this name for KUnit resources
+ * resource named "kasan_status". Do not use this name for KUnit resources
  * outside of KASAN tests.
  *
- * For hardware tag-based KASAN in sync mode, when a tag fault happens, tag
+ * For hardware tag-based KASAN, when a synchronous tag fault happens, tag
  * checking is auto-disabled. When this happens, this test handler reenables
  * tag checking. As tag checking can be only disabled or enabled per CPU,
  * this handler disables migration (preemption).
  *
- * Since the compiler doesn't see that the expression can change the fail_data
+ * Since the compiler doesn't see that the expression can change the test_status
  * fields, it can reorder or optimize away the accesses to those fields.
  * Use READ/WRITE_ONCE() for the accesses and compiler barriers around the
  * expression to prevent that.
  *
- * In between KUNIT_EXPECT_KASAN_FAIL checks, fail_data.report_found is kept as
- * false. This allows detecting KASAN reports that happen outside of the checks
- * by asserting !fail_data.report_found at the start of KUNIT_EXPECT_KASAN_FAIL
- * and in kasan_test_exit.
+ * In between KUNIT_EXPECT_KASAN_FAIL checks, test_status.report_found is kept
+ * as false. This allows detecting KASAN reports that happen outside of the
+ * checks by asserting !test_status.report_found at the start of
+ * KUNIT_EXPECT_KASAN_FAIL and in kasan_test_exit.
  */
 #define KUNIT_EXPECT_KASAN_FAIL(test, expression) do {			\
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&				\
 	    kasan_sync_fault_possible())				\
 		migrate_disable();					\
-	KUNIT_EXPECT_FALSE(test, READ_ONCE(fail_data.report_found));	\
+	KUNIT_EXPECT_FALSE(test, READ_ONCE(test_status.report_found));	\
 	barrier();							\
 	expression;							\
 	barrier();							\
-	if (!READ_ONCE(fail_data.report_found)) {			\
+	if (kasan_async_fault_possible())				\
+		kasan_force_async_fault();				\
+	if (!READ_ONCE(test_status.report_found)) {			\
 		KUNIT_FAIL(test, KUNIT_SUBTEST_INDENT "KASAN failure "	\
 				"expected in \"" #expression		\
 				 "\", but none occurred");		\
 	}								\
-	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {				\
-		if (READ_ONCE(fail_data.report_found))			\
-			kasan_enable_tagging_sync();			\
+	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&				\
+	    kasan_sync_fault_possible()) {				\
+		if (READ_ONCE(test_status.report_found) &&		\
+		    READ_ONCE(test_status.sync_fault))			\
+			kasan_enable_tagging();				\
 		migrate_enable();					\
 	}								\
-	WRITE_ONCE(fail_data.report_found, false);			\
+	WRITE_ONCE(test_status.report_found, false);			\
 } while (0)
 
 #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {			\
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index fad1887e54c0..07a76c46daa5 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -172,12 +172,7 @@ void kasan_init_hw_tags_cpu(void)
 	 * Enable async or asymm modes only when explicitly requested
 	 * through the command line.
 	 */
-	if (kasan_arg_mode == KASAN_ARG_MODE_ASYNC)
-		hw_enable_tagging_async();
-	else if (kasan_arg_mode == KASAN_ARG_MODE_ASYMM)
-		hw_enable_tagging_asymm();
-	else
-		hw_enable_tagging_sync();
+	kasan_enable_tagging();
 }
 
 /* kasan_init_hw_tags() is called once on boot CPU. */
@@ -343,11 +338,16 @@ void __kasan_poison_vmalloc(const void *start, unsigned long size)
 
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
-void kasan_enable_tagging_sync(void)
+void kasan_enable_tagging(void)
 {
-	hw_enable_tagging_sync();
+	if (kasan_arg_mode == KASAN_ARG_MODE_ASYNC)
+		hw_enable_tagging_async();
+	else if (kasan_arg_mode == KASAN_ARG_MODE_ASYMM)
+		hw_enable_tagging_asymm();
+	else
+		hw_enable_tagging_sync();
 }
-EXPORT_SYMBOL_GPL(kasan_enable_tagging_sync);
+EXPORT_SYMBOL_GPL(kasan_enable_tagging);
 
 void kasan_force_async_fault(void)
 {
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 4d67408e8407..d1e111b7d5d8 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -7,6 +7,16 @@
 #include <linux/kfence.h>
 #include <linux/stackdepot.h>
 
+#if IS_ENABLED(CONFIG_KUNIT)
+
+/* Used in KUnit-compatible KASAN tests. */
+struct kunit_kasan_status {
+	bool report_found;
+	bool sync_fault;
+};
+
+#endif
+
 #ifdef CONFIG_KASAN_HW_TAGS
 
 #include <linux/static_key.h>
@@ -350,12 +360,12 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #if defined(CONFIG_KASAN_HW_TAGS) && IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
-void kasan_enable_tagging_sync(void);
+void kasan_enable_tagging(void);
 void kasan_force_async_fault(void);
 
 #else /* CONFIG_KASAN_HW_TAGS || CONFIG_KASAN_KUNIT_TEST */
 
-static inline void kasan_enable_tagging_sync(void) { }
+static inline void kasan_enable_tagging(void) { }
 static inline void kasan_force_async_fault(void) { }
 
 #endif /* CONFIG_KASAN_HW_TAGS || CONFIG_KASAN_KUNIT_TEST */
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index f14146563d41..137c2c0b09db 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -336,20 +336,21 @@ static bool report_enabled(void)
 }
 
 #if IS_ENABLED(CONFIG_KUNIT)
-static void kasan_update_kunit_status(struct kunit *cur_test)
+static void kasan_update_kunit_status(struct kunit *cur_test, bool sync)
 {
 	struct kunit_resource *resource;
-	struct kunit_kasan_expectation *kasan_data;
+	struct kunit_kasan_status *status;
 
-	resource = kunit_find_named_resource(cur_test, "kasan_data");
+	resource = kunit_find_named_resource(cur_test, "kasan_status");
 
 	if (!resource) {
 		kunit_set_failure(cur_test);
 		return;
 	}
 
-	kasan_data = (struct kunit_kasan_expectation *)resource->data;
-	WRITE_ONCE(kasan_data->report_found, true);
+	status = (struct kunit_kasan_status *)resource->data;
+	WRITE_ONCE(status->report_found, true);
+	WRITE_ONCE(status->sync_fault, sync);
 	kunit_put_resource(resource);
 }
 #endif /* IS_ENABLED(CONFIG_KUNIT) */
@@ -363,7 +364,7 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 
 #if IS_ENABLED(CONFIG_KUNIT)
 	if (current->kunit_test)
-		kasan_update_kunit_status(current->kunit_test);
+		kasan_update_kunit_status(current->kunit_test, true);
 #endif /* IS_ENABLED(CONFIG_KUNIT) */
 
 	start_report(&flags);
@@ -383,7 +384,7 @@ void kasan_report_async(void)
 
 #if IS_ENABLED(CONFIG_KUNIT)
 	if (current->kunit_test)
-		kasan_update_kunit_status(current->kunit_test);
+		kasan_update_kunit_status(current->kunit_test, false);
 #endif /* IS_ENABLED(CONFIG_KUNIT) */
 
 	start_report(&flags);
@@ -405,7 +406,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 
 #if IS_ENABLED(CONFIG_KUNIT)
 	if (current->kunit_test)
-		kasan_update_kunit_status(current->kunit_test);
+		kasan_update_kunit_status(current->kunit_test, true);
 #endif /* IS_ENABLED(CONFIG_KUNIT) */
 
 	disable_trace_on_warning();
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/133970562ccacc93ba19d754012c562351d4a8c8.1645033139.git.andreyknvl%40google.com.
