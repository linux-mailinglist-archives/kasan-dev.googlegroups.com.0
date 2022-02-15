Return-Path: <kasan-dev+bncBAABB3EMV6IAMGQEKO7VMXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 9431F4B6FB4
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Feb 2022 16:27:40 +0100 (CET)
Received: by mail-ej1-x640.google.com with SMTP id hc39-20020a17090716a700b006ce88cf89dfsf2573045ejc.10
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Feb 2022 07:27:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644938860; cv=pass;
        d=google.com; s=arc-20160816;
        b=VyiplUPybL3sH3uJYWD/MoPd1ws/e/J1obqC8VhZYTg9uG/jC+O0XhYFy+5XQI1cjQ
         LPOeGMRjvT2+luo/3qaNnSwIuBDqLNBxHjuxWZNcwDsFz3+fVQvagAt8AvLIulYDzak2
         Fk3UrGYBcN6+xM3AHQnCPDW3QyjTrX5ThtivHTXSNuRiKEOT8XWw2o27T8pDk3bLU3ce
         uTjpcVwxH1Ti9KNbt7KtJOj8w67CQ+eollgeNJ1MXf8u4Jnmk99ktbhahvTgadIww0dr
         Z5uE5jZJLv+9+IAJ3NsoQeLvyfkUcv+dexfLVo1fq16I0eaDrdimLaHAD1ILeJLX38bJ
         gRmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=edf0Kq0E6YRNmh/MlbETMAJoA1ncWenhH6LqfjCPhFY=;
        b=DyLk5l1HypWykPvVs6lHOCoyBbrInznlxVhjsYtCoiw+o7gSH36yIulbTsc1E9PDXm
         W6OkgMVahttYnjiXorIUokWOCWDJOmR4NnlebVIn8GDzECLYHvSOQnTun9x+PLvIW52p
         33MQ4LOqeeB2XbbBlIwuG2F6fmSOb8JuH6Dm+owz4ryZ/UFdUj26ATuZmaT3HLGIDXsI
         pTDxZ19bT521DwKfrhd9qPtLCMoTwsj1UDjulahYFRXUKmACNODZxbj32XwKNZmqBG/+
         r/GxySb6zygFgtrncNrckA668+fIf0vtemuzJ13B7fZGHDYrS0MrwiyRY8y+rRYJ7hYt
         Li0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TyqFfmBR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=edf0Kq0E6YRNmh/MlbETMAJoA1ncWenhH6LqfjCPhFY=;
        b=NinDfQ0YJu5D8q3jwlIrUmT+zZVr01WtuznYf1+mEovLoqDvn8OkcognY2vrAaSqxS
         +kfJNdyFV0sqXFqPKLqWRhm5qSmlK/GjQH+WEAnD9+ZRWNX9xcmtlid6ud4wUw3Xhj/w
         UXsny/cH4vGYSz1BCo9dI4fzX2bhGQt89fyzCxPo7YkLaxDLPJqmvkXGu6Z1uBn1Y0ea
         W0nfJhG+y+1Fo1UI+jijff9HA0PHMl2ZANRN9BpihGKdZ/jH0Tdd6WurDLswUGc1z/hu
         qg/WwORXR5EurkW+rzrT3Hq2g2zxfUVmcF6IfKCnYwAz5u1+ogREELzr36YuOfglGx/5
         RK6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=edf0Kq0E6YRNmh/MlbETMAJoA1ncWenhH6LqfjCPhFY=;
        b=KgnOqBW9tn7JYvhyoJWaHqAxMarAOaG2oDVVp2VVseTsuu5vdqC7l83O7IMaFkFFQI
         kh8T65nP0PRIHVjP0GCdgqc8IU5SFEJvtU7q9z+UkpFGpXyTXAz358AnhnIoaSyqIiuQ
         1aUrEYm5Js5jOpp3Hfp56hq8DnXxQiTMXbQjVSoI9JDEwr9h/mKClppgB8eSBAvY0H9h
         2VMLrjJi6JjaLyzBqPpFYxvEE40Tu+r7HLN2HmI5r5g7MmlsprZg0RuLZ3HrMDGsphGf
         JdiGEXg5QfnOGZJu3S3Y6D2MjqCK64H3B4+1xddzfMpeHse2fdEWSqkRQSjG/GJMCTDG
         zdUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533vgFN41FqxpA2a3at/Y6jRXDGFFt739Iz6LecEW+Kgxx5Izmsk
	bLdz/369vWWwMVFnfgiBSzA=
X-Google-Smtp-Source: ABdhPJxpeXnlPqm1ytdi0vIQl7Aan2R4RdcdiDm/9yweLY8Unk7wBw/vF6RZ+RLfPoLRceD2vlXCtQ==
X-Received: by 2002:a17:907:1114:: with SMTP id qu20mr1391295ejb.201.1644938860213;
        Tue, 15 Feb 2022 07:27:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:d0b:: with SMTP id eb11ls997257edb.1.gmail; Tue, 15
 Feb 2022 07:27:39 -0800 (PST)
X-Received: by 2002:a05:6402:84f:: with SMTP id b15mr4518377edz.206.1644938859475;
        Tue, 15 Feb 2022 07:27:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644938859; cv=none;
        d=google.com; s=arc-20160816;
        b=XzWFex/wgoDwVpdmgjSaTfhLNIp9dWVzHVWJ+7lj3a4QXSJiws1oXlfsqs3nEx3fKh
         Etnsq3p0Dpj3nTrCSuugUvct6cOkIJ97+GODaGI/eBAujxzgz4d1TpLtBt6glZ5lQ1+P
         iZ8eiN4UypF00jglAkVpz745fofjbQEDG9He7fFhExJdZp3EaW3sE75+nQu7HoWdl7iX
         FLnO1LofwFFY0TSThGvj+f/UrWivzbB+JkUaupTBa+t5ce4ZUCLwrhhfzc/6Nbm4xpZR
         J65uOWJkXgxCDAATyQGlcQES6TOdU6vqA+7+uGD5g1ZDD2v+3sGtXCq389O5pcH31MKq
         MDxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Dd7SzABTkib4AM799BUOL90w6kNVBveLZbvtnSYlKo4=;
        b=qkh3/4eOVWb8AbIKEVMK4l2eDgWK3vxiI/S3m0KyrVYDJqC1x5A1gMaH9v15qcL1GB
         N7/i6wyfRPebEZseo4h6KW91UPcRb9YR9sUKlChavQHd1w+XzrBEhrz76QpUG6HitWW5
         PAJmdOw8G2CzrLc/gYxFhPq60vknxZ3FnXEkxbGAIpC36qKI1c5UOSaXeCIGtQ85eN05
         ClVbe9etKWpMRUvbPQpKmke5iEG9NpeROrZv7lxZNtbOBaQjhIySNN9u4+6nsCe/9wVR
         zJDsekj0JPFw5ZxQ++P9ckQ4Cu/BzZZid3PZin553ecjQXt/LV2DZKOj/fDzsxardo0f
         cH4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TyqFfmBR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id s15si1601805eji.1.2022.02.15.07.27.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 15 Feb 2022 07:27:39 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
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
Subject: [PATCH] kasan: test: support async (again) and asymm modes for HW_TAGS
Date: Tue, 15 Feb 2022 16:27:36 +0100
Message-Id: <51ae4a56205a41953971113ab2c264c7e2e5d969.1644938763.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=TyqFfmBR;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
structure is only internally used by KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h |  5 -----
 lib/test_kasan.c      | 39 ++++++++++++++++++++++-----------------
 mm/kasan/hw_tags.c    | 18 +++++++++---------
 mm/kasan/kasan.h      | 14 ++++++++++++--
 mm/kasan/report.c     | 17 +++++++++--------
 5 files changed, 52 insertions(+), 41 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 4a45562d8893..d9c3f9e79d7d 100644
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
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 26a5c9007653..f90ed146ed23 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -36,7 +36,7 @@ void *kasan_ptr_result;
 int kasan_int_result;
 
 static struct kunit_resource resource;
-static struct kunit_kasan_expectation fail_data;
+static struct kunit_kasan_status test_status;
 static bool multishot;
 
 /*
@@ -53,58 +53,63 @@ static int kasan_test_init(struct kunit *test)
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
index 7355cb534e4f..97c68c9de042 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -132,12 +132,7 @@ void kasan_init_hw_tags_cpu(void)
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
@@ -226,11 +221,16 @@ void kasan_free_pages(struct page *page, unsigned int order)
 
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
index c17fa8d26ffe..49d8df9cf2c6 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -7,6 +7,16 @@
 #include <linux/kfence.h>
 #include <linux/stackdepot.h>
 
+#ifdef CONFIG_KASAN_KUNIT_TEST
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
@@ -340,12 +350,12 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
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
index 3ad9624dcc56..c5a8adc570c0 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -344,20 +344,21 @@ static bool report_enabled(void)
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
@@ -371,7 +372,7 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 
 #if IS_ENABLED(CONFIG_KUNIT)
 	if (current->kunit_test)
-		kasan_update_kunit_status(current->kunit_test);
+		kasan_update_kunit_status(current->kunit_test, true);
 #endif /* IS_ENABLED(CONFIG_KUNIT) */
 
 	start_report(&flags);
@@ -391,7 +392,7 @@ void kasan_report_async(void)
 
 #if IS_ENABLED(CONFIG_KUNIT)
 	if (current->kunit_test)
-		kasan_update_kunit_status(current->kunit_test);
+		kasan_update_kunit_status(current->kunit_test, false);
 #endif /* IS_ENABLED(CONFIG_KUNIT) */
 
 	start_report(&flags);
@@ -413,7 +414,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/51ae4a56205a41953971113ab2c264c7e2e5d969.1644938763.git.andreyknvl%40google.com.
