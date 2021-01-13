Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIV47T7QKGQEJQ7LKWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id D893F2F4FBC
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:21:54 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id y19sf1100545edw.16
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:21:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610554914; cv=pass;
        d=google.com; s=arc-20160816;
        b=opkoXFGod6NtZH58Q59wUUz5rAmI3gqkBU0YCqDrXDV85zxw8pY+ZSpOpCrTml2qtx
         HLXsFD5Hm6mr5bnswZ6IY+cie7I5nxHyXdNwMLT1Xr6Bqvq3Dj4C3k5Yj57nGSB0Y603
         +0fNw3UkKkiNNvW/Bmsl0ZrU1fr4Zwuy9ww/X8/j+c8EXkiNi158Ik3sdp4FFEBu2GyR
         WXos7j8w7H9ATs0CVQ4Q2IliuEGTTQtMDb60hyIVdpCWD77dNyGiwyEJ8Eif957ia1aA
         DwFZQX47d1xRk84uliXYvvjzhwHY3RIJHw7Scobw4uaUgiyRT+M0Oc9bRRgOKnHAFCPf
         1SVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=MJCD1V1eIovaJn+iRG25NWsgVaTaK/e/ZHh2e/psPk0=;
        b=h7FWiJEveaKrP2pL2y+Hu7tMxstwDQL5LqR74wxwQ8eTHa0/qntnBnW6VGBV5H9aUT
         zASq5EjVjYX7Qa7RNFyEqnplEgmmQXvwXaVFOmt1UUQA6PycyK50jNGnvdk/J0pr2l9F
         n46lGFsRKndTngqj+umADktNGYdn1xxVHsr7T6uHxXTF9E/PCr49Ua3Sn+f4NWOnYI1p
         YOA/1I945x0g6mB45c4CXBSpEfdB2m1fuBz+6qwV5LcWB/l4eEV6wDK/Mek4AXg8ia8w
         wGyJOtic61AE/8LAI4MlchDyRQF8a352JSb4E0/fSMHyYtBY7L4PyhZ9gTC8qDP9LRV0
         nxFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oIZpxTsc;
       spf=pass (google.com: domain of 3ir7_xwokcwa8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3IR7_XwoKCWA8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MJCD1V1eIovaJn+iRG25NWsgVaTaK/e/ZHh2e/psPk0=;
        b=Qo90rgvx9iIFAhxmEvum5SZJSVbdrNbGU/+s9xPG2dcRCivLFUJolo85b9W5YkCFh1
         m2xefW9aWeecI9yJncZIdlGBDpFZKOrrixY0PzHbEDrOlQDtGy9UeKXQhQfJBTpzN6cU
         yhrKKr/97u/1+nfJTXLLyoQvcU6Dnr9DQwXEDeAo5v2IxlYTN0+wO4rL8grc6CTnxkzd
         uJj6vfRba9AIUjJX85ddvOn6freY+1MoRhC8pG/YNCYcgyD18MQBujVKTqC/aumjnd29
         438uMDD0EK++qqc0wAavgGNZry0APGhTuF1DTjLJFhY9j0BGP6HxLR0M1ziyww8IbLLg
         3gog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MJCD1V1eIovaJn+iRG25NWsgVaTaK/e/ZHh2e/psPk0=;
        b=m96/5AZzq+NahaQpu1EbrNPKqUtj+Ob9LW0r72tu0hnw8Jx2RkC+vTuHuKiHt8deeQ
         nF/R4Ux9vEOANDwK9oeBa/rX2kaMqFMcJSIpAwDcyMRbsuuhVm2fVR090Tz5iY4nTRJj
         XA5GW4yGYBKwKgzI/0H3OLC/t6IfkarXCsASO3idG079RDqaVXXJMUsayko/zYZK91Q8
         cHKyeuiUw0qDuZsjNuOUxQyJy1yzd4pss/H/Po3FfRysuj4thZPHp5k6A0rqr+m4jPeK
         bEDiC5LsXnVQG2SRe7uK1stPxWlA1do70vqAyN+cvG7gXtGDSMW0mMEodgZjoAuuW4JZ
         EJ7w==
X-Gm-Message-State: AOAM532yPwVdmYZcwX/e46Pwvw7SGWIgaNLhfQVWZJHXwZSvDt8aYOVt
	dHx26tVR5H6SPhTKyx7nhRs=
X-Google-Smtp-Source: ABdhPJxgkv7lMJz7aKb3G5T9XIRBsWUWiGRczb3zFLKf6+4lpafZ0GhgIN5exodW1E9pdBEj3Dm4Fw==
X-Received: by 2002:a05:6402:1597:: with SMTP id c23mr2477029edv.212.1610554914630;
        Wed, 13 Jan 2021 08:21:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:360c:: with SMTP id q12ls1448150ejb.3.gmail; Wed, 13
 Jan 2021 08:21:53 -0800 (PST)
X-Received: by 2002:a17:906:97cb:: with SMTP id ef11mr2077256ejb.379.1610554913722;
        Wed, 13 Jan 2021 08:21:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610554913; cv=none;
        d=google.com; s=arc-20160816;
        b=d0ktkd64DASUGJ5LgZ2omGJYalSqjKt4d5cPV2jxYPXj5d4T6GlG3TvLDxZbW52PV1
         zCvYrtfQIgn6AJBJjDQBHzm1eOBg0ir/Rw49Ed0mFxfMaMyBN8V6oLJMFmcALm0Wo1nq
         jqotFWR7iCthfEjWGmYdRpwxNeYYibj0CkP2FUCD3ZJz+8SUpUhi5bsCQsPAG6vy7RWD
         +IIgocjBEFT9Y5Aoyv1yoEfnGNhluPLFGkPl02KgR0qB5wgKYdMa3U5MuH396mFSME4l
         Hl/ITBDI3cQKD+TFmJA9NxD43zGiSF/fEZ54HJbz0LTmlSvWVpirfghmgjPKuH8zqfJK
         2E6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=m6xusvsokM0PWzPtRFY43dxv0DbWG+gsyZsDZx85iWg=;
        b=VByAdO/RIzJeDZcUKjXgHUIScjSFUDkQe8f6ct0EqoFhRCJvwzLsm6M3G8fUjdeA9F
         wrtAxKoZDbRKHPDdw4yS7FHaFl3syMaqNIKrPdPG7Uhnno9qK/LBpHa9FS6yCc73at75
         CGH05fGPbw1NHu8+FOJSMw94NWNrPTTK6pz76WvifS8zQrVrAly+N5m1KpCgatLdDmG3
         qUlKJYwlwhJmYgu9/nB0AJELx9jntB5hmkoj1xXCY2AWSRbL/liWYm0IQdzlCW92y0HW
         69wI6CUOWZlOgPdlfWd3NBhfiSpK93mncJjyM2CRAL7AmIlU2UNiJ3nWMTdSSRylNj5n
         XlzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oIZpxTsc;
       spf=pass (google.com: domain of 3ir7_xwokcwa8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3IR7_XwoKCWA8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id i3si134097edy.3.2021.01.13.08.21.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:21:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ir7_xwokcwa8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id x20so1029573wmc.0
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:21:53 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:4154:: with SMTP id
 h20mr66423wmm.72.1610554913410; Wed, 13 Jan 2021 08:21:53 -0800 (PST)
Date: Wed, 13 Jan 2021 17:21:30 +0100
In-Reply-To: <cover.1610554432.git.andreyknvl@google.com>
Message-Id: <2b43049e25dcd04850ba6c205cd6dcc7caa4a886.1610554432.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v2 03/14] kasan: clean up comments in tests
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oIZpxTsc;       spf=pass
 (google.com: domain of 3ir7_xwokcwa8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3IR7_XwoKCWA8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Clarify and update comments in KASAN tests.

Link: https://linux-review.googlesource.com/id/I6c816c51fa1e0eb7aa3dead6bda1f339d2af46c8
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c        | 59 +++++++++++++++++++++++++----------------
 lib/test_kasan_module.c |  5 ++--
 2 files changed, 39 insertions(+), 25 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 2947274cc2d3..6f46e27c2af7 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -28,10 +28,9 @@
 #define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANULE_SIZE)
 
 /*
- * We assign some test results to these globals to make sure the tests
- * are not eliminated as dead code.
+ * Some tests use these global variables to store return values from function
+ * calls that could otherwise be eliminated by the compiler as dead code.
  */
-
 void *kasan_ptr_result;
 int kasan_int_result;
 
@@ -39,14 +38,13 @@ static struct kunit_resource resource;
 static struct kunit_kasan_expectation fail_data;
 static bool multishot;
 
+/*
+ * Temporarily enable multi-shot mode. Otherwise, KASAN would only report the
+ * first detected bug and panic the kernel if panic_on_warn is enabled.
+ */
 static int kasan_test_init(struct kunit *test)
 {
-	/*
-	 * Temporarily enable multi-shot mode and set panic_on_warn=0.
-	 * Otherwise, we'd only get a report for the first case.
-	 */
 	multishot = kasan_save_enable_multi_shot();
-
 	return 0;
 }
 
@@ -56,12 +54,12 @@ static void kasan_test_exit(struct kunit *test)
 }
 
 /**
- * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
- * not cause a KASAN error. This uses a KUnit resource named "kasan_data." Do
- * Do not use this name for a KUnit resource outside here.
- *
+ * KUNIT_EXPECT_KASAN_FAIL() - check that the executed expression produces a
+ * KASAN report; causes a test failure otherwise. This relies on a KUnit
+ * resource named "kasan_data". Do not use this name for KUnit resources
+ * outside of KASAN tests.
  */
-#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do { \
+#define KUNIT_EXPECT_KASAN_FAIL(test, expression) do { \
 	fail_data.report_expected = true; \
 	fail_data.report_found = false; \
 	kunit_add_named_resource(test, \
@@ -69,7 +67,7 @@ static void kasan_test_exit(struct kunit *test)
 				NULL, \
 				&resource, \
 				"kasan_data", &fail_data); \
-	condition; \
+	expression; \
 	KUNIT_EXPECT_EQ(test, \
 			fail_data.report_expected, \
 			fail_data.report_found); \
@@ -121,7 +119,8 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
 		return;
 	}
 
-	/* Allocate a chunk that does not fit into a SLUB cache to trigger
+	/*
+	 * Allocate a chunk that does not fit into a SLUB cache to trigger
 	 * the page allocator fallback.
 	 */
 	ptr = kmalloc(size, GFP_KERNEL);
@@ -168,7 +167,9 @@ static void kmalloc_large_oob_right(struct kunit *test)
 {
 	char *ptr;
 	size_t size = KMALLOC_MAX_CACHE_SIZE - 256;
-	/* Allocate a chunk that is large enough, but still fits into a slab
+
+	/*
+	 * Allocate a chunk that is large enough, but still fits into a slab
 	 * and does not trigger the page allocator fallback in SLUB.
 	 */
 	ptr = kmalloc(size, GFP_KERNEL);
@@ -469,10 +470,13 @@ static void ksize_unpoisons_memory(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	real_size = ksize(ptr);
-	/* This access doesn't trigger an error. */
+
+	/* This access shouldn't trigger a KASAN report. */
 	ptr[size] = 'x';
-	/* This one does. */
+
+	/* This one must. */
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[real_size] = 'y');
+
 	kfree(ptr);
 }
 
@@ -568,7 +572,7 @@ static void kmem_cache_invalid_free(struct kunit *test)
 		return;
 	}
 
-	/* Trigger invalid free, the object doesn't get freed */
+	/* Trigger invalid free, the object doesn't get freed. */
 	KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_free(cache, p + 1));
 
 	/*
@@ -585,7 +589,10 @@ static void kasan_memchr(struct kunit *test)
 	char *ptr;
 	size_t size = 24;
 
-	/* See https://bugzilla.kernel.org/show_bug.cgi?id=206337 */
+	/*
+	 * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
+	 * See https://bugzilla.kernel.org/show_bug.cgi?id=206337 for details.
+	 */
 	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
 		kunit_info(test,
 			"str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
@@ -610,7 +617,10 @@ static void kasan_memcmp(struct kunit *test)
 	size_t size = 24;
 	int arr[9];
 
-	/* See https://bugzilla.kernel.org/show_bug.cgi?id=206337 */
+	/*
+	 * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
+	 * See https://bugzilla.kernel.org/show_bug.cgi?id=206337 for details.
+	 */
 	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
 		kunit_info(test,
 			"str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
@@ -634,7 +644,10 @@ static void kasan_strings(struct kunit *test)
 	char *ptr;
 	size_t size = 24;
 
-	/* See https://bugzilla.kernel.org/show_bug.cgi?id=206337 */
+	/*
+	 * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
+	 * See https://bugzilla.kernel.org/show_bug.cgi?id=206337 for details.
+	 */
 	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
 		kunit_info(test,
 			"str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
@@ -706,7 +719,7 @@ static void kasan_bitops_generic(struct kunit *test)
 	}
 
 	/*
-	 * Allocate 1 more byte, which causes kzalloc to round up to 16-bytes;
+	 * Allocate 1 more byte, which causes kzalloc to round up to 16 bytes;
 	 * this way we do not actually corrupt other memory.
 	 */
 	bits = kzalloc(sizeof(*bits) + 1, GFP_KERNEL);
diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
index 3b4cc77992d2..eee017ff8980 100644
--- a/lib/test_kasan_module.c
+++ b/lib/test_kasan_module.c
@@ -123,8 +123,9 @@ static noinline void __init kasan_workqueue_uaf(void)
 static int __init test_kasan_module_init(void)
 {
 	/*
-	 * Temporarily enable multi-shot mode. Otherwise, we'd only get a
-	 * report for the first case.
+	 * Temporarily enable multi-shot mode. Otherwise, KASAN would only
+	 * report the first detected bug and panic the kernel if panic_on_warn
+	 * is enabled.
 	 */
 	bool multishot = kasan_save_enable_multi_shot();
 
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2b43049e25dcd04850ba6c205cd6dcc7caa4a886.1610554432.git.andreyknvl%40google.com.
