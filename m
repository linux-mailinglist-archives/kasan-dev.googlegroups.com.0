Return-Path: <kasan-dev+bncBDX4HWEMTEBRBBFNQ6AAMGQEFBH23ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 84E712F82F4
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:53:09 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id u10sf1709525pjx.3
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:53:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610733188; cv=pass;
        d=google.com; s=arc-20160816;
        b=rMHEmIirK8bhMe4RzD4p0FXUh5AfDcDgNhjBfzTMyORjr+vaCIaguNAdVEmTaEZQlY
         QEbOHXjNy7hlU1R05v1W1+tYWHctSlclcr113RVDU+XF82QU0kelLT0a6Sh9YQGCflgi
         Hg2AqdLNzgMeYMi0O7uF7gPWa3e36epOFwa1e9Q8IAMq5cA8aw0DFn6l4ybluYPBfH6x
         KPOrRWzhJFJSmt1vF1Y5u20DWvZ1+hHtCkvjBYYHuEuzIOE0Y5Wnhx2RCJ+PBvRIFlmS
         s+4HErBl2hIBJiqo3hC1tVv5d2PUarEorFeJVp5ivd2d0/y9PQb+lpON/zVFrXgwcaAk
         rAJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=l1/J0jO/urc+4NpesN/x8961pPxN3YEdo4/e031+mk4=;
        b=GhN0fz07AqFJprtAvcKqk0qORM+E10Utl1cTHmt5fy8kapI56R8KBhbI3vBtnNEmwP
         b+0RoFodgI11Pe+0dhaGSCFUc8Qb7wP9WvgXqmiYpvk5TOluZa5cY+AxaOkWiqK1AFBB
         vgl17W31sm8jR0GF+M4BwRtGiBAjp2rGGCU6lTS0gDLy7S0cUlVFD2jsp0R3dUcjlz2R
         7PZjE1MyLlktJbK/F7XykITM7QegcherOBkqhY8hA/evjqDnbJFgH4glOOu55/pvhPoi
         8Qp17huDlWl0PZJUmCDGPI9HNeu2rgZMvpguZREdwqMpIq5F9mhdklh6VuMoCOXHto1o
         /bXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AhDiNVba;
       spf=pass (google.com: domain of 3gtybyaokct0zmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3gtYBYAoKCT0Zmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=l1/J0jO/urc+4NpesN/x8961pPxN3YEdo4/e031+mk4=;
        b=r2k53krT1cGOve1Qf0N3UoNmR+f7EoT1N+B/QmWCa1lv/IUhGEJj8Y9NdrSZ7nxSd6
         HMcn0U9MldlayOLPZAIzalEBIhRR1b8mci8lzHJXlVs5iXZLZq05Z4EqLEccMCeX9Mc2
         Y06bFOwWBCzs2kvWWn1R3q+fPOma+G/0EfwDgL7j0KVX1+ptazuExGuj+4hJblE4tVwl
         ATn20YrjWC4Ah8BauAuCVC2nG135J3E6/6yTwbR7Q8eBAsTvdpDxxTjSb4E7uL/XyyeX
         MvNd0296jcyNMFSwFetTHpDOaKaJQg2POPirISB82F/lNOGuTncf4wzrnk4AMihjIm31
         GUjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l1/J0jO/urc+4NpesN/x8961pPxN3YEdo4/e031+mk4=;
        b=I1jBuwc5DOl7Z7Hfi3FKeb1Xm0jKhtBxVzUv2bS+HqcOhr+vBPRs++EJ+T1P2+Pi/d
         lrFndth5pGyibvLdkHW1JFMbTHzkyuU6JpPSrzb5jDW1oFmUmCmpszFU5QISyfRekaDe
         3icJooO+SAlRk2YtvypurGkND5tpGksoTzbMaKP+4uoLyNPJVfb2H7RB8H3qYMmnT+kt
         neO9AugHoFCoEdqHPrxmVIee/u0YD+ZqrBtaCWSIC3GVnqNYGkUGrHzQsbB3KGzY571I
         1VRLutQuesPYchUM4NjRW688nKMAhhYrmB1auWOvk76mVVmxXKnnmpwXWvVq7eHNiGwO
         lJYA==
X-Gm-Message-State: AOAM532K79ezVjLYh/21Lk3zoRLS32BOb2NAc5pCK+Abl1ym1v5RG3I0
	auYTJq385iJELMCMir842U0=
X-Google-Smtp-Source: ABdhPJxWYJZz4eLHe1jxzk8G6J9QSuqXkwugZavQnfhY6WEp4TaT7gNySsJSV1nraUy7mZw26up0Bg==
X-Received: by 2002:a63:1f21:: with SMTP id f33mr13818308pgf.31.1610733188228;
        Fri, 15 Jan 2021 09:53:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:451d:: with SMTP id s29ls3769571pga.5.gmail; Fri, 15 Jan
 2021 09:53:07 -0800 (PST)
X-Received: by 2002:a63:ce58:: with SMTP id r24mr13808167pgi.192.1610733187651;
        Fri, 15 Jan 2021 09:53:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610733187; cv=none;
        d=google.com; s=arc-20160816;
        b=IqWodNQzXHbir14WfiT3ENPJwu+63tfWYSlTf+h48CxDlXpyeZFTY7KSi9EBaGycnv
         3PmusxU5BW9GzOTsm57wkHYxYpsAguIk0XMnssiTrKpuB6lbdzInovYI4VFLWgHHpBJs
         gQ/AnrbnWpTcpsl21r6t5xL+C86VsN+2m+Wbm4BjBLHmw1d4wKmPQ+iUA0vB8cZEJbQe
         jEn4hz5JVEnr7mrokl3H9xjxI/rPvL1s5oXxVRBuHckPVI+Dpht0dSQKBkbeye7+18T7
         WZAXX46GKLOHYpnIZDsfpeGPUNvNxnSL59mXUoJQO3AZ+DcN3UIjWekdFTcHv10Xcjd0
         1fzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=H1AkM+4Sh+ASgk4Ggs31KG74pCusCqq8GYWTQMctXtw=;
        b=LrCU8JZzQDiyL3V++9Yh5gab0eWsW3jorUndo90JPfczovAh+UqJWurwGqiWc6c3F+
         t/iIQfJBju+IdWRjsM5ykgw5KL4FAdHphvCtD4dNACnRHWnMIvCPTQbghQ3Z7krs7sQL
         NRY82kmF9NUOXaR7uo+jqMHHnO2AfjznB/m1qqUbJC5133RAwff51qsvf61OKMLMDGnv
         3DaEgMEXNqvyUM1RLgfQwdo0iknTFNDgXsfIxF/1aevnV9FAEr1LRqqo/6o0Y+1AYkje
         QTDDnVlOeX6POxk1PqdCSuYALefQ4ZpSWvYy2CIpu7gQiUYhc0sbtQov8O+0Oi06v8uC
         g/WA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AhDiNVba;
       spf=pass (google.com: domain of 3gtybyaokct0zmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3gtYBYAoKCT0Zmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id e11si1075658pjw.1.2021.01.15.09.53.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:53:07 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gtybyaokct0zmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id z43so8001839qtb.0
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:53:07 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:9ccb:: with SMTP id
 j11mr13309027qvf.44.1610733186695; Fri, 15 Jan 2021 09:53:06 -0800 (PST)
Date: Fri, 15 Jan 2021 18:52:40 +0100
In-Reply-To: <cover.1610733117.git.andreyknvl@google.com>
Message-Id: <ba6db104d53ae0e3796f80ef395f6873c1c1282f.1610733117.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610733117.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v4 03/15] kasan: clean up comments in tests
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=AhDiNVba;       spf=pass
 (google.com: domain of 3gtybyaokct0zmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3gtYBYAoKCT0Zmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ba6db104d53ae0e3796f80ef395f6873c1c1282f.1610733117.git.andreyknvl%40google.com.
