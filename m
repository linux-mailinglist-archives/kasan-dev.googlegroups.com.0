Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSV2QKAAMGQEPHO4YEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 31DEE2F6B17
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 20:36:43 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id cc1sf5472316qvb.3
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 11:36:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610653002; cv=pass;
        d=google.com; s=arc-20160816;
        b=Le/4f+eQ6JnzDkwBWca9K0k5caLMdxQP6YKHgU/854NHJjc79qfbUErsFCnhNaav+7
         mqGTeAIWhC6egQZfGneO2kwVocR8oJCqOtucTyTcLSEFYVJdAr+6FCJBs1gYJ2tqIz4w
         kNwkLbN3ODWfFklCPwEwNU35eW3+WAqST4mIWwnKAYhNCWci0dYgTkzauBVnTR9VGRXK
         cuNlGH95Cp7YKjrJU5P2G+UzMB01ZbiY7fmnP05XdsMZcENp5z/9s4e67Hxt7V+HAvsm
         S79wC1XhHl/eP90WME0GeGCSoMpJORh331lwrt/xFDdAhmCi60bYrHJ1+e2STM7nyzX2
         f6Pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=7igWBwEu8RKZWVKK9K4z6xeRU5X60dB9oXldFoOa6WY=;
        b=ot98BYUcuUV/GradBGsr9+Po7UpLb0vhn40T14R9kA/ZFoXm4sng1YKqBufoGsSngv
         lPHAAzDQCK8D6U18r8o0gGRUWKz5ListM5xCbw8buMoqmgnK5zHYakAS+NbnWEQg3T2Q
         XUr6mYp81+R2RR3VSe97dMT2kTPau806aKW7EAUFbqJXn66P37NPDoQ+uV/3ftW52Hai
         AjLjyzn+z459v+ZX7ioXDXgqHvd5cBpgjjhv5iqjWbf65NgdchV2ItKRE752z4hw/54M
         pZ6Yg+M8QSCIqDE26lL2gmLZHKurRUBLku/2vvba/KjmUm599yH/xR78USt4cVkEY+Wp
         M9Cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=a4R1pdGW;
       spf=pass (google.com: domain of 3sz0ayaokcywq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3SZ0AYAoKCYwq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7igWBwEu8RKZWVKK9K4z6xeRU5X60dB9oXldFoOa6WY=;
        b=b5BYT143UMUhRXlQXcqdH12kl934LCa9FNUEywu7x+mLkdJLhnomrUhlD20kVgc9Kl
         eCtpWACnKTPZXQhtPmBtIRaajBLoTUeWN8F3op4XNez3wouzmf88u2dKj6HVjr8frby6
         B3/4VbYMuDUMAkCHdpB9EXqdi2mBePUZM1LsMwEoPpgxZcBAVnenyzuJndoeWogriSAP
         8CjpBYMwlwLsT88+dUPCn82E7e8mrMzLw5jBG16MOo4M6GG9uaPlkBNfoxXdVIA/+wyA
         imTfSYKUgaZfiOup4EooX/Y+oz9RwMCLRBxIRkiNxEwHoE26Ggirokob77mlELei+1K1
         buWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7igWBwEu8RKZWVKK9K4z6xeRU5X60dB9oXldFoOa6WY=;
        b=AOdyP+/LfUFwLy+vhxwP/3iN2bY9p1nJ430LfXFt18/f4BiCnBdKLFfVZMgarw50Bv
         wkyse059Fsj9nBJSj6U1GDtUsP9cbSDHmVlCsy2NVXQS7OgW2GoBcP3w29aWwVpMZJ+/
         kgoyln5yoYr611FqYL2CiO4wNGmy57uWBkPLjO7CmCR8u89nC3FR5WBPXcnYS2ZnO1+4
         SICzebnl1qKfpRT7TRYHbv0ihPCVy4Um8witpXupTvvEskyTs0SMUSKpX56hbqmcMnbT
         ebaNcioWzlmc7bynTLUQq50dWp7yGh02ZVUzPA2DwIZMVFEndRQpQl0rqZKIQJg6Wy3d
         86vw==
X-Gm-Message-State: AOAM532ej9GFhqjmVda93K81DT5Wa8AdXXlaJ5gzP07HpOPTrbMdYOYw
	hD2jS/F49Xs44u4bprefzws=
X-Google-Smtp-Source: ABdhPJwOwUgwwUEB2fK9VgXqKGu3S1g4CFc36eZ4aO0O498VvJLe3nHpEES4ElIixUjcqFlRGP80ZA==
X-Received: by 2002:a0c:9e50:: with SMTP id z16mr8519776qve.13.1610653002290;
        Thu, 14 Jan 2021 11:36:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e193:: with SMTP id p19ls955898qvl.10.gmail; Thu, 14 Jan
 2021 11:36:41 -0800 (PST)
X-Received: by 2002:a0c:f046:: with SMTP id b6mr8625687qvl.14.1610653001781;
        Thu, 14 Jan 2021 11:36:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610653001; cv=none;
        d=google.com; s=arc-20160816;
        b=Kxs66XLXqBDIqPDHV2HhJpwQ0/qey55ZhrmhnBta19f7XTwKkTcA9Ub0IfpTD6Jldo
         nO2XKJy8H/+D1GZDV88jmhhCxZCnWLtbtHMS2RxHvqImtf0lPUMKQZtnzeVSOdfbvtls
         QbSAZPb/f1z6/8Ej0aofGd8VBs4dC3XmF3eDnheajSrptB7RFvHTA94akV6kQGbye+Hp
         5c1nsEQy7/1B60y2V1JhDqqIxKVFQWcuOn6bu84UPRnW1d0SMr5UYC9tKjc4BgvBALDb
         tzsMGoW12ijXLzjw4CLGnrQvewqGSLhCwPij7/8RGlsbZ6BDcSxuDxX9tYMXv8gSKViR
         MdLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=fbHIgAlgSq4iB7quTf2qhHGKCCFRoCrwGuazo473FaY=;
        b=uoi+RVktsX/Ompq8s5Pn/LUwZVnGf69NPA8AGH6CksWxk16+EgTYxtYKHXNb4GI5a2
         XKbyyFOgjutdyWJLMhLylVYkCuM2zS30BFuvrJtGj4trU99ubwbBss3pgnszOIOeLj8I
         XZJkXakFRhtk9RxqvFczp4dSNjbm/1fdLfjVaAJNffgOffJndhy7U8AQ41XkN4g2Pnzo
         66lSsbiOfIF+SM1BJQjTvFQAkfeSkpTgr5/B0lQLCtAA3ugbUiU/VgbzuGNg2YcjH6Tn
         4m1lSUuAHLM63r7f+G2E8ZUfH6y7quZ/95csiuazIzfQm42kRx5/7QEv/pCRfdPXKOEB
         B23A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=a4R1pdGW;
       spf=pass (google.com: domain of 3sz0ayaokcywq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3SZ0AYAoKCYwq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id q66si312863qkd.3.2021.01.14.11.36.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 11:36:41 -0800 (PST)
Received-SPF: pass (google.com: domain of 3sz0ayaokcywq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id j5so5432858qvu.22
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 11:36:41 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:5a50:: with SMTP id
 ej16mr8471157qvb.25.1610653001425; Thu, 14 Jan 2021 11:36:41 -0800 (PST)
Date: Thu, 14 Jan 2021 20:36:19 +0100
In-Reply-To: <cover.1610652890.git.andreyknvl@google.com>
Message-Id: <e926efdba3a1d9cccccbabdfcc17cef0aa8a2860.1610652890.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v3 03/15] kasan: clean up comments in tests
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
 header.i=@google.com header.s=20161025 header.b=a4R1pdGW;       spf=pass
 (google.com: domain of 3sz0ayaokcywq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3SZ0AYAoKCYwq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e926efdba3a1d9cccccbabdfcc17cef0aa8a2860.1610652890.git.andreyknvl%40google.com.
