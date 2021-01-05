Return-Path: <kasan-dev+bncBDX4HWEMTEBRBO672L7QKGQE5Z4DUXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id E8C692EB286
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jan 2021 19:28:11 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 7sf2014580lfz.12
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Jan 2021 10:28:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609871291; cv=pass;
        d=google.com; s=arc-20160816;
        b=mfeHVOrjKMX8mW0nue0WXCys3MnewHGZx/xIW1G352xWe/JkE1SV2VzkGhcWYNmmcH
         jMJUxKGoaqpBuPWEsj0BpT2CvHrpCnUks2BQ564vYGA9kA/SXJ4+L3Y7ZRFRgUepOgW7
         aTCKskcew7+pPr/9jWn0nJojNBkiEF/2qL3p7CqbStqTj0UvmeUN2C4rRAkjrAcSeCi8
         2NHhFBEA3neZmaVTp4xD43zIrcXU/8NiagPj1zApVyxgxFngNMnki7j1wl1j3eFhHwTa
         j0OFEi+LfOlHr+Bp71f1Fhqf75wLRl8xxXrY8J6xL4BevcxJLrek9zc1e35i+avZ/SOC
         xbEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Rch0E8k+cRI+IgkpVksHcsp4n8Iv4OAMJyk9Z5EG5es=;
        b=B5PAVj+ZlZ99yFGwfJgAqhR1fcJOC4yLcBJRgO8gp+qFIpnkPdeMiHbwVcyQlRGWyW
         u5vhLdCQRlRJ91SUSrWnfh61SuXDDpYWBdmKK+3NNbulWAbFX+7KXQqlUGsE95avci0w
         QMA3ydE0WFLk1TrdUl6JUfp7vzERxe37a8s4qPblSgqDa0m1SQjDp9oQOmr3JpvXKUzJ
         lr+l7jZ1E46d1m1VbpjodDVZCG49W+D6urYxEwMMzpG076m66N5vl7q9A4ZPBtYiKprQ
         Od7zk7C9i8CXtkHwTKVHvkoyIXxEegoSTYmdXULC+yERJMbt98Pxbg3KpmvFekCePlWs
         0Vjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fj8BsYWg;
       spf=pass (google.com: domain of 3ua_0xwokcfasfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ua_0XwoKCfASfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Rch0E8k+cRI+IgkpVksHcsp4n8Iv4OAMJyk9Z5EG5es=;
        b=IvT5lGlaOEe/epRcYpLYEcNMKscdZmS6o0fkkHdenEoPa0cfFi8e/uhdimHypUNGPl
         rv5azykaicVrVwu1CnTSCXYfbgcNCobbHb3qvizyofPylMFzw8eHhAEy3V611Dbj+QSi
         ZKyfwFBjVn05j3sLmQeRHhZXSSW118UNK64x2qD02ucMO6CfW9oXbz5kMklZnWBeawgB
         oy3/o119f/LbRIx5Lt4o0Kso04wDWtE2RKoqmLP31OZTkTcJ3p9k8w2ENLrz0YN4jOs3
         n+8u/bm+04PIHbW/xHvsGieE9PkVZhwF8ilsCRVdtqk5G7MQacpA1MPTACzxrvhHMl69
         uA4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Rch0E8k+cRI+IgkpVksHcsp4n8Iv4OAMJyk9Z5EG5es=;
        b=UkuaqZGm83msrKIeGfep1tYhxnaeY6fSLq9mMBlLYjKFdGwvZCmyvi0PW+kD4MgZpy
         ELB9QKKdu0yZe21daevCJDVrCPYJi0vmdXMqOzGeTzhcnEYfyqxkPevsU6kaLvSCEujb
         K01YlfMttWewLFD4jCP6LWDDMt4T3jtnpgN2oLeUR4O5kFO2QPBn9Y2IlLK0n89be29E
         2HJjUJPtab/KWIZgijsia1HNY0dh+P1vCQh2hOQz9xeJNm7XfwgQmpmz8/LVyPeMX5+w
         D68yzMpDd61SuEAPxk9FkLf17Bzz+XIka3+lNCW4wso3LUhMHSh3X93tFDcb5k0oOf7Q
         9Vog==
X-Gm-Message-State: AOAM530vIOnHSPl1Zw/+eVC8xxpE2929mis/Aljmu/15leacqbkKmvsV
	vLwu4lAhL4fnMkNyBZhc62s=
X-Google-Smtp-Source: ABdhPJzKHGVoqA0FzQW4cfAfwNyL5KkIq8GkWDr6KUcgfrB5PnFfHZGZC5a7aNOs/tbg588vFoT/Sw==
X-Received: by 2002:a19:cb45:: with SMTP id b66mr245363lfg.441.1609871291537;
        Tue, 05 Jan 2021 10:28:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:980e:: with SMTP id a14ls128289ljj.7.gmail; Tue, 05 Jan
 2021 10:28:10 -0800 (PST)
X-Received: by 2002:a2e:b0ce:: with SMTP id g14mr416543ljl.352.1609871290423;
        Tue, 05 Jan 2021 10:28:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609871290; cv=none;
        d=google.com; s=arc-20160816;
        b=Ng2ZZ1viuPhbGeRJoFQUb/aZbpCMgdDsw/Ov6DnMz6FyC1wSj1pMX/gZzMYYXkKWe9
         /GqkgTFPML1clBNFGb5FRxuuY0prMIt6Z00b7U6folmkSmhxXomeo8MxHvfxXDPKCkyL
         zRVuXOWxBSnBTnxex516NCDkKtc9AXITnx3zjYOCfO9G+HAikFn7y1xtc5TnDtCyF7gc
         3EJ23DkktgJNeN5SDrn9ZYkbS3ey1LwxeCjm9qOryWwLgROd0X3vsPH4SpvYXVqv098I
         ZvTP5yLJe9XG+57NvahQEPqm64SkrSPQuNqNOHkCrB+QPiuh8SY5SWLGDd4MYqL6jtzL
         oOFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=kMqOwAycKrvTptizhNYAx5EVpfOHvBX1uRwiTYE70ik=;
        b=RyL04EVymTUEmKZBPldWffanDhfat8xgC1l1deCtLEd1v00v2GnDkyutxiqJ+WIbi+
         5mXlq4zuzK6WY7Bo4ZFHT0lk6x2+Hu43cVE6l/Jc/SrMx9TWWOcefw68Z+EmBy4cDSeD
         Pc52+8H1qoMvOp0g8GNLGzEEGrGQ9xQdbJIealKUGcnZHNnGqbKi5/DKnRKZcete0IPm
         IrzdXSCKWoZrJbUC/d+lm3E+z82IQfAVBe9/MNnrMbwpzauyM+cIXxcVzkJWl0ow6q4x
         AR47VnyfNv+ud4bTlaRR0vu4ooXqD+ouNAAgKnm5zUl3Xl3tnUOtq87wjR5gjvBtdSks
         ApbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fj8BsYWg;
       spf=pass (google.com: domain of 3ua_0xwokcfasfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ua_0XwoKCfASfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id d3si14748ljj.4.2021.01.05.10.28.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Jan 2021 10:28:10 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ua_0xwokcfasfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id d2so189863wrr.5
        for <kasan-dev@googlegroups.com>; Tue, 05 Jan 2021 10:28:10 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:4307:: with SMTP id
 h7mr795184wrq.353.1609871289844; Tue, 05 Jan 2021 10:28:09 -0800 (PST)
Date: Tue,  5 Jan 2021 19:27:47 +0100
In-Reply-To: <cover.1609871239.git.andreyknvl@google.com>
Message-Id: <cb4e610c6584251aa2397b56c46e278da0050a25.1609871239.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.729.g45daf8777d-goog
Subject: [PATCH 03/11] kasan: clean up comments in tests
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fj8BsYWg;       spf=pass
 (google.com: domain of 3ua_0xwokcfasfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ua_0XwoKCfASfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
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

Clarify and update comments and info messages in KASAN tests.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/I6c816c51fa1e0eb7aa3dead6bda1f339d2af46c8
---
 lib/test_kasan.c        | 94 +++++++++++++++++++++++------------------
 lib/test_kasan_module.c |  5 ++-
 2 files changed, 55 insertions(+), 44 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 2947274cc2d3..46e578c8e842 100644
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
@@ -117,11 +115,12 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
 	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
 
 	if (!IS_ENABLED(CONFIG_SLUB)) {
-		kunit_info(test, "CONFIG_SLUB is not enabled.");
+		kunit_info(test, "skipping, CONFIG_SLUB required");
 		return;
 	}
 
-	/* Allocate a chunk that does not fit into a SLUB cache to trigger
+	/*
+	 * Allocate a chunk that does not fit into a SLUB cache to trigger
 	 * the page allocator fallback.
 	 */
 	ptr = kmalloc(size, GFP_KERNEL);
@@ -137,7 +136,7 @@ static void kmalloc_pagealloc_uaf(struct kunit *test)
 	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
 
 	if (!IS_ENABLED(CONFIG_SLUB)) {
-		kunit_info(test, "CONFIG_SLUB is not enabled.");
+		kunit_info(test, "skipping, CONFIG_SLUB required");
 		return;
 	}
 
@@ -154,7 +153,7 @@ static void kmalloc_pagealloc_invalid_free(struct kunit *test)
 	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
 
 	if (!IS_ENABLED(CONFIG_SLUB)) {
-		kunit_info(test, "CONFIG_SLUB is not enabled.");
+		kunit_info(test, "skipping, CONFIG_SLUB required");
 		return;
 	}
 
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
@@ -218,7 +219,7 @@ static void kmalloc_oob_16(struct kunit *test)
 
 	/* This test is specifically crafted for the generic mode. */
 	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
-		kunit_info(test, "CONFIG_KASAN_GENERIC required\n");
+		kunit_info(test, "skipping, CONFIG_KASAN_GENERIC required");
 		return;
 	}
 
@@ -454,7 +455,7 @@ static void kasan_global_oob(struct kunit *test)
 
 	/* Only generic mode instruments globals. */
 	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
-		kunit_info(test, "CONFIG_KASAN_GENERIC required");
+		kunit_info(test, "skipping, CONFIG_KASAN_GENERIC required");
 		return;
 	}
 
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
 
@@ -483,7 +487,7 @@ static void kasan_stack_oob(struct kunit *test)
 	char *p = &stack_array[ARRAY_SIZE(stack_array) + i];
 
 	if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
-		kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
+		kunit_info(test, "skipping, CONFIG_KASAN_STACK required");
 		return;
 	}
 
@@ -498,12 +502,12 @@ static void kasan_alloca_oob_left(struct kunit *test)
 
 	/* Only generic mode instruments dynamic allocas. */
 	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
-		kunit_info(test, "CONFIG_KASAN_GENERIC required");
+		kunit_info(test, "skipping, CONFIG_KASAN_GENERIC required");
 		return;
 	}
 
 	if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
-		kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
+		kunit_info(test, "skipping, CONFIG_KASAN_STACK required");
 		return;
 	}
 
@@ -518,12 +522,12 @@ static void kasan_alloca_oob_right(struct kunit *test)
 
 	/* Only generic mode instruments dynamic allocas. */
 	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
-		kunit_info(test, "CONFIG_KASAN_GENERIC required");
+		kunit_info(test, "skipping, CONFIG_KASAN_GENERIC required");
 		return;
 	}
 
 	if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
-		kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
+		kunit_info(test, "skipping, CONFIG_KASAN_STACK required");
 		return;
 	}
 
@@ -568,7 +572,7 @@ static void kmem_cache_invalid_free(struct kunit *test)
 		return;
 	}
 
-	/* Trigger invalid free, the object doesn't get freed */
+	/* Trigger invalid free, the object doesn't get freed. */
 	KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_free(cache, p + 1));
 
 	/*
@@ -585,10 +589,12 @@ static void kasan_memchr(struct kunit *test)
 	char *ptr;
 	size_t size = 24;
 
-	/* See https://bugzilla.kernel.org/show_bug.cgi?id=206337 */
+	/*
+	 * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
+	 * See https://bugzilla.kernel.org/show_bug.cgi?id=206337 for details.
+	 */
 	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
-		kunit_info(test,
-			"str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
+		kunit_info(test, "skipping, CONFIG_AMD_MEM_ENCRYPT enabled");
 		return;
 	}
 
@@ -610,10 +616,12 @@ static void kasan_memcmp(struct kunit *test)
 	size_t size = 24;
 	int arr[9];
 
-	/* See https://bugzilla.kernel.org/show_bug.cgi?id=206337 */
+	/*
+	 * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
+	 * See https://bugzilla.kernel.org/show_bug.cgi?id=206337 for details.
+	 */
 	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
-		kunit_info(test,
-			"str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
+		kunit_info(test, "skipping, CONFIG_AMD_MEM_ENCRYPT enabled");
 		return;
 	}
 
@@ -634,10 +642,12 @@ static void kasan_strings(struct kunit *test)
 	char *ptr;
 	size_t size = 24;
 
-	/* See https://bugzilla.kernel.org/show_bug.cgi?id=206337 */
+	/*
+	 * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
+	 * See https://bugzilla.kernel.org/show_bug.cgi?id=206337 for details.
+	 */
 	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
-		kunit_info(test,
-			"str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
+		kunit_info(test, "skipping, CONFIG_AMD_MEM_ENCRYPT enabled");
 		return;
 	}
 
@@ -701,12 +711,12 @@ static void kasan_bitops_generic(struct kunit *test)
 
 	/* This test is specifically crafted for the generic mode. */
 	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
-		kunit_info(test, "CONFIG_KASAN_GENERIC required\n");
+		kunit_info(test, "skipping, CONFIG_KASAN_GENERIC required");
 		return;
 	}
 
 	/*
-	 * Allocate 1 more byte, which causes kzalloc to round up to 16-bytes;
+	 * Allocate 1 more byte, which causes kzalloc to round up to 16 bytes;
 	 * this way we do not actually corrupt other memory.
 	 */
 	bits = kzalloc(sizeof(*bits) + 1, GFP_KERNEL);
@@ -733,7 +743,7 @@ static void kasan_bitops_tags(struct kunit *test)
 
 	/* This test is specifically crafted for the tag-based mode. */
 	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
-		kunit_info(test, "CONFIG_KASAN_SW_TAGS required\n");
+		kunit_info(test, "skipping, CONFIG_KASAN_SW_TAGS required");
 		return;
 	}
 
@@ -765,7 +775,7 @@ static void vmalloc_oob(struct kunit *test)
 	void *area;
 
 	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
-		kunit_info(test, "CONFIG_KASAN_VMALLOC is not enabled.");
+		kunit_info(test, "skipping, CONFIG_KASAN_VMALLOC required");
 		return;
 	}
 
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
2.29.2.729.g45daf8777d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cb4e610c6584251aa2397b56c46e278da0050a25.1609871239.git.andreyknvl%40google.com.
