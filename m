Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTN2QKAAMGQEOJWH3JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id B24CF2F6B18
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 20:36:45 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id x186sf2267494lff.7
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 11:36:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610653005; cv=pass;
        d=google.com; s=arc-20160816;
        b=no8zWYlOmXls71sxBscqElVHiUoqMdYuorS+zkhsUcWgoxKG5cgeRV5W7cskezYG1/
         QrGINgq13ct8bTGxLoEDFjSuykbvQ4hXJcHTfkRIoP/yWdQ1EiQdd9IL9TpFF1V/lBu8
         xhxsnPaHFOtrciLIkjnd4he8keZGmAsJSaI16U/jvZurjVwrv+qj8O6YttV/GBptk1M+
         VmpGsJq0e36Z2K2SOCf4xPPnXMGjy43KKFYrZnK3WoKIhNDpbU1VfCrKTujaT6CfQ1Nn
         nUuaydW3GlYgfIoFmeEOMtIiU2LisCi7A2p1f/uSL4445cj+Y86ouESZ3L5BcfogtYWL
         UZnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=hHTHvpT+yLzofjZsOl4066ELpxjbcUc5F0ZOuLB/YVE=;
        b=UPQJVGIQyTepqw/cKlRPNNQJKbg4qbPu+FR/uTmnZkZLpSFfY4eR0gXLRf7zGfANkV
         cIUbwq2MnFlabd+SC1gPspxOQXr0/5gsOGX7S/lbbT23Jn12eHYyWcXoRWT5MPbLdMCJ
         XONh4rnhM+gIyVwzKhmUnTmt4qsxLhB2u9AoTsiWyC6jMHJA327ySH6k6j8iNPgof8MA
         S9oLG6E98QnUdpQJldi6rlK7ByE7zsz58hXOKkTdV7sd5o8y9KUTz9trcZ0/TCiWbGqm
         Par5IcawGofYezwzkH4j5I4K9VWKs12L9vr2mzregYKtetpho0LYwp3dcsxBevZl4urb
         GK/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Dx+ztVnv;
       spf=pass (google.com: domain of 3s50ayaokcy4s5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3S50AYAoKCY4s5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hHTHvpT+yLzofjZsOl4066ELpxjbcUc5F0ZOuLB/YVE=;
        b=fYMK1OtB17hohfXsOpZHBvrkjZ/+u+k1kPZXn9t59g/H3JXoZpP2X+pwlHNnrltoXl
         Lg5dSWC6CKQOBZzhOMFC4PMk/MzXY+iYe8N5nFXIF90YEQCDa82q9DALpLH3SqSbGAal
         THTEmS4fnq3hYHP6t61mTPMxk0yZef80eD5l/Hk50JyGdb6f+XMGNr/fuCJZfKYEaqaV
         BDH34XquUwZ0Mn8BJZwKW4CmkNvvuZvQfe6Dcpvtm4P1HTeQJIkuxktBIz1XwLVFVL/5
         SniNVYKxqeK01qqMONjQLygcOZzksDibhBQNrDI1JDUAyPajJnvlAvza3Mkyg5kdVU/0
         wJLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hHTHvpT+yLzofjZsOl4066ELpxjbcUc5F0ZOuLB/YVE=;
        b=PWC+Y8qAd1nog7O0t1d0bIAG2sM6vbL+hXyFlSkht7x8xzhpjSKa6c8/S9Ov1KAj00
         02LKyjZ1vgpojvN2cyWUsJIJDckmocrYU/hNHIijhf7mw8aR0Pcvu6ruC0GFGwrmY2uy
         QDJTH3Wh8axzrMcpkMWnUrfxYyua4sYub+rSQUivoVW5iksJ1/WZgLeD/yRWml8dhkoZ
         2827ayzQn/LX09mBZlRk/zwfNJl6uRzec0X7WST38IswBTeAWQMfrpRq/gFHM9+tGiQw
         +CigmeW3y2l5vLIHg0O5UENKwG6RJKPG9cTI1CQPNhsolfiiSCG/fBa5xdojBHLcVaY5
         dbow==
X-Gm-Message-State: AOAM532JGkhJZpz2jMj9f1eeCS9ToPh2fLHSEw82F/GzeUd9cy/NblJm
	R0c2TE6N7GSbPrQZetr3xl0=
X-Google-Smtp-Source: ABdhPJxnrgqoa09Q+JojMGee9tPGAtuo0JQdBACl1yWOqiQl79+tYM2bhydGJvMvoKzq+j8RC8B6Fg==
X-Received: by 2002:a2e:8013:: with SMTP id j19mr3697744ljg.434.1610653005264;
        Thu, 14 Jan 2021 11:36:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:5816:: with SMTP id m22ls1143385ljb.4.gmail; Thu, 14 Jan
 2021 11:36:44 -0800 (PST)
X-Received: by 2002:a2e:9246:: with SMTP id v6mr3696598ljg.221.1610653004250;
        Thu, 14 Jan 2021 11:36:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610653004; cv=none;
        d=google.com; s=arc-20160816;
        b=qF8bQohAwSO9pYsRFchgDbly0Mi1hrqvWAC0z8rY5fOvzQ98jwBKUyf41F/qTczDdY
         uNos5Z45Nip4tt3Uw22+dSJigLzbiVUKJQSBTWg9h6G1NtS6U5DUboXMH1SnPlmEyv6d
         wuyW36uBMRqULHSQ0s43Zxsss9cMu0CiiPF6dxoc5kNG1ACjQBXsn+iaVJ9PR2WP23c4
         BQ2xEogcPyFCjo8XykHwxE3wMyT71uquXAXpfRPSMyLkxVV3NZjL3q6j8nneQ3/65sl/
         HXpB0s60bFatk+8DFWJhO9ZoUJbExjJjHDC+gf8pLdCGhysbc6qTSXkIpMycLxSiHu6r
         /RUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=zMg6r0lhSdqTSYHUPwBG8lqIjESWbLf3bRfMeCJdmw0=;
        b=syJfDi/UAJfLTgxcprqldu8GaJ5/T8TCy4//GR3qSDPIw4rt6CkhizobhaQ9k5pWKR
         LCRadBm0FNivC1jPkNkj8NkWA/XYPyTQ8WvhXWpH0hhuX/9Ku5s0h/uwSLCMZnTYqLAo
         I6eyjYV+CmCHSXURq+Mb8y69vEN0TJInUYMDFeClhoTtlYuUQWmyDZYsMEFpq/tlgS19
         G4Ia1tly6QZeWTWgvSthFZwnNRZP+Ow9onmi1eRUN0kcMgBNzdHi+cttXOA0zS3f78FP
         M7hSU7GgUtjtT6wbFfJmlZS5Mum59BO5DxFEWxY1I+8LiCAwd5/bAn8Vocc/YwOhJgdb
         GhhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Dx+ztVnv;
       spf=pass (google.com: domain of 3s50ayaokcy4s5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3S50AYAoKCY4s5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id w10si204112lfu.1.2021.01.14.11.36.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 11:36:44 -0800 (PST)
Received-SPF: pass (google.com: domain of 3s50ayaokcy4s5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id u18so2238994wmu.4
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 11:36:44 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:cf08:: with SMTP id
 l8mr5430516wmg.189.1610653003717; Thu, 14 Jan 2021 11:36:43 -0800 (PST)
Date: Thu, 14 Jan 2021 20:36:20 +0100
In-Reply-To: <cover.1610652890.git.andreyknvl@google.com>
Message-Id: <7723d28506e41b5b7da1b4540b80f3f13c92b33f.1610652890.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v3 04/15] kasan: add macros to simplify checking test constraints
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
 header.i=@google.com header.s=20161025 header.b=Dx+ztVnv;       spf=pass
 (google.com: domain of 3s50ayaokcy4s5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3S50AYAoKCY4s5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
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

Some KASAN tests require specific kernel configs to be enabled.
Instead of copy-pasting the checks for these configs add a few helper
macros and use them.

Link: https://linux-review.googlesource.com/id/I237484a7fddfedf4a4aae9cc61ecbcdbe85a0a63
Suggested-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 101 +++++++++++++++--------------------------------
 1 file changed, 31 insertions(+), 70 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 6f46e27c2af7..714ea27fcc3e 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -73,6 +73,20 @@ static void kasan_test_exit(struct kunit *test)
 			fail_data.report_found); \
 } while (0)
 
+#define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {			\
+	if (!IS_ENABLED(config)) {					\
+		kunit_info((test), "skipping, " #config " required");	\
+		return;							\
+	}								\
+} while (0)
+
+#define KASAN_TEST_NEEDS_CONFIG_OFF(test, config) do {			\
+	if (IS_ENABLED(config)) {					\
+		kunit_info((test), "skipping, " #config " enabled");	\
+		return;							\
+	}								\
+} while (0)
+
 static void kmalloc_oob_right(struct kunit *test)
 {
 	char *ptr;
@@ -114,10 +128,7 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
 	char *ptr;
 	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
 
-	if (!IS_ENABLED(CONFIG_SLUB)) {
-		kunit_info(test, "CONFIG_SLUB is not enabled.");
-		return;
-	}
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
 
 	/*
 	 * Allocate a chunk that does not fit into a SLUB cache to trigger
@@ -135,10 +146,7 @@ static void kmalloc_pagealloc_uaf(struct kunit *test)
 	char *ptr;
 	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
 
-	if (!IS_ENABLED(CONFIG_SLUB)) {
-		kunit_info(test, "CONFIG_SLUB is not enabled.");
-		return;
-	}
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
@@ -152,10 +160,7 @@ static void kmalloc_pagealloc_invalid_free(struct kunit *test)
 	char *ptr;
 	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
 
-	if (!IS_ENABLED(CONFIG_SLUB)) {
-		kunit_info(test, "CONFIG_SLUB is not enabled.");
-		return;
-	}
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
@@ -218,10 +223,7 @@ static void kmalloc_oob_16(struct kunit *test)
 	} *ptr1, *ptr2;
 
 	/* This test is specifically crafted for the generic mode. */
-	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
-		kunit_info(test, "CONFIG_KASAN_GENERIC required\n");
-		return;
-	}
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
 
 	ptr1 = kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
@@ -454,10 +456,7 @@ static void kasan_global_oob(struct kunit *test)
 	char *p = &global_array[ARRAY_SIZE(global_array) + i];
 
 	/* Only generic mode instruments globals. */
-	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
-		kunit_info(test, "CONFIG_KASAN_GENERIC required");
-		return;
-	}
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
 
 	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
@@ -486,10 +485,7 @@ static void kasan_stack_oob(struct kunit *test)
 	volatile int i = OOB_TAG_OFF;
 	char *p = &stack_array[ARRAY_SIZE(stack_array) + i];
 
-	if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
-		kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
-		return;
-	}
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_STACK);
 
 	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
@@ -501,15 +497,8 @@ static void kasan_alloca_oob_left(struct kunit *test)
 	char *p = alloca_array - 1;
 
 	/* Only generic mode instruments dynamic allocas. */
-	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
-		kunit_info(test, "CONFIG_KASAN_GENERIC required");
-		return;
-	}
-
-	if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
-		kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
-		return;
-	}
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_STACK);
 
 	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
@@ -521,15 +510,8 @@ static void kasan_alloca_oob_right(struct kunit *test)
 	char *p = alloca_array + i;
 
 	/* Only generic mode instruments dynamic allocas. */
-	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
-		kunit_info(test, "CONFIG_KASAN_GENERIC required");
-		return;
-	}
-
-	if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
-		kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
-		return;
-	}
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_STACK);
 
 	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
@@ -593,11 +575,7 @@ static void kasan_memchr(struct kunit *test)
 	 * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
 	 * See https://bugzilla.kernel.org/show_bug.cgi?id=206337 for details.
 	 */
-	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
-		kunit_info(test,
-			"str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
-		return;
-	}
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_AMD_MEM_ENCRYPT);
 
 	if (OOB_TAG_OFF)
 		size = round_up(size, OOB_TAG_OFF);
@@ -621,11 +599,7 @@ static void kasan_memcmp(struct kunit *test)
 	 * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
 	 * See https://bugzilla.kernel.org/show_bug.cgi?id=206337 for details.
 	 */
-	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
-		kunit_info(test,
-			"str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
-		return;
-	}
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_AMD_MEM_ENCRYPT);
 
 	if (OOB_TAG_OFF)
 		size = round_up(size, OOB_TAG_OFF);
@@ -648,11 +622,7 @@ static void kasan_strings(struct kunit *test)
 	 * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
 	 * See https://bugzilla.kernel.org/show_bug.cgi?id=206337 for details.
 	 */
-	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
-		kunit_info(test,
-			"str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
-		return;
-	}
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_AMD_MEM_ENCRYPT);
 
 	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
@@ -713,10 +683,7 @@ static void kasan_bitops_generic(struct kunit *test)
 	long *bits;
 
 	/* This test is specifically crafted for the generic mode. */
-	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
-		kunit_info(test, "CONFIG_KASAN_GENERIC required\n");
-		return;
-	}
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
 
 	/*
 	 * Allocate 1 more byte, which causes kzalloc to round up to 16 bytes;
@@ -744,11 +711,8 @@ static void kasan_bitops_tags(struct kunit *test)
 {
 	long *bits;
 
-	/* This test is specifically crafted for the tag-based mode. */
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
-		kunit_info(test, "CONFIG_KASAN_SW_TAGS required\n");
-		return;
-	}
+	/* This test is specifically crafted for tag-based modes. */
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_GENERIC);
 
 	/* Allocation size will be rounded to up granule size, which is 16. */
 	bits = kzalloc(sizeof(*bits), GFP_KERNEL);
@@ -777,10 +741,7 @@ static void vmalloc_oob(struct kunit *test)
 {
 	void *area;
 
-	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
-		kunit_info(test, "CONFIG_KASAN_VMALLOC is not enabled.");
-		return;
-	}
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_VMALLOC);
 
 	/*
 	 * We have to be careful not to hit the guard page.
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7723d28506e41b5b7da1b4540b80f3f13c92b33f.1610652890.git.andreyknvl%40google.com.
