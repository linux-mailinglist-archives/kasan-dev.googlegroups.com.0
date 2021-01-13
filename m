Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJF47T7QKGQEFMPBSFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 899362F4FBD
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:21:57 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id t16sf1826059qvk.13
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:21:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610554916; cv=pass;
        d=google.com; s=arc-20160816;
        b=NmcmPrtKbH8npbmXtuZqS8NlmzrSi1UeyCxdl4lxoXTPEkCkka+wK5mMDPl1p5GlPi
         +k74R4hOCTnX2Y0IsoXSFtgdJjOqdWgGeT5lQNorq8wASYg42pwqDiua0/toWv9AQOUb
         Os4IMapfDuWpJa4FWnKoby3o6mqHQNkFS/zUMefqFBpVQ4VpM6KTtYyDICx1KDYmVI1t
         vEbZwjIVWndg5jS8MyGVkkmP1v+65WPWRgXCIguscbgjztfcvCEkACfXBDSOokC1I0HV
         oO2+SHa1ctXDe76uD8XCouZ5RnuBZB+/VgipoXbIb05tzoFPNiwp/EyC6JGHTT9wBdIm
         VlMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ZIZa75Zvd+7VkhU03gmgofUWLWIoht8yTinCBsRx0YU=;
        b=yCJK3o83YyrGTEy4PKK4Q/QOFnP0W3XPMQeTSCRBOqb2bZ+WNFlQTzcV7CgbiC0EAI
         1ZzoMexzQxuMupPmFoZlc5n8NuTV2F+GEryYI6iOiR4KiZ/iaEt/KWiH3y69u0G2zRrt
         yh9dRwjaEoiUIZlSHx3flC37GHBPt7XPp5LnNOGM0B539QMQy/RHDXvs+8uAeGmVOuDH
         IwZrf3Zzii6D0BrSSc66jFL84MrjwR2225pPLWhQzPWkd27hGuf91zLrEJECKTHr4q01
         Zguy7yvh+glLRqs8b7ep51selQMwVCzMC8DjB3BETkAsGzVpThYLmp6XSh0OSLF6F4Tv
         JftQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fdy1k4tr;
       spf=pass (google.com: domain of 3ix7_xwokcwiandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3Ix7_XwoKCWIANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZIZa75Zvd+7VkhU03gmgofUWLWIoht8yTinCBsRx0YU=;
        b=KOb5sDOAqDVmBs/uoWyynChqus4+EP8/GUz2m36yNb6cGw97VazD5yrVeHBlGEm2XS
         8gje7k+0UNQSkDT5jc5Y/eK/nthg/zBfBAy/r1woQZ+okf8A+Qdcg6QoTe/KQT3rCQgm
         fxycgkkxYXanNrRGEKy6Sug+4wx5Byodi68kg9bB2Ysvli7zCrUB8DKPYxWIXOatse+5
         6rsWDWB1514XPK8bXBTVYLS8BTBfy+u3iX3ewpMnlniLT2g4YDtBKrRtXZWtUvaCIpgp
         0uVtQnR0E7YxlrXChB/wxe3AZjEIDIxPEoR3K062wnB1vU6Csh4UhJmLGgGx2BtERUBV
         bHCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZIZa75Zvd+7VkhU03gmgofUWLWIoht8yTinCBsRx0YU=;
        b=JzGROzUfyr3pHbSKWGx38gcrutMt72k23KsPiOkpgD9j7xCpsQlM6TXs/BZdzkgnTT
         lcHcQU05gyaRxA/lYRrBpKf9NLVkQSnwSPRFsf9iOldat9VClgJ8VKFIO+JUZSjvEtsc
         p2/mpqToV3+6rlrRd4uTt/kSR77OOWFIPzEVZwK0M8e25+1xVhuzHHObsot0HLVIHJ2r
         gyT8oIs+KhaGgk7z3rW54jnSs/aCFeiPncY68s3qCg2mWmqj4R14BKgj+Zh3LV9j5syE
         EfLKYPaLbTuszhbdr8CqDDIDwgCVzljzm/2QifDwy7bxmzSMyLfk5xwjk9EDTzy1NYiz
         /72w==
X-Gm-Message-State: AOAM532y0AqMwpWjznWddxJYPfNReYUXkiMNGM+Z0Nb59dgxegjm2UGJ
	5zWxMSRHBoO5QIw0O3phn9k=
X-Google-Smtp-Source: ABdhPJyJER11hfTJp7h6zpELfiZ4E1MYsoGvnbeTz6sSB026mGwsKBzEWQ9hH6sbfah8rh8kY6u5lg==
X-Received: by 2002:a37:744:: with SMTP id 65mr2659359qkh.71.1610554916458;
        Wed, 13 Jan 2021 08:21:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5a04:: with SMTP id n4ls1011504qta.5.gmail; Wed, 13 Jan
 2021 08:21:56 -0800 (PST)
X-Received: by 2002:aed:3462:: with SMTP id w89mr2958092qtd.265.1610554916025;
        Wed, 13 Jan 2021 08:21:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610554916; cv=none;
        d=google.com; s=arc-20160816;
        b=vSB9nBocgtFId/2g+2zHrIezR5esAyWUYVLU2wUr7Mx2vMVMJ6n36x+/2M7s5D8OWW
         VIYQA1s7TNVemwCvIJ9f2kHJDOivGJJbrE0uC4JdO18qSePa/uolTbOH10U/mHzzpA9T
         cNcwkOO0Zi91B4d2kqus4h27jmQMzrgxEY97ZEYeHNFvKFQntDq18Wf6Y2/TJYLjWXix
         LC9EgJLu4mU4zZfv7cvFc4bZf0+g8vFp7dhNcgMj1JjqyblTIHbuoB2eWPTHi/buFOPX
         /Xg4mTyc9SNcIgo1TWxdvnQJ16yM1cPvM3+HigBX7CWYM1R6CoqBfQqqWE+9g8/rPGZQ
         fLew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=NrBKtYAmD/isC1216fec2dkJzyenocsmafXupmAvlwI=;
        b=Kbm65BcMfAhcjGFjLXFyJTzWyi6DiqhVqUWJG6G//S5A3AOaDM/gEGzvm1X64FCO8R
         ++FuelZVxqeFUKbqAxJboeP9M5Vf5quUtpUgyra0qHLqGiYyL0MYgRjsbWjsie+kvCGa
         7PlJB51xcNqBKkZO2Hm6/a//PXzrCZHwptSeBlwEtVsxc1uaKBAsiishq1bPQnDLb5Mu
         QK3X9tN3eh/G2BYKA/mdFdG5ZAqtaCWj7PkcENsU/hUCMc2XCo7Z7mNYuWwHhOq6G5aF
         nNFSXcyanN4xWia6u5xHoL20UsFzxiADqF2P1Kh0I179Oka4vi8QNImHaT1EwFde6Flj
         QUng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fdy1k4tr;
       spf=pass (google.com: domain of 3ix7_xwokcwiandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3Ix7_XwoKCWIANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id z94si269978qtc.0.2021.01.13.08.21.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:21:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ix7_xwokcwiandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id v1so1840030qvb.2
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:21:56 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a25:d805:: with SMTP id
 p5mr4507114ybg.46.1610554915686; Wed, 13 Jan 2021 08:21:55 -0800 (PST)
Date: Wed, 13 Jan 2021 17:21:31 +0100
In-Reply-To: <cover.1610554432.git.andreyknvl@google.com>
Message-Id: <0afed913e43017575794de0777b15ef6b2bdd486.1610554432.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v2 04/14] kasan: add macros to simplify checking test constraints
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
 header.i=@google.com header.s=20161025 header.b=fdy1k4tr;       spf=pass
 (google.com: domain of 3ix7_xwokcwiandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3Ix7_XwoKCWIANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0afed913e43017575794de0777b15ef6b2bdd486.1610554432.git.andreyknvl%40google.com.
