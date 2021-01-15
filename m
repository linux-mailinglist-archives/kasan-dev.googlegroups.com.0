Return-Path: <kasan-dev+bncBDX4HWEMTEBRBBVNQ6AAMGQEUW27U4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id F2C942F82F5
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:53:10 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id x10sf2029950lfu.22
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:53:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610733190; cv=pass;
        d=google.com; s=arc-20160816;
        b=R/Wr2ce+bxFywlUf748y2aYhcu7OO94SOqi4xY06Nv3IlILPpOpBXG8u+2ukx+17PK
         n8s154Hd2VpHRkoTGu76I6zOEx3DTh4t3bUIQZGeZmnzfyYk+kuHTKeGFno7T3REFA+M
         Mc2ImMnEGCtE449AHUY1L5CBMpxaTAouJVD4iAUGzzFGX33A62KrTDu/krGQ4n1cKCsL
         uBcSbCk76KMeVaVbtM8mb+2rAf0FOf22SUtP1QO1JU+lLgzXwFIEViWkTucLxSBI8h62
         cKk5dAvMUxpLv3CqiZKk1tp59V7yuzA+fXJ1PWpnJUbM5tSL1VZptKJjwQDqOCBDLOao
         k/8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=UG5M6iELJ3QmIvIGcY2X17hWR7PK2VS3QAlfeYRh3us=;
        b=Yw/bQ2yn5AxFyeCJP5C9C4DrmC4qwZwjNfLWKCZMb6yPafaas+oO5FJBxC24k1/uCg
         eFxxUDD0cX+JU7OzpmQUHisJiNA2er/KJGN8QX5+S+5RHvxrS47vAVIYEI2Sf/57Q0xx
         lZUlhaU/VCrbM4S+d7i+cjXHCfJRmj+lySU6QAsVPQOLIVi9FgEKA0oEdSkunMO9BtsL
         LNVviTute/fmDiTU3HfJYUF5B25I+iqhuSWS0Q+QgKzR2iW3IjISPJi2OReo0D3vyLYs
         LyC9H9sJsCmsdfqDRN/+YBohy1kbbQmL559ygesGok1LjFrKTAuHuRev8KjxpI2nJDkR
         cpxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="BdrM/Ogt";
       spf=pass (google.com: domain of 3hdybyaokcuacpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3hdYBYAoKCUAcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UG5M6iELJ3QmIvIGcY2X17hWR7PK2VS3QAlfeYRh3us=;
        b=RV46BIrZr4ma4Jsie27QwzK8TsWrViWjpaA0eTRAL4Go8hgH1WgBTCNwnO5JTF6k4p
         QlWgmVJqk/WdIm3HbHmriy9M3hZ6VhcWSOYU6K3F+rilBFiby1SZeRPNBXBRfHCaRUl3
         AJlTwSnrsywQaGynA5OYjA9N1SUqG1BClSFP5huRoy7ogoyXctW5dPjm0ebe+4iXEvu6
         mS/KeaZCoLYsL9DpfbK6z53RSs0L0Lu6BR2XLWYUHSETeXMwfh6aJPrHLWP7IUzR/lTe
         agYngdw9OXC72rtldFzoWynD/PXLY3aT5dCYnpdD/e6imNEarGtbS5li98klZXoK+ywX
         fNAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UG5M6iELJ3QmIvIGcY2X17hWR7PK2VS3QAlfeYRh3us=;
        b=lF36ZbPYNW4tbKPjmk+gXMh7LySwXM16OkwyiTC0663Uwb+YB0y1lo8QL0rPO24fm6
         6ne3UXJ0jcscbjHqkIpl37yrXngZm0RvrncW6IiZlSsj/LhFL8DG6r9/kiBewaO6aGN1
         s8A7Ton/OmfG6rOsu36T5Xf2FtebxLsmQhq0rfYpa7OR2Xe1uuh+K6zGyyIrxcqXTPGk
         ZduphjTXXldcCr/EreHF2brrlvE0bAPEX/ik5AAo90pH4tgBVCFs0YeAH1ynehcrt8cO
         rqbUlBZ02V6F2kuY7Aze3tHYfpuafQJe45F5Qu6ScXc+f7SyARWM8NUWcXS4elbA3g39
         sHZg==
X-Gm-Message-State: AOAM530q84gIaVoLHoOtVrTHDaiIP5qGbMHaFYPcNbSUGqKkSN2u7huy
	liH8bZi5701mOkhiLV2x0PY=
X-Google-Smtp-Source: ABdhPJy6rrofkzrydGZCt2IXJkXGZNvwUP16MpW0CMMDLc2mDlitl9sCPFGP3iKBBUP0yOgaOCqJWQ==
X-Received: by 2002:a19:5041:: with SMTP id z1mr6404752lfj.77.1610733190546;
        Fri, 15 Jan 2021 09:53:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c1cd:: with SMTP id r196ls600302lff.1.gmail; Fri, 15 Jan
 2021 09:53:09 -0800 (PST)
X-Received: by 2002:a05:6512:3748:: with SMTP id a8mr5738481lfs.31.1610733189651;
        Fri, 15 Jan 2021 09:53:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610733189; cv=none;
        d=google.com; s=arc-20160816;
        b=YnxP9fcAAABFYPf+MwHyLiUOrVLQxLwb7VK4yRgBe2oCnVJPgUmJ4hwBw+mYKyZp1H
         fRZsLVywdj2UeUInWV6lif9+IF9EMUSo+9Sc6SzJ2VM2jEAHxLqsgyyuZpg4Y31+vomB
         BYMbl2znfP/5drozHUMWFAtHkX1qkV+6pkV7mBrOClMhgoD3pOup/9xCGMp/AXNXVq01
         LfkydTmZcTpyStfn5r5AI21ulxDpdQX3DPfS8d/iT4tzYc+tyXOrV/SRlvseiczFP9Se
         +g/IkWCvpQkTWAGCblRwKE/0CGGvyagOHnwB7nyuImzyCxCywyVWiXgG2fxtTpozR1YG
         4NFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=zMg6r0lhSdqTSYHUPwBG8lqIjESWbLf3bRfMeCJdmw0=;
        b=u08Sl7iCfhaDc36y+a4FOtC+6O4/C2RI2VV6a7iPx2/1lROUykeFQpLo0OqkZhmKaK
         VFB6mA2Ng+/osoOxM44/B4FecvHtYYyRGEVdz7FqiRCL2IL1mVg7RxrCB9rJ095lxPB+
         Og2hN57IvZnvTVOLKFGF4n20FeaIvZCVFZUjbSkigTOaRd+jhn2yJZ2tDacjykfn7HUG
         lFIoRhfnmlbNVl8Sj42KowUgX1WpboekbS6ACgFiLJ6LfRGdX/rd8NY77V2stW+8lvgx
         d1KJ+tOJ9nF7yWbHdwAU9w0qPNW7R6gIpUryzfXLPOiTGl4hRhZYRBTKI6reM3eBLBGe
         7hyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="BdrM/Ogt";
       spf=pass (google.com: domain of 3hdybyaokcuacpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3hdYBYAoKCUAcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id r12si345037ljm.1.2021.01.15.09.53.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:53:09 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hdybyaokcuacpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id i4so4472374wrm.21
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:53:09 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:4f8a:: with SMTP id
 d10mr14096449wru.219.1610733189015; Fri, 15 Jan 2021 09:53:09 -0800 (PST)
Date: Fri, 15 Jan 2021 18:52:41 +0100
In-Reply-To: <cover.1610733117.git.andreyknvl@google.com>
Message-Id: <6a0fcdb9676b7e869cfc415893ede12d916c246c.1610733117.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610733117.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v4 04/15] kasan: add macros to simplify checking test constraints
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
 header.i=@google.com header.s=20161025 header.b="BdrM/Ogt";       spf=pass
 (google.com: domain of 3hdybyaokcuacpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3hdYBYAoKCUAcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6a0fcdb9676b7e869cfc415893ede12d916c246c.1610733117.git.andreyknvl%40google.com.
