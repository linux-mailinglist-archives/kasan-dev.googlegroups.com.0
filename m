Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6VT4GAAMGQEHSL5YQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C58F30B09E
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 20:43:56 +0100 (CET)
Received: by mail-vk1-xa38.google.com with SMTP id s18sf3580807vka.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 11:43:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612208635; cv=pass;
        d=google.com; s=arc-20160816;
        b=xtoY6+SRXc4xecKfx8vHBUAocUyqVv2d+K423GCisoc8w+4wsMPsS7w6CT9qdfwXnf
         n63B9BJn4RyLS8Pbpd6fZxzH0XB9slvR/uCyaKlWjhyLnmPSdR4Qnr6Wofyg6Uk421pP
         aPadVI+EPIEkNyP2BTZlekHiwEuiMFAqZAM4xg7OYpA5Fywa9Rh5DtCrbPuA59Q5/KYk
         jKLKM0PHGEnNEUSRHa7nr3RgqhZ8PvS2BsQfDABpBCEjdiJRkDHBXLA095jycByukLyU
         3i8HwDjuWT16qiMqxMP2GGY4gPc3/RtTP37lF6zqFbQFojh/gjDdgHy+OSBvH+HoQXvj
         krWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=5kMuO06mMJ6Dyyp7P03oCzNVrs5yqG0HVUdp/EP09YI=;
        b=aWXeAjpx0YbZMKYRV3NhKbfJY/TRr7xENPXHJShFH09QBstAOtVaP4M1DHwQ7bRWTS
         190Fcz02IpaESd3xapkhy0mPTolQEAYnIEA3uCwUPXgH/byfCT2fPVAcrpTnnuqpqwc/
         xa1dRf+47EkDfsboH9N8a09Z+RIH0ZdSHJfwppnMSUCRjO3JV7Q+bQaHffFyK2RGdauY
         D6Avutf1jFXZIuvy/e2N61ykqFNV107Ha2h5FO8n/jDd+NPMdJSBXJ6Z8mQtKTn/a3oU
         ulLbLV0ClN4Ympl0vfPg2vxMjHz7w80Jw/j1/ggEmnPvBbN75dgrcgiDJX01cSX9PofO
         f21A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nnt2QvzS;
       spf=pass (google.com: domain of 3-lkyyaokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3-lkYYAoKCRcxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5kMuO06mMJ6Dyyp7P03oCzNVrs5yqG0HVUdp/EP09YI=;
        b=IMckYgX0smUxVk1sTOX5FssmuD6V5ZIDNTyfsFPTHoaWo+gLlwl8blQxMX8duIl+td
         HN1RXXVNx3eCvBxNYGRqlbDlnXwKcH+QG6MC41Y311Ilwc24C7nL4ygpQv4H139TR1TV
         JHMQBGsTGDBO13aWntKezYllkVKbd7S3wA6HQKptw2ykhnTLVWdmS0VWeYJ/LTzJQijy
         cvP5kC90Q9e7wdqtEkBVAQ/sBx7ccmDSYUcMM5CVc58XIQ2EBm3t87HLY12JN/6aBhjM
         tOrb+7qvEt+SZ4DXOtI2/qnXh8Nq1f8eswN7rTrAXaRRJHassYlQfr/yt1JKkAWkUloR
         TjWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5kMuO06mMJ6Dyyp7P03oCzNVrs5yqG0HVUdp/EP09YI=;
        b=p6O9c1gmSYPvIOfo+pCs5IspT1MEH0xQjgvbOuAAhZBsl+fI1s2Y1wqJNYKSSWr8XY
         qHXJ9R3xk2HaygzN3cxw5553E63T5ooiHJk8ynQEnuzHipRP911VPUbm/GPEWp1YD+A8
         +3b/rtiaAvGzbTV+JH6IeV1BN72EAY26U8o9UbM4SQP28XgzOeVUPswlk3v5A4kzMYdX
         sUHjc2eXfIhHlui4hd7fbdyP4MJY4n6pIl1YipdQul+14XsM8+lrezvjUsNwwblG/3J2
         K0G8Fo3uFgDmPteRwBkcvyafVCfaCYcR8tfum9FFTmWZbx12WYr+Vuz51tJWpmgS9pm9
         rMFw==
X-Gm-Message-State: AOAM531rYPXkwwiisy86PzLMNyz4E44onIVMNvr1rZxJ3/WFUuYfTfEx
	kk1dGBSL8vlQzzZ3Kej2bSc=
X-Google-Smtp-Source: ABdhPJyhLA363Q7CYpSITUtz8LDgpTsr/plA+4IDQtPnM6tmOFZW/FPol5WMR2Cu/vA4AmQOKpZ6sQ==
X-Received: by 2002:ab0:6e4:: with SMTP id g91mr10045404uag.20.1612208635123;
        Mon, 01 Feb 2021 11:43:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:fb19:: with SMTP id d25ls2095563vsr.11.gmail; Mon, 01
 Feb 2021 11:43:54 -0800 (PST)
X-Received: by 2002:a67:11c3:: with SMTP id 186mr10098509vsr.3.1612208634613;
        Mon, 01 Feb 2021 11:43:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612208634; cv=none;
        d=google.com; s=arc-20160816;
        b=I5ddLPxZGQnFybT3YmGHhmKhXsE69NTJ3/4s+qfmOOD8zt3j52otNrRyDuNx+bk33D
         CwZHW8YvsRafR6pNZhw15d1i6BicTGFUblM7HNjqQiD6kJ5lNJYLGw6RAsgy2XUQIzGP
         mikI81OSSHMaEWvWdkKzG5wdfWwPcD2ZP4MPdBYNYJZuKGEaH9gVy5IS5gZynBuqgDk2
         w0i+egrTUqBhQAbIPj48P1ZbXwYg+d2iNeGkrgop6/29SwcPMEbUQ4yBaahURFvjctQt
         8Ct8IXWEprVAyO0S7h+iJKUYf4+pItd/It6s8ark+VVqwjF5RFru/lfL8l+FaRGBR47s
         94Uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=XCxo0tPucACpabOxuZtkTLtcboXhH0Xr2jZowtJcY6I=;
        b=rHiDGfRO51g5t8Z3+/aDd8ggy8YN2xMJc5fwj/VeFUjJWAB8AXLYgg951KI+Jyeun/
         WPO/pPqEayLu7CNSGEn+Ftss6CGz5ajhrglxpFrxyGkL1+COpIpe19hr95Xp94yAF8p8
         PRXBdTWHJfm7Dv25NqYBcq07s/TzgOBnSfeZXwMD+bonyiZB2iGuYgws1eBG87c6hYLs
         vUYZNoNg/nPPT9V3eMV7KdgtSuhYu98og8DlP0VeM+IJJR1cPw5sm2wpQdUrzEgQOgUk
         0WwBe4fk/1yWqVEIkCRA+8PFQapcN6E/D6HlEDJNaxkfGWBuQIL2G5NAz7/BUN8ePJPe
         16iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nnt2QvzS;
       spf=pass (google.com: domain of 3-lkyyaokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3-lkYYAoKCRcxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id y127si811165vsc.0.2021.02.01.11.43.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Feb 2021 11:43:54 -0800 (PST)
Received-SPF: pass (google.com: domain of 3-lkyyaokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id h13so12050138qvo.18
        for <kasan-dev@googlegroups.com>; Mon, 01 Feb 2021 11:43:54 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:40c6:: with SMTP id
 x6mr16803415qvp.10.1612208634261; Mon, 01 Feb 2021 11:43:54 -0800 (PST)
Date: Mon,  1 Feb 2021 20:43:30 +0100
In-Reply-To: <cover.1612208222.git.andreyknvl@google.com>
Message-Id: <995edb531f4f976277d7da9ca8a78a96a2ea356e.1612208222.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612208222.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH 06/12] kasan: rework krealloc tests
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
 header.i=@google.com header.s=20161025 header.b=nnt2QvzS;       spf=pass
 (google.com: domain of 3-lkyyaokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3-lkYYAoKCRcxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
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

This patch reworks KASAN-KUnit tests for krealloc() to:

1. Check both slab and page_alloc based krealloc() implementations.
2. Allow at least one full granule to fit between old and new sizes for
   each KASAN mode, and check accesses to that granule accordingly.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 91 ++++++++++++++++++++++++++++++++++++++++++------
 1 file changed, 81 insertions(+), 10 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 5699e43ca01b..2bb52853f341 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -258,11 +258,14 @@ static void kmalloc_large_oob_right(struct kunit *test)
 	kfree(ptr);
 }
 
-static void kmalloc_oob_krealloc_more(struct kunit *test)
+static void krealloc_more_oob_helper(struct kunit *test,
+					size_t size1, size_t size2)
 {
 	char *ptr1, *ptr2;
-	size_t size1 = 17;
-	size_t size2 = 19;
+	size_t middle;
+
+	KUNIT_ASSERT_LT(test, size1, size2);
+	middle = size1 + (size2 - size1) / 2;
 
 	ptr1 = kmalloc(size1, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
@@ -270,15 +273,31 @@ static void kmalloc_oob_krealloc_more(struct kunit *test)
 	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2 + OOB_TAG_OFF] = 'x');
+	/* All offsets up to size2 must be accessible. */
+	ptr2[size1 - 1] = 'x';
+	ptr2[size1] = 'x';
+	ptr2[middle] = 'x';
+	ptr2[size2 - 1] = 'x';
+
+	/* Generic mode is precise, so unaligned size2 must be inaccessible. */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2] = 'x');
+
+	/* For all modes first aligned offset after size2 must be inaccessible. */
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		ptr2[round_up(size2, KASAN_GRANULE_SIZE)] = 'x');
+
 	kfree(ptr2);
 }
 
-static void kmalloc_oob_krealloc_less(struct kunit *test)
+static void krealloc_less_oob_helper(struct kunit *test,
+					size_t size1, size_t size2)
 {
 	char *ptr1, *ptr2;
-	size_t size1 = 17;
-	size_t size2 = 15;
+	size_t middle;
+
+	KUNIT_ASSERT_LT(test, size2, size1);
+	middle = size2 + (size1 - size2) / 2;
 
 	ptr1 = kmalloc(size1, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
@@ -286,10 +305,60 @@ static void kmalloc_oob_krealloc_less(struct kunit *test)
 	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2 + OOB_TAG_OFF] = 'x');
+	/* Must be accessible for all modes. */
+	ptr2[size2 - 1] = 'x';
+
+	/* Generic mode is precise, so unaligned size2 must be inaccessible. */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2] = 'x');
+
+	/* For all modes first aligned offset after size2 must be inaccessible. */
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		ptr2[round_up(size2, KASAN_GRANULE_SIZE)] = 'x');
+
+	/*
+	 * For all modes both middle and size1 should land in separate granules
+	 * and thus be inaccessible.
+	 */
+	KUNIT_EXPECT_LE(test, round_up(size2, KASAN_GRANULE_SIZE),
+				round_down(middle, KASAN_GRANULE_SIZE));
+	KUNIT_EXPECT_LE(test, round_up(middle, KASAN_GRANULE_SIZE),
+				round_down(size1, KASAN_GRANULE_SIZE));
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr2[middle] = 'x');
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size1 - 1] = 'x');
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size1] = 'x');
+
 	kfree(ptr2);
 }
 
+static void krealloc_more_oob(struct kunit *test)
+{
+	krealloc_more_oob_helper(test, 201, 235);
+}
+
+static void krealloc_less_oob(struct kunit *test)
+{
+	krealloc_less_oob_helper(test, 235, 201);
+}
+
+static void krealloc_pagealloc_more_oob(struct kunit *test)
+{
+	/* page_alloc fallback in only implemented for SLUB. */
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
+
+	krealloc_more_oob_helper(test, KMALLOC_MAX_CACHE_SIZE + 201,
+					KMALLOC_MAX_CACHE_SIZE + 235);
+}
+
+static void krealloc_pagealloc_less_oob(struct kunit *test)
+{
+	/* page_alloc fallback in only implemented for SLUB. */
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
+
+	krealloc_less_oob_helper(test, KMALLOC_MAX_CACHE_SIZE + 235,
+					KMALLOC_MAX_CACHE_SIZE + 201);
+}
+
 static void kmalloc_oob_16(struct kunit *test)
 {
 	struct {
@@ -983,8 +1052,10 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(pagealloc_oob_right),
 	KUNIT_CASE(pagealloc_uaf),
 	KUNIT_CASE(kmalloc_large_oob_right),
-	KUNIT_CASE(kmalloc_oob_krealloc_more),
-	KUNIT_CASE(kmalloc_oob_krealloc_less),
+	KUNIT_CASE(krealloc_more_oob),
+	KUNIT_CASE(krealloc_less_oob),
+	KUNIT_CASE(krealloc_pagealloc_more_oob),
+	KUNIT_CASE(krealloc_pagealloc_less_oob),
 	KUNIT_CASE(kmalloc_oob_16),
 	KUNIT_CASE(kmalloc_uaf_16),
 	KUNIT_CASE(kmalloc_oob_in_memset),
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/995edb531f4f976277d7da9ca8a78a96a2ea356e.1612208222.git.andreyknvl%40google.com.
