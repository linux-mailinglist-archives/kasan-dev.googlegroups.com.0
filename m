Return-Path: <kasan-dev+bncBDX4HWEMTEBRBCFNQ6AAMGQECQIGWSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 90A422F82F6
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:53:13 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id j21sf3360682lji.17
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:53:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610733193; cv=pass;
        d=google.com; s=arc-20160816;
        b=xmr69XYqF9O1o956CcDDy/3DzFjcmdnl6HzT5JPAxRazq+ekjZ2clBzhvuIuIUUhBU
         rC2pJC3Zx8n6R4MRdq6E6tiyBfVWHq13TkQ4yhnifUJqZY6HJiInYzzSBL38DrtklGtT
         JNVGTIo/UkVigua0BfRvHCtEcWmi8L1OPH18TP4kc4kKvWC+aMU4fLFx6CLtRh33/6Ha
         2WSVlc4m3RvCn+zVB4rAt3B94bCsvH7IJFMJ94fXKn1VWE9aDVUrY0r9olrA6GlKRGsA
         RU5vKTL8SpQY4eQLyejpw+80C+lKLNc8QKscp4T3Y7dOg7vmWNK0YQp5wDibCYUJHzpq
         hTbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=SSzDtdGbOJ3cCNd5+8Eo6XKGVNJD7dVbCXSnhuZEa3o=;
        b=rspB2AQ1xUvgy4RVuAQ+7I9wcn591Y6jjsMymXLs2pt7g0wH0YaI/jaFPR2jhncXlw
         diDwWt6a+or+gSktOwY1fS0KAqqopYEU/OTCjHYLKqTfLRLI8NyG2KyGv8GDmrAnehQp
         SCa0Xe3kldPiELFhRYaQC7k6GQJrNt0Fy8oE643bSucAvk/+Cpmxnd+LeFMXACcfS4Gq
         vzM+SzXZxDQBy9CpMwIwPHi5K1/NXSwXDCJD8m04/7fDa1hReIoA0GcqGrZHHwlcK+GY
         d0sXDutn3HmS7Ft0cZZqrJPemrCK2UZ9k3qtaqQ4+d3IYihwAVeL3fEwboQsjjSof89n
         iQJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UpDZIP6x;
       spf=pass (google.com: domain of 3h9ybyaokcuierhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3h9YBYAoKCUIerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SSzDtdGbOJ3cCNd5+8Eo6XKGVNJD7dVbCXSnhuZEa3o=;
        b=SHQW7ApvS5aP/LAf1FxEAhm36t7tIaNr5xa7hxIyaJBetdqEue8rBdCf95ULcYf0WY
         oppyDrx3o29DD45VbUni8TKhnNHlAxiZMF7pm0hh7eSwZW9kPJ6LPl/ZMyB3rm3E4mz1
         MDLxB3d3dh0U0BfzPjPFBEIWmC9ZwV3xunIrtAbp/9Prh45IAsFGfYVAb2cSu7aiPi3J
         0D8T41oXeiXYPCYb/msqsstHdv4BFvsYyRmo4YcIyT7yd+mBBpu1xZNvP9Zkcg/XT8fr
         loadqDzWDcncCvVvbkeuBArm3jlL321qWngyBUqcf7lq+duURJE8XJORKVvv6kH0jN76
         81Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SSzDtdGbOJ3cCNd5+8Eo6XKGVNJD7dVbCXSnhuZEa3o=;
        b=g/B/FXmPUtSTXDUdxfxl2CmzPcqHr2N5YvM/j93laT5F6/Gk7nYYA3tBCj3kWAvDoB
         oXxZ+8Puphlq/HcuuSZKf5Izre03LuPukrb3CdOUrmiPH4XjdBa4fVbJbCU7hc/VUydI
         rHlWxaB5nPC5SVAGDJJahpcwAhAcO5S778v0Bub11V17rLzHwWZJF9DAv+Tyj/AakePW
         5t4jG9hDT0nnuUhiLuFMHmbyHTgRLzYKz398o6DMnM5kE3tsBzbKlN+9u1/iLYfTaYJy
         ciTy3SEWhGT+0VJBq31h6u00l/LRkrURpJfo+ciY6Zkf5v/lfUf+rulHDEb8F7jejMv5
         HA4Q==
X-Gm-Message-State: AOAM530H4ac0kRbGWBOoeUz/5HkK8J2NLfzR6RLH9lkg+SAXDzB67ShA
	qRXs5pYFH+m3kIRKBBTtbZE=
X-Google-Smtp-Source: ABdhPJzKeiJYP4eYkQQ0QwHR08QEMSrpHttohQyUMjJdhoNa4c4clPBwcPexjQOWJXCzRUf/LIdeFw==
X-Received: by 2002:a19:4311:: with SMTP id q17mr6089106lfa.453.1610733193170;
        Fri, 15 Jan 2021 09:53:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:51c4:: with SMTP id u4ls3062710lfm.0.gmail; Fri, 15 Jan
 2021 09:53:12 -0800 (PST)
X-Received: by 2002:ac2:5199:: with SMTP id u25mr5748711lfi.438.1610733192150;
        Fri, 15 Jan 2021 09:53:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610733192; cv=none;
        d=google.com; s=arc-20160816;
        b=D7Tgi1n5HtCyjhHi4eu1ObGxnzj6e/6UUi6XwIVNKwBrsRrowBtryDFmAEjaN0iccg
         n848mNAUySbRz+qOR/Jir/XI72miAyHxy9/iO1KFCDKwNLP5c5in4aN08Qk8OI/0s1mC
         GD44K4tTlaEP0oZguqnf3L16p2uRGOTHK/H1wqvlk7HnvXXtRePokNdoFn82Y26B6LDb
         ZEl28q8nJoYWOJNrItVrLzM9yt7UPb8Npgko3ziT17b++IRgwBrmqJQdTJGwZ19s0iU3
         SptHmSweSpzxLoMm6rqAUnqYh+XBR16MbuWK+LlN251oEDQUrOI6Kj+iNOz3aCRFLgzQ
         DmGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=jfWJXOWlHJo7EltzDAfS0s8ib651kGruxNglu567YtE=;
        b=jZ8FJrKxRtQkJDZoGD8DHmIfiMNdjvNtZmD4uT3SBX/g/4XI2N+gz1CZsdmth1bb86
         HzrssieJWyhT+3AduYMD4qkeZqwxwDXGCh7CXo/EuJdK49T9hPz98Rszq9oLq/PUcpkN
         QyEPIY1ANzgY0+fu9UL9v27TKJ/urmkkLd/Ob8OKeAOoL6K+yov1pVKprL0oLh6wKgBh
         b1TutO7TeAVRwje5BwlUshorPe7eVHzCxNqwbPrlRCC3q4QrlYmVil6rPyPQBTiSP2fN
         6pt7+Idq4xT+KIv6U3OZzlEJomMB+2wMOUl20IrkW7VG2zZi6Mcwp7fx+KGOIDLIL8kC
         Taig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UpDZIP6x;
       spf=pass (google.com: domain of 3h9ybyaokcuierhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3h9YBYAoKCUIerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id e8si504206ljo.5.2021.01.15.09.53.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:53:12 -0800 (PST)
Received-SPF: pass (google.com: domain of 3h9ybyaokcuierhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id q2so4467472wrp.4
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:53:12 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:e919:: with SMTP id
 q25mr2033205wmc.57.1610733191375; Fri, 15 Jan 2021 09:53:11 -0800 (PST)
Date: Fri, 15 Jan 2021 18:52:42 +0100
In-Reply-To: <cover.1610733117.git.andreyknvl@google.com>
Message-Id: <da841a5408e2204bf25f3b23f70540a65844e8a4.1610733117.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610733117.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v4 05/15] kasan: add match-all tag tests
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
 header.i=@google.com header.s=20161025 header.b=UpDZIP6x;       spf=pass
 (google.com: domain of 3h9ybyaokcuierhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3h9YBYAoKCUIerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
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

Add 3 new tests for tag-based KASAN modes:

1. Check that match-all pointer tag is not assigned randomly.
2. Check that 0xff works as a match-all pointer tag.
3. Check that there are no match-all memory tags.

Note, that test #3 causes a significant number (255) of KASAN reports
to be printed during execution for the SW_TAGS mode.

Link: https://linux-review.googlesource.com/id/I78f1375efafa162b37f3abcb2c5bc2f3955dfd8e
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 92 ++++++++++++++++++++++++++++++++++++++++++++++++
 mm/kasan/kasan.h |  6 ++++
 2 files changed, 98 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 714ea27fcc3e..c344fe506ffc 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -13,6 +13,7 @@
 #include <linux/mman.h>
 #include <linux/module.h>
 #include <linux/printk.h>
+#include <linux/random.h>
 #include <linux/slab.h>
 #include <linux/string.h>
 #include <linux/uaccess.h>
@@ -754,6 +755,94 @@ static void vmalloc_oob(struct kunit *test)
 	vfree(area);
 }
 
+/*
+ * Check that the assigned pointer tag falls within the [KASAN_TAG_MIN,
+ * KASAN_TAG_KERNEL) range (note: excluding the match-all tag) for tag-based
+ * modes.
+ */
+static void match_all_not_assigned(struct kunit *test)
+{
+	char *ptr;
+	struct page *pages;
+	int i, size, order;
+
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_GENERIC);
+
+	for (i = 0; i < 256; i++) {
+		size = (get_random_int() % 1024) + 1;
+		ptr = kmalloc(size, GFP_KERNEL);
+		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+		KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_MIN);
+		KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
+		kfree(ptr);
+	}
+
+	for (i = 0; i < 256; i++) {
+		order = (get_random_int() % 4) + 1;
+		pages = alloc_pages(GFP_KERNEL, order);
+		ptr = page_address(pages);
+		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+		KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_MIN);
+		KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
+		free_pages((unsigned long)ptr, order);
+	}
+}
+
+/* Check that 0xff works as a match-all pointer tag for tag-based modes. */
+static void match_all_ptr_tag(struct kunit *test)
+{
+	char *ptr;
+	u8 tag;
+
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_GENERIC);
+
+	ptr = kmalloc(128, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	/* Backup the assigned tag. */
+	tag = get_tag(ptr);
+	KUNIT_EXPECT_NE(test, tag, (u8)KASAN_TAG_KERNEL);
+
+	/* Reset the tag to 0xff.*/
+	ptr = set_tag(ptr, KASAN_TAG_KERNEL);
+
+	/* This access shouldn't trigger a KASAN report. */
+	*ptr = 0;
+
+	/* Recover the pointer tag and free. */
+	ptr = set_tag(ptr, tag);
+	kfree(ptr);
+}
+
+/* Check that there are no match-all memory tags for tag-based modes. */
+static void match_all_mem_tag(struct kunit *test)
+{
+	char *ptr;
+	int tag;
+
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_GENERIC);
+
+	ptr = kmalloc(128, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+	KUNIT_EXPECT_NE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
+
+	/* For each possible tag value not matching the pointer tag. */
+	for (tag = KASAN_TAG_MIN; tag <= KASAN_TAG_KERNEL; tag++) {
+		if (tag == get_tag(ptr))
+			continue;
+
+		/* Mark the first memory granule with the chosen memory tag. */
+		kasan_poison(ptr, KASAN_GRANULE_SIZE, (u8)tag);
+
+		/* This access must cause a KASAN report. */
+		KUNIT_EXPECT_KASAN_FAIL(test, *ptr = 0);
+	}
+
+	/* Recover the memory tag and free. */
+	kasan_poison(ptr, KASAN_GRANULE_SIZE, get_tag(ptr));
+	kfree(ptr);
+}
+
 static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmalloc_oob_right),
 	KUNIT_CASE(kmalloc_oob_left),
@@ -793,6 +882,9 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kasan_bitops_tags),
 	KUNIT_CASE(kmalloc_double_kzfree),
 	KUNIT_CASE(vmalloc_oob),
+	KUNIT_CASE(match_all_not_assigned),
+	KUNIT_CASE(match_all_ptr_tag),
+	KUNIT_CASE(match_all_mem_tag),
 	{}
 };
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 3b38baddec47..c3fb9bf241d3 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -36,6 +36,12 @@ extern bool kasan_flag_panic __ro_after_init;
 #define KASAN_TAG_INVALID	0xFE /* inaccessible memory tag */
 #define KASAN_TAG_MAX		0xFD /* maximum value for random tags */
 
+#ifdef CONFIG_KASAN_HW_TAGS
+#define KASAN_TAG_MIN		0xF0 /* mimimum value for random tags */
+#else
+#define KASAN_TAG_MIN		0x00 /* mimimum value for random tags */
+#endif
+
 #ifdef CONFIG_KASAN_GENERIC
 #define KASAN_FREE_PAGE         0xFF  /* page was freed */
 #define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocations */
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/da841a5408e2204bf25f3b23f70540a65844e8a4.1610733117.git.andreyknvl%40google.com.
