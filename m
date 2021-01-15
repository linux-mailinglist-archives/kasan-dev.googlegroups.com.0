Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHFNQ6AAMGQEQXDJS7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A3812F8305
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:53:32 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id q18sf4470637wrc.20
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:53:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610733212; cv=pass;
        d=google.com; s=arc-20160816;
        b=ucmTWDjXuEHcgod+QClbNePLjq0nP86WL1+Qr/RsWK5V984GnoFtKoc2VDEwqLkx+i
         rw7rOqHf5tUk2Td475KfxjV3xggUZwMOJZLtZwrPwXP23RykW1+1AYg8PD9jJisK7JBk
         Xn8MqpOuow8trVxZkl7JgKDY4IZXEWruM5dsY/FXk772+vC3MAmVwdHqZipuA7bLjKek
         dJm9Wwtr9v2apK3EoywBFxbEkyS/LeIpZ1jOceiunl6UDAGFE/t2N5EyZ+MelwtRwvjM
         Dzgdw3RF8ZP5g1nlYbS4xwR2eMyc4wjUHrCGs3VnsaFTugGBLm+tp86gkAEuExBsLqeC
         Z1Hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=waQ6xpG+bnvjwvT91MhrHjFdUytXqgwO7/3uIbLcabQ=;
        b=LjMeV3qk+8sQ4azZVbIRlwmZtnHX1ifA9hK4p48jiwiBETNfcmRThrxi6rlMXVLlA4
         MFzKMuiK/ElQEae8Mp0exgiN0i26iO4R2Wn73jaA/FpIMlE9NQA6MegdVIyD4SKnsH1M
         OmdmGFNqg45DPzUzv5IGZC09DHKHp5SkYNzXIqowMhCGSpsC++7uTMTWbYC1akAX0Unh
         F0JKnZhd1MC48j8UYt9lyV4NlfdG914hEjtQg27EQjIqOe7AEberfzeV81kAP5ZO0tzp
         ir4z/SEI4GYsXHYFexkL4EfEPCsAmpSpbV30BHdWtaDjIWaEkQjWtyJknr3w41521kWd
         oN+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VQk6OorM;
       spf=pass (google.com: domain of 3m9ybyaokcvyyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3m9YBYAoKCVYyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=waQ6xpG+bnvjwvT91MhrHjFdUytXqgwO7/3uIbLcabQ=;
        b=TeTALA7naZ4EVV9s8eDqZ2/IMFBsZ0wVBbosMKGii+IB2wrL1ZXV9wkzm/s8I7FOvo
         ZLJGXh6Mm4zS+jbJVfG8xOe3XKp3rYoRz+L/PEI6tY44v9gMLmj/QAviWLSMsJ4Ar9hO
         jRYT4uzB5v34akhznRIoFIMsM52eTEx7rx4gRvEL8Ey3NI93kY3U0+HorLWSqhbNAIFp
         KV0CuUVWLq3A3KNrjqgUy8guEXWpjJjaeJiHaxWsPDhWIcT3nIHb4FG+oFTmBsX5EgsT
         QlqXM5VA5n7L4WT3rxGwptFnPhoExSBPZRyYUgmsjRlzc8HopnFdZ3Pocv8/COys+eoI
         YUlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=waQ6xpG+bnvjwvT91MhrHjFdUytXqgwO7/3uIbLcabQ=;
        b=CDXBLeLp8LP3FgULk0gen2EZ42a1mbh5DqmTAD87t8O2xCpjviRKlin6rIT+LvXzH7
         gsaBTVgzpvsS3WyfA5tA8uV5CK/xQasfCTbGyZ6QE17FA9ZVTvbBxNn5mdSsaQrjjTdV
         nwUaQpOaZS/zc0o9VhDVrOFcl/jf1crkHV4jzRyq4fQh834V9FaDqMa4jYyg6Fm73XeX
         Yaqgyc85howZ5NsTWAbqUjkd8FlXekARJ0XfyUyD/JApCEgJra0ENp3X8p/zndz2z28V
         uhScTj5Xme3T6HAsY4FESGndYPTiissmMvdUwJ5Isw6exqQRo3lTk4Y5jVzmW00P/PP3
         4wDQ==
X-Gm-Message-State: AOAM531hRdXRnu2U0cR1VQUn8osgo0cPBMHCVRvtwrYuJwvCoKA10Y8w
	1IqYzerAUQ3PMx3i1+y+t7Y=
X-Google-Smtp-Source: ABdhPJyRzXX1Ju15SL7jIiU43P3DhQKoyOyJpDoAHkgbZwYlFyXWSVElG3QVkkzkaBD3OrrbaTxKgg==
X-Received: by 2002:a5d:5049:: with SMTP id h9mr14817798wrt.404.1610733212441;
        Fri, 15 Jan 2021 09:53:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:4482:: with SMTP id r124ls2829294wma.1.canary-gmail;
 Fri, 15 Jan 2021 09:53:31 -0800 (PST)
X-Received: by 2002:a1c:4d05:: with SMTP id o5mr10153711wmh.85.1610733211601;
        Fri, 15 Jan 2021 09:53:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610733211; cv=none;
        d=google.com; s=arc-20160816;
        b=UWghIZYO321XvNylxm0ez5nbBo7EQHCSGs+W5fRCGGwfamBpFzV9zWqCZUxQ6sBy6F
         H2KvT2dshrMnpJLfs4stx/56lWSQ44W/yc0Q3jeDC5nyjLrJDraWVdsSaKQaD+NYHJj7
         8WAmyFnUkJ6iRXILpB8SI8wc7B+e65lBfhn4/BNMoreFIMnRDRiipsEEgNKHxoTDYdaq
         djgRCKeRasJpldyzpAqJQLxyqUrx0CwWF20SHl3QvDxIfoaJzGOT+zapgbFOKYQLoqQh
         rq41ytIUvypU89X9iMTv8okFh30M/TDUwH4TmEVyF8lnkYwsJsZ+67mq7ISWevrF5G58
         hMsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=dVTMart08UEQbM+6MiYEncY10URoyB/dLUX7v9OKI+o=;
        b=KBikF8HHqxoiZPhAtUmkAzArwYZ5e/z7ZG7wGvm31rkKFfcS0wNXH5VELjlKDmHD5v
         dgLk2xJ2/REcbKKsRXmJuGhMvdfcZUA6vNKxMdW+UXP7tyc/mIaBPLSGmSSPpascQGk0
         Lgjfl2zfATLxUKmObtO+uTKHTXxWaEbuzOpgQY2LuKJ8DVxCTFWAfinEAMGu42++JsS4
         gZTpbyGvR3Vj8ht47JUaWNuICHoYilbTEyXAUmLltpGAY2IY7MS2h3WELcDh0Te/AqgF
         0sbwMJ0kei7EpEqxojuHB8MBecWeDe7k9TwO9IwPY8N59xVqIc1J4A2WQhsfMneF52Ug
         EpUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VQk6OorM;
       spf=pass (google.com: domain of 3m9ybyaokcvyyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3m9YBYAoKCVYyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id e16si549149wrn.1.2021.01.15.09.53.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:53:31 -0800 (PST)
Received-SPF: pass (google.com: domain of 3m9ybyaokcvyyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id r11so4452823wrs.23
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:53:31 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:40ca:: with SMTP id
 m10mr9700946wmh.54.1610733211307; Fri, 15 Jan 2021 09:53:31 -0800 (PST)
Date: Fri, 15 Jan 2021 18:52:50 +0100
In-Reply-To: <cover.1610733117.git.andreyknvl@google.com>
Message-Id: <a2648930e55ff75b8e700f2e0d905c2b55a67483.1610733117.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610733117.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v4 13/15] kasan: add proper page allocator tests
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
 header.i=@google.com header.s=20161025 header.b=VQk6OorM;       spf=pass
 (google.com: domain of 3m9ybyaokcvyyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3m9YBYAoKCVYyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
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

The currently existing page allocator tests rely on kmalloc fallback
with large sizes that is only present for SLUB. Add proper tests that
use alloc/free_pages().

Link: https://linux-review.googlesource.com/id/Ia173d5a1b215fe6b2548d814ef0f4433cf983570
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 51 +++++++++++++++++++++++++++++++++++++++++++-----
 1 file changed, 46 insertions(+), 5 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 566d894ba20b..ab22a653762e 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -147,6 +147,12 @@ static void kmalloc_node_oob_right(struct kunit *test)
 	kfree(ptr);
 }
 
+/*
+ * These kmalloc_pagealloc_* tests try allocating a memory chunk that doesn't
+ * fit into a slab cache and therefore is allocated via the page allocator
+ * fallback. Since this kind of fallback is only implemented for SLUB, these
+ * tests are limited to that allocator.
+ */
 static void kmalloc_pagealloc_oob_right(struct kunit *test)
 {
 	char *ptr;
@@ -154,14 +160,11 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
 
 	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
 
-	/*
-	 * Allocate a chunk that does not fit into a SLUB cache to trigger
-	 * the page allocator fallback.
-	 */
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + OOB_TAG_OFF] = 0);
+
 	kfree(ptr);
 }
 
@@ -174,8 +177,8 @@ static void kmalloc_pagealloc_uaf(struct kunit *test)
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
-
 	kfree(ptr);
+
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = 0);
 }
 
@@ -192,6 +195,42 @@ static void kmalloc_pagealloc_invalid_free(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, kfree(ptr + 1));
 }
 
+static void pagealloc_oob_right(struct kunit *test)
+{
+	char *ptr;
+	struct page *pages;
+	size_t order = 4;
+	size_t size = (1UL << (PAGE_SHIFT + order));
+
+	/*
+	 * With generic KASAN page allocations have no redzones, thus
+	 * out-of-bounds detection is not guaranteed.
+	 * See https://bugzilla.kernel.org/show_bug.cgi?id=210503.
+	 */
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_GENERIC);
+
+	pages = alloc_pages(GFP_KERNEL, order);
+	ptr = page_address(pages);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
+	free_pages((unsigned long)ptr, order);
+}
+
+static void pagealloc_uaf(struct kunit *test)
+{
+	char *ptr;
+	struct page *pages;
+	size_t order = 4;
+
+	pages = alloc_pages(GFP_KERNEL, order);
+	ptr = page_address(pages);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+	free_pages((unsigned long)ptr, order);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = 0);
+}
+
 static void kmalloc_large_oob_right(struct kunit *test)
 {
 	char *ptr;
@@ -903,6 +942,8 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmalloc_pagealloc_oob_right),
 	KUNIT_CASE(kmalloc_pagealloc_uaf),
 	KUNIT_CASE(kmalloc_pagealloc_invalid_free),
+	KUNIT_CASE(pagealloc_oob_right),
+	KUNIT_CASE(pagealloc_uaf),
 	KUNIT_CASE(kmalloc_large_oob_right),
 	KUNIT_CASE(kmalloc_oob_krealloc_more),
 	KUNIT_CASE(kmalloc_oob_krealloc_less),
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a2648930e55ff75b8e700f2e0d905c2b55a67483.1610733117.git.andreyknvl%40google.com.
