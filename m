Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYN2QKAAMGQENOISXOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id DBB0A2F6B23
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 20:37:05 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id o17sf3055440wra.8
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 11:37:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610653025; cv=pass;
        d=google.com; s=arc-20160816;
        b=wUOt+sbdGgkXWZP/64HCbQMX4Hxp1FaHT7tLpmDJobNrrAQen73ME87xz7TlCdC2Tc
         X/qt2BSUoCeLBKRzr93lPGthdj9Umahpp+M22ZcIzVWleXNo+L3waHTFmUyuBMWtP+67
         CPGyTM/b9ZBi4bnIbDO1W37yK1h+KMgVjEL+c5DpcNTp0lKliNrncnh1TEi9F1tgXyRq
         HieZFTWlhCdwGRzVYTBrCfo3z9+VjaArpYkbU80Bdt5hIVJ8OnD4uk3SwA77kA58H7pU
         bWfLTNyiNVoYkFSRE2tWkUwFz3RCBWWlUryuEuRQM25wuJ93VyEDZgR+oViUo7sxgq7U
         dugg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=QZwrb4P3ce6DO4iBfiEzkg2eYb/KZlyP4o255RiKDCE=;
        b=fXfoOJrhCm9etCPfsyTPOxYar4yj/uXZiSYWfWwSrB5uOAeXOBtVlnaFW3Depk0ZjI
         UMEzCV2N3B3xdWRbHg7VyLJymZUwJGMgGwfTv20l2cBixKz92LuFSdprQ4yGteleGAYi
         XrXEGLV5nBQp9CQ1sDjJ2CjRqYu2VcF81zUletCuWfDoQ4XIySaPZGNw4HXtBzmzGpKg
         9eV5Qw1jRXvuawObwXpygpXyuEXTCX+/9dqNQmiNo78wGHShZn6lzVQXRU74W6SyaN4e
         z/IM/gSquXRi0oukoSs5iqWOxwvypAbGYwZ3P6eRbvY65Ya+pi3hSfb3gdn9DfpDfCP7
         pAjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d+cZ3zDJ;
       spf=pass (google.com: domain of 3yj0ayaokcamdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3YJ0AYAoKCaMDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QZwrb4P3ce6DO4iBfiEzkg2eYb/KZlyP4o255RiKDCE=;
        b=HBRI+HhWp9MlQ13NAgCDOVDPbR0i57zLXrEYeC+eFsE1+hkvNdXiA1kxUiRdgkapCv
         nzCYmup42/DVkiZLDZ5TXTh5qt2YdM/SXFfwEMw7SuuZ5LHz8SQFGTVxVtFsfEjavwuH
         aBSDWYYdZPi2tkDHktFdugTTgma+gxsfKZy0dEGull+JmYDz+DQYDYyNY6aGEPH2frkf
         eBs9eI0rLRhkEHITKDg//6tK05ZZR0yWDJ3Bu1zBc83OUhvLkCz4eDuN0IgYArKu4+bn
         RB8NG5vPw0GXpn00NI5J5X8q1tDevb+7PUUx+cyIGbVAN+xXY+AUrl2NjvKgZOMUIaQ1
         LbGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QZwrb4P3ce6DO4iBfiEzkg2eYb/KZlyP4o255RiKDCE=;
        b=cH6ZA4aE6KkaBdtawaHxEKHb0hwE4WLQRGau0WBp6beXIaU4wIqwXVHf5v1Yq/S0av
         OkFH8sTM2e9n1+oQ68GH3dLn1eOOkpJ9T97AemzKZ/NmomGo8AEItgeq6ikw3kO8wTni
         trrHXZpg95CQr1pP2PrvybZNxozAkmn9opfivqnrrl9dJjI7Q8rcf2xfsuqo1uDdY7Vc
         0ijqrsC2S+f4jtY/KDmW4yyTPQe3/nxf0tpDwcI6LsVFHFWkCszyxz7+Bz1JH1xpXvG3
         Cn907V+jsyp558vZq3kKa0L7tm+Nl+Dc3ONacJkMYSVrjSvt8k/cukgBS1c0GV0EqTL5
         qSWQ==
X-Gm-Message-State: AOAM530w+RIwv69otmOharLRUyxP6OjSDzCMxdzPDPu9ZpldjQuEoc60
	PbtO32B4FRx8ujieAzUI4Z0=
X-Google-Smtp-Source: ABdhPJy6KcxoLiBoh5527aRFNSsoth3yFzWkYP39lJahwKhCGtrMIxkec0kxkC997xs9tS9M8aEQdg==
X-Received: by 2002:a7b:c205:: with SMTP id x5mr5564754wmi.115.1610653025670;
        Thu, 14 Jan 2021 11:37:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6812:: with SMTP id w18ls6481457wru.1.gmail; Thu, 14 Jan
 2021 11:37:05 -0800 (PST)
X-Received: by 2002:a5d:6c66:: with SMTP id r6mr9398879wrz.86.1610653024967;
        Thu, 14 Jan 2021 11:37:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610653024; cv=none;
        d=google.com; s=arc-20160816;
        b=mt3xvq266aP/W4QUGAc74M0gzy0RfsdZKkSUjBLeifzCMg9KH9kvX2YXF32g1DjU7t
         8LWiCL2jouJyHU418N4jlDc7P+ZzwoZL5Qzqpg05zc8k/sQ57Yb+9Z0D+9v6R3LoJez7
         4q6pptkB7nO7jzc5tAu+bGXSBITsCHaZdeaMQUE/TOhybXkY+XPBz45YuOa4Tl5pomiS
         s0Bpz0dnS6FRdXL7ijep4DrSGlF0j3LQ0DllvfLIa8SoTRo66oZnjLgwY/Fg+cppiqgY
         TQKO717r+Y13pQA64/yzQSBgRD3vtfd0td1t5dXNK29GG8OnTT8NRnNHoSHMJNBviSrn
         r2GQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=dVTMart08UEQbM+6MiYEncY10URoyB/dLUX7v9OKI+o=;
        b=Lk4StW32HQ+u7ezU3VREcrJDuutNO5YTMGhE1FNyMF5a74Vrz4eENksOZka4iHJHDB
         CdT6lr138W1Q9FmPjFvCySsHjPg5Qm0hRW7Z3XP8StKvqHmXkkzsZ8hCVcAP13pcIlCZ
         fK0GogYTMj0GtDKUDno99izCyI5GYICB1VubmkZE14aKlswIWxwzszCXZ9j42v/SQzrD
         SnsdSllxHxp19swE93ip2BIEtyPuhStwK4YOOJYNpoqbVIdWLLmcwK+L4yBESRU1h2vm
         5vJOV8vV1EIvkZ1gJt9IHjILdtWzdd0gyKIhL0tQaOk3qDNby2BHNb+PwNEhn+Xi3lej
         SKyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d+cZ3zDJ;
       spf=pass (google.com: domain of 3yj0ayaokcamdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3YJ0AYAoKCaMDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id d17si459737wma.4.2021.01.14.11.37.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 11:37:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3yj0ayaokcamdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id k67so2259183wmk.5
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 11:37:04 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:208:: with SMTP id
 8mr5434266wmi.143.1610653024740; Thu, 14 Jan 2021 11:37:04 -0800 (PST)
Date: Thu, 14 Jan 2021 20:36:29 +0100
In-Reply-To: <cover.1610652890.git.andreyknvl@google.com>
Message-Id: <bfc0f14e57057863d50144a9b1864645cf389403.1610652890.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v3 13/15] kasan: add proper page allocator tests
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
 header.i=@google.com header.s=20161025 header.b=d+cZ3zDJ;       spf=pass
 (google.com: domain of 3yj0ayaokcamdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3YJ0AYAoKCaMDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bfc0f14e57057863d50144a9b1864645cf389403.1610652890.git.andreyknvl%40google.com.
