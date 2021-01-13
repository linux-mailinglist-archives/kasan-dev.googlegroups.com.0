Return-Path: <kasan-dev+bncBDX4HWEMTEBRBON47T7QKGQEL76HVVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 28EBC2F4FD2
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:22:18 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id a10sf782745lfg.13
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:22:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610554937; cv=pass;
        d=google.com; s=arc-20160816;
        b=QtW0kv3gNbiYzPtkoh2LoUehdYG0WsIZ8I/bWaiIYDiooFOm8wFoeJXGXtqDYF3Bfa
         kI+tZYc+0jHK9XYo7/BBP98kKnyAoXwtAqlFIFUyB5qBuIA/X+nszKFQu09KGjyKz89d
         9izBNPjPpvNeYwaw4iehKcTmx7O2XkJKaWxA8tSdyoOjZ/t+ZlTEJZky0LEVMwDT1Op6
         wOFf2NZbiYKy4AWCbAIQ+Ly3wc2aYFHn6B21H5zps7t2pGiqQArWyRqOqoDbU6iHWSBo
         eoU6hNtQ3JTBBxrBAr3BQgX47ADyc0+0DWA20dO5Vd7/8jDr2EY9+seWkGIUsMRz/bka
         Qq+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=zAyvF3lzrdtZbUpdRZOgqaDnPHVK7n31PQx0vwN7v6E=;
        b=V7bdH0Ur2b+jJ127uDyxgPB9Wuh8ZzZqUCgc7fsSMTPE86x0MRqb146xCqW6zpSjkD
         ytQgoCVmN+3EhRTO6M0dKJ5YRxA/PkFSQazHoLJwqo+jCus69+B+mVYqoAKQO4ymmJ2X
         S1K4nR+9KiNXOAZ4ALOc8VoRHjT80u49vvr0WXlIAHqmYtQkUR/yAkeBpCYdBf6YSjqW
         +uJJSmRY4P/oTS7pIadpaoNCTE2Yo3wMWos1h+vZlVGjqYUxwLDkcqZv0jjASp7uaxyL
         FNM2AxeTgq7IB1+OehzDBKiRRmM/WrXWVnXJLXcx++BSzBRFXlq+u2z3rci5w6GOA4QG
         9/Tw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BR5Ommjy;
       spf=pass (google.com: domain of 3ob7_xwokcxcviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3OB7_XwoKCXcViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zAyvF3lzrdtZbUpdRZOgqaDnPHVK7n31PQx0vwN7v6E=;
        b=JVgGe1K+Rw7knzmOfA2F/zjxdxofjVSbFuyK+K9aSqNjab2MztOAAO289L4MVIpQyc
         lquo6OVSTihw38wpDxk5wIhYkDkHwp24VyNwoByj3+plYl2pFO0geNBzYJFJ+MJ3DnTh
         UB8k7mGW2vAFdUJjAIIE3GS3JCo0xRwdHuE5eUT/BEvzrU3EZqS+0O/9GcsY9yWqI8hu
         /XksOV1QyYkyVFG3K3FSEFq66C7GX8eKsd3qyEn9Z3Gn7xr995VncsofkFI319K88Jna
         dwe3JJauaZK1gjwLgZ12s+wcV9/TE7SroxK8adIHO7FF4zOVl80f4fSMy/XqLmK2fdvO
         ILFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zAyvF3lzrdtZbUpdRZOgqaDnPHVK7n31PQx0vwN7v6E=;
        b=lZBdBumqyeVcEEqwNoiuePNxgMWcdrmM/7dsOXJnxtimvy78GG7sGdwziA0hAxgnMz
         M/R+bFE4bi3c70bkrCqdp1l5Ge6qDs6C4xhML2p5gaoEt+vJcDCwIliUBBD0Fn7BSTpv
         a3VhVp4fzKGOve0lclPKz3Y+h48BUBmswDoyTYWA3VA+7isG3togOZJpgF+SauiSX7hr
         jGzWZxIU9Ga24fDoPlvAOn5vCK+5HLyiZqf8cnnRS5njHoUlAEoaGnZ97gqbJ7dVh2I0
         iw6Ar6lKK7JjdFm4HsEsSCilDn6NMEhMcywwqzuzg+CjzmAQQVAW1b6VHFUN85Z5VRMz
         RUwQ==
X-Gm-Message-State: AOAM530BL+fY0u/gaQg85sXEUhAcsGtbIJub0zFOD+vt8o5HCD7b0uz+
	X7tErlD+ZXcS5CikhWy1fGg=
X-Google-Smtp-Source: ABdhPJzkAwMbwYfyIkoHdDJlvVn+20iJWHsBPihAPzqu6Np7qx/hhrq1s+JB7e4AMAYzT+nM7yDdQg==
X-Received: by 2002:a05:651c:1254:: with SMTP id h20mr1250658ljh.211.1610554937751;
        Wed, 13 Jan 2021 08:22:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3614:: with SMTP id d20ls449935lja.6.gmail; Wed, 13 Jan
 2021 08:22:16 -0800 (PST)
X-Received: by 2002:a2e:9053:: with SMTP id n19mr1319721ljg.283.1610554936761;
        Wed, 13 Jan 2021 08:22:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610554936; cv=none;
        d=google.com; s=arc-20160816;
        b=l6WZAevb3q8rfi5XKSkeBwway42cW92gd+BpNXgIjoiyqDNhCaDTz65TtbJcElNuOS
         CHo4qJNBBT2BaDQ30lEh2Nemn5EmAAecjL1u4Zv4stg90x7RqE5zCFmLtL0wWzfJsoZ5
         DEAS6eK32tazY8FmB8RVZoMa2h7tVh8DzmHATSfp/JUOhwhC38oknWkUtnU2l2OrHn70
         VU6vU1Iz7RGVAKNDY61dScpBGE1LNqsvTTQlnOVyLqGCqnEC7tnIfIsZfTwkwRRK/HVq
         Zf73Iq2onPIkEPSBuhwYd7rUvg9gxW6XVT41/ygkFUEfxHRKkddwTs4vDNDFcROlaUbo
         IAhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=qQVzFZxhqiBzY9F1wdp+d+EdRYAfotcsjSYx9y4am/0=;
        b=BTao9xyaqO3j3uX8L/TrmSe2wZPtwsmJn2dh9Ouko4/qbbPuKt94OEGuwGGIM7IJ84
         u9GqVsYoAIft/r/rEdIVupGvj/OArPMF4NgYOkbHZPd7TWnIwkC1GO5cNadQ6o5VijkT
         fMPVa+4EXtsDDjyegK/j+PdaP1KvREkb44W5BKeKyFvG2o+yPee2ARn6TrdnhH6xxhAc
         oSqZvb8gJeaEt38omBPs8nwvMMiVwcJsx+2j2xhcZlyuEzVpAtvI3clD3leepTgpPhss
         pULLB/KvgJggEl1lJQ7vz0PDbasiIj9mKdMwDwzvqn08bginYo6UepjUsukpGXZ8Ecpb
         3ofw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BR5Ommjy;
       spf=pass (google.com: domain of 3ob7_xwokcxcviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3OB7_XwoKCXcViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id z4si160142lfr.7.2021.01.13.08.22.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:22:16 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ob7_xwokcxcviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id e12so1187512wrp.10
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:22:16 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:4f82:: with SMTP id
 d2mr3382368wru.87.1610554936199; Wed, 13 Jan 2021 08:22:16 -0800 (PST)
Date: Wed, 13 Jan 2021 17:21:39 +0100
In-Reply-To: <cover.1610554432.git.andreyknvl@google.com>
Message-Id: <b7b0ca13a5a4d0d9d8b2fe88a9c3c154bb885294.1610554432.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v2 12/14] kasan: add proper page allocator tests
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
 header.i=@google.com header.s=20161025 header.b=BR5Ommjy;       spf=pass
 (google.com: domain of 3ob7_xwokcxcviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3OB7_XwoKCXcViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
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
index 710e714dc0cb..5e3d054e5b8c 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b7b0ca13a5a4d0d9d8b2fe88a9c3c154bb885294.1610554432.git.andreyknvl%40google.com.
