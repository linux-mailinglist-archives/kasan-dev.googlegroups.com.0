Return-Path: <kasan-dev+bncBAABBQFTRCWAMGQENZ5Y4PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B76D819398
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:31:29 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-40d2f54466fsf4964815e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:31:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703025088; cv=pass;
        d=google.com; s=arc-20160816;
        b=anWn1JBXzoHGxdduWbOvGMKNnTH/xPU4N+Q+AZ9FCtKgmkMra38t++qG3em469ha1x
         z6P6gsXyJYkQGhKt/tWaXqj3fg0EuyOqB3unSP9JBUb4JW/XBrDpM/aOAPOaIN/fKJxJ
         5jRue3THO5KGmsQafyfwpOl9j7+QJfmZn0BL6z5V4k/8qn9I2OwB2KIPPalVvFsNcOr1
         YEcS3yy9kGWfIc0+pRGdE5kUusVfBALohdrTjKwbgn5OMzTJd/b8dqw9r6bDHeMp6KJd
         llL4SI28QiV4a7QfkWqBzyxTgsaE+loQmtLVoUunpMiy6yNzll3/8jgPCkBSGl/EkCYz
         5Csw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6ZYmEQogV0DCxen1k1aaak4bciN1saRuXZqqnv5pGd0=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=PEx77N4pq0va4bEHhP7Zo8BFR0m/Xq/O6Ji0N0U63U7UaP6NkL67lNjyicYI4Gw6qX
         Cxh2cMAuEx0n/UHk2tmkmPbMrGGrN3Qq1OC3LJ5l0KK5ueSDcAmNXQoOvwYN2wMlmUpo
         7BwCXFohvKp21UuYq/Pl89Z3k8dPdhxSIVfWhKq+D1SYohf2Oj4VGsUlUrkBPFqNXtal
         MZ4PnYW48YK59gPOtYRR3r+B2q+2gzMq5di9wV3a7F2PaA5YMAjUwvFaEO8ZCqn29CKQ
         Yap7BFXW409XBFcg4buAMOvHEZrCqO9T3BRj5FdNz8GK9nXpEstuxKKJoQv/mNUIaFEk
         TpwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Iwn4kg+j;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::ad as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703025088; x=1703629888; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6ZYmEQogV0DCxen1k1aaak4bciN1saRuXZqqnv5pGd0=;
        b=Zp0252oew6laEc/m29bg4d6YuxTNmrWesCdkY2UYjaoxIukBgNd9o2N59K+IeFdVfL
         9Ls0XZwwyIkjwsJflUJooSxXCyPQGVmY9T7YGrBdwz8aeHceVPimNj0k5Hv3XvtRIeNU
         ZZgoYRwVKu6k6ZLUOhElHL/twjjVX9ykmN2yLD7hkAq0EmOHSp9Jr/HBhV7wFI1U16ou
         diA2VNISiKUYIu3yMRA+4JYNf2t5bJrsCpxNSzuFSr1DrIvrd5+zu5qNzcAxIwFi0hpc
         arrRq3FrzPimup0lRsUtPibhnAwUkhtOYqX9TwM6+2clXIo+WIrzpeBvjk7Ot4ZHVa0R
         RAKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703025088; x=1703629888;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6ZYmEQogV0DCxen1k1aaak4bciN1saRuXZqqnv5pGd0=;
        b=eHhslzQ9k/mCTijjhzRyfjf0lEdBPFXVFqb7tQSj/Y8X8Cc76UHyISled9vCNRyhrt
         I2OX7Xs+/cK5tZ0Vn3LcZTzd/Hi+b9vxQwkdnebeigl2k2NZ/ElJZ/GAQ2zMkokEemA1
         PpJ5GRRXvXgfDPG9kKRjCn6SMMi98pt5qMN+dgmliaka4ByXuWrnLoHnZLdijZGcBgwf
         QJx3IQEJMWurx9JcXme6IxYqxeCUDcyP2tF1eKGQweUeWKukYJx3OQcvKfDYGufJgsIR
         CcHKYoUe/IQ1OpJgYaJK7UsR+PTdxNdmbpg+ipIhq8lm8qWglRfTrxKhK+j/R/rMSdbP
         iJ1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw1WW5TTzDcKEcxLIzypKCpqfAtbBqFG2RbVYxXWBTuiNInKfH8
	KSbQw9iingFEzhRaDcqP3rg=
X-Google-Smtp-Source: AGHT+IHmO8UtG+nGD7cY0xvZNaHA/WdsGSdjMm31zswikj7FlY7Ko9+ymDGfiNb89069+X2Ib1xeKQ==
X-Received: by 2002:a05:600c:354e:b0:40b:5e21:dd49 with SMTP id i14-20020a05600c354e00b0040b5e21dd49mr10226072wmq.119.1703025088585;
        Tue, 19 Dec 2023 14:31:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5114:b0:404:7eae:e6cf with SMTP id
 o20-20020a05600c511400b004047eaee6cfls3181038wms.2.-pod-prod-05-eu; Tue, 19
 Dec 2023 14:31:27 -0800 (PST)
X-Received: by 2002:a05:600c:827:b0:40c:2dc7:bc6c with SMTP id k39-20020a05600c082700b0040c2dc7bc6cmr11009361wmp.14.1703025087032;
        Tue, 19 Dec 2023 14:31:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703025086; cv=none;
        d=google.com; s=arc-20160816;
        b=W5YmpgboxNGHhQyzds9Dbv2Yc2q2svpfSbUMljk7BX1igzBKPqJWBTWClxtkJncXFq
         OQHlljVLmc6GbqCPVXdTfuqfkrI+BhiyBbJgigIJ3LXa9+f66IGnRKOKmyskPD72kvPf
         5LQDYZnFFmPuJUPAWIbNKfm8rkte2X1ZHXLz3ZX5DxrAQaizCt4tnaiRsyaKC+pAoNyU
         WB/OtUUQ/2Jiw2hPD4s7Z8yIknEqUG1PpGOPTHqu50AmSvn2kIPzvMjksCSXCzIshC+j
         GaRhJvWzO9fi1zyxW3mlIMor5Tsjt7wuHmGZYAj8pifO5BUxdqACv/9xV6oa1MzxU4wp
         PyyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vtcYZCAnAciS7NEDq4A0NBDaIMQC+9FU2xLXkQaUBC0=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=GYsr8EK6sN9rGGNuCnMZpFK5S3US6IdlnMbd+5VOx5QTWyqcfbWhxBO6bjdkxVxoFZ
         7no7KwEM1RhMTeZUSSgY2/blei9N/eqPEjfG0r8++mIyb55DIPW3he0Kq0LZHX57cHKX
         Flo3PE8ira1gaOAfGwzasqiimPP7IeZ3I2JcHNysQnlZI9wWFsPGuDM5L4wPfGKe8U5N
         hwft/NXl65w1tZsyc4bv4UX3vCmtiYJmtw6jO2Qrxowo8WferOCxZKCn95htuKtDMn74
         Rz8LL7gMw9kAdamMcHpUUNvbr0HPaPrzVh8R8rErp+1skyThaWqI/gAtNs9PEvSuRme8
         AJ2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Iwn4kg+j;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::ad as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-173.mta0.migadu.com (out-173.mta0.migadu.com. [2001:41d0:1004:224b::ad])
        by gmr-mx.google.com with ESMTPS id dt10-20020a170907728a00b00a2355945814si283233ejc.2.2023.12.19.14.31.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:31:26 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::ad as permitted sender) client-ip=2001:41d0:1004:224b::ad;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Breno Leitao <leitao@debian.org>,
	Alexander Lobakin <alobakin@pm.me>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 17/21] kasan: rename pagealloc tests
Date: Tue, 19 Dec 2023 23:29:01 +0100
Message-Id: <f3eef6ddb87176c40958a3e5a0bd2386b52af4c6.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
References: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Iwn4kg+j;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::ad as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Rename "pagealloc" KASAN tests:

1. Use "kmalloc_large" for tests that use large kmalloc allocations.

2. Use "page_alloc" for tests that use page_alloc.

Also clean up the comments.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan_test.c | 51 ++++++++++++++++++++++---------------------
 1 file changed, 26 insertions(+), 25 deletions(-)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 0ae4e93e9311..230958de7604 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -214,12 +214,13 @@ static void kmalloc_node_oob_right(struct kunit *test)
 }
 
 /*
- * These kmalloc_pagealloc_* tests try allocating a memory chunk that doesn't
- * fit into a slab cache and therefore is allocated via the page allocator
- * fallback. Since this kind of fallback is only implemented for SLUB, these
- * tests are limited to that allocator.
+ * The kmalloc_large_* tests below use kmalloc() to allocate a memory chunk
+ * that does not fit into the largest slab cache and therefore is allocated via
+ * the page_alloc fallback for SLUB. SLAB has no such fallback, and thus these
+ * tests are not supported for it.
  */
-static void kmalloc_pagealloc_oob_right(struct kunit *test)
+
+static void kmalloc_large_oob_right(struct kunit *test)
 {
 	char *ptr;
 	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
@@ -235,7 +236,7 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
 	kfree(ptr);
 }
 
-static void kmalloc_pagealloc_uaf(struct kunit *test)
+static void kmalloc_large_uaf(struct kunit *test)
 {
 	char *ptr;
 	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
@@ -249,7 +250,7 @@ static void kmalloc_pagealloc_uaf(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
 }
 
-static void kmalloc_pagealloc_invalid_free(struct kunit *test)
+static void kmalloc_large_invalid_free(struct kunit *test)
 {
 	char *ptr;
 	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
@@ -262,7 +263,7 @@ static void kmalloc_pagealloc_invalid_free(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, kfree(ptr + 1));
 }
 
-static void pagealloc_oob_right(struct kunit *test)
+static void page_alloc_oob_right(struct kunit *test)
 {
 	char *ptr;
 	struct page *pages;
@@ -284,7 +285,7 @@ static void pagealloc_oob_right(struct kunit *test)
 	free_pages((unsigned long)ptr, order);
 }
 
-static void pagealloc_uaf(struct kunit *test)
+static void page_alloc_uaf(struct kunit *test)
 {
 	char *ptr;
 	struct page *pages;
@@ -298,15 +299,15 @@ static void pagealloc_uaf(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
 }
 
-static void kmalloc_large_oob_right(struct kunit *test)
+/*
+ * Check that KASAN detects an out-of-bounds access for a big object allocated
+ * via kmalloc(). But not as big as to trigger the page_alloc fallback for SLUB.
+ */
+static void kmalloc_big_oob_right(struct kunit *test)
 {
 	char *ptr;
 	size_t size = KMALLOC_MAX_CACHE_SIZE - 256;
 
-	/*
-	 * Allocate a chunk that is large enough, but still fits into a slab
-	 * and does not trigger the page allocator fallback in SLUB.
-	 */
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
@@ -404,18 +405,18 @@ static void krealloc_less_oob(struct kunit *test)
 	krealloc_less_oob_helper(test, 235, 201);
 }
 
-static void krealloc_pagealloc_more_oob(struct kunit *test)
+static void krealloc_large_more_oob(struct kunit *test)
 {
-	/* page_alloc fallback in only implemented for SLUB. */
+	/* page_alloc fallback is only implemented for SLUB. */
 	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
 
 	krealloc_more_oob_helper(test, KMALLOC_MAX_CACHE_SIZE + 201,
 					KMALLOC_MAX_CACHE_SIZE + 235);
 }
 
-static void krealloc_pagealloc_less_oob(struct kunit *test)
+static void krealloc_large_less_oob(struct kunit *test)
 {
-	/* page_alloc fallback in only implemented for SLUB. */
+	/* page_alloc fallback is only implemented for SLUB. */
 	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
 
 	krealloc_less_oob_helper(test, KMALLOC_MAX_CACHE_SIZE + 235,
@@ -1816,16 +1817,16 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmalloc_oob_right),
 	KUNIT_CASE(kmalloc_oob_left),
 	KUNIT_CASE(kmalloc_node_oob_right),
-	KUNIT_CASE(kmalloc_pagealloc_oob_right),
-	KUNIT_CASE(kmalloc_pagealloc_uaf),
-	KUNIT_CASE(kmalloc_pagealloc_invalid_free),
-	KUNIT_CASE(pagealloc_oob_right),
-	KUNIT_CASE(pagealloc_uaf),
 	KUNIT_CASE(kmalloc_large_oob_right),
+	KUNIT_CASE(kmalloc_large_uaf),
+	KUNIT_CASE(kmalloc_large_invalid_free),
+	KUNIT_CASE(page_alloc_oob_right),
+	KUNIT_CASE(page_alloc_uaf),
+	KUNIT_CASE(kmalloc_big_oob_right),
 	KUNIT_CASE(krealloc_more_oob),
 	KUNIT_CASE(krealloc_less_oob),
-	KUNIT_CASE(krealloc_pagealloc_more_oob),
-	KUNIT_CASE(krealloc_pagealloc_less_oob),
+	KUNIT_CASE(krealloc_large_more_oob),
+	KUNIT_CASE(krealloc_large_less_oob),
 	KUNIT_CASE(krealloc_uaf),
 	KUNIT_CASE(kmalloc_oob_16),
 	KUNIT_CASE(kmalloc_uaf_16),
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f3eef6ddb87176c40958a3e5a0bd2386b52af4c6.1703024586.git.andreyknvl%40google.com.
