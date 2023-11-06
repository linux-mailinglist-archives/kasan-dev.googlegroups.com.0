Return-Path: <kasan-dev+bncBAABBQERUWVAMGQE7CCGCFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 337607E2DDB
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 21:12:50 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-507a3426041sf5450271e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 12:12:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699301569; cv=pass;
        d=google.com; s=arc-20160816;
        b=ehAGuIuSwJEh7y4din4afFWj9fBXcs3whjm0KXVnur6oGfUmlC0cao+2q2oJth5r6q
         Yguf9crrCUpXEdNxCvv7kMLivzSRj/HhBoK3LTyqnL13pDRCrNtsTIPCnWUNfwaDRdWl
         pzBnQ6oWgHDWdMBhE3rnYqQM7CDJWeSb1wmMbkTRKVa5wNk+qoY4FYx9COhBIqRsT3bm
         UphSGYYS/uNWTB2GLiwzJ8ymgBQSGNRiCLJJ1GaKqOC87sv4U6nYTb0HOyZ4oZrzRpZ2
         o7IvUfbnR6KY7+CUMliMYfU/6hdmV9I9GM4QPnXH0nSZDSMljKTqR4kVfsIu95pyYCWh
         oJAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=TsLoYJX+rZYoqN6spcQ8pj5XENXcOTs5/NFfHYWUGZU=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=cNt9YkMFoEsFgds/tsaYfIFpIIE/UzXV3GtZqSX1WGUn/bBURLRcMf3weDQltOe043
         gOAnXyxGMUJHHL14Ve0C+B+zBPMrHNh8lg6BFIqiUX49NbfOkO9PYbgXXxgVdFYyK7mt
         Ntd648h2pIhYTbsfuPRlHtw2ySYzgulX4XeF1JKv4In32iSUPDqPG+f305SyR+EfYuYG
         MQ4yjAgxcHkEIeJj+1GB8jZyCzY7LH3+3j5w5gDd41PXLIBcwXe86M+e3XXShGLoSeyR
         Uwq+uZiaYVCEPVsYP20FFV+s7cJ+X2Y+gtRYxrvyYwRarCR/vHyd7UdxjfOZuEMuTeQm
         5/Dg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="UlmlCS1/";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.171 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699301569; x=1699906369; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TsLoYJX+rZYoqN6spcQ8pj5XENXcOTs5/NFfHYWUGZU=;
        b=lOTizAxuhJLVS8z5FXf2mFfpaY9xujifJppjgr+Exs7CPm5LoZJhcZAn5U9YTLylh/
         BWmvGrrOrhCKWK0/IvlY6Lj9KnRIYd+RPDebwjk+wTiFIVFUS62cX4vNMsm7N74txh8X
         qatRef5Vvbhd42nZsO1Qv4DNdwTE+GEIRM4FR07+ZfKxVTGWVG1/oGJypzQhEBJcZZBG
         tmxtWuSqw2SxzEh1VxsQn80bV8CE2QEfVuGtlDwwUdE6FtrwPwLQFGHa98Sg/UWpWzFY
         9MbeOrwkT+uS2G3zel25sghyTx2feoPa/3hSRn0VIMuyl8PR6kB+8bLVgH3arBiwaM7a
         6Hrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699301569; x=1699906369;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TsLoYJX+rZYoqN6spcQ8pj5XENXcOTs5/NFfHYWUGZU=;
        b=Ilomt3mbSlG6jCVkJjov07rs/5AD/saHZL/xfoqIrp32GLLoO2vwI2DjksmdqDARRU
         9ZIpXwIdSXO6lw/nGC2z/ozk+bRfkJJoD56kE7oeDMF6Qqr+64nSgiu2c6O3iRKOXTpv
         pPfRo7t/m2hOgGbwIWV6aUL5oPq5R1FN8OCT7VLODFkYlGrEljLOl/GIiWNaWJKGE13q
         v/GyewasMVZUacJ67HrDnGbxcs+o6EaAJ5lV9YuQBlR5aKOBIdB/E6u1n6YZVXqijUyG
         LSSbfOnIkuAB7bSbkZcV6tJJF75LEi+VYj3DJGcBg2k4LwuL5Hl/XifGB0h1cZL0ZtTo
         HQdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzdBQoswaOZEXThKshl2Yc1nGH5Nrrx3SQZR/RG0If4SZXxQNtq
	HRZ9BothU8uh7sw+a49wkZs=
X-Google-Smtp-Source: AGHT+IEnu6donadrhr6r3p0z3+Mm78Bp8wOuEwLZkw474grUeJEES6t0etmNDuSWBvcrraXg01vhAA==
X-Received: by 2002:a05:6512:2256:b0:507:9625:5fd3 with SMTP id i22-20020a056512225600b0050796255fd3mr28056745lfu.32.1699301568274;
        Mon, 06 Nov 2023 12:12:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3254:b0:507:9a12:cf84 with SMTP id
 c20-20020a056512325400b005079a12cf84ls2600263lfr.2.-pod-prod-09-eu; Mon, 06
 Nov 2023 12:12:46 -0800 (PST)
X-Received: by 2002:a2e:ba09:0:b0:2c0:18b8:9656 with SMTP id p9-20020a2eba09000000b002c018b89656mr22036830lja.24.1699301566538;
        Mon, 06 Nov 2023 12:12:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699301566; cv=none;
        d=google.com; s=arc-20160816;
        b=tJqP5b5wcx+T6wtvMf6K1Uzh0Ma1q+xv2sMG/P1tmQEhWvRQItXJWlezXPsEVEXtIV
         whCG7aIAM6J+0fc1J+brTQVSdDyq6rdqf08r6hb6F1FdtinryD46oCOWgmID0GNtXGVY
         Yu6EGVXA3Sd7L7g3nMfm48gl2qkRDvPqMEtE+j3f2Zrauwc6FEnlU6TeffKBy/gxgaXI
         NPU1+IRLyOnUBjmACyBSDI8lvFzMp2sv/a3QBJ+2GbEDB5FasB1ns/G5LLYASA8BASyD
         mgFO4sNuDMSsjQQtN81XDxuVxGFAxQtANHrR/9d9gB1d6nUutMPOhagb9s0A4KkY6ItP
         vhyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kJM+A7peUz+3HNFpMd2AaQcsySYXWlMk/hSPbyjpTN8=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=WUFUOIj5wa9iYT+DhBvPDaQj6NOVbOu0s5r1tgLjzKVzpNv5W/a/PIiPCN67Z5ykbV
         AryYf9WZm48CYFXclKVYhPVqqiEFe8bEIaXSjDBVnE2YqSrpOCmn5Bb4+T2reU2dA6JY
         Il+UJv7YLMbMfdyd4lPCpOmndqwSvIxAlUbEsJmRk3Fyvwru7xrLkKmPJHlZ442D6QG8
         pZo7X1j3Nd9EIaONjDGl9u4QWVhyzB2XXiSz3jStxz9YWJdsLEHj0/Jm9oCyD9p7iNt3
         58ol8W+jNFwkt9o0CPj0x6ZjiCts7DBCA5dn9i7+edEwm57Ig0S5C5j6IvpVhuMbiDCb
         qqKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="UlmlCS1/";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.171 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta1.migadu.com (out-171.mta1.migadu.com. [95.215.58.171])
        by gmr-mx.google.com with ESMTPS id p11-20020a05600c1d8b00b003fe2591111dsi837969wms.1.2023.11.06.12.12.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 12:12:46 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.171 as permitted sender) client-ip=95.215.58.171;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH RFC 16/20] kasan: rename pagealloc tests
Date: Mon,  6 Nov 2023 21:10:25 +0100
Message-Id: <0cf5eb3ea000a76c48554bbc80acb6135ebbb94a.1699297309.git.andreyknvl@google.com>
In-Reply-To: <cover.1699297309.git.andreyknvl@google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="UlmlCS1/";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.171 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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
index 9adbcd04259b..4ea403653a39 100644
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
@@ -1822,16 +1823,16 @@ static struct kunit_case kasan_kunit_test_cases[] = {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0cf5eb3ea000a76c48554bbc80acb6135ebbb94a.1699297309.git.andreyknvl%40google.com.
