Return-Path: <kasan-dev+bncBAABBP4RUWVAMGQEP5HDR4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 55F1D7E2DD9
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 21:12:48 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-4085a414d5esf80765e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 12:12:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699301568; cv=pass;
        d=google.com; s=arc-20160816;
        b=S5+kJ9XrXt0cgJWoJ1Uo52yz5YOgzw4oAA7WKqGX+R8UfKtZCo5YwUBj2S2yqgXyJ2
         Ik5pBla9WPRQTOnRo7hmoZHWAgi8r7auumAaHV84X4LvAdPPTIxF3A6sCipbRli2bXyC
         yESbk4FUXuDRVkaX+LEJMKRMrp/hsOxejenGrC9N3rp7XBkMpeiMI+JrlkUkypIwh4Za
         HA6TCPvBRrSc/loEFK+9rpmukSwYbJhmEkkYFOTLvRZAUQlsBZp79BoHKTY2xfhl8SkM
         gC2udnUaOKQXdhiN8zytLwwcgYutOtFcbrlTVQ4WjEX/mkpe5dT1c1RRRj5kUgJ6tlnF
         FKIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=7WOBryxICOPtUiftZA6SYI3J0kaBzYdrLWHsC6McQPo=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=Yjhnsri55NGltXS6bRxdhiNeSct388GrdXcXakGG+rl/ua31e7d3uvQJTUjG1HZMXj
         0zUxSM1qk7Wb6HhBOXZhehZhOlt1UvzZ5oujI4Vo7GVs1KqhqdvE+Ef8+rvaPTchWdou
         I0QbulJlE6Gx/ZtAKChJ/EDzGco7QMaqGGRDMpPLR0TsbpnxiG3iRpsmLLalg5HBrVOE
         DB0s+wuN6jVo5tRfZVW0Y0aSeQ3iJRyvDOpz7IVSv128LqjOmPWJtWp1Fu+S8f7xO/TE
         MQ2sIvnOc9TfOr3f3QoqWHlY16SprNKYXpWUcSgjvS9slvwOnpT+HKyJcsKQMEiJGOXn
         YwQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="u66VHtu/";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b4 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699301568; x=1699906368; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7WOBryxICOPtUiftZA6SYI3J0kaBzYdrLWHsC6McQPo=;
        b=hOLhn22RyXP2mK7u8HQ0EV9B8rY4GmYfU/CYzvPrEULA+FMcUUeMn06wiJKwuI++sn
         jsAsAywLqaQ638J0wTl5vIeGXZM1KybiKmwDZfbYB47qo8/3rX/fEYE9qwy5HWbht97V
         MXF9tzT4IVpQQaUy1qMaND52He5gb67iyVDqrsVGceJGXRNVHtttTvp+hZ8bbjjICRYk
         FdlzgM9FI8tQqvfZyR1zW3I2xY1JwdbAk/lOnJ9ahA2D0iDm78QCM2bt0Gmzmjcho0C2
         S46ye2HFxWVHyHIIeg+lGl5OLwr21OTaMbELDco6KVsZhhrXJFlbZoLWjLMeJMP1nhOe
         IJuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699301568; x=1699906368;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7WOBryxICOPtUiftZA6SYI3J0kaBzYdrLWHsC6McQPo=;
        b=AqIIu8/if2kTag1zKy6vZ0u842Xdz6f4b8qNFFhuA2BUamlclej7ZH+p1G02h3V6VH
         so+4AqDAmQhmt8nHg5e7yuAWDi21T6agq1ohIUOHJxG+DG36VyVek/GZ4y5mso+spbKP
         EUdLY9Bx1hY0x93PdKR2lmRlHPyA6Jp0d6GCugtRlGJI61v9NrbEuy/bJcdDgODewLsR
         qMCn+zvH8UY2mv1qqaGjZ/uWTNaZCLzhbdMKiNvq1y0yUfq94IZZ8pNAI6yRiPhSPIdU
         rS4enTgyAwfZT1MVufQ89jIcqEbWRony3cQml9LPmkL6mSRboDoEFzU9qTQrPrAGQ/s8
         PThw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxzoeQj4FyYyLd6qlnAwQioaszdZ30M/e8wLk46tBdSeg7RQ1SJ
	X+3Pqaxyw7Y08TbvpLFEJXQ=
X-Google-Smtp-Source: AGHT+IEjxQi/NLNwgOtHC9MHYh4YxeT9W+iMWzASuLHyVoyMr2gZq4JxiniO8XOBPnaQ06e2sBdkDg==
X-Received: by 2002:a05:600c:a03:b0:3fe:e9ea:9653 with SMTP id z3-20020a05600c0a0300b003fee9ea9653mr26601wmp.4.1699301567627;
        Mon, 06 Nov 2023 12:12:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1ca3:b0:404:7ae7:e280 with SMTP id
 k35-20020a05600c1ca300b004047ae7e280ls2570676wms.0.-pod-prod-00-eu-canary;
 Mon, 06 Nov 2023 12:12:46 -0800 (PST)
X-Received: by 2002:a05:6000:1542:b0:32f:75d2:5a32 with SMTP id 2-20020a056000154200b0032f75d25a32mr525565wry.6.1699301565878;
        Mon, 06 Nov 2023 12:12:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699301565; cv=none;
        d=google.com; s=arc-20160816;
        b=F5Y3jBiQxr16KspCRIyil/7h6k3YZ4npxjqxqj1g6HD8ESQrPOROYXSFHpkz3pUHCV
         o0FIRU0cUNwwy8paDg0W02whpL8HaRVhkejz4qsrtKbG+ldFoXuIRTpYO+FQ7upWV2Ju
         Vd3iKhpKTAI1Bch61AhXMQUqctuMooCLRV3PjIehmiTpYyqQ1W2nMz58fa/88JBnH1Xk
         3VTnH+DLXfhHE6q2CiFh9cK43PzY40Bu3+Kg0lAntscFJJ/lMXH2aFKM/IkssSw3mdsa
         zm9tqUjVRuyyTkF14d+FSQGn41mjk4bCEgUPDAfxPNbYcoasVg6RuT1ZuHm5DF6/pfDs
         qpAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=J0FZGClDjGLvLD3TemnnZlVkckK/FbBcRM13VFu32PM=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=SyN2HP69ma9W2emAJ6CCZvkwRdg3BWqmj9zbstubsi4kx5HyHLrg0RyNVfE0E8JtVI
         gng463Prd8/F2FMnAkLgG7qtahwkaKifk4l45LOGAhC5coPdxyZc9xuKfnLX92sBqkF2
         IOu9/2i99GVPjOskXuR9VdGX0s/yay1hTsjDhzc4LET4MXO8vH0iyQuAV9RjjNdTzSqG
         ygVZRp6id5yvUgNIf+rTRXWY8MiSDvmWpvxQX3AJK8JFuKcB45gmUJL0gFmQ/AnIDOus
         qtFAn00AlLKyD38vEkqKe2cEBK5EG0csnjA6giy2H9GNVZ0jL3iHNjlYs2vYC1QK4LHG
         plEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="u66VHtu/";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b4 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-180.mta1.migadu.com (out-180.mta1.migadu.com. [2001:41d0:203:375::b4])
        by gmr-mx.google.com with ESMTPS id s18-20020a5d69d2000000b0032c8861a1d1si36934wrw.4.2023.11.06.12.12.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 12:12:45 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b4 as permitted sender) client-ip=2001:41d0:203:375::b4;
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
Subject: [PATCH RFC 15/20] kasan: add mempool tests
Date: Mon,  6 Nov 2023 21:10:24 +0100
Message-Id: <389467628f04e7defb81cc08079cdc9c983f71a4.1699297309.git.andreyknvl@google.com>
In-Reply-To: <cover.1699297309.git.andreyknvl@google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="u66VHtu/";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::b4 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Add KASAN tests for mempool.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan_test.c | 325 ++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 325 insertions(+)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 8281eb42464b..9adbcd04259b 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -13,6 +13,7 @@
 #include <linux/io.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
+#include <linux/mempool.h>
 #include <linux/mm.h>
 #include <linux/mman.h>
 #include <linux/module.h>
@@ -798,6 +799,318 @@ static void kmem_cache_bulk(struct kunit *test)
 	kmem_cache_destroy(cache);
 }
 
+static void *mempool_prepare_kmalloc(struct kunit *test, mempool_t *pool, size_t size)
+{
+	int pool_size = 4;
+	int ret;
+	void *elem;
+
+	memset(pool, 0, sizeof(*pool));
+	ret = mempool_init_kmalloc_pool(pool, pool_size, size);
+	KUNIT_ASSERT_EQ(test, ret, 0);
+
+	/* Tell mempool to only use preallocated elements. */
+	mempool_use_prealloc_only(pool);
+
+	/*
+	 * Allocate one element to prevent mempool from freeing elements to the
+	 * underlying allocator and instead make it add them to the element
+	 * list when the tests trigger double-free and invalid-free bugs.
+	 * This allows testing KASAN annotations in add_element().
+	 */
+	elem = mempool_alloc(pool, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, elem);
+
+	return elem;
+}
+
+static struct kmem_cache *mempool_prepare_slab(struct kunit *test, mempool_t *pool, size_t size)
+{
+	struct kmem_cache *cache;
+	int pool_size = 4;
+	int ret;
+
+	cache = kmem_cache_create("test_cache", size, 0, 0, NULL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
+
+	memset(pool, 0, sizeof(*pool));
+	ret = mempool_init_slab_pool(pool, pool_size, cache);
+	KUNIT_ASSERT_EQ(test, ret, 0);
+
+	mempool_use_prealloc_only(pool);
+
+	/*
+	 * Do not allocate one preallocated element, as we skip the double-free
+	 * and invalid-free tests for slab mempool for simplicity.
+	 */
+
+	return cache;
+}
+
+static void *mempool_prepare_page(struct kunit *test, mempool_t *pool, int order)
+{
+	int pool_size = 4;
+	int ret;
+	void *elem;
+
+	memset(pool, 0, sizeof(*pool));
+	ret = mempool_init_page_pool(pool, pool_size, order);
+	KUNIT_ASSERT_EQ(test, ret, 0);
+
+	mempool_use_prealloc_only(pool);
+
+	elem = mempool_alloc(pool, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, elem);
+
+	return elem;
+}
+
+static void mempool_oob_right_helper(struct kunit *test, mempool_t *pool, size_t size)
+{
+	char *elem;
+
+	elem = mempool_alloc(pool, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, elem);
+
+	OPTIMIZER_HIDE_VAR(elem);
+
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		KUNIT_EXPECT_KASAN_FAIL(test, elem[size] = 'x');
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test,
+			elem[round_up(size, KASAN_GRANULE_SIZE)] = 'x');
+
+	mempool_free(elem, pool);
+}
+
+static void mempool_kmalloc_oob_right(struct kunit *test)
+{
+	mempool_t pool;
+	size_t size = 128 - KASAN_GRANULE_SIZE - 5;
+	void *extra_elem;
+
+	extra_elem = mempool_prepare_kmalloc(test, &pool, size);
+
+	mempool_oob_right_helper(test, &pool, size);
+
+	mempool_free(extra_elem, &pool);
+	mempool_exit(&pool);
+}
+
+static void mempool_kmalloc_large_oob_right(struct kunit *test)
+{
+	mempool_t pool;
+	size_t size = KMALLOC_MAX_CACHE_SIZE + 1;
+	void *extra_elem;
+
+	extra_elem = mempool_prepare_kmalloc(test, &pool, size);
+
+	mempool_oob_right_helper(test, &pool, size);
+
+	mempool_free(extra_elem, &pool);
+	mempool_exit(&pool);
+}
+
+static void mempool_slab_oob_right(struct kunit *test)
+{
+	mempool_t pool;
+	size_t size = 123;
+	struct kmem_cache *cache;
+
+	cache = mempool_prepare_slab(test, &pool, size);
+
+	mempool_oob_right_helper(test, &pool, size);
+
+	mempool_exit(&pool);
+	kmem_cache_destroy(cache);
+}
+
+/*
+ * Skip the out-of-bounds test for page mempool. With Generic KASAN, page
+ * allocations have no redzones, and thus the out-of-bounds detection is not
+ * guaranteed; see https://bugzilla.kernel.org/show_bug.cgi?id=210503. With
+ * the tag-based KASAN modes, the neighboring allocation might have the same
+ * tag; see https://bugzilla.kernel.org/show_bug.cgi?id=203505.
+ */
+
+static void mempool_uaf_helper(struct kunit *test, mempool_t *pool, bool page)
+{
+	char *elem, *ptr;
+
+	elem = mempool_alloc(pool, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, elem);
+
+	mempool_free(elem, pool);
+
+	ptr = page ? page_address((struct page *)elem) : elem;
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
+}
+
+static void mempool_kmalloc_uaf(struct kunit *test)
+{
+	mempool_t pool;
+	size_t size = 128;
+	void *extra_elem;
+
+	extra_elem = mempool_prepare_kmalloc(test, &pool, size);
+
+	mempool_uaf_helper(test, &pool, false);
+
+	mempool_free(extra_elem, &pool);
+	mempool_exit(&pool);
+}
+
+static void mempool_kmalloc_large_uaf(struct kunit *test)
+{
+	mempool_t pool;
+	size_t size = KMALLOC_MAX_CACHE_SIZE + 1;
+	void *extra_elem;
+
+	/* page_alloc fallback is only implemented for SLUB. */
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
+
+	extra_elem = mempool_prepare_kmalloc(test, &pool, size);
+
+	mempool_uaf_helper(test, &pool, false);
+
+	mempool_free(extra_elem, &pool);
+	mempool_exit(&pool);
+}
+
+static void mempool_slab_uaf(struct kunit *test)
+{
+	mempool_t pool;
+	size_t size = 123;
+	struct kmem_cache *cache;
+
+	cache = mempool_prepare_slab(test, &pool, size);
+
+	mempool_uaf_helper(test, &pool, false);
+
+	mempool_exit(&pool);
+	kmem_cache_destroy(cache);
+}
+
+static void mempool_page_alloc_uaf(struct kunit *test)
+{
+	mempool_t pool;
+	int order = 2;
+	void *extra_elem;
+
+	extra_elem = mempool_prepare_page(test, &pool, order);
+
+	mempool_uaf_helper(test, &pool, true);
+
+	mempool_free(extra_elem, &pool);
+	mempool_exit(&pool);
+}
+
+static void mempool_double_free_helper(struct kunit *test, mempool_t *pool)
+{
+	char *elem;
+
+	elem = mempool_alloc(pool, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, elem);
+
+	mempool_free(elem, pool);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, mempool_free(elem, pool));
+}
+
+static void mempool_kmalloc_double_free(struct kunit *test)
+{
+	mempool_t pool;
+	size_t size = 128;
+	char *extra_elem;
+
+	extra_elem = mempool_prepare_kmalloc(test, &pool, size);
+
+	mempool_double_free_helper(test, &pool);
+
+	mempool_free(extra_elem, &pool);
+	mempool_exit(&pool);
+}
+
+static void mempool_kmalloc_large_double_free(struct kunit *test)
+{
+	mempool_t pool;
+	size_t size = KMALLOC_MAX_CACHE_SIZE + 1;
+	char *extra_elem;
+
+	/* page_alloc fallback is only implemented for SLUB. */
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
+
+	extra_elem = mempool_prepare_kmalloc(test, &pool, size);
+
+	mempool_double_free_helper(test, &pool);
+
+	mempool_free(extra_elem, &pool);
+	mempool_exit(&pool);
+}
+
+static void mempool_page_alloc_double_free(struct kunit *test)
+{
+	mempool_t pool;
+	int order = 2;
+	char *extra_elem;
+
+	extra_elem = mempool_prepare_page(test, &pool, order);
+
+	mempool_double_free_helper(test, &pool);
+
+	mempool_free(extra_elem, &pool);
+	mempool_exit(&pool);
+}
+
+static void mempool_kmalloc_invalid_free_helper(struct kunit *test, mempool_t *pool)
+{
+	char *elem;
+
+	elem = mempool_alloc(pool, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, elem);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, mempool_free(elem + 1, pool));
+
+	mempool_free(elem, pool);
+}
+
+static void mempool_kmalloc_invalid_free(struct kunit *test)
+{
+	mempool_t pool;
+	size_t size = 128;
+	char *extra_elem;
+
+	extra_elem = mempool_prepare_kmalloc(test, &pool, size);
+
+	mempool_kmalloc_invalid_free_helper(test, &pool);
+
+	mempool_free(extra_elem, &pool);
+	mempool_exit(&pool);
+}
+
+static void mempool_kmalloc_large_invalid_free(struct kunit *test)
+{
+	mempool_t pool;
+	size_t size = KMALLOC_MAX_CACHE_SIZE + 1;
+	char *extra_elem;
+
+	/* page_alloc fallback is only implemented for SLUB. */
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
+
+	extra_elem = mempool_prepare_kmalloc(test, &pool, size);
+
+	mempool_kmalloc_invalid_free_helper(test, &pool);
+
+	mempool_free(extra_elem, &pool);
+	mempool_exit(&pool);
+}
+
+/*
+ * Skip the invalid-free test for page mempool. The invalid-free detection only
+ * works for compound pages and mempool preallocates all page elements without
+ * the __GFP_COMP flag.
+ */
+
 static char global_array[10];
 
 static void kasan_global_oob_right(struct kunit *test)
@@ -1538,6 +1851,18 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmem_cache_oob),
 	KUNIT_CASE(kmem_cache_accounted),
 	KUNIT_CASE(kmem_cache_bulk),
+	KUNIT_CASE(mempool_kmalloc_oob_right),
+	KUNIT_CASE(mempool_kmalloc_large_oob_right),
+	KUNIT_CASE(mempool_slab_oob_right),
+	KUNIT_CASE(mempool_kmalloc_uaf),
+	KUNIT_CASE(mempool_kmalloc_large_uaf),
+	KUNIT_CASE(mempool_slab_uaf),
+	KUNIT_CASE(mempool_page_alloc_uaf),
+	KUNIT_CASE(mempool_kmalloc_double_free),
+	KUNIT_CASE(mempool_kmalloc_large_double_free),
+	KUNIT_CASE(mempool_page_alloc_double_free),
+	KUNIT_CASE(mempool_kmalloc_invalid_free),
+	KUNIT_CASE(mempool_kmalloc_large_invalid_free),
 	KUNIT_CASE(kasan_global_oob_right),
 	KUNIT_CASE(kasan_global_oob_left),
 	KUNIT_CASE(kasan_stack_oob),
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/389467628f04e7defb81cc08079cdc9c983f71a4.1699297309.git.andreyknvl%40google.com.
