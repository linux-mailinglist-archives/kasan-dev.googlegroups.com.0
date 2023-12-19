Return-Path: <kasan-dev+bncBAABBP5TRCWAMGQEFWVQ4RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 41ACD819396
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:31:28 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-3364fa774ccsf3556675f8f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:31:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703025088; cv=pass;
        d=google.com; s=arc-20160816;
        b=0TlcResp3t4QYny4DyfAq5RVTKiZd2Tg3m1fl0AHszCo2DsIb8OqA9ZXjF8rTuCUS3
         C9snZNPVw7LUZHQL9K3o668HOmUmW7Pr+b29+OV0ptzRHOzmmIsk2q+YVVDPFXPz8rli
         D93fEkwYlOh9hUl9J+za4aOufpd3KEQr53Sq6ZMs5Cgf/l6s5fZucEhMMaCBAyDcba93
         V3I75AuYhaHSterjXe0zyakJAi5WafudeHiFgigWmYPWy0MT4Rnr1jlyB/eP1UTpmVP4
         curaKfnOE9z0eFo2S4WUNhDpUVXQGkO725bGNNV2GUiXhm/1Zkd118pCsSHzK7pymSEb
         aLww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3Fu42kgz2lERRR5gEd/MFKxsT7XKT3MN72lhaXi3xjI=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=S/wEEXSBA5nvDBYKr06JYpjDRjQAFPlptFmnHt3CdEiuM4f0UVuTu92yob867ZBuT9
         6AZNzOZpv2a+5phoAzhukS16IdHf+em4LISyG67FiYXF3blvGDEJ6v2kbQE4T3hnNDKf
         xanSbJLBrA3/myD3fcLihZWcYttb55vO7DTcS0AV6Ya2LFyK/lrZPF3UBdELOEiWjT3H
         uIXaF0H1CJbjlIDhB6mMyexIO8QKOfVMSi3hA2OdXcbG3wlnMGT3PZ3lv+x9399xtwn6
         1iofQCtac6dAmJd4/UELsK4nOc+MGsak59NMy+kebf33L5UGjFddHcE39pOt10fd/nWD
         POmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=YqrnJgAl;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b8 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703025088; x=1703629888; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3Fu42kgz2lERRR5gEd/MFKxsT7XKT3MN72lhaXi3xjI=;
        b=IHQ8/T0EZXwRCdQMZa+YLC6KPjA4Ij9+m9iN9RKQKVyHZg88t62sDBDso+GnL4cv/q
         D5rjQDvLpl32xCPf7QqcZg0jZ/dwvXjv29C8ZDN3w4E6vxeeyZu53QKFwA6viPOwCdNi
         mSUgusDx43XcchizuLgMDY9Yma6ww/8Ojcwx9gbJapVZL6CkSy4zHtc2l5Xt/Df/ay/U
         SrRO6tT8efPVg71oGVGHAjseoS9ItaaRFvOIA3nG/KMAm8mBhZUx0SEIXdXy9Dl8+Pzu
         n0f2hFpvwkeSBIA4vAs+r1/+LEdYLQjWXJhjK8Yo8w6YD6UBr2y4D8TBEg56Y73BMbpE
         bYCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703025088; x=1703629888;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3Fu42kgz2lERRR5gEd/MFKxsT7XKT3MN72lhaXi3xjI=;
        b=YblkBfs1wfZQ3uibHNqh7qAZQK+gFuGV5VuRhZ2AdXBwDY3nuTrG1hCfDLx0tkJGwT
         9W0FbriNSrn91IVJYxMw/WAuyUuTNw5JrLRIv8J/hptCV+1jIcolC0FokRykEhBDzZo9
         /vHayLHREWkhOhYWWWpVGqsEJ7fRo5SEc/EK3xQ42FAsBq9EpD/oRlx/rAqXZS7osRSt
         tTI3HWNoB7sBb6/0qx7pjEQgQTglZaT6f3QQelEuQSeJvj35NHX7dE1+UwlSBbA/CVs/
         7MYRZTinhD2B6Bo5G078Sol2ofSJ0H0s0VM7xmeEsyVhBKtBbUutnJzvbCkM5hal5Mwk
         Y8sA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxUWR7nroMiNZoAk+IEGZjx9CsVWVVHfEsksQcSJq/mvR5B96Io
	gJ5ubrvAuRzNnHNnEl6Qe6U=
X-Google-Smtp-Source: AGHT+IHx6iE897i2IsHFmvpCThPO/cyMXjhL8wdNjZEKPklAd54KEz7PLGQuKkY4lrw2+NTKM0u3ZA==
X-Received: by 2002:a05:6000:551:b0:333:2fd2:51ee with SMTP id b17-20020a056000055100b003332fd251eemr8688167wrf.103.1703025087729;
        Tue, 19 Dec 2023 14:31:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:efc6:0:b0:336:6e21:d6c3 with SMTP id i6-20020adfefc6000000b003366e21d6c3ls251208wrp.2.-pod-prod-04-eu;
 Tue, 19 Dec 2023 14:31:26 -0800 (PST)
X-Received: by 2002:a05:600c:3848:b0:40d:33e5:e3ad with SMTP id s8-20020a05600c384800b0040d33e5e3admr113680wmr.5.1703025086297;
        Tue, 19 Dec 2023 14:31:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703025086; cv=none;
        d=google.com; s=arc-20160816;
        b=iMoNHyQVkkMZ0VZe35M98oq4d5zyIf1nRBFWeL5hhEV4Ky2+pbpi/vmexi/pl2U9D7
         +F/ycLuypyQ63s7Coi+e2eU14XuV9Q1fm4r+ozZ2ziIQT51Q5NcOXLoFsf6+dewyXHA/
         9kGrtGme2KhxBXdlc5yMl2X9p7nhwkVYyoCpzfXCEhpHtPc0zlQVWEdLESS+rTyEWAs3
         UK0ngbHR6E8ATJeO1SpVaeMrMeiTtloBk4YLVNm3sGYFOI3l6Tbw1HliZvIdvLPeOvDp
         0NPcr1OXgAvywGlwGx+0f6TeMgAx635D3QJVEL/7OUNnCsLzfAY2AiH9Od10w1p4XS+7
         OXcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gqTGbtVMui+CmtAk7WElvDUhOKijpogQXuGURBykLZ0=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=xMmWtk7CGMimY8yFCnpPkEMyGr1s0wR2stGeUjrN5FEQexkdvtwDzAr8YXFgZbhLmH
         HWWoktl0seW8rvf5c7GSyuSH8xTkv9E5HNtrTfETGhleJGV2cgdpB90j8RcOi6aI5xsX
         ru5xPEZ9jGNVbRNGKuOGwUNf4627Np80+4abY0UaE/F+x/95qB+Xgod25qdgdYnxqjl5
         fttWkh/2Nk75q/0vIfX4kw/0YaRiWHhWa9KhoC9GBBEajRXJYoMq6C3BWi9d2D0Gj+pR
         UnzWaOE7hSRJee5mo3Vl4QgJKMvQ9I39HJoxsK/mZkR4eRopZ4NQzJuwGTIpR5IPWrxx
         i+lw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=YqrnJgAl;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b8 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-184.mta0.migadu.com (out-184.mta0.migadu.com. [2001:41d0:1004:224b::b8])
        by gmr-mx.google.com with ESMTPS id az27-20020a05600c601b00b0040c69a269fesi135191wmb.2.2023.12.19.14.31.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:31:26 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b8 as permitted sender) client-ip=2001:41d0:1004:224b::b8;
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
Subject: [PATCH mm 16/21] kasan: add mempool tests
Date: Tue, 19 Dec 2023 23:29:00 +0100
Message-Id: <5fd64732266be8287711b6408d86ffc78784be06.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
References: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=YqrnJgAl;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::b8 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Changes RFC->v1:
- Use read instead of write in oob_right tests to avoid triggering
  slub_debug-detected corruptions.
- Adapt tests for the mempool API change.
---
 mm/kasan/kasan_test.c | 319 ++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 319 insertions(+)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 8281eb42464b..0ae4e93e9311 100644
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
@@ -798,6 +799,312 @@ static void kmem_cache_bulk(struct kunit *test)
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
+	/*
+	 * Allocate one element to prevent mempool from freeing elements to the
+	 * underlying allocator and instead make it add them to the element
+	 * list when the tests trigger double-free and invalid-free bugs.
+	 * This allows testing KASAN annotations in add_element().
+	 */
+	elem = mempool_alloc_preallocated(pool);
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
+	elem = mempool_alloc_preallocated(pool);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, elem);
+
+	return elem;
+}
+
+static void mempool_oob_right_helper(struct kunit *test, mempool_t *pool, size_t size)
+{
+	char *elem;
+
+	elem = mempool_alloc_preallocated(pool);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, elem);
+
+	OPTIMIZER_HIDE_VAR(elem);
+
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		KUNIT_EXPECT_KASAN_FAIL(test,
+			((volatile char *)&elem[size])[0]);
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test,
+			((volatile char *)&elem[round_up(size, KASAN_GRANULE_SIZE)])[0]);
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
+	elem = mempool_alloc_preallocated(pool);
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
+	elem = mempool_alloc_preallocated(pool);
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
+	elem = mempool_alloc_preallocated(pool);
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
@@ -1538,6 +1845,18 @@ static struct kunit_case kasan_kunit_test_cases[] = {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5fd64732266be8287711b6408d86ffc78784be06.1703024586.git.andreyknvl%40google.com.
