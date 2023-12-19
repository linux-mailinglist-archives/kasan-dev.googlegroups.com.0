Return-Path: <kasan-dev+bncBAABB7VTRCWAMGQE366HA5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C1AE81939F
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:32:31 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-336599bf65esf3466938f8f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:32:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703025151; cv=pass;
        d=google.com; s=arc-20160816;
        b=X5bBZnAwczxt1fERt5mkvlUJRXY0xLWgFki1LNrofm3HBvTesF6o7J6b9XNQfbPOhB
         mK9qMVBaf5B1wLtw9F9/aBaX4YM0wztW9O/QOE8MveqZhPniRYIaklZ5DGwgXOhdp94T
         a8Hh2lc69LDCQCBinn5wVmxDE6chkJM27NGwPfT/T73XALsA9+wCrChv5k6lgS4gOcfZ
         6a4LrrMZdM2u+f2qWBh7TX2F+lkddq5uYHVSOJgtg8XeDSAvmNrwVEOYYDd6uuuucJBj
         rHJ9f70UVEkNwjy4r4GWvzQrccmdxlRoH6yclUaUTmfQp9GjZrVr3vba3NBbl4/Y4Xht
         W7zQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gRsqUJDYKpV6dUHd/K2s/0Zz4X1w+9G5FnrM/8mY1ug=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=wp0r/vC7sVmwIMwts7Z66i9+qm430woZ3f30vxscyTwx7/6i2HoBqa9fUCanEWIvD+
         uSn+EhIpX36Njdu0esLnguifsVBmSadioAEcwQ0eZzPUsdUGGzrMTpCDPc52OSE9LN2a
         j6AV9flbpwsi/U7RDwiKekrYUXeS39+7ouru+CYue2VUTO7tk1ihyE9x2dVDZjXya8p6
         Rf5N35wR0Hw/mFrYj65Jx+UOEc6wJxDnyh+OWivF9CNwoO328UcTGoB7Po2ZB4904FpB
         c+y3OiwtZcwpB0DBySV2PEAQPufm2ewSz3kT9a2sUbSfzBplDFBDyVd/LX3PGRzglWOP
         JycA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=csItksj+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ba as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703025151; x=1703629951; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gRsqUJDYKpV6dUHd/K2s/0Zz4X1w+9G5FnrM/8mY1ug=;
        b=bboQLyTDACv3XYw/X6Unv+KNzrRe/Tl1PknxJRGLkQxB37IJ2Y38BXh1hOflRusbdG
         iKIr2KxqoSlvWYVjsgP2SD1VR0b+Qm+iupEG0yGAxocnNAVTPzeko/cFZVGD8kN73P+0
         W80gndIv2969+nH+yHaKjpyDXZnorfs4A5iwT3jmUvVENCxmXPxkW7rwNE97wiBR+ZEv
         vwn8OYE2xJ7tAgLXYUeELBZWL3TQxkdr+UT7vhumVIumokcmIezkj60sSbF9K6DfPv4d
         sS08X75gVf0B85Suehow5TMZ/qJJUnbvJLtT07DyyHtHuoFNkG5KuOYucL+VSh47V7oX
         1U5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703025151; x=1703629951;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gRsqUJDYKpV6dUHd/K2s/0Zz4X1w+9G5FnrM/8mY1ug=;
        b=j0Iw/uYfSLpptpEGwKzhYH7f2N54Moq/fNLfHOUI42zYClrYvUZrQs2YitCneFFadu
         h2aDoX3fflpH1ffewO4CWSClICzpkoQ0E4V1oN2qhejoPUdKs1vcWE+9ccsLGInktKjo
         ZTcKaJP7uU8g/WeDh1gtlXo5QgCs+vbmgPwZed+YJZBm+cdUpnnfvb9PHha6wGEgL9sX
         lEzS8jr5mByIkOWRashBOU18R4Uk3VJkfNoV+EjWAMpt4fH1ckIB2c/rpvDPpUU4yDRw
         4O3lu9IfSe6qOCzhg2EqBIrJTuMtBc/fxteFeINA5sRz8orle/CsgImIgCORM9xNBULn
         40gw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzmuB/LiuuhXuorJsnandxqQaiLc/CU0HVeDLA4b2R2vfMBoiGq
	imTtunvhKiSh/MjrKSdxcrU=
X-Google-Smtp-Source: AGHT+IHedWGokvOQVBLm9REg5NpoT64k4KPxUyYzUaZppITbWN+yWm+ekkhuIas88r+dUGDNRh4vBw==
X-Received: by 2002:a5d:5182:0:b0:336:4477:38ee with SMTP id k2-20020a5d5182000000b00336447738eemr6230336wrv.69.1703025150778;
        Tue, 19 Dec 2023 14:32:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6b50:0:b0:333:57a5:61cf with SMTP id x16-20020a5d6b50000000b0033357a561cfls2168948wrw.0.-pod-prod-01-eu;
 Tue, 19 Dec 2023 14:32:29 -0800 (PST)
X-Received: by 2002:adf:e306:0:b0:332:e337:7c5f with SMTP id b6-20020adfe306000000b00332e3377c5fmr8753264wrj.61.1703025149010;
        Tue, 19 Dec 2023 14:32:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703025148; cv=none;
        d=google.com; s=arc-20160816;
        b=zIh2PU4L6eupOHUtahvdVbWMtbEZKSo76Rp748QjHcalChZ1qEJsGdZTgGF4mDynuo
         xMT+gn4arzW+54sYBbK7NlEZSSmiTRWegvD+yiz2ieaX46VCYfTQizzqwElD7oPJAzgk
         L4AjWcFVfTTA/Mmqmgi/n90YGX3JiB0unmHE5EagOWcR5eQu00svH0pWyDu9V6xnO0Ac
         gbduV2JIw6S/WVvhdpGKOICP46b/4lumgHNEYM/88702Vx0pK+W5f5yniE1VK7wRdSbv
         oZDL42S3HYutb3otcSYwBWygwh2eZYNo8e358Lg5Pg0Ehs2IEFmdA7NVkMW8BS0U3qCK
         sdmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JAXOX97EsAmXy2yhWR89ibBKpDRw8QdBu0qlhVLQFtk=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=mRxwE4Rt19Z4zE9ziU5IQ0McAyGXqTQsCBypOw2F22LZuJhxLeO4vNB4leUusWX5xy
         /9QC71omMUpcSRFLiIXMWPfiy1NC8dGbG5ZL0O7a5J7NvuL64On+io0cFNviGs2X4Ggm
         7W7gQJLU8rTSpenLO/UczcVIE8oODuRk+U6zKk53BvSwBilUny1Ev+8tJDMUZlJMV0Tr
         l/Tlk8TSOjwF09Yrv6L0lYGkN9ACiU/v7iYhDqY8NyoHoO+1+WqelOqSoOsq9HhQ0bAp
         z0Mys34AlaRGAdrRRmKCHYRmD9zHbz1z1S0HsrlCrw0E7RMW0/GIKfZmKDNJxJoLgugU
         skgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=csItksj+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ba as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-186.mta1.migadu.com (out-186.mta1.migadu.com. [2001:41d0:203:375::ba])
        by gmr-mx.google.com with ESMTPS id m6-20020adfa3c6000000b00336740619c4si60010wrb.7.2023.12.19.14.32.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:32:28 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ba as permitted sender) client-ip=2001:41d0:203:375::ba;
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
Subject: [PATCH mm 18/21] kasan: reorder tests
Date: Tue, 19 Dec 2023 23:29:02 +0100
Message-Id: <acf0ee309394dbb5764c400434753ff030dd3d6c.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
References: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=csItksj+;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::ba as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Put closely related tests next to each other.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan_test.c | 418 +++++++++++++++++++++---------------------
 1 file changed, 209 insertions(+), 209 deletions(-)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 230958de7604..1c77c73ff287 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -213,6 +213,23 @@ static void kmalloc_node_oob_right(struct kunit *test)
 	kfree(ptr);
 }
 
+/*
+ * Check that KASAN detects an out-of-bounds access for a big object allocated
+ * via kmalloc(). But not as big as to trigger the page_alloc fallback for SLUB.
+ */
+static void kmalloc_big_oob_right(struct kunit *test)
+{
+	char *ptr;
+	size_t size = KMALLOC_MAX_CACHE_SIZE - 256;
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	OPTIMIZER_HIDE_VAR(ptr);
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
+	kfree(ptr);
+}
+
 /*
  * The kmalloc_large_* tests below use kmalloc() to allocate a memory chunk
  * that does not fit into the largest slab cache and therefore is allocated via
@@ -299,23 +316,6 @@ static void page_alloc_uaf(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
 }
 
-/*
- * Check that KASAN detects an out-of-bounds access for a big object allocated
- * via kmalloc(). But not as big as to trigger the page_alloc fallback for SLUB.
- */
-static void kmalloc_big_oob_right(struct kunit *test)
-{
-	char *ptr;
-	size_t size = KMALLOC_MAX_CACHE_SIZE - 256;
-
-	ptr = kmalloc(size, GFP_KERNEL);
-	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
-
-	OPTIMIZER_HIDE_VAR(ptr);
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
-	kfree(ptr);
-}
-
 static void krealloc_more_oob_helper(struct kunit *test,
 					size_t size1, size_t size2)
 {
@@ -698,6 +698,126 @@ static void kmalloc_uaf3(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[8]);
 }
 
+static void kmalloc_double_kzfree(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 16;
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	kfree_sensitive(ptr);
+	KUNIT_EXPECT_KASAN_FAIL(test, kfree_sensitive(ptr));
+}
+
+/* Check that ksize() does NOT unpoison whole object. */
+static void ksize_unpoisons_memory(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 128 - KASAN_GRANULE_SIZE - 5;
+	size_t real_size;
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	real_size = ksize(ptr);
+	KUNIT_EXPECT_GT(test, real_size, size);
+
+	OPTIMIZER_HIDE_VAR(ptr);
+
+	/* These accesses shouldn't trigger a KASAN report. */
+	ptr[0] = 'x';
+	ptr[size - 1] = 'x';
+
+	/* These must trigger a KASAN report. */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size + 5]);
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - 1]);
+
+	kfree(ptr);
+}
+
+/*
+ * Check that a use-after-free is detected by ksize() and via normal accesses
+ * after it.
+ */
+static void ksize_uaf(struct kunit *test)
+{
+	char *ptr;
+	int size = 128 - KASAN_GRANULE_SIZE;
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+	kfree(ptr);
+
+	OPTIMIZER_HIDE_VAR(ptr);
+	KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
+}
+
+/*
+ * The two tests below check that Generic KASAN prints auxiliary stack traces
+ * for RCU callbacks and workqueues. The reports need to be inspected manually.
+ *
+ * These tests are still enabled for other KASAN modes to make sure that all
+ * modes report bad accesses in tested scenarios.
+ */
+
+static struct kasan_rcu_info {
+	int i;
+	struct rcu_head rcu;
+} *global_rcu_ptr;
+
+static void rcu_uaf_reclaim(struct rcu_head *rp)
+{
+	struct kasan_rcu_info *fp =
+		container_of(rp, struct kasan_rcu_info, rcu);
+
+	kfree(fp);
+	((volatile struct kasan_rcu_info *)fp)->i;
+}
+
+static void rcu_uaf(struct kunit *test)
+{
+	struct kasan_rcu_info *ptr;
+
+	ptr = kmalloc(sizeof(struct kasan_rcu_info), GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	global_rcu_ptr = rcu_dereference_protected(
+				(struct kasan_rcu_info __rcu *)ptr, NULL);
+
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		call_rcu(&global_rcu_ptr->rcu, rcu_uaf_reclaim);
+		rcu_barrier());
+}
+
+static void workqueue_uaf_work(struct work_struct *work)
+{
+	kfree(work);
+}
+
+static void workqueue_uaf(struct kunit *test)
+{
+	struct workqueue_struct *workqueue;
+	struct work_struct *work;
+
+	workqueue = create_workqueue("kasan_workqueue_test");
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, workqueue);
+
+	work = kmalloc(sizeof(struct work_struct), GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, work);
+
+	INIT_WORK(work, workqueue_uaf_work);
+	queue_work(workqueue, work);
+	destroy_workqueue(workqueue);
+
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		((volatile struct work_struct *)work)->data);
+}
+
 static void kfree_via_page(struct kunit *test)
 {
 	char *ptr;
@@ -748,6 +868,69 @@ static void kmem_cache_oob(struct kunit *test)
 	kmem_cache_destroy(cache);
 }
 
+static void kmem_cache_double_free(struct kunit *test)
+{
+	char *p;
+	size_t size = 200;
+	struct kmem_cache *cache;
+
+	cache = kmem_cache_create("test_cache", size, 0, 0, NULL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
+
+	p = kmem_cache_alloc(cache, GFP_KERNEL);
+	if (!p) {
+		kunit_err(test, "Allocation failed: %s\n", __func__);
+		kmem_cache_destroy(cache);
+		return;
+	}
+
+	kmem_cache_free(cache, p);
+	KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_free(cache, p));
+	kmem_cache_destroy(cache);
+}
+
+static void kmem_cache_invalid_free(struct kunit *test)
+{
+	char *p;
+	size_t size = 200;
+	struct kmem_cache *cache;
+
+	cache = kmem_cache_create("test_cache", size, 0, SLAB_TYPESAFE_BY_RCU,
+				  NULL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
+
+	p = kmem_cache_alloc(cache, GFP_KERNEL);
+	if (!p) {
+		kunit_err(test, "Allocation failed: %s\n", __func__);
+		kmem_cache_destroy(cache);
+		return;
+	}
+
+	/* Trigger invalid free, the object doesn't get freed. */
+	KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_free(cache, p + 1));
+
+	/*
+	 * Properly free the object to prevent the "Objects remaining in
+	 * test_cache on __kmem_cache_shutdown" BUG failure.
+	 */
+	kmem_cache_free(cache, p);
+
+	kmem_cache_destroy(cache);
+}
+
+static void empty_cache_ctor(void *object) { }
+
+static void kmem_cache_double_destroy(struct kunit *test)
+{
+	struct kmem_cache *cache;
+
+	/* Provide a constructor to prevent cache merging. */
+	cache = kmem_cache_create("test_cache", 200, 0, 0, empty_cache_ctor);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
+	kmem_cache_destroy(cache);
+	KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_destroy(cache));
+}
+
 static void kmem_cache_accounted(struct kunit *test)
 {
 	int i;
@@ -1145,53 +1328,6 @@ static void kasan_global_oob_left(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
 
-/* Check that ksize() does NOT unpoison whole object. */
-static void ksize_unpoisons_memory(struct kunit *test)
-{
-	char *ptr;
-	size_t size = 128 - KASAN_GRANULE_SIZE - 5;
-	size_t real_size;
-
-	ptr = kmalloc(size, GFP_KERNEL);
-	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
-
-	real_size = ksize(ptr);
-	KUNIT_EXPECT_GT(test, real_size, size);
-
-	OPTIMIZER_HIDE_VAR(ptr);
-
-	/* These accesses shouldn't trigger a KASAN report. */
-	ptr[0] = 'x';
-	ptr[size - 1] = 'x';
-
-	/* These must trigger a KASAN report. */
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
-		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size + 5]);
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - 1]);
-
-	kfree(ptr);
-}
-
-/*
- * Check that a use-after-free is detected by ksize() and via normal accesses
- * after it.
- */
-static void ksize_uaf(struct kunit *test)
-{
-	char *ptr;
-	int size = 128 - KASAN_GRANULE_SIZE;
-
-	ptr = kmalloc(size, GFP_KERNEL);
-	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
-	kfree(ptr);
-
-	OPTIMIZER_HIDE_VAR(ptr);
-	KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
-}
-
 static void kasan_stack_oob(struct kunit *test)
 {
 	char stack_array[10];
@@ -1234,69 +1370,6 @@ static void kasan_alloca_oob_right(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
 
-static void kmem_cache_double_free(struct kunit *test)
-{
-	char *p;
-	size_t size = 200;
-	struct kmem_cache *cache;
-
-	cache = kmem_cache_create("test_cache", size, 0, 0, NULL);
-	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
-
-	p = kmem_cache_alloc(cache, GFP_KERNEL);
-	if (!p) {
-		kunit_err(test, "Allocation failed: %s\n", __func__);
-		kmem_cache_destroy(cache);
-		return;
-	}
-
-	kmem_cache_free(cache, p);
-	KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_free(cache, p));
-	kmem_cache_destroy(cache);
-}
-
-static void kmem_cache_invalid_free(struct kunit *test)
-{
-	char *p;
-	size_t size = 200;
-	struct kmem_cache *cache;
-
-	cache = kmem_cache_create("test_cache", size, 0, SLAB_TYPESAFE_BY_RCU,
-				  NULL);
-	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
-
-	p = kmem_cache_alloc(cache, GFP_KERNEL);
-	if (!p) {
-		kunit_err(test, "Allocation failed: %s\n", __func__);
-		kmem_cache_destroy(cache);
-		return;
-	}
-
-	/* Trigger invalid free, the object doesn't get freed. */
-	KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_free(cache, p + 1));
-
-	/*
-	 * Properly free the object to prevent the "Objects remaining in
-	 * test_cache on __kmem_cache_shutdown" BUG failure.
-	 */
-	kmem_cache_free(cache, p);
-
-	kmem_cache_destroy(cache);
-}
-
-static void empty_cache_ctor(void *object) { }
-
-static void kmem_cache_double_destroy(struct kunit *test)
-{
-	struct kmem_cache *cache;
-
-	/* Provide a constructor to prevent cache merging. */
-	cache = kmem_cache_create("test_cache", 200, 0, 0, empty_cache_ctor);
-	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
-	kmem_cache_destroy(cache);
-	KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_destroy(cache));
-}
-
 static void kasan_memchr(struct kunit *test)
 {
 	char *ptr;
@@ -1458,79 +1531,6 @@ static void kasan_bitops_tags(struct kunit *test)
 	kfree(bits);
 }
 
-static void kmalloc_double_kzfree(struct kunit *test)
-{
-	char *ptr;
-	size_t size = 16;
-
-	ptr = kmalloc(size, GFP_KERNEL);
-	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
-
-	kfree_sensitive(ptr);
-	KUNIT_EXPECT_KASAN_FAIL(test, kfree_sensitive(ptr));
-}
-
-/*
- * The two tests below check that Generic KASAN prints auxiliary stack traces
- * for RCU callbacks and workqueues. The reports need to be inspected manually.
- *
- * These tests are still enabled for other KASAN modes to make sure that all
- * modes report bad accesses in tested scenarios.
- */
-
-static struct kasan_rcu_info {
-	int i;
-	struct rcu_head rcu;
-} *global_rcu_ptr;
-
-static void rcu_uaf_reclaim(struct rcu_head *rp)
-{
-	struct kasan_rcu_info *fp =
-		container_of(rp, struct kasan_rcu_info, rcu);
-
-	kfree(fp);
-	((volatile struct kasan_rcu_info *)fp)->i;
-}
-
-static void rcu_uaf(struct kunit *test)
-{
-	struct kasan_rcu_info *ptr;
-
-	ptr = kmalloc(sizeof(struct kasan_rcu_info), GFP_KERNEL);
-	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
-
-	global_rcu_ptr = rcu_dereference_protected(
-				(struct kasan_rcu_info __rcu *)ptr, NULL);
-
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		call_rcu(&global_rcu_ptr->rcu, rcu_uaf_reclaim);
-		rcu_barrier());
-}
-
-static void workqueue_uaf_work(struct work_struct *work)
-{
-	kfree(work);
-}
-
-static void workqueue_uaf(struct kunit *test)
-{
-	struct workqueue_struct *workqueue;
-	struct work_struct *work;
-
-	workqueue = create_workqueue("kasan_workqueue_test");
-	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, workqueue);
-
-	work = kmalloc(sizeof(struct work_struct), GFP_KERNEL);
-	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, work);
-
-	INIT_WORK(work, workqueue_uaf_work);
-	queue_work(workqueue, work);
-	destroy_workqueue(workqueue);
-
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		((volatile struct work_struct *)work)->data);
-}
-
 static void vmalloc_helpers_tags(struct kunit *test)
 {
 	void *ptr;
@@ -1817,12 +1817,12 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmalloc_oob_right),
 	KUNIT_CASE(kmalloc_oob_left),
 	KUNIT_CASE(kmalloc_node_oob_right),
+	KUNIT_CASE(kmalloc_big_oob_right),
 	KUNIT_CASE(kmalloc_large_oob_right),
 	KUNIT_CASE(kmalloc_large_uaf),
 	KUNIT_CASE(kmalloc_large_invalid_free),
 	KUNIT_CASE(page_alloc_oob_right),
 	KUNIT_CASE(page_alloc_uaf),
-	KUNIT_CASE(kmalloc_big_oob_right),
 	KUNIT_CASE(krealloc_more_oob),
 	KUNIT_CASE(krealloc_less_oob),
 	KUNIT_CASE(krealloc_large_more_oob),
@@ -1841,9 +1841,17 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmalloc_uaf_memset),
 	KUNIT_CASE(kmalloc_uaf2),
 	KUNIT_CASE(kmalloc_uaf3),
+	KUNIT_CASE(kmalloc_double_kzfree),
+	KUNIT_CASE(ksize_unpoisons_memory),
+	KUNIT_CASE(ksize_uaf),
+	KUNIT_CASE(rcu_uaf),
+	KUNIT_CASE(workqueue_uaf),
 	KUNIT_CASE(kfree_via_page),
 	KUNIT_CASE(kfree_via_phys),
 	KUNIT_CASE(kmem_cache_oob),
+	KUNIT_CASE(kmem_cache_double_free),
+	KUNIT_CASE(kmem_cache_invalid_free),
+	KUNIT_CASE(kmem_cache_double_destroy),
 	KUNIT_CASE(kmem_cache_accounted),
 	KUNIT_CASE(kmem_cache_bulk),
 	KUNIT_CASE(mempool_kmalloc_oob_right),
@@ -1863,19 +1871,11 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kasan_stack_oob),
 	KUNIT_CASE(kasan_alloca_oob_left),
 	KUNIT_CASE(kasan_alloca_oob_right),
-	KUNIT_CASE(ksize_unpoisons_memory),
-	KUNIT_CASE(ksize_uaf),
-	KUNIT_CASE(kmem_cache_double_free),
-	KUNIT_CASE(kmem_cache_invalid_free),
-	KUNIT_CASE(kmem_cache_double_destroy),
 	KUNIT_CASE(kasan_memchr),
 	KUNIT_CASE(kasan_memcmp),
 	KUNIT_CASE(kasan_strings),
 	KUNIT_CASE(kasan_bitops_generic),
 	KUNIT_CASE(kasan_bitops_tags),
-	KUNIT_CASE(kmalloc_double_kzfree),
-	KUNIT_CASE(rcu_uaf),
-	KUNIT_CASE(workqueue_uaf),
 	KUNIT_CASE(vmalloc_helpers_tags),
 	KUNIT_CASE(vmalloc_oob),
 	KUNIT_CASE(vmap_tags),
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/acf0ee309394dbb5764c400434753ff030dd3d6c.1703024586.git.andreyknvl%40google.com.
