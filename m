Return-Path: <kasan-dev+bncBAABBQERUWVAMGQE7CCGCFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 574817E2DDC
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 21:12:50 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-542d3c2a236sf2480a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 12:12:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699301570; cv=pass;
        d=google.com; s=arc-20160816;
        b=M+x7Ii8+EIrw3g2ks7J5P5wsCi8d3zKM2VSF+yrNG/c88yz11hKQz5WT1Z/11b+9Jz
         2C1EW/EYphgvmCN1V+0Q3sAtWBub2FKDauqyrWnC/F1cIXUfOmYK6j+ZJaSO4nik3VYF
         O0BRxy5iiG6/GT7qNjEeNiEEASbfVt5ETwYMPazIol7nASs41h6tqpo1rodwAN1DtWjX
         ELhULgucZTuzVG1jmo6KZCiSMAIL98TtCnDh4C2YzSxeFkoup6NClrv2k/KWxYEc8GNE
         bKYhpnuXcwjg3mngUgyCfxtT57DTgVp2A7WxzUJ19NLvRWthx5RRBmF2zhrB0DDB5eiA
         ioSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/hExJSMdZ5bL43XrbdujtVSyyJuZLEjif3oCl4jqjqU=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=hX1rCdJdWoBkP7/+oHNOkI6p5qijQoDnJP4eLWKymgyDBe9jAJLCg5LYGANg3bB2Sq
         8zZLOwf0Lj2l3nOx6s+XnaJRquebOlt1d6GRtzLPyK0ZVBaUU+sI/no8QlMD/AwZTwCB
         Rrr7k/FuTWyvlYuvcpqBuMtzuKSY5TDoPVIEnpgyTDibleFBVSD1hUGQxJ/AtkfdbDCM
         CKSEPZHqCbQfieCLfWa+AupqRfBhjyv0r3diY6dhuGh+/N6VvzkT1GnlyDQx6zbvG86l
         4+S+LWW45iBEm6TclZ6LTWafPQSH7lCN6OIKg6t2F1wFMypjmmWta6YrzxpvhRRHBRpO
         IbpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FgwksLN8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b2 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699301570; x=1699906370; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/hExJSMdZ5bL43XrbdujtVSyyJuZLEjif3oCl4jqjqU=;
        b=NS+N2OdBDbGzUx3LIbc3UFz/MAzwWCjXLvEqH3/AK7pFPj7JHmTcdl47EEPDX4Ku+v
         Ok/M/C1KlhwWncorirTdnHnZMk3iqixzbE1a+m4ceZYB1D7BtSA8OLH1EhhaADAjS4GL
         yudiCSKU5E1GPSsy2WW6x4nwbebi+/8X+K9Q8aBxdtNpnKRtctVHmTBZn4F5eaz2S13F
         EPlFNoDJA4s5KVbBPillRO9RyuCShirjRAKAwFnns3B8TqfcjjOXNFYRNjOzPNNaySu0
         ZoW0XCWDAG2vJuLmCD3zOK6Ua2H04weYeVfsBhyrJ2AHGLFAHxOmLBm606a3iW4wTFXa
         gPzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699301570; x=1699906370;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/hExJSMdZ5bL43XrbdujtVSyyJuZLEjif3oCl4jqjqU=;
        b=hm5T64SHIoE4dZafEKTCKDr2fcJSqVTnkbyjUXTsGs84vbIeqZMJGs470WRcfqmi28
         da6BtK5pr2Qm7GojZUr4lwIaouKZ1kZ8yR7L1akLxxvywiBbWochH7fIllOhKrhls8tT
         f7Jy56EJFUWpt1wB70phAnOwqpGcblJo/SQv9xhLNrdlHcDWCVh9Gp/jOTSYvNymxGSk
         M5m0FE4Wu8Aj3waOiGrI/i+G97YK3SkU4BPjlQJC5+z9kRUaGVHxOvLK0q1bpcIzqs9P
         3w838JWgTuEjnmWJbLEGeHMHxzCIiPQ9oiUwrZ8gOTeJEzQTuP+orO954DtFITiBoC4q
         EUXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yys87nZNVjJ6JMFN8int0dDZmxdjvWnltxJKN57Xr4oo22aOUfr
	GUkQUxoffat6MELYabujTog=
X-Google-Smtp-Source: AGHT+IGWkBAizxfeGa9yWLHScBber39+RMcODyvVeSXLg8dCSIuiP530r7QyFZDW2CdhCbPEkKmtFA==
X-Received: by 2002:aa7:c90c:0:b0:544:4636:db0b with SMTP id b12-20020aa7c90c000000b005444636db0bmr30719edt.1.1699301568875;
        Mon, 06 Nov 2023 12:12:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:68b:b0:534:7b4a:8d91 with SMTP id
 f11-20020a056402068b00b005347b4a8d91ls565929edy.2.-pod-prod-06-eu; Mon, 06
 Nov 2023 12:12:47 -0800 (PST)
X-Received: by 2002:a17:907:1c9c:b0:9dd:bd42:4ec7 with SMTP id nb28-20020a1709071c9c00b009ddbd424ec7mr7744147ejc.38.1699301567142;
        Mon, 06 Nov 2023 12:12:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699301567; cv=none;
        d=google.com; s=arc-20160816;
        b=QvhGTpN72M4WoumbWzk1NlqgzfyMo+TgGI4q/kpAGOvR2ajXoCb05nMKTiccvT41A0
         71tDlt8swU3B0gAazgrSvu0s0ZSw+rUct1RmMJCO6T6abCq9iBZ2AUfUONNz3XmE8mIO
         81SdpvBcbB0oVDyZNEo90s7CwxrX1jmJWzOB/8AMB2LyYWUMUT4TaVeTRa01PAsynP4f
         U0Fhi6+wimucuIJvomC4PwrbNB5/no9962/N0Q8EGmSw+VkkOvyoH8AS5/wUEY83TE+0
         tfqFwXkmEhGEuqFCYpUkWk3VXOXMpa87/mh+xhWeAAlFESStphzvpKfPHAJlr7PG2YrH
         4kQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FpmYov1aH1316OEV0hzDWuWRApXC9pzAf5GrPoQwwQE=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=iBIVyy/82LRWD/HdyOepwknUJ9v9ThYIV1sEX0iei9tu+ojyWT3UHQGw42KYS+ZxVy
         f2rpooiK4N6SrZgVcLpGbXJY3sT5sEzFxOzz/O7x3SRzk5WuKJD5INDlbYfz3vH+AbxS
         vGKjGAByf4l59xAVzG9KRgozOrYBMXFRUrdNFu4E+IE6+HILy8H83x/Xy49Gp+9CCDZ6
         WWucK973YcQLJenr27I+LJ+a7cOsRgta34HWmBFz5ujJCHsSVftYDlSK+DPn2UT8M1v7
         dEVXpWzgL3aHiqjcW2yiW0GC50XawY5YpMiepvicMfO2FETDdbuR7OV4tHIPwk8CEI7t
         DD5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FgwksLN8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b2 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-178.mta1.migadu.com (out-178.mta1.migadu.com. [2001:41d0:203:375::b2])
        by gmr-mx.google.com with ESMTPS id ti4-20020a170907c20400b009bf5b91411esi50512ejc.1.2023.11.06.12.12.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 12:12:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b2 as permitted sender) client-ip=2001:41d0:203:375::b2;
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
Subject: [PATCH RFC 17/20] kasan: reorder tests
Date: Mon,  6 Nov 2023 21:10:26 +0100
Message-Id: <f691b51115e34dd867707bebb5522cce161b46eb.1699297309.git.andreyknvl@google.com>
In-Reply-To: <cover.1699297309.git.andreyknvl@google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=FgwksLN8;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::b2 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
index 4ea403653a39..9a1bdd6ca8c4 100644
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
@@ -1151,53 +1334,6 @@ static void kasan_global_oob_left(struct kunit *test)
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
@@ -1240,69 +1376,6 @@ static void kasan_alloca_oob_right(struct kunit *test)
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
@@ -1464,79 +1537,6 @@ static void kasan_bitops_tags(struct kunit *test)
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
@@ -1823,12 +1823,12 @@ static struct kunit_case kasan_kunit_test_cases[] = {
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
@@ -1847,9 +1847,17 @@ static struct kunit_case kasan_kunit_test_cases[] = {
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
@@ -1869,19 +1877,11 @@ static struct kunit_case kasan_kunit_test_cases[] = {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f691b51115e34dd867707bebb5522cce161b46eb.1699297309.git.andreyknvl%40google.com.
