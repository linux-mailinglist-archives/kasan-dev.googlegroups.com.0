Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUPR3WWQMGQEWMSWNJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CC5F84025F
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 11:07:15 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-36387e7abccsf280955ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 02:07:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706522834; cv=pass;
        d=google.com; s=arc-20160816;
        b=bulmoYUK0O1lXZm35HMX+gXlfaEyuhPC3/KeHMzNbpaOVFnz/clHrKyb3StnO7cDOw
         BcXwCBSITwFE+2VAadYv6qmnfotV+HOtupc1LeUhIjDHGZDAoQcAHo6RiD7s4Fde8lrn
         gstackwwEVj9AEgqXbiNnyPxoMeYB9qbO/Br+1hPgcIC1Gred/1OY48Lbu1CFqsYvcWQ
         PPUFQvHZSR+sXXidUCjfnS1B/9+a/ayt53YAWA140xOdWjhCyjy/KWde1xXreB6xQlCN
         uqgbFV2o64oFhxd808IsSAO6Zo+m9yPd+bPFC0WZFOdApWSCTWKkFujERSqW0yQScKFL
         q+7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=R8aPLkbi05uQA+HZjI9gmPcOLncJE3cG+cjVTuqbRdc=;
        fh=Q6WTJ5ZnjiuB6HF3Kna6PPHtjylj1os0kvM6d8ajbeE=;
        b=nMxhh4ORHePG76gPXlO9mEGAWsHzxR2IlYmUCNqaJK34smc/DeFhcLtOgOV+rrOlWI
         VHnci4Mr02pyhcmYAWHD6bmn1fcQXf5448527HDbOcIhQOtBkkPI8wWlLA932/1td2Z4
         Jb/nPjLo/gTJH7M5d8v9YQaArCfxCEcY1d0p2aV9WzGIq1g5AxGoiDCAh3EhrSXeOHhL
         ttdJC9gNq6tiXAj5D2ivlmEcu0st+dboUGzMY4c3ObndsC+fR54WZe6r9kMjC82cOljF
         2YkCqDCqt4n2EpqmMHLvxFc2L6pJ81Jo8J/xdDN3pedN4boDfRn6aREHE1ljXm0E0R/I
         7Zyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hDtzFhP0;
       spf=pass (google.com: domain of 30hi3zqukcdm3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=30Hi3ZQUKCdM3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706522834; x=1707127634; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=R8aPLkbi05uQA+HZjI9gmPcOLncJE3cG+cjVTuqbRdc=;
        b=fgzfZxaVXLyz7PgYw0j6uZD8AP8ES5qbSDjgCiv9NWQTqj6L2l/sedlPF9j0RWODxV
         N1eaNFFBAT5lqNCxCF4EqoKjQQhfY3QLbi2a6gBz3r28LZ6hq1XquLf1w5x7PuXFNEPU
         dSvU+if0z+G+pQKtTHGL7fR8Viu61ghFqgTyRb1/ZNbJ4fcjRuA//LSGsi6HVzNUUjQJ
         dFz4EOBG0NzgYvt4xCL193HXmaxgyyh8VP2aC2sARhIYt02S7wntqREcFHXT4vSnf3sD
         lyiTaVcfpnDMQ7foxm+/qV9XOh+jsfkRxGrjw4a395ZaDs+3thsUbqrLfF/WQBWDc2fc
         bPrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706522834; x=1707127634;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=R8aPLkbi05uQA+HZjI9gmPcOLncJE3cG+cjVTuqbRdc=;
        b=jH/OfxbPeT48ttDgqthsKKxnO3KiOBp9GR4un1QLQEOIB3rR86nfrrIqHnlQYrkj5W
         YIkIqQbCVUmKU99gEQ8m9oquykmZo4Ui6u7es0Er83FjORdjpd4a8tciSN/lyHJHArMh
         k3Vq0PhedebtCNRACmeF13JMgP9+zHEmbi6QGsTaRhnnEwF6GGiXjvFcnYkWuIKXWTE0
         ZEHYPVE3YI/fA1qBEm+HWsVZG4BBy2qmjleSEMZ99hFbay+X0uyh37NYxZadk7djklhz
         PYisxyb1PoXLFwEbp+0hDJuKlVla1Mn2r3zTxZHUNW675q5+JQedZVCDGaGlvzQkvx8b
         KCOg==
X-Gm-Message-State: AOJu0Yz85jxdD+kUObPQblNuagm/NUV+Qz3GDSmb+fjZw8hGJBOw5nk0
	ciD0AY9QRF2PVQnY8nh4mnsLVp+X9q2u/Azimt+YbnK5+JqDlSKJ
X-Google-Smtp-Source: AGHT+IETprmdkY3ng1gY7+XHePf1DCybUZYc5qVjH9hqHqclt1Bu9nvlT4wco8zCu1oe1WdopNBPmA==
X-Received: by 2002:a05:6e02:17ca:b0:363:76b5:9a8b with SMTP id z10-20020a056e0217ca00b0036376b59a8bmr7004960ilu.32.1706522833872;
        Mon, 29 Jan 2024 02:07:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:f46:b0:363:7d3f:13e4 with SMTP id
 y6-20020a056e020f4600b003637d3f13e4ls313531ilj.1.-pod-prod-02-us; Mon, 29 Jan
 2024 02:07:13 -0800 (PST)
X-Received: by 2002:a05:6e02:12a7:b0:363:8299:3479 with SMTP id f7-20020a056e0212a700b0036382993479mr1512048ilr.21.1706522832974;
        Mon, 29 Jan 2024 02:07:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706522832; cv=none;
        d=google.com; s=arc-20160816;
        b=zstyrEx4OhAMqgn/5m9ohdIPcC/jYEbxYNHt3f9yBweFKPmIJladI6h01DhGQtlCmA
         dXms6JzIBeNhUALgBWDnFpASQTq4ecTAyvbpN4xRDm5B3kQuWhpIidN3K+wL0gYZKzIW
         C10my0MbYquvC3O9Rh7aBxsqK/Dgwr+KaH3aEwZPXtqLM/KalX1zMWnOMDhhM5m7clYj
         XQxhBdFkz3aaQrKKHakxA+gtYGDbltl3MCt/X9ZSU/T01168oHFuiPlPrd2XAR5WwEMg
         caEfgN7F5qDQCMFm3YDoulHG1bWmoLzE5VP4DPkA+5cUKw7x/D1bu+9l24tasv3MjYv/
         EGnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=LogR/Zah+zrx3k9gi8s3U+HMAC7cqgfXE5NI/I6QwMw=;
        fh=Q6WTJ5ZnjiuB6HF3Kna6PPHtjylj1os0kvM6d8ajbeE=;
        b=UKktvW2pwBDFRrvIudwsTnN95p3w6yNNOtUGvvSVzL1khKl8SL8QUe6uohJBidT6oU
         8Plgiz6wZzNm/zzwjaV8Jh3gbGlTNuKa0NidZpg7bKjU9GEKw+Y/776PIACixlTrwUhn
         91eStWo7w6qvnJ5A3YAwmGHcXWv9Fu4z7ZMz3kEIwqjD3iSUYQwPqzUmgcur2UVKrItq
         t/hIc+8MbznCugY05CfCzdi2ZZ5jjjDi0X3IuNuTTOOsym5sq/D0ET9p1SLxmjIUwHFC
         HpUtV9wVugmWuFrzTH3IkJ0FBoxOzRDBLHD1cKY+0JAudy3mDyuyhumfswQy76BEUyYq
         8FMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hDtzFhP0;
       spf=pass (google.com: domain of 30hi3zqukcdm3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=30Hi3ZQUKCdM3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id u7-20020a056e021a4700b0036284e36b21si481463ilv.4.2024.01.29.02.07.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Jan 2024 02:07:12 -0800 (PST)
Received-SPF: pass (google.com: domain of 30hi3zqukcdm3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-5eba564eb3fso49521337b3.1
        for <kasan-dev@googlegroups.com>; Mon, 29 Jan 2024 02:07:12 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:cb16:eb72:6e81:bff1])
 (user=elver job=sendgmr) by 2002:a05:690c:dd6:b0:5fc:43cb:cb1e with SMTP id
 db22-20020a05690c0dd600b005fc43cbcb1emr1772952ywb.10.1706522832529; Mon, 29
 Jan 2024 02:07:12 -0800 (PST)
Date: Mon, 29 Jan 2024 11:07:01 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.43.0.429.g432eaa2c6b-goog
Message-ID: <20240129100708.39460-1-elver@google.com>
Subject: [PATCH v2 1/2] stackdepot: use variable size records for
 non-evictable entries
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=hDtzFhP0;       spf=pass
 (google.com: domain of 30hi3zqukcdm3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=30Hi3ZQUKCdM3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

With the introduction of stack depot evictions, each stack record is now
fixed size, so that future reuse after an eviction can safely store
differently sized stack traces. In all cases that do not make use of
evictions, this wastes lots of space.

Fix it by re-introducing variable size stack records (up to the max
allowed size) for entries that will never be evicted. We know if an
entry will never be evicted if the flag STACK_DEPOT_FLAG_GET is not
provided, since a later stack_depot_put() attempt is undefined behavior.

With my current kernel config that enables KASAN and also SLUB owner tracking,
I observe (after a kernel boot) a whopping reduction of 296 stack depot pools,
which translates into 4736 KiB saved. The savings here are from SLUB owner
tracking only, because KASAN generic mode still uses refcounting.

Before:

  pools: 893
  allocations: 29841
  frees: 6524
  in_use: 23317
  freelist_size: 3454

After:

  pools: 597
  refcounted_allocations: 17547
  refcounted_frees: 6477
  refcounted_in_use: 11070
  freelist_size: 3497
  persistent_count: 12163
  persistent_bytes: 1717008

Fixes: 108be8def46e ("lib/stackdepot: allow users to evict stack traces")
Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
---
v2:
* Also remove KMSAN-specific DEPOT_POOLS_CAP (revert bd9d9624b7136).
* Let counters distinguish refcounted and non-refcounted entries.
* Comments.

v1 (since RFC):
* Get rid of new_pool_required to simplify the code.
* Warn on attempts to switch a non-refcounted entry to refcounting.
* Typos.
---
 include/linux/poison.h |   3 +
 lib/stackdepot.c       | 250 +++++++++++++++++++++--------------------
 2 files changed, 130 insertions(+), 123 deletions(-)

diff --git a/include/linux/poison.h b/include/linux/poison.h
index 27a7dad17eef..1f0ee2459f2a 100644
--- a/include/linux/poison.h
+++ b/include/linux/poison.h
@@ -92,4 +92,7 @@
 /********** VFS **********/
 #define VFS_PTR_POISON ((void *)(0xF5 + POISON_POINTER_DELTA))
 
+/********** lib/stackdepot.c **********/
+#define STACK_DEPOT_POISON ((void *)(0xD390 + POISON_POINTER_DELTA))
+
 #endif
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 5caa1f566553..8f3b2c84ec2d 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -22,6 +22,7 @@
 #include <linux/list.h>
 #include <linux/mm.h>
 #include <linux/mutex.h>
+#include <linux/poison.h>
 #include <linux/printk.h>
 #include <linux/rculist.h>
 #include <linux/rcupdate.h>
@@ -43,17 +44,7 @@
 #define DEPOT_OFFSET_BITS (DEPOT_POOL_ORDER + PAGE_SHIFT - DEPOT_STACK_ALIGN)
 #define DEPOT_POOL_INDEX_BITS (DEPOT_HANDLE_BITS - DEPOT_OFFSET_BITS - \
 			       STACK_DEPOT_EXTRA_BITS)
-#if IS_ENABLED(CONFIG_KMSAN) && CONFIG_STACKDEPOT_MAX_FRAMES >= 32
-/*
- * KMSAN is frequently used in fuzzing scenarios and thus saves a lot of stack
- * traces. As KMSAN does not support evicting stack traces from the stack
- * depot, the stack depot capacity might be reached quickly with large stack
- * records. Adjust the maximum number of stack depot pools for this case.
- */
-#define DEPOT_POOLS_CAP (8192 * (CONFIG_STACKDEPOT_MAX_FRAMES / 16))
-#else
 #define DEPOT_POOLS_CAP 8192
-#endif
 #define DEPOT_MAX_POOLS \
 	(((1LL << (DEPOT_POOL_INDEX_BITS)) < DEPOT_POOLS_CAP) ? \
 	 (1LL << (DEPOT_POOL_INDEX_BITS)) : DEPOT_POOLS_CAP)
@@ -93,9 +84,6 @@ struct stack_record {
 	};
 };
 
-#define DEPOT_STACK_RECORD_SIZE \
-	ALIGN(sizeof(struct stack_record), 1 << DEPOT_STACK_ALIGN)
-
 static bool stack_depot_disabled;
 static bool __stack_depot_early_init_requested __initdata = IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT);
 static bool __stack_depot_early_init_passed __initdata;
@@ -121,32 +109,31 @@ static void *stack_pools[DEPOT_MAX_POOLS];
 static void *new_pool;
 /* Number of pools in stack_pools. */
 static int pools_num;
+/* Offset to the unused space in the currently used pool. */
+static size_t pool_offset = DEPOT_POOL_SIZE;
 /* Freelist of stack records within stack_pools. */
 static LIST_HEAD(free_stacks);
-/*
- * Stack depot tries to keep an extra pool allocated even before it runs out
- * of space in the currently used pool. This flag marks whether this extra pool
- * needs to be allocated. It has the value 0 when either an extra pool is not
- * yet allocated or if the limit on the number of pools is reached.
- */
-static bool new_pool_required = true;
 /* The lock must be held when performing pool or freelist modifications. */
 static DEFINE_RAW_SPINLOCK(pool_lock);
 
 /* Statistics counters for debugfs. */
 enum depot_counter_id {
-	DEPOT_COUNTER_ALLOCS,
-	DEPOT_COUNTER_FREES,
-	DEPOT_COUNTER_INUSE,
+	DEPOT_COUNTER_REFD_ALLOCS,
+	DEPOT_COUNTER_REFD_FREES,
+	DEPOT_COUNTER_REFD_INUSE,
 	DEPOT_COUNTER_FREELIST_SIZE,
+	DEPOT_COUNTER_PERSIST_COUNT,
+	DEPOT_COUNTER_PERSIST_BYTES,
 	DEPOT_COUNTER_COUNT,
 };
 static long counters[DEPOT_COUNTER_COUNT];
 static const char *const counter_names[] = {
-	[DEPOT_COUNTER_ALLOCS]		= "allocations",
-	[DEPOT_COUNTER_FREES]		= "frees",
-	[DEPOT_COUNTER_INUSE]		= "in_use",
+	[DEPOT_COUNTER_REFD_ALLOCS]	= "refcounted_allocations",
+	[DEPOT_COUNTER_REFD_FREES]	= "refcounted_frees",
+	[DEPOT_COUNTER_REFD_INUSE]	= "refcounted_in_use",
 	[DEPOT_COUNTER_FREELIST_SIZE]	= "freelist_size",
+	[DEPOT_COUNTER_PERSIST_COUNT]	= "persistent_count",
+	[DEPOT_COUNTER_PERSIST_BYTES]	= "persistent_bytes",
 };
 static_assert(ARRAY_SIZE(counter_names) == DEPOT_COUNTER_COUNT);
 
@@ -294,48 +281,52 @@ int stack_depot_init(void)
 EXPORT_SYMBOL_GPL(stack_depot_init);
 
 /*
- * Initializes new stack depot @pool, release all its entries to the freelist,
- * and update the list of pools.
+ * Initializes new stack pool, and updates the list of pools.
  */
-static void depot_init_pool(void *pool)
+static bool depot_init_pool(void **prealloc)
 {
-	int offset;
-
 	lockdep_assert_held(&pool_lock);
 
-	/* Initialize handles and link stack records into the freelist. */
-	for (offset = 0; offset <= DEPOT_POOL_SIZE - DEPOT_STACK_RECORD_SIZE;
-	     offset += DEPOT_STACK_RECORD_SIZE) {
-		struct stack_record *stack = pool + offset;
-
-		stack->handle.pool_index = pools_num;
-		stack->handle.offset = offset >> DEPOT_STACK_ALIGN;
-		stack->handle.extra = 0;
-
-		/*
-		 * Stack traces of size 0 are never saved, and we can simply use
-		 * the size field as an indicator if this is a new unused stack
-		 * record in the freelist.
-		 */
-		stack->size = 0;
+	if (unlikely(pools_num >= DEPOT_MAX_POOLS)) {
+		/* Bail out if we reached the pool limit. */
+		WARN_ON_ONCE(pools_num > DEPOT_MAX_POOLS); /* should never happen */
+		WARN_ON_ONCE(!new_pool); /* to avoid unnecessary pre-allocation */
+		WARN_ONCE(1, "Stack depot reached limit capacity");
+		return false;
+	}
 
-		INIT_LIST_HEAD(&stack->hash_list);
-		/*
-		 * Add to the freelist front to prioritize never-used entries:
-		 * required in case there are entries in the freelist, but their
-		 * RCU cookie still belongs to the current RCU grace period
-		 * (there can still be concurrent readers).
-		 */
-		list_add(&stack->free_list, &free_stacks);
-		counters[DEPOT_COUNTER_FREELIST_SIZE]++;
+	if (!new_pool && *prealloc) {
+		/* We have preallocated memory, use it. */
+		WRITE_ONCE(new_pool, *prealloc);
+		*prealloc = NULL;
 	}
 
+	if (!new_pool)
+		return false; /* new_pool and *prealloc are NULL */
+
 	/* Save reference to the pool to be used by depot_fetch_stack(). */
-	stack_pools[pools_num] = pool;
+	stack_pools[pools_num] = new_pool;
+
+	/*
+	 * Stack depot tries to keep an extra pool allocated even before it runs
+	 * out of space in the currently used pool.
+	 *
+	 * To indicate that a new preallocation is needed new_pool is reset to
+	 * NULL; do not reset to NULL if we have reached the maximum number of
+	 * pools.
+	 */
+	if (pools_num < DEPOT_MAX_POOLS)
+		WRITE_ONCE(new_pool, NULL);
+	else
+		WRITE_ONCE(new_pool, STACK_DEPOT_POISON);
 
 	/* Pairs with concurrent READ_ONCE() in depot_fetch_stack(). */
 	WRITE_ONCE(pools_num, pools_num + 1);
 	ASSERT_EXCLUSIVE_WRITER(pools_num);
+
+	pool_offset = 0;
+
+	return true;
 }
 
 /* Keeps the preallocated memory to be used for a new stack depot pool. */
@@ -347,63 +338,51 @@ static void depot_keep_new_pool(void **prealloc)
 	 * If a new pool is already saved or the maximum number of
 	 * pools is reached, do not use the preallocated memory.
 	 */
-	if (!new_pool_required)
+	if (new_pool)
 		return;
 
-	/*
-	 * Use the preallocated memory for the new pool
-	 * as long as we do not exceed the maximum number of pools.
-	 */
-	if (pools_num < DEPOT_MAX_POOLS) {
-		new_pool = *prealloc;
-		*prealloc = NULL;
-	}
-
-	/*
-	 * At this point, either a new pool is kept or the maximum
-	 * number of pools is reached. In either case, take note that
-	 * keeping another pool is not required.
-	 */
-	WRITE_ONCE(new_pool_required, false);
+	WRITE_ONCE(new_pool, *prealloc);
+	*prealloc = NULL;
 }
 
 /*
- * Try to initialize a new stack depot pool from either a previous or the
- * current pre-allocation, and release all its entries to the freelist.
+ * Try to initialize a new stack record from the current pool, a cached pool, or
+ * the current pre-allocation.
  */
-static bool depot_try_init_pool(void **prealloc)
+static struct stack_record *depot_pop_free_pool(void **prealloc, size_t size)
 {
+	struct stack_record *stack;
+	void *current_pool;
+	u32 pool_index;
+
 	lockdep_assert_held(&pool_lock);
 
-	/* Check if we have a new pool saved and use it. */
-	if (new_pool) {
-		depot_init_pool(new_pool);
-		new_pool = NULL;
+	if (pool_offset + size > DEPOT_POOL_SIZE) {
+		if (!depot_init_pool(prealloc))
+			return NULL;
+	}
 
-		/* Take note that we might need a new new_pool. */
-		if (pools_num < DEPOT_MAX_POOLS)
-			WRITE_ONCE(new_pool_required, true);
+	if (WARN_ON_ONCE(pools_num < 1))
+		return NULL;
+	pool_index = pools_num - 1;
+	current_pool = stack_pools[pool_index];
+	if (WARN_ON_ONCE(!current_pool))
+		return NULL;
 
-		return true;
-	}
+	stack = current_pool + pool_offset;
 
-	/* Bail out if we reached the pool limit. */
-	if (unlikely(pools_num >= DEPOT_MAX_POOLS)) {
-		WARN_ONCE(1, "Stack depot reached limit capacity");
-		return false;
-	}
+	/* Pre-initialize handle once. */
+	stack->handle.pool_index = pool_index;
+	stack->handle.offset = pool_offset >> DEPOT_STACK_ALIGN;
+	stack->handle.extra = 0;
+	INIT_LIST_HEAD(&stack->hash_list);
 
-	/* Check if we have preallocated memory and use it. */
-	if (*prealloc) {
-		depot_init_pool(*prealloc);
-		*prealloc = NULL;
-		return true;
-	}
+	pool_offset += size;
 
-	return false;
+	return stack;
 }
 
-/* Try to find next free usable entry. */
+/* Try to find next free usable entry from the freelist. */
 static struct stack_record *depot_pop_free(void)
 {
 	struct stack_record *stack;
@@ -420,7 +399,7 @@ static struct stack_record *depot_pop_free(void)
 	 * check the first entry.
 	 */
 	stack = list_first_entry(&free_stacks, struct stack_record, free_list);
-	if (stack->size && !poll_state_synchronize_rcu(stack->rcu_state))
+	if (!poll_state_synchronize_rcu(stack->rcu_state))
 		return NULL;
 
 	list_del(&stack->free_list);
@@ -429,48 +408,73 @@ static struct stack_record *depot_pop_free(void)
 	return stack;
 }
 
+static inline size_t depot_stack_record_size(struct stack_record *s, unsigned int nr_entries)
+{
+	const size_t used = flex_array_size(s, entries, nr_entries);
+	const size_t unused = sizeof(s->entries) - used;
+
+	WARN_ON_ONCE(sizeof(s->entries) < used);
+
+	return ALIGN(sizeof(struct stack_record) - unused, 1 << DEPOT_STACK_ALIGN);
+}
+
 /* Allocates a new stack in a stack depot pool. */
 static struct stack_record *
-depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
+depot_alloc_stack(unsigned long *entries, int nr_entries, u32 hash, depot_flags_t flags, void **prealloc)
 {
-	struct stack_record *stack;
+	struct stack_record *stack = NULL;
+	size_t record_size;
 
 	lockdep_assert_held(&pool_lock);
 
 	/* This should already be checked by public API entry points. */
-	if (WARN_ON_ONCE(!size))
+	if (WARN_ON_ONCE(!nr_entries))
 		return NULL;
 
-	/* Check if we have a stack record to save the stack trace. */
-	stack = depot_pop_free();
-	if (!stack) {
-		/* No usable entries on the freelist - try to refill the freelist. */
-		if (!depot_try_init_pool(prealloc))
-			return NULL;
+	/* Limit number of saved frames to CONFIG_STACKDEPOT_MAX_FRAMES. */
+	if (nr_entries > CONFIG_STACKDEPOT_MAX_FRAMES)
+		nr_entries = CONFIG_STACKDEPOT_MAX_FRAMES;
+
+	if (flags & STACK_DEPOT_FLAG_GET) {
+		/*
+		 * Evictable entries have to allocate the max. size so they may
+		 * safely be re-used by differently sized allocations.
+		 */
+		record_size = depot_stack_record_size(stack, CONFIG_STACKDEPOT_MAX_FRAMES);
 		stack = depot_pop_free();
-		if (WARN_ON(!stack))
-			return NULL;
+	} else {
+		record_size = depot_stack_record_size(stack, nr_entries);
 	}
 
-	/* Limit number of saved frames to CONFIG_STACKDEPOT_MAX_FRAMES. */
-	if (size > CONFIG_STACKDEPOT_MAX_FRAMES)
-		size = CONFIG_STACKDEPOT_MAX_FRAMES;
+	if (!stack) {
+		stack = depot_pop_free_pool(prealloc, record_size);
+		if (!stack)
+			return NULL;
+	}
 
 	/* Save the stack trace. */
 	stack->hash = hash;
-	stack->size = size;
-	/* stack->handle is already filled in by depot_init_pool(). */
-	refcount_set(&stack->count, 1);
-	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
+	stack->size = nr_entries;
+	/* stack->handle is already filled in by depot_pop_free_pool(). */
+	memcpy(stack->entries, entries, flex_array_size(stack, entries, nr_entries));
+
+	if (flags & STACK_DEPOT_FLAG_GET) {
+		refcount_set(&stack->count, 1);
+		counters[DEPOT_COUNTER_REFD_ALLOCS]++;
+		counters[DEPOT_COUNTER_REFD_INUSE]++;
+	} else {
+		/* Warn on attempts to switch to refcounting this entry. */
+		refcount_set(&stack->count, REFCOUNT_SATURATED);
+		counters[DEPOT_COUNTER_PERSIST_COUNT]++;
+		counters[DEPOT_COUNTER_PERSIST_BYTES] += record_size;
+	}
 
 	/*
 	 * Let KMSAN know the stored stack record is initialized. This shall
 	 * prevent false positive reports if instrumented code accesses it.
 	 */
-	kmsan_unpoison_memory(stack, DEPOT_STACK_RECORD_SIZE);
+	kmsan_unpoison_memory(stack, record_size);
 
-	counters[DEPOT_COUNTER_ALLOCS]++;
-	counters[DEPOT_COUNTER_INUSE]++;
 	return stack;
 }
 
@@ -538,8 +542,8 @@ static void depot_free_stack(struct stack_record *stack)
 	list_add_tail(&stack->free_list, &free_stacks);
 
 	counters[DEPOT_COUNTER_FREELIST_SIZE]++;
-	counters[DEPOT_COUNTER_FREES]++;
-	counters[DEPOT_COUNTER_INUSE]--;
+	counters[DEPOT_COUNTER_REFD_FREES]++;
+	counters[DEPOT_COUNTER_REFD_INUSE]--;
 
 	printk_deferred_exit();
 	raw_spin_unlock_irqrestore(&pool_lock, flags);
@@ -660,7 +664,7 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 	 * Allocate memory for a new pool if required now:
 	 * we won't be able to do that under the lock.
 	 */
-	if (unlikely(can_alloc && READ_ONCE(new_pool_required))) {
+	if (unlikely(can_alloc && !READ_ONCE(new_pool))) {
 		/*
 		 * Zero out zone modifiers, as we don't have specific zone
 		 * requirements. Keep the flags related to allocation in atomic
@@ -681,7 +685,7 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 	found = find_stack(bucket, entries, nr_entries, hash, depot_flags);
 	if (!found) {
 		struct stack_record *new =
-			depot_alloc_stack(entries, nr_entries, hash, &prealloc);
+			depot_alloc_stack(entries, nr_entries, hash, depot_flags, &prealloc);
 
 		if (new) {
 			/*
-- 
2.43.0.429.g432eaa2c6b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240129100708.39460-1-elver%40google.com.
