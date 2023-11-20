Return-Path: <kasan-dev+bncBAABBM5Y52VAMGQEEJSA3YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id EEB267F1B79
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:49:40 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2c8850a2d62sf7633301fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:49:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502580; cv=pass;
        d=google.com; s=arc-20160816;
        b=usILbB/KKHJBXoS0sJy/nbvFVQOlnUv5HnrGWeALocSlOfN3QchKeF0+jDmMXfA2r0
         G3RWS6EtKjg4cHtjoyqXQGP/0nwz/CvVoY/0g5pNDdbFDG5DBIKpsN3LDamBgCozgluk
         CflP/mfvhgkM7n7WcxL1X05D9rDai6LcoH3N/AB2Qstdy+yLPhWUnwYHMw3dwE4bThrh
         xnTnzfUpWF24QvCr+d8QAL5XWmsiFbANMudyDUw6Sm1Ym7F9YxdlmlF/liMTMUQrvFEc
         hnS2CBnRaZG/CJsaRvoOzyFJpRdSsVkQ+LLFu9FxGX/4FrABPpchQtz2spUqZZXzRAaq
         AKSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vCgemGg10tJEfz121Ub/viwpkCmmk9xPD3Gp45COnnM=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=iYdabmHNNb6GMhfyYa4BdCfjcugMokLO0stjTkQETerGMGgZZlvadpfzK0OtZt6jrv
         rIcXvK4zw+f0YdYSvHheOHzBO2VNJeRZ8yRKaVKeBDWFxjZOUHSSlZVXiSJuknUjV0y9
         U3me0gQlhnhR1ihOx1xYMRalgW1sJ1z7A4svU/V8HR0b0CuoIE/7ZXP0SFMr+j6HEkIu
         3KX7MCa+OuuGZ+mKsManVtOV+y88LWfMuzHT6YSqQ2Oidove/Zcrfpjz12crHg7V7v+K
         609EpdUT2UqozE6TwPdgYw8W4xZsBUGPz8HPo4j34po8x9f0Yl1hTj21D/o9lb2Pb4a0
         k9XQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IaUsjEmo;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.184 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502580; x=1701107380; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vCgemGg10tJEfz121Ub/viwpkCmmk9xPD3Gp45COnnM=;
        b=BYSBj0DU+mtZOS2hLv8HckGSRvR+WrXGeUukaXuLo9cmIRoOudmALPcz5HZZtyj89y
         +BPrD6JMx3mGFuGXLYK9lnWfT3L8ZP2vwrk1SJhB178DYpcYhWxsxTO9x93sWIfRqn5X
         V/A/hzGKkhbmWkVCNB6ooqxjzTG2kmy6AtqKDrLaIokLjfMFyIvuUcOXBJfcH1evkbOw
         ybeW93QKhXFHiCB/J6zwHGS1o7svNnKfp/woJ2mzlC1xvlHymsmywFulOnoWUFglYEHs
         Fu5GryCd5OR2kqh+6XZAp5ai9KdD01p/85cqg2Fi0did8HEG/6VR84LUjMjwxw96vl4m
         M5kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502580; x=1701107380;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vCgemGg10tJEfz121Ub/viwpkCmmk9xPD3Gp45COnnM=;
        b=XbkfvvQ1wNMsjnax+OVUgONy1Nz3+kZNTl5JRMJ6wfudP4hg9QHQ04aRQXbQEU921+
         /DyZ6JXJfe4Re/CVf0S7yXzsgK/BTX94NY/64iHPIN6TdVK50sA7MNPueWbU/39lXWsn
         hinGlquHZrby8asTGNL4G/gOE8iNeWvoCehjYJ2/eVGy0RBKQ7Udjp/JftRbURx7okth
         KPeeRecKj7hF9PfGw2WvcQjTvm8UaN0LRbDFLLhE2q/h+LtXWJ0joBY2lmlro5RnODO4
         qE780k/NPZ0S8kJdn3OaEPF9xxNyV+xlVUrEr+QwovJbrTedWwd9LhR5+BwAO0hW82mG
         KxMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzsKippc51QUxSDHakrambyFwGPtoKRaQek4J21KYZ0MzIimv69
	btSCXYo/ULn5yNaS4sOU4aE=
X-Google-Smtp-Source: AGHT+IE5cJnfMSJZo62g+ZK0fgVcxl7t7L8Vxu2Sd7KemVGTdZ8F/+cH1txj0h9GP8xgxTuXqvbFSg==
X-Received: by 2002:a05:651c:10af:b0:2c5:6d8:8dfc with SMTP id k15-20020a05651c10af00b002c506d88dfcmr5057295ljn.13.1700502579794;
        Mon, 20 Nov 2023 09:49:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b83:b0:405:47db:268f with SMTP id
 n3-20020a05600c3b8300b0040547db268fls1125146wms.0.-pod-prod-09-eu; Mon, 20
 Nov 2023 09:49:38 -0800 (PST)
X-Received: by 2002:a05:600c:470a:b0:405:4a78:a892 with SMTP id v10-20020a05600c470a00b004054a78a892mr5616966wmo.9.1700502578068;
        Mon, 20 Nov 2023 09:49:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502578; cv=none;
        d=google.com; s=arc-20160816;
        b=fY0mxYWvRuzdHUzetFEfQ6benhUUs9mPSwvUSn3kIqumo6CeOEn9fjLDvO/rfRv7yX
         Ho7KDia4t9W9s1W0SIw5phvNwWFIJcOQh1twYvweY4jgUBloyDzaBAmWkookIUq981hR
         snOqq3Z3VUa+PjE0W/vH0EzewSc75poYI2EX7pi2zsQDzHCiZuWzrEGf4LEcd2mH99BD
         2smLvNfYxeEubKRZDWenV8uNCEbaWr3kvsFBmjnXMjz+9EcJPrI1kS9gGYBngKTMTsQI
         65uQUCbYqPxCGIIw1hS/oSW+d//lXxrYAzFahbh8/6WkoBMNcyAnSjo9tt8PqziIFKQE
         gU5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=K4xViYAWVaV6VQ5HtL4BYhsbr4MB9DPwoOHOaowHM8k=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=gF4r5dxrYvmPGvV4DIDQ/TyYd501BQ3xAlY9aNkaD4xoBPsVMtVFTsInzcr++FFpO4
         EgjyIk4jL2q3oNpI9E78jKv1hhJuKFaVCD+VWRdbA8gBh++pP//A88WBT7pmMRtSo1ta
         1sA2NG9WWVJkGO8NA3N5Vwh7NCzJfDCfVdKIf/L36fl00ZDimUDxGzjAPb0eZ4l/ESMQ
         35jH/AqWPzw4cphEBFvu1/P7/yKAxgBwT2WtQreh+jOHmtHBbx42jL3cHmaSX34ztGxR
         nM/CrBz+B+oEOLyzVCTuzBgfaGU0HdclgSuNB1uwNZcUg5NtLkqspXZzsdUlsJ8sks+V
         MBBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IaUsjEmo;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.184 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-184.mta0.migadu.com (out-184.mta0.migadu.com. [91.218.175.184])
        by gmr-mx.google.com with ESMTPS id bg22-20020a05600c3c9600b0040a25ec1ce5si710160wmb.0.2023.11.20.09.49.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:49:38 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.184 as permitted sender) client-ip=91.218.175.184;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v4 12/22] lib/stackdepot: use read/write lock
Date: Mon, 20 Nov 2023 18:47:10 +0100
Message-Id: <9f81ffcc4bb422ebb6326a65a770bf1918634cbb.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=IaUsjEmo;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.184
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Currently, stack depot uses the following locking scheme:

1. Lock-free accesses when looking up a stack record, which allows to
   have multiple users to look up records in parallel;
2. Spinlock for protecting the stack depot pools and the hash table
   when adding a new record.

For implementing the eviction of stack traces from stack depot, the
lock-free approach is not going to work anymore, as we will need to be
able to also remove records from the hash table.

Convert the spinlock into a read/write lock, and drop the atomic accesses,
as they are no longer required.

Looking up stack traces is now protected by the read lock and adding new
records - by the write lock. One of the following patches will add a new
function for evicting stack records, which will be protected by the write
lock as well.

With this change, multiple users can still look up records in parallel.

This is preparatory patch for implementing the eviction of stack records
from the stack depot.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changed v2->v3:
- Use lockdep_assert_held_read annotation in depot_fetch_stack.

Changes v1->v2:
- Add lockdep_assert annotations.
---
 lib/stackdepot.c | 87 +++++++++++++++++++++++++-----------------------
 1 file changed, 46 insertions(+), 41 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index a5eff165c0d5..8378b32b5310 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -23,6 +23,7 @@
 #include <linux/percpu.h>
 #include <linux/printk.h>
 #include <linux/slab.h>
+#include <linux/spinlock.h>
 #include <linux/stacktrace.h>
 #include <linux/stackdepot.h>
 #include <linux/string.h>
@@ -91,15 +92,15 @@ static void *new_pool;
 static int pools_num;
 /* Next stack in the freelist of stack records within stack_pools. */
 static struct stack_record *next_stack;
-/* Lock that protects the variables above. */
-static DEFINE_RAW_SPINLOCK(pool_lock);
 /*
  * Stack depot tries to keep an extra pool allocated even before it runs out
  * of space in the currently used pool. This flag marks whether this extra pool
  * needs to be allocated. It has the value 0 when either an extra pool is not
  * yet allocated or if the limit on the number of pools is reached.
  */
-static int new_pool_required = 1;
+static bool new_pool_required = true;
+/* Lock that protects the variables above. */
+static DEFINE_RWLOCK(pool_rwlock);
 
 static int __init disable_stack_depot(char *str)
 {
@@ -232,6 +233,8 @@ static void depot_init_pool(void *pool)
 	const int records_in_pool = DEPOT_POOL_SIZE / DEPOT_STACK_RECORD_SIZE;
 	int i, offset;
 
+	lockdep_assert_held_write(&pool_rwlock);
+
 	/* Initialize handles and link stack records to each other. */
 	for (i = 0, offset = 0;
 	     offset <= DEPOT_POOL_SIZE - DEPOT_STACK_RECORD_SIZE;
@@ -254,22 +257,17 @@ static void depot_init_pool(void *pool)
 
 	/* Save reference to the pool to be used by depot_fetch_stack(). */
 	stack_pools[pools_num] = pool;
-
-	/*
-	 * WRITE_ONCE() pairs with potential concurrent read in
-	 * depot_fetch_stack().
-	 */
-	WRITE_ONCE(pools_num, pools_num + 1);
+	pools_num++;
 }
 
 /* Keeps the preallocated memory to be used for a new stack depot pool. */
 static void depot_keep_new_pool(void **prealloc)
 {
+	lockdep_assert_held_write(&pool_rwlock);
+
 	/*
 	 * If a new pool is already saved or the maximum number of
 	 * pools is reached, do not use the preallocated memory.
-	 * Access new_pool_required non-atomically, as there are no concurrent
-	 * write accesses to this variable.
 	 */
 	if (!new_pool_required)
 		return;
@@ -287,15 +285,15 @@ static void depot_keep_new_pool(void **prealloc)
 	 * At this point, either a new pool is kept or the maximum
 	 * number of pools is reached. In either case, take note that
 	 * keeping another pool is not required.
-	 * smp_store_release() pairs with smp_load_acquire() in
-	 * stack_depot_save().
 	 */
-	smp_store_release(&new_pool_required, 0);
+	new_pool_required = false;
 }
 
 /* Updates references to the current and the next stack depot pools. */
 static bool depot_update_pools(void **prealloc)
 {
+	lockdep_assert_held_write(&pool_rwlock);
+
 	/* Check if we still have objects in the freelist. */
 	if (next_stack)
 		goto out_keep_prealloc;
@@ -307,7 +305,7 @@ static bool depot_update_pools(void **prealloc)
 
 		/* Take note that we might need a new new_pool. */
 		if (pools_num < DEPOT_MAX_POOLS)
-			smp_store_release(&new_pool_required, 1);
+			new_pool_required = true;
 
 		/* Try keeping the preallocated memory for new_pool. */
 		goto out_keep_prealloc;
@@ -341,6 +339,8 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 {
 	struct stack_record *stack;
 
+	lockdep_assert_held_write(&pool_rwlock);
+
 	/* Update current and new pools if required and possible. */
 	if (!depot_update_pools(prealloc))
 		return NULL;
@@ -376,18 +376,15 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 {
 	union handle_parts parts = { .handle = handle };
-	/*
-	 * READ_ONCE() pairs with potential concurrent write in
-	 * depot_init_pool().
-	 */
-	int pools_num_cached = READ_ONCE(pools_num);
 	void *pool;
 	size_t offset = parts.offset << DEPOT_STACK_ALIGN;
 	struct stack_record *stack;
 
-	if (parts.pool_index > pools_num_cached) {
+	lockdep_assert_held_read(&pool_rwlock);
+
+	if (parts.pool_index > pools_num) {
 		WARN(1, "pool index %d out of bounds (%d) for stack id %08x\n",
-		     parts.pool_index, pools_num_cached, handle);
+		     parts.pool_index, pools_num, handle);
 		return NULL;
 	}
 
@@ -429,6 +426,8 @@ static inline struct stack_record *find_stack(struct stack_record *bucket,
 {
 	struct stack_record *found;
 
+	lockdep_assert_held(&pool_rwlock);
+
 	for (found = bucket; found; found = found->next) {
 		if (found->hash == hash &&
 		    found->size == size &&
@@ -446,6 +445,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	depot_stack_handle_t handle = 0;
 	struct page *page = NULL;
 	void *prealloc = NULL;
+	bool need_alloc = false;
 	unsigned long flags;
 	u32 hash;
 
@@ -465,22 +465,26 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	hash = hash_stack(entries, nr_entries);
 	bucket = &stack_table[hash & stack_hash_mask];
 
-	/*
-	 * Fast path: look the stack trace up without locking.
-	 * smp_load_acquire() pairs with smp_store_release() to |bucket| below.
-	 */
-	found = find_stack(smp_load_acquire(bucket), entries, nr_entries, hash);
-	if (found)
+	read_lock_irqsave(&pool_rwlock, flags);
+
+	/* Fast path: look the stack trace up without full locking. */
+	found = find_stack(*bucket, entries, nr_entries, hash);
+	if (found) {
+		read_unlock_irqrestore(&pool_rwlock, flags);
 		goto exit;
+	}
+
+	/* Take note if another stack pool needs to be allocated. */
+	if (new_pool_required)
+		need_alloc = true;
+
+	read_unlock_irqrestore(&pool_rwlock, flags);
 
 	/*
-	 * Check if another stack pool needs to be allocated. If so, allocate
-	 * the memory now: we won't be able to do that under the lock.
-	 *
-	 * smp_load_acquire() pairs with smp_store_release() in
-	 * depot_update_pools() and depot_keep_new_pool().
+	 * Allocate memory for a new pool if required now:
+	 * we won't be able to do that under the lock.
 	 */
-	if (unlikely(can_alloc && smp_load_acquire(&new_pool_required))) {
+	if (unlikely(can_alloc && need_alloc)) {
 		/*
 		 * Zero out zone modifiers, as we don't have specific zone
 		 * requirements. Keep the flags related to allocation in atomic
@@ -494,7 +498,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 			prealloc = page_address(page);
 	}
 
-	raw_spin_lock_irqsave(&pool_lock, flags);
+	write_lock_irqsave(&pool_rwlock, flags);
 
 	found = find_stack(*bucket, entries, nr_entries, hash);
 	if (!found) {
@@ -503,11 +507,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 
 		if (new) {
 			new->next = *bucket;
-			/*
-			 * smp_store_release() pairs with smp_load_acquire()
-			 * from |bucket| above.
-			 */
-			smp_store_release(bucket, new);
+			*bucket = new;
 			found = new;
 		}
 	} else if (prealloc) {
@@ -518,7 +518,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		depot_keep_new_pool(&prealloc);
 	}
 
-	raw_spin_unlock_irqrestore(&pool_lock, flags);
+	write_unlock_irqrestore(&pool_rwlock, flags);
 exit:
 	if (prealloc) {
 		/* Stack depot didn't use this memory, free it. */
@@ -542,6 +542,7 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 			       unsigned long **entries)
 {
 	struct stack_record *stack;
+	unsigned long flags;
 
 	*entries = NULL;
 	/*
@@ -553,8 +554,12 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 	if (!handle || stack_depot_disabled)
 		return 0;
 
+	read_lock_irqsave(&pool_rwlock, flags);
+
 	stack = depot_fetch_stack(handle);
 
+	read_unlock_irqrestore(&pool_rwlock, flags);
+
 	*entries = stack->entries;
 	return stack->size;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9f81ffcc4bb422ebb6326a65a770bf1918634cbb.1700502145.git.andreyknvl%40google.com.
