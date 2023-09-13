Return-Path: <kasan-dev+bncBAABBT64Q6UAMGQERYMGZVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id A99E079F01C
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:16:00 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-401bd4ce391sf25645e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:16:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694625360; cv=pass;
        d=google.com; s=arc-20160816;
        b=UyQXBrtDydVl+ebqH/QYqXcH4kEcBhxUl6MqqcT3qn+V4b+EfOrzjv0gDtFxSHatwp
         XGSfOdb6GgvG7yDWC8ykuK6IP2VFgtkqmEfVFBVwyqGeSUPzQGpSQhOk2wCt/Z5R13un
         eDyAXDNtBG7AWp/A7U4nHQmFQGvL5Ni96k0uXuGZszjdtZg3Qzi7KbqxYrYdO43oNM0J
         2kxQjk8jne5FU058rnO7S1pzu5x4XNJk59dUIAZhxmnC3j3w5alH/0bgbGjCHhnRk+gR
         PWCi5u7xiejyp4Zi1ooQm2ubr25MJJ4uRBFeazqPs2GbEeB2lYme+wQPwMROz4r8fgpI
         Mclg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=mLsYcNB544ODe8TJblb4Gojh5N/ZExTR58n+YWaqBtY=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=wzlqj0u+D3qWImaWU1yBc6AM6RX5blfZzqcGzzAkTgyPCgIimloTPFpPHvNPN4zr9w
         ydcISdsQivDysvsxm6Wuv3/gk/ILj4KsPmiM0y6BIabif0UYm0RfINZ6WU5gRkXDiTDI
         r0C+TnNbEecvOxCfPju7txzN/J6Sq+8AUvIyUk3vhjxQqB6q/ej9umc9ysxKs5r3UHlQ
         ahxAbHf0rNSXoCivPtFaqvZ8FBVzw19zX82oubH5EgcFqoZ89lrcNTqwXxi2LAvsOVFw
         Que8OfByZ7K+pnzMRLVTHApEG50OqYIOy/LsQcehUp+ekZmOHHlpXjHdMk2uJVRKVUdF
         6SoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=L1ENvY04;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::d4 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694625360; x=1695230160; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mLsYcNB544ODe8TJblb4Gojh5N/ZExTR58n+YWaqBtY=;
        b=KPdIT1v06EQ6c26wAWxyYbBWWWJlY01AjXId0xhe4o7P+PwB9hNbaw9VciNFt2klup
         BOjQpHOL0vIEY6tHaUExvj9GhItRtxERRBEpG3YQ7qgwvtjzJp3wP348m4899eRaCxeP
         RGjAYjsMbXZCnMB4HXF3Nq8b6TJM990n7syVmy31BFFzSxPMe+Pnn1HrE4oRo6qSC+dd
         EJjOSbI30ZCCEWhcECBVsGgZEatB5LLhRA7BomkUhVGsiFeaSZeWVKDSh5upPoPYJxl+
         bi4hyTbMY8ajSOcs7085m4KiO5K/tnBLBhYh43JLvsa281z7ZOrwrtjL2FrK/YaefTAN
         IUwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694625360; x=1695230160;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mLsYcNB544ODe8TJblb4Gojh5N/ZExTR58n+YWaqBtY=;
        b=uB0HtHNALP/MSWwLq+5Z98vdON2B2Ct7NIAXowUO2ZD955jvkWs7Ha/ttjybSmObRO
         V1GDzX09R/nt8p3KLeCJYR7FGO8IubmxlrTTEqf6kPjiANvvoDjaIJic+1mNP4c8b9HK
         eGZhQHRR2w62I3LnGXhho8ZWVHtOMNlcs8g/7JonIi8/Zl1iDaf81uYHUdFYU8n/0gOy
         6X7ulUwN3dyM4++IxgECeMXcEsyu3ugEvvi1nZsscCzPSrcatZGB6ZranEDWf6wR+R8a
         3CYQuaI9POASkifNuNwalKT7FvpJbyG1KJuSfTWofFnMe28ry92WYhzVwtmTMXgxG49H
         NUsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yys1rcuwOwZ4Zh7xiWJMU+ZI75ypThOYEbF9TCM8YddyxIQ99s7
	gfbsfKvf/FTXtpNCgBXos6k=
X-Google-Smtp-Source: AGHT+IFpktNBMxhe1Nxwq8mHTHXnS2f6ekcsEVZ1vqgdNYH0smXTP5bUUukOL/jwFliZp9BbVruCRg==
X-Received: by 2002:a05:600c:45d4:b0:3fe:d691:7d63 with SMTP id s20-20020a05600c45d400b003fed6917d63mr174287wmo.6.1694625359354;
        Wed, 13 Sep 2023 10:15:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4592:b0:401:7d3b:ccb1 with SMTP id
 r18-20020a05600c459200b004017d3bccb1ls1866117wmo.1.-pod-prod-09-eu; Wed, 13
 Sep 2023 10:15:58 -0700 (PDT)
X-Received: by 2002:a7b:c4d8:0:b0:401:b3a5:ebf8 with SMTP id g24-20020a7bc4d8000000b00401b3a5ebf8mr2437604wmk.16.1694625357898;
        Wed, 13 Sep 2023 10:15:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694625357; cv=none;
        d=google.com; s=arc-20160816;
        b=qQlQ9ksy3Hmkgm9NVPhM+Q7ZHOqLb0xjPERwsI81eIKNf8ixnNXI1qZdcwf142d18v
         llbKvhJSgaLoxBCjAi5p4iQV7A0m5FsZXFrFQAlsA5VjV4t++QGyAaS0N65UphxxQBCc
         TZeWuWtMkH59F58RIcw65rbDwRTTomrD4tbMUtpJMkHwPEEhNk0WAldU6BJG+c+xsebF
         wA08tbmPbPIyyAEAjM9lH0GTQN1LElPDP/xKjFZvl6jlZZhkkJEvpTTW0vo7ayLVEU49
         c/Orp1RscwvWlxYfYMnPiaoGoaZTK7HPAZMNI3ha9EZbQv9fAkFI6f7SnMhXQTeoK+1A
         En9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CyWM6kbTs8GrrlAHDj3nsmHfEdZOGlJXB22VnHOfO0M=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=N3diy0eeWaZUQ3Z2/a3bYkUIIS+FczeIMfgX7MXfK9fZhBvxHP/lzQBRSTmvd9VMAJ
         cSp7NYKPkAEmgleB/+o8i+Q55tkTO61W85EQAzSzLhRvshA7/jORr4Yp0kKmUTmGvXVB
         ff+IcdPYM6M2F3maz2PHtbK5VeinIz6QrcTRmfMEUpl36bbo+LVFzEFIgidw5DcNywN7
         3qhFB9gMgFf61mo5naZJ/msMNP+Fe3PSwIK1lkB65vg+SjXNYPn2D4q5sjggJ+U0f+vQ
         mxdt3L7YZvOcTZEg2fPxsfX4jppuwygM5H98RhtRyHyA2Fsg5Vkgwcx+Kwes5XwR5xCy
         42zQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=L1ENvY04;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::d4 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-212.mta1.migadu.com (out-212.mta1.migadu.com. [2001:41d0:203:375::d4])
        by gmr-mx.google.com with ESMTPS id a20-20020a05600c349400b003fe16346f71si339921wmq.1.2023.09.13.10.15.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Sep 2023 10:15:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::d4 as permitted sender) client-ip=2001:41d0:203:375::d4;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 11/19] lib/stackdepot: use read/write lock
Date: Wed, 13 Sep 2023 19:14:36 +0200
Message-Id: <5c5eca8a53ea53352794de57c87440ec509c9bbc.1694625260.git.andreyknvl@google.com>
In-Reply-To: <cover.1694625260.git.andreyknvl@google.com>
References: <cover.1694625260.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=L1ENvY04;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::d4 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Add lockdep_assert annotations.
---
 lib/stackdepot.c | 86 ++++++++++++++++++++++++++----------------------
 1 file changed, 47 insertions(+), 39 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index ca8e6fee0cb4..0b4591475d4f 100644
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
@@ -226,6 +227,8 @@ static void depot_init_pool(void *pool)
 	const int records_in_pool = DEPOT_POOL_SIZE / DEPOT_STACK_RECORD_SIZE;
 	int i, offset;
 
+	lockdep_assert_held_write(&pool_rwlock);
+
 	/* Initialize handles and link stack records to each other. */
 	for (i = 0, offset = 0;
 	     offset <= DEPOT_POOL_SIZE - DEPOT_STACK_RECORD_SIZE;
@@ -248,22 +251,19 @@ static void depot_init_pool(void *pool)
 
 	/* Save reference to the pool to be used by depot_fetch_stack. */
 	stack_pools[pools_num] = pool;
-
-	/*
-	 * WRITE_ONCE pairs with potential concurrent read in
-	 * depot_fetch_stack.
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
 	 */
-	if (!next_pool_required)
+	if (!new_pool_required)
 		return;
 
 	/*
@@ -279,14 +279,15 @@ static void depot_keep_new_pool(void **prealloc)
 	 * At this point, either a new pool is kept or the maximum
 	 * number of pools is reached. In either case, take note that
 	 * keeping another pool is not required.
-	 * smp_store_release pairs with smp_load_acquire in stack_depot_save.
 	 */
-	smp_store_release(&new_pool_required, 0);
+	new_pool_required = false;
 }
 
 /* Updates refences to the current and the next stack depot pools. */
 static bool depot_update_pools(void **prealloc)
 {
+	lockdep_assert_held_write(&pool_rwlock);
+
 	/* Check if we still have objects in the freelist. */
 	if (next_stack)
 		goto out_keep_prealloc;
@@ -298,7 +299,7 @@ static bool depot_update_pools(void **prealloc)
 
 		/* Take note that we might need a new new_pool. */
 		if (pools_num < DEPOT_MAX_POOLS)
-			smp_store_release(&new_pool_required, 1);
+			new_pool_required = true;
 
 		/* Try keeping the preallocated memory for new_pool. */
 		goto out_keep_prealloc;
@@ -332,6 +333,8 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 {
 	struct stack_record *stack;
 
+	lockdep_assert_held_write(&pool_rwlock);
+
 	/* Update current and new pools if required and possible. */
 	if (!depot_update_pools(prealloc))
 		return NULL;
@@ -367,18 +370,15 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 {
 	union handle_parts parts = { .handle = handle };
-	/*
-	 * READ_ONCE pairs with potential concurrent write in
-	 * depot_init_pool.
-	 */
-	int pools_num_cached = READ_ONCE(pools_num);
 	void *pool;
 	size_t offset = parts.offset << DEPOT_STACK_ALIGN;
 	struct stack_record *stack;
 
-	if (parts.pool_index > pools_num_cached) {
+	lockdep_assert_held(&pool_rwlock);
+
+	if (parts.pool_index > pools_num) {
 		WARN(1, "pool index %d out of bounds (%d) for stack id %08x\n",
-		     parts.pool_index, pools_num_cached, handle);
+		     parts.pool_index, pools_num, handle);
 		return NULL;
 	}
 
@@ -420,6 +420,8 @@ static inline struct stack_record *find_stack(struct stack_record *bucket,
 {
 	struct stack_record *found;
 
+	lockdep_assert_held(&pool_rwlock);
+
 	for (found = bucket; found; found = found->next) {
 		if (found->hash == hash &&
 		    found->size == size &&
@@ -437,6 +439,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	depot_stack_handle_t handle = 0;
 	struct page *page = NULL;
 	void *prealloc = NULL;
+	bool need_alloc = false;
 	unsigned long flags;
 	u32 hash;
 
@@ -456,22 +459,26 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	hash = hash_stack(entries, nr_entries);
 	bucket = &stack_table[hash & stack_hash_mask];
 
-	/*
-	 * Fast path: look the stack trace up without locking.
-	 * smp_load_acquire pairs with smp_store_release to |bucket| below.
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
-	 * smp_load_acquire pairs with smp_store_release in depot_update_pools
-	 * and depot_keep_new_pool.
+	 * Allocate memory for a new pool if required now:
+	 * we won't be able to do that under the lock.
 	 */
-	if (unlikely(can_alloc && smp_load_acquire(&new_pool_required))) {
+	if (unlikely(can_alloc && need_alloc)) {
 		/*
 		 * Zero out zone modifiers, as we don't have specific zone
 		 * requirements. Keep the flags related to allocation in atomic
@@ -485,7 +492,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 			prealloc = page_address(page);
 	}
 
-	raw_spin_lock_irqsave(&pool_lock, flags);
+	write_lock_irqsave(&pool_rwlock, flags);
 
 	found = find_stack(*bucket, entries, nr_entries, hash);
 	if (!found) {
@@ -494,11 +501,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 
 		if (new) {
 			new->next = *bucket;
-			/*
-			 * smp_store_release pairs with smp_load_acquire
-			 * from |bucket| above.
-			 */
-			smp_store_release(bucket, new);
+			*bucket = new;
 			found = new;
 		}
 	} else if (prealloc) {
@@ -509,7 +512,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		depot_keep_new_pool(&prealloc);
 	}
 
-	raw_spin_unlock_irqrestore(&pool_lock, flags);
+	write_unlock_irqrestore(&pool_rwlock, flags);
 exit:
 	if (prealloc) {
 		/* Stack depot didn't use this memory, free it. */
@@ -533,6 +536,7 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 			       unsigned long **entries)
 {
 	struct stack_record *stack;
+	unsigned long flags;
 
 	*entries = NULL;
 	/*
@@ -544,8 +548,12 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5c5eca8a53ea53352794de57c87440ec509c9bbc.1694625260.git.andreyknvl%40google.com.
