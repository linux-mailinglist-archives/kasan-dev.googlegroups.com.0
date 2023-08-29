Return-Path: <kasan-dev+bncBAABBC6OXCTQMGQEC5F4OGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id D784478CA63
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 19:12:44 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-401b8089339sf28286825e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 10:12:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693329164; cv=pass;
        d=google.com; s=arc-20160816;
        b=FBBZi1u7m2cNaokCyEc9HxeQV2IVE5uA3ydFQtPXZ7Frc+YQ3EtooP1QZiCN/R6pKO
         7oNN/37zhljakhnwt76qPC4k2U3hm/Xw0jAB4BIPUrIobIfyq/T1/D/8rfgInKYjAKMP
         r+HK6HefW2tE2PPIr1PCOw9OKkokr2j5m7o6Qgm7262mzG/2Uz4kB3YfXo7bAyHaAig7
         BqRQaKz1rlu+OHMger33F+GbR+0nYFb4YxaQqrJzXFvuQboSkjBuya/6vOY9CusQv3J/
         +tkKpmL3+kF5dX7iw0jwUR8VVjeEbAErAOSgL2BUCFo2IwUwKsplnvWzZggtBuJ4RZAo
         fbpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=hN7Kp8P81uoMlGdMm+xEd/s8zlu3Hos50lVH3i5kwfM=;
        fh=ZTTSst3850TI+4y2eqKpcuCmJhEtn1qZX9lpGyHR9Jg=;
        b=wZTSS0c4DV5Sh7Kb7LwcZLmU8a6MkNYX4sLoLAs0zkxRvV9MbOr/D0RC7sbtSxvBvS
         3G+hmjFBNqEgVaPqxgD0k7rgx4ZHgwpavGbXdcXUFK2JuUbqp9Pcxpj/diRQ5vV1epud
         /q5+oQB2fqcmvvtXELlgMuHHh749ydlGi53NeK4aHJJG9juoI1V+hrZ6UifI2CMxsmiU
         Vop0T+i33c/Hemh/XJBvj1r+ImCkWl+WGh1Fc4ancYu39b1JfGnf4wULXLPn7w1TbwvM
         wWYToNt3/MBJ8zu7uLEfMEDtd8GIVcdUQxOIsplt2TGIcwEKW2Wxw3VX0JEYPPgnDdxL
         3u6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=W3s6IJQi;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::f2 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1693329164; x=1693933964;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hN7Kp8P81uoMlGdMm+xEd/s8zlu3Hos50lVH3i5kwfM=;
        b=KyjVi1QugGjtKf/C6bdrPzCX3p+GwsdY+8xrbUAIsSAxyuZkoLdKFUCoAzjQ34iR9s
         RkraSWrQaQ4oc1zd7PYL15LPWSoF21V1r2xA8x7oonknO7olyqnirZ6+rQ9c8JL4odHJ
         O+FtJaCEfZF+jvnSdJTHjMLgRTZK8sgk7UXIhy/pvp3+TrMfsmdz1ETz0Kx76K1syx1P
         ACxecR7ZlSyWksUXAUBzNZe2QH7xr21NyyA1aft6TiQCjPVbR52/ertWd70EDQL9D2wr
         SASzbK1jQXPdNEJVlCo2yvAJsHfMKE4rJvb+r2dQ83bVjhAbytDLkmNzEAu1s2GwLC4+
         F+7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693329164; x=1693933964;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hN7Kp8P81uoMlGdMm+xEd/s8zlu3Hos50lVH3i5kwfM=;
        b=VSh51bkpnC4SAAVmav/gEThYbAKRNK7S/f/P3780iGFqXAT1wHoetsbpLp5twAmFdM
         daAOMViMGkjM32Uf+DPRTzgunmk+8pNgkvJoPUi7jzpRBtgOUBI5G0cFVn+YnbbYglKg
         ovpeKsar+WSyeiKOdOQJIR1qaSDcI3tE11iuWNkuXT56YyGTQbZhm3b/1/CAttpzNF+O
         f/7y/0alQuxSe27IFXzLk5o+Rect131ax3b+RRyimZ+sCRRtrILGbXC1TACxXxOrtw6x
         u68swXRDZBGzy3FVvdj6e9idHKvszrbGg8IOWsUG9IYxcgKuOrt2iezoLHPzPwi/Fcrd
         owTw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxz294HvtAGZG0PiWKlVuP2tD72jyt1rjxIq+O52NSjPM0rbbo4
	XDUGZ2uFltf5ficOSCRud0E=
X-Google-Smtp-Source: AGHT+IHWF7GAeHvfQr0X0EnSb1XgrCBKXEi6v/B6fxrmWKaw8AGu/a/qpiTKXBcmuHE/P61qxH6/NQ==
X-Received: by 2002:a05:600c:3653:b0:401:b0f2:88b4 with SMTP id y19-20020a05600c365300b00401b0f288b4mr11005622wmq.26.1693329164151;
        Tue, 29 Aug 2023 10:12:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3546:b0:3fe:1974:f893 with SMTP id
 i6-20020a05600c354600b003fe1974f893ls2141034wmq.0.-pod-prod-07-eu; Tue, 29
 Aug 2023 10:12:42 -0700 (PDT)
X-Received: by 2002:a7b:c7c3:0:b0:3fd:2e1d:eca1 with SMTP id z3-20020a7bc7c3000000b003fd2e1deca1mr22389287wmk.4.1693329162745;
        Tue, 29 Aug 2023 10:12:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693329162; cv=none;
        d=google.com; s=arc-20160816;
        b=K2qYBQ35hsuOJwS/QE7ISJLw4M6XV+15DWO8F73FAzMyCij1SmitF9oI1JWGQZLP/K
         nYwtgoUET9O2ML9yxdyP7pke0AwA0TYuqnts4NItAg+p1by0PVc1f+75yxffAoXEMtF9
         jHzBMpDvkADgTLd0PxPqnf/Mzsq9pMYOpKe0y0UYjwd4eTBK5+KtkfeOoPw5uTgnQu0Z
         f3F1G2RpfAyjPH4bnKq4N5FnjhHB8td8+eW/Lo09aBNKnRYpBp7DfzU+55fbHI2lRv3Y
         sdptM2ENoyXerrocXb05h4U4X/hAVQ+xdjY6mQoYOUhsm7oWvyuHvIY2pwxG2arh7BYg
         a0rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VaH0nAjv38F7wcUNXUY6R+pPhb94jTIKfgVe1zCE0Y8=;
        fh=J1Qt2dYQZwHfoASHEf8Q1j6KnDtpzzpCUlDsDM7WT0M=;
        b=PqZiTKgRqY32w2zGdAElBnqf9ihX7cWs4WWClRlsqtLs6S/AoFYNWHO2218lzO/LM6
         UA+RYOFnCrjmUGQiRXcWeFxgFhP7/7ZHnNqP5PCRUr/kC/AhvSC8gM3ZLs0V4bZy8GZG
         +/71WxOoqk+cO3eHgU/rE03A1OeSm7RM8DdbpCVZfPykaUd+sxZfcqiA0UKiiaGzzQzt
         Wpli/Y8EFlRV87sE7DEbduM5KnRHt4WyQYhny3ISKco40AQ1W75j4DUa0/NDD9PIWolb
         se6zFSEjS2KmXfngqbgU4MKyxUdJ7RwZge4XVclUbN+LjgHlClC3/bAlnEyRcRH8QkdM
         /2KA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=W3s6IJQi;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::f2 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-242.mta1.migadu.com (out-242.mta1.migadu.com. [2001:41d0:203:375::f2])
        by gmr-mx.google.com with ESMTPS id p4-20020a05600c1d8400b003fee787cc43si1023873wms.1.2023.08.29.10.12.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Aug 2023 10:12:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::f2 as permitted sender) client-ip=2001:41d0:203:375::f2;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 11/15] stackdepot: use read/write lock
Date: Tue, 29 Aug 2023 19:11:21 +0200
Message-Id: <6db160185d3bd9b3312da4ccc073adcdac58709e.1693328501.git.andreyknvl@google.com>
In-Reply-To: <cover.1693328501.git.andreyknvl@google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=W3s6IJQi;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::f2 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
 lib/stackdepot.c | 76 ++++++++++++++++++++++--------------------------
 1 file changed, 35 insertions(+), 41 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 9011f4adcf20..5ad454367379 100644
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
@@ -92,15 +93,15 @@ static void *new_pool;
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
@@ -248,12 +249,7 @@ static void depot_init_pool(void *pool)
 
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
@@ -262,10 +258,8 @@ static void depot_keep_new_pool(void **prealloc)
 	/*
 	 * If a new pool is already saved or the maximum number of
 	 * pools is reached, do not use the preallocated memory.
-	 * READ_ONCE is only used to mark the variable as atomic,
-	 * there are no concurrent writes.
 	 */
-	if (!READ_ONCE(new_pool_required))
+	if (!new_pool_required)
 		return;
 
 	/*
@@ -281,9 +275,8 @@ static void depot_keep_new_pool(void **prealloc)
 	 * At this point, either a new pool is kept or the maximum
 	 * number of pools is reached. In either case, take note that
 	 * keeping another pool is not required.
-	 * smp_store_release pairs with smp_load_acquire in stack_depot_save.
 	 */
-	smp_store_release(&new_pool_required, 0);
+	new_pool_required = false;
 }
 
 /* Updates refences to the current and the next stack depot pools. */
@@ -300,7 +293,7 @@ static bool depot_update_pools(void **prealloc)
 
 		/* Take note that we might need a new new_pool. */
 		if (pools_num < DEPOT_MAX_POOLS)
-			smp_store_release(&new_pool_required, 1);
+			new_pool_required = true;
 
 		/* Try keeping the preallocated memory for new_pool. */
 		goto out_keep_prealloc;
@@ -369,18 +362,13 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
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
+	if (parts.pool_index > pools_num) {
 		WARN(1, "pool index %d out of bounds (%d) for stack id %08x\n",
-			parts.pool_index, pools_num_cached, handle);
+			parts.pool_index, pools_num, handle);
 		return NULL;
 	}
 
@@ -439,6 +427,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	depot_stack_handle_t handle = 0;
 	struct page *page = NULL;
 	void *prealloc = NULL;
+	bool need_alloc = false;
 	unsigned long flags;
 	u32 hash;
 
@@ -458,22 +447,26 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
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
-	 * smp_load_acquire pairs with smp_store_release
-	 * in depot_update_pools and depot_keep_new_pool.
+	 * Allocate memory for a new pool if required now:
+	 * we won't be able to do that under the lock.
 	 */
-	if (unlikely(can_alloc && smp_load_acquire(&new_pool_required))) {
+	if (unlikely(can_alloc && need_alloc)) {
 		/*
 		 * Zero out zone modifiers, as we don't have specific zone
 		 * requirements. Keep the flags related to allocation in atomic
@@ -487,7 +480,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 			prealloc = page_address(page);
 	}
 
-	raw_spin_lock_irqsave(&pool_lock, flags);
+	write_lock_irqsave(&pool_rwlock, flags);
 
 	found = find_stack(*bucket, entries, nr_entries, hash);
 	if (!found) {
@@ -496,11 +489,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 
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
@@ -511,7 +500,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		depot_keep_new_pool(&prealloc);
 	}
 
-	raw_spin_unlock_irqrestore(&pool_lock, flags);
+	write_unlock_irqrestore(&pool_rwlock, flags);
 exit:
 	if (prealloc) {
 		/* Stack depot didn't use this memory, free it. */
@@ -535,6 +524,7 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 			       unsigned long **entries)
 {
 	struct stack_record *stack;
+	unsigned long flags;
 
 	*entries = NULL;
 	/*
@@ -546,8 +536,12 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6db160185d3bd9b3312da4ccc073adcdac58709e.1693328501.git.andreyknvl%40google.com.
