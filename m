Return-Path: <kasan-dev+bncBAABB5NX52VAMGQEVJHBMHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id D0C9B7F1B6E
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:48:38 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-50aaa963ebfsf1753967e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:48:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502518; cv=pass;
        d=google.com; s=arc-20160816;
        b=E9tIMVLH2ZuN9EwPo5RXx8YvwBs1PNw/zztZ19tJz/UvvhISc5O/TAjril116JH1EB
         9Jus2mRwOnZiBMc+iubeRlaf4tNwS6kjwe+u+rVw7xR6GDEuiIpQ07wNVOtdje0OshIR
         jjIt55qi7hajaONMd8AAN6GpdnCpNfPe5dcfJUs5nx9GR+ozasNuS4Dk2B9odKmaByYL
         KwN5cy2qXqMi9LNDSXlHlniT2WDXWCbTec/XqmnB8aUnCvj2ZZDhM6wpipNEH+NCm5Ge
         3OAFdKkiT6cR2TwqOz9PtUjuYyHv2QDNegEHZGx6xRcTHTSbXIZ7jc6EVM64RdDxklWT
         81iQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/86zk/Pb8srcqPgCl6T7g3I/SPGTgYmVvCyiqwpLu2I=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=0W1QPEyIGSauVRM+yBNjchTJzs7OqTiMTUJmC9u+6qF4bd+hCbU10hzvVz/3DhWR7W
         0yaRoLe6QJtAEKkimyt+ENrArW/SHnTMkl8Ys8oobHICFAVnU1jtD/GblQKVSwpngXGo
         vZDZS4wQRsNdTKLewIiK3+Y55wYCpFHmF4vZZl7YlQLvRIzDyR4GatoCQFJ8yvsvZj/X
         mDGs09Z9a8xfsvQWPnYcsPdGZkR9a51pUtDWRLyOeQju50bHHCdTqw3oux5FCeXVkOuF
         FTr4bzF7pDqCcBd0S9HYP0PrjF4nKrk2+gvfQDeN6IKp4SJE9koUZNHHMXjoGUhuPzwr
         DzHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="RxqnWJ/W";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::aa as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502518; x=1701107318; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/86zk/Pb8srcqPgCl6T7g3I/SPGTgYmVvCyiqwpLu2I=;
        b=wVo6F2FRQ/Yf9Dud/zMNF7Yg2Xeje0awet6F0nJ1aAIAxhzMrqiy8fBTuIdPgAvI4L
         MoM88RkXOpNXXyaMXvdEwTIwReeM7S8ColT1EClMw+bLAorDzvv4SMUcVStot1yyDgtE
         WB4cqqhvyJVPAL5gGhCYx9fhepPIicw5l4RGxr1yHEPIFMN5FkcvINbkBjYeqMYG4+1f
         vZ8X/Y4L9VJ0OdMyJWyWprmmNdEtRPOT2qBPXihLsj436ySTF3k3vGNhXuReOLjk6yVd
         aLk/Hj40BlBpUZnKOB0gtDEIARQ0LdWTfPG8YIR2GbnGLbw1y5kxfttm5fmB49sGpPIP
         dIhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502518; x=1701107318;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/86zk/Pb8srcqPgCl6T7g3I/SPGTgYmVvCyiqwpLu2I=;
        b=A4KjpXx8PV5qzDutPxfBUE5L1crfnkvnb9eE97PIpVd9QMfncKqgDtZEAIuG7uXzI+
         XGCPYqRXPXHD4p2mBBkKPRC0toqX/jK2/e7VpDyc3E8aY4/Kw5ejiAyweL8FxzQBTQ2z
         s+Tw35dfH4uGsN0sNI2uC1i+EvXQF6kc7xmx3dejVqboIVnXerIhqiMwJm+yPlnouM73
         7AKbs7Vm2gpdks4ROLT01vL4Xg8NwA2LhpxfjwFC9db7HyQuzjh6jC2z67y9R9GL6JPN
         cXbRIOwPI4kXUcxRPVBumrwGCmRsI+sTazI5CGbLU7Cr+yM2zTwMHi6rIyuumrNQ349C
         DmpQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxOjfn0F2BdGXPjwm1ABwmE+2pitKj/2DLVDJTGHsfIv7AiY5S/
	voXWuyb02iwPp2hbUi5E+HM=
X-Google-Smtp-Source: AGHT+IGzrL6Gp3P/NZgWlX/65/tRFYp0HpPDlr0V8LdLw8WMi9dYJIpJONf2biYRzGhpEWntXzvX/Q==
X-Received: by 2002:a05:6512:312c:b0:509:44aa:8104 with SMTP id p12-20020a056512312c00b0050944aa8104mr5532004lfd.37.1700502517825;
        Mon, 20 Nov 2023 09:48:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b16:b0:509:908b:912f with SMTP id
 w22-20020a0565120b1600b00509908b912fls97486lfu.2.-pod-prod-05-eu; Mon, 20 Nov
 2023 09:48:36 -0800 (PST)
X-Received: by 2002:ac2:5149:0:b0:509:8f57:8e2 with SMTP id q9-20020ac25149000000b005098f5708e2mr5932866lfd.29.1700502516073;
        Mon, 20 Nov 2023 09:48:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502516; cv=none;
        d=google.com; s=arc-20160816;
        b=mWr7WbimLzLwhdMH1vcuq2etPme+JzYWDGEK2qr7e6BUPDIMb2ez+pZQ2lyodNzBg9
         yfOVHspjWiAtCfj2lOq4HvZqXU3Sad2kCcNYvbMaB8tRwMD15wtxSe2VzpWmkQdww6cf
         F2+FYSayojdRYsYKJyaTFLoj7aqYWGCMQHXwCrpx2TjOp3KDMIYTf0aLcEIoiX4am9Hq
         8jSlDDPr1D4bf5vd8StZwEeh+8WWIyzL9CxgUncLsLl5yWl1d5avo1Amk6eogFu0mAI7
         g6B2dyz29dx1LFUfi9JX+uxm1pbtcF54OYMfCBIKRJVZmlVP3XudU3t4M1tfRVl6mz6/
         eXGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+N1Q7uFgicZ/Pf0RFILDijpppowVMY0ExiNLLtkdgaQ=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=QtojvuWXhMN9PEdmgb7i5+DLOOAtX/ZittnGXpNncd/2P6mPWknozKYEb4ClXI8Mu5
         pjUUducuyUShSGg6OJQ7ynBAVwJqgFTGLh3GeIsdAPx5rXQ/Bitz1hVDnWMO5pa4Q7Kb
         /gkmnxg4MBvUFZSO/OX49Y20CRnRFZO7r24+YCDwOARGOs1eD423OXc1+jqNm/8+cFKK
         S/QVK0iIxez+KlHRGe0DMxeZLjF0twK1smeySnHwaWCswi6wi+kwiEpHLC+Z/DWy5i5R
         q+4h1D15xODwmdjaJ6WGU1IdaoQpfBGqEcCN/KzcZhY3HHFGyREdddENj9Ma8nrZ7ZHo
         6LVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="RxqnWJ/W";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::aa as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-170.mta0.migadu.com (out-170.mta0.migadu.com. [2001:41d0:1004:224b::aa])
        by gmr-mx.google.com with ESMTPS id t2-20020a056402240200b0053ea9bd0510si316016eda.0.2023.11.20.09.48.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:48:36 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::aa as permitted sender) client-ip=2001:41d0:1004:224b::aa;
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
Subject: [PATCH v4 11/22] lib/stackdepot: store free stack records in a freelist
Date: Mon, 20 Nov 2023 18:47:09 +0100
Message-Id: <b9e4c79955c2121b69301778643b203d3fb09ccc.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="RxqnWJ/W";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::aa as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Instead of using the global pool_offset variable to find a free slot
when storing a new stack record, mainlain a freelist of free slots
within the allocated stack pools.

A global next_stack variable is used as the head of the freelist, and
the next field in the stack_record struct is reused as freelist link
(when the record is not in the freelist, this field is used as a link
in the hash table).

This is preparatory patch for implementing the eviction of stack records
from the stack depot.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Add parentheses when referring to function calls in comments.

Changes v1->v2:
- Fix out-of-bounds when initializing a pool.
---
 lib/stackdepot.c | 131 +++++++++++++++++++++++++++++------------------
 1 file changed, 82 insertions(+), 49 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 68c1ac9aa916..a5eff165c0d5 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -54,8 +54,8 @@ union handle_parts {
 };
 
 struct stack_record {
-	struct stack_record *next;	/* Link in the hash table */
-	u32 hash;			/* Hash in the hash table */
+	struct stack_record *next;	/* Link in hash table or freelist */
+	u32 hash;			/* Hash in hash table */
 	u32 size;			/* Number of stored frames */
 	union handle_parts handle;
 	unsigned long entries[CONFIG_STACKDEPOT_MAX_FRAMES];	/* Frames */
@@ -87,10 +87,10 @@ static unsigned int stack_hash_mask;
 static void *stack_pools[DEPOT_MAX_POOLS];
 /* Newly allocated pool that is not yet added to stack_pools. */
 static void *new_pool;
-/* Currently used pool in stack_pools. */
-static int pool_index;
-/* Offset to the unused space in the currently used pool. */
-static size_t pool_offset;
+/* Number of pools in stack_pools. */
+static int pools_num;
+/* Next stack in the freelist of stack records within stack_pools. */
+static struct stack_record *next_stack;
 /* Lock that protects the variables above. */
 static DEFINE_RAW_SPINLOCK(pool_lock);
 /*
@@ -226,6 +226,42 @@ int stack_depot_init(void)
 }
 EXPORT_SYMBOL_GPL(stack_depot_init);
 
+/* Initializes a stack depol pool. */
+static void depot_init_pool(void *pool)
+{
+	const int records_in_pool = DEPOT_POOL_SIZE / DEPOT_STACK_RECORD_SIZE;
+	int i, offset;
+
+	/* Initialize handles and link stack records to each other. */
+	for (i = 0, offset = 0;
+	     offset <= DEPOT_POOL_SIZE - DEPOT_STACK_RECORD_SIZE;
+	     i++, offset += DEPOT_STACK_RECORD_SIZE) {
+		struct stack_record *stack = pool + offset;
+
+		stack->handle.pool_index = pools_num;
+		stack->handle.offset = offset >> DEPOT_STACK_ALIGN;
+		stack->handle.extra = 0;
+
+		if (i < records_in_pool - 1)
+			stack->next = (void *)stack + DEPOT_STACK_RECORD_SIZE;
+		else
+			stack->next = NULL;
+	}
+
+	/* Link stack records into the freelist. */
+	WARN_ON(next_stack);
+	next_stack = pool;
+
+	/* Save reference to the pool to be used by depot_fetch_stack(). */
+	stack_pools[pools_num] = pool;
+
+	/*
+	 * WRITE_ONCE() pairs with potential concurrent read in
+	 * depot_fetch_stack().
+	 */
+	WRITE_ONCE(pools_num, pools_num + 1);
+}
+
 /* Keeps the preallocated memory to be used for a new stack depot pool. */
 static void depot_keep_new_pool(void **prealloc)
 {
@@ -242,7 +278,7 @@ static void depot_keep_new_pool(void **prealloc)
 	 * Use the preallocated memory for the new pool
 	 * as long as we do not exceed the maximum number of pools.
 	 */
-	if (pool_index + 1 < DEPOT_MAX_POOLS) {
+	if (pools_num < DEPOT_MAX_POOLS) {
 		new_pool = *prealloc;
 		*prealloc = NULL;
 	}
@@ -258,45 +294,42 @@ static void depot_keep_new_pool(void **prealloc)
 }
 
 /* Updates references to the current and the next stack depot pools. */
-static bool depot_update_pools(size_t required_size, void **prealloc)
+static bool depot_update_pools(void **prealloc)
 {
-	/* Check if there is not enough space in the current pool. */
-	if (unlikely(pool_offset + required_size > DEPOT_POOL_SIZE)) {
-		/* Bail out if we reached the pool limit. */
-		if (unlikely(pool_index + 1 >= DEPOT_MAX_POOLS)) {
-			WARN_ONCE(1, "Stack depot reached limit capacity");
-			return false;
-		}
+	/* Check if we still have objects in the freelist. */
+	if (next_stack)
+		goto out_keep_prealloc;
 
-		/*
-		 * Move on to the new pool.
-		 * WRITE_ONCE() pairs with potential concurrent read in
-		 * stack_depot_fetch().
-		 */
-		WRITE_ONCE(pool_index, pool_index + 1);
-		stack_pools[pool_index] = new_pool;
+	/* Check if we have a new pool saved and use it. */
+	if (new_pool) {
+		depot_init_pool(new_pool);
 		new_pool = NULL;
-		pool_offset = 0;
 
-		/*
-		 * If the maximum number of pools is not reached, take note
-		 * that yet another new pool needs to be allocated.
-		 * smp_store_release() pairs with smp_load_acquire() in
-		 * stack_depot_save().
-		 */
-		if (pool_index + 1 < DEPOT_MAX_POOLS)
+		/* Take note that we might need a new new_pool. */
+		if (pools_num < DEPOT_MAX_POOLS)
 			smp_store_release(&new_pool_required, 1);
+
+		/* Try keeping the preallocated memory for new_pool. */
+		goto out_keep_prealloc;
+	}
+
+	/* Bail out if we reached the pool limit. */
+	if (unlikely(pools_num >= DEPOT_MAX_POOLS)) {
+		WARN_ONCE(1, "Stack depot reached limit capacity");
+		return false;
 	}
 
-	/* Check if the current pool is not yet allocated. */
-	if (*prealloc && stack_pools[pool_index] == NULL) {
-		/* Use the preallocated memory for the current pool. */
-		stack_pools[pool_index] = *prealloc;
+	/* Check if we have preallocated memory and use it. */
+	if (*prealloc) {
+		depot_init_pool(*prealloc);
 		*prealloc = NULL;
 		return true;
 	}
 
-	/* Otherwise, try using the preallocated memory for a new pool. */
+	return false;
+
+out_keep_prealloc:
+	/* Keep the preallocated memory for a new pool if required. */
 	if (*prealloc)
 		depot_keep_new_pool(prealloc);
 	return true;
@@ -307,35 +340,35 @@ static struct stack_record *
 depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 {
 	struct stack_record *stack;
-	size_t required_size = DEPOT_STACK_RECORD_SIZE;
 
 	/* Update current and new pools if required and possible. */
-	if (!depot_update_pools(required_size, prealloc))
+	if (!depot_update_pools(prealloc))
 		return NULL;
 
-	/* Check if we have a pool to save the stack trace. */
-	if (stack_pools[pool_index] == NULL)
+	/* Check if we have a stack record to save the stack trace. */
+	stack = next_stack;
+	if (!stack)
 		return NULL;
 
+	/* Advance the freelist. */
+	next_stack = stack->next;
+
 	/* Limit number of saved frames to CONFIG_STACKDEPOT_MAX_FRAMES. */
 	if (size > CONFIG_STACKDEPOT_MAX_FRAMES)
 		size = CONFIG_STACKDEPOT_MAX_FRAMES;
 
 	/* Save the stack trace. */
-	stack = stack_pools[pool_index] + pool_offset;
+	stack->next = NULL;
 	stack->hash = hash;
 	stack->size = size;
-	stack->handle.pool_index = pool_index;
-	stack->handle.offset = pool_offset >> DEPOT_STACK_ALIGN;
-	stack->handle.extra = 0;
+	/* stack->handle is already filled in by depot_init_pool(). */
 	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
-	pool_offset += required_size;
 
 	/*
 	 * Let KMSAN know the stored stack record is initialized. This shall
 	 * prevent false positive reports if instrumented code accesses it.
 	 */
-	kmsan_unpoison_memory(stack, required_size);
+	kmsan_unpoison_memory(stack, DEPOT_STACK_RECORD_SIZE);
 
 	return stack;
 }
@@ -345,16 +378,16 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 	union handle_parts parts = { .handle = handle };
 	/*
 	 * READ_ONCE() pairs with potential concurrent write in
-	 * depot_update_pools().
+	 * depot_init_pool().
 	 */
-	int pool_index_cached = READ_ONCE(pool_index);
+	int pools_num_cached = READ_ONCE(pools_num);
 	void *pool;
 	size_t offset = parts.offset << DEPOT_STACK_ALIGN;
 	struct stack_record *stack;
 
-	if (parts.pool_index > pool_index_cached) {
+	if (parts.pool_index > pools_num_cached) {
 		WARN(1, "pool index %d out of bounds (%d) for stack id %08x\n",
-		     parts.pool_index, pool_index_cached, handle);
+		     parts.pool_index, pools_num_cached, handle);
 		return NULL;
 	}
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b9e4c79955c2121b69301778643b203d3fb09ccc.1700502145.git.andreyknvl%40google.com.
