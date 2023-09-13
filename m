Return-Path: <kasan-dev+bncBAABBTW4Q6UAMGQEWXFZ2HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DFFB79F01B
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:16:00 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-502bd7b9274sf5735e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:16:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694625359; cv=pass;
        d=google.com; s=arc-20160816;
        b=CTZn9JotzgSpHog0rQ7a4fYv4HuXcRpLt4Z0df70c1VRnwuz2IzfAjakwYvJv2wg8K
         hPa1IxqA0q7ix3z6v54LH1NUkUCkTY5OPVwlh7vEyyIJ38PouF3PAjWc/FI5auYpPIr3
         OQA7qWBNmEq+YisXGDetIIe1K7/d6ZB2fRtNU+a7J7JZD+JrZ5Uv4F/GJUVnhZgq4kcw
         wQC63x8DQ1c9JkE0u3q82ckwsoii1LXklCwXxy1gdHoyRbPAwqp5Q4SCn64v/6ASTUFd
         QJ2ci1427/Fkv9HX1ID1DsyWryn3h2FFQXZ2tnndqhB/Bm56rKAEImKzpa+kkFHtX+Xt
         z8yA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=r8np9im0C9RT4EGNE8URaJcjXTlWeNwrLpModHH8Fgk=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=vaMAzjUlANDF2TL8fgX2CpYgScHfFU0jQ8AG/mYOMsPK7ByFRVkeHvnpjMLDOnA3yO
         x5BVCcXD2+6u0cZoiIKePOWiXylhyfUPK4GijfKqnrHCPJN60c5BlMO0taKF//VDonx0
         ZaTxagG73SBrKIiuyuePWIO5m6X4at64NTH14F6inp2yhzY+jJ4ZGzTnpmHN3VN4EYmA
         4JKkSkibUyrsd1jr2bQYsIM8vrDMXaSqgXk3SPUzm6sdWdLEuvh8tpUaVGm0Ryxwlbkm
         LRjLjgom0HwaN1LCl9jfD2OCBLXbJMGMvwJEFgeUn0DyAyKjiENo1c//HXeYwrNxUTJd
         iHAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=sHXeZyLg;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.229 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694625359; x=1695230159; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=r8np9im0C9RT4EGNE8URaJcjXTlWeNwrLpModHH8Fgk=;
        b=TITZ+s1pfY/A3Y6iWKQgGWAsqA0zIzjL9c63VCJ2U/ZNfw7YeOH2mnD+c6cUFCIWVE
         BA0RVQokx4AfbNKyoDtic/nKQbHEPbR4q8M+FvG3W0PlfeeOACumpq7BM265JiJM2c09
         YX4efYO7br8Fhj/JD70ypyW3ZTA1yKybO0GWS3rfQ5BO0aDLRGUisXb1IQWXkEjZoSkD
         v/6XxcF7xiyVp3cOYTlPYDu5AE7FBJvB3bF5LkzVlGkHJ7Pug9MtDK7xbECXxLPU2bSc
         /K+clTlPbC+bcFyml/rVoZ6idy+WK+ROYXYsKaSDozCYoyOxu0VanJrtgaYhL6Khoi+2
         YHQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694625359; x=1695230159;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=r8np9im0C9RT4EGNE8URaJcjXTlWeNwrLpModHH8Fgk=;
        b=Wkowak0MxYfeoKgyjXwuGEKxa8SSHld9BcFHvtuPpIOdr7hG0K/AMWQRyDKAU27U63
         wHuaA4zQDpErnYzedxqzz8Lj4INudR90i9RQaklcxKv/KMnndPD/Wy4u5tszHyfsUi0x
         W3y6bh7cSKaAWFqZyMOivlwYntkehKQYUbzuMUwf9j0swG4Z3NLWFxGe46sEo6ZX6aBI
         4HCFu7kbg7m/oV8pBJerAlhMI9I1fNr9KM/bEJSqVvvrYrJzAeRhqnLVun3PX2VUmsWQ
         qE4wpAZDcEUirSqv1zvwpnHR0X9sIIMwv1N7GhaVCbt34uEYmT5/Wt5g5L08yMHu7yqZ
         1odg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxmW+G2JK+q5H8FpaY1v3osgbd9wPtP/AxCEkkeaBn5OY1dUhoj
	Ki8HiwCBhTd1GCFR+NTeGrk=
X-Google-Smtp-Source: AGHT+IG5g50tqKTsW77tpsbUgWYM4fNqZ9ioOVtVBm96Lw2b9rx147+oGzV3BEOCowJ7A215nqXdoQ==
X-Received: by 2002:a05:6512:2fb:b0:500:99e8:573e with SMTP id m27-20020a05651202fb00b0050099e8573emr2362475lfq.7.1694625358755;
        Wed, 13 Sep 2023 10:15:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d610:0:b0:528:8932:bc6 with SMTP id c16-20020aa7d610000000b0052889320bc6ls438547edr.0.-pod-prod-01-eu;
 Wed, 13 Sep 2023 10:15:57 -0700 (PDT)
X-Received: by 2002:a17:906:cc4f:b0:9a9:ef7d:46b3 with SMTP id mm15-20020a170906cc4f00b009a9ef7d46b3mr2750350ejb.61.1694625357304;
        Wed, 13 Sep 2023 10:15:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694625357; cv=none;
        d=google.com; s=arc-20160816;
        b=aCsQsrgsmeWN6+VDEobGljEHlIDxmzPXJJvFlKzWXc2Z/Y19Lx5W6MDQbiA4N5m/7s
         NBW7vbFOKdFW6MmlymjRRtDgrQJvEuyWpQBNjBJGSNnGAvzwq3XAXLXQFVcMvRi6JNLl
         l+w/O1cKfIvR9zD7z5tk5SnZwPvjA4p65gWYA7+u0IKQQwVCr7hIajMaWfAikDTJn4EP
         zmb3KE6ujy0eBB7iVSm3Xgr6fuzhFD8N/jgb5RQeyshjD7NT32hvsacutwE8iOck5qbX
         RePdY1/9j1geVAWTU0bXWWekb2eeCuIoKJ6BtgVIYeN4QO5qkHsBBzkKsR1fZjz1EDss
         xfLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=toA317coTc48scxGmgrPy+Qu0+ZANZtHQIsZ7v5QrVU=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=0N7nLPsd/BlwznkJd7AJltKpjuPQsPb3hVtV/fY25XErrUoXE/pVXX3DOL3zhlRIyP
         V0a9wJ7CqAzY8OLvigu0gJmw9ZQlOpnjFlOuZHfF2YSFiNFZ4+ZfHbjGpyWxZ/g19x+u
         /u5qBpGpQNvXD+bAk1Ho7ksY7ZYZI9/R9VVK80ls0aBRfVAFga7mvJ6wh9lvKNXBLTKJ
         qYzpBWIWLCXMQKS2iZb0ENSs2PQZ5heBtdrC3b0anRD/n8L0/8OrahNGl/S2I+6992Ud
         RzTmQ/8mUcGmd2E+kt/nletiDHXvA0nTD3E0nPKpTPGYuEtpLgtjlpL2qSQSV9ztE+i6
         vH0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=sHXeZyLg;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.229 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-229.mta1.migadu.com (out-229.mta1.migadu.com. [95.215.58.229])
        by gmr-mx.google.com with ESMTPS id qf15-20020a1709077f0f00b009ad78f569ffsi486740ejc.0.2023.09.13.10.15.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Sep 2023 10:15:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.229 as permitted sender) client-ip=95.215.58.229;
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
Subject: [PATCH v2 10/19] lib/stackdepot: store free stack records in a freelist
Date: Wed, 13 Sep 2023 19:14:35 +0200
Message-Id: <b70a6d84c438ae20105ff608cd138aef5cf157e6.1694625260.git.andreyknvl@google.com>
In-Reply-To: <cover.1694625260.git.andreyknvl@google.com>
References: <cover.1694625260.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=sHXeZyLg;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.229 as
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

Instead of using the global pool_offset variable to find a free slot
when storing a new stack record, mainlain a freelist of free slots
within the allocated stack pools.

A global next_stack variable is used as the head of the freelist, and
the next field in the stack_record struct is reused as freelist link
(when the record is not in the freelist, this field is used as a link
in the hash table).

This is preparatory patch for implementing the eviction of stack records
from the stack depot.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Fix out-of-bounds when initializing a pool.
---
 lib/stackdepot.c | 131 +++++++++++++++++++++++++++++------------------
 1 file changed, 82 insertions(+), 49 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 81d8733cdbed..ca8e6fee0cb4 100644
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
@@ -220,6 +220,42 @@ int stack_depot_init(void)
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
+	/* Save reference to the pool to be used by depot_fetch_stack. */
+	stack_pools[pools_num] = pool;
+
+	/*
+	 * WRITE_ONCE pairs with potential concurrent read in
+	 * depot_fetch_stack.
+	 */
+	WRITE_ONCE(pools_num, pools_num + 1);
+}
+
 /* Keeps the preallocated memory to be used for a new stack depot pool. */
 static void depot_keep_new_pool(void **prealloc)
 {
@@ -234,7 +270,7 @@ static void depot_keep_new_pool(void **prealloc)
 	 * Use the preallocated memory for the new pool
 	 * as long as we do not exceed the maximum number of pools.
 	 */
-	if (pool_index + 1 < DEPOT_MAX_POOLS) {
+	if (pools_num < DEPOT_MAX_POOLS) {
 		new_pool = *prealloc;
 		*prealloc = NULL;
 	}
@@ -249,45 +285,42 @@ static void depot_keep_new_pool(void **prealloc)
 }
 
 /* Updates refences to the current and the next stack depot pools. */
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
-		 * WRITE_ONCE pairs with potential concurrent read in
-		 * stack_depot_fetch.
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
-		 * smp_store_release pairs with smp_load_acquire in
-		 * stack_depot_save.
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
@@ -298,35 +331,35 @@ static struct stack_record *
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
+	/* stack->handle is already filled in by depot_init_pool. */
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
@@ -336,16 +369,16 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 	union handle_parts parts = { .handle = handle };
 	/*
 	 * READ_ONCE pairs with potential concurrent write in
-	 * depot_update_pools.
+	 * depot_init_pool.
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b70a6d84c438ae20105ff608cd138aef5cf157e6.1694625260.git.andreyknvl%40google.com.
