Return-Path: <kasan-dev+bncBAABB45X52VAMGQE52Q5K6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 70BB87F1B6A
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:48:36 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-32fabf96aa5sf1054125f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:48:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502516; cv=pass;
        d=google.com; s=arc-20160816;
        b=GfyOWtpHFQOccHd7NMJNoOgq4X/gaUe44DnDWxiTkHCeUc7vAWi9vAzf//vuwVsu4T
         60jvsDR+3ysqMdPifAQKwojrEKT203RzGlh5K+G1AaF18UfzSp9crgk5O9WvbUUPZOEf
         3l6A7wV7w8tYEjQ5yep2sUxza/MmL4R656VKpOu913Ugv20CT04Rd3tSc/+JdeZTI8EF
         1Uzf60k6FO+IwaCpZFW25y1+UL5fSRR4gw+UXIOhmeI1lOGF2iC/QFp54G95RdhKIRrM
         MQ1IvzmcrasBHSbB+LVjBAv7pGVEx6DZPoAUMVgw1YLL3dbD1ZEG/MNKVBgGu9awhY7P
         kEBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tkedR655QyCzdwQ71kxLBjU+6N9gEkt4ZygiIsSFXO0=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=WDkhLqMrwaGB3DT5jRHpWLRRHkfbNvj0onJleJH18utntln+HgH945VE75eJ1amRgB
         fjJffv8UCE/7Dxn5VfYoDkBVwUZbwRTrhLtrK+bgdh8H5MhbGAnPcgq2Z0HYcGPp+x0F
         c73611ZldCFjcxBppvH0v+4ThcguGLfrTcAu5VnF1+d5elSBqRdLafJDXnbFtx8wKFlt
         663JAqJ8sR0eSiAHz1dt4dvBMGu9O3H2BBzakj50B3kCM9HQr2d6Lsvy94W6gHa2Gk0d
         3dN8MYqKwWr3ZhzBI5MzHE3x5oL+b90Qa0/gnlrvvV7CQA6CY99tG4bHUYapNkpgvFMy
         jZYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Kt5p6zSc;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502516; x=1701107316; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tkedR655QyCzdwQ71kxLBjU+6N9gEkt4ZygiIsSFXO0=;
        b=IVf5C2hEIzzBQyQIJG2JyonydGwUqxRqLMZ8FgS4Om2ixj1qJfmAA6Xub7mjRU78my
         RwkVUOo0QNzW/7q8MdY0qR4hwn/ZC4CrGxhPdcLIw3cLiXPwrBjCsE6ZSwokzjT8+c8i
         l7jsZDbrZAgG+cT1UZKya96fxnc2bnhyvS3innkSDNsej6GNVkyzVZf+Rq6H3vm/V5dm
         Isf+KwMyks0i9XnAYmmwEHE8LYUsF21Lo6ADze94+vAXr9mgzXQwVXZ0alz7mdLdsEHr
         0YkNncA/bXWnjYDWFsc7Xk+AWQ7BH+5xkilfbLl9M3nmv1gLFgnsdNTonkmTP2Fla6pC
         x+3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502516; x=1701107316;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tkedR655QyCzdwQ71kxLBjU+6N9gEkt4ZygiIsSFXO0=;
        b=iBwvCs24H/0z97mPgilMl7+6QbMfb6Y9kdi7QD/kR8+EDSJ4sJvpc6GllsH1ATFx6K
         MQ2yQLtcSxcPqrk7DiFKaXLwu8LaujDbnsc6cL7pZCI7oExoioEr4emt5/SIEjNRnlGa
         gNdeVeYfwVxQ1L9Dp6Ifjc15LXKOV012HqOZYhsK2wpMhv+CcY3grW1iel7D4dZx0TqC
         nhWQiEiWNThVSJEYaivG/bVflG0FQguLhCUuGDaj20TTGxNcTC/ZjEy5HeMdHnIwOb63
         uWnedahmMj4iYppdIcKuGpqcAZ4tociJIr9Vqvyzx1nTjqBRrnuIfC/Bbs4YteRPlPb2
         nJyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyIyGrbUjEXyw40qaN9NmChDjM1cMftsXvug48axr0/df14+WPb
	2v3WBlOwQX4CkpNcpWzMoNs=
X-Google-Smtp-Source: AGHT+IHdRbZDrof9xt6JcGkjlpn5U8YteCOpJSOthYufHrH9Ndlr9tqWjGIf0GZezzhlrgABSZhoqA==
X-Received: by 2002:a5d:4412:0:b0:32f:60df:f5e0 with SMTP id z18-20020a5d4412000000b0032f60dff5e0mr5427009wrq.4.1700502515683;
        Mon, 20 Nov 2023 09:48:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:234:b0:323:30c1:307b with SMTP id
 l20-20020a056000023400b0032330c1307bls1487980wrz.1.-pod-prod-08-eu; Mon, 20
 Nov 2023 09:48:34 -0800 (PST)
X-Received: by 2002:a5d:5987:0:b0:332:c723:127b with SMTP id n7-20020a5d5987000000b00332c723127bmr2576192wri.50.1700502514180;
        Mon, 20 Nov 2023 09:48:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502514; cv=none;
        d=google.com; s=arc-20160816;
        b=GmRRfa6SLAqwYUrY3UsLe6WSVhK59ebHhDp9GmELLux9Z+PvM00gAI8XJcDQSmORT7
         B//omwPECG6Or0YWyzGKme/K/QDro2DlyRrFe7isSKWcv6frWDI4BQ7BSSELT/lr4ncs
         PzfWzkOSxvlDy2owZdyhp0l2KTHEGv7iNXa/ERLgOGmRud4r8S5qVVbU8lCFzeBnZTXJ
         yyhYqfkQ8bP1N0rjnIGAuUlTGA24nEgd05M0zjEcxwmKzgpRg1ZZshjAtFlOd7UCOc5t
         h0acsnmwcKoqZqp5JwXMIh7TAQ3/bFP4CAnzGZp1SOHppiswu8IYKkSuIW7yQe0U3qT5
         x3PA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9IYHxZGEq/qB2Qlddv235LQK4ccHh5XyxORYKM2z5Wc=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=JUr5crsX1ONuemiGBtsPM6Xze21FcGvicZehiWfWiA1XVBy1jCJGp08W1sRYIFf4rY
         MTwTHzow+13t7egi8c+2xGeeA32mefiliAZ7DG4M2qaTc2hzqK9n9IfKpWNWKJxlRG1d
         O4OvLD0IWWVs2zNSOA6WWcwSETYmbphgzPTP9F2P1ocR/BaRovn7qL6B0nGcJ21WJ45O
         EOTuZxOIVEP906Ri9SqMeWqog8aqDWY7mkuYQEq/lYoaXExF9g97OU49UedhCoeH1e6y
         2dUxlhsh++thliQOdikLeDccKtHWtDXNvUhFLAhbsR5zHYa8MPFrtzeD7BVQqE+J/kpK
         WADw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Kt5p6zSc;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-185.mta0.migadu.com (out-185.mta0.migadu.com. [2001:41d0:1004:224b::b9])
        by gmr-mx.google.com with ESMTPS id p2-20020a5d68c2000000b00332cc5c485csi30050wrw.3.2023.11.20.09.48.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:48:34 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b9 as permitted sender) client-ip=2001:41d0:1004:224b::b9;
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
Subject: [PATCH v4 08/22] lib/stackdepot: rework helpers for depot_alloc_stack
Date: Mon, 20 Nov 2023 18:47:06 +0100
Message-Id: <71fb144d42b701fcb46708d7f4be6801a4a8270e.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Kt5p6zSc;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::b9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Split code in depot_alloc_stack and depot_init_pool into 3 functions:

1. depot_keep_next_pool that keeps preallocated memory for the next pool
   if required.

2. depot_update_pools that moves on to the next pool if there's no space
   left in the current pool, uses preallocated memory for the new current
   pool if required, and calls depot_keep_next_pool otherwise.

3. depot_alloc_stack that calls depot_update_pools and then allocates
   a stack record as before.

This makes it somewhat easier to follow the logic of depot_alloc_stack
and also serves as a preparation for implementing the eviction of stack
records from the stack depot.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Add parentheses when referring to function calls in comments.
---
 lib/stackdepot.c | 86 +++++++++++++++++++++++++++---------------------
 1 file changed, 49 insertions(+), 37 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index cfa3c6c7cc2e..b3af868627f4 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -225,11 +225,11 @@ int stack_depot_init(void)
 }
 EXPORT_SYMBOL_GPL(stack_depot_init);
 
-/* Uses preallocated memory to initialize a new stack depot pool. */
-static void depot_init_pool(void **prealloc)
+/* Keeps the preallocated memory to be used for the next stack depot pool. */
+static void depot_keep_next_pool(void **prealloc)
 {
 	/*
-	 * If the next pool is already initialized or the maximum number of
+	 * If the next pool is already saved or the maximum number of
 	 * pools is reached, do not use the preallocated memory.
 	 * Access next_pool_required non-atomically, as there are no concurrent
 	 * write accesses to this variable.
@@ -237,44 +237,34 @@ static void depot_init_pool(void **prealloc)
 	if (!next_pool_required)
 		return;
 
-	/* Check if the current pool is not yet allocated. */
-	if (stack_pools[pool_index] == NULL) {
-		/* Use the preallocated memory for the current pool. */
-		stack_pools[pool_index] = *prealloc;
+	/*
+	 * Use the preallocated memory for the next pool
+	 * as long as we do not exceed the maximum number of pools.
+	 */
+	if (pool_index + 1 < DEPOT_MAX_POOLS) {
+		stack_pools[pool_index + 1] = *prealloc;
 		*prealloc = NULL;
-	} else {
-		/*
-		 * Otherwise, use the preallocated memory for the next pool
-		 * as long as we do not exceed the maximum number of pools.
-		 */
-		if (pool_index + 1 < DEPOT_MAX_POOLS) {
-			stack_pools[pool_index + 1] = *prealloc;
-			*prealloc = NULL;
-		}
-		/*
-		 * At this point, either the next pool is initialized or the
-		 * maximum number of pools is reached. In either case, take
-		 * note that initializing another pool is not required.
-		 * smp_store_release() pairs with smp_load_acquire() in
-		 * stack_depot_save().
-		 */
-		smp_store_release(&next_pool_required, 0);
 	}
+
+	/*
+	 * At this point, either the next pool is kept or the maximum
+	 * number of pools is reached. In either case, take note that
+	 * keeping another pool is not required.
+	 * smp_store_release() pairs with smp_load_acquire() in
+	 * stack_depot_save().
+	 */
+	smp_store_release(&next_pool_required, 0);
 }
 
-/* Allocates a new stack in a stack depot pool. */
-static struct stack_record *
-depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
+/* Updates references to the current and the next stack depot pools. */
+static bool depot_update_pools(size_t required_size, void **prealloc)
 {
-	struct stack_record *stack;
-	size_t required_size = DEPOT_STACK_RECORD_SIZE;
-
 	/* Check if there is not enough space in the current pool. */
 	if (unlikely(pool_offset + required_size > DEPOT_POOL_SIZE)) {
 		/* Bail out if we reached the pool limit. */
 		if (unlikely(pool_index + 1 >= DEPOT_MAX_POOLS)) {
 			WARN_ONCE(1, "Stack depot reached limit capacity");
-			return NULL;
+			return false;
 		}
 
 		/*
@@ -284,9 +274,10 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 		 */
 		WRITE_ONCE(pool_index, pool_index + 1);
 		pool_offset = 0;
+
 		/*
 		 * If the maximum number of pools is not reached, take note
-		 * that the next pool needs to initialized.
+		 * that the next pool needs to be initialized.
 		 * smp_store_release() pairs with smp_load_acquire() in
 		 * stack_depot_save().
 		 */
@@ -294,9 +285,30 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 			smp_store_release(&next_pool_required, 1);
 	}
 
-	/* Assign the preallocated memory to a pool if required. */
+	/* Check if the current pool is not yet allocated. */
+	if (*prealloc && stack_pools[pool_index] == NULL) {
+		/* Use the preallocated memory for the current pool. */
+		stack_pools[pool_index] = *prealloc;
+		*prealloc = NULL;
+		return true;
+	}
+
+	/* Otherwise, try using the preallocated memory for the next pool. */
 	if (*prealloc)
-		depot_init_pool(prealloc);
+		depot_keep_next_pool(prealloc);
+	return true;
+}
+
+/* Allocates a new stack in a stack depot pool. */
+static struct stack_record *
+depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
+{
+	struct stack_record *stack;
+	size_t required_size = DEPOT_STACK_RECORD_SIZE;
+
+	/* Update current and next pools if required and possible. */
+	if (!depot_update_pools(required_size, prealloc))
+		return NULL;
 
 	/* Check if we have a pool to save the stack trace. */
 	if (stack_pools[pool_index] == NULL)
@@ -330,7 +342,7 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 	union handle_parts parts = { .handle = handle };
 	/*
 	 * READ_ONCE() pairs with potential concurrent write in
-	 * depot_alloc_stack().
+	 * depot_update_pools().
 	 */
 	int pool_index_cached = READ_ONCE(pool_index);
 	void *pool;
@@ -430,7 +442,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	 * the memory now - we won't be able to do that under the lock.
 	 *
 	 * smp_load_acquire() pairs with smp_store_release() in
-	 * depot_alloc_stack() and depot_init_pool().
+	 * depot_update_pools() and depot_keep_next_pool().
 	 */
 	if (unlikely(can_alloc && smp_load_acquire(&next_pool_required))) {
 		/*
@@ -467,7 +479,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		 * Stack depot already contains this stack trace, but let's
 		 * keep the preallocated memory for the future.
 		 */
-		depot_init_pool(&prealloc);
+		depot_keep_next_pool(&prealloc);
 	}
 
 	raw_spin_unlock_irqrestore(&pool_lock, flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/71fb144d42b701fcb46708d7f4be6801a4a8270e.1700502145.git.andreyknvl%40google.com.
