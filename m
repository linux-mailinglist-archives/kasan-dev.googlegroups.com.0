Return-Path: <kasan-dev+bncBAABBJ543KUQMGQEH3JLWBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 049B67D3C52
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:24:08 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-53faa428644sf21307a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:24:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698078247; cv=pass;
        d=google.com; s=arc-20160816;
        b=L+cQoC2f8SD/ra8UQCHBGlqoVqdGrURokEdswBr8wKo4UG5VlFPIqTGCk/F9eTr6dp
         2MNxoZMRjkjYjYUDEcBOR6odaxKePS4DTc0r9Fu50nNkylUimEKpA1X7iWWnss6lSBSN
         kRwzV6lcbHqL7ojCeQepYp426OVgyjHleYR+aIkb5cm299muEN+zgaDEPPbZl9BeQDaf
         raXKbZ80MNKCnvpMvfk5WZwR3K7sx6VFELPc84cIU7fs9RoGV2Oz6OgbCyNQuEXXi2zs
         htyokYdqNJCx9W0iZqMJXsCZiFz7QEtvV1+jaholGRGBmzYq8EC5fQq+rYL1SKXpy0yO
         D0Tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=cVQD/vwZukWKd+pbFpnJM3WjdjhpvHjwv/ZQ/Jx+1tM=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=C4Rbozp6QfTWktgPiQd+u0CeS12KccX70gd+kHSETeuwZns2/ahKV3SMomZ849H1Kl
         drqszlgfdmANR7giMiYSsa+zK+gfKeElXCg8DEtsbUEXjR6H+bfmAySAdqqngj9LghKN
         B/L0A6MdUWAlVQWpoitUa/UzYNOKGJEWdg0M/dCGpFfanqNaDWTJ93DcOlk44BR4JeKo
         tfGLCRXlRvN9luI1vONPsXGx5+Md6xkPb9tfuYsZDjhO/IFRq0pcTSimr6h44agxEvFw
         I97fT5b56Q37zExXmaYFoLGnqzZJI/GvKS8DTgRN8nPVA16g8yMNRFuXauUz0RquQEXt
         kS+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iTY6JYsU;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::bf as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698078247; x=1698683047; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cVQD/vwZukWKd+pbFpnJM3WjdjhpvHjwv/ZQ/Jx+1tM=;
        b=utxq/Ah+V4hv2Uzq9kVsnlpVnu9ejCtO5fucUmEI/80hDXj6PQwgNYlCwusgWPd5p2
         TWOXy42tIe8X3jJaFbZR9KDCNc6uVjwOpIx1JBVOgnuJ4FxVaLq6Q6Hw1K6F3FEhMnEQ
         TC1u7LosppFTr7jqrouP9Dhzf8Iy0Uw8/PrFlS3sOWEB1FYBvSvXLoeu4YmQqjVGSQwM
         +Vl3RL9fQOV3nJdxJUX2eW6UyjJBC5rwhOxL2sWm0938ZXzaituAQnS3uScVFc3NQ38X
         F64+aQTl19fKuruJS/uyq/9+/GdZxWSjPpc0KYRBd56vO+0X3hFcajpflD9sKCBVZLk0
         88tA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698078247; x=1698683047;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cVQD/vwZukWKd+pbFpnJM3WjdjhpvHjwv/ZQ/Jx+1tM=;
        b=CrTF6izYRpkA/ju6dtQqYZIxwtH9oU+vmIzY9PaIBMpoq9evIwycHzNqZTB4Efh2wM
         HqGhFpX30+G4mZfRTf3r1r5Vy/78fij0r2KX6Jj3cwfn82+FfWhya8zQoeV6Xjvp6tGp
         naiuTeZ9RANBim8Fw7gjZlxzc2Is+HAUUs83ZKQDayoI7Cm/FLg16XU7f7I7YwxCC97k
         6iKBRRfx6MbM9SNhybEmb5Oeh/9lbVn7XvU617xxB2I7ehh9b6GKPiufwZZE6B6FP1tc
         e7HVvz3e1Vtcpn4Z5zJ2xkDdN8X8TAGPxkO/VOc+VQm0kcR7SlcUyRu7RnThWdB6XtG5
         cAEA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxcm1K0edWUSr/RTJIzTXzmf7aZMk3OuMZv9NhmtmoLhL5glT08
	1P1+wTgyLmmwzZWdPVWiyyU=
X-Google-Smtp-Source: AGHT+IE+nqixQB3UwjFVU4ghAEu9aIab+HqwI3SnLmlvtkRK4WQxMdREOrFfkQRAtv4418RQlQh0rA==
X-Received: by 2002:a50:ee0e:0:b0:53f:c3fa:5fa5 with SMTP id g14-20020a50ee0e000000b0053fc3fa5fa5mr339575eds.3.1698078247556;
        Mon, 23 Oct 2023 09:24:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:4015:b0:507:b8d5:d6cf with SMTP id
 br21-20020a056512401500b00507b8d5d6cfls101406lfb.1.-pod-prod-05-eu; Mon, 23
 Oct 2023 09:24:06 -0700 (PDT)
X-Received: by 2002:a19:2d46:0:b0:502:f2a8:d391 with SMTP id t6-20020a192d46000000b00502f2a8d391mr7584267lft.45.1698078245951;
        Mon, 23 Oct 2023 09:24:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698078245; cv=none;
        d=google.com; s=arc-20160816;
        b=vDqGif/VPvB28KXeuNmOFgBnUH04yaDuSPolkYGV9FkxZnYynCkvSBgRA1jcLtMVzy
         RBPqDnsvv4fJNa0N6L+ZgRHdRBHgaUxGTKWuRM4p8HGXzKy3YJT0MukWVrAetEhiL/23
         uqe6O0PAuAikfDbwQ82vmq9o7aMWpRcWilBOhqMaMCFrBzGKmI0k4bNzWkbW/AmGSAiu
         inQG5QLbZXq0ZkhAcb7Iz5iPSbgHK7TE5FxveOzMONyxRMUKOwC+VAZ3LiCLXGwx8+xO
         WEY/Q9sva/GS2ED1PGfCDrUb6pQtWP2yizjgRIaH8SBnJvxJ/WPs0dYNuJhrDMcvorcN
         /mqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hVpUL5x06hsk3ZkSjFGdljEHgMA5oAygtOmJMO9tzo8=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=ZJSmR81r4+hZbXPoL9ZhgY6aB+TuSOdTl/dv8OYPUAX8NJtJ7FASjlR2RfgJuvqGou
         W/qjmT1CPDFTiMGsDXg0uiFO6NXkYPiKLAk6j9Q8A/TKtS6jvPs32XwNi7sn7o+/jExe
         zAeS41jek6klaWgD5QUg6cVYtPIzTvNoJNflxRLp9zDPrCmbl8v6bgYvKH7pT+0BulmG
         F8Bm4mC43z45DV1ePnz6K1txThHlziryyvb85KwIe+tNNqV3LVmc/4fKtIV2GNRC/Grd
         241t7cILatPsWo9prVLGndOwx2fLzWuzrLzOlgDHpnUfsVClZ/FKpI36sQXNU0uNuXaW
         1ioA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iTY6JYsU;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::bf as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-191.mta1.migadu.com (out-191.mta1.migadu.com. [2001:41d0:203:375::bf])
        by gmr-mx.google.com with ESMTPS id b23-20020a170906d11700b009ae3e884341si292001ejz.0.2023.10.23.09.24.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Oct 2023 09:24:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::bf as permitted sender) client-ip=2001:41d0:203:375::bf;
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
Subject: [PATCH v3 10/19] lib/stackdepot: store free stack records in a freelist
Date: Mon, 23 Oct 2023 18:22:41 +0200
Message-Id: <0e798c0431646643ce077117933e8a79899a2403.1698077459.git.andreyknvl@google.com>
In-Reply-To: <cover.1698077459.git.andreyknvl@google.com>
References: <cover.1698077459.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=iTY6JYsU;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::bf as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
index 5315952f26ec..1067c072a0f8 100644
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
@@ -236,7 +272,7 @@ static void depot_keep_new_pool(void **prealloc)
 	 * Use the preallocated memory for the new pool
 	 * as long as we do not exceed the maximum number of pools.
 	 */
-	if (pool_index + 1 < DEPOT_MAX_POOLS) {
+	if (pools_num < DEPOT_MAX_POOLS) {
 		new_pool = *prealloc;
 		*prealloc = NULL;
 	}
@@ -252,45 +288,42 @@ static void depot_keep_new_pool(void **prealloc)
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
@@ -301,35 +334,35 @@ static struct stack_record *
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
@@ -339,16 +372,16 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0e798c0431646643ce077117933e8a79899a2403.1698077459.git.andreyknvl%40google.com.
