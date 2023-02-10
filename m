Return-Path: <kasan-dev+bncBAABBXHITKPQMGQEE2IB4FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id B40E469290F
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 22:17:17 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id k25-20020a2e2419000000b00291830c756esf1861385ljk.19
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 13:17:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676063837; cv=pass;
        d=google.com; s=arc-20160816;
        b=xlRUSMJVHc0/pxUN2hvYKAaGBtOHMxSeGNGNKsWBjP0C3sQRURQ/9t6WHHZESwpCBb
         +p7Qy973J5MWwoUAYwOZrE1GfhfEsBvr4K1+fxiUwTOsrEg2IhwGH3H5ZInl1+0JjuA6
         3AHhod/q7tS/ie1V1ej06VqU5sthzmhPdLc6dn6fLnmE9eW05gNuWT768CEdxT4GMz5I
         TUF0aUisE9P8viGSDEXz8AJWjIHRObUe7LZK1DgaH6Bi1DYY4hDb6a+4JcknwhZcMjW/
         VevFZDn7Zuv+PRRdvL3s8qkwED9cHB3w5KlYRqcmeGnYw9wINai2SV9hYNhNagc9eKfu
         dUPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=nQMxqk5lA7K6CKtoB8GEVMpsJX4RAmh9yHAeeLlJuhE=;
        b=xSoihX8bWyAbgHIw0GWYYF7c13709gfPguZ61+nzOU2gDwfUC/z5K7/s3AnsLyEHOm
         KnJXbj6QqHnGiANzzSobbILyv8DRFGynZ77zx6UXltuxnvE6XunikV5hNohhST18prbT
         Y0yYdj9CjHC7aloVA/NWwhq7Uxyz4kWgwHJsDqRGK3IZSVPtbIjbvz/T1u6qbgX8quwm
         ngcdwxKMwVTKTu4u6o5W0DnBLtb7rXhc3D6QVFVfRbfOdAbJrio2311xA89KPOD2Sc3u
         HGsn0v4TBIrR1qRvAeo6pyq45PH7A/2FLa1v+/H2sQH7BEtro7t8hlhVisbaWJBislgn
         FqTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=dPUdX3td;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.98 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nQMxqk5lA7K6CKtoB8GEVMpsJX4RAmh9yHAeeLlJuhE=;
        b=jwxOxlhL57BjKJGqsW+2n052EohghhqHTnxfxByaJ/pdQysKc4GsE1clEOredfMBTm
         GSBdCc8pKYxqrq71/0gZK1efpfvsDHAoBBYwrJuCKyvugWAsBgwFJOtHplMWoVCfA4Ir
         m6RAdlPieJXzXtV0QG6rtXNy9flYicmCpycMI5bucbs7YcV1yuTAmRsGkt+IdiNkSuHY
         9wfcHQ2V8vw88V9zNbd0IC6W0SuBS4KIa4Jd2YSz6UepXW5g77xlcvwxL1Su8NvuupKC
         Z0bVJUDUEBk/eBrFyFFpJ3am07enP2dbaVeg2uPHhPirQ/9Fvarhl7MsF3pakNKBExt7
         GbUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nQMxqk5lA7K6CKtoB8GEVMpsJX4RAmh9yHAeeLlJuhE=;
        b=CYa/EJ1nzYiF3ni3UjAKnThkpTQ4KlM8zNnYHLw9V5T4ILIzXVljg1yuWKZO7+Sy8u
         1pJKkkJ6kTmQ6eh3PyueYnBoNpC487XXPxE05zgnE0xw4h2pquY3bqykGlhOLRbifSNm
         2n/1y8voxdsGSsM/jiPbOC/UOXQa6be2aKYcqLy9ZEBwvUoh+Vz6Cz3DlBZktOIae/xo
         gynS9hXc2yF6+S0FSbn1blQqdd5Z5nhT7+JzQNWLixea8UYLuNepNqoUa1b8cLMxuqyu
         vRoVPv7Y8wNRcfbml/UKUfXnq9IE6jR5qdviVLD3Emt24rNA/R+2zVb02diWUjm6falo
         F6QA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVkgscVsF+pD6+MUaYFt+7QyUAB2Iuxu7AUul1MAW8/jAPrmuv5
	8GFIO/gTuWRNcweJjoERgg4=
X-Google-Smtp-Source: AK7set9YcHElc+DjxpdfUAmCqiCR51axf8EOnnPl6etGbeACmjntNUPsroMk2gs1CIjqF5Xz0Nkfig==
X-Received: by 2002:a2e:b0fc:0:b0:293:42e9:9536 with SMTP id h28-20020a2eb0fc000000b0029342e99536mr51901ljl.39.1676063837187;
        Fri, 10 Feb 2023 13:17:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9f42:0:b0:280:210:b2fc with SMTP id v2-20020a2e9f42000000b002800210b2fcls1114985ljk.4.-pod-prod-gmail;
 Fri, 10 Feb 2023 13:17:16 -0800 (PST)
X-Received: by 2002:a05:651c:551:b0:28d:b174:1f39 with SMTP id q17-20020a05651c055100b0028db1741f39mr6389473ljp.30.1676063836078;
        Fri, 10 Feb 2023 13:17:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676063836; cv=none;
        d=google.com; s=arc-20160816;
        b=a1xcb8HZDRO4EXph/m30Iar2pTyCl8HoA/RsEswWf+u5Wvc0UJDLRNipq4KAsz13PQ
         OPRqFWB4IPyhI4UPqw9VKRxdcEbD5Vg91xArdtidLw7O3ChZwdAoyo/YxLX+6Tbmh83s
         Vkcthhex59UXj2dYgqPPd+75JytelMOgV2ejiBe0tRge0jMDpx3LjOkFnWlUWuooucX0
         qZ9Kv1foARhglcLMkrRsGmDY7ivyEHozpfQoNOlCdbEy8zTdTai639FGZcZpcWMSVxaa
         BFfeBthRgiqklhCFLqbyFsdD95jFOSDZ61hIls3ImGDQyP0qfK1pD4SyHnm5sX9WaMHc
         P6yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=k1dYguidu/ftb/l9KscZ+n0HL8ER05ZmODhupOX0dXU=;
        b=QsC171D19tSGu8/hP7u9aCOIa8kkP4ovyfKxYVYxI7d0hVM/Aa2VJcdq26QV0DNnUL
         N8aoFMilLkuD4zj5+iHQj9gNR7y+7JkZkPJEmEiaBwJigDWWjZTJvxzevaR35JNRT5zt
         CkbX7j74Y1I7G6L7yCPtVjk4+DKEtnxvrL1caIhb0A0Bc7DGT7jfB4znoiNNJ7iAAeol
         mdwYd8TDS8B/ZjNz/QvZYGh2g+O+GGVuEOptROBW0d7TWrNYzkNnHpC045ip57Kyo94z
         p+4NEGRztnprTSlh6VGj+JWIDubJ83HFIFNWMRXR6SmqUMUXx+LReamTpWGE0dWAKicT
         cs7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=dPUdX3td;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.98 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-98.mta1.migadu.com (out-98.mta1.migadu.com. [95.215.58.98])
        by gmr-mx.google.com with ESMTPS id b14-20020a0565120b8e00b004cb0f0982f3si316529lfv.4.2023.02.10.13.17.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Feb 2023 13:17:16 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.98 as permitted sender) client-ip=95.215.58.98;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 09/18] lib/stackdepot: rename slab to pool
Date: Fri, 10 Feb 2023 22:15:57 +0100
Message-Id: <923c507edb350c3b6ef85860f36be489dfc0ad21.1676063693.git.andreyknvl@google.com>
In-Reply-To: <cover.1676063693.git.andreyknvl@google.com>
References: <cover.1676063693.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=dPUdX3td;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.98 as
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

Use "pool" instead of "slab" for naming memory regions stack depot
uses to store stack traces. Using "slab" is confusing, as stack depot
pools have nothing to do with the slab allocator.

Also give better names to pool-related global variables: change
"depot_" prefix to "pool_" to point out that these variables are
related to stack depot pools.

Also rename the slabindex (poolindex) field in handle_parts to pool_index
to align its name with the pool_index global variable.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Use "pool" instead of "slab" for memory regions that store stack traces.
---
 lib/stackdepot.c | 106 +++++++++++++++++++++++------------------------
 1 file changed, 53 insertions(+), 53 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index d1ab53197353..522e36cf449f 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -39,7 +39,7 @@
 #define DEPOT_STACK_BITS (sizeof(depot_stack_handle_t) * 8)
 
 #define STACK_ALLOC_NULL_PROTECTION_BITS 1
-#define STACK_ALLOC_ORDER 2 /* 'Slab' size order for stack depot, 4 pages */
+#define STACK_ALLOC_ORDER 2 /* Pool size order for stack depot, 4 pages */
 #define STACK_ALLOC_SIZE (1LL << (PAGE_SHIFT + STACK_ALLOC_ORDER))
 #define STACK_ALLOC_ALIGN 4
 #define STACK_ALLOC_OFFSET_BITS (STACK_ALLOC_ORDER + PAGE_SHIFT - \
@@ -47,16 +47,16 @@
 #define STACK_ALLOC_INDEX_BITS (DEPOT_STACK_BITS - \
 		STACK_ALLOC_NULL_PROTECTION_BITS - \
 		STACK_ALLOC_OFFSET_BITS - STACK_DEPOT_EXTRA_BITS)
-#define STACK_ALLOC_SLABS_CAP 8192
-#define STACK_ALLOC_MAX_SLABS \
-	(((1LL << (STACK_ALLOC_INDEX_BITS)) < STACK_ALLOC_SLABS_CAP) ? \
-	 (1LL << (STACK_ALLOC_INDEX_BITS)) : STACK_ALLOC_SLABS_CAP)
+#define STACK_ALLOC_POOLS_CAP 8192
+#define STACK_ALLOC_MAX_POOLS \
+	(((1LL << (STACK_ALLOC_INDEX_BITS)) < STACK_ALLOC_POOLS_CAP) ? \
+	 (1LL << (STACK_ALLOC_INDEX_BITS)) : STACK_ALLOC_POOLS_CAP)
 
 /* The compact structure to store the reference to stacks. */
 union handle_parts {
 	depot_stack_handle_t handle;
 	struct {
-		u32 slabindex : STACK_ALLOC_INDEX_BITS;
+		u32 pool_index : STACK_ALLOC_INDEX_BITS;
 		u32 offset : STACK_ALLOC_OFFSET_BITS;
 		u32 valid : STACK_ALLOC_NULL_PROTECTION_BITS;
 		u32 extra : STACK_DEPOT_EXTRA_BITS;
@@ -91,15 +91,15 @@ static unsigned int stack_bucket_number_order;
 static unsigned int stack_hash_mask;
 
 /* Array of memory regions that store stack traces. */
-static void *stack_slabs[STACK_ALLOC_MAX_SLABS];
-/* Currently used slab in stack_slabs. */
-static int depot_index;
-/* Offset to the unused space in the currently used slab. */
-static size_t depot_offset;
+static void *stack_pools[STACK_ALLOC_MAX_POOLS];
+/* Currently used pool in stack_pools. */
+static int pool_index;
+/* Offset to the unused space in the currently used pool. */
+static size_t pool_offset;
 /* Lock that protects the variables above. */
-static DEFINE_RAW_SPINLOCK(depot_lock);
-/* Whether the next slab is initialized. */
-static int next_slab_inited;
+static DEFINE_RAW_SPINLOCK(pool_lock);
+/* Whether the next pool is initialized. */
+static int next_pool_inited;
 
 static int __init disable_stack_depot(char *str)
 {
@@ -220,30 +220,30 @@ int stack_depot_init(void)
 }
 EXPORT_SYMBOL_GPL(stack_depot_init);
 
-static bool init_stack_slab(void **prealloc)
+static bool init_stack_pool(void **prealloc)
 {
 	if (!*prealloc)
 		return false;
 	/*
 	 * This smp_load_acquire() pairs with smp_store_release() to
-	 * |next_slab_inited| below and in depot_alloc_stack().
+	 * |next_pool_inited| below and in depot_alloc_stack().
 	 */
-	if (smp_load_acquire(&next_slab_inited))
+	if (smp_load_acquire(&next_pool_inited))
 		return true;
-	if (stack_slabs[depot_index] == NULL) {
-		stack_slabs[depot_index] = *prealloc;
+	if (stack_pools[pool_index] == NULL) {
+		stack_pools[pool_index] = *prealloc;
 		*prealloc = NULL;
 	} else {
-		/* If this is the last depot slab, do not touch the next one. */
-		if (depot_index + 1 < STACK_ALLOC_MAX_SLABS) {
-			stack_slabs[depot_index + 1] = *prealloc;
+		/* If this is the last depot pool, do not touch the next one. */
+		if (pool_index + 1 < STACK_ALLOC_MAX_POOLS) {
+			stack_pools[pool_index + 1] = *prealloc;
 			*prealloc = NULL;
 		}
 		/*
 		 * This smp_store_release pairs with smp_load_acquire() from
-		 * |next_slab_inited| above and in stack_depot_save().
+		 * |next_pool_inited| above and in stack_depot_save().
 		 */
-		smp_store_release(&next_slab_inited, 1);
+		smp_store_release(&next_pool_inited, 1);
 	}
 	return true;
 }
@@ -257,35 +257,35 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 
 	required_size = ALIGN(required_size, 1 << STACK_ALLOC_ALIGN);
 
-	if (unlikely(depot_offset + required_size > STACK_ALLOC_SIZE)) {
-		if (unlikely(depot_index + 1 >= STACK_ALLOC_MAX_SLABS)) {
+	if (unlikely(pool_offset + required_size > STACK_ALLOC_SIZE)) {
+		if (unlikely(pool_index + 1 >= STACK_ALLOC_MAX_POOLS)) {
 			WARN_ONCE(1, "Stack depot reached limit capacity");
 			return NULL;
 		}
-		depot_index++;
-		depot_offset = 0;
+		pool_index++;
+		pool_offset = 0;
 		/*
 		 * smp_store_release() here pairs with smp_load_acquire() from
-		 * |next_slab_inited| in stack_depot_save() and
-		 * init_stack_slab().
+		 * |next_pool_inited| in stack_depot_save() and
+		 * init_stack_pool().
 		 */
-		if (depot_index + 1 < STACK_ALLOC_MAX_SLABS)
-			smp_store_release(&next_slab_inited, 0);
+		if (pool_index + 1 < STACK_ALLOC_MAX_POOLS)
+			smp_store_release(&next_pool_inited, 0);
 	}
-	init_stack_slab(prealloc);
-	if (stack_slabs[depot_index] == NULL)
+	init_stack_pool(prealloc);
+	if (stack_pools[pool_index] == NULL)
 		return NULL;
 
-	stack = stack_slabs[depot_index] + depot_offset;
+	stack = stack_pools[pool_index] + pool_offset;
 
 	stack->hash = hash;
 	stack->size = size;
-	stack->handle.slabindex = depot_index;
-	stack->handle.offset = depot_offset >> STACK_ALLOC_ALIGN;
+	stack->handle.pool_index = pool_index;
+	stack->handle.offset = pool_offset >> STACK_ALLOC_ALIGN;
 	stack->handle.valid = 1;
 	stack->handle.extra = 0;
 	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
-	depot_offset += required_size;
+	pool_offset += required_size;
 
 	return stack;
 }
@@ -336,10 +336,10 @@ static inline struct stack_record *find_stack(struct stack_record *bucket,
  * @nr_entries:		Size of the storage array
  * @extra_bits:		Flags to store in unused bits of depot_stack_handle_t
  * @alloc_flags:	Allocation gfp flags
- * @can_alloc:		Allocate stack slabs (increased chance of failure if false)
+ * @can_alloc:		Allocate stack pools (increased chance of failure if false)
  *
  * Saves a stack trace from @entries array of size @nr_entries. If @can_alloc is
- * %true, is allowed to replenish the stack slab pool in case no space is left
+ * %true, is allowed to replenish the stack pool in case no space is left
  * (allocates using GFP flags of @alloc_flags). If @can_alloc is %false, avoids
  * any allocations and will fail if no space is left to store the stack trace.
  *
@@ -396,14 +396,14 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		goto exit;
 
 	/*
-	 * Check if the current or the next stack slab need to be initialized.
+	 * Check if the current or the next stack pool need to be initialized.
 	 * If so, allocate the memory - we won't be able to do that under the
 	 * lock.
 	 *
 	 * The smp_load_acquire() here pairs with smp_store_release() to
-	 * |next_slab_inited| in depot_alloc_stack() and init_stack_slab().
+	 * |next_pool_inited| in depot_alloc_stack() and init_stack_pool().
 	 */
-	if (unlikely(can_alloc && !smp_load_acquire(&next_slab_inited))) {
+	if (unlikely(can_alloc && !smp_load_acquire(&next_pool_inited))) {
 		/*
 		 * Zero out zone modifiers, as we don't have specific zone
 		 * requirements. Keep the flags related to allocation in atomic
@@ -417,7 +417,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 			prealloc = page_address(page);
 	}
 
-	raw_spin_lock_irqsave(&depot_lock, flags);
+	raw_spin_lock_irqsave(&pool_lock, flags);
 
 	found = find_stack(*bucket, entries, nr_entries, hash);
 	if (!found) {
@@ -437,10 +437,10 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		 * We didn't need to store this stack trace, but let's keep
 		 * the preallocated memory for the future.
 		 */
-		WARN_ON(!init_stack_slab(&prealloc));
+		WARN_ON(!init_stack_pool(&prealloc));
 	}
 
-	raw_spin_unlock_irqrestore(&depot_lock, flags);
+	raw_spin_unlock_irqrestore(&pool_lock, flags);
 exit:
 	if (prealloc) {
 		/* Nobody used this memory, ok to free it. */
@@ -488,7 +488,7 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 			       unsigned long **entries)
 {
 	union handle_parts parts = { .handle = handle };
-	void *slab;
+	void *pool;
 	size_t offset = parts.offset << STACK_ALLOC_ALIGN;
 	struct stack_record *stack;
 
@@ -496,15 +496,15 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 	if (!handle)
 		return 0;
 
-	if (parts.slabindex > depot_index) {
-		WARN(1, "slab index %d out of bounds (%d) for stack id %08x\n",
-			parts.slabindex, depot_index, handle);
+	if (parts.pool_index > pool_index) {
+		WARN(1, "pool index %d out of bounds (%d) for stack id %08x\n",
+			parts.pool_index, pool_index, handle);
 		return 0;
 	}
-	slab = stack_slabs[parts.slabindex];
-	if (!slab)
+	pool = stack_pools[parts.pool_index];
+	if (!pool)
 		return 0;
-	stack = slab + offset;
+	stack = pool + offset;
 
 	*entries = stack->entries;
 	return stack->size;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/923c507edb350c3b6ef85860f36be489dfc0ad21.1676063693.git.andreyknvl%40google.com.
