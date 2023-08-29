Return-Path: <kasan-dev+bncBAABBC6OXCTQMGQEC5F4OGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id BFDC278CA62
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 19:12:44 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2bcda0aa7ffsf51755861fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 10:12:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693329164; cv=pass;
        d=google.com; s=arc-20160816;
        b=KBGdImpTJYw7UOrgyyhXrk/8Swdwm+nuTVd73LM63oi7iYGdqkFWk4NBBmLVB6eTRj
         bUruAl24NzNwWO3nWxxWyvyUvO2lCS8A93clQHb2NTYeFjBf2ZvsJxwLEpgzFjsjx/uN
         hNrBWizJrI0gMl/HSEs3wQZ0yVGq1wR5WUQ+Kwve4dnAQGCHNeuq6HWvom6cfxdyoBL5
         0iGSfF2bv0Je+5dDd9n1Acz7+ip92EbYjN2TXQblYuEpAvCoFequ9akPuZzFOTQ6O883
         31Ufkomiy+ko90H7kUxm6LVo7oTNPxWvg2uyU6iTo6y8OHMDUQCrXsm0f5rMb3CfjxV3
         ajFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=IqIZBm5ajBdk/H5rLvY1MDqsSHeKtEH2HGtwmBifZS8=;
        fh=ZTTSst3850TI+4y2eqKpcuCmJhEtn1qZX9lpGyHR9Jg=;
        b=j7s1r4u4ObzB78Sjjy3ekonXblR8N/RzTI7kzL7p4ly0FCM4gDL43UK1c0E9G8EiJG
         d/HUk/67YPI6H7DclpXW2n4uZu28PCCWcZZ/DuqzKQrfAiOqHafBwRwmoHe000qYTlAb
         DyTJSdzNt4SYmFTuUzSaBEl8BVlEjA92Q/8jJwADJBk0M9DHr0FLhSHb2xirC4axTzC2
         dxkvq9UfhMprNLx52wu2S2vG5OsgzWaBHuA50fetddfc8JO0aiKBGTeEMSEVLANAXjiq
         3r/PhDZmM50qwxzOpHdcstFWh9oI7J9GC6L2/Aw8YWnxhWOGJPdOPbgMVFzn5a3i+8gS
         Dplw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=aVdkqRkg;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::f5 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1693329164; x=1693933964;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IqIZBm5ajBdk/H5rLvY1MDqsSHeKtEH2HGtwmBifZS8=;
        b=IQmdHiW60H3dFYO7P6cILHhRrrOOUYgKeecX0PMNnwsP4dElYPgppwFmtOHMwbMuRn
         MSqx3fK/0FB0AhBHT53mbwhJ6/zfDRQKGKF/Pz6lG7X3N0IB20jeX9OrrjJToImfJCCS
         ie5K2TDhiVnfqJakmFypktHg9Ad7peO6CzW1tHepZgEtTOlhejwIybyAUd0ZpEWLOVLC
         wrz14IBy+vCctp+8p0ChdxUfJPRJFO49Zy2hJ7DfPFDAe7FnRtCUQ8rzsvQ4hP6GM5E2
         3RCZfCdTFKcI4ogNO/hcp01k0h+bIT8N83DFR47vSd46ESEdzxG9H9CbhCIwgjcHtxsT
         Z1AA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693329164; x=1693933964;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IqIZBm5ajBdk/H5rLvY1MDqsSHeKtEH2HGtwmBifZS8=;
        b=DQcPTnwQF+wMFAYbvJe5RX3yeZZlMMw/4u2yjx21bTrDozb0e26XHq/3DEE/wGUm5F
         sIYK8fMzxjo1NY9rTo4bcpVOsxZ+DyfWSBIYrWhc2/SFDKWlBweAuZlky94kLVfIq9W1
         3f8V9LIpHstPwLq+yHcKT5YCtlMUMPZMvBMlXFGTv1wsGe32z6u6gpfPUFdklS5pXf9e
         9cTkz4prrImij3Snut/m5Z2i3RPgloHjCYSrbVY3E1Q2de7c8KD79Se6KxbZF+9eh293
         EWAumFxLcbzcbqZs86wdBIXF7BEqfhO35XvyBJTwesegcRoOI/Ztui1DbtjPfleUmDcx
         Foug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyYXWeb52I7ABwUYQ518aXpaRp6KbeRudBFZ+faISFerT9VaHfZ
	zfq7gMuLYHxU7wSmzI42IMU=
X-Google-Smtp-Source: AGHT+IEIm4hedrRh9zi7UoWH/c85PeMM2IXPr2CPoACL+lNT47HtKjiSRz70CKXRUPLszJsuF19j7A==
X-Received: by 2002:a2e:8257:0:b0:2bc:c259:5dae with SMTP id j23-20020a2e8257000000b002bcc2595daemr18882381ljh.12.1693329163992;
        Tue, 29 Aug 2023 10:12:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:c96:b0:2b9:631f:ac29 with SMTP id
 bz22-20020a05651c0c9600b002b9631fac29ls215645ljb.1.-pod-prod-08-eu; Tue, 29
 Aug 2023 10:12:42 -0700 (PDT)
X-Received: by 2002:a2e:160d:0:b0:2bd:b99:ab7e with SMTP id w13-20020a2e160d000000b002bd0b99ab7emr5502297ljd.42.1693329162541;
        Tue, 29 Aug 2023 10:12:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693329162; cv=none;
        d=google.com; s=arc-20160816;
        b=Zi5kPjyAvExAVCoM1EgN1AX4uluyU3y5LeSZfuBIHdQjlwz32CTtc6tFlPzRvr8xjt
         s1JWc+gWJyemlEyGWbBN48is0tTyMJtxeHBvAZyklJGIhoWRME3XaTERD2CTxCZ6HJNM
         trpXSDXSAErImoszrAviw10ZgKdv7AhAn/ayZQNibgIwruzKlgJ0BsxuyH/fPqQIsY7u
         SCCecFCAePHS0ZVfS0v9cqRnWSF6XxVJe8WXIuBZ9Xz3myHCzVdbnaxUqzuZsY359sIg
         /7+4M9g71aM3p40hFm5bU6w+QqA/BKU39hsTj5bksZcepBXHo18LEiVqTugzrbcaw36k
         hyWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=78m2o0At4EqoxYvPO8GgUXqZmV/z9BTR2roI196o/ig=;
        fh=J1Qt2dYQZwHfoASHEf8Q1j6KnDtpzzpCUlDsDM7WT0M=;
        b=xFr6P6cxphyOiJqQBoMJ69JBkN5RoDF7I/sefxA4ki0bVoqjjYjbdk+Qt0j1YoFj1U
         R5Nvvyp6TX/plpDbehlWeiNcca8vDnaCa4Nlp3R12vOEApFEsF5PBGBXDEW8GJceEKme
         Vv5GJH7hbYd4SUOWyX4scDTHyWezVVPw9FhyZK4/rKDq6DrZTYC+ZMts/9Xf21PUJsKZ
         o7fYbNhtfHltkAoMv8qjCARYygOeO4Tz0CpB7Yvn/ADy8/xTdizI1TG9+Tc+1j2dT5Bt
         w6Dc1yWQ5IXfTl6GkgqpdNamNHb/Yr6bavEUQBcNIeF325NYSTGf9fFJA5EYZZR8lzm9
         vIeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=aVdkqRkg;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::f5 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-245.mta1.migadu.com (out-245.mta1.migadu.com. [2001:41d0:203:375::f5])
        by gmr-mx.google.com with ESMTPS id i24-20020a2e5418000000b002b9e701adbfsi1120287ljb.1.2023.08.29.10.12.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Aug 2023 10:12:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::f5 as permitted sender) client-ip=2001:41d0:203:375::f5;
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
Subject: [PATCH 10/15] stackdepot: store free stack records in a freelist
Date: Tue, 29 Aug 2023 19:11:20 +0200
Message-Id: <0853a38f849f75a428a76fe9bcd093c0502d26f4.1693328501.git.andreyknvl@google.com>
In-Reply-To: <cover.1693328501.git.andreyknvl@google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=aVdkqRkg;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::f5 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 130 +++++++++++++++++++++++++++++------------------
 1 file changed, 81 insertions(+), 49 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 5982ea79939d..9011f4adcf20 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -55,8 +55,8 @@ union handle_parts {
 };
 
 struct stack_record {
-	struct stack_record *next;	/* Link in the hash table */
-	u32 hash;			/* Hash in the hash table */
+	struct stack_record *next;	/* Link in hash table or freelist */
+	u32 hash;			/* Hash in hash table */
 	u32 size;			/* Number of stored frames */
 	union handle_parts handle;
 	unsigned long entries[DEPOT_STACK_MAX_FRAMES];	/* Frames */
@@ -88,10 +88,10 @@ static unsigned int stack_hash_mask;
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
@@ -221,6 +221,41 @@ int stack_depot_init(void)
 }
 EXPORT_SYMBOL_GPL(stack_depot_init);
 
+/* Initializes a stack depol pool. */
+static void depot_init_pool(void *pool)
+{
+	const int records_in_pool = DEPOT_POOL_SIZE / DEPOT_STACK_RECORD_SIZE;
+	int i, offset;
+
+	/* Initialize handles and link stack records to each other. */
+	for (i = 0, offset = 0; offset < DEPOT_POOL_SIZE;
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
@@ -237,7 +272,7 @@ static void depot_keep_new_pool(void **prealloc)
 	 * Use the preallocated memory for the new pool
 	 * as long as we do not exceed the maximum number of pools.
 	 */
-	if (pool_index + 1 < DEPOT_MAX_POOLS) {
+	if (pools_num < DEPOT_MAX_POOLS) {
 		new_pool = *prealloc;
 		*prealloc = NULL;
 	}
@@ -252,45 +287,42 @@ static void depot_keep_new_pool(void **prealloc)
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
@@ -301,35 +333,35 @@ static struct stack_record *
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
 	/* Limit number of saved frames to DEPOT_STACK_MAX_FRAMES. */
 	if (size > DEPOT_STACK_MAX_FRAMES)
 		size = DEPOT_STACK_MAX_FRAMES;
 
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
@@ -339,16 +371,16 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
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
-			parts.pool_index, pool_index_cached, handle);
+			parts.pool_index, pools_num_cached, handle);
 		return NULL;
 	}
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0853a38f849f75a428a76fe9bcd093c0502d26f4.1693328501.git.andreyknvl%40google.com.
