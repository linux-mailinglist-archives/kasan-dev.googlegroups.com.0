Return-Path: <kasan-dev+bncBAABBCWOXCTQMGQEA23KFUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8745E78CA5D
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 19:12:43 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2b980182002sf71041fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 10:12:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693329163; cv=pass;
        d=google.com; s=arc-20160816;
        b=RWp7s63aHBjUec/BUSC0+JYNm62+hnlTeIyY+YqPi3o13pJWZ6oG6PNd/TuMyNoO2x
         JXM48rIVdOdGsj2O1jH26hZqatyfZ2U36braEkIny5OR55JIpRneJNGwOCZIH9ZecfBE
         XUmfOVrtpJOAG273ZozjT8dWMZ2UbyG+j9mQizF8uIvara+rpzEwgvIAXMDTfZ/AHB0X
         5YoD6amcA+EuDGOM9JxG9BOMRiR9LIdIXcEEisjE7mEmKpHA74XtK562pzXEx9g0tTqj
         kYWeWi4homLe7CTJdqUlr9canB7iLH3AgIvnyr+pi8Ly8N1wgtktqBvjkW/Kmj9fjyLx
         ldmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=T9kie2biMUy9sm3pmsIsZqbZnQVJNNl8F5yrkRWNl3w=;
        fh=J1Qt2dYQZwHfoASHEf8Q1j6KnDtpzzpCUlDsDM7WT0M=;
        b=T0eZNEPCYpPsNeoasrhTpMlTFe86vgpmEJ9MbkacfywUIgJSdPBZckr7YecVWA1hR2
         UBmGkt9TGop1GmFQwHqSXj6OGjGOAsS2tyEb78X81NDLrhCiYa+KjOSWCG+Ct/KHMu6J
         YWGPFnbD4T4AP1Uem6G5coihHkq+9LHuuw5POVd47LAaRYplMwnQC2xZjkj6GJ9Qzld/
         BapX43X2GINHzCdVWG1RjZDjKWU100wNLT2VHXbnD9gEM0/LO7b14E+7/DTJw3GtStQ4
         t7WACSGeMndeTBzf2Nw+VoXASaD2/JK37Vkocc8rMgQTyIKuwol+/OwjjA0eU1l0p295
         i90w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=rTza+MTD;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.253 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1693329163; x=1693933963; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=T9kie2biMUy9sm3pmsIsZqbZnQVJNNl8F5yrkRWNl3w=;
        b=XhgBuDj6tqu6TOzsKme+athgVVE3yeO7MYp7N/2u92lQOrxQ+Mcqzr5lhCZ7l7MMC7
         Wy56/zCHEZuZMiYu+h84eBV1uplkqyoWQK0fzHewmeiEy8m2xVcMPPigenWnLQ1yxIag
         DQFQSi1AMTL0EG0hBhSoQbNLGPG4ME0/zziKTkwdeZNmURx26SIRCb1/s07yzqd9o8Gr
         mDlypsGUYv1zSdj4sP6P5GOFMCYfPx/4pctH9Jmi2L72QzYDHZNrJ7GjLxQ/DTIZ0pNq
         nJnlkOfpvqBwsSerWxigL9oh9pMVLrS+2FcGndsl3wPJjQ7eQZl6Wnldp0rBSV95sFIe
         Yn2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693329163; x=1693933963;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=T9kie2biMUy9sm3pmsIsZqbZnQVJNNl8F5yrkRWNl3w=;
        b=UEm+7+ObTjnvPwlaxlqoL1gr++zIvAtUgZg9MTIxD0HFrtE924Ixlmyv0uL/H0IwTU
         ooyZ/8EBa5dEuu9eIibghhsgISAnE47dWhIrGDDbMfKb8Xesm2Mu0eBUhtVSNddXmkwy
         ZkQTzMlqdzYFkq5MLDjd/CziK/O8eFJIcU/DEYsoxvJC4Ld9PtEbZ7zndKo95RRvwbR/
         LIHzuEpA9v/nAXWnU1OjI2S49jz7gI9V13M1GtoInGs8WyMliy4myvqNrNzZ9zHNop3w
         QI3nFls9NSBRyKQp/f12MCWQq+Op8j890G/QwI59YAT4ju2U2UF/6ceD5XkQXH94ST9m
         yOqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz4FziKGqtt8FXk5o0bXmZ2IbCpeRHuSfT1t5/nVjwXVe7S7PgA
	qxXprWCsQpT0cWC6576wcYE=
X-Google-Smtp-Source: AGHT+IFzlH/J9Mzb+i3uBurNxPvpoBI7Sybyus1B1lCyohQybRnDYT2BouxDbJF6iyuoLImyK4NK3w==
X-Received: by 2002:a2e:b559:0:b0:2b9:b1fb:5ff4 with SMTP id a25-20020a2eb559000000b002b9b1fb5ff4mr1187418ljn.21.1693329162337;
        Tue, 29 Aug 2023 10:12:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8e2d:0:b0:2bd:2240:b1c9 with SMTP id r13-20020a2e8e2d000000b002bd2240b1c9ls6884ljk.2.-pod-prod-00-eu;
 Tue, 29 Aug 2023 10:12:41 -0700 (PDT)
X-Received: by 2002:a05:6512:3c86:b0:4fe:13c9:2071 with SMTP id h6-20020a0565123c8600b004fe13c92071mr1418334lfv.2.1693329160864;
        Tue, 29 Aug 2023 10:12:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693329160; cv=none;
        d=google.com; s=arc-20160816;
        b=f80Z8Xbl3HHENTLDgKZaEzgLHagG5JnFlyaZWimPsIy2MRHNroyiG3aqZAzbRzbHG7
         aN4oOs+7A703xSv6H8uZyGAuOCyUTKEO7+kYaKHWjmNioVHxidw2f1VVCPwNYmlpeGxu
         defZNRBiKRQaUl/iS86faRtm3qfM3WLabhNwS315VhlEX8qdbr5IpcFocMCAJNXKO2i+
         QOy2b4JxHD1RrI2fXTlSmyMnraEgQLebAS/iiWsW1RDHkGqYMn6aHMclSB14S7C2HC4p
         +hCLDXGRvKqh/Dp7f5ENnJPlLbcOlCrmY6U70SAU8gXhmP1jJOaiDh9s/ZnWc5lRZIAO
         0ftw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TBLA9eVhfpPnUCaW6dvoHE+HvIWz4FYhXI+BxxI+EVo=;
        fh=J1Qt2dYQZwHfoASHEf8Q1j6KnDtpzzpCUlDsDM7WT0M=;
        b=k9RQ2tRgw6c1akik2skmGveK/g2bkCNQNy0uVXrohxaBdFg/ZI63z7RXXCrHiVg+i7
         M5gqtggTVSjrG+mAGIas+cKipPnNvS21zUwEPwueZ8bUdxtBh4nfDYxC1LkAlyplNd1Q
         dwoZ3I+rXIn7TI2rP/gqSZme1TuOQfsjzJ0ipBScOLfEVUVHUQiU6SB0WjXj7wzfm+qa
         MeNs2LdYpkbwdNd1ueQsSAK1HbfeIETs7KqXl9s0oLUY+Bv6KEynFUbFgIP8eKn2/kAZ
         aEK9WWrLWzbJsTSrSFbVBAJkqAzSlx2cApSWWA32B+eZWAQDI3i2fR7nV6xFgMjZmLLW
         UbSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=rTza+MTD;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.253 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-253.mta1.migadu.com (out-253.mta1.migadu.com. [95.215.58.253])
        by gmr-mx.google.com with ESMTPS id o23-20020ac24e97000000b004fe3719e054si642316lfr.12.2023.08.29.10.12.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Aug 2023 10:12:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.253 as permitted sender) client-ip=95.215.58.253;
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
Subject: [PATCH 07/15] stackdepot: rework helpers for depot_alloc_stack
Date: Tue, 29 Aug 2023 19:11:17 +0200
Message-Id: <a8e6add5dae996633a45a1ae7291a26e31118dfb.1693328501.git.andreyknvl@google.com>
In-Reply-To: <cover.1693328501.git.andreyknvl@google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=rTza+MTD;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.253 as
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

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 85 +++++++++++++++++++++++++++---------------------
 1 file changed, 48 insertions(+), 37 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 9ae71e1ef1a7..869d520bc690 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -220,11 +220,11 @@ int stack_depot_init(void)
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
 	 * READ_ONCE is only used to mark the variable as atomic,
 	 * there are no concurrent writes.
@@ -232,44 +232,33 @@ static void depot_init_pool(void **prealloc)
 	if (!READ_ONCE(next_pool_required))
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
-		 * smp_store_release pairs with smp_load_acquire in
-		 * stack_depot_save.
-		 */
-		smp_store_release(&next_pool_required, 0);
 	}
+
+	/*
+	 * At this point, either the next pool is kept or the maximum
+	 * number of pools is reached. In either case, take note that
+	 * keeping another pool is not required.
+	 * smp_store_release pairs with smp_load_acquire in stack_depot_save.
+	 */
+	smp_store_release(&next_pool_required, 0);
 }
 
-/* Allocates a new stack in a stack depot pool. */
-static struct stack_record *
-depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
+/* Updates refences to the current and the next stack depot pools. */
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
@@ -279,9 +268,10 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 		 */
 		WRITE_ONCE(pool_index, pool_index + 1);
 		pool_offset = 0;
+
 		/*
 		 * If the maximum number of pools is not reached, take note
-		 * that the next pool needs to initialized.
+		 * that the next pool needs to be initialized.
 		 * smp_store_release pairs with smp_load_acquire in
 		 * stack_depot_save.
 		 */
@@ -289,9 +279,30 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
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
@@ -325,7 +336,7 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 	union handle_parts parts = { .handle = handle };
 	/*
 	 * READ_ONCE pairs with potential concurrent write in
-	 * depot_alloc_stack.
+	 * depot_update_pools.
 	 */
 	int pool_index_cached = READ_ONCE(pool_index);
 	void *pool;
@@ -425,7 +436,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	 * the memory now - we won't be able to do that under the lock.
 	 *
 	 * smp_load_acquire pairs with smp_store_release
-	 * in depot_alloc_stack and depot_init_pool.
+	 * in depot_update_pools and depot_keep_next_pool.
 	 */
 	if (unlikely(can_alloc && smp_load_acquire(&next_pool_required))) {
 		/*
@@ -462,7 +473,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a8e6add5dae996633a45a1ae7291a26e31118dfb.1693328501.git.andreyknvl%40google.com.
