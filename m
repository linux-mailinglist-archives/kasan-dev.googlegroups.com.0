Return-Path: <kasan-dev+bncBAABBTG4Q6UAMGQEEHTYBEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 838B579F018
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:15:58 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-2be370ff948sf263631fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:15:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694625358; cv=pass;
        d=google.com; s=arc-20160816;
        b=AleXwrDII/Pya4zU+AMWngbrsxs7TZ/TICehtgxYEoEDpwAEaevUtpCEMcr2oV3ceH
         JQylQnQC/DfWKgVKaVkQc5fkJOTk5OQUMDPzzlXUFFQs/l4CTXbQuUYwyQ7ktZX8ZNVS
         VXm26+7Hqd6MpS5lwj6MZ+AeAyuYbGkv7OsXWxJyq9QbkKBbWpkrhR5aHDWuZeEfHQNV
         8fEhS7mulZpc6R8VX2p9pzDO4b6XEK+CLTAe2klTwC5/eZHhm1mOqS6krbF/ufJFDTko
         MGpyZjld63sPg0MJ9EOFZIpLP4Xjc/sxg2TR6cHBRc0HRQ7rbsXCcYuT0PuMIPmJzSGz
         9YJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=W7mP9XsS7P4cAPZ+sgfnchUJAhmCMkPiQbZ5oVv1+s0=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=jtATMbB0dY8RBx77KYc2mmb1qYzjDl6V0PRMPd9DyOKFLGxR+kXD4RNoOYqGYNJmXC
         oom5MTZZ5RYfbYGMN4hcVjmU2Wcwqk7wpO+/K8l618KuaMaMg2C8zxo/cOJ968PcWoIi
         lwUvCU8qyc5VOrHx4QLiv6EjNf5kZxZei1kydslbtMds3R6I9Felmd2S3e3gEm5EPXY0
         mci61cIM+2gX0kZueO12kn41kvco4Nfv8/d2EciEvWYUiE5FfQvutxvxkQZU9ylH/j1n
         MXLOwiDuD4i08yetvf20fonVB6gClcq/d8pF1oHK47PXwTUklRgcWpGSzwwUqY+sJ2T6
         Tlvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=puVK18ov;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::db as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694625358; x=1695230158; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=W7mP9XsS7P4cAPZ+sgfnchUJAhmCMkPiQbZ5oVv1+s0=;
        b=C+TAvBck1BjFT3FXPFOtWK2yA4C9BmLLGuEchTvEgKi9QjTUB5UH8/1Kt3iU3k6ldQ
         ADk3+Tfr1ZpknF8gDbVQZpD2iR7jlPyvOf1GNudkD34w/rUfKV0ay3mx6ke89tzpkUcl
         ZFFRM9O0ilIblo8IpihBIPS8c4Gt3HUF4EWAeny/IQtzczPC0zWWddbGh59Xs83QTjI3
         NncVBTGR30EG/Lyv9Z2B3TkSY3O7lxwwWLM8ZJT8e6K1FIIusQZlESFdfAv65gZvKWaV
         b0epc3arCMuSUQGVtstBEKR3+y/li/XqCsdvMJ5ce6SNxlnnCJ4RGvIYBdAE9ScO/V3C
         zspA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694625358; x=1695230158;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=W7mP9XsS7P4cAPZ+sgfnchUJAhmCMkPiQbZ5oVv1+s0=;
        b=AlwJdwPASjrw3OCv8xAOmPvUVf+P4Ruc6frSJjqkZn5pe7uX+OPqJg7/i5MtrdrCP3
         VeBBat8sZsAOO6ygei694I4wm/MDm2uJlEtLHHVrtMC3NKbMSOXwFb9F/2XZqLPB3bUZ
         vOEOIzEN0Kb+LWIdw+mvj6+Xcbi062NqTUjP0vadOW+CtlgmKPe9XcREmo2jOir5iinT
         CyxkVczFXF4Gw7f15js5sum7B5Po2JKjkjBTInuXfQUrEK/q/05NKWGCY1cWmSfJyDha
         mXy5XU/EKYU82xQCE58s8y0hPQA3jYJOD2KBDmp8lNEnxbYHQvWJZ9kLAJjpr0UB0sDx
         U+ZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy1Wtjvr8puyoW0bBdfV1ZKF8f7Uf89jNwQ41gk9Gw3NiY5lVHF
	bP/XNOCmAczPOesunn5YFAI=
X-Google-Smtp-Source: AGHT+IEL+Ml9c4h4riszdDYq5Ufdq/C6zmoxFcWa/qW4+GVjTs1bPklfNI44Y1+sjaY+mYkR93c+Kw==
X-Received: by 2002:a2e:9947:0:b0:2bd:140c:6d0f with SMTP id r7-20020a2e9947000000b002bd140c6d0fmr2814145ljj.47.1694625357017;
        Wed, 13 Sep 2023 10:15:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a7c3:0:b0:2bf:bbc4:45ed with SMTP id x3-20020a2ea7c3000000b002bfbbc445edls596072ljp.2.-pod-prod-06-eu;
 Wed, 13 Sep 2023 10:15:55 -0700 (PDT)
X-Received: by 2002:ac2:4e90:0:b0:4ff:8742:4488 with SMTP id o16-20020ac24e90000000b004ff87424488mr2238046lfr.52.1694625355672;
        Wed, 13 Sep 2023 10:15:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694625355; cv=none;
        d=google.com; s=arc-20160816;
        b=H99sEUCi69IdbBYTZNxaPQjJOdH950V5Fzim37SP8C/IGwbh95ArA2b83A6IBB7h1T
         VAdhxlgZadReuktBGGgDwWvY3hfh9BeJtPbgPs+PmngV7qTQhKx+m8o/HW/sh7a7hSfO
         ZZAHRWI2G1VrqEtTiexBCFLMSzrqEXeyeqQ9qtNKIS8ubfjJuouSYJWMOX19362GgMZn
         l79AfXgpv4Xcm3qWZt2k8kaGLGSDZykWHgrT8MwLvXYOV7hHlSZrlDds7KDOHll74faJ
         VVqD4aiXLDwCyjy5+jbxcazs2Ab8rNbsVtDNfNHFvsc/eScJQ2zVR71N1mbbv5TtycTZ
         W8dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gAOd+0bdipGa5TwT77P0cix2trL96KYDpIy1afA6aX4=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=N1+oPkNIOrDx6A4cmdQdvYxmJuDOnGKldqYfn50mcypi1eGC8bkKPNIdQqe7gHYVgI
         QvzyBFtVUQAJPVfc9PunvjU78wWm9ebLWGKNaNYZn54Tn6NckgE+tu9Hmah3Fl8fiBos
         8EL7jJ1RBUkNWw9F+39oB76fIOmiJ7Un0dh97uKPK+R1q3QvYuLJh2aYKtbcBo5t2cjK
         UepUl8UBRm1XGYkjAHEBV5pSLiZcUIYf8LAcxP2GIehl+2r18EaEX1GKJJHHZYXBRm+u
         3ePz4H5/lLPxm+eGIDj8vd4IN9b3PhSjG6/FlrY49beA6L3ZCXhtjbAIr5Givx8xR2xx
         6CBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=puVK18ov;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::db as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-219.mta1.migadu.com (out-219.mta1.migadu.com. [2001:41d0:203:375::db])
        by gmr-mx.google.com with ESMTPS id v8-20020a056512348800b005009dc902ffsi798319lfr.4.2023.09.13.10.15.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Sep 2023 10:15:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::db as permitted sender) client-ip=2001:41d0:203:375::db;
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
Subject: [PATCH v2 07/19] lib/stackdepot: rework helpers for depot_alloc_stack
Date: Wed, 13 Sep 2023 19:14:32 +0200
Message-Id: <bbf482643e882f9f870d80cb35342c61955ea291.1694625260.git.andreyknvl@google.com>
In-Reply-To: <cover.1694625260.git.andreyknvl@google.com>
References: <cover.1694625260.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=puVK18ov;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::db as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 87 +++++++++++++++++++++++++++---------------------
 1 file changed, 49 insertions(+), 38 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index babd453261f0..e85b658be050 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -219,54 +219,43 @@ int stack_depot_init(void)
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
 	 */
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
@@ -276,9 +265,10 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
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
@@ -286,9 +276,30 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
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
@@ -322,7 +333,7 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 	union handle_parts parts = { .handle = handle };
 	/*
 	 * READ_ONCE pairs with potential concurrent write in
-	 * depot_alloc_stack.
+	 * depot_update_pools.
 	 */
 	int pool_index_cached = READ_ONCE(pool_index);
 	void *pool;
@@ -421,8 +432,8 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	 * Check if another stack pool needs to be initialized. If so, allocate
 	 * the memory now - we won't be able to do that under the lock.
 	 *
-	 * smp_load_acquire pairs with smp_store_release in depot_alloc_stack
-	 * and depot_init_pool.
+	 * smp_load_acquire pairs with smp_store_release in depot_update_pools
+	 * and depot_keep_next_pool.
 	 */
 	if (unlikely(can_alloc && smp_load_acquire(&next_pool_required))) {
 		/*
@@ -459,7 +470,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bbf482643e882f9f870d80cb35342c61955ea291.1694625260.git.andreyknvl%40google.com.
