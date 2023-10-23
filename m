Return-Path: <kasan-dev+bncBAABBJN43KUQMGQEB2LGDRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 920AA7D3C56
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:24:15 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-4083fec2c30sf20616285e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:24:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698078255; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xb4X1R8S/y77LZ3U5tIegF8gVn82jeJWJjt26qHMsP556HdOwcCJLhh1FxJMVPM1gu
         Bt+NniT/z8Q9PCArGg3ZEM37qgAFr504WBJCOTiLqi30GZyvVTSRp4DI49F2Q2o5FE84
         WovXWLrGauaZAk6BN03rFUqsmqgFmn4Y+nvzJrSkOnHtF/OZ1VoWPBkOlGlzHEn3BMmq
         lFytWkvR542PXIcvA7d+l3LESttxPxOqavN+ruKlts97FjufXPoRKRgino1545cH3V6X
         nEDE+6qQM3orH2/jop57Hd7SwTMdkAAPlfHOXQZ/4QVycyytb6c47BNcaFJJvJTTmgUt
         hqBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ygpHklMTRXS6vWgMQ2gcPMQ4VETwwQWdCIofU1/StfI=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=Eaaj1E5TQDGSh6vByE7Kj7kFIlMnUjDTZb3YA8FmtkKl+SjfDV8itJ8I2f4Z7Jp7zy
         99DdSO2nNzx/7Smlumtiqf/TFYBLtp0MvfzkmKdgaNFkroRtCwNVIhc+Uq0DRF8Eub/2
         8RUdLBxuFkgN7aEI8alX61Reuv6pMABoyrSqSXn++OowRFwzvAWYN+8KsUsdjY2Gv/me
         D8NuuAqkv8tMoMch84IVPCxj+H0AkntQ69cVgRa29kCfwnl77iDsqeSSE/nHTPVWu//B
         7PHmPV7v24nRzEhZaTWdjaDIxLFYA1lgeSAVYYyZSs/qIgWG2UqOpB7bwqNg+7fgllgw
         JLGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=t+UnmZVx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::cf as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698078255; x=1698683055; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ygpHklMTRXS6vWgMQ2gcPMQ4VETwwQWdCIofU1/StfI=;
        b=ceQb9ZItUK36MUsb24ogkxGqumrWtp9V2Limmav2hMC2F0jg8BefxsShWMHNeTYYUa
         uiU9YebBx9Hlwy3lHThdx0KGELbogcVYONGyqqf1L87totA9FBKNgl3cbT5+9sS3s1Zg
         8yeQciheHIECBr/a6FkoyLmalkc94GGOdmlfxMGuRdYnjLdmiWCOLzOVCLdAqr4jaqzy
         kPjllXRC61jK6rJBO3AYKjdiaZjmb2hsuvJtoqtlTHjFSPiT6KP4eZHkWRAKkoX4fWdS
         xmhDkBSeb+lr1atF0MUvh/lESxQHb/SMhZCtv3nVmru5AfEeWtv2gqqc+7+/5jinWreG
         YaGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698078255; x=1698683055;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ygpHklMTRXS6vWgMQ2gcPMQ4VETwwQWdCIofU1/StfI=;
        b=nM2hqeWSgORK0o5VMbUlBtw2Hf2gkufONkFV9B2QTW9yvLPp7kPwXnaVmDRRsi5fdB
         5vOoInxQDCSgE8WOkzku9LLQKrRGicjKESytpuXBDKCQgvsEvZjJICOA4u9zKDt/IYMI
         LFB2/OQz0ifEQ5iMQ90Z/jwyM1cnvgK5P4pctEVPaJFU9nDKTbvJRexUwEIoGf3CZyPQ
         LLbc89Dz//UkoLz5H+lHV2wKtXF0P0xod5Z6yBMxXpcsel/WfktBe5fgjEjbiVr78ijo
         TG46dLRD+YJkjSx5AfaCrozqb2ERI1o93a5pi0jdTVnab4L3RscNy+Cgm6MApvHrElWq
         KgiQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwHTSREyl+4/SGz/vC1emNBjuJBPTg/2DhlmnjtlzY3/vPpTVwj
	8lf5eztsnC/+C15n/Oz0BOw=
X-Google-Smtp-Source: AGHT+IGmZ+vepw/00+v0NL4CxYaa8XRItdTrgChcYqujDizMdMfk4krFysZ2P2anrcwsdsHwBr8LdQ==
X-Received: by 2002:a05:600c:3ba5:b0:406:44d2:8431 with SMTP id n37-20020a05600c3ba500b0040644d28431mr7286880wms.6.1698078254020;
        Mon, 23 Oct 2023 09:24:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b06:b0:405:2359:570a with SMTP id
 m6-20020a05600c3b0600b004052359570als1374735wms.1.-pod-prod-01-eu; Mon, 23
 Oct 2023 09:24:04 -0700 (PDT)
X-Received: by 2002:a5d:6392:0:b0:32d:827e:7bd8 with SMTP id p18-20020a5d6392000000b0032d827e7bd8mr8152407wru.70.1698078244069;
        Mon, 23 Oct 2023 09:24:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698078244; cv=none;
        d=google.com; s=arc-20160816;
        b=eKpXMfb1Qn2S9e3wAt94e+nBJnPXANGwWP5Porfw91y7uZT9IMtzQm+E3pUY5CiCV9
         oWkHoceq/3qRc87VxFk2p1UUBFrwn9SGSh9qgI5tIp7wiDAVqLADvSgym0rrunmDmdDI
         RK119D6PRME/JSec2Pn95dgQuLrFenuS0UhrXhLMJtcBGnGWiWG3W0EviHOZHKSxXzLn
         VurGMt9xvy15M99NLZxlGIwoddfEMB/CDtwRl/lyDoOsgo/yF0lt39NE69URz5YxmZMo
         S1Vl9B+kwZtXx/5By+vMmxFtEB5vt0JeciGtAvq8esc32Z0QqLl9nMDxhvaGHendGRpy
         Me2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=NZ9DxgJteIUWBZVu3uTAKUKrmlqiVCjIJZsHKffVHuY=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=AdnuoRY3vjVDFqHfMJwZnTjfCHvb+eScHOjOp8wDBSphJvBsnNra93wP0vbeYCwLwX
         ANX+0cvL1CVVyybRbT2VuPUOcJZtmmErpcoLHtRHIGyTf1LsjeNJBB2YYdhzxb/RT4D2
         utdD5jwitPtVHuVD2QHtTjXPWAxteS5hwJkj5JC9VM/zZP4gV39gwK4W/SNoJUwlIJlD
         6KUGlbJMhrqE2HSV0NGWHBxpXk3qjvK5/zOxjcJ4m50uH5Jtf1kKOCm9T3m+FI2VVdK5
         qL5hEBJ339MdzcNMfdYxF/UpI7nH1YshFvDrSUjplXglIIAnZaWXIKy32WCJJRSoJqRU
         9Obw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=t+UnmZVx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::cf as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-207.mta1.migadu.com (out-207.mta1.migadu.com. [2001:41d0:203:375::cf])
        by gmr-mx.google.com with ESMTPS id m9-20020adff389000000b0032d8f0b5663si284064wro.7.2023.10.23.09.24.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Oct 2023 09:24:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::cf as permitted sender) client-ip=2001:41d0:203:375::cf;
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
Subject: [PATCH v3 07/19] lib/stackdepot: rework helpers for depot_alloc_stack
Date: Mon, 23 Oct 2023 18:22:38 +0200
Message-Id: <a09397efb805aeafafe33bdcf07813b0ffa0e3ea.1698077459.git.andreyknvl@google.com>
In-Reply-To: <cover.1698077459.git.andreyknvl@google.com>
References: <cover.1698077459.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=t+UnmZVx;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::cf as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
index 60aea549429a..3f921aaae44a 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -219,11 +219,11 @@ int stack_depot_init(void)
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
@@ -231,44 +231,34 @@ static void depot_init_pool(void **prealloc)
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
@@ -278,9 +268,10 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
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
@@ -288,9 +279,30 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
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
@@ -324,7 +336,7 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 	union handle_parts parts = { .handle = handle };
 	/*
 	 * READ_ONCE() pairs with potential concurrent write in
-	 * depot_alloc_stack().
+	 * depot_update_pools().
 	 */
 	int pool_index_cached = READ_ONCE(pool_index);
 	void *pool;
@@ -424,7 +436,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	 * the memory now - we won't be able to do that under the lock.
 	 *
 	 * smp_load_acquire() pairs with smp_store_release() in
-	 * depot_alloc_stack() and depot_init_pool().
+	 * depot_update_pools() and depot_keep_next_pool().
 	 */
 	if (unlikely(can_alloc && smp_load_acquire(&next_pool_required))) {
 		/*
@@ -461,7 +473,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a09397efb805aeafafe33bdcf07813b0ffa0e3ea.1698077459.git.andreyknvl%40google.com.
