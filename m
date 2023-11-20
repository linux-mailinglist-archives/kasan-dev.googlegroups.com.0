Return-Path: <kasan-dev+bncBAABB5FX52VAMGQESHP6ADY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 146B27F1B6C
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:48:37 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-548e2b9fc55sf255a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:48:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502516; cv=pass;
        d=google.com; s=arc-20160816;
        b=w5KjXfrShV/dUyJ+xz1teqtRyhWqynLpjs96hEUxlN4NWKdfkzNHVduYmQ2lAIPb1e
         /K+R9+d/DTwlWO4jsOoPn5pvn+r9yv9V9xZrHYaMiu0jU0E9iRjlEAg8xC4MsGbGFScw
         ACNhDXChU+KYRum+1HCaQcRhEPEX4zTpp5gXateKLeLLPLZeaXOd9XQjssLtHepnTuSq
         XH4hkDQg6C3APicH8bYWFtnn2p3+0otoF5p/aIvShlRTzmRwsqXva6LajjdI/h64XnQs
         t0heACao3nefMCRZtQVWsU/lpgOR59EVhsngp5LxvI/bRNOy097cK4OMUAwmG5NI9mkD
         Xczg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=VvI8gVp6Y2YwjpxMZ5R+CX0ntgYNP5Zxp5/elsqBcOU=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=Ng+TZmWObzYlBCPMkdN1OoLpTExM/xqNT/tRjuAag6I4IUUs08g5b50pgHWE+laBmh
         0+4NeMfPTB3uXPA+qa+3OzIQtNowO4KtGv3b2ABBJmsWHgHZcen4AQoK3nXj7396ZHEZ
         cA0a0yjFfz11gyzX4S7KEw9CRCzGWqgRTNmP34R92jwxiRkCJhDMKtiGVMJpz4K4ghQT
         1egDs2NjqDywMqe0+v3BwqWa+Ja7yz1KC2E14RDNJsGAcCoIsnIrcchise1Rg4ys7vNP
         qiUTEu8A2mFRJceCQIyrdv2FBGjLKH6PHUO9SprRDLppA+eUED0IoWZtsMIPTT5gxieQ
         y+RQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tZ0IiLou;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b6 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502516; x=1701107316; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VvI8gVp6Y2YwjpxMZ5R+CX0ntgYNP5Zxp5/elsqBcOU=;
        b=HG/j6uWXYl6MEeDFUvd1UonwqN6hh6pXSWWtxvskq8Hj6FSvZvPW6qFyp0gHY/jiRJ
         wOVHHmhFrfgIQzSmWS5s/bqmYGD6KbBzI3E95rGy48flK7PP3pE3ouqp2K0pSgGyfx+8
         oW7auM9XBtep3OTmkM5qwuO1DB1BXBh4gn5rScUKbK/xAPRHCpQ5RjcQ3xTZyva8qRmP
         qsQlDFGsRpYcX2/buvDt+/HFX5lBl2ksFPn6QY8dCPW6AOdLMnW0pTntOaQUhZxldtm1
         sbvWUwbUfIRA6D0/VC9AzcWzDMklmAw8qpd/mxXvvsNKsPAK5JnreP3BQLChJcMR1YXA
         2j4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502516; x=1701107316;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VvI8gVp6Y2YwjpxMZ5R+CX0ntgYNP5Zxp5/elsqBcOU=;
        b=sWuP9aMdbU5/iAsNeBGOfAYicebviHJoXztljtqdmVh0NsjlCRoXUvf/w3uFryPM1a
         OM4fLn4rG5y035299R1hU9JQcFbJ1+vT1UCFFdwAok2ddfcuW9oa3MnWYOUTYaQw06ct
         XjkK8MpZDUFasigmPu315DTgKmF/I/CwYMtetwCbQIDB99l5gBYDTcT7nj87v9uH48b6
         4AOdnGBw93ntlZkMGOtrU4HWVanUgTPgDLBXpnnk8eOZGUJ3H+Nr7qpPTaEHjFATqvbm
         F8jFZO2261JaihR6t6dCpRzy8CJ0K0b3obqTvAlcfF1R5W0A2C/r/ss4QwZ9R/9mwl8G
         T//g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxdsah1Cz7qirlQuShxgQN0cGDmx7D6vIHgKCvXrevG6QUXmU+z
	FXXn3/X/F2lQJ4LdtB+Wuzs=
X-Google-Smtp-Source: AGHT+IEnU54p2/R2mn3hPo5IdAqLg2Mfoo+KLLZIpphqh7dVevttY01o614bB0hjJg4DyC0hYkfrzQ==
X-Received: by 2002:a05:6402:c41:b0:544:e249:be8f with SMTP id cs1-20020a0564020c4100b00544e249be8fmr305106edb.1.1700502516498;
        Mon, 20 Nov 2023 09:48:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:370b:b0:548:47f7:adaf with SMTP id
 ek11-20020a056402370b00b0054847f7adafls603173edb.0.-pod-prod-01-eu; Mon, 20
 Nov 2023 09:48:35 -0800 (PST)
X-Received: by 2002:a05:6402:345a:b0:542:d2c4:b423 with SMTP id l26-20020a056402345a00b00542d2c4b423mr76981edc.30.1700502514873;
        Mon, 20 Nov 2023 09:48:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502514; cv=none;
        d=google.com; s=arc-20160816;
        b=J2YrMW9cwBnZshLj/HPY5Y1NeLquXbezQUg5BvlkdVCeC59kZhKe8JsRJ78S/8RAkL
         9v7+SVRuAGg4NeEEqKfGxQLCiruUiCpgA+ON2UVikrw2immy/83E6hsexz21tTG3fQ7v
         qe4mMHZOpnr3jmVwfkLmNSYo4VJVDhQjbMVl7IFnImhwvslg9bQ38Shpd7NMytbnsZyd
         AkSizNwecWb5Ru93c/lPQ8Flnf5FdJHVCR0Sxzoj/cReu2SQRgfYVLevKsaQc3F5oEfU
         d2C38vG35XvlM8mPxa0DrDRFfPSIWu9vXqesRahatsjPoZnQuihepcW5rlFSjtWPs/Yf
         IRfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hhwH9Rj+7SlwckI0c6mMcIkIslfacxpde7X6neQ7UWA=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=Je76di/rS1amcZ3j+9SQxiFthIfsA4gS37n23sMYO8WaT00uCu4FvuOdbpNnI9ySgY
         YUkso/il1UThdieunpDvvQngXQsuSoqDPAEPG3enBLIbhO0r10pwL8AVPDnz1FK9M+TF
         L2YARuauhOm1VRp0GEObainj0oFNGahDfcSTs7IQU7ZdCP1D6liB5OdX4qUkvE5QoEF5
         qsP2TFt1iVAutQdLcKfYBsHTs6oGmJpwBKU6vfvJJMK2ITus1x0wte6FBaTt9O2UEpp9
         h57d2Sr3P5RXkZRPKFcQYG1od+UL2g+cpHwla/t+Fn5/UIYKWL0Zmhpj1PS59GlLUpZL
         o/hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tZ0IiLou;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b6 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-182.mta0.migadu.com (out-182.mta0.migadu.com. [2001:41d0:1004:224b::b6])
        by gmr-mx.google.com with ESMTPS id f8-20020a056402194800b0054359279646si354673edz.3.2023.11.20.09.48.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:48:34 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b6 as permitted sender) client-ip=2001:41d0:1004:224b::b6;
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
Subject: [PATCH v4 09/22] lib/stackdepot: rename next_pool_required to new_pool_required
Date: Mon, 20 Nov 2023 18:47:07 +0100
Message-Id: <fd7cd6c6eb250c13ec5d2009d75bb4ddd1470db9.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=tZ0IiLou;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::b6 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Rename next_pool_required to new_pool_required.

This a purely code readability change: the following patch will change
stack depot to store the pointer to the new pool in a separate variable,
and "new" seems like a more logical name.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 49 ++++++++++++++++++++++++------------------------
 1 file changed, 24 insertions(+), 25 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index b3af868627f4..a38661beab97 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -93,12 +93,11 @@ static size_t pool_offset;
 static DEFINE_RAW_SPINLOCK(pool_lock);
 /*
  * Stack depot tries to keep an extra pool allocated even before it runs out
- * of space in the currently used pool.
- * This flag marks that this next extra pool needs to be allocated and
- * initialized. It has the value 0 when either the next pool is not yet
- * initialized or the limit on the number of pools is reached.
+ * of space in the currently used pool. This flag marks whether this extra pool
+ * needs to be allocated. It has the value 0 when either an extra pool is not
+ * yet allocated or if the limit on the number of pools is reached.
  */
-static int next_pool_required = 1;
+static int new_pool_required = 1;
 
 static int __init disable_stack_depot(char *str)
 {
@@ -225,20 +224,20 @@ int stack_depot_init(void)
 }
 EXPORT_SYMBOL_GPL(stack_depot_init);
 
-/* Keeps the preallocated memory to be used for the next stack depot pool. */
-static void depot_keep_next_pool(void **prealloc)
+/* Keeps the preallocated memory to be used for a new stack depot pool. */
+static void depot_keep_new_pool(void **prealloc)
 {
 	/*
-	 * If the next pool is already saved or the maximum number of
+	 * If a new pool is already saved or the maximum number of
 	 * pools is reached, do not use the preallocated memory.
-	 * Access next_pool_required non-atomically, as there are no concurrent
+	 * Access new_pool_required non-atomically, as there are no concurrent
 	 * write accesses to this variable.
 	 */
-	if (!next_pool_required)
+	if (!new_pool_required)
 		return;
 
 	/*
-	 * Use the preallocated memory for the next pool
+	 * Use the preallocated memory for the new pool
 	 * as long as we do not exceed the maximum number of pools.
 	 */
 	if (pool_index + 1 < DEPOT_MAX_POOLS) {
@@ -247,13 +246,13 @@ static void depot_keep_next_pool(void **prealloc)
 	}
 
 	/*
-	 * At this point, either the next pool is kept or the maximum
+	 * At this point, either a new pool is kept or the maximum
 	 * number of pools is reached. In either case, take note that
 	 * keeping another pool is not required.
 	 * smp_store_release() pairs with smp_load_acquire() in
 	 * stack_depot_save().
 	 */
-	smp_store_release(&next_pool_required, 0);
+	smp_store_release(&new_pool_required, 0);
 }
 
 /* Updates references to the current and the next stack depot pools. */
@@ -268,7 +267,7 @@ static bool depot_update_pools(size_t required_size, void **prealloc)
 		}
 
 		/*
-		 * Move on to the next pool.
+		 * Move on to the new pool.
 		 * WRITE_ONCE() pairs with potential concurrent read in
 		 * stack_depot_fetch().
 		 */
@@ -277,12 +276,12 @@ static bool depot_update_pools(size_t required_size, void **prealloc)
 
 		/*
 		 * If the maximum number of pools is not reached, take note
-		 * that the next pool needs to be initialized.
+		 * that yet another new pool needs to be allocated.
 		 * smp_store_release() pairs with smp_load_acquire() in
 		 * stack_depot_save().
 		 */
 		if (pool_index + 1 < DEPOT_MAX_POOLS)
-			smp_store_release(&next_pool_required, 1);
+			smp_store_release(&new_pool_required, 1);
 	}
 
 	/* Check if the current pool is not yet allocated. */
@@ -293,9 +292,9 @@ static bool depot_update_pools(size_t required_size, void **prealloc)
 		return true;
 	}
 
-	/* Otherwise, try using the preallocated memory for the next pool. */
+	/* Otherwise, try using the preallocated memory for a new pool. */
 	if (*prealloc)
-		depot_keep_next_pool(prealloc);
+		depot_keep_new_pool(prealloc);
 	return true;
 }
 
@@ -306,7 +305,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	struct stack_record *stack;
 	size_t required_size = DEPOT_STACK_RECORD_SIZE;
 
-	/* Update current and next pools if required and possible. */
+	/* Update current and new pools if required and possible. */
 	if (!depot_update_pools(required_size, prealloc))
 		return NULL;
 
@@ -438,13 +437,13 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		goto exit;
 
 	/*
-	 * Check if another stack pool needs to be initialized. If so, allocate
-	 * the memory now - we won't be able to do that under the lock.
+	 * Check if another stack pool needs to be allocated. If so, allocate
+	 * the memory now: we won't be able to do that under the lock.
 	 *
 	 * smp_load_acquire() pairs with smp_store_release() in
-	 * depot_update_pools() and depot_keep_next_pool().
+	 * depot_update_pools() and depot_keep_new_pool().
 	 */
-	if (unlikely(can_alloc && smp_load_acquire(&next_pool_required))) {
+	if (unlikely(can_alloc && smp_load_acquire(&new_pool_required))) {
 		/*
 		 * Zero out zone modifiers, as we don't have specific zone
 		 * requirements. Keep the flags related to allocation in atomic
@@ -477,9 +476,9 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	} else if (prealloc) {
 		/*
 		 * Stack depot already contains this stack trace, but let's
-		 * keep the preallocated memory for the future.
+		 * keep the preallocated memory for future.
 		 */
-		depot_keep_next_pool(&prealloc);
+		depot_keep_new_pool(&prealloc);
 	}
 
 	raw_spin_unlock_irqrestore(&pool_lock, flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fd7cd6c6eb250c13ec5d2009d75bb4ddd1470db9.1700502145.git.andreyknvl%40google.com.
