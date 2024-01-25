Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZO4ZCWQMGQEJJYBU3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id 06B0483BDCD
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jan 2024 10:48:23 +0100 (CET)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-6029c85922dsf29395027b3.3
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jan 2024 01:48:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706176102; cv=pass;
        d=google.com; s=arc-20160816;
        b=qDQoBWHnEA/iRcwKqrbUKem38mPHRQ+UXYk+gAc6hS5XPLPGsv4MtNCWSFLyx+NdwV
         zsTS25IsJurvJ+d5DVoUNw2gnJ6iBhczdeW2iQCjSyMxKsvxDuiI5Xk4EUx7xbnVVqH/
         1K/Awwl7gFArAK+Y1E13R5Xted4ykQlJpRLmJZ9kq9GFYwXezTJvdS1HQydcuBvgMvPS
         yI5HTZ+YkdLSyHuLLrjqCEP13VRdXkM9HgpLN3gxGAYo26JDdhhSR/RrOBnpJ1z4zeAg
         RXyFpsWJ9HqZQRtFJ2GuLg2zfV8q6n0nLk6mJ3puhhuFP4vPebBq/gINz0ED1ANrMr9z
         de+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=wLB2cvtW9D8ySLh6YBTVg4iVe3SWauVnwToiiSmJ/X0=;
        fh=Q6WTJ5ZnjiuB6HF3Kna6PPHtjylj1os0kvM6d8ajbeE=;
        b=MUgKgxkPlAxMUcdSbD49FPZA9C64EAue6wZ99zKGspdp+1RDXpP/asx0QjH7w5sPPN
         /46NDMBR5MiKPrI0Avse6JjsvBAKTvVXLvkeRGMIORYAXong154lnhrHmAr26Gw7ufpo
         kVMdmkWyecyKpkpfBjUwPkrGf+NlI00tAhwDx6ya6tswdjbSHXnJsYooT58Th5lfelhb
         Zy3trLj7wAc+EwEvTIjYMYCONQ3VVGyefORtR72KYHl9n6udWvFaq4vFLnCZaj4nobLt
         RLePwG99WCa4NtVuDcfyVDqLVZ4WHdZVVcs7tzJZyVKrQnqVpuWw8DD7s0KWjaJynUjJ
         vKmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zfv6CAh7;
       spf=pass (google.com: domain of 3zc6yzqukcb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3ZC6yZQUKCb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706176102; x=1706780902; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wLB2cvtW9D8ySLh6YBTVg4iVe3SWauVnwToiiSmJ/X0=;
        b=nW1OD+NohZalNA20JqWUEsLxpzCIIettzkIiUbtgnjTAXie4YSnIvobYuX8ATO81mH
         NG/+AFlOupj/Udd5R13ZMj1Pkq0gniwimZH5rX3aIau3VgffNIAdeHwi1BaZ70le93K9
         9m+Y7rV5n1spvJ6KaN4IPK3oDYR6HB+9Og9RoUPZ8XyxRvl/Hl/Iy3TIcjPE5EDb0Hpd
         ndVvP9axs0a4ndAZ+vgz+XgVH/nPXTDQNPwbavciYngxz3BwflsQZU5uj8CMZwxU1Ivg
         UUxjUtyGTCbg5xhtr3/JPEpkouiOpXngeebON87BtjgnqZJw+HoCYcQK2wA9PAe/3AJj
         Ztbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706176102; x=1706780902;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wLB2cvtW9D8ySLh6YBTVg4iVe3SWauVnwToiiSmJ/X0=;
        b=st+G8m3inqH3Zt8SUeV5riXbOHei2X9sNC42pKG/iPn5hXJqu+xw+RjEaYdzcfIPUU
         glQzkDL9aYH4/QtWB1RyepvOU2Zkk2N2t5RVMsRQgjdTF53bC6TVyrKMGx7300ASve3a
         50wAlF/PiyOWG2vmydoMkh4Akk5aWsD4eGIay7uAADSgVs0mbOecYxKg3olBeZIDcSpk
         OrbSZHcYhPi9TiudYGUR51LHVrp37M3MA1OLDOTkTFCKn7M5V4pYM740hoxKJAkfVLCk
         K20pQZiFDs2Z9YpDxW5H94F8pCBJITZ7OEG9WVV3HnRvAW967yvNmO/9Yq9khy1xC94X
         lZug==
X-Gm-Message-State: AOJu0YwqhyQQDHkH1ezx7C2Zo1XnwMuhCCcP3JH1O7GztRZPAD2F7FQw
	3C4yAQpj7KLSOZqWtCtZmApb2fC6awFCIGV7nqzmeLtTGdthkGCR
X-Google-Smtp-Source: AGHT+IFtGcDn0ID0N7elAEQP2wrVoy7XJA5MqhW39xphDW9hEALq28fJIuefxeqaEAQtFynld9wojQ==
X-Received: by 2002:a81:a157:0:b0:5ff:8a97:d59 with SMTP id y84-20020a81a157000000b005ff8a970d59mr405914ywg.57.1706176101780;
        Thu, 25 Jan 2024 01:48:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b345:0:b0:681:551c:1348 with SMTP id a5-20020a0cb345000000b00681551c1348ls4051493qvf.2.-pod-prod-08-us;
 Thu, 25 Jan 2024 01:48:20 -0800 (PST)
X-Received: by 2002:a05:6214:224d:b0:681:95a5:4ece with SMTP id c13-20020a056214224d00b0068195a54ecemr701239qvc.105.1706176100652;
        Thu, 25 Jan 2024 01:48:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706176100; cv=none;
        d=google.com; s=arc-20160816;
        b=s5W8rJWSDvCYQKgqQYixgIAsZW4ydJidF/eg2Gl5AohMa61hY3bygpn6+faugUpVTs
         BzWNrWp2HwzYixXyy0S+HQ9avcz6UjaFZ6KzZ7HPxn4v4JhSEE9/dtBziuo2kufAWri2
         rSi2UeLXstCV0s6Ji3kfhtHa4tgbvTriIp/1wbfJ0zGcW/jWKkRF8dA4AW6tDu6q4nxM
         gMUgWgfo3L99bljab0y8H017VgNeKnBblppcifkQgSAV/2NFyERisg4cGZyZOj59qoeA
         Kc0VloKFNNHftzZdNsnwbRoBwKZKalxeO64Npx5bq6wp1ZwpK4cA3OYXP0arzgwfEe3Q
         rndw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=LcyZJBErh32WdhxOYCRWNuYkcavusvnIBLghtfalcmI=;
        fh=Q6WTJ5ZnjiuB6HF3Kna6PPHtjylj1os0kvM6d8ajbeE=;
        b=LvK3WKUkzUAUVGElQlWeeT5sy3/a/uBIyA+a+iKN01HHbsgBHxAJkRbIngCBkwadAz
         iyDx+tQQU1ICPCxS5+2V+L6OEZjBkNtAkO0ildXTac12Ippie/h85IPjZO2lcpZZL5P9
         siiNyyRq1rAOS7Y85NxrFvRrcOrmDwG7O7tq59eLtEglL6zE9B3AJLXL027NpyH1L9AX
         wSAoWK8kUqqiJ0UgPg9jqC/mYse/bvy2FY+eIfJOtN9/koSx6t4VwhMm+UKCn4LuM11a
         ngrQxyAmoH+Jju40TiCE7s9zxRqqidZMh8+XkrPcD7lfmA4UuZyj5m8JJFk3iObuHTZp
         R1jQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zfv6CAh7;
       spf=pass (google.com: domain of 3zc6yzqukcb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3ZC6yZQUKCb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id n6-20020a0cfbc6000000b006817d101957si858178qvp.3.2024.01.25.01.48.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Jan 2024 01:48:20 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zc6yzqukcb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-602aa6d987cso19563767b3.2
        for <kasan-dev@googlegroups.com>; Thu, 25 Jan 2024 01:48:20 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:57d7:c308:70aa:3dee])
 (user=elver job=sendgmr) by 2002:a81:7905:0:b0:5ff:a62d:e2a with SMTP id
 u5-20020a817905000000b005ffa62d0e2amr229769ywc.4.1706176100355; Thu, 25 Jan
 2024 01:48:20 -0800 (PST)
Date: Thu, 25 Jan 2024 10:47:42 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.43.0.429.g432eaa2c6b-goog
Message-ID: <20240125094815.2041933-1-elver@google.com>
Subject: [PATCH 1/2] stackdepot: use variable size records for non-evictable entries
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=zfv6CAh7;       spf=pass
 (google.com: domain of 3zc6yzqukcb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3ZC6yZQUKCb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

With the introduction of stack depot evictions, each stack record is now
fixed size, so that future reuse after an eviction can safely store
differently sized stack traces. In all cases that do not make use of
evictions, this wastes lots of space.

Fix it by re-introducing variable size stack records (up to the max
allowed size) for entries that will never be evicted. We know if an
entry will never be evicted if the flag STACK_DEPOT_FLAG_GET is not
provided, since a later stack_depot_put() attempt is undefined behavior.

With my current kernel config that enables KASAN and also SLUB owner tracking,
I observe (after a kernel boot) a whopping reduction of 296 stack depot pools,
which translates into 4736 KiB saved. The savings here are from SLUB owner
tracking only, because KASAN generic mode still uses refcounting.

Before:

  pools: 893
  allocations: 29841
  frees: 6524
  in_use: 23317
  freelist_size: 3454

After:

  pools: 597
  allocations: 29657
  frees: 6425
  in_use: 23232
  freelist_size: 3493

Fixes: 108be8def46e ("lib/stackdepot: allow users to evict stack traces")
Signed-off-by: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
---
v1 (since RFC):
* Get rid of new_pool_required to simplify the code.
* Warn on attempts to switch a non-refcounted entry to refcounting.
* Typos.
---
 include/linux/poison.h |   3 +
 lib/stackdepot.c       | 212 +++++++++++++++++++++--------------------
 2 files changed, 113 insertions(+), 102 deletions(-)

diff --git a/include/linux/poison.h b/include/linux/poison.h
index 27a7dad17eef..1f0ee2459f2a 100644
--- a/include/linux/poison.h
+++ b/include/linux/poison.h
@@ -92,4 +92,7 @@
 /********** VFS **********/
 #define VFS_PTR_POISON ((void *)(0xF5 + POISON_POINTER_DELTA))
 
+/********** lib/stackdepot.c **********/
+#define STACK_DEPOT_POISON ((void *)(0xD390 + POISON_POINTER_DELTA))
+
 #endif
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 5caa1f566553..1b0d948a053c 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -22,6 +22,7 @@
 #include <linux/list.h>
 #include <linux/mm.h>
 #include <linux/mutex.h>
+#include <linux/poison.h>
 #include <linux/printk.h>
 #include <linux/rculist.h>
 #include <linux/rcupdate.h>
@@ -93,9 +94,6 @@ struct stack_record {
 	};
 };
 
-#define DEPOT_STACK_RECORD_SIZE \
-	ALIGN(sizeof(struct stack_record), 1 << DEPOT_STACK_ALIGN)
-
 static bool stack_depot_disabled;
 static bool __stack_depot_early_init_requested __initdata = IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT);
 static bool __stack_depot_early_init_passed __initdata;
@@ -121,15 +119,10 @@ static void *stack_pools[DEPOT_MAX_POOLS];
 static void *new_pool;
 /* Number of pools in stack_pools. */
 static int pools_num;
+/* Offset to the unused space in the currently used pool. */
+static size_t pool_offset = DEPOT_POOL_SIZE;
 /* Freelist of stack records within stack_pools. */
 static LIST_HEAD(free_stacks);
-/*
- * Stack depot tries to keep an extra pool allocated even before it runs out
- * of space in the currently used pool. This flag marks whether this extra pool
- * needs to be allocated. It has the value 0 when either an extra pool is not
- * yet allocated or if the limit on the number of pools is reached.
- */
-static bool new_pool_required = true;
 /* The lock must be held when performing pool or freelist modifications. */
 static DEFINE_RAW_SPINLOCK(pool_lock);
 
@@ -294,48 +287,52 @@ int stack_depot_init(void)
 EXPORT_SYMBOL_GPL(stack_depot_init);
 
 /*
- * Initializes new stack depot @pool, release all its entries to the freelist,
- * and update the list of pools.
+ * Initializes new stack pool, and updates the list of pools.
  */
-static void depot_init_pool(void *pool)
+static bool depot_init_pool(void **prealloc)
 {
-	int offset;
-
 	lockdep_assert_held(&pool_lock);
 
-	/* Initialize handles and link stack records into the freelist. */
-	for (offset = 0; offset <= DEPOT_POOL_SIZE - DEPOT_STACK_RECORD_SIZE;
-	     offset += DEPOT_STACK_RECORD_SIZE) {
-		struct stack_record *stack = pool + offset;
-
-		stack->handle.pool_index = pools_num;
-		stack->handle.offset = offset >> DEPOT_STACK_ALIGN;
-		stack->handle.extra = 0;
-
-		/*
-		 * Stack traces of size 0 are never saved, and we can simply use
-		 * the size field as an indicator if this is a new unused stack
-		 * record in the freelist.
-		 */
-		stack->size = 0;
+	if (unlikely(pools_num >= DEPOT_MAX_POOLS)) {
+		/* Bail out if we reached the pool limit. */
+		WARN_ON_ONCE(pools_num > DEPOT_MAX_POOLS); /* should never happen */
+		WARN_ON_ONCE(!new_pool); /* to avoid unnecessary pre-allocation */
+		WARN_ONCE(1, "Stack depot reached limit capacity");
+		return false;
+	}
 
-		INIT_LIST_HEAD(&stack->hash_list);
-		/*
-		 * Add to the freelist front to prioritize never-used entries:
-		 * required in case there are entries in the freelist, but their
-		 * RCU cookie still belongs to the current RCU grace period
-		 * (there can still be concurrent readers).
-		 */
-		list_add(&stack->free_list, &free_stacks);
-		counters[DEPOT_COUNTER_FREELIST_SIZE]++;
+	if (!new_pool && *prealloc) {
+		/* We have preallocated memory, use it. */
+		WRITE_ONCE(new_pool, *prealloc);
+		*prealloc = NULL;
 	}
 
+	if (!new_pool)
+		return false; /* new_pool and *prealloc are NULL */
+
 	/* Save reference to the pool to be used by depot_fetch_stack(). */
-	stack_pools[pools_num] = pool;
+	stack_pools[pools_num] = new_pool;
+
+	/*
+	 * Stack depot tries to keep an extra pool allocated even before it runs
+	 * out of space in the currently used pool.
+	 *
+	 * To indicate that a new preallocation is needed new_pool is reset to
+	 * NULL; do not reset to NULL if we have reached the maximum number of
+	 * pools.
+	 */
+	if (pools_num < DEPOT_MAX_POOLS)
+		WRITE_ONCE(new_pool, NULL);
+	else
+		WRITE_ONCE(new_pool, STACK_DEPOT_POISON);
 
 	/* Pairs with concurrent READ_ONCE() in depot_fetch_stack(). */
 	WRITE_ONCE(pools_num, pools_num + 1);
 	ASSERT_EXCLUSIVE_WRITER(pools_num);
+
+	pool_offset = 0;
+
+	return true;
 }
 
 /* Keeps the preallocated memory to be used for a new stack depot pool. */
@@ -347,60 +344,48 @@ static void depot_keep_new_pool(void **prealloc)
 	 * If a new pool is already saved or the maximum number of
 	 * pools is reached, do not use the preallocated memory.
 	 */
-	if (!new_pool_required)
+	if (new_pool)
 		return;
 
-	/*
-	 * Use the preallocated memory for the new pool
-	 * as long as we do not exceed the maximum number of pools.
-	 */
-	if (pools_num < DEPOT_MAX_POOLS) {
-		new_pool = *prealloc;
-		*prealloc = NULL;
-	}
-
-	/*
-	 * At this point, either a new pool is kept or the maximum
-	 * number of pools is reached. In either case, take note that
-	 * keeping another pool is not required.
-	 */
-	WRITE_ONCE(new_pool_required, false);
+	WRITE_ONCE(new_pool, *prealloc);
+	*prealloc = NULL;
 }
 
 /*
- * Try to initialize a new stack depot pool from either a previous or the
- * current pre-allocation, and release all its entries to the freelist.
+ * Try to initialize a new stack record from the current pool, a cached pool, or
+ * the current pre-allocation.
  */
-static bool depot_try_init_pool(void **prealloc)
+static struct stack_record *depot_pop_free_pool(void **prealloc, size_t size)
 {
+	struct stack_record *stack;
+	void *current_pool;
+	u32 pool_index;
+
 	lockdep_assert_held(&pool_lock);
 
-	/* Check if we have a new pool saved and use it. */
-	if (new_pool) {
-		depot_init_pool(new_pool);
-		new_pool = NULL;
+	if (pool_offset + size > DEPOT_POOL_SIZE) {
+		if (!depot_init_pool(prealloc))
+			return NULL;
+	}
 
-		/* Take note that we might need a new new_pool. */
-		if (pools_num < DEPOT_MAX_POOLS)
-			WRITE_ONCE(new_pool_required, true);
+	if (WARN_ON_ONCE(pools_num < 1))
+		return NULL;
+	pool_index = pools_num - 1;
+	current_pool = stack_pools[pool_index];
+	if (WARN_ON_ONCE(!current_pool))
+		return NULL;
 
-		return true;
-	}
+	stack = current_pool + pool_offset;
 
-	/* Bail out if we reached the pool limit. */
-	if (unlikely(pools_num >= DEPOT_MAX_POOLS)) {
-		WARN_ONCE(1, "Stack depot reached limit capacity");
-		return false;
-	}
+	/* Pre-initialize handle once. */
+	stack->handle.pool_index = pool_index;
+	stack->handle.offset = pool_offset >> DEPOT_STACK_ALIGN;
+	stack->handle.extra = 0;
+	INIT_LIST_HEAD(&stack->hash_list);
 
-	/* Check if we have preallocated memory and use it. */
-	if (*prealloc) {
-		depot_init_pool(*prealloc);
-		*prealloc = NULL;
-		return true;
-	}
+	pool_offset += size;
 
-	return false;
+	return stack;
 }
 
 /* Try to find next free usable entry. */
@@ -420,7 +405,7 @@ static struct stack_record *depot_pop_free(void)
 	 * check the first entry.
 	 */
 	stack = list_first_entry(&free_stacks, struct stack_record, free_list);
-	if (stack->size && !poll_state_synchronize_rcu(stack->rcu_state))
+	if (!poll_state_synchronize_rcu(stack->rcu_state))
 		return NULL;
 
 	list_del(&stack->free_list);
@@ -429,45 +414,68 @@ static struct stack_record *depot_pop_free(void)
 	return stack;
 }
 
+static inline size_t depot_stack_record_size(struct stack_record *s, unsigned int nr_entries)
+{
+	const size_t used = flex_array_size(s, entries, nr_entries);
+	const size_t unused = sizeof(s->entries) - used;
+
+	WARN_ON_ONCE(sizeof(s->entries) < used);
+
+	return ALIGN(sizeof(struct stack_record) - unused, 1 << DEPOT_STACK_ALIGN);
+}
+
 /* Allocates a new stack in a stack depot pool. */
 static struct stack_record *
-depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
+depot_alloc_stack(unsigned long *entries, int nr_entries, u32 hash, depot_flags_t flags, void **prealloc)
 {
-	struct stack_record *stack;
+	struct stack_record *stack = NULL;
+	size_t record_size;
 
 	lockdep_assert_held(&pool_lock);
 
 	/* This should already be checked by public API entry points. */
-	if (WARN_ON_ONCE(!size))
+	if (WARN_ON_ONCE(!nr_entries))
 		return NULL;
 
-	/* Check if we have a stack record to save the stack trace. */
-	stack = depot_pop_free();
-	if (!stack) {
-		/* No usable entries on the freelist - try to refill the freelist. */
-		if (!depot_try_init_pool(prealloc))
-			return NULL;
+	/* Limit number of saved frames to CONFIG_STACKDEPOT_MAX_FRAMES. */
+	if (nr_entries > CONFIG_STACKDEPOT_MAX_FRAMES)
+		nr_entries = CONFIG_STACKDEPOT_MAX_FRAMES;
+
+	if (flags & STACK_DEPOT_FLAG_GET) {
+		/*
+		 * Evictable entries have to allocate the max. size so they may
+		 * safely be re-used by differently sized allocations.
+		 */
+		record_size = depot_stack_record_size(stack, CONFIG_STACKDEPOT_MAX_FRAMES);
 		stack = depot_pop_free();
-		if (WARN_ON(!stack))
-			return NULL;
+	} else {
+		record_size = depot_stack_record_size(stack, nr_entries);
 	}
 
-	/* Limit number of saved frames to CONFIG_STACKDEPOT_MAX_FRAMES. */
-	if (size > CONFIG_STACKDEPOT_MAX_FRAMES)
-		size = CONFIG_STACKDEPOT_MAX_FRAMES;
+	if (!stack) {
+		stack = depot_pop_free_pool(prealloc, record_size);
+		if (!stack)
+			return NULL;
+	}
 
 	/* Save the stack trace. */
 	stack->hash = hash;
-	stack->size = size;
-	/* stack->handle is already filled in by depot_init_pool(). */
-	refcount_set(&stack->count, 1);
-	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
+	stack->size = nr_entries;
+	/* stack->handle is already filled in by depot_pop_free_pool(). */
+	memcpy(stack->entries, entries, flex_array_size(stack, entries, nr_entries));
+
+	if (flags & STACK_DEPOT_FLAG_GET) {
+		refcount_set(&stack->count, 1);
+	} else {
+		/* Warn on attempts to switch to refcounting this entry. */
+		refcount_set(&stack->count, REFCOUNT_SATURATED);
+	}
 
 	/*
 	 * Let KMSAN know the stored stack record is initialized. This shall
 	 * prevent false positive reports if instrumented code accesses it.
 	 */
-	kmsan_unpoison_memory(stack, DEPOT_STACK_RECORD_SIZE);
+	kmsan_unpoison_memory(stack, record_size);
 
 	counters[DEPOT_COUNTER_ALLOCS]++;
 	counters[DEPOT_COUNTER_INUSE]++;
@@ -660,7 +668,7 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 	 * Allocate memory for a new pool if required now:
 	 * we won't be able to do that under the lock.
 	 */
-	if (unlikely(can_alloc && READ_ONCE(new_pool_required))) {
+	if (unlikely(can_alloc && !READ_ONCE(new_pool))) {
 		/*
 		 * Zero out zone modifiers, as we don't have specific zone
 		 * requirements. Keep the flags related to allocation in atomic
@@ -681,7 +689,7 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 	found = find_stack(bucket, entries, nr_entries, hash, depot_flags);
 	if (!found) {
 		struct stack_record *new =
-			depot_alloc_stack(entries, nr_entries, hash, &prealloc);
+			depot_alloc_stack(entries, nr_entries, hash, depot_flags, &prealloc);
 
 		if (new) {
 			/*
-- 
2.43.0.429.g432eaa2c6b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240125094815.2041933-1-elver%40google.com.
