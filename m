Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXGFXKWQMGQECYCTTLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 79AB6836CBF
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Jan 2024 18:16:14 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-40e5f548313sf30514145e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jan 2024 09:16:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705943774; cv=pass;
        d=google.com; s=arc-20160816;
        b=iLeuzLxuP9g7qz9bHmVwbnsfZd79JBVOxsSRbp7BCXy4o/4IemUnho0v+JUChvNOT7
         z+vAGqIH+QRuOjXe3Z9/fpgOzAUqnvBzGK3wzYKcqjXb5acP1ckY/u0vJQ8xS0fCmHCn
         Y2CliSrlnbt1e0IAXEbn6M99g/TbFtGmxi3TTwRAcXEKiOuyylsmZuc+Q9U7YAgSPppR
         OKHaiOs7mQxj/gXGMV+X7kMmJYDRR8W0oZByc9PRJliljtZzeUjtvNtyIXHPV68+/S8v
         FN9q1CqbcslNmHU4eh+wOljvGH4pF++Dn4XpS7TZ0q5lfGTH7gp5Vtvd20xcsTyh2KrR
         2HYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=lfI5fqh8TbHj/AYk7FZPhSGVYg9GWTVXfO1e8L96A94=;
        fh=Q/d4OiL4ksp/XPthBLW72yTulI/JdIQ/Oi/Sg+RVXvU=;
        b=TPdRGfctHyGN3QDaSyX/dLD19Msg/WF5yMbbS2KHTytWHDA0PblrMgnJun9OtRoRt1
         ZHN4zotXV27aCF0ohgFUMdTeTI+XTBilHODW16PsU8QCHe9LY5N8avVkDhjAwQw7FeJh
         FaLp3H6+cJXVrUwOlH7HcVGGokB1LJsSljH3bXBBphUVc1FB42BWbyxuRmaPoMNVg1NS
         DuA7Bg39C3ZsPH1u6n/yKimcVmCQ+EWPNUky0I9/JbsvDGRdo0n67HOEGmr2rD4aaGcj
         f9qCya9iv8MgGV5kwzwpGxpqqHdRunZvANWeNnOMQAmpzVJsvPaDXDPQ64+a5JXIo7zD
         DkAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HKZJSLXk;
       spf=pass (google.com: domain of 32qkuzqukcq8t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=32qKuZQUKCQ8t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705943774; x=1706548574; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lfI5fqh8TbHj/AYk7FZPhSGVYg9GWTVXfO1e8L96A94=;
        b=SA0yXcyeJCtFXUw726VEDe6bIJl3ojnQkrYg32fOTbxS/pYV62EbipTr6boY16tkY6
         rBJAai6i38F3JxQ+uHfvErxE9ZO/qEs8b5jUXsZ6FlKPUN6/1nK6y3BB1s9GrBsEQ9kn
         wvDLluy4aypKXWgF8WaPOvwXmsY0acVArO/9wsMgbbYfAT8psJqB9OPZXUzs01gQT6+d
         kdyVqre7cyw31Ca/bJ7nBCmYisKDA80JskikRYp2Z8fDPzNUeySETVu49msqCJoWGWeP
         X7eCjxdZwFzlaVuWL0txZctzYRm1HsbcBe5jNvnxLdhPdphDtXL57HVPulCIsBCmgD4V
         YZXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705943774; x=1706548574;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=lfI5fqh8TbHj/AYk7FZPhSGVYg9GWTVXfO1e8L96A94=;
        b=UUhmN1aQmoEM3NnpFwP2dniPgvifxzfsdDe5urb3UBJJq8uRYR7eJvgUbSJdz06o0y
         4PPuW7kGo6HMvmGkp/eRya4BhywiJcBlvnpg81QLVK7t04ZHLRJPODj+s4ln0u0pBitQ
         9ojL/Lle5HqNxFwowGK7dUNqTX8POQj3L7RnCO9VHL6DRz7Y3MYMYzZ5vZ26DqeQ/m2e
         Lsxtn/VW6j0gvf7LJlYv02/REfV8jEpxEok4J3mQowxIUnl+SmNfFydfRtFp8brAW0/T
         pZeph//qZWec/PTf3LqbIO/XO6w3GlSxuc2ME37SZqyi4m4ZIDQ+AX18Q0qklhEzd/Sr
         FTQg==
X-Gm-Message-State: AOJu0Yz7A09+cGyQiiK3eB+ne6uel5Gx3PKsN/vNUcymFd1GaqF0eU4V
	WGpPlMVu2Iu4COLKK7BIuzIIK54TE7vjhJLT5WnvKr+CIonBlo4O
X-Google-Smtp-Source: AGHT+IFh6XJ52IHix6J4aSZv4cI6YOeq/8/HOZFPNXvuXAAeA5q8+xkvdgHgKMJNVN/YaSlYH2BgJw==
X-Received: by 2002:a05:600c:2e07:b0:40e:8eea:312c with SMTP id o7-20020a05600c2e0700b0040e8eea312cmr2315168wmf.74.1705943772993;
        Mon, 22 Jan 2024 09:16:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5490:b0:40e:af43:5107 with SMTP id
 iv16-20020a05600c549000b0040eaf435107ls344556wmb.0.-pod-prod-06-eu; Mon, 22
 Jan 2024 09:16:11 -0800 (PST)
X-Received: by 2002:a1c:7708:0:b0:40e:863e:2f16 with SMTP id t8-20020a1c7708000000b0040e863e2f16mr2222409wmi.128.1705943770925;
        Mon, 22 Jan 2024 09:16:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705943770; cv=none;
        d=google.com; s=arc-20160816;
        b=MKBsp14l3Tn5644j5H343KXWKzuJtkW0K2NPibjM/4GmKDw0yo28B7NMXIVY4ZTUr1
         usULWv9dc60SQbu1QDc8TkEtq+robar7pNzz3P64gJoFUGVKMldV7fGBLXmS4JP5/VKb
         1ot+O8859AUoqyvPBtHNP9prBxQCVXFfiolbVLfA57ryKOfx5WATTOus+N8Gpgh+QWfZ
         LNjCJuWPkAbdeu+wnatqvhlpjKiCtE8ekoNQx+/EBJSBNRXiQaiocovNXGizNw5+KfUk
         qPFVwnSxmCIEL4k1lvVg5s0guarnIAAZk3KCgMdwx9vZyrCZZ3DDPm2y9VGfsJ7gtT4w
         ACtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=IeBiO5JIOcbB3aarK4M/MV2q2unRSMAULj52Ob3ZR74=;
        fh=Q/d4OiL4ksp/XPthBLW72yTulI/JdIQ/Oi/Sg+RVXvU=;
        b=EO6OtQbU6zfGyPqtRzD/cWsdDLszo2SqbKNxG4P+HXRjEqauaMR3fHWtYxtmhRgHxF
         Bl+yotDD2z3Ykb9UBDISytqIM9H2KN5g+/P9e2eVhRqbPJUErhVdUDtfCKnaHRm6cP5o
         K3w4u2q7LK7jv6bmtCxi72rjMrijMEciatESrR2Y7L9Bdrlv25wzAdJOOV/9mRwZFGKZ
         G7Q2r6S0dX/eOvMMf9qC3Nt3YY2WeXdCH0+LM4u+VU84AVJWs/n+mf8F4ORTXD0iWqWI
         QtOVYearG8IYzjIMf036L7+dnKsZL/XRnYMGUeAJOGxsMOx4iPhGno/v19hO5KhIH8Ux
         mXDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HKZJSLXk;
       spf=pass (google.com: domain of 32qkuzqukcq8t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=32qKuZQUKCQ8t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id g11-20020a05600c4ecb00b0040e9e2c0cb7si242984wmq.0.2024.01.22.09.16.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Jan 2024 09:16:10 -0800 (PST)
Received-SPF: pass (google.com: domain of 32qkuzqukcq8t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-54554ea191bso2087946a12.2
        for <kasan-dev@googlegroups.com>; Mon, 22 Jan 2024 09:16:10 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:511d:f6cb:99a8:ac0d])
 (user=elver job=sendgmr) by 2002:a05:6402:4004:b0:55a:6821:7753 with SMTP id
 d4-20020a056402400400b0055a68217753mr992eda.1.1705943770543; Mon, 22 Jan 2024
 09:16:10 -0800 (PST)
Date: Mon, 22 Jan 2024 18:11:30 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.43.0.429.g432eaa2c6b-goog
Message-ID: <20240122171215.319440-2-elver@google.com>
Subject: [RFC PATCH] stackdepot: use variable size records for non-evictable entries
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=HKZJSLXk;       spf=pass
 (google.com: domain of 32qkuzqukcq8t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=32qKuZQUKCQ8t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
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

Sending this out as an early RFC.

We're stilling mulling over what to do with generic KASAN, because stack
depot eviction support was only added due to concern of too much memory
usage.

If this general approach makes sense, then I'd be in favour of just
reverting all the KASAN-generic eviction patches and leaving KASAN-tag
as the only user of evictions.

Thoughts?

---
 lib/stackdepot.c | 163 +++++++++++++++++++++++++----------------------
 1 file changed, 88 insertions(+), 75 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 5caa1f566553..726002d2ac09 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -93,9 +93,6 @@ struct stack_record {
 	};
 };
 
-#define DEPOT_STACK_RECORD_SIZE \
-	ALIGN(sizeof(struct stack_record), 1 << DEPOT_STACK_ALIGN)
-
 static bool stack_depot_disabled;
 static bool __stack_depot_early_init_requested __initdata = IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT);
 static bool __stack_depot_early_init_passed __initdata;
@@ -121,6 +118,8 @@ static void *stack_pools[DEPOT_MAX_POOLS];
 static void *new_pool;
 /* Number of pools in stack_pools. */
 static int pools_num;
+/* Offset to the unused space in the currently used pool. */
+static size_t pool_offset = DEPOT_POOL_SIZE;
 /* Freelist of stack records within stack_pools. */
 static LIST_HEAD(free_stacks);
 /*
@@ -294,48 +293,44 @@ int stack_depot_init(void)
 EXPORT_SYMBOL_GPL(stack_depot_init);
 
 /*
- * Initializes new stack depot @pool, release all its entries to the freelist,
- * and update the list of pools.
+ * Initializes new stack pool, and update the list of pools.
  */
-static void depot_init_pool(void *pool)
+static bool depot_init_pool(void **prealloc)
 {
-	int offset;
+	void *pool = NULL;
 
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
+	if (new_pool) {
+		/* We have a new pool saved, use it. */
+		pool = new_pool;
+		new_pool = NULL;
 
-		INIT_LIST_HEAD(&stack->hash_list);
-		/*
-		 * Add to the freelist front to prioritize never-used entries:
-		 * required in case there are entries in the freelist, but their
-		 * RCU cookie still belongs to the current RCU grace period
-		 * (there can still be concurrent readers).
-		 */
-		list_add(&stack->free_list, &free_stacks);
-		counters[DEPOT_COUNTER_FREELIST_SIZE]++;
+		/* Take note that we might need a new new_pool. */
+		if (pools_num < DEPOT_MAX_POOLS)
+			WRITE_ONCE(new_pool_required, true);
+	} else if (unlikely(pools_num >= DEPOT_MAX_POOLS)) {
+		/* Bail out if we reached the pool limit. */
+		WARN_ONCE(1, "Stack depot reached limit capacity");
+	} else if (*prealloc) {
+		/* We have preallocated memory, use it. */
+		pool = *prealloc;
+		*prealloc = NULL;
 	}
 
+	if (!pool)
+		return false;
+
 	/* Save reference to the pool to be used by depot_fetch_stack(). */
 	stack_pools[pools_num] = pool;
 
 	/* Pairs with concurrent READ_ONCE() in depot_fetch_stack(). */
 	WRITE_ONCE(pools_num, pools_num + 1);
 	ASSERT_EXCLUSIVE_WRITER(pools_num);
+
+	pool_offset = 0;
+
+	return true;
 }
 
 /* Keeps the preallocated memory to be used for a new stack depot pool. */
@@ -368,39 +363,40 @@ static void depot_keep_new_pool(void **prealloc)
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
@@ -420,7 +416,7 @@ static struct stack_record *depot_pop_free(void)
 	 * check the first entry.
 	 */
 	stack = list_first_entry(&free_stacks, struct stack_record, free_list);
-	if (stack->size && !poll_state_synchronize_rcu(stack->rcu_state))
+	if (!poll_state_synchronize_rcu(stack->rcu_state))
 		return NULL;
 
 	list_del(&stack->free_list);
@@ -429,45 +425,62 @@ static struct stack_record *depot_pop_free(void)
 	return stack;
 }
 
+static inline size_t depot_stack_record_size(struct stack_record *s, size_t nr_entries)
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
+	stack->size = nr_entries;
+	/* stack->handle is already filled in by depot_pop_free_pool(). */
 	refcount_set(&stack->count, 1);
-	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
+	memcpy(stack->entries, entries, flex_array_size(stack, entries, nr_entries));
 
 	/*
 	 * Let KMSAN know the stored stack record is initialized. This shall
 	 * prevent false positive reports if instrumented code accesses it.
 	 */
-	kmsan_unpoison_memory(stack, DEPOT_STACK_RECORD_SIZE);
+	kmsan_unpoison_memory(stack, record_size);
 
 	counters[DEPOT_COUNTER_ALLOCS]++;
 	counters[DEPOT_COUNTER_INUSE]++;
@@ -681,7 +694,7 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240122171215.319440-2-elver%40google.com.
