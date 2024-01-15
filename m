Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCHVSOWQMGQEFQLGXCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A93A82D5E3
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jan 2024 10:27:38 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4299130ad10sf1243081cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jan 2024 01:27:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705310857; cv=pass;
        d=google.com; s=arc-20160816;
        b=L/xBN2kulwwqZrOeohN0yrPVlddeY8yfqfsGmlMuEKEB2DwymlpJW3CjH3FnZ+dlVM
         tZIwA14srdHlWfizX+rFwh36vSbnkxleI61iyljd+dDBX2ghWe65xsUKJU0erhjXrUtL
         bhyNFkiGUz4/ZWmDlkYhLElVzZwZcKAXrrWhjtub4V6MAUJj1UqG4X8URDxbxCDr2k/q
         gtPo3mjcrfDD7eP/ugGvd1TA5ik4SAeAIEvcpRAdG8Kag9CZiFmVmuS6WngAATvS5B6d
         1nzoGPjr1LPcqnuoXxMdgLSlWr+Rps+ENjutojixxzXnBtdwhKphHIRH1gmIhk0ZPu8T
         aPrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Dn9jcRIW7eTGRdfwF1un4OpM8TJoekaX0yCS+BSOnwI=;
        fh=NNXO9fNiyEQTfXuOASYqnj2AKA2ip/gcgrV5dvf5GXM=;
        b=LYPz8p1ifS/8gGoHMJ4tVD8p9drrX7392kak/GTi6ZvjJMNeI/s2zstJI11NwxifwK
         ujCzMlieiLo222S+vKMKFdJHxhs1nePGtxvGyIEU8cjgMsQK4Dkr3Ibesn5u2eLjPhTo
         cR67ZJX2akxKypTVf3WmnszSoOjvPUreENWetWLL2KHYEUu7Vbwo1hSVBY2CZR7P6rLW
         zBjomuxHJpX+W6qCHhD2TJUploAive9rw/nVuruRCawwIJDY8UKRIUX5tK/+OkdW2Ted
         YRISUyqg9pQluUL/JOKLhow1y15qvay10g2lPOD1WgBrPgCDdN3MWE6dYjHas4gf+6/a
         uRFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=C1eelo8+;
       spf=pass (google.com: domain of 3h_qkzqukcuqkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3h_qkZQUKCUQkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705310857; x=1705915657; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Dn9jcRIW7eTGRdfwF1un4OpM8TJoekaX0yCS+BSOnwI=;
        b=t9RbbS5Mx6RctsZMD37D0Xsmvy8gFxrqidWgXd9z0mUsQDEaqGiNO48nL6QsxJZ+wm
         cMNL8pM9pbvw7PbgQH6xa6iExSSsSCdo/HPz5sbDg7RGzmxTXZ4ljWak9zuC+9jpxx5O
         q2rdIMyFqHJ045RxLGoitf+gTeWHBmRcBW7rD26s1SKCCeSCBRFeP8yusmV7v6W1/NWJ
         MRoJvB0PJBaNSiqbCqQ3Eo3bQ+nn4siciCKqI9z+w/57pxeTLk9jImcaiY88Cm2gQ7um
         eT77QW7H1xo7Bc3cyFYK/DZXIbdKDPrdrOZckjQG0Z9CMMyzjqEyvbgm+h79pjLqBmDl
         d0yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705310857; x=1705915657;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Dn9jcRIW7eTGRdfwF1un4OpM8TJoekaX0yCS+BSOnwI=;
        b=ZtUVd63Xqcd0eR5poRzqvfDEUX9u9P7B3wB+CgMY15Lp0wCV4vMwsMXuEpxI5gKXsd
         BANeCuLE4sCgFFdN6P4tUQxMWtFczhyYrtNGfc8FKszmLudNZchU0nhDns/Mxh+ZSN1d
         oTzWXRv5r1l0KyJz9shaxFzlQndEZEJI9qd4X0H9vdua8v3594b3V5hzD7uwkUsuAwEX
         IxCjIfeY3wRtqAfTxmUgaXg/cm5tPyfEWahsyUrarJndvpGNOd2HzBbTuuEp9XPnIocb
         UB46rxQhZ+Thr0pS7UOgh8UEu7LraBXxbFxXWJpCDxQeBsNHqp22D80ePB8x9Eek6vOL
         kvrA==
X-Gm-Message-State: AOJu0Ywssu2UniSQwOA3PUeuqNnOu2iZwwGxX2batRd6edVSiIB9kQ5x
	47Wpx2Myl8SqWMQQ3YZJuS0=
X-Google-Smtp-Source: AGHT+IEus8RvByhek9htZAe70wCn2GXdG4mrNSByXvphhfiAu5gqUv5igN9xKuBafjgUwTposFQZcg==
X-Received: by 2002:a05:622a:5187:b0:429:d2de:4018 with SMTP id ex7-20020a05622a518700b00429d2de4018mr580730qtb.9.1705310856743;
        Mon, 15 Jan 2024 01:27:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5d55:0:b0:429:ee90:bec3 with SMTP id g21-20020ac85d55000000b00429ee90bec3ls1109210qtx.2.-pod-prod-01-us;
 Mon, 15 Jan 2024 01:27:36 -0800 (PST)
X-Received: by 2002:a67:fc0a:0:b0:467:b08d:f469 with SMTP id o10-20020a67fc0a000000b00467b08df469mr2593642vsq.32.1705310855954;
        Mon, 15 Jan 2024 01:27:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705310855; cv=none;
        d=google.com; s=arc-20160816;
        b=r0fxqE2vgJ/yuxJ6PygBeyBjzVvCc5r61hGMvfVO2PRT9ymI6xDwMKq00j7FMGHj0a
         yLiPWELFHQBkVNPdlypPCefiEjhYUNsbFc06darapje6+FuJmt8NJHPPQYyR0lzZunoy
         38x2hMdq52PsVvgO9W332JLL3Y7IDPCh+GUMPJ93rY+CEOEkyoN8Xkz0jaxKe3oyFk63
         TL33gNiYDVp73cwI/CPLMPrfVulCrLxY0M80Ir0OpzV+lchLRym/OW7/sfsBFW0VcBRv
         hkLG0OW6LYksTXOLCUUjNsbx9b38CGir9HIdhtpWstcCa2uTkgWVjExpVgcoTSVdScVD
         QYuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=VgFgJUHhAfnFuFb40xwybJCT9olZ8luuCe0IuqSCqVE=;
        fh=NNXO9fNiyEQTfXuOASYqnj2AKA2ip/gcgrV5dvf5GXM=;
        b=h0VJwOqENi8/48Fpx0moMRm6RiAFA//MdLgaGb2h88rrVIL7vMIF+nm2xSgnEDm7wj
         x+ZNL/RQ3OQEJ7h2T+k8dm+W0pOAxM1kj+SO1/rQPWHHoUrnOPz+PbyUlawyrS2s4M4R
         s51TNe0kNAgjF2EG4DT8Gv5kV9/GsKufR3Us30IWFeM6mzRD/aRTTQ1Y5O1RZmu115YG
         sOQymYf/UxhfYV7qL5QokAexJ0XlAHNuiW8mIZphkhtjrd3yxgLR0JRfh1pBa42OnwKq
         s0ugYf4zkM4+G+BeQF2WY5QMETwJaQeBBQGPjqfaRpj4wC6S2gZ3P8Nd2S2E3D042NfI
         +l6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=C1eelo8+;
       spf=pass (google.com: domain of 3h_qkzqukcuqkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3h_qkZQUKCUQkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id az17-20020a056130039100b007cea807f1f9si645400uab.2.2024.01.15.01.27.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Jan 2024 01:27:35 -0800 (PST)
Received-SPF: pass (google.com: domain of 3h_qkzqukcuqkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dbf1c3816a3so6027872276.1
        for <kasan-dev@googlegroups.com>; Mon, 15 Jan 2024 01:27:35 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:38c7:85d7:36f7:e198])
 (user=elver job=sendgmr) by 2002:a05:6902:2388:b0:dbe:9f12:cfc6 with SMTP id
 dp8-20020a056902238800b00dbe9f12cfc6mr238101ybb.1.1705310855576; Mon, 15 Jan
 2024 01:27:35 -0800 (PST)
Date: Mon, 15 Jan 2024 10:27:19 +0100
In-Reply-To: <20240115092727.888096-1-elver@google.com>
Mime-Version: 1.0
References: <20240115092727.888096-1-elver@google.com>
X-Mailer: git-send-email 2.43.0.275.g3460e3d667-goog
Message-ID: <20240115092727.888096-2-elver@google.com>
Subject: [PATCH RFC 2/2] stackdepot: make fast paths lock-less again
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	Andi Kleen <ak@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=C1eelo8+;       spf=pass
 (google.com: domain of 3h_qkzqukcuqkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3h_qkZQUKCUQkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
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

With the introduction of the pool_rwlock (reader-writer lock), several
fast paths end up taking the pool_rwlock as readers. Furthermore,
stack_depot_put() unconditionally takes the pool_rwlock as a writer.

Despite allowing readers to make forward-progress concurrently,
reader-writer locks have inherent cache contention issues, which does
not scale well on systems with large CPU counts.

Rework the synchronization story of stack depot to again avoid taking
any locks in the fast paths. This is done by relying on RCU-protected
list traversal, and the NMI-safe subset of RCU to delay reuse of freed
stack records. See code comments for more details.

Along with the performance issues, this also fixes incorrect nesting of
rwlock within a raw_spinlock, given that stack depot should still be
usable from anywhere:

 | [ BUG: Invalid wait context ]
 | -----------------------------
 | swapper/0/1 is trying to lock:
 | ffffffff89869be8 (pool_rwlock){..--}-{3:3}, at: stack_depot_save_flags
 | other info that might help us debug this:
 | context-{5:5}
 | 2 locks held by swapper/0/1:
 |  #0: ffffffff89632440 (rcu_read_lock){....}-{1:3}, at: __queue_work
 |  #1: ffff888100092018 (&pool->lock){-.-.}-{2:2}, at: __queue_work  <-- raw_spin_lock

Stack depot usage stats are similar to the previous version after a
KASAN kernel boot:

 $ cat /sys/kernel/debug/stackdepot/stats
 pools: 838
 allocations: 29865
 frees: 6604
 in_use: 23261
 freelist_size: 1879

The number of pools is the same as previously. The freelist size is
minimally larger, but this may also be due to variance across system
boots. This shows that even though we do not eagerly wait for the next
RCU grace period (such as with synchronize_rcu() or call_rcu()) after
freeing a stack record - requiring depot_pop_free() to "poll" if an
entry may be used - new allocations are very likely to happen in later
RCU grace periods.

Fixes: 108be8def46e ("lib/stackdepot: allow users to evict stack traces")
Reported-by: Andi Kleen <ak@linux.intel.com>
Signed-off-by: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
---
 lib/stackdepot.c | 329 +++++++++++++++++++++++++++++++----------------
 1 file changed, 217 insertions(+), 112 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 80a8ca24ccc8..db174cc02d34 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -24,6 +24,8 @@
 #include <linux/mutex.h>
 #include <linux/percpu.h>
 #include <linux/printk.h>
+#include <linux/rculist.h>
+#include <linux/rcupdate.h>
 #include <linux/refcount.h>
 #include <linux/slab.h>
 #include <linux/spinlock.h>
@@ -68,12 +70,28 @@ union handle_parts {
 };
 
 struct stack_record {
-	struct list_head list;		/* Links in hash table or freelist */
+	struct list_head hash_list;	/* Links in the hash table */
 	u32 hash;			/* Hash in hash table */
 	u32 size;			/* Number of stored frames */
-	union handle_parts handle;
+	union handle_parts handle;	/* Constant after initialization */
 	refcount_t count;
-	unsigned long entries[CONFIG_STACKDEPOT_MAX_FRAMES];	/* Frames */
+	union {
+		unsigned long entries[CONFIG_STACKDEPOT_MAX_FRAMES];	/* Frames */
+		struct {
+			/*
+			 * An important invariant of the implementation is to
+			 * only place a stack record onto the freelist iff its
+			 * refcount is zero. Because stack records with a zero
+			 * refcount are never considered as valid, it is safe to
+			 * union @entries and freelist management state below.
+			 * Conversely, as soon as an entry is off the freelist
+			 * and its refcount becomes non-zero, the below must not
+			 * be accessed until being placed back on the freelist.
+			 */
+			struct list_head free_list;	/* Links in the freelist */
+			unsigned long rcu_state;	/* RCU cookie */
+		};
+	};
 };
 
 #define DEPOT_STACK_RECORD_SIZE \
@@ -113,8 +131,8 @@ static LIST_HEAD(free_stacks);
  * yet allocated or if the limit on the number of pools is reached.
  */
 static bool new_pool_required = true;
-/* Lock that protects the variables above. */
-static DEFINE_RWLOCK(pool_rwlock);
+/* The lock must be held when performing pool or free list modifications. */
+static DEFINE_RAW_SPINLOCK(pool_lock);
 
 /* Statistics counters for debugfs. */
 enum depot_counter_id {
@@ -276,14 +294,15 @@ int stack_depot_init(void)
 }
 EXPORT_SYMBOL_GPL(stack_depot_init);
 
-/* Initializes a stack depol pool. */
+/*
+ * Initializes new stack depot @pool, release all its entries to the freelist,
+ * and update the list of pools.
+ */
 static void depot_init_pool(void *pool)
 {
 	int offset;
 
-	lockdep_assert_held_write(&pool_rwlock);
-
-	WARN_ON(!list_empty(&free_stacks));
+	lockdep_assert_held(&pool_lock);
 
 	/* Initialize handles and link stack records into the freelist. */
 	for (offset = 0; offset <= DEPOT_POOL_SIZE - DEPOT_STACK_RECORD_SIZE;
@@ -294,19 +313,31 @@ static void depot_init_pool(void *pool)
 		stack->handle.offset = offset >> DEPOT_STACK_ALIGN;
 		stack->handle.extra = 0;
 
-		list_add(&stack->list, &free_stacks);
+		/*
+		 * Stack traces of size 0 are never saved, and we can simply use
+		 * the size field as an indicator if this is a new unused stack
+		 * record in the freelist.
+		 */
+		stack->size = 0;
+
+		INIT_LIST_HEAD(&stack->hash_list);
+		/* Add to the freelist front to prioritize never-used entries. */
+		list_add(&stack->free_list, &free_stacks);
 		counters[DEPOT_COUNTER_FREELIST_SIZE]++;
 	}
 
 	/* Save reference to the pool to be used by depot_fetch_stack(). */
 	stack_pools[pools_num] = pool;
-	pools_num++;
+
+	/* Pairs with concurrent READ_ONCE() in depot_fetch_stack(). */
+	WRITE_ONCE(pools_num, pools_num + 1);
+	ASSERT_EXCLUSIVE_WRITER(pools_num);
 }
 
 /* Keeps the preallocated memory to be used for a new stack depot pool. */
 static void depot_keep_new_pool(void **prealloc)
 {
-	lockdep_assert_held_write(&pool_rwlock);
+	lockdep_assert_held(&pool_lock);
 
 	/*
 	 * If a new pool is already saved or the maximum number of
@@ -329,17 +360,16 @@ static void depot_keep_new_pool(void **prealloc)
 	 * number of pools is reached. In either case, take note that
 	 * keeping another pool is not required.
 	 */
-	new_pool_required = false;
+	WRITE_ONCE(new_pool_required, false);
 }
 
-/* Updates references to the current and the next stack depot pools. */
-static bool depot_update_pools(void **prealloc)
+/*
+ * Try to initialize a new stack depot pool from either a previous or the
+ * current pre-allocation, and release all its entries to the freelist.
+ */
+static bool depot_try_init_pool(void **prealloc)
 {
-	lockdep_assert_held_write(&pool_rwlock);
-
-	/* Check if we still have objects in the freelist. */
-	if (!list_empty(&free_stacks))
-		goto out_keep_prealloc;
+	lockdep_assert_held(&pool_lock);
 
 	/* Check if we have a new pool saved and use it. */
 	if (new_pool) {
@@ -348,10 +378,9 @@ static bool depot_update_pools(void **prealloc)
 
 		/* Take note that we might need a new new_pool. */
 		if (pools_num < DEPOT_MAX_POOLS)
-			new_pool_required = true;
+			WRITE_ONCE(new_pool_required, true);
 
-		/* Try keeping the preallocated memory for new_pool. */
-		goto out_keep_prealloc;
+		return true;
 	}
 
 	/* Bail out if we reached the pool limit. */
@@ -368,35 +397,53 @@ static bool depot_update_pools(void **prealloc)
 	}
 
 	return false;
-
-out_keep_prealloc:
-	/* Keep the preallocated memory for a new pool if required. */
-	if (*prealloc)
-		depot_keep_new_pool(prealloc);
-	return true;
 }
 
-/* Allocates a new stack in a stack depot pool. */
-static struct stack_record *
-depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
+/* Try to find next free usable entry. */
+static struct stack_record *depot_pop_free(void)
 {
 	struct stack_record *stack;
 
-	lockdep_assert_held_write(&pool_rwlock);
+	lockdep_assert_held(&pool_lock);
 
-	/* Update current and new pools if required and possible. */
-	if (!depot_update_pools(prealloc))
+	if (list_empty(&free_stacks))
 		return NULL;
 
-	/* Check if we have a stack record to save the stack trace. */
-	if (list_empty(&free_stacks))
+	/*
+	 * We maintain the invariant that the elements in front are least
+	 * recently used, and are therefore more likely to be associated with an
+	 * RCU grace period in the past. Consequently it is sufficient to only
+	 * check the first entry.
+	 */
+	stack = list_first_entry(&free_stacks, struct stack_record, free_list);
+	if (stack->size && !poll_state_synchronize_rcu(stack->rcu_state))
 		return NULL;
 
-	/* Get and unlink the first entry from the freelist. */
-	stack = list_first_entry(&free_stacks, struct stack_record, list);
-	list_del(&stack->list);
+	list_del(&stack->free_list);
 	counters[DEPOT_COUNTER_FREELIST_SIZE]--;
 
+	return stack;
+}
+
+/* Allocates a new stack in a stack depot pool. */
+static struct stack_record *
+depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
+{
+	struct stack_record *stack;
+
+	lockdep_assert_held(&pool_lock);
+
+	/* Check if we have a stack record to save the stack trace. */
+	stack = depot_pop_free();
+	if (!stack) {
+		/* No usable entries on the freelist - try to refill the freelist. */
+		if (!depot_try_init_pool(prealloc))
+			return NULL;
+		stack = depot_pop_free();
+		if (WARN_ON(!stack))
+			return NULL;
+	}
+
 	/* Limit number of saved frames to CONFIG_STACKDEPOT_MAX_FRAMES. */
 	if (size > CONFIG_STACKDEPOT_MAX_FRAMES)
 		size = CONFIG_STACKDEPOT_MAX_FRAMES;
@@ -421,37 +468,73 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 
 static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 {
+	const int pools_num_cached = READ_ONCE(pools_num);
 	union handle_parts parts = { .handle = handle };
 	void *pool;
 	size_t offset = parts.offset << DEPOT_STACK_ALIGN;
 	struct stack_record *stack;
 
-	lockdep_assert_held(&pool_rwlock);
+	lockdep_assert_not_held(&pool_lock);
 
-	if (parts.pool_index > pools_num) {
+	if (parts.pool_index > pools_num_cached) {
 		WARN(1, "pool index %d out of bounds (%d) for stack id %08x\n",
-		     parts.pool_index, pools_num, handle);
+		     parts.pool_index, pools_num_cached, handle);
 		return NULL;
 	}
 
 	pool = stack_pools[parts.pool_index];
-	if (!pool)
+	if (WARN_ON(!pool))
 		return NULL;
 
 	stack = pool + offset;
+	if (WARN_ON(!refcount_read(&stack->count)))
+		return NULL;
+
 	return stack;
 }
 
 /* Links stack into the freelist. */
 static void depot_free_stack(struct stack_record *stack)
 {
-	lockdep_assert_held_write(&pool_rwlock);
+	unsigned long flags;
+
+	lockdep_assert_not_held(&pool_lock);
 
-	list_add(&stack->list, &free_stacks);
+	raw_spin_lock_irqsave(&pool_lock, flags);
+	printk_deferred_enter();
+
+	/*
+	 * Remove the entry from the hash list. Concurrent list traversal may
+	 * still observe the entry, but since the refcount is zero, this entry
+	 * will no longer be considered as valid.
+	 */
+	list_del_rcu(&stack->hash_list);
+
+	/*
+	 * Due to being used from constrained contexts such as the allocators,
+	 * NMI, or even RCU itself, stack depot cannot rely on primitives that
+	 * would sleep (such as synchronize_rcu()) or recursively call into
+	 * stack depot again (such as call_rcu()).
+	 *
+	 * Instead, get an RCU cookie, so that we can ensure this entry isn't
+	 * moved onto another list until the next grace period, and concurrent
+	 * RCU list traversal remains safe.
+	 */
+	stack->rcu_state = get_state_synchronize_rcu();
+
+	/*
+	 * Add the entry to the freelist tail, so that older entries are
+	 * considered first - their RCU cookie is more likely to no longer be
+	 * associated with the current grace period.
+	 */
+	list_add_tail(&stack->free_list, &free_stacks);
 
 	counters[DEPOT_COUNTER_FREELIST_SIZE]++;
 	counters[DEPOT_COUNTER_FREES]++;
 	counters[DEPOT_COUNTER_INUSE]--;
+
+	printk_deferred_exit();
+	raw_spin_unlock_irqrestore(&pool_lock, flags);
 }
 
 /* Calculates the hash for a stack. */
@@ -479,22 +562,65 @@ int stackdepot_memcmp(const unsigned long *u1, const unsigned long *u2,
 
 /* Finds a stack in a bucket of the hash table. */
 static inline struct stack_record *find_stack(struct list_head *bucket,
-					     unsigned long *entries, int size,
-					     u32 hash)
+					      unsigned long *entries, int size,
+					      u32 hash, depot_flags_t flags)
 {
-	struct list_head *pos;
-	struct stack_record *found;
+	struct stack_record *stack, *ret = NULL;
+
+	rcu_read_lock();
 
-	lockdep_assert_held(&pool_rwlock);
+	list_for_each_entry_rcu(stack, bucket, hash_list) {
+		if (stack->hash != hash || stack->size != size)
+			continue;
 
-	list_for_each(pos, bucket) {
-		found = list_entry(pos, struct stack_record, list);
-		if (found->hash == hash &&
-		    found->size == size &&
-		    !stackdepot_memcmp(entries, found->entries, size))
-			return found;
+		/*
+		 * This may race with depot_free_stack() accessing the freelist
+		 * management state unioned with @entries. The refcount is zero
+		 * in that case and the below refcount_inc_not_zero() will fail.
+		 */
+		if (data_race(stackdepot_memcmp(entries, stack->entries, size)))
+			continue;
+
+		/*
+		 * Try to increment refcount. If this succeeds, the stack record
+		 * is valid and has not yet been freed.
+		 *
+		 * If STACK_DEPOT_FLAG_GET is not used, it is undefined behavior
+		 * to then call stack_depot_put() later, and we can assume that
+		 * a stack record is never placed back on the freelist.
+		 */
+		if (flags & STACK_DEPOT_FLAG_GET) {
+			if (!refcount_inc_not_zero(&stack->count))
+				continue;
+			smp_mb__after_atomic();
+		} else {
+			/*
+			 * Pairs with the release implied by list_add_rcu() to
+			 * turn the list-pointer access into an acquire; as-is
+			 * it only provides dependency-ordering implied by
+			 * READ_ONCE().
+			 *
+			 * Normally this is not needed, if we were to continue
+			 * using the stack_record pointer only. But, the pointer
+			 * returned here is not actually used to lookup entries.
+			 * Instead, the handle is returned, from which a pointer
+			 * may then be reconstructed in depot_fetch_stack().
+			 *
+			 * Therefore, it is required to upgrade the ordering
+			 * from dependency-ordering only to at least acquire to
+			 * be able to use the handle as another reference to the
+			 * same stack record.
+			 */
+			smp_mb();
+		}
+
+		ret = stack;
+		break;
 	}
-	return NULL;
+
+	rcu_read_unlock();
+
+	return ret;
 }
 
 depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
@@ -508,7 +634,6 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 	struct page *page = NULL;
 	void *prealloc = NULL;
 	bool can_alloc = depot_flags & STACK_DEPOT_FLAG_CAN_ALLOC;
-	bool need_alloc = false;
 	unsigned long flags;
 	u32 hash;
 
@@ -531,31 +656,16 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 	hash = hash_stack(entries, nr_entries);
 	bucket = &stack_table[hash & stack_hash_mask];
 
-	read_lock_irqsave(&pool_rwlock, flags);
-	printk_deferred_enter();
-
-	/* Fast path: look the stack trace up without full locking. */
-	found = find_stack(bucket, entries, nr_entries, hash);
-	if (found) {
-		if (depot_flags & STACK_DEPOT_FLAG_GET)
-			refcount_inc(&found->count);
-		printk_deferred_exit();
-		read_unlock_irqrestore(&pool_rwlock, flags);
+	/* Fast path: look the stack trace up without locking. */
+	found = find_stack(bucket, entries, nr_entries, hash, depot_flags);
+	if (found)
 		goto exit;
-	}
-
-	/* Take note if another stack pool needs to be allocated. */
-	if (new_pool_required)
-		need_alloc = true;
-
-	printk_deferred_exit();
-	read_unlock_irqrestore(&pool_rwlock, flags);
 
 	/*
 	 * Allocate memory for a new pool if required now:
 	 * we won't be able to do that under the lock.
 	 */
-	if (unlikely(can_alloc && need_alloc)) {
+	if (unlikely(can_alloc && READ_ONCE(new_pool_required))) {
 		/*
 		 * Zero out zone modifiers, as we don't have specific zone
 		 * requirements. Keep the flags related to allocation in atomic
@@ -569,31 +679,36 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 			prealloc = page_address(page);
 	}
 
-	write_lock_irqsave(&pool_rwlock, flags);
+	raw_spin_lock_irqsave(&pool_lock, flags);
 	printk_deferred_enter();
 
-	found = find_stack(bucket, entries, nr_entries, hash);
+	/* Try to find again, to avoid concurrently inserting duplicates. */
+	found = find_stack(bucket, entries, nr_entries, hash, depot_flags);
 	if (!found) {
 		struct stack_record *new =
 			depot_alloc_stack(entries, nr_entries, hash, &prealloc);
 
 		if (new) {
-			list_add(&new->list, bucket);
+			/*
+			 * This releases the stack record into the bucket and
+			 * makes it visible to readers in find_stack().
+			 */
+			list_add_rcu(&new->hash_list, bucket);
 			found = new;
 		}
-	} else {
-		if (depot_flags & STACK_DEPOT_FLAG_GET)
-			refcount_inc(&found->count);
+	}
+
+	if (prealloc) {
 		/*
-		 * Stack depot already contains this stack trace, but let's
-		 * keep the preallocated memory for future.
+		 * Either stack depot already contains this stack trace, or
+		 * depot_alloc_stack() did not consume the preallocated memory.
+		 * Try to keep the preallocated memory for future.
 		 */
-		if (prealloc)
-			depot_keep_new_pool(&prealloc);
+		depot_keep_new_pool(&prealloc);
 	}
 
 	printk_deferred_exit();
-	write_unlock_irqrestore(&pool_rwlock, flags);
+	raw_spin_unlock_irqrestore(&pool_lock, flags);
 exit:
 	if (prealloc) {
 		/* Stack depot didn't use this memory, free it. */
@@ -618,7 +733,6 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 			       unsigned long **entries)
 {
 	struct stack_record *stack;
-	unsigned long flags;
 
 	*entries = NULL;
 	/*
@@ -630,13 +744,13 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 	if (!handle || stack_depot_disabled)
 		return 0;
 
-	read_lock_irqsave(&pool_rwlock, flags);
-	printk_deferred_enter();
-
 	stack = depot_fetch_stack(handle);
-
-	printk_deferred_exit();
-	read_unlock_irqrestore(&pool_rwlock, flags);
+	/*
+	 * Should never be NULL, otherwise this is a use-after-put (or just a
+	 * corrupt handle).
+	 */
+	if (WARN(!stack, "corrupt handle or use after stack_depot_put()"))
+		return 0;
 
 	*entries = stack->entries;
 	return stack->size;
@@ -646,29 +760,20 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
 void stack_depot_put(depot_stack_handle_t handle)
 {
 	struct stack_record *stack;
-	unsigned long flags;
 
 	if (!handle || stack_depot_disabled)
 		return;
 
-	write_lock_irqsave(&pool_rwlock, flags);
-	printk_deferred_enter();
-
 	stack = depot_fetch_stack(handle);
-	if (WARN_ON(!stack))
-		goto out;
-
-	if (refcount_dec_and_test(&stack->count)) {
-		/* Unlink stack from the hash table. */
-		list_del(&stack->list);
+	/*
+	 * Should always be able to find the stack record, otherwise this is an
+	 * unbalanced put attempt (or corrupt handle).
+	 */
+	if (WARN(!stack, "corrupt handle or unbalanced stack_depot_put()"))
+		return;
 
-		/* Free stack. */
+	if (refcount_dec_and_test(&stack->count))
 		depot_free_stack(stack);
-	}
-
-out:
-	printk_deferred_exit();
-	write_unlock_irqrestore(&pool_rwlock, flags);
 }
 EXPORT_SYMBOL_GPL(stack_depot_put);
 
-- 
2.43.0.275.g3460e3d667-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240115092727.888096-2-elver%40google.com.
