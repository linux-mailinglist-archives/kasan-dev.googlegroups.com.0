Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQ4KUSWQMGQEQXFILMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 107B88317EC
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 12:02:28 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2cd0804c5e6sf40461991fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 03:02:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705575747; cv=pass;
        d=google.com; s=arc-20160816;
        b=kKHc1As1qnsjCH1r4qjdx5X4hrAiyR2JigOag1SX7AOqIvacY20xx/4hua5ko71GAt
         d8g5QjrCa5hiPnihghSEptum1gK1nUnGaseGzmF95ya9ivscVtdaW2zJx+qEH9F05d+q
         Bo7YYPRVLnRufoG1F6Gyq0/uWHEufgodU0tNhuWk2ppba06HAChTcZGiprMU0mbhuw/j
         j/Bibhki9STYu9o20Exxr0tqSN3k+/AY6GPiQNT+1IDE1pNDP2cnRTsHL/mH16dZ+9oB
         FMXKv7Qw5bP9HeZ4dtzhXGMaIsJX6CeKa4RiWN5tvFg2EERo1jz/Cm7e2QAeQuBCfFw3
         Az6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=JjCuezPVGjH5r3WWZ6GdUdkJwC3lNbwRtv/V1hxF/IM=;
        fh=NNXO9fNiyEQTfXuOASYqnj2AKA2ip/gcgrV5dvf5GXM=;
        b=kKR2l48nBP70hu1eM07wqGkK5mjqWHWFP+EOg+7u8tyBsPLv5plCxjxNviay18yak7
         BVilzY/ShraUvCcHYbmfYVgYm0Y5e7k303btnjYvaOIw8Ofxm/57w5Ntw/Ohv+raR/f9
         XMcM17H4LTbPah6Hr99YctfHDu3Blgw5doHiHs8rDJNDAZOAqVe0qKqIXJa2X3jDUZ95
         xTqqKYuJjYp9Cnnqti2UcdXF10ixiLPaGb3ZB5W0j56YSaZ6RZ0KHkhDoUsArQlKG5YI
         OL51bi3e7SsotyHDz5YD1G0gv8Fjx/K71xo9jNydbeKzItnihyQlIC9hakdH6DTbnFPk
         MEbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BB7QHhgl;
       spf=pass (google.com: domain of 3qawpzqukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3QAWpZQUKCSMDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705575747; x=1706180547; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=JjCuezPVGjH5r3WWZ6GdUdkJwC3lNbwRtv/V1hxF/IM=;
        b=v0osVMcu9hgMMeljz8v0YmJuRAJrsYgjQtsv3lDi7ttCG7TO3oJV4NXbVh+1lZqqMY
         SREEifU3RmXTDAUcCLGF98iUPoA2GXTjU0xpRd6XZrmgDIg+R9LxyUzvxhPPOGdP0GME
         XA9BoP4oZamqWdjrB+zc9Mn8QPTOqbMmWw9EuR3nvERLAorpdLGKDdLSfa8hW2Ni+iGl
         zGEjbBEL5oHN9xSfRGyeh8fLEsBAfplfX7YkHsdP7766w/KirQ/JMeqK6XTtmImPhPVZ
         SF4p5N+5oDFGbnjwtDk+qnjTkx/YNz/o/FKsEkrMSZwGIEqFx53l7suLnhvYj5Q8awzs
         7cAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705575747; x=1706180547;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JjCuezPVGjH5r3WWZ6GdUdkJwC3lNbwRtv/V1hxF/IM=;
        b=fnjkUsaxcmUJ9twjoAlgsplPasPqnO6wdpXEqDdzipNO9ozP+JobNtcLieCjgnZCsV
         fY3rgez9PdOIWdhFZ3wRwTiSDim9g3j1o/wQ+rCAdk4PcK0RvAJ6A0ptmhSiH1jctvoK
         m+hjd8M+/5gzaYsHgrqmCi4n6dES07IMhfBuLKF4Dcr2P3xWTYDnh/fuO20M1/YTcV06
         x1TjbHPUIi9osY3usEmJWdkieXLD/KFJvKBbCF6CemzBGc+/WCMSf1kJr1SB+o5rSNoF
         vZwn+JN/DYCENmBpAcezOUEPhaDEZ+UFoq8X5/IOiI8NcacfGx7RdcQ778ofkdyT5wu9
         tKUg==
X-Gm-Message-State: AOJu0Yz/7QtDWxdFV5nAuXMGCC3Ju07lwwoRU76fzuRbJ4Jc/CpXV562
	y8SrGS37Ukbj6WXCOENc4ziXvK7r1uITsqnlRIBnmnt02/8wDR9D
X-Google-Smtp-Source: AGHT+IGSeAp32vaWkoEud2wOYO3VR6cRtxNR5pl+OQJRyw6glfKLdcOUtebdssuKfQRpa4xF2pIc8Q==
X-Received: by 2002:a05:651c:200c:b0:2cc:eeea:9e8f with SMTP id s12-20020a05651c200c00b002cceeea9e8fmr402155ljo.13.1705575747402;
        Thu, 18 Jan 2024 03:02:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a594:0:b0:2cd:7dee:aa1b with SMTP id m20-20020a2ea594000000b002cd7deeaa1bls169176ljp.0.-pod-prod-05-eu;
 Thu, 18 Jan 2024 03:02:25 -0800 (PST)
X-Received: by 2002:a2e:b016:0:b0:2cd:4ecf:1aca with SMTP id y22-20020a2eb016000000b002cd4ecf1acamr390416ljk.42.1705575745222;
        Thu, 18 Jan 2024 03:02:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705575745; cv=none;
        d=google.com; s=arc-20160816;
        b=rnsQAAfUNg1UqV4SQnrLVIQeN3WkWYHPd08b/psfSIhxKfHIi+h8QG91VdQxlNyAGF
         BPSKP+E076thFeg6WdT6eaEpka4wdOpaT3ovsERL6nzdm4n8dC53J3h0ps0BxcMlPqkc
         5b30K5Oh0wSrfgu0AIV/H0WK1e7i3/xufeS70x1OeuOt6DbqFZnn5/o7F3cI/bX7UJLm
         IaTtrVD5kZJwXhfaXGOnC53RoYWS8wAh1XmSuNCihdQpabYpjAa1yk5DxXTk8NEs6v/T
         TrpnKEHBOiMtzmj9bcvIj7hwowAYndw9JBPq80eun+QnKkrlnDIX5Mun8+wwmCRQX/96
         AE7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=UKCbla7ykmCxZ5zRnAg5LQd/i5SeGGTvEB8R+tet9MU=;
        fh=NNXO9fNiyEQTfXuOASYqnj2AKA2ip/gcgrV5dvf5GXM=;
        b=mDd0V4Pho94eMGqX088bVeYtZP2FSy9eOodkd7F80ST1g81NvcKc9iv9El8AP1/+ME
         mxyGUXJ8V/VK45o4Kcl1MrnxslQWDrhDYjDWHs33L1ujrQZK9H03zZX5kUlde9Jt34jT
         qDaUfDiAwjmDlmwvRe3//ZQ/MMzm49Jac7qayO/rBXSyxBpl0CCjDDrjP/9JRTEjf5fv
         r+8Vuag+wz6qbBbuhXew5eK871Sr0pOydYlyMZtp9cE6rnN/O6oTxtQUn5GF5Li065jw
         d41RUQ42KuH8xzW6MKDiERC/aS6X1bpb3+zVg08aHuCj1cPUXJxJX1+flNWtDhfF8QBh
         74Kw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BB7QHhgl;
       spf=pass (google.com: domain of 3qawpzqukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3QAWpZQUKCSMDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id p17-20020a2e9ad1000000b002ccf31911ccsi514939ljj.8.2024.01.18.03.02.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Jan 2024 03:02:25 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qawpzqukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-557326932e5so6245164a12.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Jan 2024 03:02:25 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:9d7e:25fb:9605:2bef])
 (user=elver job=sendgmr) by 2002:a05:6402:370f:b0:559:dc85:8f4d with SMTP id
 ek15-20020a056402370f00b00559dc858f4dmr4715edb.6.1705575744719; Thu, 18 Jan
 2024 03:02:24 -0800 (PST)
Date: Thu, 18 Jan 2024 12:01:30 +0100
In-Reply-To: <20240118110216.2539519-1-elver@google.com>
Mime-Version: 1.0
References: <20240118110216.2539519-1-elver@google.com>
X-Mailer: git-send-email 2.43.0.381.gb435a96ce8-goog
Message-ID: <20240118110216.2539519-2-elver@google.com>
Subject: [PATCH 2/2] stackdepot: make fast paths lock-less again
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	Andi Kleen <ak@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=BB7QHhgl;       spf=pass
 (google.com: domain of 3qawpzqukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3QAWpZQUKCSMDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
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
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
---
v1 (change since RFC):
* Remove smp_mb() in find_stack() - there still exists a dependency
  chain from the rcu_dereference(), through read of the handle, to use
  of the handle to recompute the stack record pointer - and later
  accesses are therefore ordered through the dependency-chain.
* Use rcu_read_lock_sched_notrace() to avoid recursion, because
  stackdepot may be called through KMSAN anywhere.
* Fix and add some comments.
---
 lib/stackdepot.c | 322 +++++++++++++++++++++++++++++++----------------
 1 file changed, 211 insertions(+), 111 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 80a8ca24ccc8..5caa1f566553 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -22,8 +22,9 @@
 #include <linux/list.h>
 #include <linux/mm.h>
 #include <linux/mutex.h>
-#include <linux/percpu.h>
 #include <linux/printk.h>
+#include <linux/rculist.h>
+#include <linux/rcupdate.h>
 #include <linux/refcount.h>
 #include <linux/slab.h>
 #include <linux/spinlock.h>
@@ -68,12 +69,28 @@ union handle_parts {
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
@@ -113,8 +130,8 @@ static LIST_HEAD(free_stacks);
  * yet allocated or if the limit on the number of pools is reached.
  */
 static bool new_pool_required = true;
-/* Lock that protects the variables above. */
-static DEFINE_RWLOCK(pool_rwlock);
+/* The lock must be held when performing pool or freelist modifications. */
+static DEFINE_RAW_SPINLOCK(pool_lock);
 
 /* Statistics counters for debugfs. */
 enum depot_counter_id {
@@ -276,14 +293,15 @@ int stack_depot_init(void)
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
@@ -294,19 +312,36 @@ static void depot_init_pool(void *pool)
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
+		/*
+		 * Add to the freelist front to prioritize never-used entries:
+		 * required in case there are entries in the freelist, but their
+		 * RCU cookie still belongs to the current RCU grace period
+		 * (there can still be concurrent readers).
+		 */
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
@@ -329,17 +364,16 @@ static void depot_keep_new_pool(void **prealloc)
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
@@ -348,10 +382,9 @@ static bool depot_update_pools(void **prealloc)
 
 		/* Take note that we might need a new new_pool. */
 		if (pools_num < DEPOT_MAX_POOLS)
-			new_pool_required = true;
+			WRITE_ONCE(new_pool_required, true);
 
-		/* Try keeping the preallocated memory for new_pool. */
-		goto out_keep_prealloc;
+		return true;
 	}
 
 	/* Bail out if we reached the pool limit. */
@@ -368,12 +401,32 @@ static bool depot_update_pools(void **prealloc)
 	}
 
 	return false;
+}
+
+/* Try to find next free usable entry. */
+static struct stack_record *depot_pop_free(void)
+{
+	struct stack_record *stack;
 
-out_keep_prealloc:
-	/* Keep the preallocated memory for a new pool if required. */
-	if (*prealloc)
-		depot_keep_new_pool(prealloc);
-	return true;
+	lockdep_assert_held(&pool_lock);
+
+	if (list_empty(&free_stacks))
+		return NULL;
+
+	/*
+	 * We maintain the invariant that the elements in front are least
+	 * recently used, and are therefore more likely to be associated with an
+	 * RCU grace period in the past. Consequently it is sufficient to only
+	 * check the first entry.
+	 */
+	stack = list_first_entry(&free_stacks, struct stack_record, free_list);
+	if (stack->size && !poll_state_synchronize_rcu(stack->rcu_state))
+		return NULL;
+
+	list_del(&stack->free_list);
+	counters[DEPOT_COUNTER_FREELIST_SIZE]--;
+
+	return stack;
 }
 
 /* Allocates a new stack in a stack depot pool. */
@@ -382,20 +435,22 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 {
 	struct stack_record *stack;
 
-	lockdep_assert_held_write(&pool_rwlock);
+	lockdep_assert_held(&pool_lock);
 
-	/* Update current and new pools if required and possible. */
-	if (!depot_update_pools(prealloc))
+	/* This should already be checked by public API entry points. */
+	if (WARN_ON_ONCE(!size))
 		return NULL;
 
 	/* Check if we have a stack record to save the stack trace. */
-	if (list_empty(&free_stacks))
-		return NULL;
-
-	/* Get and unlink the first entry from the freelist. */
-	stack = list_first_entry(&free_stacks, struct stack_record, list);
-	list_del(&stack->list);
-	counters[DEPOT_COUNTER_FREELIST_SIZE]--;
+	stack = depot_pop_free();
+	if (!stack) {
+		/* No usable entries on the freelist - try to refill the freelist. */
+		if (!depot_try_init_pool(prealloc))
+			return NULL;
+		stack = depot_pop_free();
+		if (WARN_ON(!stack))
+			return NULL;
+	}
 
 	/* Limit number of saved frames to CONFIG_STACKDEPOT_MAX_FRAMES. */
 	if (size > CONFIG_STACKDEPOT_MAX_FRAMES)
@@ -421,37 +476,73 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 
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
+
+	raw_spin_lock_irqsave(&pool_lock, flags);
+	printk_deferred_enter();
 
-	list_add(&stack->list, &free_stacks);
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
@@ -479,22 +570,52 @@ int stackdepot_memcmp(const unsigned long *u1, const unsigned long *u2,
 
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
+	/*
+	 * Stack depot may be used from instrumentation that instruments RCU or
+	 * tracing itself; use variant that does not call into RCU and cannot be
+	 * traced.
+	 *
+	 * Note: Such use cases must take care when using refcounting to evict
+	 * unused entries, because the stack record free-then-reuse code paths
+	 * do call into RCU.
+	 */
+	rcu_read_lock_sched_notrace();
+
+	list_for_each_entry_rcu(stack, bucket, hash_list) {
+		if (stack->hash != hash || stack->size != size)
+			continue;
 
-	lockdep_assert_held(&pool_rwlock);
+		/*
+		 * This may race with depot_free_stack() accessing the freelist
+		 * management state unioned with @entries. The refcount is zero
+		 * in that case and the below refcount_inc_not_zero() will fail.
+		 */
+		if (data_race(stackdepot_memcmp(entries, stack->entries, size)))
+			continue;
 
-	list_for_each(pos, bucket) {
-		found = list_entry(pos, struct stack_record, list);
-		if (found->hash == hash &&
-		    found->size == size &&
-		    !stackdepot_memcmp(entries, found->entries, size))
-			return found;
+		/*
+		 * Try to increment refcount. If this succeeds, the stack record
+		 * is valid and has not yet been freed.
+		 *
+		 * If STACK_DEPOT_FLAG_GET is not used, it is undefined behavior
+		 * to then call stack_depot_put() later, and we can assume that
+		 * a stack record is never placed back on the freelist.
+		 */
+		if ((flags & STACK_DEPOT_FLAG_GET) && !refcount_inc_not_zero(&stack->count))
+			continue;
+
+		ret = stack;
+		break;
 	}
-	return NULL;
+
+	rcu_read_unlock_sched_notrace();
+
+	return ret;
 }
 
 depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
@@ -508,7 +629,6 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 	struct page *page = NULL;
 	void *prealloc = NULL;
 	bool can_alloc = depot_flags & STACK_DEPOT_FLAG_CAN_ALLOC;
-	bool need_alloc = false;
 	unsigned long flags;
 	u32 hash;
 
@@ -531,31 +651,16 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
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
@@ -569,31 +674,36 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
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
@@ -618,7 +728,6 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 			       unsigned long **entries)
 {
 	struct stack_record *stack;
-	unsigned long flags;
 
 	*entries = NULL;
 	/*
@@ -630,13 +739,13 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
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
@@ -646,29 +755,20 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
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
2.43.0.381.gb435a96ce8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240118110216.2539519-2-elver%40google.com.
