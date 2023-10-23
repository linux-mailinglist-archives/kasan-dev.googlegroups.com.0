Return-Path: <kasan-dev+bncBAABBJ543KUQMGQEH3JLWBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 02BC87D3C55
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:24:09 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-53dfe3af1b9sf2259991a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:24:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698078248; cv=pass;
        d=google.com; s=arc-20160816;
        b=0GA3gb5aVu+NngE6an9dSOh3sY0p+jZUPJhc7OqeegMjKu8jf/P2zOKtqHVHduFfqL
         eVdOn6b5Z6XRyZ/PbBmYiv+AzcUElYrF7LWhly7CUR0IT8WQ4W5/ECMp86UtDDqEivDg
         WZGwCuvhKjPlwxMv5ExmKNjDKE4KGfudGCKPJvJ1xs4OOvWiu9RzmgdamRucPRXhTNkr
         nZgUSRuPYIMP9fKyk3PWyUxKhbGwoi4FIEZ9nPJgM30Yj7SwcfmqqIpS8116XrstXB7L
         OEPI5H8YHBLqVLhgvW+H2W0Ug8kkSA7HLzXBw73aws2L7JSSPx/vN2OuM1lmmLpjNao6
         vniQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=yuXovkX4aDWBmpPJce0ik4bAtnKNdoIrG4VnS7D43Ps=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=IKDE2vg68Xp05v7cNIZ0FJXXWsa6ljZVF7f7akL04lGQgJ5YnVD8IkcHjbCkjsnuOT
         MNQZBWGiCbv6EG8QBZuX7qYgFkMJJyASpPatGTiuncL5Tm1nS11+BdhILCOHjMv1BncT
         NW0vyZxEXi9j7smYy3m6AJjEXXe28b+5VnKLAP3Zu0Fl/cG6UAmZZ0fA5h3j860oBttm
         //Myx547k82l5Bo3pdveuUrNQbQ6jOLMOZvlGXil+95dQzMTf2IjFALCY/I90FLdEYLC
         ikeNF/XxzJdXN6sBkPH1Y7oVe/lU/TjZIZhrAD2Zs1ROn2cnkj0mLhuS7DWlTn9FMyKz
         b79Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=d8BAggel;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.197 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698078248; x=1698683048; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yuXovkX4aDWBmpPJce0ik4bAtnKNdoIrG4VnS7D43Ps=;
        b=kVSO1sJADxVa8eeotSbyqLm8qYh6aH6vf+tOohDRVXqVX23XpVdUYYag2iWid/llPq
         /gTwVlKnIeom76ccor1dyNKtGK2ARNFXL56a09u6kYcseg37eEsrO11EoNTbQ99HWP8S
         VVp0nfUvvOb9qlr95U9XT4tQnGlxq36q04qRAOCB+vJe9oEe+Cv7o7j1bluT9DaiEnbN
         rOTmMQshpRc4S4+IUCmQDatsnRTGvPMYUCRLFwRqMVL/1T0V4gydIKM+F1JzzTYtSrbL
         00pqfOYPZAZt+et7z30AkcwpHJxo7ell6e3JJ6jD4WpQlzbnMQksBQEoRrxv0YYLaEuU
         bpPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698078248; x=1698683048;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yuXovkX4aDWBmpPJce0ik4bAtnKNdoIrG4VnS7D43Ps=;
        b=DhTUElxsLOBZv93jxOnvQEZB155MNGuZEPkSxD2It8EuDn4rs+usj8iUqBFIOg5GM2
         SNM4DuOnklW0bpKdkmn/ylnnM6C/kFk/H/foMTyDDgBHW9GRX8Uu1mZOr35xzb3bjkBl
         zJP2ix4EwQMO+J9T3XWYJr0e2bW0IdLKPtBgBfpxNu4/yg6XMJAA93GzP1f6w+2y5bVp
         7d9Nm4iN95iuIJdhg870gvfgxPesBNwLyAmY4VFree2iSrraRRihBzE9xz9XD1KNjA2m
         wPj5D27gyPcwoNcsgtv30S/f9Pu+KtJSTafjpYe4DZVi1JluINq3KgyGeGyQOf9qkTnu
         CLcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyeM/HVAh2El/KTUmCO2Y2/J+bMIlyuGEFevsf5qPVgarHU0v8D
	HDj7y5U/C1HQQceNrmRnUE0=
X-Google-Smtp-Source: AGHT+IHjHoIXpOeAX8Pg9TkLM3/CE0Tf7K10MOqQg8kAn4YcS+t9X0VNQ5i85jY0o4uWCpeea5FkeA==
X-Received: by 2002:a05:6402:430d:b0:53f:8c61:ee50 with SMTP id m13-20020a056402430d00b0053f8c61ee50mr9284309edc.29.1698078247841;
        Mon, 23 Oct 2023 09:24:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:f28:b0:53d:b3c3:2112 with SMTP id
 i40-20020a0564020f2800b0053db3c32112ls112699eda.2.-pod-prod-01-eu; Mon, 23
 Oct 2023 09:24:06 -0700 (PDT)
X-Received: by 2002:a17:907:9487:b0:9bf:20e0:bfe9 with SMTP id dm7-20020a170907948700b009bf20e0bfe9mr8817452ejc.15.1698078246579;
        Mon, 23 Oct 2023 09:24:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698078246; cv=none;
        d=google.com; s=arc-20160816;
        b=OrbnRrDVAVVynrpjlN0L31TtVBw4r9BtAKA/cz+AbqXDbQdoPTbn/LfcpLCY4Tj4jX
         GWzRyCMbdWwDOvqdQkENBDhtJD6x4H+QHDlggbZDHNc2gIz6OlOrAEM+Spxs460mm4RP
         ydUJS3m5XG2/Sn3mYjnRSNnnQrHKLE20Fcnzw5YANJCisHRtNYNxGxDzg8TLFHGUlNrP
         EGJRqfwbGVEUHSlTXjo+982wBHcDx3jWBA++hlWEsZ47uUbpJMqQQlrF4aBw11HFJuCj
         /0c2TmYZrKvY97bmfthzL+05qcPJ6///WfVbp+upxu61sFziFUAsqs50+KZJ+q7tERMW
         QF8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=p8Hgl8kIxqRiPg7P/caKlN6EZe6EuOrMJBszDGSf5JA=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=dUEXmUzBRiO5aCTq4ktkFrU1lhM9Kj89hZDmuvqvagHvaMc0lYu26MPZzfaNpNIhdO
         Nk+CTrSM6Q0NzqHNIFdJDYxl5Npo9/jbHxjNDvfPyV+pUtG2HNu+By38j8f7PeGsu7y+
         IG7qdP6Ndp2paBw6koQaKOXzN8cRLzMmnQywxXr9JggFTh2G3noJUkVsQ2AbJO077Aqs
         BwniktDcT7alp8nvn5ZoO3u2zZwszAzbsWu3V4KhlDj3Yexxu9yI/Bo9vlQVnuHQcMCE
         Yg9vU1DpZcJZHGhbT3ihz4ZoPKPYouut3Aq5pYGfRuWK20vA0A/o4rXxM3SUvV6S4ae2
         r6KQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=d8BAggel;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.197 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-197.mta1.migadu.com (out-197.mta1.migadu.com. [95.215.58.197])
        by gmr-mx.google.com with ESMTPS id b23-20020a170906d11700b009ae3e884341si292003ejz.0.2023.10.23.09.24.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Oct 2023 09:24:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.197 as permitted sender) client-ip=95.215.58.197;
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
Subject: [PATCH v3 11/19] lib/stackdepot: use read/write lock
Date: Mon, 23 Oct 2023 18:22:42 +0200
Message-Id: <68b90916541c09fd64de22dd4666b53172f7e618.1698077459.git.andreyknvl@google.com>
In-Reply-To: <cover.1698077459.git.andreyknvl@google.com>
References: <cover.1698077459.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=d8BAggel;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.197 as
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

Currently, stack depot uses the following locking scheme:

1. Lock-free accesses when looking up a stack record, which allows to
   have multiple users to look up records in parallel;
2. Spinlock for protecting the stack depot pools and the hash table
   when adding a new record.

For implementing the eviction of stack traces from stack depot, the
lock-free approach is not going to work anymore, as we will need to be
able to also remove records from the hash table.

Convert the spinlock into a read/write lock, and drop the atomic accesses,
as they are no longer required.

Looking up stack traces is now protected by the read lock and adding new
records - by the write lock. One of the following patches will add a new
function for evicting stack records, which will be protected by the write
lock as well.

With this change, multiple users can still look up records in parallel.

This is preparatory patch for implementing the eviction of stack records
from the stack depot.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changed v2->v3:
- Use lockdep_assert_held_read annotation in depot_fetch_stack.

Changes v1->v2:
- Add lockdep_assert annotations.
---
 lib/stackdepot.c | 87 +++++++++++++++++++++++++-----------------------
 1 file changed, 46 insertions(+), 41 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 1067c072a0f8..b1ceade0acc9 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -23,6 +23,7 @@
 #include <linux/percpu.h>
 #include <linux/printk.h>
 #include <linux/slab.h>
+#include <linux/spinlock.h>
 #include <linux/stacktrace.h>
 #include <linux/stackdepot.h>
 #include <linux/string.h>
@@ -91,15 +92,15 @@ static void *new_pool;
 static int pools_num;
 /* Next stack in the freelist of stack records within stack_pools. */
 static struct stack_record *next_stack;
-/* Lock that protects the variables above. */
-static DEFINE_RAW_SPINLOCK(pool_lock);
 /*
  * Stack depot tries to keep an extra pool allocated even before it runs out
  * of space in the currently used pool. This flag marks whether this extra pool
  * needs to be allocated. It has the value 0 when either an extra pool is not
  * yet allocated or if the limit on the number of pools is reached.
  */
-static int new_pool_required = 1;
+static bool new_pool_required = true;
+/* Lock that protects the variables above. */
+static DEFINE_RWLOCK(pool_rwlock);
 
 static int __init disable_stack_depot(char *str)
 {
@@ -226,6 +227,8 @@ static void depot_init_pool(void *pool)
 	const int records_in_pool = DEPOT_POOL_SIZE / DEPOT_STACK_RECORD_SIZE;
 	int i, offset;
 
+	lockdep_assert_held_write(&pool_rwlock);
+
 	/* Initialize handles and link stack records to each other. */
 	for (i = 0, offset = 0;
 	     offset <= DEPOT_POOL_SIZE - DEPOT_STACK_RECORD_SIZE;
@@ -248,22 +251,17 @@ static void depot_init_pool(void *pool)
 
 	/* Save reference to the pool to be used by depot_fetch_stack(). */
 	stack_pools[pools_num] = pool;
-
-	/*
-	 * WRITE_ONCE() pairs with potential concurrent read in
-	 * depot_fetch_stack().
-	 */
-	WRITE_ONCE(pools_num, pools_num + 1);
+	pools_num++;
 }
 
 /* Keeps the preallocated memory to be used for a new stack depot pool. */
 static void depot_keep_new_pool(void **prealloc)
 {
+	lockdep_assert_held_write(&pool_rwlock);
+
 	/*
 	 * If a new pool is already saved or the maximum number of
 	 * pools is reached, do not use the preallocated memory.
-	 * Access new_pool_required non-atomically, as there are no concurrent
-	 * write accesses to this variable.
 	 */
 	if (!new_pool_required)
 		return;
@@ -281,15 +279,15 @@ static void depot_keep_new_pool(void **prealloc)
 	 * At this point, either a new pool is kept or the maximum
 	 * number of pools is reached. In either case, take note that
 	 * keeping another pool is not required.
-	 * smp_store_release() pairs with smp_load_acquire() in
-	 * stack_depot_save().
 	 */
-	smp_store_release(&new_pool_required, 0);
+	new_pool_required = false;
 }
 
 /* Updates refences to the current and the next stack depot pools. */
 static bool depot_update_pools(void **prealloc)
 {
+	lockdep_assert_held_write(&pool_rwlock);
+
 	/* Check if we still have objects in the freelist. */
 	if (next_stack)
 		goto out_keep_prealloc;
@@ -301,7 +299,7 @@ static bool depot_update_pools(void **prealloc)
 
 		/* Take note that we might need a new new_pool. */
 		if (pools_num < DEPOT_MAX_POOLS)
-			smp_store_release(&new_pool_required, 1);
+			new_pool_required = true;
 
 		/* Try keeping the preallocated memory for new_pool. */
 		goto out_keep_prealloc;
@@ -335,6 +333,8 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 {
 	struct stack_record *stack;
 
+	lockdep_assert_held_write(&pool_rwlock);
+
 	/* Update current and new pools if required and possible. */
 	if (!depot_update_pools(prealloc))
 		return NULL;
@@ -370,18 +370,15 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 {
 	union handle_parts parts = { .handle = handle };
-	/*
-	 * READ_ONCE() pairs with potential concurrent write in
-	 * depot_init_pool().
-	 */
-	int pools_num_cached = READ_ONCE(pools_num);
 	void *pool;
 	size_t offset = parts.offset << DEPOT_STACK_ALIGN;
 	struct stack_record *stack;
 
-	if (parts.pool_index > pools_num_cached) {
+	lockdep_assert_held_read(&pool_rwlock);
+
+	if (parts.pool_index > pools_num) {
 		WARN(1, "pool index %d out of bounds (%d) for stack id %08x\n",
-		     parts.pool_index, pools_num_cached, handle);
+		     parts.pool_index, pools_num, handle);
 		return NULL;
 	}
 
@@ -423,6 +420,8 @@ static inline struct stack_record *find_stack(struct stack_record *bucket,
 {
 	struct stack_record *found;
 
+	lockdep_assert_held(&pool_rwlock);
+
 	for (found = bucket; found; found = found->next) {
 		if (found->hash == hash &&
 		    found->size == size &&
@@ -440,6 +439,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	depot_stack_handle_t handle = 0;
 	struct page *page = NULL;
 	void *prealloc = NULL;
+	bool need_alloc = false;
 	unsigned long flags;
 	u32 hash;
 
@@ -459,22 +459,26 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	hash = hash_stack(entries, nr_entries);
 	bucket = &stack_table[hash & stack_hash_mask];
 
-	/*
-	 * Fast path: look the stack trace up without locking.
-	 * smp_load_acquire() pairs with smp_store_release() to |bucket| below.
-	 */
-	found = find_stack(smp_load_acquire(bucket), entries, nr_entries, hash);
-	if (found)
+	read_lock_irqsave(&pool_rwlock, flags);
+
+	/* Fast path: look the stack trace up without full locking. */
+	found = find_stack(*bucket, entries, nr_entries, hash);
+	if (found) {
+		read_unlock_irqrestore(&pool_rwlock, flags);
 		goto exit;
+	}
+
+	/* Take note if another stack pool needs to be allocated. */
+	if (new_pool_required)
+		need_alloc = true;
+
+	read_unlock_irqrestore(&pool_rwlock, flags);
 
 	/*
-	 * Check if another stack pool needs to be allocated. If so, allocate
-	 * the memory now: we won't be able to do that under the lock.
-	 *
-	 * smp_load_acquire() pairs with smp_store_release() in
-	 * depot_update_pools() and depot_keep_new_pool().
+	 * Allocate memory for a new pool if required now:
+	 * we won't be able to do that under the lock.
 	 */
-	if (unlikely(can_alloc && smp_load_acquire(&new_pool_required))) {
+	if (unlikely(can_alloc && need_alloc)) {
 		/*
 		 * Zero out zone modifiers, as we don't have specific zone
 		 * requirements. Keep the flags related to allocation in atomic
@@ -488,7 +492,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 			prealloc = page_address(page);
 	}
 
-	raw_spin_lock_irqsave(&pool_lock, flags);
+	write_lock_irqsave(&pool_rwlock, flags);
 
 	found = find_stack(*bucket, entries, nr_entries, hash);
 	if (!found) {
@@ -497,11 +501,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 
 		if (new) {
 			new->next = *bucket;
-			/*
-			 * smp_store_release() pairs with smp_load_acquire()
-			 * from |bucket| above.
-			 */
-			smp_store_release(bucket, new);
+			*bucket = new;
 			found = new;
 		}
 	} else if (prealloc) {
@@ -512,7 +512,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		depot_keep_new_pool(&prealloc);
 	}
 
-	raw_spin_unlock_irqrestore(&pool_lock, flags);
+	write_unlock_irqrestore(&pool_rwlock, flags);
 exit:
 	if (prealloc) {
 		/* Stack depot didn't use this memory, free it. */
@@ -536,6 +536,7 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 			       unsigned long **entries)
 {
 	struct stack_record *stack;
+	unsigned long flags;
 
 	*entries = NULL;
 	/*
@@ -547,8 +548,12 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 	if (!handle || stack_depot_disabled)
 		return 0;
 
+	read_lock_irqsave(&pool_rwlock, flags);
+
 	stack = depot_fetch_stack(handle);
 
+	read_unlock_irqrestore(&pool_rwlock, flags);
+
 	*entries = stack->entries;
 	return stack->size;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/68b90916541c09fd64de22dd4666b53172f7e618.1698077459.git.andreyknvl%40google.com.
