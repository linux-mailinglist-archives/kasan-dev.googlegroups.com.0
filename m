Return-Path: <kasan-dev+bncBAABBZV43KUQMGQEPWB6RSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D2EF7D3C5B
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:25:12 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2c54b040cf2sf29905231fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:25:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698078312; cv=pass;
        d=google.com; s=arc-20160816;
        b=sbvNLip6nbmCPF0px6vXI+ff+upwn3/fA6ef1vukAQeTv7jSf6ZNPGoJJQsTouhUG/
         X1IxFmR7hUTYXmgx7f0XgYzgjiAYGuKee4qcbYAtslWjEOjoaVV9IW05A0jb9Ku5cJbt
         7C20uJgSsUTG5UG2v2S8pCCoXVgdCiYk560yUyuegAx2vf8aJb0XkR8EW9aJUuxDrrmE
         3Q2vlj1M4jrtQbV9fIF7xSceCpWsa/NZWJZBnHseHxEpUnjNoCx7cy970n76jk/g2wVg
         8jUOMPV3+kKTuj7OIpfqW+5IqixoThpq1HAxsMU/UMictfrhNdLbFwYOFAEEmcsXShzG
         eEAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MhzZIgXGlj+A8Ogqdn/yPwE4vZQlufLF6P6s1AOkPiA=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=gjirjlo6iuFQmIyNrGwGgdiNXlvTz5OT61s9YJyW9FFyBHif6qv5flhBwcguoH14zj
         Kg4tYP5ToQr2N83I83b0wNxQM2jEyAoLLdtGazNFpJz0pJVDXehj4ZMMjjzyx1HtBrhG
         SsdCcz8yiR8HR5LdozS8cM0qnU2CdhBK3NBGEufX1HIONt9untQT22poZnx7zdUGNe/f
         0nhvEznYP5x1xqUjd4yNuE02HZex7zViSqATI3K2QBJ5NpRuS/+cme9zp+gjDwqLwjpn
         ZpqNxd+7xhnLgryQZPpmoHevD6lghZnb/Ez4+P/0am/062S7GNhn8O29eJ3IJwbCKNl3
         M1Mg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iGUJS+rO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.200 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698078312; x=1698683112; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MhzZIgXGlj+A8Ogqdn/yPwE4vZQlufLF6P6s1AOkPiA=;
        b=NmoibRpyjn6ZxFsOjCTezmTlFEzOI8B4AnLfCU5nzO3d5T0XVO1sI6+pZAFVuAQlo3
         b+UbV8KJlmb00cu5oOUZSGj0T0gVJFDYUYUqk+ShVCNfJTcmPcSiAGaWNuqTnJni6YQA
         6NY3536T6HPgcwAzyPCtDZWn5VllIHOX+GXAmzEhYl0lPgHf+5zac4BrpIZj+whTQb0C
         Ev1plpNRX8dK+27gyIBHuIJQVGPnwVBYSCqTp+ZtvqonvoPmrTNKB4a7EqEGKLO7Z4rY
         6owyITeSC2uEqYVPmjhSajzkvVG264ewgJiDG2FOvKjFcq4FMVhX3t6+WXnWOCaim1zp
         3xBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698078312; x=1698683112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MhzZIgXGlj+A8Ogqdn/yPwE4vZQlufLF6P6s1AOkPiA=;
        b=oMIOBRn0AwSsYHxeeEHeSPC50KRw4FDddKS+D3JDD4R8Rrel5Hn6GeBVlpsszt5ufG
         BqCUEZy1VJFAJl1PNNN2f15h3Z2oZGgxAu8DLk6TWpbj+nLdBaf/GtpyFKDTXcpcJP9r
         3DD5AubEaZUpWRfMcYWIh/eco9Cj93vgAZQa7dMdfi7/1g5SnQRnTkxgMQaeJrfISaSS
         BjBlBumfI4hC7Un1VXRBXiZJxahZdq+O0L5QgfzbT8qZSCKF9qR5jTfRVjkwugi+RWop
         WOhTNgEhE1st7aF55N2EbdzpVr2uxqllvnQCPwBAmoWRK9gtOvmGx4aIiy2Vv/bAGg31
         LVCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxcHrMKNScHrV3JPipfKlz/WbPf5z5dWSVAHhP/sauE3lNqBeAR
	0z7wvq5XnMLTpa8eysldQWc=
X-Google-Smtp-Source: AGHT+IFV3iA16OVxU9+GVCVcWmm4srV9OphvSPnmukc7DCOMN1Px9My+S5JBf1j0oa3s+lYznOF5kw==
X-Received: by 2002:a2e:901a:0:b0:2c5:2813:5538 with SMTP id h26-20020a2e901a000000b002c528135538mr6558385ljg.21.1698078310639;
        Mon, 23 Oct 2023 09:25:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2128:b0:2c5:14f8:2ef3 with SMTP id
 a40-20020a05651c212800b002c514f82ef3ls224470ljq.1.-pod-prod-04-eu; Mon, 23
 Oct 2023 09:25:09 -0700 (PDT)
X-Received: by 2002:a2e:91d5:0:b0:2bc:d5f1:b9cf with SMTP id u21-20020a2e91d5000000b002bcd5f1b9cfmr7106643ljg.27.1698078308952;
        Mon, 23 Oct 2023 09:25:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698078308; cv=none;
        d=google.com; s=arc-20160816;
        b=sZCrQNzZ3WQVrn0VgfSLDLUaH92xHAIzvuQI9l6jV8zmYQVcHi9rAI8rhkivmgSGLt
         nwOecFEbReXKv9weoZ5qww2qWJoNyiF3mHADjC95oR81ht0JEVl8PnR+/ovA4S8f7x5L
         2Ijj4omNs7dCi0QyCmYbv//FMLWZNLHCzo6K/Ehn1QEaDioHij9N4NwJv0keYn69gdFY
         CoKhn2BvMQ9uTPshTnh3hFbVXyQhROcTqfnAVAVx3bShiMDVOzDTi5if2nDz45zfuvqw
         GuHytD7onpI5gAHRTdjJRod5FWFYo5AeJQlHrfddIjwRYuXbqPjP7TTSX7e7bmCDhgbT
         uFWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kwAPQEKRgU/QjlEBZ2MhqIx/KOtst15cg0pwz3Hyr9g=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=zvDeMKfisP+MHYu4QHZ2ANNfyInKmehq1LtmEmXe2S+GNacMAaBrELmYun/w0c69WP
         6gCAc67QH9Utieems7RfbbxCtZDnYBZ1fePKBoZTYA7qyzEWfHXjI86dzz2BI90QO0zC
         kGC+dIBEzHDEVJIAGKfNBZPmRNDqS2Pmm5Ytvx18Gn10KaqKpRzOo4dVXEeKJIYZpRJu
         k4xNDBQfQIGXZuXOmKsGM+0pxl5M86AD4yMgVIOEdFHO055dhpRdmkHNybLa7qZ7B4Nz
         2QGr1CsxaoiFHHh8htT06S9WHGQxq8KkUowV0T1g0WiuGAmkh7MjMarmClmECZ+8tA63
         TfUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iGUJS+rO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.200 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-200.mta0.migadu.com (out-200.mta0.migadu.com. [91.218.175.200])
        by gmr-mx.google.com with ESMTPS id p20-20020a2ea4d4000000b002c29b97d5f2si306804ljm.1.2023.10.23.09.25.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Oct 2023 09:25:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.200 as permitted sender) client-ip=91.218.175.200;
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
Subject: [PATCH v3 12/19] lib/stackdepot: use list_head for stack record links
Date: Mon, 23 Oct 2023 18:22:43 +0200
Message-Id: <518e3873243845249c8fb019d744c5f5eac90205.1698077459.git.andreyknvl@google.com>
In-Reply-To: <cover.1698077459.git.andreyknvl@google.com>
References: <cover.1698077459.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=iGUJS+rO;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.200
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Switch stack_record to use list_head for links in the hash table
and in the freelist.

This will allow removing entries from the hash table buckets.

This is preparatory patch for implementing the eviction of stack records
from the stack depot.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Use the proper number of entries for initializing the stack table when
  alloc_large_system_hash() auto-calculates the number.

Changes v1->v2:
- Use list_head instead of open-coding backward links.
---
 lib/stackdepot.c | 87 ++++++++++++++++++++++++++++--------------------
 1 file changed, 50 insertions(+), 37 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index b1ceade0acc9..85fd40c63817 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -18,6 +18,7 @@
 #include <linux/jhash.h>
 #include <linux/kernel.h>
 #include <linux/kmsan.h>
+#include <linux/list.h>
 #include <linux/mm.h>
 #include <linux/mutex.h>
 #include <linux/percpu.h>
@@ -55,7 +56,7 @@ union handle_parts {
 };
 
 struct stack_record {
-	struct stack_record *next;	/* Link in hash table or freelist */
+	struct list_head list;		/* Links in hash table or freelist */
 	u32 hash;			/* Hash in hash table */
 	u32 size;			/* Number of stored frames */
 	union handle_parts handle;
@@ -77,21 +78,21 @@ static bool __stack_depot_early_init_passed __initdata;
 /* Initial seed for jhash2. */
 #define STACK_HASH_SEED 0x9747b28c
 
-/* Hash table of pointers to stored stack traces. */
-static struct stack_record **stack_table;
+/* Hash table of stored stack records. */
+static struct list_head *stack_table;
 /* Fixed order of the number of table buckets. Used when KASAN is enabled. */
 static unsigned int stack_bucket_number_order;
 /* Hash mask for indexing the table. */
 static unsigned int stack_hash_mask;
 
-/* Array of memory regions that store stack traces. */
+/* Array of memory regions that store stack records. */
 static void *stack_pools[DEPOT_MAX_POOLS];
 /* Newly allocated pool that is not yet added to stack_pools. */
 static void *new_pool;
 /* Number of pools in stack_pools. */
 static int pools_num;
-/* Next stack in the freelist of stack records within stack_pools. */
-static struct stack_record *next_stack;
+/* Freelist of stack records within stack_pools. */
+static LIST_HEAD(free_stacks);
 /*
  * Stack depot tries to keep an extra pool allocated even before it runs out
  * of space in the currently used pool. This flag marks whether this extra pool
@@ -123,6 +124,15 @@ void __init stack_depot_request_early_init(void)
 	__stack_depot_early_init_requested = true;
 }
 
+/* Initialize list_head's within the hash table. */
+static void init_stack_table(unsigned long entries)
+{
+	unsigned long i;
+
+	for (i = 0; i < entries; i++)
+		INIT_LIST_HEAD(&stack_table[i]);
+}
+
 /* Allocates a hash table via memblock. Can only be used during early boot. */
 int __init stack_depot_early_init(void)
 {
@@ -146,16 +156,16 @@ int __init stack_depot_early_init(void)
 
 	/*
 	 * If stack_bucket_number_order is not set, leave entries as 0 to rely
-	 * on the automatic calculations performed by alloc_large_system_hash.
+	 * on the automatic calculations performed by alloc_large_system_hash().
 	 */
 	if (stack_bucket_number_order)
 		entries = 1UL << stack_bucket_number_order;
 	pr_info("allocating hash table via alloc_large_system_hash\n");
 	stack_table = alloc_large_system_hash("stackdepot",
-						sizeof(struct stack_record *),
+						sizeof(struct list_head),
 						entries,
 						STACK_HASH_TABLE_SCALE,
-						HASH_EARLY | HASH_ZERO,
+						HASH_EARLY,
 						NULL,
 						&stack_hash_mask,
 						1UL << STACK_BUCKET_NUMBER_ORDER_MIN,
@@ -165,6 +175,14 @@ int __init stack_depot_early_init(void)
 		stack_depot_disabled = true;
 		return -ENOMEM;
 	}
+	if (!entries) {
+		/*
+		 * Obtain the number of entries that was calculated by
+		 * alloc_large_system_hash().
+		 */
+		entries = stack_hash_mask + 1;
+	}
+	init_stack_table(entries);
 
 	return 0;
 }
@@ -205,7 +223,7 @@ int stack_depot_init(void)
 		entries = 1UL << STACK_BUCKET_NUMBER_ORDER_MAX;
 
 	pr_info("allocating hash table of %lu entries via kvcalloc\n", entries);
-	stack_table = kvcalloc(entries, sizeof(struct stack_record *), GFP_KERNEL);
+	stack_table = kvcalloc(entries, sizeof(struct list_head), GFP_KERNEL);
 	if (!stack_table) {
 		pr_err("hash table allocation failed, disabling\n");
 		stack_depot_disabled = true;
@@ -213,6 +231,7 @@ int stack_depot_init(void)
 		goto out_unlock;
 	}
 	stack_hash_mask = entries - 1;
+	init_stack_table(entries);
 
 out_unlock:
 	mutex_unlock(&stack_depot_init_mutex);
@@ -224,31 +243,24 @@ EXPORT_SYMBOL_GPL(stack_depot_init);
 /* Initializes a stack depol pool. */
 static void depot_init_pool(void *pool)
 {
-	const int records_in_pool = DEPOT_POOL_SIZE / DEPOT_STACK_RECORD_SIZE;
-	int i, offset;
+	int offset;
 
 	lockdep_assert_held_write(&pool_rwlock);
 
-	/* Initialize handles and link stack records to each other. */
-	for (i = 0, offset = 0;
-	     offset <= DEPOT_POOL_SIZE - DEPOT_STACK_RECORD_SIZE;
-	     i++, offset += DEPOT_STACK_RECORD_SIZE) {
+	WARN_ON(!list_empty(&free_stacks));
+
+	/* Initialize handles and link stack records into the freelist. */
+	for (offset = 0; offset <= DEPOT_POOL_SIZE - DEPOT_STACK_RECORD_SIZE;
+	     offset += DEPOT_STACK_RECORD_SIZE) {
 		struct stack_record *stack = pool + offset;
 
 		stack->handle.pool_index = pools_num;
 		stack->handle.offset = offset >> DEPOT_STACK_ALIGN;
 		stack->handle.extra = 0;
 
-		if (i < records_in_pool - 1)
-			stack->next = (void *)stack + DEPOT_STACK_RECORD_SIZE;
-		else
-			stack->next = NULL;
+		list_add(&stack->list, &free_stacks);
 	}
 
-	/* Link stack records into the freelist. */
-	WARN_ON(next_stack);
-	next_stack = pool;
-
 	/* Save reference to the pool to be used by depot_fetch_stack(). */
 	stack_pools[pools_num] = pool;
 	pools_num++;
@@ -289,7 +301,7 @@ static bool depot_update_pools(void **prealloc)
 	lockdep_assert_held_write(&pool_rwlock);
 
 	/* Check if we still have objects in the freelist. */
-	if (next_stack)
+	if (!list_empty(&free_stacks))
 		goto out_keep_prealloc;
 
 	/* Check if we have a new pool saved and use it. */
@@ -340,19 +352,18 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 		return NULL;
 
 	/* Check if we have a stack record to save the stack trace. */
-	stack = next_stack;
-	if (!stack)
+	if (list_empty(&free_stacks))
 		return NULL;
 
-	/* Advance the freelist. */
-	next_stack = stack->next;
+	/* Get and unlink the first entry from the freelist. */
+	stack = list_first_entry(&free_stacks, struct stack_record, list);
+	list_del(&stack->list);
 
 	/* Limit number of saved frames to CONFIG_STACKDEPOT_MAX_FRAMES. */
 	if (size > CONFIG_STACKDEPOT_MAX_FRAMES)
 		size = CONFIG_STACKDEPOT_MAX_FRAMES;
 
 	/* Save the stack trace. */
-	stack->next = NULL;
 	stack->hash = hash;
 	stack->size = size;
 	/* stack->handle is already filled in by depot_init_pool(). */
@@ -414,15 +425,17 @@ int stackdepot_memcmp(const unsigned long *u1, const unsigned long *u2,
 }
 
 /* Finds a stack in a bucket of the hash table. */
-static inline struct stack_record *find_stack(struct stack_record *bucket,
+static inline struct stack_record *find_stack(struct list_head *bucket,
 					     unsigned long *entries, int size,
 					     u32 hash)
 {
+	struct list_head *pos;
 	struct stack_record *found;
 
 	lockdep_assert_held(&pool_rwlock);
 
-	for (found = bucket; found; found = found->next) {
+	list_for_each(pos, bucket) {
+		found = list_entry(pos, struct stack_record, list);
 		if (found->hash == hash &&
 		    found->size == size &&
 		    !stackdepot_memcmp(entries, found->entries, size))
@@ -435,7 +448,8 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 					unsigned int nr_entries,
 					gfp_t alloc_flags, bool can_alloc)
 {
-	struct stack_record *found = NULL, **bucket;
+	struct list_head *bucket;
+	struct stack_record *found = NULL;
 	depot_stack_handle_t handle = 0;
 	struct page *page = NULL;
 	void *prealloc = NULL;
@@ -462,7 +476,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	read_lock_irqsave(&pool_rwlock, flags);
 
 	/* Fast path: look the stack trace up without full locking. */
-	found = find_stack(*bucket, entries, nr_entries, hash);
+	found = find_stack(bucket, entries, nr_entries, hash);
 	if (found) {
 		read_unlock_irqrestore(&pool_rwlock, flags);
 		goto exit;
@@ -494,14 +508,13 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 
 	write_lock_irqsave(&pool_rwlock, flags);
 
-	found = find_stack(*bucket, entries, nr_entries, hash);
+	found = find_stack(bucket, entries, nr_entries, hash);
 	if (!found) {
 		struct stack_record *new =
 			depot_alloc_stack(entries, nr_entries, hash, &prealloc);
 
 		if (new) {
-			new->next = *bucket;
-			*bucket = new;
+			list_add(&new->list, bucket);
 			found = new;
 		}
 	} else if (prealloc) {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/518e3873243845249c8fb019d744c5f5eac90205.1698077459.git.andreyknvl%40google.com.
