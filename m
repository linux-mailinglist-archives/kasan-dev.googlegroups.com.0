Return-Path: <kasan-dev+bncBAABBDO5Q6UAMGQEO6Z5DUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 839A479F032
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:17:03 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-502a52cae6bsf12898e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:17:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694625423; cv=pass;
        d=google.com; s=arc-20160816;
        b=ag8OKKlSeyVqc366k5W/0GfrMVaeSyvKHwNej6GfP1+/8v7JLjeEJHOdLW/ZfdKaPP
         ExJ0NG84GY/+d3/4myx7tMuG8UKt2Bc30FAd37GAmak7ADQxLbdbO4DLieQk1oscr+WL
         fTdLV1muuiL5glRqsuLPG2ndLrCG9gXLfkXf/HUNTN6hjc7WhClr60pCIpgIMe/aToQY
         h1mzrrlTTKPZZKZ+pQTxV8FfyRcXA+tZDYaT1LtgIUX+BNVB0Qtqq2Q6oUYkp2W+TNCE
         u6SatJkzqh7aWCjgjHRw3hGtU/R/43DNgWVD2Ay5Z+1hW2UL119IYJwsLn1OJV/AsmnG
         HxRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=k6P71YvPyWFmX7578Pvu4+9LqjSCY1W4vjdWNsBIKZA=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=HYqiopoGXpLlOcNvMKTMK7HI6NCeYXUOZvaoZC1DbCZvKqnCagyiZB6fmr1w7VXf0w
         LxIy3iCIpAYzpHD79Xm4Ctn4P1AT75/BIIRFYM8RXD9ZkcqdXloEdRCBZP6nBPgDQwMv
         yXClqKfTbp7nXIt/dywsKP0UoiUafsFZVuE76WJnR3d4YcKbEmk6KtAihWibWoZaUA/i
         8HRhujHdmgphgVY7Ibvg+QLbnSGupsSEkIw0UQuzLtgr1zShsHS+TzppD37q6tVIPXr2
         rC5mfxHCt8eFOIMdsdm1/GDqSvDyWuGOgBa2orBTs5xIi909PObFlL5r1XmfEMTI/Hsa
         Ccbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=R3Jti2k9;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.214 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694625423; x=1695230223; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=k6P71YvPyWFmX7578Pvu4+9LqjSCY1W4vjdWNsBIKZA=;
        b=rfgFdmWqnsRznf1OfdVcqwJN8af7UTIfdrqil4l5V5/WTWfaQLmgn+0AKNsqQXDwqp
         0WZud63W3jllEeTz7hjw9U8QbWG1r9pGwMclmaeC+8mTvmpoRdRX56PRRaLCjlxiNqte
         rLhF0ehMPj/sWY6KxulgBIKzUNvEaAYU77GJftf261NYRY9IxP1nSgZ8GM+wj2vogN4O
         ttPt68zJA8dHbujJuA5Un1Tf3IQIPn41OF02ZBxME8IORVrhDbt9I6lFjHOSdaO8W3VB
         4eb6cNS9YBEfC3hJpCo0OVTCDkE4n/gJNZeruTs0qCbWExD+LffX+Yjri0fe2pPkb8OJ
         rVyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694625423; x=1695230223;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=k6P71YvPyWFmX7578Pvu4+9LqjSCY1W4vjdWNsBIKZA=;
        b=JnlI+dxIH2TmkW8nasYIWX5OuvJQts0+w2xCmcNmqpz0iot5EmVaYf9lt8vB5CuwT3
         ETkcDOtFImZet0rZcCgIOQHQYa4jT/GGveMYQ6Xs+6z6uYRmL+KbmvEX0/cdoxitBwj6
         DTHYtkbL7XGJTvgZwNrI37ogdLzxovWXAKrNkbstxP2q1D2MYZJy3NahdueTeaRdblpu
         iqotSjK5Ky+Ypwu/WViqu42WhqSX3W4e1tn46nSbN6GrGJCYze4xmDpJhTbxo3C0jMI8
         6VWzMxr9x9XTyWyLP2Fkjn4pp/jxc8GILh4k2lB7UghGyJds52thiEdVP/8Xk6fpZM7n
         kSMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw+2IMeGPV3mfzN++K9FEQ1zLjD+B9nI0z3E3RLxjGpK76F2zLK
	emqBwX8lEaFHxHp2YRs/ny0=
X-Google-Smtp-Source: AGHT+IEb1geTy6W5eQigiGn12aR+PcENLYpeViEy5kUNSHmcvlW/QDIP0NN9gWpdzn0BSjoP8rRUQg==
X-Received: by 2002:a05:6512:3b24:b0:4f9:54f0:b6db with SMTP id f36-20020a0565123b2400b004f954f0b6dbmr3276374lfv.13.1694625421978;
        Wed, 13 Sep 2023 10:17:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5b87:0:b0:500:83e8:9d2c with SMTP id o7-20020ac25b87000000b0050083e89d2cls194057lfn.1.-pod-prod-04-eu;
 Wed, 13 Sep 2023 10:17:00 -0700 (PDT)
X-Received: by 2002:a05:6512:b84:b0:500:9a45:62f with SMTP id b4-20020a0565120b8400b005009a45062fmr3070317lfv.8.1694625420526;
        Wed, 13 Sep 2023 10:17:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694625420; cv=none;
        d=google.com; s=arc-20160816;
        b=ufzgdiOUHlTQhpftQNJUB3xNbWRkResh49/kZwgYiRMSBsUBt/Mv/z376RbghWs9/R
         eRsJ7LWddZskQ0I8lBvk0cTHxkWCMMf3w8g72hNZRR6Zm9qjr0rQ5B60b7XLmpIMjWVf
         jS1JoM5/3HtUwDN0pimIXzQjqbVowSsO9K3kZ9OiMDCfSTMTsUKZrxlc5AIZny9G6L3o
         mmjf95dJu62BJQ7ahugur7rKmdVAI1tR7970v7MYDrZ6lrSvuO2S2QrbxzQKAU9PId+r
         5liT1nDK7o6U+nD/XbDDbvVlQeIq/b4nrUbDbzUnRbbdrON8/x1TKUK+XXvQ64DwYiz7
         rBDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4oWt0Nx5j2++AoKVMMksnS7f1HGHVd77ggPp9l5g/Uk=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=BG9dv63L6Iyd+DAwrnlbHO49M6VLG/NvESOl4bKBzb3tT1lhRkXkexLWv0RWqrAsFT
         BHvnRqO8GblvdiBekLE6ncYXTKiYouf739a5MvbF1zWGlOsxzXWC0sPitsn7+UgxcJEW
         Ou6jpvtAOmvGvZBw5rxMVyve7FjMdlA22aOAUJdBmsoNJn4Mrug8pYy1QYX0hUfxrUaP
         LO9vS1q6Lgo72V/0MTKd8xYy4sAdK4nRMQp0N4gjKEWK0HOufNjaPirpdLBVIvnZjz3n
         7A182X+CGX/pmFsIK6XaQmm+fk2Fir+snk7zW9rI8lK83qdhMo2UJL9plYBs4UOJd/jJ
         VJpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=R3Jti2k9;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.214 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-214.mta1.migadu.com (out-214.mta1.migadu.com. [95.215.58.214])
        by gmr-mx.google.com with ESMTPS id z2-20020a056512370200b004fe3ba741c8si832102lfr.8.2023.09.13.10.17.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Sep 2023 10:17:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.214 as permitted sender) client-ip=95.215.58.214;
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
Subject: [PATCH v2 12/19] lib/stackdepot: use list_head for stack record links
Date: Wed, 13 Sep 2023 19:14:37 +0200
Message-Id: <d94caa60d28349ca5a3c709fdb67545d9374e0dc.1694625260.git.andreyknvl@google.com>
In-Reply-To: <cover.1694625260.git.andreyknvl@google.com>
References: <cover.1694625260.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=R3Jti2k9;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.214 as
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

Switch stack_record to use list_head for links in the hash table
and in the freelist.

This will allow removing entries from the hash table buckets.

This is preparatory patch for implementing the eviction of stack records
from the stack depot.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Use list_head instead of open-coding backward links.
---
 lib/stackdepot.c | 77 ++++++++++++++++++++++++++----------------------
 1 file changed, 42 insertions(+), 35 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 0b4591475d4f..1b08897ebd2b 100644
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
@@ -152,10 +162,10 @@ int __init stack_depot_early_init(void)
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
@@ -165,6 +175,7 @@ int __init stack_depot_early_init(void)
 		stack_depot_disabled = true;
 		return -ENOMEM;
 	}
+	init_stack_table(entries);
 
 	return 0;
 }
@@ -205,7 +216,7 @@ int stack_depot_init(void)
 		entries = 1UL << STACK_BUCKET_NUMBER_ORDER_MAX;
 
 	pr_info("allocating hash table of %lu entries via kvcalloc\n", entries);
-	stack_table = kvcalloc(entries, sizeof(struct stack_record *), GFP_KERNEL);
+	stack_table = kvcalloc(entries, sizeof(struct list_head), GFP_KERNEL);
 	if (!stack_table) {
 		pr_err("hash table allocation failed, disabling\n");
 		stack_depot_disabled = true;
@@ -213,6 +224,7 @@ int stack_depot_init(void)
 		goto out_unlock;
 	}
 	stack_hash_mask = entries - 1;
+	init_stack_table(entries);
 
 out_unlock:
 	mutex_unlock(&stack_depot_init_mutex);
@@ -224,30 +236,24 @@ EXPORT_SYMBOL_GPL(stack_depot_init);
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
 
 	/* Save reference to the pool to be used by depot_fetch_stack. */
 	stack_pools[pools_num] = pool;
@@ -289,7 +295,7 @@ static bool depot_update_pools(void **prealloc)
 	lockdep_assert_held_write(&pool_rwlock);
 
 	/* Check if we still have objects in the freelist. */
-	if (next_stack)
+	if (!list_empty(&free_stacks))
 		goto out_keep_prealloc;
 
 	/* Check if we have a new pool saved and use it. */
@@ -340,19 +346,18 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
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
 	/* stack->handle is already filled in by depot_init_pool. */
@@ -414,15 +419,17 @@ int stackdepot_memcmp(const unsigned long *u1, const unsigned long *u2,
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
@@ -435,7 +442,8 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 					unsigned int nr_entries,
 					gfp_t alloc_flags, bool can_alloc)
 {
-	struct stack_record *found = NULL, **bucket;
+	struct list_head *bucket;
+	struct stack_record *found = NULL;
 	depot_stack_handle_t handle = 0;
 	struct page *page = NULL;
 	void *prealloc = NULL;
@@ -462,7 +470,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	read_lock_irqsave(&pool_rwlock, flags);
 
 	/* Fast path: look the stack trace up without full locking. */
-	found = find_stack(*bucket, entries, nr_entries, hash);
+	found = find_stack(bucket, entries, nr_entries, hash);
 	if (found) {
 		read_unlock_irqrestore(&pool_rwlock, flags);
 		goto exit;
@@ -494,14 +502,13 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d94caa60d28349ca5a3c709fdb67545d9374e0dc.1694625260.git.andreyknvl%40google.com.
