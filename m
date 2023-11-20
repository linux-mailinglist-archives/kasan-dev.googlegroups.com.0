Return-Path: <kasan-dev+bncBAABBNFY52VAMGQEGXUNWTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id A72D17F1B7A
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:49:41 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-5079a3362afsf4274502e87.3
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:49:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502581; cv=pass;
        d=google.com; s=arc-20160816;
        b=V4Ts2PFo/3vOItVSEFWrosxjtcAi4KUPl+hzQNyZxCPA4XZDTS5JbF0RYxgv+PcUjz
         kEo9mWOUY8GMqb27tWA3WU+2jOshtsRVSXeisTX5vlRNXZIiSvClc32P/XoOyFn+hGhR
         jUHalOG6r9wFM4NOSrWj8L6AynKhIMeW1+uvmK7QkX1p77atpye5V3qOvBP+JNeBSztZ
         EDt+p+a1KrBPU5/reHSMMhcFgHfY9wt5PookdNoVlag1QBUiJPQke+hycq5fKaGJLk5h
         rdHJWIJuLEAxvCghoSwiiPnoHZXdBzirpo5H7Oqd/cFobJWIRkUQrS7J4gk2dqRZWtdg
         IVPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Mrl9bx4C1z3+iCE+E1zHvHTaB/3r2tlwusI08iUC97A=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=HfB92Vq35U4eMKctCa+eFHQMSU5pJZEtwmtUDu/+Gr6ag6svvk0MR0Iu0l2lH4t3a7
         uJBhFqDoAsXACXakCX5WJUHm5iS2S9oazOWH3x5tdt4pyiFW+WewvrlA+wnS+LNbjnNF
         1aozXSGumkULqK5FQQWK1YEyxryi49N6qE0fLGpWXPQyVOd8lix6jBY8mKvMABQCmten
         Efg/BOhg+ZXith7vB9FxCpES1aiAgh31c+vSWi2WHSI/mSmIH7mOx9AEiVXahpvCot3Z
         ayrfxj0Kh3MvIYLZqOzS7ze0ZbJZre2A3Mw4RM6nGFsH/8tA1Av3GcqdLBeI7OpYmWCT
         LL7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ru67pJEW;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.176 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502581; x=1701107381; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Mrl9bx4C1z3+iCE+E1zHvHTaB/3r2tlwusI08iUC97A=;
        b=HLuSQMHQoSZw5UHxNqtc6H5uONkU7NTiQip3J9LHwlz8MXKInI9KcFwmanBteJW787
         pW5SNwQXRHXdqbjAwav97Uyfh5tRym9ikMDlcaxqneVKimFkXPQqYan67E7P1ZXyATHO
         BsSqKyOHMgpJROZj3wIadLC8wP7apDdYCT5PU35uWG1cAmiQxLI2XpwMCN7mq5otvdpA
         waoTQBZ6sVc0YHgtNU1x/mg9msuICPDCfvSOe8XI7mzWTHyT8oy/itlfegCPQmPFsrgK
         n11xnd7822cuue7Z0UiVUCVs45FWeWBLsujfdQ9n8xp1xsOHDUyZak2RmTXTnQt3tIR+
         mjDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502581; x=1701107381;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Mrl9bx4C1z3+iCE+E1zHvHTaB/3r2tlwusI08iUC97A=;
        b=HlG6ILMVU4x5XQAj4iaiE1I4JijMSd1zt7BvkMMcGR9sHaS+skPCI0YwkWciNnipO5
         E9GFbn4NIaMuBxelGsykmVDviEj0cS+TK4JvbRqzL8/b6hm/xU7wawZ8/bMd4Vj8SvGY
         83+OjW+G76zLzryalMXfltLIkFdnYwyMwpw7ZKsjYWl4B86N5iIT0HhIF6ba77Vdvbfu
         CNU3vudEYuzTp1aQTqvkdvkBnDwpWYy1sfF7tamJJSOuorbY7QjES1WqJR6UoBZqup+5
         P13O5NtJ3IHXZ/ZZ8TAuPVMyVCMEqW93/MvGTd+dlGgjYzDPzWLy9sRW5rxhafuAQWfm
         GswQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywj4atj5DbxN4tWxAyknQkWYjZz2XkWGFVwjOptua9CcR7h2gnr
	Idj4DUA6pAVOvKByEG6LUAE=
X-Google-Smtp-Source: AGHT+IFCEPuD77hCbt47tCC+/4gs32as+w4ISdtsu/9A2m5ZoaobJMrpTqJYzoKMLMHcx6SISPt2kA==
X-Received: by 2002:ac2:5337:0:b0:507:9fc1:ca7a with SMTP id f23-20020ac25337000000b005079fc1ca7amr6225300lfh.9.1700502580870;
        Mon, 20 Nov 2023 09:49:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d0f:b0:50a:aa99:28a8 with SMTP id
 d15-20020a0565123d0f00b0050aaa9928a8ls46730lfv.0.-pod-prod-01-eu; Mon, 20 Nov
 2023 09:49:39 -0800 (PST)
X-Received: by 2002:a2e:2a83:0:b0:2c8:2e3a:e974 with SMTP id q125-20020a2e2a83000000b002c82e3ae974mr5550403ljq.44.1700502579110;
        Mon, 20 Nov 2023 09:49:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502579; cv=none;
        d=google.com; s=arc-20160816;
        b=rWkzEBshfG0T3OBbkhKdzfzXUN2yFLslvkw7y5dv5fwO3M92G/dsBBqzBL/H1HhU2I
         ZAnfC+eYbMkU812nlWTE/MlIVDm1IXaa8OzeFCNrvUoElpQD2C0RWf+uRfuLMdVIITXc
         vk7/RSUtbJxmrZCNTLClWEgB1FdeX2m1PVwHKzErpmnIOUr3ZPosAWKP4p7Arm00wyJU
         0J8SLUFCTp8fUQkmCU4/J5nQcTnJ7wQ3nCPiDyiZFfBooqEEqwD2ORDvKRtbZRvkzpVl
         ouYMx+fn2otVAm9CDCVhF+q7QWpaHz5cTA3fECyCodH3TCcSx2neqjVrT44L9c9ZtvJn
         ofZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JJPmOktxCpdhFxDsq8sCddRT3Qn7jxR2DhkERqO3NMk=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=zkJw+U9lwO99E9/FB1dPhHBU9jzD+nNCsfLSAbh+yDU4jFR/s1jTmg3NlhmMLun8hN
         Fjb5UVg6qMGHjeDNSs/z7+4HANinQSPbdJGs7SkHbAPzr9/6eiALOCFKl3Tvqh2/wJts
         E1uOVvfkfsZZPg64hcv6VUZN7ZwbE0pQyYN6JUJLwds1rBWKpe5/7Q5WhOopwx2ahE7U
         SyzT2Ne/N3QjNpwKuduFmaG9kJr5KwX/mqK4gMU6McHZhgynNWQvnmLMxWvE1qVlu/Xr
         L4QAWkynh0T7WL7OKnTMmV1Hz+WBvIG/gk6iL6BeSatk1ZpPGRO+KkgQEVLkTwZE5yAS
         a2QA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ru67pJEW;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.176 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-176.mta0.migadu.com (out-176.mta0.migadu.com. [91.218.175.176])
        by gmr-mx.google.com with ESMTPS id l23-20020a2ea317000000b002b9d5a29ef7si321014lje.4.2023.11.20.09.49.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:49:39 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.176 as permitted sender) client-ip=91.218.175.176;
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
Subject: [PATCH v4 13/22] lib/stackdepot: use list_head for stack record links
Date: Mon, 20 Nov 2023 18:47:11 +0100
Message-Id: <4787d9a584cd33433d9ee1846b17fa3d3e1987ad.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Ru67pJEW;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.176
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
index 8378b32b5310..4bb0af423f82 100644
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
@@ -116,6 +117,15 @@ void __init stack_depot_request_early_init(void)
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
@@ -152,16 +162,16 @@ int __init stack_depot_early_init(void)
 
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
@@ -171,6 +181,14 @@ int __init stack_depot_early_init(void)
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
@@ -211,7 +229,7 @@ int stack_depot_init(void)
 		entries = 1UL << STACK_BUCKET_NUMBER_ORDER_MAX;
 
 	pr_info("allocating hash table of %lu entries via kvcalloc\n", entries);
-	stack_table = kvcalloc(entries, sizeof(struct stack_record *), GFP_KERNEL);
+	stack_table = kvcalloc(entries, sizeof(struct list_head), GFP_KERNEL);
 	if (!stack_table) {
 		pr_err("hash table allocation failed, disabling\n");
 		stack_depot_disabled = true;
@@ -219,6 +237,7 @@ int stack_depot_init(void)
 		goto out_unlock;
 	}
 	stack_hash_mask = entries - 1;
+	init_stack_table(entries);
 
 out_unlock:
 	mutex_unlock(&stack_depot_init_mutex);
@@ -230,31 +249,24 @@ EXPORT_SYMBOL_GPL(stack_depot_init);
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
@@ -295,7 +307,7 @@ static bool depot_update_pools(void **prealloc)
 	lockdep_assert_held_write(&pool_rwlock);
 
 	/* Check if we still have objects in the freelist. */
-	if (next_stack)
+	if (!list_empty(&free_stacks))
 		goto out_keep_prealloc;
 
 	/* Check if we have a new pool saved and use it. */
@@ -346,19 +358,18 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
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
@@ -420,15 +431,17 @@ int stackdepot_memcmp(const unsigned long *u1, const unsigned long *u2,
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
@@ -441,7 +454,8 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 					unsigned int nr_entries,
 					gfp_t alloc_flags, bool can_alloc)
 {
-	struct stack_record *found = NULL, **bucket;
+	struct list_head *bucket;
+	struct stack_record *found = NULL;
 	depot_stack_handle_t handle = 0;
 	struct page *page = NULL;
 	void *prealloc = NULL;
@@ -468,7 +482,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	read_lock_irqsave(&pool_rwlock, flags);
 
 	/* Fast path: look the stack trace up without full locking. */
-	found = find_stack(*bucket, entries, nr_entries, hash);
+	found = find_stack(bucket, entries, nr_entries, hash);
 	if (found) {
 		read_unlock_irqrestore(&pool_rwlock, flags);
 		goto exit;
@@ -500,14 +514,13 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4787d9a584cd33433d9ee1846b17fa3d3e1987ad.1700502145.git.andreyknvl%40google.com.
