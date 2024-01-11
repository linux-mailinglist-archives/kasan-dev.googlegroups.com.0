Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKXZQCWQMGQE6PKHRRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8810082B50F
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 20:08:32 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-50e411af4e6sf4751912e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 11:08:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705000107; cv=pass;
        d=google.com; s=arc-20160816;
        b=yxqhJg0KuNE376H/z/JUmtaSYeZpAbFxHrJw+0JJGMn+g+ZdMrW8gK8oylv9zc+jru
         9WddZfg2J/frxejefc77+HIs+qHMU2eRnSJUgAqaTtzu41OTeeOsf74Vjc8FSptP1dFB
         J8jjngDqV//uwJtJTNoHsQSFhCVv80k8c7TYXh9Zqrkp9oKaCOYmJRqMfhsLSQOm7+bJ
         hiGDyZL5xNEvhTnWLyjibLjlMEaRF64CZopzcIIasArL2sbfewM842rhx0kAeB1eJYFd
         cYux7pNfVBopLb2vD9BymFHzJkpWn+QJJnpsqSKZjIgWci9pYPPf5iraXshkfvnTCZik
         8LFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ujtKgzYdElVB8wVHNHccs5Uq3lFU4MiQU/UQ6sMy1oU=;
        fh=y9FUbJak5C6gzSTedbgzGWVmwnHgqmhZsHaMuLfouUI=;
        b=W13LWVSCvlqZKqpHfnplPDKAOrxd5/e1njqd05GkyERq+zPXYEZCNzZbgJnAeMTmtk
         1skHLTwHFOu7gaUNKIrnpgqyQ32BRXQcZImnKiDyMEVn6Mi/JJ+t/EOhUXVJ6nfX8anK
         9SGZZPLCmtaYptXRvCh/gf/ztbV5LQTP5DMAMNMKV7jq5//0n1f2WRdjo6E1T2tHLsYa
         uV8Sd0LDbX9phZKwYWORCn6Xo49xqcq/4MLzFv7zyWdiGClIbgT/AkVlhjIKwGBEzqoR
         iVm+K4CqfQrm/PfJAZ4qKS6961rEUMwWKvwKFZnTiCkogF3e9cQsfWU0aCWIereADFnl
         7k0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="MRdk4/Hy";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705000107; x=1705604907; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ujtKgzYdElVB8wVHNHccs5Uq3lFU4MiQU/UQ6sMy1oU=;
        b=W7SxpZCDCufoZp6tKrdt2lbS68gfmk/B5mQVt6zkB4WoHxlrquCbcXNF4Tta2jKp5Q
         JXyBcJtsNkir4NV8HbbIBhv++cz24ckQQ81QRYFi03Bc818ATP2DT2DLDEAa2GIIX/BX
         +mTNTdohTpP3nm64s0/ikfVupcOuVksXdmFjZ6wZC+zDbkn81WYkpEhuxI6ki+k4uUpT
         6Dc1N9K7ZgT22UJ7bEV+2+hq5HQxjYrEUiUDVGfsqfvj7AmNv0sq0guBXUMyQlGzZPNG
         TMBVHoOuDyZVie40RheJ7wwb1Vgz1lTOWQkaqCLpyy3hAOfp6AOoIJt1+rGvis0yxEFz
         ukxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705000107; x=1705604907;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ujtKgzYdElVB8wVHNHccs5Uq3lFU4MiQU/UQ6sMy1oU=;
        b=kHyGT9/fzc8aZWizZreHI/nfxua1fIX9cdleGErlOaIRVzv31xoATnJKEDnTqXdNEW
         Z0Kl8n8QBEK8wMo3g8N+hbsMfntj36S9djhA91DpVErD0T0EVVS87nyA6f1Bv1ZrGjzI
         SFdI4eazGKu6KFbduq8sroTdKsxvyAuWFvFgaxZ8XmkH3oKzoafjHZGshakrKuYKsuzl
         MIEEl9jj8Xt1O08WBLGMqB2XMl0QndCyEumTveQ0Aaw6q9BbyVDRQ5nXlx43qLc3EFvD
         jr6ojUjolrd96g/M9ZT8jYe/Ek9njxxeXB43MJHQwEfCJGoR/tzSFu7kIgZLO84dFunG
         3ztg==
X-Gm-Message-State: AOJu0Yx/mJyLbaEtY9Ct6CAFAjD2oduj0sw9HhShECahq6vFtf8KsdLy
	45wsFFC9ticMxMnN2src5SY=
X-Google-Smtp-Source: AGHT+IEGJLRovEArCwt+wLro2Uy//OdOV8uH+EKa04RH2VCMGOkWrITaObOUxuNbVhTZunpyzL3wXA==
X-Received: by 2002:a05:6512:34cc:b0:50e:745f:f456 with SMTP id w12-20020a05651234cc00b0050e745ff456mr93649lfr.24.1705000106293;
        Thu, 11 Jan 2024 11:08:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:a8f:b0:50e:7d1d:f1ff with SMTP id
 m15-20020a0565120a8f00b0050e7d1df1ffls528428lfu.1.-pod-prod-05-eu; Thu, 11
 Jan 2024 11:08:24 -0800 (PST)
X-Received: by 2002:a05:6512:3d12:b0:50e:8e98:c25c with SMTP id d18-20020a0565123d1200b0050e8e98c25cmr105906lfv.70.1705000104000;
        Thu, 11 Jan 2024 11:08:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705000103; cv=none;
        d=google.com; s=arc-20160816;
        b=grahI0XOVpViZvOUBV1JdUFChnEPFSctVI9Si5gpyjpPWX57egOxcJjhR/NoDXIS79
         7esb6kesZoW98WO+odyJFotk0ULX1Iow2iP0yne4gg0IBp19jSxEUHq5ZzEqJs4wISDx
         u643EZ15XIf27UHDEqZUHw8F2NUK2nNkvP45F+0As7wXuT9qi2lkI9PYjTW5yWw88qe2
         IokDdUid4detadJmbH50Spk/z46Tg2nqcB5pP5VeCRJzJRAcPa2ldn3wbOM6Tixv32H8
         kQ0iJ5+Te21KmhmLy8NquXJOd9a9qJzCkRMWkT9/YqhLown93IrC9z72grKdMKDuBKmn
         +6Ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=lOwO7T4CFMG6nzPWEHu/oGOp1hX9+s3u221S0T0E4Eo=;
        fh=y9FUbJak5C6gzSTedbgzGWVmwnHgqmhZsHaMuLfouUI=;
        b=iSLGNEBV3ynHT6dzGXSk2VnyhXOxWf0AtxQQo00/u7qGdKyyjBhZx8Zw6dK/0W2/sD
         QQ3VaXRe3YwV8ZSIN8mgv0ZzhXjwE2HZ3UMHJix0pDpI9CMqtbGnI//W3CRBV+thZnjI
         KuFRzqONzExal4WmrCbo+TTXPhurPSnu/WyUtnFCq300rDMX9UfvHT6agYgFHJC9lzCS
         CO1YPS/flT3WSpFKnBZt4d/YV6sQOYlhkhxFODQuXPwp/kwg4nU/GGRtFXOrBm5mEivP
         L9z9QHbhu8Zt8B08ET1ffL+hVXcKPHLvSlFlmoJXFNS2r4i8yGQxOfN/oGxLqew1GqXp
         X/UA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="MRdk4/Hy";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id k32-20020a0565123da000b0050e6bdb8f59si61403lfv.4.2024.01.11.11.08.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Jan 2024 11:08:23 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-40e5508ecb9so32460685e9.3
        for <kasan-dev@googlegroups.com>; Thu, 11 Jan 2024 11:08:23 -0800 (PST)
X-Received: by 2002:a1c:4c03:0:b0:40d:81bf:3a2f with SMTP id z3-20020a1c4c03000000b0040d81bf3a2fmr190622wmf.71.1705000103118;
        Thu, 11 Jan 2024 11:08:23 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:9c:201:986f:7ffb:7b9d:9c06])
        by smtp.gmail.com with ESMTPSA id dr3-20020a5d5f83000000b00336ca349bdesm1891337wrb.47.2024.01.11.11.08.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Jan 2024 11:08:22 -0800 (PST)
Date: Thu, 11 Jan 2024 20:08:17 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andi Kleen <ak@linux.intel.com>
Cc: Oscar Salvador <osalvador@suse.de>, andrey.konovalov@linux.dev,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v4 12/22] lib/stackdepot: use read/write lock
Message-ID: <ZaA8oQG-stLAVTbM@elver.google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
 <9f81ffcc4bb422ebb6326a65a770bf1918634cbb.1700502145.git.andreyknvl@google.com>
 <ZZUlgs69iTTlG8Lh@localhost.localdomain>
 <87sf34lrn3.fsf@linux.intel.com>
 <CANpmjNNdWwGsD3JRcEqpq_ywwDFoxsBjz6n=6vL5YksNsPyqHw@mail.gmail.com>
 <ZZ_gssjTCyoWjjhP@tassilo>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZZ_gssjTCyoWjjhP@tassilo>
User-Agent: Mutt/2.2.12 (2023-09-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="MRdk4/Hy";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Thu, Jan 11, 2024 at 04:36AM -0800, Andi Kleen wrote:
> > stackdepot is severely limited in what kernel facilities it may use
> > due to being used by such low level facilities as the allocator
> > itself.
> 
> RCU can be done quite low level too (e.g. there is NMI safe RCU)

How about the below? This should get us back the performance of the old
lock-less version. Although it's using rculist, we don't actually need
to synchronize via RCU.

Thanks,
-- Marco

------ >8 ------

From: Marco Elver <elver@google.com>
Date: Tue, 9 Jan 2024 10:21:56 +0100
Subject: [PATCH] stackdepot: make fast paths lock-less again

stack_depot_put() unconditionally takes the pool_rwlock as a writer.
This is unnecessary if the stack record is not going to be freed.
Furthermore, reader-writer locks have inherent cache contention, which
does not scale well on machines with large CPU counts.

Instead, rework the synchronization story of stack depot to again avoid
taking any locks in the fast paths. This is done by relying on RCU
primitives to give us lock-less list traversal. See code comments for
more details.

Fixes: 108be8def46e ("lib/stackdepot: allow users to evict stack traces")
Signed-off-by: Marco Elver <elver@google.com>
---
 lib/stackdepot.c | 222 ++++++++++++++++++++++++++++-------------------
 1 file changed, 133 insertions(+), 89 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index a0be5d05c7f0..9eaf46f8abc4 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -19,10 +19,13 @@
 #include <linux/kernel.h>
 #include <linux/kmsan.h>
 #include <linux/list.h>
+#include <linux/llist.h>
 #include <linux/mm.h>
 #include <linux/mutex.h>
 #include <linux/percpu.h>
 #include <linux/printk.h>
+#include <linux/rculist.h>
+#include <linux/rcupdate.h>
 #include <linux/refcount.h>
 #include <linux/slab.h>
 #include <linux/spinlock.h>
@@ -67,7 +70,8 @@ union handle_parts {
 };
 
 struct stack_record {
-	struct list_head list;		/* Links in hash table or freelist */
+	struct list_head hash_list;	/* Links in the hash table */
+	struct llist_node free_list;	/* Links in the freelist */
 	u32 hash;			/* Hash in hash table */
 	u32 size;			/* Number of stored frames */
 	union handle_parts handle;
@@ -104,7 +108,7 @@ static void *new_pool;
 /* Number of pools in stack_pools. */
 static int pools_num;
 /* Freelist of stack records within stack_pools. */
-static LIST_HEAD(free_stacks);
+static LLIST_HEAD(free_stacks);
 /*
  * Stack depot tries to keep an extra pool allocated even before it runs out
  * of space in the currently used pool. This flag marks whether this extra pool
@@ -112,8 +116,8 @@ static LIST_HEAD(free_stacks);
  * yet allocated or if the limit on the number of pools is reached.
  */
 static bool new_pool_required = true;
-/* Lock that protects the variables above. */
-static DEFINE_RWLOCK(pool_rwlock);
+/* The lock must be held when performing pool or free list modifications. */
+static DEFINE_RAW_SPINLOCK(pool_lock);
 
 static int __init disable_stack_depot(char *str)
 {
@@ -263,9 +267,7 @@ static void depot_init_pool(void *pool)
 {
 	int offset;
 
-	lockdep_assert_held_write(&pool_rwlock);
-
-	WARN_ON(!list_empty(&free_stacks));
+	lockdep_assert_held(&pool_lock);
 
 	/* Initialize handles and link stack records into the freelist. */
 	for (offset = 0; offset <= DEPOT_POOL_SIZE - DEPOT_STACK_RECORD_SIZE;
@@ -276,18 +278,25 @@ static void depot_init_pool(void *pool)
 		stack->handle.offset = offset >> DEPOT_STACK_ALIGN;
 		stack->handle.extra = 0;
 
-		list_add(&stack->list, &free_stacks);
+		llist_add(&stack->free_list, &free_stacks);
+		INIT_LIST_HEAD(&stack->hash_list);
 	}
 
 	/* Save reference to the pool to be used by depot_fetch_stack(). */
 	stack_pools[pools_num] = pool;
-	pools_num++;
+
+	/*
+	 * Release of pool pointer assignment above. Pairs with the
+	 * smp_load_acquire() in depot_fetch_stack().
+	 */
+	smp_store_release(&pools_num, pools_num + 1);
+	ASSERT_EXCLUSIVE_WRITER(pools_num);
 }
 
 /* Keeps the preallocated memory to be used for a new stack depot pool. */
 static void depot_keep_new_pool(void **prealloc)
 {
-	lockdep_assert_held_write(&pool_rwlock);
+	lockdep_assert_held(&pool_lock);
 
 	/*
 	 * If a new pool is already saved or the maximum number of
@@ -310,16 +319,16 @@ static void depot_keep_new_pool(void **prealloc)
 	 * number of pools is reached. In either case, take note that
 	 * keeping another pool is not required.
 	 */
-	new_pool_required = false;
+	WRITE_ONCE(new_pool_required, false);
 }
 
 /* Updates references to the current and the next stack depot pools. */
 static bool depot_update_pools(void **prealloc)
 {
-	lockdep_assert_held_write(&pool_rwlock);
+	lockdep_assert_held(&pool_lock);
 
 	/* Check if we still have objects in the freelist. */
-	if (!list_empty(&free_stacks))
+	if (!llist_empty(&free_stacks))
 		goto out_keep_prealloc;
 
 	/* Check if we have a new pool saved and use it. */
@@ -329,7 +338,7 @@ static bool depot_update_pools(void **prealloc)
 
 		/* Take note that we might need a new new_pool. */
 		if (pools_num < DEPOT_MAX_POOLS)
-			new_pool_required = true;
+			WRITE_ONCE(new_pool_required, true);
 
 		/* Try keeping the preallocated memory for new_pool. */
 		goto out_keep_prealloc;
@@ -362,20 +371,19 @@ static struct stack_record *
 depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 {
 	struct stack_record *stack;
+	struct llist_node *free;
 
-	lockdep_assert_held_write(&pool_rwlock);
+	lockdep_assert_held(&pool_lock);
 
 	/* Update current and new pools if required and possible. */
 	if (!depot_update_pools(prealloc))
 		return NULL;
 
 	/* Check if we have a stack record to save the stack trace. */
-	if (list_empty(&free_stacks))
+	free = llist_del_first(&free_stacks);
+	if (!free)
 		return NULL;
-
-	/* Get and unlink the first entry from the freelist. */
-	stack = list_first_entry(&free_stacks, struct stack_record, list);
-	list_del(&stack->list);
+	stack = llist_entry(free, struct stack_record, free_list);
 
 	/* Limit number of saved frames to CONFIG_STACKDEPOT_MAX_FRAMES. */
 	if (size > CONFIG_STACKDEPOT_MAX_FRAMES)
@@ -385,7 +393,6 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	stack->hash = hash;
 	stack->size = size;
 	/* stack->handle is already filled in by depot_init_pool(). */
-	refcount_set(&stack->count, 1);
 	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
 
 	/*
@@ -394,21 +401,30 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	 */
 	kmsan_unpoison_memory(stack, DEPOT_STACK_RECORD_SIZE);
 
+	/*
+	 * Release saving of the stack trace. Pairs with smp_mb() in
+	 * depot_fetch_stack().
+	 */
+	smp_mb__before_atomic();
+	refcount_set(&stack->count, 1);
+
 	return stack;
 }
 
 static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 {
+	/* Acquire the pool pointer written in depot_init_pool(). */
+	const int pools_num_cached = smp_load_acquire(&pools_num);
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
 
@@ -417,15 +433,35 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 		return NULL;
 
 	stack = pool + offset;
+
+	/*
+	 * Acquire the stack trace. Pairs with smp_mb() in depot_alloc_stack().
+	 *
+	 * This does not protect against a stack_depot_put() freeing the record
+	 * and having it subsequently being reused. Callers are responsible to
+	 * avoid using stack depot handles after passing to stack_depot_put().
+	 */
+	if (!refcount_read(&stack->count))
+		return NULL;
+	smp_mb__after_atomic();
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
+	list_del_rcu(&stack->hash_list);
+	printk_deferred_exit();
+	raw_spin_unlock_irqrestore(&pool_lock, flags);
 
-	list_add(&stack->list, &free_stacks);
+	llist_add(&stack->free_list, &free_stacks);
 }
 
 /* Calculates the hash for a stack. */
@@ -453,22 +489,55 @@ int stackdepot_memcmp(const unsigned long *u1, const unsigned long *u2,
 
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
 
-	lockdep_assert_held(&pool_rwlock);
+	/*
+	 * Due to being used from low-level code paths such as the allocators,
+	 * NMI, or even RCU itself, stackdepot cannot rely on primitives that
+	 * would sleep (such as synchronize_rcu()) or end up recursively call
+	 * into stack depot again (such as call_rcu()).
+	 *
+	 * Instead, lock-less readers only rely on RCU primitives for correct
+	 * memory ordering, but do not use RCU-based synchronization otherwise.
+	 * Instead, we perform 3-pass validation below to ensure that the stack
+	 * record we accessed is actually valid. If we fail to obtain a valid
+	 * stack record here, the slow-path in stack_depot_save_flags() will
+	 * retry to avoid inserting duplicates.
+	 *
+	 * If STACK_DEPOT_FLAG_GET is not used, it is undefined behaviour to
+	 * call stack_depot_put() later - i.e. in the non-refcounted case, we do
+	 * not have to worry that the entry will be recycled.
+	 */
+
+	list_for_each_entry_rcu(stack, bucket, hash_list) {
+		/* 1. Check if this entry could potentially match. */
+		if (data_race(stack->hash != hash || stack->size != size))
+			continue;
+
+		/*
+		 * 2. Increase refcount if not zero. If this is successful, we
+		 *    know that this stack record is valid and will not be freed by
+		 *    stack_depot_put().
+		 */
+		if ((flags & STACK_DEPOT_FLAG_GET) && unlikely(!refcount_inc_not_zero(&stack->count)))
+			continue;
+
+		/* 3. Do full validation of the record. */
+		if (likely(stack->hash == hash && stack->size == size &&
+			   !stackdepot_memcmp(entries, stack->entries, size))) {
+			ret = stack;
+			break;
+		}
 
-	list_for_each(pos, bucket) {
-		found = list_entry(pos, struct stack_record, list);
-		if (found->hash == hash &&
-		    found->size == size &&
-		    !stackdepot_memcmp(entries, found->entries, size))
-			return found;
+		/* Undo refcount - could have raced with stack_depot_put(). */
+		if ((flags & STACK_DEPOT_FLAG_GET) && unlikely(refcount_dec_and_test(&stack->count)))
+			depot_free_stack(stack);
 	}
-	return NULL;
+
+	return ret;
 }
 
 depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
@@ -482,7 +551,6 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 	struct page *page = NULL;
 	void *prealloc = NULL;
 	bool can_alloc = depot_flags & STACK_DEPOT_FLAG_CAN_ALLOC;
-	bool need_alloc = false;
 	unsigned long flags;
 	u32 hash;
 
@@ -505,31 +573,16 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
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
@@ -543,31 +596,33 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
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
+	} else if (prealloc) {
 		/*
 		 * Stack depot already contains this stack trace, but let's
 		 * keep the preallocated memory for future.
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
@@ -592,7 +647,6 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 			       unsigned long **entries)
 {
 	struct stack_record *stack;
-	unsigned long flags;
 
 	*entries = NULL;
 	/*
@@ -604,13 +658,12 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
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
+	 * Should never be NULL, otherwise this is a use-after-put.
+	 */
+	if (WARN_ON(!stack))
+		return 0;
 
 	*entries = stack->entries;
 	return stack->size;
@@ -620,29 +673,20 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
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
+	/*
+	 * Should always be able to find the stack record, otherwise this is an
+	 * unbalanced put attempt.
+	 */
 	if (WARN_ON(!stack))
-		goto out;
-
-	if (refcount_dec_and_test(&stack->count)) {
-		/* Unlink stack from the hash table. */
-		list_del(&stack->list);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZaA8oQG-stLAVTbM%40elver.google.com.
