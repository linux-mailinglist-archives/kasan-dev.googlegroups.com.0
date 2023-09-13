Return-Path: <kasan-dev+bncBAABBTG4Q6UAMGQEEHTYBEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A82A79F017
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:15:58 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2bce272ebdfsf360661fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:15:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694625357; cv=pass;
        d=google.com; s=arc-20160816;
        b=wkVLRjAUK4UOWrOQd7fUO9YQxak6awZnq7FvgHbn4kCMRO7lgIPB6dvIUmMTBOS8mo
         LHh4Bp+dbV4ML6epajzqUQkUfM3R7KPFM917TSnKLT+/juSDUMsdC19DSSoc6pLZSzI4
         jrt2qTV9yKI+A1wF1nLHwzELhlWrTDxGpOmu3J7AOXSeLcL9d/A+ovlngH/vhDW/QNEW
         Wyy1lc0rQickQbsoO87sd7aAaT8JBCB8jF/BMoooWLKWPKtwun009ShCStT7aL65A//f
         c2qQiwgbHSwhNEzJeFTg7WddN2Kx3qeY4LRk5qBob7cvCOkneunN46W193IIsk7Kx6UQ
         jY6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=M0xbFrSAJlwDCtJTXntZ2jyW7ioDKIm4o0IydPU9Fe8=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=WBQ0fbPF2R237YhiGRJfcI/+KZ73b3mPcDJr/WX0xSGdOaKZRTDYx8Dg3xEq7DP4Qa
         gJpGGVwiZVmKz44+ZJy63/AoKdUj7eytxwGxXdB/LnGQrlZ9yQbJ9FYF4FoQX8rIrIS1
         +XIKa1r0cmEEQdnD2c7pV60WzC/V+EPVpzly2sHS84IjWtiUS7MXg7YaiKMDndtbjB04
         g8Uh3eUD+FeOy48NPtTjkpshsFE1c72XwTuEwCxLQUy1GaP87IsefsmIcAa4Nv2elrCS
         SKrgQxsiN7wvpop0fMHdtyHzrrQ2O01SYMLtPzmrdhChE/H65ksfocJP6LhD9JAFvVjs
         uLBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TYMgdFjb;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.224 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694625357; x=1695230157; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=M0xbFrSAJlwDCtJTXntZ2jyW7ioDKIm4o0IydPU9Fe8=;
        b=lgahru43T9BjUcEsmfKVYpxzcL4nAYRQnjegs7StU5UrDsD+CoURDAQiahubUgKdDf
         Cp/rabrLkbmQZlG6xzfsjWaRj9PGJWCDVdqjRWY4nJs6QXYs43kyjxL3HhHPb0x2xits
         mQO2LzRja8TycTlBrtovM8HaeoznXEAuup0pFZCNLJFi08R2MZS00jOj7sV/CuiM5T7T
         qdXMe285Vl+IBmWNRW1WOfYQPnZDChALC4XRwUN8fqnrXwNr/hAR3aneUh13Ymx4o/3+
         U4BQ+Uu9kCs8vVwvirJnkTrbrncho67oCL0Gp8D1XsZzDYXtNXLI3jt7paOArGvrivJU
         Xf3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694625357; x=1695230157;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=M0xbFrSAJlwDCtJTXntZ2jyW7ioDKIm4o0IydPU9Fe8=;
        b=tzq5FOhzPEVoptVh2NB1bwwSx97ChTZpxBzlIxlfd0rEQlMj/eqAJFqVJSV1+xQzLi
         lkrO4I6HS8H/y+VE9+s/E4ZOxlsLLX/WmuLyUG5yjfMvXOrsFBor+kx6rhrPY7KGd/jo
         wZ1uvcLhN1IbIlaRH36e0ZAIIWqIKcGGKNa1gDf2oab6i+EH5fVAmlbFk1X2HHwsxIGB
         iQEmcSlyIr1HrodufxUVET6zEjXPjp80OGFHJ5QOA2j6T37nO6SijLEPDnknkkGfTRhF
         MOUdZuIXQPxRQzXikd9SylyfhWoKlguzfteNhTc6M4kta9o8slHawxdasnbJc803Hy/w
         hVlw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyTrptn+TjZBVz0TnRkd2ocKd0v3JZMhm5Xvu+TraQVWrmbFDZu
	RtTGOX8ETEzUSeZwli8v/vk=
X-Google-Smtp-Source: AGHT+IGWnAsxsDnm3Ozv2yWtZKnAKzre8nCcKZSEG78znkiJew/TeiShDdE16l3Bp6OsWDUHSKcL3Q==
X-Received: by 2002:a2e:9f4e:0:b0:2b6:e2e4:7d9a with SMTP id v14-20020a2e9f4e000000b002b6e2e47d9amr3368350ljk.38.1694625356645;
        Wed, 13 Sep 2023 10:15:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc82:0:b0:2b9:6182:b0a4 with SMTP id h2-20020a2ebc82000000b002b96182b0a4ls598783ljf.2.-pod-prod-05-eu;
 Wed, 13 Sep 2023 10:15:55 -0700 (PDT)
X-Received: by 2002:a05:6512:6c9:b0:4fd:d213:dfd0 with SMTP id u9-20020a05651206c900b004fdd213dfd0mr3744231lff.11.1694625355173;
        Wed, 13 Sep 2023 10:15:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694625355; cv=none;
        d=google.com; s=arc-20160816;
        b=ec7XPb6SXdMbUFR9L6EZt5EM+fzwnQoH6CDF5rV9r48ftPIOyGs3xEE7zJsmC/hp2v
         Wt2Upi+Et91ge1wbTMrjn03y/rllz9KXQgBjBcKxMpHyow5ImudBh//58nTb0haLn2Y3
         5aL8BTyOM+KwybHrYA5MHbzcknT/uucQNoHh1v12xIjx2iAOm6mNCKijMspD9qUvmEgn
         I/LZPdi0FzXowhApQSXJHn/zxv0K0UPFnoDWvo0xtcmbwvyILVgz/Zag7+Ge7fjwGzMi
         aA3tsFDMFnLl7XLw68Z5/4EUCiEv+lI6OwmU7n/OzcIUbhwp2gsJ4OvabDP0AfavPZ2f
         uQ7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0rCvfJyQVclVcl+nE6KRDaf9jMIyS6A7Wyxgy4VzHmE=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=Jb78L1fn1xdIarDr/5f8i/zE224vNYiSIkH6rs1PE+UhTuEUldWlZyZgBeXqjPQwpx
         PR1Rb9r3ezGyi951X2viy6XaoURoxshhuvGuOUA/O86oOJr80oAhbZjcmcnxFQdPfsjm
         4K9iJqZ2f8cKDLFvh1k8qVTsOO3KZcyMYaUgonLX9LzCjDnGVa+vFI2auL+KI0P5Y0og
         EwgqkqJmTkfHXbZl6A7uxEeBjBRBeNGi+44GwyR6vClSFKEk7JgtW/eCInbFquYNvq6c
         Mj/WVHmlWepqxwhZCLppex6+YwWSJt74TJdHbCA7DDHaUqqA2mHwRWBWJFTuVZRMw3EA
         0bNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TYMgdFjb;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.224 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-224.mta1.migadu.com (out-224.mta1.migadu.com. [95.215.58.224])
        by gmr-mx.google.com with ESMTPS id n10-20020a05651203ea00b00500d9706548si965413lfq.12.2023.09.13.10.15.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Sep 2023 10:15:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.224 as permitted sender) client-ip=95.215.58.224;
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
Subject: [PATCH v2 06/19] lib/stackdepot: fix and clean-up atomic annotations
Date: Wed, 13 Sep 2023 19:14:31 +0200
Message-Id: <e78360a883edac7bc3c6a351c99a6019beacf264.1694625260.git.andreyknvl@google.com>
In-Reply-To: <cover.1694625260.git.andreyknvl@google.com>
References: <cover.1694625260.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=TYMgdFjb;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.224 as
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

Simplify comments accompanying the use of atomic accesses in the
stack depot code.

Also drop smp_load_acquire from next_pool_required in depot_init_pool,
as both depot_init_pool and the all smp_store_release's to this variable
are executed under the stack depot lock.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

This patch is not strictly required, as the atomic accesses are fully
removed in one of the latter patches. However, I decided to keep the
patch just in case we end up needing these atomics in the following
iterations of this series.

Changes v1->v2:
- Minor comment fix as suggested by Marco.
- Drop READ_ONCE marking for next_pool_required.
---
 lib/stackdepot.c | 27 ++++++++++++---------------
 1 file changed, 12 insertions(+), 15 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 128ece21afe9..babd453261f0 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -225,10 +225,8 @@ static void depot_init_pool(void **prealloc)
 	/*
 	 * If the next pool is already initialized or the maximum number of
 	 * pools is reached, do not use the preallocated memory.
-	 * smp_load_acquire() here pairs with smp_store_release() below and
-	 * in depot_alloc_stack().
 	 */
-	if (!smp_load_acquire(&next_pool_required))
+	if (!next_pool_required)
 		return;
 
 	/* Check if the current pool is not yet allocated. */
@@ -249,8 +247,8 @@ static void depot_init_pool(void **prealloc)
 		 * At this point, either the next pool is initialized or the
 		 * maximum number of pools is reached. In either case, take
 		 * note that initializing another pool is not required.
-		 * This smp_store_release pairs with smp_load_acquire() above
-		 * and in stack_depot_save().
+		 * smp_store_release pairs with smp_load_acquire in
+		 * stack_depot_save.
 		 */
 		smp_store_release(&next_pool_required, 0);
 	}
@@ -274,15 +272,15 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 		/*
 		 * Move on to the next pool.
 		 * WRITE_ONCE pairs with potential concurrent read in
-		 * stack_depot_fetch().
+		 * stack_depot_fetch.
 		 */
 		WRITE_ONCE(pool_index, pool_index + 1);
 		pool_offset = 0;
 		/*
 		 * If the maximum number of pools is not reached, take note
 		 * that the next pool needs to initialized.
-		 * smp_store_release() here pairs with smp_load_acquire() in
-		 * stack_depot_save() and depot_init_pool().
+		 * smp_store_release pairs with smp_load_acquire in
+		 * stack_depot_save.
 		 */
 		if (pool_index + 1 < DEPOT_MAX_POOLS)
 			smp_store_release(&next_pool_required, 1);
@@ -324,7 +322,7 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 	union handle_parts parts = { .handle = handle };
 	/*
 	 * READ_ONCE pairs with potential concurrent write in
-	 * depot_alloc_stack().
+	 * depot_alloc_stack.
 	 */
 	int pool_index_cached = READ_ONCE(pool_index);
 	void *pool;
@@ -413,8 +411,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 
 	/*
 	 * Fast path: look the stack trace up without locking.
-	 * The smp_load_acquire() here pairs with smp_store_release() to
-	 * |bucket| below.
+	 * smp_load_acquire pairs with smp_store_release to |bucket| below.
 	 */
 	found = find_stack(smp_load_acquire(bucket), entries, nr_entries, hash);
 	if (found)
@@ -424,8 +421,8 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	 * Check if another stack pool needs to be initialized. If so, allocate
 	 * the memory now - we won't be able to do that under the lock.
 	 *
-	 * The smp_load_acquire() here pairs with smp_store_release() to
-	 * |next_pool_inited| in depot_alloc_stack() and depot_init_pool().
+	 * smp_load_acquire pairs with smp_store_release in depot_alloc_stack
+	 * and depot_init_pool.
 	 */
 	if (unlikely(can_alloc && smp_load_acquire(&next_pool_required))) {
 		/*
@@ -451,8 +448,8 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		if (new) {
 			new->next = *bucket;
 			/*
-			 * This smp_store_release() pairs with
-			 * smp_load_acquire() from |bucket| above.
+			 * smp_store_release pairs with smp_load_acquire
+			 * from |bucket| above.
 			 */
 			smp_store_release(bucket, new);
 			found = new;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e78360a883edac7bc3c6a351c99a6019beacf264.1694625260.git.andreyknvl%40google.com.
