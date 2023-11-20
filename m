Return-Path: <kasan-dev+bncBAABB45X52VAMGQE52Q5K6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id AE8837F1B6B
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:48:36 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2c883c7380fsf10763871fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:48:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502516; cv=pass;
        d=google.com; s=arc-20160816;
        b=eT2LDjeRL6+9AWcyqCKY81885DeiQdMGm0mN79bqeFqTq78RHDhJtjRG4516FFQxAF
         Z5anlbnF3dNwYZuu+Q6DK/ikt5wVMYt5j5y4cJd//n6b0vndtuVOUwuaQNHPXQxbkBHP
         w/5TaSI9CqnUEtKtarfLhebxCp+06gJyzqFXQaly7EAKPAie38WlCOJTqxmRoGUO09ly
         1iJ+7PJnQlgKUAgG0SbIkip2UQ8oPLzHIgLw1/u8KXMf3GL89iNXAzC1GeiNDy8J/WGB
         gVlc2yEkDSL4UG1P5aJ8P6OewX5vftpcgJgxQkBnOFbU5467aGuXSFoLGKkcCqLSUYwG
         EA1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Nrurw1TSx9y0g2J2tALt5mdA1KBU+pY+nZ7k6Mk7bVU=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=Gv/cioxVdzaf5EJWTaBGT/LkZND0FBcH4IUxZXnprRNT6VNKh8+4SNBpSTblRca0jY
         w2tcR08RaY8A2PFXBhc3yKevrdt6bh8/mRtVYqbhi52oNAR9VZFGi5scKiyQkDhBTsPS
         OnakiU432nKziuafS9NYQ0x/jZs5mm8BNT86zoy+6kDRInwOpvHWcGJos/hFxLGN1E1M
         0HcuqjSo4VqMnnf4podiSFBjGvvVCVD3XUM4Q8ETnZPIHTjETXJq6EA2pCcICUc6jmV7
         EdpVMfd0YHiGqQZV1mBaml6jT4QrJT+n3LXpUXuPesk8bBvJ+I86oQGSon/Hp9cefIGQ
         WqbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ukcrau9r;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.188 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502516; x=1701107316; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Nrurw1TSx9y0g2J2tALt5mdA1KBU+pY+nZ7k6Mk7bVU=;
        b=eqD0RJLwaFRZbqoguTYI91ZdJLSepCDmkve0BUN8fuUVoV4eBRLvwzs9f8I8vFloFp
         nlhAon9wdOwk+RcauA44H2RXp4DGYZ2QZ1e03xgWF71ARCp4m6XzBeCLgN4Amnd2Mhia
         SYXkA0d3qX0yhLmbAo6fL4cfseVe+uyHe10FlmL322Fxx8mbQHlqoRvujyp5NmdHFBfu
         tR23lrFrReAHjqwLbl9bXptst13x6ZEKpj0aJGc1fy8DVWAlxviXwcBx33ywOtt/8XSi
         O2qRcKtlofE6n29WSnmWsluHotAx5RaahwR0LFhaLldWl2X+Izdkwb38jfs7ftMT4dLu
         5CQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502516; x=1701107316;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Nrurw1TSx9y0g2J2tALt5mdA1KBU+pY+nZ7k6Mk7bVU=;
        b=kfUfaZ4l6A5HdQAdg+rKdbba3jVneaXHqgQTO0T6bDnwnssXIs3HXeHpPqcfy666fO
         Ug2JI6urX6syWFuPEg0MjeHMf9TFg928M7RPjad0If1T44CpssBeRyBULL8zI2drDeo/
         vTagZCWu3etdLOSSxVzj6INiaw+Y00QkHdhC5GSoMwg8vxIjJe99ID5H6C40Ws2SXBvg
         kGrZk/6Tytpl7SqdD+yCEZjda4Z7OxvuTA8OdeGSk1WcjAgzQ+o7cA1BIt1TT9pjyRaI
         c3FbvPjCRBQbCJGm1sn7WuwVpVIO/4qa+I2jXWpAGkqs6T0RzwT8yMR4YG2Y9zVv8E00
         uajQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyOb1N+rnsBCteQdPohfrbljb6UpZc5iZRRxRZ5u+Kjw9gsX154
	sakSJPXc/oTgpwgIk7Lm/2M=
X-Google-Smtp-Source: AGHT+IHlakMbv0UjWeRPVKhIm9hAAsKfuIkKOLfHpzLLt5Xg/re2/7PpQOWR8rb8pKV2x4W61FBVfQ==
X-Received: by 2002:a2e:7009:0:b0:2c8:87ad:fd85 with SMTP id l9-20020a2e7009000000b002c887adfd85mr1231748ljc.28.1700502515744;
        Mon, 20 Nov 2023 09:48:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:10a7:b0:2c2:9016:aa8f with SMTP id
 k7-20020a05651c10a700b002c29016aa8fls1420366ljn.2.-pod-prod-07-eu; Mon, 20
 Nov 2023 09:48:34 -0800 (PST)
X-Received: by 2002:a2e:9011:0:b0:2bc:b9c7:7ba8 with SMTP id h17-20020a2e9011000000b002bcb9c77ba8mr5543271ljg.43.1700502514114;
        Mon, 20 Nov 2023 09:48:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502514; cv=none;
        d=google.com; s=arc-20160816;
        b=FBVxFlueBNtycSolewUBTdQ0d/kmiNr0Yx4eOv/7atHWhoChwea8Co6eqUxOvvJJGr
         BtxAfs+flqZwm/v5b2l+s51eOKe4HBdaJTD+C7SLxNMuuZPEMLFNHr4+cxNTqUHE8gga
         dwHiUTKzREkRKlYVVuD+ur+7vhTWHtHhJroXRdXd+qqhN9KBaRyaGwiPzyCeivUl+HJe
         2KnCFFnZrA7LwckMW8MbtDQmfcveZON2/FcJ3kxqQFtJOI2j+sf8jsIDjhCZ947ZkwTe
         pRD/ZsfL2LQR0wj0wE+81NrG0nqkc+nuqfxogmgxnO8QZuvx7fs4O6hWJGaJzB8vpUmO
         e59g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ul/nKw7kj0oOeSlF9NlnEwH7YAqJQYzQqOqaJ7LWVgY=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=Ih9Ya3HJ1jWPuJ5/NbtHQo63wlqrRmGhVeZo5JI9SLum3iK9TBggxVi+MTgEwD1x3K
         a6i1u8bBsFwfvcSvOHX7bel75JeUuWmL/lafJaBa59lQxUPoUAVWAgQLOXJd0qod4+/4
         I2nMLgEeUCeoxqPKj/BBKrRVn+qkmNYvZXsVi5zWHwF5GbM23L7QmXFOsK3EGT0XrPhO
         bFiSvhvdaRy6PIXjgMSIJV50ObCQxfb9YOjS5VQL+/peg4+k/NkvTKoA6jZo+wbou3jx
         MmPmud5R+2HYDdxJGQgYs8/U56B59voRoiv44o+Do0T6BTRmvn+/ye0R90333qdpQ8T/
         TYHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ukcrau9r;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.188 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-188.mta0.migadu.com (out-188.mta0.migadu.com. [91.218.175.188])
        by gmr-mx.google.com with ESMTPS id e21-20020a2e9855000000b002bced4ef910si337827ljj.3.2023.11.20.09.48.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:48:34 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.188 as permitted sender) client-ip=91.218.175.188;
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
Subject: [PATCH v4 07/22] lib/stackdepot: fix and clean-up atomic annotations
Date: Mon, 20 Nov 2023 18:47:05 +0100
Message-Id: <c118ef044d8db80248d9e1f14592c72e8429e9d9.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ukcrau9r;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.188
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

Drop smp_load_acquire from next_pool_required in depot_init_pool, as both
depot_init_pool and the all smp_store_release's to this variable are
executed under the stack depot lock.

Also simplify and clean up comments accompanying the use of atomic
accesses in the stack depot code.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

This patch is not strictly required, as the atomic accesses are fully
removed in one of the latter patches. However, I decided to keep the
patch just in case we end up needing these atomics in the following
iterations of this series.

Changes v2->v3:
- Keep parentheses when referring to functions in comments.
- Add comment that explains why depot_init_pool reads next_pool_required
  non-atomically.

Changes v1->v2:
- Minor comment fix as suggested by Marco.
- Drop READ_ONCE marking for next_pool_required.
---
 lib/stackdepot.c | 29 ++++++++++++++---------------
 1 file changed, 14 insertions(+), 15 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 682497dbe081..cfa3c6c7cc2e 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -231,10 +231,10 @@ static void depot_init_pool(void **prealloc)
 	/*
 	 * If the next pool is already initialized or the maximum number of
 	 * pools is reached, do not use the preallocated memory.
-	 * smp_load_acquire() here pairs with smp_store_release() below and
-	 * in depot_alloc_stack().
+	 * Access next_pool_required non-atomically, as there are no concurrent
+	 * write accesses to this variable.
 	 */
-	if (!smp_load_acquire(&next_pool_required))
+	if (!next_pool_required)
 		return;
 
 	/* Check if the current pool is not yet allocated. */
@@ -255,8 +255,8 @@ static void depot_init_pool(void **prealloc)
 		 * At this point, either the next pool is initialized or the
 		 * maximum number of pools is reached. In either case, take
 		 * note that initializing another pool is not required.
-		 * This smp_store_release pairs with smp_load_acquire() above
-		 * and in stack_depot_save().
+		 * smp_store_release() pairs with smp_load_acquire() in
+		 * stack_depot_save().
 		 */
 		smp_store_release(&next_pool_required, 0);
 	}
@@ -279,7 +279,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 
 		/*
 		 * Move on to the next pool.
-		 * WRITE_ONCE pairs with potential concurrent read in
+		 * WRITE_ONCE() pairs with potential concurrent read in
 		 * stack_depot_fetch().
 		 */
 		WRITE_ONCE(pool_index, pool_index + 1);
@@ -287,8 +287,8 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 		/*
 		 * If the maximum number of pools is not reached, take note
 		 * that the next pool needs to initialized.
-		 * smp_store_release() here pairs with smp_load_acquire() in
-		 * stack_depot_save() and depot_init_pool().
+		 * smp_store_release() pairs with smp_load_acquire() in
+		 * stack_depot_save().
 		 */
 		if (pool_index + 1 < DEPOT_MAX_POOLS)
 			smp_store_release(&next_pool_required, 1);
@@ -329,7 +329,7 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 {
 	union handle_parts parts = { .handle = handle };
 	/*
-	 * READ_ONCE pairs with potential concurrent write in
+	 * READ_ONCE() pairs with potential concurrent write in
 	 * depot_alloc_stack().
 	 */
 	int pool_index_cached = READ_ONCE(pool_index);
@@ -419,8 +419,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 
 	/*
 	 * Fast path: look the stack trace up without locking.
-	 * The smp_load_acquire() here pairs with smp_store_release() to
-	 * |bucket| below.
+	 * smp_load_acquire() pairs with smp_store_release() to |bucket| below.
 	 */
 	found = find_stack(smp_load_acquire(bucket), entries, nr_entries, hash);
 	if (found)
@@ -430,8 +429,8 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	 * Check if another stack pool needs to be initialized. If so, allocate
 	 * the memory now - we won't be able to do that under the lock.
 	 *
-	 * The smp_load_acquire() here pairs with smp_store_release() to
-	 * |next_pool_inited| in depot_alloc_stack() and depot_init_pool().
+	 * smp_load_acquire() pairs with smp_store_release() in
+	 * depot_alloc_stack() and depot_init_pool().
 	 */
 	if (unlikely(can_alloc && smp_load_acquire(&next_pool_required))) {
 		/*
@@ -457,8 +456,8 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		if (new) {
 			new->next = *bucket;
 			/*
-			 * This smp_store_release() pairs with
-			 * smp_load_acquire() from |bucket| above.
+			 * smp_store_release() pairs with smp_load_acquire()
+			 * from |bucket| above.
 			 */
 			smp_store_release(bucket, new);
 			found = new;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c118ef044d8db80248d9e1f14592c72e8429e9d9.1700502145.git.andreyknvl%40google.com.
