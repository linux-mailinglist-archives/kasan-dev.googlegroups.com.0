Return-Path: <kasan-dev+bncBAABBTO4Q6UAMGQEJW65UXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EAA579F019
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:15:59 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2bd09fdec5csf364581fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:15:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694625358; cv=pass;
        d=google.com; s=arc-20160816;
        b=QBScnegCOCEsY6/mn+ERmH4fFMzqlJqjq6Rm+LayhLD6EOSuz4Fsxai71dNoA5n98m
         B8u2rS1w0q0ICVCBCpAqLpjP5XvexaAuLhdfKwFG+ET6XIosu9+3OVcBanA8kBwyl2zW
         wFkncAM7aezRXPy3bn06EqJIoVOK3hYGKayqdVu2pUzG7mYbU5nZBxYtZA9iW+yAlzvX
         0CJMuKpZ841GnEot0ru6Q6vcq4kLNFFTpEqWMvtkcpNd17bDQrXkNxsmLK4gRMvnQ7oL
         aDsgJgU4rASgCfCQcf8DHBBzPH8FvCLWkiay+UMJAZ/RTbEbK/BPZcPHi2GRfD8sRik8
         x+bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=BznIYPOqR9t2uP1LLG6otCyBmmIbNc4oFEqdt1IM950=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=BYLhwkv92HYMxKBd9fwc5Op/Q79jE1l9WTLpHhj+aSqIO+DKQqDnPjqfHCCgZT729L
         vgR0775j2Fnl6JSme7lkFptwVJzbFEK2y6NowQwYRXZMoSiMelEMpgs3drcLcA2IMcep
         fwzCmsxpa83VVA18kw+eoCu7470nGoSxSpcyck04wHK/GfJDdr8QgE9xSEz9uzq0KtaS
         CVk9keCL2lEeK59A7UPba4mATkxMLFENTYFfIjT0n+ZClGOeQsI/Wf1WG8aSQIOS46V+
         gcD74UmNFRfnYoc0ql1g6GPbKR0sTkNmcN/QjXh/61kc1V7TDDdgHr1UcazkOS4rJkUN
         Yssg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=n8pGZUmY;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::d2 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694625358; x=1695230158; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BznIYPOqR9t2uP1LLG6otCyBmmIbNc4oFEqdt1IM950=;
        b=hXGhnFfb5UOElYc+IxpsV7oKYMB9PsEy+FQM/OgXvoTX0OOK58En6DOf7WxiIbKd1b
         zr6PtL0O6qk4Cv8yTtqoUNpktV4acKjTm2yPyzctcp/tXybaJ+wRW78o9yd2kA4IdfH5
         SIwvcQwdXSUAd+iKzHkHW8QUDa/WdKAIpydY9HWlL0OXTgVhvO0gj5iI5O6itifDfkH2
         4RpHa6gaMd3/q2s8T+8YYZ+e6YJJPz0ZAkE6xM0KTz+UzqYOVxF1gsAS9UL58KolwW3M
         uUVa+yp8ObjP2ec+DdM/cVbBRpIVq67aPEqjvgGIdKqKLCaCUgy+TAnzSP+fAi2oiV/Y
         WQ1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694625358; x=1695230158;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BznIYPOqR9t2uP1LLG6otCyBmmIbNc4oFEqdt1IM950=;
        b=qyRtGkjKoYTRiqMcwslJ6nXiZoWeFALBSfoYnB50Qce8DPLpN1EhzhapKeBwJes2BR
         zQQHZ2ruagbcICCpffuuvXgQPSbfw13m0dpgmAJMtSarI5upSnhCD8fVq+6P82GnvNaU
         vSDtS2A7urItXoqYTEhGR8z0EYcFsspCmJAX7UUktXj+Nb+QHH/T7fFXU4OKi5bDSxOU
         gnyZRjbNLablYSn300ekw5jD2UPFnolwQh8+5IdAwg6NXq5Gfxg0+wMhxCAMiaMOGFsh
         nQvRmoQnycT9gCL5MPdZ8uc0CPVDkr1LxFGCIEnbRU9Kz5qbQ1LTiYVsbFF2yktekSc4
         y+wQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzNNxuCUTc7n7txdM5T+1k4qbxmZgo34P3MAtLcFnN+Thp/m0eP
	x8ssGzaZNi5wQAOT8EjviuU=
X-Google-Smtp-Source: AGHT+IGjWv3EDoJvS7PdmMoz462qZ6UQcouPRGQqGeKrTxZAC/lNR8glJAwWHGCrPLpRyV/WNJS3+g==
X-Received: by 2002:a2e:8083:0:b0:2bb:a123:2db7 with SMTP id i3-20020a2e8083000000b002bba1232db7mr2531204ljg.51.1694625357783;
        Wed, 13 Sep 2023 10:15:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:91ce:0:b0:2bc:b890:64b3 with SMTP id u14-20020a2e91ce000000b002bcb89064b3ls741727ljg.0.-pod-prod-04-eu;
 Wed, 13 Sep 2023 10:15:56 -0700 (PDT)
X-Received: by 2002:a2e:9057:0:b0:2b6:d790:d1a3 with SMTP id n23-20020a2e9057000000b002b6d790d1a3mr2656899ljg.11.1694625356355;
        Wed, 13 Sep 2023 10:15:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694625356; cv=none;
        d=google.com; s=arc-20160816;
        b=xmyTiocXjIeMiwe/xrqFOks9pRUa4lTwCWZb1ihGvEQ6hQk8/pXh3472NMS7PVpoaN
         hXywsQmICsMX1tqSoAHaorMTn2EoZmxhNNNIjuuCmyjq4G8rQ38e3mJTsJJQm13n6Bm0
         2Ninka6QjJMNlaD2U4LodZQ8Znh6LLGyxRNyE5PPD8qxDazbCMg/MbqnXnaMeFMXdx5B
         BGQLGSbhoPljZbnR89SEDElsepowc00+e4WrT+V8EoIha3J3ATXT+dsYHBZBa1L2MkAZ
         lNhTIp+rjNe/+16x74+N3+2rtRFLk7i17F5MUI0mUXksP6ehWBxUzxWfzhG2AVIIFcgs
         Aq/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0/KQC+g9eK7MZLi0iRkQvuX1rPqJBRg75npInF3Ouo8=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=oluZ+ksvcmJX1Pnw0qAYo18x5j8p/9qgESuYJgZUK/SIzRKypjmSmKEweSCkw/BQ8w
         jU9cPpl4dwStzaqP7p/2ouREGBFBxkpRZJd8RXarG5VOmiAe4vBHQ2JwxkUnArAC6L6M
         HUgwPGOR3ppVL5dz2FzCXfA6VyPAGGB5wH2umOY+9aEq0KCN+c+X6KQGhaGk7ZqiXmEX
         rW3XnEW5hrKqgh0hLL9/t11AkA+763uLtaaKBxs6xpP5xLPxbCy0OZgI6vyoY47CVBRl
         7z9QrgIJC6lhYKuvHYCis5uOiQ2cOOrWXYMUf3cTHeu33gO4ByJfjGHpt60wkpF/mE22
         Rr9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=n8pGZUmY;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::d2 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-210.mta1.migadu.com (out-210.mta1.migadu.com. [2001:41d0:203:375::d2])
        by gmr-mx.google.com with ESMTPS id r3-20020a2e80c3000000b002bb9bc937aesi837333ljg.8.2023.09.13.10.15.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Sep 2023 10:15:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::d2 as permitted sender) client-ip=2001:41d0:203:375::d2;
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
Subject: [PATCH v2 08/19] lib/stackdepot: rename next_pool_required to new_pool_required
Date: Wed, 13 Sep 2023 19:14:33 +0200
Message-Id: <e074fa3f4962897b84afb3d65767f5fc3b5d1234.1694625260.git.andreyknvl@google.com>
In-Reply-To: <cover.1694625260.git.andreyknvl@google.com>
References: <cover.1694625260.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=n8pGZUmY;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::d2 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Rename next_pool_required to new_pool_required.

This a purely code readability change: the following patch will change
stack depot to store the pointer to the new pool in a separate variable,
and "new" seems like a more logical name.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 45 ++++++++++++++++++++++-----------------------
 1 file changed, 22 insertions(+), 23 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index e85b658be050..e428f470faf6 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -93,12 +93,11 @@ static size_t pool_offset;
 static DEFINE_RAW_SPINLOCK(pool_lock);
 /*
  * Stack depot tries to keep an extra pool allocated even before it runs out
- * of space in the currently used pool.
- * This flag marks that this next extra pool needs to be allocated and
- * initialized. It has the value 0 when either the next pool is not yet
- * initialized or the limit on the number of pools is reached.
+ * of space in the currently used pool. This flag marks whether this extra pool
+ * needs to be allocated. It has the value 0 when either an extra pool is not
+ * yet allocated or if the limit on the number of pools is reached.
  */
-static int next_pool_required = 1;
+static int new_pool_required = 1;
 
 static int __init disable_stack_depot(char *str)
 {
@@ -219,18 +218,18 @@ int stack_depot_init(void)
 }
 EXPORT_SYMBOL_GPL(stack_depot_init);
 
-/* Keeps the preallocated memory to be used for the next stack depot pool. */
-static void depot_keep_next_pool(void **prealloc)
+/* Keeps the preallocated memory to be used for a new stack depot pool. */
+static void depot_keep_new_pool(void **prealloc)
 {
 	/*
-	 * If the next pool is already saved or the maximum number of
+	 * If a new pool is already saved or the maximum number of
 	 * pools is reached, do not use the preallocated memory.
 	 */
 	if (!next_pool_required)
 		return;
 
 	/*
-	 * Use the preallocated memory for the next pool
+	 * Use the preallocated memory for the new pool
 	 * as long as we do not exceed the maximum number of pools.
 	 */
 	if (pool_index + 1 < DEPOT_MAX_POOLS) {
@@ -239,12 +238,12 @@ static void depot_keep_next_pool(void **prealloc)
 	}
 
 	/*
-	 * At this point, either the next pool is kept or the maximum
+	 * At this point, either a new pool is kept or the maximum
 	 * number of pools is reached. In either case, take note that
 	 * keeping another pool is not required.
 	 * smp_store_release pairs with smp_load_acquire in stack_depot_save.
 	 */
-	smp_store_release(&next_pool_required, 0);
+	smp_store_release(&new_pool_required, 0);
 }
 
 /* Updates refences to the current and the next stack depot pools. */
@@ -259,7 +258,7 @@ static bool depot_update_pools(size_t required_size, void **prealloc)
 		}
 
 		/*
-		 * Move on to the next pool.
+		 * Move on to the new pool.
 		 * WRITE_ONCE pairs with potential concurrent read in
 		 * stack_depot_fetch.
 		 */
@@ -268,12 +267,12 @@ static bool depot_update_pools(size_t required_size, void **prealloc)
 
 		/*
 		 * If the maximum number of pools is not reached, take note
-		 * that the next pool needs to be initialized.
+		 * that yet another new pool needs to be allocated.
 		 * smp_store_release pairs with smp_load_acquire in
 		 * stack_depot_save.
 		 */
 		if (pool_index + 1 < DEPOT_MAX_POOLS)
-			smp_store_release(&next_pool_required, 1);
+			smp_store_release(&new_pool_required, 1);
 	}
 
 	/* Check if the current pool is not yet allocated. */
@@ -284,9 +283,9 @@ static bool depot_update_pools(size_t required_size, void **prealloc)
 		return true;
 	}
 
-	/* Otherwise, try using the preallocated memory for the next pool. */
+	/* Otherwise, try using the preallocated memory for a new pool. */
 	if (*prealloc)
-		depot_keep_next_pool(prealloc);
+		depot_keep_new_pool(prealloc);
 	return true;
 }
 
@@ -297,7 +296,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	struct stack_record *stack;
 	size_t required_size = DEPOT_STACK_RECORD_SIZE;
 
-	/* Update current and next pools if required and possible. */
+	/* Update current and new pools if required and possible. */
 	if (!depot_update_pools(required_size, prealloc))
 		return NULL;
 
@@ -429,13 +428,13 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		goto exit;
 
 	/*
-	 * Check if another stack pool needs to be initialized. If so, allocate
-	 * the memory now - we won't be able to do that under the lock.
+	 * Check if another stack pool needs to be allocated. If so, allocate
+	 * the memory now: we won't be able to do that under the lock.
 	 *
 	 * smp_load_acquire pairs with smp_store_release in depot_update_pools
-	 * and depot_keep_next_pool.
+	 * and depot_keep_new_pool.
 	 */
-	if (unlikely(can_alloc && smp_load_acquire(&next_pool_required))) {
+	if (unlikely(can_alloc && smp_load_acquire(&new_pool_required))) {
 		/*
 		 * Zero out zone modifiers, as we don't have specific zone
 		 * requirements. Keep the flags related to allocation in atomic
@@ -468,9 +467,9 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	} else if (prealloc) {
 		/*
 		 * Stack depot already contains this stack trace, but let's
-		 * keep the preallocated memory for the future.
+		 * keep the preallocated memory for future.
 		 */
-		depot_keep_next_pool(&prealloc);
+		depot_keep_new_pool(&prealloc);
 	}
 
 	raw_spin_unlock_irqrestore(&pool_lock, flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e074fa3f4962897b84afb3d65767f5fc3b5d1234.1694625260.git.andreyknvl%40google.com.
