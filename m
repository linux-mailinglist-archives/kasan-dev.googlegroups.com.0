Return-Path: <kasan-dev+bncBAABBJV43KUQMGQEZCE7BHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 31E777D3C54
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:24:08 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-5079fe7cc7csf3621961e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:24:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698078247; cv=pass;
        d=google.com; s=arc-20160816;
        b=fvWSw+yvTl+D6lU1xu/y7G0rNmjibvHInhpxUGoxRr/A2hG8752zT1Fxi5dpDj9KiZ
         lHGdTi6SGY3+WbGaR89A7qrDRk7NR1VTclZXhfh+MZSLfq848nSVKS3j1TwwZ1cGh3iC
         HcQQ8zqgNWOJKluTnIJgDq8vrfrClXGAUHdRgSdozKnmLimz0VJxQT94Re3Y8+a9uVxo
         6UgSw4S4NENRnMKw9GOV4qIxt7eq2wPlcBDPGjdr7Klv245oGfEp9UYyS1J5zO0SKadK
         vZuD3oAMRaTFDRzJmEIXPBwd/ayEJm6Oj/yxsQ56Dr5RDkjfOAiozoH5MiQPN+QZWRLO
         VStw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=REzKv2+IMgb3RNq8MQED2WF+Ds3nvRRsoeIAm+H5VaU=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=WiM3O4st+Y/0Je5YBT4o3sTdlen1JOyQbgJbdZXDfWexblg+dOsk8IEmyt5xULECrw
         Z6BjikYgktU6npCVBnAxShTGzmUqmN5dB6BOfKQuGoTHHoWtjILTortzEwhLiRJp9yLL
         0bLZZgSIArLDVHDPV9tOMH5LreMHrRO3Du9wiMythebRlQSMPsTWXPQByGPlMtd403Ai
         oE+1PCFHjeGJT6jLqZ0YmbESCozoECl9/zkpoQZFNMTqFWtV6lARTxWHu6SkmP6gEPos
         nQ8DYqUHxlkp/RNFa1cTYXpMQB16pvb7rn1aDzytOqtXxO/kQi/Up9ASnpU628vE/7rZ
         LhdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="Ln8jn/bt";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::c5 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698078247; x=1698683047; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=REzKv2+IMgb3RNq8MQED2WF+Ds3nvRRsoeIAm+H5VaU=;
        b=gGCdC+DEqIH6JSwG452B150dmaYccg7cX156YLlwHxsZALuZKE2Ly5e2zwGmPNYpfe
         S/geCxoflhjx0LsW5jsHRgwHJ7fngOtbuiE1rqvDanBBOzTDDGcxevGNuPh3In4RWbEZ
         fpEZTR9Ur85eZsXO5Do/KJZNBCEV6Dp7lK797n6PH/hAK0K6r/AQa3VUjrEH7Kkj1U/Y
         uvhRTB3LFYJrObUahakcty1Po+/UsVKd25ZYon59vikkgd1YfKrvsPX+nFmDmdnRZ1QL
         XzBsQsR6GRChizKIpd7uA4Cey6nYPBe0xLR/g/en03L/2nfOinXX2mC8iZUSokQbf2LB
         w7Rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698078247; x=1698683047;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=REzKv2+IMgb3RNq8MQED2WF+Ds3nvRRsoeIAm+H5VaU=;
        b=RYWPhwxGZO1q0fhGH4x8chZthEKrQKrejaAb1f8XLJT9Dvx6sTQREBEybSRcoKpcqU
         YvmafErBran2f7dVTar641SfBLwNJPtnvcwG0LeKH2LEvF2fl3/wK8LRAi0MlxiFwO95
         RQ/2D59uLO/nyEj5i3nEpdcMwtMoSbYkzHusTUb6EobtSdVFLt5N9bn48TSHLI7kHVRm
         xpLJQKbKkZkEaf064z6MepX+9Hp4ngGmCfISPRcjNfr4aPRqFK030rg+2iHiFxje9Cqw
         X00f2HpNa5oRSkPbG/6Beu2SjNuGOwBXMZIk0xMqs2Ff+EYYFeyHHr9FNd1iBDB8WCib
         sJFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwwomdXiGBmpA4xZ+ukZz04k+2icN0cu9yAlXIdz2A6gXFKq2f8
	coO8sPlLoXdHAT+hvZ64OlI=
X-Google-Smtp-Source: AGHT+IGjhL1z7Qkka/7V46pijhy6ODO8u25qPFS3iAoVFpdsG4n3uLI1xf20hFJlllV72gGIUNCkTg==
X-Received: by 2002:a2e:b98c:0:b0:2c5:3322:c2d6 with SMTP id p12-20020a2eb98c000000b002c53322c2d6mr5978479ljp.7.1698078246671;
        Mon, 23 Oct 2023 09:24:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:5459:0:b0:2c5:dcb:9764 with SMTP id y25-20020a2e5459000000b002c50dcb9764ls43116ljd.0.-pod-prod-02-eu;
 Mon, 23 Oct 2023 09:24:05 -0700 (PDT)
X-Received: by 2002:a2e:b8c7:0:b0:2c5:968:6daf with SMTP id s7-20020a2eb8c7000000b002c509686dafmr8046131ljp.39.1698078245081;
        Mon, 23 Oct 2023 09:24:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698078245; cv=none;
        d=google.com; s=arc-20160816;
        b=JkhcQZ43ucvfXF20yAWDqlBZqGfaIhKMogQVxjoZ7sLB8NncCn1t4dS93/NxsMDi4T
         J4eV0H3EMJBINey2y1vaXMPIlK1cu+yansDGoaaQLqmxlm2i0vSqGGSK3hfY2nfyksgf
         xkFRdica+1/kxz4TlIFvGMYK9H1UNgvVH31ruKLm0ujnGMXBQGOwozynf0kC8imC7eAX
         A9EmHM7jb2k7i5Vqe/5XOitFI08C0sPpIf/tU0gQQjItX/MvaVKNb2NMoVNdtx6NoijO
         i3ZfpeH++A92Y+ZGXPILXftdPsgsHX2K4umykrFtHX+JIDHjuRds6uprC/aZ4J08Wh4o
         ZMYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QFz7c41J1QbS9PQ1h2ItmRgQJE/l+/U2CDCp2U3Lga0=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=HSflhMnwWry0nw4eMZvYt6RqAtMlGDljNe30e9l7qpkGRXtZrdu3EzK6/rDcagynYg
         RjzYIuGRIOug8f4XdCWdabnL9dPAaIUvTYbhnTHSN8HfGbK52uYTMCaouz0Rjo+apyip
         PaYYSH4SiztyAs+Cc0XYupbwNbr30Ik/XdQBYHeFlLjVrF4uWRD56ye8NA51nS2IpG5T
         JBzNgsDF84Rpcu96D1lob1q9TOjc05WJrRI3iS0YTHwxIJJdfUHLJBsltGUVaG/pe/q+
         PYE1t3sDDczm7jvt7K8WBJT8bzbB1xkj8of/RlYVFBJ4kabYNq4Bz5HNahEQ5NIgQDwg
         pUcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="Ln8jn/bt";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::c5 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-197.mta1.migadu.com (out-197.mta1.migadu.com. [2001:41d0:203:375::c5])
        by gmr-mx.google.com with ESMTPS id p20-20020a2ea4d4000000b002c29b97d5f2si306723ljm.1.2023.10.23.09.24.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Oct 2023 09:24:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::c5 as permitted sender) client-ip=2001:41d0:203:375::c5;
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
Subject: [PATCH v3 08/19] lib/stackdepot: rename next_pool_required to new_pool_required
Date: Mon, 23 Oct 2023 18:22:39 +0200
Message-Id: <5d8faf61763307b4d71a9b5272b88fb5c5ae7521.1698077459.git.andreyknvl@google.com>
In-Reply-To: <cover.1698077459.git.andreyknvl@google.com>
References: <cover.1698077459.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="Ln8jn/bt";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::c5 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
 lib/stackdepot.c | 49 ++++++++++++++++++++++++------------------------
 1 file changed, 24 insertions(+), 25 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 3f921aaae44a..7579e20114b1 100644
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
@@ -219,20 +218,20 @@ int stack_depot_init(void)
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
-	 * Access next_pool_required non-atomically, as there are no concurrent
+	 * Access new_pool_required non-atomically, as there are no concurrent
 	 * write accesses to this variable.
 	 */
-	if (!next_pool_required)
+	if (!new_pool_required)
 		return;
 
 	/*
-	 * Use the preallocated memory for the next pool
+	 * Use the preallocated memory for the new pool
 	 * as long as we do not exceed the maximum number of pools.
 	 */
 	if (pool_index + 1 < DEPOT_MAX_POOLS) {
@@ -241,13 +240,13 @@ static void depot_keep_next_pool(void **prealloc)
 	}
 
 	/*
-	 * At this point, either the next pool is kept or the maximum
+	 * At this point, either a new pool is kept or the maximum
 	 * number of pools is reached. In either case, take note that
 	 * keeping another pool is not required.
 	 * smp_store_release() pairs with smp_load_acquire() in
 	 * stack_depot_save().
 	 */
-	smp_store_release(&next_pool_required, 0);
+	smp_store_release(&new_pool_required, 0);
 }
 
 /* Updates refences to the current and the next stack depot pools. */
@@ -262,7 +261,7 @@ static bool depot_update_pools(size_t required_size, void **prealloc)
 		}
 
 		/*
-		 * Move on to the next pool.
+		 * Move on to the new pool.
 		 * WRITE_ONCE() pairs with potential concurrent read in
 		 * stack_depot_fetch().
 		 */
@@ -271,12 +270,12 @@ static bool depot_update_pools(size_t required_size, void **prealloc)
 
 		/*
 		 * If the maximum number of pools is not reached, take note
-		 * that the next pool needs to be initialized.
+		 * that yet another new pool needs to be allocated.
 		 * smp_store_release() pairs with smp_load_acquire() in
 		 * stack_depot_save().
 		 */
 		if (pool_index + 1 < DEPOT_MAX_POOLS)
-			smp_store_release(&next_pool_required, 1);
+			smp_store_release(&new_pool_required, 1);
 	}
 
 	/* Check if the current pool is not yet allocated. */
@@ -287,9 +286,9 @@ static bool depot_update_pools(size_t required_size, void **prealloc)
 		return true;
 	}
 
-	/* Otherwise, try using the preallocated memory for the next pool. */
+	/* Otherwise, try using the preallocated memory for a new pool. */
 	if (*prealloc)
-		depot_keep_next_pool(prealloc);
+		depot_keep_new_pool(prealloc);
 	return true;
 }
 
@@ -300,7 +299,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	struct stack_record *stack;
 	size_t required_size = DEPOT_STACK_RECORD_SIZE;
 
-	/* Update current and next pools if required and possible. */
+	/* Update current and new pools if required and possible. */
 	if (!depot_update_pools(required_size, prealloc))
 		return NULL;
 
@@ -432,13 +431,13 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		goto exit;
 
 	/*
-	 * Check if another stack pool needs to be initialized. If so, allocate
-	 * the memory now - we won't be able to do that under the lock.
+	 * Check if another stack pool needs to be allocated. If so, allocate
+	 * the memory now: we won't be able to do that under the lock.
 	 *
 	 * smp_load_acquire() pairs with smp_store_release() in
-	 * depot_update_pools() and depot_keep_next_pool().
+	 * depot_update_pools() and depot_keep_new_pool().
 	 */
-	if (unlikely(can_alloc && smp_load_acquire(&next_pool_required))) {
+	if (unlikely(can_alloc && smp_load_acquire(&new_pool_required))) {
 		/*
 		 * Zero out zone modifiers, as we don't have specific zone
 		 * requirements. Keep the flags related to allocation in atomic
@@ -471,9 +470,9 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5d8faf61763307b4d71a9b5272b88fb5c5ae7521.1698077459.git.andreyknvl%40google.com.
