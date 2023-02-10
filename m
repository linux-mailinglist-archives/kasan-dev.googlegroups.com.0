Return-Path: <kasan-dev+bncBAABBXPITKPQMGQEHJUCD5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id A9F1669290E
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 22:17:17 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id fd23-20020a056402389700b004aaa054d189sf4318273edb.11
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 13:17:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676063837; cv=pass;
        d=google.com; s=arc-20160816;
        b=I3y+//Y90CzPaL7qPaxmeyE9kEpJVV1PnOYmZXSBARNiHs48PZVHVV3Bf/xEL6+GYq
         +5XAvi0hoQPN71GiGwdEMchnvyOcZ+cIYgGTrE4AEp2qd3y5Q0NVkCbpPg9UzRWLORFj
         HlQGZCWFXJdoKQ/Y/EZJ6LV5kOum/xkew3J7gfJ5KFOnN4QEtIdVipT9KjMvmH+YVoeL
         l9SylISPR9yWcNECPP3ABjZlr98d6D5Iqp3ib6gbw2fZ+MXo2xcQFaqHo+o/yQZzwI0G
         KaIlWYAVFqE3qD499w4oZUgloHcrjj4v0f2/B6Y+nt9blNyVN10Uq9o0ZSD1kB0Zrfho
         rxzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=HFdjfyYWRkx9+ejdc/tR8klwRzIdp8hfIrfQSAaMlHA=;
        b=KiHyCfrLwORdYTnv9+rGSsoDw4jy6XYQF9zWfhiKwVt/AOi70iTnH9tgV3O5SIXTrR
         rm/2J+TI61ewu8dVvmhdFcSD7R97vHomERyZHd3HDODsIn6k6480kMFUZuPyPLa0eDCj
         0zokydOCYgyBiX13o0RtP/FIz+puNiYuLiRCRWYejDJyrXqRGN94MKWwKpAF4skZqy/m
         n6P2athmxB0xokE0s/2bR8tt/Pf8bR/hTms/TTlJN9XRsN1SDgAZ4pTVIR0wJ4Ff0aLS
         6fmHZjXNma2TQbfQ4lwMT4Ct5dBCOHbsp17Vnuk8l5ywDvSegm3Orvr2zQGMqnvqhQiX
         reCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=SagK2gsx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::9f as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HFdjfyYWRkx9+ejdc/tR8klwRzIdp8hfIrfQSAaMlHA=;
        b=mhJY7dqrvIaNP2SiXxmqSmIEif20oGhqWSYi4307qlEArI6odW3kOiK9zSlp+Zw6Va
         P7YUuQB0Yv4HS2jkxPgObhwxVPXBcQHwO5R/naYhlrsUDfUiT1BHBEV0oPqTJI683/UV
         6GdHWUGM83ad1dpjDQj4CL6mmVAPQA06w/gNR0fEEQx77znp9OBvh7O4zfMWd60Q47cl
         1wUUj6QEx68hYmWiv1AaIk34vsMxi0Q8p0HzaRq9/z7jQzHJoSAi1yKxJ82V7m+px6TB
         Zt7PHj9hgAONCpwEyotIHGqnPNm1m5B9ueQtAbr6v28PrKlD2Nj4jVa7cSULv8Ukjs8L
         9k2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HFdjfyYWRkx9+ejdc/tR8klwRzIdp8hfIrfQSAaMlHA=;
        b=K+TCFAO4yKTZqRpXk0Ddx6DgH7tSK29BLdSsQ9jVQDONEz5BwCN3Zlsi5idSG4I47T
         WlamuHInMtAZrgABOmqY7xEPJc8lfAvLzcBmtNw/WxfLT3Dg0NBsQH8C+9ATUvLliD9j
         EsGYNJGoo6xObYuRZ/KSWxsBPYTRomWtoW2Zko8gLAhw6pSeSKsAqfX2hMyXH4gFwBRA
         me8SFnHUcXAOzKf/ZUiWEGmJxMeoj+PgUWa3dageYn+64NRMJu+26KRjicbAtCeooEIQ
         xaGNy23ISO564gNN4nOGzdZiSgOkT45a+xwTbcHbwPHp5CBt1mJPsiZ9h5+bDJ85YhJL
         Bovg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWGHQ/tLo9zDNgxd4WABtMBf0hinM2FVdAzfiWaugxhYtvwnU3T
	08tPRWbImwveKRl2U6XkPsY=
X-Google-Smtp-Source: AK7set+L6xf4UZjak5T1veY7jRPpfv5Q6RoqcQD6XjuvaLpn/Xu8cgytR8UsvDvSit32KI12c5OBLg==
X-Received: by 2002:a17:906:2758:b0:877:7480:c76a with SMTP id a24-20020a170906275800b008777480c76amr1653328ejd.13.1676063837354;
        Fri, 10 Feb 2023 13:17:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:f22:b0:4aa:d8d1:5599 with SMTP id
 i34-20020a0564020f2200b004aad8d15599ls6452552eda.3.-pod-prod-gmail; Fri, 10
 Feb 2023 13:17:16 -0800 (PST)
X-Received: by 2002:a50:d51d:0:b0:499:1ed2:6456 with SMTP id u29-20020a50d51d000000b004991ed26456mr17595210edi.22.1676063836336;
        Fri, 10 Feb 2023 13:17:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676063836; cv=none;
        d=google.com; s=arc-20160816;
        b=LWPRy+zglEm/qK2u855WdhGoojCAMuJB794N2ThaMHJKOScGfnQlX562PEwL8tFl/7
         el4NUHzSqRrQ9YdxAXOULY7I92HAJcCICBP1aGKqqC+I4hGXgl7pkTJyKcVIgj3BDQG4
         45KLWulHaJOaUW/wH7at5xQGL0jBhCv8V00jU2yoG0i4z83YvdQTnE7y7C6LOjtQHnik
         kJXurIkDKFOzDMi0jNlGUszEZGD4ZiptmviywtIyrg8oQq8OK52I57/Cxf5qciEDolad
         9hLZPmW1U+wE6I+Ty/QvyRJbRgssl9em32G4CSbPDSW8o/0Q5Y5rXzL71pCftTHWDdx9
         Y3cQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=C1pklH2NkOlTJAHbPzx+nHrEQIp6yNaNdAfbP7NW3o0=;
        b=iRg8Z3q+b8KB1aAAfgrm/2yXF2KoQDunfQNMFXrKtArJZdt23Bx7D34Og8fyJC5eb2
         EcNKifcfr+A84fXdfx9bL3kVHC4eGoaOM5vmDAC/FCOL+OCeQHI4wBC0GOwSSpZr7x5v
         wgIcDvEcMzlQ1ndnwWX+ZG0ztF8+dPwH8Dw5xyULeeq8LPCJocPzpqFq65vUyD4t1ZH8
         OPXPjBFWYjLy5CFicS6VEP5cgm+I6VYER2jqMQuE07oClDW1lVPBkZucNtGXnzHW/qFs
         zUvlbfxbneXcW5ZBOXnIE4noP3hne+jf1xDFYFtkaruhi3TXjXTd8Bae7G3qq9rH8h8E
         7OJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=SagK2gsx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::9f as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-159.mta1.migadu.com (out-159.mta1.migadu.com. [2001:41d0:203:375::9f])
        by gmr-mx.google.com with ESMTPS id m26-20020aa7d35a000000b004acb6374876si6503edr.1.2023.02.10.13.17.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Feb 2023 13:17:16 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::9f as permitted sender) client-ip=2001:41d0:203:375::9f;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 10/18] lib/stackdepot: rename handle and pool constants
Date: Fri, 10 Feb 2023 22:15:58 +0100
Message-Id: <84fcceb0acc261a356a0ad4bdfab9ff04bea2445.1676063693.git.andreyknvl@google.com>
In-Reply-To: <cover.1676063693.git.andreyknvl@google.com>
References: <cover.1676063693.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=SagK2gsx;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::9f as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Change the "STACK_ALLOC_" prefix to "DEPOT_" for the constants that
define the number of bits in stack depot handles and the maximum number
of pools.

The old prefix is unclear and makes wonder about how these constants
are related to stack allocations. The new prefix is also shorter.

Also simplify the comment for DEPOT_POOL_ORDER.

No functional changes.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 56 +++++++++++++++++++++++-------------------------
 1 file changed, 27 insertions(+), 29 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 522e36cf449f..97bba462ee13 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -36,30 +36,28 @@
 #include <linux/memblock.h>
 #include <linux/kasan-enabled.h>
 
-#define DEPOT_STACK_BITS (sizeof(depot_stack_handle_t) * 8)
-
-#define STACK_ALLOC_NULL_PROTECTION_BITS 1
-#define STACK_ALLOC_ORDER 2 /* Pool size order for stack depot, 4 pages */
-#define STACK_ALLOC_SIZE (1LL << (PAGE_SHIFT + STACK_ALLOC_ORDER))
-#define STACK_ALLOC_ALIGN 4
-#define STACK_ALLOC_OFFSET_BITS (STACK_ALLOC_ORDER + PAGE_SHIFT - \
-					STACK_ALLOC_ALIGN)
-#define STACK_ALLOC_INDEX_BITS (DEPOT_STACK_BITS - \
-		STACK_ALLOC_NULL_PROTECTION_BITS - \
-		STACK_ALLOC_OFFSET_BITS - STACK_DEPOT_EXTRA_BITS)
-#define STACK_ALLOC_POOLS_CAP 8192
-#define STACK_ALLOC_MAX_POOLS \
-	(((1LL << (STACK_ALLOC_INDEX_BITS)) < STACK_ALLOC_POOLS_CAP) ? \
-	 (1LL << (STACK_ALLOC_INDEX_BITS)) : STACK_ALLOC_POOLS_CAP)
+#define DEPOT_HANDLE_BITS (sizeof(depot_stack_handle_t) * 8)
+
+#define DEPOT_VALID_BITS 1
+#define DEPOT_POOL_ORDER 2 /* Pool size order, 4 pages */
+#define DEPOT_POOL_SIZE (1LL << (PAGE_SHIFT + DEPOT_POOL_ORDER))
+#define DEPOT_STACK_ALIGN 4
+#define DEPOT_OFFSET_BITS (DEPOT_POOL_ORDER + PAGE_SHIFT - DEPOT_STACK_ALIGN)
+#define DEPOT_POOL_INDEX_BITS (DEPOT_HANDLE_BITS - DEPOT_VALID_BITS - \
+			       DEPOT_OFFSET_BITS - STACK_DEPOT_EXTRA_BITS)
+#define DEPOT_POOLS_CAP 8192
+#define DEPOT_MAX_POOLS \
+	(((1LL << (DEPOT_POOL_INDEX_BITS)) < DEPOT_POOLS_CAP) ? \
+	 (1LL << (DEPOT_POOL_INDEX_BITS)) : DEPOT_POOLS_CAP)
 
 /* The compact structure to store the reference to stacks. */
 union handle_parts {
 	depot_stack_handle_t handle;
 	struct {
-		u32 pool_index : STACK_ALLOC_INDEX_BITS;
-		u32 offset : STACK_ALLOC_OFFSET_BITS;
-		u32 valid : STACK_ALLOC_NULL_PROTECTION_BITS;
-		u32 extra : STACK_DEPOT_EXTRA_BITS;
+		u32 pool_index	: DEPOT_POOL_INDEX_BITS;
+		u32 offset	: DEPOT_OFFSET_BITS;
+		u32 valid	: DEPOT_VALID_BITS;
+		u32 extra	: STACK_DEPOT_EXTRA_BITS;
 	};
 };
 
@@ -91,7 +89,7 @@ static unsigned int stack_bucket_number_order;
 static unsigned int stack_hash_mask;
 
 /* Array of memory regions that store stack traces. */
-static void *stack_pools[STACK_ALLOC_MAX_POOLS];
+static void *stack_pools[DEPOT_MAX_POOLS];
 /* Currently used pool in stack_pools. */
 static int pool_index;
 /* Offset to the unused space in the currently used pool. */
@@ -235,7 +233,7 @@ static bool init_stack_pool(void **prealloc)
 		*prealloc = NULL;
 	} else {
 		/* If this is the last depot pool, do not touch the next one. */
-		if (pool_index + 1 < STACK_ALLOC_MAX_POOLS) {
+		if (pool_index + 1 < DEPOT_MAX_POOLS) {
 			stack_pools[pool_index + 1] = *prealloc;
 			*prealloc = NULL;
 		}
@@ -255,10 +253,10 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	struct stack_record *stack;
 	size_t required_size = struct_size(stack, entries, size);
 
-	required_size = ALIGN(required_size, 1 << STACK_ALLOC_ALIGN);
+	required_size = ALIGN(required_size, 1 << DEPOT_STACK_ALIGN);
 
-	if (unlikely(pool_offset + required_size > STACK_ALLOC_SIZE)) {
-		if (unlikely(pool_index + 1 >= STACK_ALLOC_MAX_POOLS)) {
+	if (unlikely(pool_offset + required_size > DEPOT_POOL_SIZE)) {
+		if (unlikely(pool_index + 1 >= DEPOT_MAX_POOLS)) {
 			WARN_ONCE(1, "Stack depot reached limit capacity");
 			return NULL;
 		}
@@ -269,7 +267,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 		 * |next_pool_inited| in stack_depot_save() and
 		 * init_stack_pool().
 		 */
-		if (pool_index + 1 < STACK_ALLOC_MAX_POOLS)
+		if (pool_index + 1 < DEPOT_MAX_POOLS)
 			smp_store_release(&next_pool_inited, 0);
 	}
 	init_stack_pool(prealloc);
@@ -281,7 +279,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	stack->hash = hash;
 	stack->size = size;
 	stack->handle.pool_index = pool_index;
-	stack->handle.offset = pool_offset >> STACK_ALLOC_ALIGN;
+	stack->handle.offset = pool_offset >> DEPOT_STACK_ALIGN;
 	stack->handle.valid = 1;
 	stack->handle.extra = 0;
 	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
@@ -412,7 +410,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		alloc_flags &= ~GFP_ZONEMASK;
 		alloc_flags &= (GFP_ATOMIC | GFP_KERNEL);
 		alloc_flags |= __GFP_NOWARN;
-		page = alloc_pages(alloc_flags, STACK_ALLOC_ORDER);
+		page = alloc_pages(alloc_flags, DEPOT_POOL_ORDER);
 		if (page)
 			prealloc = page_address(page);
 	}
@@ -444,7 +442,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 exit:
 	if (prealloc) {
 		/* Nobody used this memory, ok to free it. */
-		free_pages((unsigned long)prealloc, STACK_ALLOC_ORDER);
+		free_pages((unsigned long)prealloc, DEPOT_POOL_ORDER);
 	}
 	if (found)
 		retval.handle = found->handle.handle;
@@ -489,7 +487,7 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 {
 	union handle_parts parts = { .handle = handle };
 	void *pool;
-	size_t offset = parts.offset << STACK_ALLOC_ALIGN;
+	size_t offset = parts.offset << DEPOT_STACK_ALIGN;
 	struct stack_record *stack;
 
 	*entries = NULL;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/84fcceb0acc261a356a0ad4bdfab9ff04bea2445.1676063693.git.andreyknvl%40google.com.
