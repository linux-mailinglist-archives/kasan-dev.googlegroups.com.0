Return-Path: <kasan-dev+bncBAABB2634CPAMGQEFNOYGGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 59CB0681BCD
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 21:51:56 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id l8-20020a05600c1d0800b003dc25f6bb5dsf8209089wms.0
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 12:51:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675111916; cv=pass;
        d=google.com; s=arc-20160816;
        b=VZB2nJhGSTFvdv4UK8m4o/0RIgl5IRkyz4K9lb/b+4TSjMxWMNuJhlH7sYmH9aw93w
         14RKkogxhl0tYC2lvXApFArh8l1KHi4dIjjkUQhkTs81hJq4/f1hIb5VZlDLNCmPxRWe
         2xSctoK4HzJHktTMWIEp1lj7euA0A00h8YWcNNcWyAO2ZaY/bux4Nz/mmIUBz4b/hnVS
         eCWfFAFc4ctuGFwe9H9rKBMXZnnBLRTPPeXBQTbnfnIfBmGsL+hnsKA3DCdfdoHaqpEB
         UIV0VKYBvfhZSqYguyTqUBV9C8lu/TXxOvYA8nU7wLrCAGELwoL/CMxWZQ5ME9QPFWxk
         Q+tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=f7OoqI/7jkuHXI7jLKktsYK2nRlV7osYIpbuq7C0JY0=;
        b=Q5qBwhYn70+8f8n+XaZbLrWgIOQJDrYLrEdQo7WSCUJEiQmpa1nttLXmB2W6NzooBo
         dkUz4O3JIUQBH4NMFcVMy164y0St8Zc3niZtubfAZoAg3+tO7f0XHp+P5W6yzkah6w0j
         rt648pvk6+CVp1Ag5c78diduJxzsIVs9MxWmygu/XHfFR8pZiTtFZc6bnomYWHwEqBUy
         mqqFKcAABU0yYuWEKgVtG57AScY8kzW8PV13/qSHK5ZjpwrPOGYyk4S2H8/VxyvoIHf0
         4TufsFaKocrBpYN000fzPglVw9ej764DXdySvmlrGVDbDVmgMCpTQbaMwdIwkkThi18o
         G4tA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=nfu6OwnD;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=f7OoqI/7jkuHXI7jLKktsYK2nRlV7osYIpbuq7C0JY0=;
        b=GwT9u36CULrFh7ewd1a38aX8G3xzp1AtWFARBMKbqoGaQQep+kbCJtaC/br6pEojPD
         oUK2X5ngEqydfmYw4cTf2aqutTf3Y4oBA9Cf67fgpkZBD3NxeUie//RkWanIzlOf7nPl
         qFWYm+sbQ9FAy1mqtotsvuKxx0fZFao8ohhc1sXhjvzXGzCGBza8AsSjykXiCv2Wmrur
         +dEsNariFUwV/ulMUL3Qm3C8CeJSy7sDi/7d6d3219JowlSfUHEWdZ0nO2DauY4tkigL
         DRdnpp5xHqq1gs4OFjJTcO+j33y/LXbLTQPVk8HMr+YJ0RsmpbPJM5y1eELT+wp1sjIR
         mnQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=f7OoqI/7jkuHXI7jLKktsYK2nRlV7osYIpbuq7C0JY0=;
        b=iXLpQ0j05fYOGDvR/zjpw4b5gAk0eSJdyAFh4nTsjFzXFQ0hgz3z0bF6iLvuxYxwJw
         TYecjp8RE5KrINTGI94A+mOaM3pdt6izzynj8ZPpqT/pJU8xaVNQl7v1eorMiFV8vTcJ
         O8EywiIew83nQf4KZhPnkJUbwE4YOny1t6MJQZxpwX8uqtapgRhXzK+t/N+cu8H4psdU
         YdF3BuZhSceVA/ar/X9EfgEir2BhEKetVcE6glHKn/W205txMpmrupQ5DJBiQWYqyqlk
         /FERc3M1GSWcU7o26+dkAfNBV45PFPW8td2f1XyMXuWU1U5Rzbsv2CSI4l185d8aGeZE
         XQ0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXv8PiWpU1uTjusZCXvlZwW8ffECvQNLRlf1IlrX53SN+kVyOv8
	1C/uSUBBmvoHdUMtNBR0KUg=
X-Google-Smtp-Source: AK7set/2lIBX1l180lEoKor8dWAvg0H2E54NB0FdWZ5RdjuOJoyCdOt/HqAXFXqPbNMPXmR4Imishg==
X-Received: by 2002:a05:600c:502c:b0:3dd:1bd0:6734 with SMTP id n44-20020a05600c502c00b003dd1bd06734mr51243wmr.47.1675111916139;
        Mon, 30 Jan 2023 12:51:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ee4b:0:b0:298:bd4a:4dd9 with SMTP id w11-20020adfee4b000000b00298bd4a4dd9ls3449072wro.1.-pod-prod-gmail;
 Mon, 30 Jan 2023 12:51:55 -0800 (PST)
X-Received: by 2002:a05:6000:11ce:b0:2bf:bd69:234b with SMTP id i14-20020a05600011ce00b002bfbd69234bmr15557523wrx.32.1675111915123;
        Mon, 30 Jan 2023 12:51:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675111915; cv=none;
        d=google.com; s=arc-20160816;
        b=Q7+be5WGkXNQKJNbzToF/ZlF0iYOCt2ggsgyQ0uccSfK9FTkdgwY/wnW7Dfff0XGhk
         PNYf2DyoTX9PQm7Fx3+qrTun+I1KCVLCxV6RiiUSZ6/7dhR0olsnbPUEAI1K6myOnVXz
         JpqIiTc9kwUUTHo17YyobmkNQYM2I0GucaJw9QScjWw3u4Tmsz1VDjwHlwmcpWVmCfhA
         L5/HIl6JBLdpjOPqb/jZnsDi0YnNDca0C9Rd/d4OpfsSJdZeBezL5Sd2mWck3EgIDolN
         d97znuHcuJPniNkt2k3rcsHFkKqNdKOT0m2GjM+goOpPtG0ZpQx+4uL/Tekip7xqs/qf
         IEvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Z64aIL/3pnEFiG6bV8LdN1R6x92gKwWr8osFMwIva5I=;
        b=ByNyxiRcgUvyqBWNyp70xdWcXrN/u9yB/a0FhWEm4bEPy2ioAo8AkIsdc3DB41pRck
         JPmcDSXbQVTvd1kaSg1mttwXZ/M1glmKtUfgVNeH3rhLGUVqa8t3y5EHO6n5BpbbcsEu
         fF0aR7X/O4MJeOQLB8M8jL/dTCp4y5jDz9f0E6Ev+V5IL5AgOZWKPPV941f4YnSSFUwo
         ZwI6ccL6r2imEl6KxsCVStJAmdcG/1ParIBMaGflZ4fvs06S4uUhkS1Bi++RiIijhDcM
         U62a97OBRgtxSUgjx7Ho4ntptSBZrJqOT5a0wUZ+xAhsoHz8Xr9LkhZitcbnmz716/qs
         a45g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=nfu6OwnD;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-11.mta0.migadu.com (out-11.mta0.migadu.com. [2001:41d0:1004:224b::b])
        by gmr-mx.google.com with ESMTPS id bp30-20020a5d5a9e000000b002be378bf638si679824wrb.6.2023.01.30.12.51.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jan 2023 12:51:55 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b as permitted sender) client-ip=2001:41d0:1004:224b::b;
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
Subject: [PATCH 12/18] lib/stackdepot: rename handle and slab constants
Date: Mon, 30 Jan 2023 21:49:36 +0100
Message-Id: <d9c6d1fa0ae6e1e65577ee81444656c99eb598d8.1675111415.git.andreyknvl@google.com>
In-Reply-To: <cover.1675111415.git.andreyknvl@google.com>
References: <cover.1675111415.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=nfu6OwnD;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::b as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
of slabs.

The old prefix is unclear and makes wonder about how these constants
are related to stack allocations. The new prefix is also shorter.

Also simplify the comment for DEPOT_SLAB_ORDER.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 56 +++++++++++++++++++++++-------------------------
 1 file changed, 27 insertions(+), 29 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 023f299bedf6..b946ba74fea0 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -36,30 +36,28 @@
 #include <linux/memblock.h>
 #include <linux/kasan-enabled.h>
 
-#define DEPOT_STACK_BITS (sizeof(depot_stack_handle_t) * 8)
-
-#define STACK_ALLOC_NULL_PROTECTION_BITS 1
-#define STACK_ALLOC_ORDER 2 /* 'Slab' size order for stack depot, 4 pages */
-#define STACK_ALLOC_SIZE (1LL << (PAGE_SHIFT + STACK_ALLOC_ORDER))
-#define STACK_ALLOC_ALIGN 4
-#define STACK_ALLOC_OFFSET_BITS (STACK_ALLOC_ORDER + PAGE_SHIFT - \
-					STACK_ALLOC_ALIGN)
-#define STACK_ALLOC_INDEX_BITS (DEPOT_STACK_BITS - \
-		STACK_ALLOC_NULL_PROTECTION_BITS - \
-		STACK_ALLOC_OFFSET_BITS - STACK_DEPOT_EXTRA_BITS)
-#define STACK_ALLOC_SLABS_CAP 8192
-#define STACK_ALLOC_MAX_SLABS \
-	(((1LL << (STACK_ALLOC_INDEX_BITS)) < STACK_ALLOC_SLABS_CAP) ? \
-	 (1LL << (STACK_ALLOC_INDEX_BITS)) : STACK_ALLOC_SLABS_CAP)
+#define DEPOT_HANDLE_BITS (sizeof(depot_stack_handle_t) * 8)
+
+#define DEPOT_VALID_BITS 1
+#define DEPOT_SLAB_ORDER 2 /* Slab size order, 4 pages */
+#define DEPOT_SLAB_SIZE (1LL << (PAGE_SHIFT + DEPOT_SLAB_ORDER))
+#define DEPOT_STACK_ALIGN 4
+#define DEPOT_OFFSET_BITS (DEPOT_SLAB_ORDER + PAGE_SHIFT - DEPOT_STACK_ALIGN)
+#define DEPOT_SLAB_INDEX_BITS (DEPOT_HANDLE_BITS - DEPOT_VALID_BITS - \
+			       DEPOT_OFFSET_BITS - STACK_DEPOT_EXTRA_BITS)
+#define DEPOT_SLABS_CAP 8192
+#define DEPOT_MAX_SLABS \
+	(((1LL << (DEPOT_SLAB_INDEX_BITS)) < DEPOT_SLABS_CAP) ? \
+	 (1LL << (DEPOT_SLAB_INDEX_BITS)) : DEPOT_SLABS_CAP)
 
 /* The compact structure to store the reference to stacks. */
 union handle_parts {
 	depot_stack_handle_t handle;
 	struct {
-		u32 slab_index : STACK_ALLOC_INDEX_BITS;
-		u32 offset : STACK_ALLOC_OFFSET_BITS;
-		u32 valid : STACK_ALLOC_NULL_PROTECTION_BITS;
-		u32 extra : STACK_DEPOT_EXTRA_BITS;
+		u32 slab_index	: DEPOT_SLAB_INDEX_BITS;
+		u32 offset	: DEPOT_OFFSET_BITS;
+		u32 valid	: DEPOT_VALID_BITS;
+		u32 extra	: STACK_DEPOT_EXTRA_BITS;
 	};
 };
 
@@ -91,7 +89,7 @@ static unsigned int stack_bucket_number_order;
 static unsigned int stack_hash_mask;
 
 /* Array of memory regions that store stack traces. */
-static void *stack_slabs[STACK_ALLOC_MAX_SLABS];
+static void *stack_slabs[DEPOT_MAX_SLABS];
 /* Currently used slab in stack_slabs. */
 static int slab_index;
 /* Offset to the unused space in the currently used slab. */
@@ -235,7 +233,7 @@ static bool depot_init_slab(void **prealloc)
 		*prealloc = NULL;
 	} else {
 		/* If this is the last depot slab, do not touch the next one. */
-		if (slab_index + 1 < STACK_ALLOC_MAX_SLABS) {
+		if (slab_index + 1 < DEPOT_MAX_SLABS) {
 			stack_slabs[slab_index + 1] = *prealloc;
 			*prealloc = NULL;
 			/*
@@ -256,10 +254,10 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	struct stack_record *stack;
 	size_t required_size = struct_size(stack, entries, size);
 
-	required_size = ALIGN(required_size, 1 << STACK_ALLOC_ALIGN);
+	required_size = ALIGN(required_size, 1 << DEPOT_STACK_ALIGN);
 
-	if (unlikely(slab_offset + required_size > STACK_ALLOC_SIZE)) {
-		if (unlikely(slab_index + 1 >= STACK_ALLOC_MAX_SLABS)) {
+	if (unlikely(slab_offset + required_size > DEPOT_SLAB_SIZE)) {
+		if (unlikely(slab_index + 1 >= DEPOT_MAX_SLABS)) {
 			WARN_ONCE(1, "Stack depot reached limit capacity");
 			return NULL;
 		}
@@ -270,7 +268,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 		 * |next_slab_inited| in stack_depot_save() and
 		 * depot_init_slab().
 		 */
-		if (slab_index + 1 < STACK_ALLOC_MAX_SLABS)
+		if (slab_index + 1 < DEPOT_MAX_SLABS)
 			smp_store_release(&next_slab_inited, 0);
 	}
 	depot_init_slab(prealloc);
@@ -282,7 +280,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	stack->hash = hash;
 	stack->size = size;
 	stack->handle.slab_index = slab_index;
-	stack->handle.offset = slab_offset >> STACK_ALLOC_ALIGN;
+	stack->handle.offset = slab_offset >> DEPOT_STACK_ALIGN;
 	stack->handle.valid = 1;
 	stack->handle.extra = 0;
 	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
@@ -413,7 +411,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		alloc_flags &= ~GFP_ZONEMASK;
 		alloc_flags &= (GFP_ATOMIC | GFP_KERNEL);
 		alloc_flags |= __GFP_NOWARN;
-		page = alloc_pages(alloc_flags, STACK_ALLOC_ORDER);
+		page = alloc_pages(alloc_flags, DEPOT_SLAB_ORDER);
 		if (page)
 			prealloc = page_address(page);
 	}
@@ -445,7 +443,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 exit:
 	if (prealloc) {
 		/* Nobody used this memory, ok to free it. */
-		free_pages((unsigned long)prealloc, STACK_ALLOC_ORDER);
+		free_pages((unsigned long)prealloc, DEPOT_SLAB_ORDER);
 	}
 	if (found)
 		retval.handle = found->handle.handle;
@@ -490,7 +488,7 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 {
 	union handle_parts parts = { .handle = handle };
 	void *slab;
-	size_t offset = parts.offset << STACK_ALLOC_ALIGN;
+	size_t offset = parts.offset << DEPOT_STACK_ALIGN;
 	struct stack_record *stack;
 
 	*entries = NULL;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d9c6d1fa0ae6e1e65577ee81444656c99eb598d8.1675111415.git.andreyknvl%40google.com.
