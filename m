Return-Path: <kasan-dev+bncBAABB3G34CPAMGQEVOXUKZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 491EE681BCE
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 21:51:57 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id r15-20020a05600c35cf00b003d9a14517b2sf10157938wmq.2
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 12:51:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675111917; cv=pass;
        d=google.com; s=arc-20160816;
        b=iSIZ11HbS6ErUJx1iOgBp+S5qqEVrxH7FiaAfcffBwnzeIM2/gZrXrP7C8YRA8wBDH
         7mXW9gETHjjrag6dcoDC6a1pWi+S+wKldo4t0hi1emE0UVdwdx9REzH5BTLsrf4Aa4Od
         D9zr4dWJ5QIaGQL8PZ1Yfv+nGhTuGAXeMACHwB7Ib9+f1+/yhfi7RLqiGIHUv70eT6JV
         KQ2HSZ57ReSRHuJ7VdzQNzz4PPafXZldKvcnXGtYNlj2Vhog17WNaS5qBdgLRJVXC32y
         WTerfBpz/5Ge2g+7N/LFjncjNSVVz5sL+NNsXiuk3OSvNF9CCFi4m1pHYU6enhZklfFD
         BqNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=deClXh56uMsdDAgMK9OXzUoxWqQBN+BQyRGzUlMbvxM=;
        b=O7iG2c5AFtrWBaZd551QOPmbeftJQdywhOn7cfQJsKfBCx66Qk3+eC4I6r+XyD+GQn
         OX3DyUq2mtpED9DPeMwfjJJbMp7v1JkN4e2r3L6VYRTjw2AXk1JULNJrIIeerWEeSSWu
         8UtWvm478QT/QaImELGxNzw0E8aTJ+hnrGaWljw/FnXqjesnjOds8aqDVp2Zo0QFBr3D
         Xv0PBfmBtgQHTylyT7Om23KpgkwQDpsLPcb2lfzlwa6RAwL4RJbek8KxwRD7Yo15Ow64
         2eNKaabf7kTPM0A9AviCgVSQ/phaaZoW4KASDgBFwRj+nGYitv5fk8PH1pXf88omCc6G
         GuuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="g5/h01z3";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.18 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=deClXh56uMsdDAgMK9OXzUoxWqQBN+BQyRGzUlMbvxM=;
        b=ADOf6m5xlzeQJzvibQQYPF3HSIAj0h8aNs4VdrEhKXgdhYYjA1XO7QNO8+toe96HDy
         y9rtkNHovJUogWxdB+aGCRpugll0EaT/NvUsLp1/eyFAH3wYfBOyXMg31J4MP2u2W5Km
         vZUz8DkYEbNMkRsVqARtD3/EXJ8YDGJKIUBWR+kVxeaF+NaXHneB670UT/Q8sH05AHCJ
         xtYYuul8g0Bob6EKEqBDs0sNjB28FvH2ECEUdNscmSxXDRYDsFiYxUBPPgdWQqws/jTg
         NogfAB8Rpg1DtUVedktxLAUtUFQtozeo+NJvQenvNylmf0CYYrqMDXcxau46Iq9CaXxp
         veKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=deClXh56uMsdDAgMK9OXzUoxWqQBN+BQyRGzUlMbvxM=;
        b=6hMleygrRVxrSoHsgo/i7Au7cHCCSCXMAhVIrV1zIOpban4YzZhr4pG86JANn9yDKZ
         aXa5TIXOd04V9LkAEs+OjdyYJ3UUlEbONciLFEtMDEymAvaAWo7BNvAi0Gd9P5UwAKZW
         FI119aR25w1SgyMtXMVGtTZAjyljcPsvcuZ3fMRWsjEEDwwPfCt8J15aWTMAldSsupWd
         kyB6FLlzu6fMu2TIe6BtSo2omUhZgE9CS+QZGIBAcpIiwooLAL7c9lDwojscpnHHri1G
         Z3bhYjEI9JbAuq0XhDleSuQf4zFaRlYUM+REqRO2ZFzrNokiULLaE+XCnImKpwkGmW5x
         2y1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUHBGnITFFhjxTa/oU/5yhV494KSo2C0hWCpqb3/OA5qUjWbMSA
	Wu+AN946UnGw6QrjmlN24Nw=
X-Google-Smtp-Source: AK7set+NdSDhPQ4QLDEqDRJZESx32u9ogUwX6Vpz0kzj0hlBbzR3cwoBEw1OBBf+GRT8VMnmP1tUfQ==
X-Received: by 2002:a05:600c:35d4:b0:3dc:583c:8ba2 with SMTP id r20-20020a05600c35d400b003dc583c8ba2mr318662wmq.79.1675111916928;
        Mon, 30 Jan 2023 12:51:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d83:b0:3dc:5300:3d83 with SMTP id
 p3-20020a05600c1d8300b003dc53003d83ls2930289wms.0.-pod-control-gmail; Mon, 30
 Jan 2023 12:51:56 -0800 (PST)
X-Received: by 2002:a05:600c:1c02:b0:3d2:3b8d:21e5 with SMTP id j2-20020a05600c1c0200b003d23b8d21e5mr51019675wms.14.1675111916120;
        Mon, 30 Jan 2023 12:51:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675111916; cv=none;
        d=google.com; s=arc-20160816;
        b=fxMQs6lPItctL3OgtZypa0vo6kh/Yh/kLO0H//gk1VqbDIecJGwK8It7sKRjlXf5fi
         f4tb4WOBRy+TRW6PXHKIfXlIGGrRGQk7uqyxbPuwQDW1uwPdmRp/leMHTjWLBBRkteiH
         AnXKhoMu5mgq2eWuqXeykWqoFvS8HrK2SZzMxWMAgw2pPgs/SSGfaWFfayjcELt9bdkT
         SBa4XPlms2KtoWBWIhZQLNE3Wl7tTtc7K9R3k+zWLzJSUJdBn+KM1rJ9NpWtg7G8//Ez
         kWK23l09b84qqae2Vx5QeK10hGs5OiqcK+4Zk3dY4jRfHJuwb9SpUJXGWln6SFDBJic5
         NQaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=n2WDy/mEQLvnsHLslgORbsPKJysJoBtCH/6FUJBS3Gs=;
        b=nfxPGf76ErMD2Mf2+kZyjDQRVOCTdgjTOPBlRcE7K4Uvw2Cd/KuS7mz4JUSL7ArOWC
         e25PM80aJNpSmQA3Rsbo0KJGwjJybyDIAJWTdMNr8RzYeSUdx24RpLa0vgSZAUVqoGnv
         cZXrd4/6pljk1AiFS0TVWlsTW4nv+Mx2ggYG8yCFGXnjWS0tregEV9D3EYLaobckRhib
         bOTu3DcMVsPqQjT65bu1vxSy6VJKc4PR6dCxwcuCtm+u3X/G2Fv6gWqTQiq9Z8t2fxL4
         l1U3RmTW/0q8WU984ZbDxRUZ+LC6vb6gIKedV90fq/M6nWoTCzQcwCwzl0jZVaZxW8R9
         kvzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="g5/h01z3";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.18 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-18.mta0.migadu.com (out-18.mta0.migadu.com. [91.218.175.18])
        by gmr-mx.google.com with ESMTPS id r22-20020a05600c35d600b003d9c774d43fsi1076411wmq.2.2023.01.30.12.51.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jan 2023 12:51:56 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.18 as permitted sender) client-ip=91.218.175.18;
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
Subject: [PATCH 14/18] lib/stackdepot: annotate depot_init_slab and depot_alloc_stack
Date: Mon, 30 Jan 2023 21:49:38 +0100
Message-Id: <3cf68a23da43cef0f8737f7a2c07f35ce6d841a7.1675111415.git.andreyknvl@google.com>
In-Reply-To: <cover.1675111415.git.andreyknvl@google.com>
References: <cover.1675111415.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="g5/h01z3";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.18 as
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

Clean up the exisiting comments and add new ones to depot_init_slab and
depot_alloc_stack.

As a part of the clean-up, remove mentions of which variable is accessed
by smp_store_release and smp_load_acquire: it is clear as is from the
code.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 35 +++++++++++++++++++++++++----------
 1 file changed, 25 insertions(+), 10 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index d6be82a5c223..7282565722f2 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -218,33 +218,41 @@ int stack_depot_init(void)
 }
 EXPORT_SYMBOL_GPL(stack_depot_init);
 
+/* Uses preallocated memory to initialize a new stack depot slab. */
 static void depot_init_slab(void **prealloc)
 {
 	/*
-	 * This smp_load_acquire() pairs with smp_store_release() to
-	 * |next_slab_inited| below and in depot_alloc_stack().
+	 * If the next slab is already initialized, do not use the
+	 * preallocated memory.
+	 * smp_load_acquire() here pairs with smp_store_release() below and
+	 * in depot_alloc_stack().
 	 */
 	if (smp_load_acquire(&next_slab_inited))
 		return;
+
+	/* Check if the current slab is not yet allocated. */
 	if (stack_slabs[slab_index] == NULL) {
+		/* Use the preallocated memory for the current slab. */
 		stack_slabs[slab_index] = *prealloc;
 		*prealloc = NULL;
 	} else {
-		/* If this is the last depot slab, do not touch the next one. */
+		/*
+		 * Otherwise, use the preallocated memory for the next slab
+		 * as long as we do not exceed the maximum number of slabs.
+		 */
 		if (slab_index + 1 < DEPOT_MAX_SLABS) {
 			stack_slabs[slab_index + 1] = *prealloc;
 			*prealloc = NULL;
 			/*
 			 * This smp_store_release pairs with smp_load_acquire()
-			 * from |next_slab_inited| above and in
-			 * stack_depot_save().
+			 * above and in stack_depot_save().
 			 */
 			smp_store_release(&next_slab_inited, 1);
 		}
 	}
 }
 
-/* Allocation of a new stack in raw storage */
+/* Allocates a new stack in a stack depot slab. */
 static struct stack_record *
 depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 {
@@ -253,28 +261,35 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 
 	required_size = ALIGN(required_size, 1 << DEPOT_STACK_ALIGN);
 
+	/* Check if there is not enough space in the current slab. */
 	if (unlikely(slab_offset + required_size > DEPOT_SLAB_SIZE)) {
+		/* Bail out if we reached the slab limit. */
 		if (unlikely(slab_index + 1 >= DEPOT_MAX_SLABS)) {
 			WARN_ONCE(1, "Stack depot reached limit capacity");
 			return NULL;
 		}
+
+		/* Move on to the next slab. */
 		slab_index++;
 		slab_offset = 0;
 		/*
-		 * smp_store_release() here pairs with smp_load_acquire() from
-		 * |next_slab_inited| in stack_depot_save() and
-		 * depot_init_slab().
+		 * smp_store_release() here pairs with smp_load_acquire() in
+		 * stack_depot_save() and depot_init_slab().
 		 */
 		if (slab_index + 1 < DEPOT_MAX_SLABS)
 			smp_store_release(&next_slab_inited, 0);
 	}
+
+	/* Assign the preallocated memory to a slab if required. */
 	if (*prealloc)
 		depot_init_slab(prealloc);
+
+	/* Check if we have a slab to save the stack trace. */
 	if (stack_slabs[slab_index] == NULL)
 		return NULL;
 
+	/* Save the stack trace. */
 	stack = stack_slabs[slab_index] + slab_offset;
-
 	stack->hash = hash;
 	stack->size = size;
 	stack->handle.slab_index = slab_index;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3cf68a23da43cef0f8737f7a2c07f35ce6d841a7.1675111415.git.andreyknvl%40google.com.
