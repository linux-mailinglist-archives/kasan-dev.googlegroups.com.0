Return-Path: <kasan-dev+bncBAABBLW34CPAMGQEFTIND4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 58104681BC6
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 21:50:55 +0100 (CET)
Received: by mail-ej1-x639.google.com with SMTP id xj11-20020a170906db0b00b0077b6ecb23fcsf8198839ejb.5
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 12:50:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675111855; cv=pass;
        d=google.com; s=arc-20160816;
        b=mqUI6PHHhQ9L4YCSOF5O2aqdzj/0rYwNSMAEknnAO4QEdVDd3y4TQW+g8VjcnxPc+W
         gIMmnAJCVLRrRmGmg8dTaxTj0EPHv54DkvUAX2aVuIyKUjx/mJPhAn7V7Xo1N7xrFMos
         j6cwFFNXJOgW17rzHj8Hs0xaL80alzM7bPqRJlGcmbgdl9XCNxZEkR2xNAMAE9KBlvI9
         XjrozzbcOtutmVQltEEjMkia6sq18MmptJQXxfWe/e+bB/Y5BDAZqpfdu2mJ2Yyisv4O
         8knW5IxzwLP9WkO5pkkRFUEfqXvviCFHD0V07KVYoJHPJNBpZsxNwpUKe+hEqnQCgSJo
         bgDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=76CaOFvEhamqns5nqAIca8RIzvrASBGzip+8vYacDxM=;
        b=qzQnoWqs6Q++y7jBy7qTGwQN6U8wc/nGqivz0+2tospm4JifYBu14vCXTs0U6gy3o4
         76tg4+qItTDhXZb2O0PI9vfy9z7fbY1XQDQZ8daNDM6Vbegr4I3hL9Wq5KYlKN+P6YX8
         Z9eWcyxsxelwkoLhy3gBjJlncGdws45Knfaw+J5sp7nJ85RQCXwtmE4qS8tiZYpVXEQ2
         TNnZt+HmpOzW3BJRYbvdF1xqxj1TmMl7ZY1mWiE8n588hbGRU44DQxFFh2MisQQFKa3k
         Uzwln+aecVYsdXQUhNdaxerwY5vO06z7TX1aSUd6q2mWzF6cEYfXnhVKXVzgfG3vG3D5
         96wg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=H0xZx4zS;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::74 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=76CaOFvEhamqns5nqAIca8RIzvrASBGzip+8vYacDxM=;
        b=oNu1BkrAog7GYLbygOmy2kY6Nivwa72+rx3vy3tMvyY3dPFJ+xtClB8neCsro+VxDV
         8UPnGkNnew+pQUjWUpwfUKRDCgwVZ+hqas2vVa19cyHKp59jaZ0qU8iYpI/GrPxl2lFC
         JmgFxxUXQislWFLLCQGec1QtjAswRXoMNgINqpC22yda8kD1BetbE3dZydHTdcYcjEE2
         lmqcZHSldj3lh4bexn/8hqTdvYLfBX6ZKt/mkp/saau1rfw/VJFyVNoJofiZRc2xVr7h
         Of994a8bovriBE9rtfefKSrjjr8DTujDmc93lbDy1xkydJpm7NOI/+8xOLLMmByabcdK
         bQOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=76CaOFvEhamqns5nqAIca8RIzvrASBGzip+8vYacDxM=;
        b=4yVcSYeRFddqgMpy5xJFxlgV427MQyz0WrPNNTB2j++qzwNdcWg8lxDeWKMLPb3J//
         BUpavsmGGpL0TLfYk6LCSlvi9zJBGrZ/N3Ps5xYLJYSJMEc4i7koO2hLO3j+BPdL8y4B
         c/Oop7a2wFCkmpxJXbJikEqMqpw7WFzjhKlCSqPowy2Ne3b7sz5lhLWylL4vgU1MynOU
         Te89oc5UtCENLs6PNJBE25BMBIVbYjvqtLAXXfEmKRd93j1rPPHcIq8vBThuuTJP2Y3T
         RktE/OLLjJmD9QqlbijFWZd7ULErvy/iSWxY0GdzMknEr+nayDR7yszNhXL9fuL6oh50
         pIEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWY54y0LlVFTngD0QhZvBn8OqaLEebk7dBzv+OHYGvmMP4UnGcX
	6ea9nIpHxSZ2cfIE/Ye3wbI=
X-Google-Smtp-Source: AK7set9pdSBB2yw3Uu4YTj1YVFd/zJWZyE4jqIi59I9ZRUSzTRb6C+3RJYYZQXMus7DXzhpzfDyVIw==
X-Received: by 2002:a17:906:19d3:b0:885:7f56:dd6d with SMTP id h19-20020a17090619d300b008857f56dd6dmr2355965ejd.227.1675111855095;
        Mon, 30 Jan 2023 12:50:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:84d:b0:43d:b3c4:cd21 with SMTP id
 b13-20020a056402084d00b0043db3c4cd21ls13210901edz.2.-pod-prod-gmail; Mon, 30
 Jan 2023 12:50:54 -0800 (PST)
X-Received: by 2002:a05:6402:34c3:b0:4a2:5a66:f4a8 with SMTP id w3-20020a05640234c300b004a25a66f4a8mr3047875edc.19.1675111854134;
        Mon, 30 Jan 2023 12:50:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675111854; cv=none;
        d=google.com; s=arc-20160816;
        b=nFr1WmuheNjKoC4/PVVoc3JR9eIHpD3kZsegsS9kAxwyYWxMt+0SFXxp+BYsSPX8hB
         /W2QHzuGSFykTPCuIswDsYuTEhJducjBVhFrPikmI8NE4wEMRK70XZLft6cxmJiRspGI
         4NpDn9cHygScSmvcRaZEXuZ5welbbyuRB4FPNybKHOfuAWuNfA15IPU8s2fTiH5EUjaT
         aTnJ4DCTPHahNsyPEtcBxgcX61oVZdLvGQj+B+1OA2LOxi2OUa9Ac9xQIQWY8nzngd1K
         EIMokTnRGS8mk1YgfJFXUrppHKuoctSlFKaQs+fIqs8Wrt2iGAptxl8a1sc+xNojrh3C
         P2og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iXlgsoHOs+BLuKG+iZUfAdscpmKEgHjXPVNxwccGfOc=;
        b=nMTyM5TTmfM557Hyd8xJfeTdeEo1BmyBTjuQ7nTe1e4aCqOmjrx7nUmODsK7hEErRc
         OVCachNY1qXTkGfoyIt6yJuJyKHAym0jJzajmKPYP3wKHlojWp1LQy2+Im4N2iXkD/Ip
         J8LjUg+cFAZYPBJDc6rRICgwfEUd1hIPUC3yQkPvuRcrUEFXjL2cm1/YZqV4UROFUkPl
         SJuPyypPzEsStxE6jtf7bnqmXz/xETKiC5YEuPblQDpD6YLwioLtrlgm9Yz90KWDqIdV
         aKgCgACpoZxpPEP0xTLkW+GdOac1t0doWzdoNg4c+J3SN3MxBKQhj64BuAYCE8b9xj0x
         tbGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=H0xZx4zS;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::74 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-116.mta0.migadu.com (out-116.mta0.migadu.com. [2001:41d0:1004:224b::74])
        by gmr-mx.google.com with ESMTPS id ez18-20020a056402451200b0046920d68fe2si548430edb.4.2023.01.30.12.50.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jan 2023 12:50:54 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::74 as permitted sender) client-ip=2001:41d0:1004:224b::74;
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
Subject: [PATCH 11/18] lib/stackdepot: rename slab variables
Date: Mon, 30 Jan 2023 21:49:35 +0100
Message-Id: <fc73ab8b1469d476363a918cbdfe28e1388c043a.1675111415.git.andreyknvl@google.com>
In-Reply-To: <cover.1675111415.git.andreyknvl@google.com>
References: <cover.1675111415.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=H0xZx4zS;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::74 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Give better names to slab-related global variables: change "depot_"
prefix to "slab_" to point out that these variables are related to
stack depot slabs.

Also rename the slabindex field in handle_parts to align its name with
the slab_index global variable.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 46 +++++++++++++++++++++++-----------------------
 1 file changed, 23 insertions(+), 23 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 69b9316b0d4b..023f299bedf6 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -56,7 +56,7 @@
 union handle_parts {
 	depot_stack_handle_t handle;
 	struct {
-		u32 slabindex : STACK_ALLOC_INDEX_BITS;
+		u32 slab_index : STACK_ALLOC_INDEX_BITS;
 		u32 offset : STACK_ALLOC_OFFSET_BITS;
 		u32 valid : STACK_ALLOC_NULL_PROTECTION_BITS;
 		u32 extra : STACK_DEPOT_EXTRA_BITS;
@@ -93,11 +93,11 @@ static unsigned int stack_hash_mask;
 /* Array of memory regions that store stack traces. */
 static void *stack_slabs[STACK_ALLOC_MAX_SLABS];
 /* Currently used slab in stack_slabs. */
-static int depot_index;
+static int slab_index;
 /* Offset to the unused space in the currently used slab. */
-static size_t depot_offset;
+static size_t slab_offset;
 /* Lock that protects the variables above. */
-static DEFINE_RAW_SPINLOCK(depot_lock);
+static DEFINE_RAW_SPINLOCK(slab_lock);
 /* Whether the next slab is initialized. */
 static int next_slab_inited;
 
@@ -230,13 +230,13 @@ static bool depot_init_slab(void **prealloc)
 	 */
 	if (smp_load_acquire(&next_slab_inited))
 		return true;
-	if (stack_slabs[depot_index] == NULL) {
-		stack_slabs[depot_index] = *prealloc;
+	if (stack_slabs[slab_index] == NULL) {
+		stack_slabs[slab_index] = *prealloc;
 		*prealloc = NULL;
 	} else {
 		/* If this is the last depot slab, do not touch the next one. */
-		if (depot_index + 1 < STACK_ALLOC_MAX_SLABS) {
-			stack_slabs[depot_index + 1] = *prealloc;
+		if (slab_index + 1 < STACK_ALLOC_MAX_SLABS) {
+			stack_slabs[slab_index + 1] = *prealloc;
 			*prealloc = NULL;
 			/*
 			 * This smp_store_release pairs with smp_load_acquire()
@@ -258,35 +258,35 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 
 	required_size = ALIGN(required_size, 1 << STACK_ALLOC_ALIGN);
 
-	if (unlikely(depot_offset + required_size > STACK_ALLOC_SIZE)) {
-		if (unlikely(depot_index + 1 >= STACK_ALLOC_MAX_SLABS)) {
+	if (unlikely(slab_offset + required_size > STACK_ALLOC_SIZE)) {
+		if (unlikely(slab_index + 1 >= STACK_ALLOC_MAX_SLABS)) {
 			WARN_ONCE(1, "Stack depot reached limit capacity");
 			return NULL;
 		}
-		depot_index++;
-		depot_offset = 0;
+		slab_index++;
+		slab_offset = 0;
 		/*
 		 * smp_store_release() here pairs with smp_load_acquire() from
 		 * |next_slab_inited| in stack_depot_save() and
 		 * depot_init_slab().
 		 */
-		if (depot_index + 1 < STACK_ALLOC_MAX_SLABS)
+		if (slab_index + 1 < STACK_ALLOC_MAX_SLABS)
 			smp_store_release(&next_slab_inited, 0);
 	}
 	depot_init_slab(prealloc);
-	if (stack_slabs[depot_index] == NULL)
+	if (stack_slabs[slab_index] == NULL)
 		return NULL;
 
-	stack = stack_slabs[depot_index] + depot_offset;
+	stack = stack_slabs[slab_index] + slab_offset;
 
 	stack->hash = hash;
 	stack->size = size;
-	stack->handle.slabindex = depot_index;
-	stack->handle.offset = depot_offset >> STACK_ALLOC_ALIGN;
+	stack->handle.slab_index = slab_index;
+	stack->handle.offset = slab_offset >> STACK_ALLOC_ALIGN;
 	stack->handle.valid = 1;
 	stack->handle.extra = 0;
 	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
-	depot_offset += required_size;
+	slab_offset += required_size;
 
 	return stack;
 }
@@ -418,7 +418,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 			prealloc = page_address(page);
 	}
 
-	raw_spin_lock_irqsave(&depot_lock, flags);
+	raw_spin_lock_irqsave(&slab_lock, flags);
 
 	found = find_stack(*bucket, entries, nr_entries, hash);
 	if (!found) {
@@ -441,7 +441,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		WARN_ON(!depot_init_slab(&prealloc));
 	}
 
-	raw_spin_unlock_irqrestore(&depot_lock, flags);
+	raw_spin_unlock_irqrestore(&slab_lock, flags);
 exit:
 	if (prealloc) {
 		/* Nobody used this memory, ok to free it. */
@@ -497,12 +497,12 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 	if (!handle)
 		return 0;
 
-	if (parts.slabindex > depot_index) {
+	if (parts.slab_index > slab_index) {
 		WARN(1, "slab index %d out of bounds (%d) for stack id %08x\n",
-			parts.slabindex, depot_index, handle);
+			parts.slab_index, slab_index, handle);
 		return 0;
 	}
-	slab = stack_slabs[parts.slabindex];
+	slab = stack_slabs[parts.slab_index];
 	if (!slab)
 		return 0;
 	stack = slab + offset;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fc73ab8b1469d476363a918cbdfe28e1388c043a.1675111415.git.andreyknvl%40google.com.
