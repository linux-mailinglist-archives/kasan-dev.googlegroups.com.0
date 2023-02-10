Return-Path: <kasan-dev+bncBAABBHHITKPQMGQEPRFEWIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 331ED692900
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 22:16:13 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id s2-20020a2e1502000000b002917ff038dasf1856333ljd.7
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 13:16:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676063772; cv=pass;
        d=google.com; s=arc-20160816;
        b=QJTQkz8X/Qk5TUC6QwuSg9wDeourgswlgPzlS/cH8HoNSVGn5PBVd9CCM04AfjXCMV
         q3Z3RXJ0zAcAS2p4uikrnBtVf32VtiS3/XJ6hns1MC4nUqmTs3TTEEm68d77J9juXXZM
         jHKc7yYXtL5N1dEhbLigC/2xDUQbXnzRGfoC0zntH0DGduzoavV2Tls3yPVqX8DowipT
         S4gRx4d8rHAZQTI5m40Cv1WADJHjLDZeqQDUBltjbZMFwKlgwpAZjAX9ORGSkI9SrkgF
         ezFUi5BTBkEBHdGhcAkP/3pxf8M3XX4fnrD9ocbe+oo7kSSQT4kt25fdnYYHP1oZN4fZ
         XahQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XlBScMm0P4x/sgIhcts/BwhctNg1+4sD6xz6GxkBhPU=;
        b=eJbuCoftumLtwfTkMka9AwlZGLrSfhWvCxgKS+1jsavxlLE3diB2cR2640LMzpGGXN
         5uztMhWrn+ul3lW7m4bxjXodt9hktGM2fQdwmC82PQyqLou32Cy8Tm6aZ3pBtbkTFs+/
         pL55J6KSs9gABkJUVStugopXVGcVIVvF/mdult6ijuwNN5uYrJ14bcpO44CR5EmP9lbw
         vPbythAH86Cq9VuJ/ww0SFlx4p/7bM35qQVbhQczWLo0uvqSZQPNaUnFryxufgbxLhME
         ob+rJB/QWav1au4pZVO1xMSJJ6LcgUGnxixffTcvByWh6oczv3WTYppMb0vXnD57wCP0
         kFiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=w90TbDJL;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.224 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XlBScMm0P4x/sgIhcts/BwhctNg1+4sD6xz6GxkBhPU=;
        b=SlgAFnanwyeVlGL5Szwj2bLgtfs/tLz11oJEeFraW/83/GgQFXsJpKr23Ti+cKOGgM
         VKSCd4G2GNqISLS7K4JxYDcbx6aTN6PModT8YZrZk/+M4BjvMxke7Drl0uUVBqWtgecz
         vNMiNYF0nUmZwPebjUICyaw5oNM89JofYAe8c3S1e96tvaHCKYuMKdzTTOMLbkAMvwph
         WI1N6lUXv6KJl/ayB/fXaWSQb3pff22KzSGq5xOxJz3Bg3r5OcW2LD83Hv7iACH+DIoJ
         SYSOaGTAX6fP0dbify0mhAy4E2I6C1mW5tI4bg4+jK159L+UHBLJ4KyJyR4KG5c6kNeT
         kwvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XlBScMm0P4x/sgIhcts/BwhctNg1+4sD6xz6GxkBhPU=;
        b=VBjFDapVcePF4iiUA4dno0gzX0sSfLZkJ2DJgB2J/pR1R3wirZkTN3f0cyGBFm94Ov
         ScR8NgAjzB1l9ulg+JQlEtPjG2trRhSK8ivYjGDjZUbWfo8fhxC7xUeFUgXzbS3rM6Ok
         ZLaY3yF69J48D1Yq0g5MI5bvE/QRDVEMq7499k60+SDhs419X2j6IpBhdDmfvW0tRflr
         3aTxFu7evJ6vmq6B5bm3c6Afo75e51YHE71bEjR4fUOw0NhWzsaxNXlLmR40LpPldr2s
         pcCF04TAEDfSDrQTmmUmmW1NG4Gd4bTRVCtft8R2FlAY87uaAILRbAJzytu4wnYRgKIj
         H18g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWOgMa82VBC4NSQaec5Mmg8rWLJneuB65N3tCYEQ1v+9Dl72DUe
	y1SAuIATExhItqpGvYuQKTg=
X-Google-Smtp-Source: AK7set/PL7cSWwrZPyIAliSZ7I5tT2SF2X4WFcHvM3c/wEjp5MlcvlEnYBIZNCN12HYWWUkCFvPTng==
X-Received: by 2002:a05:651c:171c:b0:290:6278:7806 with SMTP id be28-20020a05651c171c00b0029062787806mr2846334ljb.100.1676063772562;
        Fri, 10 Feb 2023 13:16:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b25:b0:4d5:7ca1:c92f with SMTP id
 f37-20020a0565123b2500b004d57ca1c92fls1438616lfv.2.-pod-prod-gmail; Fri, 10
 Feb 2023 13:16:11 -0800 (PST)
X-Received: by 2002:ac2:5de5:0:b0:4ca:f42f:c6a4 with SMTP id z5-20020ac25de5000000b004caf42fc6a4mr4364504lfq.36.1676063771148;
        Fri, 10 Feb 2023 13:16:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676063771; cv=none;
        d=google.com; s=arc-20160816;
        b=E4eqD15g4TYIpOOk6mENKtbbwjTnoqBXAPQmNfNcR1N/8S8q5NbYUVm+FlImSPE5vu
         tNKJW4iqB6PYSmZRdWKXz9GSSOoZ1+pEXi6Jo0kltLmvWlKJX+L1xBTPVgVG/s5c+x18
         KhFqGY2DWXylK5OjRtdFxduUS9TGHq7UDSgdrnedKsMY2yVmrF2BWQeUtGZdqVQJi9DQ
         uQSLkr4XyIph87IekH/1AGPeg4H5p7rdwKe1Wzrrey2H9JCfALmBRTSvrYYUPH3xZ5fV
         YT5HLWPS5UxnVz2x1XWZ28OhiEEGZfBWEfukarfnH4En4KLlZbXuYu74+dG7ltu9sG2Y
         npXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0D/1F5CMwtFSAEjWxVZCsgWbjza4wyrBe5NUV/UGD6o=;
        b=P2SVnGjgIDSDUB7AHkXoTXCUsLRwRjE+gsZuDdpXZbNaV9kDAOgKbMjp+W1OhhNMhG
         go+QWKBDqrk98rIwF0LKtQY2YqExhd3R24oGYQnAn+2nE8KV0xzRgK7VfPdrgFt+oDU6
         8QET8SvTrGLXDa9X8RmZpc3+2hghvpFA0mjaH3h2T4ERkYcKfJo+HaADbtb+PEVuSExq
         p0STZiHzUx6ZXJal+TDSdt1ZMrtFPDCr5PMbm2zE1OoZdyARyePtxdQdjmt/51G530FZ
         3faLbWaNvG+rkl5tjY/Ss4IIUx5yUCo4yqn+iLQ9IV7/13nPs2ourN2EmTH1kbcwV2b5
         mQXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=w90TbDJL;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.224 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-224.mta0.migadu.com (out-224.mta0.migadu.com. [91.218.175.224])
        by gmr-mx.google.com with ESMTPS id i1-20020a0565123e0100b004d3d4e49b7dsi318337lfv.13.2023.02.10.13.16.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Feb 2023 13:16:11 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.224 as permitted sender) client-ip=91.218.175.224;
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
Subject: [PATCH v2 01/18] lib/stackdepot: put functions in logical order
Date: Fri, 10 Feb 2023 22:15:49 +0100
Message-Id: <daca1319b665d826b94c596b992a8d8117846147.1676063693.git.andreyknvl@google.com>
In-Reply-To: <cover.1676063693.git.andreyknvl@google.com>
References: <cover.1676063693.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=w90TbDJL;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.224
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

Put stack depot functions' declarations and definitions in a more logical
order:

1. Functions that save stack traces into stack depot.
2. Functions that fetch and print stack traces.
3. stack_depot_get_extra_bits that operates on stack depot handles
   and does not interact with the stack depot storage.

No functional changes.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/stackdepot.h |  15 +-
 lib/stackdepot.c           | 314 ++++++++++++++++++-------------------
 2 files changed, 165 insertions(+), 164 deletions(-)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index 9ca7798d7a31..1296a6eeaec0 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -14,17 +14,13 @@
 #include <linux/gfp.h>
 
 typedef u32 depot_stack_handle_t;
+
 /*
  * Number of bits in the handle that stack depot doesn't use. Users may store
  * information in them.
  */
 #define STACK_DEPOT_EXTRA_BITS 5
 
-depot_stack_handle_t __stack_depot_save(unsigned long *entries,
-					unsigned int nr_entries,
-					unsigned int extra_bits,
-					gfp_t gfp_flags, bool can_alloc);
-
 /*
  * Every user of stack depot has to call stack_depot_init() during its own init
  * when it's decided that it will be calling stack_depot_save() later. This is
@@ -59,17 +55,22 @@ static inline void stack_depot_want_early_init(void) { }
 static inline int stack_depot_early_init(void)	{ return 0; }
 #endif
 
+depot_stack_handle_t __stack_depot_save(unsigned long *entries,
+					unsigned int nr_entries,
+					unsigned int extra_bits,
+					gfp_t gfp_flags, bool can_alloc);
+
 depot_stack_handle_t stack_depot_save(unsigned long *entries,
 				      unsigned int nr_entries, gfp_t gfp_flags);
 
 unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 			       unsigned long **entries);
 
-unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle);
+void stack_depot_print(depot_stack_handle_t stack);
 
 int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
 		       int spaces);
 
-void stack_depot_print(depot_stack_handle_t stack);
+unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle);
 
 #endif
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 79e894cf8406..4bfaf3bce619 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -79,84 +79,6 @@ static int next_slab_inited;
 static size_t depot_offset;
 static DEFINE_RAW_SPINLOCK(depot_lock);
 
-unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle)
-{
-	union handle_parts parts = { .handle = handle };
-
-	return parts.extra;
-}
-EXPORT_SYMBOL(stack_depot_get_extra_bits);
-
-static bool init_stack_slab(void **prealloc)
-{
-	if (!*prealloc)
-		return false;
-	/*
-	 * This smp_load_acquire() pairs with smp_store_release() to
-	 * |next_slab_inited| below and in depot_alloc_stack().
-	 */
-	if (smp_load_acquire(&next_slab_inited))
-		return true;
-	if (stack_slabs[depot_index] == NULL) {
-		stack_slabs[depot_index] = *prealloc;
-		*prealloc = NULL;
-	} else {
-		/* If this is the last depot slab, do not touch the next one. */
-		if (depot_index + 1 < STACK_ALLOC_MAX_SLABS) {
-			stack_slabs[depot_index + 1] = *prealloc;
-			*prealloc = NULL;
-		}
-		/*
-		 * This smp_store_release pairs with smp_load_acquire() from
-		 * |next_slab_inited| above and in stack_depot_save().
-		 */
-		smp_store_release(&next_slab_inited, 1);
-	}
-	return true;
-}
-
-/* Allocation of a new stack in raw storage */
-static struct stack_record *
-depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
-{
-	struct stack_record *stack;
-	size_t required_size = struct_size(stack, entries, size);
-
-	required_size = ALIGN(required_size, 1 << STACK_ALLOC_ALIGN);
-
-	if (unlikely(depot_offset + required_size > STACK_ALLOC_SIZE)) {
-		if (unlikely(depot_index + 1 >= STACK_ALLOC_MAX_SLABS)) {
-			WARN_ONCE(1, "Stack depot reached limit capacity");
-			return NULL;
-		}
-		depot_index++;
-		depot_offset = 0;
-		/*
-		 * smp_store_release() here pairs with smp_load_acquire() from
-		 * |next_slab_inited| in stack_depot_save() and
-		 * init_stack_slab().
-		 */
-		if (depot_index + 1 < STACK_ALLOC_MAX_SLABS)
-			smp_store_release(&next_slab_inited, 0);
-	}
-	init_stack_slab(prealloc);
-	if (stack_slabs[depot_index] == NULL)
-		return NULL;
-
-	stack = stack_slabs[depot_index] + depot_offset;
-
-	stack->hash = hash;
-	stack->size = size;
-	stack->handle.slabindex = depot_index;
-	stack->handle.offset = depot_offset >> STACK_ALLOC_ALIGN;
-	stack->handle.valid = 1;
-	stack->handle.extra = 0;
-	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
-	depot_offset += required_size;
-
-	return stack;
-}
-
 /* one hash table bucket entry per 16kB of memory */
 #define STACK_HASH_SCALE	14
 /* limited between 4k and 1M buckets */
@@ -270,6 +192,76 @@ int stack_depot_init(void)
 }
 EXPORT_SYMBOL_GPL(stack_depot_init);
 
+static bool init_stack_slab(void **prealloc)
+{
+	if (!*prealloc)
+		return false;
+	/*
+	 * This smp_load_acquire() pairs with smp_store_release() to
+	 * |next_slab_inited| below and in depot_alloc_stack().
+	 */
+	if (smp_load_acquire(&next_slab_inited))
+		return true;
+	if (stack_slabs[depot_index] == NULL) {
+		stack_slabs[depot_index] = *prealloc;
+		*prealloc = NULL;
+	} else {
+		/* If this is the last depot slab, do not touch the next one. */
+		if (depot_index + 1 < STACK_ALLOC_MAX_SLABS) {
+			stack_slabs[depot_index + 1] = *prealloc;
+			*prealloc = NULL;
+		}
+		/*
+		 * This smp_store_release pairs with smp_load_acquire() from
+		 * |next_slab_inited| above and in stack_depot_save().
+		 */
+		smp_store_release(&next_slab_inited, 1);
+	}
+	return true;
+}
+
+/* Allocation of a new stack in raw storage */
+static struct stack_record *
+depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
+{
+	struct stack_record *stack;
+	size_t required_size = struct_size(stack, entries, size);
+
+	required_size = ALIGN(required_size, 1 << STACK_ALLOC_ALIGN);
+
+	if (unlikely(depot_offset + required_size > STACK_ALLOC_SIZE)) {
+		if (unlikely(depot_index + 1 >= STACK_ALLOC_MAX_SLABS)) {
+			WARN_ONCE(1, "Stack depot reached limit capacity");
+			return NULL;
+		}
+		depot_index++;
+		depot_offset = 0;
+		/*
+		 * smp_store_release() here pairs with smp_load_acquire() from
+		 * |next_slab_inited| in stack_depot_save() and
+		 * init_stack_slab().
+		 */
+		if (depot_index + 1 < STACK_ALLOC_MAX_SLABS)
+			smp_store_release(&next_slab_inited, 0);
+	}
+	init_stack_slab(prealloc);
+	if (stack_slabs[depot_index] == NULL)
+		return NULL;
+
+	stack = stack_slabs[depot_index] + depot_offset;
+
+	stack->hash = hash;
+	stack->size = size;
+	stack->handle.slabindex = depot_index;
+	stack->handle.offset = depot_offset >> STACK_ALLOC_ALIGN;
+	stack->handle.valid = 1;
+	stack->handle.extra = 0;
+	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
+	depot_offset += required_size;
+
+	return stack;
+}
+
 /* Calculate hash for a stack */
 static inline u32 hash_stack(unsigned long *entries, unsigned int size)
 {
@@ -309,85 +301,6 @@ static inline struct stack_record *find_stack(struct stack_record *bucket,
 	return NULL;
 }
 
-/**
- * stack_depot_snprint - print stack entries from a depot into a buffer
- *
- * @handle:	Stack depot handle which was returned from
- *		stack_depot_save().
- * @buf:	Pointer to the print buffer
- *
- * @size:	Size of the print buffer
- *
- * @spaces:	Number of leading spaces to print
- *
- * Return:	Number of bytes printed.
- */
-int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
-		       int spaces)
-{
-	unsigned long *entries;
-	unsigned int nr_entries;
-
-	nr_entries = stack_depot_fetch(handle, &entries);
-	return nr_entries ? stack_trace_snprint(buf, size, entries, nr_entries,
-						spaces) : 0;
-}
-EXPORT_SYMBOL_GPL(stack_depot_snprint);
-
-/**
- * stack_depot_print - print stack entries from a depot
- *
- * @stack:		Stack depot handle which was returned from
- *			stack_depot_save().
- *
- */
-void stack_depot_print(depot_stack_handle_t stack)
-{
-	unsigned long *entries;
-	unsigned int nr_entries;
-
-	nr_entries = stack_depot_fetch(stack, &entries);
-	if (nr_entries > 0)
-		stack_trace_print(entries, nr_entries, 0);
-}
-EXPORT_SYMBOL_GPL(stack_depot_print);
-
-/**
- * stack_depot_fetch - Fetch stack entries from a depot
- *
- * @handle:		Stack depot handle which was returned from
- *			stack_depot_save().
- * @entries:		Pointer to store the entries address
- *
- * Return: The number of trace entries for this depot.
- */
-unsigned int stack_depot_fetch(depot_stack_handle_t handle,
-			       unsigned long **entries)
-{
-	union handle_parts parts = { .handle = handle };
-	void *slab;
-	size_t offset = parts.offset << STACK_ALLOC_ALIGN;
-	struct stack_record *stack;
-
-	*entries = NULL;
-	if (!handle)
-		return 0;
-
-	if (parts.slabindex > depot_index) {
-		WARN(1, "slab index %d out of bounds (%d) for stack id %08x\n",
-			parts.slabindex, depot_index, handle);
-		return 0;
-	}
-	slab = stack_slabs[parts.slabindex];
-	if (!slab)
-		return 0;
-	stack = slab + offset;
-
-	*entries = stack->entries;
-	return stack->size;
-}
-EXPORT_SYMBOL_GPL(stack_depot_fetch);
-
 /**
  * __stack_depot_save - Save a stack trace from an array
  *
@@ -533,3 +446,90 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
 	return __stack_depot_save(entries, nr_entries, 0, alloc_flags, true);
 }
 EXPORT_SYMBOL_GPL(stack_depot_save);
+
+/**
+ * stack_depot_fetch - Fetch stack entries from a depot
+ *
+ * @handle:		Stack depot handle which was returned from
+ *			stack_depot_save().
+ * @entries:		Pointer to store the entries address
+ *
+ * Return: The number of trace entries for this depot.
+ */
+unsigned int stack_depot_fetch(depot_stack_handle_t handle,
+			       unsigned long **entries)
+{
+	union handle_parts parts = { .handle = handle };
+	void *slab;
+	size_t offset = parts.offset << STACK_ALLOC_ALIGN;
+	struct stack_record *stack;
+
+	*entries = NULL;
+	if (!handle)
+		return 0;
+
+	if (parts.slabindex > depot_index) {
+		WARN(1, "slab index %d out of bounds (%d) for stack id %08x\n",
+			parts.slabindex, depot_index, handle);
+		return 0;
+	}
+	slab = stack_slabs[parts.slabindex];
+	if (!slab)
+		return 0;
+	stack = slab + offset;
+
+	*entries = stack->entries;
+	return stack->size;
+}
+EXPORT_SYMBOL_GPL(stack_depot_fetch);
+
+/**
+ * stack_depot_print - print stack entries from a depot
+ *
+ * @stack:		Stack depot handle which was returned from
+ *			stack_depot_save().
+ *
+ */
+void stack_depot_print(depot_stack_handle_t stack)
+{
+	unsigned long *entries;
+	unsigned int nr_entries;
+
+	nr_entries = stack_depot_fetch(stack, &entries);
+	if (nr_entries > 0)
+		stack_trace_print(entries, nr_entries, 0);
+}
+EXPORT_SYMBOL_GPL(stack_depot_print);
+
+/**
+ * stack_depot_snprint - print stack entries from a depot into a buffer
+ *
+ * @handle:	Stack depot handle which was returned from
+ *		stack_depot_save().
+ * @buf:	Pointer to the print buffer
+ *
+ * @size:	Size of the print buffer
+ *
+ * @spaces:	Number of leading spaces to print
+ *
+ * Return:	Number of bytes printed.
+ */
+int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
+		       int spaces)
+{
+	unsigned long *entries;
+	unsigned int nr_entries;
+
+	nr_entries = stack_depot_fetch(handle, &entries);
+	return nr_entries ? stack_trace_snprint(buf, size, entries, nr_entries,
+						spaces) : 0;
+}
+EXPORT_SYMBOL_GPL(stack_depot_snprint);
+
+unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle)
+{
+	union handle_parts parts = { .handle = handle };
+
+	return parts.extra;
+}
+EXPORT_SYMBOL(stack_depot_get_extra_bits);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/daca1319b665d826b94c596b992a8d8117846147.1676063693.git.andreyknvl%40google.com.
