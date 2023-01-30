Return-Path: <kasan-dev+bncBAABB3O24CPAMGQEG6P6OYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 46FD1681BBD
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 21:49:50 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id a20-20020ac25214000000b004b57756f937sf5929279lfl.3
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 12:49:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675111789; cv=pass;
        d=google.com; s=arc-20160816;
        b=QmTQX3kjzC0aBKU1Rv9c8m3M4NBwhLSHviDqtFNmYr7ttgijPF1enioAuZxJRME3Dm
         f+2HpK/R3qjw7j+SSLBEp2tkymgTXRDf7iKXKg3rYTwpDX/FTUk4rwCLySU5X3e33WdJ
         kxCZhtGpFuoZNDQt/DdbVznyhi3umn+3zXlOrs7V+3ubMXP5+XeLS1RWI6m9CD3/X8pU
         v4Wluusw3qvClNCwpNDK4651xFXiwC1ZLf7alz/HwC9BztmOfanEcg19P0K5zk04ZjBC
         pm1zmZZ/yt35m+RMV7hvA3UiFSvnU6qnC7nOfgTVB6tsBsGRv8Vy4TE4aZegkR70zUfK
         4Z2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=no4r/njBi0ZgU5tVHmMs8P56CGGXEul1peu6h9oEt/M=;
        b=gdvzu1Y1V/ej+kgTsDrFZixy0SIPatibmsqlEWVNqM9uLmPtFA17p0dSbJx4MUsXJg
         H2H9Trr/8HeTQnr5O2nICMUAf3Shp7crBtjwg75+NbGbtVplOrKhr3OVRGAjjBqCl8bp
         AOO1Dvts8hMje7aP5N7RDjQklzNkxQaQs96fR8ckCtmOQFhhMFNTLkJYYRyJqqDSK5LZ
         0VvnQ8Dyi6iniPhwNNMXMALHKHH8OdG2O5vYLoicq+zK9XhYtp46a2grsM0XdqEe419Y
         pG3LVEBEaMC/u9NF/43kN/YOITZcR0lnz5Pc3sFRXejZiDirbvzsVVM6VnYR/J/x4o7Q
         qYmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="Oa/CuJOa";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.134 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=no4r/njBi0ZgU5tVHmMs8P56CGGXEul1peu6h9oEt/M=;
        b=hWz2dNzRoqyL5JSPkapNiQJJ62zA9slf3S3jmjrCPy9Kuv6VaeJN8Dxgdy+pPXl8gw
         DRWzU2zL6RKscfAbcYTcfLyFLIbyQUjt/sVuia6fpcPDqvr2f7rNOfNCB7ji2JhiwVRh
         OMtClY0T49MWl8x66al4gl3WdZ/loJUEydjs5zLplhpBasaegNKRJhlnmJ9+ZllOEhE0
         WdfrppmmQOyvX8aTy/2aXm96EguEJi6cdeMrTEw22XpYiNUMZo+hqyHAgWFc7jZUVis8
         W93X5ll94G5npwKZj2c3nPfaz0g+Px2xHZiHPLDWxEPo+ExhMAwNAw4K5Z8FpCBRpxML
         7C5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=no4r/njBi0ZgU5tVHmMs8P56CGGXEul1peu6h9oEt/M=;
        b=p5FK4py2uPdj548djmI8j9kBNUWyzXZVnd/p/4PLN6DbMk2uWGWh96m1sMCAio47q0
         y8vRiQ3C7ZCL+iF0kbEcoR+SKTy0UZxhPipY7jIvFIh5M1UgVEjwueky3LXANu0ObZyp
         RO6dG1mkWs+uMLL3izKr0IbTX+dFYmfNAUJe7lZwH70tp7IJgy4XaLeoGtiD7Z47c540
         3qQILHmCdoCgR05C+s+FTEUTFwQum1PJ4EYUzSWVOCAEPjh3WkhVoihw46/O14or/KnT
         g4eO7wP/kwaAWRQmsuXXyZo1Mlyi78pKfw+6Rt+8u3u0teWZLWQ81AYCFHyeI63gjOBd
         W1GA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koPHid2VnSDbIR2BM7FXz18QKlM+C7kLEXzntT7XattCAFDMKhF
	PYLatmbGCfFRQ8RECXg8i48=
X-Google-Smtp-Source: AMrXdXvi0D1HvBTdTvQCMWerw6QCT+AVUUS6exqCG4iNPDu7tL6kmTGJYbVLZCJCEfWep1HXfbrP8g==
X-Received: by 2002:ac2:46f3:0:b0:4a2:48c1:455f with SMTP id q19-20020ac246f3000000b004a248c1455fmr3563476lfo.96.1675111789439;
        Mon, 30 Jan 2023 12:49:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4f13:0:b0:4d5:7ca1:c92f with SMTP id k19-20020ac24f13000000b004d57ca1c92fls753709lfr.2.-pod-prod-gmail;
 Mon, 30 Jan 2023 12:49:48 -0800 (PST)
X-Received: by 2002:ac2:43ba:0:b0:4a4:68b7:f892 with SMTP id t26-20020ac243ba000000b004a468b7f892mr12545586lfl.54.1675111788349;
        Mon, 30 Jan 2023 12:49:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675111788; cv=none;
        d=google.com; s=arc-20160816;
        b=Db4mpT4ndyD4JcMS3leRz7Jo2+JPRNF0jGO1JJXdX6odJ6RN0HpQzDnA6J0qqwNNSX
         Ez5JBW7x9D24Vzf7f6ESa3RERYX++K0CG1EwUHAehYjTex/pXem4KMhscjT+IWZkaDR7
         NxMYGaxXKMPSHDvfv23AY6x+o+6XbfjAChWBGKTPeWtj92WrXRWTrc8/XY1wBBHi8bSk
         G0aw7HwkDfPyZ/Q4N3blj5rq9JZ9E54EGDmGZCSihHDxZYbFwWf4VCkhISmJbowamt9Z
         YKL7cS1FUw/QIxggw0sWWKohA0cSW+LEo1MdrZh6VGCHqf/yeXrHGtjVjmswS0OWVXX/
         ymnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=qcsUnulCBN0ghXL+bzeFYdD4TQnNlpFLy99BvSyy4/8=;
        b=wTZVnOs70QyfMKHyCixxESi/ZN46jt290g42goixMS7HqZ4oIebEc/KraSH4fn7mJ6
         onGvPOrhyj3rAl2/IVvzTOrEOtGOmBYy8FUiSdS5jkWTkY1gr3czwr8VLv9JzIfVpyAR
         6qfqq1Bk1O3pqgIcuuapA6hzvNjq+boBp5w3Vv9Nghc/41soYTM4Os2YyykfHaCgLU54
         HGMKUPquwPNMekAoZwA2Xt7TrvTMqYRTXjsZb52L5IMv3UNRTZ9G/fJMrl7O5QHrldxa
         8QaTzCsfR3BDKROgpnkO9GPVIj7Ad9f79Yh/8JeSe6xwWUWyKxR9BFoGRb2ynuyzk+Pv
         k4+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="Oa/CuJOa";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.134 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-134.mta1.migadu.com (out-134.mta1.migadu.com. [95.215.58.134])
        by gmr-mx.google.com with ESMTPS id o19-20020a198c13000000b004d34d4743c0si123428lfd.2.2023.01.30.12.49.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jan 2023 12:49:48 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.134 as permitted sender) client-ip=95.215.58.134;
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
Subject: [PATCH 02/18] lib/stackdepot: put functions in logical order
Date: Mon, 30 Jan 2023 21:49:26 +0100
Message-Id: <632393332c364171c69b7c054b3b2233acbfa996.1675111415.git.andreyknvl@google.com>
In-Reply-To: <cover.1675111415.git.andreyknvl@google.com>
References: <cover.1675111415.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="Oa/CuJOa";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.134 as
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

Put stack depot functions' declarations and definitions in a more logical
order:

1. Functions that save stack traces into stack depot.
2. Functions that fetch and print stack traces.
3. stack_depot_get_extra_bits that operates on stack depot handles
   and does not interact with the stack depot storage.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/stackdepot.h |  15 +-
 lib/stackdepot.c           | 316 ++++++++++++++++++-------------------
 2 files changed, 166 insertions(+), 165 deletions(-)

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
index 0eed9bbcf23e..23d2a68a587b 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -79,85 +79,6 @@ static int next_slab_inited;
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
-			/*
-			 * This smp_store_release pairs with smp_load_acquire()
-			 * from |next_slab_inited| above and in
-			 * stack_depot_save().
-			 */
-			smp_store_release(&next_slab_inited, 1);
-		}
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
@@ -271,6 +192,77 @@ int stack_depot_init(void)
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
+			/*
+			 * This smp_store_release pairs with smp_load_acquire()
+			 * from |next_slab_inited| above and in
+			 * stack_depot_save().
+			 */
+			smp_store_release(&next_slab_inited, 1);
+		}
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
@@ -310,85 +302,6 @@ static inline struct stack_record *find_stack(struct stack_record *bucket,
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
@@ -534,3 +447,90 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/632393332c364171c69b7c054b3b2233acbfa996.1675111415.git.andreyknvl%40google.com.
