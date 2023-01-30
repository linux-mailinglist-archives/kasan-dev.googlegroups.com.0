Return-Path: <kasan-dev+bncBAABB3W34CPAMGQEU3ZDXGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 80DCA681BD2
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 21:51:59 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id bi41-20020a0565120ea900b004d584f37a04sf6032431lfb.21
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 12:51:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675111919; cv=pass;
        d=google.com; s=arc-20160816;
        b=fIbBi8j5HwTU5mo07WSEJuV+JB2kgMM0kqo3K4/6m9QIgPYnozPQzt7D7PWnu7DGsu
         wkCaheKIF90Rmtb3RdfW6WN3OFVmYJVP3CUnq2S1Hb/hC4X/gUH/nhFsHSMeoaWKqZgl
         XEVEVyrJ7gUfy2GNNuCj+ttHwywVH42UrA3P3gVV8G2Qn1QjkftY3yNWHCGTOTC3tn8a
         q9dJjLaqr71+HfxIL6ULQev0W4D3yLK3ZxYuIdtvF+bbxQj8sbCR1qnmBLp6GrOje8VS
         PDFcOAc7y+tI5Nz+l1AvymNQ2tB3LtinFAuYER9ecS1V4SMhPKrk77zMXYmX1x6TB0xy
         7SCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0UzJ69na7ze/BlPNj+TnOHe+mSNklzxfMVY4r25qy74=;
        b=lTxlEd0LUheMUGOwHCNNbXIy5hD1YGBd3L5ForXnmDNEcSfcChcGytK/3o/C77IZrd
         MgAr6/PITHLH7MrGbTaFlUpLFCSaqPhGjsPDzU9d8UMRch3+WN8FJhdKTQVLT5r3jfYu
         Vn9LZlMSEk/UfGWageIReviH9US0KRH6FxvfDZqQyEk3JtZkQv8P3gEBWTGwbjRZi3XC
         NJHh3ecxGip5vamnTYJFQdHPCWB1Nv/64Fjs32upxPhfg7bmc/VXSLtbcUYbirQ7aOWE
         +2a0t8WjlVUDn6BPV1cLIzYoaXcwWz6f7nmY6eUxMfYeLYxJwSXr4NkcI30fa85stuEC
         dnTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=N0ZO7gPg;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.5 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0UzJ69na7ze/BlPNj+TnOHe+mSNklzxfMVY4r25qy74=;
        b=PxGmUZI0YUarWTFB7sY+Imai2zuGBdd7A5iZWM9Nkh9jt8wrVes7wZVUfI2eLVog2f
         wADx5OCWk5LaniQxI+CWiX/oz+9hDGRMdlseXs7J4mo3CqN/mk54xaMoOu5Z7LHy280N
         pVB1is6uzVneu3OrUExEhICzVxBWDC4c4S5yukqVMoaEzLYNrLV6C+MaLM+ihcNHtscB
         PYnCEomkyvPCGd2Y3WZDRAzZDnfQKEblz3rW6JB29YS6/6Z5oYH3EpDHuHVvjgpI77t5
         ok+8kY/+isbPEJvV8GfnwRC+NpJm4JyHJscyl6EErbz8InC+D6s/Df1jkpVhYvsb4L+h
         HGqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0UzJ69na7ze/BlPNj+TnOHe+mSNklzxfMVY4r25qy74=;
        b=CNhaNeGQ+u/lKDE8EXOUSN7DTpEk+Xlp9FKVoeIco+lv2SfGmLUF7ywoYIaCxKpbdG
         zvMcy25guy7Kr/v3IjQSuBPDuT21gdRxqaupOqklgXQAjR3s7ZGg0bBfLOu6znbi8cny
         REPSQvr87nWS0vFYwvTt2XPvbwmxrIDW2t7Ug29RY+1r7ZwmCma3YV21+y+ijzPrRTuc
         OCx9b/Lgv/y3MqhiGfarknmb1LEDPgQkKsiKzOED8nhe/DFzpoMCz4lTokFBqqEgf2tz
         8RbIHvbpE8MYACjlXYtnmXTgYrhtrV3WF4hRjtKQ0qseKSlE+/7hUQmcZy8KF2YWWRyy
         xZSg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqWyFjdiZUZz/dScOcmRWpGHup3yxFSknZrHL+1FwZRYp4dvBsC
	whfqHpZfmrHYyVurAvJSLK0=
X-Google-Smtp-Source: AMrXdXtT/cRmwxHAOkn4juc2LaJUkHT6DN6ztoa1hEkKm/hmF4NqUP+Pzcj14gKT4kvGCEIn6hRxFg==
X-Received: by 2002:a05:6512:159:b0:4b5:2958:bd06 with SMTP id m25-20020a056512015900b004b52958bd06mr4989317lfo.26.1675111919020;
        Mon, 30 Jan 2023 12:51:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4891:0:b0:4d1:8575:2d31 with SMTP id x17-20020ac24891000000b004d185752d31ls762754lfc.0.-pod-prod-gmail;
 Mon, 30 Jan 2023 12:51:58 -0800 (PST)
X-Received: by 2002:ac2:5686:0:b0:4cb:20b3:e7f6 with SMTP id 6-20020ac25686000000b004cb20b3e7f6mr11652480lfr.19.1675111918111;
        Mon, 30 Jan 2023 12:51:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675111918; cv=none;
        d=google.com; s=arc-20160816;
        b=WkgdsT738dKuCxv2Hkwu78nb6xL9LG/rvG6D8+L2iiVKY/gWdq7MaslvUxIRNCrVOo
         2GQCeywDmRDeUpqYYMV6eBukn+KKnxGYw6shjKwoLioQIqI5E/xQv2KnDCdNhTg4bh/f
         fjbZmtBVqpYXVIe2xHUdehG3vOMElHxoBwMpLv5aD9Uyr+c5+BSAETSMpvYUudc05e3z
         NBgFyhJwkjeWnWZ28BDBdcaPtQjuNq67BFQMUcxixXd2403Lz3KUiibDHDAIlpiWe5iO
         yShvxjceWKg0R7I1eff5j37SdjGTkgWwU5KW/YVEYwldA0VFeMnttoyxnngexkHfHx1B
         0vIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=f1IK6xrmRNNY97ld0D9rdSaArRx+XdmL+DdOqeJXePk=;
        b=OC2pzMnInJj4E0PwLEAqknddssYg0d6v8IXgo4Js+TfxNPK5iu6xJOlqCF4cTiY2oz
         egrbpFEfCZ2sbJesrl6HqRG6Wz1XpxZGpNr0xzZChipVX/JvS/oOB+wXNw2FyZ9gGW56
         Gl71j6/dMX5RMtsy17CsIpF26pAM+alb1PkDHTaid9IBKuJu0Z/eTNH7xO3vrYZH3105
         kMo1H1vEhLYj99tX5HMqSZ2846Yv1jLli55YQbsL96KjNdEsj+uI4TrPfzKexnbljSCZ
         mmKj2TQUuIgaZtI7+Ye+b+BMJEPO9GcEdZHLohDE1/OnHVVBWpfvKnO47lPbc5d25WMl
         ecVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=N0ZO7gPg;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.5 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-5.mta0.migadu.com (out-5.mta0.migadu.com. [91.218.175.5])
        by gmr-mx.google.com with ESMTPS id c39-20020a05651223a700b004d57ca1c967si694815lfv.0.2023.01.30.12.51.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jan 2023 12:51:58 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.5 as permitted sender) client-ip=91.218.175.5;
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
Subject: [PATCH 17/18] lib/stackdepot: various comments clean-ups
Date: Mon, 30 Jan 2023 21:49:41 +0100
Message-Id: <e6d509e769bacc1842de868084e157787e6a3817.1675111415.git.andreyknvl@google.com>
In-Reply-To: <cover.1675111415.git.andreyknvl@google.com>
References: <cover.1675111415.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=N0ZO7gPg;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.5 as
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

Clean up comments in include/linux/stackdepot.h and lib/stackdepot.c:

1. Rework the initialization comment in stackdepot.h.
2. Rework the header comment in stackdepot.c.
3. Various clean-ups for other comments.

Also adjust whitespaces for find_stack and depot_alloc_stack call sites.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/stackdepot.h |  36 +++++------
 lib/stackdepot.c           | 120 ++++++++++++++++++-------------------
 2 files changed, 78 insertions(+), 78 deletions(-)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index f999811c66d7..173740987d8b 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -1,11 +1,11 @@
 /* SPDX-License-Identifier: GPL-2.0-or-later */
 /*
- * A generic stack depot implementation
+ * Stack depot - a stack trace storage that avoids duplication.
  *
  * Author: Alexander Potapenko <glider@google.com>
  * Copyright (C) 2016 Google, Inc.
  *
- * Based on code by Dmitry Chernenkov.
+ * Based on the code by Dmitry Chernenkov.
  */
 
 #ifndef _LINUX_STACKDEPOT_H
@@ -17,35 +17,37 @@ typedef u32 depot_stack_handle_t;
 
 /*
  * Number of bits in the handle that stack depot doesn't use. Users may store
- * information in them.
+ * information in them via stack_depot_set/get_extra_bits.
  */
 #define STACK_DEPOT_EXTRA_BITS 5
 
 /*
- * Every user of stack depot has to call stack_depot_init() during its own init
- * when it's decided that it will be calling stack_depot_save() later. This is
- * recommended for e.g. modules initialized later in the boot process, when
- * slab_is_available() is true.
+ * Using stack depot requires its initialization, which can be done in 3 ways:
  *
- * The alternative is to select STACKDEPOT_ALWAYS_INIT to have stack depot
- * enabled as part of mm_init(), for subsystems where it's known at compile time
- * that stack depot will be used.
+ * 1. Selecting CONFIG_STACKDEPOT_ALWAYS_INIT. This option is suitable in
+ *    scenarios where it's known at compile time that stack depot will be used.
+ *    Enabling this config makes the kernel initialize stack depot in mm_init().
  *
- * Another alternative is to call stack_depot_request_early_init(), when the
- * decision to use stack depot is taken e.g. when evaluating kernel boot
- * parameters, which precedes the enablement point in mm_init().
+ * 2. Calling stack_depot_request_early_init() during early boot, before
+ *    stack_depot_early_init() in mm_init() completes. For example, this can
+ *    be done when evaluating kernel boot parameters.
+ *
+ * 3. Calling stack_depot_init(). Possible after boot is complete. This option
+ *    is recommended for modules initialized later in the boot process, after
+ *    mm_init() completes.
  *
  * stack_depot_init() and stack_depot_request_early_init() can be called
- * regardless of CONFIG_STACKDEPOT and are no-op when disabled. The actual
- * save/fetch/print functions should only be called from code that makes sure
- * CONFIG_STACKDEPOT is enabled.
+ * regardless of whether CONFIG_STACKDEPOT is enabled and are no-op when this
+ * config is disabled. The save/fetch/print stack depot functions can only be
+ * called from the code that makes sure CONFIG_STACKDEPOT is enabled _and_
+ * initializes stack depot via one of the ways listed above.
  */
 #ifdef CONFIG_STACKDEPOT
 int stack_depot_init(void);
 
 void __init stack_depot_request_early_init(void);
 
-/* This is supposed to be called only from mm_init() */
+/* Must be only called from mm_init(). */
 int __init stack_depot_early_init(void);
 #else
 static inline int stack_depot_init(void) { return 0; }
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index cc2fe8563af4..5128f9486ceb 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -1,22 +1,26 @@
 // SPDX-License-Identifier: GPL-2.0-only
 /*
- * Generic stack depot for storing stack traces.
+ * Stack depot - a stack trace storage that avoids duplication.
  *
- * Some debugging tools need to save stack traces of certain events which can
- * be later presented to the user. For example, KASAN needs to safe alloc and
- * free stacks for each object, but storing two stack traces per object
- * requires too much memory (e.g. SLUB_DEBUG needs 256 bytes per object for
- * that).
+ * Stack depot is intended to be used by subsystems that need to store and
+ * later retrieve many potentially duplicated stack traces without wasting
+ * memory.
  *
- * Instead, stack depot maintains a hashtable of unique stacktraces. Since alloc
- * and free stacks repeat a lot, we save about 100x space.
- * Stacks are never removed from depot, so we store them contiguously one after
- * another in a contiguous memory allocation.
+ * For example, KASAN needs to save allocation and free stack traces for each
+ * object. Storing two stack traces per object requires a lot of memory (e.g.
+ * SLUB_DEBUG needs 256 bytes per object for that). Since allocation and free
+ * stack traces often repeat, using stack depot allows to save about 100x space.
+ *
+ * Internally, stack depot maintains a hash table of unique stacktraces. The
+ * stack traces themselves are stored contiguously one after another in a set
+ * of separate page allocations.
+ *
+ * Stack traces are never removed from stack depot.
  *
  * Author: Alexander Potapenko <glider@google.com>
  * Copyright (C) 2016 Google, Inc.
  *
- * Based on code by Dmitry Chernenkov.
+ * Based on the code by Dmitry Chernenkov.
  */
 
 #define pr_fmt(fmt) "stackdepot: " fmt
@@ -50,7 +54,7 @@
 	(((1LL << (DEPOT_SLAB_INDEX_BITS)) < DEPOT_SLABS_CAP) ? \
 	 (1LL << (DEPOT_SLAB_INDEX_BITS)) : DEPOT_SLABS_CAP)
 
-/* The compact structure to store the reference to stacks. */
+/* Compact structure that stores a reference to a stack. */
 union handle_parts {
 	depot_stack_handle_t handle;
 	struct {
@@ -62,11 +66,11 @@ union handle_parts {
 };
 
 struct stack_record {
-	struct stack_record *next;	/* Link in the hashtable */
-	u32 hash;			/* Hash in the hastable */
-	u32 size;			/* Number of frames in the stack */
+	struct stack_record *next;	/* Link in the hash table */
+	u32 hash;			/* Hash in the hash table */
+	u32 size;			/* Number of stored frames */
 	union handle_parts handle;
-	unsigned long entries[];	/* Variable-sized array of entries. */
+	unsigned long entries[];	/* Variable-sized array of frames */
 };
 
 static bool stack_depot_disabled;
@@ -305,7 +309,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	return stack;
 }
 
-/* Calculate hash for a stack */
+/* Calculates the hash for a stack. */
 static inline u32 hash_stack(unsigned long *entries, unsigned int size)
 {
 	return jhash2((u32 *)entries,
@@ -313,9 +317,9 @@ static inline u32 hash_stack(unsigned long *entries, unsigned int size)
 		      STACK_HASH_SEED);
 }
 
-/* Use our own, non-instrumented version of memcmp().
- *
- * We actually don't care about the order, just the equality.
+/*
+ * Non-instrumented version of memcmp().
+ * Does not check the lexicographical order, only the equality.
  */
 static inline
 int stackdepot_memcmp(const unsigned long *u1, const unsigned long *u2,
@@ -328,7 +332,7 @@ int stackdepot_memcmp(const unsigned long *u1, const unsigned long *u2,
 	return 0;
 }
 
-/* Find a stack that is equal to the one stored in entries in the hash */
+/* Finds a stack in a bucket of the hash table. */
 static inline struct stack_record *find_stack(struct stack_record *bucket,
 					     unsigned long *entries, int size,
 					     u32 hash)
@@ -345,27 +349,27 @@ static inline struct stack_record *find_stack(struct stack_record *bucket,
 }
 
 /**
- * __stack_depot_save - Save a stack trace from an array
+ * __stack_depot_save - Save a stack trace to stack depot
  *
- * @entries:		Pointer to storage array
- * @nr_entries:		Size of the storage array
- * @alloc_flags:	Allocation gfp flags
+ * @entries:		Pointer to the stack trace
+ * @nr_entries:		Number of frames in the stack
+ * @alloc_flags:	Allocation GFP flags
  * @can_alloc:		Allocate stack slabs (increased chance of failure if false)
  *
  * Saves a stack trace from @entries array of size @nr_entries. If @can_alloc is
- * %true, is allowed to replenish the stack slab pool in case no space is left
+ * %true, stack depot can replenish the stack slab pool in case no space is left
  * (allocates using GFP flags of @alloc_flags). If @can_alloc is %false, avoids
- * any allocations and will fail if no space is left to store the stack trace.
+ * any allocations and fails if no space is left to store the stack trace.
  *
- * If the stack trace in @entries is from an interrupt, only the portion up to
- * interrupt entry is saved.
+ * If the provided stack trace comes from the interrupt context, only the part
+ * up to the interrupt entry is saved.
  *
  * Context: Any context, but setting @can_alloc to %false is required if
  *          alloc_pages() cannot be used from the current context. Currently
- *          this is the case from contexts where neither %GFP_ATOMIC nor
+ *          this is the case for contexts where neither %GFP_ATOMIC nor
  *          %GFP_NOWAIT can be used (NMI, raw_spin_lock).
  *
- * Return: The handle of the stack struct stored in depot, 0 on failure.
+ * Return: Handle of the stack struct stored in depot, 0 on failure
  */
 depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 					unsigned int nr_entries,
@@ -380,11 +384,11 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 
 	/*
 	 * If this stack trace is from an interrupt, including anything before
-	 * interrupt entry usually leads to unbounded stackdepot growth.
+	 * interrupt entry usually leads to unbounded stack depot growth.
 	 *
-	 * Because use of filter_irq_stacks() is a requirement to ensure
-	 * stackdepot can efficiently deduplicate interrupt stacks, always
-	 * filter_irq_stacks() to simplify all callers' use of stackdepot.
+	 * Since use of filter_irq_stacks() is a requirement to ensure stack
+	 * depot can efficiently deduplicate interrupt stacks, always
+	 * filter_irq_stacks() to simplify all callers' use of stack depot.
 	 */
 	nr_entries = filter_irq_stacks(entries, nr_entries);
 
@@ -399,8 +403,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	 * The smp_load_acquire() here pairs with smp_store_release() to
 	 * |bucket| below.
 	 */
-	found = find_stack(smp_load_acquire(bucket), entries,
-			   nr_entries, hash);
+	found = find_stack(smp_load_acquire(bucket), entries, nr_entries, hash);
 	if (found)
 		goto exit;
 
@@ -430,7 +433,8 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 
 	found = find_stack(*bucket, entries, nr_entries, hash);
 	if (!found) {
-		struct stack_record *new = depot_alloc_stack(entries, nr_entries, hash, &prealloc);
+		struct stack_record *new =
+			depot_alloc_stack(entries, nr_entries, hash, &prealloc);
 
 		if (new) {
 			new->next = *bucket;
@@ -443,8 +447,8 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		}
 	} else if (prealloc) {
 		/*
-		 * We didn't need to store this stack trace, but let's keep
-		 * the preallocated memory for the future.
+		 * Stack depot already contains this stack trace, but let's
+		 * keep the preallocated memory for the future.
 		 */
 		depot_init_slab(&prealloc);
 	}
@@ -452,7 +456,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	raw_spin_unlock_irqrestore(&slab_lock, flags);
 exit:
 	if (prealloc) {
-		/* Nobody used this memory, ok to free it. */
+		/* Stack depot didn't use this memory, free it. */
 		free_pages((unsigned long)prealloc, DEPOT_SLAB_ORDER);
 	}
 	if (found)
@@ -463,16 +467,16 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 EXPORT_SYMBOL_GPL(__stack_depot_save);
 
 /**
- * stack_depot_save - Save a stack trace from an array
+ * stack_depot_save - Save a stack trace to stack depot
  *
- * @entries:		Pointer to storage array
- * @nr_entries:		Size of the storage array
- * @alloc_flags:	Allocation gfp flags
+ * @entries:		Pointer to the stack trace
+ * @nr_entries:		Number of frames in the stack
+ * @alloc_flags:	Allocation GFP flags
  *
  * Context: Contexts where allocations via alloc_pages() are allowed.
  *          See __stack_depot_save() for more details.
  *
- * Return: The handle of the stack struct stored in depot, 0 on failure.
+ * Return: Handle of the stack trace stored in depot, 0 on failure
  */
 depot_stack_handle_t stack_depot_save(unsigned long *entries,
 				      unsigned int nr_entries,
@@ -483,13 +487,12 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
 EXPORT_SYMBOL_GPL(stack_depot_save);
 
 /**
- * stack_depot_fetch - Fetch stack entries from a depot
+ * stack_depot_fetch - Fetch a stack trace from stack depot
  *
- * @handle:		Stack depot handle which was returned from
- *			stack_depot_save().
- * @entries:		Pointer to store the entries address
+ * @handle:	Stack depot handle returned from stack_depot_save()
+ * @entries:	Pointer to store the address of the stack trace
  *
- * Return: The number of trace entries for this depot.
+ * Return: Number of frames for the fetched stack
  */
 unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 			       unsigned long **entries)
@@ -521,11 +524,9 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 EXPORT_SYMBOL_GPL(stack_depot_fetch);
 
 /**
- * stack_depot_print - print stack entries from a depot
- *
- * @stack:		Stack depot handle which was returned from
- *			stack_depot_save().
+ * stack_depot_print - Print a stack trace from stack depot
  *
+ * @stack:	Stack depot handle returned from stack_depot_save()
  */
 void stack_depot_print(depot_stack_handle_t stack)
 {
@@ -539,17 +540,14 @@ void stack_depot_print(depot_stack_handle_t stack)
 EXPORT_SYMBOL_GPL(stack_depot_print);
 
 /**
- * stack_depot_snprint - print stack entries from a depot into a buffer
+ * stack_depot_snprint - Print a stack trace from stack depot into a buffer
  *
- * @handle:	Stack depot handle which was returned from
- *		stack_depot_save().
+ * @handle:	Stack depot handle returned from stack_depot_save()
  * @buf:	Pointer to the print buffer
- *
  * @size:	Size of the print buffer
- *
  * @spaces:	Number of leading spaces to print
  *
- * Return:	Number of bytes printed.
+ * Return:	Number of bytes printed
  */
 int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
 		       int spaces)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e6d509e769bacc1842de868084e157787e6a3817.1675111415.git.andreyknvl%40google.com.
