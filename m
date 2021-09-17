Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHXOSGFAMGQEEDUIAPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 405D940F681
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 13:08:15 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id x143-20020a19c795000000b003fa152e3484sf4743660lff.23
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 04:08:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631876894; cv=pass;
        d=google.com; s=arc-20160816;
        b=CkKkDxPCTIaDDa/MeQGLQoAyWwHQ6TX905j7mrN51ZswlcZIsiEswSixTj6o8OTNns
         +wc7crJ5XDWQcEy/KhL0pX5ll6PwdNlToKz/u7yRwPXRMYWrBuLtyqo1DqSdwYzba6Z8
         bbaLDW8L5kXqnHBQi92itnUVGm0TqQ05iPt5kBdV52Fs2/z1+B2ZqXwhbGM2jjiwUl/C
         j8lGSPhWjB1nta628lk7AiXwqtF51rDAT3ac0xn44v09ik2Fs8NhF8lV6GJgniksv3sB
         0SnCDaqkwSFnbpynUQOPAligpe8jTgkvPruNtjLpoMyWqCtupmNmkjzfPjjxdT3NfCD4
         JaYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=1hyzf1Rb0VYseNjMg9oNIjd/Tejzpax1Hd4+MqOe4jE=;
        b=JPixElWmR3hbMbqsyNzVZG/XMc9pkj9JrcK0pJxdxrVQGoX1ZVSHSUs1F1mNF0E8KS
         p/JI1r+Fvx7KJbZkPJ3noLPVZUqeYdGm8RgNtl37OvZ52iM5wyztGdFt4jLi3pAFM7vo
         Tuan1xcb15U7chIA7ehmj2OVaLil9O1VcEoRhe8AD1OOeVcgHVt2ysqzx8l33K6DObVi
         7Fsk0dbjqZouGT2Qb+sZrhuhV0AHEpFoe+Rb2A8D6W9jnkmpt++WdnVCP0AludgxUyu0
         7gw3wWjrr83vPq0m2zmAKO6zHI9RDl1xWwCBdGtnaSrytSSTJS+rSWeFJ4NCSdx0bWkw
         BnXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GhWbwajv;
       spf=pass (google.com: domain of 3hhdeyqukcs0nuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3HHdEYQUKCS0NUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1hyzf1Rb0VYseNjMg9oNIjd/Tejzpax1Hd4+MqOe4jE=;
        b=nBH9lUkzHJcvmL6aUGYX3vR2TqTds3WgrVWUVu6tuJ+JdFHCk2pvUEcrWJ4dDmLZvK
         FdAI9smP+ED4amgR4sOR0N5sBSQIk+sSolJ8zQMDz5+HyLYagxhFnkBmmVywoEJgmsD9
         W2xlaTF0dqFjUrHedWS9w512lHsTt5A6s1OWzeE8jImvUnoDSCsILoB2RCwFYSzte7sF
         xMnqqBini/iPxi5Ganb1Jy/AE1ejPsWMFcZ45SgCObRsIpDaoY2L50tWmBQvqT2zYRv9
         pd5DJat8i7cBBu3WqVPJeDJ997fLHyRSq72GbkQsmguU6wB2PLTSnEoqJhW9m9bkPbWz
         tcag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1hyzf1Rb0VYseNjMg9oNIjd/Tejzpax1Hd4+MqOe4jE=;
        b=XqxB8UVGf2DVv10CHaMLNc6tUaxTQI2uw8O0aNRXyxVd0fynCAzNCFMXqVopqZ9aQa
         3llKNMuXXBHnL4lqOR/Z4owFf7+8Eo8VLEWrgswg90vRfKhsGL+zQBtjsMXjvxpi9fhV
         TweeOsGBOr1c1F8ualiTCROKx6zmyQabUxSZIGtO1t8mKzRoAMgzQZTCuWoseXziXaxf
         fypi9duAkZ/TX6BHOrAUmC7g2+7C415mlSD7+NXQPGCQfWgdIbl0FON6JZBNLdepHRJT
         rZYOjVSAQNtOZjRjxNBbHhEjXQrj7pofaGQ+WusKSyeO33//03CRK5yURp87/0QUr1IF
         kPCg==
X-Gm-Message-State: AOAM530UvjcKcqILuyzQUCdH/HFAGyayqMUN5ZfpBbI1bcl+/Ic4puqC
	lOTcnkcGxa+kr155yZEV8bM=
X-Google-Smtp-Source: ABdhPJxtfhj7KYmamQtFSUXJKvO/du+8OYXlDwXpbxX0yhXgB97BBsBySiqZ52lB7EN4dhZVSB2Oyw==
X-Received: by 2002:a05:6512:2208:: with SMTP id h8mr7886161lfu.494.1631876894749;
        Fri, 17 Sep 2021 04:08:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:13a9:: with SMTP id p41ls1587877lfa.0.gmail; Fri,
 17 Sep 2021 04:08:13 -0700 (PDT)
X-Received: by 2002:a19:7601:: with SMTP id c1mr7496244lff.448.1631876893585;
        Fri, 17 Sep 2021 04:08:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631876893; cv=none;
        d=google.com; s=arc-20160816;
        b=vglJUGVjygrj5ErvkG18RTBEJLHiyzwa65Gd/TPqmVR6p/ThspWI6AcBFSVk16xogU
         jt5gFHrTnPW2a8K/RIgzGhsB/uBSwyxZm0M0vqaCuxgBwxWxV2kmbXclux1jENH7MP7q
         b8zploXjLHvMC06aqMWRrelEOh7tut+7c17dXo8pFqxL//EmvfpgFF1BzaTR2EuTy/7t
         ZMT6c6EPVkADVMMRi0+IA0hJIuxthwPlawsRcPZpnlU8q4pJG5sVjN1uhhRXJsmWNmRv
         unaA/uvfqlz+KN4EYIhianFB1weCsEb2Jo9bmGdpBSyHemXnAB1dSOy5KJve/ByJdI6S
         rgcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=uDdPzmnsldiiwWZYw9Tc+4pkR1I79p2wunSmR5EOuHU=;
        b=JYZkpzN+VJAuOS0TKQj2LMktdkFAtg+zlWpzkDlYCDdFs4KqnP01JueSFpl1SbVJJe
         QHtE2sVwEoBYsQSBqSrDX3TTRuoJSYxunWlTj66m0elUWk/OMlBthhH17LE5e9TSOcfz
         XjsxyLSqfk4Bdg5wxmKBayfW4lRor7nzFkRtsrWMKfwGYJt2o8m5bMuK90nrLFJdO/CF
         609ca3LiiZESFUs6+vdUNRZWgqKcui+Q8pTAHFajQUAT/w5EEqszUuFGUoStDU24a8yL
         bUMwLGf1cXZrFgxR3hf5lLq0r+qywikqobbTVR0E2ChrSQnZ0Hn45R/AiBlqFPerdTci
         675Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GhWbwajv;
       spf=pass (google.com: domain of 3hhdeyqukcs0nuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3HHdEYQUKCS0NUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id c15si11500ljn.5.2021.09.17.04.08.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Sep 2021 04:08:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hhdeyqukcs0nuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id v15-20020adff68f000000b0015df51efa18so3585069wrp.16
        for <kasan-dev@googlegroups.com>; Fri, 17 Sep 2021 04:08:13 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:1a57:84a3:9bae:8070])
 (user=elver job=sendgmr) by 2002:a5d:4591:: with SMTP id p17mr11339950wrq.59.1631876892798;
 Fri, 17 Sep 2021 04:08:12 -0700 (PDT)
Date: Fri, 17 Sep 2021 13:07:55 +0200
In-Reply-To: <20210917110756.1121272-1-elver@google.com>
Message-Id: <20210917110756.1121272-2-elver@google.com>
Mime-Version: 1.0
References: <20210917110756.1121272-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.464.g1972c5931b-goog
Subject: [PATCH 2/3] kfence: limit currently covered allocations when pool
 nearly full
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=GhWbwajv;       spf=pass
 (google.com: domain of 3hhdeyqukcs0nuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3HHdEYQUKCS0NUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

One of KFENCE's main design principles is that with increasing uptime,
allocation coverage increases sufficiently to detect previously
undetected bugs.

We have observed that frequent long-lived allocations of the same
source (e.g. pagecache) tend to permanently fill up the KFENCE pool
with increasing system uptime, thus breaking the above requirement.
The workaround thus far had been increasing the sample interval and/or
increasing the KFENCE pool size, but is no reliable solution.

To ensure diverse coverage of allocations, limit currently covered
allocations of the same source once pool utilization reaches 75% or
above. The effect is retaining reasonable allocation coverage when the
pool is close to full.

A side-effect is that this also limits frequent long-lived allocations
of the same source filling up the pool permanently.

Uniqueness of an allocation for coverage purposes is based on its
(partial) allocation stack trace (the source). A lossy hash map is
used to check if an allocation is covered; if the allocation is
currently covered, the allocation is skipped by KFENCE.

Testing was done using:

	(a) a synthetic workload that performs frequent long-lived
	    allocations (default config values + <10ms sample intervals
	    + smaller-than-default pool sizes), and

	(b) normal desktop workloads on an otherwise idle machine where
	    the problem was first reported (default config values).

In the case of (b) the observed result confirms that sampled allocation
rate no longer drops to zero after a few days of uptime, all while
"allocations skipped (covered)" are no more than 2% of total sampled
allocations.

Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/core.c   | 120 ++++++++++++++++++++++++++++++++++++++++++++-
 mm/kfence/kfence.h |   2 +
 2 files changed, 120 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 2755800f3e2a..3b78402d7a5e 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -11,11 +11,13 @@
 #include <linux/bug.h>
 #include <linux/debugfs.h>
 #include <linux/irq_work.h>
+#include <linux/jhash.h>
 #include <linux/kcsan-checks.h>
 #include <linux/kfence.h>
 #include <linux/kmemleak.h>
 #include <linux/list.h>
 #include <linux/lockdep.h>
+#include <linux/log2.h>
 #include <linux/memblock.h>
 #include <linux/moduleparam.h>
 #include <linux/random.h>
@@ -86,6 +88,28 @@ module_param_cb(sample_interval, &sample_interval_param_ops, &kfence_sample_inte
 char *__kfence_pool __ro_after_init;
 EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
 
+/*
+ * A lossy hash map of allocation stack trace coverage: limits currently covered
+ * allocations of the same source filling up the pool when close to full.
+ *
+ * The required data fits in 64 bits, and therefore we can avoid a per-entry (or
+ * global) lock by simply storing each entry's data in an atomic64_t.
+ */
+union alloc_covered_entry {
+	struct {
+		u32 alloc_stack_hash;	/* stack trace hash */
+		u32 covered;		/* current coverage count */
+	};
+	u64 entry;
+};
+#define ALLOC_COVERED_SIZE (1 << const_ilog2(CONFIG_KFENCE_NUM_OBJECTS | 128)) /* >= 128 */
+#define ALLOC_COVERED_MASK (ALLOC_COVERED_SIZE - 1)
+static atomic64_t alloc_covered[ALLOC_COVERED_SIZE];
+/* Stack depth used to determine uniqueness of an allocation. */
+#define UNIQUE_ALLOC_STACK_DEPTH 8
+/* Pool usage threshold when currently covered allocations are skipped. */
+#define SKIP_COVERED_THRESHOLD ((CONFIG_KFENCE_NUM_OBJECTS * 3) / 4) /* 75% */
+
 /*
  * Per-object metadata, with one-to-one mapping of object metadata to
  * backing pages (in __kfence_pool).
@@ -114,6 +138,7 @@ enum kfence_counter_id {
 	KFENCE_COUNTER_BUGS,
 	KFENCE_COUNTER_SKIP_INCOMPAT,
 	KFENCE_COUNTER_SKIP_CAPACITY,
+	KFENCE_COUNTER_SKIP_COVERED,
 	KFENCE_COUNTER_COUNT,
 };
 static atomic_long_t counters[KFENCE_COUNTER_COUNT];
@@ -125,11 +150,73 @@ static const char *const counter_names[] = {
 	[KFENCE_COUNTER_BUGS]		= "total bugs",
 	[KFENCE_COUNTER_SKIP_INCOMPAT]	= "skipped allocations (incompatible)",
 	[KFENCE_COUNTER_SKIP_CAPACITY]	= "skipped allocations (capacity)",
+	[KFENCE_COUNTER_SKIP_COVERED]	= "skipped allocations (covered)",
 };
 static_assert(ARRAY_SIZE(counter_names) == KFENCE_COUNTER_COUNT);
 
 /* === Internals ============================================================ */
 
+static u32 get_alloc_stack_hash(void)
+{
+	unsigned long stack_entries[UNIQUE_ALLOC_STACK_DEPTH];
+	size_t num_entries;
+
+	num_entries = stack_trace_save(stack_entries, UNIQUE_ALLOC_STACK_DEPTH, 1);
+	return jhash(stack_entries, num_entries * sizeof(stack_entries[0]), 0);
+}
+
+/*
+ * Check if the allocation stack trace hash @alloc_stack_hash is contained in
+ * @alloc_covered and currently covered.
+ */
+static bool alloc_covered_contains(u32 alloc_stack_hash)
+{
+	union alloc_covered_entry entry;
+
+	if (!alloc_stack_hash)
+		return false;
+
+	entry.entry = (u64)atomic64_read(&alloc_covered[alloc_stack_hash & ALLOC_COVERED_MASK]);
+	return entry.alloc_stack_hash == alloc_stack_hash && entry.covered;
+}
+
+/*
+ * Adds (or subtracts) coverage count to entry corresponding to
+ * @alloc_stack_hash. If @alloc_stack_hash is not yet contained in
+ * @alloc_covered, resets (potentially evicting existing) entry.
+ */
+static void alloc_covered_add(u32 alloc_stack_hash, int val)
+{
+	union alloc_covered_entry old;
+	union alloc_covered_entry new;
+	atomic64_t *bucket;
+
+	if (!alloc_stack_hash)
+		return;
+
+	bucket = &alloc_covered[alloc_stack_hash & ALLOC_COVERED_MASK];
+	old.entry = (u64)atomic64_read(bucket);
+	new.alloc_stack_hash = alloc_stack_hash;
+	do {
+		if (val > 0) {
+			new.covered = old.alloc_stack_hash == alloc_stack_hash
+					? old.covered + val	/* increment */
+					: val;			/* evict/reset */
+		} else if (old.alloc_stack_hash == alloc_stack_hash && old.covered) {
+			new.covered = old.covered + val;
+		} else {
+			/*
+			 * Hash mismatch or covered has become zero. The latter
+			 * is possible if we race with:
+			 *	reset (!= alloc_stack_hash)
+			 *	 -> reset (== alloc_stack_hash)
+			 *	  -> decrement
+			 */
+			break;
+		}
+	} while (!atomic64_try_cmpxchg_relaxed(bucket, (s64 *)&old.entry, (s64)new.entry));
+}
+
 static bool kfence_protect(unsigned long addr)
 {
 	return !KFENCE_WARN_ON(!kfence_protect_page(ALIGN_DOWN(addr, PAGE_SIZE), true));
@@ -261,7 +348,8 @@ static __always_inline void for_each_canary(const struct kfence_metadata *meta,
 	}
 }
 
-static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp)
+static void *
+kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp, u32 alloc_stack_hash)
 {
 	struct kfence_metadata *meta = NULL;
 	unsigned long flags;
@@ -322,6 +410,8 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 	/* Pairs with READ_ONCE() in kfence_shutdown_cache(). */
 	WRITE_ONCE(meta->cache, cache);
 	meta->size = size;
+	meta->alloc_stack_hash = alloc_stack_hash;
+
 	for_each_canary(meta, set_canary_byte);
 
 	/* Set required struct page fields. */
@@ -334,6 +424,8 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 
 	raw_spin_unlock_irqrestore(&meta->lock, flags);
 
+	alloc_covered_add(alloc_stack_hash, 1);
+
 	/* Memory initialization. */
 
 	/*
@@ -362,6 +454,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool zombie)
 {
 	struct kcsan_scoped_access assert_page_exclusive;
+	u32 alloc_stack_hash;
 	unsigned long flags;
 
 	raw_spin_lock_irqsave(&meta->lock, flags);
@@ -404,8 +497,13 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
 	/* Mark the object as freed. */
 	metadata_update_state(meta, KFENCE_OBJECT_FREED);
 
+	alloc_stack_hash = meta->alloc_stack_hash;
+	meta->alloc_stack_hash = 0;
+
 	raw_spin_unlock_irqrestore(&meta->lock, flags);
 
+	alloc_covered_add(alloc_stack_hash, -1);
+
 	/* Protect to detect use-after-frees. */
 	kfence_protect((unsigned long)addr);
 
@@ -744,6 +842,8 @@ void kfence_shutdown_cache(struct kmem_cache *s)
 
 void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 {
+	u32 alloc_stack_hash;
+
 	/*
 	 * Perform size check before switching kfence_allocation_gate, so that
 	 * we don't disable KFENCE without making an allocation.
@@ -788,7 +888,23 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 	if (!READ_ONCE(kfence_enabled))
 		return NULL;
 
-	return kfence_guarded_alloc(s, size, flags);
+	/*
+	 * Do expensive check for coverage of allocation in slow-path after
+	 * allocation_gate has already become non-zero, even though it might
+	 * mean not making any allocation within a given sample interval.
+	 *
+	 * This ensures reasonable allocation coverage when the pool is almost
+	 * full, including avoiding long-lived allocations of the same source
+	 * filling up the pool (e.g. pagecache allocations).
+	 */
+	alloc_stack_hash = get_alloc_stack_hash();
+	if (atomic_long_read(&counters[KFENCE_COUNTER_ALLOCATED]) > SKIP_COVERED_THRESHOLD &&
+	    alloc_covered_contains(alloc_stack_hash)) {
+		atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_COVERED]);
+		return NULL;
+	}
+
+	return kfence_guarded_alloc(s, size, flags, alloc_stack_hash);
 }
 
 size_t kfence_ksize(const void *addr)
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index c1f23c61e5f9..2a2d5de9d379 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -87,6 +87,8 @@ struct kfence_metadata {
 	/* Allocation and free stack information. */
 	struct kfence_track alloc_track;
 	struct kfence_track free_track;
+	/* For updating alloc_covered on frees. */
+	u32 alloc_stack_hash;
 };
 
 extern struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
-- 
2.33.0.464.g1972c5931b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210917110756.1121272-2-elver%40google.com.
