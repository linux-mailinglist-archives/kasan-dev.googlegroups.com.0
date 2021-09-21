Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFW7U2FAMGQETHY2UOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id E324341314F
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 12:10:30 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id g9-20020a0565123b8900b003f33a027130sf14636525lfv.18
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 03:10:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632219030; cv=pass;
        d=google.com; s=arc-20160816;
        b=pI/4WmgBnGJUah5MgUFMuFd+SZD9lQ2LxAUjDRV/P9h6WyHFhlYvUeb+ApL7dWg/HA
         tzCC+iG89FCclAmJhioriC1BHO+FF3euPZ6kN5HcuipUfXZ+RcJngWplKEzQKs4Tzbk6
         M1bL/39qiVifX9vK5NFZwWQz71iXBGftZS30kT9NBWGYnd8U3YxMmVBoUZ9v7GMmIhD8
         DAWxHDIHYv5cONCefWyRXkqhX77t254wNMQ1JpbLsi38QAUq4wWOyUlbIUjAWmQKfNZF
         Da8WItBGlRs28dlnxKITPlItxGi3YYUpKgltRlKIVBTV7ZE7I+KC4V+vhebbGOfb63Af
         kddg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=fj6Byo5smNRR2gKwuDXjPRHCSJr582RJPob72tvGbvM=;
        b=i+YdThsLf6XoDxQPiJ+WWsBgD0SClhsWJpMh3P6uN7oW7/uemsqU/8QLhToLJRzMZg
         3IpY4NotLmtfLjim/zOY/LnRi7uU/nt4RDWiU7zZJWdRyzs8d3UOfAZcd2tz6hrGuS4Z
         NPEeiNM1uA0oPcQIWNnY378mP18x+Se5Cq89JqgpqLa9FnBFiJjYsoPYZa/U6wTauHL8
         CpxkCQBIJ/9ayegX8g/BxFHy0ohDpty4tzxumF6/ylN/CF+Qz/H4TGL+KQSVAH5QhHid
         7QB2FsjV1Zbo38ZNjt8lnwHmaQUiEduuGfrIPUJVct20+Dd38XIzOWj8CKV49xw178VP
         y4GQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AByc0i2a;
       spf=pass (google.com: domain of 3lk9jyqukcsslsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3lK9JYQUKCSsLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fj6Byo5smNRR2gKwuDXjPRHCSJr582RJPob72tvGbvM=;
        b=lDxd9VNAInUQRKPtsruQ/T2530dhyK6InWzG8ldu+5fWs8dKsgQU9PtbHjrSEgc0ww
         XpCyYHiVJCcnmIzsHiV1cE9z/Kxu51CUYwJ9Y1TNUW2v4djaer5Nh4clGrgwL+a2ck44
         IHWHB67XJZCWppZy/vSRJnDc3YK3SDUgiypVymY04JR4kX+U4pK1M5bPvW9CQXAQsWal
         UUVJuNdfZ9Q3sFHfV+Nh7fKsfg10JbyqLAaEnAt677Q5VJdwXcPGHkvocaedmnFjR/+Q
         4D3D4n4Sfn/kyrrLS8nlFIhFTuYbtf90h0NRlmjosnCeu7pbryrX6WmBT/crmDZmj/Ni
         Wq3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fj6Byo5smNRR2gKwuDXjPRHCSJr582RJPob72tvGbvM=;
        b=HsD1cFsDytA8GeOPMV8EL7mqO6aOzXJzBc/FL76bYZUI8pSFBD8eKcZ+BCj2fR87BJ
         aywUBoKWqlnRRai4WshGIWFLV6n7pQrZ6dJ7ejBHeIlJSynnUuaQzptzq+sJ6hNvIuRz
         9B6j4NxyADed2FL/YljgSJYJ4qznLeTi0mUIBS+R85VXTqOJSzd0ZxCz4AqdmtLRxdIL
         SrZ3BmpVQEZpU1S8IWY/u7QAmwXQl8QPCJoEMH2BLzjGqPptqlVifh2Uk34GMpPY8c0B
         rX93FDLT+PKodKxwXnUlr9+v00GCx3D4By7XAMd6zCoemlYZwKKAaWit5AKkRNDMIqrp
         WveA==
X-Gm-Message-State: AOAM531+HgokPlVo84u1A6XlCWw6wmV28ZbX3g2qDVZ/dNMcsWn8OAWO
	/0EsP4dyMrs/AVSd0Boxj24=
X-Google-Smtp-Source: ABdhPJyqg3OAj+62GVasDhN1hD7RCB5QydU8zzQ1u2OzaDguZL+EQz2bb+p2YaASiR/G6+LdSM8uHA==
X-Received: by 2002:a2e:a28d:: with SMTP id k13mr26101128lja.446.1632219030477;
        Tue, 21 Sep 2021 03:10:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:168c:: with SMTP id bd12ls1427617ljb.5.gmail; Tue,
 21 Sep 2021 03:10:29 -0700 (PDT)
X-Received: by 2002:a2e:9598:: with SMTP id w24mr26035615ljh.77.1632219029358;
        Tue, 21 Sep 2021 03:10:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632219029; cv=none;
        d=google.com; s=arc-20160816;
        b=TC+PQoNMgPlHqucXll3CzYkaDPEfuG0dtb6DeEH14eq85YvnQMhu2Nt/d4oXO4jHfr
         Wx6UIgx3Q+DN6F06NiQI/R8hSVgnAG0kmltATT017Q9jHfosKT+Bb6VLqC6Y8+FJ7DbP
         W5QlqRMos34+zi8Zsug7+kfZEPnhTOM1QxDnqo0kQA5vP40uwY8GjG9K+Vmvh5oHY/I3
         jkYCLlA28U4eFwzmbzsxTxkh4UBjETl7jrjxrPXkKsvCzHAkHT7XkqHEgsFB3pUQUexv
         gGkwbl9Bs11MBGqgT7+N7TyqS7H69F5t8newyr4+4zZhh6Qyg50f1GXSwE7Li5GL5ciq
         0MeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=tX0nZu/PV7Fs/kpXK7987zjFf32SdSUPUBR9+wpGpH0=;
        b=fVIOqSeckorvPUcT+QgmWCXhwZRq/jiBLwfYgl26KQO9aUgkrrc2nLiFiAwyp8CU5e
         XxKGePaGxuxlz879e3srVNxiNgekfJ8k6v5GCdvQfoEvcPUaNx+0dx2y+HV2Y24KG8ak
         jJvdCkymN3LQ13xsTipjt3lXMYhctar5RIcSmbtJwzm7xgaXgfExcfjImKUduEnkBPq0
         7q3ouSdBXFVILrKIijYcSGvLOgTtOSzioFALnPXvVRq2f1NNLDwWavdBX7smfIqyGbpx
         k2AUE2E0WhI/hhYR68G48N85+zxALUeayXSujtPu05MhVbDv5F0q7N+SIw3VcCZGESfM
         O89A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AByc0i2a;
       spf=pass (google.com: domain of 3lk9jyqukcsslsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3lK9JYQUKCSsLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id x16si137667ljp.5.2021.09.21.03.10.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Sep 2021 03:10:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lk9jyqukcsslsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id r7-20020a5d6947000000b0015e0f68a63bso8415238wrw.22
        for <kasan-dev@googlegroups.com>; Tue, 21 Sep 2021 03:10:29 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:dd03:c280:4625:60db])
 (user=elver job=sendgmr) by 2002:adf:f545:: with SMTP id j5mr33922187wrp.9.1632219028674;
 Tue, 21 Sep 2021 03:10:28 -0700 (PDT)
Date: Tue, 21 Sep 2021 12:10:13 +0200
In-Reply-To: <20210921101014.1938382-1-elver@google.com>
Message-Id: <20210921101014.1938382-4-elver@google.com>
Mime-Version: 1.0
References: <20210921101014.1938382-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.464.g1972c5931b-goog
Subject: [PATCH v2 4/5] kfence: limit currently covered allocations when pool
 nearly full
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=AByc0i2a;       spf=pass
 (google.com: domain of 3lk9jyqukcsslsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3lK9JYQUKCSsLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
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
allocations of the same source once pool utilization reaches 75%
(configurable via `kfence.skip_covered_thresh`) or above. The effect is
retaining reasonable allocation coverage when the pool is close to full.

A side-effect is that this also limits frequent long-lived allocations
of the same source filling up the pool permanently.

Uniqueness of an allocation for coverage purposes is based on its
(partial) allocation stack trace (the source). A Counting Bloom filter
is used to check if an allocation is covered; if the allocation is
currently covered, the allocation is skipped by KFENCE.

Testing was done using:

	(a) a synthetic workload that performs frequent long-lived
	    allocations (default config values; sample_interval=1;
	    num_objects=63), and

	(b) normal desktop workloads on an otherwise idle machine where
	    the problem was first reported after a few days of uptime
	    (default config values).

In both test cases the sampled allocation rate no longer drops to zero
at any point. In the case of (b) we observe (after 2 days uptime) 15%
unique allocations in the pool, 77% pool utilization, with 20% "skipped
allocations (covered)".

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Switch to counting bloom filter to guarantee currently covered
  allocations being skipped.
* Use a module param for skip_covered threshold.
* Use kfence pool address as hash entropy.
* Use filter_irq_stacks().
---
 mm/kfence/core.c   | 113 ++++++++++++++++++++++++++++++++++++++++++++-
 mm/kfence/kfence.h |   2 +
 2 files changed, 113 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index db01814f8ff0..9b3fb30f24c3 100644
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
@@ -82,6 +84,10 @@ static const struct kernel_param_ops sample_interval_param_ops = {
 };
 module_param_cb(sample_interval, &sample_interval_param_ops, &kfence_sample_interval, 0600);
 
+/* Pool usage% threshold when currently covered allocations are skipped. */
+static unsigned long kfence_skip_covered_thresh __read_mostly = 75;
+module_param_named(skip_covered_thresh, kfence_skip_covered_thresh, ulong, 0644);
+
 /* The pool of pages used for guard pages and objects. */
 char *__kfence_pool __ro_after_init;
 EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
@@ -105,6 +111,25 @@ DEFINE_STATIC_KEY_FALSE(kfence_allocation_key);
 /* Gates the allocation, ensuring only one succeeds in a given period. */
 atomic_t kfence_allocation_gate = ATOMIC_INIT(1);
 
+/*
+ * A Counting Bloom filter of allocation coverage: limits currently covered
+ * allocations of the same source filling up the pool.
+ *
+ * Assuming a range of 15%-85% unique allocations in the pool at any point in
+ * time, the below parameters provide a probablity of 0.02-0.33 for false
+ * positive hits respectively:
+ *
+ *	P(alloc_traces) = (1 - e^(-HNUM * (alloc_traces / SIZE)) ^ HNUM
+ */
+#define ALLOC_COVERED_HNUM	2
+#define ALLOC_COVERED_SIZE	(1 << (const_ilog2(CONFIG_KFENCE_NUM_OBJECTS) + 2))
+#define ALLOC_COVERED_HNEXT(h)	(1664525 * (h) + 1013904223)
+#define ALLOC_COVERED_MASK	(ALLOC_COVERED_SIZE - 1)
+static atomic_t alloc_covered[ALLOC_COVERED_SIZE];
+
+/* Stack depth used to determine uniqueness of an allocation. */
+#define UNIQUE_ALLOC_STACK_DEPTH 8UL
+
 /* Statistics counters for debugfs. */
 enum kfence_counter_id {
 	KFENCE_COUNTER_ALLOCATED,
@@ -114,6 +139,7 @@ enum kfence_counter_id {
 	KFENCE_COUNTER_BUGS,
 	KFENCE_COUNTER_SKIP_INCOMPAT,
 	KFENCE_COUNTER_SKIP_CAPACITY,
+	KFENCE_COUNTER_SKIP_COVERED,
 	KFENCE_COUNTER_COUNT,
 };
 static atomic_long_t counters[KFENCE_COUNTER_COUNT];
@@ -125,11 +151,66 @@ static const char *const counter_names[] = {
 	[KFENCE_COUNTER_BUGS]		= "total bugs",
 	[KFENCE_COUNTER_SKIP_INCOMPAT]	= "skipped allocations (incompatible)",
 	[KFENCE_COUNTER_SKIP_CAPACITY]	= "skipped allocations (capacity)",
+	[KFENCE_COUNTER_SKIP_COVERED]	= "skipped allocations (covered)",
 };
 static_assert(ARRAY_SIZE(counter_names) == KFENCE_COUNTER_COUNT);
 
 /* === Internals ============================================================ */
 
+static inline bool should_skip_covered(void)
+{
+	unsigned long thresh = (CONFIG_KFENCE_NUM_OBJECTS * kfence_skip_covered_thresh) / 100;
+
+	return atomic_long_read(&counters[KFENCE_COUNTER_ALLOCATED]) > thresh;
+}
+
+static u32 get_alloc_stack_hash(unsigned long *stack_entries, size_t num_entries)
+{
+	/* Some randomness across reboots / different machines. */
+	u32 seed = (u32)((unsigned long)__kfence_pool >> (BITS_PER_LONG - 32));
+
+	num_entries = min(num_entries, UNIQUE_ALLOC_STACK_DEPTH);
+	num_entries = filter_irq_stacks(stack_entries, num_entries);
+	return jhash(stack_entries, num_entries * sizeof(stack_entries[0]), seed);
+}
+
+/*
+ * Adds (or subtracts) count @val for allocation stack trace hash
+ * @alloc_stack_hash from Counting Bloom filter.
+ */
+static void alloc_covered_add(u32 alloc_stack_hash, int val)
+{
+	int i;
+
+	if (!alloc_stack_hash)
+		return;
+
+	for (i = 0; i < ALLOC_COVERED_HNUM; i++) {
+		atomic_add(val, &alloc_covered[alloc_stack_hash & ALLOC_COVERED_MASK]);
+		alloc_stack_hash = ALLOC_COVERED_HNEXT(alloc_stack_hash);
+	}
+}
+
+/*
+ * Returns true if the allocation stack trace hash @alloc_stack_hash is
+ * currently contained (non-zero count) in Counting Bloom filter.
+ */
+static bool alloc_covered_contains(u32 alloc_stack_hash)
+{
+	int i;
+
+	if (!alloc_stack_hash)
+		return false;
+
+	for (i = 0; i < ALLOC_COVERED_HNUM; i++) {
+		if (!atomic_read(&alloc_covered[alloc_stack_hash & ALLOC_COVERED_MASK]))
+			return false;
+		alloc_stack_hash = ALLOC_COVERED_HNEXT(alloc_stack_hash);
+	}
+
+	return true;
+}
+
 static bool kfence_protect(unsigned long addr)
 {
 	return !KFENCE_WARN_ON(!kfence_protect_page(ALIGN_DOWN(addr, PAGE_SIZE), true));
@@ -269,7 +350,8 @@ static __always_inline void for_each_canary(const struct kfence_metadata *meta,
 }
 
 static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp,
-				  unsigned long *stack_entries, size_t num_stack_entries)
+				  unsigned long *stack_entries, size_t num_stack_entries,
+				  u32 alloc_stack_hash)
 {
 	struct kfence_metadata *meta = NULL;
 	unsigned long flags;
@@ -332,6 +414,8 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 	/* Pairs with READ_ONCE() in kfence_shutdown_cache(). */
 	WRITE_ONCE(meta->cache, cache);
 	meta->size = size;
+	meta->alloc_stack_hash = alloc_stack_hash;
+
 	for_each_canary(meta, set_canary_byte);
 
 	/* Set required struct page fields. */
@@ -344,6 +428,8 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 
 	raw_spin_unlock_irqrestore(&meta->lock, flags);
 
+	alloc_covered_add(alloc_stack_hash, 1);
+
 	/* Memory initialization. */
 
 	/*
@@ -368,6 +454,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool zombie)
 {
 	struct kcsan_scoped_access assert_page_exclusive;
+	u32 alloc_stack_hash;
 	unsigned long flags;
 
 	raw_spin_lock_irqsave(&meta->lock, flags);
@@ -410,8 +497,13 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
 	/* Mark the object as freed. */
 	metadata_update_state(meta, KFENCE_OBJECT_FREED, NULL, 0);
 
+	alloc_stack_hash = meta->alloc_stack_hash;
+	meta->alloc_stack_hash = 0;
+
 	raw_spin_unlock_irqrestore(&meta->lock, flags);
 
+	alloc_covered_add(alloc_stack_hash, -1);
+
 	/* Protect to detect use-after-frees. */
 	kfence_protect((unsigned long)addr);
 
@@ -752,6 +844,7 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 {
 	unsigned long stack_entries[KFENCE_STACK_DEPTH];
 	size_t num_stack_entries;
+	u32 alloc_stack_hash;
 
 	/*
 	 * Perform size check before switching kfence_allocation_gate, so that
@@ -799,7 +892,23 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 
 	num_stack_entries = stack_trace_save(stack_entries, KFENCE_STACK_DEPTH, 0);
 
-	return kfence_guarded_alloc(s, size, flags, stack_entries, num_stack_entries);
+	/*
+	 * Do expensive check for coverage of allocation in slow-path after
+	 * allocation_gate has already become non-zero, even though it might
+	 * mean not making any allocation within a given sample interval.
+	 *
+	 * This ensures reasonable allocation coverage when the pool is almost
+	 * full, including avoiding long-lived allocations of the same source
+	 * filling up the pool (e.g. pagecache allocations).
+	 */
+	alloc_stack_hash = get_alloc_stack_hash(stack_entries, num_stack_entries);
+	if (should_skip_covered() && alloc_covered_contains(alloc_stack_hash)) {
+		atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_COVERED]);
+		return NULL;
+	}
+
+	return kfence_guarded_alloc(s, size, flags, stack_entries, num_stack_entries,
+				    alloc_stack_hash);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210921101014.1938382-4-elver%40google.com.
