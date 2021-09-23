Return-Path: <kasan-dev+bncBC7OBJGL2MHBB45WWGFAMGQEJX55LYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D2A97415C37
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 12:48:20 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id z26-20020a05660200da00b005b86e36a1f4sf5359197ioe.15
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 03:48:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632394099; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZTRJGJdOYhHJPfLqIhLQvTgZmDqP4xA9fWjglVBNbb2qYvJmt6nNYVMSkDxtXenmdu
         w4Nj7OhKzxOq5UDBXtdOEMj2gj0MoboiIzYB58JXLDmqTzFNXFTqGXEOfzlHFFy69DA/
         trU9JpNK6mun0worIcihDNh+GDgmkiSPkfAzGkTWAG6Ia4yjzQ46xaYTEp41Mu0Nyi8J
         WpglRrBAYfw/XxgAbusG85GdPf2VGGYT7IEKNodVBt1bwi6UIbcFTbzXsw7C5OOD3vpd
         X4x39lgJHY0JrscxbtYvDj29PL9WuCUsN2hcwMCo1MZx3kzPAyBTT+TZJceyZ8uQp6W2
         Gt6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=fFa/wctTpHRCD1OSArr/ML1XpEslmr0lW1gkUNAKjfA=;
        b=iwTJ8cCPCCy+MYuyPaDS0Xl9gUFpkHPjVjsiDU29Y35039yVxKhh9ax/e1E2dFLYqs
         UwFAYjsyip5582NvZUHzTJlix3ssXEVn1wTkvNp+/lj5Q7aembq+CfZHQLrA/+CAE2A/
         4oLRsAHNV7BSk0FuEZGTekGGR4ZzC+IdbUhyXdOytCXx2+SdHLNkNlaUo7SfZUJP5o0f
         vSH8Ij4DSFUIluqlgWptilqVO9ad/V5zoicOkt7g0KA9x8123eNYM3VSNYsGRITFc9ML
         75hQ0floYBCMtax66H1wabg6pXr6QFT+/PwHBiqpWNQsaYyzt/ZuE0CIOtHeTOunzCWg
         8ekg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=skXFe3aS;
       spf=pass (google.com: domain of 3cltmyqukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3cltMYQUKCWsNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fFa/wctTpHRCD1OSArr/ML1XpEslmr0lW1gkUNAKjfA=;
        b=c2ubcZKOs1ijRirTdZnhS8+X2Ue/3SHnK+6pNeCd9OrAGuOrojjz0w8E+avWHDJwcr
         CfLHNyZHjiVEbfaLv8h0JoPdfFTxCTjz1AYsBAXgVooR4oMkMBf05g3UBeIS0SBev0qH
         uVsvCvO1oVon7T5XaeA3OpJHF2wbiBZ/Qzm1gFANTLTRLw7eItJoBI4d7CDLNWhCj13X
         un90st4unwoV4kNnQI+45elGw2kgG6twrZlQ2jS6ugvSegmXG49E49e5oEjsnUpYv8qU
         KSkZOCa+uk8oHkIREp6ckvpUPgJFpYZTQ+F0re8Arp8LH8qNFRRq4H/wXBbuOkz2IT+8
         CeXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fFa/wctTpHRCD1OSArr/ML1XpEslmr0lW1gkUNAKjfA=;
        b=I3XHKk0g6tGq6MTPpgn5dUnCed5HCYe0HBTQZeNUy0vVT6gm9b6eR2Q5KiEQBNo7WV
         Za04OKzmRbSgnI/4NPafT6HODzAqECgSaC7gAhLRxSCPH7nJbh3zquj2uiG9dbSnLVbd
         ASi7QRyoAnOLM53CUs0Aalz915+fF6sYPBSGmDgp3/opW4lgcgle1Rg8S59Qiz6mLneo
         gumvv0KADQjfEuKHoFLmauSzsW7DKWQDo1ImjocemrdXF98scIwEZMrF6Zo9lU55pSt/
         1UfhD7Jxbf3So47gk6lpZ8F/DmwQ8ODNhCc3l3Th/u7ZtdkJeqlPloNbvECw/X0SMUfo
         zX3w==
X-Gm-Message-State: AOAM533Hk/t4n6kg0S1Us3dwCtALkvwd0ryyUPVA9B3obsCAI0f1u+Lq
	qceoL+J2hWt+1c+hSVrCCaw=
X-Google-Smtp-Source: ABdhPJzgmlA4izy+LZdhWnlbtlgwqGOW8J04Jbzj9Qi1Hn+ssaMf6rZSAtjzqW7qJibiTz5V2zH45A==
X-Received: by 2002:a5d:950d:: with SMTP id d13mr3226992iom.138.1632394099665;
        Thu, 23 Sep 2021 03:48:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:10cf:: with SMTP id s15ls1383563ilj.3.gmail; Thu,
 23 Sep 2021 03:48:19 -0700 (PDT)
X-Received: by 2002:a05:6e02:12c4:: with SMTP id i4mr3187495ilm.211.1632394099258;
        Thu, 23 Sep 2021 03:48:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632394099; cv=none;
        d=google.com; s=arc-20160816;
        b=Exa3JEFG5MW0tWqXR03R+P9M7OKD6reSkpN9Zv449PGZbskJP1bo9lRh/BaEL8R7O+
         CU/IBBuBfcHiqt5KHomIXwCLLORMngn1Wua7nO6GCgrCFL6X401C9oDqzftlhMwzR4ce
         HGwHbTl0CszSNPFasyvtJ+FL89dvyjG9bv+/x7dMFhapSv2Pb1yKVNBApKGjmg2jlWy/
         /Twmz9CqxAj2e8eAhSP/uKp61Ekz45Soo6bRtDeGf6zHo0PwDhSWqIi6AJKPA0+qPkV+
         //xNVlBwoRqhPJApBrom1YwJQxViQr1rIswtfQR6jloIX57IRY8loS9qtcZK96G0/Ylf
         zrZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=zqdGAxiwy73PPAUb3qLgXKxgIEaGpSoYFxR743aTgss=;
        b=kBQ4xyazTzW1y6Of8DeIZVdRW2InoCCI31pd8VAlI8uRiO7Ic72FAu83z0gf0qdmoM
         ti40Xj7viAXo9FXPrIYIDk6BSg1h3U8aEzLmbKJvuD9Bs4G7z9BKRPw6jQzCHz9OR7gl
         1un/MSJARAKQUU0NDsbAepsRRsbUfAxBCef3cdHTTd38qNgIrUdk4yjS3qj2omDKrkM1
         MGvHS6lZ5VflcJluHfMN6zO8JX6ULzWWw4m1BiKA25/Zth8VcPZpvB3jQbNsTkYCPaP3
         1I5AMvVUxYbY1xh5OuDdgoai60bp4HQcB5TTQDKJ8OpbHOxqo3oaMcE5pBcQl0taoJmt
         TyIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=skXFe3aS;
       spf=pass (google.com: domain of 3cltmyqukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3cltMYQUKCWsNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id o17si315448ilo.5.2021.09.23.03.48.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Sep 2021 03:48:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cltmyqukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id r5-20020a05620a298500b0045dac5fb940so3463164qkp.17
        for <kasan-dev@googlegroups.com>; Thu, 23 Sep 2021 03:48:19 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:bd72:fd35:a085:c2e3])
 (user=elver job=sendgmr) by 2002:a05:6214:142c:: with SMTP id
 o12mr3671612qvx.26.1632394098782; Thu, 23 Sep 2021 03:48:18 -0700 (PDT)
Date: Thu, 23 Sep 2021 12:48:02 +0200
In-Reply-To: <20210923104803.2620285-1-elver@google.com>
Message-Id: <20210923104803.2620285-4-elver@google.com>
Mime-Version: 1.0
References: <20210923104803.2620285-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.464.g1972c5931b-goog
Subject: [PATCH v3 4/5] kfence: limit currently covered allocations when pool
 nearly full
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=skXFe3aS;       spf=pass
 (google.com: domain of 3cltmyqukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3cltMYQUKCWsNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
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
v3:
* Remove unneeded !alloc_stack_hash checks.
* Remove unneeded meta->alloc_stack_hash=0 in kfence_guarded_free().

v2:
* Switch to counting bloom filter to guarantee currently covered
  allocations being skipped.
* Use a module param for skip_covered threshold.
* Use kfence pool address as hash entropy.
* Use filter_irq_stacks().
---
 mm/kfence/core.c   | 103 ++++++++++++++++++++++++++++++++++++++++++++-
 mm/kfence/kfence.h |   2 +
 2 files changed, 103 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index db01814f8ff0..58a0f6f1acc5 100644
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
@@ -125,11 +151,60 @@ static const char *const counter_names[] = {
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
@@ -269,7 +344,8 @@ static __always_inline void for_each_canary(const struct kfence_metadata *meta,
 }
 
 static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp,
-				  unsigned long *stack_entries, size_t num_stack_entries)
+				  unsigned long *stack_entries, size_t num_stack_entries,
+				  u32 alloc_stack_hash)
 {
 	struct kfence_metadata *meta = NULL;
 	unsigned long flags;
@@ -332,6 +408,8 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 	/* Pairs with READ_ONCE() in kfence_shutdown_cache(). */
 	WRITE_ONCE(meta->cache, cache);
 	meta->size = size;
+	meta->alloc_stack_hash = alloc_stack_hash;
+
 	for_each_canary(meta, set_canary_byte);
 
 	/* Set required struct page fields. */
@@ -344,6 +422,8 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 
 	raw_spin_unlock_irqrestore(&meta->lock, flags);
 
+	alloc_covered_add(alloc_stack_hash, 1);
+
 	/* Memory initialization. */
 
 	/*
@@ -412,6 +492,8 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
 
 	raw_spin_unlock_irqrestore(&meta->lock, flags);
 
+	alloc_covered_add(meta->alloc_stack_hash, -1);
+
 	/* Protect to detect use-after-frees. */
 	kfence_protect((unsigned long)addr);
 
@@ -752,6 +834,7 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 {
 	unsigned long stack_entries[KFENCE_STACK_DEPTH];
 	size_t num_stack_entries;
+	u32 alloc_stack_hash;
 
 	/*
 	 * Perform size check before switching kfence_allocation_gate, so that
@@ -799,7 +882,23 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210923104803.2620285-4-elver%40google.com.
