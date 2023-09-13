Return-Path: <kasan-dev+bncBAABBD65Q6UAMGQEKARWI2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C8DF79F035
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:17:04 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-501c70f247csf13223e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:17:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694625424; cv=pass;
        d=google.com; s=arc-20160816;
        b=YEwztmmd3s4QGBresL2jVt49TvXwrEU5whETMJai45GyRnREcZzVhWQvLHuMJ3LSAE
         7Klu0EYV5Y9Ny8cqG46m9ZHQrA5Qs+IRwQaIjS2At2M1Y/yXoROFh93Kk7KIYSr81KeI
         w3Wi4s8a908JpP7F8ohi54fv74eaafCzwZ3CD+EU43YjhVEBXEbGe1FhddiVt8zfBJun
         nnORWbe1IPcv/hXVDHqwIAdWmb1CidDTdo3qYCqp49hoyv9Gu3KghELmV9N2L3Gp4967
         XAPSrKk76/cvsNDOldVURndnqbINXdMqXk44sY+COg3zEPtvFlnvN5OXFb8ZWR1qcRRG
         PLuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SVj2il8kXwurYjKXtmtbwcUduz6TMprIfh9xOZb7qJI=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=gR7gDhkeMb2Ar6eOJd5Nrj9sU2dv5wX6P1ZZOiui9nl95h62jePaU+i5xaO2uYvJxz
         sOz7YdZ5Ozzds2i8YvexOnb755jE3feAJOwXEJs5/nVK3Hx74GB56FRBajF4EGFE5ARX
         gZujZ+rLU3PO/X1vyAMgg6fljXbmaq+puTI22UWAKRe0xtCltdlceF6jlVQONrCo4yPO
         5ziGB7OixEDbzPh4E3TEliLVUWFiugf3AJ9+ytx4/W/dm0Ks1MUot+GUUwviLtYXAR26
         9ojmmmgTm+AJ1ZS8Jth6LWQDHV02kdKqpe4MW+MIdwYfF2ucqPh66g0oWw4DTF2awMyy
         i7gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iZqHPx4f;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.227 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694625424; x=1695230224; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SVj2il8kXwurYjKXtmtbwcUduz6TMprIfh9xOZb7qJI=;
        b=U96FmcDP9fA6lS/meG5TnMCoAKCgaRbsc7hiC+uhnycZM+XFW43KDc0Mg8MHcxbBMA
         EQfE16UQsEtNnik2bm/o1/3vdmI/PDoOxMOsnuYDegyqpG+4KBKGn1Cyd5VEqactYcFL
         byRRhYXscWFx8tvEQS8wsRDiB2rXGRrL0aSACfhVqxvgGN9rrO372ZPkPB2C62EHTEdN
         LY1GnVuo8K+6rOjhgIdF1Nj0bWhfn11e5X2g+E5D/Ty8br7VOibC3RluzR3ITncXfjEz
         L7nW3FKfIF45NIoLoYzfHcHDzSkL0JbImy9cazhnqPbJCsd40WkUjsKtwFv/jJIYJxdU
         Ting==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694625424; x=1695230224;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SVj2il8kXwurYjKXtmtbwcUduz6TMprIfh9xOZb7qJI=;
        b=bItPEqq8Uizmh5zGQSVun/9GlMpcluQt7vbOxUUpQ1vljg8QZE4YnrUnZNhcW03H9c
         J/nBThkMUrfQo91y1+oJR6vNQ8WrTzHZeq1K9jFzIIEeeByfWjH+Igmevg6SWVL6ZVV1
         qKX3Rs9q9mSS3t/R0kbZL23c1lb56dWM1YfB+L9mT0Aw2y4HcQNEkjheOy/1FtG9u7nu
         fI1Exa9uRWE25XDHxsh+3iDnRztrLp8aIl3hvzxQv0s4yW2g0+JLQBMZV4Rpf/uWwoh5
         EWJ+tEl1GSLVNc6KMVxHhWogYxDnswSqwetAbhwJY0JWeOa9RMSof8u3jRX5bRkmIXGa
         j1lA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwnTJ3in4eQWUaF/ZzlNHq8y5ukBXrOgOAYCb14F5H6eF5Y1eHn
	LB46Kb49SFjxsSbVJ8NVa4I=
X-Google-Smtp-Source: AGHT+IHp9uvbcGuokT164ay008huF6A/WdDoI6+74HB81Ov8TS9QwHdtorXmpRrbqMIc5eFIh4rSjg==
X-Received: by 2002:a19:ca42:0:b0:501:a5de:afed with SMTP id h2-20020a19ca42000000b00501a5deafedmr2334377lfj.37.1694625423353;
        Wed, 13 Sep 2023 10:17:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3136:b0:4fb:7be6:88e with SMTP id
 p22-20020a056512313600b004fb7be6088els1652463lfd.0.-pod-prod-08-eu; Wed, 13
 Sep 2023 10:17:02 -0700 (PDT)
X-Received: by 2002:a05:6512:234d:b0:4e0:a426:6ddc with SMTP id p13-20020a056512234d00b004e0a4266ddcmr3477505lfu.0.1694625421845;
        Wed, 13 Sep 2023 10:17:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694625421; cv=none;
        d=google.com; s=arc-20160816;
        b=qdfsQI2uLA/jQ+j3K6Ng3JKyehMgARWUJyQNkpEOFn0Y038HjHYocM5UU/EXlQZztu
         EUbRjwvtOXUTog95sVb3cKy7NAzDY0gt7byfWJRQow7HRiYisFZz/qkJnabfWfcfC2+5
         D4AnstME3fqm/iEwsX7fKqAqypyQlT8l9kxvypwmmJtRDccWG4fj+9qbZ8fJvWRilanR
         FO8t8cRawQxAkvD7+9ND8eIXYNdq/4G5ZAEdQ7b6C/Hq9WXKRwvDxiqkXsoUuJ/TnTcc
         x5dWTvgPAeVAdDmRJuB/Hc9lPuSfvTm+9ayuSuhsEUf3fRgCxzNfn/s2lmulTiJKMIpI
         Gr4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Y6OFfwxwVZx7oqRr59fNDzzOOQmJw0k24eVuDSDilTk=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=Tp50A2r3yN+HZjj7m5Dg7zmNyniG9ZNZgJvGfVWWFGxGmRoY0Ecs8A5lEd49niNzta
         bze5pxBgnEBrkYRwJNvuXaxYzQD8LjJ02a08/7pZPrAGXwilHK5kplUXCyucpLOB5lkl
         iuZ3tlNCP9nhhMJasast/goAhoRRmJOs9RKUZnRbl2Dvw7pZp1A2Te/aa61kolAQ6KGt
         gr2XqZGAGZ2qnVdClbQj2MyZQBnbGV2YWXRgjWvgeOC1A66OVbwhA4LjV3UCz6e2KuVf
         DRNOpLrlIFg5ux2Mr0UcX6dtkj2WtbWxYy61oxE8Rh4FiN93U2e9piGbt5SjgP84tp9O
         Zdvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iZqHPx4f;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.227 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-227.mta1.migadu.com (out-227.mta1.migadu.com. [95.215.58.227])
        by gmr-mx.google.com with ESMTPS id n10-20020a05651203ea00b00500d9706548si965599lfq.12.2023.09.13.10.17.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Sep 2023 10:17:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.227 as permitted sender) client-ip=95.215.58.227;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 14/19] lib/stackdepot, kasan: add flags to __stack_depot_save and rename
Date: Wed, 13 Sep 2023 19:14:39 +0200
Message-Id: <2a161c99c47a45f8e9f7a21a732c60f0cd674a66.1694625260.git.andreyknvl@google.com>
In-Reply-To: <cover.1694625260.git.andreyknvl@google.com>
References: <cover.1694625260.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=iZqHPx4f;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.227 as
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

Change the bool can_alloc argument of __stack_depot_save to a
u32 argument that accepts a set of flags.

The following patch will add another flag to stack_depot_save_flags
besides the existing STACK_DEPOT_FLAG_CAN_ALLOC.

Also rename the function to stack_depot_save_flags, as __stack_depot_save
is a cryptic name,

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- This is a new patch.
---
 include/linux/stackdepot.h | 36 +++++++++++++++++++++++++-----------
 lib/stackdepot.c           | 16 +++++++++++-----
 mm/kasan/common.c          |  7 ++++---
 mm/kasan/generic.c         |  9 +++++----
 mm/kasan/kasan.h           |  2 +-
 mm/kasan/tags.c            |  3 ++-
 6 files changed, 48 insertions(+), 25 deletions(-)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index e58306783d8e..0b262e14144e 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -32,6 +32,17 @@ typedef u32 depot_stack_handle_t;
  */
 #define STACK_DEPOT_EXTRA_BITS 5
 
+typedef u32 depot_flags_t;
+
+/*
+ * Flags that can be passed to stack_depot_save_flags(); see the comment next
+ * to its declaration for more details.
+ */
+#define STACK_DEPOT_FLAG_CAN_ALLOC	((depot_flags_t)0x0001)
+
+#define STACK_DEPOT_FLAGS_NUM	1
+#define STACK_DEPOT_FLAGS_MASK	((depot_flags_t)((1 << STACK_DEPOT_FLAGS_NUM) - 1))
+
 /*
  * Using stack depot requires its initialization, which can be done in 3 ways:
  *
@@ -69,31 +80,34 @@ static inline int stack_depot_early_init(void)	{ return 0; }
 #endif
 
 /**
- * __stack_depot_save - Save a stack trace to stack depot
+ * stack_depot_save_flags - Save a stack trace to stack depot
  *
  * @entries:		Pointer to the stack trace
  * @nr_entries:		Number of frames in the stack
  * @alloc_flags:	Allocation GFP flags
- * @can_alloc:		Allocate stack pools (increased chance of failure if false)
+ * @depot_flags:	Stack depot flags
+ *
+ * Saves a stack trace from @entries array of size @nr_entries.
  *
- * Saves a stack trace from @entries array of size @nr_entries. If @can_alloc is
- * %true, stack depot can replenish the stack pools in case no space is left
- * (allocates using GFP flags of @alloc_flags). If @can_alloc is %false, avoids
- * any allocations and fails if no space is left to store the stack trace.
+ * If STACK_DEPOT_FLAG_CAN_ALLOC is set in @depot_flags, stack depot can
+ * replenish the stack pools in case no space is left (allocates using GFP
+ * flags of @alloc_flags). Otherwise, stack depot avoids any allocations and
+ * fails if no space is left to store the stack trace.
  *
  * If the provided stack trace comes from the interrupt context, only the part
  * up to the interrupt entry is saved.
  *
- * Context: Any context, but setting @can_alloc to %false is required if
+ * Context: Any context, but setting STACK_DEPOT_FLAG_CAN_ALLOC is required if
  *          alloc_pages() cannot be used from the current context. Currently
  *          this is the case for contexts where neither %GFP_ATOMIC nor
  *          %GFP_NOWAIT can be used (NMI, raw_spin_lock).
  *
  * Return: Handle of the stack struct stored in depot, 0 on failure
  */
-depot_stack_handle_t __stack_depot_save(unsigned long *entries,
-					unsigned int nr_entries,
-					gfp_t gfp_flags, bool can_alloc);
+depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
+					    unsigned int nr_entries,
+					    gfp_t gfp_flags,
+					    depot_flags_t depot_flags);
 
 /**
  * stack_depot_save - Save a stack trace to stack depot
@@ -103,7 +117,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
  * @alloc_flags:	Allocation GFP flags
  *
  * Context: Contexts where allocations via alloc_pages() are allowed.
- *          See __stack_depot_save() for more details.
+ *          See stack_depot_save_flags() for more details.
  *
  * Return: Handle of the stack trace stored in depot, 0 on failure
  */
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 1b08897ebd2b..e5121225f124 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -438,19 +438,24 @@ static inline struct stack_record *find_stack(struct list_head *bucket,
 	return NULL;
 }
 
-depot_stack_handle_t __stack_depot_save(unsigned long *entries,
-					unsigned int nr_entries,
-					gfp_t alloc_flags, bool can_alloc)
+depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
+					    unsigned int nr_entries,
+					    gfp_t alloc_flags,
+					    depot_flags_t depot_flags)
 {
 	struct list_head *bucket;
 	struct stack_record *found = NULL;
 	depot_stack_handle_t handle = 0;
 	struct page *page = NULL;
 	void *prealloc = NULL;
+	bool can_alloc = depot_flags & STACK_DEPOT_FLAG_CAN_ALLOC;
 	bool need_alloc = false;
 	unsigned long flags;
 	u32 hash;
 
+	if (depot_flags & ~STACK_DEPOT_FLAGS_MASK)
+		return 0;
+
 	/*
 	 * If this stack trace is from an interrupt, including anything before
 	 * interrupt entry usually leads to unbounded stack depot growth.
@@ -529,13 +534,14 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		handle = found->handle.handle;
 	return handle;
 }
-EXPORT_SYMBOL_GPL(__stack_depot_save);
+EXPORT_SYMBOL_GPL(stack_depot_save_flags);
 
 depot_stack_handle_t stack_depot_save(unsigned long *entries,
 				      unsigned int nr_entries,
 				      gfp_t alloc_flags)
 {
-	return __stack_depot_save(entries, nr_entries, alloc_flags, true);
+	return stack_depot_save_flags(entries, nr_entries, alloc_flags,
+				      STACK_DEPOT_FLAG_CAN_ALLOC);
 }
 EXPORT_SYMBOL_GPL(stack_depot_save);
 
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 256930da578a..825a0240ec02 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -22,6 +22,7 @@
 #include <linux/sched.h>
 #include <linux/sched/task_stack.h>
 #include <linux/slab.h>
+#include <linux/stackdepot.h>
 #include <linux/stacktrace.h>
 #include <linux/string.h>
 #include <linux/types.h>
@@ -37,19 +38,19 @@ struct slab *kasan_addr_to_slab(const void *addr)
 	return NULL;
 }
 
-depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
+depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_flags)
 {
 	unsigned long entries[KASAN_STACK_DEPTH];
 	unsigned int nr_entries;
 
 	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
-	return __stack_depot_save(entries, nr_entries, flags, can_alloc);
+	return stack_depot_save_flags(entries, nr_entries, flags, depot_flags);
 }
 
 void kasan_set_track(struct kasan_track *track, gfp_t flags)
 {
 	track->pid = current->pid;
-	track->stack = kasan_save_stack(flags, true);
+	track->stack = kasan_save_stack(flags, STACK_DEPOT_FLAG_CAN_ALLOC);
 }
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 4d837ab83f08..5d168c9afb32 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -25,6 +25,7 @@
 #include <linux/sched.h>
 #include <linux/sched/task_stack.h>
 #include <linux/slab.h>
+#include <linux/stackdepot.h>
 #include <linux/stacktrace.h>
 #include <linux/string.h>
 #include <linux/types.h>
@@ -472,7 +473,7 @@ size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
 			sizeof(struct kasan_free_meta) : 0);
 }
 
-static void __kasan_record_aux_stack(void *addr, bool can_alloc)
+static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
 {
 	struct slab *slab = kasan_addr_to_slab(addr);
 	struct kmem_cache *cache;
@@ -489,17 +490,17 @@ static void __kasan_record_aux_stack(void *addr, bool can_alloc)
 		return;
 
 	alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
-	alloc_meta->aux_stack[0] = kasan_save_stack(0, can_alloc);
+	alloc_meta->aux_stack[0] = kasan_save_stack(0, depot_flags);
 }
 
 void kasan_record_aux_stack(void *addr)
 {
-	return __kasan_record_aux_stack(addr, true);
+	return __kasan_record_aux_stack(addr, STACK_DEPOT_FLAG_CAN_ALLOC);
 }
 
 void kasan_record_aux_stack_noalloc(void *addr)
 {
-	return __kasan_record_aux_stack(addr, false);
+	return __kasan_record_aux_stack(addr, 0);
 }
 
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index f70e3d7a602e..de3206e11888 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -370,7 +370,7 @@ static inline void kasan_init_cache_meta(struct kmem_cache *cache, unsigned int
 static inline void kasan_init_object_meta(struct kmem_cache *cache, const void *object) { }
 #endif
 
-depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
+depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_flags);
 void kasan_set_track(struct kasan_track *track, gfp_t flags);
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
 void kasan_save_free_info(struct kmem_cache *cache, void *object);
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 7dcfe341d48e..4fd32121b0fd 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -13,6 +13,7 @@
 #include <linux/memblock.h>
 #include <linux/memory.h>
 #include <linux/mm.h>
+#include <linux/stackdepot.h>
 #include <linux/static_key.h>
 #include <linux/string.h>
 #include <linux/types.h>
@@ -101,7 +102,7 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
 	struct kasan_stack_ring_entry *entry;
 	void *old_ptr;
 
-	stack = kasan_save_stack(gfp_flags, true);
+	stack = kasan_save_stack(gfp_flags, STACK_DEPOT_FLAG_CAN_ALLOC);
 
 	/*
 	 * Prevent save_stack_info() from modifying stack ring
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2a161c99c47a45f8e9f7a21a732c60f0cd674a66.1694625260.git.andreyknvl%40google.com.
