Return-Path: <kasan-dev+bncBAABBNNY52VAMGQE6YXTZEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 80C327F1B7C
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:49:42 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-53e3bfec5bdsf3434449a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:49:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502582; cv=pass;
        d=google.com; s=arc-20160816;
        b=qWaVO/A4ZGijU9VlSmzYw402ps15FShJbALgE+cdPlBJ/rTMRF2XRBAG6b5QauNCWb
         b1bAjNXoSc4gIkkuBUzzlb4GncZI70Dor7eNOgjt1sxwYWRI8KDZSGEGXSdF42wtAkzg
         5KnnGwfBaPxSVFLPJPEwmtOartiJ2apdzS5eZEpt4MfA+xr7fKm0I4guP1SFGBK7nHFh
         vq+a0BU9lCaN7RM+Z78jM+EV6UD6ZGoXEUBOWTMbQKogbYd6saS7sU9Ca9fBaSFDqrZB
         j52QVy1FiR5781iS+go61DNzPXhDJR7bQG3IlXu4+7dQCRGMV/HAfU8HSlnVuv+PjKYc
         Uttw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=aKxjLHYl26q1ydX496xf4l1ixyt8LhRjVRxzZjaOHTo=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=aSeGrOBwpQuiYHfYEgsYEa/irs4k8cjPn9tJfbCGW5jOr7o6JxTpF00qwVvG5CvyoV
         /iB2ju3kR6r5uG49xuGb/ZfD+k9qIhxsAhU74aq4y6UkhjnVdNYmb0lKvrR+pAQ7JZHh
         sdZEHmYQAa0H0t7dJewFDWYDdAVC6ZnxaEmnHujByPczzkRRKwkTGUPixyyWFXso1DCU
         49XgDBiHheE+XZcTOc/q8NbqT02uLZGQ/Fp+hrkBPjV+tucBNod+D4u7G3Ok/Pbknm1u
         TXsGywf60TgZyK6ppFQXl55LhgTUu8Pus+5y5/cyat9uhBVnMfp5vszKapAuaFkO3dPC
         dhXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HqbyNSHD;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.186 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502582; x=1701107382; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aKxjLHYl26q1ydX496xf4l1ixyt8LhRjVRxzZjaOHTo=;
        b=SGPubS9JAIchVcLt74aUqRbV1L5ROX6Ci/ZgfXfvEPUupjBdGjzQkqIgY2kDVJX+U7
         3p80WJwGzBkEp5FA74DCT2Or6VI22oivo1KHL2X2+cSa2WH1Ua2WEYQX7GvpS6+PKC6A
         bAigoh1Om6kvkID9gVrp1prJ7UXf8F7SbMzi0g2QlYnAj176538kIPspQjUD6ZEIL247
         90aaNNIcfQLOOtnth9Fnw5K9e+ocgSXXiH2PezzEdAHukjm4x8sSuGt3EYiBSaJYrxoi
         JCc3hXG2P24rJphRgakijKlX77fi108SShCRzNTbt/leWfrwVkndGu1W+LHqzQZemBcL
         Xdpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502582; x=1701107382;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aKxjLHYl26q1ydX496xf4l1ixyt8LhRjVRxzZjaOHTo=;
        b=pwYtGCaQqplQFMlmJm/plJ3Iuuv5ZxHMdurMQreC8MtBxgSaJyLSdTTi5Ye52ODplm
         qH/3Ke+eqLEG2ogFfV1/ndkORVwuT0+Uy52p2nahcGjRujmy7JaVuQsT4OmfRazXwZ8R
         CG+rhIaJCHyRCTDntNLrfyJNLcnY3dJnZBi6IjvUow7vzCWrt0JqF1ROCdst/EFnoSZL
         yZwmFJM6LoUcQzfwqOgJqNdb/dnDrQGuDtk51fzn8Xt3qdW+NPMic+Qg+kAyievM07Wl
         lxtuabruZHzZtFCnOq6HUui+yVyp6CfpWLQUg2vgKQNqonIkqSlJIIl/OSxdncz7otKG
         pywQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxmw0azfR8c0dpddFaC4791aSjIvoGHawpOtRYh0JND9dOOG0TV
	VJLM0vFNmN2bcxsk3hJb/GA=
X-Google-Smtp-Source: AGHT+IGv8siEUpk+JNWJa6Ho6cPz/1nCCjkrp5W+iXAjLBLX333KCcorB/TnY8yZhced0iU5MgFGNg==
X-Received: by 2002:aa7:d5cf:0:b0:545:4bf3:ac89 with SMTP id d15-20020aa7d5cf000000b005454bf3ac89mr103472eds.23.1700502581622;
        Mon, 20 Nov 2023 09:49:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:c4b:b0:53f:9025:541f with SMTP id
 cs11-20020a0564020c4b00b0053f9025541fls200847edb.1.-pod-prod-04-eu; Mon, 20
 Nov 2023 09:49:40 -0800 (PST)
X-Received: by 2002:a50:9518:0:b0:540:4b90:3dc3 with SMTP id u24-20020a509518000000b005404b903dc3mr86751eda.14.1700502579944;
        Mon, 20 Nov 2023 09:49:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502579; cv=none;
        d=google.com; s=arc-20160816;
        b=hIAmKoWa4rMjxJ+hGnAAJ+vLibj6wAKYOq/EYrgOLDJthfAMmIeg7MwQRyc8mIQADK
         y1KhqoRUPkUhNzemHjzwZA9kClF4cw6iUBY0Yu8b8FraWXrT+CKfIFuKlpZsHb//V7mg
         N6dpyPtQAalgBRLRZb63Fb/Y7xQyrhRckR+fpXxRigdCXAfQKxjbFBlju0Kr0WQ4pic2
         mxLC5lwi4b62KxwrMacOjhwUkbOMUkzyd4BrOaYWbY2xEIc3mBi+g9byJOFC2foCom+G
         /BegxdeB92AVM9/Jl6fzVwPvN45JBscPRDtMLsMC3l7dAgmyntTbm3Afh5zs0H1NCTHf
         8hfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=aXTF/ovgO7tSDGaC/rtVyVWMqky+xGAg2LPsWIiIw38=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=JW4RI5LzLOTo4vIxt2OJ5XPCZqTshx0uoq/OkNJVDt3rgnwDs4GdzZX20aSUbme7l2
         yzFKbs7Z0tIgMaTwQDXvpUr/YFg1+X/kX4Hks6AtU0QDRsJiLAAIYYrvRYTV+GAv5uS0
         Tp6+sdzjxyXAgVPCn28SD2ZEqwXgyBDiLkFNND4HOn3ILg5Se0vsioheawqvkUAelJ3P
         slhYsmuNC3OF7eAsT0l+3ArgTBI7882pmSNhB5PiJKfCsgr2ogxU5KzJXAFTJUt00PVJ
         /D1JyFMTJPIg9GpNTr8MCP7f04QqI3kUy7cjVsh+imzTNFRx8dyCsHxxxyDj7oC30GC4
         Xrig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HqbyNSHD;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.186 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-186.mta0.migadu.com (out-186.mta0.migadu.com. [91.218.175.186])
        by gmr-mx.google.com with ESMTPS id fi27-20020a056402551b00b0053e26876354si352514edb.5.2023.11.20.09.49.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:49:39 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.186 as permitted sender) client-ip=91.218.175.186;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v4 15/22] lib/stackdepot, kasan: add flags to __stack_depot_save and rename
Date: Mon, 20 Nov 2023 18:47:13 +0100
Message-Id: <645fa15239621eebbd3a10331e5864b718839512.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=HqbyNSHD;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.186
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

Change the bool can_alloc argument of __stack_depot_save to a
u32 argument that accepts a set of flags.

The following patch will add another flag to stack_depot_save_flags
besides the existing STACK_DEPOT_FLAG_CAN_ALLOC.

Also rename the function to stack_depot_save_flags, as __stack_depot_save
is a cryptic name,

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- WARN_ON invalid flags in stack_depot_save_flags.

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
index 4bb0af423f82..59d61d5c09a7 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -450,19 +450,24 @@ static inline struct stack_record *find_stack(struct list_head *bucket,
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
 
+	if (WARN_ON(depot_flags & ~STACK_DEPOT_FLAGS_MASK))
+		return 0;
+
 	/*
 	 * If this stack trace is from an interrupt, including anything before
 	 * interrupt entry usually leads to unbounded stack depot growth.
@@ -541,13 +546,14 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
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
index 8b06bab5c406..b29d46b83d1f 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -368,7 +368,7 @@ static inline void kasan_init_cache_meta(struct kmem_cache *cache, unsigned int
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/645fa15239621eebbd3a10331e5864b718839512.1700502145.git.andreyknvl%40google.com.
