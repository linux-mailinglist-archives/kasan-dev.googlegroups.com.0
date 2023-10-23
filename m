Return-Path: <kasan-dev+bncBAABBZ543KUQMGQE4VELZAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id E8E807D3C5A
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:25:11 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-4084163ecd9sf21133185e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:25:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698078311; cv=pass;
        d=google.com; s=arc-20160816;
        b=tIHJBWRhh3u8ioo6vXXOHKP0kaZNA+M4FiZusrRRNJBOr9KyOZdLPPELQJHpigY2Hy
         hDKMrcxVepedYDukFgd4aDm+guBd38+wUMDXVJ7x8T4GHOlF5oI7mIwDcV3WkS1uDeeE
         tf8KwxcqMuE2C3s7DqeVOWo5uXN9SJ7jZbcasHpcO8tjxyspGOMlsXXIu25HfXN8KOB9
         98xod0nUtiR1HdxF44YrjswQWLILKUg+ezSLpdtdPqAILnoEd/UeekQ206lXFBc4OCzm
         qBYrAWSSRPGqo/S8f1C4E2jqA8ikRoEmYbZ70WVL/rVYIAVzVPM53g2ZF7QheJoF9exC
         Szbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=7lo9R0kfVHmWoAcxnsCBeTh4raB5T2eGRhv2tkrWIPc=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=PHy28heLRVuqxqQ54ExRos2Qqa8NCMXa0kmdPeo2lu12JStKI77KY6gOOM1d5jm6tI
         By8EnqRoNz6xnkbh8h8dqmDQSWCqUMGLJpCVG/fbmsZROk1IHz2jOdT614qh88UQQn5g
         xl1DGwpbT1dlWuTjtd6VEsf7AjzNfVzjKsbHbfxxviRwevly3Xv8pdhs2Uq0PjlXM5Fn
         31BGdNQ0GDeXi7fwROPGhfd38ZwEKNty6m5L1k2Vs3MyodOWIzEnvbyxz3SWwSV1nSy4
         abeFFUKE4qz7/CZQktwOqJ0pwSDGze/m6n9RyyYy77Uhs2s1gSL1/QGP66a9ZQoTkE1S
         vWgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=cQKAccVp;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698078311; x=1698683111; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7lo9R0kfVHmWoAcxnsCBeTh4raB5T2eGRhv2tkrWIPc=;
        b=ussuDQ+SHLstMzDFi5/VuCpw0tEcOJwhB8pXSHZcfqkn9RYE3sBE5qoq/0ev3WzfWo
         J2NLh5El6Lk847dmTt+2R2d3PtKI62r0gE1Zws8bRx0RDAmovxZgA/MlUlymAVx+I1gg
         GGpWIvVcD+xyxCzaxLqjuO0NxY+91u7KhynAN26OkIFszIICImxrqobFFZWm7W5PuHI7
         ctng50LxyApJqyPJB+5l3UcxV/+EAvtCuriB9IMBTaaBGWq1/0fFEzJ75eS48xcjO42t
         1PT4uWLkoVx3MSp/3+noiNx2FRe+hvt3aXtcOQifHLrdx3WBhRI6QkrHV6JTC9pkqMs0
         15SQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698078311; x=1698683111;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7lo9R0kfVHmWoAcxnsCBeTh4raB5T2eGRhv2tkrWIPc=;
        b=nGAxcnclhibbFtnwUQYC6UATGWeBTROe0goCqoVbJiVT7YECRVNvNy3jsEc9gyl+Br
         tzkxbVZkzkjddLdXmK9ch5kz4jB9EGPB5I9ZXKqtiBud90BAc+5Nn3AE0zNNESyigaOE
         hfRhMnwnxxcSA9IaTnULBYzD+3C/99pa9aewQuTr+q2Vkl4N6VGWK5XIgd6QmUuen/sZ
         73WJb8T8Bk6v3LqFw5G8vKCXaXnP4mZv4g4ZaeUnv4SLRT0OnsiUeckoLzZptSvTfG7Z
         mbdQjhnJL/YZ1F5SSFLBv7cQQ5jPgjSSskHpiXrn+6rJ26A91zC7UBs3re995ZRQIRng
         e+iQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzocTXB8ijSgIHNAQVwIrSHssv1Zfzxa4mkqJhxMX5L0SeQo0To
	DCpcdOXo3cUqTNW2KX9KcHs=
X-Google-Smtp-Source: AGHT+IFZYmEvFFvumaajptT8ToIMycP0h+CjvNJm7BCzU5kOFofHzkfexcgO/XBCXJc3mcM5qq267w==
X-Received: by 2002:a05:600c:1d22:b0:408:4475:8cc1 with SMTP id l34-20020a05600c1d2200b0040844758cc1mr8094666wms.35.1698078311184;
        Mon, 23 Oct 2023 09:25:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d09:b0:406:6882:6832 with SMTP id
 l9-20020a05600c1d0900b0040668826832ls281408wms.2.-pod-prod-09-eu; Mon, 23 Oct
 2023 09:25:10 -0700 (PDT)
X-Received: by 2002:a05:600c:3b9a:b0:3f5:fff8:d4f3 with SMTP id n26-20020a05600c3b9a00b003f5fff8d4f3mr7688232wms.7.1698078309792;
        Mon, 23 Oct 2023 09:25:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698078309; cv=none;
        d=google.com; s=arc-20160816;
        b=DsEJaP619oCRQheOVB64JppPy0gKA7X+WdOjwSEMyqcBp6dCYXTDJUbpxeVKLetgHG
         r0TE8Qufh7fTvrH9g9Pq+e2f4rWWqxrWjeli3qCKcqo+oDG1rW7C1OceZw4uauUB4H1o
         Nc/qPEp4Dap6zYovp88TjiayqIm7rEqIGAK+Z2958tJW2Q4AmkpoBK4v03L9SREHEu61
         MaRDNCGg+Ezrd9J+k9K3OKs1ukE+8QwWbo+LK/7mGyf6H4gbjCQdMZ0lyVyvAMSFJkYI
         6O0+S40m2XXI0cp6+d4+yH3s/mvAdG/gBzOLkeEWwYwm0dbiPCYAOp0Rof3iM+QRyopA
         vPBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MAMDAy8Q02glfcWzfXnjTMXtIPTZ6ms/1w5eICwlRhw=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=ynt97vkzvU1Gl6UXLpgO9kbkzur2hrHOnqu/V+lGZriJP+heZrVlkm/JVwxhFHaoQN
         yBz/iSSdst1lFrucyn+rfhhtnPVX3J4d9GyogYW8VVnUhV8dSswnnfirN0MnD4mZlPlg
         fXcvtBEpncxsIFDBEPQgF4ajFjIwfPL69Rd/h96RPhK8+YBAs0rq1411/CHnLeP+JFxw
         iorusDewiUSowEpKm/6NhtEIzkU5PGDPLOEZ5O66ALaMR9wTcckA5d2bgqyBOrwxmpXH
         eX+7+iBU90eLFZP2pjCPv/eNHAQ7wcClGlnhOx4dVIHFunIgwIpQzQA3CqAtJZs6kXIg
         iKGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=cQKAccVp;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-204.mta0.migadu.com (out-204.mta0.migadu.com. [91.218.175.204])
        by gmr-mx.google.com with ESMTPS id h14-20020a05600c314e00b00407c8777ecasi485962wmo.0.2023.10.23.09.25.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Oct 2023 09:25:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.204 as permitted sender) client-ip=91.218.175.204;
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
Subject: [PATCH v3 14/19] lib/stackdepot, kasan: add flags to __stack_depot_save and rename
Date: Mon, 23 Oct 2023 18:22:45 +0200
Message-Id: <391437de83944753819a6c0b1d95bd7aa55ea106.1698077459.git.andreyknvl@google.com>
In-Reply-To: <cover.1698077459.git.andreyknvl@google.com>
References: <cover.1698077459.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=cQKAccVp;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.204
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
index 85fd40c63817..902d69d3ee30 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -444,19 +444,24 @@ static inline struct stack_record *find_stack(struct list_head *bucket,
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
@@ -535,13 +540,14 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
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
index d37831b8511c..3787266d9794 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/391437de83944753819a6c0b1d95bd7aa55ea106.1698077459.git.andreyknvl%40google.com.
