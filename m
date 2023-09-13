Return-Path: <kasan-dev+bncBAABBDW5Q6UAMGQEXCYBADQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 65C7079F034
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:17:04 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-402c46c4a04sf207455e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:17:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694625424; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yuh4duE6pAK4SR/GzuIAAyr1wCscMzi5BoKWLDqFSB8n7H7B8OktyF+zakckWC6LFz
         SpOGlzD5CZWDvKsovEa3HVkac0VvuL+u5HEtb520f+LxtHrcEMd8EytypC1eUg9iM29f
         fJHKWRJVpW10n17ahN2nwrJWfCvTbrtxvp55q3Wt1cZEyaIoP2Sw0meRcDKf8ehl3p0O
         EjRTCX9oxJKZ2Z3ewA3KzE77sZFviC25RquOcjYdRRK9Zs6WZqhRev/gb5vKPTBNB5r3
         HuLmOcMcUS6xwgACYLZOZ/DQ3gFSFFB3H9VOp0Y34b8AOThNXa76MHRdSrHnVFSpQArb
         lRMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=oMiPYeNnGaJ9sTePqafYeulNL92J0ySv5AiBvJdU23c=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=IH/Kpo8F1JU2ECbW+2jJdoq67C1tLoNx1hYbFLJ835RpI8bMuqG/iXCYH6GAqGiqWE
         +hqyBM9vUyxHWfyf7IDkq6VJx5AIzTxzLqK4ms81lzC2+z1bNtjPKh7VR4F0d+/U9bPx
         pmK6YpByjshYv9bsc00R1li0ggoah4bnewlOSi9TdnA7spskvuZs3/hNBXTloDBDaXj/
         282TYjuchZFkITS6DwCE0e3sqO0y/9YfzH63JsLZ1F1D2zV57eCgdKUjiTDWtRsfrFD0
         ea5muz/tnmBZXmCvoE+3kmbuwJJ5o4yDv5ngEJKlHA+dLsuQN3kCbJlFW5bDAfc2eaZq
         J2sA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=rPLyIHlB;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::d5 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694625424; x=1695230224; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oMiPYeNnGaJ9sTePqafYeulNL92J0ySv5AiBvJdU23c=;
        b=Pi63ldjzU6ON/jeaYnqP3CI/kM8sHwvzEgo2kyyw75VZ9kRJRDdlo83f8Sc5bjVIum
         AgONUEY6vMeba74aRJydH87UxMlWYsrl+jeH4kyzJsJ5N96qmaDM7ano+lLTrqekzvnv
         OaDXJ90k9aBVgBSD50ukpUrpuBjKoShGI0I0vn6acObZl+ZCM/vsskib6WqkMiX0ScRY
         5PVXpGHV/g9E6EesH2GiK9sTOo369lr8NrPHIut7nJhD+MQ1K26XSGGu0Yrbg3bBKA+H
         gduWJindFyy+xSQpnhjs3Pa6qvAjbhSg4pcUkpgViDSa0PEuLJbV1HmfjYMhY23hwmlm
         tIMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694625424; x=1695230224;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oMiPYeNnGaJ9sTePqafYeulNL92J0ySv5AiBvJdU23c=;
        b=v1LUcwwcoaItXQ5HUXN59psBL25cjVQEU1EfUXRdTBWOKw7rfXIBk/aPuMpgXh3hbX
         ABC/FPkq5d5JO7eNNRtvEm2qIddAHz643Tw2rsSK63jvO6FzMlqDD4M91i0Zmt9/P28L
         eQxaBbS4jXewzNp6jyLfCS+Th19irv2iBOr8J6mu/iapKrbO2Z4HzGUoesRPefFNk0Sf
         s8UrROdCthBbYNSADxs1+IwQeKD8YEDuExRh/A4uUO/F/kBXqResJosuQgHyOnsLkyDN
         /43YgBqsXWPpYzMsvU4jAbTa+/LNSYAiJ8cSWsqKNaPqpaQALkfNL4hzi06TnvIlxokr
         mSIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyxnlauI19kcE2tQQaikQgyAaJTCNfub4LMDiy8LaiGPj+T5DJM
	l01GJn1nhfe8U6alZrdNkaDIsg==
X-Google-Smtp-Source: AGHT+IFZN6KHPURtAUgrav7QBLNIAJXo8oNCn4aLu5Tv1Hd80s+SgT0byZ+L+9fo9gkwciRrCV6ThQ==
X-Received: by 2002:a1c:7c02:0:b0:401:b0f2:88cf with SMTP id x2-20020a1c7c02000000b00401b0f288cfmr2687698wmc.40.1694625423182;
        Wed, 13 Sep 2023 10:17:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:807:b0:31f:908e:6979 with SMTP id
 bt7-20020a056000080700b0031f908e6979ls1579227wrb.1.-pod-prod-06-eu; Wed, 13
 Sep 2023 10:17:02 -0700 (PDT)
X-Received: by 2002:adf:d0c3:0:b0:31a:d2f9:7372 with SMTP id z3-20020adfd0c3000000b0031ad2f97372mr2691047wrh.29.1694625421950;
        Wed, 13 Sep 2023 10:17:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694625421; cv=none;
        d=google.com; s=arc-20160816;
        b=k2kF6jXtNfgZL010R6yvo83d0sYxqlRTW9o7wj+ogkOJ0ohVOOgOIHuwZoQitq3CMS
         7kQQhPREHVOZu6ojZV29GuAAgB5ibkvFxfJy2m0HXGAw0IoEpMjO5II8eysOBud4CZHb
         cgiGqE+V0gp00XY0OCaUMYaQkm6mbtw/F4xQRndGN1Q6wB7pIKRW9R80zifMwyWdqHt5
         bnBji1LZWqGByj52j100pJZS3C1zkfpswZcYSIHEO8rOIDIYry6OYlS5Fd5ZgBqQ9Yzf
         kjMlxFY9oFkbYVd3821oN+718uapFuAre0BHIo3WdTcg4vYfgDr01pYXgeUUXsCmU49U
         ZM2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iWiSl9lpWFlYTb7e84Z8P7HowCNwXEfuw/46H+rnea4=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=hBfbaQZF16FFJFcfl8EzKhVgb/ISgJqSYdubBzt68xXo7HZEvFoXDOH6WyBcLAk91w
         gABESEVyV5mra7744pjxLjbwXajt2YdAXIlc7q7OjVppnlHEM7pWhiOYhmYSM4cUL62R
         2A11j2a0R9XXo0weToS+CG+gm671d0K8jKkAMoyH4pQdNBmvznx81iVtrwIF7SqzMe+l
         IZG3eaZZ5cwlF4XLBPpHkRhG2Na80nkJj2DTdHWp4hsel0leAHVEBbpqCLJeEphDqbgz
         sjd8KTgXS/3kSKTX7pa63Nj27fTq3P9kRHpFtzYVypPXmT+L6FIt/D6RtGHlEBZ9e6gr
         M1vQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=rPLyIHlB;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::d5 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-213.mta1.migadu.com (out-213.mta1.migadu.com. [2001:41d0:203:375::d5])
        by gmr-mx.google.com with ESMTPS id t32-20020a056402242000b0052e7b1828cfsi961325eda.5.2023.09.13.10.17.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Sep 2023 10:17:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::d5 as permitted sender) client-ip=2001:41d0:203:375::d5;
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
Subject: [PATCH v2 15/19] lib/stackdepot: add refcount for records
Date: Wed, 13 Sep 2023 19:14:40 +0200
Message-Id: <c15b94412d146957c8be423c8dc1d3b66f659709.1694625260.git.andreyknvl@google.com>
In-Reply-To: <cover.1694625260.git.andreyknvl@google.com>
References: <cover.1694625260.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=rPLyIHlB;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::d5 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Add a reference counter for how many times a stack records has been added
to stack depot.

Add a new STACK_DEPOT_FLAG_GET flag to stack_depot_save_flags that
instructs the stack depot to increment the refcount.

Do not yet decrement the refcount; this is implemented in one of the
following patches.

Do not yet enable any users to use the flag to avoid overflowing the
refcount.

This is preparatory patch for implementing the eviction of stack records
from the stack depot.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Add forgotten refcount_inc() under write lock.
- Add STACK_DEPOT_FLAG_GET flag for stack_depot_save_flags.
---
 include/linux/stackdepot.h | 13 ++++++++++---
 lib/stackdepot.c           | 12 ++++++++++--
 2 files changed, 20 insertions(+), 5 deletions(-)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index 0b262e14144e..611716702d73 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -39,8 +39,9 @@ typedef u32 depot_flags_t;
  * to its declaration for more details.
  */
 #define STACK_DEPOT_FLAG_CAN_ALLOC	((depot_flags_t)0x0001)
+#define STACK_DEPOT_FLAG_GET		((depot_flags_t)0x0002)
 
-#define STACK_DEPOT_FLAGS_NUM	1
+#define STACK_DEPOT_FLAGS_NUM	2
 #define STACK_DEPOT_FLAGS_MASK	((depot_flags_t)((1 << STACK_DEPOT_FLAGS_NUM) - 1))
 
 /*
@@ -94,6 +95,9 @@ static inline int stack_depot_early_init(void)	{ return 0; }
  * flags of @alloc_flags). Otherwise, stack depot avoids any allocations and
  * fails if no space is left to store the stack trace.
  *
+ * If STACK_DEPOT_FLAG_GET is set in @depot_flags, stack depot will increment
+ * the refcount on the saved stack trace if it already exists in stack depot.
+ *
  * If the provided stack trace comes from the interrupt context, only the part
  * up to the interrupt entry is saved.
  *
@@ -116,8 +120,11 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
  * @nr_entries:		Number of frames in the stack
  * @alloc_flags:	Allocation GFP flags
  *
- * Context: Contexts where allocations via alloc_pages() are allowed.
- *          See stack_depot_save_flags() for more details.
+ * Does not increment the refcount on the saved stack trace; see
+ * stack_depot_save_flags() for more details.
+ *
+ * Context: Contexts where allocations via alloc_pages() are allowed;
+ *          see stack_depot_save_flags() for more details.
  *
  * Return: Handle of the stack trace stored in depot, 0 on failure
  */
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index e5121225f124..e2c622054265 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -23,6 +23,7 @@
 #include <linux/mutex.h>
 #include <linux/percpu.h>
 #include <linux/printk.h>
+#include <linux/refcount.h>
 #include <linux/slab.h>
 #include <linux/spinlock.h>
 #include <linux/stacktrace.h>
@@ -60,6 +61,7 @@ struct stack_record {
 	u32 hash;			/* Hash in hash table */
 	u32 size;			/* Number of stored frames */
 	union handle_parts handle;
+	refcount_t count;
 	unsigned long entries[CONFIG_STACKDEPOT_MAX_FRAMES];	/* Frames */
 };
 
@@ -361,6 +363,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	stack->hash = hash;
 	stack->size = size;
 	/* stack->handle is already filled in by depot_init_pool. */
+	refcount_set(&stack->count, 1);
 	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
 
 	/*
@@ -477,6 +480,8 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 	/* Fast path: look the stack trace up without full locking. */
 	found = find_stack(bucket, entries, nr_entries, hash);
 	if (found) {
+		if (depot_flags & STACK_DEPOT_FLAG_GET)
+			refcount_inc(&found->count);
 		read_unlock_irqrestore(&pool_rwlock, flags);
 		goto exit;
 	}
@@ -516,12 +521,15 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 			list_add(&new->list, bucket);
 			found = new;
 		}
-	} else if (prealloc) {
+	} else {
+		if (depot_flags & STACK_DEPOT_FLAG_GET)
+			refcount_inc(&found->count);
 		/*
 		 * Stack depot already contains this stack trace, but let's
 		 * keep the preallocated memory for future.
 		 */
-		depot_keep_new_pool(&prealloc);
+		if (prealloc)
+			depot_keep_new_pool(&prealloc);
 	}
 
 	write_unlock_irqrestore(&pool_rwlock, flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c15b94412d146957c8be423c8dc1d3b66f659709.1694625260.git.andreyknvl%40google.com.
