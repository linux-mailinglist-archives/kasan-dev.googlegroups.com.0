Return-Path: <kasan-dev+bncBAABBZ543KUQMGQE4VELZAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id A68297D3C5C
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:25:12 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-54029fbd343sf1149170a12.2
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:25:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698078312; cv=pass;
        d=google.com; s=arc-20160816;
        b=C8rc+l4GOJGSEGRtdr+3Cx5XN/57M/Nrq9HkXzWJtdalSC7SNYZPdSdVhnxe5RPJut
         iy93maz1WgEFdJNVvh7ilVReX+8JcTebrNXq177pl4rfb0UXtTP9Ri9IRooDV6scXimu
         X+ehcRVJzVqolOfCdzjsW3Z4muga0TtiPda0dykQCW7RhYjGsauvMM/xk2b+xZJveAH9
         VEcjK98StR491SB9uRN+xe55STRaEFlLnTvXWpVo+H6CR0zHrYjw0rAlPxYzMe266fnr
         moH9cQpesFakEmrvmGSmqkvqwP74ZugaNb2V0rnLi69HpJQmiWrEZqhlv8EIJ5FfP8Pe
         I4KA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wyC79namYP/1RcrfVrkYam/faNlW1UhPHSnA1I7omWE=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=KCsW/pMdS/EsQXhHBwXMgiNXhlifsmyLJJnsVJEGkTUADJDyj4E41tXLgthf1y51zV
         a2eW+dvvGs454e0m8tiXJTLqjLifYDKNjtNbN+yFeXLqDCKKDM3/VHU69palzTScfkc3
         NVNs6nkLmo/IrtMUmdSSjU1F2B/peitVD13BDaM4lwN3noGpjV8S+xA8xNS/QmLAWzl5
         hnSn57UOhNkneDFV4dMmsdUIHEDVt2Peia+omsYszOM+XO38ecA3sT4op5RvCQ6yQAz5
         OmEJVqVs33Izs1Op313DNhVkAU17QDoqnLOkaCVuCQqFeeZ+3+Dc6dgeRZLtfihi3Gf0
         5B5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="Kx/VCgxq";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.200 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698078312; x=1698683112; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wyC79namYP/1RcrfVrkYam/faNlW1UhPHSnA1I7omWE=;
        b=nUgzWywUCYYErQNLb3DyO4wyMEWb59c+ZRr965HFHUt2VedSBWbFyjBp5fKduO1ltt
         O2WOBzov59/27kJTCZBTIJjoKiInwAD4H0pfL0gHz2JVhrswj2LTw5szAcWSmIduyRNV
         NYjM+tv+3dl1iDYSegoRUOc1uxDJdEHNxfLdv1Kq6cxLILVZhJKWpC40251bLDjxGHO4
         9fdbSH1HhLnk0JJs23bFjuyc0edkLaYfegFBr/eF4wskBQgyQeZmpZxjIsr0IN07Iv+1
         wZNLr+o2DQCsehPfrkcsIbPcxP1WXO6PlAk7QavNglnvbaMLPsQ02HDL/ujU/+oGJw7p
         gUkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698078312; x=1698683112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wyC79namYP/1RcrfVrkYam/faNlW1UhPHSnA1I7omWE=;
        b=JXZiJYSevbsNBaj1KGhyROrVGMICM+bBvUQE4p6QhqDoRtMbCGNs/ctysKQJuEP6ne
         2SFCyy6jWtsKFUDeHkx12tIDGCdtysPNW7tM7BJD8M3Oj/bwC35Q0Y8XBtY8Tdzc5DGY
         5MQpDsUi4rl9miPxyKncqCEFZ1tJ7J2+i9daDbQtu6sjDhA+giDpJbPsTeFTOVkqjtFI
         YRgCLipE3eSqPCa/ycz0V525upsYi+J3e9F6g6c8O85pyRyC3qzvFyU1OuhTml4+FLlV
         S8n+TDsDxBAKxAPfKCA93/oo/eobTs14vSu6d/YizE6lp9pRuTPsYOWsGrqLNreutz0L
         hXew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwBEYDQIv1yb6YZc+oH9CycEayfkY/bBZmWmUCjWlJeMe23EKqE
	ywoPxu/o83cjr5+Tk05BbEQ=
X-Google-Smtp-Source: AGHT+IHbvOm0FkLc0OI1CwWtGRIMuMRorMcqddmOdoVa2eLl50yo3BRnmxjptRZw7CnpfXg/tc2+tw==
X-Received: by 2002:a05:6402:2713:b0:53f:b9d0:9818 with SMTP id y19-20020a056402271300b0053fb9d09818mr5627008edd.42.1698078312125;
        Mon, 23 Oct 2023 09:25:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:321c:b0:53f:9578:1b14 with SMTP id
 g28-20020a056402321c00b0053f95781b14ls39644eda.0.-pod-prod-02-eu; Mon, 23 Oct
 2023 09:25:10 -0700 (PDT)
X-Received: by 2002:a17:907:988:b0:9c7:5667:5648 with SMTP id bf8-20020a170907098800b009c756675648mr5808567ejc.51.1698078310458;
        Mon, 23 Oct 2023 09:25:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698078310; cv=none;
        d=google.com; s=arc-20160816;
        b=qyXYwDQzANnb6CAmE/8uaG36mUQAym2C+1zJvdJQ8KgPwozNd5ijvHmxDqztvMr6/5
         +gyf5q8MzpS0ZA74D56n7W/Y9qLFvKfVrmg5qthrBSh0qn957FB+53VSJYwSUMLPq9fI
         SolGc4OC9tP/iPb1xfOGPmB4xE+KewpLwjKgJBuVd289m3zXBnO7SHXf978cy6SvTcmJ
         Xl8qnNKnD1YsixEn9320jtiSkeNtNVgpTBhwOBre0NzCoMiW0xdO5O9iWtsKWdFFUorX
         eXDNrHSa0RSx72cUTnKgCpcDbxkAXgkp22SyAGt7feEdsJLhhZhcKFYoXaDWK86quDXx
         t/Gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1heVLz37BMf9+qEekt7VobiQTsOf70yuv2uAcQVIL/s=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=tT8YxYsSUfiwPwOuIUyztR/oew2MFKAfZmv9J92xpZeSihKOG7gZWAgZC+TJWEvW87
         5AWrM7q2c/zJhZQ5/DrTSoJZFn/B9rIoiA86kqQ9myUFrTYkgx3fQSBK5aIgUpxr6+TG
         8gAcrH0oByqm8frpHkb2cOfH7o1lBapVBIqE1lNAixku0gtDITIJQmS1A3aMXlDBY9Zj
         8gGLRVFySLbOgpb7M1WKXNVQsmXa1gtPz173MNgbAI294NBfbBCR1vM4OfWvclLx2r1W
         Hd3kxX92EpJMNSR4yWgVEm0Qr0EW5Mk0SYUo3Qh2E1ftK+9xKQo8ziv64sjj0J6rMnUb
         SC4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="Kx/VCgxq";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.200 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-200.mta0.migadu.com (out-200.mta0.migadu.com. [91.218.175.200])
        by gmr-mx.google.com with ESMTPS id b23-20020a170906d11700b009ae3e884341si292083ejz.0.2023.10.23.09.25.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Oct 2023 09:25:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.200 as permitted sender) client-ip=91.218.175.200;
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
Subject: [PATCH v3 15/19] lib/stackdepot: add refcount for records
Date: Mon, 23 Oct 2023 18:22:46 +0200
Message-Id: <21c7e1646cf9ae61123851c5f62bfd02f21f6bf8.1698077459.git.andreyknvl@google.com>
In-Reply-To: <cover.1698077459.git.andreyknvl@google.com>
References: <cover.1698077459.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="Kx/VCgxq";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.200
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

Reviewed-by: Alexander Potapenko <glider@google.com>
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
index 902d69d3ee30..278ed646e418 100644
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
 
@@ -367,6 +369,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	stack->hash = hash;
 	stack->size = size;
 	/* stack->handle is already filled in by depot_init_pool(). */
+	refcount_set(&stack->count, 1);
 	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
 
 	/*
@@ -483,6 +486,8 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 	/* Fast path: look the stack trace up without full locking. */
 	found = find_stack(bucket, entries, nr_entries, hash);
 	if (found) {
+		if (depot_flags & STACK_DEPOT_FLAG_GET)
+			refcount_inc(&found->count);
 		read_unlock_irqrestore(&pool_rwlock, flags);
 		goto exit;
 	}
@@ -522,12 +527,15 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/21c7e1646cf9ae61123851c5f62bfd02f21f6bf8.1698077459.git.andreyknvl%40google.com.
