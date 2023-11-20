Return-Path: <kasan-dev+bncBAABBNNY52VAMGQE6YXTZEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id BCAE67F1B7D
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:49:42 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-4085a414d5esf8945e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:49:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502582; cv=pass;
        d=google.com; s=arc-20160816;
        b=LKxTw6ZDy4F//sekQthUTxZpXe7VjSmVoKPgYN97DPeTyDpKWjRrpI4/UmDXDEcHJx
         WSwFqjRY7ND4RdsLtZfBguDY4+P2FvDIMmsX/C7UcLF6tT3xV+xI9Fg4gqPocet9ThHY
         ETt6CW/J+YC6/zJ4jpd4JK2XqNk1Qr1Dxm2ZARDT+FoxfOKiRPEAkW6ts6XhZSBgszuq
         PJmnAd6eNbAUYMRSJKhGBmncix5zS50+uie5kEe7ZTlP56YmzYkcc7exsjRcaWCG9k2+
         zajemIg+HUCLLgOZBcpIHkDgR2jjE3YoWMvk5kt5AOSBJG6EUxTGXL5AxXnCLdknBhmU
         VbpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=F7ZscdpSemS/lLguTkrSDFgmt5eXhGn9fluPJ3Id8Ms=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=utPSdH3lhHlAyvoTkt79qbVMyJbggSZMFG7kt7sOJ3El/ctNO+55C1xZJCFKr3i4nt
         nHD6E3RWKlAyL2lYsIKwNN1ZURYGvnUeppzQDy99yUjSrZqxG36gJ06q6tbMxLBqweLO
         Ra+qqupCaXQ4ub+lFSiKuohiHnf2hc4SeI9g1jCl3gqCtdbijhFOL5nUH0Pga0/NIGu5
         qQGAujuKAAfRaKu0cuKa/xxLxZ9TAEt2OkIia7X1bKrmadtWL/QdBnpgmh6uNXmJVLqf
         eQ+rQG56LhfnQrBEqbHpi8VwwaC/SemNtnz4+2afuHjXenumiYORfSbXayjJ6OIH/IDY
         xAaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="rZ/C2Hcs";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.172 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502582; x=1701107382; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F7ZscdpSemS/lLguTkrSDFgmt5eXhGn9fluPJ3Id8Ms=;
        b=wkAvC1LUH+ZFEy7Jj/jEOHXr7hgRRGfU+JNCoUWbF9aEjCrycqbb/Rqb5YN19XwRE1
         /oVeYd3I+kXvqJWqucYWefS4hZu2RRQblcSeVOv8/kJUkz2/p1lXkYjNhSMHc9hj5x7L
         0yvzbwgkW7fVXhFBQJo59sqe6qMgfzXxrTsDmnWtDn8mPzVblVfbMws/39tuMHTKyfcV
         U5KBvzequr9NtyBTLDLPHUA87n3TUhT+AZ4ZxyV9eNWHRZkh8zEyRQvG4nyOpa79CmKy
         Qv3FkKyWftKpkOgIP0KwR/kwsL/TyY+CWHnhsiv9anXlfF0aypyPrInez26mISE8v3fI
         mxXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502582; x=1701107382;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=F7ZscdpSemS/lLguTkrSDFgmt5eXhGn9fluPJ3Id8Ms=;
        b=fXs7G69iEuvvwhpFrmYyCsP/lkVbBn41tQnx5DGnZwGxmvTz3GgtMozPxZ3bQ3DLHn
         lmGR+cosNUDV1GG9x8Y5XsZbbeFPuB0RvaaaIDS32OSKz5EIJwD7nOtbKYM5RsM7IDU3
         Y0TVP8TuR3Iyb4ULFB2AV4CslzOhVWVkEfO601yY8fg77VnSk0kqRCeGfmLy+vrn/BmI
         zXkm3HCepp6zVD8ry2KZxRZve0921LL3pIfyOJSeEe7QtuFQG1JKKF1mCsVB4zopvlxb
         p5k5NH6dpD5KCTQBtfnYhe6sYvuByFlbppKYGeosgfiQkLnnLsXJ6gTwPpzZclgBZuHS
         9k0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx7y/hjBlDaMEMfsX4EbUqsBMGW3SwhltijlhoEQTb6Mt6lQkqz
	bn9e3YNf/266ZQ3DMkWwXc4=
X-Google-Smtp-Source: AGHT+IGHpSOHNUHV/IBaoNLAWgotiM0MitjRsH7OcBtIOI6+YweueLn1LyGnos79awLM+DFCM8nOmA==
X-Received: by 2002:a05:600c:474a:b0:3f4:fb7:48d4 with SMTP id w10-20020a05600c474a00b003f40fb748d4mr402439wmo.3.1700502581970;
        Mon, 20 Nov 2023 09:49:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:234:b0:323:30c1:307b with SMTP id
 l20-20020a056000023400b0032330c1307bls1488104wrz.1.-pod-prod-08-eu; Mon, 20
 Nov 2023 09:49:40 -0800 (PST)
X-Received: by 2002:adf:efd0:0:b0:332:ccdc:70fa with SMTP id i16-20020adfefd0000000b00332ccdc70famr188517wrp.9.1700502580503;
        Mon, 20 Nov 2023 09:49:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502580; cv=none;
        d=google.com; s=arc-20160816;
        b=SjfNNQe3fl+l4sQiFyWH05KVnV2UhTiZslsOd6V9beV5/2eec2DqK+zEoQxT9uhCY+
         REbUB5MJwgDCyhOUVUVmL6f65XcH9RoCTj1oLi/mTnV4lt4CniBIoja8kR0gBqGp4hmd
         VilAiSXe4t51mQ51I86Qlyc4ydZ77q2qEqO9UZZ//1fLJDyBS7Faf9y1+nis/IVq4aSk
         gvSNMrG8D/suMhf42+N/KLjr9T+xKvWsr1JLzbQHXaHkSt66ty7HB//+hFIpV3UoBb5N
         7TWfhajlqESrQF80fqjd/Sfd39oPDzp/9z0oUkfFkee4qolZkOM43HXm5OM5G3KeISz4
         3jLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=91QxaYvk4RHHEJwI4Sc7Oo7z2rlFVPgOoXOer3eAY+g=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=zbMvMMKMIzwOZSLNbtEdTwfRtApJm8Z3k3rlstvDI7n38W9k4qMyiMKqh3uSiz5VaC
         aQWdYcvHxe7MOmW0WRMk6jpaT/XG6OZyeg3djvoovJ7Tb01qiZvYReaAvI/mXEiJKt90
         xBsIo6mlzXCKfFulJ4cBWbkZP2EZ8aA9oVyY8q1JdIrfPjDzu6KwkxIgBUBrfOma4vY6
         m1TFg7rB2o7GitBhoOXz3FsIUL6DNaIyfG9/AdnowVURSoJ0GkuMqDvnmUasT4XGlgPQ
         aVrKry8x/FuEn4d7Yi+kLw3XWoHqMq8yHpJs3dNeAgRLWByu0kQIYJ+ELeqevVRDNOZg
         4gJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="rZ/C2Hcs";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.172 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-172.mta0.migadu.com (out-172.mta0.migadu.com. [91.218.175.172])
        by gmr-mx.google.com with ESMTPS id p2-20020a5d68c2000000b00332cc5c485csi30164wrw.3.2023.11.20.09.49.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:49:40 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.172 as permitted sender) client-ip=91.218.175.172;
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
Subject: [PATCH v4 16/22] lib/stackdepot: add refcount for records
Date: Mon, 20 Nov 2023 18:47:14 +0100
Message-Id: <a3fc14a2359d019d2a008d4ff8b46a665371ffee.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="rZ/C2Hcs";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.172
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
index 59d61d5c09a7..911dee11bf39 100644
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
 
@@ -373,6 +375,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	stack->hash = hash;
 	stack->size = size;
 	/* stack->handle is already filled in by depot_init_pool(). */
+	refcount_set(&stack->count, 1);
 	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
 
 	/*
@@ -489,6 +492,8 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 	/* Fast path: look the stack trace up without full locking. */
 	found = find_stack(bucket, entries, nr_entries, hash);
 	if (found) {
+		if (depot_flags & STACK_DEPOT_FLAG_GET)
+			refcount_inc(&found->count);
 		read_unlock_irqrestore(&pool_rwlock, flags);
 		goto exit;
 	}
@@ -528,12 +533,15 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a3fc14a2359d019d2a008d4ff8b46a665371ffee.1700502145.git.andreyknvl%40google.com.
