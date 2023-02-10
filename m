Return-Path: <kasan-dev+bncBAABBG7JTKPQMGQEHHPJMPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id A83B869291C
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 22:18:20 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id s22-20020a2eb8d6000000b002905bd2a7b1sf1858530ljp.9
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 13:18:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676063900; cv=pass;
        d=google.com; s=arc-20160816;
        b=rcMCKF4YG4ya1B97qSHn0RjGa7fThFb6b2bug3QrnN3IhgxU5V+HCGhkIgnHRwiWjC
         4x3EJO7JVfYpyqM16YWefPvWT3bW6CAIRxxJNq3keHOqJlocX2D7n3tgOtLNG9cR4ZQW
         ehrUxYTM01tQjfj4iIN5000jze+H8sEE0aippM3N/C9gH3lRhCEnDmZ3BiPtd8X645Zg
         QzFBPyWdEoWW591r8AyinzJbpflst5QmsOomAd/qOdl2By5/qQxoXWB7YHE1eQ20rH2V
         +t4+PuQ/RgLqgnIlOqCSA+9p2aaZRLbtp4yUVvxMDuKLJeMv9NUlYPwhAlhOwuPFDxdz
         ziPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=IcpO0lGh/Wyjn2JO/EBkSnN8Ywp5Yp7gN0xbo+1jH0A=;
        b=BzhsevlejWkzUD5uopxqRDi9IhpU+u3SH4YlvcGjTW12jcxmYuRn/ahsIRL++zEzAb
         Wc4THTz1L/z26VCxg/tqBTpKj/8jKtyC5rjElATUUK86bDrLU7suJqICDWuMJtF+HBlT
         L2qxHxNogcHWq6clAScVbDwb1gzmsXqaAjOuAK70KThygMIR8g7Nbc411OSe8kJARPLe
         i9HbhecV8fv8rK1a+UrcaBWx4NbgXx6dFyPO1UvcdIeMTCt3evwPxDSCXO/vo1/8VRAj
         QjnMcfZ8+4/SNA9GLaNvKNTWhYHh/an6ZGyy6eVJPoyBRRbxS55te1s6tCdAJ0llBFl+
         NwAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=B+1V8biN;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::8c as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IcpO0lGh/Wyjn2JO/EBkSnN8Ywp5Yp7gN0xbo+1jH0A=;
        b=S+mu4Je5pJsYbdHgIuufhQGFACBIVl2NQ9ez2ieN7KFGZqO3AlODt4a5MNcmLtNv1D
         a2sfUSES+yAHROFJC+E+sQO3Z7uDbzKC/ThkQXZL2hznlf504ItF4MlolRORCFgZnE8N
         gK+Y7evA3APZWKN7c6gBLszjH2iHEHauFVvZ++nt77SoHK0Q/iyY81Hnluh+OAO32XWz
         9kepI3mNC3xnKMpLR2QPSbep+kfByPxRl/57YnamqdPOO6IrbdS2FUp8UWO1MY/Iw4Bv
         h/DPtvql6QVyWk6CDk4XK9kMUWOeesxRGSKjd8yF63CVBmcYCC03XhLHtTeWeK/ilbHb
         13YQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IcpO0lGh/Wyjn2JO/EBkSnN8Ywp5Yp7gN0xbo+1jH0A=;
        b=f+jbgdkNbr6MBZ7SLaKmuRwUDzuSDwyHUhhBkXSm0tVcOqL6Hx4CzWFyAqmtiMmLFq
         BuPY7ex1MpzfLqJHNAKD/EB6SNY9cpYPeIoK3n9CCRMOs+2HTtBnO/JQ7rsnhn6+1El0
         rbJt4Y7KHlNtMfG3/nyI7ZzgAYKU4icbxKJwN5oVuEhE/wRLdqe+EpCjjvDH7Kn+j4wD
         FV0CWtduaiYdAcw+KJQI/zeZObwwNHmOezV+zaoN01ij/ZMrGa16yhSfhmKYPaEv+cJT
         dOxww2siFsu7b9qZFmu4fvobIL56udnSgA6r7cX05WIj4azxRo6ZepOGDja487SYPj5d
         Q09A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKX6sV41rII4EL+wv4rDrNtTUIJmQaGbJx/Q375YalQg4oGwG4Kk
	w7pG6kTZwj0+lpCOgMjbP7s=
X-Google-Smtp-Source: AK7set+nSfIGXk/lXQJtqj1noa6/lt2fd/JcdE0UI0V7t2JEhHalnSLCadBUSSJBA6fbD2v8Bvv5wg==
X-Received: by 2002:ac2:5494:0:b0:4db:2be1:c7d8 with SMTP id t20-20020ac25494000000b004db2be1c7d8mr673375lfk.256.1676063900166;
        Fri, 10 Feb 2023 13:18:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:239f:b0:4cf:ff9f:bbfd with SMTP id
 c31-20020a056512239f00b004cfff9fbbfdls4337642lfv.1.-pod-prod-gmail; Fri, 10
 Feb 2023 13:18:19 -0800 (PST)
X-Received: by 2002:a05:6512:38c9:b0:4cb:4571:9efe with SMTP id p9-20020a05651238c900b004cb45719efemr5062645lft.35.1676063899204;
        Fri, 10 Feb 2023 13:18:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676063899; cv=none;
        d=google.com; s=arc-20160816;
        b=al8UIx4qUduAaz+RPuyj6o3Fh8eSeOEisVSdJbYs3PWzaAOQ5/sYJZvh5c/TKQR0qj
         baBhL9/InYOYPqg33uzx6pZbAMVySkCXvOulUJMd3HEpSNlFPuxMYtDOqtgqj6KpqwH7
         JLpIogYihDN3LpSa7yO/QJbibtn7Z9dHombT8VvA2A6h33IDZ7FB4ZAFXkmo4USMQs5J
         ZmOswU5EbNBx/+bi+PVGyq41VRhjSxXesrKC2pSdOaLDyouv+equvpHjMaCSpjyT3Z3S
         31i9XGTrRw6N0bEefnK+aw2OyKZUdc+lnsLMN5exbE/xg0KWJuJsB73qZrB+uoryAR12
         5Pgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AbtsRD1ly4MmHuz3K8pgOTgQ9ciqaNAhgw745M5z3qM=;
        b=0IGPs8ieeINNnwHqnecfuNGjABqEwOZc2aCZ2WVRfWCQQpxFtuuvY9Oo/4iAjXNAqO
         +KS/QBqkL2He46GbAedAgMjvL/Gxwa0tZVIuq1VHW99o8Zy4bFDctGaRr7Ro8SwLnaet
         B6YUN4EYvxkV4OPhb4xuXv6MyErS4YQp/c243MpCMoJ1HlNBJJQuv1bLcpeLm58+4RUr
         zokCDIwtkTHVyBDlMAunTzTjIG8KCqZem04uoqGLxIWvVXGFbKXpi96f+Jw97ouYSboD
         5wiJhv3M1Ym7sbq2UkbYF3UzafTQRSU6IZXf/6InxsIFa2RZhroZsn1nKWaNzsUhtIsD
         YKbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=B+1V8biN;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::8c as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-140.mta1.migadu.com (out-140.mta1.migadu.com. [2001:41d0:203:375::8c])
        by gmr-mx.google.com with ESMTPS id k33-20020a0565123da100b00492ce810d43si300469lfv.10.2023.02.10.13.18.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Feb 2023 13:18:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::8c as permitted sender) client-ip=2001:41d0:203:375::8c;
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
Subject: [PATCH v2 14/18] lib/stackdepot: rename next_pool_inited to next_pool_required
Date: Fri, 10 Feb 2023 22:16:02 +0100
Message-Id: <484fd2695dff7a9bdc437a32f8a6ee228535aa02.1676063693.git.andreyknvl@google.com>
In-Reply-To: <cover.1676063693.git.andreyknvl@google.com>
References: <cover.1676063693.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=B+1V8biN;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::8c as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Stack depot uses next_pool_inited to mark that either the next pool is
initialized or the limit on the number of pools is reached. However,
the flag name only reflects the former part of its purpose, which is
confusing.

Rename next_pool_inited to next_pool_required and invert its value.

Also annotate usages of next_pool_required with comments.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 30 +++++++++++++++++++++---------
 1 file changed, 21 insertions(+), 9 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index c4bc198c3d93..4df162a84bfe 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -96,8 +96,14 @@ static int pool_index;
 static size_t pool_offset;
 /* Lock that protects the variables above. */
 static DEFINE_RAW_SPINLOCK(pool_lock);
-/* Whether the next pool is initialized. */
-static int next_pool_inited;
+/*
+ * Stack depot tries to keep an extra pool allocated even before it runs out
+ * of space in the currently used pool.
+ * This flag marks that this next extra pool needs to be allocated and
+ * initialized. It has the value 0 when either the next pool is not yet
+ * initialized or the limit on the number of pools is reached.
+ */
+static int next_pool_required = 1;
 
 static int __init disable_stack_depot(char *str)
 {
@@ -222,10 +228,12 @@ EXPORT_SYMBOL_GPL(stack_depot_init);
 static void depot_init_pool(void **prealloc)
 {
 	/*
+	 * If the next pool is already initialized or the maximum number of
+	 * pools is reached, do not use the preallocated memory.
 	 * smp_load_acquire() here pairs with smp_store_release() below and
 	 * in depot_alloc_stack().
 	 */
-	if (smp_load_acquire(&next_pool_inited))
+	if (!smp_load_acquire(&next_pool_required))
 		return;
 
 	/* Check if the current pool is not yet allocated. */
@@ -243,10 +251,13 @@ static void depot_init_pool(void **prealloc)
 			*prealloc = NULL;
 		}
 		/*
+		 * At this point, either the next pool is initialized or the
+		 * maximum number of pools is reached. In either case, take
+		 * note that initializing another pool is not required.
 		 * This smp_store_release pairs with smp_load_acquire() above
 		 * and in stack_depot_save().
 		 */
-		smp_store_release(&next_pool_inited, 1);
+		smp_store_release(&next_pool_required, 0);
 	}
 }
 
@@ -271,11 +282,13 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 		pool_index++;
 		pool_offset = 0;
 		/*
+		 * If the maximum number of pools is not reached, take note
+		 * that the next pool needs to initialized.
 		 * smp_store_release() here pairs with smp_load_acquire() in
 		 * stack_depot_save() and depot_init_pool().
 		 */
 		if (pool_index + 1 < DEPOT_MAX_POOLS)
-			smp_store_release(&next_pool_inited, 0);
+			smp_store_release(&next_pool_required, 1);
 	}
 
 	/* Assign the preallocated memory to a pool if required. */
@@ -406,14 +419,13 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		goto exit;
 
 	/*
-	 * Check if the current or the next stack pool need to be initialized.
-	 * If so, allocate the memory - we won't be able to do that under the
-	 * lock.
+	 * Check if another stack pool needs to be initialized. If so, allocate
+	 * the memory now - we won't be able to do that under the lock.
 	 *
 	 * The smp_load_acquire() here pairs with smp_store_release() to
 	 * |next_pool_inited| in depot_alloc_stack() and depot_init_pool().
 	 */
-	if (unlikely(can_alloc && !smp_load_acquire(&next_pool_inited))) {
+	if (unlikely(can_alloc && smp_load_acquire(&next_pool_required))) {
 		/*
 		 * Zero out zone modifiers, as we don't have specific zone
 		 * requirements. Keep the flags related to allocation in atomic
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/484fd2695dff7a9bdc437a32f8a6ee228535aa02.1676063693.git.andreyknvl%40google.com.
