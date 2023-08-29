Return-Path: <kasan-dev+bncBAABBCWOXCTQMGQEA23KFUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CEBE78CA5E
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 19:12:43 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-500777449e5sf5227691e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 10:12:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693329163; cv=pass;
        d=google.com; s=arc-20160816;
        b=lfpUriab4yWcbUxStnOS8j05UQk73CwEVB5C+ShnQpNWSbgKdPVKf/5SwD/1jGDt5p
         kgnsWp5NTWjClwqycXLSbRZrUz5F8sImUcNTEX/2BFEwdKEGaBqIEd8CJXl/gdAxaY1I
         SNWb4QrhsZJRyoyuGiHTRqjuQI5ITteV+qUkZL+p6fKER2Wtp8szsYmVxjH12BAeWkgb
         vP9XLjIvO+SODeEafSEV9OtuZAZxB/sEE1EtJC7ks88LpEVpi5yQSOrk2ybue0xB3+6z
         IqbI9+15NQi9W8OC7kf4ahp2ZJDMtLpFl7KDLha5gSgwMOIF2HW2HduylOidpzDhcH+t
         7Csw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3gt/uVibTCDujShygzDXgbbrCfCMGd16m12JImsZ+OU=;
        fh=ZTTSst3850TI+4y2eqKpcuCmJhEtn1qZX9lpGyHR9Jg=;
        b=PoqS0mBw7sN9r/WY5REpL6IvA2u5j+u2yLFkP8Gni4NHKDCVPzt8Ep+5zVoNFqbaRH
         QcsMgXvcYnNG7jzz1BAma3+YmDMf5Of7GCUGH7KEYwQ+YWCt2Uq9BZrjcUlwrSAUaViW
         6v1KlqGZE0MglZoe71jlK/PmWsni4ACYtagMMAJnV8ZpLDamyU2/uAfaXtLYyhxcD9+i
         MCDL4567qeRs9cqgZbLVqvWyubelGyHRP73mOLDTg+RleWSw8oVfTv8xpjZmwLvftXqY
         0EY7rXUR8q8BEy2W3xg4RmtemEYt9xqvFoms+4nYbmpTXr/HjpsAL5FDB/5It5VRYo8y
         ycWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=dEoDb6yz;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.244 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1693329163; x=1693933963;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3gt/uVibTCDujShygzDXgbbrCfCMGd16m12JImsZ+OU=;
        b=TgQjbhvvaLWxHdFraUiRyxLR3jBCdJ1zq4kxLqaoCJxpNsV00sNbVdeDDWHiUXJpQZ
         f8dYz7yXyGDoGqoUho/P+t85SIxzJmYhcuasCDck9XF810PKXe5LNJzV00DWGRLjHcIO
         O3mNCnGDJgt7DL0DI+QQO1yiPiRV6PB8qvbCqCS3frB1HUqs3Z7oWSiMf5UQby0gcMqE
         D1q62pHdGf6EGLSrh5W4ntqWY5OoyYIdGKpq5Xh9HwdTEEBVJALWXMFF9Nb/UBRvnn3l
         O94x59wefn7TUF4TsSoqvTVluOzvGRw0kY4mvdz7MWNvdbLHnFctWQgguShJC6TsvgE8
         LvJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693329163; x=1693933963;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3gt/uVibTCDujShygzDXgbbrCfCMGd16m12JImsZ+OU=;
        b=WT+dW/Yhbtem057RkXr1KCQpaANUlWjm8djdQFMmb3uIdRZEce7oiWBZo6sKttGzX8
         0sAZp9XSDYitE2XJDaGVeK6oHpDvyuwCNL70D0PFKRddlkD8F69zPtTg1JMdA8ObCS5Q
         bbV7keYEl9dE/nb2+X7P+4Z1HJjkjdTCUwdgaYC5GadTeSDbhIaCq0ML8fQhUKbzqNer
         XbgyEV8As2rC9JvpAsWFcQDfnjRlN/4CCwiXM6KoNWFLWujasuHhszIKgyjEMsJvrBmK
         spyeBD3RgSvumEvKjWl+E6mqo6OkXLguFDi98azCx7dCAeG/m1Hloe+c7X+dStVqxtz0
         HLjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzAVAWHJBQE2caYsHJunmBlAqQtxSLMCdlER47vwIvfDjTd9RZ9
	lE4zsMMRFZwyNrQFVWOktAQ=
X-Google-Smtp-Source: AGHT+IEHAAe24eMyGiAaSdUwq1skfxt8L9nXxzux52zbCyOXC4SiZviHLRQ/ofVsoFeuQzP5VnG8uA==
X-Received: by 2002:a05:6512:2354:b0:4ff:a8c6:d1aa with SMTP id p20-20020a056512235400b004ffa8c6d1aamr22026789lfu.48.1693329162703;
        Tue, 29 Aug 2023 10:12:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:2d0a:0:b0:4ff:80d4:e131 with SMTP id k10-20020a192d0a000000b004ff80d4e131ls1298148lfj.1.-pod-prod-09-eu;
 Tue, 29 Aug 2023 10:12:41 -0700 (PDT)
X-Received: by 2002:a05:6512:1587:b0:4fd:d470:203b with SMTP id bp7-20020a056512158700b004fdd470203bmr24177693lfb.69.1693329161261;
        Tue, 29 Aug 2023 10:12:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693329161; cv=none;
        d=google.com; s=arc-20160816;
        b=obXKc0QdpryhDWZyZCc7Hyu4ajsMqiKk2OSdmbOvvo2SI1Vp6NCmidcWQmYMN11m7z
         /5kTD+Di/8BloXhXgG6Izx0Zas+x750NxmKx5LYItKMGRz25BnTrVf7c3bQHMUlIy7e4
         ZBKorNwn37gvJA019eGhlNIB5uIZ6Y4dDBNssPFeZzHfVKbzaqgBP1Piv5aS2+RgkMlV
         dwcwAdG4ceuJf8ivTBhasKCI92cdgBmQ4+y6RnGRIqf7bKhTk7nveXzD8vsETnXRsZFD
         Pmh+UhDdDi5UE/XY0GWJQ3zgLAUQxEZoxYHe4ITDs8aiOPog7NN281XMKQ0KW5wja8Zs
         mZJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Z7PnYrb1S+8x+6HixwHlp8BbvsuCogeXMw7DcmkZ+jU=;
        fh=J1Qt2dYQZwHfoASHEf8Q1j6KnDtpzzpCUlDsDM7WT0M=;
        b=OSgVI6bOlIe/zrIpnnOwYE7U0OjHxT5vz2R27bLyM4XdL3H8wgbLhQ7t0818rCB+pk
         vANp4vtu51QWHHHef5EASuB5gjrMIdQPNH1rDYrLLfozoaxOnN1s8of9LH+rdURC/+XH
         Yl+sFaEZMmyRasclvQxuqfWi0+2eoWhereF9uSm008ss1+jfOXL+uH0Vkp+gHjAnmDbF
         gv5dI0Tfg/tGHjBAvFeTtkwLp4iBJCv/Mp16OQOWHgCtRJjqRXJOk96e4sURObJBlzEF
         fYxU3gqY3Ng8av3FV0B9SHndLtWdlTZOyhkkYNW24mQurjlrNrxeAnDkScyFaFXNKgKl
         vlpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=dEoDb6yz;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.244 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-244.mta1.migadu.com (out-244.mta1.migadu.com. [95.215.58.244])
        by gmr-mx.google.com with ESMTPS id a28-20020ac25e7c000000b005009dc902ffsi723043lfr.4.2023.08.29.10.12.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Aug 2023 10:12:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.244 as permitted sender) client-ip=95.215.58.244;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 08/15] stackdepot: rename next_pool_required to new_pool_required
Date: Tue, 29 Aug 2023 19:11:18 +0200
Message-Id: <f5dad29285c8aa7b4a1a3f809e554e7d28a87b6c.1693328501.git.andreyknvl@google.com>
In-Reply-To: <cover.1693328501.git.andreyknvl@google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=dEoDb6yz;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.244 as
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

Rename next_pool_required to new_pool_required.

This a purely code readability change: the following patch will change
stack depot to store the pointer to the new pool in a separate variable,
and "new" seems like a more logical name.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 47 +++++++++++++++++++++++------------------------
 1 file changed, 23 insertions(+), 24 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 869d520bc690..11934ea3b1c2 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -94,12 +94,11 @@ static size_t pool_offset;
 static DEFINE_RAW_SPINLOCK(pool_lock);
 /*
  * Stack depot tries to keep an extra pool allocated even before it runs out
- * of space in the currently used pool.
- * This flag marks that this next extra pool needs to be allocated and
- * initialized. It has the value 0 when either the next pool is not yet
- * initialized or the limit on the number of pools is reached.
+ * of space in the currently used pool. This flag marks whether this extra pool
+ * needs to be allocated. It has the value 0 when either an extra pool is not
+ * yet allocated or if the limit on the number of pools is reached.
  */
-static int next_pool_required = 1;
+static int new_pool_required = 1;
 
 static int __init disable_stack_depot(char *str)
 {
@@ -220,20 +219,20 @@ int stack_depot_init(void)
 }
 EXPORT_SYMBOL_GPL(stack_depot_init);
 
-/* Keeps the preallocated memory to be used for the next stack depot pool. */
-static void depot_keep_next_pool(void **prealloc)
+/* Keeps the preallocated memory to be used for a new stack depot pool. */
+static void depot_keep_new_pool(void **prealloc)
 {
 	/*
-	 * If the next pool is already saved or the maximum number of
+	 * If a new pool is already saved or the maximum number of
 	 * pools is reached, do not use the preallocated memory.
 	 * READ_ONCE is only used to mark the variable as atomic,
 	 * there are no concurrent writes.
 	 */
-	if (!READ_ONCE(next_pool_required))
+	if (!READ_ONCE(new_pool_required))
 		return;
 
 	/*
-	 * Use the preallocated memory for the next pool
+	 * Use the preallocated memory for the new pool
 	 * as long as we do not exceed the maximum number of pools.
 	 */
 	if (pool_index + 1 < DEPOT_MAX_POOLS) {
@@ -242,12 +241,12 @@ static void depot_keep_next_pool(void **prealloc)
 	}
 
 	/*
-	 * At this point, either the next pool is kept or the maximum
+	 * At this point, either a new pool is kept or the maximum
 	 * number of pools is reached. In either case, take note that
 	 * keeping another pool is not required.
 	 * smp_store_release pairs with smp_load_acquire in stack_depot_save.
 	 */
-	smp_store_release(&next_pool_required, 0);
+	smp_store_release(&new_pool_required, 0);
 }
 
 /* Updates refences to the current and the next stack depot pools. */
@@ -262,7 +261,7 @@ static bool depot_update_pools(size_t required_size, void **prealloc)
 		}
 
 		/*
-		 * Move on to the next pool.
+		 * Move on to the new pool.
 		 * WRITE_ONCE pairs with potential concurrent read in
 		 * stack_depot_fetch.
 		 */
@@ -271,12 +270,12 @@ static bool depot_update_pools(size_t required_size, void **prealloc)
 
 		/*
 		 * If the maximum number of pools is not reached, take note
-		 * that the next pool needs to be initialized.
+		 * that yet another new pool needs to be allocated.
 		 * smp_store_release pairs with smp_load_acquire in
 		 * stack_depot_save.
 		 */
 		if (pool_index + 1 < DEPOT_MAX_POOLS)
-			smp_store_release(&next_pool_required, 1);
+			smp_store_release(&new_pool_required, 1);
 	}
 
 	/* Check if the current pool is not yet allocated. */
@@ -287,9 +286,9 @@ static bool depot_update_pools(size_t required_size, void **prealloc)
 		return true;
 	}
 
-	/* Otherwise, try using the preallocated memory for the next pool. */
+	/* Otherwise, try using the preallocated memory for a new pool. */
 	if (*prealloc)
-		depot_keep_next_pool(prealloc);
+		depot_keep_new_pool(prealloc);
 	return true;
 }
 
@@ -300,7 +299,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	struct stack_record *stack;
 	size_t required_size = DEPOT_STACK_RECORD_SIZE;
 
-	/* Update current and next pools if required and possible. */
+	/* Update current and new pools if required and possible. */
 	if (!depot_update_pools(required_size, prealloc))
 		return NULL;
 
@@ -432,13 +431,13 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		goto exit;
 
 	/*
-	 * Check if another stack pool needs to be initialized. If so, allocate
-	 * the memory now - we won't be able to do that under the lock.
+	 * Check if another stack pool needs to be allocated. If so, allocate
+	 * the memory now: we won't be able to do that under the lock.
 	 *
 	 * smp_load_acquire pairs with smp_store_release
-	 * in depot_update_pools and depot_keep_next_pool.
+	 * in depot_update_pools and depot_keep_new_pool.
 	 */
-	if (unlikely(can_alloc && smp_load_acquire(&next_pool_required))) {
+	if (unlikely(can_alloc && smp_load_acquire(&new_pool_required))) {
 		/*
 		 * Zero out zone modifiers, as we don't have specific zone
 		 * requirements. Keep the flags related to allocation in atomic
@@ -471,9 +470,9 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	} else if (prealloc) {
 		/*
 		 * Stack depot already contains this stack trace, but let's
-		 * keep the preallocated memory for the future.
+		 * keep the preallocated memory for future.
 		 */
-		depot_keep_next_pool(&prealloc);
+		depot_keep_new_pool(&prealloc);
 	}
 
 	raw_spin_unlock_irqrestore(&pool_lock, flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f5dad29285c8aa7b4a1a3f809e554e7d28a87b6c.1693328501.git.andreyknvl%40google.com.
