Return-Path: <kasan-dev+bncBAABBJF43KUQMGQEJI23JLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id EAFC77D3C51
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:24:07 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-32db9cd71d7sf1796905f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:24:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698078247; cv=pass;
        d=google.com; s=arc-20160816;
        b=xdSXxbH800NNScy9Yjyo0tJF8N678KlcEoUeQfAg92QX2tCXP9TvGNgDLi2caFwu9J
         QaEhbObZTQUl2L9MPGBSy6SexWqFfb/kN7uOOvUsAC1Ysb/KyskAb01JQ8XJAeQUUkW8
         OUTsO69cgHYqRfXviLO7LhfytlBhy9hjXPn3tKwY85Dfhxp2RwyyWmwVZg6ut8/R/x/h
         ygf3sp/RXwk/3hgH8RwZp3Zu1V2+mmb0VYmJZJ9RRok2xP3wzY18A0Qx8nitHKRQACI8
         R+mz/6zfNLWyZx8GOLQgGLprkwTAZl/vMlIMGLtuiTg1gSd6wiKQCRm3LF8lQAASeLOO
         tQzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9r1u9Nbk8beSvwIHANN6Ma2rolsWJvlyrWUlD4WWkyw=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=ZOQNde28iokyeo2Nczrudo5tOBHBXGbIyIHHxYxNQV2/Yar1CMBnJ1UGVGe8+dB5E2
         VZeYa+1waHuSCAiG9MyG/HnyoI4F00LFfvfSxnhzPC1+zBpp391j5YDwG28koxlF35oN
         /Oei1ymANk4M3Xx0OnlXSx8hfbiyQz7ds+FoDy0R2kSMoECAHSz02oKWZ4cjNXjf1pPE
         gsEDF71PaX8Lkl0NpRW75omWEvuqD23uE+xOnyU5lQgHC6fPSJxn6BLyiDIMvIYrOlio
         CtO+ffBjK/BpXy+WS1y4z6LOEKqMmBeJg8+hU0lIdWOw+1BYdGaHNy/kj0UC0ogTa7zJ
         WzHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tTmhSqri;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::cf as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698078247; x=1698683047; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9r1u9Nbk8beSvwIHANN6Ma2rolsWJvlyrWUlD4WWkyw=;
        b=hGnXIc3u4F/cG7Z7CSyjZovUL36Riqkpl/sE6HUtzLS74KcetheZAq5A4dutHn/R/8
         xXS9YTiVHHjY/BatkYyGpeGlPYdk7YMcY3LXB9oYBwa9QBDgyn2opd4iA6bdNxyJ2mAv
         CMo6trL6bEIa2vFW9OUqCnrxQf2WlFtqFPo6eFZsQASOKI3jsZgqQnLe5JpL7Mmshz3y
         i2OSeEUHNh7jMa+neQhCfyMqyDl+pcZ6O3DX+LKvaWnjMAwkioOkmdxcRgWXHpwW+3xa
         3Dc1+K5tdQ69/NkbA6spZzcoWh2wgH3WcYGxmz/xafG+PD4/qyKd6Ipzvm1Pbd0ucxYZ
         lzDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698078247; x=1698683047;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9r1u9Nbk8beSvwIHANN6Ma2rolsWJvlyrWUlD4WWkyw=;
        b=ZaH+P1PEQC12poaJTdB1O3wrxwtYuGReG9JU2sdZ4hEt5Mk9uZqWpKMsgwS+xoq0Og
         lIt65FmnUnXxWJLNkZzvbfZxik8mMKUe2yOBdsaO42Mt5ryzf5c428jATN0PflDG6dtf
         y/nUn9P8z6/vUXd2rpFMpJaSdmdNp9ihNAtaGtCQ5q4QrpMyrnoD5OtHHoXXasKrds3x
         Lv79fjaB1Hts6O7UBMRhs3MhFbGkdB7vPqKBgcxXzRGmY8nWdVFj7i/dTnV+Ou6IBAqF
         mvXfvkTbLB3+CZC8vN/zUeAAGIYiL1lbByaDchQH6WQX71OBfqBLcg9sPwq9LFXDux2m
         QMxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyWWoo6gMmvn/mTi0ouoQzy0ltrBhAytVpZlrd2TE19aB7OJ9Zx
	YuHwIV3P+PqzSp9NDk+bR5U=
X-Google-Smtp-Source: AGHT+IHOsUptNhEBlHRcc+0PmBAwY3NxG/dMbX4cinSocnBVgmgTQG1SH9QZeUCrRuxND5UpeYPtTg==
X-Received: by 2002:a5d:5956:0:b0:32d:de4f:140b with SMTP id e22-20020a5d5956000000b0032dde4f140bmr14063252wri.6.1698078246531;
        Mon, 23 Oct 2023 09:24:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3591:b0:3fe:ef50:e1d8 with SMTP id
 p17-20020a05600c359100b003feef50e1d8ls1324750wmq.1.-pod-prod-00-eu; Mon, 23
 Oct 2023 09:24:03 -0700 (PDT)
X-Received: by 2002:a05:600c:b4d:b0:408:33ba:569a with SMTP id k13-20020a05600c0b4d00b0040833ba569amr13226904wmr.8.1698078243590;
        Mon, 23 Oct 2023 09:24:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698078243; cv=none;
        d=google.com; s=arc-20160816;
        b=L+tpZbnVjbxJQhF+F8WZtJWeYPUg9HLzAvQ169ITMNEP0Z20d0daFIUBX8DFB+83G/
         zVfaOctv4+ZDTshqczfa2hc85Jcvtc3a8bItKU+rzeAyoM9zQjQTPhW14jqBY0erQA+M
         l7BtjzK//R5rZdmFHKVcLOZEqbnPYX58csvqQ2+09/rXFwSMlEX9PFZAFr0IzjcYDrd1
         jC0W6D9OpO7pP+p/7FXG+9tvcBP3XnG/UlDZypcw4aaG1xeEWlSfVAKr0sJM86zCP/il
         XpoINRjWJgeRS7CK8uVG8OZf1Ql3XpRD+/xq+Qfr7vEvUjK0ijqEwuFgPfWlt+p688oi
         NFqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6w0l/5/OLmmiPtUBy12XvNW481vH2W+yw4PJnFK30wA=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=i3Bpk7ZTzf0ex5JlNe2+3vHHV9trCEQynVQ4FazG32epzqDSG5CCqdNs4CKLxSw8b1
         R0vh/rdPPxM2e1ioa0x3XBdK0sHbvxu1jl3LDXtbcCASmHaj4uWrE3P0yBXq84sElBvQ
         Fx5rbKlOXs5w6bAW/Cm4s8Yfj2GCMExVpFIlPUcK8QuJl9Q3MxYkAS0AzcO3NNv6ortU
         5Snvt2lKGcZYspfW/Q+MiuxivKREJFehavA8j0aAdBeSNVOAqz6hBPXfX0yjsRX76knr
         DKsQZOWqw45K0/Qp4g8H3F14q2t9tBXUjZHn9UfFF2POxdbbmzdU56EDRJq9v2HLPyv8
         RPSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tTmhSqri;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::cf as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-207.mta1.migadu.com (out-207.mta1.migadu.com. [2001:41d0:203:375::cf])
        by gmr-mx.google.com with ESMTPS id j28-20020a05600c1c1c00b0040476a42269si303689wms.2.2023.10.23.09.24.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Oct 2023 09:24:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::cf as permitted sender) client-ip=2001:41d0:203:375::cf;
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
Subject: [PATCH v3 06/19] lib/stackdepot: fix and clean-up atomic annotations
Date: Mon, 23 Oct 2023 18:22:37 +0200
Message-Id: <8f649d7e5919c56bcc5d2d356c9584fdcb87800e.1698077459.git.andreyknvl@google.com>
In-Reply-To: <cover.1698077459.git.andreyknvl@google.com>
References: <cover.1698077459.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=tTmhSqri;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::cf as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Drop smp_load_acquire from next_pool_required in depot_init_pool, as both
depot_init_pool and the all smp_store_release's to this variable are
executed under the stack depot lock.

Also simplify and clean up comments accompanying the use of atomic
accesses in the stack depot code.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

This patch is not strictly required, as the atomic accesses are fully
removed in one of the latter patches. However, I decided to keep the
patch just in case we end up needing these atomics in the following
iterations of this series.

Changes v2->v3:
- Keep parentheses when referring to functions in comments.
- Add comment that explains why depot_init_pool reads next_pool_required
  non-atomically.

Changes v1->v2:
- Minor comment fix as suggested by Marco.
- Drop READ_ONCE marking for next_pool_required.
---
 lib/stackdepot.c | 29 ++++++++++++++---------------
 1 file changed, 14 insertions(+), 15 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 128ece21afe9..60aea549429a 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -225,10 +225,10 @@ static void depot_init_pool(void **prealloc)
 	/*
 	 * If the next pool is already initialized or the maximum number of
 	 * pools is reached, do not use the preallocated memory.
-	 * smp_load_acquire() here pairs with smp_store_release() below and
-	 * in depot_alloc_stack().
+	 * Access next_pool_required non-atomically, as there are no concurrent
+	 * write accesses to this variable.
 	 */
-	if (!smp_load_acquire(&next_pool_required))
+	if (!next_pool_required)
 		return;
 
 	/* Check if the current pool is not yet allocated. */
@@ -249,8 +249,8 @@ static void depot_init_pool(void **prealloc)
 		 * At this point, either the next pool is initialized or the
 		 * maximum number of pools is reached. In either case, take
 		 * note that initializing another pool is not required.
-		 * This smp_store_release pairs with smp_load_acquire() above
-		 * and in stack_depot_save().
+		 * smp_store_release() pairs with smp_load_acquire() in
+		 * stack_depot_save().
 		 */
 		smp_store_release(&next_pool_required, 0);
 	}
@@ -273,7 +273,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 
 		/*
 		 * Move on to the next pool.
-		 * WRITE_ONCE pairs with potential concurrent read in
+		 * WRITE_ONCE() pairs with potential concurrent read in
 		 * stack_depot_fetch().
 		 */
 		WRITE_ONCE(pool_index, pool_index + 1);
@@ -281,8 +281,8 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 		/*
 		 * If the maximum number of pools is not reached, take note
 		 * that the next pool needs to initialized.
-		 * smp_store_release() here pairs with smp_load_acquire() in
-		 * stack_depot_save() and depot_init_pool().
+		 * smp_store_release() pairs with smp_load_acquire() in
+		 * stack_depot_save().
 		 */
 		if (pool_index + 1 < DEPOT_MAX_POOLS)
 			smp_store_release(&next_pool_required, 1);
@@ -323,7 +323,7 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 {
 	union handle_parts parts = { .handle = handle };
 	/*
-	 * READ_ONCE pairs with potential concurrent write in
+	 * READ_ONCE() pairs with potential concurrent write in
 	 * depot_alloc_stack().
 	 */
 	int pool_index_cached = READ_ONCE(pool_index);
@@ -413,8 +413,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 
 	/*
 	 * Fast path: look the stack trace up without locking.
-	 * The smp_load_acquire() here pairs with smp_store_release() to
-	 * |bucket| below.
+	 * smp_load_acquire() pairs with smp_store_release() to |bucket| below.
 	 */
 	found = find_stack(smp_load_acquire(bucket), entries, nr_entries, hash);
 	if (found)
@@ -424,8 +423,8 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	 * Check if another stack pool needs to be initialized. If so, allocate
 	 * the memory now - we won't be able to do that under the lock.
 	 *
-	 * The smp_load_acquire() here pairs with smp_store_release() to
-	 * |next_pool_inited| in depot_alloc_stack() and depot_init_pool().
+	 * smp_load_acquire() pairs with smp_store_release() in
+	 * depot_alloc_stack() and depot_init_pool().
 	 */
 	if (unlikely(can_alloc && smp_load_acquire(&next_pool_required))) {
 		/*
@@ -451,8 +450,8 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		if (new) {
 			new->next = *bucket;
 			/*
-			 * This smp_store_release() pairs with
-			 * smp_load_acquire() from |bucket| above.
+			 * smp_store_release() pairs with smp_load_acquire()
+			 * from |bucket| above.
 			 */
 			smp_store_release(bucket, new);
 			found = new;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8f649d7e5919c56bcc5d2d356c9584fdcb87800e.1698077459.git.andreyknvl%40google.com.
