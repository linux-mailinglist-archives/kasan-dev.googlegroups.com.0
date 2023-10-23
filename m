Return-Path: <kasan-dev+bncBAABBZV33KUQMGQEG72T7XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id E6D507D3C42
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:23:03 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2c503b47880sf18834961fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:23:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698078183; cv=pass;
        d=google.com; s=arc-20160816;
        b=r3rNWTFZzJX54XmScyK6hWyQugztlfy/UXVB4xFMM3gf4I4dSCfGBiaaeVSkOafeRa
         gXnDvTZRLldSUrOwaYBxx8cxd/HaCmYyxmAnnDfZ78YTyvf1d+jAOBGpIPM5jXNihEdc
         wFfefAvH4lYfFd0uofB/WQruQVpGhv1VfcEWP45x0GyzWq0xZKHubOhFza+ZhCyCyKc3
         BZ2zQ7GxGyZYdT9xwfHLkhQ5qjNLpHYYevPdMR5+wd7pi3Kr12HdkLbMEAWsfqM5I/VP
         GXymoPh+rRvslSy5psmnN9vfN7E1RxPPmsukStv89UnF/eSRwtHskPV6EVd/wh5SUnVv
         hAnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=E3KKVlJlh9eZn6ds2g8kuoobzg1pYW7z/Lr9b5o3BMA=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=sSrypGH/Eicjj5ZbN0iuXBjwOoxN7WWhJMHchLuPHdmJobjF5X2DwPbTowbBGFbmsS
         3RdChEXKxYdmCM79OtIBxrwSR4oClFGx2v0WKfNAZ6TIgohpztNOZirsqihOZMcvM1iV
         naJRjvG69vSnIP6T1UcY4Bw5t9JtyWRrtIGimsvI7dZuHfpVgpqcjN+KCpsQq91vXJxU
         LggLAmZ+379gzVgRmqkUWvxrDGOpeUe/B+N8GqtJIXB5pfv7enbK2NbRxk6OAQMpJaiq
         dJLp2XA3jRN8DfDgb5bHtdA2TuZ+LhosFXRVI5QFA+9EE4ZBeWEa0R9bbIz+l5ZSzBqu
         7Z6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=MDW7AbX4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.203 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698078183; x=1698682983; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=E3KKVlJlh9eZn6ds2g8kuoobzg1pYW7z/Lr9b5o3BMA=;
        b=LmDPv/XpmnswNQRIN7pCFhBrh8t1mYdhjsj/fY2R4rwOkolSyqtgGUTl7YKTg2PgVj
         +V8/chSwIvuIphFfvOxDDRLiCpRCdfdNcbT9RTg5WEKLc4cA+BrIMlji4s1Fp+t0lFxD
         /IjSvY+7JnaomHa3iFAFXrTSc0H8Mh/ziCxnW7QcAy9/2vG7JikdPi8m7danv0bwFE+d
         7FQ0iyjghP5YTH9M/YBGymsp0UgbNXIK0/5zkkrap6PfOYW1Tn4XELytRpTR2goQs6uk
         M3SSMXBfsrnPG9nM+GaIB19pn5H/7Jg7y7NQ6KfFFPPrbRdGfam8DMboS3YJBQHj4jBb
         JXoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698078183; x=1698682983;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=E3KKVlJlh9eZn6ds2g8kuoobzg1pYW7z/Lr9b5o3BMA=;
        b=PeDaWEBmuUUoH45rxpMfLNjUlWwzpYGsJCb4imR7gV+xWK6A+f0AVc8GVroXN2nkhy
         1zPMEFa1IiwLhUlT3sTm3j5qKDi02kdytgLgJkpoBIH46vPcHjHbgOCfGl176H+Cfn7L
         5MnGy3ocVsJ1ZxNx6rnjSMLNUdPJJHwnjVt0P4VpG3nJD53DvggG737N1wMQ/Hog3sqn
         Bo9moD6G4mGCNJ3T5lAPLJOv3IefNlvavwjduopXrTXvR3IMY2Tq3MwO1L3B85mSajKS
         XxNgNW+oUXWCAWFok2/TW1wOKyHzKv4luMAqGIkMxh8yeomPUCutNQH13E+ehggP1Gmr
         /3Lw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxONteYy9Ej3vaCCwsssU7lRSbA5nErPRFtxECZeyYsmqkN/27Q
	2EXG02//O+IBYY5zvTDiWLI=
X-Google-Smtp-Source: AGHT+IFL/SqqaRoj0hdIS6bhYIKNbM88ORxOlF5aBKPxKRHYFSjr2eLXYoDgbag4qMjHXQMYO6g95Q==
X-Received: by 2002:a05:651c:221b:b0:2c5:22cc:eb38 with SMTP id y27-20020a05651c221b00b002c522cceb38mr3682031ljq.1.1698078182528;
        Mon, 23 Oct 2023 09:23:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:1457:0:b0:2c1:261b:7353 with SMTP id 23-20020a2e1457000000b002c1261b7353ls106770lju.0.-pod-prod-00-eu;
 Mon, 23 Oct 2023 09:23:01 -0700 (PDT)
X-Received: by 2002:a05:6512:3196:b0:500:7bf0:2b91 with SMTP id i22-20020a056512319600b005007bf02b91mr4412661lfe.13.1698078180772;
        Mon, 23 Oct 2023 09:23:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698078180; cv=none;
        d=google.com; s=arc-20160816;
        b=O93vYikWVVX1kfYFlx1BHh9moBFDhbL4wGL6jYHEP7Pz8cCsW3FoUTqY+bI5GPGcVn
         sjyUTKTo1Mnsv5v+XEbyFjg1jHdOhIO1qXelbM4agbGwdbdK4RGf7uG/Sq4U2igw3+LH
         gSHnZFEjb+d/7p0Mm54KGoh0/DOzQieWeinVx6/6QQNXxFHFdfD0vjLgGnArUHoVPjMp
         6oO14G1CyFd+mr2VgMZTU1bK2czi8nUgDesfotxzdW6W76/yFuQK7sUjSAdD2snLakS6
         OvbXjzhKquU1uJYRPW70RRG/ejaQyfRjSF6nNfcABdrpqjQGi/GAqRzrKdczae7iszaf
         lHwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9Tw+dU2o5sfOuuXbX4FJVP/5BAKc6p0/nQ7cBmUzv5Q=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=YAFCidXGVbuqXjr+4yHxvpyttLitkbv0VbTSbYGz8cwdtH5BQabzAp3xAhNT95HhJU
         +n3Puytj8HQHMX4OL/4QVafDb6FTyOJ9k8qW4RMQHqWIkg/K6/IXtREJ8UbYtWxrY6xd
         x1SXacqNQnLHIrTLUvmmtZrvWUBZu5cMR/A+2XWafaYTHjvednsOMFBIbA6dnIvua26c
         UmdMimttPQ1ucZ2/1s5cSkapSQuqm2ZDlh1Lf8HchAiRYCmLLYNrcwJUTX1rW3vNOiJv
         IzAgjjy8euvWhskMRgugjDDqBbOurr07I7VLuikByhuihvJZg8geSp+1B53qoxzLwhOC
         hm0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=MDW7AbX4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.203 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-203.mta0.migadu.com (out-203.mta0.migadu.com. [91.218.175.203])
        by gmr-mx.google.com with ESMTPS id d29-20020a0565123d1d00b005008765a16fsi311383lfv.13.2023.10.23.09.23.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Oct 2023 09:23:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.203 as permitted sender) client-ip=91.218.175.203;
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
Subject: [PATCH v3 04/19] lib/stackdepot: add depot_fetch_stack helper
Date: Mon, 23 Oct 2023 18:22:35 +0200
Message-Id: <48b71b2ff972088aacb3466d4de5afd46b6aa7e5.1698077459.git.andreyknvl@google.com>
In-Reply-To: <cover.1698077459.git.andreyknvl@google.com>
References: <cover.1698077459.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=MDW7AbX4;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.203
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

Add a helper depot_fetch_stack function that fetches the pointer to
a stack record.

With this change, all static depot_* functions now operate on stack pools
and the exported stack_depot_* functions operate on the hash table.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Minor comment fix as suggested by Alexander.
---
 lib/stackdepot.c | 45 ++++++++++++++++++++++++++++-----------------
 1 file changed, 28 insertions(+), 17 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 482eac40791e..9a004f15f59d 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -304,6 +304,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	stack->handle.extra = 0;
 	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
 	pool_offset += required_size;
+
 	/*
 	 * Let KMSAN know the stored stack record is initialized. This shall
 	 * prevent false positive reports if instrumented code accesses it.
@@ -313,6 +314,32 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	return stack;
 }
 
+static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
+{
+	union handle_parts parts = { .handle = handle };
+	/*
+	 * READ_ONCE pairs with potential concurrent write in
+	 * depot_alloc_stack().
+	 */
+	int pool_index_cached = READ_ONCE(pool_index);
+	void *pool;
+	size_t offset = parts.offset << DEPOT_STACK_ALIGN;
+	struct stack_record *stack;
+
+	if (parts.pool_index > pool_index_cached) {
+		WARN(1, "pool index %d out of bounds (%d) for stack id %08x\n",
+		     parts.pool_index, pool_index_cached, handle);
+		return NULL;
+	}
+
+	pool = stack_pools[parts.pool_index];
+	if (!pool)
+		return NULL;
+
+	stack = pool + offset;
+	return stack;
+}
+
 /* Calculates the hash for a stack. */
 static inline u32 hash_stack(unsigned long *entries, unsigned int size)
 {
@@ -456,14 +483,6 @@ EXPORT_SYMBOL_GPL(stack_depot_save);
 unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 			       unsigned long **entries)
 {
-	union handle_parts parts = { .handle = handle };
-	/*
-	 * READ_ONCE pairs with potential concurrent write in
-	 * depot_alloc_stack.
-	 */
-	int pool_index_cached = READ_ONCE(pool_index);
-	void *pool;
-	size_t offset = parts.offset << DEPOT_STACK_ALIGN;
 	struct stack_record *stack;
 
 	*entries = NULL;
@@ -476,15 +495,7 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 	if (!handle || stack_depot_disabled)
 		return 0;
 
-	if (parts.pool_index > pool_index_cached) {
-		WARN(1, "pool index %d out of bounds (%d) for stack id %08x\n",
-			parts.pool_index, pool_index_cached, handle);
-		return 0;
-	}
-	pool = stack_pools[parts.pool_index];
-	if (!pool)
-		return 0;
-	stack = pool + offset;
+	stack = depot_fetch_stack(handle);
 
 	*entries = stack->entries;
 	return stack->size;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/48b71b2ff972088aacb3466d4de5afd46b6aa7e5.1698077459.git.andreyknvl%40google.com.
