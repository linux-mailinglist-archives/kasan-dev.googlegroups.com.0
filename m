Return-Path: <kasan-dev+bncBAABBZV33KUQMGQEG72T7XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E9967D3C43
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:23:04 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-50483ed1172sf3371532e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:23:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698078184; cv=pass;
        d=google.com; s=arc-20160816;
        b=MKNJruyQGymdl0Xz3Q9Zl0fHdnZ3g5FbEXdSuubpjXLSBTSJNtTHxHgbYPn3Fefcto
         OsyRmrMMoG4drYyTNHz0oINYC5RdFpG7dQh7jujvRXHGD9pfwVweVAdPuBAEbdYc6Lra
         DbzZAlD0ezebxAqoLnR5RwT/8u7oA3D4LzZL0Dbw39mpq5yEVauGI0DvVG/gC/WWWjJI
         cArkGFMwzuFeb8faOS1ht1tXHYElw2uoLIO78Wze7KYgG4gDB28syt9/UMwSX2q7L5/w
         CPdRVpKqOyyRqK7yymIs97hFs+Mbab4lgnPnpZWXjufhbbDv4KNvLsw+43jkvyY1X5Tj
         59HQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ChZjDIRkVAbSqKx6wyb4+39Jtuir0WFAnUVI2BAhMuA=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=fqBGqBGCXQ77nokwKDe6f4xzWBI3B6UJdMD70RLsA5niKRSiJMgOfjwlAN7MBu6LgM
         cOk5JlK+wUfwTiVRnmWvB4mSxdbPvZZIR6lBg2bWQUMmSN90xdlolSkQ5y0cwJDd0spH
         P77z96HquA3E61OEEFu3+5EWzC2gu0KvD5dLyen5BFtyD/D4JaOQZaPS7j89EpCj0FvD
         +GHSO5bq5k8MM9CeSl5lALJ2se0bTr4BNr5qkJtmqsX5zKGVMYE0iI3EuQTjcjROke5H
         UKiTOZ3vjm5Gf05Uz6c5S7h7LdFvId038UnzmsSv3sttTevI9+Oi0dMUjzdzTaWIcWlE
         FqOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=rkq81ZIH;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::d2 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698078184; x=1698682984; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ChZjDIRkVAbSqKx6wyb4+39Jtuir0WFAnUVI2BAhMuA=;
        b=imSZtKdCvc4j+N5t0jqe9XuOhUE0EGf/vBjl3C0GFiwvNuKqSjGaVcTjRlSz1/bSIa
         Tr57bZX8gzlU9ItLkV85Nu5mr5v+0MgsKKo5KEP6sTA4/BVV8FKTlHO3n4IpJhC2E1Zx
         jM58Sy9YB67GtwySF7zFFIP+TGrwPZPbWtBUVbRVOVKc8VQ5xlmFUmgTBSv7aeWWnBFi
         lXVMVB4PDiG1TysDim1dzWcNJdKDJ6ZGfW2IWsmqy7CnBFx5FYAC9HbI4WxRcOsbj9ib
         2eqUJuK+VbvZ7SpjXkOAqj6wqFAq7UMCJMkXVmlQjdmcUKl8mN5KOL/IbDQxy95M+tV2
         //5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698078184; x=1698682984;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ChZjDIRkVAbSqKx6wyb4+39Jtuir0WFAnUVI2BAhMuA=;
        b=RTDeldCVlGSGZZyS2WdGIzsD3hEfUKoU4dtcKQrc+dVuVRwlp03gUbD5d7bCD2p+4m
         qSV7GQrJxwMb+ro4aMSgsUP/wkNlZGpky3zO1DRMO+0DMJzuZIGANp+UgUbEtLAG+GOX
         KR1oC0603WmbdzF69sq1Oi+gcbJUQQmsMsru9+4Q5C87R/0YzOMVrQTgtKQUz1RDKeqA
         MuinVNXT58qS4Tscp2HvHOQfN+YVlgx+NAk2D4nmL8TP0dy4dhxTqs6RtJqdHz5UNsNr
         pBuN009j7BabzLmpT63p+wTiwafBp1FwWVf8CcQjTGXcxYN5qA570Haih2bUw+gpQ2V0
         NqtQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyHkAPk+zh4mWFwYgAIh30mn7Q+SO14UT/e4xnK1HX/nWpMDpbS
	uZaLxBhgXom5dhyzCWVBOdk=
X-Google-Smtp-Source: AGHT+IGWLTA0JUE26Pw6hEBONfYeZkeGQanQ13bh+R/I7OpoEgHyEhMI+bBFB876mKepjqoHKc9lmg==
X-Received: by 2002:a19:2d02:0:b0:507:9ff3:d6ec with SMTP id k2-20020a192d02000000b005079ff3d6ecmr7343153lfj.50.1698078182557;
        Mon, 23 Oct 2023 09:23:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:f28:b0:53d:b3c3:2112 with SMTP id
 i40-20020a0564020f2800b0053db3c32112ls112275eda.2.-pod-prod-01-eu; Mon, 23
 Oct 2023 09:23:01 -0700 (PDT)
X-Received: by 2002:a50:c357:0:b0:53f:e1b2:912e with SMTP id q23-20020a50c357000000b0053fe1b2912emr6265592edb.41.1698078180982;
        Mon, 23 Oct 2023 09:23:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698078180; cv=none;
        d=google.com; s=arc-20160816;
        b=mXWt9Hc3mEOP2qgkUIyZpLNLwrls8+th3EI9vj7/2hIaajCgWZk+LQDnuH/jo3rgQ5
         TkspH9sSSTL9rTj2KoRpyfEOZHnAf9yQ2MSX44A07jNS4Lk69pHSbEb9c9ykQPU//DCQ
         y+m7gkdkZDcYP5QsSYXH8Kg/fEnhBKV9EQGoWDRV5g61B79q26dvUMAcYS4aDjOzDopX
         ofkDUysxCOvmHcp0muyc0TXdeI0lMIUskhqOJDbmLp1C+x851yH6i+wV599tJN2OL9Ow
         xoRBjG0waaIvpuQUD/87UxXy+N2lqAKPw1KZ0KXzfcg9EbDhKFAWCvJvckA54Hy1viNM
         eCnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=bMe0IukHdtXUzp2BGVWle8stWPjWZ8/o4+6QYAoowVk=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=OQC4rrMrosZ35NOMO3gDuaHocEe6DB5aXtRE9w7InN/fAt3uXZnBQ2B+AX+//4xxkJ
         ThdGtyR9c+p5LZ8SsujLfgsH1gBHcuEtDnGq3wp0kCGXY4p8Y1mtm/lCO3wnXOomwacg
         K/w4MJ+DRSja+mSG4W9dCwC4Y7cTqcpJrfb3Y/c5nS/3BQ2RuB5KIa1aUWepkTcKFLst
         YDjsziOI98l/El6vmrmDYtQ+HD/hTIBQNNtgmB/Kj2yLt27Ce5DThHieW1UBts+PvP0N
         JvTi/FsoVNGxnPDNK6r3qcq4zfRf6066pK+opseu7hj/rpVV9IiU8YD2LYOnB9Gs6h3X
         aRqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=rkq81ZIH;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::d2 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-210.mta0.migadu.com (out-210.mta0.migadu.com. [2001:41d0:1004:224b::d2])
        by gmr-mx.google.com with ESMTPS id cx16-20020a05640222b000b0053e26876354si221868edb.5.2023.10.23.09.23.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Oct 2023 09:23:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::d2 as permitted sender) client-ip=2001:41d0:1004:224b::d2;
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
Subject: [PATCH v3 05/19] lib/stackdepot: use fixed-sized slots for stack records
Date: Mon, 23 Oct 2023 18:22:36 +0200
Message-Id: <4340f57fa82fde81e00f64f98d69ee4a5d5ed9a8.1698077459.git.andreyknvl@google.com>
In-Reply-To: <cover.1698077459.git.andreyknvl@google.com>
References: <cover.1698077459.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=rkq81ZIH;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::d2 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Instead of storing stack records in stack depot pools one right after
another, use fixed-sized slots.

Add a new Kconfig option STACKDEPOT_MAX_FRAMES that allows to select
the size of the slot in frames. Use 64 as the default value, which is
the maximum stack trace size both KASAN and KMSAN use right now.

Also add descriptions for other stack depot Kconfig options.

This is preparatory patch for implementing the eviction of stack records
from the stack depot.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Keep previously existing Kconfig options not configurable by users.

Changes v1->v2:
- Add and use STACKDEPOT_MAX_FRAMES Kconfig option.
---
 lib/Kconfig      | 10 ++++++++++
 lib/stackdepot.c | 13 +++++++++----
 2 files changed, 19 insertions(+), 4 deletions(-)

diff --git a/lib/Kconfig b/lib/Kconfig
index c686f4adc124..5f3fa3659fa9 100644
--- a/lib/Kconfig
+++ b/lib/Kconfig
@@ -710,10 +710,20 @@ config ARCH_STACKWALK
 config STACKDEPOT
 	bool
 	select STACKTRACE
+	help
+	  Stack depot: stack trace storage that avoids duplication
 
 config STACKDEPOT_ALWAYS_INIT
 	bool
 	select STACKDEPOT
+	help
+	  Always initialize stack depot during early boot
+
+config STACKDEPOT_MAX_FRAMES
+	int "Maximum number of frames in trace saved in stack depot"
+	range 1 256
+	default 64
+	depends on STACKDEPOT
 
 config REF_TRACKER
 	bool
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 9a004f15f59d..128ece21afe9 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -58,9 +58,12 @@ struct stack_record {
 	u32 hash;			/* Hash in the hash table */
 	u32 size;			/* Number of stored frames */
 	union handle_parts handle;
-	unsigned long entries[];	/* Variable-sized array of frames */
+	unsigned long entries[CONFIG_STACKDEPOT_MAX_FRAMES];	/* Frames */
 };
 
+#define DEPOT_STACK_RECORD_SIZE \
+	ALIGN(sizeof(struct stack_record), 1 << DEPOT_STACK_ALIGN)
+
 static bool stack_depot_disabled;
 static bool __stack_depot_early_init_requested __initdata = IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT);
 static bool __stack_depot_early_init_passed __initdata;
@@ -258,9 +261,7 @@ static struct stack_record *
 depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 {
 	struct stack_record *stack;
-	size_t required_size = struct_size(stack, entries, size);
-
-	required_size = ALIGN(required_size, 1 << DEPOT_STACK_ALIGN);
+	size_t required_size = DEPOT_STACK_RECORD_SIZE;
 
 	/* Check if there is not enough space in the current pool. */
 	if (unlikely(pool_offset + required_size > DEPOT_POOL_SIZE)) {
@@ -295,6 +296,10 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	if (stack_pools[pool_index] == NULL)
 		return NULL;
 
+	/* Limit number of saved frames to CONFIG_STACKDEPOT_MAX_FRAMES. */
+	if (size > CONFIG_STACKDEPOT_MAX_FRAMES)
+		size = CONFIG_STACKDEPOT_MAX_FRAMES;
+
 	/* Save the stack trace. */
 	stack = stack_pools[pool_index] + pool_offset;
 	stack->hash = hash;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4340f57fa82fde81e00f64f98d69ee4a5d5ed9a8.1698077459.git.andreyknvl%40google.com.
