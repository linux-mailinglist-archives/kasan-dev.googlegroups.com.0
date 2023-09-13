Return-Path: <kasan-dev+bncBAABBDG4Q6UAMGQEBC5D7SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 794BC79F007
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:14:54 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-31fa20ed472sf6670f8f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:14:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694625294; cv=pass;
        d=google.com; s=arc-20160816;
        b=xy3m+Ty/wzK4F+EJEKatIdoAwiYqePnaI3fBg/YaIo+UsP+rgFIDjsQ86EKtsvlaxK
         Q+d6kAYCQjTY0rTCAVSYT7KNiYF8VkdA8pRYAFsWTLOT57Q6nsVSh+6FNsuZUc4DXNVZ
         Ki0GNoFFIYcXrGoeoD0TM/mtzo/9nIdCosqvzf4KGbEfQtyiEFQc1D9y1xyhd1Nce5Jg
         OYuUkJSZIzuIWg5t/OGLmq0Bexed+uGZXjQS2sgxrptuPY+pfHdX7oVU7s0YWf1JvXhG
         zQETk/utfWVZXhoXLUmvaV6uNLimd314GOPn3e9MCcWkxxtEdzRCWD5jcHiaxnDcm8xr
         xEdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=RlwO4DjjStxZ6++wSI5Br/3t3eo5W/o/yK+v8xG6qvM=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=HWLA50aISuDkGXLNUmsTUVTkq6jCtxF+O4OgQAgNfhSIDAJhFCoj7XY3FM3NvBrpcU
         zTgg8weQOH/T9Z5Oqqt4MxNAqofPVmYNoeXyMofulU1RABbQWwncC8VZQLfV/FberMtC
         L8FjdzYkzAub3sT15naqvYBc4JuXvdfyywApDSIg7xxMzJRiS7iyxQonjRY43Oibhcrm
         Zw0iVQ3WR44dlIdy5JS2jdYpH0mKxxqxTlo9C5nYGmfi3AJAEQaNE0qYFiwPipymnjvc
         EdDalnY06tPvxnoDeLHSGRuyVIVQ378QSkSvWW8hVCC0kE4dHMTmH+w2vngyZFS/OdZZ
         vE7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=S9us7jlk;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.222 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694625294; x=1695230094; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RlwO4DjjStxZ6++wSI5Br/3t3eo5W/o/yK+v8xG6qvM=;
        b=wQ/QCXM/eMvQsvhGxQ0r1V0lSD3hJnCxa7sbHwqPuunllFTE8F19NJT0vDa6uc26ya
         A0QZ4SwAuZXbYLXMYtZaijSxIjOPlf8UOOnbNfsN+K9jkAzI2YHXjrS/vZR5J65MvNHQ
         TyFVEvLGuuVCmMvIv6G2Tefdr6av5c7n1Vxq7tNv8hi37SpG4Lg70VJXzfB46hI8MEuE
         GyrHtgtvJIebjXMb1XIbJPoDIBnH6n0KGB15KbgkRFSAcf/KfXdtT3KtQ/JYDatIFBN+
         X2EBuOk6ADCu87dqXKrgBFQg1plIQxYI0VeSZRvpvUt0+YI2ZaobpDrORyGjcUInsIxL
         +TaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694625294; x=1695230094;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RlwO4DjjStxZ6++wSI5Br/3t3eo5W/o/yK+v8xG6qvM=;
        b=VuRUPQyXATWgJ7aOgYLDyZ+MBoK2HrjeVmngo0bAEghAYfVnHre7l2ktJ3BHkbSv0C
         I0dalzAhovZSbcVHd0rTJWbLwk1EfajpkgGy7ZLjXkcu1jDsrLxnC8asI/vhSmPV8oO8
         HXcxdsRc4UZjSukIwITxIPNugN7qkmqAGhTJJ63aqdtGocHngmPZ0ZcwsPkdlkZ1Vxy6
         zpz3ihGGfAXwGh35CU+x2MeTh67aGlJ+mYJpyaJ+Yi1wuh6WvDvHrIDb7dOee5OxXebF
         EI9niqG93YYvFH5+Q1HrL46mK2wCRWWn98vKcwmkB/ehHwV6YylvRo1LH75XnHN6ROUF
         JgNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxfw2us+wLdH2r83gQ7z4Relg2mlNy2I7+K8lxJDJrwJV2FPD/O
	CrfKUAeVli3jnZd6VV+6JRc=
X-Google-Smtp-Source: AGHT+IG32MqjMURrqChxG257HlwjpqW9pawLr4OuvUvCnplN3kMXlLXtzWDT5I4SE3HGu3Hlxl4LZw==
X-Received: by 2002:a05:6000:11d1:b0:319:7b96:a1be with SMTP id i17-20020a05600011d100b003197b96a1bemr2564355wrx.71.1694625293214;
        Wed, 13 Sep 2023 10:14:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:500f:b0:52f:489a:d0f with SMTP id
 p15-20020a056402500f00b0052f489a0d0fls1009635eda.2.-pod-prod-08-eu; Wed, 13
 Sep 2023 10:14:51 -0700 (PDT)
X-Received: by 2002:a05:6402:8d6:b0:525:7d81:71ee with SMTP id d22-20020a05640208d600b005257d8171eemr2742975edz.15.1694625291856;
        Wed, 13 Sep 2023 10:14:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694625291; cv=none;
        d=google.com; s=arc-20160816;
        b=hFBYFrMMMcDrS/PSV5cPqhzCAM7ry03R3Csc3p41uCGnE456t8nN++NCwD3BbL23QE
         gnJrZcaflSTv0A4yXtlgesjj8wPrStWOnv46w6ogYJCEQbBwE9FcQalSknqm6vNElDwP
         ai03Nsgim0R2cC70WsY9hELm6IOOGA9G6jluXblqH5lZ5oelkcZ6UInN/bjFcg1wF9Is
         sPtHCugkak1XPOiUivEpaOHw2LKVRB+0AmSYrNmHBHDx/G43mfX4feyrone14B2g7OA1
         PFtlpPbDLKxBeSpmBjs7VqgEeiHiv3d8JXV564pHr0mm+sNP+AIB4aXtRGzaw7vznG+e
         MgWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gml8DcgHPrqnYJfUQnrXQLUWDOAsSsS+HJ/vnfgqmKg=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=EWdVzDfMy2g1U0acCw3gYstlWZnjAP+yrI5y/DoXdcmUrth5ysU67dzP0uItkoyETd
         qfPMDMLUCLDVaY2fVTYDddwQjLB5Br425nxlvrvY83pmeLx2ghVkpDZxi6LM5IgRItYj
         MTYxdrdYAQmVinl7z3o1ebHaq8ONC3y8J3jEGCM673/wUoOt3vKFRzYn6Uj1WZZ7cQy7
         o85QKg3KxNif6UoNtamRq38R9tQrJLXR49PflvBnTyqak6cV9hUfFkjWS60EtVUwQ5Bg
         oVwQuSVYBXcNI4xN9srLOmKsEqYBieBZDVdKJWB9hxyBBX7yqFPvQ0CMKje3LVOhIMOR
         lztQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=S9us7jlk;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.222 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-222.mta0.migadu.com (out-222.mta0.migadu.com. [91.218.175.222])
        by gmr-mx.google.com with ESMTPS id q8-20020a056402248800b0052c258ede41si1021224eda.0.2023.09.13.10.14.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Sep 2023 10:14:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.222 as permitted sender) client-ip=91.218.175.222;
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
Subject: [PATCH v2 05/19] lib/stackdepot: use fixed-sized slots for stack records
Date: Wed, 13 Sep 2023 19:14:30 +0200
Message-Id: <658f5f34d4f94721844ad8ba41452d54b4f8ace5.1694625260.git.andreyknvl@google.com>
In-Reply-To: <cover.1694625260.git.andreyknvl@google.com>
References: <cover.1694625260.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=S9us7jlk;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.222
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

Changes v1->v2:
- Add and use STACKDEPOT_MAX_FRAMES Kconfig option.
---
 lib/Kconfig      | 10 ++++++++--
 lib/stackdepot.c | 13 +++++++++----
 2 files changed, 17 insertions(+), 6 deletions(-)

diff --git a/lib/Kconfig b/lib/Kconfig
index c686f4adc124..7c32f424a6f3 100644
--- a/lib/Kconfig
+++ b/lib/Kconfig
@@ -708,13 +708,19 @@ config ARCH_STACKWALK
        bool
 
 config STACKDEPOT
-	bool
+	bool "Stack depot: stack trace storage that avoids duplication"
 	select STACKTRACE
 
 config STACKDEPOT_ALWAYS_INIT
-	bool
+	bool "Always initialize stack depot during early boot"
 	select STACKDEPOT
 
+config STACKDEPOT_MAX_FRAMES
+	int "Maximum number of frames in trace saved in stack depot"
+	range 1 256
+	default 64
+	depends on STACKDEPOT
+
 config REF_TRACKER
 	bool
 	depends on STACKTRACE_SUPPORT
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/658f5f34d4f94721844ad8ba41452d54b4f8ace5.1694625260.git.andreyknvl%40google.com.
