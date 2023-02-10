Return-Path: <kasan-dev+bncBAABBGXJTKPQMGQEYMYORHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id D525469291A
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 22:18:19 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id cf15-20020a056512280f00b004a28ba148bbsf2756502lfb.22
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 13:18:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676063899; cv=pass;
        d=google.com; s=arc-20160816;
        b=TFOWqCdkvQaiZvb9hhI7bQIJniL5RpK27ZVglqYzqQPqJI8ZCn+vNsNtb+hOY7JJIf
         VB3att529oTbfGa36LjjapbR1R2RKTpzwdJ22OyzZH3bmrTAnj5NJ1/HKUD7XrnVylxA
         LgdcQTol3iI1Ay3OgDGvD1+pDFED3yrUWznl0N7QYVX6in6Gklkl2pEUfB6LQAXPmQ1l
         HLKbw2fFQu739CCOSNI6MktAYldn+B0I59Zdd1CSrNykK+jNr1ztDXx/pwT3z/M6xpT1
         proikJjYe2xwLGtwB4c1Ty6QcW6iJIsZzN+hlxVLm8y6Toh5NUeSDsKSXpZyPJgqlbg2
         tn0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MZPrp3RplEizcRBOCsBGKIugRol0wBfkYLVrPfskCLo=;
        b=InJ3Nm3SzLJ/RdiAfVSE3Sm8WTi3hgIuydiYv1nVmxNAU1ao0j9750bCwRG/S4j7Jd
         LwuRbHrR8Cd9oq5JFPF8XZs+MriesGogMIAmb5oeofSE6rPOLHqQOqcdN35xm/CJH24K
         bsD8cKhXgJmZfsvvmSyA3JepQBOlASTF1a8t2H4lEK3GhmQIPM9/lWfW9LsOUi7WQFnD
         ONSOTnr4MIa3o1PBdisNPBikwbvdbXZ8yDlU/gTIlungOhla9V14s/R0LlTJZ0GoS8gI
         ZEFqE4y0KLoP/Ol+EaJLahFgvEk/9HpqIsXVzyS5B9ahN0dXbxwYhtz5bns0QESrohr7
         +6Dg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=b9EI77+L;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::54 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MZPrp3RplEizcRBOCsBGKIugRol0wBfkYLVrPfskCLo=;
        b=RB77T51uVYMq2jwnZmiUuOk+zOnpVKjjdtBRIYwQ7L80G8w6nnXpS9nYAgjKGmSO9/
         GcjykG3WhotPqJXD+zguAuKULftccpZSGHAq/xlzKCLBjVPqhimicaqIvuy2WjPU4Rto
         UMDZSEEGrO8PyyCIOUj8uZsbfpMJAZAlkn5z/BNv4j7dVa1QM5uAaw9W0UnRk8f0/raQ
         ju1a809KKkbxmK7Yo7XHkoXYEQTcUER/oFkugLZ5egZs3vs+0DP4AxHAWRCbIPlQYllX
         G0sTXxTg1r9CBuRFK/EBhHkbefSfe5P0tpXJoX6CF6IsTRr/5jlcdklGvYzaCHUpraQF
         ldvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MZPrp3RplEizcRBOCsBGKIugRol0wBfkYLVrPfskCLo=;
        b=yKuHiJVefDxYI3Nns3lmNKpi8HpgBXHVuIcQJXOYUhG3hm+PJ6pHrcy/hFdu7EI4vb
         QnlBCE20/PREikH5iXaU8FBTX/6xdbGozXrA2+qKTB17fppYA44ZsSfUhVeWSroO6UE6
         aJ/1kkpa8zryUKdPfzmBtFPLmpKxMDN1D49NG9sdpKEDnjlfiu2L54764CeDI7qC4fuU
         N7JPPdyWruW8HYAlGN71T3J1e7naq5B8uiwXjXUSG05HAJRogWX2OfkyVc3XhKtADBa1
         W6EvEsOO4VdfH9NxbQkGvB+4XzxtzruygmzczD71ghasYHihOWix+aZZmGkC4N+DGa4p
         iQ/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXj6HV2USP67mk6Yt7pWRTjNUISuqZhhFvFlWQnKO2x8BPpBYzD
	XJrDf6bdsGmmqsVdLOhUJws=
X-Google-Smtp-Source: AK7set86QHo5bPUYA+Y40g57ENZCIJ63cGu79/NFA5M50fliY3qcAel/ghtURFqBcySvDhGefbM+AQ==
X-Received: by 2002:a19:7406:0:b0:4d7:44c9:9f54 with SMTP id v6-20020a197406000000b004d744c99f54mr2576716lfe.35.1676063899148;
        Fri, 10 Feb 2023 13:18:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2526:b0:4db:2bf0:d4b5 with SMTP id
 be38-20020a056512252600b004db2bf0d4b5ls1471163lfb.0.-pod-prod-gmail; Fri, 10
 Feb 2023 13:18:18 -0800 (PST)
X-Received: by 2002:ac2:5d22:0:b0:4a9:39f4:579a with SMTP id i2-20020ac25d22000000b004a939f4579amr3698769lfb.66.1676063898119;
        Fri, 10 Feb 2023 13:18:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676063898; cv=none;
        d=google.com; s=arc-20160816;
        b=H6Y3PCS+DKiFmP03Vecrz1tP5FpY5VB7Gc7diI3z+XRAaQpnMtpSjb5ZBX/i6omkpc
         sE9fThroA/r8QrDQb9O1w2UhCPqEqQ2YrxB/fF1vM4d8N281D/pwgIyzUIIZaJ05yNkO
         oth6kBlAV76lppByM48wYe7tcvpB5+gLyVIeIA8eEgAYmrXnBJGJMsXw0+WEN6AjxtUT
         bkUQO66rxHMLlU+XFbNLYex1iyvkVAyHNi+PdS5/tEUn1RJ6Dx6t5ty8Yi2zWpXmO8Dy
         nMtAL+mwJmWt0bqX3yDfWkeHn9MJaWtdfR2fNPD+Af7QIjQBnbTY009ebNW8abOn7Mbk
         88ZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QNTpFR8imhU+1RyFIUQnZTnn23HrW1qgGxbRYaqWOq4=;
        b=c2pKC3KIUBzC1rnnoJwjBNF1MehsLjxsyp0PR093yY2hbSMen0GlEVgi728l2ZL7vn
         nG5Vz9joLLEnKbSus3vfg3kZpHgrlOqAKjhjomcQndB0Tb5MIWtcfblLT+Z5EsLke7CM
         PhwXcZ6DY7X2Nj4QjozqODAJE37LMHndgPffjDP3g1f9Dnt/VIb3feYfvscCaAttIj4t
         m0EBXMlESxrCtmvYfgbB5+3Ktzpdbh41UIKnVKbFiJgB6UBloD9/LZB7xdHgZGRtQKF5
         xv4hPGtUgvrfcZbcbG45DHqG9Lq24fVZc4keST6heTxWlIxNfCr32Yf5tfSmN+jMmVyB
         rL6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=b9EI77+L;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::54 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-84.mta1.migadu.com (out-84.mta1.migadu.com. [2001:41d0:203:375::54])
        by gmr-mx.google.com with ESMTPS id w12-20020a05651204cc00b004ce3ceb0e80si327963lfq.5.2023.02.10.13.18.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Feb 2023 13:18:18 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::54 as permitted sender) client-ip=2001:41d0:203:375::54;
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
Subject: [PATCH v2 12/18] lib/stacktrace: drop impossible WARN_ON for depot_init_pool
Date: Fri, 10 Feb 2023 22:16:00 +0100
Message-Id: <ce149f9bdcbc80a92549b54da67eafb27f846b7b.1676063693.git.andreyknvl@google.com>
In-Reply-To: <cover.1676063693.git.andreyknvl@google.com>
References: <cover.1676063693.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=b9EI77+L;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::54 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

depot_init_pool has two call sites:

1. In depot_alloc_stack with a potentially NULL prealloc.
2. In __stack_depot_save with a non-NULL prealloc.

At the same time depot_init_pool can only return false when prealloc is
NULL.

As the second call site makes sure that prealloc is not NULL, the WARN_ON
there can never trigger. Thus, drop the WARN_ON and also move the prealloc
check from depot_init_pool to its first call site.

Also change the return type of depot_init_pool to void as it now always
returns true.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 12 +++++-------
 1 file changed, 5 insertions(+), 7 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 7f5f08bb6c3a..d4d988276b91 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -218,16 +218,14 @@ int stack_depot_init(void)
 }
 EXPORT_SYMBOL_GPL(stack_depot_init);
 
-static bool depot_init_pool(void **prealloc)
+static void depot_init_pool(void **prealloc)
 {
-	if (!*prealloc)
-		return false;
 	/*
 	 * This smp_load_acquire() pairs with smp_store_release() to
 	 * |next_pool_inited| below and in depot_alloc_stack().
 	 */
 	if (smp_load_acquire(&next_pool_inited))
-		return true;
+		return;
 	if (stack_pools[pool_index] == NULL) {
 		stack_pools[pool_index] = *prealloc;
 		*prealloc = NULL;
@@ -243,7 +241,6 @@ static bool depot_init_pool(void **prealloc)
 		 */
 		smp_store_release(&next_pool_inited, 1);
 	}
-	return true;
 }
 
 /* Allocation of a new stack in raw storage */
@@ -270,7 +267,8 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 		if (pool_index + 1 < DEPOT_MAX_POOLS)
 			smp_store_release(&next_pool_inited, 0);
 	}
-	depot_init_pool(prealloc);
+	if (*prealloc)
+		depot_init_pool(prealloc);
 	if (stack_pools[pool_index] == NULL)
 		return NULL;
 
@@ -435,7 +433,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		 * We didn't need to store this stack trace, but let's keep
 		 * the preallocated memory for the future.
 		 */
-		WARN_ON(!depot_init_pool(&prealloc));
+		depot_init_pool(&prealloc);
 	}
 
 	raw_spin_unlock_irqrestore(&pool_lock, flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ce149f9bdcbc80a92549b54da67eafb27f846b7b.1676063693.git.andreyknvl%40google.com.
