Return-Path: <kasan-dev+bncBAABBPNTRCWAMGQE7WDDBTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id CAB6A819394
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:31:26 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-54c882dcb76sf151713a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:31:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703025086; cv=pass;
        d=google.com; s=arc-20160816;
        b=O3rdTdZlSZeczuT4rSSjCppcRewhK/cGA5Bd//z9rKGg6h/aeu/DHmoDNNCyQ2wb0S
         Z4qtM0IlVNzs0366UH3uq4hDF1m0bLfvnoieAy0zYf/CTuoqObFC5UUzymdCfkn7z7cu
         zMtmpM1T2qgk8Hb3qBT4Xeq+SAaxVMKqyur92D7EXXSgSHuVuOOWCIksRurIuyCsibpk
         jY6D/YO0kjTTCuDLHCBRf5cJ6RkuKbdywkVO6HJvAWb3Gw6E290MpdNCDgNWR8dOwFsq
         TlJEem+5fmSB+IDLKr0i+jo+XvGvmuHMtlMYPaNeWE9rHRCXVQXJnKZ8rd+P9wLBPksM
         g0qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=K/ISToMl6mfm/9R8qQ4uYvzlsebQQMFBXfQoI5pk18Q=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=hMkElaiKLRx+/fH4VCEe+pCuLKVWmUp4I3sHk3s1UJ1o8qjJH5JWH6w+5WSjFYkSSO
         G3PpEEjM5kvmQTLyaIbIjPAkKnGZPyFojZgcocs+IhmWYjdCmgb9W//qIScz9fEm/vXl
         PL3auVRy0QdPjj5XVy0X/RxJyWWagivWgHJFYrhZiNik5OaAGDOyqw2JFxvweJiFHl41
         HHr5hqFPaVeUsd1m/WpDwCpeGcNK+rUGLEt7/hYhd/l7E51tSwF6Asgkp0H08xmlk0s+
         I+ibmLBeFhmRAa2qctd+FndCa5ZGHoQkhFANnCFqfW8lFczjRbZGmMno6F5iYabTtj2M
         L6NQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Kt1rNfuv;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.185 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703025086; x=1703629886; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=K/ISToMl6mfm/9R8qQ4uYvzlsebQQMFBXfQoI5pk18Q=;
        b=uafeKOO649aJe+d+MI/kh92htMd5SomUrssMFZz4QPd/aAnBKbpm7PuGkz3KyCi7tX
         Hm1+2j/PMPaT1v5Ue7gBFPwyBaoKQHhfv+7F4/9cVThJ7ebiCyzaXKFOoI+Swqx9epDn
         6zPDHJorGwJk96ptPfLv0w/6F0Q1PkhyT0VSejom67ZGhsBpuFAQG4VInCrCR+Q5ComR
         +IhzJcSgXVsL4/Lkv/HbcPNfQaNip7O/0ixkW9ulXq9w6qRbD7CLzwixQ9yherQpchfD
         cUlKMzryJfGKliqNW0C94Sb5sM842yWdFUl82/VbPCDInvG9dfZQKEWYdmqwBHUwM1gd
         Q0aQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703025086; x=1703629886;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=K/ISToMl6mfm/9R8qQ4uYvzlsebQQMFBXfQoI5pk18Q=;
        b=ChX7xmSm/kE3Ijq6ofeJvjbu/TGOwmYe1VHD/0Ity50xhgCsu/LD4KTSOmuj5V650m
         Y++DoKC3bSPkCDDAePLZQKW9vVzOKMS8zqoT8bcQMLk2nZwKk3VXXJKu+/Xpq719Jtwe
         0lfsHKet2Vxp+vqYiCPqqGnXFjD0j8x0vMebzgm9JLlSct8hMslvBpe4HuGfyZrpFdWb
         SWPr58/PveA5B3a2bBmSB9zLgvYHhjS5IV32SWLWg5fak10VYnQ/xYte6cimvQguFg+x
         hxtUEcPY9LPIJbiM37jx8EeB2R/B3yNVqyDdVi+GYsuTmDdyD+Qe/Wa6ly4OTQNE1G6U
         nPUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwJwjD+oQU/WB/zFMarLdN5P24wPp0OFSbK85D3ivqQPGhoy83A
	RgK1CGKbt1fzK+eUrfMjXfQ=
X-Google-Smtp-Source: AGHT+IGIxIH0Q1/pNM5olhPOvvB4/DdBOviW68E4KGi32JPYbpDOQIMm8fNx/3v0MUsXIoVjO8EVyQ==
X-Received: by 2002:a50:8ad2:0:b0:552:ada6:7485 with SMTP id k18-20020a508ad2000000b00552ada67485mr2045355edk.24.1703025085961;
        Tue, 19 Dec 2023 14:31:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1ca6:b0:553:62f4:d7 with SMTP id
 cz6-20020a0564021ca600b0055362f400d7ls1498615edb.2.-pod-prod-00-eu; Tue, 19
 Dec 2023 14:31:24 -0800 (PST)
X-Received: by 2002:a17:906:c411:b0:a1f:4d21:301a with SMTP id u17-20020a170906c41100b00a1f4d21301amr1646851ejz.13.1703025084420;
        Tue, 19 Dec 2023 14:31:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703025084; cv=none;
        d=google.com; s=arc-20160816;
        b=eGZ2G1kXNIc/+QDEc585ez05prEStS57982MDEEWPNa4m8mNlwYp0OR4OvTTb+R0VQ
         TGyJGXWzip2wJ7Z/QwYp+JXBrWjWRjQSnrys5/DWgtsXyatv+0e8FIfvyyX2xSU9Q9vV
         3RsbRtRW6AGDFpgpquL0+RLdsbsBLBbrSnpcQ5LvoMIg6OA/VRSxOhC2HTAlXIl40R2D
         8DOQ63ZalkbNM2b9ihNuqRJgr35FLFEPEkhs69htmCsyijeOsJivpNW1J2u/CLZarNWO
         r+bk/1RitsKuCfFZDCy2SHQHh1yjYL1r1YjvqWQ4vkXF6cYlBAXJk6hfgGJgsYUvW9oo
         ikEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KVsX1wYh/u3bsgXc0v6541Y+g0kgoewEBIuD2sVrVOE=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=zZKKvlz/tL1gyKDmHxDtBr/99X5kxh7Kbm/JS20HrKIbbfaiTTonMmSOXVhL2ldi/t
         ugto9jYrFZMqhe1LhBSJUEPbKwOWw4/TJkuL9oOPxNBtgwzZxKf68HM7q3TaGxHSGmqY
         +fLVo3+7bzdMzbr7RyECsgTBJe5PvNp++wL+lyBGOtsqi+rs/HugA5FOIDDW5EFYDLN5
         ypLddhSMNgS+ESwM2L21ZDJPKR7sdJ3ju6/mr/9Ox/fCzB6tdEQ7aZixx9tdk5vpMuht
         nK+kq9D/OdFV4oFWeF7Mh8rGDvh3ErJdWO37KqqUpYwIU+kSIRpag7weJmixx/M7nSoN
         Zoww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Kt1rNfuv;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.185 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-185.mta0.migadu.com (out-185.mta0.migadu.com. [91.218.175.185])
        by gmr-mx.google.com with ESMTPS id u4-20020a50eac4000000b0054cb5798047si1072153edp.3.2023.12.19.14.31.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:31:24 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.185 as permitted sender) client-ip=91.218.175.185;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Breno Leitao <leitao@debian.org>,
	Alexander Lobakin <alobakin@pm.me>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 13/21] mempool: skip slub_debug poisoning when KASAN is enabled
Date: Tue, 19 Dec 2023 23:28:57 +0100
Message-Id: <98a4b1617e8ceeb266ef9a46f5e8c7f67a563ad2.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
References: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Kt1rNfuv;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.185
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

With the changes in the following patch, KASAN starts saving its metadata
within freed mempool elements.

Thus, skip slub_debug poisoning and checking of mempool elements when
KASAN is enabled. Corruptions of freed mempool elements will be detected
by KASAN anyway.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes RFC->v1:
- This is a new patch.
---
 mm/mempool.c | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/mm/mempool.c b/mm/mempool.c
index 7e1c729f292b..1fd39478c85e 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -56,6 +56,10 @@ static void __check_element(mempool_t *pool, void *element, size_t size)
 
 static void check_element(mempool_t *pool, void *element)
 {
+	/* Skip checking: KASAN might save its metadata in the element. */
+	if (kasan_enabled())
+		return;
+
 	/* Mempools backed by slab allocator */
 	if (pool->free == mempool_kfree) {
 		__check_element(pool, element, (size_t)pool->pool_data);
@@ -81,6 +85,10 @@ static void __poison_element(void *element, size_t size)
 
 static void poison_element(mempool_t *pool, void *element)
 {
+	/* Skip poisoning: KASAN might save its metadata in the element. */
+	if (kasan_enabled())
+		return;
+
 	/* Mempools backed by slab allocator */
 	if (pool->alloc == mempool_kmalloc) {
 		__poison_element(element, (size_t)pool->pool_data);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/98a4b1617e8ceeb266ef9a46f5e8c7f67a563ad2.1703024586.git.andreyknvl%40google.com.
