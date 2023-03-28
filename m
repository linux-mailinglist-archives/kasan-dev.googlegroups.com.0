Return-Path: <kasan-dev+bncBDKPDS4R5ECRBSPURKQQMGQEDUI2UEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id DDB806CBB96
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 11:58:35 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id i7-20020a626d07000000b005d29737db06sf5666017pfc.15
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 02:58:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679997514; cv=pass;
        d=google.com; s=arc-20160816;
        b=DXZ0fC2zeO1y/dqBxnIkYUr1chg/q4APqrBRocHVs2U8okDPcusl76nspS/d1w4o60
         cKkzVPWZSp+OpkZjKRZ8YCqMMi2LbXnti7Svu4gnZLmQYi3mQcR9efMe9SXY8UqmvWDy
         xk0dZwBvJofjn0l8htGdsd4if6bytbceTTLecbKnnACwJK4nbomckNuvW3ZihewO4pm7
         epjuPDvprKCL7968WO/MMnWXPryilE6aIiXLV038vDYNcClgvgHc51kzVdE1znfDafPv
         83ml93llp6Cm/ATdFILnbVcH3dSy/uILY2pUvqBGfp0rvVpoMTSjCvfejqGReRDtDhrg
         YgLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=dZZVgK9Yw6MSNgE621Ndr1XFZpKyPmg1QzDhgmMxBl8=;
        b=OBclzVsBj6k6Rd5LAt4O8wj5SzXisGAS1gVD0gwR0hVuAcMBhbfeAB7eGJDnFLQSWE
         p1MHnz7dPHj59FABm085PHzZncxa6ZRMAdIYgwOPSJF6R/y3klszLPCFVvZydNSqFEFt
         fE/hutyT5Ehrwk4kK4qXLDckBtk0OhrzqvAJUjT7yUZIeqkBRZ+IBYo1bYUUZX4R8u4A
         DMw7aM5XDV7HnTVTYx2ZDbe3v7gL/1JwX2C7dDOD0r+PTBdLmz1Sdd23hkK2YHGx1HsX
         TcTaov34FWSUg0NMGHxYIPiGXIhK5CALn+GfEb1cbsEviVj/o4k+/nrTQ4EM/ghTIXAd
         AJhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b="GNYV/SpQ";
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679997514;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dZZVgK9Yw6MSNgE621Ndr1XFZpKyPmg1QzDhgmMxBl8=;
        b=XZru12jyon9obh9Pj+AdgLoawX8A2VQk5rDzUFTiTnX8mOvVg3YdUx/gj0F4T3QvIR
         tRh+PPX2ygXh2FIZ5MVZvv9md5dkk/jB1Ee55Ol788zDKSDNtxkF/4pxHzKqwYA7cVbd
         ChokA/JC7ILsQHtCBhqHJxtpX/CybxdzCfVAWrO9o9tsXjGXvce3J+7vU9jtLZ6yrcB5
         gYgvuuk2AkDtLc5G6pyNhqDOJ0qxkWk5H0mq66Zm1d2RcJZAf6b/IE+1ihRQyM2I1+En
         /NXgUrSY8IJrBvrGOPHeEJWBCjbO+vjsS/C49+OeZaK2bAo2S7dNMugkqJ2wLf6byLPR
         nKQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679997514;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=dZZVgK9Yw6MSNgE621Ndr1XFZpKyPmg1QzDhgmMxBl8=;
        b=UDeD/7JVlUpAzMa3bFdztg76MdRnCYMPuZtYKFJQ8VQ1Hh4MmcwQfJwdn6PtQQg8xB
         9hAQTawtPvRXQXoqv532PU+DxmWfz36YzXAoXhRI4TZNrbac6yUr1gUCqrahzqcVQbwn
         9oB0fEEmluGr9gUmiC5UaxEVzi0YqX3TEAny3y8ue6uhheTTH2o20miqyd6iuv+k6AMr
         8G2MJ+BAcbadrg5Yz5knaAU+v5TPUlLdsivMB5R5o7i2OlwjIFvjHSW/iRGwkxHi7mp8
         zdw3CEny/ts6EeDgvhJQFONtIEQSTwu//cZkZIkF6RGeju+nSHYSDmyyKrCnqvpWhQ6Q
         CoEQ==
X-Gm-Message-State: AAQBX9fY8pSyK9XIYBiGa1wsqDCpNJrmnUr0w4fJKys0lMjbep7hv5cp
	tgh/24U/AoNI2ic/MLdjUHM=
X-Google-Smtp-Source: AKy350bVBCTntkbDA44PNcSHi2rr2QiHvPe7QC0CknG8y9uE2R7GqFZgAnbniVjILYfYdiY00f4+rg==
X-Received: by 2002:a17:902:d885:b0:1a0:4933:c6ad with SMTP id b5-20020a170902d88500b001a04933c6admr5548270plz.3.1679997514136;
        Tue, 28 Mar 2023 02:58:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ecca:b0:199:50f5:6729 with SMTP id
 a10-20020a170902ecca00b0019950f56729ls9639435plh.11.-pod-prod-gmail; Tue, 28
 Mar 2023 02:58:33 -0700 (PDT)
X-Received: by 2002:a17:90a:31c:b0:23f:ec0f:aab8 with SMTP id 28-20020a17090a031c00b0023fec0faab8mr16098541pje.40.1679997513330;
        Tue, 28 Mar 2023 02:58:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679997513; cv=none;
        d=google.com; s=arc-20160816;
        b=ZWSCwcdhzLljS26CBbxUWv0RgEMKddl6wLC7my5IUehIDiNshmUtEwSmuNNyamYpc4
         C7ObDyQA4Lf1btLv4i1oERxkPd4fHINTw3G6E9k+Wy7flvxJILYHqbshdkifTFkhWIZR
         we/Tmzw3RSl8QXox/8l5MWbSIQRkFc6QHBsr7VMnMkzOuCTb+MbOsgadSNCCg5gt1BOO
         4Uj9zDMvnR94/FS8mI9/25//rzffrfldfBAaO02pMAiIX/1eU+ebP5a67U9LXenHHWWh
         yhpHK6UNocBxObItXH0+F+Hhd3QgPtw1clRNK4MKWkdtXE59Bj03vuKP0TIb0N1P+gHu
         FBbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=oXReBzDsI5mUppZ3rGyjpCu82GIXuKJKMV0lZiD0JNk=;
        b=GFOQECV/u/tYvakkMOh/Np0uPSu82XXCjAYaDxpqbsqRnnfm936/syOaFR81FTJ4hR
         rg7mvXOMkZddveKjK0X7WrSrJku/QOWWyEd0OmRANY3Jx0G0LkKsa+o7P2T1Z7GxD64x
         upeBjVRFVWAoxFhLsdnJdgDus7gARu7nB7j9HcyM6Dy31zyHvvWDsdtgUe631iu8V0Ug
         VWgzUVweWZdNaDEWAtX216JwLWKdeCuQcIbwu1kJBadHzQVufjxw1ajhDvhmizO+aeae
         vz5aehaw2+SnmjVYjfbM5uv+0oKrKdk/lj/JJsezrGKR3Cp8v9x5fCPhC/vsGsYX5kiM
         DhwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b="GNYV/SpQ";
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id lb16-20020a17090b4a5000b002405490a573si462725pjb.0.2023.03.28.02.58.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Mar 2023 02:58:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id l14so7567992pfc.11
        for <kasan-dev@googlegroups.com>; Tue, 28 Mar 2023 02:58:33 -0700 (PDT)
X-Received: by 2002:aa7:96f8:0:b0:600:cc40:2589 with SMTP id i24-20020aa796f8000000b00600cc402589mr3361407pfq.3.1679997512966;
        Tue, 28 Mar 2023 02:58:32 -0700 (PDT)
Received: from PXLDJ45XCM.bytedance.net ([139.177.225.236])
        by smtp.gmail.com with ESMTPSA id m26-20020aa78a1a000000b005a8a5be96b2sm17207556pfa.104.2023.03.28.02.58.28
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Tue, 28 Mar 2023 02:58:32 -0700 (PDT)
From: "'Muchun Song' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	jannh@google.com,
	sjpark@amazon.de,
	muchun.song@linux.dev
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Muchun Song <songmuchun@bytedance.com>
Subject: [PATCH 1/6] mm: kfence: simplify kfence pool initialization
Date: Tue, 28 Mar 2023 17:58:02 +0800
Message-Id: <20230328095807.7014-2-songmuchun@bytedance.com>
X-Mailer: git-send-email 2.37.1 (Apple Git-137.1)
In-Reply-To: <20230328095807.7014-1-songmuchun@bytedance.com>
References: <20230328095807.7014-1-songmuchun@bytedance.com>
MIME-Version: 1.0
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b="GNYV/SpQ";       spf=pass
 (google.com: domain of songmuchun@bytedance.com designates
 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
X-Original-From: Muchun Song <songmuchun@bytedance.com>
Reply-To: Muchun Song <songmuchun@bytedance.com>
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

There are three similar loops to initialize kfence pool, we could merge
all of them into one loop to simplify the code and make code more
efficient.

Signed-off-by: Muchun Song <songmuchun@bytedance.com>
---
 mm/kfence/core.c | 47 ++++++-----------------------------------------
 1 file changed, 6 insertions(+), 41 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 7d01a2c76e80..de62a84d4830 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -539,35 +539,10 @@ static void rcu_guarded_free(struct rcu_head *h)
 static unsigned long kfence_init_pool(void)
 {
 	unsigned long addr = (unsigned long)__kfence_pool;
-	struct page *pages;
 	int i;
 
 	if (!arch_kfence_init_pool())
 		return addr;
-
-	pages = virt_to_page(__kfence_pool);
-
-	/*
-	 * Set up object pages: they must have PG_slab set, to avoid freeing
-	 * these as real pages.
-	 *
-	 * We also want to avoid inserting kfence_free() in the kfree()
-	 * fast-path in SLUB, and therefore need to ensure kfree() correctly
-	 * enters __slab_free() slow-path.
-	 */
-	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
-		struct slab *slab = page_slab(nth_page(pages, i));
-
-		if (!i || (i % 2))
-			continue;
-
-		__folio_set_slab(slab_folio(slab));
-#ifdef CONFIG_MEMCG
-		slab->memcg_data = (unsigned long)&kfence_metadata[i / 2 - 1].objcg |
-				   MEMCG_DATA_OBJCGS;
-#endif
-	}
-
 	/*
 	 * Protect the first 2 pages. The first page is mostly unnecessary, and
 	 * merely serves as an extended guard page. However, adding one
@@ -581,8 +556,9 @@ static unsigned long kfence_init_pool(void)
 		addr += PAGE_SIZE;
 	}
 
-	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
+	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++, addr += 2 * PAGE_SIZE) {
 		struct kfence_metadata *meta = &kfence_metadata[i];
+		struct slab *slab = page_slab(virt_to_page(addr));
 
 		/* Initialize metadata. */
 		INIT_LIST_HEAD(&meta->list);
@@ -593,26 +569,15 @@ static unsigned long kfence_init_pool(void)
 
 		/* Protect the right redzone. */
 		if (unlikely(!kfence_protect(addr + PAGE_SIZE)))
-			goto reset_slab;
-
-		addr += 2 * PAGE_SIZE;
-	}
-
-	return 0;
-
-reset_slab:
-	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
-		struct slab *slab = page_slab(nth_page(pages, i));
+			return addr;
 
-		if (!i || (i % 2))
-			continue;
+		__folio_set_slab(slab_folio(slab));
 #ifdef CONFIG_MEMCG
-		slab->memcg_data = 0;
+		slab->memcg_data = (unsigned long)&meta->objcg | MEMCG_DATA_OBJCGS;
 #endif
-		__folio_clear_slab(slab_folio(slab));
 	}
 
-	return addr;
+	return 0;
 }
 
 static bool __init kfence_init_pool_early(void)
-- 
2.11.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230328095807.7014-2-songmuchun%40bytedance.com.
