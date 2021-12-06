Return-Path: <kasan-dev+bncBAABBYMCXKGQMGQEUGYZHXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 9550246AA81
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:32:17 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id z138-20020a1c7e90000000b003319c5f9164sf180395wmc.7
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:32:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638826337; cv=pass;
        d=google.com; s=arc-20160816;
        b=NLjTg2ZwavbwQPYimtW4xuYjc2IH+vX7Cxi1JPjFBBEwVJsKvdBJ1opztt2Pbruunu
         UcVqgT4IY8bJCpX6WPmT6DHLmWdxh4oTcckxd7H/uD44Xy4P65g39QU87fCSZS+rexCb
         /ocigsY5ycwvDszr0xZQrb48RTTWru2PuF9rYD4+IDA+3HoToHqnPutHrq8tEvFK8hT3
         L4J5eWUpUTfr/vEaOGIlB1fZ7NsBJjDlEXiSYrp/FWKHJqCQXYH7UgjPSvO+HR+Pmwx+
         n8eEVXWMvxPF1llLJVsBSRWiwI7i9Juof70x2VDU3uIrUR1L944X5nfmHn9aTLfdtkNT
         GctA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0l80MF4D5yyJJ93JjzRmgxmRTVseNlUy85BvHGk/Wk8=;
        b=B/R/Rfn23+ZIiH63IwKY2N0xWyuPAieURz27IXHS+qKJwUPclN99YjcO7l/apW6aRX
         4O9na2cEZM4+ER0iXdrYfU8XR0VDj6Kr3oLztgknaD8nf90MxSBCeed53Irpi5JnnWlJ
         7B1u0ZSp50JF5o7RjrJQPTmFygrH0PiNTwjJFuV2IpQZ3dHr/Z9hDUgDh4mNbzf+8E9f
         NiNljPsOgGwY8CiWscjiqeG/CFZn8z83hUykANOtRjhZgzqN8ZTYZNY5Ybx8P6payhbE
         9BPW6boUTFIVEh9Ncxh/Wg8XdEjVK+ttxRMNHBGF+EuxjbO+UNhlj2n34l4aizs0CqKg
         e2Cw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=GN1CK5Qb;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0l80MF4D5yyJJ93JjzRmgxmRTVseNlUy85BvHGk/Wk8=;
        b=PjvCbUnZ92xXWWtHwek95vQFVNRqWpgOlPViyz1j666z/zUl3wETgXwEmMDOSYU9M3
         YpO2sFv2B4rV3tUABRqWjtWYV3ZbESvrBKx0TGQfvHnRvjBkoTy9g9JuZv4II+EEYG0R
         MUG8IM9LjyAi0Bvi1lcVUrc5weF1UFzL6yt8B2L7yPKE8cxkxO7chB/kt5tUhmU5PmIC
         bXEnsf4adN6nQPWwpngQ4ZwMaQPjjdhAVlnXUBnJI+dAK7gWWNPcga5HGZNX10XpS8Yt
         hCaX7fXMFNSrcVGbyTY0NEPMJnfCcakthpKtNlr9YKzI0M8KkxaUdgqK/V2vVGDLeKUL
         uFfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0l80MF4D5yyJJ93JjzRmgxmRTVseNlUy85BvHGk/Wk8=;
        b=bGAnaIoryuZOu4RLDQitL21uOXk1BLaB1OTZoJ+yc9HG0tc48CTRXTc5lUSQSlU965
         smnq5AR+gOnIKFTbw2WO/9w+PJV6+iMMLal+IEaaqX4QTIi1bKWRjQShouOtjX7+mreI
         ecHPDLbrJ3Ygg/oO7LyV9KAtfB+ItC8WwBK8G1M/+5mTXLDD0wfd9iCTnoaZou3JCwfr
         3yvotUXV/drFKymmz/dt3cPl36QIMfDq5V2IZ0Mmjc6VnmoXwGXRjfjF/y9/7UWU9C4b
         UeJFWxWVH8pdYCWr/ZJBoBPCGKuBNFW3LjU+dy9rKZBVjDr2ctA3fFCGx8YHcIRmmmix
         0B9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532iHPOBQxKPdLcJBALS5xXWuVTt4yXROoT3SKn74yQvbc+uF09n
	X4zuhiJVSrwwd9b1A5pYfiU=
X-Google-Smtp-Source: ABdhPJxlX4vQJzHyUEClSXIU+hMfi7fRKmpfQis2N0kmeMtEyP4sf9b8QncBU4UujKG3V4LkKUR2+w==
X-Received: by 2002:a5d:58ed:: with SMTP id f13mr46453544wrd.373.1638826337401;
        Mon, 06 Dec 2021 13:32:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:c90f:: with SMTP id f15ls218408wmb.1.gmail; Mon, 06 Dec
 2021 13:32:16 -0800 (PST)
X-Received: by 2002:a7b:c256:: with SMTP id b22mr1452909wmj.176.1638826336678;
        Mon, 06 Dec 2021 13:32:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638826336; cv=none;
        d=google.com; s=arc-20160816;
        b=vPh1ThPWiG4p4LdnJ94o9XxFrlxgxxnZFBQle9Dggvjo4DKBpZJYHAj3GZ0/vlxIwd
         JrGAOkW6xbOItkh0w717ZHOjUcxGMrKLWmjZoQ39HIe7qn4sRGS2BvNU7HoHSuEgrsfQ
         NbfaochGrFjIdn8DmO8hQ0jriUV/hJ+L4O85Bnk4r9SAnhYXY2KQF+5a1oxPUWzZXp07
         CcFXze3bVnrbL3JN7zujiNAChszxSaDMh16gRmubN1TSJVtJwsxHJEtY7edUH8sUJC20
         kT/lTB+mL9K/s/xnzrJvs0SL2P4W+DhNZQE1zR0uf14CUB3/W5L/3FkQw2E7/PR7hxKS
         l04A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fp6vcpTXqTgKp/R/kxaUnxOXIVcgUxd+g1l9srxGKbc=;
        b=JKrvq3QYEjop0ms/j1Zcw1bd5YZTmquFeT3m+Flnp4yATnIDjhiTXCR/zEYLMLczSO
         Thr86sJ+ArWsDnx8I0CdXcePvJNkz/+zBaHWnf/JQHf0U1WUOK3/0klCeun6jwWJdjlx
         WdGPBKHuIYSGlIygQRUyQ0vUqL9DoTBA5DKwpOuZjmXRpuQay3ymgS9kA36w9fbS7rvS
         SG3PlW1BnsaagaWDRLSA8NOIhcmxrYwFXTveoK5ByHoO7iFoG7StPoh4nbZkaL6CXlfq
         LbKxSSObX8K3Rq46Logp2IAFmpX7YD2b/otpw7BfnJQaQrG4yxdRFeLXhSntpVYkY4jZ
         8wsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=GN1CK5Qb;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id c2si97322wmq.2.2021.12.06.13.32.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:32:16 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 03/34] kasan, page_alloc: merge kasan_free_pages into free_pages_prepare
Date: Mon,  6 Dec 2021 22:31:38 +0100
Message-Id: <ed744bb1a857899257d7c7a461b1cdc4300b99dd.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=GN1CK5Qb;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
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

Currently, the code responsible for initializing and poisoning memory
in free_pages_prepare() is scattered across two locations:
kasan_free_pages() for HW_TAGS KASAN and free_pages_prepare() itself.
This is confusing.

This and a few following patches combine the code from these two
locations. Along the way, these patches also simplify the performed
checks to make them easier to follow.

This patch replaces the only caller of kasan_free_pages() with its
implementation.

As kasan_has_integrated_init() is only true when CONFIG_KASAN_HW_TAGS
is enabled, moving the code does no functional changes.

This patch is not useful by itself but makes the simplifications in
the following patches easier to follow.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
 include/linux/kasan.h |  8 --------
 mm/kasan/common.c     |  2 +-
 mm/kasan/hw_tags.c    | 11 -----------
 mm/page_alloc.c       |  6 ++++--
 4 files changed, 5 insertions(+), 22 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index d8783b682669..89a43d8ae4fe 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -95,7 +95,6 @@ static inline bool kasan_hw_tags_enabled(void)
 }
 
 void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags);
-void kasan_free_pages(struct page *page, unsigned int order);
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
@@ -116,13 +115,6 @@ static __always_inline void kasan_alloc_pages(struct page *page,
 	BUILD_BUG();
 }
 
-static __always_inline void kasan_free_pages(struct page *page,
-					     unsigned int order)
-{
-	/* Only available for integrated init. */
-	BUILD_BUG();
-}
-
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 static inline bool kasan_has_integrated_init(void)
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 8428da2aaf17..66078cc1b4f0 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -387,7 +387,7 @@ static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
 	}
 
 	/*
-	 * The object will be poisoned by kasan_free_pages() or
+	 * The object will be poisoned by kasan_poison_pages() or
 	 * kasan_slab_free_mempool().
 	 */
 
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 7355cb534e4f..0b8225add2e4 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -213,17 +213,6 @@ void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
 	}
 }
 
-void kasan_free_pages(struct page *page, unsigned int order)
-{
-	/*
-	 * This condition should match the one in free_pages_prepare() in
-	 * page_alloc.c.
-	 */
-	bool init = want_init_on_free();
-
-	kasan_poison_pages(page, order, init);
-}
-
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
 void kasan_enable_tagging_sync(void)
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 3589333b5b77..3f3ea41f8c64 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1353,15 +1353,17 @@ static __always_inline bool free_pages_prepare(struct page *page,
 
 	/*
 	 * As memory initialization might be integrated into KASAN,
-	 * kasan_free_pages and kernel_init_free_pages must be
+	 * KASAN poisoning and memory initialization code must be
 	 * kept together to avoid discrepancies in behavior.
 	 *
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
 	if (kasan_has_integrated_init()) {
+		bool init = want_init_on_free();
+
 		if (!skip_kasan_poison)
-			kasan_free_pages(page, order);
+			kasan_poison_pages(page, order, init);
 	} else {
 		bool init = want_init_on_free();
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ed744bb1a857899257d7c7a461b1cdc4300b99dd.1638825394.git.andreyknvl%40google.com.
