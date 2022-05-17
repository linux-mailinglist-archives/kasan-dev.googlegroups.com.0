Return-Path: <kasan-dev+bncBDDL3KWR4EBRB5GJR6KAMGQESVOVI7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6334852AA0E
	for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 20:10:03 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id k5-20020a05600c0b4500b003941ca130f9sf8493873wmr.0
        for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 11:10:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652810996; cv=pass;
        d=google.com; s=arc-20160816;
        b=w4/dCA7agNTa97AuFPkdeEyLrDX8O7xwSauA6q5xj1Tg7zTsanYF2USehVGNwp3hE3
         eB4EiriPdOA7AjqhFz3QhvlERt+OaPVsbKpj2edpAptJHGCYxp68Du7PsDtvQlcC4rVh
         2idwgKAJzU9qfk6WRKEFxOySdXfVHTKpfgZ8XjAwbZ3X0WOoLeV4sPqZBiA/zpiORBhN
         JO9/jRZUNp13SkKyK80aKVvi3k3Izn4zyRTQEWBAqOI9VjSRqYEd0x6Ul/kl3S1LZVD3
         Zo78xUPWDks8hwmENUvUHzazaga/znMkLRdR75CrOsO6Ah42Kc/FieFVuJJsZXs3ytPr
         67tQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pvCnPNvLC3zlDViX0ZF8ovs97qGMemRFQPPu8pigjy4=;
        b=NxMGBZFIJp4S+rFzes3XQ2AhZrwPS5kIz0ioT67WsFUoVynXfy6PZpchH9pnWgA80x
         DF9D0wrr4qX4OcJoSUGH1JqfPZptugmkgBO3EwgArINhOG7XSygv0SRcVFxIh7706Skb
         +Yc/q9rwCtRwwjJVgMwRjYwQrdRi3nyeijqpb7yCwXW7G751emyG9E86x4LC/FpeLcMS
         CCBiYdaQ/i5jvU9y5lJFSl3WqQZ0YNoOF0O/RIxvxqhOMEU3YgLPbQHugnfcQdchMyri
         J34gjz/4y5omo2pH41mDpyxS5i9nST4vmk0TL4Uj3R3J95CnxvHPK5qr7Yf8/12ZgsLH
         +Ayw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pvCnPNvLC3zlDViX0ZF8ovs97qGMemRFQPPu8pigjy4=;
        b=VbhtnV9fw28dMP0UHcPwfx9XOuMB++t+nGMQ4Sz3UBhVHi5LThbI57yiGZZXO6JIme
         4pL5kL6KQ4PnH5ktG6rcOoEpG+M7CDe5j91xFRo85zvNxS0wREIjS8oHj6zbC0DVYMRh
         OY2AcowvNP+/xEpxM1G/QnOsbc/hAC9nx2ME2XK550lR588Sj2t3qT6nsQ75d6SlYtql
         Obtj1jlNzeyMgge3dVV/dBWlD7cONzoPNB9u2LVYKaMbziFDzLB//HfaPLWXji9YZbMy
         Zi9iS4wJW5CgDC2ZE8WUqUw7iXBN+QKbLUgFCYQJzMw2b7HLDUyNfq1be9XcSxaSe7wm
         2hgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pvCnPNvLC3zlDViX0ZF8ovs97qGMemRFQPPu8pigjy4=;
        b=gvIch8tUV07uU8eJFwiFf40T8ae6OFxjbZZzUCw+3yHvqIV4xmSaR019Wm2GrHlZTg
         Lmi5uuCXI4gLNrYgoOirjoVljrQcf1+RwqxCGtbW5md6Gx8sMS6jfosyt1M2pSRBGrpx
         JaM9UzlpdidFlHe/ElYtL7CnxhceWWwYVMHrOvv12MFJAIx1b6Vgv54s2HactJbAnELK
         SYXXSDTWVge9INy9uvbmJv+g0eXUUK67yIIngl4ieALueXKF4jFVhPuneqsq+NLYnPgt
         8WpsAh3i2CBfaSbjMwVc/IMVaCatQpIMtt2QOTiD0vjELLAcC6DKyyp2hu99SLlfnTsM
         dzAw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530PfMehB6UnC/jiWVfGxdV1x9GSJZJLme9aZQdbkCO/V7kNB5F9
	mVpDjHBHLELGOmM5bL9f5+o=
X-Google-Smtp-Source: ABdhPJxDagRvbBmE2ZBcLBsW+CrIrPGpy7xtlUTaMkSPi54tqlJRvx7pU9nxi40H3J1Uwi0I39+X7A==
X-Received: by 2002:a5d:64e6:0:b0:20c:4f23:96fc with SMTP id g6-20020a5d64e6000000b0020c4f2396fcmr19995270wri.154.1652810996673;
        Tue, 17 May 2022 11:09:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:64ca:0:b0:20c:bb44:bd7 with SMTP id f10-20020a5d64ca000000b0020cbb440bd7ls4053597wri.0.gmail;
 Tue, 17 May 2022 11:09:55 -0700 (PDT)
X-Received: by 2002:adf:cf06:0:b0:20d:1236:b1ff with SMTP id o6-20020adfcf06000000b0020d1236b1ffmr6222418wrj.496.1652810995418;
        Tue, 17 May 2022 11:09:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652810995; cv=none;
        d=google.com; s=arc-20160816;
        b=Lsor65vNIgzDSm7+f3msheqtu9M9KhGz189xMVIVbi79OFJTa7gEGKwZ6ail/WKweF
         bhSuXKl136P9tmIfv/dpRzUeiGCa4lbZFubDtlmRb40NThjHdD3U0+bIY+u2AY3+dIpM
         wg6CJCQVS6Xb8mez5MGjAX5HLrrONkoMyeYwidjwYqD1GZe090Rj3ryfo0ku1YwJYL70
         R9Js0scPeINKnu5fhecZGRlhX7IQUZHGUu2EohcItPC6VVLAOjF9QV8zHZr85Gt4qqft
         Qdr7GvezvMotGGmYWHV1hRO1rum4EwxNiPUOp5DGeS2wgZaKq+sMMtzoQVge9ZMfIJsg
         fmNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=CSh6S8wijjz4mA1fZvT+lIbSX4TG9fYxu5hqEAlTqhQ=;
        b=ecG5n8pMxlU/3iV3ZXyvZqzUE3AOtTo6CSPlQRXA8EpFf0eivLP507+YHrF9OcaLru
         YVHCRez0dT9Wqt7mZ+thqMz7hdTU0oBKLz6qKF3Vb+CZF65ZWonmMz8g862s6sRu8Xkm
         pO3qkQzsEQPQMcZPAkhlVhM52Ep41ZDMA0eW0N3Dg3BbKgw1uhtO0kXJ8jjLb+Gz+kFO
         PAMtBlvBMOVSfHqJ7Wn2XWsX+v4mPCER5gzXQZ/O/AOk+kG6pLgrIuU+5Xk6Tjt9Q3Tz
         tAAAvsNYtajC7zoPrb5KDlfoGp+5P0XzDNamia+2DcoQxfU5p0CL6aCBY+DX07OoZzHu
         ysVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id 190-20020a1c19c7000000b00396f5233248si170427wmz.0.2022.05.17.11.09.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 May 2022 11:09:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 20084B81B6B;
	Tue, 17 May 2022 18:09:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2AD9EC34100;
	Tue, 17 May 2022 18:09:52 +0000 (UTC)
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>
Cc: Will Deacon <will@kernel.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH 2/3] mm: kasan: Reset the tag on pages intended for user
Date: Tue, 17 May 2022 19:09:44 +0100
Message-Id: <20220517180945.756303-3-catalin.marinas@arm.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20220517180945.756303-1-catalin.marinas@arm.com>
References: <20220517180945.756303-1-catalin.marinas@arm.com>
MIME-Version: 1.0
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On allocation kasan colours a page with a random tag and stores such tag
in page->flags so that a subsequent page_to_virt() reconstructs the
correct tagged pointer. However, when such page is mapped in user-space
with PROT_MTE, the kernel's initial tag is overridden. Ensure that such
pages have the tag reset (match-all) at allocation time since any late
clearing of the tag is racy with other page_to_virt() dereferencing.

Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 include/linux/gfp.h | 10 +++++++---
 mm/page_alloc.c     |  9 ++++++---
 2 files changed, 13 insertions(+), 6 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index 3e3d36fc2109..88b1d4fe4dcb 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -58,13 +58,15 @@ struct vm_area_struct;
 #define ___GFP_SKIP_ZERO		0x1000000u
 #define ___GFP_SKIP_KASAN_UNPOISON	0x2000000u
 #define ___GFP_SKIP_KASAN_POISON	0x4000000u
+#define ___GFP_PAGE_KASAN_TAG_RESET	0x8000000u
 #else
 #define ___GFP_SKIP_ZERO		0
 #define ___GFP_SKIP_KASAN_UNPOISON	0
 #define ___GFP_SKIP_KASAN_POISON	0
+#define ___GFP_PAGE_KASAN_TAG_RESET	0
 #endif
 #ifdef CONFIG_LOCKDEP
-#define ___GFP_NOLOCKDEP	0x8000000u
+#define ___GFP_NOLOCKDEP	0x10000000u
 #else
 #define ___GFP_NOLOCKDEP	0
 #endif
@@ -259,12 +261,13 @@ struct vm_area_struct;
 #define __GFP_SKIP_ZERO ((__force gfp_t)___GFP_SKIP_ZERO)
 #define __GFP_SKIP_KASAN_UNPOISON ((__force gfp_t)___GFP_SKIP_KASAN_UNPOISON)
 #define __GFP_SKIP_KASAN_POISON   ((__force gfp_t)___GFP_SKIP_KASAN_POISON)
+#define __GFP_PAGE_KASAN_TAG_RESET ((__force gfp_t)___GFP_PAGE_KASAN_TAG_RESET)
 
 /* Disable lockdep for GFP context tracking */
 #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
 
 /* Room for N __GFP_FOO bits */
-#define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))
+#define __GFP_BITS_SHIFT (28 + IS_ENABLED(CONFIG_LOCKDEP))
 #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
 
 /**
@@ -343,7 +346,8 @@ struct vm_area_struct;
 #define GFP_NOWAIT	(__GFP_KSWAPD_RECLAIM)
 #define GFP_NOIO	(__GFP_RECLAIM)
 #define GFP_NOFS	(__GFP_RECLAIM | __GFP_IO)
-#define GFP_USER	(__GFP_RECLAIM | __GFP_IO | __GFP_FS | __GFP_HARDWALL)
+#define GFP_USER	(__GFP_RECLAIM | __GFP_IO | __GFP_FS | __GFP_HARDWALL | \
+			 __GFP_PAGE_KASAN_TAG_RESET)
 #define GFP_DMA		__GFP_DMA
 #define GFP_DMA32	__GFP_DMA32
 #define GFP_HIGHUSER	(GFP_USER | __GFP_HIGHMEM)
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 0e42038382c1..f9018a84f4e3 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2382,6 +2382,7 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags) &&
 			!should_skip_init(gfp_flags);
 	bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
+	int i;
 
 	set_page_private(page, 0);
 	set_page_refcounted(page);
@@ -2407,8 +2408,6 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	 * should be initialized as well).
 	 */
 	if (init_tags) {
-		int i;
-
 		/* Initialize both memory and tags. */
 		for (i = 0; i != 1 << order; ++i)
 			tag_clear_highpage(page + i);
@@ -2430,7 +2429,11 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	/* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
 	if (kasan_hw_tags_enabled() && (gfp_flags & __GFP_SKIP_KASAN_POISON))
 		SetPageSkipKASanPoison(page);
-
+	/* if match-all page address required, reset the tag */
+	if (gfp_flags & __GFP_PAGE_KASAN_TAG_RESET) {
+		for (i = 0; i != 1 << order; ++i)
+			page_kasan_tag_reset(page + i);
+	};
 	set_page_owner(page, order, gfp_flags);
 	page_table_check_alloc(page, order);
 }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220517180945.756303-3-catalin.marinas%40arm.com.
