Return-Path: <kasan-dev+bncBAABBPMKXCHAMGQEABQY3HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FCEE481F9E
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:15:10 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id o11-20020a2e90cb000000b0022dd251d30asf4865373ljg.8
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:15:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891710; cv=pass;
        d=google.com; s=arc-20160816;
        b=R3SPwEi7I5jfll27YMBzGe7Wot5rKFBtwxmzh15FCGsSVZT1HhgTO0W4K/rWosdqy/
         ZgmaHuK5qa3OIeHbGzBsUuqTh2xdHToYOrzTiD1ImMzHSvnzXj+iaf6gCRIxC59ivE2p
         dY4j2xqMgEuqVunBx8EaCoUzXoLzZbAqCZrqq4FC/5zrfLiTnPyTyWVTuHLAAAuFOO4w
         QZPUrKg/Nh6P1EVds8b/l0OeyM3hucIMiRBXBMgY7fAVJasNbo3wgXjRR/ing4tw/khx
         dwDf+NCKwBTLGIIJapTe9X2bKYzIWS3LY8FC6Oua7mMMi2S6qOGhXKVQA+zIDZp9KfvI
         rtWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xUdHSdHjipjMmOgxkDBgz8ehDecbyLH0zzOKxDt7MCc=;
        b=y+vW/paY4PUSyaOipv6pvic/ZktvtCgem/GUDX9z0MaXO29P61EXXHSlM8pRHzkXzw
         c4lP+xO4ZmVrV49CAUpLgkuXPzJ7qmgSTxDhXpVXkpNQfDlI9R7Ye4yax7Aw+N4F7dWI
         QR84rfOAovgSHpEBteqPzyyt4ZLV6Ac9fXqJQzCqeNvSbY0niyVICFxYqW0PiwonKRqC
         KyBQhF3RQmG+Ec076lHPLDxHfHKVvZgz2AMHVqtXHhvTVJk4NEoTxnYDYtT9GpmXs1ee
         x7Ku6x+9DlIqgwBdwPqUJztm/+yYZXehMDpG0djr9VetDWWHJmWW8QvnQ4niL+ktWArF
         vUsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iS56tw2t;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xUdHSdHjipjMmOgxkDBgz8ehDecbyLH0zzOKxDt7MCc=;
        b=CpKJ1cYVuMtdAikJHk6ghg7GhCD27ArGaqNwymsR3lrKDy6oYcPw35OyuxW4KQNr4e
         hKzI0B1Qor+ur5y+cnsks3DI+6DZ5rzGWAGesUjzt/IP7p8JR7gfe27ZotNoHhGm7hJ3
         /B0GwIhk8D3e8Eyp0St8XWZoOk9eQFCqvXSNBtZ1p6Jr8QQJCxf4fgMK6p23BYw2FT1Q
         YnotK/w1R7UoVatgY24uzfJZOVKh4c+qHHueNTUXrBQzi1w/9inlltz1XzvP/mhtPe7W
         PhWp6meOgpfYz5w3DOlxxAkr3/sKyizxd76yJYmsLnpMH2SbDMDIEPuX8ZLNcAvgWAC2
         QCdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xUdHSdHjipjMmOgxkDBgz8ehDecbyLH0zzOKxDt7MCc=;
        b=GQ2Y5evl1Y8ztFMYjtqxfU3dN3ucgo22+5vBZL5wFrD8ipAIdCUKQTW+wb3/Ko1TJw
         hhGR6JWLnKWAtYlZRfRA16xrljj4F7PKuxEG9exLLUR9IYI5Uw/ri9AGLqL9aywsZw0g
         dg9P7IALPP2vKVoIwemSg/p5+FUPtnkygBnfWumynBRFtes9hl+PHbTrs2PNmooQFLV9
         KM55nA7XO9bX2vEyPWAawEzruRzmJAk19ETK/luTf6K3eX6ywroBdfBfTv0DoaKhf3EE
         T9zhWrt9ZFw3qFVOBZ2pg8m4UgqSPDs9CfS4WIUFD91KKSnZODeY1dHb1MKi6rzaoY9T
         CXyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532WPUro+NgYHGU2z6jFeiLMQHDpV/rA18KK9XBZnyKv5XNWg0zz
	Sn7FAF43RD8V9r+WpD8g30k=
X-Google-Smtp-Source: ABdhPJzJc5jH7JFfZ9c6tDC0TFo/2cyuotZo6agxKTZC3Fg/4Sf5AXLFXCN6bSNww5Lw2+MyAsHFXQ==
X-Received: by 2002:a2e:82d0:: with SMTP id n16mr20869845ljh.238.1640891709847;
        Thu, 30 Dec 2021 11:15:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d2a:: with SMTP id d42ls2237825lfv.0.gmail; Thu,
 30 Dec 2021 11:15:09 -0800 (PST)
X-Received: by 2002:a05:6512:3341:: with SMTP id y1mr28090858lfd.311.1640891709195;
        Thu, 30 Dec 2021 11:15:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891709; cv=none;
        d=google.com; s=arc-20160816;
        b=dQP9Lnvdz/ClpQDWbBzUIIHI7hnL8nsz0NYxdsSGdxEnAhEcYDbRu3jUQu93x/vjdV
         OMhh9MY2wgiY4p9U2O23N9EhLMyN4rAqDqRq6qGX8TYRLSJkeIv6eqHrpyRpHj+Yifb4
         cI8fcmg7A6cB1A+etaXS9W2paTGMHQwhETO8cPdCc32BN+KbySntczDWa4cy5W/M3p3+
         Mm0PiilzYKLrp71SWL/MZM4AImocRj71SFnDB/qePK/iMbOXkmgZdz1c/ZZmZHsidnt6
         VK0dkSjm2YYgDe6GaEOXvSQ32T1qhpCBXrw/4F2oysCib1w67EwaEutonck0q/UQwTMv
         AUFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Lnm9A41ImFCEtqp3Gi0grxBV1YcMXYG5Az9GP4mftA4=;
        b=MD+0/EjdS6kopp0WTiuOdLuyiOReHQDTt94jO5I3YidHA4YDQp5X/uf5n+4x1cpUPg
         4dUYA80vzn0BmSp7szZS2BUZSAFVXzUG9POBoYoGixqmOqPWzYCdetpkxNWzlMsHgMZ3
         PM6Bi296O7PxIp6+eSkjAbJL3aAQ9jE2jsvNVpg9/WiXmmqjOqCZt1a/gr9+I1aQcP5P
         l0W78tPV/GpGOvHVQhoSir4bns1uvJLxQmyi8KbPwQram/eflRZ58pREIO9NlctqnArp
         Mcf48hi8omirjr42bPS5p/ELe8gThqfVNSnKBvPuGzimd3y7qIzJGDykDvrGj2XAgBjU
         UejA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iS56tw2t;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id v76si976743lfa.6.2021.12.30.11.15.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:15:09 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v5 19/39] kasan: reorder vmalloc hooks
Date: Thu, 30 Dec 2021 20:14:44 +0100
Message-Id: <08443a07096a5c955ce434bf65947d491fe6fae7.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=iS56tw2t;       spf=pass
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

Group functions that [de]populate shadow memory for vmalloc.
Group functions that [un]poison memory for vmalloc.

This patch does no functional changes but prepares KASAN code for
adding vmalloc support to HW_TAGS KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
 include/linux/kasan.h | 20 +++++++++-----------
 mm/kasan/shadow.c     | 43 ++++++++++++++++++++++---------------------
 2 files changed, 31 insertions(+), 32 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 55f1d4edf6b5..46a63374c86f 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -418,34 +418,32 @@ static inline void kasan_init_hw_tags(void) { }
 
 #ifdef CONFIG_KASAN_VMALLOC
 
+void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
 int kasan_populate_vmalloc(unsigned long addr, unsigned long size);
-void kasan_poison_vmalloc(const void *start, unsigned long size);
-void kasan_unpoison_vmalloc(const void *start, unsigned long size);
 void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
 
-void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
+void kasan_unpoison_vmalloc(const void *start, unsigned long size);
+void kasan_poison_vmalloc(const void *start, unsigned long size);
 
 #else /* CONFIG_KASAN_VMALLOC */
 
+static inline void kasan_populate_early_vm_area_shadow(void *start,
+						       unsigned long size) { }
 static inline int kasan_populate_vmalloc(unsigned long start,
 					unsigned long size)
 {
 	return 0;
 }
-
-static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
-{ }
-static inline void kasan_unpoison_vmalloc(const void *start, unsigned long size)
-{ }
 static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long end,
 					 unsigned long free_region_start,
-					 unsigned long free_region_end) {}
+					 unsigned long free_region_end) { }
 
-static inline void kasan_populate_early_vm_area_shadow(void *start,
-						       unsigned long size)
+static inline void kasan_unpoison_vmalloc(const void *start, unsigned long size)
+{ }
+static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
 { }
 
 #endif /* CONFIG_KASAN_VMALLOC */
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index e5c4393eb861..bf7ab62fbfb9 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -345,27 +345,6 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 	return 0;
 }
 
-/*
- * Poison the shadow for a vmalloc region. Called as part of the
- * freeing process at the time the region is freed.
- */
-void kasan_poison_vmalloc(const void *start, unsigned long size)
-{
-	if (!is_vmalloc_or_module_addr(start))
-		return;
-
-	size = round_up(size, KASAN_GRANULE_SIZE);
-	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
-}
-
-void kasan_unpoison_vmalloc(const void *start, unsigned long size)
-{
-	if (!is_vmalloc_or_module_addr(start))
-		return;
-
-	kasan_unpoison(start, size, false);
-}
-
 static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 					void *unused)
 {
@@ -496,6 +475,28 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	}
 }
 
+
+void kasan_unpoison_vmalloc(const void *start, unsigned long size)
+{
+	if (!is_vmalloc_or_module_addr(start))
+		return;
+
+	kasan_unpoison(start, size, false);
+}
+
+/*
+ * Poison the shadow for a vmalloc region. Called as part of the
+ * freeing process at the time the region is freed.
+ */
+void kasan_poison_vmalloc(const void *start, unsigned long size)
+{
+	if (!is_vmalloc_or_module_addr(start))
+		return;
+
+	size = round_up(size, KASAN_GRANULE_SIZE);
+	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
+}
+
 #else /* CONFIG_KASAN_VMALLOC */
 
 int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/08443a07096a5c955ce434bf65947d491fe6fae7.1640891329.git.andreyknvl%40google.com.
