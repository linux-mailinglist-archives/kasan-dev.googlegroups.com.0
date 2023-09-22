Return-Path: <kasan-dev+bncBD2ZJZWL7ICRBU73WSUAMGQEPDRWVIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 021E97AA9BF
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Sep 2023 09:10:12 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-3fe182913c5sf14175515e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Sep 2023 00:10:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1695366611; cv=pass;
        d=google.com; s=arc-20160816;
        b=FH31mIZAU6lrFJhOShzDXd5GWwTZ1t4/uHZtgYq29szW0Xr38F4lK+Cd2ZYcsUMt3+
         SmfEw3+DMOemuXbwnT4BmaGC3P/IM1YZSn7zCiF56et4xNONu/cgI+gN9DSnEgrZNvbc
         qJptZcwCM1PfQnNghaP5uLN+Nfmj1JVDOBDnEulZNGlCiZqTYto4KUA6s0nc/mJJWc/u
         A6E12wzlm8AgnVa0gDcrQG8xy+HYmyQGIegbbf8icoKK/vJ/4uIgfjsQMPbZYwkK/cT0
         To6uOoywDg59coH2EM3I/BrTzBTwa3LmzvkGYpekmrP9jHqYMlg83qfzX8Wbcn3bHiug
         qkxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=yU6rqptjLxkvMPvT4y8eQu3LzOdbHXFwWOSBeByvOL4=;
        fh=KSy1dDf6lUvgdoPctzpy47/Mjv6bi14N3nvpkZLQDdc=;
        b=ao2pX5aNo3qaU7bmcVXRk8pu3UraLw0HUajBQJ1x2neQjGJW7gQU4kN5HOhQVzewPG
         l9eQIRH8PoRBbo8CbfoggSDwSlqmQQZc5t7RMJIqbXpATp2cM8qab93xcuVlkFTLlty0
         thgSc4LQibm7XCa4pjnOMRrrFejEbSQmS+GCCKdu4e7EoXYxOIplAZRq1C9HGrpV3h5O
         Ylw6BnN8wPlu3U6B5X7RY6IzYF7/7op/6Vhq18nQINzXZOFZU0N1Hroa1nfgEGyJ6eVb
         oAUNSD449M20gmPUDGWpm19XXw5xEdcAoy2YQdW11I0L9823RYh72iBlIQoYw64WcLPp
         oziQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iSP4Wnij;
       spf=pass (google.com: domain of yajun.deng@linux.dev designates 2001:41d0:1004:224b::e5 as permitted sender) smtp.mailfrom=yajun.deng@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1695366611; x=1695971411; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yU6rqptjLxkvMPvT4y8eQu3LzOdbHXFwWOSBeByvOL4=;
        b=Ltd3jX3z/R/WadMn7lSpFit1ElSWf3gfI5rH62kvIdSFu6W80MkCZrXXzDWGtX8X5T
         F9gP8yHca3MlrgwSkyUXnQr5pyAIze289zhBxbGO7w7a4quEqutcBWpjonu+00DV5K5K
         2bSCLHxgUvzslDJFfuzjmBFvz/v4vAOreBmxxETp2QGMZvsvFPGwD+sVRYaJc3GbpIkQ
         m8xPO7qGYgx86AeTWILURfYxuGWkq7T/T91UCYPulPAiBZPB6olZZ+E2vH1p3sSiYAcv
         VkjlCnw9WdEejXYGrVZL6KGIkbJSArWAsPNL5NNTuXyY6sSxl9JjfAu0C56L/2xXGFNa
         QcFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1695366611; x=1695971411;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yU6rqptjLxkvMPvT4y8eQu3LzOdbHXFwWOSBeByvOL4=;
        b=CTGfAZDpUqWul0NZcGepRPfNu8WCnrYGisHQDU9S2fqMlhEVbdmKr4k3ayXvAxC/is
         llucaycBMo2kgG1bP9SORKynYaVcJBEoD7dAQQtNGUfQAT3n3+RCP/a/7vqT7O+Ze3bO
         LJgTUzAujNlNgCt1DrJoe5ZYAKfyuMZ2TQqCeaD9TmSv2TT8mtLNBz/eMVG4xMYA13w9
         ky8piUmXESFiLeQVG3KO5TLzykp/RvnLr5v0/V9y4xJEcU9AusBZsXCjd2oP59gR7jQn
         B88YILw90KTzgJlN5cp6T6MkfyMWB372R1YLl+tR5mMcYyAqQEibvDH+GNn3jxSSty3Z
         KdKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx3lr7Pu2cl7olDUt90xNh2X+vJNLXKPy0KNk9xTESXxVRmOqkr
	NbMVJeR8dANx9Gj8I2nlZhw=
X-Google-Smtp-Source: AGHT+IFXPd2nkLpMFjZIjBeFUCy4glmWTOOGOjfyWFIH3xD1vZHpOMA1/eVDCbNV53WsporSEVc31A==
X-Received: by 2002:a5d:658b:0:b0:31f:e5b8:4693 with SMTP id q11-20020a5d658b000000b0031fe5b84693mr6016410wru.25.1695366611278;
        Fri, 22 Sep 2023 00:10:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ce92:0:b0:313:f4ee:a4cc with SMTP id r18-20020adfce92000000b00313f4eea4ccls54719wrn.1.-pod-prod-01-eu;
 Fri, 22 Sep 2023 00:10:09 -0700 (PDT)
X-Received: by 2002:adf:f104:0:b0:31f:dff5:cba7 with SMTP id r4-20020adff104000000b0031fdff5cba7mr6737633wro.6.1695366609659;
        Fri, 22 Sep 2023 00:10:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1695366609; cv=none;
        d=google.com; s=arc-20160816;
        b=KkTB58VuzBaeAFoTXrVa+DZpyLERiOnqPDeVA0wcAKc0qJXdWKAgI75R6uOwWqDvgU
         8J8vW77fQV9DbaNO5UyvHr5LAUJyFgWnqd1uojGVAi8oS3qh0LCfOxpHFBK1/at6d68u
         mV74vS5nF+19ytF3mUtkV6S2+X9a7BBflJH4vw8WCBgip1ZYVHyid0gUBKr0v9+BVQ5B
         7EyryEek4ysieA8QBpNzjtR1ZT29ujjvaUHE+UYRpeIrt39Q8hPP1QSEws1KkFFfSZI+
         MgcBV91g0M9Cp0hJdJbJoa4GQfESbCdyKQQmzeW1LuhHOarKU/+h36E+bNTOa1RrRnue
         LvyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eNDRWQx4rNnkd5izfMYcW2fBhjnfX3xJn3/1FZ3VThE=;
        fh=KSy1dDf6lUvgdoPctzpy47/Mjv6bi14N3nvpkZLQDdc=;
        b=zSkj9wmJZMz2up/jFCfu16YE11lv6HOy0J3dLdvXRgxr46MWXJPBfr95NuS2l3ykOD
         YdLrtJ4Oab/Q8NFBzOx6eKfk97tjezs+XCOmaZBnmQdRxmZX6uX1O9aIcyjlxP3934HE
         eXxBiQYOZQYfnZ3HYU+zvbEdmEy3T2TaXxvf/cxn7/gVF6veTEsn+7rsjn3xturWsKCF
         FyHNrXd7jGzXKUYITqOzvolA1I+xxrC+nPh8DXm7/cyarrJJxqwhtVSkro3V4pZkbbJQ
         BAYSVILCDE6RCmuEs4i46gOVGjllrruAUc8Nakf/DZQjRcz+PeGNNKqsUNmfGvOxKOCy
         kTxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iSP4Wnij;
       spf=pass (google.com: domain of yajun.deng@linux.dev designates 2001:41d0:1004:224b::e5 as permitted sender) smtp.mailfrom=yajun.deng@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-229.mta0.migadu.com (out-229.mta0.migadu.com. [2001:41d0:1004:224b::e5])
        by gmr-mx.google.com with ESMTPS id f7-20020a5d5687000000b0031acfc2c473si208565wrv.3.2023.09.22.00.10.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Sep 2023 00:10:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of yajun.deng@linux.dev designates 2001:41d0:1004:224b::e5 as permitted sender) client-ip=2001:41d0:1004:224b::e5;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Yajun Deng <yajun.deng@linux.dev>
To: akpm@linux-foundation.org,
	mike.kravetz@oracle.com,
	muchun.song@linux.dev,
	glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	rppt@kernel.org,
	david@redhat.com,
	osalvador@suse.de
Cc: linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Yajun Deng <yajun.deng@linux.dev>
Subject: [PATCH 2/4] mm: Introduce MEMINIT_LATE context
Date: Fri, 22 Sep 2023 15:09:21 +0800
Message-Id: <20230922070923.355656-3-yajun.deng@linux.dev>
In-Reply-To: <20230922070923.355656-1-yajun.deng@linux.dev>
References: <20230922070923.355656-1-yajun.deng@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: yajun.deng@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=iSP4Wnij;       spf=pass
 (google.com: domain of yajun.deng@linux.dev designates 2001:41d0:1004:224b::e5
 as permitted sender) smtp.mailfrom=yajun.deng@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

__free_pages_core() will always reset pages count and clear reserved flag.
It will consume a lot of time if there are a lot of pages.

Introduce MEMINIT_LATE context, if the context is MEMINIT_EARLY, we
don't need reset pages count and clear reserved flag.

Signed-off-by: Yajun Deng <yajun.deng@linux.dev>
---
 include/linux/mmzone.h |  1 +
 mm/internal.h          |  7 ++++---
 mm/kmsan/init.c        |  2 +-
 mm/memblock.c          |  4 ++--
 mm/memory_hotplug.c    |  2 +-
 mm/mm_init.c           | 11 ++++++-----
 mm/page_alloc.c        | 14 ++++++++------
 7 files changed, 23 insertions(+), 18 deletions(-)

diff --git a/include/linux/mmzone.h b/include/linux/mmzone.h
index 1e9cf3aa1097..253e792d409f 100644
--- a/include/linux/mmzone.h
+++ b/include/linux/mmzone.h
@@ -1442,6 +1442,7 @@ bool zone_watermark_ok_safe(struct zone *z, unsigned int order,
  */
 enum meminit_context {
 	MEMINIT_EARLY,
+	MEMINIT_LATE,
 	MEMINIT_HOTPLUG,
 };
 
diff --git a/mm/internal.h b/mm/internal.h
index 8bded7f98493..31737196257c 100644
--- a/mm/internal.h
+++ b/mm/internal.h
@@ -394,9 +394,10 @@ static inline void clear_zone_contiguous(struct zone *zone)
 extern int __isolate_free_page(struct page *page, unsigned int order);
 extern void __putback_isolated_page(struct page *page, unsigned int order,
 				    int mt);
-extern void memblock_free_pages(struct page *page, unsigned long pfn,
-					unsigned int order);
-extern void __free_pages_core(struct page *page, unsigned int order);
+extern void memblock_free_pages(unsigned long pfn, unsigned int order,
+				enum meminit_context context);
+extern void __free_pages_core(struct page *page, unsigned int order,
+			      enum meminit_context context);
 
 /*
  * This will have no effect, other than possibly generating a warning, if the
diff --git a/mm/kmsan/init.c b/mm/kmsan/init.c
index ffedf4dbc49d..b7ed98b854a6 100644
--- a/mm/kmsan/init.c
+++ b/mm/kmsan/init.c
@@ -172,7 +172,7 @@ static void do_collection(void)
 		shadow = smallstack_pop(&collect);
 		origin = smallstack_pop(&collect);
 		kmsan_setup_meta(page, shadow, origin, collect.order);
-		__free_pages_core(page, collect.order);
+		__free_pages_core(page, collect.order, MEMINIT_LATE);
 	}
 }
 
diff --git a/mm/memblock.c b/mm/memblock.c
index 5a88d6d24d79..a32364366bb2 100644
--- a/mm/memblock.c
+++ b/mm/memblock.c
@@ -1685,7 +1685,7 @@ void __init memblock_free_late(phys_addr_t base, phys_addr_t size)
 	end = PFN_DOWN(base + size);
 
 	for (; cursor < end; cursor++) {
-		memblock_free_pages(pfn_to_page(cursor), cursor, 0);
+		memblock_free_pages(cursor, 0, MEMINIT_LATE);
 		totalram_pages_inc();
 	}
 }
@@ -2089,7 +2089,7 @@ static void __init __free_pages_memory(unsigned long start, unsigned long end)
 		while (start + (1UL << order) > end)
 			order--;
 
-		memblock_free_pages(pfn_to_page(start), start, order);
+		memblock_free_pages(start, order, MEMINIT_LATE);
 
 		start += (1UL << order);
 	}
diff --git a/mm/memory_hotplug.c b/mm/memory_hotplug.c
index 3b301c4023ff..d38548265f26 100644
--- a/mm/memory_hotplug.c
+++ b/mm/memory_hotplug.c
@@ -634,7 +634,7 @@ void generic_online_page(struct page *page, unsigned int order)
 	 * case in page freeing fast path.
 	 */
 	debug_pagealloc_map_pages(page, 1 << order);
-	__free_pages_core(page, order);
+	__free_pages_core(page, order, MEMINIT_HOTPLUG);
 	totalram_pages_add(1UL << order);
 }
 EXPORT_SYMBOL_GPL(generic_online_page);
diff --git a/mm/mm_init.c b/mm/mm_init.c
index c40042098a82..0a4437aae30d 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -1976,7 +1976,7 @@ static void __init deferred_free_range(unsigned long pfn,
 	if (nr_pages == MAX_ORDER_NR_PAGES && IS_MAX_ORDER_ALIGNED(pfn)) {
 		for (i = 0; i < nr_pages; i += pageblock_nr_pages)
 			set_pageblock_migratetype(page + i, MIGRATE_MOVABLE);
-		__free_pages_core(page, MAX_ORDER);
+		__free_pages_core(page, MAX_ORDER, MEMINIT_LATE);
 		return;
 	}
 
@@ -1986,7 +1986,7 @@ static void __init deferred_free_range(unsigned long pfn,
 	for (i = 0; i < nr_pages; i++, page++, pfn++) {
 		if (pageblock_aligned(pfn))
 			set_pageblock_migratetype(page, MIGRATE_MOVABLE);
-		__free_pages_core(page, 0);
+		__free_pages_core(page, 0, MEMINIT_LATE);
 	}
 }
 
@@ -2568,9 +2568,10 @@ void __init set_dma_reserve(unsigned long new_dma_reserve)
 	dma_reserve = new_dma_reserve;
 }
 
-void __init memblock_free_pages(struct page *page, unsigned long pfn,
-							unsigned int order)
+void __init memblock_free_pages(unsigned long pfn, unsigned int order,
+				enum meminit_context context)
 {
+	struct page *page = pfn_to_page(pfn);
 
 	if (IS_ENABLED(CONFIG_DEFERRED_STRUCT_PAGE_INIT)) {
 		int nid = early_pfn_to_nid(pfn);
@@ -2583,7 +2584,7 @@ void __init memblock_free_pages(struct page *page, unsigned long pfn,
 		/* KMSAN will take care of these pages. */
 		return;
 	}
-	__free_pages_core(page, order);
+	__free_pages_core(page, order, context);
 }
 
 DEFINE_STATIC_KEY_MAYBE(CONFIG_INIT_ON_ALLOC_DEFAULT_ON, init_on_alloc);
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 06be8821d833..6c4f4531bee0 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1278,7 +1278,7 @@ static void __free_pages_ok(struct page *page, unsigned int order,
 	__count_vm_events(PGFREE, 1 << order);
 }
 
-void __free_pages_core(struct page *page, unsigned int order)
+void __free_pages_core(struct page *page, unsigned int order, enum meminit_context context)
 {
 	unsigned int nr_pages = 1 << order;
 	struct page *p = page;
@@ -1289,14 +1289,16 @@ void __free_pages_core(struct page *page, unsigned int order)
 	 * of all pages to 1 ("allocated"/"not free"). We have to set the
 	 * refcount of all involved pages to 0.
 	 */
-	prefetchw(p);
-	for (loop = 0; loop < (nr_pages - 1); loop++, p++) {
-		prefetchw(p + 1);
+	if (context != MEMINIT_EARLY) {
+		prefetchw(p);
+		for (loop = 0; loop < (nr_pages - 1); loop++, p++) {
+			prefetchw(p + 1);
+			__ClearPageReserved(p);
+			set_page_count(p, 0);
+		}
 		__ClearPageReserved(p);
 		set_page_count(p, 0);
 	}
-	__ClearPageReserved(p);
-	set_page_count(p, 0);
 
 	atomic_long_add(nr_pages, &page_zone(page)->managed_pages);
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230922070923.355656-3-yajun.deng%40linux.dev.
