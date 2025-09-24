Return-Path: <kasan-dev+bncBCCMH5WKTMGRBW4DZ7DAMGQEDC5OSBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 03C63B994FC
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 12:03:09 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-3f6b44ab789sf1827204f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 03:03:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758708188; cv=pass;
        d=google.com; s=arc-20240605;
        b=gbhe5N4kK/0O0z1bMAPqbP7nnxdHWcSZuE4xbDzYzH0weUa7nb52I8R/wUkPB1awp+
         R8EG/wBRTr/4VObtOi82Hf+8ugPURWvX5g82ygHA1FoXFDJ2i1oSP64m3pLJB90umTw/
         xiV7p0ze+aLCofFLye5Yhep0DUIeC9VHIKoKx0XCzKhWQgEJF3sgGdddNiZsXFfRyAPO
         zmUJK8tow0/RByGvIWtgKqLiFTJuxCBzpDJRf0oVX3/LJQH7jDvJuB7E8FtQme01yItP
         FSPxdS3IlyPSVgG+eLIIFVbFtIGMd1LVw9WrKR65OLVu+dFicWkLxiDtcwHmAUKtJxUI
         Ig4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=G01+is5owBFHf38mjJye9Lu6sXETYXYSMw91Yj1LT58=;
        fh=FV+JyTTY7x/DfUsSTHUSCwqW826Y1Vu3/II0ZNhNuvY=;
        b=KarNMmVNXHvfiswNqVW3GUUqyztasrHv0jqR6uBf5cjc7O5uIvRAh4Mr7gX1QRdNm5
         8GoeX4H6iFZKjrrKo2lwvf28NObKyG+uqaIrjbLZ5gs0RGKjYk0U96klcleMC0WQlsLM
         hkNjWcqZgaKIxxqpTCc6GON3z83luRoZMXAd+m7FfWEoydd+abb+Vzn2uttykyopTB0n
         9nZv2Ma37wboxBq7harWRkbZrXjKo+Ct2/4d+BuOjLdUEYR7sxSi3x3AnsbTQAa+FG08
         9zmShgOyQtDkp0gXEti4SqR8/Wb4kUH0vnNHYPSWhCOH8lrlvI9rJhTLJ4ye5hrOCo5K
         874A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SbSTNezN;
       spf=pass (google.com: domain of 32mhtaaykcfcfkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=32MHTaAYKCfcfkhcdqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758708188; x=1759312988; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=G01+is5owBFHf38mjJye9Lu6sXETYXYSMw91Yj1LT58=;
        b=T+jNT9awJjxzIQ2BCBeG+0PyhAWBRboPyuTnOjAxiWMsgjScFcPZ+JL5PXb+50RwFF
         fKOhW2z//5QmD4Tse+T1uTw6KS+87JRjxy66XbOsneae87lvXaoBkHRfYz+682NsJrR+
         UnPKItHOZ18ktPgTDbNusxTy5o0x0gL1Q9qvxbDAiqbxdX9pU0h9iWmBqbZpBI7ZhES5
         HA9S1YypqHOdRftSRnLUUAt8qd3/zAzpjwKxKBhdApsAwLgvop+sqcDnbD4fY26bQ1A6
         4Su+qUxD3gRn29mG4PGfL1YYzO2DIkJ+y+rE1RqMCO3RdJnyHcsbsLe2L3XrwOKSSDig
         gw9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758708188; x=1759312988;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=G01+is5owBFHf38mjJye9Lu6sXETYXYSMw91Yj1LT58=;
        b=HnpSsl++ENnv3FjeGOiuWrMcrwo30Lqo/2s3nYrVi+XCMmksLsP+DCNq+YUcrtMK77
         JwmjYnzglsZgiu1U/wZWzNjQoKAyWKrlzUDb6+uF6uvO3LU6YW6XxPW2QfuHJu9VVFWK
         gblvRYt2LBWMJ8ilA3DsaaQZzizmFvyA91dJyCO9pcsuGw5UzSf7Nz1H4fzxXxSx6tiW
         WviMLxtxjksbqhWTccQDoQbP/sDosczsWe26EN3z5yi+RRC3C+pvQSXAVwfHOAZxCY+8
         Kd4uXTD3iUOBTwuRt/HpGmeKsdz1juTTYErnE8husTbk6xVc7Jrn4XmjRYlQwfF+VuAG
         2cjw==
X-Forwarded-Encrypted: i=2; AJvYcCWF55Bu3N931ziTOtLfcZxh36m3rVUGZ/NntRBk3iHw/hVmTK2v9l8fmYRqQwQEysUpigjHgQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy978Fl+Q5zRZNVKKw4FVl6/n9wVXFY/d6fTh/kGJ4s2udfI2gr
	BOglFMZ9uyO701L4jQJlN4SOIobbYOGIJ30RS5zAv6R3jxbLaM5AWuhM
X-Google-Smtp-Source: AGHT+IEL9w1rQAQtWKwvi/ODYoJ1wKc5KfofDfyNFyM42jwIkwdIG9e2uPqj4Dk5YlUy7hDmpnR08Q==
X-Received: by 2002:a05:6000:40dc:b0:3f7:4637:f052 with SMTP id ffacd0b85a97d-405cb7bbb1bmr5583596f8f.44.1758708188096;
        Wed, 24 Sep 2025 03:03:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6FSkMJmX7UFDkzrkCSccOweBXS7BpVabU+gvtNTzO60g==
Received: by 2002:a05:600c:5290:b0:46b:38cc:d7cc with SMTP id
 5b1f17b1804b1-46b38ccd960ls34585145e9.2.-pod-prod-01-eu; Wed, 24 Sep 2025
 03:03:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU1sLK1U3vd5SygAvRhaxriPp/SO6H9eWWCxNvfBdcU/mHlDvtpzJzaPEfc7K8VX7iUx1KV3zslygA=@googlegroups.com
X-Received: by 2002:a05:6000:24c9:b0:400:1bbb:d257 with SMTP id ffacd0b85a97d-405c5ccd1e2mr5603309f8f.26.1758708185309;
        Wed, 24 Sep 2025 03:03:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758708185; cv=none;
        d=google.com; s=arc-20240605;
        b=NOclw7S/7uVc65EDtFjuF9JC4QwoQy6mpGacJSP9K57glDXSXPS+l+CS+vTlOmvIaG
         iX779+cJgjEcaUGrRf1a+K/gFJi4Q1fhyWLxzp4mLKLdqhz/96PAiGxmgQ+LsOGLfJ6W
         jrLGlL5p5yoQ/ILRzO2G/u2DAeLsxABXLB9FZ1QCNift9IBirfksqF2vWLbeZc14CkKj
         fqjrDCECUZHFI76p8uJMZASrncUmB0lAWG/aKGsg9VV0jD7CjQ0zmb40ThAncBRLKrVC
         VbQLERQpAowfgq7Qd3mFGFMXMitCUrtDttKx5gVbU4EhAiliklL+TygjqT4gq0nhyhoG
         LKeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=ZjocDtApH+mYILuh2MoVR7BbFeZzIGZsGcmRz0O6aqA=;
        fh=jewNmAwYZV1elOv33a4REUFxXyEKF3YUvUZ7vIvBWQ8=;
        b=DluLizfWXMiVpmVldM3JHkD6u8mZnQehpH0/b66qVCYtjtZr2kA12R6Q3QNOU734qU
         m/Ixx36oWgLYR5hR6LH/RtQZLJNplx/HLrHXh5XQBMcEUO2+3d4+rUM5lxoRJ6gMGoad
         ZpxLeMqktAS3FibaMrAAsfKnilJi431jWbp0n9LeLV48ownn51u7SW96Tju3H8TMd/DO
         /U4iscGNPNGUt67fO2vyrpFn5rLKD0WAdY4HughR7duhzeLkug+nZXahg11aosfAsd1P
         g6UEn/JecWyFNSiSzhQleZ2ahzIJkhBH9hiW7GoTJuE4/6cGDG2cxVKN63PfOWkrxI8A
         zRFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SbSTNezN;
       spf=pass (google.com: domain of 32mhtaaykcfcfkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=32MHTaAYKCfcfkhcdqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-46e2a9af972si215565e9.2.2025.09.24.03.03.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 03:03:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of 32mhtaaykcfcfkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-45e037fd142so54859545e9.3
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 03:03:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVZimn44RK+wETYyqfWYzjzGl3zK4xcsYr6ElOICXWrAP5Xc1FJxuPwHsKIH7njlDQ2HWSqHYV4uxc=@googlegroups.com
X-Received: from wrbet7.prod.google.com ([2002:a05:6000:2307:b0:3ed:665b:ec9d])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:288b:b0:3ee:1296:d9e6
 with SMTP id ffacd0b85a97d-405cdc1e751mr3789906f8f.61.1758708184637; Wed, 24
 Sep 2025 03:03:04 -0700 (PDT)
Date: Wed, 24 Sep 2025 12:03:01 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.51.0.534.gc79095c0ca-goog
Message-ID: <20250924100301.1558645-1-glider@google.com>
Subject: [PATCH v2] mm/memblock: Correct totalram_pages accounting with KMSAN
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: akpm@linux-foundation.org, david@redhat.com, vbabka@suse.cz, 
	rppt@kernel.org, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	elver@google.com, dvyukov@google.com, kasan-dev@googlegroups.com, 
	Aleksandr Nogikh <nogikh@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=SbSTNezN;       spf=pass
 (google.com: domain of 32mhtaaykcfcfkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=32MHTaAYKCfcfkhcdqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

When KMSAN is enabled, `kmsan_memblock_free_pages()` can hold back pages
for metadata instead of returning them to the early allocator. The callers,
however, would unconditionally increment `totalram_pages`, assuming the
pages were always freed. This resulted in an incorrect calculation of the
total available RAM, causing the kernel to believe it had more memory than
it actually did.

This patch refactors `memblock_free_pages()` to return the number of pages
it successfully frees. If KMSAN stashes the pages, the function now
returns 0; otherwise, it returns the number of pages in the block.

The callers in `memblock.c` have been updated to use this return value,
ensuring that `totalram_pages` is incremented only by the number of pages
actually returned to the allocator. This corrects the total RAM accounting
when KMSAN is active.

Cc: Aleksandr Nogikh <nogikh@google.com>
Fixes: 3c2065098260 ("init: kmsan: call KMSAN initialization routines")
Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: David Hildenbrand <david@redhat.com>

---
v2:
- Remove extern from the declaration of memblock_free_pages() in
  mm/internal.h as suggested by Mike Rapoport.
- Fix formatting in the definition of memblock_free_pages() in
  mm/mm_init.c as suggested by Mike Rapoport.
- Refactor memblock_free_late() to improve readability as suggested by
  David Hildenbrand.
---
 mm/internal.h |  4 ++--
 mm/memblock.c | 21 +++++++++++----------
 mm/mm_init.c  |  9 +++++----
 3 files changed, 18 insertions(+), 16 deletions(-)

diff --git a/mm/internal.h b/mm/internal.h
index 45b725c3dc030..ac841c53653eb 100644
--- a/mm/internal.h
+++ b/mm/internal.h
@@ -742,8 +742,8 @@ static inline void clear_zone_contiguous(struct zone *zone)
 extern int __isolate_free_page(struct page *page, unsigned int order);
 extern void __putback_isolated_page(struct page *page, unsigned int order,
 				    int mt);
-extern void memblock_free_pages(struct page *page, unsigned long pfn,
-					unsigned int order);
+unsigned long memblock_free_pages(struct page *page, unsigned long pfn,
+				  unsigned int order);
 extern void __free_pages_core(struct page *page, unsigned int order,
 		enum meminit_context context);
 
diff --git a/mm/memblock.c b/mm/memblock.c
index 117d963e677c9..9b23baee7dfe7 100644
--- a/mm/memblock.c
+++ b/mm/memblock.c
@@ -1826,6 +1826,7 @@ void *__init __memblock_alloc_or_panic(phys_addr_t size, phys_addr_t align,
 void __init memblock_free_late(phys_addr_t base, phys_addr_t size)
 {
 	phys_addr_t cursor, end;
+	unsigned long freed_pages = 0;
 
 	end = base + size - 1;
 	memblock_dbg("%s: [%pa-%pa] %pS\n",
@@ -1834,10 +1835,9 @@ void __init memblock_free_late(phys_addr_t base, phys_addr_t size)
 	cursor = PFN_UP(base);
 	end = PFN_DOWN(base + size);
 
-	for (; cursor < end; cursor++) {
-		memblock_free_pages(pfn_to_page(cursor), cursor, 0);
-		totalram_pages_inc();
-	}
+	for (; cursor < end; cursor++)
+		freed_pages += memblock_free_pages(pfn_to_page(cursor), cursor, 0);
+	totalram_pages_add(freed_pages);
 }
 
 /*
@@ -2259,9 +2259,11 @@ static void __init free_unused_memmap(void)
 #endif
 }
 
-static void __init __free_pages_memory(unsigned long start, unsigned long end)
+static unsigned long __init __free_pages_memory(unsigned long start,
+						unsigned long end)
 {
 	int order;
+	unsigned long freed = 0;
 
 	while (start < end) {
 		/*
@@ -2279,14 +2281,15 @@ static void __init __free_pages_memory(unsigned long start, unsigned long end)
 		while (start + (1UL << order) > end)
 			order--;
 
-		memblock_free_pages(pfn_to_page(start), start, order);
+		freed += memblock_free_pages(pfn_to_page(start), start, order);
 
 		start += (1UL << order);
 	}
+	return freed;
 }
 
 static unsigned long __init __free_memory_core(phys_addr_t start,
-				 phys_addr_t end)
+					       phys_addr_t end)
 {
 	unsigned long start_pfn = PFN_UP(start);
 	unsigned long end_pfn = PFN_DOWN(end);
@@ -2297,9 +2300,7 @@ static unsigned long __init __free_memory_core(phys_addr_t start,
 	if (start_pfn >= end_pfn)
 		return 0;
 
-	__free_pages_memory(start_pfn, end_pfn);
-
-	return end_pfn - start_pfn;
+	return __free_pages_memory(start_pfn, end_pfn);
 }
 
 static void __init memmap_init_reserved_pages(void)
diff --git a/mm/mm_init.c b/mm/mm_init.c
index 5c21b3af216b2..9883612768511 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -2548,24 +2548,25 @@ void *__init alloc_large_system_hash(const char *tablename,
 	return table;
 }
 
-void __init memblock_free_pages(struct page *page, unsigned long pfn,
-							unsigned int order)
+unsigned long __init memblock_free_pages(struct page *page, unsigned long pfn,
+					 unsigned int order)
 {
 	if (IS_ENABLED(CONFIG_DEFERRED_STRUCT_PAGE_INIT)) {
 		int nid = early_pfn_to_nid(pfn);
 
 		if (!early_page_initialised(pfn, nid))
-			return;
+			return 0;
 	}
 
 	if (!kmsan_memblock_free_pages(page, order)) {
 		/* KMSAN will take care of these pages. */
-		return;
+		return 0;
 	}
 
 	/* pages were reserved and not allocated */
 	clear_page_tag_ref(page);
 	__free_pages_core(page, order, MEMINIT_EARLY);
+	return 1UL << order;
 }
 
 DEFINE_STATIC_KEY_MAYBE(CONFIG_INIT_ON_ALLOC_DEFAULT_ON, init_on_alloc);
-- 
2.51.0.534.gc79095c0ca-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924100301.1558645-1-glider%40google.com.
