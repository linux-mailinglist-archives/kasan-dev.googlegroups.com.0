Return-Path: <kasan-dev+bncBDX4HWEMTEBRBCMT3P4QKGQEF3WP5OY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E6F9244DB9
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:27:37 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id f7sf3592576wrs.8
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:27:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426057; cv=pass;
        d=google.com; s=arc-20160816;
        b=FGuEBPrYPSSjf3FLjLzvhXdYlAA1xf4HSRVNKR0V/UQx5A8NtmEimDk1+Gw63b1hIr
         m3Bu6JHbTZohVTw76bDH5SgAa5u6G0USB/xuWxVeXc5FlDQFivgI374+zZ8cXm1tN9wR
         xUjK4lxGRxlfPBGHaVn45t5R7v68F7U1ogItzMhZx8mpZGWHYUE7d5pEh4b1zA4pvnyJ
         6omi+VZ8oDki08bXgW8ycg+uwoNSd2b+8UMUHVdG1QCMkPOBIr2d2pJ1yxRrjJx9280o
         dPOo33z+a2aFuISdMPowOOxtVHH/eotvOxkA/Ce5BMJ4Kt9Pt82bWo1jx6qc8MAf2KYs
         mjfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=vCcIg9SD35HGtu1ghsXjGGCsZXfKbrGmm23E0Kri+Dw=;
        b=jWT5uSqkqtm1eD8JxsU2Pax0ppL5Q6JcNeGFP3SLUMvPMCuNNqLztPb1ew61nS/mtP
         aSwRThyo9cw10vwGtnH3tzeIBrTV+sxNg6ijvTXez4wzRc1uJ9tXOLbT1MQrNhCSUZ05
         Geb8yz8wdF1DJvLZb2pVoQ537peeDvgNUbeuf6c5ztWYPIWQM0fVTKtVABu0hGc6zV+B
         AoKX+QlV5gZeCZV8KGCTJwMABM+wSWkgEMxf4XUB9D9S4iTzJtkctmHCTgzAToOK69LK
         WLH8/5Z5AGbAhRa3fP22Y/IUgEDy7ZpswyY0IjhmeRbHsSsk9Cb4MKvuw7+S8T1JLgr3
         b4bA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PkaDjnEO;
       spf=pass (google.com: domain of 3h8k2xwokcfqwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3h8k2XwoKCfQWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vCcIg9SD35HGtu1ghsXjGGCsZXfKbrGmm23E0Kri+Dw=;
        b=ju7coUu6lGhhiqf+o7Z3ad4se1MyK428AptH5xnqEJDdfYiR0AwXBnriB6ERawirbN
         DpUyqRb8A3azK+BRW7TCOCCLJRCGNQyhU1ClLvpo0tpJ2Bsh7jy0oKa5jlfAXokZNnWG
         GECgUJOt8oYYlLV/vvNEl4p0RXSTgIbfvgqmKMUIKqRxsg8jUKptd2CBCJL5it8Wk4H3
         +dViwtpk3eN7sn4pE/mByZcGgX6d0KXtkssSWKAVbXVbWGS6JfqIkLum0bf0phFdaWtZ
         3xFSc0rYIceFZ/ocSoTthkuUL7frUPifw0DGXjMdtV+UuoInvwFEYYGL6dkDYXVQgEhW
         rMxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vCcIg9SD35HGtu1ghsXjGGCsZXfKbrGmm23E0Kri+Dw=;
        b=VZBpfhwr9nEKKkwROUzXCy/J/5uDv9BpyZsDB3YyUskNhiWfsXosBKgY7vvAUtVW5B
         0sRrWUg0K6yVV/7RNlY8MwLFpn5AHHoXRTzU7Kr0FV4BCyj//W8fQ/2wkoTKGhrFRmzS
         6SHKVPo/neifiBShfZuZ7XRCT2/IbM/ObG8cOEB9llv1WZz+mQ/ps13gJmpmMBpNKtLD
         qCt2kWKaztwF3khxTPcnWnhG+9v34vyudjs7uXVXOaeQuUxLwM80mYQvCucQ7DoaryWw
         v/o+KTOaarPuyyCfZ6SwKtFV1c9q/3sNoHv28+OjAe/IIO71RyWGMu3fft8ao6d8s+1o
         71Iw==
X-Gm-Message-State: AOAM5326Yw25FkReugM0de0p29+zJ3Zcf9TffYU/nm6SHijfLZhw46YA
	b6cCvm/57j5x+m/Iq9WfXu8=
X-Google-Smtp-Source: ABdhPJx0+hVBxeQoLOTFY3EsmVB1PnE97VB50qRG6h+GdXlbrVv6odDlof2T6C4OiYM48CGm8IwBNQ==
X-Received: by 2002:a7b:cd97:: with SMTP id y23mr3562666wmj.21.1597426057286;
        Fri, 14 Aug 2020 10:27:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:81f4:: with SMTP id 107ls710307wra.2.gmail; Fri, 14 Aug
 2020 10:27:36 -0700 (PDT)
X-Received: by 2002:adf:92a1:: with SMTP id 30mr3933114wrn.56.1597426056686;
        Fri, 14 Aug 2020 10:27:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426056; cv=none;
        d=google.com; s=arc-20160816;
        b=SyVlY73Wc3ENaXC3vRzBXnt3AfcDEJtDetGTpWIDrzlXuomTjn294LqLgPoGtEsyPe
         UDJDKx6vftvBdFw9H1gqG20BHfRoNtA9v24biyeHkLKvHS0wHTpRvV+Lvw8FRUutPntj
         0HaWo2B+UWXZzzflTxgi2iq/0gB09J9HQUjwmlMrs7nTP+q0xBnuGV5cOYNhiHeKaLOB
         wTBtG8Gwf+EOy90uRazl4C3AvqiP1ausoR4Fo3aPXIXDxciCq+7ue7nSjUnchQTrK4D7
         DEuIsWO/zCLUUNeAVRIGChcruiKDZenfvCTwuFedQRCD1F2hqBy9eaGgd56sBS5hEXEd
         3nMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=bRu728EFW5d2BLJ1Gu8QpaNzOgGu693ugUiPSDZNjhM=;
        b=Mm8mftlyvnPh7K3CCtQjfemYlyfJNtNVELdUPJ7EDBn9b6jMR8Go8L/Q9CgUx+S+Eh
         Xhf2S2X4i5u/EGtNliagySibJg9tfTuDd+LrwJxQKeqPPpDArrLvekfGYR6Ez27SZqKl
         vrjtt24KM+M1jAS10DzesojnCPmtLYyrZVqX4ch9sb5OByco6XZZ3QtnYYrnZaIRjviW
         ZJMT4o9yejjLpMKtRmPR/7AtKTDxOAoYFet0/Fv/Rv6tvcfz37DJd8ibahxmvpp9GKbn
         BmhTz5J6/Cx/L4mEmEwXxKPAYEUMst8E8KjHmCMIbXMaBEE2BJYeFdfSj+H4ddWVihIz
         UZWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PkaDjnEO;
       spf=pass (google.com: domain of 3h8k2xwokcfqwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3h8k2XwoKCfQWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id w6si640250wmk.2.2020.08.14.10.27.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:27:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3h8k2xwokcfqwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id b13so3604793wrq.19
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:27:36 -0700 (PDT)
X-Received: by 2002:a05:600c:c3:: with SMTP id u3mr423894wmm.1.1597426055942;
 Fri, 14 Aug 2020 10:27:35 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:26:47 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <d4f7c14e57341ae52df4fde5425e2ae5d24534dd.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 05/35] kasan: rename KASAN_SHADOW_* to KASAN_GRANULE_*
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PkaDjnEO;       spf=pass
 (google.com: domain of 3h8k2xwokcfqwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3h8k2XwoKCfQWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

The new mode won't be using shadow memory, but will still use the concept
of memory granules. Rename KASAN_SHADOW_SCALE_SIZE to KASAN_GRANULE_SIZE,
and KASAN_SHADOW_MASK to KASAN_GRANULE_MASK.

Also use MASK when used as a mask, otherwise use SIZE.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst |  2 +-
 lib/test_kasan.c                  |  2 +-
 mm/kasan/common.c                 | 39 ++++++++++++++++---------------
 mm/kasan/generic.c                | 14 +++++------
 mm/kasan/generic_report.c         |  8 +++----
 mm/kasan/init.c                   |  8 +++----
 mm/kasan/kasan.h                  |  4 ++--
 mm/kasan/report.c                 | 10 ++++----
 mm/kasan/tags_report.c            |  2 +-
 9 files changed, 45 insertions(+), 44 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 38fd5681fade..a3030fc6afe5 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -264,7 +264,7 @@ Most mappings in vmalloc space are small, requiring less than a full
 page of shadow space. Allocating a full shadow page per mapping would
 therefore be wasteful. Furthermore, to ensure that different mappings
 use different shadow pages, mappings would have to be aligned to
-``KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE``.
+``KASAN_GRANULE_SIZE * PAGE_SIZE``.
 
 Instead, we share backing space across multiple mappings. We allocate
 a backing page when a mapping in vmalloc space uses a particular page
diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 5d3f496893ef..247a14f40016 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -25,7 +25,7 @@
 
 #include "../mm/kasan/kasan.h"
 
-#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_SHADOW_SCALE_SIZE)
+#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANULE_SIZE)
 
 /*
  * We assign some test results to these globals to make sure the tests
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 65933b27df81..c9daf2c33651 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -111,7 +111,7 @@ void *memcpy(void *dest, const void *src, size_t len)
 
 /*
  * Poisons the shadow memory for 'size' bytes starting from 'addr'.
- * Memory addresses should be aligned to KASAN_SHADOW_SCALE_SIZE.
+ * Memory addresses should be aligned to KASAN_GRANULE_SIZE.
  */
 void kasan_poison_memory(const void *address, size_t size, u8 value)
 {
@@ -143,13 +143,13 @@ void kasan_unpoison_memory(const void *address, size_t size)
 
 	kasan_poison_memory(address, size, tag);
 
-	if (size & KASAN_SHADOW_MASK) {
+	if (size & KASAN_GRANULE_MASK) {
 		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
 
 		if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
 			*shadow = tag;
 		else
-			*shadow = size & KASAN_SHADOW_MASK;
+			*shadow = size & KASAN_GRANULE_MASK;
 	}
 }
 
@@ -301,7 +301,7 @@ void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
 void kasan_poison_object_data(struct kmem_cache *cache, void *object)
 {
 	kasan_poison_memory(object,
-			round_up(cache->object_size, KASAN_SHADOW_SCALE_SIZE),
+			round_up(cache->object_size, KASAN_GRANULE_SIZE),
 			KASAN_KMALLOC_REDZONE);
 }
 
@@ -373,7 +373,7 @@ static inline bool shadow_invalid(u8 tag, s8 shadow_byte)
 {
 	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
 		return shadow_byte < 0 ||
-			shadow_byte >= KASAN_SHADOW_SCALE_SIZE;
+			shadow_byte >= KASAN_GRANULE_SIZE;
 
 	/* else CONFIG_KASAN_SW_TAGS: */
 	if ((u8)shadow_byte == KASAN_TAG_INVALID)
@@ -412,7 +412,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 		return true;
 	}
 
-	rounded_up_size = round_up(cache->object_size, KASAN_SHADOW_SCALE_SIZE);
+	rounded_up_size = round_up(cache->object_size, KASAN_GRANULE_SIZE);
 	kasan_poison_memory(object, rounded_up_size, KASAN_KMALLOC_FREE);
 
 	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
@@ -445,9 +445,9 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 		return NULL;
 
 	redzone_start = round_up((unsigned long)(object + size),
-				KASAN_SHADOW_SCALE_SIZE);
+				KASAN_GRANULE_SIZE);
 	redzone_end = round_up((unsigned long)object + cache->object_size,
-				KASAN_SHADOW_SCALE_SIZE);
+				KASAN_GRANULE_SIZE);
 
 	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
 		tag = assign_tag(cache, object, false, keep_tag);
@@ -491,7 +491,7 @@ void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
 
 	page = virt_to_page(ptr);
 	redzone_start = round_up((unsigned long)(ptr + size),
-				KASAN_SHADOW_SCALE_SIZE);
+				KASAN_GRANULE_SIZE);
 	redzone_end = (unsigned long)ptr + page_size(page);
 
 	kasan_unpoison_memory(ptr, size);
@@ -589,8 +589,8 @@ static int __meminit kasan_mem_notifier(struct notifier_block *nb,
 	shadow_size = nr_shadow_pages << PAGE_SHIFT;
 	shadow_end = shadow_start + shadow_size;
 
-	if (WARN_ON(mem_data->nr_pages % KASAN_SHADOW_SCALE_SIZE) ||
-		WARN_ON(start_kaddr % (KASAN_SHADOW_SCALE_SIZE << PAGE_SHIFT)))
+	if (WARN_ON(mem_data->nr_pages % KASAN_GRANULE_SIZE) ||
+		WARN_ON(start_kaddr % (KASAN_GRANULE_SIZE << PAGE_SHIFT)))
 		return NOTIFY_BAD;
 
 	switch (action) {
@@ -748,7 +748,7 @@ void kasan_poison_vmalloc(const void *start, unsigned long size)
 	if (!is_vmalloc_or_module_addr(start))
 		return;
 
-	size = round_up(size, KASAN_SHADOW_SCALE_SIZE);
+	size = round_up(size, KASAN_GRANULE_SIZE);
 	kasan_poison_memory(start, size, KASAN_VMALLOC_INVALID);
 }
 
@@ -861,22 +861,22 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	unsigned long region_start, region_end;
 	unsigned long size;
 
-	region_start = ALIGN(start, PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
-	region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
+	region_start = ALIGN(start, PAGE_SIZE * KASAN_GRANULE_SIZE);
+	region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_GRANULE_SIZE);
 
 	free_region_start = ALIGN(free_region_start,
-				  PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
+				  PAGE_SIZE * KASAN_GRANULE_SIZE);
 
 	if (start != region_start &&
 	    free_region_start < region_start)
-		region_start -= PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE;
+		region_start -= PAGE_SIZE * KASAN_GRANULE_SIZE;
 
 	free_region_end = ALIGN_DOWN(free_region_end,
-				     PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
+				     PAGE_SIZE * KASAN_GRANULE_SIZE);
 
 	if (end != region_end &&
 	    free_region_end > region_end)
-		region_end += PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE;
+		region_end += PAGE_SIZE * KASAN_GRANULE_SIZE;
 
 	shadow_start = kasan_mem_to_shadow((void *)region_start);
 	shadow_end = kasan_mem_to_shadow((void *)region_end);
@@ -902,7 +902,8 @@ int kasan_module_alloc(void *addr, size_t size)
 	unsigned long shadow_start;
 
 	shadow_start = (unsigned long)kasan_mem_to_shadow(addr);
-	scaled_size = (size + KASAN_SHADOW_MASK) >> KASAN_SHADOW_SCALE_SHIFT;
+	scaled_size = (size + KASAN_GRANULE_SIZE - 1) >>
+				KASAN_SHADOW_SCALE_SHIFT;
 	shadow_size = round_up(scaled_size, PAGE_SIZE);
 
 	if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 4b5f905198d8..f6d68aa9872f 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -51,7 +51,7 @@ static __always_inline bool memory_is_poisoned_1(unsigned long addr)
 	s8 shadow_value = *(s8 *)kasan_mem_to_shadow((void *)addr);
 
 	if (unlikely(shadow_value)) {
-		s8 last_accessible_byte = addr & KASAN_SHADOW_MASK;
+		s8 last_accessible_byte = addr & KASAN_GRANULE_MASK;
 		return unlikely(last_accessible_byte >= shadow_value);
 	}
 
@@ -67,7 +67,7 @@ static __always_inline bool memory_is_poisoned_2_4_8(unsigned long addr,
 	 * Access crosses 8(shadow size)-byte boundary. Such access maps
 	 * into 2 shadow bytes, so we need to check them both.
 	 */
-	if (unlikely(((addr + size - 1) & KASAN_SHADOW_MASK) < size - 1))
+	if (unlikely(((addr + size - 1) & KASAN_GRANULE_MASK) < size - 1))
 		return *shadow_addr || memory_is_poisoned_1(addr + size - 1);
 
 	return memory_is_poisoned_1(addr + size - 1);
@@ -78,7 +78,7 @@ static __always_inline bool memory_is_poisoned_16(unsigned long addr)
 	u16 *shadow_addr = (u16 *)kasan_mem_to_shadow((void *)addr);
 
 	/* Unaligned 16-bytes access maps into 3 shadow bytes. */
-	if (unlikely(!IS_ALIGNED(addr, KASAN_SHADOW_SCALE_SIZE)))
+	if (unlikely(!IS_ALIGNED(addr, KASAN_GRANULE_SIZE)))
 		return *shadow_addr || memory_is_poisoned_1(addr + 15);
 
 	return *shadow_addr;
@@ -139,7 +139,7 @@ static __always_inline bool memory_is_poisoned_n(unsigned long addr,
 		s8 *last_shadow = (s8 *)kasan_mem_to_shadow((void *)last_byte);
 
 		if (unlikely(ret != (unsigned long)last_shadow ||
-			((long)(last_byte & KASAN_SHADOW_MASK) >= *last_shadow)))
+			((long)(last_byte & KASAN_GRANULE_MASK) >= *last_shadow)))
 			return true;
 	}
 	return false;
@@ -205,7 +205,7 @@ void kasan_cache_shutdown(struct kmem_cache *cache)
 
 static void register_global(struct kasan_global *global)
 {
-	size_t aligned_size = round_up(global->size, KASAN_SHADOW_SCALE_SIZE);
+	size_t aligned_size = round_up(global->size, KASAN_GRANULE_SIZE);
 
 	kasan_unpoison_memory(global->beg, global->size);
 
@@ -279,10 +279,10 @@ EXPORT_SYMBOL(__asan_handle_no_return);
 /* Emitted by compiler to poison alloca()ed objects. */
 void __asan_alloca_poison(unsigned long addr, size_t size)
 {
-	size_t rounded_up_size = round_up(size, KASAN_SHADOW_SCALE_SIZE);
+	size_t rounded_up_size = round_up(size, KASAN_GRANULE_SIZE);
 	size_t padding_size = round_up(size, KASAN_ALLOCA_REDZONE_SIZE) -
 			rounded_up_size;
-	size_t rounded_down_size = round_down(size, KASAN_SHADOW_SCALE_SIZE);
+	size_t rounded_down_size = round_down(size, KASAN_GRANULE_SIZE);
 
 	const void *left_redzone = (const void *)(addr -
 			KASAN_ALLOCA_REDZONE_SIZE);
diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
index a38c7a9e192a..4dce1633b082 100644
--- a/mm/kasan/generic_report.c
+++ b/mm/kasan/generic_report.c
@@ -39,7 +39,7 @@ void *find_first_bad_addr(void *addr, size_t size)
 	void *p = addr;
 
 	while (p < addr + size && !(*(u8 *)kasan_mem_to_shadow(p)))
-		p += KASAN_SHADOW_SCALE_SIZE;
+		p += KASAN_GRANULE_SIZE;
 	return p;
 }
 
@@ -51,14 +51,14 @@ static const char *get_shadow_bug_type(struct kasan_access_info *info)
 	shadow_addr = (u8 *)kasan_mem_to_shadow(info->first_bad_addr);
 
 	/*
-	 * If shadow byte value is in [0, KASAN_SHADOW_SCALE_SIZE) we can look
+	 * If shadow byte value is in [0, KASAN_GRANULE_SIZE) we can look
 	 * at the next shadow byte to determine the type of the bad access.
 	 */
-	if (*shadow_addr > 0 && *shadow_addr <= KASAN_SHADOW_SCALE_SIZE - 1)
+	if (*shadow_addr > 0 && *shadow_addr <= KASAN_GRANULE_SIZE - 1)
 		shadow_addr++;
 
 	switch (*shadow_addr) {
-	case 0 ... KASAN_SHADOW_SCALE_SIZE - 1:
+	case 0 ... KASAN_GRANULE_SIZE - 1:
 		/*
 		 * In theory it's still possible to see these shadow values
 		 * due to a data race in the kernel code.
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index fe6be0be1f76..754b641c83c7 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -447,8 +447,8 @@ void kasan_remove_zero_shadow(void *start, unsigned long size)
 	end = addr + (size >> KASAN_SHADOW_SCALE_SHIFT);
 
 	if (WARN_ON((unsigned long)start %
-			(KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE)) ||
-	    WARN_ON(size % (KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE)))
+			(KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
+	    WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
 		return;
 
 	for (; addr < end; addr = next) {
@@ -482,8 +482,8 @@ int kasan_add_zero_shadow(void *start, unsigned long size)
 	shadow_end = shadow_start + (size >> KASAN_SHADOW_SCALE_SHIFT);
 
 	if (WARN_ON((unsigned long)start %
-			(KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE)) ||
-	    WARN_ON(size % (KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE)))
+			(KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
+	    WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
 		return -EINVAL;
 
 	ret = kasan_populate_early_shadow(shadow_start, shadow_end);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 03450d3b31f7..c31e2c739301 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -5,8 +5,8 @@
 #include <linux/kasan.h>
 #include <linux/stackdepot.h>
 
-#define KASAN_SHADOW_SCALE_SIZE (1UL << KASAN_SHADOW_SCALE_SHIFT)
-#define KASAN_SHADOW_MASK       (KASAN_SHADOW_SCALE_SIZE - 1)
+#define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
+#define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
 
 #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
 #define KASAN_TAG_INVALID	0xFE /* inaccessible memory tag */
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 4f49fa6cd1aa..7c025d792e2f 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -317,24 +317,24 @@ static bool __must_check get_address_stack_frame_info(const void *addr,
 		return false;
 
 	aligned_addr = round_down((unsigned long)addr, sizeof(long));
-	mem_ptr = round_down(aligned_addr, KASAN_SHADOW_SCALE_SIZE);
+	mem_ptr = round_down(aligned_addr, KASAN_GRANULE_SIZE);
 	shadow_ptr = kasan_mem_to_shadow((void *)aligned_addr);
 	shadow_bottom = kasan_mem_to_shadow(end_of_stack(current));
 
 	while (shadow_ptr >= shadow_bottom && *shadow_ptr != KASAN_STACK_LEFT) {
 		shadow_ptr--;
-		mem_ptr -= KASAN_SHADOW_SCALE_SIZE;
+		mem_ptr -= KASAN_GRANULE_SIZE;
 	}
 
 	while (shadow_ptr >= shadow_bottom && *shadow_ptr == KASAN_STACK_LEFT) {
 		shadow_ptr--;
-		mem_ptr -= KASAN_SHADOW_SCALE_SIZE;
+		mem_ptr -= KASAN_GRANULE_SIZE;
 	}
 
 	if (shadow_ptr < shadow_bottom)
 		return false;
 
-	frame = (const unsigned long *)(mem_ptr + KASAN_SHADOW_SCALE_SIZE);
+	frame = (const unsigned long *)(mem_ptr + KASAN_GRANULE_SIZE);
 	if (frame[0] != KASAN_CURRENT_STACK_FRAME_MAGIC) {
 		pr_err("KASAN internal error: frame info validation failed; invalid marker: %lu\n",
 		       frame[0]);
@@ -572,6 +572,6 @@ void kasan_non_canonical_hook(unsigned long addr)
 	else
 		bug_type = "maybe wild-memory-access";
 	pr_alert("KASAN: %s in range [0x%016lx-0x%016lx]\n", bug_type,
-		 orig_addr, orig_addr + KASAN_SHADOW_MASK);
+		 orig_addr, orig_addr + KASAN_GRANULE_SIZE - 1);
 }
 #endif
diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
index bee43717d6f0..6ddb55676a7c 100644
--- a/mm/kasan/tags_report.c
+++ b/mm/kasan/tags_report.c
@@ -81,7 +81,7 @@ void *find_first_bad_addr(void *addr, size_t size)
 	void *end = p + size;
 
 	while (p < end && tag == *(u8 *)kasan_mem_to_shadow(p))
-		p += KASAN_SHADOW_SCALE_SIZE;
+		p += KASAN_GRANULE_SIZE;
 	return p;
 }
 
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d4f7c14e57341ae52df4fde5425e2ae5d24534dd.1597425745.git.andreyknvl%40google.com.
