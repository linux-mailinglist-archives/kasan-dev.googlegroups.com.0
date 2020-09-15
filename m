Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNG6QT5QKGQEIQCXPUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 926B426AF4F
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:16:36 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id j7sf1706512wro.14
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:16:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204596; cv=pass;
        d=google.com; s=arc-20160816;
        b=dYdgwEcYEV9Ajji/+u0Ifj2tXkm68wmZbiHlhlmfeSlW6qCgp+ymcCkcEvcot5dXQ5
         HvSrWAIUomfd41DlY06G3yaQeMb4hgUENx7W7OFriRoij/nSDrq70btKXMlG1Mq/rK8m
         +6/y3XMTURZFteOAzKgb9dDLEnvMGKmxP6XMqTzKhJq1wOa2GI1GwQOBnRdbg326TsSM
         tC7pRaj++RU61Ja/EqY6Ewo+r59Os0xYhl6DjKZz+Go3mRXzfIMuvEZuV4U7+weXLp/b
         kD0c50sPvX4L2OUoUPZ04nBDa/8kJq3WubhqkZEaIBnc1keHLacFDXMYznJAvBoRtPaj
         WVjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Z4xKW/fZke2E0lK2gSGOHYlvGUAu3l/66s1Ux6yMSg0=;
        b=vD+29/zmrgEcX0C8DEEo/gg3PyCjU2cJrE/CnuQvYcIvWBXUegQlC8hN7EWS8riEI2
         QmRQxtYXsNVpiV1KwSNideNtb4TG+1It0uD6xZ0frgLQEIoKy7G8WjlDVqcg27Fvosm0
         YndmsqPJOCpB3HPEaRAVg8bswRiqyshTiuRWUUdCCPB61GKTGqxj4cXOxkEORNbx9Ep3
         DTH+5Q8b8LTvXxnc48q8QFFppOpNE9KQIsE5EUk07VxDfoJiik9P/y3JvIBDE5u6uUcI
         GgatzbH083/fntKmioVkUOJjblazGzl9Asda9y0C9qBzO0ux/gxNsvkVz1KHk7VDV8xL
         Q8Og==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=t0eTYWs7;
       spf=pass (google.com: domain of 3mi9hxwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Mi9hXwoKCRcxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Z4xKW/fZke2E0lK2gSGOHYlvGUAu3l/66s1Ux6yMSg0=;
        b=sHW+gUw4MZ6oO6yoW51TTtP+BKvmnsTsCcxMJOq1zSR/kFDSdBFD/mE6Fy8hC6BnS7
         hK2NqPvgIw99zOb4JZnQB8zMIMO5h3uox80XoplCzx+KUyEjkpzO2qRng51VtE7ugQul
         8+sLwrF89dtrHoTygIC/lQgXKxjcJzw+neM69mdN5XBRXteUSehiXvQNRIcUKj8pwrY9
         1plwrIk/VbvfueXc/YNBGFc0KpnYAEaq7DcXEek5+dLdmSY8H/Ojt1omtw6IBbn3ttVP
         7JY72yfk/HvOIjsABoCe2499hfI1jRNsmJcXrZw0sYhz9tFQ7ahMNsi7yHBcHGsfAzmU
         NWLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z4xKW/fZke2E0lK2gSGOHYlvGUAu3l/66s1Ux6yMSg0=;
        b=YPbcxCqqYlAamyPN4G4EERziSMkc/zvmpdSOLknhLzR3NPli1VklbygWObYG0XlMYr
         M32EAFk0qL2CSFBBsqXocXD7CeBhqWP7nRR3J2a1pOds7NLlGteg/DDSIK48KuKPf83E
         4fhxpMfF2TFDk3p84A7OYT8P2SStK6EM75DYR52XhTzMSNWpy+sCHhfsyig8+LWRnkHV
         PsHLhDwQ40s62Wa5JYRBvCAeiYt380pklQO2VY1E/MfjENoPvegW+B2soqW6ZR6ZVBiN
         Y44dNVNqa2vsBcq7H9LLn0OwSeLkx8655UPH8z9ZJvz882+yh7Xrhl/wjcrB/Es1OWjh
         itPg==
X-Gm-Message-State: AOAM533NmhZlpKEWGS2uNrgNxZiEvOkaPreAvg/grk+BsIirm1NDHTsr
	YZLP47liIcoO0G/IfTpG/rY=
X-Google-Smtp-Source: ABdhPJysYkQHvWqxTYHlTCtMjWySNOCBmwXIq83gML344sM60HYjXyMVXgz7AqjGGTQPGwXbMiDTsg==
X-Received: by 2002:a1c:b407:: with SMTP id d7mr1293685wmf.59.1600204596308;
        Tue, 15 Sep 2020 14:16:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:428e:: with SMTP id k14ls355658wrq.0.gmail; Tue, 15 Sep
 2020 14:16:35 -0700 (PDT)
X-Received: by 2002:a5d:570b:: with SMTP id a11mr23919176wrv.139.1600204595438;
        Tue, 15 Sep 2020 14:16:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204595; cv=none;
        d=google.com; s=arc-20160816;
        b=Ppj6r2MZIyJ0Cl6rFM77s/sRXKlT4wVeTGd/RchNP4dErZgT2iVImNMalrE8hqg+Wm
         qcxWDjmQ41s/51/nzHfmUxfFKmcLWnnUi4bZQdoDZPL176Kp0zzuia8FJvfORduKAU4S
         m1vegxybCX6lOFgB3iI3OtsmjYbfVnnhC0mbLE3uUH03eAX2XQPcO3zdtwLSqfNBPWJP
         3Sn3rTKbOJUGk6faAiXYG2f1PExsSHGGFM/VWQCV1IFkkyQjFv7T39pfvUup220jI+hX
         qOEZZ2GJdv0RdwJpBdpxMnhF7jdU/pVdmPZTSzm2mAWkeCC9azoE/qhR2t9NobeiocJe
         UglA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=XoIhA9NWDSF4RgwX3fO6DA1DH9CaH0djORIURJ0FEcY=;
        b=nWtyIOyEYQGl5PxBaTWJ/Rs8lGKOOvTKrqru4yzet/SBQHhqLzGEBVt/ChJD+hi9Jv
         GotYgVmF2CdSaCJBLFwRK9SckILP5/pdSeQYuRVSyZEz9G/VNZn2sZNeTggdPhhTBYeH
         Z8tuPWqPmN5/KZY53UG33pdEflcFtEqTSj+mjhPR2Y+yPSgrLB2nWdupXeSWZmsugWu5
         X0B3lKDtnoAxDTuOaH1GjsG/5W8e47OTbe2rdHa4M+MzRTvaHOioX7Yqw0sm9RAJtGef
         IJZXrKiqwzVWau1kniz6MyGNGY3/6PZWF5MzV/vlnDRP2V9YaWROIdJvKNgRPiUE6yZp
         YAfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=t0eTYWs7;
       spf=pass (google.com: domain of 3mi9hxwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Mi9hXwoKCRcxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id z62si28014wmb.0.2020.09.15.14.16.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:16:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mi9hxwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id a12so1705821wrg.13
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:16:35 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:9ecb:: with SMTP id
 h194mr1206364wme.140.1600204594842; Tue, 15 Sep 2020 14:16:34 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:15:47 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <0d1862fec200eec644bbf0e2d5969fb94d2e923e.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 05/37] kasan: rename KASAN_SHADOW_* to KASAN_GRANULE_*
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
 header.i=@google.com header.s=20161025 header.b=t0eTYWs7;       spf=pass
 (google.com: domain of 3mi9hxwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Mi9hXwoKCRcxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
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
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: Iac733e2248aa9d29f6fc425d8946ba07cca73ecf
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
index 53e953bb1d1d..ddd0b80f24a1 100644
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
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0d1862fec200eec644bbf0e2d5969fb94d2e923e.1600204505.git.andreyknvl%40google.com.
