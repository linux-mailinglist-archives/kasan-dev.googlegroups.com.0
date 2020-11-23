Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQVN6D6QKGQEOIGDDFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F3F92C153E
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:08:36 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id 143sf9630223pfv.16
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:08:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162115; cv=pass;
        d=google.com; s=arc-20160816;
        b=GgeWBwyRoTkF0jLhq6baEYraB4fc8Zsv71wTFQpUyv6gMkiKIOuQFePsaWYewcIs06
         WBDmsXwJQ9b/HrVfdNn7zkoV+OFmni9tEgJbsjgnsu+CtoZNmE5zPS/pWNbrq8URJqVw
         UzkyrYvzhyMuBypAYaEZvSVz7PuWQvpnIcEoLZEa799f7dNjS9XM12oyAz6cqEl8Zpqq
         hLl2Bwz431lB+U7jw8qujLKDOKiK6FtThXIskzMMZB673d2BJ86/qe65Bqeo++nrEUKH
         hdsVvJ5fSaPruSvRTqbEw3xSzcVhJQXotKXt0CA7ILoxGO5c5tZ3UpXvf3cgHs8uPzf2
         zsaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Q4DMwh8FAw+/0ttscSIdy3rYeCMuol7fWDLMZvfb4Qc=;
        b=z6ISW+LUSZnZcF8ZOHLwP49DfBQxv/G2SJgv4RKUmwZepJ4GIsgC3b8avEdDyOXa7k
         39ptQCa45IKF4g8PfcfNnDf6lZQkJXsz4FFjrMXpsZCnQL4VWUweyISuRtxf6Q4IVSpg
         m4MKR0BRzDYCHmf7KfpPZbE7+JhzAd47BY4uE0Lon/na85vOqAPTnYg+uB97476wJURD
         ZQhqWzSgWd6XqdGtaEvGqofDGvYm1KuvOoQqMtCGGfI1rD1/gONGhrJw/ER2egetJ21y
         naVy4uOui0vTuZ7ZsqNZPxNgdeGSNnEPgvZcskLQzVeM/H/OHk3wkH8Afm/EIu5UGZa3
         HmjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YSoCfppK;
       spf=pass (google.com: domain of 3wra8xwokceierhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3wRa8XwoKCeIERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Q4DMwh8FAw+/0ttscSIdy3rYeCMuol7fWDLMZvfb4Qc=;
        b=NkQ93SBA2kEQ5WLP2MsO4vlrSd7YHCtZNNc3ADM8A6k3oplQXox5LK+JJTQgcJB/4q
         ZjQ72+UWORawnD98SvxzHqfx3Ft7xHVzUIe9koMhczwMk8KfKOA3CL4GvjSmSKcNjARI
         uK/U+hNOpewOEg6GtX1oiJISCKfFNUEsIQaihhYhXZwt0BMW/qa97ffcis+qx9rxhLZ+
         BsSfRpdJK1ajrzElcO6QN+hUx9EHkV+mt8dtH5ofA7Py4HzULPQUzzErHKRokzdoMulD
         Z7crKUHFjeOV7Z7RqlUh73O1kBHNhUiN5Q+UBlGVaCvZfsGsNMmTIwkxDgBOC0CeRiF2
         n2ZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q4DMwh8FAw+/0ttscSIdy3rYeCMuol7fWDLMZvfb4Qc=;
        b=bk2qK8Yurzudz4WR2zWhrAROTefp7XsPnfPPRsPpdsNvuccg6FlB/du++CkSEzf1KU
         ICEq+7rPDd/S1ZPPccV6q46gmC8YWjc2N/vBRQO1IU/VlLeaihfixreH/NyAAL8uKYQM
         +Emwd7UpEs029D2KliSKEdO4bb6PoYhDEeQDrf07ck+lSar6cxB9Gy/cV5AlQIuFWUrs
         otqCqS3ejJkJzas+hgK0oOjJpRTCuRKvWENZnjIf8OMsQ+AoHO9/ZC7zpUjpYrkRs/Mz
         ZhL1cCev9laclQ+r/TRnLkLBIm7bz+ouWzl6/6s5QAE2E9HmimuuT9DYyVsuZ3rL/qJN
         HCPQ==
X-Gm-Message-State: AOAM532Zk7fh06sX/V8CpizrTes2kgfiDjK4gX4LILzdeWdW23AMa4Od
	GVUOpXg5rEPwh3ZN546UoAE=
X-Google-Smtp-Source: ABdhPJzuZrDxMS7AAMtQ1QXDYt2wX9Itg+bj25BrREzTr1mdXmfCfn+Bgvavo3vMBR8sN/M03cQWSg==
X-Received: by 2002:a17:90a:ea89:: with SMTP id h9mr632953pjz.227.1606162115038;
        Mon, 23 Nov 2020 12:08:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:524:: with SMTP id 33ls6687323plf.6.gmail; Mon, 23
 Nov 2020 12:08:34 -0800 (PST)
X-Received: by 2002:a17:902:8341:b029:d8:d123:2297 with SMTP id z1-20020a1709028341b02900d8d1232297mr1010514pln.65.1606162114432;
        Mon, 23 Nov 2020 12:08:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162114; cv=none;
        d=google.com; s=arc-20160816;
        b=S4jT+vF69AOdzFdzxB84pscBL4aD7HUSHPY5ffAP4uk4naoL0qU9HSkY6iXMaLJUEI
         y1ygVJ/V/Yu5/BaIVTDrPwPxCNltf5KO40sUTeRQNw59upnKIabxRYUja3/RgbWAsAfc
         Hc4t1LdhtzRp19pkdBvcVAThYnmKt3Mb3KAR7es1rzhWL2+YyYGPI6DuiqDy76NqMQ0F
         /IKRYI1kXfKg7RdoYZNJ4PuVygIe8eAHXD9ledtqipLrUOD0Gs1ANawtQNAezy3037sb
         XtGCuURF150d/4DxtBHela8zQMHlEP4+5/sNmiYVKTCyLYfu62xSJLqrKXTSz08Ij4A7
         h7Xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=hMc/Qp6Xj3haf/LF7qlu7Ur99+rU3tZ6npfM7aHztzM=;
        b=orDntJdhdozEPq0jLaoSzMRazyhf7fB93m+k+6scCvvLHU2EBRaX9RmOFpb63C9Gq9
         I4/2N2G+wL6wJxEUBdn1+9r0j//iUQpR/bQVFb1iiIolGs9lUr3qalRRW7YAZWRqlSZa
         5tQWOcr4leV7dkNPeHLFV2X3feM0LR9dY6dM9tNuRi+UDxD8EDwGjoLMDvvb4IBrI8Ms
         s7rk0jA1BPOg4mv5uZ82NKYnCqitqzXdCriY3PVY7knLLr+CXNq9uSOhLd7Y9mTPxLeP
         r3hUhiahx47WDUXXucj2wuMpW3mQQj0aITmaWfffxyvBF0oQxE9Mz6kOzH/JoE0Vxet5
         VhJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YSoCfppK;
       spf=pass (google.com: domain of 3wra8xwokceierhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3wRa8XwoKCeIERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id mp11si36236pjb.1.2020.11.23.12.08.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:08:34 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wra8xwokceierhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id a22so5030318qtx.20
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:08:34 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:5bef:: with SMTP id
 k15mr1207709qvc.25.1606162113470; Mon, 23 Nov 2020 12:08:33 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:30 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <939b5754e47f528a6e6a6f28ffc5815d8d128033.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 06/42] kasan: rename KASAN_SHADOW_* to KASAN_GRANULE_*
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YSoCfppK;       spf=pass
 (google.com: domain of 3wra8xwokceierhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3wRa8XwoKCeIERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
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
of memory granules. Each memory granule maps to a single metadata entry:
8 bytes per one shadow byte for generic mode, 16 bytes per one shadow byte
for software tag-based mode, and 16 bytes per one allocation tag for
hardware tag-based mode.

Rename KASAN_SHADOW_SCALE_SIZE to KASAN_GRANULE_SIZE, and KASAN_SHADOW_MASK
to KASAN_GRANULE_MASK.

Also use MASK when used as a mask, otherwise use SIZE.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: Iac733e2248aa9d29f6fc425d8946ba07cca73ecf
---
 Documentation/dev-tools/kasan.rst |  2 +-
 lib/test_kasan.c                  |  2 +-
 lib/test_kasan_module.c           |  2 +-
 mm/kasan/common.c                 | 39 ++++++++++++++++---------------
 mm/kasan/generic.c                | 14 +++++------
 mm/kasan/generic_report.c         |  8 +++----
 mm/kasan/init.c                   |  8 +++----
 mm/kasan/kasan.h                  |  4 ++--
 mm/kasan/report.c                 | 10 ++++----
 mm/kasan/tags_report.c            |  2 +-
 10 files changed, 46 insertions(+), 45 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index b3e489064a18..2d55d788971c 100644
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
index 662f862702fc..2947274cc2d3 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -25,7 +25,7 @@
 
 #include "../mm/kasan/kasan.h"
 
-#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_SHADOW_SCALE_SIZE)
+#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANULE_SIZE)
 
 /*
  * We assign some test results to these globals to make sure the tests
diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
index 2d68db6ae67b..fcb991c3aaf8 100644
--- a/lib/test_kasan_module.c
+++ b/lib/test_kasan_module.c
@@ -15,7 +15,7 @@
 
 #include "../mm/kasan/kasan.h"
 
-#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_SHADOW_SCALE_SIZE)
+#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANULE_SIZE)
 
 static noinline void __init copy_user_test(void)
 {
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6adbf5891aff..80dd71e88ef8 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -107,7 +107,7 @@ void *memcpy(void *dest, const void *src, size_t len)
 
 /*
  * Poisons the shadow memory for 'size' bytes starting from 'addr'.
- * Memory addresses should be aligned to KASAN_SHADOW_SCALE_SIZE.
+ * Memory addresses should be aligned to KASAN_GRANULE_SIZE.
  */
 void poison_range(const void *address, size_t size, u8 value)
 {
@@ -151,13 +151,13 @@ void unpoison_range(const void *address, size_t size)
 
 	poison_range(address, size, tag);
 
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
 
@@ -314,7 +314,7 @@ void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
 void kasan_poison_object_data(struct kmem_cache *cache, void *object)
 {
 	poison_range(object,
-			round_up(cache->object_size, KASAN_SHADOW_SCALE_SIZE),
+			round_up(cache->object_size, KASAN_GRANULE_SIZE),
 			KASAN_KMALLOC_REDZONE);
 }
 
@@ -386,7 +386,7 @@ static inline bool shadow_invalid(u8 tag, s8 shadow_byte)
 {
 	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
 		return shadow_byte < 0 ||
-			shadow_byte >= KASAN_SHADOW_SCALE_SIZE;
+			shadow_byte >= KASAN_GRANULE_SIZE;
 
 	/* else CONFIG_KASAN_SW_TAGS: */
 	if ((u8)shadow_byte == KASAN_TAG_INVALID)
@@ -428,7 +428,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 		return true;
 	}
 
-	rounded_up_size = round_up(cache->object_size, KASAN_SHADOW_SCALE_SIZE);
+	rounded_up_size = round_up(cache->object_size, KASAN_GRANULE_SIZE);
 	poison_range(object, rounded_up_size, KASAN_KMALLOC_FREE);
 
 	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
@@ -464,9 +464,9 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 		return (void *)object;
 
 	redzone_start = round_up((unsigned long)(object + size),
-				KASAN_SHADOW_SCALE_SIZE);
+				KASAN_GRANULE_SIZE);
 	redzone_end = round_up((unsigned long)object + cache->object_size,
-				KASAN_SHADOW_SCALE_SIZE);
+				KASAN_GRANULE_SIZE);
 
 	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
 		tag = assign_tag(cache, object, false, keep_tag);
@@ -510,7 +510,7 @@ void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
 
 	page = virt_to_page(ptr);
 	redzone_start = round_up((unsigned long)(ptr + size),
-				KASAN_SHADOW_SCALE_SIZE);
+				KASAN_GRANULE_SIZE);
 	redzone_end = (unsigned long)ptr + page_size(page);
 
 	unpoison_range(ptr, size);
@@ -608,8 +608,8 @@ static int __meminit kasan_mem_notifier(struct notifier_block *nb,
 	shadow_size = nr_shadow_pages << PAGE_SHIFT;
 	shadow_end = shadow_start + shadow_size;
 
-	if (WARN_ON(mem_data->nr_pages % KASAN_SHADOW_SCALE_SIZE) ||
-		WARN_ON(start_kaddr % (KASAN_SHADOW_SCALE_SIZE << PAGE_SHIFT)))
+	if (WARN_ON(mem_data->nr_pages % KASAN_GRANULE_SIZE) ||
+		WARN_ON(start_kaddr % (KASAN_GRANULE_SIZE << PAGE_SHIFT)))
 		return NOTIFY_BAD;
 
 	switch (action) {
@@ -767,7 +767,7 @@ void kasan_poison_vmalloc(const void *start, unsigned long size)
 	if (!is_vmalloc_or_module_addr(start))
 		return;
 
-	size = round_up(size, KASAN_SHADOW_SCALE_SIZE);
+	size = round_up(size, KASAN_GRANULE_SIZE);
 	poison_range(start, size, KASAN_VMALLOC_INVALID);
 }
 
@@ -880,22 +880,22 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
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
@@ -921,7 +921,8 @@ int kasan_module_alloc(void *addr, size_t size)
 	unsigned long shadow_start;
 
 	shadow_start = (unsigned long)kasan_mem_to_shadow(addr);
-	scaled_size = (size + KASAN_SHADOW_MASK) >> KASAN_SHADOW_SCALE_SHIFT;
+	scaled_size = (size + KASAN_GRANULE_SIZE - 1) >>
+				KASAN_SHADOW_SCALE_SHIFT;
 	shadow_size = round_up(scaled_size, PAGE_SIZE);
 
 	if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index cdc2d8112f3e..754217c258a8 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -47,7 +47,7 @@ static __always_inline bool memory_is_poisoned_1(unsigned long addr)
 	s8 shadow_value = *(s8 *)kasan_mem_to_shadow((void *)addr);
 
 	if (unlikely(shadow_value)) {
-		s8 last_accessible_byte = addr & KASAN_SHADOW_MASK;
+		s8 last_accessible_byte = addr & KASAN_GRANULE_MASK;
 		return unlikely(last_accessible_byte >= shadow_value);
 	}
 
@@ -63,7 +63,7 @@ static __always_inline bool memory_is_poisoned_2_4_8(unsigned long addr,
 	 * Access crosses 8(shadow size)-byte boundary. Such access maps
 	 * into 2 shadow bytes, so we need to check them both.
 	 */
-	if (unlikely(((addr + size - 1) & KASAN_SHADOW_MASK) < size - 1))
+	if (unlikely(((addr + size - 1) & KASAN_GRANULE_MASK) < size - 1))
 		return *shadow_addr || memory_is_poisoned_1(addr + size - 1);
 
 	return memory_is_poisoned_1(addr + size - 1);
@@ -74,7 +74,7 @@ static __always_inline bool memory_is_poisoned_16(unsigned long addr)
 	u16 *shadow_addr = (u16 *)kasan_mem_to_shadow((void *)addr);
 
 	/* Unaligned 16-bytes access maps into 3 shadow bytes. */
-	if (unlikely(!IS_ALIGNED(addr, KASAN_SHADOW_SCALE_SIZE)))
+	if (unlikely(!IS_ALIGNED(addr, KASAN_GRANULE_SIZE)))
 		return *shadow_addr || memory_is_poisoned_1(addr + 15);
 
 	return *shadow_addr;
@@ -135,7 +135,7 @@ static __always_inline bool memory_is_poisoned_n(unsigned long addr,
 		s8 *last_shadow = (s8 *)kasan_mem_to_shadow((void *)last_byte);
 
 		if (unlikely(ret != (unsigned long)last_shadow ||
-			((long)(last_byte & KASAN_SHADOW_MASK) >= *last_shadow)))
+			((long)(last_byte & KASAN_GRANULE_MASK) >= *last_shadow)))
 			return true;
 	}
 	return false;
@@ -201,7 +201,7 @@ void kasan_cache_shutdown(struct kmem_cache *cache)
 
 static void register_global(struct kasan_global *global)
 {
-	size_t aligned_size = round_up(global->size, KASAN_SHADOW_SCALE_SIZE);
+	size_t aligned_size = round_up(global->size, KASAN_GRANULE_SIZE);
 
 	unpoison_range(global->beg, global->size);
 
@@ -275,10 +275,10 @@ EXPORT_SYMBOL(__asan_handle_no_return);
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
index 6bb3f66992df..7d5b9e5c7cfe 100644
--- a/mm/kasan/generic_report.c
+++ b/mm/kasan/generic_report.c
@@ -34,7 +34,7 @@ void *find_first_bad_addr(void *addr, size_t size)
 	void *p = addr;
 
 	while (p < addr + size && !(*(u8 *)kasan_mem_to_shadow(p)))
-		p += KASAN_SHADOW_SCALE_SIZE;
+		p += KASAN_GRANULE_SIZE;
 	return p;
 }
 
@@ -46,14 +46,14 @@ static const char *get_shadow_bug_type(struct kasan_access_info *info)
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
index 9ce8cc5b8621..dfddd6c39fe6 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -442,8 +442,8 @@ void kasan_remove_zero_shadow(void *start, unsigned long size)
 	end = addr + (size >> KASAN_SHADOW_SCALE_SHIFT);
 
 	if (WARN_ON((unsigned long)start %
-			(KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE)) ||
-	    WARN_ON(size % (KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE)))
+			(KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
+	    WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
 		return;
 
 	for (; addr < end; addr = next) {
@@ -477,8 +477,8 @@ int kasan_add_zero_shadow(void *start, unsigned long size)
 	shadow_end = shadow_start + (size >> KASAN_SHADOW_SCALE_SHIFT);
 
 	if (WARN_ON((unsigned long)start %
-			(KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE)) ||
-	    WARN_ON(size % (KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE)))
+			(KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
+	    WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
 		return -EINVAL;
 
 	ret = kasan_populate_early_shadow(shadow_start, shadow_end);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 42ab02c61331..53b095f56f28 100644
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
index d500923abc8b..7b8dcb799a78 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -314,24 +314,24 @@ static bool __must_check get_address_stack_frame_info(const void *addr,
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
@@ -599,6 +599,6 @@ void kasan_non_canonical_hook(unsigned long addr)
 	else
 		bug_type = "maybe wild-memory-access";
 	pr_alert("KASAN: %s in range [0x%016lx-0x%016lx]\n", bug_type,
-		 orig_addr, orig_addr + KASAN_SHADOW_MASK);
+		 orig_addr, orig_addr + KASAN_GRANULE_SIZE - 1);
 }
 #endif
diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
index 5f183501b871..c87d5a343b4e 100644
--- a/mm/kasan/tags_report.c
+++ b/mm/kasan/tags_report.c
@@ -76,7 +76,7 @@ void *find_first_bad_addr(void *addr, size_t size)
 	void *end = p + size;
 
 	while (p < end && tag == *(u8 *)kasan_mem_to_shadow(p))
-		p += KASAN_SHADOW_SCALE_SIZE;
+		p += KASAN_GRANULE_SIZE;
 	return p;
 }
 
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/939b5754e47f528a6e6a6f28ffc5815d8d128033.1606161801.git.andreyknvl%40google.com.
