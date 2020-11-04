Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7HNRT6QKGQE2CSSW5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 175B62A7118
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:19:25 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id o7sf106834lfo.9
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:19:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604531964; cv=pass;
        d=google.com; s=arc-20160816;
        b=TD6537YiZAhKkc14dYH7326U1AgJpUSF9zdyHMi6crk2eu7E5KVCo6BMH1o8X9qLOQ
         VAYH1wZx9hhPumy6DTELVs2DIBjYeXc7GoHasPw2aFBe0Po30BvNeIM5CB8U0ybPGCX+
         3sGlDjST9ixP5nvZjhPQ9susXpopTi5BdC3Ba1C14NBo9ss0qk1+814loXxrZPr+BNa4
         awRaJqzohV6DWvvyRiiET887l98xZg4q/sPXXzxidr+G0qVJSIPCdUnJxJYtYZerah1S
         Vm7P9pQXMkN/VENQbAOxMvHa92Uj0bE3ymcuKwfB/owejipfPjiwinM7dMkPvQveAoz8
         hHJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=XoNdo5jsdWlKuMDOcWUj3TIJIUXS+bs3pjENE+8wyU8=;
        b=v43Vf90DrQClaaYQzCpvL+nEVpJks4i1vSs0Kh3ZShgf9SnqPeJgSw4Ztc1ehsla1u
         Xn6dDmjem11CPMgBvovJz6HDrCJEO7lwKAw9EU9qhCXQ4WvFrlztvEPvbJ0bqSfThZv7
         0x0iAadbnI6kDCaj38g8sgQcd/6X5x0HFOOyieVU0wfS7x6n5+Xj/f6cbViwRy7Jz42e
         KGdcefSOZJesjGEOD1G2G3bn/kXZEBFAyknV6aaGrNRzKzNzd0RKj0r3vXUlWRd82spk
         BpMU0w/+xP3xjuX8YN80kzLrE5utgfVenaQfO/XJW108BXz6O0nf5bOhiRfxe9YCZnNt
         UAiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="C284X/O6";
       spf=pass (google.com: domain of 3-zajxwokcfgfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3-zajXwoKCfgfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XoNdo5jsdWlKuMDOcWUj3TIJIUXS+bs3pjENE+8wyU8=;
        b=FC0nHP2RZmQVDN8K9zKd6W0JZBmSxCqRiI3jiQwpn0Q1CLGLNGJG/og2rn7FJpC/HP
         2XslwTwxXVmlUCujR0HlXwka3lNLPp9URRsADkhfnjKKrz0dSVmEyNhLmRSuOs+HKfia
         sD9F/v9eKfw334Mw+pHZ0Qkrn+empL1B/snDXXmMm5uBWPlqy4YzMWBQOo8eFj3iRXX/
         RO+m1v37ZgobCaqxr9GfC3MjwfsWyEBSu4tuJlgk3Tj+5aU3pFRP7txGq3WU21OgAsHF
         HLhWaxhjIPkxWusxIiXJM9Qs4dXmQsKy0Gs0byr70fkUtrwjVpLtJQKnwvs3t+tBKRYJ
         IJzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XoNdo5jsdWlKuMDOcWUj3TIJIUXS+bs3pjENE+8wyU8=;
        b=JwwL9ELejR3uVmuwsJJveE2dHZ+nUGyohsBHx3xFJgH6RPtYHV/qp2nATFyDODdf1c
         4YkRtITpDiBZc7dg0gPSeTOUWGWWa2K4CNXKcSisfT0QtTQB8+WWQxe+vTHi12DCoPvB
         CQaLquJ09oU7zb1qxMx46WGwdmwNR8gjQekA6bTnAT5rMFublnWFUoMsI2xxzI4NQCAM
         r19EI9LPZ/fb1g3WrYWUUDuhaqB03NWpVCJEiu2hg+1Kh12YjdXwPl6ovSv5gzpHYgY3
         bXlD0jxd93v8dHST7NKwZMp2onTzBHS2VLvR4/6La/404Rv4QVz0cnQX7i5XeOBl6+77
         c+Zg==
X-Gm-Message-State: AOAM530YirOyfxJqmNuFJFiqEul9e3a+k2R62+ySmxBJpYlmJkDwMUxI
	vcqQZdt4dnJiuG68txoxLNo=
X-Google-Smtp-Source: ABdhPJyYt4P/Jc1HdF3XJpDy8PQNP71/lAHu1ZXiGJnXMwIzx1IMkOb2LxQCrOVsEOpff8LIhC2TWg==
X-Received: by 2002:a2e:9917:: with SMTP id v23mr117830lji.234.1604531964623;
        Wed, 04 Nov 2020 15:19:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:586:: with SMTP id 128ls2255209lff.1.gmail; Wed, 04 Nov
 2020 15:19:23 -0800 (PST)
X-Received: by 2002:ac2:41ca:: with SMTP id d10mr13475lfi.439.1604531963578;
        Wed, 04 Nov 2020 15:19:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531963; cv=none;
        d=google.com; s=arc-20160816;
        b=yErIkeNtvmO4CX6RlgcHEwWHDV0NU09DyAfqBJ8B9xrDu4sk65UZsJoyAa9UjjccuQ
         P1aGEmXwAu93K67OKI1nmkTepn3OVqmEhMZ6OpZ+a1nzh+8Fm3DHRl7UYhmbZM4EgvZk
         Go4J0S0NIhhjMwWvr73TkQkPIX8An/zoYNCK33Jol9wm6GprFceeTGNePiqnF/DyS123
         XTgu2uJ0UPfRY9J2x6DFUNvFbXvkhMUT9W7z0ZjxR5HA3OdZfoyDWtgBZfsoN0OaexHa
         XTwtCRbz7ZwF8cSvueJotaFmt4K0XaRf2CF9htPchwvD2SIlbhHPTdjTU3ZfJcvcNowk
         S+Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=IUUW0kfppB1Efh4tHJPvwp7oL4IQLWE1cA6kijbJlXk=;
        b=Lj8W5OOLfH5HQM9moUdtdF6Y5gP/g0vOD7z1bwQJI9cEzcbqr4LwC28LOaD5clfO2P
         VRZD5JGkqclEpKabg+odpICVJ8w7n97vkxZq8FzSZ3F2Arg8u0elkqHVgKMG5XXT3VK7
         HXqWV+cL1CMA93rBU0tuj1wsIqedDaH9F6nXQZplYhLZNY2dxgdBWS7xFzVMuZdW9+ju
         49xs/DVCiOHcPC6fe7eLW7omCaU5uQqLvN3lNwt9tq43sDOJ9DCRNu7tDRJimYgqk6Q7
         Dxz1Qb8xPQi22P1rb6my8TKcqe7n4lA8sDKS9yYnX/OOs2isUPU9t4xaqcGFXiU9Y9Ju
         Z5nA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="C284X/O6";
       spf=pass (google.com: domain of 3-zajxwokcfgfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3-zajXwoKCfgfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id a1si130822lff.2.2020.11.04.15.19.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:23 -0800 (PST)
Received-SPF: pass (google.com: domain of 3-zajxwokcfgfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id 27so70780ejy.8
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:23 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6402:1844:: with SMTP id
 v4mr180332edy.346.1604531963010; Wed, 04 Nov 2020 15:19:23 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:22 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <279a9eafac9ba2090bb02bbdcaf9d9a2deb9214d.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 07/43] kasan: rename KASAN_SHADOW_* to KASAN_GRANULE_*
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="C284X/O6";       spf=pass
 (google.com: domain of 3-zajxwokcfgfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3-zajXwoKCfgfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
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
index 2b68addaadcd..edca4be5e405 100644
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
index a4b73fa0dd7e..f65c9f792f8f 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -106,7 +106,7 @@ void *memcpy(void *dest, const void *src, size_t len)
 
 /*
  * Poisons the shadow memory for 'size' bytes starting from 'addr'.
- * Memory addresses should be aligned to KASAN_SHADOW_SCALE_SIZE.
+ * Memory addresses should be aligned to KASAN_GRANULE_SIZE.
  */
 void kasan_poison_memory(const void *address, size_t size, u8 value)
 {
@@ -138,13 +138,13 @@ void kasan_unpoison_memory(const void *address, size_t size)
 
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
 
@@ -296,7 +296,7 @@ void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
 void kasan_poison_object_data(struct kmem_cache *cache, void *object)
 {
 	kasan_poison_memory(object,
-			round_up(cache->object_size, KASAN_SHADOW_SCALE_SIZE),
+			round_up(cache->object_size, KASAN_GRANULE_SIZE),
 			KASAN_KMALLOC_REDZONE);
 }
 
@@ -368,7 +368,7 @@ static inline bool shadow_invalid(u8 tag, s8 shadow_byte)
 {
 	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
 		return shadow_byte < 0 ||
-			shadow_byte >= KASAN_SHADOW_SCALE_SIZE;
+			shadow_byte >= KASAN_GRANULE_SIZE;
 
 	/* else CONFIG_KASAN_SW_TAGS: */
 	if ((u8)shadow_byte == KASAN_TAG_INVALID)
@@ -407,7 +407,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 		return true;
 	}
 
-	rounded_up_size = round_up(cache->object_size, KASAN_SHADOW_SCALE_SIZE);
+	rounded_up_size = round_up(cache->object_size, KASAN_GRANULE_SIZE);
 	kasan_poison_memory(object, rounded_up_size, KASAN_KMALLOC_FREE);
 
 	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
@@ -440,9 +440,9 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 		return NULL;
 
 	redzone_start = round_up((unsigned long)(object + size),
-				KASAN_SHADOW_SCALE_SIZE);
+				KASAN_GRANULE_SIZE);
 	redzone_end = round_up((unsigned long)object + cache->object_size,
-				KASAN_SHADOW_SCALE_SIZE);
+				KASAN_GRANULE_SIZE);
 
 	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
 		tag = assign_tag(cache, object, false, keep_tag);
@@ -486,7 +486,7 @@ void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
 
 	page = virt_to_page(ptr);
 	redzone_start = round_up((unsigned long)(ptr + size),
-				KASAN_SHADOW_SCALE_SIZE);
+				KASAN_GRANULE_SIZE);
 	redzone_end = (unsigned long)ptr + page_size(page);
 
 	kasan_unpoison_memory(ptr, size);
@@ -584,8 +584,8 @@ static int __meminit kasan_mem_notifier(struct notifier_block *nb,
 	shadow_size = nr_shadow_pages << PAGE_SHIFT;
 	shadow_end = shadow_start + shadow_size;
 
-	if (WARN_ON(mem_data->nr_pages % KASAN_SHADOW_SCALE_SIZE) ||
-		WARN_ON(start_kaddr % (KASAN_SHADOW_SCALE_SIZE << PAGE_SHIFT)))
+	if (WARN_ON(mem_data->nr_pages % KASAN_GRANULE_SIZE) ||
+		WARN_ON(start_kaddr % (KASAN_GRANULE_SIZE << PAGE_SHIFT)))
 		return NOTIFY_BAD;
 
 	switch (action) {
@@ -743,7 +743,7 @@ void kasan_poison_vmalloc(const void *start, unsigned long size)
 	if (!is_vmalloc_or_module_addr(start))
 		return;
 
-	size = round_up(size, KASAN_SHADOW_SCALE_SIZE);
+	size = round_up(size, KASAN_GRANULE_SIZE);
 	kasan_poison_memory(start, size, KASAN_VMALLOC_INVALID);
 }
 
@@ -856,22 +856,22 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
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
@@ -897,7 +897,8 @@ int kasan_module_alloc(void *addr, size_t size)
 	unsigned long shadow_start;
 
 	shadow_start = (unsigned long)kasan_mem_to_shadow(addr);
-	scaled_size = (size + KASAN_SHADOW_MASK) >> KASAN_SHADOW_SCALE_SHIFT;
+	scaled_size = (size + KASAN_GRANULE_SIZE - 1) >>
+				KASAN_SHADOW_SCALE_SHIFT;
 	shadow_size = round_up(scaled_size, PAGE_SIZE);
 
 	if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 7006157c674b..ec4417156943 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -46,7 +46,7 @@ static __always_inline bool memory_is_poisoned_1(unsigned long addr)
 	s8 shadow_value = *(s8 *)kasan_mem_to_shadow((void *)addr);
 
 	if (unlikely(shadow_value)) {
-		s8 last_accessible_byte = addr & KASAN_SHADOW_MASK;
+		s8 last_accessible_byte = addr & KASAN_GRANULE_MASK;
 		return unlikely(last_accessible_byte >= shadow_value);
 	}
 
@@ -62,7 +62,7 @@ static __always_inline bool memory_is_poisoned_2_4_8(unsigned long addr,
 	 * Access crosses 8(shadow size)-byte boundary. Such access maps
 	 * into 2 shadow bytes, so we need to check them both.
 	 */
-	if (unlikely(((addr + size - 1) & KASAN_SHADOW_MASK) < size - 1))
+	if (unlikely(((addr + size - 1) & KASAN_GRANULE_MASK) < size - 1))
 		return *shadow_addr || memory_is_poisoned_1(addr + size - 1);
 
 	return memory_is_poisoned_1(addr + size - 1);
@@ -73,7 +73,7 @@ static __always_inline bool memory_is_poisoned_16(unsigned long addr)
 	u16 *shadow_addr = (u16 *)kasan_mem_to_shadow((void *)addr);
 
 	/* Unaligned 16-bytes access maps into 3 shadow bytes. */
-	if (unlikely(!IS_ALIGNED(addr, KASAN_SHADOW_SCALE_SIZE)))
+	if (unlikely(!IS_ALIGNED(addr, KASAN_GRANULE_SIZE)))
 		return *shadow_addr || memory_is_poisoned_1(addr + 15);
 
 	return *shadow_addr;
@@ -134,7 +134,7 @@ static __always_inline bool memory_is_poisoned_n(unsigned long addr,
 		s8 *last_shadow = (s8 *)kasan_mem_to_shadow((void *)last_byte);
 
 		if (unlikely(ret != (unsigned long)last_shadow ||
-			((long)(last_byte & KASAN_SHADOW_MASK) >= *last_shadow)))
+			((long)(last_byte & KASAN_GRANULE_MASK) >= *last_shadow)))
 			return true;
 	}
 	return false;
@@ -200,7 +200,7 @@ void kasan_cache_shutdown(struct kmem_cache *cache)
 
 static void register_global(struct kasan_global *global)
 {
-	size_t aligned_size = round_up(global->size, KASAN_SHADOW_SCALE_SIZE);
+	size_t aligned_size = round_up(global->size, KASAN_GRANULE_SIZE);
 
 	kasan_unpoison_memory(global->beg, global->size);
 
@@ -274,10 +274,10 @@ EXPORT_SYMBOL(__asan_handle_no_return);
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/279a9eafac9ba2090bb02bbdcaf9d9a2deb9214d.1604531793.git.andreyknvl%40google.com.
