Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMW4QD6QKGQE5MAOEII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 927032A2F05
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:05:07 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id g20sf8686496plj.10
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:05:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333106; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y+B6enyh1pg9/2DBCgwtO82mDH1hvRWyfLTxyDeMImB1ljPYr/va37FlsV6Sop6HSr
         hHNAiKpXxtVKXpozMHFmgnCPlINrVc+fl/aBQ6xJQrpdgaZ5nsKz5Ucj82gRuNyoE3oG
         pP2lBSves9eOxWe/oXCexGI1Dmb9+UkauuKzDKKclk+KgjHHtAQV4cKgV/wWK76x/iZ+
         qZoPuVPCl3PgylAHHJZ4vcDyTAjzn3quxmJzv1ih0ppaJU+t0GPLGm/acDj3AEP9Ub4u
         Xn9KxZlc8e2bCO+kUyhK49C+1DcN/YaKSqUQHQYDMNIy7oQpmh1pWvCBcASE9NAXauN0
         4F0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=CnddbqIYXWwELCkcvurS9f8zWFbw5J8DKkIMd+FIoOs=;
        b=RhHfX0DNtJ+b3pzY3VrV4LqPHLEM39k0h8U05dwY5lhKeJaUp1TBiFCj2qY7E7ogS+
         iwrbtyxaimLHpOwyRAutv8fwj1yUISaOKGwgOlmwJEhC3mtKZD7ihzQGEj8MMfqJ9fy7
         YxcQuZTYT9Kx3hMHVO2M+B3q2/o+YO/dI1UfndxXhAZ/niKHotPwclxAK79voSG1DXmj
         lofAXnBR5+RX2ghoSHsuXL7U5nepH2KXUjloq8YO5fqqaXCLkdMJG0J2Zi9PLOdDw2yK
         3Wu1V0lxLzgy2ciljKJkQvlaFrIsIeNclt6udWfJyALIPDZbiIM/nVUV/NvL+4/wO92O
         sigw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aFbR9o+4;
       spf=pass (google.com: domain of 3mc6gxwokcrer4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3MC6gXwoKCREr4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CnddbqIYXWwELCkcvurS9f8zWFbw5J8DKkIMd+FIoOs=;
        b=iCQHunQ1J1CQKajxkaKOOnHqgx642LmTaOI5rNE/Ar5Hoz3mePT9J6K/3L/r3o0pZv
         lbW0m9W8O+wn+BeEUO48WAKNVdvW4fxK33ILfa3LfLBiZ8CVtci8dkhKpX0Y//lkobMc
         gVpnorMrCd+xxZog3dGW4cJYo89nuAFW9/LRJ6mPT7JPhAtEuLg2ZSYNsbLAzUTQu1m8
         GqU/ldQA/DxAF7M3r6exCsOItINx2HbaZTcRPvb0CEJJ6KMYaf0ksZw18II/EWYuEutM
         RnljzBcoliQ/cZyDsUY22+iMMBJb72whGmzf7moCKEf/60ylIkU+ZOlKMrTIVoCj1OwG
         2Ufw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CnddbqIYXWwELCkcvurS9f8zWFbw5J8DKkIMd+FIoOs=;
        b=aT5XXMNd44Mn4vikqP/1lssGpY4R3PpPPUcRLMOOOD0GITDyEE8A2+8brw2MlVygtT
         uG6iP9ML8MOnEkI1w7O56WluHZjWBuTkUv4JC0N+gog8T/+gYQqTGexSQ6xPLJW2B/7W
         H7VoyFA+mXIg0krQl/3+H6KzrP/XudO4Y+6wbEL3x+/EERDy9YjwkMSQPE30aYZw7uz3
         f1OQSSLmypcBLHP7T8/1JQJjKoqSvi4YIEenjcWlqH5dGXDte+W1xt2+39jUIdRhGv/l
         Z4CS583Mk2U+r0EPlxbTvsO4zofxkZ8PxSuzcqqTqG6MMgwdj9zMBnHmX7wPepx62JUk
         r5Ng==
X-Gm-Message-State: AOAM532AOsEUudFZmum7atQUNwABaK5mvK7a56kv22+dUrU+HH4/BFnS
	4p/WTmi9pi5W17aendEP60g=
X-Google-Smtp-Source: ABdhPJwtEOLwI6SwtOelhG3RBYgFqAMNPRUJz2UxBJFzJjzFreIOatcMeb0QW60jLBlF3FqJDpmqVw==
X-Received: by 2002:a17:90a:341:: with SMTP id 1mr18288609pjf.189.1604333106182;
        Mon, 02 Nov 2020 08:05:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:9205:: with SMTP id o5ls2305562pfd.7.gmail; Mon, 02 Nov
 2020 08:05:05 -0800 (PST)
X-Received: by 2002:aa7:83d7:0:b029:164:28d:f350 with SMTP id j23-20020aa783d70000b0290164028df350mr21668460pfn.71.1604333105643;
        Mon, 02 Nov 2020 08:05:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333105; cv=none;
        d=google.com; s=arc-20160816;
        b=BDB/jHKc4D+5bs13pDILATgJRbxIcx0Z6DE7BBbRbOLX7KmRMrdADkKyPc2q1fnbha
         YR+B8kwRgEssanN0/kxNZmxlF2e6XDXbyQcUvFlhI1ZSfNXz6ss8Zg6bxSRjbi8lhMlt
         loWrS5XJzPRsH65xPd2oq8HehqAtZ8pfebW+Dx6N6QzS/32TkT17cdcrrm/jocobJM/0
         r7fUjo0B7RbhT77CqoWanU7eerUitNttqjJK9EjbMMiDebduqPi02nUqBFRlam7NSioM
         DOXw4GeP8OfKDlPXLV/F0KMtLSQUae0PQFAh1D9WYJyfxnpMDFIlzkA6FbpP2n59+5fp
         4DnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=upSOSk3mKQQrNc8nRQo9il0OfC9yC+TTxgrYiC8EvbE=;
        b=Rkx4QCJne8LlCNIxhdWmQJts5vjgB923/XJ8hxV0HGHuI4JszaFywf4qzllKypBjct
         BAiMHXQUW06xg206Z3AodhWUN72yc2FBuck15MThnxqQwPfQ5IR5N7w1mUM+iPQLs+KG
         UUXQwHhqONyMK4sb3xErqHqW7dlIdgS2BZsL943VE9Y4rz5Fq3a8PaUkfpoAwfhBCzep
         GsGzSzyhStAgSCYoYFMD346KCiTvoYjoitNj73BQDh6x/prVjrVJTBGaDJbeIS5jUa9x
         3fYo5V8d+936gcXF1p7DgpJRf/Jh8cFrYZpXRXKClgs0UnxnoXogAFSh16BFzjm1Gjrw
         cc0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aFbR9o+4;
       spf=pass (google.com: domain of 3mc6gxwokcrer4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3MC6gXwoKCREr4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id p1si176938plq.4.2020.11.02.08.05.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:05 -0800 (PST)
Received-SPF: pass (google.com: domain of 3mc6gxwokcrer4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id k15so8536178qvx.4
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:05 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:f3d0:: with SMTP id
 f16mr13830148qvm.42.1604333104727; Mon, 02 Nov 2020 08:05:04 -0800 (PST)
Date: Mon,  2 Nov 2020 17:03:56 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <4dee872cf377e011290bbe2e90c7e7fd24e789dd.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 16/41] kasan: rename KASAN_SHADOW_* to KASAN_GRANULE_*
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aFbR9o+4;       spf=pass
 (google.com: domain of 3mc6gxwokcrer4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3MC6gXwoKCREr4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
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
 mm/kasan/common.c                 | 39 ++++++++++++++++---------------
 mm/kasan/generic.c                | 14 +++++------
 mm/kasan/generic_report.c         |  8 +++----
 mm/kasan/init.c                   |  8 +++----
 mm/kasan/kasan.h                  |  4 ++--
 mm/kasan/report.c                 | 10 ++++----
 mm/kasan/tags_report.c            |  2 +-
 9 files changed, 45 insertions(+), 44 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index c09c9ca2ff1c..b6db715830f9 100644
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
index 63c26171a791..0328fc3298e9 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -25,7 +25,7 @@
 
 #include "../mm/kasan/kasan.h"
 
-#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_SHADOW_SCALE_SIZE)
+#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANULE_SIZE)
 
 /*
  * We assign some test results to these globals to make sure the tests
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
index f844007d5d94..fc9e4250a098 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4dee872cf377e011290bbe2e90c7e7fd24e789dd.1604333009.git.andreyknvl%40google.com.
