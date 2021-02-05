Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQED62AAMGQEWDMS66I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B80B310EC0
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 18:34:57 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id o8sf5861050ljp.15
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 09:34:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612546496; cv=pass;
        d=google.com; s=arc-20160816;
        b=H+B3u5NUXDg9K6AmzdlinhVt/yznJ0UE3FwAB64rmXM4aoEeDyTQD+TldaTrZZO0YD
         BPy6vWAtEuhkgOCi6yvSbiH8o9Gd4AKomtoRmXMPKctMYC1/riRevPG+2cSzpTX82ZTl
         iswpgD81ppaxlpVFWUyd4zetPDMGRA7z/dCu8ngI9Y5IVjGJNsNglstJDsSW0x+Pmq3D
         vuMjO1tDUjaC4O6ac3+h/QekZtMLDjXvm3T3zqlhZqeTmDiollf+fbb8GFbE+qrw0mlv
         EM0d4xw5vEd45tEhpCmqVAkugGQSZlA1RIjHap501FctfG/JsTKhPXJhMVcMaDwwNfnQ
         VWqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=HX/KUsP+6cRFpaiD6uaHsY0KXCT23sYFR1Ks20+rNWc=;
        b=S0emKURmZmRIiHhzSHwf2Xc5zwVS28nSsL9kDsuZNVp77gdNFnUreXkE41odYtLcpW
         lT3pJZa0WLosnwCiLvoHO2iG0ReV84EqT/Tk5he7dwKVRNXohtIUUe1zjnYZPmTC3Qju
         UsoA9o1lVafZ5LkY8Htey0fdWScCHqNBBw0Oqu/YIlW+6ZJhXbbb1/NPLyv9AE2NLt6F
         Cvn5wMHag5x7aWBt9ApKUWaUQobdgQUiu0Kr2N7aKo+XPCuHYwkmKr9uwse7MAK9aht9
         LMIFPPSep0Q56C6A2jGJnoKonxxfIuUzafFA6CO+QBU4Gu8uUFXP9mxnaA3oO4biLcTP
         umww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=t56fsyt4;
       spf=pass (google.com: domain of 3v4edyaokcuacpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3v4EdYAoKCUAcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HX/KUsP+6cRFpaiD6uaHsY0KXCT23sYFR1Ks20+rNWc=;
        b=mfnQavHCXUXvYEzySWIMN7LFIJmPHCXDJo2VdMVOBqCVPQBsAiRUVQnkhAiJkBGgaB
         A7EK7l6XiO6DZx6l42311hzjIPXfL8NOzgsYq4wlCVSJ+qOULDs/XawdQsb1nX3BHZXg
         gglawdx0LjnAUjgqBjps4bUdJOW931jEBXvnVDL7ihinMliWvcoEfhyFbTX6pObfFbvY
         Wdkj1zsjDWeVHNS2z4bnHHOcybW7F/0GZxX+Khw72VNFhl5h/HNi6T58fYzD543r8feK
         XFb7utx84WmRV6gy37CXcYVBmlFBaPlKt4UgRWo3e0a6WRV2qq2vrZcOifjNUdOSx9m3
         lMkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HX/KUsP+6cRFpaiD6uaHsY0KXCT23sYFR1Ks20+rNWc=;
        b=mpUlg1GXZ6KbUhRqXesNvaSbiTTZ1M3aSj8JQeZYLJ4IF+dfwv1mvCgVUUYQ/nSAHc
         hr3Cuhh2BWewXSpDQ6kdNV82rK9Li7CyH8sUVo0FYsTBXvpxCzO+0wOxy9jMiMJKn9E0
         jLei//iGC/x0Uc1MXYztMZJ7c4jRa40OGbeC+5OhEqmetDDJ3wUEdyqXXARU5hlMk6/L
         uf1PiD2IX/Jimq4bWsHrkmVa2QpuelJJ2EGHsN8+kLxHhnA6wFsR8h4po/IAFtBR9cDN
         7HBzI+KZ7Z7q4uFEf6eevIA2azqeD4sDYUMYQHIw47Rr1s92VQ5J6pT2j4iiqcf90Gmt
         jorQ==
X-Gm-Message-State: AOAM532Ft8YyQf0DGCm9UETjG3FqRWH8RtX384PHiR/eVDiSLBOsPVX8
	Q18+RVipZnRvM2VvpDTsBlw=
X-Google-Smtp-Source: ABdhPJyj2Trogh1ejUlNVxq3M6SLZE4H3CtEL0oJpE0z95WezlW9U1UFT+v3hP/d73B8PN1RRALl6w==
X-Received: by 2002:ac2:561b:: with SMTP id v27mr3089166lfd.233.1612546496740;
        Fri, 05 Feb 2021 09:34:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9ad2:: with SMTP id p18ls1821597ljj.5.gmail; Fri, 05 Feb
 2021 09:34:55 -0800 (PST)
X-Received: by 2002:a2e:86c2:: with SMTP id n2mr3301664ljj.90.1612546495780;
        Fri, 05 Feb 2021 09:34:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612546495; cv=none;
        d=google.com; s=arc-20160816;
        b=w5pumEckZ27whbGS0vqp38MUKqgfVRDTp3NiZObY28nZd8ypMBWMMI3KnUiq129Imt
         butprBnN2U59hkGdtFPz/7zLZhYiFAQipF5D1PO1xugYngW+kYpDFBVcNPwzdOT973NG
         ZJzlJkQTB/2086cmUevN5DWJhASk2WeYJDFHt4xwAJrg0ohWIzkHQo1/WkEuYMZ1YadR
         54mURXhNKsmT9t3E74rirMn+5tCryK1kUBlTPz1h61yAzpDDUbliU+m0dARDvp+ww1PH
         2TjqC5na/56eBhSBernJdFcA5jeHhBjyTBjOoIB9aveDoaiVJGvAP3rNSVnc+97M3GKr
         83hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=UPTowWhmoRbOR7zm1ysa/6XpOoPbcb0RCUTUBjiaP4A=;
        b=D2aa4OMUaR4Ehk4iBhaCXOJ1dOd6kI/fjpnx03ALfZweasDz/+FHOY3gf39jtmTxiI
         +1v4jHGfu2qBPT6u+/ib6xK8LxvBjJJNuX+c00nDSVuovdLwSUaSkEc/fZkmcPzlgIIt
         w1qWT4Yf9r7i5WoXkqbnArfWrXUgO/8GC96Ks62j4lCc6cv2ZMKmGczclaBHJjETtQy0
         aqosVeHISmpS9jpZFxMR1QwUGCymEyd3j7zZdtmPglaJKTID/KUMKiVxKsChc5tfoyT1
         Il3wkAt7taKicv6hoDGQKm5m1kj8l5ih/BwSgc1SqWL9a56tmJ1iXXyQhCK8atR1cda2
         3i8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=t56fsyt4;
       spf=pass (google.com: domain of 3v4edyaokcuacpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3v4EdYAoKCUAcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id c20si428966lff.11.2021.02.05.09.34.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 09:34:55 -0800 (PST)
Received-SPF: pass (google.com: domain of 3v4edyaokcuacpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id l10so5718202wry.16
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 09:34:55 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a1c:a707:: with SMTP id
 q7mr4463252wme.15.1612546495078; Fri, 05 Feb 2021 09:34:55 -0800 (PST)
Date: Fri,  5 Feb 2021 18:34:36 +0100
In-Reply-To: <cover.1612546384.git.andreyknvl@google.com>
Message-Id: <7e3961cb52be380bc412860332063f5f7ce10d13.1612546384.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612546384.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v3 mm 02/13] kasan, mm: optimize kmalloc poisoning
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=t56fsyt4;       spf=pass
 (google.com: domain of 3v4edyaokcuacpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3v4EdYAoKCUAcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
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

For allocations from kmalloc caches, kasan_kmalloc() always follows
kasan_slab_alloc(). Currenly, both of them unpoison the whole object,
which is unnecessary.

This patch provides separate implementations for both annotations:
kasan_slab_alloc() unpoisons the whole object, and kasan_kmalloc()
only poisons the redzone.

For generic KASAN, the redzone start might not be aligned to
KASAN_GRANULE_SIZE. Therefore, the poisoning is split in two parts:
kasan_poison_last_granule() poisons the unaligned part, and then
kasan_poison() poisons the rest.

This patch also clarifies alignment guarantees of each of the poisoning
functions and drops the unnecessary round_up() call for redzone_end.

With this change, the early SLUB cache annotation needs to be changed to
kasan_slab_alloc(), as kasan_kmalloc() doesn't unpoison objects now.
The number of poisoned bytes for objects in this cache stays the same, as
kmem_cache_node->object_size is equal to sizeof(struct kmem_cache_node).

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 93 +++++++++++++++++++++++++++++++----------------
 mm/kasan/kasan.h  | 43 +++++++++++++++++++++-
 mm/kasan/shadow.c | 28 +++++++-------
 mm/slub.c         |  3 +-
 4 files changed, 119 insertions(+), 48 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index bfdf5464f4ef..00edbc3eb32e 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -278,21 +278,11 @@ void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
  *    based on objects indexes, so that objects that are next to each other
  *    get different tags.
  */
-static u8 assign_tag(struct kmem_cache *cache, const void *object,
-			bool init, bool keep_tag)
+static u8 assign_tag(struct kmem_cache *cache, const void *object, bool init)
 {
 	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
 		return 0xff;
 
-	/*
-	 * 1. When an object is kmalloc()'ed, two hooks are called:
-	 *    kasan_slab_alloc() and kasan_kmalloc(). We assign the
-	 *    tag only in the first one.
-	 * 2. We reuse the same tag for krealloc'ed objects.
-	 */
-	if (keep_tag)
-		return get_tag(object);
-
 	/*
 	 * If the cache neither has a constructor nor has SLAB_TYPESAFE_BY_RCU
 	 * set, assign a tag when the object is being allocated (init == false).
@@ -325,7 +315,7 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 	}
 
 	/* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
-	object = set_tag(object, assign_tag(cache, object, true, false));
+	object = set_tag(object, assign_tag(cache, object, true));
 
 	return (void *)object;
 }
@@ -413,12 +403,46 @@ static void set_alloc_info(struct kmem_cache *cache, void *object,
 		kasan_set_track(&alloc_meta->alloc_track, flags);
 }
 
+void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
+					void *object, gfp_t flags)
+{
+	u8 tag;
+	void *tagged_object;
+
+	if (gfpflags_allow_blocking(flags))
+		kasan_quarantine_reduce();
+
+	if (unlikely(object == NULL))
+		return NULL;
+
+	if (is_kfence_address(object))
+		return (void *)object;
+
+	/*
+	 * Generate and assign random tag for tag-based modes.
+	 * Tag is ignored in set_tag() for the generic mode.
+	 */
+	tag = assign_tag(cache, object, false);
+	tagged_object = set_tag(object, tag);
+
+	/*
+	 * Unpoison the whole object.
+	 * For kmalloc() allocations, kasan_kmalloc() will do precise poisoning.
+	 */
+	kasan_unpoison(tagged_object, cache->object_size);
+
+	/* Save alloc info (if possible) for non-kmalloc() allocations. */
+	if (kasan_stack_collection_enabled())
+		set_alloc_info(cache, (void *)object, flags, false);
+
+	return tagged_object;
+}
+
 static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
-				size_t size, gfp_t flags, bool is_kmalloc)
+					size_t size, gfp_t flags)
 {
 	unsigned long redzone_start;
 	unsigned long redzone_end;
-	u8 tag;
 
 	if (gfpflags_allow_blocking(flags))
 		kasan_quarantine_reduce();
@@ -429,33 +453,41 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	if (is_kfence_address(kasan_reset_tag(object)))
 		return (void *)object;
 
+	/*
+	 * The object has already been unpoisoned by kasan_slab_alloc() for
+	 * kmalloc() or by ksize() for krealloc().
+	 */
+
+	/*
+	 * The redzone has byte-level precision for the generic mode.
+	 * Partially poison the last object granule to cover the unaligned
+	 * part of the redzone.
+	 */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		kasan_poison_last_granule((void *)object, size);
+
+	/* Poison the aligned part of the redzone. */
 	redzone_start = round_up((unsigned long)(object + size),
 				KASAN_GRANULE_SIZE);
-	redzone_end = round_up((unsigned long)object + cache->object_size,
-				KASAN_GRANULE_SIZE);
-	tag = assign_tag(cache, object, false, is_kmalloc);
-
-	/* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
-	kasan_unpoison(set_tag(object, tag), size);
+	redzone_end = (unsigned long)object + cache->object_size;
 	kasan_poison((void *)redzone_start, redzone_end - redzone_start,
 			   KASAN_KMALLOC_REDZONE);
 
+	/*
+	 * Save alloc info (if possible) for kmalloc() allocations.
+	 * This also rewrites the alloc info when called from kasan_krealloc().
+	 */
 	if (kasan_stack_collection_enabled())
-		set_alloc_info(cache, (void *)object, flags, is_kmalloc);
+		set_alloc_info(cache, (void *)object, flags, true);
 
-	return set_tag(object, tag);
-}
-
-void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
-					void *object, gfp_t flags)
-{
-	return ____kasan_kmalloc(cache, object, cache->object_size, flags, false);
+	/* Keep the tag that was set by kasan_slab_alloc(). */
+	return (void *)object;
 }
 
 void * __must_check __kasan_kmalloc(struct kmem_cache *cache, const void *object,
 					size_t size, gfp_t flags)
 {
-	return ____kasan_kmalloc(cache, object, size, flags, true);
+	return ____kasan_kmalloc(cache, object, size, flags);
 }
 EXPORT_SYMBOL(__kasan_kmalloc);
 
@@ -496,8 +528,7 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 	if (unlikely(!PageSlab(page)))
 		return __kasan_kmalloc_large(object, size, flags);
 	else
-		return ____kasan_kmalloc(page->slab_cache, object, size,
-						flags, true);
+		return ____kasan_kmalloc(page->slab_cache, object, size, flags);
 }
 
 void __kasan_kfree_large(void *ptr, unsigned long ip)
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 4fb8106f8e31..d0a3516e0909 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -355,12 +355,51 @@ static inline bool kasan_byte_accessible(const void *addr)
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
-void kasan_poison(const void *address, size_t size, u8 value);
-void kasan_unpoison(const void *address, size_t size);
+/**
+ * kasan_poison - mark the memory range as unaccessible
+ * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
+ * @size - range size
+ * @value - value that's written to metadata for the range
+ *
+ * The size gets aligned to KASAN_GRANULE_SIZE before marking the range.
+ */
+void kasan_poison(const void *addr, size_t size, u8 value);
+
+/**
+ * kasan_unpoison - mark the memory range as accessible
+ * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
+ * @size - range size
+ *
+ * For the tag-based modes, the @size gets aligned to KASAN_GRANULE_SIZE before
+ * marking the range.
+ * For the generic mode, the last granule of the memory range gets partially
+ * unpoisoned based on the @size.
+ */
+void kasan_unpoison(const void *addr, size_t size);
+
 bool kasan_byte_accessible(const void *addr);
 
 #endif /* CONFIG_KASAN_HW_TAGS */
 
+#ifdef CONFIG_KASAN_GENERIC
+
+/**
+ * kasan_poison_last_granule - mark the last granule of the memory range as
+ * unaccessible
+ * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
+ * @size - range size
+ *
+ * This function is only available for the generic mode, as it's the only mode
+ * that has partially poisoned memory granules.
+ */
+void kasan_poison_last_granule(const void *address, size_t size);
+
+#else /* CONFIG_KASAN_GENERIC */
+
+static inline void kasan_poison_last_granule(const void *address, size_t size) { }
+
+#endif /* CONFIG_KASAN_GENERIC */
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 1372a2fc0ca9..1ed7817e4ee6 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -69,10 +69,6 @@ void *memcpy(void *dest, const void *src, size_t len)
 	return __memcpy(dest, src, len);
 }
 
-/*
- * Poisons the shadow memory for 'size' bytes starting from 'addr'.
- * Memory addresses should be aligned to KASAN_GRANULE_SIZE.
- */
 void kasan_poison(const void *address, size_t size, u8 value)
 {
 	void *shadow_start, *shadow_end;
@@ -83,12 +79,12 @@ void kasan_poison(const void *address, size_t size, u8 value)
 	 * addresses to this function.
 	 */
 	address = kasan_reset_tag(address);
-	size = round_up(size, KASAN_GRANULE_SIZE);
 
 	/* Skip KFENCE memory if called explicitly outside of sl*b. */
 	if (is_kfence_address(address))
 		return;
 
+	size = round_up(size, KASAN_GRANULE_SIZE);
 	shadow_start = kasan_mem_to_shadow(address);
 	shadow_end = kasan_mem_to_shadow(address + size);
 
@@ -96,6 +92,16 @@ void kasan_poison(const void *address, size_t size, u8 value)
 }
 EXPORT_SYMBOL(kasan_poison);
 
+#ifdef CONFIG_KASAN_GENERIC
+void kasan_poison_last_granule(const void *address, size_t size)
+{
+	if (size & KASAN_GRANULE_MASK) {
+		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
+		*shadow = size & KASAN_GRANULE_MASK;
+	}
+}
+#endif
+
 void kasan_unpoison(const void *address, size_t size)
 {
 	u8 tag = get_tag(address);
@@ -115,16 +121,12 @@ void kasan_unpoison(const void *address, size_t size)
 	if (is_kfence_address(address))
 		return;
 
+	/* Unpoison round_up(size, KASAN_GRANULE_SIZE) bytes. */
 	kasan_poison(address, size, tag);
 
-	if (size & KASAN_GRANULE_MASK) {
-		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
-
-		if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
-			*shadow = tag;
-		else /* CONFIG_KASAN_GENERIC */
-			*shadow = size & KASAN_GRANULE_MASK;
-	}
+	/* Partially poison the last granule for the generic mode. */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		kasan_poison_last_granule(address, size);
 }
 
 #ifdef CONFIG_MEMORY_HOTPLUG
diff --git a/mm/slub.c b/mm/slub.c
index 176b1cb0d006..e564008c2329 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3565,8 +3565,7 @@ static void early_kmem_cache_node_alloc(int node)
 	init_object(kmem_cache_node, n, SLUB_RED_ACTIVE);
 	init_tracking(kmem_cache_node, n);
 #endif
-	n = kasan_kmalloc(kmem_cache_node, n, sizeof(struct kmem_cache_node),
-		      GFP_KERNEL);
+	n = kasan_slab_alloc(kmem_cache_node, n, GFP_KERNEL);
 	page->freelist = get_freepointer(kmem_cache_node, n);
 	page->inuse = 1;
 	page->frozen = 0;
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7e3961cb52be380bc412860332063f5f7ce10d13.1612546384.git.andreyknvl%40google.com.
