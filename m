Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKON6WAAMGQEUT4GXTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1283F310D39
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 16:39:22 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id y9sf3938536wmi.8
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 07:39:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612539561; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vci7R12HfxnV/zFgRvuDWdApuSb5vjACXHis3OBMaVasxyfTrBeuXZjd5FrUV2yUHH
         njNW52YpZTFU5Z6/32wbibHwwSBO1Z6W1hyTgM6rRJNBE0rT5VKJ7TNML7iyxrpdVy10
         XBlNPHFIIqLIkPGPqS3pMeaWOvZ9XIGayqfFYk//A3JaG0tCA+MeOCN7MRWAZGdxtxFM
         nXMBPXoKXbJK/m2Ft/pVwRamkSVVuzfwcA2HpBlLtnU0lWkmdyaAe9+Wao5+mlMiRHpk
         mgz3sjooBzb8IqmZViwoX3JofW5ztKMDYGij49ytV/TI0gB8TW/i88/Cwo79d3jRph4X
         avfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=LUi+Bvj9+yDbEQYqyZvON8V1b9cttMPpqA9PyakjT3g=;
        b=tegw1vxsr9Oi693XnrC2vkKss/cYVn4REvLs9Ll9Q8b4FCgkSzWMh6QzS3rF9OWvTz
         olqY7SI95LM+Q0Y1icR++VfrfhPdMEGxXAu3EtOehQbC09lUCKs1+sS4BtBYShlConwB
         EUEcD3ROfbtfSEYARrcDqpXFoIvVMli0iF082WMVbj+98lltqDwYZDMFId9b4AVdGT/A
         NkLQkoeDgYfTJZdQWGCEWc5brDg1x2lSkBTh/ha2xSG2l5R7GQzHbr5JI3rV2aM7sLRg
         BfGyQnP0DDp196ZmwYyzJF6DOi+VWTTvYWYN36UVdz2Vl0W0TYhU/5zLYTAWx3AuiSBv
         U8Pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N8dGmHEb;
       spf=pass (google.com: domain of 3qgydyaokcfetgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3qGYdYAoKCfETgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LUi+Bvj9+yDbEQYqyZvON8V1b9cttMPpqA9PyakjT3g=;
        b=Qjuk8edKuGxTmPYdwELT5rJiYM2xpSCJcIQS+ir4PbSV91zk5JMsE8sGiYyChkSl4E
         nFembhynHB4uEIvFTWg+djaMaC1W+8wPhZi+BWDt3mf7yXT4iSMdyqDg+KTsBTOwSTnk
         JoJm7EXj4YXZ0LKEvtZxXno3wuRMn+iiuHrD5vmnL1J82nMXdrDFqXvs5Xf43qHa42Qh
         5yuNpcMK3xb41zCz2KgCGN0ygnHiGJOmWN6lCLXUL0FTcCaqruUjKlGhwHE3vkACKAxj
         GuAVqJBYWxvKjVDJbBcmMcurtqbSHYgwy/4Sh/Ul0+gT8DcO6unz1zIB7s+cm4Nj+zBn
         c4eA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LUi+Bvj9+yDbEQYqyZvON8V1b9cttMPpqA9PyakjT3g=;
        b=uUOiko/7zpqaretbFaKAicwoNTXLt5xdYjZIOBFAwLaGDIPKxMePCsrFgwbrvcKilT
         p3OUgIO0smmZWXDrfdzKfPoz7jaI5aeDiIKFtRwn02saQVZyGMDQTSDplHuzF5ECOjQk
         nu6YRCNzjtzHxMJUULzO43RbDGx6Hn7qWwUn99sgp5Gosx0igj6bPf9Cusk2TUVKUIHK
         TCK8zv2cvf1rCl4yO8vV0hYKYe4OWH1XvdYvjpqMRekPa9XFL2i/9jN8OHbM8Rus4YZA
         FsZdS8bsG4DlfdaOyGlFLGJbYUUXxJYBqXMINOsnU7Lx2A5Mv+RcIBiaosxMTJkgTGEI
         0z7A==
X-Gm-Message-State: AOAM533PBdanqSFWKz1lvW3yqyor9F9syxBnAhhNwWEabkFMk2mmDq2Y
	779qJtxR9/XKS3xCoVFU/80=
X-Google-Smtp-Source: ABdhPJwZZfg70UK3r6zORutg6Em5FyI4Ys54QTtR3KhNTYqei+TLzoZc58bvPEDl0VEb/qa/r3vfBg==
X-Received: by 2002:a5d:4e92:: with SMTP id e18mr5885091wru.66.1612539561770;
        Fri, 05 Feb 2021 07:39:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:385:: with SMTP id 127ls4354799wmd.0.canary-gmail; Fri,
 05 Feb 2021 07:39:21 -0800 (PST)
X-Received: by 2002:a1c:2b05:: with SMTP id r5mr4059719wmr.179.1612539560895;
        Fri, 05 Feb 2021 07:39:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612539560; cv=none;
        d=google.com; s=arc-20160816;
        b=bqPwWvKD9AXpNQA42Phtxkty1Gzv55fsSEPbDvejkcYUTcU4oivyAI8FtFz4ju4rvO
         3dnSq3AzQ+VkZHfbYMkdvc2X0sEjRLjFxSGnlDeaf/n4jUFFEhPDDiiBt2ODqtnfGsXA
         U9Zutaojvt+TniekLTL8z9MMuFPDofF3IVVA8AjsxT0a8Y3hBQbBG/3rOlZZIzjziUuJ
         sn25ubgMzwr8ao+ZdomIRNr+bODpZ+fgmPSmoHpqP8cBFYbNBB3vnYwhAB8uhr+JNhUL
         cnByqq3jC4kr4vE7vImWmuMlsI7+A8/Kvg0YdDrOEjo7EGQeTpVWHC2S1DbBYvlUAX2H
         Q7Kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=q8NBwqooOPRUby5+8HD62t04N8TexwYKtcMMLD/hsYw=;
        b=afhJlnejVZiwh5HPwFTF3wUpTsZImZaqY5M79+j1iqlrZ94mZtINYKkm+zBm6/W9AZ
         Js30G/EJlrOrvRYQ/cdNQn16p2MpwZTz3r6EiuB44rOcEtSdkL2tgRFyBrMtn5kQ/5Cy
         q7+NCepuEm1FZ+HM2W73tPP3CtzvrDxrF6aW+Lmdozhi01MfcMVNb/C1LyecWi5TeIp+
         iWVhTczp+w4QBs1z7SEmtDVJL63DemQQS/vKQZMjvaxMl9TC9NQ+VdZvcH4QLfjtWuRv
         mU1dIvXv8ntgGVNUofSSNJB/1rG/NlvESe4kJ2P07yS/fopFb5xdZyKCCCLJIcNjPmCh
         K9ZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N8dGmHEb;
       spf=pass (google.com: domain of 3qgydyaokcfetgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3qGYdYAoKCfETgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id e11si568206wrd.3.2021.02.05.07.39.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 07:39:20 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qgydyaokcfetgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id n14so5643317wru.6
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 07:39:20 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:48a8:: with SMTP id
 j40mr143776wmp.57.1612539560487; Fri, 05 Feb 2021 07:39:20 -0800 (PST)
Date: Fri,  5 Feb 2021 16:39:02 +0100
In-Reply-To: <cover.1612538932.git.andreyknvl@google.com>
Message-Id: <4aad006aea0dcf7cd24e0cac13026dc8b93a0961.1612538932.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612538932.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v2 01/12] kasan, mm: don't save alloc stacks twice
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
 header.i=@google.com header.s=20161025 header.b=N8dGmHEb;       spf=pass
 (google.com: domain of 3qgydyaokcfetgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3qGYdYAoKCfETgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
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

Currently KASAN saves allocation stacks in both kasan_slab_alloc() and
kasan_kmalloc() annotations. This patch changes KASAN to save allocation
stacks for slab objects from kmalloc caches in kasan_kmalloc() only,
and stacks for other slab objects in kasan_slab_alloc() only.

This change requires ____kasan_kmalloc() knowing whether the object
belongs to a kmalloc cache. This is implemented by adding a flag field
to the kasan_info structure. That flag is only set for kmalloc caches
via a new kasan_cache_create_kmalloc() annotation.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h |  9 +++++++++
 mm/kasan/common.c     | 18 ++++++++++++++----
 mm/slab_common.c      |  1 +
 3 files changed, 24 insertions(+), 4 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 6d8f3227c264..2d5de4092185 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -83,6 +83,7 @@ static inline void kasan_disable_current(void) {}
 struct kasan_cache {
 	int alloc_meta_offset;
 	int free_meta_offset;
+	bool is_kmalloc;
 };
 
 #ifdef CONFIG_KASAN_HW_TAGS
@@ -143,6 +144,13 @@ static __always_inline void kasan_cache_create(struct kmem_cache *cache,
 		__kasan_cache_create(cache, size, flags);
 }
 
+void __kasan_cache_create_kmalloc(struct kmem_cache *cache);
+static __always_inline void kasan_cache_create_kmalloc(struct kmem_cache *cache)
+{
+	if (kasan_enabled())
+		__kasan_cache_create_kmalloc(cache);
+}
+
 size_t __kasan_metadata_size(struct kmem_cache *cache);
 static __always_inline size_t kasan_metadata_size(struct kmem_cache *cache)
 {
@@ -278,6 +286,7 @@ static inline void kasan_free_pages(struct page *page, unsigned int order) {}
 static inline void kasan_cache_create(struct kmem_cache *cache,
 				      unsigned int *size,
 				      slab_flags_t *flags) {}
+static inline void kasan_cache_create_kmalloc(struct kmem_cache *cache) {}
 static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 static inline void kasan_poison_slab(struct page *page) {}
 static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index fe852f3cfa42..bfdf5464f4ef 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -210,6 +210,11 @@ void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 		*size = optimal_size;
 }
 
+void __kasan_cache_create_kmalloc(struct kmem_cache *cache)
+{
+	cache->kasan_info.is_kmalloc = true;
+}
+
 size_t __kasan_metadata_size(struct kmem_cache *cache)
 {
 	if (!kasan_stack_collection_enabled())
@@ -394,17 +399,22 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
 	}
 }
 
-static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
+static void set_alloc_info(struct kmem_cache *cache, void *object,
+				gfp_t flags, bool is_kmalloc)
 {
 	struct kasan_alloc_meta *alloc_meta;
 
+	/* Don't save alloc info for kmalloc caches in kasan_slab_alloc(). */
+	if (cache->kasan_info.is_kmalloc && !is_kmalloc)
+		return;
+
 	alloc_meta = kasan_get_alloc_meta(cache, object);
 	if (alloc_meta)
 		kasan_set_track(&alloc_meta->alloc_track, flags);
 }
 
 static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
-				size_t size, gfp_t flags, bool keep_tag)
+				size_t size, gfp_t flags, bool is_kmalloc)
 {
 	unsigned long redzone_start;
 	unsigned long redzone_end;
@@ -423,7 +433,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 				KASAN_GRANULE_SIZE);
 	redzone_end = round_up((unsigned long)object + cache->object_size,
 				KASAN_GRANULE_SIZE);
-	tag = assign_tag(cache, object, false, keep_tag);
+	tag = assign_tag(cache, object, false, is_kmalloc);
 
 	/* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
 	kasan_unpoison(set_tag(object, tag), size);
@@ -431,7 +441,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 			   KASAN_KMALLOC_REDZONE);
 
 	if (kasan_stack_collection_enabled())
-		set_alloc_info(cache, (void *)object, flags);
+		set_alloc_info(cache, (void *)object, flags, is_kmalloc);
 
 	return set_tag(object, tag);
 }
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 9aa3d2fe4c55..39d1a8ff9bb8 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -647,6 +647,7 @@ struct kmem_cache *__init create_kmalloc_cache(const char *name,
 		panic("Out of memory when creating slab %s\n", name);
 
 	create_boot_cache(s, name, size, flags, useroffset, usersize);
+	kasan_cache_create_kmalloc(s);
 	list_add(&s->list, &slab_caches);
 	s->refcount = 1;
 	return s;
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4aad006aea0dcf7cd24e0cac13026dc8b93a0961.1612538932.git.andreyknvl%40google.com.
