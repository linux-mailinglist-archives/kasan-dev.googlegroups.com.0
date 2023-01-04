Return-Path: <kasan-dev+bncBDN7L7O25EIBB5FP2SOQMGQE7MAQWCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0489865CCC8
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Jan 2023 07:08:53 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id f17-20020ac25091000000b004b565e69540sf11552198lfm.12
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Jan 2023 22:08:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672812532; cv=pass;
        d=google.com; s=arc-20160816;
        b=y5rHr2ggLsFBo02nOej6ajTDKF5LmPesb6YDiwoByCZoelX1QbiXzelrWlRooiqRRO
         z6oC2boij897OlU2rI2Ur8DnTouZkOtUI/BsPNZEhfSrLNb6gufrwS1hv/yfgat54WA9
         Hpq3UHeaEh7xvQhbXYkrWap2yScJHYZhURy2DcSfvyLfGqBnqe4MZJ5satomK0gGpZTa
         eCh5trK7C0/URdXfGrcNr6hq5bJiCVzZb/syet4J/Y/5CQLUhqTqLyk+7yUjhHrKDAv5
         Mg27U4zwWF6Y+JuowERGyOCPfhR4n6jv8zaN72z7rV4cJMTbJpkFfWFNFNpOrzZpX6+m
         LQiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=c7Wm/HWliRlwyoEoWMbNWHJsY7jlN5/FW+ZStwCKmo4=;
        b=R8Rf430dpXxX+C/b7PyLqBKDHB0+lQeHoDJC/m3hlBdd0sh0WaH8yY8V4QyhlW+9Pn
         dXfOepvwRy+bfWqvZkTi+F62x6iBeQhtiOQ0fpNH0STbesAClTz0h06cMckA7A88bc4/
         nhmtNcsUBeMs8MfEmkuoBQTt6K+Qw3GDEzbC8LrwGyS3z80Q02EEFBwssf+rc/7F+b9t
         vg4sUXPjrJXpW6jOyQElh5j7cdIPcZ8FrbXaP368orZTVpFq4zV6LiQ1QiwzygYvSjKa
         wuHIiVtMtcwzloYBmjk4sm+hza7EPjGWFgQOMEeV7lzI6StuWI7beu2AeedslICH6tQi
         u1NA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=SJfKpvYh;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.65 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=c7Wm/HWliRlwyoEoWMbNWHJsY7jlN5/FW+ZStwCKmo4=;
        b=DFq/YIunwKEIofriF93/Ua0d8EilyILCAb/1bqQJnyqj6mx68FP70iBG1SN904VwCV
         vaN8oOPbnCEFXhiv8kIt7cB/XR5KtDcUnUiaW1OpOaHZNP58qPYzUQFh+JxAlIYe2AWl
         mX9W+YcpBsoHQZGCDx301YqNGYzNfjTfzyyuLEyvWCwUPZyPGcnRGSZWUXZpsK5f4OfJ
         GkuiVj6CjT8dfbiWCv0XsqvVRwCIIuu/ik7g1Vk/dDcn2zOW3cDxOVSOUP6roL60aVgu
         hm830pGHFjx0DHZjR0Re/TLntB+qDzGWgFXxfUmMSf+j6NR3DUgyPeAQTwKqgDra1UNj
         6NUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=c7Wm/HWliRlwyoEoWMbNWHJsY7jlN5/FW+ZStwCKmo4=;
        b=I4jKunqPVYKLjx3n8V0k+S2x9jq0K66Ez3psloDlL7skS2+Zea/TpLqQOlpIZNa7Af
         KFGNrPehhMzzmQEniYo51LjTIwoKT/L6BQI5IivzQlWiGqN6ejJk4bAfUzPNGGRCx53U
         JBoZjyLWn2HpMowwa8DZpvXuylkUsNUUReJZn0NSWXJemvsUR6vhJKNGTSKDQwi1rAn6
         bJ7LgFhq1zfrnacxOO4goTSEOOp7LEiDH3DH/fbnQ/inMnv8XtBA/IR0Cwg5iMElbrZ4
         rWhF8Wdvsq+was2AUbkYYYAWeNBk2iWuxrnvXAj8c3yhJVjGYrUdB/1gnUh76SCk4hdp
         GS4Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpQ+7T5W3WQmrg2VbXtYg/t2V/L1t7DWjqy6PCBoVxGCyBJjJ5P
	P6dgsCVU7Cz8KzK6SIOyGrA=
X-Google-Smtp-Source: AMrXdXv3en/e4zes+wx+kI2OvF0K1EbSas3ZQ7Pi47pXxNyl50qvl3/pvAI1QiqJOtUwi8uhS3i0AA==
X-Received: by 2002:a05:6512:1090:b0:4c5:a0b4:3372 with SMTP id j16-20020a056512109000b004c5a0b43372mr3488299lfg.160.1672812532306;
        Tue, 03 Jan 2023 22:08:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4e8a:0:b0:4c8:8384:83f3 with SMTP id o10-20020ac24e8a000000b004c8838483f3ls2601300lfr.3.-pod-prod-gmail;
 Tue, 03 Jan 2023 22:08:51 -0800 (PST)
X-Received: by 2002:a05:6512:1594:b0:4b5:6a20:ca90 with SMTP id bp20-20020a056512159400b004b56a20ca90mr15277823lfb.10.1672812531353;
        Tue, 03 Jan 2023 22:08:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672812531; cv=none;
        d=google.com; s=arc-20160816;
        b=m0JCEEofK5DQM/Eh1JOnalidmQHcRYv3tdnROqA5XnL3YjBD1klKR6sYWuz4rIGuxx
         jdQN4YLBGsuX0JSmlffubLUg1zOZ4SVrqSlidpEBop4QHASr+aop/zYIo1jyWWRP8Iec
         tsqeuJzswQ51zPbZQGeUgcx4sqnlI7rVIpzUgN8EyZ596yMpd8CULfN9iiPcyS8bu8Ol
         RnTT9zLV3U26pVPv+25Pys7cfP3gVPiI8jpZVK0D1ODB8JiN8mjyE1kVHIkSQlZyIUFb
         bO7GtdgsO52Krdi4517fu/5VHPk25MpqPil1cpNkRokiioyiDGt80UoRJaPZHIyOzC32
         sYWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ICYbAgxo1gxvMoVCz28YjqvVpuUwn4trUmXKW6YLBhQ=;
        b=U8U1hZeOI3OyqtCRAWKa0dRO+FQxMOZHyMX8MEJVQr8KmMl24Nzve6BXNs00Ijtgxq
         IuFxCvCJnfLOWh0I1FwxxsYv+8TaKVZhuc9VlPti7mASjiSPXTPW/B7oovrNLpq11sph
         p0mpmE9YNsdu7cpba2jWrn95yAt8e+XIfqOJbGF4vpXJxWYasrBBlg3PnFTrdu8igDX+
         wiPfHZsyJ/FVXTBcMo9e0Zw9DY4upZh01H3msCn2P0iZvXAGzyREH3LZ1XHNJ8ACE9a8
         oWMt63g3TCjkBPThv3GZRyCi39QFTfBzmuNlgpAVg68xp7wRL4yNOVh9CY5XHGNoUCyC
         1dOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=SJfKpvYh;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.65 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga03.intel.com (mga03.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id o22-20020a05651205d600b004b5767257ecsi1249279lfo.8.2023.01.03.22.08.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 03 Jan 2023 22:08:51 -0800 (PST)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.65 as permitted sender) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6500,9779,10579"; a="323840139"
X-IronPort-AV: E=Sophos;i="5.96,299,1665471600"; 
   d="scan'208";a="323840139"
Received: from orsmga004.jf.intel.com ([10.7.209.38])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 03 Jan 2023 22:08:50 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10579"; a="779094081"
X-IronPort-AV: E=Sophos;i="5.96,299,1665471600"; 
   d="scan'208";a="779094081"
Received: from feng-clx.sh.intel.com ([10.238.200.228])
  by orsmga004.jf.intel.com with ESMTP; 03 Jan 2023 22:08:45 -0800
From: Feng Tang <feng.tang@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Feng Tang <feng.tang@intel.com>
Subject: [Patch v3 -mm 2/2] mm/kasan: simplify and refine kasan_cache code
Date: Wed,  4 Jan 2023 14:06:05 +0800
Message-Id: <20230104060605.930910-2-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20230104060605.930910-1-feng.tang@intel.com>
References: <20230104060605.930910-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=SJfKpvYh;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 134.134.136.65 as
 permitted sender) smtp.mailfrom=feng.tang@intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

struct 'kasan_cache' has a member 'is_kmalloc' indicating whether
its host kmem_cache is a kmalloc cache. With newly introduced
is_kmalloc_cache() helper, 'is_kmalloc' and its related function can
be replaced and removed.

Also 'kasan_cache' is only needed by KASAN generic mode, and not by
SW/HW tag modes, so refine its protection macro accordingly, suggested
by Andrey Konoval.

Signed-off-by: Feng Tang <feng.tang@intel.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
---
Changlog:

  Since v2:
  * Rebase latest -mm tree, fix a conflict with kasan changes
  * Collect Reviewed-by tag

  Since v1
  * Use CONFIG_KASAN_GENERIC instead of CONFIG_KASAN for 'kasan_cache',
    as suggested by Andrey Konovalov

 include/linux/kasan.h    | 22 +++++-----------------
 include/linux/slab_def.h |  2 +-
 include/linux/slub_def.h |  2 +-
 mm/kasan/common.c        |  9 ++-------
 mm/slab_common.c         |  1 -
 5 files changed, 9 insertions(+), 27 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 5ebbaf672009..f7ef70661ce2 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -96,15 +96,6 @@ static inline bool kasan_has_integrated_init(void)
 }
 
 #ifdef CONFIG_KASAN
-
-struct kasan_cache {
-#ifdef CONFIG_KASAN_GENERIC
-	int alloc_meta_offset;
-	int free_meta_offset;
-#endif
-	bool is_kmalloc;
-};
-
 void __kasan_unpoison_range(const void *addr, size_t size);
 static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
 {
@@ -129,13 +120,6 @@ static __always_inline bool kasan_unpoison_pages(struct page *page,
 	return false;
 }
 
-void __kasan_cache_create_kmalloc(struct kmem_cache *cache);
-static __always_inline void kasan_cache_create_kmalloc(struct kmem_cache *cache)
-{
-	if (kasan_enabled())
-		__kasan_cache_create_kmalloc(cache);
-}
-
 void __kasan_poison_slab(struct slab *slab);
 static __always_inline void kasan_poison_slab(struct slab *slab)
 {
@@ -255,7 +239,6 @@ static inline bool kasan_unpoison_pages(struct page *page, unsigned int order,
 {
 	return false;
 }
-static inline void kasan_cache_create_kmalloc(struct kmem_cache *cache) {}
 static inline void kasan_poison_slab(struct slab *slab) {}
 static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
 					void *object) {}
@@ -306,6 +289,11 @@ static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 
 #ifdef CONFIG_KASAN_GENERIC
 
+struct kasan_cache {
+	int alloc_meta_offset;
+	int free_meta_offset;
+};
+
 size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object);
 slab_flags_t kasan_never_merge(void);
 void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
diff --git a/include/linux/slab_def.h b/include/linux/slab_def.h
index 5834bad8ad78..a61e7d55d0d3 100644
--- a/include/linux/slab_def.h
+++ b/include/linux/slab_def.h
@@ -72,7 +72,7 @@ struct kmem_cache {
 	int obj_offset;
 #endif /* CONFIG_DEBUG_SLAB */
 
-#ifdef CONFIG_KASAN
+#ifdef CONFIG_KASAN_GENERIC
 	struct kasan_cache kasan_info;
 #endif
 
diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
index aa0ee1678d29..f6df03f934e5 100644
--- a/include/linux/slub_def.h
+++ b/include/linux/slub_def.h
@@ -136,7 +136,7 @@ struct kmem_cache {
 	unsigned int *random_seq;
 #endif
 
-#ifdef CONFIG_KASAN
+#ifdef CONFIG_KASAN_GENERIC
 	struct kasan_cache kasan_info;
 #endif
 
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 1d0008e1c420..6b8e9c848573 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -122,11 +122,6 @@ void __kasan_poison_pages(struct page *page, unsigned int order, bool init)
 			     KASAN_PAGE_FREE, init);
 }
 
-void __kasan_cache_create_kmalloc(struct kmem_cache *cache)
-{
-	cache->kasan_info.is_kmalloc = true;
-}
-
 void __kasan_poison_slab(struct slab *slab)
 {
 	struct page *page = slab_page(slab);
@@ -326,7 +321,7 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 	kasan_unpoison(tagged_object, cache->object_size, init);
 
 	/* Save alloc info (if possible) for non-kmalloc() allocations. */
-	if (kasan_stack_collection_enabled() && !cache->kasan_info.is_kmalloc)
+	if (kasan_stack_collection_enabled() && !is_kmalloc_cache(cache))
 		kasan_save_alloc_info(cache, tagged_object, flags);
 
 	return tagged_object;
@@ -372,7 +367,7 @@ static inline void *____kasan_kmalloc(struct kmem_cache *cache,
 	 * Save alloc info (if possible) for kmalloc() allocations.
 	 * This also rewrites the alloc info when called from kasan_krealloc().
 	 */
-	if (kasan_stack_collection_enabled() && cache->kasan_info.is_kmalloc)
+	if (kasan_stack_collection_enabled() && is_kmalloc_cache(cache))
 		kasan_save_alloc_info(cache, (void *)object, flags);
 
 	/* Keep the tag that was set by kasan_slab_alloc(). */
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 1cba98acc486..bf4e777cfe90 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -670,7 +670,6 @@ struct kmem_cache *__init create_kmalloc_cache(const char *name,
 
 	create_boot_cache(s, name, size, flags | SLAB_KMALLOC, useroffset,
 								usersize);
-	kasan_cache_create_kmalloc(s);
 	list_add(&s->list, &slab_caches);
 	s->refcount = 1;
 	return s;
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230104060605.930910-2-feng.tang%40intel.com.
