Return-Path: <kasan-dev+bncBDN7L7O25EIBB6VG7CNQMGQENKWMWQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id BF01B635CF5
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Nov 2022 13:35:06 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id p14-20020a05600c204e00b003cf4cce4da5sf779807wmg.0
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Nov 2022 04:35:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669206906; cv=pass;
        d=google.com; s=arc-20160816;
        b=OT/aQmVGsivu4trULssi5y7PbwsHsX6g7jfR5eg7X0EdVcu3lsYvjlWECuyL32yPwh
         1cpmDgNkIvQwuB96R4kdJjhZSoleF4womOysd7g0WRA59BeydvOjRCEDBIrBG4FQGoxP
         2218flRxEmabVoEr3eT6Mhp2kjjso/qm7nBOXxJR/02PWMQPNRDubTSLncI93s3qNUmo
         agYqHyDfF/PMT5SeLjsKonaBooHm2OYi5MHEh3WT3WWxmI8DXnHQ3xNjyyf3R33uhCFq
         p624YBVcbT0b9E1H1ARBSbk0ECgL/GbEpitHUA+OJZKstRhBhX2/eVfCRGK327esxTff
         3fFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/QRSOSAXgEj7h2xZZHmgSYgOf9GZMCLPaXAEu31fSbk=;
        b=0aTyTr8TZOWwuBOMe8qAfh64fkYFt5DilVnttO8f4oZwixYYiH7U8pCwcB5hEEhltW
         am04KH/jBsZnTHQptLXCbRs/Mx41nja4Xr2I45RIrcVFiW+WBrKiTt0YPF4dALfshT0y
         OzNZlBmJgEydU1t48KawZwS5LprXRd12C2uJu7/VBRkovx9r7eH3ueGGmi9oyxF8ydUU
         L3DSp7FuHs9A8FbiejHFpqQei4au8iUOlT7s9291dcYGx/n/40+XYddlHE6hMdDO+M1k
         VH7GC6xsX8/i1gMK87pbpQO5tZNSYYjhB3gtQ9zZLbDEsb+EAphGE2RlatcP5xn36f0q
         llqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=mJ2ejFi7;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/QRSOSAXgEj7h2xZZHmgSYgOf9GZMCLPaXAEu31fSbk=;
        b=BFGDeFuWEAGgqFB+NGPLXZ4ylu9JVp3+TfeuGS7gh8tvoL41hagGwzTRiQBLHFuF0x
         7N1/nTwJRcRawkTmjZvrjL6uqa7CvnzyN+05ep11CKKrBbrf4XVQZkSnSJZi4RBxyNJ2
         rqvv2qPpsD6kkEa110c7OihbnISHXjmlHXu9DBI2HeKIIK9d0WFeDn6ckMvA8orcKKh1
         I474RYJhGuVDfioyq0aRr3wP4TxlWF6MpwCBOZhumUbcn9Xa9XW+n4Dw52G9xhSBzSKb
         9JdGthtIGDkLTsLaY5iJfN/f06Z3HqaJzYLh3Lorc5Gdhq9+gQkRscIZZcboynrbtFiT
         cGhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/QRSOSAXgEj7h2xZZHmgSYgOf9GZMCLPaXAEu31fSbk=;
        b=GQnKp3Xxdueu9AFgFltuVvgvemoXAsQN4W1Fl+xXv/1KHeh2ApPX4Cs6vc+K3kt0b4
         lplpbFP2M4BdDvC++RcMBZe1T5BDC+SKzna7/NHCrWA7+09I3pPBef+Pf+AHkjROST1f
         KMSE1+09nNJ1EoWF6Ua3MIyiszVVpc43JzdFAv89pNPYC+B/RzXP1PqIEijSFX/6LZfx
         8uOCSjJXIVVAjLaquWpNzluPjlVU0Gs/9oKY9hXxNAGlyLmAZIHtJmRTsfClT5o6E6pR
         nWMWXkuH+F0savEjCgoclQJKvKDihcqWZ0YeDLPCJnroWbG7l+Xnkva3xTKPRnrBgHUf
         EwqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmE/vX30J8BhBGxzwmvBDk4gPjTumQ6jixiN7CxzEJKxbiV+E7w
	0dkKWvW6q1lYBvIyMtMtJt8=
X-Google-Smtp-Source: AA0mqf6Gh/AvGekalOp6dYv87lgTjVpMEObs4i0ohT7DNYV+HBV4CQY4mW2W2YStZg4hkLhlQ6X3lA==
X-Received: by 2002:a05:600c:4f01:b0:3cf:8952:2fd2 with SMTP id l1-20020a05600c4f0100b003cf89522fd2mr9958292wmq.9.1669206906457;
        Wed, 23 Nov 2022 04:35:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:24a:b0:22c:d34e:768c with SMTP id
 m10-20020a056000024a00b0022cd34e768cls2134593wrz.0.-pod-prod-gmail; Wed, 23
 Nov 2022 04:35:05 -0800 (PST)
X-Received: by 2002:adf:ea0b:0:b0:236:695b:6275 with SMTP id q11-20020adfea0b000000b00236695b6275mr17626451wrm.116.1669206905644;
        Wed, 23 Nov 2022 04:35:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669206905; cv=none;
        d=google.com; s=arc-20160816;
        b=yfauAb4ykY24zuCCRj0RyHTjRfxID1plMDnksQcQAr/x8NUNUjRkidcf9gYUs1qb4i
         QG/sFjsQbnP/mP8IRnnZT51V00+kQlMeqT/8obxkiy8beEbpd9rD2VWxBqStQ7AsAazp
         +oMdWVDMLG292bmHLf1tpShb7Y0c4VPB/gITh4UqwVMjzurSKwMtlgbkH/EJqejB5Rbf
         GcpZUmou3vw+NuOTMq17LQSFjzAtqqxdRhJsPgaOExlDTzsU+MpVUNJntDmI5afZsqAq
         znHp7DuhOBcvK4FLJGeZlN2Sxw9CzCeTiUZIG/nnHDsAonrjgmCju3U3xv6TigVi5/zc
         tdMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=DKpDEUuzQP3JS6vSn7fniF3BoC56bwIDZKe8r0jOrQM=;
        b=wWQLYSpfY6OtWm3geB9NWPcetPx6sfzVKMX1qQdUpiwM97SxIdKvibSafD7tI9RhgY
         /1Bf1WXDPqRviBKzybTLDrHJYmxF0Og6KPwfxhdTEXnurw1Z0KPKG8m1qJlSBkXd02Oh
         YKHfP0dy8ccKcKNr/hgUX1yFDL22YpXh8vlCe4XpYjGu1TWhCeUhI22lNWMeLMdHtlu+
         02uBP5otsCr2ro6yducO/YN6K+ZkhgS64YtTmIctOTEWFRd5PoA8YAwoWpjGrcNdqaPU
         XyOsBb2cP0vG7jVJSe35/pf0vY8YNKuqttDEH1pGdKj997zZLJ7NPmPWrTe1zZd9JRsx
         2qNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=mJ2ejFi7;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga02.intel.com (mga02.intel.com. [134.134.136.20])
        by gmr-mx.google.com with ESMTPS id l190-20020a1c25c7000000b003c6e63dcbb3si131907wml.1.2022.11.23.04.35.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 23 Nov 2022 04:35:05 -0800 (PST)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) client-ip=134.134.136.20;
X-IronPort-AV: E=McAfee;i="6500,9779,10539"; a="301614995"
X-IronPort-AV: E=Sophos;i="5.96,187,1665471600"; 
   d="scan'208";a="301614995"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by orsmga101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 23 Nov 2022 04:35:04 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10539"; a="705349470"
X-IronPort-AV: E=Sophos;i="5.96,187,1665471600"; 
   d="scan'208";a="705349470"
Received: from feng-clx.sh.intel.com ([10.238.200.228])
  by fmsmga008.fm.intel.com with ESMTP; 23 Nov 2022 04:35:00 -0800
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
Subject: [PATCH v2 -next 2/2] mm/kasan: simplify and refine kasan_cache code
Date: Wed, 23 Nov 2022 20:31:59 +0800
Message-Id: <20221123123159.2325763-2-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20221123123159.2325763-1-feng.tang@intel.com>
References: <20221123123159.2325763-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=mJ2ejFi7;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as
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
---
Changlog:

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
index dff604912687..0ff382f79f80 100644
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
@@ -252,7 +236,6 @@ static inline void kasan_poison_pages(struct page *page, unsigned int order,
 				      bool init) {}
 static inline bool kasan_unpoison_pages(struct page *page, unsigned int order,
 					bool init) { return false; }
-static inline void kasan_cache_create_kmalloc(struct kmem_cache *cache) {}
 static inline void kasan_poison_slab(struct slab *slab) {}
 static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
 					void *object) {}
@@ -303,6 +286,11 @@ static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 
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
index f0ffad6a3365..39f7f1f95de2 100644
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
index f9c68a9dac04..4e7cdada4bbb 100644
--- a/include/linux/slub_def.h
+++ b/include/linux/slub_def.h
@@ -132,7 +132,7 @@ struct kmem_cache {
 	unsigned int *random_seq;
 #endif
 
-#ifdef CONFIG_KASAN
+#ifdef CONFIG_KASAN_GENERIC
 	struct kasan_cache kasan_info;
 #endif
 
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 1f30080a7a4c..6e265beefc27 100644
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
index 8276022f0da4..a5480d67f391 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -663,7 +663,6 @@ struct kmem_cache *__init create_kmalloc_cache(const char *name,
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221123123159.2325763-2-feng.tang%40intel.com.
