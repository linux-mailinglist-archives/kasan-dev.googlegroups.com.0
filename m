Return-Path: <kasan-dev+bncBDN7L7O25EIBBW4F52NQMGQEO6OE6YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 7875363245B
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 14:53:32 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id j20-20020adfb314000000b002366d9f67aasf3201294wrd.3
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 05:53:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669038812; cv=pass;
        d=google.com; s=arc-20160816;
        b=TI7n0JNGQPGbVD6yphVFyhIWFSy+ocC1CHQZyfxDgdZiHVhR7Id/OVh6N4Bxb3HbGa
         QQoZgNDNIzuxp55WRxsz0JQv06YucCadzVqU1gCouMia8Ra7iSa5HexiNoB4jmXiNMQB
         aW0dfWMT6h8Kf5dtmpXzBEp1fH70i50cqNoGeqjmAbjMkgJN1KEVJTUng1P8wjVy+3qu
         7JI9aw1hZfssEJ/NbvSWgVj3rZzl8q+7hune+oDUGGZ8sn+kY15ZqT0Ta9AoWdtZ3e6K
         c8v25RxJdlQ8T5VmuwOZl9lRUyt2OgRG78IxLndm5CjI8AuOuQaXCPtoa2geRnIlBplf
         brpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=H+UvKi4BO9CjH1TzUYgdK2C0jKyMvaSvWZh1ECzTMko=;
        b=nmuENjjmvlaTamN/aGWuEDSGIsXMPBbIjzLT10CmE4OeyXH+pcXbUv0wQL65n74BTc
         360x7xoufEAPRVXSmQBOVia9KkTmm9P4mtLcMjwghkgPoL+y+zeMzcsCsPT7t2rJs/in
         vBAHd9X5HJ1pAcfDiOvuppMEvsOSZSjkbVikDpP004UE6KVRYTUPNibYRxKQB4HUhvOW
         yPNH4Ln7oiEhfk53Z2BUT32+AYZux6LLE+bivFsJk66g9JrGatxA4x1RYB/FcmIPuq9U
         dVaabCHurT77gCk5ZLYIwuwHfyu/51B8xBfJB4bu6CyJB/yNRgfkMngzBPeCZi+Kpe9V
         2Rkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=BBXMjNn1;
       spf=pass (google.com: domain of feng.tang@intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=H+UvKi4BO9CjH1TzUYgdK2C0jKyMvaSvWZh1ECzTMko=;
        b=kk80fpASg7u87iP1B2zDl9g7ASltOLFzuZDLkin0c/HwSsiuOSCnnDv0nSPgeK9G1r
         l8NbTWAjtVsGH9+R0p0hQnau1VQRdNCsFpBpDTKeUPsfUJx3CGy0zU8t5fCpUqmW0JUy
         iwWbWAbM070dLI0Upmd4JRlvc9yz7rDiaudtzLTDunvZSLi/mc8O3Sz5eLOU/5YFcjff
         opGIBiAdT18WaH2Qpq3joyvE6TKBMnTZEPPCk0h6l7Ic58W1GMMxo1Qo+dUYXkIgPlRO
         OQzNn/WA3ynsdxt+vvYuqvjdog5E4OPhCyR0gdWUrZr16GBflZu8lIjuqBAhpN/kVa8R
         BkGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=H+UvKi4BO9CjH1TzUYgdK2C0jKyMvaSvWZh1ECzTMko=;
        b=kYEorWr5g3Ie6asmNHk6fcUw8JUsoUMqv1Ni4u7E1EeDaMh6WJsSJJTLBRS1poEE/1
         ZfzhsHUjgw50sXsMOAbTs6w5LK3RLFuSid4y6kkzt5XR99SyvHdRlNoQsXXg/LiCYLwT
         9tGRqA7TqoLDMcSN+TcFEoIvF0HpMwYrBjI5uE9j7abUo2L23bdHTg3hj1wqK9tHKrNt
         7jq3GN0Lw9YFY2sHD6zg0o1C9wxAEfZ7oN1qDEvjEjrEbeRM1yy5viRGkdpXTd/qEcY6
         Y6xT1KqzpWz5Xf17gzwslUWD96jY3OZz1VOwxNLBeQv9ioVeRjYCoZmepgszUOGN5rkv
         5ITA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pkjGoydjchS07hcbeGh5Q4pEwamF4Q5E3UoEBH4uwhRhFC/XRBA
	AZcJ0U6KtCAnhJqWYRSTmxk=
X-Google-Smtp-Source: AA0mqf5OzB21PukSSrZFAXYppUp6rVTTHx4YHUVIubVD4m90HlGTdxyTlhO2lHfb9Sokp1TT9/wgDg==
X-Received: by 2002:a05:600c:3b1e:b0:3c6:c182:b125 with SMTP id m30-20020a05600c3b1e00b003c6c182b125mr6190617wms.145.1669038812026;
        Mon, 21 Nov 2022 05:53:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5247:0:b0:236:8fa4:71d1 with SMTP id k7-20020a5d5247000000b002368fa471d1ls1636867wrc.1.-pod-prod-gmail;
 Mon, 21 Nov 2022 05:53:31 -0800 (PST)
X-Received: by 2002:a05:6000:1a48:b0:241:d16a:19a8 with SMTP id t8-20020a0560001a4800b00241d16a19a8mr4174400wry.695.1669038811189;
        Mon, 21 Nov 2022 05:53:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669038811; cv=none;
        d=google.com; s=arc-20160816;
        b=kQBmQhKTBUEx4DPy3fOh9AaXwOzHUK0uIAnz12YDheBDfoe8J6uzIXAKHDAzZ8VnlU
         Sbr2jahaanvTZ+CeyKzcw6oMClyGBumS7P4lv2hkLZBFcuBCpNT3XCTWtlYwf8YtJXxc
         lS9h3M6e/38i+bAexE2QxoZLD4hruVLFjJsvzCTeu5HMXvNnEsYKe8iRHMQMEV0qSl11
         c5cWNL9lAHEf1vDN6RisKzl4AWH1DCM/dgKTmIDAfjBo15VlbQYalYuEKYOTZQDCC1tW
         k0Rce23ZGbkRcPJ7vjVkNG2qf0ZDscsT2g3uRB/efOhlpXpdOluIgPSGbliOushlgJH1
         PShQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=qGPUeE4ITf2p+O2BZkcAmNpuuPsa1nAB6HxRM2M3MtI=;
        b=EQonBv8ElR+skUEvG/jJLs4z8tkcSlqXdaqbQsfzOK0DLvhD6pVMYYMGAp/mQacgiz
         0aX/MztGc//PpES0x8LA8G7NeIo3vluhNnHMUZDib7CwiQAYA/sUXLMrp8hOJT8QbnZS
         cXGszkeNVOchTux0DUPFIJU2sVl4+xfKsROZg//rgWnhyPcF3u3LoVGYuMTRPOQM0lRj
         0+x4/jnoIe9+S4oIy5/de/uBivYaFeBFf3YViQUEYRuH0c6GhdX3tERzsoG/ZFJiv3ud
         2MZL6KJqWjoOsbr+Ly23UZfAG0Dyr3MYigpHINzhDviX+yFnlBYhbBx5UDgvauo95C1t
         sqkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=BBXMjNn1;
       spf=pass (google.com: domain of feng.tang@intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga17.intel.com (mga17.intel.com. [192.55.52.151])
        by gmr-mx.google.com with ESMTPS id bt2-20020a056000080200b002416691399csi383477wrb.4.2022.11.21.05.53.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Nov 2022 05:53:31 -0800 (PST)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.151 as permitted sender) client-ip=192.55.52.151;
X-IronPort-AV: E=McAfee;i="6500,9779,10537"; a="293949390"
X-IronPort-AV: E=Sophos;i="5.96,181,1665471600"; 
   d="scan'208";a="293949390"
Received: from fmsmga006.fm.intel.com ([10.253.24.20])
  by fmsmga107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Nov 2022 05:53:30 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10537"; a="886125108"
X-IronPort-AV: E=Sophos;i="5.96,181,1665471600"; 
   d="scan'208";a="886125108"
Received: from feng-clx.sh.intel.com ([10.238.200.228])
  by fmsmga006.fm.intel.com with ESMTP; 21 Nov 2022 05:53:26 -0800
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
Subject: [PATCH -next 2/2] mm/kasan: simplify is_kmalloc check
Date: Mon, 21 Nov 2022 21:50:24 +0800
Message-Id: <20221121135024.1655240-2-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20221121135024.1655240-1-feng.tang@intel.com>
References: <20221121135024.1655240-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=BBXMjNn1;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 192.55.52.151 as
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

Use new is_kmalloc_cache() to simplify the code of checking whether
a kmem_cache is a kmalloc cache.

Signed-off-by: Feng Tang <feng.tang@intel.com>
---
 include/linux/kasan.h | 9 ---------
 mm/kasan/common.c     | 9 ++-------
 mm/slab_common.c      | 1 -
 3 files changed, 2 insertions(+), 17 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index dff604912687..fc46f5d6f404 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -102,7 +102,6 @@ struct kasan_cache {
 	int alloc_meta_offset;
 	int free_meta_offset;
 #endif
-	bool is_kmalloc;
 };
 
 void __kasan_unpoison_range(const void *addr, size_t size);
@@ -129,13 +128,6 @@ static __always_inline bool kasan_unpoison_pages(struct page *page,
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
@@ -252,7 +244,6 @@ static inline void kasan_poison_pages(struct page *page, unsigned int order,
 				      bool init) {}
 static inline bool kasan_unpoison_pages(struct page *page, unsigned int order,
 					bool init) { return false; }
-static inline void kasan_cache_create_kmalloc(struct kmem_cache *cache) {}
 static inline void kasan_poison_slab(struct slab *slab) {}
 static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
 					void *object) {}
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 1f30080a7a4c..f7e0e5067e7a 100644
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
+	if (kasan_stack_collection_enabled() && is_kmalloc_cache(cache))
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221121135024.1655240-2-feng.tang%40intel.com.
