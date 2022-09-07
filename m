Return-Path: <kasan-dev+bncBDN7L7O25EIBBA4I4GMAMGQEQCVSIBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 760145AFD20
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 09:10:59 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id i29-20020adfa51d000000b00228fa8325c0sf276023wrb.15
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 00:10:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662534659; cv=pass;
        d=google.com; s=arc-20160816;
        b=oF+eKu5YgA2qM5F9qtU9VWd1l5w2gqQtZE9qoXYgQ50mOjFijrKWrL0VbvVenolW1B
         TxU8QYdo57ZzmJ1EhZGtbiKH3nR8OmOl5munUF3Comg37UjhQMA56DlYGoPz+TR9O9Dl
         +s6el+RkQXvAriO1E8LHnUf33T+P9swMGBieSd8WfxtmDD47KJXOykrupPUIOhCOpN2x
         0JpB7aULZsASQG4UK5ihmEh4CZOPJMp9/zSIlsFXO7EzeaVRImvnOy4R6m1bdMV9z0Qt
         uFIsNUQB+mMUYoRs7FcJfV0ne6mjXHcuZCOGEhbeLw13zUR5i+MkBy4V8tMQ7JhC2OIE
         FpOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QBUL/Ygbuz9OaR9FO2L6NRKRNffSexOZcTikNkt73PY=;
        b=Nf/CkrCX/5VEA9cLa3MdqJWuzUwB55x8zlCM2TV6TNEBapSJ1DhHJOZXqJjzaCbibk
         OiatyA+9n6nqCLZUYSVBsoCXYtYF5CehjdM/6EkpMKl1mPAyOYJIZG9zQrDVTDbT1hix
         NTfYLnF8ufM74kQNw7PIePQnSDvT9VaRDmh3NNTNSjo+0He/7Lu5OBECDSknX7gQHqNg
         49OF6eTor72B6MEBp6ATcxNxc0gmMWKJh1YlFMS3agEJAJPa52Qzn9mmV1LUF2HyenCI
         DPWBjwlxdY1RuoHLP61Poft/Ib6x7jeZGu2V90TURiUVlz75WI71XnqDQBHkRbRaFTcf
         JIjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=earTROn6;
       spf=softfail (google.com: domain of transitioning feng.tang@intel.com does not designate 134.134.136.65 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=QBUL/Ygbuz9OaR9FO2L6NRKRNffSexOZcTikNkt73PY=;
        b=d/gEeN/6llWaq9Pw0AHrlx9nbywFsQhrdxAXRXZdmi8czbVH4CxYuqnSgMVz8ADCg+
         1eisoHtOK82ppC9/PpkRaUziJmkOng44jSlI5cL2NSCmcJVBoj2ozwa3suuu0PBx7uTG
         +N4I5YEwlo7O2F/cQfxUk9YlHwOHqxiKoX036bMAplqVTLm8Jlv0Gcesz34FGO2JJ/5B
         uYZ0gmZxtxOUt3sYmiJsqBwPoJ1zFtCxR1hD1Eu3a3L6TSbdscTp9vh9dYW+wl4oFzU6
         ueQHffwYeVqVNgO0M7stA6+yyFFHS4BOPGgwCANTKKhFNnMPK4eOy6MbluPET42G2j/P
         AmlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=QBUL/Ygbuz9OaR9FO2L6NRKRNffSexOZcTikNkt73PY=;
        b=jcCy8Kr1vlycZL6VPfYDo8pLay3LpjJjyxosTM4wBvtJyysH2E25tWe5s+uUQfZnXw
         MFjjAbmp9Wsftp04Hz8jzxhtA2mUOTHyKFbQ/HqbGsTLG0xXGZZLWf5WXV60SSbJzni5
         uzJXHxX25FUgMYTvU/7Juhk9fpyBDzSPWfwh+8SmqI/Smu++fPMUCTWi4dcZy9lT45Uy
         cJoV1c0Y7njtlO92iaETfoD4L5GPAuHBjvZdBz6nSiz/CGIahlg6VaXqWJwgug1XIYZf
         h+d9syTJV8xulWmsrWz1H1Yafugs5/qIYclpwVVK4MfsTNqHtdCTIu6DcCQUDCq7aQmp
         VlNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo30tra9U/dWleSIX7Y/VuVi6z2OaU4SQzboKTGahlXgGvgz/vZU
	wbZM7YU3X+UNah49vUmWl5A=
X-Google-Smtp-Source: AA6agR6IaxV/APicPGmPwn/p5B0ub+2wJ0LHKkJAzSr68V9zJKP1CDBezgGC9oORp9LgQ39u9XFnpw==
X-Received: by 2002:a05:600c:a199:b0:3a5:dddf:ac6d with SMTP id id25-20020a05600ca19900b003a5dddfac6dmr1047172wmb.44.1662534659226;
        Wed, 07 Sep 2022 00:10:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d213:0:b0:228:ddd7:f40e with SMTP id j19-20020adfd213000000b00228ddd7f40els547865wrh.3.-pod-prod-gmail;
 Wed, 07 Sep 2022 00:10:58 -0700 (PDT)
X-Received: by 2002:a5d:62d0:0:b0:228:d6ee:9bf4 with SMTP id o16-20020a5d62d0000000b00228d6ee9bf4mr1111565wrv.34.1662534658286;
        Wed, 07 Sep 2022 00:10:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662534658; cv=none;
        d=google.com; s=arc-20160816;
        b=HYtXk9BB7DFyd+DbGw4RKXf2AdrEH2APf74ZJFXTZ/jM2k4g4YzjAS0dYBeAxgfR0/
         iFGeD0ZQOQkn+WDMZ5CFVb+Zm9tmLgonGKooYNRAyeu8A/ZNQKpqgEYO1C3MzkEFcVaV
         K2jhWST+8fUjPGoVSvZLCYUGN14h1egw9KsgPd+GvZjQRSE588ZvWTBZV5eWUHCg8VaP
         lwHaJfaNDGvhkO+0rXQu5ATxS4ebaGVtFeis4Ek9WlrYWixr+udYV5xGOuVkCRvAr9l3
         GPUuPOwMwgrWBf89m30z9i+oq4rH1ZsXAwX3GOdKSeJ0J1wDDUgJWvVAF7SNcLdXt5z9
         KGWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=K6KORaPf2wkeklIAdwnig2cQf/eC91oDOg62kOu8d7o=;
        b=fJmLVjzYCYlLJItpDsYQXASLi56YMpIm+bl08JvK7yOwBjYP7ka7+ttA7NRxNaelPq
         PmrdSqws0Q9eKUUf/BgcQNDZeJ7/I3mm8K+B4MxHmXSMrcR/8yWsHEvpmgjfw7XFjQNt
         q/LmTQFclQGGy0xXCHs8zKTnylFYuOtr/8m4YsdXJma8zB3+h79A5ETeU8jLfheBFg1H
         CDGYRUEsy6epWKRD1Elgk7n4pOlYmLB5uMLm0FkzxOeTLy6k4PKGV7hn9Skx3RNIlriS
         67pLvsz6Ml/ueW0oslm8JdcNohQJOhc+uIMJo18WNKOvso5fOubDkaoXkpuTJXlivQii
         V+Cg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=earTROn6;
       spf=softfail (google.com: domain of transitioning feng.tang@intel.com does not designate 134.134.136.65 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga03.intel.com (mga03.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id y18-20020a05600c365200b003a5ce2af2c7si724421wmq.1.2022.09.07.00.10.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 07 Sep 2022 00:10:58 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning feng.tang@intel.com does not designate 134.134.136.65 as permitted sender) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6500,9779,10462"; a="298115293"
X-IronPort-AV: E=Sophos;i="5.93,296,1654585200"; 
   d="scan'208";a="298115293"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 07 Sep 2022 00:10:57 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,296,1654585200"; 
   d="scan'208";a="676053413"
Received: from feng-clx.sh.intel.com ([10.238.200.228])
  by fmsmga008.fm.intel.com with ESMTP; 07 Sep 2022 00:10:53 -0700
From: Feng Tang <feng.tang@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>
Cc: Dave Hansen <dave.hansen@intel.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH v5 2/4] mm/slub: only zero the requested size of buffer for kzalloc
Date: Wed,  7 Sep 2022 15:10:21 +0800
Message-Id: <20220907071023.3838692-3-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220907071023.3838692-1-feng.tang@intel.com>
References: <20220907071023.3838692-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=earTROn6;       spf=softfail
 (google.com: domain of transitioning feng.tang@intel.com does not designate
 134.134.136.65 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

kzalloc/kmalloc will round up the request size to a fixed size
(mostly power of 2), so the allocated memory could be more than
requested. Currently kzalloc family APIs will zero all the
allocated memory.

To detect out-of-bound usage of the extra allocated memory, only
zero the requested part, so that sanity check could be added to
the extra space later.

For kzalloc users who will call ksize() later and utilize this
extra space, please be aware that the space is not zeroed any
more.

Signed-off-by: Feng Tang <feng.tang@intel.com>
---
 mm/slab.c | 6 +++---
 mm/slab.h | 9 +++++++--
 mm/slub.c | 6 +++---
 3 files changed, 13 insertions(+), 8 deletions(-)

diff --git a/mm/slab.c b/mm/slab.c
index a5486ff8362a..73ecaa7066e1 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -3253,7 +3253,7 @@ slab_alloc_node(struct kmem_cache *cachep, struct list_lru *lru, gfp_t flags,
 	init = slab_want_init_on_alloc(flags, cachep);
 
 out:
-	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init);
+	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init, 0);
 	return objp;
 }
 
@@ -3506,13 +3506,13 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	 * Done outside of the IRQ disabled section.
 	 */
 	slab_post_alloc_hook(s, objcg, flags, size, p,
-				slab_want_init_on_alloc(flags, s));
+				slab_want_init_on_alloc(flags, s), 0);
 	/* FIXME: Trace call missing. Christoph would like a bulk variant */
 	return size;
 error:
 	local_irq_enable();
 	cache_alloc_debugcheck_after_bulk(s, flags, i, p, _RET_IP_);
-	slab_post_alloc_hook(s, objcg, flags, i, p, false);
+	slab_post_alloc_hook(s, objcg, flags, i, p, false, 0);
 	kmem_cache_free_bulk(s, i, p);
 	return 0;
 }
diff --git a/mm/slab.h b/mm/slab.h
index d0ef9dd44b71..20f9e2a9814f 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -730,12 +730,17 @@ static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
 
 static inline void slab_post_alloc_hook(struct kmem_cache *s,
 					struct obj_cgroup *objcg, gfp_t flags,
-					size_t size, void **p, bool init)
+					size_t size, void **p, bool init,
+					unsigned int orig_size)
 {
 	size_t i;
 
 	flags &= gfp_allowed_mask;
 
+	/* If original request size(kmalloc) is not set, use object_size */
+	if (!orig_size)
+		orig_size = s->object_size;
+
 	/*
 	 * As memory initialization might be integrated into KASAN,
 	 * kasan_slab_alloc and initialization memset must be
@@ -746,7 +751,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
 	for (i = 0; i < size; i++) {
 		p[i] = kasan_slab_alloc(s, p[i], flags, init);
 		if (p[i] && init && !kasan_has_integrated_init())
-			memset(p[i], 0, s->object_size);
+			memset(p[i], 0, orig_size);
 		kmemleak_alloc_recursive(p[i], s->object_size, 1,
 					 s->flags, flags);
 	}
diff --git a/mm/slub.c b/mm/slub.c
index effd994438e6..f523601d3fcf 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3376,7 +3376,7 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s, struct list_l
 	init = slab_want_init_on_alloc(gfpflags, s);
 
 out:
-	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init);
+	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init, orig_size);
 
 	return object;
 }
@@ -3833,11 +3833,11 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	 * Done outside of the IRQ disabled fastpath loop.
 	 */
 	slab_post_alloc_hook(s, objcg, flags, size, p,
-				slab_want_init_on_alloc(flags, s));
+				slab_want_init_on_alloc(flags, s), 0);
 	return i;
 error:
 	slub_put_cpu_ptr(s->cpu_slab);
-	slab_post_alloc_hook(s, objcg, flags, i, p, false);
+	slab_post_alloc_hook(s, objcg, flags, i, p, false, 0);
 	kmem_cache_free_bulk(s, i, p);
 	return 0;
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220907071023.3838692-3-feng.tang%40intel.com.
