Return-Path: <kasan-dev+bncBDN7L7O25EIBB6FG7CNQMGQE22BVATY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id CDB4D635CF4
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Nov 2022 13:35:04 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id m17-20020a05600c3b1100b003cf9cc47da5sf9558917wms.9
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Nov 2022 04:35:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669206904; cv=pass;
        d=google.com; s=arc-20160816;
        b=A3leX87mfV2/4LcgzgU0ow9ZGIUoMeNOGy1k22JyB9nCMWP0USpp3CIIWEuKiyvUod
         YbfgfD3yx2Gvlujd4WavEMgdnPGf3CRbOl/GOdUByXergjHbm2CKXy/4G+ET2Yu6TL90
         8HF2JHDcSRTTiA0zDY/YTpqiwvLNOHe9VHmmEukfYPkuskZQmw/xN5kNLROSI0+lK++J
         7lH9+HTerg9NbvqKOCgvthl3AYlKrjLXkvhk1L8NrdfgN2R/d5V+GXjYZk375EcnjT08
         Xk13L6IGGJQuF5Kjbij29mAEEq/QIsW8MRlJDZPyod6ZaLaJ3vOUow8HAfVfoh/P9o9k
         jyrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=X8/KBJ+9YqAl8pNMOOTdkxSWgS8xSOvcudURdeYs+No=;
        b=unOFtWLyqUUenBjVFBfYK8Sz8j1MVaEHdkSmTJ+Y9jZ4Aysb0XiwoI3yxe/+ILJSiq
         rVbTCNghk7R/OSkBEL0NhAkzDVpM4wonSF2Y58FG6ff/Cx3PjjHwnrwGPikdqhknFo5h
         NnijgFSIlVq+YQv+NQvMBaCNqpiKLAy8Gpc4bFzVLhUwceltYaHBwAp39b8V+mU/+PP/
         hHqLybRevFW6EROoNQezqeZ5OwUk7TGvwOVIEKW5N7j64qgZqD0kQ2FYXJEHBtjIM9+s
         WggAwiyPPyHtAg/8WzlRy/Si+wSR97tUCXbUdAAVMYl9erHf7xObTNuzQoXknxhDBxBm
         yg1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=LJObVJpR;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=X8/KBJ+9YqAl8pNMOOTdkxSWgS8xSOvcudURdeYs+No=;
        b=QVFEjI3E0ePk6OI50Co2HYvQZo/toeLTYBfRivGhkgrulcyvjr+sfjtndIA9BTt6oI
         +Hj49W5PHlNsSrv+TLxK0AjVXOg2rWL1Xc8JvzE0kftN2rRIm5NjdMBciJbRHSudYKWp
         OhEsj31KnKqnPuAmnPDrdCAXj3Jh2wlnE3+yuQlfQ06dn7A5dOqoEXm7+mqmhbkP2P4S
         EAb9GbZhPhFWbCL1WdseqfWATCj4NfChcN7diTg5hYC8px+rFw6EYFi6n4JWG0MuJq4K
         /Wn+NDvtCMtdhQ6LN9fC5wBVrvxp06dTaOVoj2XkIYM+ANEvqf9fvZb6Q/tHkoophAuu
         yMvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=X8/KBJ+9YqAl8pNMOOTdkxSWgS8xSOvcudURdeYs+No=;
        b=Ex7Tl80J6B87W+jbR9o049oMbjdl6DnJ0Os4nqkDJeQcJ3HYTDDou3SbUs76JmwAxX
         yFLOuPLoxsDshD5C6ZbvZIeSsgQuC5QJWUvbR8ZHcYeOyxPOVIHGaB47in3+AhjpHcrF
         FVLKOMONu5HLL1IyPhoGXgkxSImGAEil2PCtWoWhbNejXe52KpGvyHjufwx15nYDTVeh
         zNj74WAhkmKdxrHFz0E48eZxyvgy9d7G+kzBjytwAb7K9/dRyJXPeU570Ejx09iWvNGH
         iCKmOoBVqQOsdc9Nu520Kow8w2obF/jCSQ1IufE49jTfnCz4ebBKMRPCX1P4y/o3w+xt
         zrZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnFkKZCi1ajb50HPw4gcy3iDs6qh1wwB/+A3skbVW6YGx2eTVed
	Oze/lnNVkFhINHlTXD3zRSI=
X-Google-Smtp-Source: AA0mqf6bP8lZhuptbm5pP+47RoHmjGBmnYPv9ZAsbCPw/u9ATDyivX13ezxZQeGIrlhCKGQXqON3bQ==
X-Received: by 2002:adf:e4c3:0:b0:241:e0e1:2006 with SMTP id v3-20020adfe4c3000000b00241e0e12006mr5484201wrm.62.1669206904357;
        Wed, 23 Nov 2022 04:35:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1f9a:b0:225:6559:3374 with SMTP id
 bw26-20020a0560001f9a00b0022565593374ls6389542wrb.2.-pod-prod-gmail; Wed, 23
 Nov 2022 04:35:03 -0800 (PST)
X-Received: by 2002:adf:ea81:0:b0:241:bcc1:7643 with SMTP id s1-20020adfea81000000b00241bcc17643mr5691143wrm.673.1669206903383;
        Wed, 23 Nov 2022 04:35:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669206903; cv=none;
        d=google.com; s=arc-20160816;
        b=R9vpRFQKoLaBEEyBO1JRQI6rFy68Y2YU3UqwMd3Ca5ekGs0mEd996PcD/GaVIY84DA
         7Gl/lKfjgIbZDQK4BaHjpfhpxwaHvso34ZKv8CJe59ZA+SSE0+q8vhlfkRpbKFQH7pOL
         c7UjIxGXYWY5E4KyLWFizg0XOJulDBNOq5TZzBNPWVWQo/peuGyuWqqYcDxu4IScecnj
         eetwRPM+XzTxqRIKGe2I6lVtl2OIDw/LCrU8ormtxmcNfY0hY2eoi61f32B1Ddxo1hoq
         /c6EdqTXeMN1UFFvfk7Ck9egS89vT7eT6mGEO1D/BYwMM16y8PUhGf1AdtmhhSrdbmPf
         SQfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=CJmzxhK0F+EQBwqW32oQ/vEbzIh81a1UF0l3egqzynI=;
        b=K+Ti9eu+4TNJ9eSxtrFmuQPohk6yetuNq1fhA821WFjAab7agka+GtCaGWV2zxVK50
         lgOu1Sd8Yrp2qjAVB+JsXc9YI2JXqegAC/yNBwkInyjSchg8E6klHZJc9WQsse4J7Tjv
         AODyauYknDvqAa1mrzuNoZKfaFqnNNrCY7iJfqYnUsOHBzmEHi3BKjleu/v7TdCbgF25
         WRvxWwCX11rGuPZDtnGNZg5nWvlppXznaNb4IcGhulBqZeiLBpc4OKw9RqThiIo7hb9f
         1KukpCFoKlxvPwbeafogrl8iDfQwcJlIBRWbngBsgsT8cTQ70FlzTWBY7G4/ZrNMECmu
         JFZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=LJObVJpR;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga02.intel.com (mga02.intel.com. [134.134.136.20])
        by gmr-mx.google.com with ESMTPS id l190-20020a1c25c7000000b003c6e63dcbb3si131907wml.1.2022.11.23.04.35.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 23 Nov 2022 04:35:03 -0800 (PST)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) client-ip=134.134.136.20;
X-IronPort-AV: E=McAfee;i="6500,9779,10539"; a="301614981"
X-IronPort-AV: E=Sophos;i="5.96,187,1665471600"; 
   d="scan'208";a="301614981"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by orsmga101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 23 Nov 2022 04:35:01 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10539"; a="705349428"
X-IronPort-AV: E=Sophos;i="5.96,187,1665471600"; 
   d="scan'208";a="705349428"
Received: from feng-clx.sh.intel.com ([10.238.200.228])
  by fmsmga008.fm.intel.com with ESMTP; 23 Nov 2022 04:34:57 -0800
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
Subject: [PATCH v2 -next 1/2] mm/slb: add is_kmalloc_cache() helper function
Date: Wed, 23 Nov 2022 20:31:58 +0800
Message-Id: <20221123123159.2325763-1-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=LJObVJpR;       spf=pass
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

commit 6edf2576a6cc ("mm/slub: enable debugging memory wasting of
kmalloc") introduces 'SLAB_KMALLOC' bit specifying whether a
kmem_cache is a kmalloc cache for slab/slub (slob doesn't have
dedicated kmalloc caches).

Add a helper inline function for other components like kasan to
simplify code.

Signed-off-by: Feng Tang <feng.tang@intel.com>
---
changlog:
  
  since v1:
  * don't use macro for the helper (Andrew Morton)
  * place the inline function in mm/slb.h to solve data structure
    definition issue (Vlastimil Babka)

 mm/slab.h | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/mm/slab.h b/mm/slab.h
index e3b3231af742..0d72fd62751a 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -325,6 +325,14 @@ static inline slab_flags_t kmem_cache_flags(unsigned int object_size,
 }
 #endif
 
+static inline bool is_kmalloc_cache(struct kmem_cache *s)
+{
+#ifndef CONFIG_SLOB
+	return (s->flags & SLAB_KMALLOC);
+#else
+	return false;
+#endif
+}
 
 /* Legal flag mask for kmem_cache_create(), for various configurations */
 #define SLAB_CORE_FLAGS (SLAB_HWCACHE_ALIGN | SLAB_CACHE_DMA | \
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221123123159.2325763-1-feng.tang%40intel.com.
