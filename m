Return-Path: <kasan-dev+bncBDN7L7O25EIBBWMF52NQMGQEAAHOUJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2383663245A
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 14:53:30 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 1-20020a05600c028100b003cf7833293csf9320836wmk.3
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 05:53:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669038809; cv=pass;
        d=google.com; s=arc-20160816;
        b=ME5h4UvKJ1eXwEDPV0UfqtXuAkPaipt2Z72kMWCZB5GZRz7AJBT5vXjtszx6gP8EZu
         dSUFnKfW9hthb+J7D5O9G6NeDMxNzlwhV5wpw055Lb5qBkLOq47zuqVlvInF8DagVIOG
         K1zVd9Zdy60vwn2iDqgvNY/xk3IO2QRBmKrCPDOoR/qunmCRyQ/Ack2MeJI67ZOE66Ny
         1BkOC3DtJdg9d55ihJttFPEuTYnq/YPL09esYSbt5I3iCrfWCapTzett4IVi6OrXL4S6
         Joq13kDXE0W19+bJhFUTpymdo2FOkAkKXVftlbaOFP1/6r+9hpIKtEGBbP/QhgcNPzUu
         Mikw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=PqtaNtF5wn93EYCfkEdPtbc0WD+cn2qU6l1rjs7gS9o=;
        b=gVUzbHfp3v3xSCBtdm6ufo7ZhdMvEkXn8imReURcDSlRLFGjPWi8ra0KLz3TVqsXlD
         YOep+fz2nLJ+VxtHAmIWLJhc67oNlAenSsjvGPH1vZzjb+dGs8W5rUcSA/BEZ2X9vG0H
         aumB95wq+yl0upMHKyQdW7Sp2MuQIPZvVSVzQ2rn+t8m/WskHHh4hBGmIc5sYcM7iqFt
         PWw5fk0+/j62x/pMyVNvU+YAg4gNELj784n896vFd4IioSECr4CSCJQPJzmyXDr2f8ov
         4sMUuvfwf45BcFPb3ysPd1WwiNCUqgInAzuiZLCZCq0tde/k1P3ga6KT3cuEhRPUV+JY
         SMbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=HI8jWgqP;
       spf=pass (google.com: domain of feng.tang@intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=PqtaNtF5wn93EYCfkEdPtbc0WD+cn2qU6l1rjs7gS9o=;
        b=CT4wS8E1H6cIflN7Fx2B5z+hNKvhGmOXL9tpQEe72ZfJuPmdlgvDG6yZsxW0MLpXx8
         4bt5BijjS3YGxL7AmCi+7XfPUeM4MOhANQM2dmoYI8DxgNfTGARdn5Wo6f78A8M36+7y
         qwGXARS7dujRj2OvlnqIzFQ08KfZFVwG9flry0n0p/A5GrxnifE4w29FLqkXGkJYXOSp
         9gFCXqH9Eb+GZK7e8ZWX2ST3bVTEQzTn2M7sSnvGtXTikD3q5yZLX7HYHGpXvsbyZ00M
         VL9vRQzNiZ0SLd/8uxAnyoMr1IuTR7TR+h7XmwJycyeSuG1O7RcEC3TgsJQBG14dsucv
         +hvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=PqtaNtF5wn93EYCfkEdPtbc0WD+cn2qU6l1rjs7gS9o=;
        b=vsgOEXn0+c8crL0So/xVQ2YM7CthsiEuiRt3EAtS66O621nz7P3WH2Q7WdGs0SxeqC
         R619CPKCOzMK+q+jGo7T7e8gr47AbRfK4J6snfQs3z56X4r+zPgqtYKBr5AHIA8s9f/7
         E3tdVcXzMioU0DGunkj2htishFx5ZIcLHFfDMh8gPhYwaZby0BXkZXqG6+zOKweFTWgM
         vd1Qgtv7SFAagQ6SEofsffxNQXxsfpsyZHUDELXl7NoIP5yyPlomKhg/jJ4IZm9XDeP7
         5ny8ZULn/3xbfB+N9LQT5KAR3G9fGHdkwdh1lnY4p7AtcbcaBhHFIbDXa9ggh99zM9jB
         tvsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plYWDJxcrjXgOerarMJmTIATeJb/jjYMw/NpdQye/i63bwkQ3Jy
	c6+QITwQaMh98FPquK+x658=
X-Google-Smtp-Source: AA0mqf4xBGj97DY5ngLwxgGnWj1iVHoJBY06KG5ZCI05IZxBzR0JnOI/bTur+Rw66QS0xc58BT6L4A==
X-Received: by 2002:adf:e8cc:0:b0:236:7a1c:c437 with SMTP id k12-20020adfe8cc000000b002367a1cc437mr10955001wrn.124.1669038809720;
        Mon, 21 Nov 2022 05:53:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5247:0:b0:236:8fa4:71d1 with SMTP id k7-20020a5d5247000000b002368fa471d1ls1636701wrc.1.-pod-prod-gmail;
 Mon, 21 Nov 2022 05:53:28 -0800 (PST)
X-Received: by 2002:a5d:4577:0:b0:241:c9fc:71bc with SMTP id a23-20020a5d4577000000b00241c9fc71bcmr5382956wrc.317.1669038808737;
        Mon, 21 Nov 2022 05:53:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669038808; cv=none;
        d=google.com; s=arc-20160816;
        b=gnZFU0wBJchO2qX0xwU+g0iPU1uOZs31i2JwxN0PfxqVz9UleonM3MSw/pGnj/Z2pJ
         ovlSEh5wCFHyHm1gUaNk2LeNtcI81y7FoxSpthtnkeKyPK+N8T8XsQIRz6uPGPqkd0Hq
         giwIwtVXX7awtuF1B0vE2bAyY6ocY/I+jr66tyma3/TVpM6TgbjinMM/oId6WYVK+vKo
         QPprTaTfNf+GUyrcn6sgrNJfJ9jYW1A8j/DAoUGuQ7a8ZuPpShhw6ePXDP2TiYxVnJLi
         IpLw3/mDryixmTASSLrIzkF/unmLkvoLckROoOGaBwuBKcTTq5mReoIowMK0PFzTwdbL
         mxiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=UICwHwUy/rM4e5XTjGUHW4OK+5ASBUwTNuClQeGn99A=;
        b=OP3r07PqL++SJaaLpSR/8nw32G9Nc6y0HzlUb0426G58VFsYuQCT68vTOFX+xAryXM
         PWXJ6iEqun45RGMvRJhd+sKMez0yn4fGQbw41qG1unMnPOcdLoWUqBlQieP/IHjsAtct
         HI9MA6/9F7863rwKZ9m+8514B5UGvcEJNUK+9TgI8Xl0GqAbTCdn7kKEaYCrJIlHY4Mn
         EXyyGpKjCAS71Jed791gZmI5RbDpNZy5Rsd9SS/GnwBrdjmDEHh+Xmi+sGGQeWTTyYvQ
         GI1WvY0cboru7cvJxZMJmLrtwXXOZOLAWonAvoJzm8GFewMwopMBo0Ic4qofNKl8BHGu
         xhoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=HI8jWgqP;
       spf=pass (google.com: domain of feng.tang@intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga17.intel.com (mga17.intel.com. [192.55.52.151])
        by gmr-mx.google.com with ESMTPS id bt2-20020a056000080200b002416691399csi383477wrb.4.2022.11.21.05.53.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Nov 2022 05:53:28 -0800 (PST)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.151 as permitted sender) client-ip=192.55.52.151;
X-IronPort-AV: E=McAfee;i="6500,9779,10537"; a="293949380"
X-IronPort-AV: E=Sophos;i="5.96,181,1665471600"; 
   d="scan'208";a="293949380"
Received: from fmsmga006.fm.intel.com ([10.253.24.20])
  by fmsmga107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Nov 2022 05:53:26 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10537"; a="886125081"
X-IronPort-AV: E=Sophos;i="5.96,181,1665471600"; 
   d="scan'208";a="886125081"
Received: from feng-clx.sh.intel.com ([10.238.200.228])
  by fmsmga006.fm.intel.com with ESMTP; 21 Nov 2022 05:53:22 -0800
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
Subject: [PATCH -next 1/2] mm/slab: add is_kmalloc_cache() helper macro
Date: Mon, 21 Nov 2022 21:50:23 +0800
Message-Id: <20221121135024.1655240-1-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=HI8jWgqP;       spf=pass
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

commit 6edf2576a6cc ("mm/slub: enable debugging memory wasting of
kmalloc") introduces 'SLAB_KMALLOC' bit specifying whether a
kmem_cache is a kmalloc cache for slab/slub (slob doesn't have
dedicated kmalloc caches).

Add a helper macro for other components like kasan to simplify code.

Signed-off-by: Feng Tang <feng.tang@intel.com>
---
 include/linux/slab.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index 1c670c16c737..ee6499088ad3 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -758,6 +758,12 @@ extern void kvfree_sensitive(const void *addr, size_t len);
 
 unsigned int kmem_cache_size(struct kmem_cache *s);
 
+#ifndef CONFIG_SLOB
+#define is_kmalloc_cache(s) ((s)->flags & SLAB_KMALLOC)
+#else
+#define is_kmalloc_cache(s) (false)
+#endif
+
 /**
  * kmalloc_size_roundup - Report allocation bucket size for the given size
  *
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221121135024.1655240-1-feng.tang%40intel.com.
