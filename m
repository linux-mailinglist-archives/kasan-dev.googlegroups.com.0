Return-Path: <kasan-dev+bncBAABB46J3GMAMGQEUD5NH3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2497B5ADA98
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:07:10 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id y14-20020a056402440e00b0044301c7ccd9sf6299930eda.19
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:07:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412019; cv=pass;
        d=google.com; s=arc-20160816;
        b=rX99pnyjoqIcBzshu8Gs93NRwN1IGQ6wiCNASsoRfXXgZym1BnC7DBKfu/fY6GOJvT
         XdsZ91EkdYWSb5QfDKv9fseDUHZ7C/U3hr4osLnSnr7VsdLztI1bmNRCk42qB1mrja4h
         ZB0C+DXC/hOSvEvUI5Bm8DBjkivc8xkWNViARUB7s2khbFIIuoaQXlw0N/HoDg6EZp8r
         g6o9+m4NGTIe40f9NhseAUFz6Zy++pf9sQIoz0WkMq8CZjxV0Cpcw/JM2I/42sYCyerf
         VINxjBzouKyVFT3IuhtA9AfZOvSYfnFljXRGOnJyESjq/AcF1+scEIO88irN5pxFrUEH
         d6SA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4VCpCQjiJK1YgqMLz0fDt/mIjX7tVKMEmgwTSnXvd3w=;
        b=KdNu+MUtjF1wYuaZijPj6UuUJN8dzm4ML/7MwpeFpmVsqQjnjmwNJCzeIZ8Hss2iQ9
         XoEaRrOtCzB3D3hXgBJmFaivnyWM+qrQ+owtRh7RF8ufd8e2uGOmu2/y/RqAUGoEA+t4
         rhRDsaI9Kiqkcj4gAT1QaXB31m6OMhyYnnDp5MKb9PbcahZwUUcidlQSvdmsFs2N9Zj1
         LzayYLY/gjC/gph95ORMtx/OV98Sv0z2p3Ohqdcvh8eve9VWeIA3up5sHWbJDQsIfqv1
         Xk1LSkBBRMBCVKGIVeiB6X9/cCXAcZ8RcAAyHiNCNjHKSe8Fx3YNR/nHZZFAwM7hUb3y
         fjcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=katmbP0r;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=4VCpCQjiJK1YgqMLz0fDt/mIjX7tVKMEmgwTSnXvd3w=;
        b=GQDWarRA9/ELlGYOS9hfiG8kwyKW5zSM98zoeuG2X3xyvXQNSxd7wMbNXxuyu8UNiu
         Z2Uch0BAOwjBSz/n5fjS2MzLZFRBmZ29RItmnnOgNXjS/sVHAigUYQ+75nOZ0nqEctuC
         CJiigfI6AGtCCTBYBF1erpzEs4V/j5XH4eXboVnBGe7DWo9rO4pDVTbsQIC+wc87jGI9
         e7flizilMCg7NQLAhjCy8G2HTplgdhE7Im0X1kg8ukuQAA8+Yzi4kBxCiTiRWTCMEirq
         /mu37+gmEGlFsvDePCkuk50BP1rEYNTMcNC1cZuaHBsDit6BAzhxG/eMQcQJhRBR1I2l
         FqUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=4VCpCQjiJK1YgqMLz0fDt/mIjX7tVKMEmgwTSnXvd3w=;
        b=RCGY0OSjv75UIE61/SKdG+8wFp9dNkEXgIQBV03hxKtYDEm+n4v8VigsYQc9z1ymzo
         hPwmRNVhcNa+Rwjouvzn2OCOkc19mtuX/sW76r5DiRWez/7jgqSJnsiteq0Ip270uCaE
         CCxULBs5dTQ5lvZOh0MjefWtZJwv66y4KtRI/tOriHFb24OsRFTUCT8Gdhfs+uIfons3
         IrR6AcdCOULjdBuotGishIHrpfL9lYDS5BG+ndimOkQmMV/ObzrkeHCP8u1bvUw1azuT
         0tpEGkR0NJe7n/zBOqY4JrK01k6DCZFOrNCSFc+Fyw+BSySdq73m/l7yy1IzGAYm9RK1
         PnSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2AcbSNItmt4Adp4DWiVwxnbvXlai1zBTuAu8/gLgMCCZQbDKb0
	4U5OqKFaKCkOBfoubmY5qAA=
X-Google-Smtp-Source: AA6agR5wVQ7O4eys/sKut6YsfjZZQurzPhMh2bzwpHEMD3/AAeo79tcZRbKcxSmr7yGahHuXNv5huQ==
X-Received: by 2002:a05:6402:34cb:b0:448:9fac:20a0 with SMTP id w11-20020a05640234cb00b004489fac20a0mr29164909edc.160.1662412019871;
        Mon, 05 Sep 2022 14:06:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:26c8:b0:448:77f2:6859 with SMTP id
 x8-20020a05640226c800b0044877f26859ls7997895edd.3.-pod-prod-gmail; Mon, 05
 Sep 2022 14:06:59 -0700 (PDT)
X-Received: by 2002:a05:6402:90e:b0:443:ec4b:2b03 with SMTP id g14-20020a056402090e00b00443ec4b2b03mr43877948edz.71.1662412019288;
        Mon, 05 Sep 2022 14:06:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412019; cv=none;
        d=google.com; s=arc-20160816;
        b=U833uguGsuM6JkShKPHVdqRK4K2tFIz+zMmyaJQVPEJOVCRQqtuYttY0qxyIU/Da6D
         MBbjO02zE2VKbX3ggoT49IX/QD578qb7UckT4xpNIuTuEr/5JOUR9rmkiCujLCOFwIzr
         6cr28JenqE2DfFngG3mBMrLDc2UsK+AsP7h1G3uZGan6FMq73uGvPA7T8C832s53TyKU
         xN/p0IU1eRvB0gqvPUpwv1b9htUvi4tY601cbU19eOMMNgLJvITLLD1fLw/d68xAJWkY
         SKSyiwmDtowwALUQFq3CwVXNwh+SdCqFES2LdPvif3STbwE22xyHM70vsLEtWCtw3dqU
         4t5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=LvbxOQLMAtsJ+FTF8w7d0e45EzA9CvFVJzzzizy4D/I=;
        b=Q93ujjuOtnMZiLiD5VbvDSw8/6+VGc7Le9IFkpzfOaXvZ2XURlj76ox4/d0aWST812
         x0JP01GxUuiybsUlIFU6sxqdc/C3UERkoClyJOB3adaS1f74CO4+B2PZq/nYPMaZJ/ME
         u4/poQqFX8DwrnDvWrtg/RNWVL3ku1HrHXJOrBivERSc25ZY4JmuJYnfVeRpOPgt1tDF
         qP3ULmQf1eLIo6vmDDN5dsKHIkz6+F5CAeh1bRp1JBKArf5W++VETSZTDJJbfzs0VfDx
         9BSpE4yOVL+4T3sSKNHKRwtbTMhT5x4rA5POIFHX8Yvexk+wsMh0KOXNjePxzxJm9gFo
         pm9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=katmbP0r;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id y4-20020aa7ccc4000000b00443fc51752dsi525788edt.0.2022.09.05.14.06.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:06:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 08/34] kasan: introduce kasan_init_object_meta
Date: Mon,  5 Sep 2022 23:05:23 +0200
Message-Id: <47c12938fc7f8105e7aaa592527c0e9d3c81fc37.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=katmbP0r;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Add a kasan_init_object_meta() helper that initializes metadata for a slab
object and use it in the common code.

For now, the implementations of this helper are the same for the Generic
and tag-based modes, but they will diverge later in the series.

This change hides references to alloc_meta from the common code. This is
desired as only the Generic mode will be using per-object metadata after
this series.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c  | 10 +++-------
 mm/kasan/generic.c |  9 +++++++++
 mm/kasan/kasan.h   |  2 ++
 mm/kasan/tags.c    |  9 +++++++++
 4 files changed, 23 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 93e64e1b4413..18107675a7fe 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -313,13 +313,9 @@ static inline u8 assign_tag(struct kmem_cache *cache,
 void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 						const void *object)
 {
-	struct kasan_alloc_meta *alloc_meta;
-
-	if (kasan_stack_collection_enabled()) {
-		alloc_meta = kasan_get_alloc_meta(cache, object);
-		if (alloc_meta)
-			__memset(alloc_meta, 0, sizeof(*alloc_meta));
-	}
+	/* Initialize per-object metadata if it is present. */
+	if (kasan_stack_collection_enabled())
+		kasan_init_object_meta(cache, object);
 
 	/* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
 	object = set_tag(object, assign_tag(cache, object, true));
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index f212b9ae57b5..5462ddbc21e6 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -328,6 +328,15 @@ DEFINE_ASAN_SET_SHADOW(f3);
 DEFINE_ASAN_SET_SHADOW(f5);
 DEFINE_ASAN_SET_SHADOW(f8);
 
+void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (alloc_meta)
+		__memset(alloc_meta, 0, sizeof(*alloc_meta));
+}
+
 static void __kasan_record_aux_stack(void *addr, bool can_alloc)
 {
 	struct slab *slab = kasan_addr_to_slab(addr);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index b65a51349c51..2c8c3cce7bc6 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -279,6 +279,8 @@ void kasan_report_invalid_free(void *object, unsigned long ip, enum kasan_report
 struct page *kasan_addr_to_page(const void *addr);
 struct slab *kasan_addr_to_slab(const void *addr);
 
+void kasan_init_object_meta(struct kmem_cache *cache, const void *object);
+
 depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
 void kasan_set_track(struct kasan_track *track, gfp_t flags);
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 7b1fc8e7c99c..2e200969a4b8 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -17,6 +17,15 @@
 
 #include "kasan.h"
 
+void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (alloc_meta)
+		__memset(alloc_meta, 0, sizeof(*alloc_meta));
+}
+
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 {
 	struct kasan_alloc_meta *alloc_meta;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/47c12938fc7f8105e7aaa592527c0e9d3c81fc37.1662411799.git.andreyknvl%40google.com.
