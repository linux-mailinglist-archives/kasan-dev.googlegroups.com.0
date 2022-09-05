Return-Path: <kasan-dev+bncBAABBNGJ3GMAMGQEKQ26TAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 62F695ADA8A
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:05:57 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id dz16-20020a0564021d5000b004489f04cc2csf6329810edb.10
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:05:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662411957; cv=pass;
        d=google.com; s=arc-20160816;
        b=tvs88MFOTHRELENX1oG+JYU6U4QpsWfgBbAqjz1fTwllLiS9mogscnRPPG9lJVUnJw
         1pQxghUl965WL1ostMWyYu3v2kgATpKVvd/WURK4EyffAqUvjzUPFgOu0WiMjx8RXH5H
         684Z21MBMQ7K2Ivlv7Wx7ZHBKlMAnfWKliZOk0jwWwqPNSC79QQRrXPfQKMRS9/dz+Cf
         ims0Sh4ybzExeyHej0esAkJqGmy2ZAlNf+jgGJqrLIQ3HXwxDsAv4ocy6Mzeev3Rx2x3
         EQlXCE/NQorQ3JJtxMgNS1BoLCBZPfqUegydjgLVtNQYqjEdaG2dzKOWlnZd1EIhQXVU
         3RJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6xyXy4agqhABg7ZF2KwF6/UsxXs4IE3AfHoo9UxJ1h4=;
        b=RsMvhUgMhJSOTWWy017K4ZrTmtNTW8ybCmmgCHXm3J/M7AnQJFEKt4knsnCkopVn6q
         yhk2zkkCMWa5SiK3+GcWfzBsovz4Gu6PnAZnnAe0L1+8IjLGgvyCfzt8IYCkHMHLqktU
         4aTNqCOFRNPRYpWxtx4cY8gSMrwGdrjsdawzD5la8GUByqUin3+GK73UgAzzoSv/wqkJ
         43psc8R1Co3cRIQneuuvA6rpfe7ua7EOldk+dXrq41PiQ5L79wpIYbG2l1bxd31jgeK2
         vpYdQ6vkHRDg5PyRx8cwOfljAGRZgpI8xJMafsec4wgceQjXmXffEo4xBc5NhGPgeNVv
         lcEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=UiCs9fbm;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=6xyXy4agqhABg7ZF2KwF6/UsxXs4IE3AfHoo9UxJ1h4=;
        b=QgJ5i0LilioeCrGFIPv56mKdZEIVMDYzZrpVBQxGQQYBOzWUykzH+8U9XX2D+5Icyq
         FHugsd+b7I7HL2RJB1KLMOiLTof0RXGEWaLfFO3rGZYPN9WkCxYYH4uNIo6EmLv+8gTM
         RI0os8YTSKa7H+zM8Z2QpjNw5r1y0tdBxPn+qif9L52mfLOSf9/LwcW0WuKzMM8IHQx6
         X/KGASg0BN4Nd97oT4ftZAJCdz2Jsr0ReygIZlJCdlk8s5rr46DCZlkN8zwgmPWM/wst
         0D1IaAz4BjYSUOlTZTsPd8j6lqKh2jQ1eHgTfUWwiWpuOu9BhAJVQs8df391AWuSLIKr
         dLrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=6xyXy4agqhABg7ZF2KwF6/UsxXs4IE3AfHoo9UxJ1h4=;
        b=i5ED5YfnqJLu2ZxrvCASCbzOan6NZCU6WvjI6vczOn8RGdpWGYdqgre+5NPP58GQh5
         MeI6PVIHhr/pZlRhsRVu0kFY14qytzoqL7c2tWOOzP4YO1DxtVOsmJuU9yIiT3+EJXV+
         zIFmK2G+7aU8We3RR5T0h+fRrUYXIZDP1UEa206hMRNPNVojEr3YK+rfMiAJaM2l+O5e
         4GBFbfvGmfWy8gp6SYdnwiTqNGi7FRx5UCMszHXsr/UeEZBvKBdyTniApcr4wlkBX0OH
         dmMb55X7jHBULwLrTjt5CAhJOiu9CIh7r3Imxp5BNMm6eYT+kWE6R6zHffXN8rBed/yE
         DrvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0KfvNdHKoIy/ew57oF+6wbZjflir85Bp1pFXw66+AOHn/C/bmV
	G+hbD4cW6/VKvqfFgc/UBEw=
X-Google-Smtp-Source: AA6agR6Yg10lJWilhkVNPZlatgUC1RiWNxH6q02Bv2sn90XdfgQl4TA+ossVI4jn1rRbKuFS9fIGhA==
X-Received: by 2002:a17:907:d08:b0:72f:b107:c07a with SMTP id gn8-20020a1709070d0800b0072fb107c07amr37270130ejc.340.1662411957041;
        Mon, 05 Sep 2022 14:05:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:98f3:b0:73d:6af2:48f4 with SMTP id
 ke19-20020a17090798f300b0073d6af248f4ls3988167ejc.3.-pod-prod-gmail; Mon, 05
 Sep 2022 14:05:56 -0700 (PDT)
X-Received: by 2002:a17:907:7fa5:b0:730:5d54:4c24 with SMTP id qk37-20020a1709077fa500b007305d544c24mr37316832ejc.641.1662411956289;
        Mon, 05 Sep 2022 14:05:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662411956; cv=none;
        d=google.com; s=arc-20160816;
        b=qbpBtnsWr9Q/GadM7JLqJ9c3EKX49SjKwMC1JyFB4HvopqQWe8rgpzYvZMCksNfsTI
         ZHGg5Je19fVIhEfu8NZ7kw7wR4z2EJ+QHTgL+uLfP2FleqS15j44alYBD9BnbMNyChpo
         D1mFRskcAaxzlBFbZzob9+G4j3BuCI/pu5ecXyBkfRS11k8G6xLmc3E9wR3PkkBd4wPz
         xqt087Z4Ldc+JDhzNJ3plZ48Pq77lJbe4Iz3XmZYvflvZSRM4GZTjsY+d9rI1GVXaN0Q
         xsuOKVNcUtaKf33p2gsYUGv9Hdefl9MaMkevcQZSdyV4uGoAj7L7ViV/QqwbLc+lpE3X
         L5IQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Cn0WG5cs8BZzzIvc+ar694tNHCn0gGHMmu5NddSKicA=;
        b=rqAY7J5dSq8PgntgqmKQyWhsgBrYr2Y5ybNW3oLavgz817wB+bAGlIvCC3GetIxCXQ
         6bziQ8ET1Y3OdpBfLANPrRbp4/RjiUl5dKx3e0Ax+X1+CZIFBActcb4O1qOBEk3SL9Dm
         zSN+Ol/cCox7PcSOljPDuyF1m0K50Azx5y3BaUk4q1EbAD8t/uV5IAwlTKo3I+3bFfAb
         7mpdu2ZYKzG0z626uZrSwS/qK83CnJC14OjAnz6uP2thqvxML62KfNYZZZFLw34M0ZGp
         stP/m1dL03MqUlp2DNkzsbjuszevpu7Eeca8D9vyo2jerLYqo2j8WfQqkdRWXH7awmF7
         oGng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=UiCs9fbm;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id og36-20020a1709071de400b007415240d93dsi448742ejc.2.2022.09.05.14.05.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:05:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
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
Subject: [PATCH mm v3 04/34] kasan: split save_alloc_info implementations
Date: Mon,  5 Sep 2022 23:05:19 +0200
Message-Id: <77f1a078489c1e859aedb5403f772e5e1f7410a0.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=UiCs9fbm;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Provide standalone implementations of save_alloc_info() for the Generic
and tag-based modes.

For now, the implementations are the same, but they will diverge later
in the series.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c  | 13 ++-----------
 mm/kasan/generic.c |  9 +++++++++
 mm/kasan/kasan.h   |  1 +
 mm/kasan/tags.c    |  9 +++++++++
 4 files changed, 21 insertions(+), 11 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6a75237ed308..93e64e1b4413 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -424,15 +424,6 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
 	}
 }
 
-static void save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
-{
-	struct kasan_alloc_meta *alloc_meta;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (alloc_meta)
-		kasan_set_track(&alloc_meta->alloc_track, flags);
-}
-
 void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 					void *object, gfp_t flags, bool init)
 {
@@ -463,7 +454,7 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 
 	/* Save alloc info (if possible) for non-kmalloc() allocations. */
 	if (kasan_stack_collection_enabled() && !cache->kasan_info.is_kmalloc)
-		save_alloc_info(cache, (void *)object, flags);
+		kasan_save_alloc_info(cache, (void *)object, flags);
 
 	return tagged_object;
 }
@@ -509,7 +500,7 @@ static inline void *____kasan_kmalloc(struct kmem_cache *cache,
 	 * This also rewrites the alloc info when called from kasan_krealloc().
 	 */
 	if (kasan_stack_collection_enabled() && cache->kasan_info.is_kmalloc)
-		save_alloc_info(cache, (void *)object, flags);
+		kasan_save_alloc_info(cache, (void *)object, flags);
 
 	/* Keep the tag that was set by kasan_slab_alloc(). */
 	return (void *)object;
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 03a3770cfeae..98c451a3b01f 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -358,6 +358,15 @@ void kasan_record_aux_stack_noalloc(void *addr)
 	return __kasan_record_aux_stack(addr, false);
 }
 
+void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (alloc_meta)
+		kasan_set_track(&alloc_meta->alloc_track, flags);
+}
+
 void kasan_save_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index bf16a74dc027..d401fb770f67 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -285,6 +285,7 @@ struct slab *kasan_addr_to_slab(const void *addr);
 
 depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
 void kasan_set_track(struct kasan_track *track, gfp_t flags);
+void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
 void kasan_save_free_info(struct kmem_cache *cache, void *object, u8 tag);
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 				void *object, u8 tag);
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index b453a353bc86..1ba3c8399f72 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -17,6 +17,15 @@
 
 #include "kasan.h"
 
+void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (alloc_meta)
+		kasan_set_track(&alloc_meta->alloc_track, flags);
+}
+
 void kasan_save_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/77f1a078489c1e859aedb5403f772e5e1f7410a0.1662411799.git.andreyknvl%40google.com.
