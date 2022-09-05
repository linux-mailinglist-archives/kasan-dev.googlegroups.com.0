Return-Path: <kasan-dev+bncBAABB5OJ3GMAMGQEMN6AE2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 726215ADA95
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:07:02 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id h6-20020ac24d26000000b0049462d32f45sf1969198lfk.4
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:07:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412022; cv=pass;
        d=google.com; s=arc-20160816;
        b=zZq1hVqL7pV4OJ2M4Wga22CV6KtcqSmNnw3jgkqY8XDD8TEUNdk1hNly+SWw4y5dPb
         5buSn5UU0rnysG+IoZ3dqVyjUGyLvcE2DT4/zBBtSstImJObyqPnax3kX5eMI3Ez15hk
         zu6tp25OKDc+RpfC3U2QXV2epSRBhfefWpT3HNA5ELBlpDeiUMrM5YV724mD7zb7v125
         JA4KVhxKgbcFxvRWNU4vPyL4P6QLwesJWMqCmkqfmw3CND54IHkqZuCvAVuKn7yXqJte
         5EFTZ/diHpA8Cz9nNbtFKYggtbbe6UJCC9uqeQ/7ZL8JgORPZ85CSyQr1V4GUl7g2hmr
         0Wpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kQSXMKvkV3OcjFkSUl5euODw6aXKNYK6LYrNoofDbzY=;
        b=YGfo4jP21nSc9NQZDiiDVFDUuQ8m219xEa0WhXYP6F+vfrGT8kgM9p2vodcGYbQ/6M
         VkYleN9Az43AZeNXjt/3bUCdv+2po2Sn22eNwnpQm5JfNEqOrZpXmpPJmxuGoo19oNuO
         Ty0myRBip+czuifcpVZxVUKK0PZKp+Drqz8mHES5B/BV1O3haRLj6EMBogT4FInvokKr
         eCKBmnKzS6xge9vQ44siJu/VCHP2aKfaT+MZ/vFTOPA7WCK/zWLDcutoOsrUUhXFx/ky
         2TTWTLS8+nMo/Bl51aFod+V5OnhOyGruSstmXO8z8lO+z/KAZ4T2mZW5txrM88+rLKBl
         az4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=plz4p63E;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=kQSXMKvkV3OcjFkSUl5euODw6aXKNYK6LYrNoofDbzY=;
        b=Vdb6d0wXT853UUqYqdM2/ggqcEGhJsjZA3URsVoxdwf+KCSFpcPToHbwEWayfVUfkx
         d9tJYuBGd6R8y70p+YyPS7QYyuuP/EglSif09pXOAy7jsDNduW1J7ul4iUC0oLZuS+nt
         t0MxLEMwg0//e/ZaAGmiKkAN6Snws2R7ecPtaOmqegmxWhEuTWCiKyJWTKeQ9/06l3xH
         0Hk2Z6WZM1aFuypQN9A3fN5dYw4neaQcqE6thtf+FcKO8yjw7m6RN9XI9V25dqWiDYMf
         x73N2jdgVvX2uuC3WqP2UplTv8qjmkACNe03UlZqaaY2DKW8RPRVDkFCgsMKkxdoWbV7
         k4pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=kQSXMKvkV3OcjFkSUl5euODw6aXKNYK6LYrNoofDbzY=;
        b=S5HyHrQwqEBX5XIkGt90g42Jyy+biCQshskjTcAtu0mUZLFaHyghhh12aDieHNfb7b
         Opm6EDRovBDOIfTViKwsYFVwPbBIFAnXL5Z/AgO52x7wKyoiEJB/CPa4ZXhitIiCnMe8
         Qo9KPMh6IkldEx1iRBbPqq/b4hyovuWVFJMDmFdF9EtM7RhsyZn3UR6HqMd6iXSJJWuZ
         7++Z9LO0D8TyrseqG03UYXyKeA7AuSzUyFhbGDJAASBYJB3zr7K8I4MqCqH7/IsfWCqf
         zfInSlrFOeh7i5mtdgtNjLyZn3ISO4VsVnR5VNK4s1VAVAu1MCWpquYqDpsfQPTqRSMC
         i0Tw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0oEbA/Xo5ilHC7nuleaImU4hgxcyW3BPPfCFCFqWEhOgt/I6zt
	V38d0kmyzD1SyFBAvt9G1nQ=
X-Google-Smtp-Source: AA6agR4yk8LOejQyklAdZ8Zsrv3O8xucKojJbjkea9oKUSIkjgFwRpcpIeouCDU5V8EBsYvbkt6Oig==
X-Received: by 2002:a2e:b892:0:b0:25f:e0f4:8911 with SMTP id r18-20020a2eb892000000b0025fe0f48911mr14338084ljp.25.1662412021980;
        Mon, 05 Sep 2022 14:07:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3582:b0:494:6c7d:cf65 with SMTP id
 m2-20020a056512358200b004946c7dcf65ls5360043lfr.2.-pod-prod-gmail; Mon, 05
 Sep 2022 14:07:01 -0700 (PDT)
X-Received: by 2002:a05:6512:b24:b0:491:10ba:3283 with SMTP id w36-20020a0565120b2400b0049110ba3283mr15760139lfu.566.1662412021182;
        Mon, 05 Sep 2022 14:07:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412021; cv=none;
        d=google.com; s=arc-20160816;
        b=aHekXekYLpysHY/Ikr85dwDHHLpfNENG3Lt1EEjYNePd/yryDvgwlQFzxdF99aFEVh
         8oF7faPe2QdlDsgnIicBtJGnmt/ddNefEYn0PgxOAjoA2zyQEcfPJWJMj9uEHIon4uXy
         +rKQ7BWSp2igHlRp+V6sdu8uU6FdnP48IZU4M9egzip6NxRKZI/oAngP03SWMQU/FKAf
         EMeT2bmEh/DbpyCsxFUcjou/J+fy2vWRkCt8kkQtedIsFha9WLQ5uTRDhgRdou9giHc4
         2FDmrHKv6bSna5HdccOltDxAEfnqeAtAxxKJvnaPVAyBRFuw0b0lM0Osy8/e6yDS93gV
         X2fQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KZj5Stmnr0/sWtO9VbN14ZS/87FVvMxPXaS8Nqcfb3w=;
        b=VFrgqHdWTt1mr4ns96eNSPly3uudCz1Ld9E9gWlFwQzJ7y2uMooe+1VK63+UTywfXI
         jemEsQFfswyZhRj4wR5YLw2v/6IO2OgKre/amnnwLa6a1XdwmVBEjWTyxGkqZzcXfVIb
         lTDt/Xk+x3CTW4u9ImXdoq/jOGcNZZRQZz+cZxhs+ZciumJYHTIpflHboB2/fVKfbc7O
         RsUmjWmJXe7WW26VKMIA1qMbQywNlvPb7Gm9W6lAiNvROW131YJ2/FrjoFpvujFQWoc5
         OgehFCgWoHQOTUnIMaiyf4G5CtOeVbpwYppV950lkfvzmdsjUNXQnaasqKyuwu7M/B2H
         qm3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=plz4p63E;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id z6-20020a05651c11c600b0026187cf0f12si401673ljo.8.2022.09.05.14.07.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:07:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
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
Subject: [PATCH mm v3 10/34] kasan: move kasan_get_*_meta to generic.c
Date: Mon,  5 Sep 2022 23:05:25 +0200
Message-Id: <ffcfc0ad654d78a2ef4ca054c943ddb4e5ca477b.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=plz4p63E;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Move the implementations of kasan_get_alloc/free_meta() to generic.c,
as the common KASAN code does not use these functions anymore.

Also drop kasan_reset_tag() from the implementation, as the Generic
mode does not tag pointers.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c  | 19 -------------------
 mm/kasan/generic.c | 17 +++++++++++++++++
 mm/kasan/kasan.h   | 14 +++++++-------
 3 files changed, 24 insertions(+), 26 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 18107675a7fe..19ddc0ed0e7b 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -229,25 +229,6 @@ size_t __kasan_metadata_size(struct kmem_cache *cache)
 		 sizeof(struct kasan_free_meta) : 0);
 }
 
-struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
-					      const void *object)
-{
-	if (!cache->kasan_info.alloc_meta_offset)
-		return NULL;
-	return kasan_reset_tag(object) + cache->kasan_info.alloc_meta_offset;
-}
-
-#ifdef CONFIG_KASAN_GENERIC
-struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
-					    const void *object)
-{
-	BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
-	if (cache->kasan_info.free_meta_offset == KASAN_NO_FREE_META)
-		return NULL;
-	return kasan_reset_tag(object) + cache->kasan_info.free_meta_offset;
-}
-#endif
-
 void __kasan_poison_slab(struct slab *slab)
 {
 	struct page *page = slab_page(slab);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 5462ddbc21e6..fa654cb96a0d 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -328,6 +328,23 @@ DEFINE_ASAN_SET_SHADOW(f3);
 DEFINE_ASAN_SET_SHADOW(f5);
 DEFINE_ASAN_SET_SHADOW(f8);
 
+struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
+					      const void *object)
+{
+	if (!cache->kasan_info.alloc_meta_offset)
+		return NULL;
+	return (void *)object + cache->kasan_info.alloc_meta_offset;
+}
+
+struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
+					    const void *object)
+{
+	BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
+	if (cache->kasan_info.free_meta_offset == KASAN_NO_FREE_META)
+		return NULL;
+	return (void *)object + cache->kasan_info.free_meta_offset;
+}
+
 void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
 {
 	struct kasan_alloc_meta *alloc_meta;
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 2c8c3cce7bc6..fdd577f3eb9d 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -209,13 +209,6 @@ struct kunit_kasan_status {
 };
 #endif
 
-struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
-						const void *object);
-#ifdef CONFIG_KASAN_GENERIC
-struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
-						const void *object);
-#endif
-
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
@@ -281,6 +274,13 @@ struct slab *kasan_addr_to_slab(const void *addr);
 
 void kasan_init_object_meta(struct kmem_cache *cache, const void *object);
 
+#ifdef CONFIG_KASAN_GENERIC
+struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
+						const void *object);
+struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
+						const void *object);
+#endif
+
 depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
 void kasan_set_track(struct kasan_track *track, gfp_t flags);
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ffcfc0ad654d78a2ef4ca054c943ddb4e5ca477b.1662411799.git.andreyknvl%40google.com.
