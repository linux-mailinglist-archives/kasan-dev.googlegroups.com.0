Return-Path: <kasan-dev+bncBAABBL7N26LAMGQE6HRUBOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C050578ECE
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:11:28 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id d41-20020a0565123d2900b00489ed34ed26sf4754348lfv.15
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:11:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189487; cv=pass;
        d=google.com; s=arc-20160816;
        b=S22JQZXUs8URN+gluD1402kzhwO/yc2EWMEcabl0p/qi7hCXM3Q6zs0GQaA3yfdkga
         jaNmsoC4KIpnlK4ExT7/g7jKjrJdLGGWMHfi9pFUAGR40uZnvFu3G4xtxFwY/QytCvlh
         /XIs7ciQox1rVJ0GNJFNGCGBCtGOFkUmiwpG9pWCCqxgMvyi4MnqwVVlUBc+TwgwWOb/
         KeiHhMTw1k7aSpgBRVOIRdVJQz+KXC6BGkMPbFnsy0QWK3nxhBCGLHX2l0hm97J/qHIo
         3gcLO2Rb02TFpsGLsWvodw7aFTmZ5GsI+YOOKwT2Yb5EPUAHms/GIiKJWg5znH8vqNT4
         zAzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=yHbMBaM9waT10kTEihu+fgDMrpcOuY0h15Vnifbbz5g=;
        b=uttPKhRfNNGnVndp40DCnR2Gz9XAG/9MDcsZFsXvoNLJv82aj7bUl7sR+gZULD34MU
         UG1FLBBBIHtwHYVDK/2l9+mwtGts12DJKo3KFKzHndzFCbOoyQeCXLZ0gNB/BzugURX5
         aLNeC6Y69xG33wxkC8hLj/Hwzw79QNxrCHFcxO8BH0ieUIURqmKVPUHHKPUeaq+/i/A7
         mKcF/XcSu+xJTDjUQDy4SnMH1z8In00WPsRHsVeYyjQha4/MG134GxxYRhCKHyXc3h75
         7HHFh4RxkJMIiEUY3xnYWOq0borYrq//62khocjxITn9D+y5lY+kceV7G7IhqCwzlL+1
         LaRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ULYDHgqF;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yHbMBaM9waT10kTEihu+fgDMrpcOuY0h15Vnifbbz5g=;
        b=acW8gw05fjmHLuqBI2ddE68znlHABehOBOu6vDN2GbKOG0w5ECXq5PandhLsWOTHgf
         MuUgexlTrp4o2drc3Mmkh61bsehSgFwudbFtw6yK2dubIio8xZi0/Vbe3ToSwrAGKrlw
         PPBfjUnmY4HYpGjqYUcvF+zy/JqdkYq924Li9XYftquFgfA7ONbux/6Od/I19LySOEr9
         k9WqCebxcOhB8yp5jGxeeGtfhuRCB7VL5NIa7o/XiN1Iu947AZI1NquDYv9TwpaQcW43
         TzpUgmz/xaNo1s/2eQ9agr6qT16RrHKGzd3JyZuc7M/Nb0jlOpC7BuQy43S7l1lUt6uk
         96Zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yHbMBaM9waT10kTEihu+fgDMrpcOuY0h15Vnifbbz5g=;
        b=ghej0siuyQ3jTgTNgaWtFcWO2l8G+sgwagfGJLSxAt/9S7EfiuwiKYjParYCO0cK64
         mH/4Ti16gGUJ8ZNzVu2xooCPgkwqAzGWDMwa/wYTS16Wv+m0krg9+DgTqc0uo7q2yMr/
         YemF5T+jzptFrb3Gj1ePP95uoK3o/1bO7INFrUOf2bq7HowbhRvxNBMCDfWR4g2/j4B/
         I6kLqIJR8rFyxe6T9b4j6E9oiwKpgtLMGSR4AdsiNtF8e/zpwC14MVnjyOzYqsVIRNNA
         xKfHJLfuYgmPF+oVBNCQ/xdpGqEksGar4ztdlC0QXOqEau5foNHAw9ql2f8zkUubZHQm
         x9xg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora94qCfOAPlMQkHHJRJNnZmjUt3sanAsgF1qcnwyVuDqIyGCI196
	ZHbV8IW3yvSlQx79M6tsR/c=
X-Google-Smtp-Source: AGRyM1vMaCGqdSDK+Dqz6gh1WClFJYowVUQzQfBNMUXgWJp1xhYfxYLIsxQlNpF3LEyQ+I12vn8x7g==
X-Received: by 2002:a05:6512:130f:b0:47f:bf0b:234 with SMTP id x15-20020a056512130f00b0047fbf0b0234mr16970474lfu.351.1658189487513;
        Mon, 18 Jul 2022 17:11:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f78:0:b0:488:e60f:2057 with SMTP id c24-20020ac25f78000000b00488e60f2057ls16043lfc.2.-pod-prod-gmail;
 Mon, 18 Jul 2022 17:11:26 -0700 (PDT)
X-Received: by 2002:a05:6512:1043:b0:48a:4996:a62c with SMTP id c3-20020a056512104300b0048a4996a62cmr2365468lfb.416.1658189486740;
        Mon, 18 Jul 2022 17:11:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189486; cv=none;
        d=google.com; s=arc-20160816;
        b=VVa+LNbFgbNLjrcSBJuBJoWDpe8vx36JVbBk+tWmpjgWDSjCh+cvMOX88ss6Ak1yvg
         a2l8HgbHKOpn0PiY3UqEE7kji41G0MxilUkV5fnN7VYJCOLOc1+HdLi0daYonRa8VS1H
         fd3N09onL1GGDV7hwinrhgNOm3UY8UdlBk9ggWUlXQzkdLk3tmqFBGSfcO3fCUFP1eSO
         xk2clAyhGSovm7ynroSV6utXcvOaHZWmrOjoEPIScll6JfNjt2FuPwjhTEjPCqsp3y0i
         CJQHKvwvblPUxyCwo0NGRoPWFOuSKscWuyB+oCvkgKhvShmH6+5uhtYG17vVZ927vbab
         2aVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Sn8ckiCeLdpAj/t/GZ1RgeSnIgxHqO3THsvUoIUG2I0=;
        b=qk1vy0UKRyc9VvtqMJWL6/vvZjPymNqDIMfRQJM1wrD2lq2bwUtLI8TN3NTr0WiJwI
         66PEbDtLd9EXNNKXPrkW2Bv6devxoT9dMFUa21Hi2k8wDS/5VGhH2GYwi+9nG6O/gGAn
         xua6ATq35/2n7F6wrJBfPZ/JfFs6/bfvNRTQTGgfgPrLFYSKqEFPZGRHvJXXDxSixdIw
         CvNtvKDsJ5Z6kin37asvNYbt7V/dxA3yxP1eGRTrExQhl54+MDt9Pmpgenh6V2ee3pTq
         Q80WbO2UWoW7UDFuS12T5R2ZA5LaLbOiWbQrYA/jmD6a/g+MGIcmOdrUBaxH1BgGHMj9
         IB/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ULYDHgqF;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id k13-20020ac257cd000000b0048a29c923e9si232449lfo.5.2022.07.18.17.11.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:11:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 10/33] kasan: move kasan_get_*_meta to generic.c
Date: Tue, 19 Jul 2022 02:09:50 +0200
Message-Id: <b3aff7da34bdd71b9acf2ec7c5d90389506931ab.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ULYDHgqF;       spf=pass
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

Move the implementations of kasan_get_alloc/free_meta() to generic.c,
as the common KASAN code does not use these functions anymore.

Also drop kasan_reset_tag() from the implementation, as the Generic
mode does not tag pointers.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c  | 19 -------------------
 mm/kasan/generic.c | 17 +++++++++++++++++
 mm/kasan/kasan.h   | 14 +++++++-------
 3 files changed, 24 insertions(+), 26 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index f57469b6b346..d46bb2b351ff 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -228,25 +228,6 @@ size_t __kasan_metadata_size(struct kmem_cache *cache)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b3aff7da34bdd71b9acf2ec7c5d90389506931ab.1658189199.git.andreyknvl%40google.com.
