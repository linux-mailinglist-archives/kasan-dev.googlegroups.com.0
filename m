Return-Path: <kasan-dev+bncBAABB5OJ3GMAMGQEMN6AE2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C5625ADA96
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:07:02 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id qf22-20020a1709077f1600b00741638c5f3csf2666134ejc.23
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:07:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412022; cv=pass;
        d=google.com; s=arc-20160816;
        b=lqAeuMrpOwCXY2RgvzC7F4jthppnibgToaqwLhumKQWmUhVJ+nDzCpFRaKTpteht1s
         fWoYSE+beDQgzvHO3p0EpDlImFKE9gFEjbG7IWoY67SXUAXYo69tKmw9yy7HxtZZInsI
         yY5wvRnji6fr59m3VI3A5JbITfv/S/Z0oezsnF7gF82aKa9fEoylPzCT4J4xKKChzYKu
         Hn3VPpPXTe+jOEvwRJzUCbUdPxbr/x+DatJqZYz5ivH3ehcZnxEyN8EPA4HSpdNiqZ8G
         OnNFvDzjUiwrrP7gsYFEE4RDNW+Qq/n6XXjQnTZENHh9kG0RqmbOgfszY+nUDcz7X7t2
         SpwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=B37cnNk7KTFPlqI1t9dyDqIIHlCBt/LP/l8Dh0vuNoA=;
        b=JgvflqrxfZAUWBnu5IJ+GvurnHVcp72v9zAhvV4WLsLotxvvRL86PCByzb3ZKwoZ7+
         Vj/HBKoUGT8U52QjDz7t6Yj7CQGWH0Qmr852OO79Im32utd35rKWn6+0i9+fC259dftq
         /aMV3SKNFXsq8Pc/vq+puxLq6xVJFFrv4XhZcF7IUjkhF0/6tKozh1+Pc4VjwJRgmHMT
         8meUM/WmXCtK0TgWvVxxuIJZYkFjmlIGokr8c37qQpQmvBjoBRSnBvjjkbUhEtWqGTM2
         9Rs1uWj3U0RNkoZCraGOf/SvIdfKvNlVrGnujn/WiSpMWk5rBB+GALbfajplk3SAVIkG
         SwSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tshzPPvn;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=B37cnNk7KTFPlqI1t9dyDqIIHlCBt/LP/l8Dh0vuNoA=;
        b=IeXPEwSrZFGq0G1CgRj5GqGBpkieVTPrkKTO2PFf7uuRJ9bHjvrs8NfaiIsaHD8KaP
         hPgYAwtIM1ktVRxW55mJoYE4Gi+6Ts+j1aNi2ulzQulNYjHbNk9hbqLkptdt/w4Dldq4
         XfzVDucxGkPYOvAsnnucMe7kOX7o0P/kTNZtM5G5nEFoYnPSkhwmfBJxFGSiSbvAFIdW
         +QIeQpsOtP/XrOfqiFWSxyc6vhL3+MBk133UCzqufeO9Ml4wRzPTX9aSimibmCTs7kPq
         CZyIDfbGZ5OTg0Qf41GkqAoB8iDqJ57HG64XFj0oxqL8jsLIVZ9kf4SFouLNAicUT991
         zFNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=B37cnNk7KTFPlqI1t9dyDqIIHlCBt/LP/l8Dh0vuNoA=;
        b=yjSRv+YZC0ZFJfFHY6SisPGCmhsWdFo2sO1K/zAlCGXZhlU8avkSIR6VPOio9DDA/9
         v55foNA7pB69cioE9iUNa+o0Cypm5wiOEx3cx+10+H0iwMUsHBs35EFlgonONhzr/Wrw
         3IFxtNgDjISXzeVNYn4JXkdl8zyTCmOUfC/ZyVqcg3yBpnuOWkRsqA33UoRCBNngFCAz
         HGd7EufPpgoBjAohsoN0TfCeMEYMvUxoQAaQR87xGHRa4jcWdDeYOtLJC/RPw78+awNG
         w0+xxDLzCTxdtsZsmBU9p2eiJbf/4IDfnZVkA6a7LcT0VAfE+/s05GceJy8M6To2EppS
         GWPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2Hry0p6y4KC/7/fuuWwZtdZoGjR7Z6BWmVsUKr7m9knvMSSi6o
	kNIk5+itUpXNmwUunV/qScU=
X-Google-Smtp-Source: AA6agR4sSh0LrmrmgxL/Jx3iCzVhh00ZWqW6MRvEhf72cm+2lIdZJ+iX5fFsOD63NdWqciHZS6O0UA==
X-Received: by 2002:a05:6402:156:b0:440:b458:93df with SMTP id s22-20020a056402015600b00440b45893dfmr46518939edu.337.1662412022148;
        Mon, 05 Sep 2022 14:07:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3994:b0:726:abf9:5f2e with SMTP id
 h20-20020a170906399400b00726abf95f2els3983396eje.9.-pod-prod-gmail; Mon, 05
 Sep 2022 14:07:01 -0700 (PDT)
X-Received: by 2002:a17:906:974b:b0:733:10e:b940 with SMTP id o11-20020a170906974b00b00733010eb940mr37106554ejy.326.1662412021490;
        Mon, 05 Sep 2022 14:07:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412021; cv=none;
        d=google.com; s=arc-20160816;
        b=PzPXBcn00n7lVoZD5YvkOOcR0YJL7+7pm3jQWekxGz0RC89OiIrl8r1ENyYpcdOjQC
         RwzEf3NA7yF8M5GArbE6I8Ek5pPknFBY3K5tGb1VJhfQHSSKmlTXV02m5o8t/g5r2f0m
         v6hmt+Pn9J9qFCTwwW/ANF+BIWEnDahGJp3JBZFTTcGYD/MrCigbe8bz+2+RiicjJ+Hx
         4FAjKtCDDFamAFkSy07alsYK84EHCgIBzdEKD8gtDzpaMamk0p0DfHOvFzX3dYMW64YE
         juMmn7QBiFTs6mzXsE/m5GGIvQ9ImJG265t15ebCE0qbpiWe2ZOhGJAFGVP9ZHdYzFHV
         qdog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=snUut4Q4q+dUymH54JVYowFIFl//oD93Q0T08XoiwNc=;
        b=DDA+m+r5qn08oZ18dHhrBrv+0kUfbLyuXnR+59NrXSuhUxIwMOL7ROu1UoqVsAdhG0
         w8mWmQnwYt8VKC+PzLgWxwZfwRZtIja3AS85E7PEGUOo84B44Xf6yCZ5isA9q0sdF/h0
         HqvTeY21nDBQxym6uY6U26ks+nbymLixNJwQCkieolaG+NHPZT/JyUFJwPRyFEhaezMx
         O3mN8eZq2SzTBiV1SG0HSBRv7++a81xDmYHPsRorp7KHJE+EGI02GfmPZ9DJFZfoFlrS
         OX/klXePeYBnUogPA1A7DnQmJBTy5Lq+hXbIwxJeVXwvc9DS2KrnRTcJW2ghTvnyeeZz
         07+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tshzPPvn;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id d5-20020aa7d685000000b0044ea33a8ac8si125982edr.2.2022.09.05.14.07.01
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
Subject: [PATCH mm v3 11/34] kasan: introduce kasan_requires_meta
Date: Mon,  5 Sep 2022 23:05:26 +0200
Message-Id: <cf837e9996246aaaeebf704ccf8ec26a34fcf64f.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=tshzPPvn;       spf=pass
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

Add a kasan_requires_meta() helper that indicates whether the enabled
KASAN mode requires per-object metadata and use this helper in the common
code.

Also hide kasan_init_object_meta() under CONFIG_KASAN_GENERIC ifdef check,
as Generic is the only mode that uses per-object metadata.

To allow for a potential future change that makes Generic KASAN support
the kasan.stacktrace command-line parameter, let kasan_requires_meta()
return kasan_stack_collection_enabled() instead of simply returning true.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 13 +++++--------
 mm/kasan/kasan.h  | 33 +++++++++++++++++++++++++++++----
 mm/kasan/tags.c   |  4 ----
 3 files changed, 34 insertions(+), 16 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 19ddc0ed0e7b..d0300954d76b 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -88,13 +88,10 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 }
 #endif /* CONFIG_KASAN_STACK */
 
-/*
- * Only allow cache merging when stack collection is disabled and no metadata
- * is present.
- */
+/* Only allow cache merging when no per-object metadata is present. */
 slab_flags_t __kasan_never_merge(void)
 {
-	if (kasan_stack_collection_enabled())
+	if (kasan_requires_meta())
 		return SLAB_KASAN;
 	return 0;
 }
@@ -152,7 +149,7 @@ void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 	 */
 	*flags |= SLAB_KASAN;
 
-	if (!kasan_stack_collection_enabled())
+	if (!kasan_requires_meta())
 		return;
 
 	ok_size = *size;
@@ -220,7 +217,7 @@ void __kasan_cache_create_kmalloc(struct kmem_cache *cache)
 
 size_t __kasan_metadata_size(struct kmem_cache *cache)
 {
-	if (!kasan_stack_collection_enabled())
+	if (!kasan_requires_meta())
 		return 0;
 	return (cache->kasan_info.alloc_meta_offset ?
 		sizeof(struct kasan_alloc_meta) : 0) +
@@ -295,7 +292,7 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 						const void *object)
 {
 	/* Initialize per-object metadata if it is present. */
-	if (kasan_stack_collection_enabled())
+	if (kasan_requires_meta())
 		kasan_init_object_meta(cache, object);
 
 	/* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index fdd577f3eb9d..1736abd661b6 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -43,7 +43,7 @@ static inline bool kasan_sync_fault_possible(void)
 	return kasan_mode == KASAN_MODE_SYNC || kasan_mode == KASAN_MODE_ASYMM;
 }
 
-#else
+#else /* CONFIG_KASAN_HW_TAGS */
 
 static inline bool kasan_stack_collection_enabled(void)
 {
@@ -60,7 +60,31 @@ static inline bool kasan_sync_fault_possible(void)
 	return true;
 }
 
-#endif
+#endif /* CONFIG_KASAN_HW_TAGS */
+
+#ifdef CONFIG_KASAN_GENERIC
+
+/* Generic KASAN uses per-object metadata to store stack traces. */
+static inline bool kasan_requires_meta(void)
+{
+	/*
+	 * Technically, Generic KASAN always collects stack traces right now.
+	 * However, let's use kasan_stack_collection_enabled() in case the
+	 * kasan.stacktrace command-line argument is changed to affect
+	 * Generic KASAN.
+	 */
+	return kasan_stack_collection_enabled();
+}
+
+#else /* CONFIG_KASAN_GENERIC */
+
+/* Tag-based KASAN modes do not use per-object metadata. */
+static inline bool kasan_requires_meta(void)
+{
+	return false;
+}
+
+#endif /* CONFIG_KASAN_GENERIC */
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
@@ -272,13 +296,14 @@ void kasan_report_invalid_free(void *object, unsigned long ip, enum kasan_report
 struct page *kasan_addr_to_page(const void *addr);
 struct slab *kasan_addr_to_slab(const void *addr);
 
-void kasan_init_object_meta(struct kmem_cache *cache, const void *object);
-
 #ifdef CONFIG_KASAN_GENERIC
+void kasan_init_object_meta(struct kmem_cache *cache, const void *object);
 struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
 						const void *object);
 struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 						const void *object);
+#else
+static inline void kasan_init_object_meta(struct kmem_cache *cache, const void *object) { }
 #endif
 
 depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index f11c89505c77..4f24669085e9 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -17,10 +17,6 @@
 
 #include "kasan.h"
 
-void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
-{
-}
-
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 {
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cf837e9996246aaaeebf704ccf8ec26a34fcf64f.1662411799.git.andreyknvl%40google.com.
