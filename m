Return-Path: <kasan-dev+bncBAABBNWK3GMAMGQEJDEOKMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id C52675ADAA1
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:08:06 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id y15-20020a2e7d0f000000b0025ec5be5c22sf3229870ljc.16
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:08:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412086; cv=pass;
        d=google.com; s=arc-20160816;
        b=xzXKqSEuwxydKlPgkzfwT4O8PBx32HcXD9QmjsXCFGs4CAeA6OIfVyrZZwOulIL7UJ
         NQzVfV1cYFoDeIoWgnc7z6q0vpgrbakjwx9cTf1ztM/jAjgkgiDzRnEXqWrHi51appK1
         i29NuEHalyfY/fhlwDA+fE8DV2KjEqX2E3jAIPiw/+q1RtvCQnDwrF3pD+E4Tfwc36YU
         Xla0B1fU5aJi+pDOTRvMVeQapA/JZ3DrDfX6e3cBzTwDXuUI1HX8bluRzTq10/SdcEkZ
         KxReHpUbKu+7Jjl006o9YkWfYoQMQlaIM82ERdxh4xYoMoyL+/BC6mQkOhzg/COuiNjZ
         raTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3q5iNf4GjPCXCh4mV/Rb7ijRSIlmNuEYedqq733G5/8=;
        b=mA3cQAetgq96O7bA2PfbykogBcdQ/FjyvwmNN0s0qyBjL0MwLJIvr/g9tmxAzpijHG
         uz0BwbGpSRLml2QETVv5WGQAVaEQ2NwXQ4LOt8WT+pjH7mbA883JBo1a5naVdxOxJhml
         AbY3GGvjMpTX9zpx64W5SuKk7xOuRDyxSt96qsEcmBGdag3rVtmwJecnEKPeHK1nCkpz
         J44X5K3jGzpxlE+EZmClyY1JSnd6gHlhYtOOIk/9OsIgK3nM1ZHZGT54fmKziMVYIzEH
         XU8GdmE5kNkDVGIcwfIvf/EYW7EGTeG6a7l6Hp2mAAPW0tsF8tUMRnWcABjuzDWg13zB
         j2NQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=RcfZDHJe;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=3q5iNf4GjPCXCh4mV/Rb7ijRSIlmNuEYedqq733G5/8=;
        b=F51jb8P3lzHITDtrSudhnObt7/DEiqCJNeN0+aCJaM2OpmR1KFxSjXQIvxWCx5RFrA
         1pGgXHxlwqlH572x9Yi1N3bWqz9HIK8LArXARMDx7MZPCqMHp/bTcoRpwXmkxkPKHIAH
         ESR9S28falqZSAOIa8u4Y3d5Oz/FpCJMCHm9MG3Odh5JwzJwnyUWuVyqNVWLNq715n8X
         ++VDxwZZ7OKedUCpeDjHVI2k+0KybCbNTnKFRK5jS/lbgJZfVbpgU2nXYE5/gc2feaOo
         VHwNfxwqb5WCQQ8k5JQBqm/AyyOGI+rxyEw0Kt7OsFg1kX2vryM6W2jD03cIwjcxvFiW
         aSDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=3q5iNf4GjPCXCh4mV/Rb7ijRSIlmNuEYedqq733G5/8=;
        b=XSAT/19ePIux33mruxZjk52cSCy8OH+xE6PRlHLsr6lz3xvMCr5Agx5eGZRhOuib8e
         jSirP2mpo77ZtOPNPa68WvwTM8BUmiMTQxhVKNJbsxeDf+coHQSLsMK01W5teR3Oytmv
         Jsx/DDdAqvS/nvhC07lZSeUEh6Eg21OYvUJrNy7Fhdo3rh9BQOlU3nOmflvEqvcDl6rx
         ir9YfclGbkN0K0mloUw+Z9hc54Jw3ww6dNKY4XlkuRS7JSqflX7qH3IXC0tC/LkJ2axh
         HjPIT/FhcaetLzAYp/SFiQCLmGcr3J5ginLk+djRtdCH34NBrySToBxneVK4fkM6lh7y
         l7RA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0EbgM4ESfuWaoM2YlC6Qjt5jLRxzMIpmiafOhcZ2CJl5rAlrVl
	LaAvI4BAdanf26SwwHOQS10=
X-Google-Smtp-Source: AA6agR5jJn0gPgEpJVOrxjMJ4Yws/awu4GIb0X+n9QTTj3+Meb80YBzyySA6ZdY8INK6uEUWTRp/dA==
X-Received: by 2002:ac2:4ac9:0:b0:497:1e56:6415 with SMTP id m9-20020ac24ac9000000b004971e566415mr140700lfp.161.1662412086286;
        Mon, 05 Sep 2022 14:08:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3582:b0:494:6c7d:cf65 with SMTP id
 m2-20020a056512358200b004946c7dcf65ls5360779lfr.2.-pod-prod-gmail; Mon, 05
 Sep 2022 14:08:05 -0700 (PDT)
X-Received: by 2002:a05:6512:3a91:b0:494:6c0b:66c7 with SMTP id q17-20020a0565123a9100b004946c0b66c7mr11952527lfu.481.1662412085572;
        Mon, 05 Sep 2022 14:08:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412085; cv=none;
        d=google.com; s=arc-20160816;
        b=fSWiaT1iARzWIgzvLCk4UFUNsYrA3A26nuS8M1lZP7E9YiYjd+OU8wV3xOeT3qAWN+
         uJF8NpaeAarOFAhXvyY8T8sUqpQDnfKPJHoA2wQxFlFNA8OvgOrl4JrM/ItN51QyAdgR
         h6vEEuV2DpFlad+xFPiM0BzAJ9AwxZfsrlPuMpK+T//TiUUiXgagkiCvHJ/KOReix+Tj
         odBUKaJHcFTI+damHbTBofJjmhnxGPzjK8a9+xTNsNlCKofDiB9OXNnkgZWekffJ/Z3d
         evzbZJaT50ct+3Mp389Hg7eE8kTIAb0U3Vd64KoVnPqZB1kycV6UmOgu8ulEKB3NaG5l
         8+pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nkqQis8OrAGkyhzJVWYxF7zMQuECBh17BdvtUxTmMSg=;
        b=hGQ7S5rxPAnRSu9FU0GsAxjyPQTFPyxRAf+PpBKS5foxXmlC2FY4y85VFchQFWHVD4
         djjonk+enO7LwBLdymYxYv2BtrS3wsTcTEKdl3u8PuMhQG9dvm2JoW7QKuKR/Rgjtg0Z
         p8QpRftCmIac0cvTQUAt+QSRKYd+E7kkZywPeXY4yUlGbAKGtE9yK2Jwxb5UzxiM7lbN
         uZLHVYtTg0p3pDP3fXk1Ev8PfzLPg6WU9f3rgjv6mHrTPuCTlV51dzVw/m8NaXJzOLtW
         JiGbfcpg3+UlvECswQkHpubV7qW0uBz5ttYD31Eq2O9mEDJCK8S3y63KEjmleQbzXyB1
         4b2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=RcfZDHJe;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id s7-20020a2eb8c7000000b00268889719fdsi357502ljp.4.2022.09.05.14.08.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:08:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
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
Subject: [PATCH mm v3 14/34] kasan: only define kasan_metadata_size for Generic mode
Date: Mon,  5 Sep 2022 23:05:29 +0200
Message-Id: <8f81d4938b80446bc72538a08217009f328a3e23.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=RcfZDHJe;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

KASAN provides a helper for calculating the size of per-object metadata
stored in the redzone.

As now only the Generic mode uses per-object metadata, only define
kasan_metadata_size() for this mode.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 17 ++++++++---------
 mm/kasan/common.c     | 11 -----------
 mm/kasan/generic.c    | 11 +++++++++++
 3 files changed, 19 insertions(+), 20 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index b092277bf48d..027df7599573 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -150,14 +150,6 @@ static __always_inline void kasan_cache_create_kmalloc(struct kmem_cache *cache)
 		__kasan_cache_create_kmalloc(cache);
 }
 
-size_t __kasan_metadata_size(struct kmem_cache *cache);
-static __always_inline size_t kasan_metadata_size(struct kmem_cache *cache)
-{
-	if (kasan_enabled())
-		return __kasan_metadata_size(cache);
-	return 0;
-}
-
 void __kasan_poison_slab(struct slab *slab);
 static __always_inline void kasan_poison_slab(struct slab *slab)
 {
@@ -282,7 +274,6 @@ static inline void kasan_cache_create(struct kmem_cache *cache,
 				      unsigned int *size,
 				      slab_flags_t *flags) {}
 static inline void kasan_cache_create_kmalloc(struct kmem_cache *cache) {}
-static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 static inline void kasan_poison_slab(struct slab *slab) {}
 static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
 					void *object) {}
@@ -333,6 +324,8 @@ static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 
 #ifdef CONFIG_KASAN_GENERIC
 
+size_t kasan_metadata_size(struct kmem_cache *cache);
+
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
 void kasan_record_aux_stack(void *ptr);
@@ -340,6 +333,12 @@ void kasan_record_aux_stack_noalloc(void *ptr);
 
 #else /* CONFIG_KASAN_GENERIC */
 
+/* Tag-based KASAN modes do not use per-object metadata. */
+static inline size_t kasan_metadata_size(struct kmem_cache *cache)
+{
+	return 0;
+}
+
 static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
 static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
 static inline void kasan_record_aux_stack(void *ptr) {}
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index b6a74fe5e740..7c79c560315d 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -139,17 +139,6 @@ void __kasan_cache_create_kmalloc(struct kmem_cache *cache)
 	cache->kasan_info.is_kmalloc = true;
 }
 
-size_t __kasan_metadata_size(struct kmem_cache *cache)
-{
-	if (!kasan_requires_meta())
-		return 0;
-	return (cache->kasan_info.alloc_meta_offset ?
-		sizeof(struct kasan_alloc_meta) : 0) +
-		((cache->kasan_info.free_meta_offset &&
-		  cache->kasan_info.free_meta_offset != KASAN_NO_FREE_META) ?
-		 sizeof(struct kasan_free_meta) : 0);
-}
-
 void __kasan_poison_slab(struct slab *slab)
 {
 	struct page *page = slab_page(slab);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 5125fad76f70..806ab92032c3 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -427,6 +427,17 @@ void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
 		__memset(alloc_meta, 0, sizeof(*alloc_meta));
 }
 
+size_t kasan_metadata_size(struct kmem_cache *cache)
+{
+	if (!kasan_requires_meta())
+		return 0;
+	return (cache->kasan_info.alloc_meta_offset ?
+		sizeof(struct kasan_alloc_meta) : 0) +
+		((cache->kasan_info.free_meta_offset &&
+		  cache->kasan_info.free_meta_offset != KASAN_NO_FREE_META) ?
+		 sizeof(struct kasan_free_meta) : 0);
+}
+
 static void __kasan_record_aux_stack(void *addr, bool can_alloc)
 {
 	struct slab *slab = kasan_addr_to_slab(addr);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8f81d4938b80446bc72538a08217009f328a3e23.1662411799.git.andreyknvl%40google.com.
