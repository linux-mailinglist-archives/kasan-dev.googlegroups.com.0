Return-Path: <kasan-dev+bncBAABBNWK3GMAMGQEJDEOKMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4174A5ADAA2
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:08:07 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id j36-20020a05600c1c2400b003a540d88677sf5815864wms.1
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:08:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412087; cv=pass;
        d=google.com; s=arc-20160816;
        b=QAzJ/ciaeGgcz78qxo0G9WHI8LxH7Z8eGFV9fhEgHyXaU4hWx8N0x1GPl0npR+C+Hf
         ENjkgh5Eiwgx19Y1y3klXbODRE6xjmp/IUe6dnOZ8VZ64x2LOVA4oDkD+6ySXvOsVQyr
         5AI+JSgI8Ll3mzJUHcC2w18iEVCyDuhtJe0MI2V9MWd/GTEFHQCgvZPbCwde3VIH9AoG
         J+i8ckpp4hbL4GClgjjxZMlAvh+kFnGZFTn7lPTIqp4RKEutq9PXCX1vXj2G5MoPLESC
         Ur5vBW5lG/0Q043GYc30OpjrdQlO90hNNF/F5VrF0n6WGReJxV1f3ewC2mr760cVrMVL
         22bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Bm4wfXtSvjHw3P0sTMhTUfj3ZTcVho6wIKu/7kfrUAg=;
        b=RceVyUq+Jp0y+BcmhHLphN6S1JPwKj48+ZWVtM3tBDru0xx28DZPmSyACcKaAhqZqu
         Bjjeto1pjJfwu3MH6DklJn6QkKbASwaX0Q4huIu6IZ0H8gSWPHHlx1+8J4AHwYiwa3b+
         kgvaUS6UBL5buyB2/kPH559uiQbDS4IwQa/Vk3giTtI56EhkiQWNNKGTnPdw7dM+W2/8
         rQYLXYeKXwBURu+gdLblM+ecMrz6gut7LV2OCubKDNIm1Gg0112k56ja1nTKr865cP/k
         hOjdowrTT7SiBfXGGj64FAtrGYCVQrwG8oxuN+skFTbk1kOGUZkTS8ka7aIro2oirz9S
         8deQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=boGTz93I;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=Bm4wfXtSvjHw3P0sTMhTUfj3ZTcVho6wIKu/7kfrUAg=;
        b=aBpCiAh5tsJy0gXNk9lJFIsAQBB/fD46v0BXl31O6D0gL7+TlS/fsCMp0cFpC31omg
         36c8Eaw8/gIUoM9rjsq5gMDHYKYROCoGCj1VgmiCRQhiuBBzXYWG+poykKGn9gLXBpio
         OmV40oqu3XE0YMeTQ9I7ZilCoAADit5eHIFnsTcJLJkIzfN8m5hKg9sPrlc504vK9cNK
         MKsDRzh+Vp8AFi3DQUzqZWSZJ/hPLO1PMGQOs8Ejo66rp0gXEOBRnj+OyJZKglGHrhP9
         +TmxP9XxrEhR1szsZGAMYQXVaSCKGf9ncDFfvkehRc0r1flKljKj8gX+i9tmn05AE8Nx
         dIkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=Bm4wfXtSvjHw3P0sTMhTUfj3ZTcVho6wIKu/7kfrUAg=;
        b=jUO5j0qLeLtpcLVA5OZeE/WThVVxDO6leZdPqT7wgjWDLC9+IIaAMdl3v+FR8vmjMU
         Yg3PK24XQJqnxx0sL6r9ExMcdQE0U78Wg4SqS2txc3PcRu27dnSW2eQpRvh5rulKH+XP
         /vagmK3/vMqCHxFlwCmrpjEmwK5pWaIRFttH1dVx6ESkJ248eCfbZyyk0JWfZ3bt2MCo
         kQSvXSQpLTJjTUnsV0o8K9nhQa79Gaa4+Jq/TvsIbpkZynEoSkD9aNRUIm50V1aZAAYS
         agIoDTduldcUGq0eSj53nmSAWPSSfeQ6MfSV2Fp307OS8l4BuUnCxWXvavS5QK7Eo55D
         rU9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3WsIw8PbcAn33LtyrCbag/Hx/zFCp6T/YK2TJPWn8Gqh9dDC0p
	2o0JRwZ+COlHELqQeZTBMNY=
X-Google-Smtp-Source: AA6agR5eanctcJi63PGrnfRwTsdVkNGvAmJW2NUa58oUQzSvHKq7oBlbSFm18px2wJ1GjYkO++LtvA==
X-Received: by 2002:a05:6000:1d91:b0:225:71d6:3fa5 with SMTP id bk17-20020a0560001d9100b0022571d63fa5mr24961652wrb.14.1662412086905;
        Mon, 05 Sep 2022 14:08:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c4c5:0:b0:3a5:24fe:28ff with SMTP id g5-20020a7bc4c5000000b003a524fe28ffls4172308wmk.0.-pod-control-gmail;
 Mon, 05 Sep 2022 14:08:06 -0700 (PDT)
X-Received: by 2002:a7b:ce91:0:b0:3a7:b67c:888f with SMTP id q17-20020a7bce91000000b003a7b67c888fmr12030897wmj.187.1662412086141;
        Mon, 05 Sep 2022 14:08:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412086; cv=none;
        d=google.com; s=arc-20160816;
        b=JUMbLFl5jW0uMFNZke68Sy61MvvJIfJBbwSG5cedyVDTr14XuJss9+oDJvACN3l9oZ
         X7qZkUcvb1oZxWEk2kdsZCWKZyUUETj1BPST+JTHrSS6Wxlr93bgAB9BqovdrLF3BCRZ
         ZhEOW+yaD0lT4AqSTuIrd5v1IywmfC/Y8LUxh5TGBWK9zKpnJ8J/K76ogYkYxw4DZ+Cn
         1Uez2w6QcILCQVAeX+Y78lvAySk8QWlForpTnN713T2CTyYyO3v8HtspUo2qiQh0RLcP
         14GhPSNiHxxfJvvyC6Ahw+lgblqdnWSfh8I6wuznXU7UQcMRbySuZQZppWiHeXW0gtzI
         eD/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=seyO/qcSJYVowkIOZCiExEBVBp5SOVzPECSR5PeA5GE=;
        b=OVRycYOSLYN47gA1TDjIoth57G9sXWQbBjfcwnQLLbZlKoreepSonLXfUmlEWgNtgy
         dTxYhuycrNh3ScJ5R5Ph2eg99i6to+kKmAd+jSW1odzuCBxmM2/47PZaWyiSvr0YIWcm
         xn5kx/EGKGxB75ipykpGTeig4SPhKMU+RdKOIBv21LfCgLXg0/EWEwBIgJdNlPhRH6Si
         1RQ7HW2Esrss56WGeeUt84bFWdBY49cXK4Usbeiqaf3u0siFUxrCX8d4VJZWmjyQxM/M
         xp5fcfZdal/5zxiooQSktwDnfO1KBzF7GxVXydRTULywvQTiOBkoil3Vn+1JAZe+jcDu
         5mFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=boGTz93I;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id ck14-20020a5d5e8e000000b00228d6a43531si62090wrb.1.2022.09.05.14.08.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:08:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
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
Subject: [PATCH mm v3 15/34] kasan: only define kasan_never_merge for Generic mode
Date: Mon,  5 Sep 2022 23:05:30 +0200
Message-Id: <81ed01f29ff3443580b7e2fe362a8b47b1e8006d.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=boGTz93I;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
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

KASAN prevents merging of slab caches whose objects have per-object
metadata stored in redzones.

As now only the Generic mode uses per-object metadata, define
kasan_never_merge() only for this mode.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 18 ++++++------------
 mm/kasan/common.c     |  8 --------
 mm/kasan/generic.c    |  8 ++++++++
 3 files changed, 14 insertions(+), 20 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 027df7599573..9743d4b3a918 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -103,14 +103,6 @@ struct kasan_cache {
 	bool is_kmalloc;
 };
 
-slab_flags_t __kasan_never_merge(void);
-static __always_inline slab_flags_t kasan_never_merge(void)
-{
-	if (kasan_enabled())
-		return __kasan_never_merge();
-	return 0;
-}
-
 void __kasan_unpoison_range(const void *addr, size_t size);
 static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
 {
@@ -261,10 +253,6 @@ static __always_inline bool kasan_check_byte(const void *addr)
 
 #else /* CONFIG_KASAN */
 
-static inline slab_flags_t kasan_never_merge(void)
-{
-	return 0;
-}
 static inline void kasan_unpoison_range(const void *address, size_t size) {}
 static inline void kasan_poison_pages(struct page *page, unsigned int order,
 				      bool init) {}
@@ -325,6 +313,7 @@ static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 #ifdef CONFIG_KASAN_GENERIC
 
 size_t kasan_metadata_size(struct kmem_cache *cache);
+slab_flags_t kasan_never_merge(void);
 
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
@@ -338,6 +327,11 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache)
 {
 	return 0;
 }
+/* And thus nothing prevents cache merging. */
+static inline slab_flags_t kasan_never_merge(void)
+{
+	return 0;
+}
 
 static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
 static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 7c79c560315d..c2690e938030 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -88,14 +88,6 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 }
 #endif /* CONFIG_KASAN_STACK */
 
-/* Only allow cache merging when no per-object metadata is present. */
-slab_flags_t __kasan_never_merge(void)
-{
-	if (kasan_requires_meta())
-		return SLAB_KASAN;
-	return 0;
-}
-
 void __kasan_unpoison_pages(struct page *page, unsigned int order, bool init)
 {
 	u8 tag;
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 806ab92032c3..25333bf3c99f 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -328,6 +328,14 @@ DEFINE_ASAN_SET_SHADOW(f3);
 DEFINE_ASAN_SET_SHADOW(f5);
 DEFINE_ASAN_SET_SHADOW(f8);
 
+/* Only allow cache merging when no per-object metadata is present. */
+slab_flags_t kasan_never_merge(void)
+{
+	if (!kasan_requires_meta())
+		return 0;
+	return SLAB_KASAN;
+}
+
 /*
  * Adaptive redzone policy taken from the userspace AddressSanitizer runtime.
  * For larger allocations larger redzones are used.
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/81ed01f29ff3443580b7e2fe362a8b47b1e8006d.1662411799.git.andreyknvl%40google.com.
