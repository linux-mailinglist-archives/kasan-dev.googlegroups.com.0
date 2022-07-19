Return-Path: <kasan-dev+bncBAABB4HN26LAMGQECZDZPUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 99722578EDB
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:12:32 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 23-20020a05600c229700b003a2eda0c59csf4842759wmf.7
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:12:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189552; cv=pass;
        d=google.com; s=arc-20160816;
        b=icF0G/Rfl/1wbH7xaOE8o8TBdY5CH89x/aZ1KKBXusAvKa4M0zT6E2vdYmbX3yKYmc
         D4ST6ZPBbaSRCLMvJxBnyhy/1kHWqLJtcwZq3uTJSVWnMvBdkOk+haHnL/vzbagTPZ5j
         N4HtlKG2mpgi2HHIOClUHxHH+gTzjpSFX2VEPxvkb4LJCw1g2k6BrsT6u/qkhjL7OarZ
         X+m0za7F8Y8tp39R/cG9XcQgPwAvBmWSL28A1RHe2MiQy+7RzhsXFFkfqdj+6TGp3/RE
         tBRa0PMQlEmjX44g2/V+G+zU0FdeS0o3uItHFegv6zCFQCi1aCi3PAM1j2xitqbTpppw
         sqLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DXAbmvgvBhT6CIFPwy2AU532I3K2NY2/h1CVJUm7FU8=;
        b=CVB0bOmJerlWD6HeXZbNin6hR/tAq4DAiWa5+AM0eY/nE44Z+B7muKSGUKs/VIsowJ
         263y/P2yRM0LYqGHNpu5UNR+ZU6tkT62MQg3ioyZ7w2UiBDG4m5rZuy7Gtbe5EreWVMB
         FhCr4LBgHIBb/EgTSpxzXZM+rInRmbfjelEbeRs2GLBE8dw8zqr2kSt0gBhufFZDG6/K
         GnuSvpVQ54vGYqC0yhT9N6CitBY7AtHZkfv37VrwkR+uH18PGLCYLaIOmS43e1kyB/Dc
         5FHBlWqerRSskWAf5Sic8qS4LHxka7zTccDetpOgtnjygYN0eS0W9cFnHEhDBmfEBU0u
         GG8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="w/ZmYnkg";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DXAbmvgvBhT6CIFPwy2AU532I3K2NY2/h1CVJUm7FU8=;
        b=Js7nLfcV030D1UlrdQ9oqX+uufj1lN7LNjKVa9z9R7RGk2Ut5qLVZHXhaXyQOMIg2g
         q+mP9qRq76L4Hn+2rGWdpscWdixQAqRHmRj2CoUoDntO8ZSh9TxM/TXvYJ0kXQzZ7Rxw
         EQ00bfWtnIzfxu2Qs9GeTYNSBwCdSvPpIDbYgseZdLFDg2EMo/fxSM82R+7qP9whHGGF
         Fd3JCXI+lfVwRXNdLlwfis6GAg4GHtlCu2j8Qlhf9Cb0M20MSR/NZPNDhcvQJ/WnOJdf
         z1ABMMgTUmZxC26Ydsxwq/JSmSGowy7xuQAActXxwdGwjum0jfFHp6tzLchuw/MM2jsS
         IF7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DXAbmvgvBhT6CIFPwy2AU532I3K2NY2/h1CVJUm7FU8=;
        b=Xl5ZLVV8jdzAwK8USHUWe9ylfStH531MRhQcChDJnOvnweqWfW8tWfOL58k9AWnb+P
         u3w1j34PGlRLEpT8JCXRB0U4VTkED2b11FTTHUW6lzu5Auudmb/Ek8Z6HHKGDsvDHzs4
         oEoekIhypZ3XnfOHmIU44VttoG4vlrPwWZLaQZi0O1QPrIvSdJX150vsw8VHiwxwkrcF
         3letptlzT8MDqXWver8INFy/3jXlP0Mxfkfifqdvv4hRP0q3zXsXVa5vdOv19zprDSMe
         /l6bcXosfygyYryObEzKnZqlR+Go1vS2eGtPD3X1GCT6Eg7tPIzGGvLM928GKAZOyJ4P
         oXKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8tSmjmeqMFm2uyNmhF+FwgrE5131DynRsGMQD6viPXA5qW1O4b
	MXJ/AekRiaQfJjkPttFY1W8=
X-Google-Smtp-Source: AGRyM1sa8SWrpkd8NzdsJJj4gqYXw1srVDZr94TRJw4sdqL/MBKkOtiMJe9qWSFLtE9YB1vvBrU87A==
X-Received: by 2002:a05:600c:3b9a:b0:3a3:21c2:e289 with SMTP id n26-20020a05600c3b9a00b003a321c2e289mr1348162wms.77.1658189552392;
        Mon, 18 Jul 2022 17:12:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c30c:0:b0:397:344c:c4f3 with SMTP id k12-20020a7bc30c000000b00397344cc4f3ls42027wmj.2.-pod-prod-gmail;
 Mon, 18 Jul 2022 17:12:31 -0700 (PDT)
X-Received: by 2002:a05:600c:3494:b0:3a0:37f0:86ad with SMTP id a20-20020a05600c349400b003a037f086admr28581125wmq.65.1658189551679;
        Mon, 18 Jul 2022 17:12:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189551; cv=none;
        d=google.com; s=arc-20160816;
        b=VUquiKQTNRdMgVtQeQJAKBNizjritHflpCO5cA1lBLsnmd3/Vr3Wjf8ylkrvjUDf+f
         ORZkmdoXN9+Um1pb0Z3JN6yKJ9oTMVntdpgIGazZvmrWvQDHffPPinvrrINMaxd70O++
         UgIa3bGDh32KjFLWyyoooOj4WLjyYSHsd6PKd+vKSddOyj92bTc83SO6XFLdsDCcqLhP
         F/u2YNn47zBHA/ubFKyoBUBZiMB9q8zrsbeeK2gHC73WN2eKbXTsFdND73PC4oQNsSRB
         UCo+3/FbA0mpuTIhMl08f36vpsK7MPMXSQVbTDwgHi5yGJNMqQhWggnGYsZ0kGX+Q+V4
         hYHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vEHfoxHnRz348LrTxEZAdD8nCG/gIjPOVMNgHO+/ASA=;
        b=U0GI0fa93b9rWf/1CXlUJGHaDsATjt1/ZhmCXjl7lqlZrw5Dq+Rfdkjwsfo0MktenX
         9/foiSyi6j4QpBvip8kUL24CHnUkIlu7+3KUmVva47cqCRUnpCFErJW8yAWcRfluWA2c
         2MFLpPta8RjuLLEbLfNl2PdIipjYgOuDdTiDrpsVyUSMmq/8M4I7/93XqwFF95/4ocbM
         P5sW/foPiwZ7ryY2nVu5+3E6T4wCJklPsLJzWXlw17O2Ouj/vavKRInqemnXgcQXqfCi
         9jiLb5v9yesbAprUEle7LnsuEpmcwXzgYzrNv08o/UarIvTi1bn7CiErqNTSkAls/qLj
         tlDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="w/ZmYnkg";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id p127-20020a1c2985000000b003a2e98573desi11448wmp.3.2022.07.18.17.12.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:12:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
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
Subject: [PATCH mm v2 15/33] kasan: only define kasan_never_merge for Generic mode
Date: Tue, 19 Jul 2022 02:09:55 +0200
Message-Id: <8ae180159c3789ca75bc69857958c31d25ea96ee.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="w/ZmYnkg";       spf=pass
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
index 0cef41f8a60d..e4ff0e4e7a9d 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8ae180159c3789ca75bc69857958c31d25ea96ee.1658189199.git.andreyknvl%40google.com.
