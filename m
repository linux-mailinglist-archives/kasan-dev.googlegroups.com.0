Return-Path: <kasan-dev+bncBDX4HWEMTEBRBAMOY36AKGQE6R42LXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 15339295FB8
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:20:02 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id l12sf424678wme.2
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:20:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372801; cv=pass;
        d=google.com; s=arc-20160816;
        b=diKSkiZ6+tnOR5h1Yu9eTqikzBRedsOMWf7CEG8T1rBPJ6ILNZxeLiDQNYUuWENY+F
         Bu4bgtLeFl+iRwd5hG0S3b/4WyacrSa3Fj5U/3bS2iDuK61uWT5BYlQJVspmhkEus017
         Xr1BydqfZU3gejQgwn0UawSpvINyCga2q/YSrvonAHQKeSt4OvoTKsHX/9tymro0xTie
         WBWcbkbhVnGdD1DJ4R2wkvwxkLijDf2fdSoFd7Y3qzRcnxdxNcaJjjeWrROtqDNLTaO+
         JDyJh8bjQhD7RgU8ijpKta8LZnMg6G1XHN3g2reW7kXcKcp4dfZacMeL4F4ZaGsn6HIS
         aXcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=6osFj7eSKcGQcP7VBvLUw7uV1pkHYDwuZKTBBNoFXXg=;
        b=skmMkdtkKOyxnWmby1+WFJ5JWGeIcEhkIQTZV7msGRZo3fbi703ouf2fAnFyasXrws
         umQzQzIfSfj52WsRdiq6NPK4TOvzgDPPssqwV/WWg/qa3ch/KG0m9H0NRNn1cKoFBuqd
         jwRHM3MtbwvBYT2Cagn1mBtQlzqvEg6djD/tQi94dlKsW3UDDnNq/pVc9ZFGOlG7hdew
         OuPjKsQDwr3poFgPOh+NC8Qb7m7qa1KPCfEVNTBYwsbey0uHRwH9QpMorOt31wc8T8yw
         G3wbolGpROgOPSyu0Hwx8f5aPtTQ0wfAnEePMV8f0xksWWgK97qRrcYncmOe2nfTzNqR
         uKFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T8XkZLbo;
       spf=pass (google.com: domain of 3aierxwokcvczc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3AIeRXwoKCVczC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6osFj7eSKcGQcP7VBvLUw7uV1pkHYDwuZKTBBNoFXXg=;
        b=kqio6+fqB1jb03BnHWPgQJLC5ImNxVZCj+4Rxc7PA2fksndRwLiZwHsQL6txkHOEyP
         TlhyVWwGcGf10LUzjWhhP5iyumulYGDaOWOcBSeX+nvJeZ4+3y+23ER5+9Yidw7aL802
         hOZPK7kDb8mlR9TBGyvBYbfDBVWdJwk8RV66VQ+LzQO1eLHJxHFQyo/LuA2TU3V7le6I
         ZGsLi81gIsDv5nITo12SUHHQMZNOEy8++tRB54l4XYbtzGCOCX0ffFUZlZD7DJuKyv4e
         X45WRnEZj4OL2PsuWXcVNz+Dlt8N2oMwUggNJof1ToOw4vYE7cUYtfVQrhTyFbWimNRI
         /QaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6osFj7eSKcGQcP7VBvLUw7uV1pkHYDwuZKTBBNoFXXg=;
        b=OnBKbGv3kGCETdKb/BH2OjQpLvun+mjkT4f1xxegmNxh6oqnqIDrd7BaP4nYBCiur3
         nIAgIcBZxeC7BGZUJpeiCOJvaAwcBnXVnYwAO/B0/YcNbaOw1s95opmF9LJSNMvkIk86
         eZJB/3r72vg2A6pGGdfduNQGJKEMFJOko0q1xcroOukfrSelNf9kg9+Vg+YEu9V3zZWQ
         iZb0ybXRSVD6Cx5veUKLwgfGTSJkGuQ83DC7AlglLxN5OTdjwxN6LFhtuFD+GU7+qkuE
         4dXVJlcrPf//AjnxWYhZdAut92n6rpBRF6gohdDtvQYEbjrfWCUatmnqMhWPhp3k5at5
         RwnQ==
X-Gm-Message-State: AOAM530Qznec+bhQfgmc10PBHmlFMGzgOd+pRIo5JcoZw6HvJbasOCp7
	8msNGUJvwqshptXbbElA+Ho=
X-Google-Smtp-Source: ABdhPJxaqXMQC+TeA6GSQhNmznwfGnfpAnmlf0rLxOTp0eY5JjTEFegfk2QNCW9s4cReQf2tz4g6Iw==
X-Received: by 2002:a7b:c305:: with SMTP id k5mr2636912wmj.102.1603372801845;
        Thu, 22 Oct 2020 06:20:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4ac3:: with SMTP id y3ls2403193wrs.2.gmail; Thu, 22 Oct
 2020 06:20:01 -0700 (PDT)
X-Received: by 2002:adf:fa8a:: with SMTP id h10mr2682892wrr.336.1603372800858;
        Thu, 22 Oct 2020 06:20:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372800; cv=none;
        d=google.com; s=arc-20160816;
        b=YbnhrX+miU9CuG+u2QdKyuc1iEnoW5A3ZJjBf/4oBZSH0xOtWmyTquFSyNqWw9RcBw
         0ZL0TTs66nhLoSZouPIWNgKNH+5UY6ugOZU4JdLPDc4dphumaf7P3b85txTmAjLeDjHA
         riRYo2yCm0Z5kqtEmskiXL19VsRu33sh764OeT/r6zChkje9x1QUl+aZRlRKiYNhNou7
         zwnXOunCEZ8LGu1UyUsUTiQeWwfI9LbHRofB8qUbCPkBVodnqOl4o0Cfk6L/wswFpGjj
         4aieD7anZEsSBl11mseUEeoNtPX+StFuKv6dapSfIUv3/JL/sdMMNBIUxM7NL/SIw1lV
         r1AQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=RAUHacgq2cb8MVx0OL/jnsTS0+3Q5wxOMCs5kif8wrA=;
        b=BteDCLWOLfi74FrOmFbeNro28f5C2Ubf+yixEDU6+9XxfK44yrw/+fTM2/QS4+H+ZG
         BqeNwAkKq2o87StCB5oC+YB5+j9HvhsaUxpjt8wsT47AfQDAQCl0QCc26DpuQ9UMMnSs
         O4OIzlXNWj0z3F6zI3/SfzXV3JvSql0LsH0Q4R5OAqJQXfFgYnPH5xzXCbrd73XCL1Ju
         EjfPiVAN1mvPCcv8WxiZsUBqv2JGAmKC5keElnkb/Jpci3NQ/5ArkAXN+9vjoNZm10DD
         pNRkFeNhb3Gz/Js8o1uU5LyR3v5kKlkeMFj6552HMUy9UqxAXJF7+ZJ5Bqu6lH9osYZl
         GMnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T8XkZLbo;
       spf=pass (google.com: domain of 3aierxwokcvczc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3AIeRXwoKCVczC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 14si57704wmf.4.2020.10.22.06.20.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:20:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3aierxwokcvczc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id r7so422778wmr.5
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:20:00 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:7707:: with SMTP id
 t7mr2703228wmi.54.1603372800484; Thu, 22 Oct 2020 06:20:00 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:19:07 +0200
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
Message-Id: <21fa5f4eb6ee132a57b716ff6245f2c98de2d204.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 15/21] kasan: check kasan_enabled in annotations
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Kostya Serebryany <kcc@google.com>, 
	Peter Collingbourne <pcc@google.com>, Serban Constantinescu <serbanc@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=T8XkZLbo;       spf=pass
 (google.com: domain of 3aierxwokcvczc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3AIeRXwoKCVczC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Declare the kasan_enabled static key in include/linux/kasan.h and in
include/linux/mm.h and check it in all kasan annotations. This allows to
avoid any slowdown caused by function calls when kasan_enabled is
disabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/I2589451d3c96c97abbcbf714baabe6161c6f153e
---
 include/linux/kasan.h | 210 ++++++++++++++++++++++++++++++++----------
 include/linux/mm.h    |  27 ++++--
 mm/kasan/common.c     |  60 ++++++------
 3 files changed, 211 insertions(+), 86 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 2b9023224474..8654275aa62e 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -2,6 +2,7 @@
 #ifndef _LINUX_KASAN_H
 #define _LINUX_KASAN_H
 
+#include <linux/jump_label.h>
 #include <linux/types.h>
 
 struct kmem_cache;
@@ -66,40 +67,154 @@ static inline void kasan_disable_current(void) {}
 
 #ifdef CONFIG_KASAN
 
-void kasan_alloc_pages(struct page *page, unsigned int order);
-void kasan_free_pages(struct page *page, unsigned int order);
+struct kasan_cache {
+	int alloc_meta_offset;
+	int free_meta_offset;
+};
+
+#ifdef CONFIG_KASAN_HW_TAGS
+DECLARE_STATIC_KEY_FALSE(kasan_enabled);
+#else
+DECLARE_STATIC_KEY_TRUE(kasan_enabled);
+#endif
 
-void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
-			slab_flags_t *flags);
+void __kasan_alloc_pages(struct page *page, unsigned int order);
+static inline void kasan_alloc_pages(struct page *page, unsigned int order)
+{
+	if (static_branch_likely(&kasan_enabled))
+		__kasan_alloc_pages(page, order);
+}
 
-void kasan_unpoison_data(const void *address, size_t size);
-void kasan_unpoison_slab(const void *ptr);
+void __kasan_free_pages(struct page *page, unsigned int order);
+static inline void kasan_free_pages(struct page *page, unsigned int order)
+{
+	if (static_branch_likely(&kasan_enabled))
+		__kasan_free_pages(page, order);
+}
 
-void kasan_poison_slab(struct page *page);
-void kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
-void kasan_poison_object_data(struct kmem_cache *cache, void *object);
-void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
-					const void *object);
+void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
+				slab_flags_t *flags);
+static inline void kasan_cache_create(struct kmem_cache *cache,
+			unsigned int *size, slab_flags_t *flags)
+{
+	if (static_branch_likely(&kasan_enabled))
+		__kasan_cache_create(cache, size, flags);
+}
 
-void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
-						gfp_t flags);
-void kasan_kfree_large(void *ptr, unsigned long ip);
-void kasan_poison_kfree(void *ptr, unsigned long ip);
-void * __must_check kasan_kmalloc(struct kmem_cache *s, const void *object,
-					size_t size, gfp_t flags);
-void * __must_check kasan_krealloc(const void *object, size_t new_size,
-					gfp_t flags);
+size_t __kasan_metadata_size(struct kmem_cache *cache);
+static inline size_t kasan_metadata_size(struct kmem_cache *cache)
+{
+	if (static_branch_likely(&kasan_enabled))
+		return __kasan_metadata_size(cache);
+	return 0;
+}
 
-void * __must_check kasan_slab_alloc(struct kmem_cache *s, void *object,
-					gfp_t flags);
-bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
+void __kasan_unpoison_data(const void *addr, size_t size);
+static inline void kasan_unpoison_data(const void *addr, size_t size)
+{
+	if (static_branch_likely(&kasan_enabled))
+		__kasan_unpoison_data(addr, size);
+}
 
-struct kasan_cache {
-	int alloc_meta_offset;
-	int free_meta_offset;
-};
+void __kasan_unpoison_slab(const void *ptr);
+static inline void kasan_unpoison_slab(const void *ptr)
+{
+	if (static_branch_likely(&kasan_enabled))
+		__kasan_unpoison_slab(ptr);
+}
+
+void __kasan_poison_slab(struct page *page);
+static inline void kasan_poison_slab(struct page *page)
+{
+	if (static_branch_likely(&kasan_enabled))
+		return __kasan_poison_slab(page);
+}
+
+void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
+static inline void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
+{
+	if (static_branch_likely(&kasan_enabled))
+		return __kasan_unpoison_object_data(cache, object);
+}
+
+void __kasan_poison_object_data(struct kmem_cache *cache, void *object);
+static inline void kasan_poison_object_data(struct kmem_cache *cache, void *object)
+{
+	if (static_branch_likely(&kasan_enabled))
+		__kasan_poison_object_data(cache, object);
+}
+
+void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
+					  const void *object);
+static inline void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
+						      const void *object)
+{
+	if (static_branch_likely(&kasan_enabled))
+		return __kasan_init_slab_obj(cache, object);
+	return (void *)object;
+}
+
+bool __kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
+static inline bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip)
+{
+	if (static_branch_likely(&kasan_enabled))
+		return __kasan_slab_free(s, object, ip);
+	return false;
+}
 
-size_t kasan_metadata_size(struct kmem_cache *cache);
+void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
+				       void *object, gfp_t flags);
+static inline void * __must_check kasan_slab_alloc(struct kmem_cache *s,
+						   void *object, gfp_t flags)
+{
+	if (static_branch_likely(&kasan_enabled))
+		return __kasan_slab_alloc(s, object, flags);
+	return object;
+}
+
+void * __must_check __kasan_kmalloc(struct kmem_cache *s, const void *object,
+				    size_t size, gfp_t flags);
+static inline void * __must_check kasan_kmalloc(struct kmem_cache *s, const void *object,
+						size_t size, gfp_t flags)
+{
+	if (static_branch_likely(&kasan_enabled))
+		return __kasan_kmalloc(s, object, size, flags);
+	return (void *)object;
+}
+
+void * __must_check __kasan_kmalloc_large(const void *ptr,
+					  size_t size, gfp_t flags);
+static inline void * __must_check kasan_kmalloc_large(const void *ptr,
+						      size_t size, gfp_t flags)
+{
+	if (static_branch_likely(&kasan_enabled))
+		return __kasan_kmalloc_large(ptr, size, flags);
+	return (void *)ptr;
+}
+
+void * __must_check __kasan_krealloc(const void *object,
+				     size_t new_size, gfp_t flags);
+static inline void * __must_check kasan_krealloc(const void *object,
+						 size_t new_size, gfp_t flags)
+{
+	if (static_branch_likely(&kasan_enabled))
+		return __kasan_krealloc(object, new_size, flags);
+	return (void *)object;
+}
+
+void __kasan_poison_kfree(void *ptr, unsigned long ip);
+static inline void kasan_poison_kfree(void *ptr, unsigned long ip)
+{
+	if (static_branch_likely(&kasan_enabled))
+		__kasan_poison_kfree(ptr, ip);
+}
+
+void __kasan_kfree_large(void *ptr, unsigned long ip);
+static inline void kasan_kfree_large(void *ptr, unsigned long ip)
+{
+	if (static_branch_likely(&kasan_enabled))
+		__kasan_kfree_large(ptr, ip);
+}
 
 bool kasan_save_enable_multi_shot(void);
 void kasan_restore_multi_shot(bool enabled);
@@ -108,14 +223,12 @@ void kasan_restore_multi_shot(bool enabled);
 
 static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
 static inline void kasan_free_pages(struct page *page, unsigned int order) {}
-
 static inline void kasan_cache_create(struct kmem_cache *cache,
 				      unsigned int *size,
 				      slab_flags_t *flags) {}
-
-static inline void kasan_unpoison_data(const void *address, size_t size) { }
-static inline void kasan_unpoison_slab(const void *ptr) { }
-
+static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
+static inline void kasan_unpoison_data(const void *address, size_t size) {}
+static inline void kasan_unpoison_slab(const void *ptr) {}
 static inline void kasan_poison_slab(struct page *page) {}
 static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
 					void *object) {}
@@ -126,36 +239,33 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
 {
 	return (void *)object;
 }
-
-static inline void *kasan_kmalloc_large(void *ptr, size_t size, gfp_t flags)
+static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
+				   unsigned long ip)
 {
-	return ptr;
+	return false;
 }
-static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
-static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
-static inline void *kasan_kmalloc(struct kmem_cache *s, const void *object,
-				size_t size, gfp_t flags)
+static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
+				   gfp_t flags)
 {
-	return (void *)object;
+	return object;
 }
-static inline void *kasan_krealloc(const void *object, size_t new_size,
-				 gfp_t flags)
+static inline void *kasan_kmalloc(struct kmem_cache *s, const void *object,
+				size_t size, gfp_t flags)
 {
 	return (void *)object;
 }
 
-static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
-				   gfp_t flags)
+static inline void *kasan_kmalloc_large(const void *ptr, size_t size, gfp_t flags)
 {
-	return object;
+	return (void *)ptr;
 }
-static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
-				   unsigned long ip)
+static inline void *kasan_krealloc(const void *object, size_t new_size,
+				 gfp_t flags)
 {
-	return false;
+	return (void *)object;
 }
-
-static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
+static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
+static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
 
 #endif /* CONFIG_KASAN */
 
diff --git a/include/linux/mm.h b/include/linux/mm.h
index a3cac68c737c..701e9d7666d6 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -1412,22 +1412,36 @@ static inline bool cpupid_match_pid(struct task_struct *task, int cpupid)
 #endif /* CONFIG_NUMA_BALANCING */
 
 #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
+
+#ifdef CONFIG_KASAN_HW_TAGS
+DECLARE_STATIC_KEY_FALSE(kasan_enabled);
+#else
+DECLARE_STATIC_KEY_TRUE(kasan_enabled);
+#endif
+
 static inline u8 page_kasan_tag(const struct page *page)
 {
-	return (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
+	if (static_branch_likely(&kasan_enabled))
+		return (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
+	return 0xff;
 }
 
 static inline void page_kasan_tag_set(struct page *page, u8 tag)
 {
-	page->flags &= ~(KASAN_TAG_MASK << KASAN_TAG_PGSHIFT);
-	page->flags |= (tag & KASAN_TAG_MASK) << KASAN_TAG_PGSHIFT;
+	if (static_branch_likely(&kasan_enabled)) {
+		page->flags &= ~(KASAN_TAG_MASK << KASAN_TAG_PGSHIFT);
+		page->flags |= (tag & KASAN_TAG_MASK) << KASAN_TAG_PGSHIFT;
+	}
 }
 
 static inline void page_kasan_tag_reset(struct page *page)
 {
-	page_kasan_tag_set(page, 0xff);
+	if (static_branch_likely(&kasan_enabled))
+		page_kasan_tag_set(page, 0xff);
 }
-#else
+
+#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
+
 static inline u8 page_kasan_tag(const struct page *page)
 {
 	return 0xff;
@@ -1435,7 +1449,8 @@ static inline u8 page_kasan_tag(const struct page *page)
 
 static inline void page_kasan_tag_set(struct page *page, u8 tag) { }
 static inline void page_kasan_tag_reset(struct page *page) { }
-#endif
+
+#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
 static inline struct zone *page_zone(const struct page *page)
 {
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index cc129ef62ab1..c5ec60e1a4d2 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -81,7 +81,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 }
 #endif /* CONFIG_KASAN_STACK */
 
-void kasan_alloc_pages(struct page *page, unsigned int order)
+void __kasan_alloc_pages(struct page *page, unsigned int order)
 {
 	u8 tag;
 	unsigned long i;
@@ -95,7 +95,7 @@ void kasan_alloc_pages(struct page *page, unsigned int order)
 	kasan_unpoison_memory(page_address(page), PAGE_SIZE << order);
 }
 
-void kasan_free_pages(struct page *page, unsigned int order)
+void __kasan_free_pages(struct page *page, unsigned int order)
 {
 	if (likely(!PageHighMem(page)))
 		kasan_poison_memory(page_address(page),
@@ -122,8 +122,8 @@ static inline unsigned int optimal_redzone(unsigned int object_size)
 		object_size <= (1 << 16) - 1024 ? 1024 : 2048;
 }
 
-void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
-			slab_flags_t *flags)
+void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
+			  slab_flags_t *flags)
 {
 	unsigned int orig_size = *size;
 	unsigned int redzone_size;
@@ -165,7 +165,7 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 	*flags |= SLAB_KASAN;
 }
 
-size_t kasan_metadata_size(struct kmem_cache *cache)
+size_t __kasan_metadata_size(struct kmem_cache *cache)
 {
 	if (static_branch_unlikely(&kasan_stack))
 		return (cache->kasan_info.alloc_meta_offset ?
@@ -188,17 +188,17 @@ struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 	return (void *)reset_tag(object) + cache->kasan_info.free_meta_offset;
 }
 
-void kasan_unpoison_data(const void *address, size_t size)
+void __kasan_unpoison_data(const void *addr, size_t size)
 {
-	kasan_unpoison_memory(address, size);
+	kasan_unpoison_memory(addr, size);
 }
 
-void kasan_unpoison_slab(const void *ptr)
+void __kasan_unpoison_slab(const void *ptr)
 {
 	kasan_unpoison_memory(ptr, __ksize(ptr));
 }
 
-void kasan_poison_slab(struct page *page)
+void __kasan_poison_slab(struct page *page)
 {
 	unsigned long i;
 
@@ -208,12 +208,12 @@ void kasan_poison_slab(struct page *page)
 			KASAN_KMALLOC_REDZONE);
 }
 
-void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
+void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
 {
 	kasan_unpoison_memory(object, cache->object_size);
 }
 
-void kasan_poison_object_data(struct kmem_cache *cache, void *object)
+void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
 {
 	kasan_poison_memory(object,
 			round_up(cache->object_size, KASAN_GRANULE_SIZE),
@@ -266,7 +266,7 @@ static u8 assign_tag(struct kmem_cache *cache, const void *object,
 #endif
 }
 
-void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
+void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 						const void *object)
 {
 	struct kasan_alloc_meta *alloc_meta;
@@ -285,7 +285,7 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
 	return (void *)object;
 }
 
-static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
+static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 			      unsigned long ip, bool quarantine)
 {
 	u8 tag;
@@ -329,9 +329,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	return false;
 }
 
-bool kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
+bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
 {
-	return __kasan_slab_free(cache, object, ip, true);
+	return ____kasan_slab_free(cache, object, ip, true);
 }
 
 static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
@@ -339,7 +339,7 @@ static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 	kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
 }
 
-static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
+static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 				size_t size, gfp_t flags, bool keep_tag)
 {
 	unsigned long redzone_start;
@@ -371,20 +371,20 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	return set_tag(object, tag);
 }
 
-void * __must_check kasan_slab_alloc(struct kmem_cache *cache, void *object,
-					gfp_t flags)
+void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
+					void *object, gfp_t flags)
 {
-	return __kasan_kmalloc(cache, object, cache->object_size, flags, false);
+	return ____kasan_kmalloc(cache, object, cache->object_size, flags, false);
 }
 
-void * __must_check kasan_kmalloc(struct kmem_cache *cache, const void *object,
-				size_t size, gfp_t flags)
+void * __must_check __kasan_kmalloc(struct kmem_cache *cache, const void *object,
+					size_t size, gfp_t flags)
 {
-	return __kasan_kmalloc(cache, object, size, flags, true);
+	return ____kasan_kmalloc(cache, object, size, flags, true);
 }
-EXPORT_SYMBOL(kasan_kmalloc);
+EXPORT_SYMBOL(__kasan_kmalloc);
 
-void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
+void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
 						gfp_t flags)
 {
 	struct page *page;
@@ -409,7 +409,7 @@ void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
 	return (void *)ptr;
 }
 
-void * __must_check kasan_krealloc(const void *object, size_t size, gfp_t flags)
+void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flags)
 {
 	struct page *page;
 
@@ -419,13 +419,13 @@ void * __must_check kasan_krealloc(const void *object, size_t size, gfp_t flags)
 	page = virt_to_head_page(object);
 
 	if (unlikely(!PageSlab(page)))
-		return kasan_kmalloc_large(object, size, flags);
+		return __kasan_kmalloc_large(object, size, flags);
 	else
-		return __kasan_kmalloc(page->slab_cache, object, size,
+		return ____kasan_kmalloc(page->slab_cache, object, size,
 						flags, true);
 }
 
-void kasan_poison_kfree(void *ptr, unsigned long ip)
+void __kasan_poison_kfree(void *ptr, unsigned long ip)
 {
 	struct page *page;
 
@@ -438,11 +438,11 @@ void kasan_poison_kfree(void *ptr, unsigned long ip)
 		}
 		kasan_poison_memory(ptr, page_size(page), KASAN_FREE_PAGE);
 	} else {
-		__kasan_slab_free(page->slab_cache, ptr, ip, false);
+		____kasan_slab_free(page->slab_cache, ptr, ip, false);
 	}
 }
 
-void kasan_kfree_large(void *ptr, unsigned long ip)
+void __kasan_kfree_large(void *ptr, unsigned long ip)
 {
 	if (ptr != page_address(virt_to_head_page(ptr)))
 		kasan_report_invalid_free(ptr, ip);
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/21fa5f4eb6ee132a57b716ff6245f2c98de2d204.1603372719.git.andreyknvl%40google.com.
