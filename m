Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWVQ6D6QKGQEF47PVIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 06EDE2C1575
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:15:24 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id n5sf2422046qvt.14
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:15:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162523; cv=pass;
        d=google.com; s=arc-20160816;
        b=IuCXpb1ogd5C+gbm9QTsN9OOIQCx7zrQxfPuj98D+PmgAJu/Z3ZQTz642jBafwyxNs
         6PxaaEz+pGNffqnSv5QunoukpC6HktTHQoPNLqvC3jsNyIM8QpVD8Erk/SONWW2AOwai
         WVdC3nUlyFLM3Ec2qYhMOHWdaMIKW75JVWbNbJJBAjNHDuINBhRusmrTKCm0/wTIIcY7
         P7krTP5XPye8SlgDgJ5VJ5FxR6OAVUiB/C/bqRiFoJrNfMxIXz2HDZqt6E3xZtcRSQGf
         X5ypLKxfPShEHv9vGsFX5Lx2g5VFvddAKNOeNbu/4Ce/UTbu80W6OViM3pYBohE68NiK
         LS1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=YueSa4HL228DxSyTJrz3WF5WAoVBJ+qzrb2Da/LrQwE=;
        b=J3pqpQ0pQ053QiIirLKWcvVast3VMB6CvqAlS71Xg+o/lFaC4JBzb/yRNv7y0yWlCp
         EasVXFwSwkVbWopWLPx53JiGKdQ3BZ52+8kqoJHSFWTbzLKCT4siZaLu9foqpvL7v9O6
         kY/kK1qyF/08A5qzwCd0FpGpFZZtXhlZNCW8qtcI0Uy2oUUVRpKgldMMAqVoY7KEbon9
         e0bOwu5xQSiru5EY1/0HuizIpiBeUnNG4eaHzl0NYoV74kFCvKtfg4jrKj6s/rKMEdro
         ML0a1kB7HKRdCaD6dQ/+yRd+sXgEs0FrKwcYOU280BLjiLFQ9U8MhuA717RphLPN/ame
         IygQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RnHQK3gT;
       spf=pass (google.com: domain of 3wri8xwokcx4cpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3WRi8XwoKCX4cpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YueSa4HL228DxSyTJrz3WF5WAoVBJ+qzrb2Da/LrQwE=;
        b=V8obsQw7rDQ8xJt1sOpF1ht5Rr89bzguwdZGwYlFlfs/lZqVPjCSQv3EDZ8Nw8xJ/H
         bZGe+vChuchm+tO1JLKYRMZcPZ8veSGBUbEUGc6ojPQZFx1Rc/5xNluDJb4J7dLonhk4
         MZXWhIrsqO4ubxKt7jHHXPucmaTXYhokgnwt/d+yL4FU6xKx8AzmD4QOtWRHT94e/oii
         PgXvztPzYTtQFDDPHiLzi3qzP0ekMUYZrcvYV7rq7UP1k5v29Mlg5IUYOG5ieMVy9Wka
         wbzWCIxJzRY+mYnXqKInjJbNL9qCQfNWKWP45XPEl9B+HpaUB+Tw9/Z5BwDVivwrDGFQ
         bixw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YueSa4HL228DxSyTJrz3WF5WAoVBJ+qzrb2Da/LrQwE=;
        b=WmA9pzfdwoMH4GBZq26WiDzo0Wt8PLBBy27VwklMyEbRcPhCDfun23NIl038WP5tXU
         kAlJZPxGjjWFBc+/TkhZlHLdkteEN+nuYkQ3RhxCydMnKogUprvCoQBN3I+fyjD4Ok0N
         F2x+KWDvovRYMyGvodRY3pDxXcFOEeMckis/OnPpg4VcFJHVDUfsfo66juJ6NCkOLn2Z
         5EC279jlKY4i030Q3hs1M8ojr+E+Z1SxxxocIJTT2i6TrTn0AutWGMs+HoveSw4wxKV9
         n1mxQz9kZgOhEWRxmlB1Y16f0x27yVjbn1IO3oMWgey9i6LFJxlbZs1/gKLUgP0P1Llr
         Inzw==
X-Gm-Message-State: AOAM532V0uaG2EOD2+lqfv3SEMH7yVdv+XmiI03lbmrA+ZEp3xO1RiMe
	VDI5xx/7MBS3uHdbw7ydphA=
X-Google-Smtp-Source: ABdhPJzZFj2JOwTUIeHqiMf3dTgQG1xv7VdopAZu/FhQy7fQkKq6NSeLTihoGZf5Wuv5O+LBI3z4ug==
X-Received: by 2002:ac8:4554:: with SMTP id z20mr886873qtn.330.1606162522887;
        Mon, 23 Nov 2020 12:15:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:7904:: with SMTP id u4ls3101198qkc.7.gmail; Mon, 23 Nov
 2020 12:15:22 -0800 (PST)
X-Received: by 2002:a05:620a:15f7:: with SMTP id p23mr1258808qkm.98.1606162522233;
        Mon, 23 Nov 2020 12:15:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162522; cv=none;
        d=google.com; s=arc-20160816;
        b=YLG++G5dk/eaoE2gaY+lm3w8wqIeFEsrULISrju2PIujymmLamhN2KGLQEPz3gJmHf
         CLA2Dp93g/kiz4Vvs7oY3ZBE/XM+5gQW6FlN0abt1nXj27mRoFpjJXvUbOVhdSVrCrYU
         2O2jqncD5yjG1pkULauW9hbQ6g/kHcdlM+iXdIlkfhf8MrLt02T2DthUvpSXmMj5YZzU
         cBD2j6cuZDg3VlEjvRItJAOhY2kerpW59opqh6b7f6jRGyWKR3hjFXLWbhjCyWtjo1Fd
         /ZN+lsf5dDqWiwrxeiQhfbqT4tWKDmAYKwFvwqsXxYbEuRnNS0/a8nm+mj4Lp+EwPc0t
         Vdsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=nlC0gdqYkTMGAEqxvmFcC299FPQJg14RB1uP6sPoMPA=;
        b=FxKC71OUl7EjYkn+7Zjdy74YpDGS6LUdsBkG2nHVD8vJ69l+YbBDZQTHB1t+DaLcUj
         4jRGofsu8dIPZReMbXQf/qt9CDtyTJF4LjJNNvlDOh3nPDw9L5bhRoDPkvbriz3Ydv0P
         n0AHAxp4vN6d2Do0XdFNX6X3dzfvV3HMomAaBOzuFkEFCCKfkgjv4do5b23sJvR2WHkt
         U0HBEwz2lkmxQQfQnwQpfe6cX8VGQGMgrtTmR0HUKvj7rks2VI+rBciXfngBzXdnJZYZ
         F/qCqA2dLBYkyeC7e5PBEJGBj8Tko5a0i7b0lyBZ+C832Jv+etcu4Rtx9GmsZ1P1xJG6
         Oueg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RnHQK3gT;
       spf=pass (google.com: domain of 3wri8xwokcx4cpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3WRi8XwoKCX4cpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id k54si86122qtk.4.2020.11.23.12.15.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:15:22 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wri8xwokcx4cpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id y5so14465518qtb.13
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:15:22 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4051:: with SMTP id
 r17mr1091487qvp.39.1606162521864; Mon, 23 Nov 2020 12:15:21 -0800 (PST)
Date: Mon, 23 Nov 2020 21:14:42 +0100
In-Reply-To: <cover.1606162397.git.andreyknvl@google.com>
Message-Id: <9f90e3c0aa840dbb4833367c2335193299f69023.1606162397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606162397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v4 12/19] kasan, mm: check kasan_enabled in annotations
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Vincenzo Frascino <Vincenzo.Frascino@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RnHQK3gT;       spf=pass
 (google.com: domain of 3wri8xwokcx4cpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3WRi8XwoKCX4cpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
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

Co-developed-by: Vincenzo Frascino <Vincenzo.Frascino@arm.com>
Signed-off-by: Vincenzo Frascino <Vincenzo.Frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://linux-review.googlesource.com/id/I2589451d3c96c97abbcbf714baabe6161c6f153e
---
 include/linux/kasan.h | 213 ++++++++++++++++++++++++++++++++----------
 include/linux/mm.h    |  22 +++--
 mm/kasan/common.c     |  56 +++++------
 3 files changed, 210 insertions(+), 81 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 872bf145ddde..f631f99aa4b4 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -2,6 +2,7 @@
 #ifndef _LINUX_KASAN_H
 #define _LINUX_KASAN_H
 
+#include <linux/static_key.h>
 #include <linux/types.h>
 
 struct kmem_cache;
@@ -74,54 +75,176 @@ static inline void kasan_disable_current(void) {}
 
 #ifdef CONFIG_KASAN
 
-void kasan_unpoison_range(const void *address, size_t size);
+struct kasan_cache {
+	int alloc_meta_offset;
+	int free_meta_offset;
+};
 
-void kasan_alloc_pages(struct page *page, unsigned int order);
-void kasan_free_pages(struct page *page, unsigned int order);
+#ifdef CONFIG_KASAN_HW_TAGS
+DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
+static __always_inline bool kasan_enabled(void)
+{
+	return static_branch_likely(&kasan_flag_enabled);
+}
+#else
+static inline bool kasan_enabled(void)
+{
+	return true;
+}
+#endif
 
-void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
-			slab_flags_t *flags);
+void __kasan_unpoison_range(const void *addr, size_t size);
+static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
+{
+	if (kasan_enabled())
+		__kasan_unpoison_range(addr, size);
+}
 
-void kasan_poison_slab(struct page *page);
-void kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
-void kasan_poison_object_data(struct kmem_cache *cache, void *object);
-void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
-					const void *object);
+void __kasan_alloc_pages(struct page *page, unsigned int order);
+static __always_inline void kasan_alloc_pages(struct page *page,
+						unsigned int order)
+{
+	if (kasan_enabled())
+		__kasan_alloc_pages(page, order);
+}
 
-void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
-						gfp_t flags);
-void kasan_kfree_large(void *ptr, unsigned long ip);
-void kasan_poison_kfree(void *ptr, unsigned long ip);
-void * __must_check kasan_kmalloc(struct kmem_cache *s, const void *object,
-					size_t size, gfp_t flags);
-void * __must_check kasan_krealloc(const void *object, size_t new_size,
-					gfp_t flags);
+void __kasan_free_pages(struct page *page, unsigned int order);
+static __always_inline void kasan_free_pages(struct page *page,
+						unsigned int order)
+{
+	if (kasan_enabled())
+		__kasan_free_pages(page, order);
+}
 
-void * __must_check kasan_slab_alloc(struct kmem_cache *s, void *object,
-					gfp_t flags);
-bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
+void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
+				slab_flags_t *flags);
+static __always_inline void kasan_cache_create(struct kmem_cache *cache,
+				unsigned int *size, slab_flags_t *flags)
+{
+	if (kasan_enabled())
+		__kasan_cache_create(cache, size, flags);
+}
 
-struct kasan_cache {
-	int alloc_meta_offset;
-	int free_meta_offset;
-};
+size_t __kasan_metadata_size(struct kmem_cache *cache);
+static __always_inline size_t kasan_metadata_size(struct kmem_cache *cache)
+{
+	if (kasan_enabled())
+		return __kasan_metadata_size(cache);
+	return 0;
+}
+
+void __kasan_poison_slab(struct page *page);
+static __always_inline void kasan_poison_slab(struct page *page)
+{
+	if (kasan_enabled())
+		__kasan_poison_slab(page);
+}
+
+void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
+static __always_inline void kasan_unpoison_object_data(struct kmem_cache *cache,
+							void *object)
+{
+	if (kasan_enabled())
+		__kasan_unpoison_object_data(cache, object);
+}
+
+void __kasan_poison_object_data(struct kmem_cache *cache, void *object);
+static __always_inline void kasan_poison_object_data(struct kmem_cache *cache,
+							void *object)
+{
+	if (kasan_enabled())
+		__kasan_poison_object_data(cache, object);
+}
+
+void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
+					  const void *object);
+static __always_inline void * __must_check kasan_init_slab_obj(
+				struct kmem_cache *cache, const void *object)
+{
+	if (kasan_enabled())
+		return __kasan_init_slab_obj(cache, object);
+	return (void *)object;
+}
+
+bool __kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
+static __always_inline bool kasan_slab_free(struct kmem_cache *s, void *object,
+						unsigned long ip)
+{
+	if (kasan_enabled())
+		return __kasan_slab_free(s, object, ip);
+	return false;
+}
+
+void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
+				       void *object, gfp_t flags);
+static __always_inline void * __must_check kasan_slab_alloc(
+				struct kmem_cache *s, void *object, gfp_t flags)
+{
+	if (kasan_enabled())
+		return __kasan_slab_alloc(s, object, flags);
+	return object;
+}
+
+void * __must_check __kasan_kmalloc(struct kmem_cache *s, const void *object,
+				    size_t size, gfp_t flags);
+static __always_inline void * __must_check kasan_kmalloc(struct kmem_cache *s,
+				const void *object, size_t size, gfp_t flags)
+{
+	if (kasan_enabled())
+		return __kasan_kmalloc(s, object, size, flags);
+	return (void *)object;
+}
 
-size_t kasan_metadata_size(struct kmem_cache *cache);
+void * __must_check __kasan_kmalloc_large(const void *ptr,
+					  size_t size, gfp_t flags);
+static __always_inline void * __must_check kasan_kmalloc_large(const void *ptr,
+						      size_t size, gfp_t flags)
+{
+	if (kasan_enabled())
+		return __kasan_kmalloc_large(ptr, size, flags);
+	return (void *)ptr;
+}
+
+void * __must_check __kasan_krealloc(const void *object,
+				     size_t new_size, gfp_t flags);
+static __always_inline void * __must_check kasan_krealloc(const void *object,
+						 size_t new_size, gfp_t flags)
+{
+	if (kasan_enabled())
+		return __kasan_krealloc(object, new_size, flags);
+	return (void *)object;
+}
+
+void __kasan_poison_kfree(void *ptr, unsigned long ip);
+static __always_inline void kasan_poison_kfree(void *ptr, unsigned long ip)
+{
+	if (kasan_enabled())
+		__kasan_poison_kfree(ptr, ip);
+}
+
+void __kasan_kfree_large(void *ptr, unsigned long ip);
+static __always_inline void kasan_kfree_large(void *ptr, unsigned long ip)
+{
+	if (kasan_enabled())
+		__kasan_kfree_large(ptr, ip);
+}
 
 bool kasan_save_enable_multi_shot(void);
 void kasan_restore_multi_shot(bool enabled);
 
 #else /* CONFIG_KASAN */
 
+static inline bool kasan_enabled(void)
+{
+	return false;
+}
 static inline void kasan_unpoison_range(const void *address, size_t size) {}
-
 static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
 static inline void kasan_free_pages(struct page *page, unsigned int order) {}
-
 static inline void kasan_cache_create(struct kmem_cache *cache,
 				      unsigned int *size,
 				      slab_flags_t *flags) {}
-
+static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 static inline void kasan_poison_slab(struct page *page) {}
 static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
 					void *object) {}
@@ -132,36 +255,32 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
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
+}
+static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
+				   gfp_t flags)
+{
+	return object;
 }
-static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
-static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
 static inline void *kasan_kmalloc(struct kmem_cache *s, const void *object,
 				size_t size, gfp_t flags)
 {
 	return (void *)object;
 }
+static inline void *kasan_kmalloc_large(const void *ptr, size_t size, gfp_t flags)
+{
+	return (void *)ptr;
+}
 static inline void *kasan_krealloc(const void *object, size_t new_size,
 				 gfp_t flags)
 {
 	return (void *)object;
 }
-
-static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
-				   gfp_t flags)
-{
-	return object;
-}
-static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
-				   unsigned long ip)
-{
-	return false;
-}
-
-static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
+static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
+static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
 
 #endif /* CONFIG_KASAN */
 
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 035957363055..82c57668748c 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -31,6 +31,7 @@
 #include <linux/sizes.h>
 #include <linux/sched.h>
 #include <linux/pgtable.h>
+#include <linux/kasan.h>
 
 struct mempolicy;
 struct anon_vma;
@@ -1422,22 +1423,30 @@ static inline bool cpupid_match_pid(struct task_struct *task, int cpupid)
 #endif /* CONFIG_NUMA_BALANCING */
 
 #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
+
 static inline u8 page_kasan_tag(const struct page *page)
 {
-	return (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
+	if (kasan_enabled())
+		return (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
+	return 0xff;
 }
 
 static inline void page_kasan_tag_set(struct page *page, u8 tag)
 {
-	page->flags &= ~(KASAN_TAG_MASK << KASAN_TAG_PGSHIFT);
-	page->flags |= (tag & KASAN_TAG_MASK) << KASAN_TAG_PGSHIFT;
+	if (kasan_enabled()) {
+		page->flags &= ~(KASAN_TAG_MASK << KASAN_TAG_PGSHIFT);
+		page->flags |= (tag & KASAN_TAG_MASK) << KASAN_TAG_PGSHIFT;
+	}
 }
 
 static inline void page_kasan_tag_reset(struct page *page)
 {
-	page_kasan_tag_set(page, 0xff);
+	if (kasan_enabled())
+		page_kasan_tag_set(page, 0xff);
 }
-#else
+
+#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
+
 static inline u8 page_kasan_tag(const struct page *page)
 {
 	return 0xff;
@@ -1445,7 +1454,8 @@ static inline u8 page_kasan_tag(const struct page *page)
 
 static inline void page_kasan_tag_set(struct page *page, u8 tag) { }
 static inline void page_kasan_tag_reset(struct page *page) { }
-#endif
+
+#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
 static inline struct zone *page_zone(const struct page *page)
 {
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a11e3e75eb08..17918bd20ed9 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -59,7 +59,7 @@ void kasan_disable_current(void)
 }
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
-void kasan_unpoison_range(const void *address, size_t size)
+void __kasan_unpoison_range(const void *address, size_t size)
 {
 	unpoison_range(address, size);
 }
@@ -87,7 +87,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 }
 #endif /* CONFIG_KASAN_STACK */
 
-void kasan_alloc_pages(struct page *page, unsigned int order)
+void __kasan_alloc_pages(struct page *page, unsigned int order)
 {
 	u8 tag;
 	unsigned long i;
@@ -101,7 +101,7 @@ void kasan_alloc_pages(struct page *page, unsigned int order)
 	unpoison_range(page_address(page), PAGE_SIZE << order);
 }
 
-void kasan_free_pages(struct page *page, unsigned int order)
+void __kasan_free_pages(struct page *page, unsigned int order)
 {
 	if (likely(!PageHighMem(page)))
 		poison_range(page_address(page),
@@ -128,8 +128,8 @@ static inline unsigned int optimal_redzone(unsigned int object_size)
 		object_size <= (1 << 16) - 1024 ? 1024 : 2048;
 }
 
-void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
-			slab_flags_t *flags)
+void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
+			  slab_flags_t *flags)
 {
 	unsigned int orig_size = *size;
 	unsigned int redzone_size;
@@ -174,7 +174,7 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 	*flags |= SLAB_KASAN;
 }
 
-size_t kasan_metadata_size(struct kmem_cache *cache)
+size_t __kasan_metadata_size(struct kmem_cache *cache)
 {
 	if (!kasan_stack_collection_enabled())
 		return 0;
@@ -197,7 +197,7 @@ struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 	return kasan_reset_tag(object) + cache->kasan_info.free_meta_offset;
 }
 
-void kasan_poison_slab(struct page *page)
+void __kasan_poison_slab(struct page *page)
 {
 	unsigned long i;
 
@@ -207,12 +207,12 @@ void kasan_poison_slab(struct page *page)
 		     KASAN_KMALLOC_REDZONE);
 }
 
-void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
+void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
 {
 	unpoison_range(object, cache->object_size);
 }
 
-void kasan_poison_object_data(struct kmem_cache *cache, void *object)
+void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
 {
 	poison_range(object,
 			round_up(cache->object_size, KASAN_GRANULE_SIZE),
@@ -265,7 +265,7 @@ static u8 assign_tag(struct kmem_cache *cache, const void *object,
 #endif
 }
 
-void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
+void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 						const void *object)
 {
 	struct kasan_alloc_meta *alloc_meta;
@@ -284,7 +284,7 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
 	return (void *)object;
 }
 
-static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
+static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 			      unsigned long ip, bool quarantine)
 {
 	u8 tag;
@@ -330,9 +330,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	return IS_ENABLED(CONFIG_KASAN_GENERIC);
 }
 
-bool kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
+bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
 {
-	return __kasan_slab_free(cache, object, ip, true);
+	return ____kasan_slab_free(cache, object, ip, true);
 }
 
 static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
@@ -340,7 +340,7 @@ static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 	kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
 }
 
-static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
+static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 				size_t size, gfp_t flags, bool keep_tag)
 {
 	unsigned long redzone_start;
@@ -375,20 +375,20 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
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
@@ -413,7 +413,7 @@ void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
 	return (void *)ptr;
 }
 
-void * __must_check kasan_krealloc(const void *object, size_t size, gfp_t flags)
+void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flags)
 {
 	struct page *page;
 
@@ -423,13 +423,13 @@ void * __must_check kasan_krealloc(const void *object, size_t size, gfp_t flags)
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
 
@@ -442,11 +442,11 @@ void kasan_poison_kfree(void *ptr, unsigned long ip)
 		}
 		poison_range(ptr, page_size(page), KASAN_FREE_PAGE);
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9f90e3c0aa840dbb4833367c2335193299f69023.1606162397.git.andreyknvl%40google.com.
