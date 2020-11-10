Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSVEVT6QKGQE5XQS4IY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 81DCD2AE331
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:20:59 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id y14sf86301lfl.7
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:20:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046859; cv=pass;
        d=google.com; s=arc-20160816;
        b=z00NcU4YzFOqtFsEANoOFeAoDxqU4iGRs/AMXNjlB/0RrHvyqymdC8kPzDmJ/RDI9e
         AO++Yn3lxF8vHrViYtidHW1udmpx/YuUZkjppxiWW1ENV7AJApZHVI1majRpSDtLNUVQ
         vHAXleAUboAhfRNTft0I6ek90slEgH34+xMrBDtmB9OtNbgqiiF6d7nyJxvOoc71PxID
         QkjHmYD2NWIYU5I3gmJe3laK/O6CZKHDYZo0s5cLpCkAwFX6ydASCjWPDRvy30Zc4IGT
         PsM3zl9PkGfOfpuPNgd3fqoOkmNY454m86xP1TE0AwZj5GG3mNAJzISt5HW6R55cvxu/
         x+hQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=8vNrwF5Dl8CkPvytmARFAl8295PmuUeiu05A84CHgsY=;
        b=TxE8WSEsrpWSxAMhSsL2xZldCldkcCD22kVtMOk8k+lzcDt+JjRrB1KtkAXptWEfGn
         pn9O+YJiBOQA98tsYLeoqGBJ/ZWe1HUwX3irR/wm04WlBLu4/tdhsGAptMBj3wSm2R/v
         VsWqd39rAx7leQ17PyxZNTV8idQarHqRutedaWzQrMGSpRrm1z+ZguO0mA0zvKXs/Hta
         JV75UzL45wDP0n97Zi7AEpVp8tENDo72W+ldXVIuNFeYZT+bCahJ0MVSMQmZkgovWnFx
         1/zyDzfO8JhtA5biBLTwEh1Kz9UKIzmZTaLc7o9enjSFHdej3EA6n3wCv7zJENM5jU7I
         T8yA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pkAAotds;
       spf=pass (google.com: domain of 3srkrxwokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3SRKrXwoKCR44H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8vNrwF5Dl8CkPvytmARFAl8295PmuUeiu05A84CHgsY=;
        b=rv38s5oxq9Xtk/x+zBGaSt3Dalp4HcrKI0K75A3qfEvmVJhsxQReL5a7dqKms5NntC
         A7ow6ceas5fPqrhXf6DZxNsVYDW5ynncOagAU/YfVFphHlA60FtL5Rde+f8jtCuN+Mzm
         i9JnJ0c5eLl9UR81qCTExfI/TBRTZtonUja+Mi5ogqr3B6pJQYnf0wD++MbLXl5Y37fW
         h8w1221jR6R6nXZbjQFzjMhvw1Edj0HgitjzKHDA4F5qAaLGp+ISK91/nI41Gj9vh8m9
         Ani0QX1KDr2zpfa3uumt0mRgylvmUC/3uFIzewFLseGpJXGK72p484HbroKK8zc0oCMl
         7ocw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8vNrwF5Dl8CkPvytmARFAl8295PmuUeiu05A84CHgsY=;
        b=Po2hyflnXbbsWjDPszN3LuaErkuGy2v+DAFpykh+J0VbXBdTJJatnFZH1HbdKU3Aws
         T0HyqGY0SxUtYhAT+LHcq8OFu0Ll0b3mh5w0IA0A8sVzgNLyKTG9nDWm5yOHPGJC6CcB
         VzzhQQtnba5+YvfrOH4UGpszFdkp0PZ2OpAe1meLG9hPucKjMQ7YAQEKpB7LgXSL+W+E
         gvMLtCY/ce/RbOvuki94I1nq/M40KQeTKNH08UBThbXuweCST54OZZInlX+ui4MlXq/j
         mIvhREe+gr5/g+zmc3wRKeVxGqdX2a1vrEvN4byaJ51+Y0g3HYiNTKduBnt2iGzlDwvO
         CRjg==
X-Gm-Message-State: AOAM530O//2SVYiMmwCaNIgxuJsm3OcJokA3aPYwTVt8lsqKQmkZ1tPO
	fKVzsAJaBecKXvS9UDrvu9U=
X-Google-Smtp-Source: ABdhPJyvqE98oIYt9HAgJfCWPxB81kq93MBTWXM4AwnNHjjz3iygooi/sW0yR2AS/ofh4DWLePMZ0g==
X-Received: by 2002:ac2:4ac4:: with SMTP id m4mr5416927lfp.339.1605046859100;
        Tue, 10 Nov 2020 14:20:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9908:: with SMTP id v8ls264468lji.1.gmail; Tue, 10 Nov
 2020 14:20:58 -0800 (PST)
X-Received: by 2002:a05:651c:545:: with SMTP id q5mr5325641ljp.124.1605046858049;
        Tue, 10 Nov 2020 14:20:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046858; cv=none;
        d=google.com; s=arc-20160816;
        b=fHlIIbKRa5MDdIFEsP1nS7Zhbl8UvLkiq0Y7Au2bsB9z/xEZHwVnfQ9izslxqdiLeB
         a5/qatNc7RjZpzPUAjIw6UlLq3f2tDfmzUxcnQQKDZYTeI/ihlrFP6A2fAiZRDRA3ahF
         qpvvg9qd6Uf6CJhHp8mswv5jfJFXH7IMY8ksrUAilr7b+dcebbW4O+jGoaDj5sa2b0rG
         2A+FtncwEmr7MCQkLXO+zvD7u65X4TpeVWl/ZPhLihBFk6oAPk/ceoU7BtRmKce5grCY
         QivoT0Kc+r3jhN3lHYZXjlBxkcY2uFIEeDpKaeiZaypKlvQt/RRnXuo8CvFmM7rdGudU
         XGxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=o1/1nos0zFZPL9mIFzV6FCy+ZXGKjAVVVyDw35QavK4=;
        b=hk5lNLYX8ZsJm6ZaqshnqFJQZoLS2oRoOzY2X0dQSS2zKmNYsZyVZk4xOzTpuqGfCv
         axQeD1CIn0fjJCl+2/3jH3OmsgXzqQUYtNEvxmZ9oA+siSoVHrzUaBoQwFiL94Gn4NW+
         6t3HKN8+q0ZeC5CpAhnF/YdcY4o5E/nNKR/5khTqhC+0dhbTF28sXHW9zhqppsyXH9Nl
         QwHZ/Q3G+d3o+ELmXOtWYY6iaZ9Vq00ndGm50c/WSx57ugU8QuoPeomAPTVbxYR8c9/R
         pCENmUjTBMEl49V+PNWP55T8U9CAmVCpvqZXUPFSqpHhYAzg34So+GMw/ligPCaGdA5z
         eYmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pkAAotds;
       spf=pass (google.com: domain of 3srkrxwokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3SRKrXwoKCR44H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id m18si4111lfr.11.2020.11.10.14.20.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:20:58 -0800 (PST)
Received-SPF: pass (google.com: domain of 3srkrxwokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id e15so1235331wme.4
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:20:58 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6000:10e:: with SMTP id
 o14mr26646190wrx.225.1605046857657; Tue, 10 Nov 2020 14:20:57 -0800 (PST)
Date: Tue, 10 Nov 2020 23:20:16 +0100
In-Reply-To: <cover.1605046662.git.andreyknvl@google.com>
Message-Id: <22c1a837d4d0c0b241a700c88f180f5e831a1953.1605046662.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v2 12/20] kasan, mm: check kasan_enabled in annotations
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pkAAotds;       spf=pass
 (google.com: domain of 3srkrxwokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3SRKrXwoKCR44H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
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
 include/linux/kasan.h | 220 ++++++++++++++++++++++++++++++++----------
 include/linux/mm.h    |  22 +++--
 mm/kasan/common.c     |  60 ++++++------
 3 files changed, 216 insertions(+), 86 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index f1a5042ae4fc..779f8e703982 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -2,6 +2,7 @@
 #ifndef _LINUX_KASAN_H
 #define _LINUX_KASAN_H
 
+#include <linux/jump_label.h>
 #include <linux/types.h>
 
 struct kmem_cache;
@@ -74,56 +75,179 @@ static inline void kasan_disable_current(void) {}
 
 #ifdef CONFIG_KASAN
 
-void kasan_alloc_pages(struct page *page, unsigned int order);
-void kasan_free_pages(struct page *page, unsigned int order);
+struct kasan_cache {
+	int alloc_meta_offset;
+	int free_meta_offset;
+};
 
-void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
-			slab_flags_t *flags);
+#ifdef CONFIG_KASAN_HW_TAGS
+DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
+static inline kasan_enabled(void)
+{
+	return static_branch_likely(&kasan_flag_enabled);
+}
+#else
+static inline kasan_enabled(void)
+{
+	return true;
+}
+#endif
 
-void kasan_unpoison_data(const void *address, size_t size);
-void kasan_unpoison_slab(const void *ptr);
+void __kasan_alloc_pages(struct page *page, unsigned int order);
+static inline void kasan_alloc_pages(struct page *page, unsigned int order)
+{
+	if (kasan_enabled())
+		__kasan_alloc_pages(page, order);
+}
 
-void kasan_poison_slab(struct page *page);
-void kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
-void kasan_poison_object_data(struct kmem_cache *cache, void *object);
-void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
-					const void *object);
+void __kasan_free_pages(struct page *page, unsigned int order);
+static inline void kasan_free_pages(struct page *page, unsigned int order)
+{
+	if (kasan_enabled())
+		__kasan_free_pages(page, order);
+}
 
-void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
-						gfp_t flags);
-void kasan_kfree_large(void *ptr, unsigned long ip);
-void kasan_poison_kfree(void *ptr, unsigned long ip);
-void * __must_check kasan_kmalloc(struct kmem_cache *s, const void *object,
-					size_t size, gfp_t flags);
-void * __must_check kasan_krealloc(const void *object, size_t new_size,
-					gfp_t flags);
+void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
+				slab_flags_t *flags);
+static inline void kasan_cache_create(struct kmem_cache *cache,
+			unsigned int *size, slab_flags_t *flags)
+{
+	if (kasan_enabled())
+		__kasan_cache_create(cache, size, flags);
+}
 
-void * __must_check kasan_slab_alloc(struct kmem_cache *s, void *object,
-					gfp_t flags);
-bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
+size_t __kasan_metadata_size(struct kmem_cache *cache);
+static inline size_t kasan_metadata_size(struct kmem_cache *cache)
+{
+	if (kasan_enabled())
+		return __kasan_metadata_size(cache);
+	return 0;
+}
 
-struct kasan_cache {
-	int alloc_meta_offset;
-	int free_meta_offset;
-};
+void __kasan_unpoison_data(const void *addr, size_t size);
+static inline void kasan_unpoison_data(const void *addr, size_t size)
+{
+	if (kasan_enabled())
+		__kasan_unpoison_data(addr, size);
+}
+
+void __kasan_unpoison_slab(const void *ptr);
+static inline void kasan_unpoison_slab(const void *ptr)
+{
+	if (kasan_enabled())
+		__kasan_unpoison_slab(ptr);
+}
+
+void __kasan_poison_slab(struct page *page);
+static inline void kasan_poison_slab(struct page *page)
+{
+	if (kasan_enabled())
+		return __kasan_poison_slab(page);
+}
+
+void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
+static inline void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
+{
+	if (kasan_enabled())
+		return __kasan_unpoison_object_data(cache, object);
+}
+
+void __kasan_poison_object_data(struct kmem_cache *cache, void *object);
+static inline void kasan_poison_object_data(struct kmem_cache *cache, void *object)
+{
+	if (kasan_enabled())
+		__kasan_poison_object_data(cache, object);
+}
+
+void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
+					  const void *object);
+static inline void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
+						      const void *object)
+{
+	if (kasan_enabled())
+		return __kasan_init_slab_obj(cache, object);
+	return (void *)object;
+}
+
+bool __kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
+static inline bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip)
+{
+	if (kasan_enabled())
+		return __kasan_slab_free(s, object, ip);
+	return false;
+}
+
+void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
+				       void *object, gfp_t flags);
+static inline void * __must_check kasan_slab_alloc(struct kmem_cache *s,
+						   void *object, gfp_t flags)
+{
+	if (kasan_enabled())
+		return __kasan_slab_alloc(s, object, flags);
+	return object;
+}
 
-size_t kasan_metadata_size(struct kmem_cache *cache);
+void * __must_check __kasan_kmalloc(struct kmem_cache *s, const void *object,
+				    size_t size, gfp_t flags);
+static inline void * __must_check kasan_kmalloc(struct kmem_cache *s, const void *object,
+						size_t size, gfp_t flags)
+{
+	if (kasan_enabled())
+		return __kasan_kmalloc(s, object, size, flags);
+	return (void *)object;
+}
+
+void * __must_check __kasan_kmalloc_large(const void *ptr,
+					  size_t size, gfp_t flags);
+static inline void * __must_check kasan_kmalloc_large(const void *ptr,
+						      size_t size, gfp_t flags)
+{
+	if (kasan_enabled())
+		return __kasan_kmalloc_large(ptr, size, flags);
+	return (void *)ptr;
+}
+
+void * __must_check __kasan_krealloc(const void *object,
+				     size_t new_size, gfp_t flags);
+static inline void * __must_check kasan_krealloc(const void *object,
+						 size_t new_size, gfp_t flags)
+{
+	if (kasan_enabled())
+		return __kasan_krealloc(object, new_size, flags);
+	return (void *)object;
+}
+
+void __kasan_poison_kfree(void *ptr, unsigned long ip);
+static inline void kasan_poison_kfree(void *ptr, unsigned long ip)
+{
+	if (kasan_enabled())
+		__kasan_poison_kfree(ptr, ip);
+}
+
+void __kasan_kfree_large(void *ptr, unsigned long ip);
+static inline void kasan_kfree_large(void *ptr, unsigned long ip)
+{
+	if (kasan_enabled())
+		__kasan_kfree_large(ptr, ip);
+}
 
 bool kasan_save_enable_multi_shot(void);
 void kasan_restore_multi_shot(bool enabled);
 
 #else /* CONFIG_KASAN */
 
+static inline kasan_enabled(void)
+{
+	return false;
+}
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
@@ -134,36 +258,32 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
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
index 0793d03a4183..8d84a6b2fa3c 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -31,6 +31,7 @@
 #include <linux/sizes.h>
 #include <linux/sched.h>
 #include <linux/pgtable.h>
+#include <linux/kasan.h>
 
 struct mempolicy;
 struct anon_vma;
@@ -1414,22 +1415,30 @@ static inline bool cpupid_match_pid(struct task_struct *task, int cpupid)
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
@@ -1437,7 +1446,8 @@ static inline u8 page_kasan_tag(const struct page *page)
 
 static inline void page_kasan_tag_set(struct page *page, u8 tag) { }
 static inline void page_kasan_tag_reset(struct page *page) { }
-#endif
+
+#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
 static inline struct zone *page_zone(const struct page *page)
 {
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index efad5ed6a3bd..385863eaec2c 100644
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
@@ -168,7 +168,7 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 	*flags |= SLAB_KASAN;
 }
 
-size_t kasan_metadata_size(struct kmem_cache *cache)
+size_t __kasan_metadata_size(struct kmem_cache *cache)
 {
 	if (!kasan_stack_collection_enabled())
 		return 0;
@@ -191,17 +191,17 @@ struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 	return kasan_reset_tag(object) + cache->kasan_info.free_meta_offset;
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
 
@@ -211,12 +211,12 @@ void kasan_poison_slab(struct page *page)
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
@@ -269,7 +269,7 @@ static u8 assign_tag(struct kmem_cache *cache, const void *object,
 #endif
 }
 
-void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
+void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 						const void *object)
 {
 	struct kasan_alloc_meta *alloc_meta;
@@ -288,7 +288,7 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
 	return (void *)object;
 }
 
-static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
+static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 			      unsigned long ip, bool quarantine)
 {
 	u8 tag;
@@ -331,9 +331,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	return IS_ENABLED(CONFIG_KASAN_GENERIC);
 }
 
-bool kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
+bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
 {
-	return __kasan_slab_free(cache, object, ip, true);
+	return ____kasan_slab_free(cache, object, ip, true);
 }
 
 static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
@@ -341,7 +341,7 @@ static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 	kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
 }
 
-static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
+static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 				size_t size, gfp_t flags, bool keep_tag)
 {
 	unsigned long redzone_start;
@@ -373,20 +373,20 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
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
@@ -411,7 +411,7 @@ void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
 	return (void *)ptr;
 }
 
-void * __must_check kasan_krealloc(const void *object, size_t size, gfp_t flags)
+void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flags)
 {
 	struct page *page;
 
@@ -421,13 +421,13 @@ void * __must_check kasan_krealloc(const void *object, size_t size, gfp_t flags)
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
 
@@ -440,11 +440,11 @@ void kasan_poison_kfree(void *ptr, unsigned long ip)
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/22c1a837d4d0c0b241a700c88f180f5e831a1953.1605046662.git.andreyknvl%40google.com.
