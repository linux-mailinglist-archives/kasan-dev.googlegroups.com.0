Return-Path: <kasan-dev+bncBDX4HWEMTEBRBO5N6D6QKGQEUNZYZQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 159002C1539
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:08:28 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id 100sf14474740qtf.14
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:08:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162107; cv=pass;
        d=google.com; s=arc-20160816;
        b=st6LtCOyi0JKY9PTooVyJxQUyuUwC1nsHyISYUqjxqlgDd8nfQOuRomLHmJEkD8gra
         Rz90CQ+jG0EyWizt4qbFZeXP6EXFErKMHw3GtVAURPRvKc3n/uVK+UWp11eO2QPe3Uus
         eGSY+SnTcAgiVFvvo1HXaAxDufDPzY5BsrdwM5hN50A//SJgI+9ekBFmsi2r4TtyBXMx
         9Zem01PToXO3uJ4GbdPYh12uffp9VJw7fBy65UeD0Ej/H/Hx0gyGMsQihRB+q0/wfn9O
         DBclfTwNLubcBoFh0CiU8GYWOECr4oiBBuyt/54bBG8WNEDeMfd+/D30mmPSpdYzCqFq
         YVUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=NYYgLBxev/mLk3v9XryTUDQzGFjHsTmRi+j+NGdhcbY=;
        b=CQjwmj4jbMfuFdclYbUye5H0jWyxcfxk9ViUhjgMardmrzltcz+83E724S01GIdb2D
         IWfKVU3/Lv+K4LEGZDbJO5YFPAqoq98cD2/mBm0dRWaoKbJkaX8vTvsEq7/IjGTelAjG
         TtMvsoki3RzHQxJHo+CtnfPaKwZryJkpHHnkr21KBypG0xbDSdMmz7y7ihaG+MknlXyp
         QSbo58DrKn6YJKo9ddfLZruYepBj9PZE5UxkMDABRQdqfgJucwTOxWaedwYHQZSxl2nF
         sdZ/GKZY30mGJnLt0yd9duPStTt36GD93cOOdOWnaT225dULVMais4ZDFy5yKhwDVUnp
         KzGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Avbr1YBi;
       spf=pass (google.com: domain of 3uha8xwokcds7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3uha8XwoKCds7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NYYgLBxev/mLk3v9XryTUDQzGFjHsTmRi+j+NGdhcbY=;
        b=E92XhGH6+VsgEg7XdNasU6ZZoSSPqIb+BOPFhAeYqGHDAmfyXMg4rVmoVNiv+Oqk8p
         4maetXX23TRo1pxR51u70wLNO4H3frfqOSfnxI7lEzHTtv4DS3yJysukHzfxWtjhKm9t
         iebKyyryZOfe2OWH8yBAD8+f/tIaLWd432k8PxrEIl+BcKFfdblcSyLtErEoGcG1+1T5
         JuuwcKEQGxct6yaQLsCd2Z7G5gtp6SqZcw1YcThvAe6/31He+pSx6teMBZ6EqQt3I5fr
         u8hkO4OnNKmIWWRa1ZPHhJfDJheSBeRxxeLRrAJsX3nP5QPL4eXB/Ucu+EfD333k4oEO
         zxhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NYYgLBxev/mLk3v9XryTUDQzGFjHsTmRi+j+NGdhcbY=;
        b=nG/Tl8H4cuZPwMOJ5mkruXP0LC8qDsxDZsxyj9U8s7Zx0a3L6rm5bnObBkPBE49BFN
         AGfgLatLS596koxeQ2aCKF4DVug7nrj/cbZ4rOCQioVeMyu/NkhilSc7CVZTh4PxuAVO
         IGUiAL6vA5aeKENdSIYKIMzG9t9xculgjSifd2cIIYy69Gev1qsTDFgMKZTMQQ0fXYQ8
         qGE3bRrwt0uXHO1+79EKUv7ahDaVMfA/WiuMgSTzS1emXGvOKRdgwcZREBqGHdZGrwji
         tvjh+TTP5u+RdsLV2BgzBVffzLcxJAu48Rb8AZoUnUfsDN0zBoQTEcyiBTvHzYDv0b+7
         A4Sw==
X-Gm-Message-State: AOAM531qbTbk6G2cCC8dxBu14n2qtazGfHuekmzSybfZnLfJ7GFiXCeD
	venGD0sDhBMgyyyV4P4fYkc=
X-Google-Smtp-Source: ABdhPJwTGoyViwSAhfKVSYAGExIYZmKhTgD7RpOHSTZ2+J7kDuqwlEn32a9pSdGMXH5ucdob1+kh5A==
X-Received: by 2002:a37:6c3:: with SMTP id 186mr1268016qkg.39.1606162107131;
        Mon, 23 Nov 2020 12:08:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:572:: with SMTP id p18ls7078876qkp.0.gmail; Mon, 23
 Nov 2020 12:08:26 -0800 (PST)
X-Received: by 2002:a05:620a:2e8:: with SMTP id a8mr1337988qko.144.1606162106698;
        Mon, 23 Nov 2020 12:08:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162106; cv=none;
        d=google.com; s=arc-20160816;
        b=ijHy1Wrv5Y1LwUI8cgt5Ni4oZrg/S/L8297WJIO7Si5MR07enBVnpW8asOHJCZ7loF
         3FPEld2gNjNZ9ql6+L4SAdRyRbCCNrz5dIp9kB8bQhSDoSdQja2mrs+drK0pr7AeGW/U
         /MAALYXkJpLqPpfThaMKWR93aPEyRLMZsdIxjQ2QN7K8CumpGgz/aF7MqNq0ZSSIeDUr
         MtwC5tN1bamxE7xv+1jQAioG9KTJdFiBc1Lxzmq5IF2XmBY1H5TQE1DXO58rQtChxNHJ
         PYGaed6DfoYXo8b2oF1eLtQCgWD8HA2AfX+S3r29RTYc9eMO6bl+wtcMRnT+iO3xu+0t
         hc5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=lPgNuJ7g8osGvKVBTtZcjnXRnyaRLAu+LcMmxZ/fR9s=;
        b=MrAYCoUK1l0DXsYvIeQMEyyRDwpSJW1MOkxBrUaxCFvKe26IKHqhkyJHnyN6sO54MB
         o5Q8TJzHMdAWn83rTMUUGIRwdObxyHc4cfL135jbvKtYu/3mhXalSpRi7/wokImh7h+a
         niyD4vI0wTlZLTIlsT3KkAd/ZY6QJK12MM1gbcEpJtCbTDqJVkWExCVVyqVrmIR2g3ld
         QwJjQ/UWyG+27PnZrYA8wPI9whD9brZ1k2f93ybiOgAbxiaA7IpxVny+V6JMMrl8eBbB
         x2XDIimBgTobUnwMFiCRxtYUq383QqAHogLSLkxiummjmsXqUaEqo5Wg+uuCVksKWFBu
         4dHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Avbr1YBi;
       spf=pass (google.com: domain of 3uha8xwokcds7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3uha8XwoKCds7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id g19si602557qko.1.2020.11.23.12.08.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:08:26 -0800 (PST)
Received-SPF: pass (google.com: domain of 3uha8xwokcds7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id b15so2708053qvm.10
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:08:26 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:804a:: with SMTP id
 68mr1140058qva.1.1606162106332; Mon, 23 Nov 2020 12:08:26 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:27 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <80a6fdd29b039962843bd6cf22ce2643a7c8904e.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 03/42] kasan: group vmalloc code
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Avbr1YBi;       spf=pass
 (google.com: domain of 3uha8xwokcds7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3uha8XwoKCds7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

Group all vmalloc-related function declarations in include/linux/kasan.h,
and their implementations in mm/kasan/common.c.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: Ie20b6c689203cd6de4fd7f2c465ec081c00c5f15
---
 include/linux/kasan.h | 41 +++++++++++++----------
 mm/kasan/common.c     | 78 ++++++++++++++++++++++---------------------
 2 files changed, 63 insertions(+), 56 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 30d343b4a40a..59538e795df4 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -75,19 +75,6 @@ struct kasan_cache {
 	int free_meta_offset;
 };
 
-/*
- * These functions provide a special case to support backing module
- * allocations with real shadow memory. With KASAN vmalloc, the special
- * case is unnecessary, as the work is handled in the generic case.
- */
-#ifndef CONFIG_KASAN_VMALLOC
-int kasan_module_alloc(void *addr, size_t size);
-void kasan_free_shadow(const struct vm_struct *vm);
-#else
-static inline int kasan_module_alloc(void *addr, size_t size) { return 0; }
-static inline void kasan_free_shadow(const struct vm_struct *vm) {}
-#endif
-
 int kasan_add_zero_shadow(void *start, unsigned long size);
 void kasan_remove_zero_shadow(void *start, unsigned long size);
 
@@ -156,9 +143,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 	return false;
 }
 
-static inline int kasan_module_alloc(void *addr, size_t size) { return 0; }
-static inline void kasan_free_shadow(const struct vm_struct *vm) {}
-
 static inline int kasan_add_zero_shadow(void *start, unsigned long size)
 {
 	return 0;
@@ -211,13 +195,16 @@ static inline void *kasan_reset_tag(const void *addr)
 #endif /* CONFIG_KASAN_SW_TAGS */
 
 #ifdef CONFIG_KASAN_VMALLOC
+
 int kasan_populate_vmalloc(unsigned long addr, unsigned long size);
 void kasan_poison_vmalloc(const void *start, unsigned long size);
 void kasan_unpoison_vmalloc(const void *start, unsigned long size);
 void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
-#else
+
+#else /* CONFIG_KASAN_VMALLOC */
+
 static inline int kasan_populate_vmalloc(unsigned long start,
 					unsigned long size)
 {
@@ -232,7 +219,25 @@ static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long end,
 					 unsigned long free_region_start,
 					 unsigned long free_region_end) {}
-#endif
+
+#endif /* CONFIG_KASAN_VMALLOC */
+
+#if defined(CONFIG_KASAN) && !defined(CONFIG_KASAN_VMALLOC)
+
+/*
+ * These functions provide a special case to support backing module
+ * allocations with real shadow memory. With KASAN vmalloc, the special
+ * case is unnecessary, as the work is handled in the generic case.
+ */
+int kasan_module_alloc(void *addr, size_t size);
+void kasan_free_shadow(const struct vm_struct *vm);
+
+#else /* CONFIG_KASAN && !CONFIG_KASAN_VMALLOC */
+
+static inline int kasan_module_alloc(void *addr, size_t size) { return 0; }
+static inline void kasan_free_shadow(const struct vm_struct *vm) {}
+
+#endif /* CONFIG_KASAN && !CONFIG_KASAN_VMALLOC */
 
 #ifdef CONFIG_KASAN_INLINE
 void kasan_non_canonical_hook(unsigned long addr);
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 578d34b12a21..f5739be60edc 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -555,44 +555,6 @@ void kasan_kfree_large(void *ptr, unsigned long ip)
 	/* The object will be poisoned by page_alloc. */
 }
 
-#ifndef CONFIG_KASAN_VMALLOC
-int kasan_module_alloc(void *addr, size_t size)
-{
-	void *ret;
-	size_t scaled_size;
-	size_t shadow_size;
-	unsigned long shadow_start;
-
-	shadow_start = (unsigned long)kasan_mem_to_shadow(addr);
-	scaled_size = (size + KASAN_SHADOW_MASK) >> KASAN_SHADOW_SCALE_SHIFT;
-	shadow_size = round_up(scaled_size, PAGE_SIZE);
-
-	if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
-		return -EINVAL;
-
-	ret = __vmalloc_node_range(shadow_size, 1, shadow_start,
-			shadow_start + shadow_size,
-			GFP_KERNEL,
-			PAGE_KERNEL, VM_NO_GUARD, NUMA_NO_NODE,
-			__builtin_return_address(0));
-
-	if (ret) {
-		__memset(ret, KASAN_SHADOW_INIT, shadow_size);
-		find_vm_area(addr)->flags |= VM_KASAN;
-		kmemleak_ignore(ret);
-		return 0;
-	}
-
-	return -ENOMEM;
-}
-
-void kasan_free_shadow(const struct vm_struct *vm)
-{
-	if (vm->flags & VM_KASAN)
-		vfree(kasan_mem_to_shadow(vm->addr));
-}
-#endif
-
 #ifdef CONFIG_MEMORY_HOTPLUG
 static bool shadow_mapped(unsigned long addr)
 {
@@ -704,6 +666,7 @@ core_initcall(kasan_memhotplug_init);
 #endif
 
 #ifdef CONFIG_KASAN_VMALLOC
+
 static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 				      void *unused)
 {
@@ -942,4 +905,43 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 				       (unsigned long)shadow_end);
 	}
 }
+
+#else /* CONFIG_KASAN_VMALLOC */
+
+int kasan_module_alloc(void *addr, size_t size)
+{
+	void *ret;
+	size_t scaled_size;
+	size_t shadow_size;
+	unsigned long shadow_start;
+
+	shadow_start = (unsigned long)kasan_mem_to_shadow(addr);
+	scaled_size = (size + KASAN_SHADOW_MASK) >> KASAN_SHADOW_SCALE_SHIFT;
+	shadow_size = round_up(scaled_size, PAGE_SIZE);
+
+	if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
+		return -EINVAL;
+
+	ret = __vmalloc_node_range(shadow_size, 1, shadow_start,
+			shadow_start + shadow_size,
+			GFP_KERNEL,
+			PAGE_KERNEL, VM_NO_GUARD, NUMA_NO_NODE,
+			__builtin_return_address(0));
+
+	if (ret) {
+		__memset(ret, KASAN_SHADOW_INIT, shadow_size);
+		find_vm_area(addr)->flags |= VM_KASAN;
+		kmemleak_ignore(ret);
+		return 0;
+	}
+
+	return -ENOMEM;
+}
+
+void kasan_free_shadow(const struct vm_struct *vm)
+{
+	if (vm->flags & VM_KASAN)
+		vfree(kasan_mem_to_shadow(vm->addr));
+}
+
 #endif
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/80a6fdd29b039962843bd6cf22ce2643a7c8904e.1606161801.git.andreyknvl%40google.com.
