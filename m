Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNULXT6QKGQEYGQ3URI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 987312B27FA
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:16:23 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id x131sf4577441oif.1
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:16:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305782; cv=pass;
        d=google.com; s=arc-20160816;
        b=t8Y3sRw/JE7wfeq/VIQ5pBzZkhYO/kzRssQqIOL/Qw8F1rHPIEMrjod7KuO3xObl9G
         pfdqqiaL08msYaeHeg4ACGDufvBoTHkHzM5SqaVhvxDA0FOnR1aa9yeG9D2gcWBxojlz
         Xy0dttD25lPbjGFvwH3sXSUxdvislPp8H/MryHUNWdCeFj4gc8OxcDE5tOcuYszQFrWK
         m55wBbCVMjYF4P84P6RttG10jAIwW7GETWbehNj6x17IV+Gz6KhbmhIm6/wrJs8dAU3x
         kP+pFBhBoEnA/4PJHnPwJbh/0Bt5lqLJZe6jfG9JZmLwvTQ5Kt5mfy6e1RwqYZte2a0p
         l7SA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=opKp6hX5xThY4RhytwkfyZ9EsLvTme0VUmxaizoUhBg=;
        b=TxXnY50YLema31Jzea3BazMcADS4dtAN7+czIai3ygzrP3WLYjeohy16Y1DaU8n2BI
         akmHzmDlw4bNR7u+5If0F7cjGs+evBf5aCHdLClwGmYjuwuEzhrJxPmFSMGjpu/Si3rm
         Y+N5eSxm6HiUqCHa/GxQuchoY4v0BnNoj4TOhRj4UD2AZs/154nbOkaZTYinUz7bAtyI
         Z1bkwUAtVlvwCNr48QqxUUNLbbOyNQcfRVAXRl3ZKkO1uENmdmzZMGMEV2M+BEPPQiS4
         ShLVWP11T2+iEt8JxU+qydH1rV5A2am551iO8MA7Vzp+4si/qT+2Wa2FWcq7LMZuvLkD
         HzYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=K8qhPHlp;
       spf=pass (google.com: domain of 3tqwvxwokcyaerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3tQWvXwoKCYAerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=opKp6hX5xThY4RhytwkfyZ9EsLvTme0VUmxaizoUhBg=;
        b=ho9M6U+ObiWr5zYVUxyH4DD4lC4yxuc/ViQfxCuLsNfY8RD+m5RzMqtYvtrX9CTzHR
         /PDQIW6WX1TdkOtBHbiB3O9Y26KvEnpRakkK+9Os4Ihdng3fZRdB5OueF/PzocP3bDSR
         N2kUT0gaQng26yD6Tg0w8kgbbAgOAdAaC4UYJNLkTnUHu+i8zwOi7SvGvWGTnjHyhzL8
         85lSSZTWBO91PC9DVq3Rcqjn+woy9clrUruMJnZej49OutVuL7RFbCv4aibyj8e5rGq2
         vj+dSDivgS7a0Kp3zb2cIIRznDl6fQYqkh4a1c8UB7cGyY+JUh+n4T5zZMe3VhRGKGg+
         jPRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=opKp6hX5xThY4RhytwkfyZ9EsLvTme0VUmxaizoUhBg=;
        b=hEEJqxHL69p/5BqUhDb7PCYVOQsERNZvX5Dum9+DlmNXTQaSlH+WtWHu3VMFjJY4pt
         xLWWpnj1u0hFKBIztnVCmAXbyA1NmvIyVu0rurOi5hqhErwrgk6whBBDpJdx0XlOyTVz
         SHzjiXz3eP70tfMrxBMZv4CRNnAZno+805RAwLInfGnR7aQqW54NIRvh+aghlrx2HBUC
         iPqIXLXmOktFK6cSGGv18iDJFU+h24RB5M8EP5WiX3HWdhiDfnNqWYzs3xCsgyyYftHn
         YWLe2u4O060ZL/vhQjIAkQkn19GogZBdz8Dc2zRKhwKLGzpgCoEHRnemf5hj6CD899Ku
         TnuA==
X-Gm-Message-State: AOAM5318NbyS+QNblT/OjPhC2mO62ta8Oajjxt9bS0n7AXO9N0h718qk
	lhTWq0n1mCPEiym5CSMtUZc=
X-Google-Smtp-Source: ABdhPJxW8tU+4tddr8o9c7TsJM18z3p5CMZCjPEZV/IK8BORmPXzbPaND2wBEbI/VH1v+/v1AbiHSg==
X-Received: by 2002:aca:5944:: with SMTP id n65mr3000137oib.80.1605305782552;
        Fri, 13 Nov 2020 14:16:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:198c:: with SMTP id k12ls1920096otk.3.gmail; Fri, 13 Nov
 2020 14:16:22 -0800 (PST)
X-Received: by 2002:a9d:4b81:: with SMTP id k1mr3158021otf.371.1605305782163;
        Fri, 13 Nov 2020 14:16:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305782; cv=none;
        d=google.com; s=arc-20160816;
        b=ip5A/gogoXOZq6oU4bdLndkP7lRk1f1t/9ZMB8YyDI8J3gr//Df2NIwtzB0pzTjp7+
         xDhqs1tFQKfPrQf8Tz5dV5/GkRHuKC12k+c6SwdY0FGJtooFMn50B/s2StKhPZ/ttNTt
         1je6EUJY/LP9p3ugZZghXrJpP23YOnrG8zqHEN9zg1EFMV1x2UVhvNBe8tcnb5/yzUui
         s69twRNhs+MmbnAgzMUQJ37rev1/A8ZFblUmtLyY6pez/22W8nDendpLYlFghFfx2KrH
         ZxkfbWASQJUQCDntI1l9KB0qpcyFeWtzESfDhtWUppTEkz/8slzFsWIvB2Dxvx+GYk1s
         cdaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=TDaX+ddMLh38t5Wib3wuvab4pTYPP2sulDt0VX0nIrU=;
        b=U7b3aRtdk6pcbl/HsUZ48GEMGHk688nK2+I3c75E6IkbgiDz2vLZmalwxT2AAs6Gpk
         /SwnNUvjM3YbjXL/A3zjQGgoF+kfgTO18fcWFDggrmhyWtIJiV78baHp/wHBba/trFGx
         nS2usYdG65K2J2DC4JYRwD/D9cqb0+qrWBji0zZtLNNb9l4OgWZYlPqeg8wvrkpF9Ov6
         hGcCrfDtrlpgcyDFiK4ynvujxRX195pkvlfC+tOPOhbsSyVClHepH15SgfWqJ0Qk656N
         LBCWZIlEmFdFUQUq+K9SFzTF+u9BcdstQqs4gdBgTgdYS7rJM3e8+V8tGhOEg7U/8sUw
         lpIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=K8qhPHlp;
       spf=pass (google.com: domain of 3tqwvxwokcyaerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3tQWvXwoKCYAerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id d20si1020661oti.1.2020.11.13.14.16.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:16:22 -0800 (PST)
Received-SPF: pass (google.com: domain of 3tqwvxwokcyaerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id c71so6085464qkg.21
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:16:22 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4721:: with SMTP id
 l1mr4446952qvz.30.1605305781661; Fri, 13 Nov 2020 14:16:21 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:31 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <62b55eaabb9bfb642989413fee2b9cd780b046ce.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 03/42] kasan: group vmalloc code
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
 header.i=@google.com header.s=20161025 header.b=K8qhPHlp;       spf=pass
 (google.com: domain of 3tqwvxwokcyaerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3tQWvXwoKCYAerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
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
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/62b55eaabb9bfb642989413fee2b9cd780b046ce.1605305705.git.andreyknvl%40google.com.
