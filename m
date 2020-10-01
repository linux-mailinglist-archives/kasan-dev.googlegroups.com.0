Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7GD3H5QKGQEZBTYARY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 62377280AEF
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:10:53 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 20sf47792lfg.23
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:10:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593853; cv=pass;
        d=google.com; s=arc-20160816;
        b=hhPOSlxCV9pyIVMgHbqha2uhZJYiYGm807TPHxe+inNn8Gx2Kr9hcME63KTcMPkaPo
         sj6a+eyERER6BYPaeMkraiH2BL6SuTMc4UvcWzCmnEzyWhmI6nWVCKUCnPpmrw0tQghM
         n4l1Pl/XSRp9Fx2DlCiu6G+9fTE/eBXxHFCD98BhZc9qSUSElj5+4wh4XnFWAIBRBYbc
         cTUwZrAWbTHZnrfCFkno8J8BFYP6bvOkJTC/P0SzLnyy8ggIGTOANkoeE0bZqG2ApMS0
         RJcuC4nz+d8znBlnNJceAmgrZlC3IeYo0/mfuLxrGsBI1DPMoITPFrR1VQsKLegPHg0U
         rPEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Bt+qbupgAcM0EJb9Ge8zKTEjDOZUH5MUAxiCt9vC+kE=;
        b=Ey5UJgL0VuyK5nc5+kbFWasoCtL6xHUyhIxjzr7mNm6t0W20cDE5ggRoPnfPT2exOJ
         oOwLsaE8wRNasGD4UMy6SSBQzpDxiq54VqRylXFg3l+6DRDe9BG1av7Rs2inwMhh1R67
         gdTBemQSE5+WRPMzlzOty4jir9+BGOEyVe53Ad0TAMNINEOMBxH0FZCvAdw6G2JOEhJc
         HcKO0bIYUBsmB/+6qwLXS6yk2eNFMeJQqla1QY8Xtcmxd5NnXJpZ20MxvCSp4zGdD8/n
         nh6wV5WY6YBGKivKQO42tbwFmErGIPzTVlLUMd9ORvyjsl5EOIr63/Pf7sbw6VswStl+
         2pVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lLK156o2;
       spf=pass (google.com: domain of 3-2f2xwokczo4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3-2F2XwoKCZo4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Bt+qbupgAcM0EJb9Ge8zKTEjDOZUH5MUAxiCt9vC+kE=;
        b=isLv8i3a9LqePOC4Xc7LtAMvb1xn/oyt0akAf5MfMZiCwejzWDJUzeMjkbLDxqB9Gs
         mOwXy++HnE0Iybo+fj/yrCHdC53rOq4zj8aoW2H8GQVIb2c3sSit0bsMlwiYehwBr0Go
         xitDWkywmlXKk32D93m5j0j8Yfvv/XcrvRAcn9L9n7yhpyxKy2kSik9BXdOWHLtNF8gT
         xX6fzXYDu/vhdvY6hZukSj5PxM8CoEsJa7pOpsMkfuoKoQo5DMTyaQlGBZY/3oLcvNdg
         D6qvg+/XLFqPlOR9gg5tcyj9EQc9OpvxMiQ5UXzexByMQ3HUrcRyz3WgWOtWVdZGcOR7
         muCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Bt+qbupgAcM0EJb9Ge8zKTEjDOZUH5MUAxiCt9vC+kE=;
        b=aVR1GkliJoL1r+Gf4Y9Eejx0cKZMWRHsZfKjsRqi7bHPHftrjhNf7Ug++WeTMDGiZm
         PD9RZG5TNH66K9SJ51En030Nsx0jUPDW4wgQRCaEmRcibn8kldopH82gS1wtRuys8Of1
         g6eFpO91KZX3mHAHBRmW4pEBr/WI+dFFu3nbxIzQRD5XocDeVa1MMGE0ivuQmmLErWQB
         IA5U9DzsKnmtz9tNbEZ+AE2cMkc+J5cYRL5zYLQ+ed2fFuHyiI0/mgerkTvtQcjTIhPa
         WGun815RNlrgSDTgRMgB5+ZO994kkfPlynY5Uo/+Mobi7wkIBzPy48LaSa1M94uYJ+hp
         3LJw==
X-Gm-Message-State: AOAM533y8AeDUp2aT1rdoxjUFCJ1s5CZdGzjX+0E/jkvVCwAHQJ6Deix
	sJOT2a62/5gZvgbjTFH2egc=
X-Google-Smtp-Source: ABdhPJxPb6e97ltLjTNZUzZhiMb5R2EqSLvvqbYyCuH9XPF/DxtJc3UEe8NW+3UBZy+PuFHrr80I4g==
X-Received: by 2002:a2e:9b02:: with SMTP id u2mr3385151lji.303.1601593852918;
        Thu, 01 Oct 2020 16:10:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:86c8:: with SMTP id n8ls1071121ljj.1.gmail; Thu, 01 Oct
 2020 16:10:52 -0700 (PDT)
X-Received: by 2002:a2e:b00e:: with SMTP id y14mr2860800ljk.427.1601593852036;
        Thu, 01 Oct 2020 16:10:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593852; cv=none;
        d=google.com; s=arc-20160816;
        b=DyPbgbW+5gxYbiD38F9MuUI2XICsCXDMkv/rJqcZuZFtQZcOilVufKamlFrjs4QVt3
         h74lwk4fttymnDEgniWSpCX1lXqxxsD1oYOxRgNhLM2/3e7/uxCDd18U5e8PHqOGFSyS
         4a2p8l5gvnuDOVn/Atubp9WtvqW4NP2vbIJwYb+RiLBUP3LzVzK4mkkzjF3wSAtPgfEe
         dZJogeiq50mbBSOJmqZHC6IqsxhJvB+bni9jjwiAF1qb/NkKLGsdqTUWMRwymGPHn86f
         Nsn2aRYbI/WC0nJUBRJBYKXxITmC7HURzYgSlySrEk1RHkqPk7Jopiq00oso/uHb61l3
         G4Pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=vEdvtaim2+A9VptC1VB9MgtNlk8EGvB8Qh1XAtSBRGw=;
        b=FSFqklWVOkd38KGOA72narmBLWhOAHyGRSBtqUC3nIcZJa3OHXjVloCR/YifbzA5oq
         r68ykuGarqnDG1vAo9Ixq/fjcxLMKTCH9VMjD9WRknbK1d/k03CDnIxF45Io+YwBn0p/
         xeHGJCTzgHfLM11V4tS2knBtbqyE7EbkdJwT2Gr5hdPoscV9hAbS0eHSOpDDJ55kxhBb
         yFRsDCFMKQi0aE8oFeTQZtQtOxX+On1PakfAw6awDT61VLLWKzqBX5qrYvdY3Hlvepms
         2Kr+1JAezyNh0FVEQaLUt1n4B+scs2Y4t8KbrO3C/6USRjbR6d/Ny3WUHoAjWdBVgmvI
         L5rg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lLK156o2;
       spf=pass (google.com: domain of 3-2f2xwokczo4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3-2F2XwoKCZo4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id f23si219425ljg.8.2020.10.01.16.10.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:10:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-2f2xwokczo4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id g16so166273edy.22
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:10:52 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a50:fb98:: with SMTP id
 e24mr10723448edq.130.1601593851505; Thu, 01 Oct 2020 16:10:51 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:04 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <cfdad0fc55c5a8b3a879627e2d20a0459a35af3f.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 03/39] kasan: group vmalloc code
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lLK156o2;       spf=pass
 (google.com: domain of 3-2f2xwokczo4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3-2F2XwoKCZo4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: Ie20b6c689203cd6de4fd7f2c465ec081c00c5f15
---
 include/linux/kasan.h | 41 +++++++++++++----------
 mm/kasan/common.c     | 78 ++++++++++++++++++++++---------------------
 2 files changed, 63 insertions(+), 56 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 087fba34b209..bd5b4965a269 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -69,19 +69,6 @@ struct kasan_cache {
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
 
@@ -150,9 +137,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 	return false;
 }
 
-static inline int kasan_module_alloc(void *addr, size_t size) { return 0; }
-static inline void kasan_free_shadow(const struct vm_struct *vm) {}
-
 static inline int kasan_add_zero_shadow(void *start, unsigned long size)
 {
 	return 0;
@@ -205,13 +189,16 @@ static inline void *kasan_reset_tag(const void *addr)
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
@@ -226,7 +213,25 @@ static inline void kasan_release_vmalloc(unsigned long start,
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
index 33d863f55db1..89e5ef9417a7 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -536,44 +536,6 @@ void kasan_kfree_large(void *ptr, unsigned long ip)
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
@@ -685,6 +647,7 @@ core_initcall(kasan_memhotplug_init);
 #endif
 
 #ifdef CONFIG_KASAN_VMALLOC
+
 static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 				      void *unused)
 {
@@ -923,4 +886,43 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
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
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cfdad0fc55c5a8b3a879627e2d20a0459a35af3f.1601593784.git.andreyknvl%40google.com.
