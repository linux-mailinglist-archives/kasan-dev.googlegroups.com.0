Return-Path: <kasan-dev+bncBDX4HWEMTEBRB4XNRT6QKGQE5SYTUGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 29FFE2A7112
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:19:15 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id f70sf17643wme.7
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:19:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604531955; cv=pass;
        d=google.com; s=arc-20160816;
        b=HHPCGhiBvW59H17QhlZEva6hrlWbzZVTRRhTmgd1KXbBMUs8fHyUZgcpioW5Aep9Ge
         T8an4EYzCKy+wHjJmVNcwxybgBo3HJpzJ/LzlBEBHBrPueMTMNOBsopleCwd56vdajCX
         4DHArWZ3wrLHyBFqX836xNkwrFjZEYcK6R2ob9/YhVOfcnyTSeueskMc5r4bq7kpgGyN
         XH7bEFwCTgtu6cyawMBHtYXFZLDav9GDI9CJgOfMz7g9mIV8EVQDk4h9iMo9oJ2ZW6tU
         yNLmQEbrUSXGXLB30ZZu7VWXIxPtQg389adVwMA3zTswNcW6H3yRiPXwS4rWaeNhx/ZN
         CAeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Gj6YDEQzte0GuIxzzF8fxAQFWhHQmE8PQ7Epo4zt60Y=;
        b=luJ8D9blk/cz76eehfdUeHx3O4cogqTv8BZjlnl0GWIYZIctfddVd3GbeJX92+diAN
         ydqMbTSKI2OFIzxEwXzyol0e9xn/yV1h53wkcgXjzgSqbZcY6IsExLzdUOcjfzTXmgTf
         fHqSKsxuFF520WjhN+ZX5JoJK/65rgYmhQNWm9GenQGAXCLrnVQiqKrN2pgIaKy0OGSL
         dBKyS3COi5INBH6ZRLPPa5kLY5upRhNJ/ALZZNK2J70DiD4y0O1q3RwXlnlANu41D4kY
         34ahDFHHX1YUn2kJlhvPACwZlcCkN7xybj0XkuNWxQhFLZK78vaYQjCA1qOh+t9htwPD
         g2eg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Nde54gFH;
       spf=pass (google.com: domain of 38tajxwokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=38TajXwoKCe4QdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Gj6YDEQzte0GuIxzzF8fxAQFWhHQmE8PQ7Epo4zt60Y=;
        b=oBsoLrNteyfw76Aw25S/wG7Xi6rGOnSe+QXe7/i59KZFFaJJTQJgf+jgIOsCOtynjQ
         DrZcxezSvyKVxH8olT1ItwfBKc9VVD3faZcBr61MzZI49kNvXddMPugInED1GrJVVDoh
         nEZgT7rxEr8QWMeS3tbp4Z+Zp4AHvpt/AMDZqMVGyZllsxxZznrEQFwATNfQf058GDy4
         /Th7dQdlmd0ObMNOh94KJM+JMrFJl7fqxh5wLfB2UYWOyjIE4eELGFKtYxSlpYIF6nOH
         2iW91fJx7z42qOuTOBK8DqnfxaY6NGMn8gyr57NWn3Ov2DAFpBBfn8Ka2zBpBTdatPj/
         RM4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Gj6YDEQzte0GuIxzzF8fxAQFWhHQmE8PQ7Epo4zt60Y=;
        b=snJRNeK7iP9EYLsmo49S0o87plEohcmjbLv0LXum99JUVFIgWiyliu7S/o4uvXaT59
         YtEdvrcUTRIiF9YN6Q1LDFXLY7daYThEJmutmO2PfhHXvitb72r6ID0DKCY02R8wWS02
         yqAVapMWQRUD63fnFFo33+MZZVpO48l3RA+V5fMSkMIx0g0mtRyGf7rfN+7Ttf2mTCK7
         m9amv663bQ1ruOiSjGY6asvcw9pR/6znPCg5IZsrdvAnQ4/ro6gJ2o2e+qRXFtYME3XT
         p1pqzNYODJEM9wwE8bSdgTWy1PksnDn32GEbYWwfGlaBg7Kj/xRuc+71JMpM3jEpcSqA
         OfKA==
X-Gm-Message-State: AOAM533uDopSVzksPVDXRhx1Ptw2dHrV+nv6oM+er2lqjDqgGGvmBeDX
	2Og/VfDdQu7c4wDN9lopXnU=
X-Google-Smtp-Source: ABdhPJzNHVq9mWpxzLX6VYLBX1JWrDCyiN4wFsIUSTWQTs3nyqsdZt+z4Qm4/Lydsi0+NbjUoEbOiQ==
X-Received: by 2002:a1c:ddc4:: with SMTP id u187mr61454wmg.55.1604531954881;
        Wed, 04 Nov 2020 15:19:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7e4e:: with SMTP id z75ls1894648wmc.0.canary-gmail; Wed,
 04 Nov 2020 15:19:14 -0800 (PST)
X-Received: by 2002:a1c:4ca:: with SMTP id 193mr52278wme.137.1604531954038;
        Wed, 04 Nov 2020 15:19:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531954; cv=none;
        d=google.com; s=arc-20160816;
        b=CkDs+6uc7O6r6Vya/fkJP9rN9n2d72HkYv21YY7oiIpGEUK+nESlG7PRzBxta55jeQ
         nViTSAT8+knbs0bs0il4GT373C46T2s+UHk0rWQvUcxtBvbD7AUyurLjQyL7JZfdhh/2
         KrQNPBAbm/VHO6muHgzEHZutcSRz+lbG1/AAK58wOwpLx1gaejnkf/kHKujZ1LjdyQ45
         0unDYos18I0JhPxIw46BI3Cjdm3WGS6VrMclkzndgs0LL7dFP+7YG8OZQgAlwMo6XLje
         eopck/onU/p5UNERL/jmrwqYk7ZSlZ1TOWjMA7pAMP8x6Aghkv1EvKhm98p/ZfCEdF8Y
         w+ZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=RYRi/FAOTZ78lCIR1B7o4Jmj2D/EUC7lc1NuI1GE5uU=;
        b=bMTEjtKNQljvd1FpYuua6XTqpLFhlfpGOnrgJGQt3kDFptN3SYOJBOM+At0MFfXT8V
         TZhi+kUzHnxatkWc5FVPChBr+pyb08nalt58CwsmrLaOLsHXLpSuAD5SHVomkF8x/jKC
         TiBY0hlcNE9xq9R5JGCxH1eICBS3zxSq0bbG/z0ZkTFvuUSwOWgmdHwoWcdC9N901rH3
         8Joqhe39QhLV9xojXyP6qMtbSUbTZ2vCk1g2h/QPKaxk1Xh+rgcBE+xJ3aOBMN90WFax
         wA/UVDir0dx8VbDKfHn6ZcGNXeMGip09YNoqFDKXkIYJMQvqSM7s4MlgToFtRyPqmbJl
         35jA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Nde54gFH;
       spf=pass (google.com: domain of 38tajxwokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=38TajXwoKCe4QdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id n19si191607wmk.1.2020.11.04.15.19.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:14 -0800 (PST)
Received-SPF: pass (google.com: domain of 38tajxwokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id p18so57295ejl.14
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:14 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a50:fe98:: with SMTP id
 d24mr157767edt.223.1604531953601; Wed, 04 Nov 2020 15:19:13 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:18 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <7762ae3696d59e0e38ed69d0a98930aea883be82.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 03/43] kasan: group vmalloc code
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Nde54gFH;       spf=pass
 (google.com: domain of 38tajxwokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=38TajXwoKCe4QdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7762ae3696d59e0e38ed69d0a98930aea883be82.1604531793.git.andreyknvl%40google.com.
