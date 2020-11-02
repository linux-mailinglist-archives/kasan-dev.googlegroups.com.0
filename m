Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKG4QD6QKGQEHB5T6PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 43B8E2A2F01
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:04:57 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id y5sf933629qtb.13
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:04:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333096; cv=pass;
        d=google.com; s=arc-20160816;
        b=MwfIliJLwaSnH0/h3N1XulJXP11JjvUDkfP3aFrosjDUL4mQr+JPzGyuuNvl+jZTrd
         k+G24kyR/K90YdtkqQ+54NQj9j0jIQGCG/9mPtH6YZrj2y0EsVKyPup1ZgHu2gPFJOWo
         3dFOEz/hvbPGVQ8qF7rN3KAAlkQc5XyJPQ4G6v/IvP31PVEL/ZwqT4cWLPhpzlFyBnJM
         bebAmBQ7+5z12XOtZYhy7HVM8inwtolyjYMJIRYbOR4NIkZ6slJ36sztiRyXEKMmUgmj
         jnt6UphWp9qf1nm12+oU5ZRheRivtf5sVW7L7E2gIIm58Ilh6kEZ8zjkImQQaGPJmxbK
         QvJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=XV+nPWpvRVn340ag8vxHB+F3YVJk+qvxz7+31HPCHzo=;
        b=GzQTnjjPWguxuzB1rMQLNfZpbszOhwWYMWn2dy9w5+YngR1CNZQrpynOhmkn/6LYEA
         D1uKzNKS5rFfe/aCm8DB3Z+cHUmqWPmqKLoPTIq6a9UAnjrMXdUomp/v9am2w+SSXCUP
         Si2Sy4ahELSp6C6EjO5awtzBpneEMIg9UG5YvUCx+6n/QS9gSwwUa+jlhiO06iQ5bbsV
         HEg/zVD3n0n1Yc4/Gq4fNvtabr6HLICTW40R5TwdVmzNsRsfjNSrrGhhUetuSRCQypSK
         M0jWSEQlqqW0s7+CUEdSQSdedW9sLgsZ7asUkubP934V8X9hP7q/saIngsWmn+34t3+l
         FG9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rDH2DOvD;
       spf=pass (google.com: domain of 3jy6gxwokcqgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3Jy6gXwoKCQgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XV+nPWpvRVn340ag8vxHB+F3YVJk+qvxz7+31HPCHzo=;
        b=MinxT9H8Pequ2dWGbntC2Wv18uPo9Yr2CCqLxbqlhFzx6b9Okwom8OD2NuDUoLs5AM
         B4q55TgCvb5j6kq0BawNv8+hcg6oaPprq3ULguQ6zIcoF1o1cNBEiMWOVt5GuXom3N5p
         aYdgm4jEKt+3U6PH5+X6vs+iOc0VtA1PawcTbmKJuBS4rnzhebeTTYHyqAGhhRcGaItO
         k85W7ZclaUNr6hiAdtNkep6xtNSLIgNS8UbbGCf9Sumk6AyFCYk3pnqnCu8dYdXxbh5A
         mCZQNE/Wwgn5DMpxwMbGrJhSr56ge9jcbVkS/BIDVO647uQM/mJrxGFNqBTxskE6rNWH
         O/lQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XV+nPWpvRVn340ag8vxHB+F3YVJk+qvxz7+31HPCHzo=;
        b=Y1fwHDedCTYLVqvFQhhxgjpgwMK2leNWzbRu2BK8ssl+DRYFxv8uk6+HKlIYVhAT1H
         Gn8vVbpYDjDAAT8CQZMMhuOJ9dMqV7IRa6vZqgp2NJg56xpEBwMjuzTPOVR3WZMVi46N
         QX+1rf4DI/4b7BLcNOivhlQu52kYSX05vWFGDfjJJnjQJfed++KGXGZ7MuIsIW0pw6C6
         uykbw4rPem08JigJZ1uxY0BY7WENL27Wk4NTa41b/PnGLZXplh5gvPdQmP4QO2dEhjpE
         arNPhiz46xxaXFM2Es674ShFZ+wbOHb5Fwt/+UrCVWVQlftwD326OxLph6f+t6NNCMrP
         zhgQ==
X-Gm-Message-State: AOAM530vFIXPvRocYJkNF+RLb65OC6n6loovUV2Zm2R8Qas0STYzsBP5
	LG2T2uwx/3ZLWqhRS3yIzLs=
X-Google-Smtp-Source: ABdhPJwJuf1m6I93t1RxHA67f6SZGMc8NFFE+cBw5PwRrdKyE32jq1XUGG8zX/+VfDrWCSLFY1NtsA==
X-Received: by 2002:a0c:8d05:: with SMTP id r5mr23283727qvb.31.1604333096228;
        Mon, 02 Nov 2020 08:04:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1448:: with SMTP id b8ls1882012qvy.1.gmail; Mon, 02
 Nov 2020 08:04:55 -0800 (PST)
X-Received: by 2002:ad4:40c6:: with SMTP id x6mr22829257qvp.20.1604333095739;
        Mon, 02 Nov 2020 08:04:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333095; cv=none;
        d=google.com; s=arc-20160816;
        b=qUGLpt4CI1/K88Keo9GIgRcsKqRKmh69TQLvC4UtspvyxcA5V3+SLL9AU4MNZqky9o
         /JJ0iZDwjNSCH14Jy3idpzP8Rhev1Av6fsyM7vrygeRWfY7o5Sr4m0qN+bWCPnxDwjLt
         KwtA94OAeKePgqTedkE1pcXYYtSMt1Cqj4fORDI2FO1Zf9Z3uuGY0cke1Suhf+jYUmr3
         rfUgZsBhcxMGPGePERZ3qGuKG1igYiZjYCZfR00q65os0YmZ56RpmebbcZdXs3+kF8go
         G5AsVPkqkmie1IX181SICYv6kSe3wixA62Y1IWwWIFvC+tXzUorTAjoXqQ2yReXVslon
         lsmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=RYRi/FAOTZ78lCIR1B7o4Jmj2D/EUC7lc1NuI1GE5uU=;
        b=YDRSJ6aN/6gUOIrpDD+uFcDZ/s1LBqEAIsrfs35YPqeboKdRN+nk8jghhsMFn6IPEw
         eYuQRFARUwxWpJmvgWi+vQjpjZ+YW7VcM1Jn+K0Q69Z849GHBh7VW+Lgl1Wq3EsMC5Cc
         AtOqcTWMCaai+HPOckH3tB3Z4LwtHuSbrAdsdDWgGLVQPmRw0JHYAVWDb0DZHXzlCwfK
         LAe55nd4TeSsjshAiRlvfxDS4E9vM/gjZUKBB062ijPfCR4l3cZ21OjhAI/OyQLamy3g
         WLQGna47P4Zqo8orG8M/9eK4gi++RH/+PxgJkL5DPRWS+j4k3LhvZTuGYMF/k9HgMIk+
         4j1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rDH2DOvD;
       spf=pass (google.com: domain of 3jy6gxwokcqgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3Jy6gXwoKCQgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id x21si797290qtx.1.2020.11.02.08.04.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:04:55 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jy6gxwokcqgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id q14so3482857qki.23
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:04:55 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4770:: with SMTP id
 d16mr19655039qvx.61.1604333095423; Mon, 02 Nov 2020 08:04:55 -0800 (PST)
Date: Mon,  2 Nov 2020 17:03:52 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <1ccf387a74117d86f3c9422547920a0c8f08b8d2.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 12/41] kasan: group vmalloc code
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rDH2DOvD;       spf=pass
 (google.com: domain of 3jy6gxwokcqgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3Jy6gXwoKCQgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1ccf387a74117d86f3c9422547920a0c8f08b8d2.1604333009.git.andreyknvl%40google.com.
