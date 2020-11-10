Return-Path: <kasan-dev+bncBDX4HWEMTEBRBAVAVT6QKGQEYYFA7BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 790C32AE2AA
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:11:17 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id h65sf58719oia.14
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:11:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046274; cv=pass;
        d=google.com; s=arc-20160816;
        b=MCeHJSYmw72jhLWV7V2XK6M4Nx4Lwgdo3YWHDWa5Uw5m33RG2CzW42VW8x8tLKPHQV
         57UkBeY2mWqJsZ5Z+4yADCb0BX03uJb/frysGAxNrPkqjKoT8AkbkNq9mW2cs1PbB7AI
         8AzOM2LIkTFYiDd4JoQa+QAEGFWaT8Ku8mVcFetXqg27QiP4TUifD2obSWnffrA5D7qj
         e25SMgMXUnRA+0syAZoMRpi14hMXvd0/hGioIlrBJgevol7AmxfeRySO4KG2LtggjMaT
         Y1GFqJmm+XGJvPqj7V82KxF9UPsL9I/ZcQDMuT8sv7oOYvnbzSrGvEolRlH/2hmy9ic7
         Hb/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=fLC9lIuZx55vey1XgOGDorIypfs9dC4DvMbKB6heeto=;
        b=xBVWX9+XuEUX4zDcgfLVKaAXvhXW8he0NX8ZOovi4tEQ+Aibc66bCy7InF00laMmnQ
         kuJWo65NijAHfQZUpGOLvJzoTnF10I+IWAkAOsTuKxAOp7cYfhCUgB+7FPDIIGhQzZoU
         QvJtJ2dxm/022D2JLshwTr/Dd/qvxD6lSyw/OHtf46Ki1ipChYtlqsubDGBV/uz1/Qe7
         RMJSuobY90X1RP89GZD9SvsfLlup3dDZezkDSDM0bMQaY1cxooSOKEa46fkpMRi6wUaT
         CawhL6x7hHOb7ZK+RRDegFyWjO7iil9dXEG5NYuGHnuwc6YqX2n0rpajfKCBvIqRxSb7
         xiyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fVXSSC7c;
       spf=pass (google.com: domain of 3arcrxwokcdaw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3ARCrXwoKCdAw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fLC9lIuZx55vey1XgOGDorIypfs9dC4DvMbKB6heeto=;
        b=U7HRChWPPYbJ48y0vDXyJJ1b3kkHqZGR21+umi7O7d70hBXSBOj5k6VVpRvkxgHhJH
         wWM4kRDV/nF3N8EsZF+PmC4GlaVbJ4qkruRRnKxW4xkER6egEqYtmxkW6dYW3JgJsGHp
         q9ImF5Gw/bIBFmxo761pt5xV4KkFpLMrlz/PmugmOZ8MSdcipcZRy1PXA+VNzOVO8qsf
         r/um9iO3SgIMv0tf+Kt6AM8K4XQ3lrktZckWys/X+Y5WFFu3Puv/MdbWXcNE1zelTwN7
         TpYpkzNoGhxVbojtuqbeHUvmP0bwgpqA4waUfYzHJGaIb+M9Pr+5H/kSsAP3gFO4+NOX
         V0Aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fLC9lIuZx55vey1XgOGDorIypfs9dC4DvMbKB6heeto=;
        b=NLROcV+G00axJSV+YjmdaAAgi5fppVvFG+uM6fQoq7tuXrSDknyKDEJuUrXEIeiapD
         BnSIRXwC9UAjM0x36ZC109E9zEmFwwIIpnSwD2ylO7eApsuttsGEo4RfgH+ODr1/R1rm
         cTTax0Ks8rOT7kABD7W5n4Jc3fAt2xHamuZz+OhPHbV8xAOvd56yGgbkjTpQq23cVviJ
         2KqWxLIqUXv4XB9HP6ArVNFnjal4O5OhNA60xselGtIkgqG2GXErTUM3Y15vPuS1UMkB
         VyYxZtCNnmTyvWVAJpJ8JuaQqpBkjVPVR3ozMRdHLQsRyBbOyZY4oaDBrCktsiTdNvHu
         UwLA==
X-Gm-Message-State: AOAM531FEqA67Sh433eFGKNZAi4MGLbHcu0xwnjgDXedplnwSctwh4h/
	T55wwON8WOCgjUJoyMP4JkQ=
X-Google-Smtp-Source: ABdhPJyIHVynV+au4gukiQjMdtK5LEBV3IzK9nl9zTHyeDxrrFYOlQk+CqyNxSB1QF63Ch0LHvBfFQ==
X-Received: by 2002:aca:4257:: with SMTP id p84mr182287oia.68.1605046274316;
        Tue, 10 Nov 2020 14:11:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:51cd:: with SMTP id d13ls3351142oth.11.gmail; Tue, 10
 Nov 2020 14:11:13 -0800 (PST)
X-Received: by 2002:a05:6830:3155:: with SMTP id c21mr11014469ots.281.1605046273681;
        Tue, 10 Nov 2020 14:11:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046273; cv=none;
        d=google.com; s=arc-20160816;
        b=w9hVnHbed79Kbb8S5UXaU1B6FsIMSmaNoT5NWcOs38pZJ2ZbVWTU9wEphSTA0Aljk5
         EWd7KuYCnXGu0wfYuxxt0BRv29nbe8FfhMeCU/8M1VCLWxQeRR8nYFSgpzA7gAtyY974
         Wg2oBPyQvp57U0caJDl+B+caF7Db+sL38Rbc6KrpYDYRjwkV40japFjNAjFmUwsP1qaR
         DoIkRVZ7yNOHhoOx+f4e0RF98t61nvEV0Hyt+hXLbEtGKwGC60B/IV4Kw2kn8y2CT5yt
         CjOemhGDeCl0vi4mIWgSxxQ2D92Wi2vA10yvQFrjyRlz838556nWKHuIW7BDdqFtp4/A
         IJnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=XraCnBPyNFRl2jORnfbsPA7ISP+sfWOQd9nhL08xkeo=;
        b=WSXRpd8ihduG5OgkAU/F8yVYjw7runbVM5Yo3muUBB968QYbzf0rXLOsJYz2se2lIX
         PIbHClsAlG1aQk6OT/oC+uDCA25F68zLM7t4OgYSNf6KpunLEHcQsUDEToSyiO3KNcbn
         osSpXr5d2yPDKP+YigN2qRvy+HaDpVNVnKmQWDj88Gv6aE7NGrRZLsDNxq8CbMBcdJ4D
         oLCDyV+EtLgJiLb/XfG2Mp+OZ1wmvYfuiYeyWtyIgRj7Q5BrFKTg7xgpi8YqZ/qnQBPC
         Zcq1Ul+DcoErI/gD5FQubWcTY6XBJu3Iyn3K8z7jMIoal3xX0xfDnTuknlPxS04I8xGX
         XlHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fVXSSC7c;
       spf=pass (google.com: domain of 3arcrxwokcdaw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3ARCrXwoKCdAw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id f16si12080otc.0.2020.11.10.14.11.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:11:13 -0800 (PST)
Received-SPF: pass (google.com: domain of 3arcrxwokcdaw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id w189so196341qkd.6
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:11:13 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4303:: with SMTP id
 c3mr22199156qvs.13.1605046273097; Tue, 10 Nov 2020 14:11:13 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:00 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <4d261d4cbd9842c51cb6f9b36cadc9054cabe86b.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 03/44] kasan: group vmalloc code
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
 header.i=@google.com header.s=20161025 header.b=fVXSSC7c;       spf=pass
 (google.com: domain of 3arcrxwokcdaw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3ARCrXwoKCdAw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4d261d4cbd9842c51cb6f9b36cadc9054cabe86b.1605046192.git.andreyknvl%40google.com.
