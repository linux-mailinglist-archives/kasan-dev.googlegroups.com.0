Return-Path: <kasan-dev+bncBDX4HWEMTEBRBU6FWT5QKGQEPQISZXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id E6F84277BC1
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:00 +0200 (CEST)
Received: by mail-vs1-xe3b.google.com with SMTP id v131sf331131vsv.9
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987860; cv=pass;
        d=google.com; s=arc-20160816;
        b=grwGsQ6lBLUCgMi8gPZxPH26yG0OHS/0VQNb6TyShDCzlkHgX2n4uyeZ65Ry/R5BKd
         EseeFPnL065m6ekrgqCzZpVtugFB64oBY4b+DP3NaW9PfQjCmgFvQRcJvifp58c76z+J
         zL0QABF3va0YAbVox3U75EWvXdeeCKcW3vzskrmo+xzEkGJBR7VRdmVGFtL832NJqHru
         4Oqde8KudBbPwMSTozYGYS9ic54ASdhHF7ZlwpOLN4y0OqCcsDCvfwZ45Zd302VGvbfP
         /1vwZ220sXNGF5qfw8znNGZMKRPJnOnqVz2br60Z2gebj78bXKxWST20vZ/RkX6nWyty
         N+0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=1dS3hu3MvwCwGE75OWxhOL/CCRFLtazgKzhE+eDRr4E=;
        b=SGKh1P9FaduyuI2fwlH1BrBaPuHolLZsy3SkYwDP5ga6iDijN/jLbppkmtBa8r98Bf
         8lT3DcpgDgFH4qBiNEXcHS9ta8Rgparxi3A+yHGapwy7B2ida0dwPMo8nXg5HbnzVfii
         ta+8dOyOYbyj90ujCbUmQNCNNXd75qB0aZbf0nLz/U0JJWxxq/joSFRUH8O7yBi+nGjq
         Wj7xL0AEG1ZlTw9zyWstcEvnrQLQfjrWRHXnqmV7unvvFaI38bYboHNls5xj9mhV8HbZ
         dRMEvo4T6mYNqdReqoog120KXcHFQNd+WSVgnJRCHifyAtFGsSEtUBY1/2NQSjytibNz
         fg/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Qa/XFF7I";
       spf=pass (google.com: domain of 30ijtxwokcc0t6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=30iJtXwoKCc0t6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1dS3hu3MvwCwGE75OWxhOL/CCRFLtazgKzhE+eDRr4E=;
        b=FGtjjXKwPg5Q9otc2+bXBg0c8RaDT71lRFtMzrwC7vDrp9BN6dQQZbfXIqxufkIDwZ
         HJyC9wxEjt9KUWz/WUe3gPNx9heqLgHSmYO+kOhCMB4624vFVzKHMEJuBuvnQJRmTBky
         t/HaTFRXDqnOnMmy5rcSEoYnjal1oHYGmSZ5jkSazM/fz2zsRocFQKcYQ143ze3upATy
         M4ABg6Y9aOJUY6NMQJxU5uMnsMsXPekA4/SDVSWwC+tUWFuUmRsb1eVczHC+tgqx6FNI
         KCBUdNd89IGNclnVF1y8aSRjgAAxGWl69nEm1HBpDt0aNVDy5ZKsewod0fWQG2USTAFD
         8p+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1dS3hu3MvwCwGE75OWxhOL/CCRFLtazgKzhE+eDRr4E=;
        b=XDKi4GBWPZEWZ33K4TugEMwAFf4GtZpw5IqE2KcwMSvDj9cikHNIXZxBpo8E2+0amD
         j8cYBz+vQjs7fXCCPCtsvk/sjdr1iND0ZJqJ1V42VVvvwTTq5/CBUvXpNWDfUnwDJFlP
         dkozlRIx4zGZqkvMDP630oxEpC/87i2Ov2ws6+ZV00t4pLUzjiRlt2r4ERhoyOCiQmOm
         CXZFtvOimeBbkLPdSzpVefMh6xdwY3lu4/3vK9RI/JxeJ8pFD7qsf8BLU/ARtHHsSv+P
         ZOQzlS1jEXD5SnBUtxVcswlF795mNsm8vJl8dCDaIPEylWUTWbJrRgAVIB3afSb5II/v
         2dQg==
X-Gm-Message-State: AOAM5335dOi8OYkcpT1HAtvrJc9iYOYgx9ef7n2kpxf92c3qEFuLUGuc
	J3kpk0hD+tlxrAXnoLqxEF8=
X-Google-Smtp-Source: ABdhPJxpmzh4W9QlYSSZuUHeb6xyaQxhCCd1FrPiFs4MM+Y0mr25WrPNhQyf3DoB+BJ5T+xuxQRqjw==
X-Received: by 2002:a67:b917:: with SMTP id q23mr1202072vsn.37.1600987859819;
        Thu, 24 Sep 2020 15:50:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:bb07:: with SMTP id m7ls131543vsn.4.gmail; Thu, 24 Sep
 2020 15:50:59 -0700 (PDT)
X-Received: by 2002:a67:68d2:: with SMTP id d201mr1252809vsc.41.1600987859317;
        Thu, 24 Sep 2020 15:50:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987859; cv=none;
        d=google.com; s=arc-20160816;
        b=zHfyQAf4JqNoztHcam3vD6eRUKtJxLT/HPznUoARu78gfcRlg7oTtnnOQ1uk4MAbAc
         00gl8OBrhwhqpKib6Rh4AdfA1IA7AE4OEXniKdlQjqSGqjVzXh1AAdXvxO9OVdhBrKnX
         Ap09OhVNSIwFNlNLDPE8rkSvPerauvjufSPCMmXpBTQUDWGaezJmiFd766jHOrSmx0WA
         Asd0paYNfBUKmPS8WsZNG+OdpWhgn+q5dEp9ng+qdpYLSUxelbU1Ccjt0kJyv6msvKXo
         4K6bZ6iGm4djNYE35Zl2sZkklO9yQKo4Wbe26e+MhVHrUbqopjIQOc/edbNtIBm+xJlf
         xxvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=yypuRQuJeHLa3RceX6osZfjChtMSXcG4z/tOFqcPOsg=;
        b=kBRAn6XuoMw1QQ0CeLhBL5ILQawYOOk/DagBh9TTV2jwKP7Ngwkv6LQ+eZ6T4L1TPa
         Ja9EAi/RQDiYWFQ5jLjo1e2Gr8uEMhp7p0eR4Q8nnyrwSkFsw6bIaOuAMd+7egg4YQCU
         sks3ge50vbJtGOapQvrfQznAwHcdrfAK+dWnDk0iSoozj6PZ6mzTA6CbTBtyjEjML2UR
         0hoEL6lB4hIYZ6YqLMyHfm7wesCPTqVqt7pxTTQApyDW78xlQ5mnI5d7TA8IxcgWH2dJ
         x9mwjvc/RKd+Lbc/VUrH4L0AvAfRLCWBAGRFblKkfr4zM+YxMGkN0AhNTf7iY9wk46x0
         fl7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Qa/XFF7I";
       spf=pass (google.com: domain of 30ijtxwokcc0t6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=30iJtXwoKCc0t6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id y65si45947vkf.1.2020.09.24.15.50.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:50:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30ijtxwokcc0t6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id w8so463804qvt.18
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:50:59 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4527:: with SMTP id
 l7mr1574122qvu.2.1600987858744; Thu, 24 Sep 2020 15:50:58 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:10 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <4f59e6ddef35c6a3b93b0951a47e7e9b8a680667.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 03/39] kasan: group vmalloc code
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
 header.i=@google.com header.s=20161025 header.b="Qa/XFF7I";       spf=pass
 (google.com: domain of 30ijtxwokcc0t6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=30iJtXwoKCc0t6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
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
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4f59e6ddef35c6a3b93b0951a47e7e9b8a680667.1600987622.git.andreyknvl%40google.com.
