Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3VO5T6AKGQEQOSUCIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E2F229F4EE
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:26:39 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id g20sf2674677plj.10
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:26:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999598; cv=pass;
        d=google.com; s=arc-20160816;
        b=m2++qvA+RJGcV9/CKffso0AWEsbBhoFWuV+AsiRhjOTi8mWuak9X3rGXpV6y96IQA5
         SB9QzMGeho+qXKwBDpwNNI4pA3uBTARzNA/6efQPYX9FIT1oqAOsTXFPxQ2hZgfsgKOj
         WGYp/E91UVtIa92N7vLKVFEMdeFkh7VgyaSvY44fxa2uF2GCNqRnLnf+yEZ6KAVGjWxK
         nHBTSBrKOwqYaibu0UbwercNZV1sTMp1syChslnfGNZkU1In5mZ11B4MVhdMyOoctDc7
         xgi+1cNtQ5WusGGhHGA3B/8SIuLTgf4t9REOGl/FSwdUUa4I5dUiuwyvHV9YC7aGsDMO
         hFoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=+HVnkJf7zEwh9Ash1f53QBsqkrfcB2Apc3/YlUpQVBM=;
        b=wufzk18uLrLrfToGPxdrCLn4WO1E1/j9ulwVieN8YcZKbnqHYcpjTIoSPppGrqV42U
         85aji8SF3xRZN+YZSMd4/iWvT+M4oa4S05uAVOhTTUIew4xLPfPG9ueV/XUsVFZBTa6K
         NiIzOjrI2UHCAolt8yBrj5pBa5TrT5Cd3xZ03BVPWxRcnFvqUaGU5ITiK0soMt78uf4+
         3+AsCNVEpYg+WkbHZLDEajabTFeeX9c/aXpopls7875aJ3gQm3yT2QMSaNISE8B8vPiJ
         0wTCKnuWAdtAUmxTiyfnCJS5YYLhOiGKpRFsIUyHpMd5yndXrsVm6Q3wpGLgwNQdsKUr
         zCkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Eos4LXO7;
       spf=pass (google.com: domain of 3bbebxwokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3bBebXwoKCQslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+HVnkJf7zEwh9Ash1f53QBsqkrfcB2Apc3/YlUpQVBM=;
        b=JH7Ugy0iYntdFPMk8x83EL1O9oJefQmlspLRQodBMdm65r3454A54IAoKTJS0W1vYq
         s3UsPtueq/MWlASxa/XVJx6odzSWhwGDTJ/PJ2o/tlkADDCxHHm7W5KqHme23X+Z6x7t
         nzZHF9AaGhpOiWAbiVtErpeH2Eq8il21Ys5z/D+mlntuHsFYmmJfPj9P6BC2zReAPKgR
         z6BmO4bDpqgBQKYE5v4so6ju3IofKzh3rM/Sh0U9X6lYrh/qKTjD878Z5jQ6Gy1Cn0mc
         v7WMBw7Q/6+aGb36XRK7c5/aY5QQ+05pRbo/a54/URcBrVwuspFSrEr8sPq9R6wNAPZg
         s2MQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+HVnkJf7zEwh9Ash1f53QBsqkrfcB2Apc3/YlUpQVBM=;
        b=pO6/CH+imQw3LmR4M/qlxGbpos5n6vFdjnrKP+ZuPbtJzfHOHdAzpeYbFWCdGHY60G
         5W2ppVS57hN3NhHJJgq3B35pKJL+PbWirjEiNlW6yzfwMzmm0jdB6zyAun1EbVjwIRk5
         gR4QckC/LZf4Sf7Hg1fpRXE/1kqn0ycNY9DPpG9AR5wFqk5JUaakTpYeBn35azGVE7Rb
         ULz3m+M+czehIeBDj2uwaIXfKp/pRkZzYA0W+SL8qxhK1kvba9ft3OnU4iaz09SBip4V
         zuCVVXFuda4v177p8KJg759Jzk46whsIBGp5bf8nS822S/84scgFzW7aWOu2MQ6t3Zg+
         98JQ==
X-Gm-Message-State: AOAM532mxX7ZBHVhKhyYI2Zg91kGxBE02cCxrWhTmhELrlwJdyLoamLq
	EFnEZoUq12zKXB2jBmlsung=
X-Google-Smtp-Source: ABdhPJzExFmDF/sCvt0i9M/y9Cp2xef+QoD1MDR6v2T4YXDQ62oiBEoUNQeZYNcltqIcFOV37t7SQw==
X-Received: by 2002:a17:902:9049:b029:d5:eadd:3d13 with SMTP id w9-20020a1709029049b02900d5eadd3d13mr5272645plz.15.1603999598115;
        Thu, 29 Oct 2020 12:26:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:3fc9:: with SMTP id m192ls1424272pga.5.gmail; Thu, 29
 Oct 2020 12:26:37 -0700 (PDT)
X-Received: by 2002:a63:184:: with SMTP id 126mr5493874pgb.43.1603999597474;
        Thu, 29 Oct 2020 12:26:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999597; cv=none;
        d=google.com; s=arc-20160816;
        b=iuhjdkCgRPk35U99mfIMqW/Beh0eBGBGcVOV48fARMzt3+KPzuBBI9IjHtXmpYdzpj
         pm5fgu9B3YM5pBMcb2nFVj0MN/2DK/HjsewDaqqLwjfZTMo5rhojDOw9qaPBVokvLijn
         vdfYduLMCVfuuGCGLIQKcaFXZOKjaBY2PIoF3wrEVe7CCedHn+tXqfsq3mNASN6nB1Ph
         oO87+E9l0oqX+7bRI2R386H2P5AtVKw9s3ti3b2hNceKacTY11N/tsh5TAmWHztvmgsS
         g+XyZw6STDafm2hhbnswjjjBuRAtZ/cfVQDXheVUiFMAG7q2e34ktupnHWZqAH6FoYZ4
         jq4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=RYRi/FAOTZ78lCIR1B7o4Jmj2D/EUC7lc1NuI1GE5uU=;
        b=v1RCeotOwmddPl/vmXphSTS+a++SZsRhOQssC8N9ThqBZfEdY3k7tKgkvoZZWQJ74z
         7cdGTlXI3hNRLCTnntUUK4Hc+JawEjN4jHbgT5gPhBZ1nIkrK2tApBbZ6DZ27qLh+Cec
         Rc7DB5VQJah9hGDy+QfO/smrn5IloLM2UPDinZ9HShaJ4N+I+eQv4p97gBSD4RJR1Xp9
         vVsUx7xvk2IW4+dYweID1XgqJLEHknoJgwGwsHbwy9mEkDnYX+KK2vjNSj7Z/Mfi0V+s
         mXTdQsFxBaK5F/tbqssNAHZ3I/xLB2f5kI1kEF6xo1C7vjW4Xs8jTRcgxfd1LnKbK8uq
         L3rA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Eos4LXO7;
       spf=pass (google.com: domain of 3bbebxwokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3bBebXwoKCQslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id f189si252073pgc.4.2020.10.29.12.26.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:26:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bbebxwokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id c9so3713174ybs.8
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:26:37 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a25:578a:: with SMTP id
 l132mr7644513ybb.200.1603999596671; Thu, 29 Oct 2020 12:26:36 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:33 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <99c317d5ff82d1eab8c4c70e22f58f60e3ed8cda.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 12/40] kasan: group vmalloc code
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
 header.i=@google.com header.s=20161025 header.b=Eos4LXO7;       spf=pass
 (google.com: domain of 3bbebxwokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3bBebXwoKCQslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/99c317d5ff82d1eab8c4c70e22f58f60e3ed8cda.1603999489.git.andreyknvl%40google.com.
