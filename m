Return-Path: <kasan-dev+bncBDX4HWEMTEBRBAUT3P4QKGQESDXVVPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id D0499244DB5
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:27:30 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id x13sf2182158lfq.3
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:27:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426050; cv=pass;
        d=google.com; s=arc-20160816;
        b=E+PC0AIP6prCIshBvOirR9bvamviqQP9HuMER+wtYON880bJ6VVXwXKJI81bmZ9w6V
         Vfr6yGE0yKU0p3SAhpPsrQ/TS690ADBpjMTgEIm+rc+IT+jo934ZTX4+5uOHVvVK3PZI
         OSvyihd8l9THlzzsZI4zC7kEKRB9NH1YUMc8wYLEVWZ6SEOwfGDuaX8UcUaGcQRTXCSG
         wASODJGYMm0sdFJvv3sYKBgnC6mmEj0Q9jlc4tyC8XapwoSDQJ616moOV1/SQh8HzptZ
         2JAVraroyIO4lY7haXDxtl1I9pdlP70G/DmWFNuA9X0DsLpL3gNQsVVe7rBX2WeqeZyD
         wHLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=N4/dWiTy9I9JpyRlLyCZn+LTOp6lyfaSrWBRHKucZk8=;
        b=VsaJW7wzZ2gdvaQRMQswgWdxJo80K12LUMe5czjcjzaiUlvRRPYuFhUcoo+VOLy1f7
         mLG79o4kpiaOwmVgVF0ys8XR3fG6u7TqMvvmFxnurtqaWXm38VyBr3UivsK1tno80P0d
         hpNim0h2PbzS1WGR6bA5MDGhFhdxpu1p2u8kr9267/w00c5USY2YcbUAH+yvlOzPZNxi
         5wmv8turTjReQhnWOEws0ev5k3aGFBNtt4Oe+IXDXDTi/eX1onUgyucAlyjnjB/YPnUx
         JID02AFo21soret5Fd2Mx1N4PrDhZPjZrUrswzNrquuhzkQ25O2pknKEaGFGZQNFDUcy
         ZwHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k29AXaVl;
       spf=pass (google.com: domain of 3gmk2xwokce0pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3gMk2XwoKCe0PcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N4/dWiTy9I9JpyRlLyCZn+LTOp6lyfaSrWBRHKucZk8=;
        b=m3TAnWnOxp6jpdSuNNm4UtCzNg/kvZub2lAZJz6Avz5B64OG77Jg4E0OCHd7R8smRE
         CUp/FHb6zz3ymaWOesQdF5moqzLtUzJsYtb/5YOVzCWCHZWGaP+WBh1AbzVlx2yrp8Jn
         /5NuQcnzeprY/LnSwnfjW6ZtLKQJrG9nz2Xlq5zM/Kb4C0akOiVo88ZmC0FUuoA3SU+k
         lyorpdy1G6+U/xr3fjuY81as5Vx6Cz4vgiOBK/pqQiJ6OtaL4UTqhacwqcp4EJNIJekH
         grsRQRgOhhb0q/YiHnfYXudGbAGbZhFmXvsIFRIx4kBWmO0YmCzxUGJPurqOuRoVD0Hm
         fj/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N4/dWiTy9I9JpyRlLyCZn+LTOp6lyfaSrWBRHKucZk8=;
        b=NQOLbZervLFgsmE5vvxxXVPZ1/++am3eU5fmAUgtwEOL5paNlUMIERXZr4Dd+ZuxHY
         owb7N/qaU7Ui3783VhO+HbPNtbOpFPjxQUXSekYcQOh5g42bks/W/OeiCev5WKWsTBSj
         vCcGDvCFNrUl+AhDGy2N0p91IkEvcV2QHIpdQWTJ//hElbJIJ59zsfxVebHm5UGkogDf
         5ecQE1XrseYx03ivqKjDtcf5QmPzblA+p3hBt3DSJsvskl+DuCE4nK6SVkdynFuIquEd
         O29DEL9mFycOGxQZbyQv5OrJKc8J4hSODItcWDtujGupaUUG+5m6rLQ+wJwmfB9ftrHE
         9AcQ==
X-Gm-Message-State: AOAM533pwj/HLWIQX8kROI8iSLQlVGFl7J5reHq8EKin3Trf1p7e35Dl
	1bCP5hFAUrGPyeWWU3ESIKE=
X-Google-Smtp-Source: ABdhPJwiQvTECwKIDDPQPa9w7VR66nGWVrFIl6QDjZoy71PAKqyX4M+b5sY15XmfDPNMp8uGqMcuiQ==
X-Received: by 2002:a19:cc3:: with SMTP id 186mr1736836lfm.134.1597426050369;
        Fri, 14 Aug 2020 10:27:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8994:: with SMTP id c20ls171005lji.0.gmail; Fri, 14 Aug
 2020 10:27:29 -0700 (PDT)
X-Received: by 2002:a2e:b6c3:: with SMTP id m3mr1814257ljo.450.1597426049640;
        Fri, 14 Aug 2020 10:27:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426049; cv=none;
        d=google.com; s=arc-20160816;
        b=luGxd0w7ns1DA9CYBslKNgARFWo2UMtmJXcGik20fd61u8YsyKvugPWCEobZrkBV3i
         7wxcOivyMXRPHkWEUbpAaUrHpxaZCCPoxy4UMD2b6Jk2oRcqRWeoDNMFJn9igCr5cDof
         t9Rxkv9DsFEBbRekqfBiFsYvx+lXGLincB/qvbi30oCxHKGqKvPvxD9Bkvfpzcfhz/ex
         /HZYSyOHIFk50ndbZbLhAzDhVDHHYWAX5OZC7FUH/Cz1WmbKJeFwAOiXO+i0hIrhfJek
         K5oO1nAeu/YI2hQiJOLijLw2s0Sncr64Q6w/5sv6qWB95zLwtfPod26/WTUN2N1W/VvM
         EnVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=5tE8GLGo7vmJDiQkkrzIva7DqUQiT7j3QisIKP5hp8U=;
        b=EROhWVJMof4ckhWizd0Rd+zdgB8C6ek/Vd7MYY1P+wgeVc3Zsj8Q3nCo6bPTUsDllk
         xBPn03nude1kiR0BdHM26TNqd7Au1X8GiI4P+wEMN7g9hd9UwCwEmLjfOgFIuxtGLIwR
         V4hsWcTCF9fkmKw+eCBNiaHAQCXvM7oQBgK/AntUqgGRhYnoe6jZCIF/yQpLxDKpNVjd
         3zhOTXJ/AVc6zwGQgm/1iGGhg+zuKbkHkRdxaK/mxhOs9lFenOCkNh4lln5r5awqgrjq
         6wI0O+Bk/gPJg3tl+eGw/ngm/ZdQLwaqLN0bnk4r+GrsaHLm8b4cz2kH0ZoTZEzkvbON
         9siw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k29AXaVl;
       spf=pass (google.com: domain of 3gmk2xwokce0pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3gMk2XwoKCe0PcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 141si477549lfh.4.2020.08.14.10.27.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:27:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gmk2xwokce0pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id s23so3593065wrb.12
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:27:29 -0700 (PDT)
X-Received: by 2002:a05:600c:c3:: with SMTP id u3mr423861wmm.1.1597426048519;
 Fri, 14 Aug 2020 10:27:28 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:26:44 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <b8fbbb6078e50065c3942aefd5cbc83ee7bf9d0c.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 02/35] kasan: group vmalloc code
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
 header.i=@google.com header.s=20161025 header.b=k29AXaVl;       spf=pass
 (google.com: domain of 3gmk2xwokce0pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3gMk2XwoKCe0PcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
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
index 950fd372a07e..d1c987f324cd 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -541,44 +541,6 @@ void kasan_kfree_large(void *ptr, unsigned long ip)
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
@@ -690,6 +652,7 @@ core_initcall(kasan_memhotplug_init);
 #endif
 
 #ifdef CONFIG_KASAN_VMALLOC
+
 static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 				      void *unused)
 {
@@ -928,4 +891,43 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
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
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b8fbbb6078e50065c3942aefd5cbc83ee7bf9d0c.1597425745.git.andreyknvl%40google.com.
