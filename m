Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYUASP6AKGQEEHRSEWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E21828C2F5
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:23 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id m24sf4066027otk.23
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535522; cv=pass;
        d=google.com; s=arc-20160816;
        b=OUJns+xNtLYm/D8xPfoj3XAlE3YQ3WpNrTXfpczLnIgbbdxZQTHLLg+fN4MGwy3R+1
         F0T7OFUvVmcRnuCYFEurwpvKCQT7xZht2mrIDe8r1hMZKit++zvzyihnB0Kxk8A6Kq9O
         nost9hZlKCqLaf8hkyKzR0XSWoNuVPouyqYc3+4maPw3Z4Ametx0v9HFFUDHRn/z8lEr
         wzhDVyaQ1crt+saU7YLjwOOHNVqGwmkA1tJz6dLAlwd/AWOmC2vECd313Vay1qJdoste
         Ooq5KPUlG8WlIl+/loitBJDJtaVjSgpdwNDDh3fN+uiQ23x8Sq2yDCGOrnNl+acJPz/Y
         ruBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=5cus6TmaCXhvXlFAo4yT75hDmOwofsE9zZUjBTgNZVI=;
        b=vx2lhyLNAFwVZbBNInwwf4JT093JvIH2kQ068f2/aWdiVkvDRXNbDAlnM/dzL2k8GM
         nB0gReurFzAtDljTL8SHxk0CkmG63ekXgzBkSabylXXi3M8N5RCngFaRlk8JVzpZPRRD
         UH/vuku/ZqfB8E6tTXfDrdBDgx7o4Ouvcqz3/jJUJbrn5vxhFYkY3N/1YlGe8VQKqU4t
         RJdwO/zTQsBm29pn2OeY31zq3sJP2+avqeqL6MKkH7NBkoTVto15i/6oohzvYaGbHU7H
         oGea2WhLMMDX+OgRBsgvdVVMQ9L5LgrFsvxcq8e2x3zamd0So8hHdgEtnkKE5Tzbihs/
         qG0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BB8Pva1A;
       spf=pass (google.com: domain of 3yccexwokcfyylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3YcCEXwoKCfYYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5cus6TmaCXhvXlFAo4yT75hDmOwofsE9zZUjBTgNZVI=;
        b=lAFeaPuj4HfZjHBS+SrKueXUeC+Bk2aqapghFA5BN0RA5EzjxodILw7P3eO6Ud+c5J
         lmoQAf+TtixxtW2+hXm9Wa6UeTtv0CXk1RvO+vLhFq1NU2AnjzJcXzD3/QTXQUTVhAO0
         tzyitcwXMS+nKBsxV+Qgp5fOvDZVUhRHtn9hBh7zClVfyhxCgYZKaKrqU0/rQxplSX8f
         X6pUNRlZPicR0wap81m3Og166MxhgEx+u1mJ/JEQEt1srjdIy6gK6cqBe5i7703E5q6C
         VKfV5vEKh+mDOoJxhvigCc/HBHIA/QIMkqwJTruzK0BbYXaZBZF/cI9nWSBY27xQXcQN
         NbGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5cus6TmaCXhvXlFAo4yT75hDmOwofsE9zZUjBTgNZVI=;
        b=P6iAH9uIpC3pM/AvBG937faBPCjjKPDXpR971a9pFDNFFKWZ+nyPUAxhHsibrWo4dy
         HFnE1PqzZfDR3xQkAgUK56ezwwjVay7Gr4oPPmyz56vkZwqJ+K1Ls6yfrJXilcjaJ47q
         9hjO8/toFVQjarMaY09ysQwhUcsyLjuvbIcz03doJifDQYfAEWfzhdIFobVHAmyT4myA
         KJ939qaNpUHzq+Z6AZZ087pqDeUA/BN62WedfTnGAcc3GC4bNMBdCUXF1hCFITqTUK6y
         gLfuJ+64YBZYlhzSpXuaGQXwWUGm2tbyFmEPdw6oiu+zK/xVMqRXCyTgcS0L7bHz9pMn
         SUVA==
X-Gm-Message-State: AOAM532Cpm/4JyxyezZNWb65RNsujkmP5s9ViaeeWy8rluAMP7JzZ77M
	YPBT8UUVkzBfIf/k3v+YQYw=
X-Google-Smtp-Source: ABdhPJyT3nBJBEotOrffv6/iNT4XOOKJrBVSibm6KiYK0q+TrOomTcbZyo3LkpA8biEkUCvtT9dzKQ==
X-Received: by 2002:a9d:70ce:: with SMTP id w14mr19151686otj.355.1602535522493;
        Mon, 12 Oct 2020 13:45:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:fd17:: with SMTP id b23ls240622oii.2.gmail; Mon, 12 Oct
 2020 13:45:22 -0700 (PDT)
X-Received: by 2002:aca:fcd3:: with SMTP id a202mr11964492oii.138.1602535522158;
        Mon, 12 Oct 2020 13:45:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535522; cv=none;
        d=google.com; s=arc-20160816;
        b=e8q16QpkFZrhmKHzrz8If0wigKjYUM43RmkRUN5HkNOtCux4tiMNjMdtCKFAXnYnnK
         9UT24Qq+NfiEDWFO0x5KoYcvdCaIL8/AkUsDLF43KGTQEMj/QLtFC1FK3K62rS13P/ql
         wZY0Rgu/FKL4jNIRApUIbClACJFahr0JO5kAF0YV4NJ8kpmawNi2+OuTMc/CtSO+CACB
         nt+9Pb8A6+V9OGD4kM3v8agiib5iA0+ocar9otSHJK70uf+cLmWAxMBv9BQuEDKjj1zp
         fbpOB+KuLZfipxK4nJZsN0vAY/dQJ2Ig/ImvelknbLH+Ejeg8v6bfwamleNSYqsfSzyB
         9mgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=W7UxnEGOiXbQ1Lj6KaW6aIJw/laA+Z6xLD5rNYqGoxM=;
        b=yuY5ndNiha5Gftw22vrLBg+m0LVUTO0v0k9Fdgiwp8HpUKnax7XxG78m5jh+UgqqWg
         h1m43Ob2uXa3aT8NCpbs6mW0VJ5+1elzrlQLZknSx3HwMUrdXhoPOYEsG9r1xXdg1IpM
         Bee4hNtQ3Y12MSQe9CddWIPdy8Fj851etH6PQCXxeGurYmkxtbBpvg1UDXRZlSuJ/Cnd
         s7tJIlb3zKY4L1ORhAocgE0npOUGP0c2KjahZApQanr0QjhufUJFAJXUw893XcBldqOt
         K+EcmBMfTU9gpd8swI9l4hjIpGJHcU89rmOpTwXzvIbITnBV6QbtwZHJXgZmyLIafwX8
         KQUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BB8Pva1A;
       spf=pass (google.com: domain of 3yccexwokcfyylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3YcCEXwoKCfYYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id r6si2754500oth.4.2020.10.12.13.45.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yccexwokcfyylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id i10so13576150qkh.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:22 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:42a5:: with SMTP id
 e5mr26656910qvr.58.1602535521746; Mon, 12 Oct 2020 13:45:21 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:18 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <ae585cbce86c7a721ef86a4a2af4ea8a0816b433.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 12/40] kasan: group vmalloc code
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
 header.i=@google.com header.s=20161025 header.b=BB8Pva1A;       spf=pass
 (google.com: domain of 3yccexwokcfyylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3YcCEXwoKCfYYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ae585cbce86c7a721ef86a4a2af4ea8a0816b433.1602535397.git.andreyknvl%40google.com.
