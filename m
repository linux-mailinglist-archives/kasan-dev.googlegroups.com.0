Return-Path: <kasan-dev+bncBDQ27FVWWUFRBSMI4XUQKGQEZMZJAKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AB827469D
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 07:55:22 +0200 (CEST)
Received: by mail-vk1-xa3a.google.com with SMTP id p196sf21230822vke.17
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2019 22:55:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564034121; cv=pass;
        d=google.com; s=arc-20160816;
        b=aRHJ4omky9Zdm3m0BeYC+EdVboZaz/1LC8sXAUX0QFmQASINmJTgEm+yaQHu7C9gHW
         xiFWizp1GX22koskdXcPFMZudUEh918dJgG9vClVZciyVx4UxcB+dPNs7drNBg0nLBff
         PFFheoolUF9yATRxitxegCOKfYSYiFGGYUq16FGQ3OEj9v4OvxCMmuVeLsobo2uK/hmk
         /WcYwsFwjhACqTXfIj4vhX+6jI8O3M9GrmYYxtCD2lwD0DXSC00Ufzzm9k0O2ANUCnuP
         prsd623TBryDAXcZWcS7ZfdyFFrBgQwhiyx6PbnOR3GlZWn+Fvxv84DciJSGHe0NMEYt
         kAEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=o2fJ4mPUgXPDMYydyvD+9P+Qv/ZQPNVf9KmVdgdM9/U=;
        b=sBOw4QwM4b7WQKrkNY8QkPaF5OYLfZ5TE1oLFd++u6i2TAkAk53nPZG31cD3Y+Ttcr
         C2uaziA0rKrVDXc5NRGoYuKGhB+aIlsbBqVMQGKKuvg4TNsBeGo98HEKQeJEQixGL/nr
         jKdTfj4LcH7EJevzYtLW4HTuoY4WEEBDiRo6dQm7YTWFJLoVf3Y/AJjngaLh52zNfDK/
         owaPPVNW3TWXV5K5Tr+1TNAipUwh4YXYApRXl6M/Td7ren7cdK3NO07K+tgRthfsXV1T
         NGvgzrKXe2rpAvtVHIhOhp3uUzW0NdRl9L8wRlJqCFlOhMNPmGROmLLOdreaikB2xkqP
         vIvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="Zmc/p7O1";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o2fJ4mPUgXPDMYydyvD+9P+Qv/ZQPNVf9KmVdgdM9/U=;
        b=inKswEKSW07GpT0q6v9hl0ou5Ed/A+Ev5DRldw1mFPJZsvK04LXfzVLGqhCb2BjgJY
         Trj2Fv3fPUrrLuOIjfDUm8AJfPKy7fP3Tkh6maoo+ZuGi7uPYxZ50Tx0fnBPQcWaff0R
         Qtt5LDxarEzI0sU7flNm/ebT9FD2U9caP6VU+Boni1V8u4yWW/T+TkvXcGZ5r29gkT8x
         3Oe8g3POziMj0f+3JmLfbMsO++MrKE2TD8PYdNpy8j84DGQjib8upJB3SS3ovmKIgmQQ
         1yYXmy6YqSCqD+Gh40TBkxT85yYE4S1AeZngtZPAYYkdtSwdCGpSaiiOxnieOGclgUEP
         1QfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o2fJ4mPUgXPDMYydyvD+9P+Qv/ZQPNVf9KmVdgdM9/U=;
        b=YrRg5o6LlX86zPThqUuuwXPCVvj5F3NWjGf/f6FQAts3GdprJhI1kKKhP5mg9wXtYq
         pMXm021VoFuAxeqZPKXWCf8pN91p0owkgnjatTeoOKo4b61ZeTowl3zZZy+/6KSnQLmE
         JhkCyCMtpFGlBbHuyMuvBkLUTZm/Vc8DfYr8Wz0vvdnZyH8kL6x171PwbZYqX58NY4ej
         yHAmYGUrhuhNs8viE9ezMM671YAe3pzQ1U5tS4Zd88ZSrshH4SmscWDTUTzrLskvzFkd
         xkt1rEb/dgnCQ41QhcnlMit2kYO4oTUuKW6FsO21Nva3n9JXiHgcWCIZAL/MfLBMz633
         cBGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU2GnM4g/oYB5tQr+fHVQsxkfYCrUVcj4KiRgaEnPwjrE7rxiXJ
	bOwAHvyIX45MuSliMLFENz0=
X-Google-Smtp-Source: APXvYqwX0DYi1RpkfjL5JEi0N55Q5aautVcfoajMeAOCKkfUYIis15HSQHxgGIaISrRaj5HduGu5UQ==
X-Received: by 2002:ab0:3359:: with SMTP id h25mr23499967uap.132.1564034121447;
        Wed, 24 Jul 2019 22:55:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:8bc3:: with SMTP id n186ls6271219vsd.12.gmail; Wed, 24
 Jul 2019 22:55:21 -0700 (PDT)
X-Received: by 2002:a67:ed87:: with SMTP id d7mr11056155vsp.130.1564034121167;
        Wed, 24 Jul 2019 22:55:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564034121; cv=none;
        d=google.com; s=arc-20160816;
        b=sfF4gFxN1iUdXmW9KDzlUyUCNHpacFY5a/bKOw5fJfR4SdEvPC+U31rucSZadkgeBf
         sSMYI4OjMifEhgz0ey2UnxdmRIrFb6cNGEstsaIz34YIG0LIB4nLi93o8sdBPOYbw8qR
         GWg1WUW2MLU1qniVXZq/oVxg9PKlsOLrkgYmB++Sa8hcQtP3CWSAMoprg+VE+6AH0JNR
         OzLoAGsZyMo5h7Gh6D3fcDFpHzsQHlgvF5QxOR3Tj/gcD0R3dNV6deNmoXcMkzQb5q3o
         fIa0wdw0twCYQ0SGYturwRcjeGPIdsHf0l9/5qcK9tWfojKL8w1XpGel56dsBVJiccfX
         ogpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Oxl+RCvil52hYTqcKqyIsHOOUO+9BUEaRpCf2OUbYYo=;
        b=FbBRl8gDJ1eJYmYKqflv7czcEBnWj9py2cy9IUo6Uaia35hsyzhTUzQf6h7liTAkxH
         rnw1P1LT177SOyfqukHU9+VNIyrC8qckFu27RLJBVkuK50Uqc5tz1w3WhjRxaagKTOGk
         /Ku3JhGfwKD4TkmINnMsDn2cYj6MInacnCzW2Fyx1Ag5+EwTn8q/RfcaNVukcS+xBL1I
         4iDq1Rjx8QR8Rc5lGZIYg1fyYbd068n3Q4PRp5jKx2o+ZMnzd5Fhd/xEb8bW/Vg3eMr/
         ENYsMmboTdE9bqEM1JSR7Rrmt5Ua5RBIiT7D6FG26ZM7UvxTnEdCzsL+bo+sg9ihaMcF
         XSJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="Zmc/p7O1";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id i9si3169909vsj.0.2019.07.24.22.55.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Jul 2019 22:55:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id l21so22428530pgm.3
        for <kasan-dev@googlegroups.com>; Wed, 24 Jul 2019 22:55:21 -0700 (PDT)
X-Received: by 2002:a63:4185:: with SMTP id o127mr45303225pga.82.1564034119675;
        Wed, 24 Jul 2019 22:55:19 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id r13sm64772392pfr.25.2019.07.24.22.55.18
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Wed, 24 Jul 2019 22:55:18 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	dvyukov@google.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH 1/3] kasan: support backing vmalloc space with real shadow memory
Date: Thu, 25 Jul 2019 15:55:01 +1000
Message-Id: <20190725055503.19507-2-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190725055503.19507-1-dja@axtens.net>
References: <20190725055503.19507-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="Zmc/p7O1";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as
 permitted sender) smtp.mailfrom=dja@axtens.net
Content-Type: text/plain; charset="UTF-8"
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

Hook into vmalloc and vmap, and dynamically allocate real shadow
memory to back the mappings.

Most mappings in vmalloc space are small, requiring less than a full
page of shadow space. Allocating a full shadow page per mapping would
therefore be wasteful. Furthermore, to ensure that different mappings
use different shadow pages, mappings would have to be aligned to
KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE.

Instead, share backing space across multiple mappings. Allocate
a backing page the first time a mapping in vmalloc space uses a
particular page of the shadow region. Keep this page around
regardless of whether the mapping is later freed - in the mean time
the page could have become shared by another vmalloc mapping.

This can in theory lead to unbounded memory growth, but the vmalloc
allocator is pretty good at reusing addresses, so the practical memory
usage grows at first but then stays fairly stable.

This requires architecture support to actually use: arches must stop
mapping the read-only zero page over portion of the shadow region that
covers the vmalloc space and instead leave it unmapped.

This allows KASAN with VMAP_STACK, and will be needed for architectures
that do not have a separate module space (e.g. powerpc64, which I am
currently working on).

Link: https://bugzilla.kernel.org/show_bug.cgi?id=202009
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 Documentation/dev-tools/kasan.rst | 60 +++++++++++++++++++++++++++++++
 include/linux/kasan.h             | 16 +++++++++
 lib/Kconfig.kasan                 | 16 +++++++++
 lib/test_kasan.c                  | 26 ++++++++++++++
 mm/kasan/common.c                 | 51 ++++++++++++++++++++++++++
 mm/kasan/generic_report.c         |  3 ++
 mm/kasan/kasan.h                  |  1 +
 mm/vmalloc.c                      | 15 +++++++-
 8 files changed, 187 insertions(+), 1 deletion(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index b72d07d70239..35fda484a672 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -215,3 +215,63 @@ brk handler is used to print bug reports.
 A potential expansion of this mode is a hardware tag-based mode, which would
 use hardware memory tagging support instead of compiler instrumentation and
 manual shadow memory manipulation.
+
+What memory accesses are sanitised by KASAN?
+--------------------------------------------
+
+The kernel maps memory in a number of different parts of the address
+space. This poses something of a problem for KASAN, which requires
+that all addresses accessed by instrumented code have a valid shadow
+region.
+
+The range of kernel virtual addresses is large: there is not enough
+real memory to support a real shadow region for every address that
+could be accessed by the kernel.
+
+By default
+~~~~~~~~~~
+
+By default, architectures only map real memory over the shadow region
+for the linear mapping (and potentially other small areas). For all
+other areas - such as vmalloc and vmemmap space - a single read-only
+page is mapped over the shadow area. This read-only shadow page
+declares all memory accesses as permitted.
+
+This presents a problem for modules: they do not live in the linear
+mapping, but in a dedicated module space. By hooking in to the module
+allocator, KASAN can temporarily map real shadow memory to cover
+them. This allows detection of invalid accesses to module globals, for
+example.
+
+This also creates an incompatibility with ``VMAP_STACK``: if the stack
+lives in vmalloc space, it will be shadowed by the read-only page, and
+the kernel will fault when trying to set up the shadow data for stack
+variables.
+
+CONFIG_KASAN_VMALLOC
+~~~~~~~~~~~~~~~~~~~~
+
+With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
+cost of greater memory usage. Currently this is only supported on x86.
+
+This works by hooking into vmalloc and vmap, and dynamically
+allocating real shadow memory to back the mappings.
+
+Most mappings in vmalloc space are small, requiring less than a full
+page of shadow space. Allocating a full shadow page per mapping would
+therefore be wasteful. Furthermore, to ensure that different mappings
+use different shadow pages, mappings would have to be aligned to
+``KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE``.
+
+Instead, we share backing space across multiple mappings. We allocate
+a backing page the first time a mapping in vmalloc space uses a
+particular page of the shadow region. We keep this page around
+regardless of whether the mapping is later freed - in the mean time
+this page could have become shared by another vmalloc mapping.
+
+This can in theory lead to unbounded memory growth, but the vmalloc
+allocator is pretty good at reusing addresses, so the practical memory
+usage grows at first but then stays fairly stable.
+
+This allows ``VMAP_STACK`` support on x86, and enables support of
+architectures that do not have a fixed module region.
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index cc8a03cc9674..fcabc5a03fca 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -70,8 +70,18 @@ struct kasan_cache {
 	int free_meta_offset;
 };
 
+/*
+ * These functions provide a special case to support backing module
+ * allocations with real shadow memory. With KASAN vmalloc, the special
+ * case is unnecessary, as the work is handled in the generic case.
+ */
+#ifndef CONFIG_KASAN_VMALLOC
 int kasan_module_alloc(void *addr, size_t size);
 void kasan_free_shadow(const struct vm_struct *vm);
+#else
+static inline int kasan_module_alloc(void *addr, size_t size) { return 0; }
+static inline void kasan_free_shadow(const struct vm_struct *vm) {}
+#endif
 
 int kasan_add_zero_shadow(void *start, unsigned long size);
 void kasan_remove_zero_shadow(void *start, unsigned long size);
@@ -194,4 +204,10 @@ static inline void *kasan_reset_tag(const void *addr)
 
 #endif /* CONFIG_KASAN_SW_TAGS */
 
+#ifdef CONFIG_KASAN_VMALLOC
+void kasan_cover_vmalloc(unsigned long requested_size, struct vm_struct *area);
+#else
+static inline void kasan_cover_vmalloc(unsigned long requested_size, struct vm_struct *area) {}
+#endif
+
 #endif /* LINUX_KASAN_H */
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 4fafba1a923b..a320dc2e9317 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -6,6 +6,9 @@ config HAVE_ARCH_KASAN
 config HAVE_ARCH_KASAN_SW_TAGS
 	bool
 
+config	HAVE_ARCH_KASAN_VMALLOC
+	bool
+
 config CC_HAS_KASAN_GENERIC
 	def_bool $(cc-option, -fsanitize=kernel-address)
 
@@ -135,6 +138,19 @@ config KASAN_S390_4_LEVEL_PAGING
 	  to 3TB of RAM with KASan enabled). This options allows to force
 	  4-level paging instead.
 
+config KASAN_VMALLOC
+	bool "Back mappings in vmalloc space with real shadow memory"
+	depends on KASAN && HAVE_ARCH_KASAN_VMALLOC
+	help
+	  By default, the shadow region for vmalloc space is the read-only
+	  zero page. This means that KASAN cannot detect errors involving
+	  vmalloc space.
+
+	  Enabling this option will hook in to vmap/vmalloc and back those
+	  mappings with real shadow memory allocated on demand. This allows
+	  for KASAN to detect more sorts of errors (and to support vmapped
+	  stacks), but at the cost of higher memory usage.
+
 config TEST_KASAN
 	tristate "Module for testing KASAN for bug detection"
 	depends on m && KASAN
diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index b63b367a94e8..d375246f5f96 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -18,6 +18,7 @@
 #include <linux/slab.h>
 #include <linux/string.h>
 #include <linux/uaccess.h>
+#include <linux/vmalloc.h>
 
 /*
  * Note: test functions are marked noinline so that their names appear in
@@ -709,6 +710,30 @@ static noinline void __init kmalloc_double_kzfree(void)
 	kzfree(ptr);
 }
 
+#ifdef CONFIG_KASAN_VMALLOC
+static noinline void __init vmalloc_oob(void)
+{
+	void *area;
+
+	pr_info("vmalloc out-of-bounds\n");
+
+	/*
+	 * We have to be careful not to hit the guard page.
+	 * The MMU will catch that and crash us.
+	 */
+	area = vmalloc(3000);
+	if (!area) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	((volatile char *)area)[3100];
+	vfree(area);
+}
+#else
+static void __init vmalloc_oob(void) {}
+#endif
+
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -752,6 +777,7 @@ static int __init kmalloc_tests_init(void)
 	kasan_strings();
 	kasan_bitops();
 	kmalloc_double_kzfree();
+	vmalloc_oob();
 
 	kasan_restore_multi_shot(multishot);
 
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 2277b82902d8..a3bb84efccbf 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -568,6 +568,7 @@ void kasan_kfree_large(void *ptr, unsigned long ip)
 	/* The object will be poisoned by page_alloc. */
 }
 
+#ifndef CONFIG_KASAN_VMALLOC
 int kasan_module_alloc(void *addr, size_t size)
 {
 	void *ret;
@@ -603,6 +604,7 @@ void kasan_free_shadow(const struct vm_struct *vm)
 	if (vm->flags & VM_KASAN)
 		vfree(kasan_mem_to_shadow(vm->addr));
 }
+#endif
 
 extern void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip);
 
@@ -722,3 +724,52 @@ static int __init kasan_memhotplug_init(void)
 
 core_initcall(kasan_memhotplug_init);
 #endif
+
+#ifdef CONFIG_KASAN_VMALLOC
+void kasan_cover_vmalloc(unsigned long requested_size, struct vm_struct *area)
+{
+	unsigned long shadow_alloc_start, shadow_alloc_end;
+	unsigned long addr;
+	unsigned long backing;
+	pgd_t *pgdp;
+	p4d_t *p4dp;
+	pud_t *pudp;
+	pmd_t *pmdp;
+	pte_t *ptep;
+	pte_t backing_pte;
+
+	shadow_alloc_start = ALIGN_DOWN(
+		(unsigned long)kasan_mem_to_shadow(area->addr),
+		PAGE_SIZE);
+	shadow_alloc_end = ALIGN(
+		(unsigned long)kasan_mem_to_shadow(area->addr + area->size),
+		PAGE_SIZE);
+
+	addr = shadow_alloc_start;
+	do {
+		pgdp = pgd_offset_k(addr);
+		p4dp = p4d_alloc(&init_mm, pgdp, addr);
+		pudp = pud_alloc(&init_mm, p4dp, addr);
+		pmdp = pmd_alloc(&init_mm, pudp, addr);
+		ptep = pte_alloc_kernel(pmdp, addr);
+
+		/*
+		 * we can validly get here if pte is not none: it means we
+		 * allocated this page earlier to use part of it for another
+		 * allocation
+		 */
+		if (pte_none(*ptep)) {
+			backing = __get_free_page(GFP_KERNEL);
+			backing_pte = pfn_pte(PFN_DOWN(__pa(backing)),
+					      PAGE_KERNEL);
+			set_pte_at(&init_mm, addr, ptep, backing_pte);
+		}
+	} while (addr += PAGE_SIZE, addr != shadow_alloc_end);
+
+	requested_size = round_up(requested_size, KASAN_SHADOW_SCALE_SIZE);
+	kasan_unpoison_shadow(area->addr, requested_size);
+	kasan_poison_shadow(area->addr + requested_size,
+			    area->size - requested_size,
+			    KASAN_VMALLOC_INVALID);
+}
+#endif
diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
index 36c645939bc9..2d97efd4954f 100644
--- a/mm/kasan/generic_report.c
+++ b/mm/kasan/generic_report.c
@@ -86,6 +86,9 @@ static const char *get_shadow_bug_type(struct kasan_access_info *info)
 	case KASAN_ALLOCA_RIGHT:
 		bug_type = "alloca-out-of-bounds";
 		break;
+	case KASAN_VMALLOC_INVALID:
+		bug_type = "vmalloc-out-of-bounds";
+		break;
 	}
 
 	return bug_type;
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 014f19e76247..8b1f2fbc780b 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -25,6 +25,7 @@
 #endif
 
 #define KASAN_GLOBAL_REDZONE    0xFA  /* redzone for global variable */
+#define KASAN_VMALLOC_INVALID   0xF9  /* unallocated space in vmapped page */
 
 /*
  * Stack redzone shadow values
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 4fa8d84599b0..8cbcb5056c9b 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2012,6 +2012,15 @@ static void setup_vmalloc_vm(struct vm_struct *vm, struct vmap_area *va,
 	va->vm = vm;
 	va->flags |= VM_VM_AREA;
 	spin_unlock(&vmap_area_lock);
+
+	/*
+	 * If we are in vmalloc space we need to cover the shadow area with
+	 * real memory. If we come here through VM_ALLOC, this is done
+	 * by a higher level function that has access to the true size,
+	 * which might not be a full page.
+	 */
+	if (is_vmalloc_addr(vm->addr) && !(vm->flags & VM_ALLOC))
+		kasan_cover_vmalloc(vm->size, vm);
 }
 
 static void clear_vm_uninitialized_flag(struct vm_struct *vm)
@@ -2483,6 +2492,8 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 	if (!addr)
 		return NULL;
 
+	kasan_cover_vmalloc(real_size, area);
+
 	/*
 	 * In this function, newly allocated vm_struct has VM_UNINITIALIZED
 	 * flag. It means that vm_struct is not fully initialized.
@@ -3324,9 +3335,11 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	spin_unlock(&vmap_area_lock);
 
 	/* insert all vm's */
-	for (area = 0; area < nr_vms; area++)
+	for (area = 0; area < nr_vms; area++) {
 		setup_vmalloc_vm(vms[area], vas[area], VM_ALLOC,
 				 pcpu_get_vm_areas);
+		kasan_cover_vmalloc(sizes[area], vms[area]);
+	}
 
 	kfree(vas);
 	return vms;
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190725055503.19507-2-dja%40axtens.net.
