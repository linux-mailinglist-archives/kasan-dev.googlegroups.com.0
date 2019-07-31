Return-Path: <kasan-dev+bncBDQ27FVWWUFRBMMAQXVAKGQEVO577SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id BC5867BA7B
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2019 09:16:02 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id w200sf40712564ybg.11
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2019 00:16:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564557361; cv=pass;
        d=google.com; s=arc-20160816;
        b=SDm4va8Yknpea5zTBmd0zn40jYimhM9dCWQwb4SGYrTPV9FP0/ZxZ622zmH2H40m7b
         ezwGadcXN/ByrvO5omASN9ALkeyRofHheVnNacy7Lr/zv91J6J8SASwhR5sJsuHNJvb9
         CC5xnCSeCVrQP0OSj1ebZwq5lJE2lG0UZSfOlHT80ZaoRr8+D37FIiHMqaujnk0RhX1D
         fYBPTSheuqIxZm1uQIROTr9IZMcPCnn8BTYSu0XcG+nsCiSJDon0KHGNZVXjRcBgTPcV
         F5YvKaBm2zHPWx9wIjIqs6DZushGuWfqAsKra1mowX6Of4bech7TZ6WDLIoJk1/9Q+YA
         mUVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gV+FRVVrM3dO64CRkV4kVtbqYY3z4TziwqWzm3VVjBg=;
        b=rpCL6x68Tv3ucSJalMdc4G1refsvLb0iIM4G+5fDo8x50WhSvvL+B4L+z2U0YjtKQa
         pYWzvGvBJFqlSpIrVw53WhIbSRjC5AHhciu2UgdQa0gz7R4BwnezlCXM8qRIUgyK0l91
         2uxHtQkoKftS+NMlDcxfCIymJ4xsz0ObrZpwqy44Ds9sb8SCjuTzLju7X+Ky0Aa3utaV
         uDVXFo6uNP33ur1zjWoEzQBRDa/cNd1lpe6mQv4p9EYrsUm2kaw8+/36J0VNyd0mqich
         jmnQRj2oefN8yOa3ZCsy/CzsjtAGwIaF3h+uZ1MK+zdHREVpOHsxh2s16nMgONkBaz2E
         r1Og==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=qIDHcXG7;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gV+FRVVrM3dO64CRkV4kVtbqYY3z4TziwqWzm3VVjBg=;
        b=d5pOmC4PAZADelmp46nuC33BRThZkP5AV/zXOYxThlcI6YDQyeYLSqMPbvwA0rD1uY
         18FRGXikeP1iyXQ5siiQXxZAD2tfZuy0AWcbK1iLCPZQc1i2idUN4TMRBeO5ru0dv60+
         +85MVdJn3m53EPP2W6MvlLh7XMGftoXDU/7RVcipgOVpc6QKzWjId/P0/3ABOrGuYDgj
         Ad6YSC1EpWawABNicfPaEnH4g0+h2X7ohaiWsIT/ZMYvq/TfHwtYEUqFnpa0crqgE2yM
         n+k+DBGZyxePgC8ZC/xwAG5sLwf5qmDwhvpV9g89gYOz7AX2xpx1dQT+3cFUyQo7YLf8
         r1LA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gV+FRVVrM3dO64CRkV4kVtbqYY3z4TziwqWzm3VVjBg=;
        b=QEw2sC65hGpi8ahbu0utdys3Vp5fr+RGNMHiya/g8uZQW3selPGiaMsuPGelDA0MmV
         GoF9Ykqd1fNM/1bb9P8rIt4+Nbrosfsd9iIwQ7R2TR+z0uon2ninlEYwkDXeAqI+D/sn
         32gfKadDhe8IaGNVxg/f1wsSUSmphr0xURxPYTbEushSy6Acpg2cKXzh6wNA8l9dZpXc
         oO2djJ+S7VdEix3obeQK8pAD2R8Qch0vHbVn2sFnMR6CO+xtA3+f6IoUmGiaOHhxy4d2
         7atICoyLDX9JK1uH84nrSF07KOZYt3sQsF/eHVKpHW5/gURflDZ9qhHARdY5mEkIl5uX
         fVrA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXMdx/9LuOX9xtbnPFfnfy9q/lwXJg56PbgV5aV/DOeZ4uXemOA
	1LFGUG2jPzkk1BUH81FYKzA=
X-Google-Smtp-Source: APXvYqzovA38ATpOJAAgh18mYkw8mziqPFxBhZrLaEsfH0sUtfIyapXNIuhqweTtPrQHPBV6Ozu13w==
X-Received: by 2002:a81:984e:: with SMTP id p75mr73957804ywg.200.1564557361727;
        Wed, 31 Jul 2019 00:16:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:48d3:: with SMTP id v202ls10697203ywa.9.gmail; Wed, 31
 Jul 2019 00:16:01 -0700 (PDT)
X-Received: by 2002:a81:1a05:: with SMTP id a5mr74778890ywa.111.1564557361500;
        Wed, 31 Jul 2019 00:16:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564557361; cv=none;
        d=google.com; s=arc-20160816;
        b=bAZWqYDU/WNqMC63WHAA+/DkF4a88VnSAXfWypZtrnnRc2yhilni+QalOBy1KLGXB/
         mpl89EsiC30b70TndaNm2vBooR0fVUE8vuONpuCgzbRQAkuoRzDGdVS3TkB3F32CgZVW
         oe4UErnNRKI/zRghRR8LSZejTCAAsqYJfap89c523R4Flj7P1+kJ4lJvuY0J9FKAU17A
         qZu51uE7YmNAJj+eAzUxfJkrTY82j1u2xUUMj/SVrgw5nlek7ssFQrlIsS1oNXnHj3bm
         O0Ozp2/yjjOJ3yrylAIGzQfdmMjyEiWiEXBCmi7Act3lizCk+kUulWctYMEx1+sZPWHP
         0FLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ckINI7DWJx4t0SHL49BoktL6GXoY0zg6g25Z0xvH2hk=;
        b=fhhU8j9DwY/jE54nB39wNthVmvtRCFYk4ItIxSWpVz7d0FX5Fnm5HUdWDJTLPTx5qG
         Dkm8nujIKop5IW/b4YiErbzhaTVLPVrYSfVOGbVxHCoF4fE6Oa8TKdt7R97NuRn8fP6d
         vQUPx4Y27e8FYKpkkxzERlNV7kEJfiXD4MzVY6U45KHsp6T6pbzm8zTjtEu3FzGtnbBa
         2FwuVveb2Kj6J2GUO2SHD6FVwmZ88G2+xRTNXGwCgKAQf1lLUVoXEhS1YBQBqu1F9e0A
         M4CB0qqYJJBmIDl/UGnGiu7bveqtRNYCM5KrHJ0DKU+JnBOd9GEhlFiLoEzqweEn0gi2
         j4Hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=qIDHcXG7;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id b74si2829987yba.4.2019.07.31.00.16.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 31 Jul 2019 00:16:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id az7so30050635plb.5
        for <kasan-dev@googlegroups.com>; Wed, 31 Jul 2019 00:16:01 -0700 (PDT)
X-Received: by 2002:a17:902:bd94:: with SMTP id q20mr108836009pls.307.1564557360253;
        Wed, 31 Jul 2019 00:16:00 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id 67sm39489035pfd.177.2019.07.31.00.15.58
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Wed, 31 Jul 2019 00:15:59 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org,
	mark.rutland@arm.com,
	dvyukov@google.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v3 1/3] kasan: support backing vmalloc space with real shadow memory
Date: Wed, 31 Jul 2019 17:15:48 +1000
Message-Id: <20190731071550.31814-2-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190731071550.31814-1-dja@axtens.net>
References: <20190731071550.31814-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=qIDHcXG7;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as
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
currently working on). It also allows relaxing the module alignment
back to PAGE_SIZE.

Link: https://bugzilla.kernel.org/show_bug.cgi?id=202009
Signed-off-by: Daniel Axtens <dja@axtens.net>

---

v2: let kasan_unpoison_shadow deal with ranges that do not use a
    full shadow byte.

v3: relax module alignment
    rename to kasan_populate_vmalloc which is a much better name
    deal with concurrency correctly
---
 Documentation/dev-tools/kasan.rst | 60 ++++++++++++++++++++++
 include/linux/kasan.h             | 16 ++++++
 include/linux/moduleloader.h      |  2 +-
 lib/Kconfig.kasan                 | 16 ++++++
 lib/test_kasan.c                  | 26 ++++++++++
 mm/kasan/common.c                 | 83 +++++++++++++++++++++++++++++++
 mm/kasan/generic_report.c         |  3 ++
 mm/kasan/kasan.h                  |  1 +
 mm/vmalloc.c                      | 15 +++++-
 9 files changed, 220 insertions(+), 2 deletions(-)

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
index cc8a03cc9674..ec81113fcee4 100644
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
+void kasan_populate_vmalloc(unsigned long requested_size, struct vm_struct *area);
+#else
+static inline void kasan_populate_vmalloc(unsigned long requested_size, struct vm_struct *area) {}
+#endif
+
 #endif /* LINUX_KASAN_H */
diff --git a/include/linux/moduleloader.h b/include/linux/moduleloader.h
index 5229c18025e9..ca92aea8a6bd 100644
--- a/include/linux/moduleloader.h
+++ b/include/linux/moduleloader.h
@@ -91,7 +91,7 @@ void module_arch_cleanup(struct module *mod);
 /* Any cleanup before freeing mod->module_init */
 void module_arch_freeing_init(struct module *mod);
 
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN) && !defined(CONFIG_KASAN_VMALLOC)
 #include <linux/kasan.h>
 #define MODULE_ALIGN (PAGE_SIZE << KASAN_SHADOW_SCALE_SHIFT)
 #else
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
index 2277b82902d8..e1a748c3f3db 100644
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
 
@@ -722,3 +724,84 @@ static int __init kasan_memhotplug_init(void)
 
 core_initcall(kasan_memhotplug_init);
 #endif
+
+#ifdef CONFIG_KASAN_VMALLOC
+void kasan_populate_vmalloc(unsigned long requested_size, struct vm_struct *area)
+{
+	unsigned long shadow_alloc_start, shadow_alloc_end;
+	unsigned long addr;
+	unsigned long page;
+	pgd_t *pgdp;
+	p4d_t *p4dp;
+	pud_t *pudp;
+	pmd_t *pmdp;
+	pte_t *ptep;
+	pte_t pte;
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
+		 * The pte may not be none if we allocated the page earlier to
+		 * use part of it for another allocation.
+		 *
+		 * Because we only ever add to the vmalloc shadow pages and
+		 * never free any, we can optimise here by checking for the pte
+		 * presence outside the lock. It's OK to race with another
+		 * allocation here because we do the 'real' test under the lock.
+		 * This just allows us to save creating/freeing the new shadow
+		 * page in the common case.
+		 */
+		if (!pte_none(*ptep))
+			continue;
+
+		/*
+		 * We're probably going to need to populate the shadow.
+		 * Allocate and poision the shadow page now, outside the lock.
+		 */
+		page = __get_free_page(GFP_KERNEL);
+		memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
+		pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
+
+		spin_lock(&init_mm.page_table_lock);
+		if (pte_none(*ptep)) {
+			set_pte_at(&init_mm, addr, ptep, pte);
+			page = 0;
+		}
+		spin_unlock(&init_mm.page_table_lock);
+
+		/* catch the case where we raced and don't need the page */
+		if (page)
+			free_page(page);
+	} while (addr += PAGE_SIZE, addr != shadow_alloc_end);
+
+	kasan_unpoison_shadow(area->addr, requested_size);
+
+	/*
+	 * We have to poison the remainder of the allocation each time, not
+	 * just when the shadow page is first allocated, because vmalloc may
+	 * reuse addresses, and an early large allocation would cause us to
+	 * miss OOBs in future smaller allocations.
+	 *
+	 * The alternative is to poison the shadow on vfree()/vunmap(). We
+	 * don't because the unmapping the virtual addresses should be
+	 * sufficient to find most UAFs.
+	 */
+	requested_size = round_up(requested_size, KASAN_SHADOW_SCALE_SIZE);
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
index 4fa8d84599b0..406097ff8ced 100644
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
+		kasan_populate_vmalloc(vm->size, vm);
 }
 
 static void clear_vm_uninitialized_flag(struct vm_struct *vm)
@@ -2483,6 +2492,8 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 	if (!addr)
 		return NULL;
 
+	kasan_populate_vmalloc(real_size, area);
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
+		kasan_populate_vmalloc(sizes[area], vms[area]);
+	}
 
 	kfree(vas);
 	return vms;
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190731071550.31814-2-dja%40axtens.net.
