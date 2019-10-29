Return-Path: <kasan-dev+bncBDQ27FVWWUFRBOH433WQKGQE642Y3DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id F25BFE7F1D
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2019 05:21:13 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id b24sf10131390pgi.5
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Oct 2019 21:21:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572322872; cv=pass;
        d=google.com; s=arc-20160816;
        b=WqZpaSG0LH/3RVby7SLRbnK+GO/74Kq6H8hRq2DnmxijiDhoAttw1RYR3VH56Q/IU1
         xwvHiPKjqKvlFiyhBvbIrCJhQXlDG9Kiyvhio7W3QhH5B0Nqf9/ZPbQceoEfvoGGoWqK
         G9C0N7WDlgxXcDOyrQRvo+kNCRMtO69znZcgIuNqDsJ4PkEYhIoktfR0v9716wbomdZ7
         mIP4/hnxwDtg08j61uAMoW/tr4FzpIrGV81vkwMcPocctPEzZBZrrT5ACpPnzYjxYlRt
         vw9qphy0q9vEjCvcTubjk+alaZqeQhn+HbwyXsf1etalOaruK2RDUCNqaikFfp6Xoa44
         O4XQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=iO7WneYgg0B0EsKh/UxLl8iCF5V2iP/ndDxm9TMRzms=;
        b=viXIid98wYtlyAzCJ5SouuIpaZ+5ddeEQ5a8bprZ8rOj1Mm4aDxeCFs2pRvxTU2GFk
         MFZZvzshnExqObj/1N5s5jyPLzz+zClOMK4W71Ih35I7wBrYJFSKhhxDNFtq+qv9g3Q7
         x/07NEmZJiWT9axrilrGe2Oy62FiopHj8v28ns9lUeCYJgI9I9J5Aq7Dj5rw8xJrupeG
         BoWv2cnKtuVbHaQa/gUR3496sIyublVqjE2f6BrD3U9XkSdnKHdFtgEvkmwWtsctxzPM
         8LL4iBVrJWnkQZy06jVF7Hf8RvHCSkprIg3cc28OyLqASAsRXuLsSfCzoRGpdHZvrDHZ
         a1Fw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Ptcyww7R;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iO7WneYgg0B0EsKh/UxLl8iCF5V2iP/ndDxm9TMRzms=;
        b=csqw8WSj9Oj+XsR+nM8zRo65isYxgr9N70DwVOzrGic1OPQ2R308yTLSt5biLbHp0Y
         oN3la7NkEYIrOVUv8xjeKHpHA08wYQW+VeG9u0STb67Te4O6NVIIFxNjoC/UrppqFlMX
         8zqY0PfyqaUEbdkjaBQMigA6wJL4vysYj+O2dqkgwuVSLT5XDL5g6DBRyzSPzcyaKLiT
         UGDXyNNssD5V8/om7bm8vETeSCeoTFIZit1oH1+bN/A+8cS/lumPzlcyIaXD2SsLiYgy
         LwbX0RRrbZvL+RNgwyor1l2mdt7OaiQUNZQjA5hEYxuSfEC5AUZKHhGErjnBL7EzwaVN
         Uw5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iO7WneYgg0B0EsKh/UxLl8iCF5V2iP/ndDxm9TMRzms=;
        b=kMSHogGG1kfOV3cUi12d6MYy/AAN9oEOPIkgfy4dqtPzUSE3QyhKNs9s2DaTBDglfO
         UepU6FvEC2GaFHEO5vMD/c1eHN9Ao7BO1Uos7wB6B1rLb5Cpg6jT14IhqAz9uNRwzWuC
         V451Dr8/VtkRzaiD5V+Y5jdB7Azq00mNlN3aL+ArNukKq+TMV4vd2TzYsSFDfjVwRejC
         0T4k/vemzNTR5hHSSSamzMOqsLWN27nAimAPu7cIWfQi3YiX+jRrsib9pi6nJH6gEEiz
         axCwmJeleLmpT0VIlzJk2Vz/ZcbYXbOt2NBWxdLORy2a19wVk2Uc2Xv1mY93rp1poIpi
         w1pg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWbpB8dbY3SzHPLXK7l8VSe+1XzLVs1HMkAg9nowoVTRP8ldWW/
	j3FioKRz3P9cn5l6vWrQ31Y=
X-Google-Smtp-Source: APXvYqz0jvEVCL8aPIj+zKeYjmNGVnLiLqzDqj/YCo/aL13ErGxxBS13Qt0MuYxMZV1i5BB2ku722Q==
X-Received: by 2002:a17:90a:a891:: with SMTP id h17mr3700499pjq.32.1572322872168;
        Mon, 28 Oct 2019 21:21:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f303:: with SMTP id ca3ls1037861pjb.0.gmail; Mon, 28
 Oct 2019 21:21:11 -0700 (PDT)
X-Received: by 2002:a17:90a:a417:: with SMTP id y23mr3483970pjp.126.1572322871686;
        Mon, 28 Oct 2019 21:21:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572322871; cv=none;
        d=google.com; s=arc-20160816;
        b=dznwlMFg5BvjX+HzDW5VseYwH4CNMGSjfcTHBQiEAI97RVhC1Oc0tx0vkqW6fIX1IH
         1avpcWZoQKLxBDfH+gBl2Myl4ILiz2FdU5r5N/Su5p/wVfoZ7q89v7MnsrnW8OojGlmq
         srp5DKBfU2T7MKFlcBvgEKcpsN6eMnVeyafDBes7/EXoYsYtPxIDtKF55VC7H1vkP9Ao
         sTviLqOtSRwAr83B+ZxdteZUfdDwLXhS2Jiv7//ui/SHm+APBM8Xz7NRsqBJjUjrRqva
         BoU3OPFIUigvBlqmX6x2POY8vBWpUtnaZ40Y2/sdRINut8WfgQ0iQVsIkJeFxkrvRL6O
         OXeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4Oxoy4AcIpDr0SnzVXM1SUVNYlzjqfyUtQpnB1pgOHo=;
        b=e9pktkPy89Mo3xXfRLoO/pbZ3e/cHKGep//WHWwDbfsg1ZRhmYNyqwW79+Wt9ErhYF
         GHUc86ru6aRGPj+nlilJfXDyHpRv78l6kxCHYGypvoElBwPL+Shg/0xInmgTgJoCPAky
         NohSXdOLMgsfbEjE4+4LBoIg5g4ETeTq9Nnj85tOdC5vQW+48QmfCa4cM1gstSKGPuyw
         DSmIdR4IIjtGX8zXhXr9bdtu4YMXq8FWh5xQ6C8IsA5rqBZ6GRGlAIEQCf3WOsI7AsOZ
         THfLWhOW5KsOs9NtseaIXRW1Ym2WNsxUFPXDt68E4JBSscw4zjOeWgeJ9yuZ3yvmxbUM
         qQ/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Ptcyww7R;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id h13si72786plr.2.2019.10.28.21.21.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Oct 2019 21:21:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id l3so8578247pgr.8
        for <kasan-dev@googlegroups.com>; Mon, 28 Oct 2019 21:21:11 -0700 (PDT)
X-Received: by 2002:a62:ee0d:: with SMTP id e13mr21663200pfi.58.1572322870424;
        Mon, 28 Oct 2019 21:21:10 -0700 (PDT)
Received: from localhost ([2001:44b8:802:1120:783a:2bb9:f7cb:7c3c])
        by smtp.gmail.com with ESMTPSA id l62sm12704553pfl.167.2019.10.28.21.21.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Oct 2019 21:21:09 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org,
	mark.rutland@arm.com,
	dvyukov@google.com,
	christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v10 1/5] kasan: support backing vmalloc space with real shadow memory
Date: Tue, 29 Oct 2019 15:20:55 +1100
Message-Id: <20191029042059.28541-2-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191029042059.28541-1-dja@axtens.net>
References: <20191029042059.28541-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=Ptcyww7R;       spf=pass
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

Instead, share backing space across multiple mappings. Allocate a
backing page when a mapping in vmalloc space uses a particular page of
the shadow region. This page can be shared by other vmalloc mappings
later on.

We hook in to the vmap infrastructure to lazily clean up unused shadow
memory.

To avoid the difficulties around swapping mappings around, this code
expects that the part of the shadow region that covers the vmalloc
space will not be covered by the early shadow page, but will be left
unmapped. This will require changes in arch-specific code.

This allows KASAN with VMAP_STACK, and may be helpful for architectures
that do not have a separate module space (e.g. powerpc64, which I am
currently working on). It also allows relaxing the module alignment
back to PAGE_SIZE.

Link: https://bugzilla.kernel.org/show_bug.cgi?id=202009
Acked-by: Vasily Gorbik <gor@linux.ibm.com>
Co-developed-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Mark Rutland <mark.rutland@arm.com> [shadow rework]
Signed-off-by: Daniel Axtens <dja@axtens.net>

--

v2: let kasan_unpoison_shadow deal with ranges that do not use a
    full shadow byte.

v3: relax module alignment
    rename to kasan_populate_vmalloc which is a much better name
    deal with concurrency correctly

v4: Mark's rework
    Poision pages on vfree
    Handle allocation failures

v5: Per Christophe Leroy, split out test and dynamically free pages.

v6: Guard freeing page properly. Drop WARN_ON_ONCE(pte_none(*ptep)),
     on reflection it's unnecessary debugging cruft with too high a
     false positive rate.

v7: tlb flush, thanks Mark.
    explain more clearly how freeing works and is concurrency-safe.

v9:  - Pull in Uladzislau Rezki's changes to better line up with the
       design of the new vmalloc implementation. Thanks Vlad.
     - clarify comment explaining smp_wmb() per Mark and Andrey's discussion
     - tighten up the allocation of backing memory so that it only
       happens for vmalloc or module  space allocations. Thanks Andrey
       Ryabinin.
     - A TLB flush in the freeing path, thanks Mark Rutland.

v10: - rebase on next, pulling in Vlad's new work on splitting the
       vmalloc locks. This doesn't require changes in our behaviour
       but does require rechecking and rewording the explanation of why
       our behaviour is safe.
     - after much discussion of barriers, I now document where I think they
       are needed and why. Thanks Mark and Andrey.
     - clean up some TLB flushing. We were doing it twice - once after each
       page and once at the end of the whole process. Only do it at the end
       of the whole depopulate process.
     - checkpatch cleanups
---
 Documentation/dev-tools/kasan.rst |  63 ++++++++
 include/linux/kasan.h             |  31 ++++
 include/linux/moduleloader.h      |   2 +-
 include/linux/vmalloc.h           |  12 ++
 lib/Kconfig.kasan                 |  16 +++
 mm/kasan/common.c                 | 231 ++++++++++++++++++++++++++++++
 mm/kasan/generic_report.c         |   3 +
 mm/kasan/kasan.h                  |   1 +
 mm/vmalloc.c                      |  53 +++++--
 9 files changed, 403 insertions(+), 9 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 525296121d89..e4d66e7c50de 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -218,3 +218,66 @@ brk handler is used to print bug reports.
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
+a backing page when a mapping in vmalloc space uses a particular page
+of the shadow region. This page can be shared by other vmalloc
+mappings later on.
+
+We hook in to the vmap infrastructure to lazily clean up unused shadow
+memory.
+
+To avoid the difficulties around swapping mappings around, we expect
+that the part of the shadow region that covers the vmalloc space will
+not be covered by the early shadow page, but will be left
+unmapped. This will require changes in arch-specific code.
+
+This allows ``VMAP_STACK`` support on x86, and can simplify support of
+architectures that do not have a fixed module region.
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index cc8a03cc9674..4f404c565db1 100644
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
@@ -194,4 +204,25 @@ static inline void *kasan_reset_tag(const void *addr)
 
 #endif /* CONFIG_KASAN_SW_TAGS */
 
+#ifdef CONFIG_KASAN_VMALLOC
+int kasan_populate_vmalloc(unsigned long requested_size,
+			   struct vm_struct *area);
+void kasan_poison_vmalloc(void *start, unsigned long size);
+void kasan_release_vmalloc(unsigned long start, unsigned long end,
+			   unsigned long free_region_start,
+			   unsigned long free_region_end);
+#else
+static inline int kasan_populate_vmalloc(unsigned long requested_size,
+					 struct vm_struct *area)
+{
+	return 0;
+}
+
+static inline void kasan_poison_vmalloc(void *start, unsigned long size) {}
+static inline void kasan_release_vmalloc(unsigned long start,
+					 unsigned long end,
+					 unsigned long free_region_start,
+					 unsigned long free_region_end) {}
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
diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
index 4e7809408073..61c43d1a29ca 100644
--- a/include/linux/vmalloc.h
+++ b/include/linux/vmalloc.h
@@ -22,6 +22,18 @@ struct notifier_block;		/* in notifier.h */
 #define VM_UNINITIALIZED	0x00000020	/* vm_struct is not fully initialized */
 #define VM_NO_GUARD		0x00000040      /* don't add guard page */
 #define VM_KASAN		0x00000080      /* has allocated kasan shadow memory */
+
+/*
+ * VM_KASAN is used slighly differently depending on CONFIG_KASAN_VMALLOC.
+ *
+ * If IS_ENABLED(CONFIG_KASAN_VMALLOC), VM_KASAN is set on a vm_struct after
+ * shadow memory has been mapped. It's used to handle allocation errors so that
+ * we don't try to poision shadow on free if it was never allocated.
+ *
+ * Otherwise, VM_KASAN is set for kasan_module_alloc() allocations and used to
+ * determine which allocations need the module shadow freed.
+ */
+
 /*
  * Memory with VM_FLUSH_RESET_PERMS cannot be freed in an interrupt or with
  * vfree_atomic().
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 6c9682ce0254..81f5464ea9e1 100644
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
 
@@ -142,6 +145,19 @@ config KASAN_SW_TAGS_IDENTIFY
 	  (use-after-free or out-of-bounds) at the cost of increased
 	  memory consumption.
 
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
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6814d6d6a023..6e7bc5d3fa83 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -36,6 +36,8 @@
 #include <linux/bug.h>
 #include <linux/uaccess.h>
 
+#include <asm/tlbflush.h>
+
 #include "kasan.h"
 #include "../slab.h"
 
@@ -590,6 +592,7 @@ void kasan_kfree_large(void *ptr, unsigned long ip)
 	/* The object will be poisoned by page_alloc. */
 }
 
+#ifndef CONFIG_KASAN_VMALLOC
 int kasan_module_alloc(void *addr, size_t size)
 {
 	void *ret;
@@ -625,6 +628,7 @@ void kasan_free_shadow(const struct vm_struct *vm)
 	if (vm->flags & VM_KASAN)
 		vfree(kasan_mem_to_shadow(vm->addr));
 }
+#endif
 
 extern void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip);
 
@@ -744,3 +748,230 @@ static int __init kasan_memhotplug_init(void)
 
 core_initcall(kasan_memhotplug_init);
 #endif
+
+#ifdef CONFIG_KASAN_VMALLOC
+static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
+				      void *unused)
+{
+	unsigned long page;
+	pte_t pte;
+
+	if (likely(!pte_none(*ptep)))
+		return 0;
+
+	page = __get_free_page(GFP_KERNEL);
+	if (!page)
+		return -ENOMEM;
+
+	memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
+	pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
+
+	spin_lock(&init_mm.page_table_lock);
+	if (likely(pte_none(*ptep))) {
+		set_pte_at(&init_mm, addr, ptep, pte);
+		page = 0;
+	}
+	spin_unlock(&init_mm.page_table_lock);
+	if (page)
+		free_page(page);
+	return 0;
+}
+
+int kasan_populate_vmalloc(unsigned long requested_size, struct vm_struct *area)
+{
+	unsigned long shadow_start, shadow_end;
+	int ret;
+
+	shadow_start = (unsigned long)kasan_mem_to_shadow(area->addr);
+	shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
+	shadow_end = (unsigned long)kasan_mem_to_shadow(area->addr +
+							area->size);
+	shadow_end = ALIGN(shadow_end, PAGE_SIZE);
+
+	ret = apply_to_page_range(&init_mm, shadow_start,
+				  shadow_end - shadow_start,
+				  kasan_populate_vmalloc_pte, NULL);
+	if (ret)
+		return ret;
+
+	kasan_unpoison_shadow(area->addr, requested_size);
+
+	area->flags |= VM_KASAN;
+
+	/*
+	 * We need to be careful about inter-cpu effects here. Consider:
+	 *
+	 *   CPU#0				  CPU#1
+	 * WRITE_ONCE(p, vmalloc(100));		while (x = READ_ONCE(p)) ;
+	 *					p[99] = 1;
+	 *
+	 * With compiler instrumentation, that ends up looking like this:
+	 *
+	 *   CPU#0				  CPU#1
+	 * // vmalloc() allocates memory
+	 * // let a = area->addr
+	 * // we reach kasan_populate_vmalloc
+	 * // and call kasan_unpoison_shadow:
+	 * STORE shadow(a), unpoison_val
+	 * ...
+	 * STORE shadow(a+99), unpoison_val	x = LOAD p
+	 * // rest of vmalloc process		<data dependency>
+	 * STORE p, a				LOAD shadow(x+99)
+	 *
+	 * If there is no barrier between the end of unpoisioning the shadow
+	 * and the store of the result to p, the stores could be committed
+	 * in a different order by CPU#0, and CPU#1 could erroneously observe
+	 * poison in the shadow.
+	 *
+	 * We need some sort of barrier between the stores.
+	 *
+	 * In the vmalloc() case, this is provided by a smp_wmb() in
+	 * clear_vm_uninitialized_flag(). In the per-cpu allocator and in
+	 * get_vm_area() and friends, the caller gets shadow allocated but
+	 * doesn't have any pages mapped into the virtual address space that
+	 * has been reserved. Mapping those pages in will involve taking and
+	 * releasing a page-table lock, which will provide the barrier.
+	 */
+
+	return 0;
+}
+
+/*
+ * Poison the shadow for a vmalloc region. Called as part of the
+ * freeing process at the time the region is freed.
+ */
+void kasan_poison_vmalloc(void *start, unsigned long size)
+{
+	size = round_up(size, KASAN_SHADOW_SCALE_SIZE);
+	kasan_poison_shadow(start, size, KASAN_VMALLOC_INVALID);
+}
+
+static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
+					void *unused)
+{
+	unsigned long page;
+
+	page = (unsigned long)__va(pte_pfn(*ptep) << PAGE_SHIFT);
+
+	spin_lock(&init_mm.page_table_lock);
+
+	if (likely(!pte_none(*ptep))) {
+		pte_clear(&init_mm, addr, ptep);
+		free_page(page);
+	}
+	spin_unlock(&init_mm.page_table_lock);
+
+	return 0;
+}
+
+/*
+ * Release the backing for the vmalloc region [start, end), which
+ * lies within the free region [free_region_start, free_region_end).
+ *
+ * This can be run lazily, long after the region was freed. It runs
+ * under vmap_area_lock, so it's not safe to interact with the vmalloc/vmap
+ * infrastructure.
+ *
+ * How does this work?
+ * -------------------
+ *
+ * We have a region that is page aligned, labelled as A.
+ * That might not map onto the shadow in a way that is page-aligned:
+ *
+ *                    start                     end
+ *                    v                         v
+ * |????????|????????|AAAAAAAA|AA....AA|AAAAAAAA|????????| < vmalloc
+ *  -------- -------- --------          -------- --------
+ *      |        |       |                 |        |
+ *      |        |       |         /-------/        |
+ *      \-------\|/------/         |/---------------/
+ *              |||                ||
+ *             |??AAAAAA|AAAAAAAA|AA??????|                < shadow
+ *                 (1)      (2)      (3)
+ *
+ * First we align the start upwards and the end downwards, so that the
+ * shadow of the region aligns with shadow page boundaries. In the
+ * example, this gives us the shadow page (2). This is the shadow entirely
+ * covered by this allocation.
+ *
+ * Then we have the tricky bits. We want to know if we can free the
+ * partially covered shadow pages - (1) and (3) in the example. For this,
+ * we are given the start and end of the free region that contains this
+ * allocation. Extending our previous example, we could have:
+ *
+ *  free_region_start                                    free_region_end
+ *  |                 start                     end      |
+ *  v                 v                         v        v
+ * |FFFFFFFF|FFFFFFFF|AAAAAAAA|AA....AA|AAAAAAAA|FFFFFFFF| < vmalloc
+ *  -------- -------- --------          -------- --------
+ *      |        |       |                 |        |
+ *      |        |       |         /-------/        |
+ *      \-------\|/------/         |/---------------/
+ *              |||                ||
+ *             |FFAAAAAA|AAAAAAAA|AAF?????|                < shadow
+ *                 (1)      (2)      (3)
+ *
+ * Once again, we align the start of the free region up, and the end of
+ * the free region down so that the shadow is page aligned. So we can free
+ * page (1) - we know no allocation currently uses anything in that page,
+ * because all of it is in the vmalloc free region. But we cannot free
+ * page (3), because we can't be sure that the rest of it is unused.
+ *
+ * We only consider pages that contain part of the original region for
+ * freeing: we don't try to free other pages from the free region or we'd
+ * end up trying to free huge chunks of virtual address space.
+ *
+ * Concurrency
+ * -----------
+ *
+ * How do we know that we're not freeing a page that is simultaneously
+ * being used for a fresh allocation in kasan_populate_vmalloc(_pte)?
+ *
+ * We _can_ have kasan_release_vmalloc and kasan_populate_vmalloc running
+ * at the same time. While we run under free_vmap_area_lock, the population
+ * code does not.
+ *
+ * free_vmap_area_lock instead operates to ensure that the larger range
+ * [free_region_start, free_region_end) is safe: because __alloc_vmap_area and
+ * the per-cpu region-finding algorithm both run under free_vmap_area_lock,
+ * no space identified as free will become used while we are running. This
+ * means that so long as we are careful with alignment and only free shadow
+ * pages entirely covered by the free region, we will not run in to any
+ * trouble - any simultaneous allocations will be for disjoint regions.
+ */
+void kasan_release_vmalloc(unsigned long start, unsigned long end,
+			   unsigned long free_region_start,
+			   unsigned long free_region_end)
+{
+	void *shadow_start, *shadow_end;
+	unsigned long region_start, region_end;
+
+	region_start = ALIGN(start, PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
+	region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
+
+	free_region_start = ALIGN(free_region_start,
+				  PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
+
+	if (start != region_start &&
+	    free_region_start < region_start)
+		region_start -= PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE;
+
+	free_region_end = ALIGN_DOWN(free_region_end,
+				     PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
+
+	if (end != region_end &&
+	    free_region_end > region_end)
+		region_end += PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE;
+
+	shadow_start = kasan_mem_to_shadow((void *)region_start);
+	shadow_end = kasan_mem_to_shadow((void *)region_end);
+
+	if (shadow_end > shadow_start) {
+		apply_to_page_range(&init_mm, (unsigned long)shadow_start,
+				    (unsigned long)(shadow_end - shadow_start),
+				    kasan_depopulate_vmalloc_pte, NULL);
+		flush_tlb_kernel_range((unsigned long)shadow_start,
+				       (unsigned long)shadow_end);
+	}
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
index 35cff6bbb716..3a083274628e 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -25,6 +25,7 @@
 #endif
 
 #define KASAN_GLOBAL_REDZONE    0xFA  /* redzone for global variable */
+#define KASAN_VMALLOC_INVALID   0xF9  /* unallocated space in vmapped page */
 
 /*
  * Stack redzone shadow values
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index f48f64c8d200..cbcc2646c122 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -683,7 +683,7 @@ insert_vmap_area_augment(struct vmap_area *va,
  * free area is inserted. If VA has been merged, it is
  * freed.
  */
-static __always_inline void
+static __always_inline struct vmap_area *
 merge_or_add_vmap_area(struct vmap_area *va,
 	struct rb_root *root, struct list_head *head)
 {
@@ -750,7 +750,10 @@ merge_or_add_vmap_area(struct vmap_area *va,
 
 			/* Free vmap_area object. */
 			kmem_cache_free(vmap_area_cachep, va);
-			return;
+
+			/* Point to the new merged area. */
+			va = sibling;
+			merged = true;
 		}
 	}
 
@@ -759,6 +762,8 @@ merge_or_add_vmap_area(struct vmap_area *va,
 		link_va(va, root, parent, link, head);
 		augment_tree_propagate_from(va);
 	}
+
+	return va;
 }
 
 static __always_inline bool
@@ -1196,8 +1201,8 @@ static void free_vmap_area(struct vmap_area *va)
 	 * Insert/Merge it back to the free tree/list.
 	 */
 	spin_lock(&free_vmap_area_lock);
-	merge_or_add_vmap_area(va,
-		&free_vmap_area_root, &free_vmap_area_list);
+	(void)merge_or_add_vmap_area(va, &free_vmap_area_root,
+				     &free_vmap_area_list);
 	spin_unlock(&free_vmap_area_lock);
 }
 
@@ -1294,14 +1299,19 @@ static bool __purge_vmap_area_lazy(unsigned long start, unsigned long end)
 	spin_lock(&free_vmap_area_lock);
 	llist_for_each_entry_safe(va, n_va, valist, purge_list) {
 		unsigned long nr = (va->va_end - va->va_start) >> PAGE_SHIFT;
+		unsigned long orig_start = va->va_start;
+		unsigned long orig_end = va->va_end;
 
 		/*
 		 * Finally insert or merge lazily-freed area. It is
 		 * detached and there is no need to "unlink" it from
 		 * anything.
 		 */
-		merge_or_add_vmap_area(va,
-			&free_vmap_area_root, &free_vmap_area_list);
+		va = merge_or_add_vmap_area(va, &free_vmap_area_root,
+					    &free_vmap_area_list);
+
+		kasan_release_vmalloc(orig_start, orig_end,
+				      va->va_start, va->va_end);
 
 		atomic_long_sub(nr, &vmap_lazy_nr);
 
@@ -2090,6 +2100,22 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
 
 	setup_vmalloc_vm(area, va, flags, caller);
 
+	/*
+	 * For KASAN, if we are in vmalloc space, we need to cover the shadow
+	 * area with real memory. If we come here through VM_ALLOC, this is
+	 * done by a higher level function that has access to the true size,
+	 * which might not be a full page.
+	 *
+	 * We assume module space comes via VM_ALLOC path.
+	 */
+	if (is_vmalloc_addr(area->addr) && !(area->flags & VM_ALLOC)) {
+		if (kasan_populate_vmalloc(area->size, area)) {
+			unmap_vmap_area(va);
+			kfree(area);
+			return NULL;
+		}
+	}
+
 	return area;
 }
 
@@ -2267,6 +2293,9 @@ static void __vunmap(const void *addr, int deallocate_pages)
 	debug_check_no_locks_freed(area->addr, get_vm_area_size(area));
 	debug_check_no_obj_freed(area->addr, get_vm_area_size(area));
 
+	if (area->flags & VM_KASAN)
+		kasan_poison_vmalloc(area->addr, area->size);
+
 	vm_remove_mappings(area, deallocate_pages);
 
 	if (deallocate_pages) {
@@ -2519,6 +2548,11 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 	if (!addr)
 		return NULL;
 
+	if (is_vmalloc_or_module_addr(area->addr)) {
+		if (kasan_populate_vmalloc(real_size, area))
+			return NULL;
+	}
+
 	/*
 	 * In this function, newly allocated vm_struct has VM_UNINITIALIZED
 	 * flag. It means that vm_struct is not fully initialized.
@@ -3377,6 +3411,9 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 
 		setup_vmalloc_vm_locked(vms[area], vas[area], VM_ALLOC,
 				 pcpu_get_vm_areas);
+
+		/* assume success here */
+		kasan_populate_vmalloc(sizes[area], vms[area]);
 	}
 	spin_unlock(&vmap_area_lock);
 
@@ -3391,8 +3428,8 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	 * and when pcpu_get_vm_areas() is success.
 	 */
 	while (area--) {
-		merge_or_add_vmap_area(vas[area],
-			&free_vmap_area_root, &free_vmap_area_list);
+		(void)merge_or_add_vmap_area(vas[area], &free_vmap_area_root,
+					     &free_vmap_area_list);
 		vas[area] = NULL;
 	}
 
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191029042059.28541-2-dja%40axtens.net.
