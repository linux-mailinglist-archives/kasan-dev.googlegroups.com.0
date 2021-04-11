Return-Path: <kasan-dev+bncBC447XVYUEMRBEOOZSBQMGQEN32M2QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id ECF8535B61F
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Apr 2021 18:42:57 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id b4sf1913370wrq.9
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Apr 2021 09:42:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618159377; cv=pass;
        d=google.com; s=arc-20160816;
        b=OCQvvUTCbGVaQxz2NMvtgo2YnR3QY6/OxkQJmuZVD90knzzPqW5g6UWkkUxYWifIRi
         V4K11/yEXfjb2IzQv9OsSyeafGNckgHwLcHSgnfDafnBHceB3UjrWe/qqO6fJryWdZy1
         Hk8aCntDK0ZkR2Qmxd65zcNBiZ5Wbluy/xAQ/gw5Cs2bfY4xUfuYUhcTVzq4p2aIcvyY
         8XUmU9AoG7C4dUOdeQ7mf3H665ktmCaiCGKW0u7CoUg2n+NMwCiBvYm1dQvOTiBMhLvk
         W9E2fMcHtK9y2XYMI1ZIIE+mhEiT7LsNa+0cRjEjvGaz5nKHpDHFxfXXFOFuZn6WD1hG
         ctHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=HGj1cWZXUQAEkduWrI4OJHjfwJ6aNhEySI3wyfsO/sI=;
        b=TRK8+Fw8UGuIc9R2sefxR8gEYzkm3JkGkLYncHdoWXaWfADJ9nxmHbTEYQGDE/z71U
         CwWKDM6BeXtOLcXDNAUZDcAE4AZuHWBDX6aKq2DM+lyGvi0Ew4ddOxLARtVB4QJZAPL+
         vOQyOhJKPHMIqCFoprQ93lNjje/5kilBjosW7mNCQCEvoI83wkUMSA06sbLiwduV3EzB
         Jiywo84bDPrUJWplHKMa71sBX4tui5HenMM/6fIkG2WPe8716Rugtb6Udfox9gl3U1zy
         iqEsX7JbgMICRy2SqR0VTKQbrBLi4uKX9++KV/zC9c2kbHEdtJ5nW6XODvVbqtlg924X
         8M0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.198 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HGj1cWZXUQAEkduWrI4OJHjfwJ6aNhEySI3wyfsO/sI=;
        b=dJCs4nQPEMrFXHBuEh66y+2ZS9ZnNoHSQ8B32PlB49ZhwnuJjRArv9ww8VRVVrP1KT
         KLPldndhYDWfNr08y4eDblTuvB65JPaHWg/D0R+8UVCBL2eMVh5PXfr1wuLZPD9n25FB
         ogEjG4X3Mux2AGZq1rWtlygsdxNrQ4a+pYDPnZec9/FVHd2t52h61hNtaGsv4YbzMjkB
         pIDoNfz2X3sVbseu+9CTyC/KyEbpG05WZ8LWk6cpDwPMLLoc4KgwI1828JCrq1wNpwRl
         z3bNakuUqmirVhFi0MgtS+j7JgknXuSeXTG93L6VKMfOMCIg/7z6btmRB9RJLgFQ5vGP
         mt+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HGj1cWZXUQAEkduWrI4OJHjfwJ6aNhEySI3wyfsO/sI=;
        b=PQfDJgvCnfaKbmx1N1eOndtWJOCxk/lVtYYscJXUrfEP2OnwoLNM2u1mulctcOffif
         N/1y6a6BPkhx4wJBmf+Lg/rmxZMQuLwXoQWTV24k+OgNfOSxBaSxmQvEH0Z1cb5C9dBb
         7Cce8OksUPEcC86CpSIV/cIjJR0hsajOVDDxNbH1k2ngmOLuAXjoe26KeMqwB8v45Qnx
         w6U2v79ISiHyh6Yv7dnGnILXE3TIK03hwhJvpm+Zb3BFQ0UfHuzNN7kSK6OXOSkQoDL3
         K6ZovYo1+V2PihoyNGM0coJPujxycXI2Dwp/e9tnZw0sKjBIYOUEeug2faegO/0Cvsyg
         s+ww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532r4UWJsdf0vBVa1oLKxhNDYqdLrLyrMk+m9uv1/bDHHIZhYyWo
	PlPw8kWZO+GPGdiJ30o/yAU=
X-Google-Smtp-Source: ABdhPJzwO/YGKUc/VGaCnVW9ElxxcQh1HH279YZYWTnyb79YBc8yOMi7Cex4jjGJ6/pN+V26n6hYIQ==
X-Received: by 2002:a1c:6a13:: with SMTP id f19mr19866955wmc.145.1618159377722;
        Sun, 11 Apr 2021 09:42:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3511:: with SMTP id h17ls5344259wmq.1.gmail; Sun,
 11 Apr 2021 09:42:56 -0700 (PDT)
X-Received: by 2002:a7b:c857:: with SMTP id c23mr1172747wml.28.1618159376840;
        Sun, 11 Apr 2021 09:42:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618159376; cv=none;
        d=google.com; s=arc-20160816;
        b=IvB+ZbsreLbA1pd+L42DE0VQLKxNc0ka5c6aMpCetDGqOh8ZZ4MXIuCRttDS0ZUUDU
         mR4NUVfEptCnZT55q+9y/OfsK+2LmkuNgbUb30SmXiuvDmo9bjC2Z/wd0WP3sLasUiX+
         JqlFB3UxPpe+4QWVL/du4HKkr3m/A1xdo4YlqdbxQqWcMM+3GgnpF1flDfy0Yr0GR12J
         s9xwb0HhWmr/8TPWo+s1ZChvPNP9CqXELxrDPOuiVQrNA3Wr7ijfBzSgUllsFvyQC/23
         KNJ71mY9ODv4YqVsJvsmA6bOJXTRXkZ3P0mrIelwN/8opyUK3nd/1CWd6IC9Z5kiNKzX
         jh+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=ORCdLPfKvHBbkiaUlHDLc6Cuvr+7rQfYWfVJsJlgbAI=;
        b=dVmx611GwPRBCSBTFJk7jJC51Ou6mryJSmefAC0Jun4PdausM4BCSn02bxvFikXAGf
         7O2hXsDcOpB80MWemaSR/HQP9xZ1J/xWwwqStnox3MtjJL3V40ijniVaOb+PVCyGwGR4
         qQXu2UjbvzjATd/dpqUnPGbqZx8BKvY0fT0NMJmR1/oZPB0AFrxji6Fs9xpp8wQ4BAYJ
         YzvbxiTbvScvsqjrlSBtkKC7VxwM92SS8Lv5RsEar6CXZ2ke3yLvKCdeaQhGVV5FdqgQ
         SM05MlPV8s/4l+UgmjzWjrH94nmhsPyqtGaTS1NSromosNURYXjLdMEhFQUOqk1JrB+M
         ah5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.198 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay6-d.mail.gandi.net (relay6-d.mail.gandi.net. [217.70.183.198])
        by gmr-mx.google.com with ESMTPS id s8si1012740wrn.5.2021.04.11.09.42.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 11 Apr 2021 09:42:56 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.198 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.198;
X-Originating-IP: 2.7.49.219
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay6-d.mail.gandi.net (Postfix) with ESMTPSA id 7FACBC0002;
	Sun, 11 Apr 2021 16:42:52 +0000 (UTC)
From: Alexandre Ghiti <alex@ghiti.fr>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Arnd Bergmann <arnd@arndb.de>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org,
	linux-mm@kvack.org
Cc: Alexandre Ghiti <alex@ghiti.fr>
Subject: [PATCH v5 1/3] riscv: Move kernel mapping outside of linear mapping
Date: Sun, 11 Apr 2021 12:41:44 -0400
Message-Id: <20210411164146.20232-2-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210411164146.20232-1-alex@ghiti.fr>
References: <20210411164146.20232-1-alex@ghiti.fr>
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.198 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

This is a preparatory patch for relocatable kernel and sv48 support.

The kernel used to be linked at PAGE_OFFSET address therefore we could use
the linear mapping for the kernel mapping. But the relocated kernel base
address will be different from PAGE_OFFSET and since in the linear mapping,
two different virtual addresses cannot point to the same physical address,
the kernel mapping needs to lie outside the linear mapping so that we don't
have to copy it at the same physical offset.

The kernel mapping is moved to the last 2GB of the address space, BPF
is now always after the kernel and modules use the 2GB memory range right
before the kernel, so BPF and modules regions do not overlap. KASLR
implementation will simply have to move the kernel in the last 2GB range
and just take care of leaving enough space for BPF.

In addition, by moving the kernel to the end of the address space, both
sv39 and sv48 kernels will be exactly the same without needing to be
relocated at runtime.

Suggested-by: Arnd Bergmann <arnd@arndb.de>
Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
---
 arch/riscv/boot/loader.lds.S        |  3 +-
 arch/riscv/include/asm/page.h       | 17 +++++-
 arch/riscv/include/asm/pgtable.h    | 37 ++++++++----
 arch/riscv/include/asm/set_memory.h |  1 +
 arch/riscv/kernel/head.S            |  3 +-
 arch/riscv/kernel/module.c          |  6 +-
 arch/riscv/kernel/setup.c           |  5 ++
 arch/riscv/kernel/vmlinux.lds.S     |  3 +-
 arch/riscv/mm/fault.c               | 13 +++++
 arch/riscv/mm/init.c                | 87 ++++++++++++++++++++++-------
 arch/riscv/mm/kasan_init.c          |  9 +++
 arch/riscv/mm/physaddr.c            |  2 +-
 12 files changed, 146 insertions(+), 40 deletions(-)

diff --git a/arch/riscv/boot/loader.lds.S b/arch/riscv/boot/loader.lds.S
index 47a5003c2e28..62d94696a19c 100644
--- a/arch/riscv/boot/loader.lds.S
+++ b/arch/riscv/boot/loader.lds.S
@@ -1,13 +1,14 @@
 /* SPDX-License-Identifier: GPL-2.0 */
 
 #include <asm/page.h>
+#include <asm/pgtable.h>
 
 OUTPUT_ARCH(riscv)
 ENTRY(_start)
 
 SECTIONS
 {
-	. = PAGE_OFFSET;
+	. = KERNEL_LINK_ADDR;
 
 	.payload : {
 		*(.payload)
diff --git a/arch/riscv/include/asm/page.h b/arch/riscv/include/asm/page.h
index adc9d26f3d75..22cfb2be60dc 100644
--- a/arch/riscv/include/asm/page.h
+++ b/arch/riscv/include/asm/page.h
@@ -90,15 +90,28 @@ typedef struct page *pgtable_t;
 
 #ifdef CONFIG_MMU
 extern unsigned long va_pa_offset;
+extern unsigned long va_kernel_pa_offset;
 extern unsigned long pfn_base;
 #define ARCH_PFN_OFFSET		(pfn_base)
 #else
 #define va_pa_offset		0
+#define va_kernel_pa_offset	0
 #define ARCH_PFN_OFFSET		(PAGE_OFFSET >> PAGE_SHIFT)
 #endif /* CONFIG_MMU */
 
-#define __pa_to_va_nodebug(x)	((void *)((unsigned long) (x) + va_pa_offset))
-#define __va_to_pa_nodebug(x)	((unsigned long)(x) - va_pa_offset)
+extern unsigned long kernel_virt_addr;
+
+#define linear_mapping_pa_to_va(x)	((void *)((unsigned long)(x) + va_pa_offset))
+#define kernel_mapping_pa_to_va(x)	((void *)((unsigned long)(x) + va_kernel_pa_offset))
+#define __pa_to_va_nodebug(x)		linear_mapping_pa_to_va(x)
+
+#define linear_mapping_va_to_pa(x)	((unsigned long)(x) - va_pa_offset)
+#define kernel_mapping_va_to_pa(x)	((unsigned long)(x) - va_kernel_pa_offset)
+#define __va_to_pa_nodebug(x)	({						\
+	unsigned long _x = x;							\
+	(_x < kernel_virt_addr) ?						\
+		linear_mapping_va_to_pa(_x) : kernel_mapping_va_to_pa(_x);	\
+	})
 
 #ifdef CONFIG_DEBUG_VIRTUAL
 extern phys_addr_t __virt_to_phys(unsigned long x);
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index ebf817c1bdf4..80e63a93e903 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -11,23 +11,30 @@
 
 #include <asm/pgtable-bits.h>
 
-#ifndef __ASSEMBLY__
-
-/* Page Upper Directory not used in RISC-V */
-#include <asm-generic/pgtable-nopud.h>
-#include <asm/page.h>
-#include <asm/tlbflush.h>
-#include <linux/mm_types.h>
+#ifndef CONFIG_MMU
+#define KERNEL_LINK_ADDR	PAGE_OFFSET
+#else
 
-#ifdef CONFIG_MMU
+#define ADDRESS_SPACE_END	(UL(-1))
+/*
+ * Leave 2GB for kernel and BPF at the end of the address space
+ */
+#define KERNEL_LINK_ADDR	(ADDRESS_SPACE_END - SZ_2G + 1)
 
 #define VMALLOC_SIZE     (KERN_VIRT_SIZE >> 1)
 #define VMALLOC_END      (PAGE_OFFSET - 1)
 #define VMALLOC_START    (PAGE_OFFSET - VMALLOC_SIZE)
 
+/* KASLR should leave at least 128MB for BPF after the kernel */
 #define BPF_JIT_REGION_SIZE	(SZ_128M)
-#define BPF_JIT_REGION_START	(PAGE_OFFSET - BPF_JIT_REGION_SIZE)
-#define BPF_JIT_REGION_END	(VMALLOC_END)
+#define BPF_JIT_REGION_START	PFN_ALIGN((unsigned long)&_end)
+#define BPF_JIT_REGION_END	(BPF_JIT_REGION_START + BPF_JIT_REGION_SIZE)
+
+/* Modules always live before the kernel */
+#ifdef CONFIG_64BIT
+#define MODULES_VADDR	(PFN_ALIGN((unsigned long)&_end) - SZ_2G)
+#define MODULES_END	(PFN_ALIGN((unsigned long)&_start))
+#endif
 
 /*
  * Roughly size the vmemmap space to be large enough to fit enough
@@ -57,9 +64,16 @@
 #define FIXADDR_SIZE     PGDIR_SIZE
 #endif
 #define FIXADDR_START    (FIXADDR_TOP - FIXADDR_SIZE)
-
 #endif
 
+#ifndef __ASSEMBLY__
+
+/* Page Upper Directory not used in RISC-V */
+#include <asm-generic/pgtable-nopud.h>
+#include <asm/page.h>
+#include <asm/tlbflush.h>
+#include <linux/mm_types.h>
+
 #ifdef CONFIG_64BIT
 #include <asm/pgtable-64.h>
 #else
@@ -484,6 +498,7 @@ static inline int ptep_clear_flush_young(struct vm_area_struct *vma,
 
 #define kern_addr_valid(addr)   (1) /* FIXME */
 
+extern char _start[];
 extern void *dtb_early_va;
 extern uintptr_t dtb_early_pa;
 void setup_bootmem(void);
diff --git a/arch/riscv/include/asm/set_memory.h b/arch/riscv/include/asm/set_memory.h
index 6887b3d9f371..a9c56776fa0e 100644
--- a/arch/riscv/include/asm/set_memory.h
+++ b/arch/riscv/include/asm/set_memory.h
@@ -17,6 +17,7 @@ int set_memory_x(unsigned long addr, int numpages);
 int set_memory_nx(unsigned long addr, int numpages);
 int set_memory_rw_nx(unsigned long addr, int numpages);
 void protect_kernel_text_data(void);
+void protect_kernel_linear_mapping_text_rodata(void);
 #else
 static inline int set_memory_ro(unsigned long addr, int numpages) { return 0; }
 static inline int set_memory_rw(unsigned long addr, int numpages) { return 0; }
diff --git a/arch/riscv/kernel/head.S b/arch/riscv/kernel/head.S
index f5a9bad86e58..6cb05f22e52a 100644
--- a/arch/riscv/kernel/head.S
+++ b/arch/riscv/kernel/head.S
@@ -69,7 +69,8 @@ pe_head_start:
 #ifdef CONFIG_MMU
 relocate:
 	/* Relocate return address */
-	li a1, PAGE_OFFSET
+	la a1, kernel_virt_addr
+	REG_L a1, 0(a1)
 	la a2, _start
 	sub a1, a1, a2
 	add ra, ra, a1
diff --git a/arch/riscv/kernel/module.c b/arch/riscv/kernel/module.c
index 104fba889cf7..ce153771e5e9 100644
--- a/arch/riscv/kernel/module.c
+++ b/arch/riscv/kernel/module.c
@@ -408,12 +408,10 @@ int apply_relocate_add(Elf_Shdr *sechdrs, const char *strtab,
 }
 
 #if defined(CONFIG_MMU) && defined(CONFIG_64BIT)
-#define VMALLOC_MODULE_START \
-	 max(PFN_ALIGN((unsigned long)&_end - SZ_2G), VMALLOC_START)
 void *module_alloc(unsigned long size)
 {
-	return __vmalloc_node_range(size, 1, VMALLOC_MODULE_START,
-				    VMALLOC_END, GFP_KERNEL,
+	return __vmalloc_node_range(size, 1, MODULES_VADDR,
+				    MODULES_END, GFP_KERNEL,
 				    PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
 				    __builtin_return_address(0));
 }
diff --git a/arch/riscv/kernel/setup.c b/arch/riscv/kernel/setup.c
index e85bacff1b50..30e4af0fd50c 100644
--- a/arch/riscv/kernel/setup.c
+++ b/arch/riscv/kernel/setup.c
@@ -265,6 +265,11 @@ void __init setup_arch(char **cmdline_p)
 
 	if (IS_ENABLED(CONFIG_STRICT_KERNEL_RWX))
 		protect_kernel_text_data();
+
+#if defined(CONFIG_64BIT) && defined(CONFIG_MMU)
+	protect_kernel_linear_mapping_text_rodata();
+#endif
+
 #ifdef CONFIG_SWIOTLB
 	swiotlb_init(1);
 #endif
diff --git a/arch/riscv/kernel/vmlinux.lds.S b/arch/riscv/kernel/vmlinux.lds.S
index de03cb22d0e9..0726c05e0336 100644
--- a/arch/riscv/kernel/vmlinux.lds.S
+++ b/arch/riscv/kernel/vmlinux.lds.S
@@ -4,7 +4,8 @@
  * Copyright (C) 2017 SiFive
  */
 
-#define LOAD_OFFSET PAGE_OFFSET
+#include <asm/pgtable.h>
+#define LOAD_OFFSET KERNEL_LINK_ADDR
 #include <asm/vmlinux.lds.h>
 #include <asm/page.h>
 #include <asm/cache.h>
diff --git a/arch/riscv/mm/fault.c b/arch/riscv/mm/fault.c
index 8f17519208c7..1b14d523a95c 100644
--- a/arch/riscv/mm/fault.c
+++ b/arch/riscv/mm/fault.c
@@ -231,6 +231,19 @@ asmlinkage void do_page_fault(struct pt_regs *regs)
 		return;
 	}
 
+#ifdef CONFIG_64BIT
+	/*
+	 * Modules in 64bit kernels lie in their own virtual region which is not
+	 * in the vmalloc region, but dealing with page faults in this region
+	 * or the vmalloc region amounts to doing the same thing: checking that
+	 * the mapping exists in init_mm.pgd and updating user page table, so
+	 * just use vmalloc_fault.
+	 */
+	if (unlikely(addr >= MODULES_VADDR && addr < MODULES_END)) {
+		vmalloc_fault(regs, code, addr);
+		return;
+	}
+#endif
 	/* Enable interrupts if they were enabled in the parent context. */
 	if (likely(regs->status & SR_PIE))
 		local_irq_enable();
diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index 7f5036fbee8c..093f3a96ecfc 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -25,6 +25,9 @@
 
 #include "../kernel/head.h"
 
+unsigned long kernel_virt_addr = KERNEL_LINK_ADDR;
+EXPORT_SYMBOL(kernel_virt_addr);
+
 unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)]
 							__page_aligned_bss;
 EXPORT_SYMBOL(empty_zero_page);
@@ -88,6 +91,8 @@ static void print_vm_layout(void)
 		  (unsigned long)VMALLOC_END);
 	print_mlm("lowmem", (unsigned long)PAGE_OFFSET,
 		  (unsigned long)high_memory);
+	print_mlm("kernel", (unsigned long)KERNEL_LINK_ADDR,
+		  (unsigned long)ADDRESS_SPACE_END);
 }
 #else
 static void print_vm_layout(void) { }
@@ -116,8 +121,13 @@ void __init setup_bootmem(void)
 	/* The maximal physical memory size is -PAGE_OFFSET. */
 	memblock_enforce_memory_limit(-PAGE_OFFSET);
 
-	/* Reserve from the start of the kernel to the end of the kernel */
-	memblock_reserve(vmlinux_start, vmlinux_end - vmlinux_start);
+	/*
+	 * Reserve from the start of the kernel to the end of the kernel
+	 * and make sure we align the reservation on PMD_SIZE since we will
+	 * map the kernel in the linear mapping as read-only: we do not want
+	 * any allocation to happen between _end and the next pmd aligned page.
+	 */
+	memblock_reserve(vmlinux_start, (vmlinux_end - vmlinux_start + PMD_SIZE - 1) & PMD_MASK);
 
 	/*
 	 * memblock allocator is not aware of the fact that last 4K bytes of
@@ -152,8 +162,12 @@ void __init setup_bootmem(void)
 #ifdef CONFIG_MMU
 static struct pt_alloc_ops pt_ops;
 
+/* Offset between linear mapping virtual address and kernel load address */
 unsigned long va_pa_offset;
 EXPORT_SYMBOL(va_pa_offset);
+/* Offset between kernel mapping virtual address and kernel load address */
+unsigned long va_kernel_pa_offset;
+EXPORT_SYMBOL(va_kernel_pa_offset);
 unsigned long pfn_base;
 EXPORT_SYMBOL(pfn_base);
 
@@ -257,7 +271,7 @@ static pmd_t *get_pmd_virt_late(phys_addr_t pa)
 
 static phys_addr_t __init alloc_pmd_early(uintptr_t va)
 {
-	BUG_ON((va - PAGE_OFFSET) >> PGDIR_SHIFT);
+	BUG_ON((va - kernel_virt_addr) >> PGDIR_SHIFT);
 
 	return (uintptr_t)early_pmd;
 }
@@ -372,17 +386,32 @@ static uintptr_t __init best_map_size(phys_addr_t base, phys_addr_t size)
 #error "setup_vm() is called from head.S before relocate so it should not use absolute addressing."
 #endif
 
+uintptr_t load_pa, load_sz;
+
+static void __init create_kernel_page_table(pgd_t *pgdir, uintptr_t map_size)
+{
+	uintptr_t va, end_va;
+
+	end_va = kernel_virt_addr + load_sz;
+	for (va = kernel_virt_addr; va < end_va; va += map_size)
+		create_pgd_mapping(pgdir, va,
+				   load_pa + (va - kernel_virt_addr),
+				   map_size, PAGE_KERNEL_EXEC);
+}
+
 asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 {
-	uintptr_t va, pa, end_va;
-	uintptr_t load_pa = (uintptr_t)(&_start);
-	uintptr_t load_sz = (uintptr_t)(&_end) - load_pa;
+	uintptr_t pa;
 	uintptr_t map_size;
 #ifndef __PAGETABLE_PMD_FOLDED
 	pmd_t fix_bmap_spmd, fix_bmap_epmd;
 #endif
+	load_pa = (uintptr_t)(&_start);
+	load_sz = (uintptr_t)(&_end) - load_pa;
 
 	va_pa_offset = PAGE_OFFSET - load_pa;
+	va_kernel_pa_offset = kernel_virt_addr - load_pa;
+
 	pfn_base = PFN_DOWN(load_pa);
 
 	/*
@@ -410,26 +439,22 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 	create_pmd_mapping(fixmap_pmd, FIXADDR_START,
 			   (uintptr_t)fixmap_pte, PMD_SIZE, PAGE_TABLE);
 	/* Setup trampoline PGD and PMD */
-	create_pgd_mapping(trampoline_pg_dir, PAGE_OFFSET,
+	create_pgd_mapping(trampoline_pg_dir, kernel_virt_addr,
 			   (uintptr_t)trampoline_pmd, PGDIR_SIZE, PAGE_TABLE);
-	create_pmd_mapping(trampoline_pmd, PAGE_OFFSET,
+	create_pmd_mapping(trampoline_pmd, kernel_virt_addr,
 			   load_pa, PMD_SIZE, PAGE_KERNEL_EXEC);
 #else
 	/* Setup trampoline PGD */
-	create_pgd_mapping(trampoline_pg_dir, PAGE_OFFSET,
+	create_pgd_mapping(trampoline_pg_dir, kernel_virt_addr,
 			   load_pa, PGDIR_SIZE, PAGE_KERNEL_EXEC);
 #endif
 
 	/*
-	 * Setup early PGD covering entire kernel which will allows
+	 * Setup early PGD covering entire kernel which will allow
 	 * us to reach paging_init(). We map all memory banks later
 	 * in setup_vm_final() below.
 	 */
-	end_va = PAGE_OFFSET + load_sz;
-	for (va = PAGE_OFFSET; va < end_va; va += map_size)
-		create_pgd_mapping(early_pg_dir, va,
-				   load_pa + (va - PAGE_OFFSET),
-				   map_size, PAGE_KERNEL_EXEC);
+	create_kernel_page_table(early_pg_dir, map_size);
 
 #ifndef __PAGETABLE_PMD_FOLDED
 	/* Setup early PMD for DTB */
@@ -444,7 +469,12 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 			   pa + PMD_SIZE, PMD_SIZE, PAGE_KERNEL);
 	dtb_early_va = (void *)DTB_EARLY_BASE_VA + (dtb_pa & (PMD_SIZE - 1));
 #else /* CONFIG_BUILTIN_DTB */
-	dtb_early_va = __va(dtb_pa);
+	/*
+	 * __va can't be used since it would return a linear mapping address
+	 * whereas dtb_early_va will be used before setup_vm_final installs
+	 * the linear mapping.
+	 */
+	dtb_early_va = kernel_mapping_pa_to_va(dtb_pa);
 #endif /* CONFIG_BUILTIN_DTB */
 #else
 #ifndef CONFIG_BUILTIN_DTB
@@ -456,7 +486,7 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 			   pa + PGDIR_SIZE, PGDIR_SIZE, PAGE_KERNEL);
 	dtb_early_va = (void *)DTB_EARLY_BASE_VA + (dtb_pa & (PGDIR_SIZE - 1));
 #else /* CONFIG_BUILTIN_DTB */
-	dtb_early_va = __va(dtb_pa);
+	dtb_early_va = kernel_mapping_pa_to_va(dtb_pa);
 #endif /* CONFIG_BUILTIN_DTB */
 #endif
 	dtb_early_pa = dtb_pa;
@@ -492,6 +522,22 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 #endif
 }
 
+#ifdef CONFIG_64BIT
+void protect_kernel_linear_mapping_text_rodata(void)
+{
+	unsigned long text_start = (unsigned long)lm_alias(_start);
+	unsigned long init_text_start = (unsigned long)lm_alias(__init_text_begin);
+	unsigned long rodata_start = (unsigned long)lm_alias(__start_rodata);
+	unsigned long data_start = (unsigned long)lm_alias(_data);
+
+	set_memory_ro(text_start, (init_text_start - text_start) >> PAGE_SHIFT);
+	set_memory_nx(text_start, (init_text_start - text_start) >> PAGE_SHIFT);
+
+	set_memory_ro(rodata_start, (data_start - rodata_start) >> PAGE_SHIFT);
+	set_memory_nx(rodata_start, (data_start - rodata_start) >> PAGE_SHIFT);
+}
+#endif
+
 static void __init setup_vm_final(void)
 {
 	uintptr_t va, map_size;
@@ -513,7 +559,7 @@ static void __init setup_vm_final(void)
 			   __pa_symbol(fixmap_pgd_next),
 			   PGDIR_SIZE, PAGE_TABLE);
 
-	/* Map all memory banks */
+	/* Map all memory banks in the linear mapping */
 	for_each_mem_range(i, &start, &end) {
 		if (start >= end)
 			break;
@@ -525,10 +571,13 @@ static void __init setup_vm_final(void)
 		for (pa = start; pa < end; pa += map_size) {
 			va = (uintptr_t)__va(pa);
 			create_pgd_mapping(swapper_pg_dir, va, pa,
-					   map_size, PAGE_KERNEL_EXEC);
+					   map_size, PAGE_KERNEL);
 		}
 	}
 
+	/* Map the kernel */
+	create_kernel_page_table(swapper_pg_dir, PMD_SIZE);
+
 	/* Clear fixmap PTE and PMD mappings */
 	clear_fixmap(FIX_PTE);
 	clear_fixmap(FIX_PMD);
diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 2c39f0386673..28f4d52cf17e 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -171,6 +171,10 @@ void __init kasan_init(void)
 	phys_addr_t _start, _end;
 	u64 i;
 
+	/*
+	 * Populate all kernel virtual address space with kasan_early_shadow_page
+	 * except for the linear mapping and the modules/kernel/BPF mapping.
+	 */
 	kasan_populate_early_shadow((void *)KASAN_SHADOW_START,
 				    (void *)kasan_mem_to_shadow((void *)
 								VMEMMAP_END));
@@ -183,6 +187,7 @@ void __init kasan_init(void)
 			(void *)kasan_mem_to_shadow((void *)VMALLOC_START),
 			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
 
+	/* Populate the linear mapping */
 	for_each_mem_range(i, &_start, &_end) {
 		void *start = (void *)__va(_start);
 		void *end = (void *)__va(_end);
@@ -193,6 +198,10 @@ void __init kasan_init(void)
 		kasan_populate(kasan_mem_to_shadow(start), kasan_mem_to_shadow(end));
 	};
 
+	/* Populate kernel, BPF, modules mapping */
+	kasan_populate(kasan_mem_to_shadow((const void *)MODULES_VADDR),
+		       kasan_mem_to_shadow((const void *)BPF_JIT_REGION_END));
+
 	for (i = 0; i < PTRS_PER_PTE; i++)
 		set_pte(&kasan_early_shadow_pte[i],
 			mk_pte(virt_to_page(kasan_early_shadow_page),
diff --git a/arch/riscv/mm/physaddr.c b/arch/riscv/mm/physaddr.c
index e8e4dcd39fed..35703d5ef5fd 100644
--- a/arch/riscv/mm/physaddr.c
+++ b/arch/riscv/mm/physaddr.c
@@ -23,7 +23,7 @@ EXPORT_SYMBOL(__virt_to_phys);
 
 phys_addr_t __phys_addr_symbol(unsigned long x)
 {
-	unsigned long kernel_start = (unsigned long)PAGE_OFFSET;
+	unsigned long kernel_start = (unsigned long)kernel_virt_addr;
 	unsigned long kernel_end = (unsigned long)_end;
 
 	/*
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210411164146.20232-2-alex%40ghiti.fr.
