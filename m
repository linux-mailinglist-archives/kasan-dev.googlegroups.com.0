Return-Path: <kasan-dev+bncBC447XVYUEMRBPUKWKBAMGQEUDQC6UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 02507339D38
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Mar 2021 10:26:23 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id m71sf8856906lfa.5
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Mar 2021 01:26:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615627582; cv=pass;
        d=google.com; s=arc-20160816;
        b=d9qZ53TNbE2WIjdkz0N8TVcggaQOcB7AbFczn3O7kimqX7mu1HjDE0h9WaiiEoVvtu
         tclc7PaDs+7gfQemrjqPHZ3E/2Ckw3IfEKTM9x2kGj//Kl71qDxStRUlZPRwEAGzNkY3
         o1qo5t+NiGHNZ/ydWvG4fTVSa+bS1c1JdzKe1zuNfk4D1SlR+V76xz1pMQhQDvQ/A93v
         GoRrLI6eY01xfzg7UloGC08lIHRcoF3/QbD8I1BXGV3bU2EVmaObRODSxSLHGLMUgs3b
         z+prfZM0z/2eBgzkVmcmGZ2x3QWVZe8U7NcBFbV5mKXVFMljwBV/cu4+XpDecud1pcwS
         RGOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=l6jLpK6/x8hptSCvR1AN0B00q/PIa7xoS8bDB3neD98=;
        b=04Ra6JJKp1iKIUPk+z4ozwmTLCmEO3DzorG5DVE2Zxb6mMiA7VAtm8TbH02BcIDhOX
         06axlwCxUAatidZJRdPlfW7eLX97MWZeaIaO3N/hja99F/AyeIn7367lSLHfNFfgVX3H
         EI1DFueLESp5f+B/xCYgEXA+GVZ7ZzpCcUqlISEHHK5vjueLc1jMfXsiR9w+fCh95C5i
         C+aTQ1yq97MKhNoLdPKZ5ZDxBRg47WF9p1Rz6cGQuC9GqjsCddud3JNanAZ/gJFT2osY
         hbUq786XQB9symK+gWuMHzyD1K5Ik1ukoWQq4TvClRKF4OJ7KDflK2TrtXPu3swMgEO/
         FQxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l6jLpK6/x8hptSCvR1AN0B00q/PIa7xoS8bDB3neD98=;
        b=KwquqiO3lNuPps1eFkRU0Z0/bzyRhu2TrRfCYqswqVU58hI46jIjaMs6sUFUtithgp
         R9C9ZpYhfkpnBhWA/RSQKt/Na/aplOddbtDavIRYdCEftjwOm0JiLmM5/fik6YXQarFS
         iPVxSTgg5gPQeqDiPegzlYzlcjP2FQVYbHRSSXJHLdMVhhbVG850yZuJ7NXCcgYrC2Qd
         GnKGa/AfUNq4RZw9/Uruzp19QvbEW0SH/6zVJxK4hDWp6O4MbAzsZNQTsYjlGtwi1U+I
         8vFkoHP7cxbzwnoblxndfL46wA4eaP4ZK2UphAoKrBAZx/pqjF9AGyZmWRO5n6BIojMl
         c6YA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l6jLpK6/x8hptSCvR1AN0B00q/PIa7xoS8bDB3neD98=;
        b=WUiIt5J0Nn1lQaK+Br4wHxmh2C9loITjSY/HH7z27nobIAybj1egt5ustJ4Gex8zj/
         nL2+UBphWhdLsMTURtudqeysJ8ccrt5gqsRrX0QPbpizUyWemJq0u4nz+vCNV+Q00bwe
         5oS1JwsnGMRXCwfdf3Sr7Scr5bBkL7Mxtvkm7Lb2lXkylkBAP/uJ8j5v6yrZJNUrlAiE
         wbZ1zxjaMUBG/j+TiGL1EIsldnQGAdv764D6KnzCMOMBMhWwaVPky+Mh9JNAUoQjOPAE
         vMhfRpELHv0NdT7pG5PPM1OVUbl+ILQyoZv+GVDXn7gDIT1KE4HFCqQChk6cmH/stO0U
         W9LA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532YSigv7FpTMTiGY19SMMhaWcXOuxXu8v+MHun4CgIrC7ovYgmc
	/39OYuje8vnjrjrGjSe/K7Q=
X-Google-Smtp-Source: ABdhPJxgkf5WBUVn3vM8H2iAbLFu+RHdr2FWuxtK4f5lvQ1JoGCTnFfFw9fmt3IbaghSdA2LL4q35w==
X-Received: by 2002:ac2:4add:: with SMTP id m29mr2102181lfp.90.1615627582592;
        Sat, 13 Mar 2021 01:26:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9a48:: with SMTP id k8ls2451842ljj.10.gmail; Sat, 13 Mar
 2021 01:26:21 -0800 (PST)
X-Received: by 2002:a2e:9c10:: with SMTP id s16mr4508950lji.457.1615627581574;
        Sat, 13 Mar 2021 01:26:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615627581; cv=none;
        d=google.com; s=arc-20160816;
        b=gQW6jJ78eLosxM69IfVvIEXTgr1+IbY8VhtVjIY2pw1BbswrHWbppwZL/ivuGClqlS
         mLgiM/mIQoIFlW7zW+hmuguNSYIR1PF8PrHh1bVdNH3o3R6qzr4IyzKYuItGX3v6dVq4
         KsCe8Nxde/p1mTzFRH+EdjKX/AodU4MicMH9vwZF6B943KU5V5aKUgbCM3NtrCP7YU5k
         384PSPER2dnz6I2Kf4n9M7+N2kDwlocfFp5s6txfykGtsyWAO+yKglKVPdmPKE4DhOHe
         B7SROckiMTH/im51Q1YCT9pnKP+E+Ttct/CifB/iTMcKrK3uCLCEQlIHv1wzwy6Qj+Z1
         GCZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=VzItWoSDVzcAswgOstY/g1rGY6m+FUtIWuOd4nS4XZY=;
        b=EAtvRr85517qzian467oz27YDWPx/+CAc7kS7BCJ+5ZJaLhvgJuxLeUAI0a1pOoJSo
         RbHJX5ISza1gcyRMCpS1alDiTgycd9ss6kLBekL3EX07qsMGx90uDzYn67zmRHH4u7QX
         j12PAGSDA1jcDV11lyUkvqjEOlHTe19F9CZrCvBZIu5Kf5LZgncayeUgdDJWvDs3erLR
         tqQoeysObpFkoix14s+B1LrKGRsAs/NYiWrw7fz6Shb6CXvNE40sAJeAE8VFgLAU+cth
         eKbZFArwA3O/NrswksMRdqVbTpc0DrsU2yJ6cNep3jrESN6gQlLdzCgB57t4q1EXKYA8
         UfCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay4-d.mail.gandi.net (relay4-d.mail.gandi.net. [217.70.183.196])
        by gmr-mx.google.com with ESMTPS id 63si297331lfd.1.2021.03.13.01.26.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 13 Mar 2021 01:26:21 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.196;
X-Originating-IP: 2.7.49.219
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay4-d.mail.gandi.net (Postfix) with ESMTPSA id 84B91E0003;
	Sat, 13 Mar 2021 09:26:16 +0000 (UTC)
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
Subject: [PATCH v2 1/3] riscv: Move kernel mapping outside of linear mapping
Date: Sat, 13 Mar 2021 04:25:07 -0500
Message-Id: <20210313092509.4918-2-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210313092509.4918-1-alex@ghiti.fr>
References: <20210313092509.4918-1-alex@ghiti.fr>
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.196 is neither permitted nor denied by best guess
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
 arch/riscv/include/asm/page.h       | 18 ++++++-
 arch/riscv/include/asm/pgtable.h    | 37 +++++++++----
 arch/riscv/include/asm/set_memory.h |  1 +
 arch/riscv/kernel/head.S            |  3 +-
 arch/riscv/kernel/module.c          |  6 +--
 arch/riscv/kernel/setup.c           |  3 ++
 arch/riscv/kernel/vmlinux.lds.S     |  3 +-
 arch/riscv/mm/fault.c               | 13 +++++
 arch/riscv/mm/init.c                | 83 +++++++++++++++++++++++------
 arch/riscv/mm/kasan_init.c          |  9 ++++
 arch/riscv/mm/physaddr.c            |  2 +-
 12 files changed, 143 insertions(+), 38 deletions(-)

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
index adc9d26f3d75..dd69e4a58ee0 100644
--- a/arch/riscv/include/asm/page.h
+++ b/arch/riscv/include/asm/page.h
@@ -90,15 +90,29 @@ typedef struct page *pgtable_t;
 
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
+extern uintptr_t load_pa, load_sz, load_sz_pmd;
+
+#define linear_mapping_pa_to_va(x)	((void *)((unsigned long)(x) + va_pa_offset))
+#define __pa_to_va_nodebug(x)		linear_mapping_pa_to_va(x)
+
+#define linear_mapping_va_to_pa(x)	((unsigned long)(x) - va_pa_offset)
+#define kernel_mapping_va_to_pa(x)	\
+	((unsigned long)(x) - va_kernel_pa_offset)
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
index e85bacff1b50..f0a97a73b8ab 100644
--- a/arch/riscv/kernel/setup.c
+++ b/arch/riscv/kernel/setup.c
@@ -265,6 +265,9 @@ void __init setup_arch(char **cmdline_p)
 
 	if (IS_ENABLED(CONFIG_STRICT_KERNEL_RWX))
 		protect_kernel_text_data();
+
+	protect_kernel_linear_mapping_text_rodata();
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
index 7f5036fbee8c..6c7bdd546a2f 100644
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
+	memblock_reserve(load_pa, load_sz_pmd);
 
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
@@ -372,17 +386,39 @@ static uintptr_t __init best_map_size(phys_addr_t base, phys_addr_t size)
 #error "setup_vm() is called from head.S before relocate so it should not use absolute addressing."
 #endif
 
+uintptr_t load_pa;
+EXPORT_SYMBOL(load_pa);
+uintptr_t load_sz;
+EXPORT_SYMBOL(load_sz);
+uintptr_t load_sz_pmd;
+EXPORT_SYMBOL(load_sz_pmd);
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
+	load_sz_pmd = (load_sz + PMD_SIZE - 1) & PMD_MASK;
+
 	va_pa_offset = PAGE_OFFSET - load_pa;
+	va_kernel_pa_offset = kernel_virt_addr - load_pa;
+
 	pfn_base = PFN_DOWN(load_pa);
 
 	/*
@@ -410,26 +446,22 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
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
@@ -492,6 +524,20 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 #endif
 }
 
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
index 3fc18f469efb..1b968855d389 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -194,6 +194,10 @@ void __init kasan_init(void)
 	phys_addr_t _start, _end;
 	u64 i;
 
+	/*
+	 * Populate all kernel virtual address space with kasan_early_shadow_page
+	 * except for the linear mapping and the modules/kernel/BPF mapping.
+	 */
 	kasan_populate_early_shadow((void *)KASAN_SHADOW_START,
 				    (void *)kasan_mem_to_shadow((void *)
 								VMEMMAP_END));
@@ -206,6 +210,7 @@ void __init kasan_init(void)
 			(void *)kasan_mem_to_shadow((void *)VMALLOC_START),
 			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
 
+	/* Populate the linear mapping */
 	for_each_mem_range(i, &_start, &_end) {
 		void *start = (void *)__va(_start);
 		void *end = (void *)__va(_end);
@@ -216,6 +221,10 @@ void __init kasan_init(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210313092509.4918-2-alex%40ghiti.fr.
