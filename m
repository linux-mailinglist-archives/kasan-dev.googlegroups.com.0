Return-Path: <kasan-dev+bncBC447XVYUEMRBPNS5SBQMGQEFQLOQTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id E2A9936315A
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Apr 2021 19:22:07 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id h3-20020adfa4c30000b02901027da44a81sf6260942wrb.19
        for <lists+kasan-dev@lfdr.de>; Sat, 17 Apr 2021 10:22:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618680125; cv=pass;
        d=google.com; s=arc-20160816;
        b=N3iIKn2uCWrL/k7iMadlXrlYeMrSVDMr4wZaDV2kSzPM2dOeQIXfGSTdFwPNQWFsEW
         29warj4mT+m3guncSOeMsP9U9KjwuaMtZedrGeSxEy5d3YDeI61P19sJ9Mj0jmpgK7Jf
         eNOE65VflvHiTEVWZPZJB8WhovFOzqUHTJ9JffBFkoI1YLCtisYcjm5ZM+KTns7BL7Fv
         CdNC1OGXCxQ4UQ614krUJCKv4DoxO5nuRTX8FqZmRwjf0KLddZTfEQViIseNEVohplzg
         ajzmFMJ2J4C4K/bDwXHXYgZTyh9JY+Hkon2vvMA5wVWQPz8JsL/KE9wk92AayQM7J2mt
         2B6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=NyHQlJsRW/wtY7Cp+lc3aQmot7SiE06qZ2FYYJmkxgY=;
        b=Bdu7KOukJeZfatzWkxJWdZ5EW5+WyIxyNESSxXceDrNXHguxd4ASvYVin01foc3unw
         dOl/HW285ZnJ36RxdjDHk1GMLSS36VbMNEs64UVE4Y1Q1+N0++Nb3BsfkLvq+jkhLCGL
         m5uxtpaN/QecWVYwNK3L3MtJdHwNXoEX3TZ5IxMyFWW6r1TSBP0z5t++sL2RPt6MTNwn
         gXmJM7zb5SAM0saMXmLWj4yRiQ+vt373IylEOfx5fmfcUBnP3gGb9e5aS0I+UbBXrNxu
         TOAkLiEFwIUXtwAYd/DN23wDLpE82EebWIwN64DX4O4YLcaz8kW9ylHjhlUlhsTJrZk4
         Q/Cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.231 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NyHQlJsRW/wtY7Cp+lc3aQmot7SiE06qZ2FYYJmkxgY=;
        b=WK6ecQW84aDZNpv0S4buyWMdv5ihenOMoATn9xVVbhHyr8Nbh+poAGL49MzQPYa13B
         2vzDz1qINnx07WOcCET3QxopI7QFuQtRPB1ywY4wTItbvxS95SHi9LiT0DuzOrfXArZP
         h/Vpb1xXqj44Yu/+qLaHkbH5GHwBaVTyDZQtZ6NHo3WBLSJGIkK1Es9n9FBt8zUT00S5
         MNEJItKlamgf0B62aC882lzGWpLCbROnKOO1/+2WzWdYIpcGJ1h4WBafaBOuc6eWHwur
         G9O31G8CTCIThe3Adxi72ltccrXQjtyVaIz8qmuFaKah3Uh7Wh7ARo/AA1yBnBBzLb+l
         8VGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NyHQlJsRW/wtY7Cp+lc3aQmot7SiE06qZ2FYYJmkxgY=;
        b=MOKTeRfgtgcSZyOmKNyiU1paGR9LcI+FIBi6Psa2DUNvm4V8O4qolQJyyHPQx+SFl7
         LlbsTRQ02U6tu8kCKhEZSW2AdTz1uxc64/+mrZ/tFAWDqF4nZiINHgsgVAZ8gDK+N/0u
         PL136eN6M6gveRoHcSiNJ7ZPl23hCQhUZ6sYugZHmWJeH0x/DpAdZ98ZUV/BAgCWxNAA
         QjS9bHlhjWKPHbWhTkP5Yn+tTApZBufVBNAXpdFu9PFj7R5xDtacgFCSC6Dum8WlPixc
         SZuydac3PYikMEckXyti+G5YUryRw32r4ZQim7UxFPaLRu5qRKc7F6q7DuMs8txlT6Uj
         R7NA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532f8j93eMB8vjvyHRsitFMcNq+1vFp1Cff2EuxuQW0o7uZEIALI
	I/61D1OPWcjPulv51YZbHy4=
X-Google-Smtp-Source: ABdhPJwIAxQBvIKUrK5+iW+XIto1dZ+XcF8KtSospQBpeDvqcDCGEUMGF3RAEjaJQMSFyZWrtwMWFQ==
X-Received: by 2002:adf:d1ce:: with SMTP id b14mr5275052wrd.159.1618680125705;
        Sat, 17 Apr 2021 10:22:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:c205:: with SMTP id s5ls5841852wmf.3.canary-gmail; Sat,
 17 Apr 2021 10:22:04 -0700 (PDT)
X-Received: by 2002:a05:600c:17c3:: with SMTP id y3mr13682428wmo.185.1618680124788;
        Sat, 17 Apr 2021 10:22:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618680124; cv=none;
        d=google.com; s=arc-20160816;
        b=GXYsGVTEyBPORaZ3p2ZmgeWlbdffJpOTlTirnJlWZ4zH2rY/FS5rhYBiFaomjXn737
         9AR7kgRJsfr5CzLLkfFKVrLYTfAVGGQAVOqN1H7Bicll3KoQmtBjom5p2QspGXHpVtwh
         WUJTeWGPV0hpcAMEbSUS7uaiomnvdgf+GTMHlT4W0DhsbPOsuULCFeYHo13tAhTityM0
         jmLBIoT6seO34qbZUavgb2b/DhnSysKtGzxwLE9ysTi0PBtIFbcZzCM1xr+boOVQ8Twq
         UbatcI6CCfzxDv0reZIU2GOB7ER7EdIC7gFJg/LMfI+q6kkiZTFLR9JeXCL1qPZ1d9lh
         mawA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=nbQqbZA5sAvHxnWJW0raOTKk398HGn3qUNCGAdQF63Y=;
        b=Efsg0wisrrkGLC7huZp2YXMqZQrcSVTXHxAbRPjdseVLy7qmGGk7l/ow/IdVu61bAN
         tt07kvhBcFXP6q2NKXUwapXkA58nfBrs4phS6nWb8EF8ImsR33t0TBO3WgYRlnsoWAdQ
         /eqV7KGZx+0a1RaNEJQvYhUCXkFz8cKsR/UkKhh08tr15vnK9SZsJyD6AJIC3dSc0lJM
         wCe8s7UHPc3Eclx4Jt6gEw6ieOAQpHslqakcknbxi6V2aKSYiRKdskX0Ws0icF5sAPy8
         bVLYX4BcENmeurldoKg5wYIdnzWbH0OCmMHpjVxYwtCEMgmT9ZuPgnmhnQ7cqGx4vU4l
         JuDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.231 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay11.mail.gandi.net (relay11.mail.gandi.net. [217.70.178.231])
        by gmr-mx.google.com with ESMTPS id s141si758393wme.2.2021.04.17.10.22.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 17 Apr 2021 10:22:04 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.178.231 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.178.231;
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay11.mail.gandi.net (Postfix) with ESMTPSA id 0A91C100004;
	Sat, 17 Apr 2021 17:22:00 +0000 (UTC)
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
Subject: [PATCH] riscv: Fix 32b kernel caused by 64b kernel mapping moving outside linear mapping
Date: Sat, 17 Apr 2021 13:21:59 -0400
Message-Id: <20210417172159.32085-1-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.178.231 is neither permitted nor denied by best guess
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

Fix multiple leftovers when moving the kernel mapping outside the linear
mapping for 64b kernel that left the 32b kernel unusable.

Fixes: 4b67f48da707 ("riscv: Move kernel mapping outside of linear mapping")
Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
---
 arch/riscv/include/asm/page.h    |  9 +++++++++
 arch/riscv/include/asm/pgtable.h | 16 ++++++++++++----
 arch/riscv/mm/init.c             | 25 ++++++++++++++++++++++++-
 3 files changed, 45 insertions(+), 5 deletions(-)

diff --git a/arch/riscv/include/asm/page.h b/arch/riscv/include/asm/page.h
index 22cfb2be60dc..f64b61296c0c 100644
--- a/arch/riscv/include/asm/page.h
+++ b/arch/riscv/include/asm/page.h
@@ -90,15 +90,20 @@ typedef struct page *pgtable_t;
 
 #ifdef CONFIG_MMU
 extern unsigned long va_pa_offset;
+#ifdef CONFIG_64BIT
 extern unsigned long va_kernel_pa_offset;
+#endif
 extern unsigned long pfn_base;
 #define ARCH_PFN_OFFSET		(pfn_base)
 #else
 #define va_pa_offset		0
+#ifdef CONFIG_64BIT
 #define va_kernel_pa_offset	0
+#endif
 #define ARCH_PFN_OFFSET		(PAGE_OFFSET >> PAGE_SHIFT)
 #endif /* CONFIG_MMU */
 
+#ifdef CONFIG_64BIT
 extern unsigned long kernel_virt_addr;
 
 #define linear_mapping_pa_to_va(x)	((void *)((unsigned long)(x) + va_pa_offset))
@@ -112,6 +117,10 @@ extern unsigned long kernel_virt_addr;
 	(_x < kernel_virt_addr) ?						\
 		linear_mapping_va_to_pa(_x) : kernel_mapping_va_to_pa(_x);	\
 	})
+#else
+#define __pa_to_va_nodebug(x)  ((void *)((unsigned long) (x) + va_pa_offset))
+#define __va_to_pa_nodebug(x)  ((unsigned long)(x) - va_pa_offset)
+#endif
 
 #ifdef CONFIG_DEBUG_VIRTUAL
 extern phys_addr_t __virt_to_phys(unsigned long x);
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index 80e63a93e903..5afda75cc2c3 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -16,19 +16,27 @@
 #else
 
 #define ADDRESS_SPACE_END	(UL(-1))
-/*
- * Leave 2GB for kernel and BPF at the end of the address space
- */
+
+#ifdef CONFIG_64BIT
+/* Leave 2GB for kernel and BPF at the end of the address space */
 #define KERNEL_LINK_ADDR	(ADDRESS_SPACE_END - SZ_2G + 1)
+#else
+#define KERNEL_LINK_ADDR	PAGE_OFFSET
+#endif
 
 #define VMALLOC_SIZE     (KERN_VIRT_SIZE >> 1)
 #define VMALLOC_END      (PAGE_OFFSET - 1)
 #define VMALLOC_START    (PAGE_OFFSET - VMALLOC_SIZE)
 
-/* KASLR should leave at least 128MB for BPF after the kernel */
 #define BPF_JIT_REGION_SIZE	(SZ_128M)
+#ifdef CONFIG_64BIT
+/* KASLR should leave at least 128MB for BPF after the kernel */
 #define BPF_JIT_REGION_START	PFN_ALIGN((unsigned long)&_end)
 #define BPF_JIT_REGION_END	(BPF_JIT_REGION_START + BPF_JIT_REGION_SIZE)
+#else
+#define BPF_JIT_REGION_START	(PAGE_OFFSET - BPF_JIT_REGION_SIZE)
+#define BPF_JIT_REGION_END	(VMALLOC_END)
+#endif
 
 /* Modules always live before the kernel */
 #ifdef CONFIG_64BIT
diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index 093f3a96ecfc..dc9b988e0778 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -91,8 +91,10 @@ static void print_vm_layout(void)
 		  (unsigned long)VMALLOC_END);
 	print_mlm("lowmem", (unsigned long)PAGE_OFFSET,
 		  (unsigned long)high_memory);
+#ifdef CONFIG_64BIT
 	print_mlm("kernel", (unsigned long)KERNEL_LINK_ADDR,
 		  (unsigned long)ADDRESS_SPACE_END);
+#endif
 }
 #else
 static void print_vm_layout(void) { }
@@ -165,9 +167,11 @@ static struct pt_alloc_ops pt_ops;
 /* Offset between linear mapping virtual address and kernel load address */
 unsigned long va_pa_offset;
 EXPORT_SYMBOL(va_pa_offset);
+#ifdef CONFIG_64BIT
 /* Offset between kernel mapping virtual address and kernel load address */
 unsigned long va_kernel_pa_offset;
 EXPORT_SYMBOL(va_kernel_pa_offset);
+#endif
 unsigned long pfn_base;
 EXPORT_SYMBOL(pfn_base);
 
@@ -410,7 +414,9 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 	load_sz = (uintptr_t)(&_end) - load_pa;
 
 	va_pa_offset = PAGE_OFFSET - load_pa;
+#ifdef CONFIG_64BIT
 	va_kernel_pa_offset = kernel_virt_addr - load_pa;
+#endif
 
 	pfn_base = PFN_DOWN(load_pa);
 
@@ -469,12 +475,16 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 			   pa + PMD_SIZE, PMD_SIZE, PAGE_KERNEL);
 	dtb_early_va = (void *)DTB_EARLY_BASE_VA + (dtb_pa & (PMD_SIZE - 1));
 #else /* CONFIG_BUILTIN_DTB */
+#ifdef CONFIG_64BIT
 	/*
 	 * __va can't be used since it would return a linear mapping address
 	 * whereas dtb_early_va will be used before setup_vm_final installs
 	 * the linear mapping.
 	 */
 	dtb_early_va = kernel_mapping_pa_to_va(dtb_pa);
+#else
+	dtb_early_va = __va(dtb_pa);
+#endif /* CONFIG_64BIT */
 #endif /* CONFIG_BUILTIN_DTB */
 #else
 #ifndef CONFIG_BUILTIN_DTB
@@ -486,7 +496,11 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 			   pa + PGDIR_SIZE, PGDIR_SIZE, PAGE_KERNEL);
 	dtb_early_va = (void *)DTB_EARLY_BASE_VA + (dtb_pa & (PGDIR_SIZE - 1));
 #else /* CONFIG_BUILTIN_DTB */
+#ifdef CONFIG_64BIT
 	dtb_early_va = kernel_mapping_pa_to_va(dtb_pa);
+#else
+	dtb_early_va = __va(dtb_pa);
+#endif /* CONFIG_64BIT */
 #endif /* CONFIG_BUILTIN_DTB */
 #endif
 	dtb_early_pa = dtb_pa;
@@ -571,12 +585,21 @@ static void __init setup_vm_final(void)
 		for (pa = start; pa < end; pa += map_size) {
 			va = (uintptr_t)__va(pa);
 			create_pgd_mapping(swapper_pg_dir, va, pa,
-					   map_size, PAGE_KERNEL);
+					   map_size,
+#ifdef CONFIG_64BIT
+					   PAGE_KERNEL
+#else
+					   PAGE_KERNEL_EXEC
+#endif
+					);
+
 		}
 	}
 
+#ifdef CONFIG_64BIT
 	/* Map the kernel */
 	create_kernel_page_table(swapper_pg_dir, PMD_SIZE);
+#endif
 
 	/* Clear fixmap PTE and PMD mappings */
 	clear_fixmap(FIX_PTE);
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210417172159.32085-1-alex%40ghiti.fr.
