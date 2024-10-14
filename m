Return-Path: <kasan-dev+bncBAABBBNOWK4AMGQELUZUPXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id D1B1F99BE6E
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 05:59:02 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3a3a5f6cb13sf30125475ab.3
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 20:59:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728878341; cv=pass;
        d=google.com; s=arc-20240605;
        b=H+YxroAtal4y71EPtHpWQxel6VmsHF7ZrMkxFavAxpt4Q4x8NtoN8gwlgeU2KDCmvF
         adrE7cSeBaPP6W3BKrlXMZofErejuLnzNY/QmT+eu3PiqNooulyDkoa93/xzTuG+NWIG
         xQIb5/9JgNp6LWjJMhxLrRNA8VbpBzbr3A3xZp9n5KXGbG+vAX6oJ0uIBTRNi94Cbtu7
         ukflwcThyK03nFVrl/81MbNXOl4PSIiTUlhBDBnPSVzMw5s7sOHm1/u/YbFiWIdusNrV
         oDSvyAhJ2gB3Z1/qxYdS3L0T0o1JXnBJP/8SYMjwPJtZXCteBU2AA8LLFstF4sIM9rcl
         wYxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XN75hg6tewN0OX3CfvZt7Oi8SEkxjh9aMv3E7SLTZz0=;
        fh=8Cwqlt4HF/gph66HhmEga4eNd15ess71cv0oFwr3l0M=;
        b=SSi2jRChHOzbrm6+u0eDDuL2XFV8N76/ax+vMlA+sIsauI9xITWP4iaVYlY6/MB7U5
         2P7J24yGJ76S+3I0jJPB3Er8GWiz3zYXBvwfyBrnTJg3s1O2U/wK6MA82J69QqbaqJD1
         L9s88L8bOxH4GOCrfhSYKoFmSZfjSGjo7xSN6YwBRtTQo+6thmpf1VouKjFvGPJqvySA
         EdOMX5eOJrmEf3hz75CuacHre3tCx2COlBqZnFG+LlPcNytkwunpn569QIssc8OcsY/u
         DTfSdjoGZE44AOzw4Y4N2EYbFd9UJUeIAlBvLxKAUNveMEo7H1otd5wLrK/IcI5xZKg7
         EN1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728878341; x=1729483141; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XN75hg6tewN0OX3CfvZt7Oi8SEkxjh9aMv3E7SLTZz0=;
        b=ICl4+mzgAUUm57c3GU+xZwn+N/lUTvPXQCy2VS2BGBsJ0HU4rNLwnl83SnrCSYpyQg
         iSgiodrWzLA3O1pTfOhjnZnC3luDzP6AAgitMTsXJ3zyuxvSySBiVy8v8Ku4T4FTBmUn
         4EbXlAQs801B6J7jLlGIrt3+hCPtitteDrMlfCO9GsBX50EeGVTMY9Rk/fQE4gAz9HPA
         qisIGTsbYmzL/5CAQBmG/7xJkfPvYw6FcqKSlriffoD1mS0wYymnnw7EWFWFSKw6zu0B
         1fFxbYN1AGmqBGD3eHSyyYjEqayo/h0qlhMoXzp+Sy/AN9VSKfqlw0QAIHnb2odl2j01
         CLTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728878341; x=1729483141;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XN75hg6tewN0OX3CfvZt7Oi8SEkxjh9aMv3E7SLTZz0=;
        b=u6BW83YYH7+PD3RrFDum4+aALv7WaW7JGz5ORkPcT2g3qK9JGOwAi9i0a+GYjdpki0
         mI0madnwySbzIBBM83yGVkfi//2nCEjfVJsB555H8F2wvbP8Eh4SkjT/P21TjSJbhnjg
         DbDqG12ojtcdaIScJEkZdBVneXquIN2siiIPbyqImf7+a3qkr5P5t0NOWKkuz+qnQ5h5
         8HSRlZTazksTxsQMkFbNKvtEsO3tBZ9HB+iNTVNzDYIVwl5P+XzoeZl+SYnv5/HUw3DO
         uHlnlY6tgob/P8upjQsIFRLGdDjM1kDqg6P8ewiu3nVtpvRZRWeGG21Zi60DyUgmqVws
         2cOg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW5QT7U7UB/wgrJSUjQkZ/Q71G6Ym8iH/aNXCI0nEd4mNrAOOjPPCTTP576WQUL/aO8+2bXqw==@lfdr.de
X-Gm-Message-State: AOJu0Ywu0t+4XEsGu+qmcyUv6JcS8lqzqIx/R9+y/2cBvbwHxCaqa4tm
	4rmS4GNdTKldnm+wVN3IZ6D9CXpP6yygz+irPjhH/HfOcMPlmJH0
X-Google-Smtp-Source: AGHT+IFjfb+yMPtHkqH1ws6o/LFoCx61ysNxIYRHjTO2NJyEB7262laOhQh4+MHsoS0fQOdw42zIKQ==
X-Received: by 2002:a05:6e02:214f:b0:3a3:b256:f325 with SMTP id e9e14a558f8ab-3a3b5fb2ce4mr62629715ab.20.1728878341433;
        Sun, 13 Oct 2024 20:59:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1805:b0:3a0:90de:1bae with SMTP id
 e9e14a558f8ab-3a3a742c886ls4151935ab.1.-pod-prod-09-us; Sun, 13 Oct 2024
 20:59:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXqs0wRal92jvzVYkBF3Gb+4ULoFpqRqHTjk82KhAGbYKXovq4wuVBq2aKXe0FF7bkV2CdFAQ4/4U4=@googlegroups.com
X-Received: by 2002:a05:6e02:b44:b0:3a1:f549:7272 with SMTP id e9e14a558f8ab-3a3b5fc3bafmr72395895ab.23.1728878340563;
        Sun, 13 Oct 2024 20:59:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728878340; cv=none;
        d=google.com; s=arc-20240605;
        b=GcEPu4Vh2IaCEpe3eQcUejwEewbRv3b4A2u3+Aa0gjHYxs0/081VVqRTHztN6SRVw5
         WbhKdLJxeAnfVD9wJKnucTPaOrR39dOo6ZA4BZrgwQjr6izIRyWORIinGkvDzrdwktUB
         nw8nyuOCmvapcSWHos4X5aEGURKtoXIirdoClS2n06L2U1E+9aBNTFZVEyizPwJXXYck
         hMRlbJaCfM8ysILLD4lkOAJeR+UOfga10cXOWKAFsfhufHyohaxiSdbSYtQ+5GH5Nyeb
         Yj6O7amEGvvEc0K55ypYCHuHaiOgjKxbfDZOKKIdiobhHaGtJAqe8qYPXTKlcYg02tQF
         YKIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=p7I8M5tc4Tck4U2HYdN2nAH2O+CY+L0GJMEbYTmhcQU=;
        fh=W/+Rlbd92klLtgnDZozu+1Zm8L3oNk9WCo5yqUG4SDo=;
        b=KTnr9uXzsSDSR0bnC31xxs22Mdlo5xYORjwyPl7RFx77xsrnIz7owSZwt/AgUzJoot
         JIz/LX9+67txkjmebmhLXOKWr6rqgfnxWA9cVENoe0eMK2ILka9v7dz++zc/GNA5/IaW
         E1eh61j2D29Uzaayu8PH5PaRF7sz5XVnkJqr1kcqeELouTd8F/BqED3oW+egWGmslygd
         QaLzCwA1Yg7if8yKG4Zd+0mH5RlBJilbhXBGZ1QTeK9D4jOHNu2U0YP5BTgBND94T+5b
         93SwfZ9CL0YbTBaciHlMvIhezaZiugJK8HgTKtLcTjIoTzRPwZ8No4MrAr5qgG0jdXj5
         +cEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id e9e14a558f8ab-3a3afdf12casi3318495ab.5.2024.10.13.20.58.59
        for <kasan-dev@googlegroups.com>;
        Sun, 13 Oct 2024 20:59:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.2.5.213])
	by gateway (Coremail) with SMTP id _____8DxhbABlwxnfQIaAA--.37521S3;
	Mon, 14 Oct 2024 11:58:57 +0800 (CST)
Received: from localhost.localdomain (unknown [10.2.5.213])
	by front1 (Coremail) with SMTP id qMiowMBxXuT_lgxnc6EoAA--.1717S3;
	Mon, 14 Oct 2024 11:58:56 +0800 (CST)
From: Bibo Mao <maobibo@loongson.cn>
To: Huacai Chen <chenhuacai@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: David Hildenbrand <david@redhat.com>,
	Barry Song <baohua@kernel.org>,
	loongarch@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH v2 1/3] LoongArch: Set initial pte entry with PAGE_GLOBAL for kernel space
Date: Mon, 14 Oct 2024 11:58:53 +0800
Message-Id: <20241014035855.1119220-2-maobibo@loongson.cn>
X-Mailer: git-send-email 2.39.3
In-Reply-To: <20241014035855.1119220-1-maobibo@loongson.cn>
References: <20241014035855.1119220-1-maobibo@loongson.cn>
MIME-Version: 1.0
X-CM-TRANSID: qMiowMBxXuT_lgxnc6EoAA--.1717S3
X-CM-SenderInfo: xpdruxter6z05rqj20fqof0/
X-Coremail-Antispam: 1Uk129KBjDUn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7KY7
	ZEXasCq-sGcSsGvfJ3UbIjqfuFe4nvWSU5nxnvy29KBjDU0xBIdaVrnUUvcSsGvfC2Kfnx
	nUUI43ZEXa7xR_UUUUUUUUU==
X-Original-Sender: maobibo@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=maobibo@loongson.cn
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

Unlike general architectures, there are two pages in one TLB entry
on LoongArch system. For kernel space, it requires both two pte
entries with PAGE_GLOBAL bit set, else HW treats it as non-global
tlb, there will be potential problems if tlb entry for kernel space
is not global. Such as fail to flush kernel tlb with function
local_flush_tlb_kernel_range() which only flush tlb with global bit.

With function kernel_pte_init() added, it can be used to init pte
table when it is created for kernel address space, and the default
initial pte value is PAGE_GLOBAL rather than zero at beginning.

Kernel address space areas includes fixmap, percpu, vmalloc, kasan
and vmemmap areas set default pte entry with PAGE_GLOBAL set.

Signed-off-by: Bibo Mao <maobibo@loongson.cn>
---
 arch/loongarch/include/asm/pgalloc.h | 13 +++++++++++++
 arch/loongarch/include/asm/pgtable.h |  1 +
 arch/loongarch/mm/init.c             |  4 +++-
 arch/loongarch/mm/kasan_init.c       |  4 +++-
 arch/loongarch/mm/pgtable.c          | 22 ++++++++++++++++++++++
 include/linux/mm.h                   |  1 +
 mm/kasan/init.c                      |  8 +++++++-
 mm/sparse-vmemmap.c                  |  5 +++++
 8 files changed, 55 insertions(+), 3 deletions(-)

diff --git a/arch/loongarch/include/asm/pgalloc.h b/arch/loongarch/include/asm/pgalloc.h
index 4e2d6b7ca2ee..b2698c03dc2c 100644
--- a/arch/loongarch/include/asm/pgalloc.h
+++ b/arch/loongarch/include/asm/pgalloc.h
@@ -10,8 +10,21 @@
 
 #define __HAVE_ARCH_PMD_ALLOC_ONE
 #define __HAVE_ARCH_PUD_ALLOC_ONE
+#define __HAVE_ARCH_PTE_ALLOC_ONE_KERNEL
 #include <asm-generic/pgalloc.h>
 
+static inline pte_t *pte_alloc_one_kernel(struct mm_struct *mm)
+{
+	pte_t *pte;
+
+	pte = (pte_t *) __get_free_page(GFP_KERNEL);
+	if (!pte)
+		return NULL;
+
+	kernel_pte_init(pte);
+	return pte;
+}
+
 static inline void pmd_populate_kernel(struct mm_struct *mm,
 				       pmd_t *pmd, pte_t *pte)
 {
diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/include/asm/pgtable.h
index 9965f52ef65b..22e3a8f96213 100644
--- a/arch/loongarch/include/asm/pgtable.h
+++ b/arch/loongarch/include/asm/pgtable.h
@@ -269,6 +269,7 @@ extern void set_pmd_at(struct mm_struct *mm, unsigned long addr, pmd_t *pmdp, pm
 extern void pgd_init(void *addr);
 extern void pud_init(void *addr);
 extern void pmd_init(void *addr);
+extern void kernel_pte_init(void *addr);
 
 /*
  * Encode/decode swap entries and swap PTEs. Swap PTEs are all PTEs that
diff --git a/arch/loongarch/mm/init.c b/arch/loongarch/mm/init.c
index 8a87a482c8f4..9f26e933a8a3 100644
--- a/arch/loongarch/mm/init.c
+++ b/arch/loongarch/mm/init.c
@@ -198,9 +198,11 @@ pte_t * __init populate_kernel_pte(unsigned long addr)
 	if (!pmd_present(pmdp_get(pmd))) {
 		pte_t *pte;
 
-		pte = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
+		pte = memblock_alloc_raw(PAGE_SIZE, PAGE_SIZE);
 		if (!pte)
 			panic("%s: Failed to allocate memory\n", __func__);
+
+		kernel_pte_init(pte);
 		pmd_populate_kernel(&init_mm, pmd, pte);
 	}
 
diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_init.c
index 427d6b1aec09..34988573b0d5 100644
--- a/arch/loongarch/mm/kasan_init.c
+++ b/arch/loongarch/mm/kasan_init.c
@@ -152,6 +152,8 @@ static void __init kasan_pte_populate(pmd_t *pmdp, unsigned long addr,
 		phys_addr_t page_phys = early ?
 					__pa_symbol(kasan_early_shadow_page)
 					      : kasan_alloc_zeroed_page(node);
+		if (!early)
+			kernel_pte_init(__va(page_phys));
 		next = addr + PAGE_SIZE;
 		set_pte(ptep, pfn_pte(__phys_to_pfn(page_phys), PAGE_KERNEL));
 	} while (ptep++, addr = next, addr != end && __pte_none(early, ptep_get(ptep)));
@@ -287,7 +289,7 @@ void __init kasan_init(void)
 		set_pte(&kasan_early_shadow_pte[i],
 			pfn_pte(__phys_to_pfn(__pa_symbol(kasan_early_shadow_page)), PAGE_KERNEL_RO));
 
-	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
+	kernel_pte_init(kasan_early_shadow_page);
 	csr_write64(__pa_symbol(swapper_pg_dir), LOONGARCH_CSR_PGDH);
 	local_flush_tlb_all();
 
diff --git a/arch/loongarch/mm/pgtable.c b/arch/loongarch/mm/pgtable.c
index eb6a29b491a7..228ffc1db0a3 100644
--- a/arch/loongarch/mm/pgtable.c
+++ b/arch/loongarch/mm/pgtable.c
@@ -38,6 +38,28 @@ pgd_t *pgd_alloc(struct mm_struct *mm)
 }
 EXPORT_SYMBOL_GPL(pgd_alloc);
 
+void kernel_pte_init(void *addr)
+{
+	unsigned long *p, *end;
+	unsigned long entry;
+
+	entry = (unsigned long)_PAGE_GLOBAL;
+	p = (unsigned long *)addr;
+	end = p + PTRS_PER_PTE;
+
+	do {
+		p[0] = entry;
+		p[1] = entry;
+		p[2] = entry;
+		p[3] = entry;
+		p[4] = entry;
+		p += 8;
+		p[-3] = entry;
+		p[-2] = entry;
+		p[-1] = entry;
+	} while (p != end);
+}
+
 void pgd_init(void *addr)
 {
 	unsigned long *p, *end;
diff --git a/include/linux/mm.h b/include/linux/mm.h
index ecf63d2b0582..6909fe059a2c 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -3818,6 +3818,7 @@ void *sparse_buffer_alloc(unsigned long size);
 struct page * __populate_section_memmap(unsigned long pfn,
 		unsigned long nr_pages, int nid, struct vmem_altmap *altmap,
 		struct dev_pagemap *pgmap);
+void kernel_pte_init(void *addr);
 void pmd_init(void *addr);
 void pud_init(void *addr);
 pgd_t *vmemmap_pgd_populate(unsigned long addr, int node);
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index 89895f38f722..ac607c306292 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -106,6 +106,10 @@ static void __ref zero_pte_populate(pmd_t *pmd, unsigned long addr,
 	}
 }
 
+void __weak __meminit kernel_pte_init(void *addr)
+{
+}
+
 static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr,
 				unsigned long end)
 {
@@ -126,8 +130,10 @@ static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr,
 
 			if (slab_is_available())
 				p = pte_alloc_one_kernel(&init_mm);
-			else
+			else {
 				p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
+				kernel_pte_init(p);
+			}
 			if (!p)
 				return -ENOMEM;
 
diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
index edcc7a6b0f6f..c0388b2e959d 100644
--- a/mm/sparse-vmemmap.c
+++ b/mm/sparse-vmemmap.c
@@ -184,6 +184,10 @@ static void * __meminit vmemmap_alloc_block_zero(unsigned long size, int node)
 	return p;
 }
 
+void __weak __meminit kernel_pte_init(void *addr)
+{
+}
+
 pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned long addr, int node)
 {
 	pmd_t *pmd = pmd_offset(pud, addr);
@@ -191,6 +195,7 @@ pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned long addr, int node)
 		void *p = vmemmap_alloc_block_zero(PAGE_SIZE, node);
 		if (!p)
 			return NULL;
+		kernel_pte_init(p);
 		pmd_populate_kernel(&init_mm, pmd, p);
 	}
 	return pmd;
-- 
2.39.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241014035855.1119220-2-maobibo%40loongson.cn.
