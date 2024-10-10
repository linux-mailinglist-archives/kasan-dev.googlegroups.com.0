Return-Path: <kasan-dev+bncBAABBHU6TW4AMGQEMGHWOPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 231F0997B7A
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 05:50:56 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-6cbc7418693sf8754576d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Oct 2024 20:50:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728532255; cv=pass;
        d=google.com; s=arc-20240605;
        b=lm1CfwXrP86VKpzO6k/GpTmnYpRJPvXrp8rxGoz9h69R7fKvHt2YYoKZlTGhwnizvj
         q6ElsMUkh5vj5y+iZXikHzlS341Qm68kXIUNK2Xm1zyk4SCB2FJVtCRTqPFo1MazxJRK
         h81KrDu3e3VFd8OiFXrYjydx0WGFMa0Wbl8/Gefl7p/HmIQbD4FHHmZ7K0RLudsS/ztT
         rnibd0Psp2/gqe7EPjXv+cPvSAezcJ6n8Hf2qeB8K9UejfgVa0bL/OCd+ln0GZh4Xcwb
         qA8DH0eHGqTEdLs1m+Ex6IlsGXPL/BwflsmnX4c8uf+VPQPmXV5eEwqT9n+iuXaBSGAd
         /8uQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=oyBOaFnM6HVG+FhR9CLlWk7UlY6kTLEh/2GYxklYloI=;
        fh=x2JRXknmD8q9kM6+pxpZwef5DuTXT+QyVr4P9fXqqGE=;
        b=fnc2Zab2gF3+QzIo3TSvBJNIg7Xd/cE7XglI5l6Gbn5BXxVzgVGlS6tu9+MSF+72/f
         KIDb6EyvA/BTpyMMfdWq7BN4KZ8eGBR2E27bXE7HxLE2INzrs9tnLXXf74uYHaUsIItL
         sq85Q5cNW0vU87GN4Xi2rqO2LLOf+bnkSPjiRl/q6jtlrWo1uut1W/MG4pQG8sCmHIMG
         ENvXRW4I9c0/jdgdnijxc/PfnQO2TFdNAkB5VpM3jNrqqEz+dYczQH4JxIRzAE0flXNf
         2iKXpCJfNh9c87iXPe0GhNIhoYz4S6iDQdrquPJm/mv/hkE5+2ke652k31IBgND23a+K
         4WoQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728532255; x=1729137055; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oyBOaFnM6HVG+FhR9CLlWk7UlY6kTLEh/2GYxklYloI=;
        b=Iik71UxZNzD4IeVfcflTKP7EJ3OnB07FQLKZWVJm8SWinj5WzQcU7f4em8B4I9PbOu
         Q1RFvV9Al/CqA6mZy+ywwLG+PqHSBussTTFktPCuxazujGULrGHc66TzxvimJlYzWTNK
         hBAjeGaD+dPsmkJRDSoIGwUdI5ZxA4RvMpjGA3bTpMOoI2mesIg8xUECjUTSAACrs14e
         BfHDkRLxHo0YKthWffMxuzsjByj/lNqLQ/HDW2QrSTU/2P0Q8CwrPwlnwzKUQWW20aqA
         kUfhNdYrme503GY2t8e0YPgBbbumIDnGQrVSc/JvJTr8xgdeaBfuwuH2fzAn6+G8fvYB
         PEtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728532255; x=1729137055;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oyBOaFnM6HVG+FhR9CLlWk7UlY6kTLEh/2GYxklYloI=;
        b=D6iQJQncwjbmwZ9Xa0LtaWz2agSmB5S465MwEWp07gfDq0QL6oTnJn/kHesUV5K3YQ
         VaqlH9qF1Ae5WRgo1yGDewixnsCqIS/Sa3kDobNxqlSuYUsPfvNHJ2KnlQu/sHsNpEqS
         xuWIfzsfKH4EG6ZZsCGMJzP7slWnbGSnFaaeGl9Be7VRN1MYJoo3zdz6oEclri0dwLxo
         V6zdQslBR3EOYT/bKSdoNL4WfZo+09q8mo7g2tZTalL2k7Vb7/yNUgw4QJ6BQY9T0Fea
         bwou0150D47aWLKYob1MsEYWoHS0jgXrSjLj8UUNrjsZJhMYAYE3yVNRWPPbNmVGTc/V
         GKHg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVN+FqG365Zg/DtxmxV0w64W55eNgsyJlFuVRlOat4/Itnm+dQ2xxkH1l/9eE7BXKL3KeBZeQ==@lfdr.de
X-Gm-Message-State: AOJu0YyZJgTED0ZQlTIF0qv9dXALTDdWIzMXRLCMOasqS+AWkzjHSX3p
	98rcWS10MhOZT6YvjGtrjEooi7Cu/6e1cn7WAMRReGRTuaBec6PA
X-Google-Smtp-Source: AGHT+IFYsKin1cdupkI3FPRg8kd0mzb7FfppGdPudYeJPvlw8F1o5K4q3CeKXcZ9ypraN3xvN7xEXA==
X-Received: by 2002:a05:6214:2dc4:b0:6cb:4b6e:9162 with SMTP id 6a1803df08f44-6cbc955cc90mr54728446d6.33.1728532254898;
        Wed, 09 Oct 2024 20:50:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4ea7:0:b0:6c5:15ae:4b18 with SMTP id 6a1803df08f44-6cbe549e69cls453316d6.0.-pod-prod-02-us;
 Wed, 09 Oct 2024 20:50:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWu8cxnl0nVco4mkJOUeS4RvUajzyD7Y3V3ghiZOjlwVXc/qfkOX0hf+qKQFuTYxBnbK5UG7uQqC50=@googlegroups.com
X-Received: by 2002:a05:6122:1805:b0:50a:d1e3:82f7 with SMTP id 71dfb90a1353d-50cf0c56945mr5188223e0c.8.1728532254275;
        Wed, 09 Oct 2024 20:50:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728532254; cv=none;
        d=google.com; s=arc-20240605;
        b=TccAn0Fy80THzxm9K2Jx13DZmDSxUwQLsNtVGmUxX6pzX/3ZuTrppJDAlm7KMApUUF
         hOPGhQXxj+JshBAvtEtl84vzxFv25Q8JTyZ/Fm5EDv032eNTtCaTMXt2Oc4PXSnlLyNh
         r7IT1xWIIM2pdm2vMYpSEDh/xY9m2ZUNCons+Va6q3ADX+2GHwDP9NsENsANHfKG1sgo
         XfTNNXWeFu6JiPx0+ut7uGdPJSkI9TPgexGeOaRE9qKhN8tVZlnmzWGWWzFRM+lgg8Np
         fXuRe8wnkcZnCfkrq72XK9csWVnBAckF/bMMgOeOYYTxX4fFfyV7UUOb08BMtB3Dktx6
         Dshw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=rd4ZkujWkFK413qElnLYwYdjOhfxwEaEsEBX+Qwnza0=;
        fh=W/+Rlbd92klLtgnDZozu+1Zm8L3oNk9WCo5yqUG4SDo=;
        b=FTbTF/PsNsT7idbxP8cQAKrTrdZ7id1WIxok3xRGnlidiM4cv0r9tZMNHX9+qBttHL
         G5Tl/nJJkdchyFEhgRDxK2B5PvnezgISGhwt7emViEHBedeuLlUt88MTkA7IYSU6P/yQ
         MBcVsl95qaWBNncMcctGrye6NMUt9Ottvq1zP3AyPjU99IQhyni2RmuvDrvmdiK1G1CT
         FLmmQX7drPYDnVxkeObs3u5ZYQkE0+3KoNdzWvZrBeAte7M31kmB/28Ck0vK3G925NhF
         GDoKpgokqwIY4m1ts7nDGr4IPjYNu/pydVZtLMdK2BbgmHPJTaevGIF2Z4gMxP+VVG1M
         RdCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id 71dfb90a1353d-50d08a78eacsi22845e0c.5.2024.10.09.20.50.52
        for <kasan-dev@googlegroups.com>;
        Wed, 09 Oct 2024 20:50:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.2.5.213])
	by gateway (Coremail) with SMTP id _____8CxrrMaTwdnxLsRAA--.26958S3;
	Thu, 10 Oct 2024 11:50:50 +0800 (CST)
Received: from localhost.localdomain (unknown [10.2.5.213])
	by front1 (Coremail) with SMTP id qMiowMDx7tUZTwdnFP8hAA--.52915S3;
	Thu, 10 Oct 2024 11:50:49 +0800 (CST)
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
Subject: [PATCH 1/4] LoongArch: Set pte entry with PAGE_GLOBAL for kernel space
Date: Thu, 10 Oct 2024 11:50:45 +0800
Message-Id: <20241010035048.3422527-2-maobibo@loongson.cn>
X-Mailer: git-send-email 2.39.3
In-Reply-To: <20241010035048.3422527-1-maobibo@loongson.cn>
References: <20241010035048.3422527-1-maobibo@loongson.cn>
MIME-Version: 1.0
X-CM-TRANSID: qMiowMDx7tUZTwdnFP8hAA--.52915S3
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

Unlike general architectures, there are two pages for one TLB entry
on LoongArch system. For kernel space, it requires both two pte
entries with PAGE_GLOBAL set, else HW treats it as non-global tlb,
there will be potential problems if tlb entry for kernel space is
not global. Such as fail to flush kernel tlb with function
local_flush_tlb_kernel_range() which only flush tlb with global bit.

Here function kernel_pte_init() is added, it can be used to init
pte table when it is created, so the default inital pte is
PAGE_GLOBAL rather than zero at beginning.

Kernel space areas includes fixmap, percpu, vmalloc and kasan areas
set default pte entry with PAGE_GLOBAL set.

Signed-off-by: Bibo Mao <maobibo@loongson.cn>
---
 arch/loongarch/include/asm/pgalloc.h | 13 +++++++++++++
 arch/loongarch/include/asm/pgtable.h |  1 +
 arch/loongarch/mm/init.c             |  4 +++-
 arch/loongarch/mm/kasan_init.c       |  4 +++-
 arch/loongarch/mm/pgtable.c          | 22 ++++++++++++++++++++++
 5 files changed, 42 insertions(+), 2 deletions(-)

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
-- 
2.39.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241010035048.3422527-2-maobibo%40loongson.cn.
