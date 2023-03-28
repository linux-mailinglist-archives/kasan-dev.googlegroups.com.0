Return-Path: <kasan-dev+bncBDKPDS4R5ECRBU7URKQQMGQEOHIBT6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FD376CBB99
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 11:58:45 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id u11-20020a170902e80b00b001a043e84bdfsf7477973plg.23
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 02:58:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679997524; cv=pass;
        d=google.com; s=arc-20160816;
        b=lL4+ff39jVCGesI91fUxdFH6mMzCN4tJDCZQyw/FLdqp3lo84S0CxiZLnFJ0QFE5EZ
         ZoanUu/eCYPnLVGCkeLhUPVb01DNVjprPB6aaRvw0sWvYn4OjWu8rabdOrZWq0kzCHpn
         1ijNRTUi8D38Xqv6i64uiSt1Q/NM71ZjnyuU+CuB4OFu/WL+4FgASdEMjX8PTl/A8JRR
         vloM9KQiGsjxPCRfbMlU1/EjQG+np4MY/TdXNWmd3aOh944dbDaTPMwgJF00bRABvETX
         TR2XgQDC9vJu30v9ieRpciBHIgvsRHYlzUYDn7PEyunp/PAR4zr0whwHd27HFNVF22MF
         iNhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=UFIloPLvFirPqqM9hH2pbChLnCCZhNK2Guv0w95SzYo=;
        b=XJOCAML/u5zYorVoOmrFC6XOCeKZoFSjg+6/8eSxl6c55sEo+3OWapcEA5uh7Z8qBw
         gTPVHGcrFPqcaqhTqVZOdR6bQk22GzdZvDy5nwNDjIXt5Q4537DvfRxHxrwcqefnppmC
         mNH3GMBMaipqoJA05gL07Wd8v1ngABrouSXQvoplz/FfMbNSEEMYQe+0abhNlL3dLM24
         b154cMrCpQhvoAzRQGNUpKZ0YxE56CWy7GtaEytYdG8a7sHKEIGxSrpi1LvRWL0bZOzK
         Lacovo6IcDhbLPsnxRyKnfkz5yZlKQ2t5s7VFm8SIjgCnQGV2nprr5M93mWQUM5EkNBb
         TjrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=RU+saPvg;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679997524;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=UFIloPLvFirPqqM9hH2pbChLnCCZhNK2Guv0w95SzYo=;
        b=byp6iwr2VHQUnAtf1Y31LJZt1VFPMFv6xiTZOo6QDUi0ZHmeOoLN94usLnHliV97Kn
         A8auolRgWe1KxMsruJuQYsAHajXtU2X+Kzi6R8+r2PXLYgTZlqI6wafoTU1a1Ng8VX66
         KRzvfEVd1yfhiSJ3y/Sh/9GfFLl1r/9y7cUfPL0+dm1T0bzERemCIB9lyK4hbAwVGY7y
         QNjrHMbTPchu9juFZLPc5LOFxFOrTpQyUj6XaKwYRzGffyLCNvvmuXTVgNJ2focJY3x4
         hdfPw1akcqGVIH3LyVVY6eYm7OePBAbgc1+sEtJzQYE/fJSCks/gcrh0C4UA70dHPkGe
         XTGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679997524;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=UFIloPLvFirPqqM9hH2pbChLnCCZhNK2Guv0w95SzYo=;
        b=C+A4r/24HsOeyj+bximXhozX64iyLp2Q1WyvDYzVDveD1tK8+Qy710Z5Bd3d0JrhFm
         wMaKDLLpY/KUYRmpb3tnJ17O7xKUumThXT21kUggic7fnm7b539DG7nO2E4/d1LiW+SK
         EsThKf2aPj2Moz+gff10gpyE+JiHPcjfIT2FrfqkuXJxOfGpZNrmiTJhX9cYwHbJCCqZ
         B/Czxlh4nIQ/jLX3wAt0wAeuw9PaMlALsTryDZB/MRyQJUW1aPhoI7bLgwoarepw7+4c
         QFSdtyOvvTBke1kKnivdm70R5xS0flB1463RGI0FceqRmotyyJR3RuqiDxtFHv9zgaj+
         MpdQ==
X-Gm-Message-State: AAQBX9dl5j9q8tq8ibLxSKePWFTRr1Nc6lfebgM2YQLd6ZE+Xo64R5jG
	N26/AO7KKF6Kt12iNNb5b8k=
X-Google-Smtp-Source: AKy350ZLPQDKis0iqW8v4qgJ4ErBhFsJnMgUZRhuufOrkg1fsSLJ/2yLKxLrMx5TxvPu6FjDVFX9QQ==
X-Received: by 2002:a05:6a00:1995:b0:626:2638:5a51 with SMTP id d21-20020a056a00199500b0062626385a51mr7783549pfl.5.1679997524018;
        Tue, 28 Mar 2023 02:58:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:384c:b0:237:7ef0:5b8 with SMTP id
 l12-20020a17090a384c00b002377ef005b8ls13590868pjf.3.-pod-canary-gmail; Tue,
 28 Mar 2023 02:58:43 -0700 (PDT)
X-Received: by 2002:a17:90b:1d01:b0:23f:abfc:5acb with SMTP id on1-20020a17090b1d0100b0023fabfc5acbmr15787257pjb.18.1679997523265;
        Tue, 28 Mar 2023 02:58:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679997523; cv=none;
        d=google.com; s=arc-20160816;
        b=Or+uUeNnnHcb2rARjJE6DAnMorTPgjtdx8PmJfy5SN4ldpAOGafc2nmsx0Z2UZ/yi3
         X/qLpvRXFZrOpIphHsDTjF3vjF4KPHP0jTS4dNFJ/OA3rSPxeCaJsfbOP7rE5iJnb7cL
         XKnb+qQHVJegTwTT/k8R0k/NIOsx7s4Hb6f/IiGAm/ty/oSyEFXttD/nk/aqJOO5m+fI
         vWhk9W0F4TM6s4ZxQNLRep52e+qNfXtPyUK8uDNqVnN87Xr7Uv07SoNSD08QrIGNt9GZ
         G3h+KR+lZjmx/CZJfRXhpJ4OawMJI9ohNKyGYmPalutIaDdcaw4TQr+UPWqte0Df/Idd
         +0ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hUuhgY917ceHjuJWRr2UIN+zKxCzAXrecq/+Z8gmroA=;
        b=t66A14B1+6i7YRqSqqFdeHWo9OLZtLZQmo+mMbSUfXuW+c3G4ULoBgUdh6/2Rz8m+1
         yRn8IVewJCNvn/8LCStO6PlQ6d2WY5ME+nGg07doKGEOT+7zA8EtTwrvNA7UXUuvxeO4
         zc28b07FhFHfUgb1byvJe8fp3fMxKuWAwas0HhnEd+6d7kxde8btccb0GT+Rci60LhAu
         rd8pYiyDGDQJqyUvrUyA9pVHl9gCVfUe9FX+QQ4jUKmq2MnPtu1epN4qSVfKgJH4GLXh
         ImjI86J/lpLxt5P5CUJU3qFe/bPh4PRLgU5C20a3mg5NVDNziX9tCtIZydkCsFk0jhko
         6cog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=RU+saPvg;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id pb3-20020a17090b3c0300b0023dbbc039bbsi78611pjb.0.2023.03.28.02.58.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Mar 2023 02:58:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id z19so11150313plo.2
        for <kasan-dev@googlegroups.com>; Tue, 28 Mar 2023 02:58:43 -0700 (PDT)
X-Received: by 2002:a05:6a20:c119:b0:d4:77a6:156f with SMTP id bh25-20020a056a20c11900b000d477a6156fmr12759375pzb.53.1679997522898;
        Tue, 28 Mar 2023 02:58:42 -0700 (PDT)
Received: from PXLDJ45XCM.bytedance.net ([139.177.225.236])
        by smtp.gmail.com with ESMTPSA id m26-20020aa78a1a000000b005a8a5be96b2sm17207556pfa.104.2023.03.28.02.58.38
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Tue, 28 Mar 2023 02:58:42 -0700 (PDT)
From: "'Muchun Song' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	jannh@google.com,
	sjpark@amazon.de,
	muchun.song@linux.dev
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Muchun Song <songmuchun@bytedance.com>
Subject: [PATCH 3/6] mm: kfence: make kfence_protect_page() void
Date: Tue, 28 Mar 2023 17:58:04 +0800
Message-Id: <20230328095807.7014-4-songmuchun@bytedance.com>
X-Mailer: git-send-email 2.37.1 (Apple Git-137.1)
In-Reply-To: <20230328095807.7014-1-songmuchun@bytedance.com>
References: <20230328095807.7014-1-songmuchun@bytedance.com>
MIME-Version: 1.0
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=RU+saPvg;       spf=pass
 (google.com: domain of songmuchun@bytedance.com designates
 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
X-Original-From: Muchun Song <songmuchun@bytedance.com>
Reply-To: Muchun Song <songmuchun@bytedance.com>
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

The arch_kfence_init_pool() make sure kfence pool is mapped with base page
size (e.g. 4KB), so the following PTE lookup in kfence_protect_page() will
always succeed. Then there is no way to stop kfence_protect_page() always
returning true, so make it void to simplify the code.

Signed-off-by: Muchun Song <songmuchun@bytedance.com>
---
 arch/arm/include/asm/kfence.h     |   4 +-
 arch/arm64/include/asm/kfence.h   |   4 +-
 arch/parisc/include/asm/kfence.h  |   7 +-
 arch/powerpc/include/asm/kfence.h |   8 +--
 arch/riscv/include/asm/kfence.h   |   4 +-
 arch/s390/include/asm/kfence.h    |   3 +-
 arch/x86/include/asm/kfence.h     |   9 +--
 mm/kfence/core.c                  | 142 +++++++++++++++++---------------------
 8 files changed, 73 insertions(+), 108 deletions(-)

diff --git a/arch/arm/include/asm/kfence.h b/arch/arm/include/asm/kfence.h
index 7980d0f2271f..c30a5f8125e8 100644
--- a/arch/arm/include/asm/kfence.h
+++ b/arch/arm/include/asm/kfence.h
@@ -43,11 +43,9 @@ static inline bool arch_kfence_init_pool(void)
 	return true;
 }
 
-static inline bool kfence_protect_page(unsigned long addr, bool protect)
+static inline void kfence_protect_page(unsigned long addr, bool protect)
 {
 	set_memory_valid(addr, 1, !protect);
-
-	return true;
 }
 
 #endif /* __ASM_ARM_KFENCE_H */
diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
index a81937fae9f6..7717c6d98b6f 100644
--- a/arch/arm64/include/asm/kfence.h
+++ b/arch/arm64/include/asm/kfence.h
@@ -12,11 +12,9 @@
 
 static inline bool arch_kfence_init_pool(void) { return true; }
 
-static inline bool kfence_protect_page(unsigned long addr, bool protect)
+static inline void kfence_protect_page(unsigned long addr, bool protect)
 {
 	set_memory_valid(addr, 1, !protect);
-
-	return true;
 }
 
 #ifdef CONFIG_KFENCE
diff --git a/arch/parisc/include/asm/kfence.h b/arch/parisc/include/asm/kfence.h
index 6259e5ac1fea..290792009315 100644
--- a/arch/parisc/include/asm/kfence.h
+++ b/arch/parisc/include/asm/kfence.h
@@ -19,13 +19,10 @@ static inline bool arch_kfence_init_pool(void)
 }
 
 /* Protect the given page and flush TLB. */
-static inline bool kfence_protect_page(unsigned long addr, bool protect)
+static inline void kfence_protect_page(unsigned long addr, bool protect)
 {
 	pte_t *pte = virt_to_kpte(addr);
 
-	if (WARN_ON(!pte))
-		return false;
-
 	/*
 	 * We need to avoid IPIs, as we may get KFENCE allocations or faults
 	 * with interrupts disabled.
@@ -37,8 +34,6 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
 		set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
 
 	flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
-
-	return true;
 }
 
 #endif /* _ASM_PARISC_KFENCE_H */
diff --git a/arch/powerpc/include/asm/kfence.h b/arch/powerpc/include/asm/kfence.h
index 6fd2b4d486c5..9d8502a7d0a4 100644
--- a/arch/powerpc/include/asm/kfence.h
+++ b/arch/powerpc/include/asm/kfence.h
@@ -21,16 +21,14 @@ static inline bool arch_kfence_init_pool(void)
 }
 
 #ifdef CONFIG_PPC64
-static inline bool kfence_protect_page(unsigned long addr, bool protect)
+static inline void kfence_protect_page(unsigned long addr, bool protect)
 {
 	struct page *page = virt_to_page(addr);
 
 	__kernel_map_pages(page, 1, !protect);
-
-	return true;
 }
 #else
-static inline bool kfence_protect_page(unsigned long addr, bool protect)
+static inline void kfence_protect_page(unsigned long addr, bool protect)
 {
 	pte_t *kpte = virt_to_kpte(addr);
 
@@ -40,8 +38,6 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
 	} else {
 		pte_update(&init_mm, addr, kpte, 0, _PAGE_PRESENT, 0);
 	}
-
-	return true;
 }
 #endif
 
diff --git a/arch/riscv/include/asm/kfence.h b/arch/riscv/include/asm/kfence.h
index d887a54042aa..1299f47170b5 100644
--- a/arch/riscv/include/asm/kfence.h
+++ b/arch/riscv/include/asm/kfence.h
@@ -46,7 +46,7 @@ static inline bool arch_kfence_init_pool(void)
 	return true;
 }
 
-static inline bool kfence_protect_page(unsigned long addr, bool protect)
+static inline void kfence_protect_page(unsigned long addr, bool protect)
 {
 	pte_t *pte = virt_to_kpte(addr);
 
@@ -56,8 +56,6 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
 		set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
 
 	flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
-
-	return true;
 }
 
 #endif /* _ASM_RISCV_KFENCE_H */
diff --git a/arch/s390/include/asm/kfence.h b/arch/s390/include/asm/kfence.h
index d55ba878378b..6d7b3632d79c 100644
--- a/arch/s390/include/asm/kfence.h
+++ b/arch/s390/include/asm/kfence.h
@@ -33,10 +33,9 @@ static __always_inline void kfence_split_mapping(void)
 #endif
 }
 
-static inline bool kfence_protect_page(unsigned long addr, bool protect)
+static inline void kfence_protect_page(unsigned long addr, bool protect)
 {
 	__kernel_map_pages(virt_to_page(addr), 1, !protect);
-	return true;
 }
 
 #endif /* _ASM_S390_KFENCE_H */
diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.h
index ff5c7134a37a..6ffd4a078a71 100644
--- a/arch/x86/include/asm/kfence.h
+++ b/arch/x86/include/asm/kfence.h
@@ -38,13 +38,9 @@ static inline bool arch_kfence_init_pool(void)
 }
 
 /* Protect the given page and flush TLB. */
-static inline bool kfence_protect_page(unsigned long addr, bool protect)
+static inline void kfence_protect_page(unsigned long addr, bool protect)
 {
-	unsigned int level;
-	pte_t *pte = lookup_address(addr, &level);
-
-	if (WARN_ON(!pte || level != PG_LEVEL_4K))
-		return false;
+	pte_t *pte = virt_to_kpte(addr);
 
 	/*
 	 * We need to avoid IPIs, as we may get KFENCE allocations or faults
@@ -65,7 +61,6 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
 	preempt_disable();
 	flush_tlb_one_kernel(addr);
 	preempt_enable();
-	return true;
 }
 
 #endif /* !MODULE */
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 6781af1dfa66..5726bf2ae13c 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -229,14 +229,14 @@ static bool alloc_covered_contains(u32 alloc_stack_hash)
 	return true;
 }
 
-static bool kfence_protect(unsigned long addr)
+static inline void kfence_protect(unsigned long addr)
 {
-	return !KFENCE_WARN_ON(!kfence_protect_page(ALIGN_DOWN(addr, PAGE_SIZE), true));
+	kfence_protect_page(ALIGN_DOWN(addr, PAGE_SIZE), true);
 }
 
-static bool kfence_unprotect(unsigned long addr)
+static inline void kfence_unprotect(unsigned long addr)
 {
-	return !KFENCE_WARN_ON(!kfence_protect_page(ALIGN_DOWN(addr, PAGE_SIZE), false));
+	kfence_protect_page(ALIGN_DOWN(addr, PAGE_SIZE), false);
 }
 
 static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *meta)
@@ -531,30 +531,19 @@ static void rcu_guarded_free(struct rcu_head *h)
 	kfence_guarded_free((void *)meta->addr, meta, false);
 }
 
-/*
- * Initialization of the KFENCE pool after its allocation.
- * Returns 0 on success; otherwise returns the address up to
- * which partial initialization succeeded.
- */
-static unsigned long kfence_init_pool(void)
+static void kfence_init_pool(void)
 {
 	unsigned long addr = (unsigned long)__kfence_pool;
 	int i;
 
-	if (!arch_kfence_init_pool())
-		return addr;
 	/*
 	 * Protect the first 2 pages. The first page is mostly unnecessary, and
 	 * merely serves as an extended guard page. However, adding one
 	 * additional page in the beginning gives us an even number of pages,
 	 * which simplifies the mapping of address to metadata index.
 	 */
-	for (i = 0; i < 2; i++) {
-		if (unlikely(!kfence_protect(addr)))
-			return addr;
-
-		addr += PAGE_SIZE;
-	}
+	for (i = 0; i < 2; i++, addr += PAGE_SIZE)
+		kfence_protect(addr);
 
 	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++, addr += 2 * PAGE_SIZE) {
 		struct kfence_metadata *meta = &kfence_metadata[i];
@@ -568,38 +557,33 @@ static unsigned long kfence_init_pool(void)
 		list_add_tail(&meta->list, &kfence_freelist);
 
 		/* Protect the right redzone. */
-		if (unlikely(!kfence_protect(addr + PAGE_SIZE)))
-			return addr;
+		kfence_protect(addr + PAGE_SIZE);
 
 		__folio_set_slab(slab_folio(slab));
 #ifdef CONFIG_MEMCG
 		slab->memcg_data = (unsigned long)&meta->objcg | MEMCG_DATA_OBJCGS;
 #endif
 	}
-
-	return 0;
 }
 
 static bool __init kfence_init_pool_early(void)
 {
-	unsigned long addr;
-
 	if (!__kfence_pool)
 		return false;
 
-	addr = kfence_init_pool();
-
-	if (!addr) {
-		/*
-		 * The pool is live and will never be deallocated from this point on.
-		 * Ignore the pool object from the kmemleak phys object tree, as it would
-		 * otherwise overlap with allocations returned by kfence_alloc(), which
-		 * are registered with kmemleak through the slab post-alloc hook.
-		 */
-		kmemleak_ignore_phys(__pa(__kfence_pool));
-		return true;
-	}
+	if (!arch_kfence_init_pool())
+		goto free;
 
+	kfence_init_pool();
+	/*
+	 * The pool is live and will never be deallocated from this point on.
+	 * Ignore the pool object from the kmemleak phys object tree, as it would
+	 * otherwise overlap with allocations returned by kfence_alloc(), which
+	 * are registered with kmemleak through the slab post-alloc hook.
+	 */
+	kmemleak_ignore_phys(__pa(__kfence_pool));
+	return true;
+free:
 	/*
 	 * Only release unprotected pages, and do not try to go back and change
 	 * page attributes due to risk of failing to do so as well. If changing
@@ -607,27 +591,7 @@ static bool __init kfence_init_pool_early(void)
 	 * fails for the first page, and therefore expect addr==__kfence_pool in
 	 * most failure cases.
 	 */
-	memblock_free_late(__pa(addr), KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool));
-	__kfence_pool = NULL;
-	return false;
-}
-
-static bool kfence_init_pool_late(void)
-{
-	unsigned long addr, free_size;
-
-	addr = kfence_init_pool();
-
-	if (!addr)
-		return true;
-
-	/* Same as above. */
-	free_size = KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool);
-#ifdef CONFIG_CONTIG_ALLOC
-	free_contig_range(page_to_pfn(virt_to_page((void *)addr)), free_size / PAGE_SIZE);
-#else
-	free_pages_exact((void *)addr, free_size);
-#endif
+	memblock_free_late(__pa(__kfence_pool), KFENCE_POOL_SIZE);
 	__kfence_pool = NULL;
 	return false;
 }
@@ -830,30 +794,50 @@ void __init kfence_init(void)
 	kfence_init_enable();
 }
 
-static int kfence_init_late(void)
-{
-	const unsigned long nr_pages = KFENCE_POOL_SIZE / PAGE_SIZE;
 #ifdef CONFIG_CONTIG_ALLOC
-	struct page *pages;
+static inline void *kfence_pool_alloc(void)
+{
+	struct page *page = alloc_contig_pages(KFENCE_POOL_SIZE / PAGE_SIZE,
+					       GFP_KERNEL, first_online_node, NULL);
 
-	pages = alloc_contig_pages(nr_pages, GFP_KERNEL, first_online_node, NULL);
-	if (!pages)
-		return -ENOMEM;
-	__kfence_pool = page_to_virt(pages);
+	return page ? page_to_virt(page) : NULL;
+}
+
+static inline void kfence_pool_free(const void *ptr)
+{
+	free_contig_range(page_to_pfn(virt_to_page(ptr)), KFENCE_POOL_SIZE / PAGE_SIZE);
+}
 #else
+static inline void *kfence_pool_alloc(void)
+{
 	BUILD_BUG_ON_MSG(get_order(KFENCE_POOL_SIZE) > MAX_ORDER,
 			 "CONFIG_KFENCE_NUM_OBJECTS is too large for buddy allocator");
 
-	__kfence_pool = alloc_pages_exact(KFENCE_POOL_SIZE, GFP_KERNEL);
+	return alloc_pages_exact(KFENCE_POOL_SIZE, GFP_KERNEL);
+}
+
+static inline void kfence_pool_free(const void *ptr)
+{
+	free_pages_exact(virt_to_page(ptr), KFENCE_POOL_SIZE);
+}
+#endif
+
+static int kfence_init_late(void)
+{
+	if (__kfence_pool)
+		return 0;
+
+	__kfence_pool = kfence_pool_alloc();
 	if (!__kfence_pool)
 		return -ENOMEM;
-#endif
 
-	if (!kfence_init_pool_late()) {
-		pr_err("%s failed\n", __func__);
+	if (!arch_kfence_init_pool()) {
+		kfence_pool_free(__kfence_pool);
+		__kfence_pool = NULL;
 		return -EBUSY;
 	}
 
+	kfence_init_pool();
 	kfence_init_enable();
 	kfence_debugfs_init();
 
@@ -862,8 +846,8 @@ static int kfence_init_late(void)
 
 static int kfence_enable_late(void)
 {
-	if (!__kfence_pool)
-		return kfence_init_late();
+	if (kfence_init_late())
+		return -ENOMEM;
 
 	WRITE_ONCE(kfence_enabled, true);
 	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
@@ -1054,8 +1038,9 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 	if (!is_kfence_address((void *)addr))
 		return false;
 
-	if (!READ_ONCE(kfence_enabled)) /* If disabled at runtime ... */
-		return kfence_unprotect(addr); /* ... unprotect and proceed. */
+	/* If disabled at runtime ... unprotect and proceed. */
+	if (!READ_ONCE(kfence_enabled))
+		goto out;
 
 	atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
 
@@ -1079,7 +1064,7 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 		}
 
 		if (!to_report)
-			goto out;
+			goto report;
 
 		raw_spin_lock_irqsave(&to_report->lock, flags);
 		to_report->unprotected_page = addr;
@@ -1093,7 +1078,7 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 	} else {
 		to_report = addr_to_metadata(addr);
 		if (!to_report)
-			goto out;
+			goto report;
 
 		raw_spin_lock_irqsave(&to_report->lock, flags);
 		error_type = KFENCE_ERROR_UAF;
@@ -1105,7 +1090,7 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 		 */
 	}
 
-out:
+report:
 	if (to_report) {
 		kfence_report_error(addr, is_write, regs, to_report, error_type);
 		raw_spin_unlock_irqrestore(&to_report->lock, flags);
@@ -1113,6 +1098,7 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 		/* This may be a UAF or OOB access, but we can't be sure. */
 		kfence_report_error(addr, is_write, regs, NULL, KFENCE_ERROR_INVALID);
 	}
-
-	return kfence_unprotect(addr); /* Unprotect and let access proceed. */
+out:
+	kfence_unprotect(addr);
+	return true;
 }
-- 
2.11.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230328095807.7014-4-songmuchun%40bytedance.com.
