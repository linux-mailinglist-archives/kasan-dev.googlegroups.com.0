Return-Path: <kasan-dev+bncBDXY7I6V6AMRBANC56YQMGQE4WKOYAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id D5D458C04DC
	for <lists+kasan-dev@lfdr.de>; Wed,  8 May 2024 21:22:42 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-572babec6c6sf1207005a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 08 May 2024 12:22:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715196162; cv=pass;
        d=google.com; s=arc-20160816;
        b=BJ/iGnVlT1bIWdqXY2UqeQFI44PAa2i7GS9qkSpJefMMidE0a8iuXUToqcHOt3IO2f
         FsMIn4zq0TkTEdkrSbs504KfaVAGrTRTGb/kGs547gmF8eUD3G+h2THdQdTIHBrFn3HD
         BrVs1xWfQXSufzcynFMa4veAcK9dpwSt9hcp2V0RZwWzuIU28yAuYVdj5Te/WisZ+obQ
         33T7x2VZoooqvpjXZbpZtsMMJNOP+To5H/KPZC1N/+sCtra81JrpERciaHIBSO/nT20q
         rKz8xCSvD60cgCfMg9/V92mcAolGFTr9we/23rr5eqWX9+tvH1h5109+dG0+1y3shMd2
         LIMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Dg3ywxWQ/NspuwHXNap435+WFywpqF3+le5GrPkVSqQ=;
        fh=PtbDbw7CJiESuAUJVgpdqw+1uH2/Me4PBiq3CcR1xGk=;
        b=PC9MeHXa8C79i0QTGN1Rx0fMsesO+uNOCUzAay1K178I0nXCEAodhBReQqtDLlQ3Y7
         2tBI24CSBObW0/6ZQNtE4O5gNHPpiIFsDnqg76s4N34C2fmQlIom1dr7b/lE5tBMBvGV
         tX5LYx3YsXqg+nsIqyPcc7OVKVHPrfHj5UR7ms1hJIstP7Fe1cHPhkNeV6K2maK/d4cz
         AywY2ALPCVxxvJnDvCwCazznDWCErbZ4uX0csELWrmD2DHKQZwNImXwwKMihUe4W/Yu8
         cO4WDhLH3w++zeA/8dt9bMr2enCtpHFbVe4Hi4+wq0K/SJiuSLLmm+bFhbRWKMm3Teid
         7xbg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=Do2FOnKh;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715196162; x=1715800962; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Dg3ywxWQ/NspuwHXNap435+WFywpqF3+le5GrPkVSqQ=;
        b=WUkNc9Cz0obudgV7CqlIxgqyeh1tp6b5uOUpEoq5ZYMs81pLZoa8D75o2tKSoHJF8p
         T/XubcJWVoD3KwJ5v7s+kxddnGWMeNvOCONxXZIrQCF5Xx3vP6stSprIamFdbWbWmMXo
         srkUxF6Jo7X8XRZO0i7+H5j/OAOn8flkCJLrm1dg1mgK5+P4RblzgaY0qqI1ZljnJuIH
         JCJge6XP/10cWrWEPfhbVyODkS+FTKcaV0aP/ZxXDc6PVCRR53D2DfhkjO681CbvaK6P
         X6J9/OOm4+Y8kgilKHQlWDIPQLvYmdIUQE07MsyG40aSjB72OpGwam9yPEZfW8BjqNs2
         uLcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715196162; x=1715800962;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Dg3ywxWQ/NspuwHXNap435+WFywpqF3+le5GrPkVSqQ=;
        b=MP+zLX5erO1NoSid+cGTkv2uyy5LQAuCQjX5U+KW2bZoShQW2e6Dqh8xJvxUx5uRwH
         6E03F2EtDnzSU9SJMLuZQEaOsklSVL5gAcD3P+L/j3v3eawwOs/zw0n+q0rJNRvui/pZ
         HBG2ymjiyvALIQonVWVxwQ+FS8MRzS0/kHz8Y1YuuNwdhlt/giJQyDywsWikAFoifJpG
         QnjtZFT6r8HDwd2cJI7AbmQ+ernGafakRO1CpJkD34SCZ6k1kPA0nA0uuO4S0amTC/R2
         Bv0ysFtMoWRYG8wKE8YEewd+cJiQVKA4JOeH6iMy20Csq20gpc3p4lmTMl6Aw089iv2M
         PRJQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX9WSVekanIUKcYPtPT0OY9VG/ZkNUw3VCXPU2L7qGhqF/gC5t1AHWepXru/OHNgofkXrm4C1HPUdq3HuBkbH5XTItfX0SlRg==
X-Gm-Message-State: AOJu0YwI/J8CjS30SaHHoxyWwxd7rsJEB5PPwfYsBBNhobw932f0NnML
	lnUkl9m6ZMFmqEQOQol3lTaaBmCOUy9uiYWUVdboHIsSwMXIAQDW
X-Google-Smtp-Source: AGHT+IF69BLTO9lAjvAZeIprCgHZBerMXRM6vJr7BAiorivfp11xLyomUvpNYC/eDTALwa0ktiWIcg==
X-Received: by 2002:aa7:d757:0:b0:572:b03f:906c with SMTP id 4fb4d7f45d1cf-57332685c92mr489804a12.1.1715196161291;
        Wed, 08 May 2024 12:22:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3222:b0:572:3ac4:56ed with SMTP id
 4fb4d7f45d1cf-57332e95b57ls114762a12.0.-pod-prod-00-eu; Wed, 08 May 2024
 12:22:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVa7CHw/w1+lnLAitXSLmQX7+YC7dclXiFTze7qCUb1GjCRhlm0PKwnjVFlFdp/wlZGs33Er+mhegl+yIoigHy/mv+BdYyb3UdXaQ==
X-Received: by 2002:aa7:c992:0:b0:572:b0a8:65fd with SMTP id 4fb4d7f45d1cf-573326eddfemr438100a12.6.1715196159242;
        Wed, 08 May 2024 12:22:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715196159; cv=none;
        d=google.com; s=arc-20160816;
        b=u4CItiJvdzQy+zvEa4Nqa93wyOPST0Vzom49VuVeIgCgB9/khjQnAn+zurAqtzmJaQ
         /0xiNKHEAoZDP4bvUkLLybuoS8qk5Ft3QyVmDEb4dC89IWLOny6F5WSXcdRNyVAPl2O5
         iLevbShdybh4J+Z065BVH4q2460K/kGMgcRLtXmKbyOMByW4MFprm/K6BwzRHF4YEWxE
         wfRLu0MFq1TNfkKMjndf35fGtWGUGKaWmKz03PyVE1yVMXJ8JNFmNuEr6ABhidPgu3iK
         2wlCh9/cEhqj/wOYFpxjjoYVz9IDh9SYZj06TPuqKIEQXWASm+yEiHh9Bj9o+DTSd/Af
         U/fA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/S8/CVFlZq+KrirwWJV8BSI4dNCVaFyTIK5dU7sIVgI=;
        fh=9mBXq/HVBc1UytRrpixiQlAx2sCVVtDdtry8hXlTSPw=;
        b=e7L4Dqp1vuQju8xd3kWKKZXgEZEQmmmdWKnp5C/LfQcQwB3MKpJkCe+fjjiwbNVEbq
         ol/kvvEh/KYZLvd0QqYGWnN9AjJNXsgOekbaudJN7S620vgCV2pkD6RUc4CPgeDb1OyN
         1u7QfdTW2l2Ka9GeGonI82Qm28VanAiKOpkssZGtSo1CP/dOKeOAHtEUVmj6VdjT21B+
         px1+YdWIQg9O7yzUBR5SRXZ/47qPQREx5e30wpBiKygLBwgWyPVWMyOlS/CN/fBBzDZM
         2B6eKh5tqDKbXFqUVb4AEdzqKUxGnfU/BKUTJT3KfSjAJ6EYuCzhah2gvPiw5dXC3dx2
         7opA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=Do2FOnKh;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id bl16-20020a056402211000b0057051ef3286si511994edb.5.2024.05.08.12.22.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 May 2024 12:22:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-41fc2f7fbb5so607735e9.1
        for <kasan-dev@googlegroups.com>; Wed, 08 May 2024 12:22:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW7RhZGzcWzR/H7ecoR7mtYNQZvG3SRZOibP/BWprJKb3Lq78QmzAzBYWYm/O1Z+OGbjPw5qIYb46urryTjzu3ye1qwg734turJcw==
X-Received: by 2002:a05:600c:3b83:b0:41b:4506:9fd with SMTP id 5b1f17b1804b1-41fbcb42dd6mr4932615e9.6.1715196158601;
        Wed, 08 May 2024 12:22:38 -0700 (PDT)
Received: from alex-rivos.ba.rivosinc.com (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id f20-20020a05600c155400b0041bf7da4200sm3310028wmg.33.2024.05.08.12.22.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 May 2024 12:22:38 -0700 (PDT)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Ryan Roberts <ryan.roberts@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Ard Biesheuvel <ardb@kernel.org>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <atishp@atishpatra.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-efi@vger.kernel.org,
	kvm@vger.kernel.org,
	kvm-riscv@lists.infradead.org,
	linux-mm@kvack.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH 03/12] mm, riscv, arm64: Use common set_ptes() function
Date: Wed,  8 May 2024 21:19:22 +0200
Message-Id: <20240508191931.46060-4-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20240508191931.46060-1-alexghiti@rivosinc.com>
References: <20240508191931.46060-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=Do2FOnKh;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

Make riscv use the contpte aware set_ptes() function from arm64.

Note that riscv can support multiple contpte sizes so the arm64 code was
modified to take into account this possibility.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/arm64/include/asm/pgtable.h |  88 ++++------
 arch/arm64/mm/contpte.c          | 162 ------------------
 arch/arm64/mm/mmu.c              |   2 +-
 arch/riscv/include/asm/pgtable.h |  76 +++++++++
 include/linux/contpte.h          |  10 ++
 mm/contpte.c                     | 277 ++++++++++++++++++++++++++++++-
 6 files changed, 398 insertions(+), 217 deletions(-)

diff --git a/arch/arm64/include/asm/pgtable.h b/arch/arm64/include/asm/pgtable.h
index a878735deb9f..e85b3a052a02 100644
--- a/arch/arm64/include/asm/pgtable.h
+++ b/arch/arm64/include/asm/pgtable.h
@@ -118,10 +118,17 @@ static inline pteval_t __phys_to_pte_val(phys_addr_t phys)
 #define pte_tagged(pte)		((pte_val(pte) & PTE_ATTRINDX_MASK) == \
 				 PTE_ATTRINDX(MT_NORMAL_TAGGED))
 
-#define pte_cont_addr_end(addr, end)						\
-({	unsigned long __boundary = ((addr) + CONT_PTE_SIZE) & CONT_PTE_MASK;	\
-	(__boundary - 1 < (end) - 1) ? __boundary : (end);			\
-})
+static inline unsigned long arch_contpte_addr_end(unsigned long addr,
+						  unsigned long end,
+						  int *ncontig)
+{
+	unsigned long __boundary = (addr + CONT_PTE_SIZE) & CONT_PTE_MASK;
+
+	if (ncontig)
+		*ncontig = CONT_PTES;
+
+	return (__boundary - 1 < end - 1) ? __boundary : end;
+}
 
 #define pmd_cont_addr_end(addr, end)						\
 ({	unsigned long __boundary = ((addr) + CONT_PMD_SIZE) & CONT_PMD_MASK;	\
@@ -1377,13 +1384,7 @@ extern void ptep_modify_prot_commit(struct vm_area_struct *vma,
  * where it is possible and makes sense to do so. The PTE_CONT bit is considered
  * a private implementation detail of the public ptep API (see below).
  */
-extern void __contpte_try_fold(struct mm_struct *mm, unsigned long addr,
-				pte_t *ptep, pte_t pte);
-extern void __contpte_try_unfold(struct mm_struct *mm, unsigned long addr,
-				 pte_t *ptep, pte_t pte);
 extern pte_t contpte_ptep_get_lockless(pte_t *orig_ptep);
-extern void contpte_set_ptes(struct mm_struct *mm, unsigned long addr,
-				pte_t *ptep, pte_t pte, unsigned int nr);
 extern void contpte_clear_full_ptes(struct mm_struct *mm, unsigned long addr,
 				pte_t *ptep, unsigned int nr, int full);
 extern pte_t contpte_get_and_clear_full_ptes(struct mm_struct *mm,
@@ -1399,36 +1400,6 @@ extern int contpte_ptep_set_access_flags(struct vm_area_struct *vma,
 				unsigned long addr, pte_t *ptep,
 				pte_t entry, int dirty);
 
-static __always_inline void contpte_try_fold(struct mm_struct *mm,
-				unsigned long addr, pte_t *ptep, pte_t pte)
-{
-	/*
-	 * Only bother trying if both the virtual and physical addresses are
-	 * aligned and correspond to the last entry in a contig range. The core
-	 * code mostly modifies ranges from low to high, so this is the likely
-	 * the last modification in the contig range, so a good time to fold.
-	 * We can't fold special mappings, because there is no associated folio.
-	 */
-
-	const unsigned long contmask = CONT_PTES - 1;
-	bool valign = ((addr >> PAGE_SHIFT) & contmask) == contmask;
-
-	if (unlikely(valign)) {
-		bool palign = (pte_pfn(pte) & contmask) == contmask;
-
-		if (unlikely(palign &&
-		    pte_valid(pte) && !pte_cont(pte) && !pte_special(pte)))
-			__contpte_try_fold(mm, addr, ptep, pte);
-	}
-}
-
-static __always_inline void contpte_try_unfold(struct mm_struct *mm,
-				unsigned long addr, pte_t *ptep, pte_t pte)
-{
-	if (unlikely(pte_valid_cont(pte)))
-		__contpte_try_unfold(mm, addr, ptep, pte);
-}
-
 #define pte_batch_hint pte_batch_hint
 static inline unsigned int pte_batch_hint(pte_t *ptep, pte_t pte)
 {
@@ -1485,20 +1456,9 @@ static inline void set_pte(pte_t *ptep, pte_t pte)
 	__set_pte(ptep, pte_mknoncont(pte));
 }
 
+extern void set_ptes(struct mm_struct *mm, unsigned long addr,
+		     pte_t *ptep, pte_t pte, unsigned int nr);
 #define set_ptes set_ptes
-static __always_inline void set_ptes(struct mm_struct *mm, unsigned long addr,
-				pte_t *ptep, pte_t pte, unsigned int nr)
-{
-	pte = pte_mknoncont(pte);
-
-	if (likely(nr == 1)) {
-		contpte_try_unfold(mm, addr, ptep, __ptep_get(ptep));
-		__set_ptes(mm, addr, ptep, pte, 1);
-		contpte_try_fold(mm, addr, ptep, pte);
-	} else {
-		contpte_set_ptes(mm, addr, ptep, pte, nr);
-	}
-}
 
 static inline void pte_clear(struct mm_struct *mm,
 				unsigned long addr, pte_t *ptep)
@@ -1686,6 +1646,28 @@ static inline pte_t *arch_contpte_align_down(pte_t *ptep)
 	return PTR_ALIGN_DOWN(ptep, sizeof(*ptep) * CONT_PTES);
 }
 
+static inline void arch_contpte_flush_tlb_range(struct vm_area_struct *vma,
+						unsigned long start,
+						unsigned long end,
+						unsigned long stride)
+{
+	__flush_tlb_range(vma, start, end, stride, true, 3);
+}
+
+static inline int arch_contpte_get_first_ncontig(size_t *pgsize)
+{
+	if (pgsize)
+		*pgsize = PAGE_SIZE;
+
+	return CONT_PTES;
+}
+
+/* Must return 0 when ncontig does not have any next. */
+static inline int arch_contpte_get_next_ncontig(int ncontig, size_t *pgsize)
+{
+	return 0;
+}
+
 #endif /* !__ASSEMBLY__ */
 
 #endif /* __ASM_PGTABLE_H */
diff --git a/arch/arm64/mm/contpte.c b/arch/arm64/mm/contpte.c
index d5512ebb26e9..e225e458856e 100644
--- a/arch/arm64/mm/contpte.c
+++ b/arch/arm64/mm/contpte.c
@@ -8,19 +8,6 @@
 #include <linux/export.h>
 #include <asm/tlbflush.h>
 
-static inline bool mm_is_user(struct mm_struct *mm)
-{
-	/*
-	 * Don't attempt to apply the contig bit to kernel mappings, because
-	 * dynamically adding/removing the contig bit can cause page faults.
-	 * These racing faults are ok for user space, since they get serialized
-	 * on the PTL. But kernel mappings can't tolerate faults.
-	 */
-	if (unlikely(mm_is_efi(mm)))
-		return false;
-	return mm != &init_mm;
-}
-
 static void contpte_try_unfold_partial(struct mm_struct *mm, unsigned long addr,
 					pte_t *ptep, unsigned int nr)
 {
@@ -41,112 +28,6 @@ static void contpte_try_unfold_partial(struct mm_struct *mm, unsigned long addr,
 	}
 }
 
-static void contpte_convert(struct mm_struct *mm, unsigned long addr,
-			    pte_t *ptep, pte_t pte)
-{
-	struct vm_area_struct vma = TLB_FLUSH_VMA(mm, 0);
-	unsigned long start_addr;
-	pte_t *start_ptep;
-	int i;
-
-	start_ptep = ptep = arch_contpte_align_down(ptep);
-	start_addr = addr = ALIGN_DOWN(addr, CONT_PTE_SIZE);
-	pte = pfn_pte(ALIGN_DOWN(pte_pfn(pte), CONT_PTES), pte_pgprot(pte));
-
-	for (i = 0; i < CONT_PTES; i++, ptep++, addr += PAGE_SIZE) {
-		pte_t ptent = __ptep_get_and_clear(mm, addr, ptep);
-
-		if (pte_dirty(ptent))
-			pte = pte_mkdirty(pte);
-
-		if (pte_young(ptent))
-			pte = pte_mkyoung(pte);
-	}
-
-	__flush_tlb_range(&vma, start_addr, addr, PAGE_SIZE, true, 3);
-
-	__set_ptes(mm, start_addr, start_ptep, pte, CONT_PTES);
-}
-
-void __contpte_try_fold(struct mm_struct *mm, unsigned long addr,
-			pte_t *ptep, pte_t pte)
-{
-	/*
-	 * We have already checked that the virtual and pysical addresses are
-	 * correctly aligned for a contpte mapping in contpte_try_fold() so the
-	 * remaining checks are to ensure that the contpte range is fully
-	 * covered by a single folio, and ensure that all the ptes are valid
-	 * with contiguous PFNs and matching prots. We ignore the state of the
-	 * access and dirty bits for the purpose of deciding if its a contiguous
-	 * range; the folding process will generate a single contpte entry which
-	 * has a single access and dirty bit. Those 2 bits are the logical OR of
-	 * their respective bits in the constituent pte entries. In order to
-	 * ensure the contpte range is covered by a single folio, we must
-	 * recover the folio from the pfn, but special mappings don't have a
-	 * folio backing them. Fortunately contpte_try_fold() already checked
-	 * that the pte is not special - we never try to fold special mappings.
-	 * Note we can't use vm_normal_page() for this since we don't have the
-	 * vma.
-	 */
-
-	unsigned long folio_start, folio_end;
-	unsigned long cont_start, cont_end;
-	pte_t expected_pte, subpte;
-	struct folio *folio;
-	struct page *page;
-	unsigned long pfn;
-	pte_t *orig_ptep;
-	pgprot_t prot;
-
-	int i;
-
-	if (!mm_is_user(mm))
-		return;
-
-	page = pte_page(pte);
-	folio = page_folio(page);
-	folio_start = addr - (page - &folio->page) * PAGE_SIZE;
-	folio_end = folio_start + folio_nr_pages(folio) * PAGE_SIZE;
-	cont_start = ALIGN_DOWN(addr, CONT_PTE_SIZE);
-	cont_end = cont_start + CONT_PTE_SIZE;
-
-	if (folio_start > cont_start || folio_end < cont_end)
-		return;
-
-	pfn = ALIGN_DOWN(pte_pfn(pte), CONT_PTES);
-	prot = pte_pgprot(pte_mkold(pte_mkclean(pte)));
-	expected_pte = pfn_pte(pfn, prot);
-	orig_ptep = ptep;
-	ptep = arch_contpte_align_down(ptep);
-
-	for (i = 0; i < CONT_PTES; i++) {
-		subpte = pte_mkold(pte_mkclean(__ptep_get(ptep)));
-		if (!pte_same(subpte, expected_pte))
-			return;
-		expected_pte = pte_advance_pfn(expected_pte, 1);
-		ptep++;
-	}
-
-	pte = pte_mkcont(pte);
-	contpte_convert(mm, addr, orig_ptep, pte);
-}
-EXPORT_SYMBOL_GPL(__contpte_try_fold);
-
-void __contpte_try_unfold(struct mm_struct *mm, unsigned long addr,
-			pte_t *ptep, pte_t pte)
-{
-	/*
-	 * We have already checked that the ptes are contiguous in
-	 * contpte_try_unfold(), so just check that the mm is user space.
-	 */
-	if (!mm_is_user(mm))
-		return;
-
-	pte = pte_mknoncont(pte);
-	contpte_convert(mm, addr, ptep, pte);
-}
-EXPORT_SYMBOL_GPL(__contpte_try_unfold);
-
 pte_t contpte_ptep_get_lockless(pte_t *orig_ptep)
 {
 	/*
@@ -204,49 +85,6 @@ pte_t contpte_ptep_get_lockless(pte_t *orig_ptep)
 }
 EXPORT_SYMBOL_GPL(contpte_ptep_get_lockless);
 
-void contpte_set_ptes(struct mm_struct *mm, unsigned long addr,
-					pte_t *ptep, pte_t pte, unsigned int nr)
-{
-	unsigned long next;
-	unsigned long end;
-	unsigned long pfn;
-	pgprot_t prot;
-
-	/*
-	 * The set_ptes() spec guarantees that when nr > 1, the initial state of
-	 * all ptes is not-present. Therefore we never need to unfold or
-	 * otherwise invalidate a range before we set the new ptes.
-	 * contpte_set_ptes() should never be called for nr < 2.
-	 */
-	VM_WARN_ON(nr == 1);
-
-	if (!mm_is_user(mm))
-		return __set_ptes(mm, addr, ptep, pte, nr);
-
-	end = addr + (nr << PAGE_SHIFT);
-	pfn = pte_pfn(pte);
-	prot = pte_pgprot(pte);
-
-	do {
-		next = pte_cont_addr_end(addr, end);
-		nr = (next - addr) >> PAGE_SHIFT;
-		pte = pfn_pte(pfn, prot);
-
-		if (((addr | next | (pfn << PAGE_SHIFT)) & ~CONT_PTE_MASK) == 0)
-			pte = pte_mkcont(pte);
-		else
-			pte = pte_mknoncont(pte);
-
-		__set_ptes(mm, addr, ptep, pte, nr);
-
-		addr = next;
-		ptep += nr;
-		pfn += nr;
-
-	} while (addr != end);
-}
-EXPORT_SYMBOL_GPL(contpte_set_ptes);
-
 void contpte_clear_full_ptes(struct mm_struct *mm, unsigned long addr,
 				pte_t *ptep, unsigned int nr, int full)
 {
diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index 495b732d5af3..b7ad732660aa 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -222,7 +222,7 @@ static void alloc_init_cont_pte(pmd_t *pmdp, unsigned long addr,
 	do {
 		pgprot_t __prot = prot;
 
-		next = pte_cont_addr_end(addr, end);
+		next = arch_contpte_addr_end(addr, end, NULL);
 
 		/* use a contiguous mapping if the range is suitably aligned */
 		if ((((addr | next | phys) & ~CONT_PTE_MASK) == 0) &&
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index 8d05179f6bbe..ebfe6b16529e 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -301,6 +301,20 @@ static inline unsigned long pte_napot(pte_t pte)
 #define pte_valid_napot(pte)	(pte_present(pte) && pte_napot(pte))
 #define pte_valid_cont		pte_valid_napot
 
+/*
+ * contpte is what we expose to the core mm code, this is not exactly a napot
+ * mapping since the size is not encoded in the pfn yet.
+ */
+static inline pte_t pte_mknoncont(pte_t pte)
+{
+	return __pte(pte_val(pte) & ~_PAGE_NAPOT);
+}
+
+static inline pte_t pte_mkcont(pte_t pte)
+{
+	return __pte(pte_val(pte) | _PAGE_NAPOT);
+}
+
 static inline pte_t pte_mknapot(pte_t pte, unsigned int order)
 {
 	int pos = order - 1 + _PAGE_PFN_SHIFT;
@@ -329,6 +343,11 @@ static inline unsigned long pte_napot(pte_t pte)
 
 #endif /* CONFIG_RISCV_ISA_SVNAPOT */
 
+static inline pgprot_t pte_pgprot(pte_t pte)
+{
+	return __pgprot(pte_val(pte) & ~_PAGE_PFN_MASK);
+}
+
 /* Yields the page frame number (PFN) of a page table entry */
 static inline unsigned long pte_pfn(pte_t pte)
 {
@@ -354,6 +373,11 @@ static inline int pte_present(pte_t pte)
 	return (pte_val(pte) & (_PAGE_PRESENT | _PAGE_PROT_NONE));
 }
 
+static inline int pte_valid(pte_t pte)
+{
+	return (pte_val(pte) & _PAGE_PRESENT);
+}
+
 static inline int pte_none(pte_t pte)
 {
 	return (pte_val(pte) == 0);
@@ -583,6 +607,55 @@ static inline pte_t *arch_contpte_align_down(pte_t *ptep)
 	return PTR_ALIGN_DOWN(ptep, sizeof(*ptep) * ncontig);
 }
 
+static inline void arch_contpte_flush_tlb_range(struct vm_area_struct *vma,
+						unsigned long start,
+						unsigned long end,
+						unsigned long stride)
+{
+	flush_tlb_mm_range(vma->vm_mm, start, end, stride);
+}
+
+static inline int arch_contpte_get_first_ncontig(size_t *pgsize)
+{
+	if (pgsize)
+		*pgsize = PAGE_SIZE;
+
+	return 1 << NAPOT_CONT64KB_ORDER;
+}
+
+/* Must return 0 when ncontig does not have any next. */
+static inline int arch_contpte_get_next_ncontig(int ncontig, size_t *pgsize)
+{
+	return 0;
+}
+
+#define for_each_contpte_order_rev(ncontig, order, pgsize)				\
+	for (pgsize = PAGE_SIZE, order = NAPOT_ORDER_MAX - 1, ncontig = BIT(order);	\
+	     ncontig >= BIT(NAPOT_CONT_ORDER_BASE);					\
+	     order--, ncontig = BIT(order))
+
+static inline unsigned long arch_contpte_addr_end(unsigned long addr,
+						  unsigned long end,
+						  int *ncontig)
+{
+	unsigned long contpte_saddr, contpte_eaddr, contpte_size;
+	size_t pgsize;
+	int contig, order;
+
+	for_each_contpte_order_rev(contig, order, pgsize) {
+		contpte_size = contig * pgsize;
+		contpte_saddr = ALIGN_DOWN(addr, contpte_size);
+		contpte_eaddr = contpte_saddr + contpte_size;
+
+		if (contpte_saddr >= addr && contpte_eaddr <= end) {
+			*ncontig = contig;
+			return contpte_eaddr;
+		}
+	}
+
+	*ncontig = 0;
+	return end;
+}
 #endif
 
 static inline pte_t __ptep_get(pte_t *ptep)
@@ -712,6 +785,9 @@ static inline int ptep_clear_flush_young(struct vm_area_struct *vma,
 
 extern pte_t ptep_get(pte_t *ptep);
 #define ptep_get ptep_get
+extern void set_ptes(struct mm_struct *mm, unsigned long addr,
+		     pte_t *ptep, pte_t pteval, unsigned int nr);
+#define set_ptes set_ptes
 
 #else /* CONFIG_THP_CONTPTE */
 
diff --git a/include/linux/contpte.h b/include/linux/contpte.h
index 46acac7222ca..54d10204e9af 100644
--- a/include/linux/contpte.h
+++ b/include/linux/contpte.h
@@ -8,5 +8,15 @@
  * a private implementation detail of the public ptep API (see below).
  */
 pte_t contpte_ptep_get(pte_t *ptep, pte_t orig_pte);
+void __contpte_try_fold(struct mm_struct *mm, unsigned long addr,
+			pte_t *ptep, pte_t pte);
+void contpte_try_fold(struct mm_struct *mm, unsigned long addr,
+		      pte_t *ptep, pte_t pte);
+void __contpte_try_unfold(struct mm_struct *mm, unsigned long addr,
+			  pte_t *ptep, pte_t pte);
+void contpte_try_unfold(struct mm_struct *mm, unsigned long addr,
+			pte_t *ptep, pte_t pte);
+void contpte_set_ptes(struct mm_struct *mm, unsigned long addr,
+		      pte_t *ptep, pte_t pte, unsigned int nr);
 
 #endif /* _LINUX_CONTPTE_H */
diff --git a/mm/contpte.c b/mm/contpte.c
index d365356bbf92..566745d7842f 100644
--- a/mm/contpte.c
+++ b/mm/contpte.c
@@ -7,6 +7,7 @@
 #include <linux/pgtable.h>
 #include <linux/hugetlb.h>
 #include <linux/contpte.h>
+#include <linux/efi.h>
 
 /*
  * Any arch that wants to use that needs to define:
@@ -20,6 +21,14 @@
  *   - arch_contpte_get_num_contig()
  *   - pte_valid_cont()
  *   - arch_contpte_align_down()
+ *   - arch_contpte_flush_tlb_range()
+ *   - arch_contpte_get_first_ncontig()
+ *   - arch_contpte_get_next_ncontig()
+ *   - arch_contpte_addr_end()
+ *   - pte_mkcont()
+ *   - pte_mknoncont()
+ *   - pte_valid()
+ *   - pte_pgprot()
  */
 
 /*
@@ -32,6 +41,7 @@
  *   - huge_ptep_set_wrprotect()
  *   - huge_ptep_clear_flush()
  *   - ptep_get()
+ *   - set_ptes()
  */
 
 pte_t huge_ptep_get(pte_t *ptep)
@@ -314,4 +324,269 @@ __always_inline pte_t ptep_get(pte_t *ptep)
 
 	return contpte_ptep_get(ptep, pte);
 }
-#endif /* CONTPTE_THP_CONTPTE */
+EXPORT_SYMBOL_GPL(ptep_get);
+
+static inline bool mm_is_user(struct mm_struct *mm)
+{
+	/*
+	 * Don't attempt to apply the contig bit to kernel mappings, because
+	 * dynamically adding/removing the contig bit can cause page faults.
+	 * These racing faults are ok for user space, since they get serialized
+	 * on the PTL. But kernel mappings can't tolerate faults.
+	 */
+	if (unlikely(mm_is_efi(mm)))
+		return false;
+	return mm != &init_mm;
+}
+
+static void contpte_convert(struct mm_struct *mm, unsigned long addr,
+			    pte_t *ptep, pte_t pte,
+			    int ncontig, size_t pgsize)
+{
+	struct vm_area_struct vma = TLB_FLUSH_VMA(mm, 0);
+	unsigned long start_addr;
+	pte_t *start_ptep;
+	int i;
+
+	start_addr = addr;
+	start_ptep = ptep;
+
+	for (i = 0; i < ncontig; i++, ptep++, addr += pgsize) {
+		pte_t ptent = __ptep_get_and_clear(mm, addr, ptep);
+
+		if (pte_dirty(ptent))
+			pte = pte_mkdirty(pte);
+
+		if (pte_young(ptent))
+			pte = pte_mkyoung(pte);
+	}
+
+	arch_contpte_flush_tlb_range(&vma, start_addr, addr, pgsize);
+
+	__set_ptes(mm, start_addr, start_ptep, pte, ncontig);
+}
+
+void __contpte_try_unfold(struct mm_struct *mm, unsigned long addr,
+			  pte_t *ptep, pte_t pte)
+{
+	unsigned long start_addr;
+	pte_t *start_ptep;
+	size_t pgsize;
+	int ncontig;
+
+	/*
+	 * We have already checked that the ptes are contiguous in
+	 * contpte_try_unfold(), so just check that the mm is user space.
+	 */
+	if (!mm_is_user(mm))
+		return;
+
+	pte = pte_mknoncont(pte);
+	start_ptep = arch_contpte_align_down(ptep);
+	ncontig = arch_contpte_get_num_contig(mm, addr, start_ptep, 0, &pgsize);
+	start_addr = ALIGN_DOWN(addr, ncontig * pgsize);
+	pte = pfn_pte(ALIGN_DOWN(pte_pfn(pte), ncontig), pte_pgprot(pte));
+
+	contpte_convert(mm, start_addr, start_ptep, pte, ncontig, pgsize);
+}
+
+__always_inline void contpte_try_unfold(struct mm_struct *mm,
+					unsigned long addr, pte_t *ptep,
+					pte_t pte)
+{
+	if (unlikely(pte_valid_cont(pte)))
+		__contpte_try_unfold(mm, addr, ptep, pte);
+}
+EXPORT_SYMBOL_GPL(contpte_try_unfold);
+
+static bool contpte_is_last_pte(unsigned long addr, pte_t pte, int ncontig)
+{
+	const unsigned long contmask = ncontig - 1;
+	bool valign = ((addr >> PAGE_SHIFT) & contmask) == contmask;
+
+	if (unlikely(valign)) {
+		bool palign = (pte_pfn(pte) & contmask) == contmask;
+
+		if (unlikely(palign &&
+		    pte_valid(pte) && !pte_cont(pte) && !pte_special(pte)))
+			return true;
+	}
+
+	return false;
+}
+
+void __contpte_try_fold(struct mm_struct *mm, unsigned long addr,
+			pte_t *ptep, pte_t pte)
+{
+	/*
+	 * We have already checked that the virtual and pysical addresses are
+	 * correctly aligned for a contpte mapping in contpte_try_fold() so the
+	 * remaining checks are to ensure that the contpte range is fully
+	 * covered by a single folio, and ensure that all the ptes are valid
+	 * with contiguous PFNs and matching prots. We ignore the state of the
+	 * access and dirty bits for the purpose of deciding if its a contiguous
+	 * range; the folding process will generate a single contpte entry which
+	 * has a single access and dirty bit. Those 2 bits are the logical OR of
+	 * their respective bits in the constituent pte entries. In order to
+	 * ensure the contpte range is covered by a single folio, we must
+	 * recover the folio from the pfn, but special mappings don't have a
+	 * folio backing them. Fortunately contpte_try_fold() already checked
+	 * that the pte is not special - we never try to fold special mappings.
+	 * Note we can't use vm_normal_page() for this since we don't have the
+	 * vma.
+	 */
+
+	unsigned long folio_start, folio_end;
+	unsigned long cont_start, cont_end;
+	pte_t expected_pte, subpte;
+	struct folio *folio;
+	struct page *page;
+	unsigned long pfn;
+	pte_t *cur_ptep;
+	pgprot_t prot;
+	size_t pgsize;
+	int i, ncontig, ncontig_prev;
+
+	if (!mm_is_user(mm))
+		return;
+
+	page = pte_page(pte);
+	folio = page_folio(page);
+	folio_start = addr - (page - &folio->page) * PAGE_SIZE;
+	folio_end = folio_start + folio_nr_pages(folio) * PAGE_SIZE;
+
+	prot = pte_pgprot(pte_mkold(pte_mkclean(pte)));
+	ncontig_prev = 0;
+	ncontig = arch_contpte_get_first_ncontig(&pgsize);
+
+	do {
+		/* Make sure we still belong to the same folio */
+		cont_start = ALIGN_DOWN(addr, ncontig * pgsize);
+		cont_end = cont_start + ncontig * pgsize;
+
+		if (folio_start > cont_start || folio_end < cont_end)
+			break;
+
+		pfn = ALIGN_DOWN(pte_pfn(pte), ncontig);
+		expected_pte = pfn_pte(pfn, prot);
+		cur_ptep = PTR_ALIGN_DOWN(ptep, sizeof(*ptep) * ncontig);
+
+		/*
+		 * Either the region is already a contpte mapping or make sure
+		 * the ptes belong to a contpte region.
+		 */
+		if (!pte_valid_cont(__ptep_get(cur_ptep))) {
+			for (i = 0; i < ncontig - ncontig_prev; i++) {
+				subpte = pte_mkold(pte_mkclean(__ptep_get(cur_ptep)));
+				if (!pte_same(subpte, expected_pte))
+					goto out;
+				expected_pte = pte_advance_pfn(expected_pte, 1);
+				cur_ptep++;
+			}
+		}
+
+		/*
+		 * Compute the next contpte region to check: avoid checking
+		 * the same region again by only checking the "second-half"
+		 * (the "region buddy") of the current region, which keeps the
+		 * whole thing in O(n).
+		 */
+		ncontig_prev = ncontig;
+		ncontig = arch_contpte_get_next_ncontig(ncontig, &pgsize);
+		/* set_ptes spec states that "The PTEs are all in the same PMD" */
+		if (!ncontig || pgsize > PAGE_SIZE)
+			break;
+	} while (contpte_is_last_pte(addr, pte, ncontig));
+
+out:
+	if (!ncontig_prev)
+		return;
+
+	ptep = PTR_ALIGN_DOWN(ptep, sizeof(*ptep) * ncontig_prev);
+	cont_start = ALIGN_DOWN(addr, ncontig_prev * PAGE_SIZE);
+	pte = pte_mkcont(pte);
+	pte = pfn_pte(ALIGN_DOWN(pte_pfn(pte), ncontig_prev), pte_pgprot(pte));
+
+	contpte_convert(mm, cont_start, ptep, pte, ncontig_prev, PAGE_SIZE);
+}
+EXPORT_SYMBOL_GPL(__contpte_try_fold);
+
+__always_inline void contpte_try_fold(struct mm_struct *mm,
+				      unsigned long addr, pte_t *ptep, pte_t pte)
+{
+	/*
+	 * Only bother trying if both the virtual and physical addresses are
+	 * aligned and correspond to the last entry in a contig range. The core
+	 * code mostly modifies ranges from low to high, so this is the likely
+	 * the last modification in the contig range, so a good time to fold.
+	 * We can't fold special mappings, because there is no associated folio.
+	 *
+	 * Only test if the first ncontig is aligned, because it can't be the
+	 * last pte of a size larger than the first ncontig and not the last
+	 * of the first ncontig.
+	 */
+	int ncontig = arch_contpte_get_first_ncontig(NULL);
+
+	if (contpte_is_last_pte(addr, pte, ncontig))
+		__contpte_try_fold(mm, addr, ptep, pte);
+}
+
+void contpte_set_ptes(struct mm_struct *mm, unsigned long addr,
+		      pte_t *ptep, pte_t pte, unsigned int nr)
+{
+	unsigned long contmask;
+	unsigned long next;
+	unsigned long end;
+	unsigned long pfn;
+	pgprot_t prot;
+	int ncontig;
+
+	/*
+	 * The set_ptes() spec guarantees that when nr > 1, the initial state of
+	 * all ptes is not-present. Therefore we never need to unfold or
+	 * otherwise invalidate a range before we set the new ptes.
+	 * contpte_set_ptes() should never be called for nr < 2.
+	 */
+	VM_WARN_ON(nr == 1);
+
+	if (!mm_is_user(mm))
+		return __set_ptes(mm, addr, ptep, pte, nr);
+
+	end = addr + (nr << PAGE_SHIFT);
+	pfn = pte_pfn(pte);
+	prot = pte_pgprot(pte);
+
+	do {
+		next = arch_contpte_addr_end(addr, end, &ncontig);
+		nr = (next - addr) >> PAGE_SHIFT;
+		pte = pfn_pte(pfn, prot);
+		contmask = (ncontig << PAGE_SHIFT) - 1;
+
+		if (ncontig && ((addr | next | (pfn << PAGE_SHIFT)) & contmask) == 0)
+			pte = pte_mkcont(pte);
+		else
+			pte = pte_mknoncont(pte);
+
+		__set_ptes(mm, addr, ptep, pte, nr);
+
+		addr = next;
+		ptep += nr;
+		pfn += nr;
+	} while (addr != end);
+}
+EXPORT_SYMBOL_GPL(contpte_set_ptes);
+
+__always_inline void set_ptes(struct mm_struct *mm, unsigned long addr,
+			      pte_t *ptep, pte_t pte, unsigned int nr)
+{
+	pte = pte_mknoncont(pte);
+
+	if (likely(nr == 1)) {
+		contpte_try_unfold(mm, addr, ptep, __ptep_get(ptep));
+		__set_ptes(mm, addr, ptep, pte, 1);
+		contpte_try_fold(mm, addr, ptep, pte);
+	} else {
+		contpte_set_ptes(mm, addr, ptep, pte, nr);
+	}
+}
+#endif /* CONFIG_THP_CONTPTE */
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240508191931.46060-4-alexghiti%40rivosinc.com.
