Return-Path: <kasan-dev+bncBDXY7I6V6AMRBI555OUAMGQEFV5NOVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 55E8E7B5624
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Oct 2023 17:15:49 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-51bdae07082sf14783a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Oct 2023 08:15:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696259749; cv=pass;
        d=google.com; s=arc-20160816;
        b=vYMlgqbfrCXZyuZKIXRkJ64TxDLZ9xMKKkvKDfibq0ZRnFwwPOUpnOy+PKxT51L7Wu
         sWdnLAPx/6ls7GoB8mJOu/iiP6sCvcBXVFQK40cl8zDWW2GGDlF5v5yE7Go7MMEB/z4c
         dhC+ajxOvkIdveJHTxyJKi3Z8kCMQ4cnWwx8CWZozxKdEhMwvPQn4j9WYKJnex+2Rbr0
         vNwRtiiuSuYjNLBAkk8PyAxFvFwXyxOwEVikWwHfq0lZr9mgDEl28qH5EzbSx6tAsY37
         aak9JcYj+dFOxmKXmNTM9Jm/Ohtk1ZJZrEyyg+Y5le38D9UmwYM0CIU7fBCRENJtx8b6
         Bt5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XeWZ/qy7u9wM5CKIhvKh5U7sJuNsbtqQ4kXowVtm97U=;
        fh=uXvJMJMnIF8WaKRrdgquas9RQiOXXOyuQb5203rEpB4=;
        b=iwaqdyIZGb57a2ubype/iAq+IhZ244cs3U6e/1iJhVA64OlRdtxFMNfghBJkkGMdpK
         SkHIEFeOU3xwBpsR994b/ceMOP/oRKM+8gLIHHJ8QhQCp7947uJpDGKzQRCWTmjEvJUO
         5FThn5utd221I5ooiDXV/jHcP6CG1qeQIcnMkTjvwakIgzgwyqrVHiM+SK0zdSwTmOX1
         nDhk9Ah7ZKTEWDACe07/+ud6x4mK3UTDoRobh/nTbWclfkB2adkV+XfO+7PTL+afpLbk
         KQEQILMylAzd79oZgCFtjTqpIcWKI1MKK2r/R3H0D2ohVUHtPaTfI12MGVq22TZq/H2a
         pkgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=y0Dcnkeo;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696259749; x=1696864549; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XeWZ/qy7u9wM5CKIhvKh5U7sJuNsbtqQ4kXowVtm97U=;
        b=tdNF2aSk79VmBqSDzgtKD2Z5T/KKG9h1K4CuZsuVAh5FFk7F9drdSdfmBPzdjxk4ug
         jEYCsUcuC+aeiW2O72qEZDRd75W8bYVg8WTNUnGttCTT5GurUUijccqlZThy2Nha1T93
         jyfgGIjnxsMpbmm0QGJmFmPiBvWyiTMDkK4j8ZEiqAfU69+0QRrbkqDXIUXyS1I1YtSb
         aEXclt13+2fMW/2fZ9v4F7L0w/yX4QHJDUw0PrmMIDbC0KzHaEwdYfYCVaW9+uD0dqOA
         eFeIVeSku9ZAOoiL0KxoPQ6zkHDTGN1Cgek8B0M4I6h1ptIRf6SUCPSaub4mn3q2ZqVN
         2o7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696259749; x=1696864549;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XeWZ/qy7u9wM5CKIhvKh5U7sJuNsbtqQ4kXowVtm97U=;
        b=sLFFqvXfZSsnPfRhiVA/yeV//Ug1EMbHeN89UAI7Xoh5HA7MWvOmI2ADLg0qW60YUd
         lOCy8VqeW8pzywunyM9D1DIBvoYKm//Cr5dcLWvy4MIbYtkYrfnTemAulPFIWMYSyLl9
         pvnNNrhVdD7Fnt0A1oXPfWZB9MBVxCe5U8rN+n8oN3BrgcCRc9m+x1z7QMddJvPPHr8/
         HW5IJRTlHXOcc5Vv0yi95K2U62SxkhGNoyNdYcL7gQ/i5DEBiua6TJULDMz5bQoME62Z
         LkPHZleTZjfmNuWipKJEU+4ffa3Bu8KMXK6dhInQ76gbra3VpY29xqzDtJpvalA5r91j
         5tGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yza4pn41l97YM37l8XFcgwiSp8bxBrDxzTMW4XTFujJOXr1THWQ
	G3Lsv2vx0z0urbSQ/t9QU80=
X-Google-Smtp-Source: AGHT+IHqvHy6s4zHsDvxeLJhAvzZcHmJs98eg23xcY0FFA9d1KjARtjcG/0iFpqHCJb3iXDh2YM11g==
X-Received: by 2002:a05:6402:782:b0:538:1d3b:172f with SMTP id d2-20020a056402078200b005381d3b172fmr93892edy.3.1696259747685;
        Mon, 02 Oct 2023 08:15:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:770e:0:b0:504:2467:eb86 with SMTP id s14-20020a19770e000000b005042467eb86ls693211lfc.0.-pod-prod-09-eu;
 Mon, 02 Oct 2023 08:15:45 -0700 (PDT)
X-Received: by 2002:a05:6512:214d:b0:4fd:d470:203b with SMTP id s13-20020a056512214d00b004fdd470203bmr8829155lfr.69.1696259745729;
        Mon, 02 Oct 2023 08:15:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696259745; cv=none;
        d=google.com; s=arc-20160816;
        b=KVtotdcJhIdw4+siNO222EDBFt3mOqTLkiU1sjl+n0xX+V1534gmUSbvtlmOI/3fMb
         4te84GIKAJka1Z3uC1J3Q+8K9oocwj8KVYhphmi/1SX0LMM9m4bXo63hAKS4PlyRXGtL
         bA6yX+qIiycjo6mNjPrrCzvI+MaWoHDMnhq8xwqL03ZA5ubS3qIal0DIa9ADOfhxOVHU
         o+fQDa4jWeNTEgvE5Mua45RUIrPeTZNm7fNfambhp5QvDdoacl+RLyC9F/QANtxxggZH
         Ru9/vUNtwtxIhGWsV3jKEJWlC71VWXge8zthE69qmlOF3vj2tEx44UCNMcBkuoo6UxUG
         VBGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OEEG+xtUAsULDYONgax1Tf3ExxOI3c/UAKYhQT00Brk=;
        fh=uXvJMJMnIF8WaKRrdgquas9RQiOXXOyuQb5203rEpB4=;
        b=v1cz9a0O1X5PnYC3olDXORrW6nbkMYjwOElbD5Tifr3ZvZX38QclWcvi+V9YMsvESq
         ley0l4OWRkAG26SZPgxMzTuKWExZLxm1In6yBdISaSkUrJ3m+JYyyfkCQ6fQLG6aby5e
         td/lLtFAXLrWyXre0TXXQd7QptajXRyafWO9kuRTgTYYrVrQvMuGvUvp1p3qDuINEHWx
         WA3UrbqclqNs916Ew0ekVczZSokyyns7fFj4P6yKPF30bOifKBc3ulNNwNUI6NBRnYTe
         WX+Qo8B6PMI428RphZhCcDOO/CmEJv3bcieCCrpjYSpfBAk/bUrpeXM4go1j7Fbf8/nS
         GHMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=y0Dcnkeo;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id t14-20020a056512208e00b0050338083127si1870022lfr.12.2023.10.02.08.15.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Oct 2023 08:15:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-4064867903cso66336455e9.2
        for <kasan-dev@googlegroups.com>; Mon, 02 Oct 2023 08:15:45 -0700 (PDT)
X-Received: by 2002:a05:600c:470e:b0:406:7029:c4f2 with SMTP id v14-20020a05600c470e00b004067029c4f2mr3333134wmo.26.1696259744708;
        Mon, 02 Oct 2023 08:15:44 -0700 (PDT)
Received: from alex-rivos.home (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id q9-20020a7bce89000000b003fefcbe7fa8sm7451252wmj.28.2023.10.02.08.15.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Oct 2023 08:15:44 -0700 (PDT)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Ryan Roberts <ryan.roberts@arm.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <atishp@atishpatra.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kvm@vger.kernel.org,
	kvm-riscv@lists.infradead.org,
	linux-efi@vger.kernel.org,
	linux-mm@kvack.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH 5/5] riscv: Use accessors to page table entries instead of direct dereference
Date: Mon,  2 Oct 2023 17:10:31 +0200
Message-Id: <20231002151031.110551-6-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20231002151031.110551-1-alexghiti@rivosinc.com>
References: <20231002151031.110551-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=y0Dcnkeo;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

As very well explained in commit 20a004e7b017 ("arm64: mm: Use
READ_ONCE/WRITE_ONCE when accessing page tables"), an architecture whose
page table walker can modify the PTE in parallel must use
READ_ONCE()/WRITE_ONCE() macro to avoid any compiler transformation.

So apply that to riscv which is such architecture.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/include/asm/kfence.h  |  4 +--
 arch/riscv/include/asm/pgtable.h | 29 +++++---------------
 arch/riscv/kernel/efi.c          |  2 +-
 arch/riscv/kvm/mmu.c             | 22 ++++++++--------
 arch/riscv/mm/fault.c            | 16 ++++++------
 arch/riscv/mm/hugetlbpage.c      | 12 ++++-----
 arch/riscv/mm/kasan_init.c       | 45 +++++++++++++++++---------------
 arch/riscv/mm/pageattr.c         | 20 +++++++-------
 arch/riscv/mm/pgtable.c          | 33 +++++++++++++++++++----
 9 files changed, 96 insertions(+), 87 deletions(-)

diff --git a/arch/riscv/include/asm/kfence.h b/arch/riscv/include/asm/kfence.h
index 3b482d0a4633..1ed91e379723 100644
--- a/arch/riscv/include/asm/kfence.h
+++ b/arch/riscv/include/asm/kfence.h
@@ -18,9 +18,9 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
 	pte_t *ptep = virt_to_kpte(addr);
 
 	if (protect)
-		set_pte(ptep, __pte(pte_val(*ptep) & ~_PAGE_PRESENT));
+		set_pte(ptep, __pte(pte_val(ptep_get(ptep)) & ~_PAGE_PRESENT));
 	else
-		set_pte(ptep, __pte(pte_val(*ptep) | _PAGE_PRESENT));
+		set_pte(ptep, __pte(pte_val(ptep_get(ptep)) | _PAGE_PRESENT));
 
 	flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
 
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index b820775f4973..8d2370ca9909 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -543,19 +543,12 @@ static inline void pte_clear(struct mm_struct *mm,
 	__set_pte_at(ptep, __pte(0));
 }
 
-#define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
-static inline int ptep_set_access_flags(struct vm_area_struct *vma,
-					unsigned long address, pte_t *ptep,
-					pte_t entry, int dirty)
-{
-	if (!pte_same(*ptep, entry))
-		__set_pte_at(ptep, entry);
-	/*
-	 * update_mmu_cache will unconditionally execute, handling both
-	 * the case that the PTE changed and the spurious fault case.
-	 */
-	return true;
-}
+#define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS	/* defined in mm/pgtable.c */
+extern int ptep_set_access_flags(struct vm_area_struct *vma, unsigned long address,
+				 pte_t *ptep, pte_t entry, int dirty);
+#define __HAVE_ARCH_PTEP_TEST_AND_CLEAR_YOUNG	/* defined in mm/pgtable.c */
+extern int ptep_test_and_clear_young(struct vm_area_struct *vma, unsigned long address,
+				     pte_t *ptep);
 
 #define __HAVE_ARCH_PTEP_GET_AND_CLEAR
 static inline pte_t ptep_get_and_clear(struct mm_struct *mm,
@@ -568,16 +561,6 @@ static inline pte_t ptep_get_and_clear(struct mm_struct *mm,
 	return pte;
 }
 
-#define __HAVE_ARCH_PTEP_TEST_AND_CLEAR_YOUNG
-static inline int ptep_test_and_clear_young(struct vm_area_struct *vma,
-					    unsigned long address,
-					    pte_t *ptep)
-{
-	if (!pte_young(*ptep))
-		return 0;
-	return test_and_clear_bit(_PAGE_ACCESSED_OFFSET, &pte_val(*ptep));
-}
-
 #define __HAVE_ARCH_PTEP_SET_WRPROTECT
 static inline void ptep_set_wrprotect(struct mm_struct *mm,
 				      unsigned long address, pte_t *ptep)
diff --git a/arch/riscv/kernel/efi.c b/arch/riscv/kernel/efi.c
index aa6209a74c83..b64bf1624a05 100644
--- a/arch/riscv/kernel/efi.c
+++ b/arch/riscv/kernel/efi.c
@@ -60,7 +60,7 @@ int __init efi_create_mapping(struct mm_struct *mm, efi_memory_desc_t *md)
 static int __init set_permissions(pte_t *ptep, unsigned long addr, void *data)
 {
 	efi_memory_desc_t *md = data;
-	pte_t pte = READ_ONCE(*ptep);
+	pte_t pte = ptep_get(ptep);
 	unsigned long val;
 
 	if (md->attribute & EFI_MEMORY_RO) {
diff --git a/arch/riscv/kvm/mmu.c b/arch/riscv/kvm/mmu.c
index 35db276bf0c2..8d249877f9d8 100644
--- a/arch/riscv/kvm/mmu.c
+++ b/arch/riscv/kvm/mmu.c
@@ -103,7 +103,7 @@ static bool gstage_get_leaf_entry(struct kvm *kvm, gpa_t addr,
 	*ptep_level = current_level;
 	ptep = (pte_t *)kvm->arch.pgdp;
 	ptep = &ptep[gstage_pte_index(addr, current_level)];
-	while (ptep && pte_val(*ptep)) {
+	while (ptep && pte_val(ptep_get(ptep))) {
 		if (gstage_pte_leaf(ptep)) {
 			*ptep_level = current_level;
 			*ptepp = ptep;
@@ -113,7 +113,7 @@ static bool gstage_get_leaf_entry(struct kvm *kvm, gpa_t addr,
 		if (current_level) {
 			current_level--;
 			*ptep_level = current_level;
-			ptep = (pte_t *)gstage_pte_page_vaddr(*ptep);
+			ptep = (pte_t *)gstage_pte_page_vaddr(ptep_get(ptep));
 			ptep = &ptep[gstage_pte_index(addr, current_level)];
 		} else {
 			ptep = NULL;
@@ -149,25 +149,25 @@ static int gstage_set_pte(struct kvm *kvm, u32 level,
 		if (gstage_pte_leaf(ptep))
 			return -EEXIST;
 
-		if (!pte_val(*ptep)) {
+		if (!pte_val(ptep_get(ptep))) {
 			if (!pcache)
 				return -ENOMEM;
 			next_ptep = kvm_mmu_memory_cache_alloc(pcache);
 			if (!next_ptep)
 				return -ENOMEM;
-			*ptep = pfn_pte(PFN_DOWN(__pa(next_ptep)),
-					__pgprot(_PAGE_TABLE));
+			set_pte(ptep, pfn_pte(PFN_DOWN(__pa(next_ptep)),
+					      __pgprot(_PAGE_TABLE)));
 		} else {
 			if (gstage_pte_leaf(ptep))
 				return -EEXIST;
-			next_ptep = (pte_t *)gstage_pte_page_vaddr(*ptep);
+			next_ptep = (pte_t *)gstage_pte_page_vaddr(ptep_get(ptep));
 		}
 
 		current_level--;
 		ptep = &next_ptep[gstage_pte_index(addr, current_level)];
 	}
 
-	*ptep = *new_pte;
+	set_pte(ptep, *new_pte);
 	if (gstage_pte_leaf(ptep))
 		gstage_remote_tlb_flush(kvm, current_level, addr);
 
@@ -239,11 +239,11 @@ static void gstage_op_pte(struct kvm *kvm, gpa_t addr,
 
 	BUG_ON(addr & (page_size - 1));
 
-	if (!pte_val(*ptep))
+	if (!pte_val(ptep_get(ptep)))
 		return;
 
 	if (ptep_level && !gstage_pte_leaf(ptep)) {
-		next_ptep = (pte_t *)gstage_pte_page_vaddr(*ptep);
+		next_ptep = (pte_t *)gstage_pte_page_vaddr(ptep_get(ptep));
 		next_ptep_level = ptep_level - 1;
 		ret = gstage_level_to_page_size(next_ptep_level,
 						&next_page_size);
@@ -261,7 +261,7 @@ static void gstage_op_pte(struct kvm *kvm, gpa_t addr,
 		if (op == GSTAGE_OP_CLEAR)
 			set_pte(ptep, __pte(0));
 		else if (op == GSTAGE_OP_WP)
-			set_pte(ptep, __pte(pte_val(*ptep) & ~_PAGE_WRITE));
+			set_pte(ptep, __pte(pte_val(ptep_get(ptep)) & ~_PAGE_WRITE));
 		gstage_remote_tlb_flush(kvm, ptep_level, addr);
 	}
 }
@@ -603,7 +603,7 @@ bool kvm_test_age_gfn(struct kvm *kvm, struct kvm_gfn_range *range)
 				   &ptep, &ptep_level))
 		return false;
 
-	return pte_young(*ptep);
+	return pte_young(ptep_get(ptep));
 }
 
 int kvm_riscv_gstage_map(struct kvm_vcpu *vcpu,
diff --git a/arch/riscv/mm/fault.c b/arch/riscv/mm/fault.c
index 6284ef4b644a..24c826746322 100644
--- a/arch/riscv/mm/fault.c
+++ b/arch/riscv/mm/fault.c
@@ -136,24 +136,24 @@ static inline void vmalloc_fault(struct pt_regs *regs, int code, unsigned long a
 	pgdp = (pgd_t *)pfn_to_virt(pfn) + index;
 	pgdp_k = init_mm.pgd + index;
 
-	if (!pgd_present(*pgdp_k)) {
+	if (!pgd_present(pgdp_get(pgdp_k))) {
 		no_context(regs, addr);
 		return;
 	}
-	set_pgd(pgdp, *pgdp_k);
+	set_pgd(pgdp, pgdp_get(pgdp_k));
 
 	p4dp_k = p4d_offset(pgdp_k, addr);
-	if (!p4d_present(*p4dp_k)) {
+	if (!p4d_present(p4dp_get(p4dp_k))) {
 		no_context(regs, addr);
 		return;
 	}
 
 	pudp_k = pud_offset(p4dp_k, addr);
-	if (!pud_present(*pudp_k)) {
+	if (!pud_present(pudp_get(pudp_k))) {
 		no_context(regs, addr);
 		return;
 	}
-	if (pud_leaf(*pudp_k))
+	if (pud_leaf(pudp_get(pudp_k)))
 		goto flush_tlb;
 
 	/*
@@ -161,11 +161,11 @@ static inline void vmalloc_fault(struct pt_regs *regs, int code, unsigned long a
 	 * to copy individual PTEs
 	 */
 	pmdp_k = pmd_offset(pudp_k, addr);
-	if (!pmd_present(*pmdp_k)) {
+	if (!pmd_present(pmdp_get(pmdp_k))) {
 		no_context(regs, addr);
 		return;
 	}
-	if (pmd_leaf(*pmdp_k))
+	if (pmd_leaf(pmdp_get(pmdp_k)))
 		goto flush_tlb;
 
 	/*
@@ -175,7 +175,7 @@ static inline void vmalloc_fault(struct pt_regs *regs, int code, unsigned long a
 	 * silently loop forever.
 	 */
 	ptep_k = pte_offset_kernel(pmdp_k, addr);
-	if (!pte_present(*ptep_k)) {
+	if (!pte_present(ptep_get(ptep_k))) {
 		no_context(regs, addr);
 		return;
 	}
diff --git a/arch/riscv/mm/hugetlbpage.c b/arch/riscv/mm/hugetlbpage.c
index 7781e83b2f29..a9d8e5bbac27 100644
--- a/arch/riscv/mm/hugetlbpage.c
+++ b/arch/riscv/mm/hugetlbpage.c
@@ -54,7 +54,7 @@ pte_t *huge_pte_alloc(struct mm_struct *mm,
 	}
 
 	if (sz == PMD_SIZE) {
-		if (want_pmd_share(vma, addr) && pud_none(*pudp))
+		if (want_pmd_share(vma, addr) && pud_none(pudp_get(pudp)))
 			ptep = huge_pmd_share(mm, vma, addr, pudp);
 		else
 			ptep = (pte_t *)pmd_alloc(mm, pudp, addr);
@@ -93,11 +93,11 @@ pte_t *huge_pte_offset(struct mm_struct *mm,
 	pmd_t *pmdp;
 
 	pgdp = pgd_offset(mm, addr);
-	if (!pgd_present(*pgdp))
+	if (!pgd_present(pgdp_get(pgdp)))
 		return NULL;
 
 	p4dp = p4d_offset(pgdp, addr);
-	if (!p4d_present(*p4dp))
+	if (!p4d_present(p4dp_get(p4dp)))
 		return NULL;
 
 	pudp = pud_offset(p4dp, addr);
@@ -105,7 +105,7 @@ pte_t *huge_pte_offset(struct mm_struct *mm,
 		/* must be pud huge, non-present or none */
 		return (pte_t *)pudp;
 
-	if (!pud_present(*pudp))
+	if (!pud_present(pudp_get(pudp)))
 		return NULL;
 
 	pmdp = pmd_offset(pudp, addr);
@@ -113,7 +113,7 @@ pte_t *huge_pte_offset(struct mm_struct *mm,
 		/* must be pmd huge, non-present or none */
 		return (pte_t *)pmdp;
 
-	if (!pmd_present(*pmdp))
+	if (!pmd_present(pmdp_get(pmdp)))
 		return NULL;
 
 	for_each_napot_order(order) {
@@ -285,7 +285,7 @@ void huge_pte_clear(struct mm_struct *mm,
 		    pte_t *ptep,
 		    unsigned long sz)
 {
-	pte_t pte = READ_ONCE(*ptep);
+	pte_t pte = ptep_get(ptep);
 	int i, pte_num;
 
 	if (!pte_napot(pte)) {
diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index ce0cb8e51d0a..aaadb7385e9f 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -31,7 +31,7 @@ static void __init kasan_populate_pte(pmd_t *pmdp, unsigned long vaddr, unsigned
 	phys_addr_t phys_addr;
 	pte_t *ptep, *p;
 
-	if (pmd_none(*pmdp)) {
+	if (pmd_none(pmdp_get(pmdp))) {
 		p = memblock_alloc(PTRS_PER_PTE * sizeof(pte_t), PAGE_SIZE);
 		set_pmd(pmdp, pfn_pmd(PFN_DOWN(__pa(p)), PAGE_TABLE));
 	}
@@ -39,7 +39,7 @@ static void __init kasan_populate_pte(pmd_t *pmdp, unsigned long vaddr, unsigned
 	ptep = pte_offset_kernel(pmdp, vaddr);
 
 	do {
-		if (pte_none(*ptep)) {
+		if (pte_none(ptep_get(ptep))) {
 			phys_addr = memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
 			set_pte(ptep, pfn_pte(PFN_DOWN(phys_addr), PAGE_KERNEL));
 			memset(__va(phys_addr), KASAN_SHADOW_INIT, PAGE_SIZE);
@@ -53,7 +53,7 @@ static void __init kasan_populate_pmd(pud_t *pudp, unsigned long vaddr, unsigned
 	pmd_t *pmdp, *p;
 	unsigned long next;
 
-	if (pud_none(*pudp)) {
+	if (pud_none(pudp_get(pudp))) {
 		p = memblock_alloc(PTRS_PER_PMD * sizeof(pmd_t), PAGE_SIZE);
 		set_pud(pudp, pfn_pud(PFN_DOWN(__pa(p)), PAGE_TABLE));
 	}
@@ -63,7 +63,8 @@ static void __init kasan_populate_pmd(pud_t *pudp, unsigned long vaddr, unsigned
 	do {
 		next = pmd_addr_end(vaddr, end);
 
-		if (pmd_none(*pmdp) && IS_ALIGNED(vaddr, PMD_SIZE) && (next - vaddr) >= PMD_SIZE) {
+		if (pmd_none(pmdp_get(pmdp)) && IS_ALIGNED(vaddr, PMD_SIZE) &&
+		    (next - vaddr) >= PMD_SIZE) {
 			phys_addr = memblock_phys_alloc(PMD_SIZE, PMD_SIZE);
 			if (phys_addr) {
 				set_pmd(pmdp, pfn_pmd(PFN_DOWN(phys_addr), PAGE_KERNEL));
@@ -83,7 +84,7 @@ static void __init kasan_populate_pud(p4d_t *p4dp,
 	pud_t *pudp, *p;
 	unsigned long next;
 
-	if (p4d_none(*p4dp)) {
+	if (p4d_none(p4dp_get(p4dp))) {
 		p = memblock_alloc(PTRS_PER_PUD * sizeof(pud_t), PAGE_SIZE);
 		set_p4d(p4dp, pfn_p4d(PFN_DOWN(__pa(p)), PAGE_TABLE));
 	}
@@ -93,7 +94,8 @@ static void __init kasan_populate_pud(p4d_t *p4dp,
 	do {
 		next = pud_addr_end(vaddr, end);
 
-		if (pud_none(*pudp) && IS_ALIGNED(vaddr, PUD_SIZE) && (next - vaddr) >= PUD_SIZE) {
+		if (pud_none(pudp_get(pudp)) && IS_ALIGNED(vaddr, PUD_SIZE) &&
+		    (next - vaddr) >= PUD_SIZE) {
 			phys_addr = memblock_phys_alloc(PUD_SIZE, PUD_SIZE);
 			if (phys_addr) {
 				set_pud(pudp, pfn_pud(PFN_DOWN(phys_addr), PAGE_KERNEL));
@@ -113,7 +115,7 @@ static void __init kasan_populate_p4d(pgd_t *pgdp,
 	p4d_t *p4dp, *p;
 	unsigned long next;
 
-	if (pgd_none(*pgdp)) {
+	if (pgd_none(pgdp_get(pgdp))) {
 		p = memblock_alloc(PTRS_PER_P4D * sizeof(p4d_t), PAGE_SIZE);
 		set_pgd(pgdp, pfn_pgd(PFN_DOWN(__pa(p)), PAGE_TABLE));
 	}
@@ -123,7 +125,8 @@ static void __init kasan_populate_p4d(pgd_t *pgdp,
 	do {
 		next = p4d_addr_end(vaddr, end);
 
-		if (p4d_none(*p4dp) && IS_ALIGNED(vaddr, P4D_SIZE) && (next - vaddr) >= P4D_SIZE) {
+		if (p4d_none(p4dp_get(p4dp)) && IS_ALIGNED(vaddr, P4D_SIZE) &&
+		    (next - vaddr) >= P4D_SIZE) {
 			phys_addr = memblock_phys_alloc(P4D_SIZE, P4D_SIZE);
 			if (phys_addr) {
 				set_p4d(p4dp, pfn_p4d(PFN_DOWN(phys_addr), PAGE_KERNEL));
@@ -145,7 +148,7 @@ static void __init kasan_populate_pgd(pgd_t *pgdp,
 	do {
 		next = pgd_addr_end(vaddr, end);
 
-		if (pgd_none(*pgdp) && IS_ALIGNED(vaddr, PGDIR_SIZE) &&
+		if (pgd_none(pgdp_get(pgdp)) && IS_ALIGNED(vaddr, PGDIR_SIZE) &&
 		    (next - vaddr) >= PGDIR_SIZE) {
 			phys_addr = memblock_phys_alloc(PGDIR_SIZE, PGDIR_SIZE);
 			if (phys_addr) {
@@ -168,7 +171,7 @@ static void __init kasan_early_clear_pud(p4d_t *p4dp,
 	if (!pgtable_l4_enabled) {
 		pudp = (pud_t *)p4dp;
 	} else {
-		base_pudp = pt_ops.get_pud_virt(pfn_to_phys(_p4d_pfn(*p4dp)));
+		base_pudp = pt_ops.get_pud_virt(pfn_to_phys(_p4d_pfn(p4dp_get(p4dp))));
 		pudp = base_pudp + pud_index(vaddr);
 	}
 
@@ -193,7 +196,7 @@ static void __init kasan_early_clear_p4d(pgd_t *pgdp,
 	if (!pgtable_l5_enabled) {
 		p4dp = (p4d_t *)pgdp;
 	} else {
-		base_p4dp = pt_ops.get_p4d_virt(pfn_to_phys(_pgd_pfn(*pgdp)));
+		base_p4dp = pt_ops.get_p4d_virt(pfn_to_phys(_pgd_pfn(pgdp_get(pgdp))));
 		p4dp = base_p4dp + p4d_index(vaddr);
 	}
 
@@ -239,14 +242,14 @@ static void __init kasan_early_populate_pud(p4d_t *p4dp,
 	if (!pgtable_l4_enabled) {
 		pudp = (pud_t *)p4dp;
 	} else {
-		base_pudp = pt_ops.get_pud_virt(pfn_to_phys(_p4d_pfn(*p4dp)));
+		base_pudp = pt_ops.get_pud_virt(pfn_to_phys(_p4d_pfn(p4dp_get(p4dp))));
 		pudp = base_pudp + pud_index(vaddr);
 	}
 
 	do {
 		next = pud_addr_end(vaddr, end);
 
-		if (pud_none(*pudp) && IS_ALIGNED(vaddr, PUD_SIZE) &&
+		if (pud_none(pudp_get(pudp)) && IS_ALIGNED(vaddr, PUD_SIZE) &&
 		    (next - vaddr) >= PUD_SIZE) {
 			phys_addr = __pa((uintptr_t)kasan_early_shadow_pmd);
 			set_pud(pudp, pfn_pud(PFN_DOWN(phys_addr), PAGE_TABLE));
@@ -277,14 +280,14 @@ static void __init kasan_early_populate_p4d(pgd_t *pgdp,
 	if (!pgtable_l5_enabled) {
 		p4dp = (p4d_t *)pgdp;
 	} else {
-		base_p4dp = pt_ops.get_p4d_virt(pfn_to_phys(_pgd_pfn(*pgdp)));
+		base_p4dp = pt_ops.get_p4d_virt(pfn_to_phys(_pgd_pfn(pgdp_get(pgdp))));
 		p4dp = base_p4dp + p4d_index(vaddr);
 	}
 
 	do {
 		next = p4d_addr_end(vaddr, end);
 
-		if (p4d_none(*p4dp) && IS_ALIGNED(vaddr, P4D_SIZE) &&
+		if (p4d_none(p4dp_get(p4dp)) && IS_ALIGNED(vaddr, P4D_SIZE) &&
 		    (next - vaddr) >= P4D_SIZE) {
 			phys_addr = __pa((uintptr_t)kasan_early_shadow_pud);
 			set_p4d(p4dp, pfn_p4d(PFN_DOWN(phys_addr), PAGE_TABLE));
@@ -305,7 +308,7 @@ static void __init kasan_early_populate_pgd(pgd_t *pgdp,
 	do {
 		next = pgd_addr_end(vaddr, end);
 
-		if (pgd_none(*pgdp) && IS_ALIGNED(vaddr, PGDIR_SIZE) &&
+		if (pgd_none(pgdp_get(pgdp)) && IS_ALIGNED(vaddr, PGDIR_SIZE) &&
 		    (next - vaddr) >= PGDIR_SIZE) {
 			phys_addr = __pa((uintptr_t)kasan_early_shadow_p4d);
 			set_pgd(pgdp, pfn_pgd(PFN_DOWN(phys_addr), PAGE_TABLE));
@@ -381,7 +384,7 @@ static void __init kasan_shallow_populate_pud(p4d_t *p4dp,
 	do {
 		next = pud_addr_end(vaddr, end);
 
-		if (pud_none(*pudp_k)) {
+		if (pud_none(pudp_get(pudp_k))) {
 			p = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
 			set_pud(pudp_k, pfn_pud(PFN_DOWN(__pa(p)), PAGE_TABLE));
 			continue;
@@ -401,7 +404,7 @@ static void __init kasan_shallow_populate_p4d(pgd_t *pgdp,
 	do {
 		next = p4d_addr_end(vaddr, end);
 
-		if (p4d_none(*p4dp_k)) {
+		if (p4d_none(p4dp_get(p4dp_k))) {
 			p = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
 			set_p4d(p4dp_k, pfn_p4d(PFN_DOWN(__pa(p)), PAGE_TABLE));
 			continue;
@@ -420,7 +423,7 @@ static void __init kasan_shallow_populate_pgd(unsigned long vaddr, unsigned long
 	do {
 		next = pgd_addr_end(vaddr, end);
 
-		if (pgd_none(*pgdp_k)) {
+		if (pgd_none(pgdp_get(pgdp_k))) {
 			p = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
 			set_pgd(pgdp_k, pfn_pgd(PFN_DOWN(__pa(p)), PAGE_TABLE));
 			continue;
@@ -451,7 +454,7 @@ static void __init create_tmp_mapping(void)
 
 	/* Copy the last p4d since it is shared with the kernel mapping. */
 	if (pgtable_l5_enabled) {
-		ptr = (p4d_t *)pgd_page_vaddr(*pgd_offset_k(KASAN_SHADOW_END));
+		ptr = (p4d_t *)pgd_page_vaddr(pgdp_get(pgd_offset_k(KASAN_SHADOW_END)));
 		memcpy(tmp_p4d, ptr, sizeof(p4d_t) * PTRS_PER_P4D);
 		set_pgd(&tmp_pg_dir[pgd_index(KASAN_SHADOW_END)],
 			pfn_pgd(PFN_DOWN(__pa(tmp_p4d)), PAGE_TABLE));
@@ -462,7 +465,7 @@ static void __init create_tmp_mapping(void)
 
 	/* Copy the last pud since it is shared with the kernel mapping. */
 	if (pgtable_l4_enabled) {
-		ptr = (pud_t *)p4d_page_vaddr(*(base_p4d + p4d_index(KASAN_SHADOW_END)));
+		ptr = (pud_t *)p4d_page_vaddr(p4dp_get(base_p4dp + p4d_index(KASAN_SHADOW_END)));
 		memcpy(tmp_pud, ptr, sizeof(pud_t) * PTRS_PER_PUD);
 		set_p4d(&base_p4dp[p4d_index(KASAN_SHADOW_END)],
 			pfn_p4d(PFN_DOWN(__pa(tmp_pud)), PAGE_TABLE));
diff --git a/arch/riscv/mm/pageattr.c b/arch/riscv/mm/pageattr.c
index ffca6f19dd9c..2198a8810811 100644
--- a/arch/riscv/mm/pageattr.c
+++ b/arch/riscv/mm/pageattr.c
@@ -28,7 +28,7 @@ static unsigned long set_pageattr_masks(unsigned long val, struct mm_walk *walk)
 static int pageattr_pgd_entry(pgd_t *pgdp, unsigned long addr,
 			      unsigned long next, struct mm_walk *walk)
 {
-	pgd_t val = READ_ONCE(*pgdp);
+	pgd_t val = pgdp_get(pgdp);
 
 	if (pgd_leaf(val)) {
 		val = __pgd(set_pageattr_masks(pgd_val(val), walk));
@@ -41,7 +41,7 @@ static int pageattr_pgd_entry(pgd_t *pgdp, unsigned long addr,
 static int pageattr_p4d_entry(p4d_t *p4dp, unsigned long addr,
 			      unsigned long next, struct mm_walk *walk)
 {
-	p4d_t val = READ_ONCE(*p4dp);
+	p4d_t val = p4dp_get(p4dp);
 
 	if (p4d_leaf(val)) {
 		val = __p4d(set_pageattr_masks(p4d_val(val), walk));
@@ -54,7 +54,7 @@ static int pageattr_p4d_entry(p4d_t *p4dp, unsigned long addr,
 static int pageattr_pud_entry(pud_t *pudp, unsigned long addr,
 			      unsigned long next, struct mm_walk *walk)
 {
-	pud_t val = READ_ONCE(*pudp);
+	pud_t val = pudp_get(pudp);
 
 	if (pud_leaf(val)) {
 		val = __pud(set_pageattr_masks(pud_val(val), walk));
@@ -67,7 +67,7 @@ static int pageattr_pud_entry(pud_t *pudp, unsigned long addr,
 static int pageattr_pmd_entry(pmd_t *pmdp, unsigned long addr,
 			      unsigned long next, struct mm_walk *walk)
 {
-	pmd_t val = READ_ONCE(*pmdp);
+	pmd_t val = pmdp_get(pmdp);
 
 	if (pmd_leaf(val)) {
 		val = __pmd(set_pageattr_masks(pmd_val(val), walk));
@@ -80,7 +80,7 @@ static int pageattr_pmd_entry(pmd_t *pmdp, unsigned long addr,
 static int pageattr_pte_entry(pte_t *ptep, unsigned long addr,
 			      unsigned long next, struct mm_walk *walk)
 {
-	pte_t val = READ_ONCE(*ptep);
+	pte_t val = ptep_get(ptep);
 
 	val = __pte(set_pageattr_masks(pte_val(val), walk));
 	set_pte(ptep, val);
@@ -216,33 +216,33 @@ bool kernel_page_present(struct page *page)
 	pte_t *ptep;
 
 	pgdp = pgd_offset_k(addr);
-	pgd = *pgdp;
+	pgd = pgdp_get(pgdp);
 	if (!pgd_present(pgd))
 		return false;
 	if (pgd_leaf(pgd))
 		return true;
 
 	p4dp = p4d_offset(pgdp, addr);
-	p4d = *p4dp;
+	p4d = p4dp_get(p4dp);
 	if (!p4d_present(p4d))
 		return false;
 	if (p4d_leaf(p4d))
 		return true;
 
 	pudp = pud_offset(p4dp, addr);
-	pud = *pudp;
+	pud = pudp_get(pudp);
 	if (!pud_present(pud))
 		return false;
 	if (pud_leaf(pud))
 		return true;
 
 	pmdp = pmd_offset(pudp, addr);
-	pmd = *pmdp;
+	pmd = pmdp_get(pmdp);
 	if (!pmd_present(pmd))
 		return false;
 	if (pmd_leaf(pmd))
 		return true;
 
 	ptep = pte_offset_kernel(pmdp, addr);
-	return pte_present(*ptep);
+	return pte_present(ptep_get(ptep));
 }
diff --git a/arch/riscv/mm/pgtable.c b/arch/riscv/mm/pgtable.c
index 9c93f24d0829..777fcb116bb4 100644
--- a/arch/riscv/mm/pgtable.c
+++ b/arch/riscv/mm/pgtable.c
@@ -5,6 +5,29 @@
 #include <linux/kernel.h>
 #include <linux/pgtable.h>
 
+int ptep_set_access_flags(struct vm_area_struct *vma,
+			  unsigned long address, pte_t *ptep,
+			  pte_t entry, int dirty)
+{
+	if (!pte_same(ptep_get(ptep), entry))
+		__set_pte_at(ptep, entry);
+	/*
+	 * update_mmu_cache will unconditionally execute, handling both
+	 * the case that the PTE changed and the spurious fault case.
+	 */
+	return true;
+}
+
+int ptep_test_and_clear_young(struct vm_area_struct *vma,
+			      unsigned long address,
+			      pte_t *ptep)
+{
+	if (!pte_young(ptep_get(ptep)))
+		return 0;
+	return test_and_clear_bit(_PAGE_ACCESSED_OFFSET, &pte_val(*ptep));
+}
+EXPORT_SYMBOL_GPL(ptep_test_and_clear_young);
+
 #ifdef CONFIG_HAVE_ARCH_HUGE_VMAP
 int p4d_set_huge(p4d_t *p4dp, phys_addr_t addr, pgprot_t prot)
 {
@@ -25,7 +48,7 @@ int pud_set_huge(pud_t *pudp, phys_addr_t phys, pgprot_t prot)
 
 int pud_clear_huge(pud_t *pudp)
 {
-	if (!pud_leaf(READ_ONCE(*pudp)))
+	if (!pud_leaf(pudp_get(pudp)))
 		return 0;
 	pud_clear(pudp);
 	return 1;
@@ -33,7 +56,7 @@ int pud_clear_huge(pud_t *pudp)
 
 int pud_free_pmd_page(pud_t *pudp, unsigned long addr)
 {
-	pmd_t *pmdp = pud_pgtable(*pudp);
+	pmd_t *pmdp = pud_pgtable(pudp_get(pudp));
 	int i;
 
 	pud_clear(pudp);
@@ -63,7 +86,7 @@ int pmd_set_huge(pmd_t *pmdp, phys_addr_t phys, pgprot_t prot)
 
 int pmd_clear_huge(pmd_t *pmdp)
 {
-	if (!pmd_leaf(READ_ONCE(*pmdp)))
+	if (!pmd_leaf(pmdp_get(pmdp)))
 		return 0;
 	pmd_clear(pmdp);
 	return 1;
@@ -71,7 +94,7 @@ int pmd_clear_huge(pmd_t *pmdp)
 
 int pmd_free_pte_page(pmd_t *pmdp, unsigned long addr)
 {
-	pte_t *ptep = (pte_t *)pmd_page_vaddr(*pmdp);
+	pte_t *ptep = (pte_t *)pmd_page_vaddr(pmdp_get(pmdp));
 
 	pmd_clear(pmdp);
 
@@ -88,7 +111,7 @@ pmd_t pmdp_collapse_flush(struct vm_area_struct *vma,
 	pmd_t pmd = pmdp_huge_get_and_clear(vma->vm_mm, address, pmdp);
 
 	VM_BUG_ON(address & ~HPAGE_PMD_MASK);
-	VM_BUG_ON(pmd_trans_huge(*pmdp));
+	VM_BUG_ON(pmd_trans_huge(pmdp_get(pmdp)));
 	/*
 	 * When leaf PTE entries (regular pages) are collapsed into a leaf
 	 * PMD entry (huge page), a valid non-leaf PTE is converted into a
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231002151031.110551-6-alexghiti%40rivosinc.com.
