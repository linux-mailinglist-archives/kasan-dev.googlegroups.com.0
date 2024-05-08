Return-Path: <kasan-dev+bncBDXY7I6V6AMRB4FE56YQMGQEBFJZYFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 07F278C0501
	for <lists+kasan-dev@lfdr.de>; Wed,  8 May 2024 21:28:50 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-51f8cf57f17sf29192e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 08 May 2024 12:28:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715196529; cv=pass;
        d=google.com; s=arc-20160816;
        b=jEKHStFJh/Ydphyc/t365FNfGLodxsj0hZeq5ghTOJ5Ie+o91rBhqC8Xui3FZTQT79
         vtCeksTus0+a98NiZ/FGHdlsmqGwx+8HWk1sRQ1nioLIajWwLnPFtBMm6n9/vBZWdqNu
         legIQUyqqm1gIgeDecUbhMlYSNMaSip89cTZia9aGd/wiCQSuaRKMTmJJWKrUjwyxZeK
         4oCsTVnJ/QZIDIlElsVQseqghkrfoEIojztcMZXwjZG0p6GEtQ7rk8TQXRX3dzw5LNz+
         z8jkLb8B6muqEK+Pghj4eM5fgB9LmwlvcrDTRjgVPECT3j+lKTAmt1gENBe9uVNg2gmB
         ynYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XMWjpts1t8zCWfO3qJYZgYgAKaH1bS/JH028TXZC1Qc=;
        fh=5qtutJ/8XqWf+laUawvs2YXyOyFSpd4sk6/+vz9u7AU=;
        b=DXysPN9919HxBjEA59rAI7EGvPTotLE9crPSzKR8kzkg1RMlyzBWB5IXLJchAHhE6z
         4kpdPOhKiz+GuqmhfZW1Yxke//YFGV8KUhCVJ5TmTPLla1mqYSQjLzvL1sZX+Ca2Cr/4
         nXz+ywjUY6u9ESfg7YZLO81S4GR0FPCgHIJ3oGQOPQlilTS2xwLj+OEKdMHWLsU5js0a
         vfOfBi3Z4JOW/2PUMgvzQ9VyOgzoS+qm5QsejqK0wiWu+RkRMjnOteB+sTNaodlKkEVL
         j2SYTAD/hPRAu6hR+Ho4pAz5ZT8q/C+apNkC7VmomElTM55A2exPFNS4k0Aj7CUF2T0y
         PP2Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=mB7v+wL+;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715196529; x=1715801329; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XMWjpts1t8zCWfO3qJYZgYgAKaH1bS/JH028TXZC1Qc=;
        b=V+V4TL4ux9/+dzXFiI9saPNx8dG07Yla2yM6Su9XWBqrY1oaaoizAwbP/Wg4IyUZ6c
         5/7HRlUCP4jnjwTNCF6guhHDV/G1+jKk6ijjWbN5QHPTLYGMy9ggPQi7mAus+bezqhGK
         Q1S1nci5HKXY3AWfKMVZ0YOjWYH3nc+/4NsofLb7+6bsLfc7hXR394p2PUo5kNhg8UPL
         qQf42/H3XYbmPIbN0Tpbig+95e6eQgrzOGEB4SYjrlcdNRan9DvgfziXjScpDVvEGn2B
         xhQlCdGVVB9a9QewYqakH9lNJ+7dHHvSdFhFidT3IOJGtzk5BPaoN7ZvLvCFDR/IyWqA
         v89Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715196529; x=1715801329;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XMWjpts1t8zCWfO3qJYZgYgAKaH1bS/JH028TXZC1Qc=;
        b=GAEaK0w7pGaREogUtvT1vSaGufTsoCdhz0sxPITojr9rr7TwNMUP+tHWAbAcIeNeq2
         x8kbDk8WqHFv1CHITW20HtT3wu3Mw1PyvH/CW4xfnMDLVooSbmmDbACpe7GS4sGDdjUS
         cXwsnLJPdeNhV2yPJWrOQyd0eYoqbRvNUh7iV5W0vE6l/gpn6aoYeFVdoHKdQ4aOJiIx
         nJv8HQvtx0l8GO3kCK4ZwBmT28F6zpmWaBo075Wj8YAgvZPM7ixLLlZNYCQlhTsGb786
         pP40ZaRm+ZKMQR2kBnlXwIomQGCV42jmvrzB6oHHOmr1WQpVw3GLpUW5paqpaHxR5eJ1
         rrtg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWnaL9cwH8wPYDYVw+bFWcH0bOtZSzVseeYMyyeeWs1wjeDyuV29WlKUcjNTITip0XvwS+nlCH5KQ/ipdblZgtEr+6FFzf45w==
X-Gm-Message-State: AOJu0YycuBRBfhu/E5L7JGpy2vSIgbqyRJ8O5BkG0yVm2ZKENI4Rb3g3
	YiLFa03qI8pJ3UQDJjsxoRkPjc9tkW9GtJTLcaB8yMhExFpii+pN
X-Google-Smtp-Source: AGHT+IH3sG4dku8yQPcMftaboZJny1NtK7e5mguwvol2OSKFftKzFAl+uxm5XYfh+1inqPSzh/M9Pg==
X-Received: by 2002:ac2:5981:0:b0:51e:76a4:4e6d with SMTP id 2adb3069b0e04-5217cc4f6e2mr2132828e87.51.1715196529099;
        Wed, 08 May 2024 12:28:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3085:b0:51f:b750:da37 with SMTP id
 2adb3069b0e04-521e462e4c3ls76340e87.2.-pod-prod-02-eu; Wed, 08 May 2024
 12:28:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUm1AVPXWJF/qKfalfRS9PSYnbkRrUitve5aMuCPx8DHKMBCgYIKF9c8qOiBB6nONqVKBJomKD1TLIixKz5exNPXYkUIa35R3yiLw==
X-Received: by 2002:a05:6512:29a:b0:51f:5872:dd8c with SMTP id 2adb3069b0e04-5217c667325mr2283528e87.39.1715196527047;
        Wed, 08 May 2024 12:28:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715196527; cv=none;
        d=google.com; s=arc-20160816;
        b=rZoghEfog9iHf+T5lwAHAh5aC32lgigxOaAkgRhRVYVaY1SszqRwvKvEGQvywCcGO/
         R+tL2wiRW9lsES3so667Tme/agED290VrDGmzvMneh/TsXvOOxbUPNYYhnqRHT6bU+d1
         aVLkn1lzmd4BT3cl/vDzZfQe6ypoIYy7EJl32WZRQYLE7Usqe26ZuYZolu+HtX6lPdq7
         /3ysxD/67ACfe+7DsqYRkCm6LjW4hHsfI4UIrjDnZ3HqxKcRlKB/2YG7+RyNtraNEDl6
         ghvObq8Tg0q40qfVOGfZXCTONgTO9tC3KjVgotvXeErz3WpPHC0eTZucHHWkqqaXNIrK
         jI9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=SrlnOIvJhP/2Gfg4T9gM6ETbApI/dif7rW/ZR+x6Q9w=;
        fh=RivYVtRC9FfnhWja4blIrvWAfUYZZirD319whj8rWgo=;
        b=riGb4KOpfcKQt3aD/oNQ4h8U49UAd55mAnd/zwDJ29RRmM+a8fwR/7ucXvsFZnYzW9
         tOZDXOfBaBv0gBIZbQ56y9QMo+7u/yplsS+kpkhn1GEL30iGMVw/7DxBkhr0+viUGz/k
         DJBOJ9MIJdY9UOcsFcFbYDz7Z4k9pvvX+8FkVm24hX5++gbUPMDSM36LIqaG2JllaHXV
         jlkw9QwxD9NKapvIxsOJMh1LdwEcsbeamXsRSAAWwT4O9Z72n0dk4vWyxOC1fugxzV6M
         nlOQaOno2I1hi9EwQ74oW2C4l3eIZWsrTZHRBlhA9zPALLbXOip75E1KQyGhUxE/exly
         GFRA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=mB7v+wL+;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id k11-20020ac24f0b000000b0051b29095060si455595lfr.12.2024.05.08.12.28.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 May 2024 12:28:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-34f7d8bfaa0so43606f8f.0
        for <kasan-dev@googlegroups.com>; Wed, 08 May 2024 12:28:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUg8/WgrOOtGlDGsecbaqbZvn7RLohM00WzYBJjNL/f1BcYwIKeXQnQ1g90VAuIDS3v+OFZIpziFEXCkvtQqM/aEvE02xQQsKhQmQ==
X-Received: by 2002:a5d:6350:0:b0:34c:65ba:5d43 with SMTP id ffacd0b85a97d-34fca621699mr2523239f8f.46.1715196526270;
        Wed, 08 May 2024 12:28:46 -0700 (PDT)
Received: from alex-rivos.ba.rivosinc.com (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id cx8-20020a056000092800b0034e01a80176sm16002694wrb.114.2024.05.08.12.28.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 May 2024 12:28:45 -0700 (PDT)
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
Subject: [PATCH 09/12] mm, riscv, arm64: Use common ptep_clear_flush_young() function
Date: Wed,  8 May 2024 21:19:28 +0200
Message-Id: <20240508191931.46060-10-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20240508191931.46060-1-alexghiti@rivosinc.com>
References: <20240508191931.46060-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=mB7v+wL+;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

Make riscv use the contpte aware ptep_clear_flush_young() function from
arm64.

Note that riscv used to not flush the tlb after clearing the accessed
bit, which it does now: this will be improved when we implement svinval
support.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/arm64/include/asm/pgtable.h | 22 ++++++++----------
 arch/arm64/mm/contpte.c          | 21 -----------------
 arch/riscv/include/asm/pgtable.h | 12 +++++++---
 include/linux/contpte.h          |  2 ++
 mm/contpte.c                     | 40 ++++++++++++++++++++++++++++++++
 5 files changed, 61 insertions(+), 36 deletions(-)

diff --git a/arch/arm64/include/asm/pgtable.h b/arch/arm64/include/asm/pgtable.h
index 9a8702d1ad00..92c12fb85cb4 100644
--- a/arch/arm64/include/asm/pgtable.h
+++ b/arch/arm64/include/asm/pgtable.h
@@ -1389,8 +1389,6 @@ extern void contpte_clear_full_ptes(struct mm_struct *mm, unsigned long addr,
 extern pte_t contpte_get_and_clear_full_ptes(struct mm_struct *mm,
 				unsigned long addr, pte_t *ptep,
 				unsigned int nr, int full);
-extern int contpte_ptep_clear_flush_young(struct vm_area_struct *vma,
-				unsigned long addr, pte_t *ptep);
 extern void contpte_wrprotect_ptes(struct mm_struct *mm, unsigned long addr,
 				pte_t *ptep, unsigned int nr);
 extern int contpte_ptep_set_access_flags(struct vm_area_struct *vma,
@@ -1479,16 +1477,8 @@ extern int ptep_test_and_clear_young(struct vm_area_struct *vma,
 				unsigned long addr, pte_t *ptep);
 
 #define __HAVE_ARCH_PTEP_CLEAR_YOUNG_FLUSH
-static inline int ptep_clear_flush_young(struct vm_area_struct *vma,
-				unsigned long addr, pte_t *ptep)
-{
-	pte_t orig_pte = __ptep_get(ptep);
-
-	if (likely(!pte_valid_cont(orig_pte)))
-		return __ptep_clear_flush_young(vma, addr, ptep);
-
-	return contpte_ptep_clear_flush_young(vma, addr, ptep);
-}
+extern int ptep_clear_flush_young(struct vm_area_struct *vma,
+				  unsigned long addr, pte_t *ptep);
 
 #define wrprotect_ptes wrprotect_ptes
 static __always_inline void wrprotect_ptes(struct mm_struct *mm,
@@ -1616,6 +1606,14 @@ static inline void arch_contpte_flush_tlb_range(struct vm_area_struct *vma,
 	__flush_tlb_range(vma, start, end, stride, true, 3);
 }
 
+static inline void arch_contpte_flush_tlb_range_nosync(struct vm_area_struct *vma,
+						       unsigned long start,
+						       unsigned long end,
+						       unsigned long stride)
+{
+	__flush_tlb_range_nosync(vma, start, end, stride, true, 3);
+}
+
 static inline int arch_contpte_get_first_ncontig(size_t *pgsize)
 {
 	if (pgsize)
diff --git a/arch/arm64/mm/contpte.c b/arch/arm64/mm/contpte.c
index 9bf471633ca4..16940511943c 100644
--- a/arch/arm64/mm/contpte.c
+++ b/arch/arm64/mm/contpte.c
@@ -45,27 +45,6 @@ pte_t contpte_get_and_clear_full_ptes(struct mm_struct *mm,
 }
 EXPORT_SYMBOL_GPL(contpte_get_and_clear_full_ptes);
 
-int contpte_ptep_clear_flush_young(struct vm_area_struct *vma,
-					unsigned long addr, pte_t *ptep)
-{
-	int young;
-
-	young = contpte_ptep_test_and_clear_young(vma, addr, ptep);
-
-	if (young) {
-		/*
-		 * See comment in __ptep_clear_flush_young(); same rationale for
-		 * eliding the trailing DSB applies here.
-		 */
-		addr = ALIGN_DOWN(addr, CONT_PTE_SIZE);
-		__flush_tlb_range_nosync(vma, addr, addr + CONT_PTE_SIZE,
-					 PAGE_SIZE, true, 3);
-	}
-
-	return young;
-}
-EXPORT_SYMBOL_GPL(contpte_ptep_clear_flush_young);
-
 void contpte_wrprotect_ptes(struct mm_struct *mm, unsigned long addr,
 					pte_t *ptep, unsigned int nr)
 {
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index d39cb24c6c4a..42c7884b8d2e 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -615,6 +615,8 @@ static inline void arch_contpte_flush_tlb_range(struct vm_area_struct *vma,
 	flush_tlb_mm_range(vma->vm_mm, start, end, stride);
 }
 
+#define arch_contpte_flush_tlb_range_nosync	arch_contpte_flush_tlb_range
+
 static inline int arch_contpte_get_first_ncontig(size_t *pgsize)
 {
 	if (pgsize)
@@ -758,9 +760,8 @@ static inline void __ptep_set_wrprotect(struct mm_struct *mm,
 	atomic_long_and(~(unsigned long)_PAGE_WRITE, (atomic_long_t *)ptep);
 }
 
-#define __HAVE_ARCH_PTEP_CLEAR_YOUNG_FLUSH
-static inline int ptep_clear_flush_young(struct vm_area_struct *vma,
-					 unsigned long address, pte_t *ptep)
+static inline int __ptep_clear_flush_young(struct vm_area_struct *vma,
+					   unsigned long address, pte_t *ptep)
 {
 	/*
 	 * This comment is borrowed from x86, but applies equally to RISC-V:
@@ -799,6 +800,9 @@ extern pte_t ptep_get_and_clear(struct mm_struct *mm,
 #define __HAVE_ARCH_PTEP_TEST_AND_CLEAR_YOUNG
 extern int ptep_test_and_clear_young(struct vm_area_struct *vma,
 				     unsigned long addr, pte_t *ptep);
+#define __HAVE_ARCH_PTEP_CLEAR_YOUNG_FLUSH
+extern int ptep_clear_flush_young(struct vm_area_struct *vma,
+				  unsigned long addr, pte_t *ptep);
 
 #else /* CONFIG_THP_CONTPTE */
 
@@ -810,6 +814,8 @@ extern int ptep_test_and_clear_young(struct vm_area_struct *vma,
 #define ptep_get_and_clear	__ptep_get_and_clear
 #define __HAVE_ARCH_PTEP_TEST_AND_CLEAR_YOUNG
 #define ptep_test_and_clear_young	__ptep_test_and_clear_young
+#define __HAVE_ARCH_PTEP_CLEAR_YOUNG_FLUSH
+#define ptep_clear_flush_young	__ptep_clear_flush_young
 
 #endif /* CONFIG_THP_CONTPTE */
 
diff --git a/include/linux/contpte.h b/include/linux/contpte.h
index 38092adbe0d4..76a49ac8b6f5 100644
--- a/include/linux/contpte.h
+++ b/include/linux/contpte.h
@@ -21,5 +21,7 @@ void contpte_set_ptes(struct mm_struct *mm, unsigned long addr,
 		      pte_t *ptep, pte_t pte, unsigned int nr);
 int contpte_ptep_test_and_clear_young(struct vm_area_struct *vma,
 				      unsigned long addr, pte_t *ptep);
+int contpte_ptep_clear_flush_young(struct vm_area_struct *vma,
+				   unsigned long addr, pte_t *ptep);
 
 #endif /* _LINUX_CONTPTE_H */
diff --git a/mm/contpte.c b/mm/contpte.c
index 220e9d81f401..600277b1196c 100644
--- a/mm/contpte.c
+++ b/mm/contpte.c
@@ -48,6 +48,7 @@
  *   - pte_clear()
  *   - ptep_get_and_clear()
  *   - ptep_test_and_clear_young()
+ *   - ptep_clear_flush_young()
  */
 
 pte_t huge_ptep_get(pte_t *ptep)
@@ -729,4 +730,43 @@ __always_inline int ptep_test_and_clear_young(struct vm_area_struct *vma,
 
 	return contpte_ptep_test_and_clear_young(vma, addr, ptep);
 }
+
+int contpte_ptep_clear_flush_young(struct vm_area_struct *vma,
+				   unsigned long addr, pte_t *ptep)
+{
+	int young;
+
+	young = contpte_ptep_test_and_clear_young(vma, addr, ptep);
+
+	if (young) {
+		/*
+		 * See comment in __ptep_clear_flush_young(); same rationale for
+		 * eliding the trailing DSB applies here.
+		 */
+		size_t pgsize;
+		int ncontig;
+
+		ncontig = arch_contpte_get_num_contig(vma->vm_mm, addr, ptep,
+						      0, &pgsize);
+
+		addr = ALIGN_DOWN(addr, ncontig * pgsize);
+		arch_contpte_flush_tlb_range_nosync(vma, addr,
+						    addr + ncontig * pgsize,
+						    pgsize);
+	}
+
+	return young;
+}
+EXPORT_SYMBOL_GPL(contpte_ptep_clear_flush_young);
+
+__always_inline int ptep_clear_flush_young(struct vm_area_struct *vma,
+					   unsigned long addr, pte_t *ptep)
+{
+	pte_t orig_pte = __ptep_get(ptep);
+
+	if (likely(!pte_valid_cont(orig_pte)))
+		return __ptep_clear_flush_young(vma, addr, ptep);
+
+	return contpte_ptep_clear_flush_young(vma, addr, ptep);
+}
 #endif /* CONFIG_THP_CONTPTE */
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240508191931.46060-10-alexghiti%40rivosinc.com.
