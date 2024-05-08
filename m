Return-Path: <kasan-dev+bncBDXY7I6V6AMRBLVF56YQMGQEHTQX3BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 702728C0505
	for <lists+kasan-dev@lfdr.de>; Wed,  8 May 2024 21:29:51 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2e482d3d8b3sf894861fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 08 May 2024 12:29:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715196591; cv=pass;
        d=google.com; s=arc-20160816;
        b=AnoOYfk8zr4T+J+qpfpnXjzio6gqj/Ng1s9bakxOvHnYcEhS5JZYrDsL+Ik9XUSjRJ
         hjAzO3lKgaGGdy+rylHVq+UItlQBrgDYqyARyK96GIq8kOndLq4208GyTnzMNJ3qdvO2
         QqtWR7+85ocbI2nU2U4wCZJgZ6UtYDUvluixYShvl0rIv0r3wLvmszEzmpsSwJ5NXus2
         7l5OtaAf9sU/5y8HVMVafDK0RVzMOW2sUt3s9RGRnt0XBedz0NFJapn1JPBr4rYkH9ZK
         t1IvYBi2IlA02q6CyvotQa/XyVcZUEg/YaQsj2hcAFNlQRh5a/ove7/39cMlhU1ykJHB
         /hyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DE1ZWJFhmPzjp/I8Vq/xfgfPLr52Iluz4qcy6quk+U0=;
        fh=KAM8PAE2vq6EE8cL5AVvesQzP4Gsjhoruj3aMgw9aEE=;
        b=GErm8VxqzCTALBcQUEiXj04t9S/DtS8U4ZMBoC1giHjc4edXAEaRKTdvwWRYI69oB2
         wcvltGj7l/nWv29MZwj+nHbTRYXYsus+wG/FEzc/dYXKo2GcF37lLJXEjuFRkeEFFjrB
         3Ed45G+T+CmCu2Bf3pjkEyK9zUpBp8ll2PzqrLU2P3E6RebONupKdU0TJaUL5t7T5LIC
         7+4zeM2epj9PzY5l7u0ZVjwle25kPo60XEmfOMdwMe6xz4MGAX7iaWy+ksu3SBC16xv7
         Q0/4DgkAhA94keOlz4bNhMhKfQcMHM+P1jW+wxXpUr6mFtWeQlRRFCn4u8p9PWW8BUmI
         dCHg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=x3U0mP76;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715196591; x=1715801391; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DE1ZWJFhmPzjp/I8Vq/xfgfPLr52Iluz4qcy6quk+U0=;
        b=t5k4FGaXj6tGrJADSMrIY+ZGUOl6Q09sUjCk71ar7bvWaX/jZ95F/nwIhOOW/o5cJ3
         91VmOWN0bMAVdVNydgDi2MWV3/BvP6VSnlMrYrCduBEBO+f+LDBMeHOTE1whZD+wzwsT
         dMltxH2kNX2ORPqdIJ4mnUem86mzbbbhNtFYYMTOyDSzUbJDTPnD/TiXGzsUXhdyG2Ud
         Vh8+mTgQegKz9fw4QXqCr1ny3yxRCFBihgc+0BoZjyS4H7THlQDgOlc4lHV+Z0ySayWr
         MJoxQFjzGccpXyBJe+SbXQc22m0uykKl703VBDoQ9wy6LzBfK5Y2m8Siiy+Jyop+VqBb
         RiEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715196591; x=1715801391;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DE1ZWJFhmPzjp/I8Vq/xfgfPLr52Iluz4qcy6quk+U0=;
        b=BVNHc28HC+lVmwqMx3fug9LuRNAXJUgZ1JiCBWTiBFoxrD8mdswY0TCzlSBc+bxr6I
         SbG3M2KSwjWcl0QTEe4AMs7i+CyLEu8WDpJGJ51/yqZA0nmoTxesnnuGIfVeVV2tsv6F
         /iX7G3P1WGlyAy6+mcTApG+DiFStxWlyPr1vXXIk0T6qmPQN0PUc4fC9OWIuxGCHx3ze
         k3+XCDG6PY1o6EL3oahCxTvFA3A6DewWqaOZGRxgipmVFSo9tBxd+/XO318Wtl7arzbq
         zgBwQhkmj5NGuoAZ4ZhVs7dx0diewRPFVPMSqhTnIT+2gn8k9eDXU2+g35guiMR7HNFO
         VMJQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVhunFhLPkkemw3hwqmyh5SvC4Mzr5C6BdoLYFQEEHsR1fd0RURno/+rr74mb/UTFlUh4zSRmQxgz/TueEXAnEQaU5vAISRkQ==
X-Gm-Message-State: AOJu0YxnhDHScHbPjcQ37OEfBdbaarCrYmqc9fmMPGKoPsBDPhC41/cS
	3YmiH961yOvnZpkCwYYI676/6LDKeLvBPb5PygYl/o4qmouuU24k
X-Google-Smtp-Source: AGHT+IFSAM3r+QS83+y7GJVSKv/dwMvB7ArnOtm0pAKZ5+bxJOLsWZPrXTbTcdXU5MHUcVWSEGzWbg==
X-Received: by 2002:ac2:4425:0:b0:51a:c207:12b with SMTP id 2adb3069b0e04-5217c66736bmr2197152e87.37.1715196590262;
        Wed, 08 May 2024 12:29:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:b0:518:e762:8bab with SMTP id
 2adb3069b0e04-521e3033ea1ls100926e87.0.-pod-prod-02-eu; Wed, 08 May 2024
 12:29:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW1hRZFgTgW8KGiLyEkrmNJu8YEL4NEiSGy7qaET8nxATTI3L3yLUVtRt9u4dbo35CI9xpcnQ+WOHgdbUacu6kUc+ugVJUupeJAMg==
X-Received: by 2002:a05:6512:1320:b0:51d:3675:6a08 with SMTP id 2adb3069b0e04-5217ce46ca2mr2366287e87.66.1715196588255;
        Wed, 08 May 2024 12:29:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715196588; cv=none;
        d=google.com; s=arc-20160816;
        b=rTn1iuSc9tFbwmWx5Jluh9DVBQZhbvET+kmJIYv4fBhmLtEQlTLkgTYUvw3J6Ie1ta
         GZ8grvv/r5mH6oFylaVVbCUozShf8sZIWPhB1ZPQgwr/zeDXY5yzTlbdRqsYFNGeR6nX
         CfSS3HoTxOlRpDiDy05Mcif/PQXijlm28K6Q45Dcsw7payP8m4s6MJyC7o17qWoNTwyf
         UrUUjp3u4iLSNEsgU+1fKaw3f+O3tJ9fs5Y8UQ1gnfBaSHEfC4uI+pnOpM5HNqoAybCK
         sGx62SV8K9+VhuUaI6laV7ggMW1+jyYRM/v88qWrm2JNbNzQFtqYVehbnw2eFewxFHV1
         dLnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uckq1a6OF7H/9ROfgD12E/DRrLJPxYkFYbl5+hSyETI=;
        fh=5rgSiFytXgl4gIPJkhz0EB3oy+/4wvEKnbcno8dJ34A=;
        b=k/Bz91KjC7b7HTM0Eq3bAse2C5xlrjvufuh2EfPXe8+xBSF7qHxsz1jSbwqQ1GsD8Q
         BmpMXMJEbl+8ZVmQHhUrHVtpHYMkjWyxms3SBxwFajrsYCAuZx4ocTDsGs46mDKLSst6
         YoWHuFAxe2M2wWETQbPJLaXLs9v3wgMVbLEw4nb91adxlJSlzZpd08PLUBTSQRGB1EVF
         VSuuOR1Lkg8EHVBD4WDURU1i9Aj8p5TbaChlalpR/q3Ht6yoHYMDJf0EBDI6tcWAaICc
         s8ADf+LlxKfonKNtnAWVdekXMqXsyL+FK7KuDj6efxn4XIoIzhzzN+m/3VMkvFn5Nw6G
         EzhQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=x3U0mP76;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id z16-20020a056512371000b0052093e53496si231417lfr.0.2024.05.08.12.29.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 May 2024 12:29:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id 5b1f17b1804b1-41b794510cdso611825e9.2
        for <kasan-dev@googlegroups.com>; Wed, 08 May 2024 12:29:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVZPUXE2sf87s39fKff+rNl2sxgyvocesNqNDKCzVIS13GtMHjdpbUQp8Qq0vEwdIzxQ0ywt5e/KUKMSw7vxiISnsHsHz3FvD9HeA==
X-Received: by 2002:a05:600c:4e93:b0:41b:fc3a:f1ef with SMTP id 5b1f17b1804b1-41f71acca18mr25217385e9.33.1715196587426;
        Wed, 08 May 2024 12:29:47 -0700 (PDT)
Received: from alex-rivos.ba.rivosinc.com (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id d16-20020a05600c34d000b00419f572671dsm3314921wmq.20.2024.05.08.12.29.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 May 2024 12:29:47 -0700 (PDT)
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
Subject: [PATCH 10/12] mm, riscv, arm64: Use common ptep_set_access_flags() function
Date: Wed,  8 May 2024 21:19:29 +0200
Message-Id: <20240508191931.46060-11-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20240508191931.46060-1-alexghiti@rivosinc.com>
References: <20240508191931.46060-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=x3U0mP76;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

Make riscv use the contpte aware ptep_set_access_flags() function from
arm64.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/arm64/include/asm/pgtable.h | 19 ++--------
 arch/arm64/mm/contpte.c          | 46 -----------------------
 arch/riscv/include/asm/pgtable.h | 10 +++--
 include/linux/contpte.h          |  3 ++
 mm/contpte.c                     | 63 ++++++++++++++++++++++++++++++++
 5 files changed, 76 insertions(+), 65 deletions(-)

diff --git a/arch/arm64/include/asm/pgtable.h b/arch/arm64/include/asm/pgtable.h
index 92c12fb85cb4..6591aab11c67 100644
--- a/arch/arm64/include/asm/pgtable.h
+++ b/arch/arm64/include/asm/pgtable.h
@@ -1391,9 +1391,6 @@ extern pte_t contpte_get_and_clear_full_ptes(struct mm_struct *mm,
 				unsigned int nr, int full);
 extern void contpte_wrprotect_ptes(struct mm_struct *mm, unsigned long addr,
 				pte_t *ptep, unsigned int nr);
-extern int contpte_ptep_set_access_flags(struct vm_area_struct *vma,
-				unsigned long addr, pte_t *ptep,
-				pte_t entry, int dirty);
 
 #define pte_batch_hint pte_batch_hint
 static inline unsigned int pte_batch_hint(pte_t *ptep, pte_t pte)
@@ -1512,19 +1509,9 @@ static inline void ptep_set_wrprotect(struct mm_struct *mm,
 }
 
 #define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
-static inline int ptep_set_access_flags(struct vm_area_struct *vma,
-				unsigned long addr, pte_t *ptep,
-				pte_t entry, int dirty)
-{
-	pte_t orig_pte = __ptep_get(ptep);
-
-	entry = pte_mknoncont(entry);
-
-	if (likely(!pte_valid_cont(orig_pte)))
-		return __ptep_set_access_flags(vma, addr, ptep, entry, dirty);
-
-	return contpte_ptep_set_access_flags(vma, addr, ptep, entry, dirty);
-}
+extern int ptep_set_access_flags(struct vm_area_struct *vma,
+				 unsigned long addr, pte_t *ptep,
+				 pte_t entry, int dirty);
 
 #else /* CONFIG_THP_CONTPTE */
 
diff --git a/arch/arm64/mm/contpte.c b/arch/arm64/mm/contpte.c
index 16940511943c..5675a61452ac 100644
--- a/arch/arm64/mm/contpte.c
+++ b/arch/arm64/mm/contpte.c
@@ -62,49 +62,3 @@ void contpte_wrprotect_ptes(struct mm_struct *mm, unsigned long addr,
 	__wrprotect_ptes(mm, addr, ptep, nr);
 }
 EXPORT_SYMBOL_GPL(contpte_wrprotect_ptes);
-
-int contpte_ptep_set_access_flags(struct vm_area_struct *vma,
-					unsigned long addr, pte_t *ptep,
-					pte_t entry, int dirty)
-{
-	unsigned long start_addr;
-	pte_t orig_pte;
-	int i;
-
-	/*
-	 * Gather the access/dirty bits for the contiguous range. If nothing has
-	 * changed, its a noop.
-	 */
-	orig_pte = pte_mknoncont(ptep_get(ptep));
-	if (pte_val(orig_pte) == pte_val(entry))
-		return 0;
-
-	/*
-	 * We can fix up access/dirty bits without having to unfold the contig
-	 * range. But if the write bit is changing, we must unfold.
-	 */
-	if (pte_write(orig_pte) == pte_write(entry)) {
-		/*
-		 * For HW access management, we technically only need to update
-		 * the flag on a single pte in the range. But for SW access
-		 * management, we need to update all the ptes to prevent extra
-		 * faults. Avoid per-page tlb flush in __ptep_set_access_flags()
-		 * and instead flush the whole range at the end.
-		 */
-		ptep = arch_contpte_align_down(ptep);
-		start_addr = addr = ALIGN_DOWN(addr, CONT_PTE_SIZE);
-
-		for (i = 0; i < CONT_PTES; i++, ptep++, addr += PAGE_SIZE)
-			__ptep_set_access_flags(vma, addr, ptep, entry, 0);
-
-		if (dirty)
-			__flush_tlb_range(vma, start_addr, addr,
-							PAGE_SIZE, true, 3);
-	} else {
-		__contpte_try_unfold(vma->vm_mm, addr, ptep, orig_pte);
-		__ptep_set_access_flags(vma, addr, ptep, entry, dirty);
-	}
-
-	return 1;
-}
-EXPORT_SYMBOL_GPL(contpte_ptep_set_access_flags);
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index 42c7884b8d2e..b151a5aa4de8 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -803,6 +803,10 @@ extern int ptep_test_and_clear_young(struct vm_area_struct *vma,
 #define __HAVE_ARCH_PTEP_CLEAR_YOUNG_FLUSH
 extern int ptep_clear_flush_young(struct vm_area_struct *vma,
 				  unsigned long addr, pte_t *ptep);
+#define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
+extern int ptep_set_access_flags(struct vm_area_struct *vma,
+				 unsigned long address, pte_t *ptep,
+				 pte_t entry, int dirty);
 
 #else /* CONFIG_THP_CONTPTE */
 
@@ -816,11 +820,11 @@ extern int ptep_clear_flush_young(struct vm_area_struct *vma,
 #define ptep_test_and_clear_young	__ptep_test_and_clear_young
 #define __HAVE_ARCH_PTEP_CLEAR_YOUNG_FLUSH
 #define ptep_clear_flush_young	__ptep_clear_flush_young
+#define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
+#define ptep_set_access_flags	__ptep_set_access_flags
 
 #endif /* CONFIG_THP_CONTPTE */
 
-#define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
-#define ptep_set_access_flags	__ptep_set_access_flags
 #define __HAVE_ARCH_PTEP_SET_WRPROTECT
 #define ptep_set_wrprotect	__ptep_set_wrprotect
 
@@ -990,7 +994,7 @@ static inline int pmdp_set_access_flags(struct vm_area_struct *vma,
 					unsigned long address, pmd_t *pmdp,
 					pmd_t entry, int dirty)
 {
-	return ptep_set_access_flags(vma, address, (pte_t *)pmdp, pmd_pte(entry), dirty);
+	return __ptep_set_access_flags(vma, address, (pte_t *)pmdp, pmd_pte(entry), dirty);
 }
 
 #define __HAVE_ARCH_PMDP_TEST_AND_CLEAR_YOUNG
diff --git a/include/linux/contpte.h b/include/linux/contpte.h
index 76a49ac8b6f5..76244b0c678a 100644
--- a/include/linux/contpte.h
+++ b/include/linux/contpte.h
@@ -23,5 +23,8 @@ int contpte_ptep_test_and_clear_young(struct vm_area_struct *vma,
 				      unsigned long addr, pte_t *ptep);
 int contpte_ptep_clear_flush_young(struct vm_area_struct *vma,
 				   unsigned long addr, pte_t *ptep);
+int contpte_ptep_set_access_flags(struct vm_area_struct *vma,
+				  unsigned long addr, pte_t *ptep,
+				  pte_t entry, int dirty);
 
 #endif /* _LINUX_CONTPTE_H */
diff --git a/mm/contpte.c b/mm/contpte.c
index 600277b1196c..9cbbff1f67ad 100644
--- a/mm/contpte.c
+++ b/mm/contpte.c
@@ -769,4 +769,67 @@ __always_inline int ptep_clear_flush_young(struct vm_area_struct *vma,
 
 	return contpte_ptep_clear_flush_young(vma, addr, ptep);
 }
+
+int contpte_ptep_set_access_flags(struct vm_area_struct *vma,
+				  unsigned long addr, pte_t *ptep,
+				  pte_t entry, int dirty)
+{
+	unsigned long start_addr;
+	pte_t orig_pte;
+	int i;
+
+	/*
+	 * Gather the access/dirty bits for the contiguous range. If nothing has
+	 * changed, its a noop.
+	 */
+	orig_pte = pte_mknoncont(ptep_get(ptep));
+	if (pte_val(orig_pte) == pte_val(entry))
+		return 0;
+
+	/*
+	 * We can fix up access/dirty bits without having to unfold the contig
+	 * range. But if the write bit is changing, we must unfold.
+	 */
+	if (pte_write(orig_pte) == pte_write(entry)) {
+		/*
+		 * For HW access management, we technically only need to update
+		 * the flag on a single pte in the range. But for SW access
+		 * management, we need to update all the ptes to prevent extra
+		 * faults. Avoid per-page tlb flush in __ptep_set_access_flags()
+		 * and instead flush the whole range at the end.
+		 */
+		size_t pgsize;
+		int ncontig;
+
+		ptep = arch_contpte_align_down(ptep);
+		ncontig = arch_contpte_get_num_contig(vma->vm_mm, addr, ptep, 0, &pgsize);
+		start_addr = addr = ALIGN_DOWN(addr, ncontig * pgsize);
+
+		for (i = 0; i < ncontig; i++, ptep++, addr += pgsize)
+			__ptep_set_access_flags(vma, addr, ptep, entry, 0);
+
+		if (dirty)
+			arch_contpte_flush_tlb_range(vma, start_addr, addr, pgsize);
+	} else {
+		__contpte_try_unfold(vma->vm_mm, addr, ptep, orig_pte);
+		__ptep_set_access_flags(vma, addr, ptep, entry, dirty);
+	}
+
+	return 1;
+}
+EXPORT_SYMBOL_GPL(contpte_ptep_set_access_flags);
+
+__always_inline int ptep_set_access_flags(struct vm_area_struct *vma,
+					  unsigned long addr, pte_t *ptep,
+					  pte_t entry, int dirty)
+{
+	pte_t orig_pte = __ptep_get(ptep);
+
+	entry = pte_mknoncont(entry);
+
+	if (likely(!pte_valid_cont(orig_pte)))
+		return __ptep_set_access_flags(vma, addr, ptep, entry, dirty);
+
+	return contpte_ptep_set_access_flags(vma, addr, ptep, entry, dirty);
+}
 #endif /* CONFIG_THP_CONTPTE */
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240508191931.46060-11-alexghiti%40rivosinc.com.
