Return-Path: <kasan-dev+bncBDXY7I6V6AMRB25F56YQMGQEIVJT2FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id CAEF18C050B
	for <lists+kasan-dev@lfdr.de>; Wed,  8 May 2024 21:30:52 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-34c68b0d27esf36914f8f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 08 May 2024 12:30:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715196652; cv=pass;
        d=google.com; s=arc-20160816;
        b=xWhgVTPJyHxx1nOMKT3r4Y16cI6CFI1tMsxnvIZQ7r5PjZZVaE4omCT8XQqSFpN8/G
         lbTFNG552dmjRf2r7Ssh4ue7zTQF6h/1hHhOCkuiNy1r102GMfgzgaH516GQvj1a6pD/
         40JqYXjJ1hXYyP1R2lCb+oJCZF408gWh/Qij3n/lfswhXFmjt3Cc2JLwP9Lv4ZP5l6id
         iWXBptqVeBnA1ldqGZo8GHYFE1IAqg9+5d2S3R+1P7vVhEBnHZtR0w7QQNFGCAaLsh0o
         I2bt8uP/XI22CHMkriYhElVAjoKy1XJXvSe0nNehP0bOsmNebbl6VQohT+rUif5CkUfa
         lKLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6zoHEyMR9BgHkPsLkQVMiC3G4vT4GiINwz6aLfHyBkU=;
        fh=6Dy5eL9CombShiQJeQoVB162gJL2+a2CGaGI68kcTpk=;
        b=TbXeasx4hnk1wqZvY/9dw9EL096Q6tFHGwsJxmYxIwdsoBe0xqzr7IwyGi1CaqiPTI
         Y8J/S73cK3UA3mAnslhtko891+uK6SpCB7lgfsbnZ4u8TO4xTV1ZPnFe/ZbBgzv02C90
         vTwAeuYxATAzqV8XcmW2kgGYSNU04uRaaOTp96UFfwVK/mpWY9xVfRGANImwc2XiNGTb
         +dLgE6N+Ev1pMYyGhsczmJVfp1v4syPqfGvgujQYDarPr8Rbfk2E8UlHUU+vpwMighVR
         VCy/CPFUEt0AFScft3FRWQKT1j/FBAwDQ0oz2wghbmpIyF8lUGtZBhO2V3wXB9BQTicO
         c86g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b="reVIaXZ/";
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715196652; x=1715801452; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6zoHEyMR9BgHkPsLkQVMiC3G4vT4GiINwz6aLfHyBkU=;
        b=h2C2wNYPBGh55ZWOPdy4xGFnZ+NS/1Y8XHUSuA/ZTE718DBVCFZH6BmE7jY55CW0In
         LhZ3XNgg88VENyhVeJ9f+Idf4C+5VpCqer7CbdgPZRhg+Ds/OB9dxpHee4fzgcQeN3ou
         utRF1rd+7ANETaMAmeqfdFWUQKTsDyl7HZ7Nepr15N8xJAgRPjEqQYVk2jSo8yUPFlWH
         6gTABRMuuPM4Te6uOU5rkdBKK9JtGPJDpg+QxWkuQsdKFCv8ebnqaxG77VFb0fHn4KTL
         fr4l6uLmRGvGfVn3/j8B2sAO/i9cXZ52RK8mJKw4Zg10DIo8SW9Cng5Q5hfpVHat6lN+
         gOww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715196652; x=1715801452;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6zoHEyMR9BgHkPsLkQVMiC3G4vT4GiINwz6aLfHyBkU=;
        b=VX1bim+tS+u4OyQ96Bgwmg19y2aBiEqceQsI7W+e4Nl1PYQfo1WfE0ZW2lVCzW1urI
         UjMqxfqIE4PmW97K/dmLKSbED4zF6+gqEpWuiehnhRPgI1yfX91fwXV3MlgKJnXE1OVc
         vdzhIGi1ABak5PFGfsmP+ovY3mQS4EcrERfeMDYOZzLFOaKzPny/m4QOeX6ZYURfF9sE
         v7w9RBMJwKdXz1DsgUpxGoqVtebonthQjxJG8lMfywXak3RrJQrFvqAYEwsgF0aCJ3Qx
         yQNKyckJPdqiXtEBw63S7IjrBfiPVWJMavYh7IRfP5GeCwAW/jxYG+2Etx0KWTnBkzXU
         1i4A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWmeFkZDPTUCYfqDjZnA/k1u2X3QTmp2zErn8NGwFYCu6NR2hSYVtm7yARa8WpFuzkYrZoh8W1f5zC1wJJODUXnLm2pzhBdUA==
X-Gm-Message-State: AOJu0YwFOzQ+3b57OQ+XJP/e5tdOek9UQgSEkLPqqg8J4+DKCpIr5bld
	EPpDVsl4qxTh85U3E9alO1Ga1+nkeL9WJI0aKRbG7kdcZ3hgl/tm
X-Google-Smtp-Source: AGHT+IHjF8BpfEQFP6cU1vWJJ7579ychUkYGx3LEekkVfrAQUUmN/+H6KaN+5AghRSq96cZ2ef5FJA==
X-Received: by 2002:a5d:4e51:0:b0:34f:3293:85c6 with SMTP id ffacd0b85a97d-34fcabefddbmr3469518f8f.64.1715196651346;
        Wed, 08 May 2024 12:30:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e707:0:b0:34d:9bcc:e0aa with SMTP id ffacd0b85a97d-3501d8b68cals26386f8f.2.-pod-prod-08-eu;
 Wed, 08 May 2024 12:30:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV9PmM8EdzlzSb6RExopcy5fyF5sua4i0Nd5YiIQjEN7R6xBI44OzuNuGQtQVzeiT+CKtTrRBNeehJFEiWp1T6m8KxL+Ms26wf8wg==
X-Received: by 2002:adf:e5d0:0:b0:343:7fa5:3462 with SMTP id ffacd0b85a97d-34fca61fc1bmr2937935f8f.24.1715196649363;
        Wed, 08 May 2024 12:30:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715196649; cv=none;
        d=google.com; s=arc-20160816;
        b=QdM130slKt4WUZHSid/NIFOyC61bpjwFxQaWhkwtn9X5a0UKA6magFfHplRGLXElT8
         kmSBPANBgxWDDqEajWn4LdlxHjFKPoNmYIJuzvhJ4aNJNNVeu9sfFdM49zf9KnpAy85e
         KFeuFqI/WH+S3NaEjvuSnM8bY/ADeV2xH/T/XHH++yLwSjCJwLK9AkeXgxA1N3TETLqx
         HbMCfFCMSXhRXlx/IbElbacGaDVI5n9vgA4Ypj1s/sJskQ5CEYVtMq8z12bN0k8ysyF3
         hmlh2CQLyyw6wIAim0TxGUuWCvcv7jooOpTH2PDLKotJsE+f5hQdw3Kg+fk9NP/ZShoa
         fHxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=K1s8quCXzhpwj2tdUrwB8sMaHFPnndxHFKfGkIDXtWo=;
        fh=yIsAgRv1mmxmytH4gg+31hFtjk7JGF3xbGD4O2iE6zw=;
        b=fxvXQc2kSbWZSeRLuNkWqvyITPhSKKlBHsDddQpSboP2IIwAqYWrYesjk2NVJfQyC4
         OsTPnPTFm6p7xbPDWJsVX2E4CPr++8+J1/x+neB25F0MF7jFjQ+YE6EaDuUj17WddqNw
         K9JI7yVJzkokyIImjkYvjBW0x27UetnlEbd+t7rbGN4Fg4PU7UB3UfoZ6xyRVPNJ3xPK
         U4EiHb34K13528Con7lvpprknR15eHUS2KxzJIN+HxEKN8DBkrG1tFBtaHm0aW7OUF/f
         MhcS+y99voEOiiOUraSIEMhQxkWVAfqp5m+JQwPE09BRQ8HHZ9I18GktER8yG+LvNphm
         duTw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b="reVIaXZ/";
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-lj1-x22c.google.com (mail-lj1-x22c.google.com. [2a00:1450:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id ee11-20020a056000210b00b0034c0de00e92si278158wrb.6.2024.05.08.12.30.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 May 2024 12:30:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::22c as permitted sender) client-ip=2a00:1450:4864:20::22c;
Received: by mail-lj1-x22c.google.com with SMTP id 38308e7fff4ca-2e3e18c240fso1536201fa.0
        for <kasan-dev@googlegroups.com>; Wed, 08 May 2024 12:30:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUoiA7N9D0o53P2XYBEyUnD+qVko9zSA5KsWWgm8FLVuzr1bORSyhmFgUAGRB79xrZs4oEXWbn7qN33LjvQjhHqHcAhPPdj9X4d1w==
X-Received: by 2002:a05:651c:1541:b0:2df:e192:47ec with SMTP id 38308e7fff4ca-2e447081ef2mr37890971fa.29.1715196648606;
        Wed, 08 May 2024 12:30:48 -0700 (PDT)
Received: from alex-rivos.ba.rivosinc.com (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id b15-20020a05600c4e0f00b0041aa79f27a0sm3273819wmq.38.2024.05.08.12.30.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 May 2024 12:30:48 -0700 (PDT)
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
Subject: [PATCH 11/12] mm, riscv, arm64: Use common ptep_set_wrprotect()/wrprotect_ptes() functions
Date: Wed,  8 May 2024 21:19:30 +0200
Message-Id: <20240508191931.46060-12-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20240508191931.46060-1-alexghiti@rivosinc.com>
References: <20240508191931.46060-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b="reVIaXZ/";       spf=pass (google.com: domain of
 alexghiti@rivosinc.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

Make riscv use the contpte aware ptep_set_wrprotect()/wrprotect_ptes()
function from arm64.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/arm64/include/asm/pgtable.h | 56 ++++++------------------
 arch/arm64/mm/contpte.c          | 18 --------
 arch/riscv/include/asm/pgtable.h | 25 +++++++++--
 include/linux/contpte.h          |  2 +
 mm/contpte.c                     | 75 +++++++++++++++++++++++++++++++-
 5 files changed, 110 insertions(+), 66 deletions(-)

diff --git a/arch/arm64/include/asm/pgtable.h b/arch/arm64/include/asm/pgtable.h
index 6591aab11c67..162efd9647dd 100644
--- a/arch/arm64/include/asm/pgtable.h
+++ b/arch/arm64/include/asm/pgtable.h
@@ -1208,7 +1208,11 @@ static inline pmd_t pmdp_huge_get_and_clear(struct mm_struct *mm,
 }
 #endif /* CONFIG_TRANSPARENT_HUGEPAGE */
 
-static inline void ___ptep_set_wrprotect(struct mm_struct *mm,
+/*
+ * __ptep_set_wrprotect - mark read-only while trasferring potential hardware
+ * dirty status (PTE_DBM && !PTE_RDONLY) to the software PTE_DIRTY bit.
+ */
+static inline void __ptep_set_wrprotect(struct mm_struct *mm,
 					unsigned long address, pte_t *ptep,
 					pte_t pte)
 {
@@ -1222,23 +1226,13 @@ static inline void ___ptep_set_wrprotect(struct mm_struct *mm,
 	} while (pte_val(pte) != pte_val(old_pte));
 }
 
-/*
- * __ptep_set_wrprotect - mark read-only while trasferring potential hardware
- * dirty status (PTE_DBM && !PTE_RDONLY) to the software PTE_DIRTY bit.
- */
-static inline void __ptep_set_wrprotect(struct mm_struct *mm,
-					unsigned long address, pte_t *ptep)
-{
-	___ptep_set_wrprotect(mm, address, ptep, __ptep_get(ptep));
-}
-
 static inline void __wrprotect_ptes(struct mm_struct *mm, unsigned long address,
 				pte_t *ptep, unsigned int nr)
 {
 	unsigned int i;
 
 	for (i = 0; i < nr; i++, address += PAGE_SIZE, ptep++)
-		__ptep_set_wrprotect(mm, address, ptep);
+		__ptep_set_wrprotect(mm, address, ptep, __ptep_get(ptep));
 }
 
 #ifdef CONFIG_TRANSPARENT_HUGEPAGE
@@ -1246,7 +1240,7 @@ static inline void __wrprotect_ptes(struct mm_struct *mm, unsigned long address,
 static inline void pmdp_set_wrprotect(struct mm_struct *mm,
 				      unsigned long address, pmd_t *pmdp)
 {
-	__ptep_set_wrprotect(mm, address, (pte_t *)pmdp);
+	__ptep_set_wrprotect(mm, address, (pte_t *)pmdp, __ptep_get((pte_t *)pmdp));
 }
 
 #define pmdp_establish pmdp_establish
@@ -1389,8 +1383,6 @@ extern void contpte_clear_full_ptes(struct mm_struct *mm, unsigned long addr,
 extern pte_t contpte_get_and_clear_full_ptes(struct mm_struct *mm,
 				unsigned long addr, pte_t *ptep,
 				unsigned int nr, int full);
-extern void contpte_wrprotect_ptes(struct mm_struct *mm, unsigned long addr,
-				pte_t *ptep, unsigned int nr);
 
 #define pte_batch_hint pte_batch_hint
 static inline unsigned int pte_batch_hint(pte_t *ptep, pte_t pte)
@@ -1478,35 +1470,12 @@ extern int ptep_clear_flush_young(struct vm_area_struct *vma,
 				  unsigned long addr, pte_t *ptep);
 
 #define wrprotect_ptes wrprotect_ptes
-static __always_inline void wrprotect_ptes(struct mm_struct *mm,
-				unsigned long addr, pte_t *ptep, unsigned int nr)
-{
-	if (likely(nr == 1)) {
-		/*
-		 * Optimization: wrprotect_ptes() can only be called for present
-		 * ptes so we only need to check contig bit as condition for
-		 * unfold, and we can remove the contig bit from the pte we read
-		 * to avoid re-reading. This speeds up fork() which is sensitive
-		 * for order-0 folios. Equivalent to contpte_try_unfold().
-		 */
-		pte_t orig_pte = __ptep_get(ptep);
-
-		if (unlikely(pte_cont(orig_pte))) {
-			__contpte_try_unfold(mm, addr, ptep, orig_pte);
-			orig_pte = pte_mknoncont(orig_pte);
-		}
-		___ptep_set_wrprotect(mm, addr, ptep, orig_pte);
-	} else {
-		contpte_wrprotect_ptes(mm, addr, ptep, nr);
-	}
-}
+extern void wrprotect_ptes(struct mm_struct *mm,
+			   unsigned long addr, pte_t *ptep, unsigned int nr);
 
 #define __HAVE_ARCH_PTEP_SET_WRPROTECT
-static inline void ptep_set_wrprotect(struct mm_struct *mm,
-				unsigned long addr, pte_t *ptep)
-{
-	wrprotect_ptes(mm, addr, ptep, 1);
-}
+extern void ptep_set_wrprotect(struct mm_struct *mm,
+			       unsigned long addr, pte_t *ptep);
 
 #define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
 extern int ptep_set_access_flags(struct vm_area_struct *vma,
@@ -1528,7 +1497,8 @@ extern int ptep_set_access_flags(struct vm_area_struct *vma,
 #define __HAVE_ARCH_PTEP_CLEAR_YOUNG_FLUSH
 #define ptep_clear_flush_young			__ptep_clear_flush_young
 #define __HAVE_ARCH_PTEP_SET_WRPROTECT
-#define ptep_set_wrprotect			__ptep_set_wrprotect
+#define ptep_set_wrprotect(mm, addr, ptep)					\
+			__ptep_set_wrprotect(mm, addr, ptep, __ptep_get(ptep))
 #define wrprotect_ptes				__wrprotect_ptes
 #define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
 #define ptep_set_access_flags			__ptep_set_access_flags
diff --git a/arch/arm64/mm/contpte.c b/arch/arm64/mm/contpte.c
index 5675a61452ac..1cef93b15d6e 100644
--- a/arch/arm64/mm/contpte.c
+++ b/arch/arm64/mm/contpte.c
@@ -44,21 +44,3 @@ pte_t contpte_get_and_clear_full_ptes(struct mm_struct *mm,
 	return __get_and_clear_full_ptes(mm, addr, ptep, nr, full);
 }
 EXPORT_SYMBOL_GPL(contpte_get_and_clear_full_ptes);
-
-void contpte_wrprotect_ptes(struct mm_struct *mm, unsigned long addr,
-					pte_t *ptep, unsigned int nr)
-{
-	/*
-	 * If wrprotecting an entire contig range, we can avoid unfolding. Just
-	 * set wrprotect and wait for the later mmu_gather flush to invalidate
-	 * the tlb. Until the flush, the page may or may not be wrprotected.
-	 * After the flush, it is guaranteed wrprotected. If it's a partial
-	 * range though, we must unfold, because we can't have a case where
-	 * CONT_PTE is set but wrprotect applies to a subset of the PTEs; this
-	 * would cause it to continue to be unpredictable after the flush.
-	 */
-
-	contpte_try_unfold_partial(mm, addr, ptep, nr);
-	__wrprotect_ptes(mm, addr, ptep, nr);
-}
-EXPORT_SYMBOL_GPL(contpte_wrprotect_ptes);
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index b151a5aa4de8..728f31da5e6a 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -755,11 +755,21 @@ static inline pte_t __ptep_get_and_clear(struct mm_struct *mm,
 }
 
 static inline void __ptep_set_wrprotect(struct mm_struct *mm,
-					unsigned long address, pte_t *ptep)
+					unsigned long address, pte_t *ptep,
+					pte_t pte)
 {
 	atomic_long_and(~(unsigned long)_PAGE_WRITE, (atomic_long_t *)ptep);
 }
 
+static inline void __wrprotect_ptes(struct mm_struct *mm, unsigned long address,
+				    pte_t *ptep, unsigned int nr)
+{
+	unsigned int i;
+
+	for (i = 0; i < nr; i++, address += PAGE_SIZE, ptep++)
+		__ptep_set_wrprotect(mm, address, ptep, __ptep_get(ptep));
+}
+
 static inline int __ptep_clear_flush_young(struct vm_area_struct *vma,
 					   unsigned long address, pte_t *ptep)
 {
@@ -807,6 +817,12 @@ extern int ptep_clear_flush_young(struct vm_area_struct *vma,
 extern int ptep_set_access_flags(struct vm_area_struct *vma,
 				 unsigned long address, pte_t *ptep,
 				 pte_t entry, int dirty);
+#define __HAVE_ARCH_PTEP_SET_WRPROTECT
+extern void ptep_set_wrprotect(struct mm_struct *mm,
+			       unsigned long addr, pte_t *ptep);
+extern void wrprotect_ptes(struct mm_struct *mm, unsigned long addr,
+			   pte_t *ptep, unsigned int nr);
+#define wrprotect_ptes	wrprotect_ptes
 
 #else /* CONFIG_THP_CONTPTE */
 
@@ -822,12 +838,13 @@ extern int ptep_set_access_flags(struct vm_area_struct *vma,
 #define ptep_clear_flush_young	__ptep_clear_flush_young
 #define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
 #define ptep_set_access_flags	__ptep_set_access_flags
+#define __HAVE_ARCH_PTEP_SET_WRPROTECT
+#define ptep_set_wrprotect(mm, addr, ptep)					\
+			__ptep_set_wrprotect(mm, addr, ptep, __ptep_get(ptep))
+#define wrprotect_ptes		__wrprotect_ptes
 
 #endif /* CONFIG_THP_CONTPTE */
 
-#define __HAVE_ARCH_PTEP_SET_WRPROTECT
-#define ptep_set_wrprotect	__ptep_set_wrprotect
-
 #define pgprot_nx pgprot_nx
 static inline pgprot_t pgprot_nx(pgprot_t _prot)
 {
diff --git a/include/linux/contpte.h b/include/linux/contpte.h
index 76244b0c678a..d1439db1706c 100644
--- a/include/linux/contpte.h
+++ b/include/linux/contpte.h
@@ -26,5 +26,7 @@ int contpte_ptep_clear_flush_young(struct vm_area_struct *vma,
 int contpte_ptep_set_access_flags(struct vm_area_struct *vma,
 				  unsigned long addr, pte_t *ptep,
 				  pte_t entry, int dirty);
+void contpte_wrprotect_ptes(struct mm_struct *mm, unsigned long addr,
+			    pte_t *ptep, unsigned int nr);
 
 #endif /* _LINUX_CONTPTE_H */
diff --git a/mm/contpte.c b/mm/contpte.c
index 9cbbff1f67ad..fe36b6b1d20a 100644
--- a/mm/contpte.c
+++ b/mm/contpte.c
@@ -49,6 +49,8 @@
  *   - ptep_get_and_clear()
  *   - ptep_test_and_clear_young()
  *   - ptep_clear_flush_young()
+ *   - wrprotect_ptes()
+ *   - ptep_set_wrprotect()
  */
 
 pte_t huge_ptep_get(pte_t *ptep)
@@ -266,7 +268,7 @@ void huge_ptep_set_wrprotect(struct mm_struct *mm,
 	pte_t pte;
 
 	if (!pte_cont(__ptep_get(ptep))) {
-		__ptep_set_wrprotect(mm, addr, ptep);
+		__ptep_set_wrprotect(mm, addr, ptep, __ptep_get(ptep));
 		return;
 	}
 
@@ -832,4 +834,75 @@ __always_inline int ptep_set_access_flags(struct vm_area_struct *vma,
 
 	return contpte_ptep_set_access_flags(vma, addr, ptep, entry, dirty);
 }
+
+static void contpte_try_unfold_partial(struct mm_struct *mm, unsigned long addr,
+				       pte_t *ptep, unsigned int nr)
+{
+	/*
+	 * Unfold any partially covered contpte block at the beginning and end
+	 * of the range.
+	 */
+	size_t pgsize;
+	int ncontig;
+
+	ncontig = arch_contpte_get_num_contig(mm, addr, ptep, 0, &pgsize);
+
+	if (ptep != arch_contpte_align_down(ptep) || nr < ncontig)
+		contpte_try_unfold(mm, addr, ptep, __ptep_get(ptep));
+
+	if (ptep + nr != arch_contpte_align_down(ptep + nr)) {
+		unsigned long last_addr = addr + pgsize * (nr - 1);
+		pte_t *last_ptep = ptep + nr - 1;
+
+		contpte_try_unfold(mm, last_addr, last_ptep,
+				   __ptep_get(last_ptep));
+	}
+}
+
+void contpte_wrprotect_ptes(struct mm_struct *mm, unsigned long addr,
+			    pte_t *ptep, unsigned int nr)
+{
+	/*
+	 * If wrprotecting an entire contig range, we can avoid unfolding. Just
+	 * set wrprotect and wait for the later mmu_gather flush to invalidate
+	 * the tlb. Until the flush, the page may or may not be wrprotected.
+	 * After the flush, it is guaranteed wrprotected. If it's a partial
+	 * range though, we must unfold, because we can't have a case where
+	 * CONT_PTE is set but wrprotect applies to a subset of the PTEs; this
+	 * would cause it to continue to be unpredictable after the flush.
+	 */
+
+	contpte_try_unfold_partial(mm, addr, ptep, nr);
+	__wrprotect_ptes(mm, addr, ptep, nr);
+}
+EXPORT_SYMBOL_GPL(contpte_wrprotect_ptes);
+
+__always_inline void wrprotect_ptes(struct mm_struct *mm, unsigned long addr,
+		pte_t *ptep, unsigned int nr)
+{
+	if (likely(nr == 1)) {
+		/*
+		 * Optimization: wrprotect_ptes() can only be called for present
+		 * ptes so we only need to check contig bit as condition for
+		 * unfold, and we can remove the contig bit from the pte we read
+		 * to avoid re-reading. This speeds up fork() which is sensitive
+		 * for order-0 folios. Equivalent to contpte_try_unfold().
+		 */
+		pte_t orig_pte = __ptep_get(ptep);
+
+		if (unlikely(pte_cont(orig_pte))) {
+			__contpte_try_unfold(mm, addr, ptep, orig_pte);
+			orig_pte = pte_mknoncont(orig_pte);
+		}
+		__ptep_set_wrprotect(mm, addr, ptep, orig_pte);
+	} else {
+		contpte_wrprotect_ptes(mm, addr, ptep, nr);
+	}
+}
+
+__always_inline void ptep_set_wrprotect(struct mm_struct *mm,
+					unsigned long addr, pte_t *ptep)
+{
+	wrprotect_ptes(mm, addr, ptep, 1);
+}
 #endif /* CONFIG_THP_CONTPTE */
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240508191931.46060-12-alexghiti%40rivosinc.com.
