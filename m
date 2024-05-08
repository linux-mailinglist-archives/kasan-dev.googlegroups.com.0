Return-Path: <kasan-dev+bncBDXY7I6V6AMRBOFD56YQMGQE3YJS7UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 360688C04ED
	for <lists+kasan-dev@lfdr.de>; Wed,  8 May 2024 21:25:46 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2e2288e5aebsf231331fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 08 May 2024 12:25:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715196345; cv=pass;
        d=google.com; s=arc-20160816;
        b=CvzFIJN0af079/Q7r2yOJLjnPB8XLkAyvZZ3wQyvwaje93kdzBRq5/TsdjlGLaaSX4
         EZzgSWh4h/7w1mRZqGDsvmNgJSTQCcQmreRoZmtFICa8xV/eEuBSAdbjHvV47rlm7yZx
         gAu+OH5mmuFm9Uf2t8eqqtu/R6D7xsK4WiLyF9WaTrXlKEA5oYwkQJCfKFCsCVzcAYA4
         ZOZ7iE3tq+/wmFcCvsyESLgc9pr4P+lr81UKE9TEgs42kpM5kd9GdJdZChKphas9snqR
         dP2FvYBaSK1PJttDhi9iyMAmXr3mDgKykDV2ulJ7k+B3p3cObwkDhLjh+aiOT9bO1dw0
         yPOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Jj12gDl0yIoPaJUVteNMvth2SrtRrYlRhlDdJVT/YPE=;
        fh=51++E9+wQSx98DDhnZG4nmkXqk6TZTTG6glKnT/r0nE=;
        b=QmV//xPT+jgXrUt1Jx/mguvSxKmXmtwY/au+0wOrteyKeoEXdXRRaasUcq4zzGAReN
         2o+VOqf+O7H3pQlwUd9bQwjU23LECClKbpr7zabvdnkG18FPacmh8D9YT6otMse5FHF5
         gdfrB1lN5ppYA+KW6GBMZbivRwPY14BPGGnBLvk1O3f+yAIGc1Bjf17e1daNsW26sfFn
         hy4I3q54RsyCBjaVK3LxlvGPQXDenYzW27Bgub6+oQcDC0MjDW7ZZFKmolzPlnbwQQdX
         7me64ul2Czurxw8Ut0oOPvtduc3SjaAM8WO3/Y7HLHYkZyeehk2LZjiQ4UoBqnSbkJWq
         PROw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=K+kX0Egk;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715196345; x=1715801145; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Jj12gDl0yIoPaJUVteNMvth2SrtRrYlRhlDdJVT/YPE=;
        b=SRDVkiINBMb6fwJ0IrcEozUiX6dUpptFHkp7uHwdJF4NTjhfrSl8hSjt3pTykCie3N
         jt+dDJ/uJJjnamIf+Yxws1RswY5qN0/C1T0p6K17fwYRmg27gKacwQBLxPbQqpU/EEhT
         IXEom7FKjoyLGBuHuur0X7XcdyRZeYjKB9yJEzGo3sCvZ8fcECIBNDQNLe9yMoiL/5RD
         rCIsoCp2htQSncXyeKS+SljjG6S7zVardWjTrsz5GtpCM3MknntxqnkMl3OybI8NkIuf
         a5Kx9VbLR6p19et2yCUmZGrwVRBaR1Vdv1+s3X0kcYr8EWzbwi3jLGBaorOZSgJeMWyA
         fbGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715196345; x=1715801145;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Jj12gDl0yIoPaJUVteNMvth2SrtRrYlRhlDdJVT/YPE=;
        b=FHTMYNVW9Bi7NQ6FgGxvfE1xdUXPq8h7TA6hcb33d+fpaCTT5JTLN4g8XjaxdNJJS5
         X/R4ClXzOLMwPNG9YKHAaPhK2ROBsAOkbtf4bUlC+nUBbwsWJwUNGRdcR1+fVp661THx
         zAncD2Y8Z1AkPaMawklOJcRCqv3Jh9kq/ssrD0ELoYuUqP9qtvAgXjRhQyfa2Q8SPVEL
         paeTmrLgnt4L91CVqy1+KvWndlOLBRKzJGIAzUZX/wkjXhv8DQ2SmHothJubo8vX58hS
         VAAwdqBoXfLXHFL5iiJXm0+7MFpNIrWtvfeohbl0uJIdV3qnWvdKWPjzkeLzUR9mNWCY
         C/AA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXWk9Tmw6WBm56MGneMz8Pqc3rdpojNzclBXTT3hdz8B0/2PL0v7dkd0Xs//xNgcRj0f/tNnV724OP++3He+vSbEG4vcZiFJw==
X-Gm-Message-State: AOJu0Yw1iEGl+8m0KfAbedRqf0WeBaTAxG/J6GfAcZ5yG5I/DPsgELT5
	Tow2/RZewEzLjoom92QSpwSOncqwKYQ7sg1aCfPC7s5eJlur/4B4
X-Google-Smtp-Source: AGHT+IHEXNyvUkBRpOU3Uifu5n2O7wGiY1Haub3Ys2t8X3d+GQovxX5oUXqvblHj23kicDz7c3uCLw==
X-Received: by 2002:a2e:9610:0:b0:2df:4bad:cb7f with SMTP id 38308e7fff4ca-2e446e7fecamr21153401fa.2.1715196344996;
        Wed, 08 May 2024 12:25:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c8a:b0:418:1a07:de36 with SMTP id
 5b1f17b1804b1-41fc20ed206ls460665e9.2.-pod-prod-07-eu; Wed, 08 May 2024
 12:25:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWC+fL9xo0K0rUTV2MEPT5FAh/5imNZaldQ0nQw8V5CTqdgT2n3TL3rUds7tkzmpWo1FHcpfD/f2kMtyXBuIATZ2N9+s7WGRO2fyQ==
X-Received: by 2002:a05:600c:5808:b0:41b:cc7d:1207 with SMTP id 5b1f17b1804b1-41f71ec26abmr28617665e9.19.1715196343238;
        Wed, 08 May 2024 12:25:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715196343; cv=none;
        d=google.com; s=arc-20160816;
        b=JfUYFUNOlbafm7iW7sMv/TYD98jpdbfL2byDW3JaysQRMMXLsdzPs+bvTe8ZJi7a7Q
         uZD11H2rPMJRCm7lP6mosGCAQSoq15K3Wf+vYg4CMcMCbEgeOto/KcwcLIo+qFIH0G6e
         5IhLN4U3oF61W4CDyJXQCU8GmmsixKGuPjtaZ5p6RCaAkNkrMeolGbd1/AaGSYoJ0g4V
         ak0lClCXifYLk/fxRCjMyAShNjsmy1dmyjCtiy72KlWkqmPXe9Y67edaxqsi36F5vGMp
         xp/W9mNWKf3+V24kIZb1iSknB9u3BsU9TvDKlPa7kk8hO885VwgqoJlfa9ohLui2cwdd
         RFyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Nb289X82Pwy2psbtYSkuOYlUdcLMn+kmFJiTkQU5Z+c=;
        fh=zWkPbqksS01xIy7nkHgx7beN/oDeOMetrRh9OVWaa5I=;
        b=s6VW+oqkuBFSPyMkGY4lux14ixg9Fjf7FPoWA+iiddiSKmN2thmXugaUnNYizuTNvd
         uKuzkxQYBvU/8RNHJx040PGBlFJFV0mXjEP3KadLnp5j8ulvjodIPlnycrlVXN2n7INl
         0oMiYZqFFzizePoCHq4Ly4TtC0TkFzl/9xcv5doA01Xtt8+MJj8epgPGjY4VsMZ2xknD
         RVGDt3enO6bAkx+QJMtDWE+UBtCY/wvsdvLVINdnZ1hGbnTbqr7B+lqMTCd7zG+LA3PN
         B5K7EBghkzjOJ2BY7fmhKxLdDqhF8+cZ2HbLo9soqBZCytQAnctMDoAlB1IFm1VvAtez
         69Zw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=K+kX0Egk;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-41f4d07597csi1454255e9.1.2024.05.08.12.25.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 May 2024 12:25:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-41c1b75ca31so452425e9.2
        for <kasan-dev@googlegroups.com>; Wed, 08 May 2024 12:25:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUAX32o2IlpdTZG2EUQvsqjDAJH0Zr9ov5c2q02OZQrlXCP9oHbR8SvLJIQRnBFgawSyp1xNfU1klJcCd6hKlH6ux9hyO87rtJPJw==
X-Received: by 2002:adf:a492:0:b0:343:a368:f792 with SMTP id ffacd0b85a97d-34fca621315mr2849241f8f.52.1715196342717;
        Wed, 08 May 2024 12:25:42 -0700 (PDT)
Received: from alex-rivos.ba.rivosinc.com (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id b12-20020a5d4d8c000000b0034e65b8b43fsm14038517wru.8.2024.05.08.12.25.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 May 2024 12:25:42 -0700 (PDT)
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
Subject: [PATCH 06/12] mm, riscv, arm64: Use common pte_clear() function
Date: Wed,  8 May 2024 21:19:25 +0200
Message-Id: <20240508191931.46060-7-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20240508191931.46060-1-alexghiti@rivosinc.com>
References: <20240508191931.46060-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=K+kX0Egk;       spf=pass (google.com: domain of alexghiti@rivosinc.com
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

Make riscv use the contpte aware pte_clear() function from arm64.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/arm64/include/asm/pgtable.h | 9 +++------
 arch/riscv/include/asm/pgtable.h | 4 +++-
 arch/riscv/mm/init.c             | 2 +-
 mm/contpte.c                     | 6 ++++++
 4 files changed, 13 insertions(+), 8 deletions(-)

diff --git a/arch/arm64/include/asm/pgtable.h b/arch/arm64/include/asm/pgtable.h
index bb6210fb72c8..74e582f2884f 100644
--- a/arch/arm64/include/asm/pgtable.h
+++ b/arch/arm64/include/asm/pgtable.h
@@ -1439,12 +1439,9 @@ extern void set_ptes(struct mm_struct *mm, unsigned long addr,
 		     pte_t *ptep, pte_t pte, unsigned int nr);
 #define set_ptes set_ptes
 
-static inline void pte_clear(struct mm_struct *mm,
-				unsigned long addr, pte_t *ptep)
-{
-	contpte_try_unfold(mm, addr, ptep, __ptep_get(ptep));
-	__pte_clear(mm, addr, ptep);
-}
+extern void pte_clear(struct mm_struct *mm,
+		      unsigned long addr, pte_t *ptep);
+#define pte_clear pte_clear
 
 #define clear_full_ptes clear_full_ptes
 static inline void clear_full_ptes(struct mm_struct *mm, unsigned long addr,
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index 4f8f673787e7..41534f4b8a6d 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -792,18 +792,20 @@ extern void set_ptes(struct mm_struct *mm, unsigned long addr,
 #define set_ptes set_ptes
 extern void set_pte(pte_t *ptep, pte_t pte);
 #define set_pte set_pte
+extern void pte_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep);
+#define pte_clear pte_clear
 
 #else /* CONFIG_THP_CONTPTE */
 
 #define ptep_get		__ptep_get
 #define set_ptes		__set_ptes
 #define set_pte			__set_pte
+#define pte_clear		__pte_clear
 
 #endif /* CONFIG_THP_CONTPTE */
 
 #define __HAVE_ARCH_PTEP_GET_AND_CLEAR
 #define ptep_get_and_clear	__ptep_get_and_clear
-#define pte_clear		__pte_clear
 #define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
 #define ptep_set_access_flags	__ptep_set_access_flags
 #define __HAVE_ARCH_PTEP_SET_WRPROTECT
diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index bb5c6578204c..c82f17b3060b 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -327,7 +327,7 @@ void __set_fixmap(enum fixed_addresses idx, phys_addr_t phys, pgprot_t prot)
 	if (pgprot_val(prot))
 		__set_pte(ptep, pfn_pte(phys >> PAGE_SHIFT, prot));
 	else
-		pte_clear(&init_mm, addr, ptep);
+		__pte_clear(&init_mm, addr, ptep);
 	local_flush_tlb_page(addr);
 }
 
diff --git a/mm/contpte.c b/mm/contpte.c
index 543ae5b5a863..c9eff6426ca0 100644
--- a/mm/contpte.c
+++ b/mm/contpte.c
@@ -45,6 +45,7 @@
  *   - set_ptes()
  *   - ptep_get_lockless()
  *   - set_pte()
+ *   - pte_clear()
  */
 
 pte_t huge_ptep_get(pte_t *ptep)
@@ -676,4 +677,9 @@ void set_pte(pte_t *ptep, pte_t pte)
 	__set_pte(ptep, pte_mknoncont(pte));
 }
 
+void pte_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
+{
+	contpte_try_unfold(mm, addr, ptep, __ptep_get(ptep));
+	__pte_clear(mm, addr, ptep);
+}
 #endif /* CONFIG_THP_CONTPTE */
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240508191931.46060-7-alexghiti%40rivosinc.com.
