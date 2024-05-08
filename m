Return-Path: <kasan-dev+bncBDXY7I6V6AMRBJ5G56YQMGQE2JZYFVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DFB48C0510
	for <lists+kasan-dev@lfdr.de>; Wed,  8 May 2024 21:31:53 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-41dc9c831acsf5978855e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 08 May 2024 12:31:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715196713; cv=pass;
        d=google.com; s=arc-20160816;
        b=qE7PuthewQT38dIZTJLuISKmUYiy+AjwlJ3kCc4Yz4q5kA+0kD+esmAKDwS3ksuWlD
         vr5ZiS6XXU5Jlf85BxBcPqas1jqWh7Ga9nXvPsE23YmKIBkad6z/lpYSm5/dScXabXNX
         mMQtse5fMMayskNakwegTNEV0pF3OqisPSvRtlvpbX41pwriAGHrcdz1ztc/WtQVO+WS
         46JtdQ3XY8PkRsOkbYwfNd+BtfS09qhp8Ypx2fUmnVQY1BPHejBJzGkEzZgqmJrcCFan
         fnb0DhB1eJJL8x4qCPpmMm1V9JStuM8Y+QdHeIDHInYBNFXBBdYE1kGNxauR96rZRV12
         Xo/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Xvp+VKYSYWsmDDtsez1QWSbb6aPEn1dtWozFIdswk/c=;
        fh=Ala2gLuT41Tz0GdbkHPxoXh0re9DODy4gHc8uACNSI0=;
        b=TE1C+qwccAjK50lAlgk96UcQKHoZg3GZBSCPdfKJUnvIl3AKQNB3lh4I89zUH8vHlQ
         B1yDOhiW2UukCpnu1yiOwcFunNnZv9t1a264rttj9ku2CH+IlFbgoaHySVvM5RXBjDzS
         LWebBMmMq04rbNDQzxUzSQ7Jy7lZObZvxmwTOKT5KJFccdgYImyIXYPSjfXHD5UYVTG+
         bcgdEMyAGCq8ZUZ558ofynkN8wQpawg7MaF3nn/g2Sg3xorjXtA9l4Wlhq+Hkh/RMQ3m
         QiBdMQYlu8Ye0GO9bRKTpZ4LYmfQBhGDDHgoK50nI+q/dQZ2m1WRIrHt/1GeeRVhiP+Q
         6juw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=ifgShe5x;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715196713; x=1715801513; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Xvp+VKYSYWsmDDtsez1QWSbb6aPEn1dtWozFIdswk/c=;
        b=wGCEgWQsoniUdXGK9FdHdblxWWBMP1s5YT888pkj8eqqCdkJS1mPRRy+H2z2hdDVD6
         micXn4H0GfaIVEdtN4XE0ZgOJiP83T/1Furos1fT8g0WIgaOO5wm2tJvNcdMiG0PQdZR
         dI4jvbq9iuGSQDd1QLT8XB/pAMHjjH+g0plc4OatKh1PhS/CMiNiVm59CdmOvj4i0g08
         E8+fpOX2V6os7X52PbTl3E2URVNrNIKYYjKlBgGa3uxMkZ+/TuZl+OhglA1cXtq73yXA
         +ZXnabt/lUoLtIWWzwK/qU6/4u2S5cAPsQm3UFa82aGXPxStgvMOBVM12GZiPNceiUdQ
         PS3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715196713; x=1715801513;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Xvp+VKYSYWsmDDtsez1QWSbb6aPEn1dtWozFIdswk/c=;
        b=Yg8mAFj6Onta2v/N1jASaO9BZDIZg/vPQnmmfl5dBA/oxrOAAsksa/F4UD1OFuAV7g
         MglUPJagVuvXYgcQgildLDYVN/zam8AqO+L7AyQxL2DLvRBwqLuQJXI0EAt1QRFNCxd1
         SwiHKjw1DCyhVpVi+WxofBzZarIaRl8PWDDSmkY2S7VfBbTIjsHXF1EUSNpvnAF8BYeQ
         C/cHrW5ERIYeKNZ1JAyj1Gbln3mZmUVWKjnwX5ijGd3s3z8zNrhVt6rPd+OjmcH1Llig
         cMjjwgWjmbsnKQ/GxdJ9JmbXz6dQ77mF5G5jaNcFMWWwKxEnH23sWkBCGHaqw8lSHZty
         8BeQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWnxiu7I7z/ag+BAIWjzfvso8EorArZea1Ek6nTFI0fX4ueJl8x/ttfe9LZnbPqqj1x9EK3g5hFkSxJ43aUVepHOeASdgoH9Q==
X-Gm-Message-State: AOJu0YyfQkTL3W+6vnrhJAsfHxhp2jfD32qHnfy0u8lwO/xySFVkmER2
	AQlduJtrWNSD29CXQs2383Q5bO7LdGR3OHwZBzzDZEKvDrDnnqs3
X-Google-Smtp-Source: AGHT+IH+sOeNFFR9S8TX/5T2bNaO4gG6m7SHw1tskwSo8APo75Bke2yqJ/pSxL3VnBpfCYgUc6e+HQ==
X-Received: by 2002:a05:600c:3b04:b0:418:f5a:580b with SMTP id 5b1f17b1804b1-41fbcfb8113mr4655035e9.18.1715196712174;
        Wed, 08 May 2024 12:31:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d25:b0:41a:4283:7397 with SMTP id
 5b1f17b1804b1-41fc22dded5ls466175e9.0.-pod-prod-00-eu; Wed, 08 May 2024
 12:31:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUVPIqLg0cb2PbsBhWZu2zz9odqH7h7363+OtMaPjT2r9koUB4q9JXqc+oHgZAbnEkIWgUQj2PzRfVuMh9Ixylkl3A6wvVLJBy4zA==
X-Received: by 2002:a05:600c:3585:b0:418:2ab6:7123 with SMTP id 5b1f17b1804b1-41fbcc5f63bmr5156405e9.10.1715196710414;
        Wed, 08 May 2024 12:31:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715196710; cv=none;
        d=google.com; s=arc-20160816;
        b=Tpnlr6kBNaoc3kd74ebiMnFv5JWnSZ65Jf20ZoPUU/BkJ+HmOZNw4oW/y5/ftT84oO
         LTfV9BVsRgUFNjKXF8by/mmShc2LTxXNnPAGh11DOIkyT6kSfLm/676QKKXdYkLVQHe6
         tlKvhTHmN8vQSu1W+ahEl8nW1vpHEBkf6l7A2aJHUHWYAAdDjyjPaats3HJ7LO8ZMhVk
         6SSI/Hb1lHv7DbLRnq2HYC+ES27Guv4UCTVRtj86ueZoe+Zq+FhhCFwx8LLAdvp8t+0v
         TMZZeBHU0o1/PshfyQi4JYJgiVJ5iWYPtxmTUORgYRhrIxi236XR3mgXWPfRFCY6eBxa
         ajCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3Mj4lZQ0sNzizek27x00kn2/PQ3ffbB6QFBBUZYNyzk=;
        fh=ZU0+XgIFW//yNdxAV4KZvuPZAlKOYgc/SmiVhmPvEbQ=;
        b=KX3f/9lnjMgvYbca8IrzkoBmeAasFxlsrKyFXh00SHalZhEJ6P9tBMr5CZ0wpY4LXx
         43uQdZXWONqZJOwX1DLz4RGU/16xkuRH299Q2ZiDOu+8zwCqXV2uqLtG6lactHN74SBS
         yHjLGE0SkkoZ2eYGYg4vOSuDGkHAyCfR4ruOnPD8XdB5Hl/bsOlFX3oa6X0Zo5jSBR5l
         /Oqjxl4aIw/93zblBDwHQIgF3+TaSOY2zq/H/oFoYkLmERH/BtNRnKkv0zinXhA/4A9q
         H3n0Zc4P1LBxk2K+i6hTEf0BbdyDLVoY3h4V23Rq+1oQ9WALM/wtv+hi4mPbdpCeYkSk
         W5JA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=ifgShe5x;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-41f4307e4cfsi2566115e9.0.2024.05.08.12.31.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 May 2024 12:31:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-34e0d47bd98so692618f8f.0
        for <kasan-dev@googlegroups.com>; Wed, 08 May 2024 12:31:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWYU5a9UyOCCX1ijgUXurqz8zA7cY05PEPou0RmUMtIjpJR5CIYx+goYg4gIiaB6At2HOoEbVDSn4sAKAkVJusRglfbKDKO5be+NQ==
X-Received: by 2002:adf:fe8a:0:b0:34c:fd92:3359 with SMTP id ffacd0b85a97d-350185d57e7mr489056f8f.21.1715196709811;
        Wed, 08 May 2024 12:31:49 -0700 (PDT)
Received: from alex-rivos.ba.rivosinc.com (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id s2-20020a5d4242000000b003472489d26fsm15924162wrr.19.2024.05.08.12.31.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 May 2024 12:31:49 -0700 (PDT)
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
Subject: [PATCH 12/12] mm, riscv, arm64: Use common get_and_clear_full_ptes()/clear_full_ptes() functions
Date: Wed,  8 May 2024 21:19:31 +0200
Message-Id: <20240508191931.46060-13-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20240508191931.46060-1-alexghiti@rivosinc.com>
References: <20240508191931.46060-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=ifgShe5x;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

Make riscv use the contpte aware get_and_clear_full_ptes()/clear_full_ptes()
function from arm64.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/arm64/include/asm/pgtable.h | 41 ++++------------------------
 arch/arm64/mm/Makefile           |  1 -
 arch/arm64/mm/contpte.c          | 46 -------------------------------
 arch/riscv/include/asm/pgtable.h | 39 ++++++++++++++++++++++++++
 include/linux/contpte.h          |  5 ++++
 mm/contpte.c                     | 47 ++++++++++++++++++++++++++++++++
 6 files changed, 96 insertions(+), 83 deletions(-)
 delete mode 100644 arch/arm64/mm/contpte.c

diff --git a/arch/arm64/include/asm/pgtable.h b/arch/arm64/include/asm/pgtable.h
index 162efd9647dd..f8a3159f9df0 100644
--- a/arch/arm64/include/asm/pgtable.h
+++ b/arch/arm64/include/asm/pgtable.h
@@ -1373,17 +1373,6 @@ extern void ptep_modify_prot_commit(struct vm_area_struct *vma,
 
 #ifdef CONFIG_THP_CONTPTE
 
-/*
- * The contpte APIs are used to transparently manage the contiguous bit in ptes
- * where it is possible and makes sense to do so. The PTE_CONT bit is considered
- * a private implementation detail of the public ptep API (see below).
- */
-extern void contpte_clear_full_ptes(struct mm_struct *mm, unsigned long addr,
-				pte_t *ptep, unsigned int nr, int full);
-extern pte_t contpte_get_and_clear_full_ptes(struct mm_struct *mm,
-				unsigned long addr, pte_t *ptep,
-				unsigned int nr, int full);
-
 #define pte_batch_hint pte_batch_hint
 static inline unsigned int pte_batch_hint(pte_t *ptep, pte_t pte)
 {
@@ -1428,34 +1417,14 @@ extern void pte_clear(struct mm_struct *mm,
 		      unsigned long addr, pte_t *ptep);
 #define pte_clear pte_clear
 
+extern void clear_full_ptes(struct mm_struct *mm, unsigned long addr,
+			    pte_t *ptep, unsigned int nr, int full);
 #define clear_full_ptes clear_full_ptes
-static inline void clear_full_ptes(struct mm_struct *mm, unsigned long addr,
-				pte_t *ptep, unsigned int nr, int full)
-{
-	if (likely(nr == 1)) {
-		contpte_try_unfold(mm, addr, ptep, __ptep_get(ptep));
-		__clear_full_ptes(mm, addr, ptep, nr, full);
-	} else {
-		contpte_clear_full_ptes(mm, addr, ptep, nr, full);
-	}
-}
 
+extern pte_t get_and_clear_full_ptes(struct mm_struct *mm,
+				     unsigned long addr, pte_t *ptep,
+				     unsigned int nr, int full);
 #define get_and_clear_full_ptes get_and_clear_full_ptes
-static inline pte_t get_and_clear_full_ptes(struct mm_struct *mm,
-				unsigned long addr, pte_t *ptep,
-				unsigned int nr, int full)
-{
-	pte_t pte;
-
-	if (likely(nr == 1)) {
-		contpte_try_unfold(mm, addr, ptep, __ptep_get(ptep));
-		pte = __get_and_clear_full_ptes(mm, addr, ptep, nr, full);
-	} else {
-		pte = contpte_get_and_clear_full_ptes(mm, addr, ptep, nr, full);
-	}
-
-	return pte;
-}
 
 #define __HAVE_ARCH_PTEP_GET_AND_CLEAR
 extern pte_t ptep_get_and_clear(struct mm_struct *mm,
diff --git a/arch/arm64/mm/Makefile b/arch/arm64/mm/Makefile
index 52a1b2082627..dbd1bc95967d 100644
--- a/arch/arm64/mm/Makefile
+++ b/arch/arm64/mm/Makefile
@@ -3,7 +3,6 @@ obj-y				:= dma-mapping.o extable.o fault.o init.o \
 				   cache.o copypage.o flush.o \
 				   ioremap.o mmap.o pgd.o mmu.o \
 				   context.o proc.o pageattr.o fixmap.o
-obj-$(CONFIG_THP_CONTPTE)	+= contpte.o
 obj-$(CONFIG_HUGETLB_PAGE)	+= hugetlbpage.o
 obj-$(CONFIG_PTDUMP_CORE)	+= ptdump.o
 obj-$(CONFIG_PTDUMP_DEBUGFS)	+= ptdump_debugfs.o
diff --git a/arch/arm64/mm/contpte.c b/arch/arm64/mm/contpte.c
deleted file mode 100644
index 1cef93b15d6e..000000000000
--- a/arch/arm64/mm/contpte.c
+++ /dev/null
@@ -1,46 +0,0 @@
-// SPDX-License-Identifier: GPL-2.0-only
-/*
- * Copyright (C) 2023 ARM Ltd.
- */
-
-#include <linux/mm.h>
-#include <linux/efi.h>
-#include <linux/export.h>
-#include <asm/tlbflush.h>
-
-static void contpte_try_unfold_partial(struct mm_struct *mm, unsigned long addr,
-					pte_t *ptep, unsigned int nr)
-{
-	/*
-	 * Unfold any partially covered contpte block at the beginning and end
-	 * of the range.
-	 */
-
-	if (ptep != arch_contpte_align_down(ptep) || nr < CONT_PTES)
-		contpte_try_unfold(mm, addr, ptep, __ptep_get(ptep));
-
-	if (ptep + nr != arch_contpte_align_down(ptep + nr)) {
-		unsigned long last_addr = addr + PAGE_SIZE * (nr - 1);
-		pte_t *last_ptep = ptep + nr - 1;
-
-		contpte_try_unfold(mm, last_addr, last_ptep,
-				   __ptep_get(last_ptep));
-	}
-}
-
-void contpte_clear_full_ptes(struct mm_struct *mm, unsigned long addr,
-				pte_t *ptep, unsigned int nr, int full)
-{
-	contpte_try_unfold_partial(mm, addr, ptep, nr);
-	__clear_full_ptes(mm, addr, ptep, nr, full);
-}
-EXPORT_SYMBOL_GPL(contpte_clear_full_ptes);
-
-pte_t contpte_get_and_clear_full_ptes(struct mm_struct *mm,
-				unsigned long addr, pte_t *ptep,
-				unsigned int nr, int full)
-{
-	contpte_try_unfold_partial(mm, addr, ptep, nr);
-	return __get_and_clear_full_ptes(mm, addr, ptep, nr, full);
-}
-EXPORT_SYMBOL_GPL(contpte_get_and_clear_full_ptes);
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index 728f31da5e6a..a4843bdfdb37 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -754,6 +754,37 @@ static inline pte_t __ptep_get_and_clear(struct mm_struct *mm,
 	return pte;
 }
 
+static inline void __clear_full_ptes(struct mm_struct *mm, unsigned long addr,
+				     pte_t *ptep, unsigned int nr, int full)
+{
+	for (;;) {
+		__ptep_get_and_clear(mm, addr, ptep);
+		if (--nr == 0)
+			break;
+		ptep++;
+		addr += PAGE_SIZE;
+	}
+}
+
+static inline pte_t __get_and_clear_full_ptes(struct mm_struct *mm,
+					      unsigned long addr, pte_t *ptep,
+					      unsigned int nr, int full)
+{
+	pte_t pte, tmp_pte;
+
+	pte = __ptep_get_and_clear(mm, addr, ptep);
+	while (--nr) {
+		ptep++;
+		addr += PAGE_SIZE;
+		tmp_pte = __ptep_get_and_clear(mm, addr, ptep);
+		if (pte_dirty(tmp_pte))
+			pte = pte_mkdirty(pte);
+		if (pte_young(tmp_pte))
+			pte = pte_mkyoung(pte);
+	}
+	return pte;
+}
+
 static inline void __ptep_set_wrprotect(struct mm_struct *mm,
 					unsigned long address, pte_t *ptep,
 					pte_t pte)
@@ -823,6 +854,13 @@ extern void ptep_set_wrprotect(struct mm_struct *mm,
 extern void wrprotect_ptes(struct mm_struct *mm, unsigned long addr,
 			   pte_t *ptep, unsigned int nr);
 #define wrprotect_ptes	wrprotect_ptes
+extern void clear_full_ptes(struct mm_struct *mm, unsigned long addr,
+			    pte_t *ptep, unsigned int nr, int full);
+#define clear_full_ptes	clear_full_ptes
+extern pte_t get_and_clear_full_ptes(struct mm_struct *mm,
+				     unsigned long addr, pte_t *ptep,
+				     unsigned int nr, int full);
+#define get_and_clear_full_ptes	get_and_clear_full_ptes
 
 #else /* CONFIG_THP_CONTPTE */
 
@@ -842,6 +880,7 @@ extern void wrprotect_ptes(struct mm_struct *mm, unsigned long addr,
 #define ptep_set_wrprotect(mm, addr, ptep)					\
 			__ptep_set_wrprotect(mm, addr, ptep, __ptep_get(ptep))
 #define wrprotect_ptes		__wrprotect_ptes
+#define clear_full_ptes		__clear_full_ptes
 
 #endif /* CONFIG_THP_CONTPTE */
 
diff --git a/include/linux/contpte.h b/include/linux/contpte.h
index d1439db1706c..b24554ebca41 100644
--- a/include/linux/contpte.h
+++ b/include/linux/contpte.h
@@ -28,5 +28,10 @@ int contpte_ptep_set_access_flags(struct vm_area_struct *vma,
 				  pte_t entry, int dirty);
 void contpte_wrprotect_ptes(struct mm_struct *mm, unsigned long addr,
 			    pte_t *ptep, unsigned int nr);
+void contpte_clear_full_ptes(struct mm_struct *mm, unsigned long addr,
+			     pte_t *ptep, unsigned int nr, int full);
+pte_t contpte_get_and_clear_full_ptes(struct mm_struct *mm,
+				      unsigned long addr, pte_t *ptep,
+				      unsigned int nr, int full);
 
 #endif /* _LINUX_CONTPTE_H */
diff --git a/mm/contpte.c b/mm/contpte.c
index fe36b6b1d20a..677344e0e3c3 100644
--- a/mm/contpte.c
+++ b/mm/contpte.c
@@ -51,6 +51,8 @@
  *   - ptep_clear_flush_young()
  *   - wrprotect_ptes()
  *   - ptep_set_wrprotect()
+ *   - clear_full_ptes()
+ *   - get_and_clear_full_ptes()
  */
 
 pte_t huge_ptep_get(pte_t *ptep)
@@ -905,4 +907,49 @@ __always_inline void ptep_set_wrprotect(struct mm_struct *mm,
 {
 	wrprotect_ptes(mm, addr, ptep, 1);
 }
+
+void contpte_clear_full_ptes(struct mm_struct *mm, unsigned long addr,
+			     pte_t *ptep, unsigned int nr, int full)
+{
+	contpte_try_unfold_partial(mm, addr, ptep, nr);
+	__clear_full_ptes(mm, addr, ptep, nr, full);
+}
+EXPORT_SYMBOL_GPL(contpte_clear_full_ptes);
+
+pte_t contpte_get_and_clear_full_ptes(struct mm_struct *mm,
+				      unsigned long addr, pte_t *ptep,
+				      unsigned int nr, int full)
+{
+	contpte_try_unfold_partial(mm, addr, ptep, nr);
+	return __get_and_clear_full_ptes(mm, addr, ptep, nr, full);
+}
+EXPORT_SYMBOL_GPL(contpte_get_and_clear_full_ptes);
+
+__always_inline void clear_full_ptes(struct mm_struct *mm, unsigned long addr,
+				     pte_t *ptep, unsigned int nr, int full)
+{
+	if (likely(nr == 1)) {
+		contpte_try_unfold(mm, addr, ptep, __ptep_get(ptep));
+		__clear_full_ptes(mm, addr, ptep, nr, full);
+	} else {
+		contpte_clear_full_ptes(mm, addr, ptep, nr, full);
+	}
+}
+
+__always_inline pte_t get_and_clear_full_ptes(struct mm_struct *mm,
+					      unsigned long addr, pte_t *ptep,
+					      unsigned int nr, int full)
+{
+	pte_t pte;
+
+	if (likely(nr == 1)) {
+		contpte_try_unfold(mm, addr, ptep, __ptep_get(ptep));
+		pte = __get_and_clear_full_ptes(mm, addr, ptep, nr, full);
+	} else {
+		pte = contpte_get_and_clear_full_ptes(mm, addr, ptep, nr, full);
+	}
+
+	return pte;
+}
+
 #endif /* CONFIG_THP_CONTPTE */
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240508191931.46060-13-alexghiti%40rivosinc.com.
