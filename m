Return-Path: <kasan-dev+bncBDXY7I6V6AMRBPVC56YQMGQEIVAI5BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id D65898C04E0
	for <lists+kasan-dev@lfdr.de>; Wed,  8 May 2024 21:23:42 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-572af13b582sf4266a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 08 May 2024 12:23:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715196222; cv=pass;
        d=google.com; s=arc-20160816;
        b=KF4vP1zzlfPr2jVhsStZm9uJL/DU8woowrMZ+qI21SH/8fdU4ATNfWuJNS59yjfrt9
         bUnAUdWiiXjUm0yrOwEC8SNsxVEt/nS6x56/V/+5skftyD/qmHKT6/8Bq8Mt1ty6uIJr
         xX+X02VQUnYELzFrrkORkTRA0YUUplWjRgM8fIZFNXUGQpsWSduiPwYgqBHoBWwrNblF
         k2tY5osXxNbq7h4AZhG6HBJn8chlKMp6eZd/Cvo7GiCJaHn07h0HAaL3gUl6E+4q7jqh
         5YZZYGxLsMer8BJU4HHOcPgG4U4BCkwBoQ4NI8JgVH0h0RT6750mlVzQe6kAxENYXqjZ
         utrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=C9Z6nrig2ybUda0qb72Knza7OV9+8J+ndYovL5vcRaQ=;
        fh=eb5OtVU/3VogeaIorpALzGZwyDFiAOqyNAwy57KiqP0=;
        b=EynWYFQlo00CM9v/JT4vkqA7FK3ge3FjDGhQUr8OgViuci0iOWJchMvnck7pnTMY3R
         uuqBGVj0fCHrZd04u1VpHVWPhh7Xd5hsFPTQQ3njssTT6zW68BH570MQ09ycuY1fbMvc
         07j54JoHRgjqvVy6bI7QupHiZpviymM8mAa8ODhfMApqOgrZxkwFaqROz8NsuZLI24kO
         SuH6STwgDhUqwIEpMop1uiTlJj9wWi9lI2mieg39lDeuRZ0NtNsCeEWAa9DUAlIeRj+i
         1pyJ4tjgRqIH1q/ezezOwIAS8PVg9Zu67NRWAU5jB/Cctd8CLptohWcmY9qhRR8wCQR/
         gfGQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b="Lv/cCeMk";
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715196222; x=1715801022; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=C9Z6nrig2ybUda0qb72Knza7OV9+8J+ndYovL5vcRaQ=;
        b=SArsolQ+vav4g6LKO79xjXxtJCGi9hQgjjGngYc/TsYjj436g36CUewZZ5smqIxi1F
         a6IiwN78Qh/DBWgJHvodZswZPN/FTAUkWmMFlz7ioFdqC8u9J9tcPDD5hzYDBXUnAMOo
         QnW1J5CL/qrxxn9U70/XC6r0/SW9HtXDmVbcysMQOu8HKpp2DuZZiE4n3hh7JDr3Vh9h
         CoMOS9KyYstEOCifMnXjS3ZJ5IeNhBsEXFi93NIisJc1YQ9Sl8dbkKwBEGg+WE2zp4Ap
         zmBiDYUdvsbYW3+yth2TRocivyvNgXC8MFmfK4m9sVH1JMT4Us5NgQm1gDqFrsMIiJxi
         MEsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715196222; x=1715801022;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=C9Z6nrig2ybUda0qb72Knza7OV9+8J+ndYovL5vcRaQ=;
        b=Hi4vraiNmUKaQFIwWqN+qnJB6BcxU/JfB+ISOvLuJa5hUth0dSaDr/djE3qb8SG5dB
         plpOBEyNovV7LSdDj3MSWsuTT/0XZyAMb0qqb+dmkNzlXfhPUCoMAMKvd/7/a7VQFjRu
         sqxuHxyRsTSsIUpGmrQJpXl26xlCeq4gGOZQFUybcLomMFspgp37tp5yB36iCntNKBbz
         sLeTDyGouv8sPzQdIb6lwOvxjto2cJTWtDyeHPE+JW7noM1KYLyIcLgZUNYsowwjFZAi
         LM8PlJQ88XgnzUCsZr8eAioXFi5+ofWGt4Q9ihEI4eEvTDj1PBdWu3ziTx7aM8cEPY5m
         YZCg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXVs6z8m91U/F89p42ZWM6OufX+POYeiAcBfT83sFlrwW437Mgjb7NjysuereGmSQ5JwIdY926XLrw05K+MLoDee+OzH3X9LQ==
X-Gm-Message-State: AOJu0Yzu5zm/8gV8WBmFWvZGaY6Vzfzxl3B0HhO/pS36f+6N7Z5onDK9
	7if0anLCdro6AKCZf80Pcp+g8qE0vTxz6o3IQgcT0up2FXQNadVC
X-Google-Smtp-Source: AGHT+IErJGcIaqZO7tBB/0EuXxUz4b2DhMgTiAVonk3DJQtYQPIbOM6SK5jJq2mFQW0xg/IPKCv7PA==
X-Received: by 2002:a05:6402:1763:b0:572:554b:ec66 with SMTP id 4fb4d7f45d1cf-57334b922acmr16899a12.3.1715196222350;
        Wed, 08 May 2024 12:23:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3222:b0:572:3ac4:56ed with SMTP id
 4fb4d7f45d1cf-57332e95b57ls115118a12.0.-pod-prod-00-eu; Wed, 08 May 2024
 12:23:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCURNiuWi7K65VcQ+JC3ch1CUZ4i+NWTkjNr4KZslEtrJyJHCpP1oYtM4hqPDfI9VSR1m2WOipd9Y2uXmybXmI7KxyaAJGl8PO2ToA==
X-Received: by 2002:a17:906:7748:b0:a59:92b0:e0d3 with SMTP id a640c23a62f3a-a5a118c5393mr36463666b.34.1715196220583;
        Wed, 08 May 2024 12:23:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715196220; cv=none;
        d=google.com; s=arc-20160816;
        b=ZSBVi5jgUE7hbqmk/MDzUQhCQ6EfRJ7iCrSX+KWS4rRlcMTLVv+mPldULjVSneXTf/
         n0vQfXtvg/90c+j+fC1ozOtDX1AagjXeyLOZ6vX47wWa1pWajoAKaWlLAaNHEi0++aLT
         nVfqaSpqUtxwVp0tUN0T5PMBAOqqIvFcwyxyH+sU5fgqkGCkxPJ1uWKxcRxD0jZ3pR3V
         Mq3C5XtjYOeSYkCgHdoZd+wLnmyG2SmHjdMQgPYZXr6CqrlHF7N2Yz7GRarsNnnN/enQ
         M533ilRsNKPFGvq6MdwbPz6eTOT4mIblYOtfZdrLkuZ/8dVpNQ1HB8DfEhaoeX1jyXmg
         FRTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=99tlcIPBJBGOnw31Oe30kKMBjt8TwvO6BCavKhZeDaw=;
        fh=M0fYv4RD2ASzlmxZdo8C58CSJH1lOl1QMaWajH2dgKM=;
        b=L/YbstM67WiniHK9g6mGUAHJzRooYc1EdSOwpwJ9uwBifn6M/0ezNnSqTRz5qrZbQZ
         sb7oYLHu4JZF/kT9xuDiAsPgtluytYLzqYXCOq+zwzFbOZXW0fhn4PLz/JVxd/39+QAj
         HhjHoa7MsK6E2qzUZMvNwKcUTrpN7GkisLF6RbnZxj2aCubPwrNrwnCBGBcF1IMm08UF
         JYr31vwGQ3/Lme+9uxTZOL+X0GvBFgKO0Bapt8KAIObaXWUCdOwx/Xi/ARX++2Scz2DT
         rRKAGILNHq+wSfslDAQlGWF4T7JoUXPrxxNxZtaTCwrrYAmDPYYS0s449MrrWndIhdgX
         wygw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b="Lv/cCeMk";
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id f12-20020a0564021e8c00b005727dc54dfbsi397976edf.3.2024.05.08.12.23.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 May 2024 12:23:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-41ebcf01013so855145e9.0
        for <kasan-dev@googlegroups.com>; Wed, 08 May 2024 12:23:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCURb+WNPL7CW/tBD3agYVxRBnqFF4FLGbPN3joUJvPLMHKOLTGJ8uI/mQPtN5sB9exZg6XlJsyIAV4z8lcZjtQv1GunSs9f0upTUw==
X-Received: by 2002:a05:600c:3ca9:b0:41b:ed36:e055 with SMTP id 5b1f17b1804b1-41fbcb4b4fbmr4761445e9.7.1715196220131;
        Wed, 08 May 2024 12:23:40 -0700 (PDT)
Received: from alex-rivos.ba.rivosinc.com (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-41f42e74625sm47255965e9.0.2024.05.08.12.23.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 May 2024 12:23:39 -0700 (PDT)
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
Subject: [PATCH 04/12] mm, riscv, arm64: Use common ptep_get_lockless() function
Date: Wed,  8 May 2024 21:19:23 +0200
Message-Id: <20240508191931.46060-5-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20240508191931.46060-1-alexghiti@rivosinc.com>
References: <20240508191931.46060-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b="Lv/cCeMk";       spf=pass (google.com: domain of
 alexghiti@rivosinc.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

Make riscv use the contpte aware ptep_get_lockless() function from arm64.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/arm64/include/asm/pgtable.h | 11 +----
 arch/arm64/mm/contpte.c          | 57 --------------------------
 arch/riscv/include/asm/pgtable.h |  2 +
 include/linux/contpte.h          |  1 +
 mm/contpte.c                     | 69 ++++++++++++++++++++++++++++++++
 5 files changed, 73 insertions(+), 67 deletions(-)

diff --git a/arch/arm64/include/asm/pgtable.h b/arch/arm64/include/asm/pgtable.h
index e85b3a052a02..8a0603257436 100644
--- a/arch/arm64/include/asm/pgtable.h
+++ b/arch/arm64/include/asm/pgtable.h
@@ -1384,7 +1384,6 @@ extern void ptep_modify_prot_commit(struct vm_area_struct *vma,
  * where it is possible and makes sense to do so. The PTE_CONT bit is considered
  * a private implementation detail of the public ptep API (see below).
  */
-extern pte_t contpte_ptep_get_lockless(pte_t *orig_ptep);
 extern void contpte_clear_full_ptes(struct mm_struct *mm, unsigned long addr,
 				pte_t *ptep, unsigned int nr, int full);
 extern pte_t contpte_get_and_clear_full_ptes(struct mm_struct *mm,
@@ -1430,16 +1429,8 @@ static inline unsigned int pte_batch_hint(pte_t *ptep, pte_t pte)
 extern pte_t ptep_get(pte_t *ptep);
 #define ptep_get ptep_get
 
+extern pte_t ptep_get_lockless(pte_t *ptep);
 #define ptep_get_lockless ptep_get_lockless
-static inline pte_t ptep_get_lockless(pte_t *ptep)
-{
-	pte_t pte = __ptep_get(ptep);
-
-	if (likely(!pte_valid_cont(pte)))
-		return pte;
-
-	return contpte_ptep_get_lockless(ptep);
-}
 
 static inline void set_pte(pte_t *ptep, pte_t pte)
 {
diff --git a/arch/arm64/mm/contpte.c b/arch/arm64/mm/contpte.c
index e225e458856e..5e9e40145085 100644
--- a/arch/arm64/mm/contpte.c
+++ b/arch/arm64/mm/contpte.c
@@ -28,63 +28,6 @@ static void contpte_try_unfold_partial(struct mm_struct *mm, unsigned long addr,
 	}
 }
 
-pte_t contpte_ptep_get_lockless(pte_t *orig_ptep)
-{
-	/*
-	 * The ptep_get_lockless() API requires us to read and return *orig_ptep
-	 * so that it is self-consistent, without the PTL held, so we may be
-	 * racing with other threads modifying the pte. Usually a READ_ONCE()
-	 * would suffice, but for the contpte case, we also need to gather the
-	 * access and dirty bits from across all ptes in the contiguous block,
-	 * and we can't read all of those neighbouring ptes atomically, so any
-	 * contiguous range may be unfolded/modified/refolded under our feet.
-	 * Therefore we ensure we read a _consistent_ contpte range by checking
-	 * that all ptes in the range are valid and have CONT_PTE set, that all
-	 * pfns are contiguous and that all pgprots are the same (ignoring
-	 * access/dirty). If we find a pte that is not consistent, then we must
-	 * be racing with an update so start again. If the target pte does not
-	 * have CONT_PTE set then that is considered consistent on its own
-	 * because it is not part of a contpte range.
-	 */
-
-	pgprot_t orig_prot;
-	unsigned long pfn;
-	pte_t orig_pte;
-	pgprot_t prot;
-	pte_t *ptep;
-	pte_t pte;
-	int i;
-
-retry:
-	orig_pte = __ptep_get(orig_ptep);
-
-	if (!pte_valid_cont(orig_pte))
-		return orig_pte;
-
-	orig_prot = pte_pgprot(pte_mkold(pte_mkclean(orig_pte)));
-	ptep = arch_contpte_align_down(orig_ptep);
-	pfn = pte_pfn(orig_pte) - (orig_ptep - ptep);
-
-	for (i = 0; i < CONT_PTES; i++, ptep++, pfn++) {
-		pte = __ptep_get(ptep);
-		prot = pte_pgprot(pte_mkold(pte_mkclean(pte)));
-
-		if (!pte_valid_cont(pte) ||
-		   pte_pfn(pte) != pfn ||
-		   pgprot_val(prot) != pgprot_val(orig_prot))
-			goto retry;
-
-		if (pte_dirty(pte))
-			orig_pte = pte_mkdirty(orig_pte);
-
-		if (pte_young(pte))
-			orig_pte = pte_mkyoung(orig_pte);
-	}
-
-	return orig_pte;
-}
-EXPORT_SYMBOL_GPL(contpte_ptep_get_lockless);
-
 void contpte_clear_full_ptes(struct mm_struct *mm, unsigned long addr,
 				pte_t *ptep, unsigned int nr, int full)
 {
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index ebfe6b16529e..62cad1b974f1 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -785,6 +785,8 @@ static inline int ptep_clear_flush_young(struct vm_area_struct *vma,
 
 extern pte_t ptep_get(pte_t *ptep);
 #define ptep_get ptep_get
+extern pte_t ptep_get_lockless(pte_t *ptep);
+#define ptep_get_lockless ptep_get_lockless
 extern void set_ptes(struct mm_struct *mm, unsigned long addr,
 		     pte_t *ptep, pte_t pteval, unsigned int nr);
 #define set_ptes set_ptes
diff --git a/include/linux/contpte.h b/include/linux/contpte.h
index 54d10204e9af..01da4bfc3af6 100644
--- a/include/linux/contpte.h
+++ b/include/linux/contpte.h
@@ -8,6 +8,7 @@
  * a private implementation detail of the public ptep API (see below).
  */
 pte_t contpte_ptep_get(pte_t *ptep, pte_t orig_pte);
+pte_t contpte_ptep_get_lockless(pte_t *orig_ptep);
 void __contpte_try_fold(struct mm_struct *mm, unsigned long addr,
 			pte_t *ptep, pte_t pte);
 void contpte_try_fold(struct mm_struct *mm, unsigned long addr,
diff --git a/mm/contpte.c b/mm/contpte.c
index 566745d7842f..060e0bc1a2a3 100644
--- a/mm/contpte.c
+++ b/mm/contpte.c
@@ -42,6 +42,7 @@
  *   - huge_ptep_clear_flush()
  *   - ptep_get()
  *   - set_ptes()
+ *   - ptep_get_lockless()
  */
 
 pte_t huge_ptep_get(pte_t *ptep)
@@ -589,4 +590,72 @@ __always_inline void set_ptes(struct mm_struct *mm, unsigned long addr,
 		contpte_set_ptes(mm, addr, ptep, pte, nr);
 	}
 }
+
+pte_t contpte_ptep_get_lockless(pte_t *orig_ptep)
+{
+	/*
+	 * The ptep_get_lockless() API requires us to read and return *orig_ptep
+	 * so that it is self-consistent, without the PTL held, so we may be
+	 * racing with other threads modifying the pte. Usually a READ_ONCE()
+	 * would suffice, but for the contpte case, we also need to gather the
+	 * access and dirty bits from across all ptes in the contiguous block,
+	 * and we can't read all of those neighbouring ptes atomically, so any
+	 * contiguous range may be unfolded/modified/refolded under our feet.
+	 * Therefore we ensure we read a _consistent_ contpte range by checking
+	 * that all ptes in the range are valid and have CONT_PTE set, that all
+	 * pfns are contiguous and that all pgprots are the same (ignoring
+	 * access/dirty). If we find a pte that is not consistent, then we must
+	 * be racing with an update so start again. If the target pte does not
+	 * have CONT_PTE set then that is considered consistent on its own
+	 * because it is not part of a contpte range.
+	 */
+
+	pgprot_t orig_prot;
+	unsigned long pfn;
+	pte_t orig_pte;
+	pgprot_t prot;
+	pte_t *ptep;
+	pte_t pte;
+	int i, ncontig;
+
+retry:
+	orig_pte = __ptep_get(orig_ptep);
+
+	if (!pte_valid_cont(orig_pte))
+		return orig_pte;
+
+	orig_prot = pte_pgprot(pte_mkold(pte_mkclean(orig_pte)));
+	ptep = arch_contpte_align_down(orig_ptep);
+	ncontig = arch_contpte_get_num_contig(NULL, 0, ptep, 0, NULL);
+	pfn = pte_pfn(orig_pte) - (orig_ptep - ptep);
+
+	for (i = 0; i < ncontig; i++, ptep++, pfn++) {
+		pte = __ptep_get(ptep);
+		prot = pte_pgprot(pte_mkold(pte_mkclean(pte)));
+
+		if (!pte_valid_cont(pte) ||
+				pte_pfn(pte) != pfn ||
+				pgprot_val(prot) != pgprot_val(orig_prot))
+			goto retry;
+
+		if (pte_dirty(pte))
+			orig_pte = pte_mkdirty(orig_pte);
+
+		if (pte_young(pte))
+			orig_pte = pte_mkyoung(orig_pte);
+	}
+
+	return orig_pte;
+}
+EXPORT_SYMBOL_GPL(contpte_ptep_get_lockless);
+
+__always_inline pte_t ptep_get_lockless(pte_t *ptep)
+{
+	pte_t pte = __ptep_get(ptep);
+
+	if (likely(!pte_valid_cont(pte)))
+		return pte;
+
+	return contpte_ptep_get_lockless(ptep);
+}
 #endif /* CONFIG_THP_CONTPTE */
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240508191931.46060-5-alexghiti%40rivosinc.com.
