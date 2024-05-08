Return-Path: <kasan-dev+bncBDXY7I6V6AMRBM5E56YQMGQES6CRFWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id CC1598C04FB
	for <lists+kasan-dev@lfdr.de>; Wed,  8 May 2024 21:27:49 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-51f1c389ed0sf571641e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 08 May 2024 12:27:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715196469; cv=pass;
        d=google.com; s=arc-20160816;
        b=FIwLG2mDMmLhr6eVjRyC+GqY6/f+XAsFKiCAOUy6klwawW/XY2egcqICj6Z5IWm56c
         iG9OpJSg38173aU3UHGIgoLhxmfii0YaxW+nI/tvRG4qdW3rpaqHegBokpiBtV4Kxqhk
         uqeCrfXJTa0s/nwopckuJoNFPHSc+v6XK+Ssb67HEl2+3ZUevvHvctBQv7zfw9sfDXn2
         vLkRfznfB68IUs5c8zg3ug4/foRWM0UKKYYRg5giVNwI0ZuWEXvhnUItLPGabcqfXZN2
         HG+Lpf2EhokXnRROV234gdbMEHb+3+4utIuHB1HY7pVuizFDDo68SyV4UFR1wADxy/TL
         NZVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=TgjjBR+F9J19c9cLsHodur9X/rEPw/rgQbsuaFiS2cM=;
        fh=7DkxMw8BSQodFV+xx5IpAcP8zeHLyu27vjo9crg3aRc=;
        b=bcM+zy1mIFBk35J1vQpWJDSqsqzuy3pSAyyqOjrvy+eYWXL8uaRzm3kthIsxcc/dqn
         DiDzxQNbQXFEp47dMfJPbLdlxvjr38vwmDAfCNZTgClVWddd8REvnpKldqM7dRCDup+o
         GzoKI+rumPLafzB+HbUO3hdEAFvhI2wMQSfnbU1BaQuW4At1LiY7PpzZGY+1JxDsiZFq
         r54pgta4uYMkPVbQ7G5dLpLj3ZCqp+R33B2zmSl8Yt74yZQjSn907DJu6I2W/e+Zc2Lr
         S6o7t4dR3OW88P2SMX9zADeYhR1PLGiGnuAhxGI7kbxNAawxiZWYIc6TzxO3pk++aZLn
         Fg/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=H3q145hs;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715196469; x=1715801269; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TgjjBR+F9J19c9cLsHodur9X/rEPw/rgQbsuaFiS2cM=;
        b=kMcKjsgzHru6cwIhIoUnaTETfJMfDsQY+ZB4Y0TT5qvDvAO9VWhTHUmJAO97RG6FlZ
         5fHF4rLHWziyEbyNvsd6wAUXZDTRLp4AvBqHQ8zy5Umms0AQn+1MrlFup09EfNU9lY0O
         ZyCWGCQYax8MxNVyXe2ZTmtXuaZchdCmuwg/IUsiEelqkOly4R0kEgllQDQ5amcmMJ3I
         B0c6ihtRHzooyanQLmu4WkXwY3dM+8iYrxrhNLKikxjLLDZnR5MYszG9qLIDdweZP0+O
         o+B5DUyX6zKAvrLRIcbulZo/S0/Q9Q8jjf2aid6OJvO1D09s4Z/oxEeHDfvURnfrsR31
         +Ndw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715196469; x=1715801269;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TgjjBR+F9J19c9cLsHodur9X/rEPw/rgQbsuaFiS2cM=;
        b=VF+cMtigGiIzqak5Y1/L/phXshOtipo/ZB4wqhDnYOQ3O3VS+ziK/wPGA0nitfJgtW
         bWrXH6faUUcvQo/RE5Z0e8akzS4bC93nSw4xyqUM4cU5SRvhc8CG9kfmceBAlZr8v0ic
         afwcac9HmsupUm6GH8vzA+v8xYiEY0/9lJ9Dq3UG042BdJPNAckbPFD0nK4sUX4kuF5b
         VVLpCgdX5/MqvCpQPuRZc8f88ZSeiVgF/D+h42qBNLetjgBo5OaeAxMXgO8uHYzPuEug
         pF2QeAkf3DQlTG/ZRTPEdka3UMlVNz5HB3QQhDSYpudUa7KoNY5rwOAPmR71VEdtRW3Q
         8fhA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXGIT6C27I84Ceqfy6Klrhk0S/GXFDPFHGcmc/im+aqvo2nHNzEhIvqymHrh1mYiu8Gakvac0IZXbrjtPw+ar3sfPjVFb6uiQ==
X-Gm-Message-State: AOJu0YznrS1bGobmcncd0nprrhvtw+KKxnXvTQ/V4qIRV4uYwhafenNu
	xYYlc+EFdbyKf3evyccoR7lkaJV6tMp27GDj8m4zfj4/6MGh8sDQ
X-Google-Smtp-Source: AGHT+IE0JTfe88ZvXIi2dcfpX+E1R81eVxanfJV3dEGlqOMknEzs30tJrxUpk6mJEuXnAFrnU8EkgQ==
X-Received: by 2002:a19:5e1e:0:b0:51f:3f6c:f7d5 with SMTP id 2adb3069b0e04-521e0c445abmr153046e87.8.1715196468041;
        Wed, 08 May 2024 12:27:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1312:b0:520:399d:ae9b with SMTP id
 2adb3069b0e04-521e4c06effls34986e87.1.-pod-prod-00-eu; Wed, 08 May 2024
 12:27:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWz8bs5c1eOIqRAmNiDXYqwxukVkVF3x5/NeSGwfgKh80vlO0TvBlrnZRkhPhxAcCcv+pCUsAK75IsbvZtyHYAEVVZG2pcjkWYejA==
X-Received: by 2002:ac2:5d31:0:b0:521:50e8:2ab2 with SMTP id 2adb3069b0e04-521e0f61e60mr128513e87.13.1715196465852;
        Wed, 08 May 2024 12:27:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715196465; cv=none;
        d=google.com; s=arc-20160816;
        b=wV+X3u1WsLmts/L6PKNoKxZakojJ2WX9t4i4H2GPcA5ohgN7zbReKzpHnuLannu1RP
         Nj8N7ZMvi7vuUgEQNqpmK8/wAB8qMT7GLCkRDktWMp1lbTMzzXl3liNLlaH66vlSX4gF
         hIYNbXLn7CKlnSzj1GThKyavWsP7mcniMuOBktGMNQUIPCxPIaDdVnBbyAUispRNrLqw
         2TjwBbfaoMNQjpoHWFOJPOT4LW86pK6V0DOzpBRC5amA7i+yXpaeb5KVQ6O5wcIeDffd
         E42s+RqAiPoSsne+YXO3xcj0YVmzLOC//3IFlFAWFwgJfxi7g/JxqVFOryfWEXwA2+0R
         zDAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jcfQWqIQyCa6XQTZ9KciN3KqArzYv/m686IwSCSxNEA=;
        fh=XlAAp/KDWEsZwpQ/rCr+qf8ga5Dqath9N+Spro8nJMc=;
        b=ijH3gURdXNmMfMfJWxVEQkLQdNyc9JiPd2pJdeVwAs9Iq/iff5GoovqBzZKXjfrDfv
         yKllara7D/S+Mj1Dug74TVdmmpKd8OHNGdFkkfOrysa9l8gxnrLMl+ufweQgEVhwJzDg
         MWxtLaTT+LzUvbXxrEFbypdVPSAGyMm/X/7dkcvCaLi8g+NZSVQprN5lTFNwFwb0Yxoz
         +t9McBlUhOYQtplfspNONfgqBINrEjlZxmn0I6dNlP6kH6Hf5BGGllMYKaWozAkrUK5T
         M21ddIeWmabXiq6actUov0wGulPsQ70iKZcr8qKPwmoiRTAWtNIcrtxrfTQLi7e9uqyD
         Zusw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=H3q145hs;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id o18-20020ac24bd2000000b0051f4b748d3bsi445497lfq.11.2024.05.08.12.27.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 May 2024 12:27:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-41ba1ba55ffso795185e9.1
        for <kasan-dev@googlegroups.com>; Wed, 08 May 2024 12:27:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVdQBelySGxPjneJr4RV50necHmO2RcpU9oOU84LNBUCKMYjN1AsIeMVk7SLJtGUyfrvBKjCAennB4QEo9tCAEEPfzYxVLJIBog2w==
X-Received: by 2002:a05:600c:3103:b0:41b:f43b:e263 with SMTP id 5b1f17b1804b1-41fbc12bdcbmr5274575e9.0.1715196465070;
        Wed, 08 May 2024 12:27:45 -0700 (PDT)
Received: from alex-rivos.ba.rivosinc.com (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-41f87c24f8fsm33175985e9.15.2024.05.08.12.27.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 May 2024 12:27:44 -0700 (PDT)
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
Subject: [PATCH 08/12] mm, riscv, arm64: Use common ptep_test_and_clear_young() function
Date: Wed,  8 May 2024 21:19:27 +0200
Message-Id: <20240508191931.46060-9-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20240508191931.46060-1-alexghiti@rivosinc.com>
References: <20240508191931.46060-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=H3q145hs;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

Make riscv use the contpte aware ptep_test_and_clear_young() function from
arm64.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/arm64/include/asm/pgtable.h | 14 ++----------
 arch/arm64/mm/contpte.c          | 25 --------------------
 arch/riscv/include/asm/pgtable.h | 12 ++++++----
 arch/riscv/kvm/mmu.c             |  2 +-
 arch/riscv/mm/pgtable.c          |  2 +-
 include/linux/contpte.h          |  2 ++
 mm/contpte.c                     | 39 ++++++++++++++++++++++++++++++++
 7 files changed, 53 insertions(+), 43 deletions(-)

diff --git a/arch/arm64/include/asm/pgtable.h b/arch/arm64/include/asm/pgtable.h
index ff7fe1d9cabe..9a8702d1ad00 100644
--- a/arch/arm64/include/asm/pgtable.h
+++ b/arch/arm64/include/asm/pgtable.h
@@ -1389,8 +1389,6 @@ extern void contpte_clear_full_ptes(struct mm_struct *mm, unsigned long addr,
 extern pte_t contpte_get_and_clear_full_ptes(struct mm_struct *mm,
 				unsigned long addr, pte_t *ptep,
 				unsigned int nr, int full);
-extern int contpte_ptep_test_and_clear_young(struct vm_area_struct *vma,
-				unsigned long addr, pte_t *ptep);
 extern int contpte_ptep_clear_flush_young(struct vm_area_struct *vma,
 				unsigned long addr, pte_t *ptep);
 extern void contpte_wrprotect_ptes(struct mm_struct *mm, unsigned long addr,
@@ -1477,16 +1475,8 @@ extern pte_t ptep_get_and_clear(struct mm_struct *mm,
 				unsigned long addr, pte_t *ptep);
 
 #define __HAVE_ARCH_PTEP_TEST_AND_CLEAR_YOUNG
-static inline int ptep_test_and_clear_young(struct vm_area_struct *vma,
-				unsigned long addr, pte_t *ptep)
-{
-	pte_t orig_pte = __ptep_get(ptep);
-
-	if (likely(!pte_valid_cont(orig_pte)))
-		return __ptep_test_and_clear_young(vma, addr, ptep);
-
-	return contpte_ptep_test_and_clear_young(vma, addr, ptep);
-}
+extern int ptep_test_and_clear_young(struct vm_area_struct *vma,
+				unsigned long addr, pte_t *ptep);
 
 #define __HAVE_ARCH_PTEP_CLEAR_YOUNG_FLUSH
 static inline int ptep_clear_flush_young(struct vm_area_struct *vma,
diff --git a/arch/arm64/mm/contpte.c b/arch/arm64/mm/contpte.c
index 5e9e40145085..9bf471633ca4 100644
--- a/arch/arm64/mm/contpte.c
+++ b/arch/arm64/mm/contpte.c
@@ -45,31 +45,6 @@ pte_t contpte_get_and_clear_full_ptes(struct mm_struct *mm,
 }
 EXPORT_SYMBOL_GPL(contpte_get_and_clear_full_ptes);
 
-int contpte_ptep_test_and_clear_young(struct vm_area_struct *vma,
-					unsigned long addr, pte_t *ptep)
-{
-	/*
-	 * ptep_clear_flush_young() technically requires us to clear the access
-	 * flag for a _single_ pte. However, the core-mm code actually tracks
-	 * access/dirty per folio, not per page. And since we only create a
-	 * contig range when the range is covered by a single folio, we can get
-	 * away with clearing young for the whole contig range here, so we avoid
-	 * having to unfold.
-	 */
-
-	int young = 0;
-	int i;
-
-	ptep = arch_contpte_align_down(ptep);
-	addr = ALIGN_DOWN(addr, CONT_PTE_SIZE);
-
-	for (i = 0; i < CONT_PTES; i++, ptep++, addr += PAGE_SIZE)
-		young |= __ptep_test_and_clear_young(vma, addr, ptep);
-
-	return young;
-}
-EXPORT_SYMBOL_GPL(contpte_ptep_test_and_clear_young);
-
 int contpte_ptep_clear_flush_young(struct vm_area_struct *vma,
 					unsigned long addr, pte_t *ptep)
 {
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index 03cd640137ed..d39cb24c6c4a 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -739,8 +739,7 @@ static inline void __pte_clear(struct mm_struct *mm,
 
 extern int __ptep_set_access_flags(struct vm_area_struct *vma, unsigned long address,
 				   pte_t *ptep, pte_t entry, int dirty);
-#define __HAVE_ARCH_PTEP_TEST_AND_CLEAR_YOUNG	/* defined in mm/pgtable.c */
-extern int ptep_test_and_clear_young(struct vm_area_struct *vma, unsigned long address,
+extern int __ptep_test_and_clear_young(struct vm_area_struct *vma, unsigned long address,
 				     pte_t *ptep);
 
 static inline pte_t __ptep_get_and_clear(struct mm_struct *mm,
@@ -778,7 +777,7 @@ static inline int ptep_clear_flush_young(struct vm_area_struct *vma,
 	 * shouldn't really matter because there's no real memory
 	 * pressure for swapout to react to. ]
 	 */
-	return ptep_test_and_clear_young(vma, address, ptep);
+	return __ptep_test_and_clear_young(vma, address, ptep);
 }
 
 #ifdef CONFIG_THP_CONTPTE
@@ -797,6 +796,9 @@ extern void pte_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep);
 #define __HAVE_ARCH_PTEP_GET_AND_CLEAR
 extern pte_t ptep_get_and_clear(struct mm_struct *mm,
 				unsigned long addr, pte_t *ptep);
+#define __HAVE_ARCH_PTEP_TEST_AND_CLEAR_YOUNG
+extern int ptep_test_and_clear_young(struct vm_area_struct *vma,
+				     unsigned long addr, pte_t *ptep);
 
 #else /* CONFIG_THP_CONTPTE */
 
@@ -806,6 +808,8 @@ extern pte_t ptep_get_and_clear(struct mm_struct *mm,
 #define pte_clear		__pte_clear
 #define __HAVE_ARCH_PTEP_GET_AND_CLEAR
 #define ptep_get_and_clear	__ptep_get_and_clear
+#define __HAVE_ARCH_PTEP_TEST_AND_CLEAR_YOUNG
+#define ptep_test_and_clear_young	__ptep_test_and_clear_young
 
 #endif /* CONFIG_THP_CONTPTE */
 
@@ -987,7 +991,7 @@ static inline int pmdp_set_access_flags(struct vm_area_struct *vma,
 static inline int pmdp_test_and_clear_young(struct vm_area_struct *vma,
 					unsigned long address, pmd_t *pmdp)
 {
-	return ptep_test_and_clear_young(vma, address, (pte_t *)pmdp);
+	return __ptep_test_and_clear_young(vma, address, (pte_t *)pmdp);
 }
 
 #define __HAVE_ARCH_PMDP_HUGE_GET_AND_CLEAR
diff --git a/arch/riscv/kvm/mmu.c b/arch/riscv/kvm/mmu.c
index 1ee6139d495f..554926e33760 100644
--- a/arch/riscv/kvm/mmu.c
+++ b/arch/riscv/kvm/mmu.c
@@ -585,7 +585,7 @@ bool kvm_age_gfn(struct kvm *kvm, struct kvm_gfn_range *range)
 				   &ptep, &ptep_level))
 		return false;
 
-	return ptep_test_and_clear_young(NULL, 0, ptep);
+	return __ptep_test_and_clear_young(NULL, 0, ptep);
 }
 
 bool kvm_test_age_gfn(struct kvm *kvm, struct kvm_gfn_range *range)
diff --git a/arch/riscv/mm/pgtable.c b/arch/riscv/mm/pgtable.c
index 5756bde9eb42..5f31d0594109 100644
--- a/arch/riscv/mm/pgtable.c
+++ b/arch/riscv/mm/pgtable.c
@@ -18,7 +18,7 @@ int __ptep_set_access_flags(struct vm_area_struct *vma,
 	return true;
 }
 
-int ptep_test_and_clear_young(struct vm_area_struct *vma,
+int __ptep_test_and_clear_young(struct vm_area_struct *vma,
 			      unsigned long address,
 			      pte_t *ptep)
 {
diff --git a/include/linux/contpte.h b/include/linux/contpte.h
index 01da4bfc3af6..38092adbe0d4 100644
--- a/include/linux/contpte.h
+++ b/include/linux/contpte.h
@@ -19,5 +19,7 @@ void contpte_try_unfold(struct mm_struct *mm, unsigned long addr,
 			pte_t *ptep, pte_t pte);
 void contpte_set_ptes(struct mm_struct *mm, unsigned long addr,
 		      pte_t *ptep, pte_t pte, unsigned int nr);
+int contpte_ptep_test_and_clear_young(struct vm_area_struct *vma,
+				      unsigned long addr, pte_t *ptep);
 
 #endif /* _LINUX_CONTPTE_H */
diff --git a/mm/contpte.c b/mm/contpte.c
index 5bf939639233..220e9d81f401 100644
--- a/mm/contpte.c
+++ b/mm/contpte.c
@@ -47,6 +47,7 @@
  *   - set_pte()
  *   - pte_clear()
  *   - ptep_get_and_clear()
+ *   - ptep_test_and_clear_young()
  */
 
 pte_t huge_ptep_get(pte_t *ptep)
@@ -690,4 +691,42 @@ pte_t ptep_get_and_clear(struct mm_struct *mm,
 	contpte_try_unfold(mm, addr, ptep, __ptep_get(ptep));
 	return __ptep_get_and_clear(mm, addr, ptep);
 }
+
+int contpte_ptep_test_and_clear_young(struct vm_area_struct *vma,
+				      unsigned long addr, pte_t *ptep)
+{
+	/*
+	 * ptep_clear_flush_young() technically requires us to clear the access
+	 * flag for a _single_ pte. However, the core-mm code actually tracks
+	 * access/dirty per folio, not per page. And since we only create a
+	 * contig range when the range is covered by a single folio, we can get
+	 * away with clearing young for the whole contig range here, so we avoid
+	 * having to unfold.
+	 */
+
+	size_t pgsize;
+	int young = 0;
+	int i, ncontig;
+
+	ptep = arch_contpte_align_down(ptep);
+	ncontig = arch_contpte_get_num_contig(vma->vm_mm, addr, ptep, 0, &pgsize);
+	addr = ALIGN_DOWN(addr, ncontig * pgsize);
+
+	for (i = 0; i < ncontig; i++, ptep++, addr += pgsize)
+		young |= __ptep_test_and_clear_young(vma, addr, ptep);
+
+	return young;
+}
+EXPORT_SYMBOL_GPL(contpte_ptep_test_and_clear_young);
+
+__always_inline int ptep_test_and_clear_young(struct vm_area_struct *vma,
+					      unsigned long addr, pte_t *ptep)
+{
+	pte_t orig_pte = __ptep_get(ptep);
+
+	if (likely(!pte_valid_cont(orig_pte)))
+		return __ptep_test_and_clear_young(vma, addr, ptep);
+
+	return contpte_ptep_test_and_clear_young(vma, addr, ptep);
+}
 #endif /* CONFIG_THP_CONTPTE */
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240508191931.46060-9-alexghiti%40rivosinc.com.
