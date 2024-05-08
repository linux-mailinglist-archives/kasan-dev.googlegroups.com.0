Return-Path: <kasan-dev+bncBDXY7I6V6AMRB65C56YQMGQE6LBLILA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 17E6D8C04E8
	for <lists+kasan-dev@lfdr.de>; Wed,  8 May 2024 21:24:46 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-521996339aasf29223e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 08 May 2024 12:24:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715196285; cv=pass;
        d=google.com; s=arc-20160816;
        b=pCr3C56OeZ4n19VE9v6BUBWnQCAAkn1Cp67ILWslXckudlXS45FIT0KQ9dTQcTW4ss
         VvSiE0rr8AzTZl7YvQ7SF/cgsceSuHTXh7pQ6Xdgf16O82jknM3o/DnnVD2T2YCSigjp
         4vPqWIhwknMhIeuWARzEkLx6pA2dOu/pA9ca9VZ6V0IwVGTL/rFY4ULbo5PYycTj411Y
         cJNU5DuQEyJpbd3+T8gIJt42GuCWzhfig2LpJm1SZbmgPVBAGDa2Jlfy7iATt9BBJL2U
         zy10G5LJNnLSHDg3TvQQGpoJDDQX34m4riBJX3CoJxHCSZPsGGWgEIA18zM7EiLd+8sx
         4MTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=u86Er4Iwl8AmzSVjzmvaPNdOl58s09oWRAQDYLmfQ0M=;
        fh=pBX5GQcMCgJIJYw7uFrAifIKTotiNOhw6mtUHfz2XxE=;
        b=U/8hNWPSsMD3Eu03dihA+Fo6IIZjUgumvUZAsJrfXX2YzMy8+XwUleyGvxaeS/pthV
         V6B8hzzD0PExrYUbJv6lzkAM39llVNJ9dB763Bl3ZZ74VRe8TlFSxl4JWiJxYysoUC8Y
         hJ/jWwfF2KgoI3jyxpHGE5ZZB8DIhz/xb9hyPuNHidqT2uGGPwD3EBzII/3Yw27+HZMg
         N+i9ums8FBUp5BQLdurD6VDcPDAP6R6/LPEO9VEZSjl7RCoUFva3tuy+hdzP+Kuk9cYP
         3A1uyvQIMEJqZmn1sYoBrgpmyQ/wcnOozKh6XOehu6HiIJTgS6ADMIlCPstj0x4HwGNY
         PdTg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=W55iQkOR;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715196285; x=1715801085; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=u86Er4Iwl8AmzSVjzmvaPNdOl58s09oWRAQDYLmfQ0M=;
        b=A8fmBKE+5s/rfquItWLlH5S55cxX+QovmCLd60pyfW/iIqPyHE0v+HvnhAyroBmmTn
         Te8jLqngqNTRKoWIzWzKh29BEtpPL+XuqmRk7oLH2p9AO72AtXAPtfmEvSTAk9pxH0vJ
         evYSJ80FXn9kMqOljdYn1IXmDjfr2GGTVINQR4qkt/4hYvZrC2Z0NOaYG3mHiy1FJa6f
         QFrOcsquP+UtefhgnAb4wD2f/YWDKoh+np8YVn8du8J6woNzjQbvNo3lpR2ZwxbdR6PR
         F8OP4kAZ99RPh42hWSJtbgWpL7bmDDWVs4UXGhWWEF8BfzqkzJrx7a1GgTNAldsksv6Z
         Erqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715196285; x=1715801085;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=u86Er4Iwl8AmzSVjzmvaPNdOl58s09oWRAQDYLmfQ0M=;
        b=PapVwTsH6Q4bOTqhI3emJGi3+6efV2+C0NLu0nDKjP7kEBx2s0rm38Uyewd+Yc8CYY
         tq5O51f8lnOi8niJRNN8EjWgyXB1vHQBvH1HJ7qhblpu7Ki6VZMxZ6NpOI9U8hnl9aVN
         Ik2vmyBj2glDdcTumpBzu0fc+RdcYn8zQvxXD8Rpe72ILYV/KL81Sa2AJfBvEOvfJjzz
         KgXB3GqycBbdZARsx3sPlE7ibw3cbYTekPm7SoukUavBTs960mgnz4DOceiSt+MSoCVz
         9GGHgyvJNjEzTq83kkJp/atcfOg2SES5HlfR/2GdMUMqz0Ng+UVgm3acqLMbL08EtRkR
         Vhtg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWmj7ZhJzPT1Pl5vqBfxJ6HUyGzgDJ+VRp14YkFsoJzRroeOgmiFMJchlLnABEV3OLvoHhr+LcDFqczGsmhUrR26e/ySdSiuQ==
X-Gm-Message-State: AOJu0YwmTAeGFXWhG1SVcyljBlEctNk5qGp/gVIfhcT20/qyyw9487Lc
	wzEDPr0sIonD5MFkNLjhb1Ozo8EilMYD0mQ3TvKYKl8PMxwmzbE5
X-Google-Smtp-Source: AGHT+IHeBbsVMbxRW7Sd8FdjJzWgihRCqqiijuHvf2Pt3EEo7VkYICJwwQnfHKOyeysBBaKgzGBJ1w==
X-Received: by 2002:ac2:4a71:0:b0:519:e878:9385 with SMTP id 2adb3069b0e04-5217c5671a9mr2869756e87.18.1715196284013;
        Wed, 08 May 2024 12:24:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e17:b0:518:c467:55bd with SMTP id
 2adb3069b0e04-521e4629ccals105349e87.1.-pod-prod-05-eu; Wed, 08 May 2024
 12:24:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUra99/0NDpfLQ/tEoVsld/gwJm6f43MW37ctCNtBp5QZbEilBB65VYdrL1qKaMZ9bN0dhTl8BwVmW8HQtAnoUDh5F6Ypc1ktCmrg==
X-Received: by 2002:a05:6512:34da:b0:51d:9291:6945 with SMTP id 2adb3069b0e04-5217cd495fbmr2855512e87.44.1715196281861;
        Wed, 08 May 2024 12:24:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715196281; cv=none;
        d=google.com; s=arc-20160816;
        b=kYQs+9pyl6FZRAhaDxEmhGHFiO+2vkuZq3BQBIR/2NKKmf5DYbQ2Q/Ycjq+1Xjx2gV
         uxH64PSlDLgiDCJ0GDVIJvXSAPQJDCol89qIE5hxjoflO/E/NUOdKuVdg/3a653mAtsa
         a6rq71AtY+ZFKMq5lwydCP50jGgiBtKqGV0JWC2+Ez4skR6VhSa/H5CQPf43gt1719dN
         6lkmIrDv40aVRTl67V/cvp9IT6Ob7DNmfvz1zN+09IcbLHBmc1ug8Z8E69XRkmarL3ac
         z6RFZvulq8SuOSbKfLrKej9AfIfmDsGl/c6iaNFhbAyf2L/bdbTiQ8zNdQxJszGiSMwe
         YsNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=bID6WfA+atBgi3UdotMTiBHvNsJiSSNtZP3FlzKWl8Q=;
        fh=ULhkVpg8dj1p51hfMSmmMB/mLtE8G8lSkCYtF7MfWf0=;
        b=TcToPSOzaDUS+r5OCJa4uwS7QmK/LvEuGUoNU//pvJrmZaVlNHVgisjbAqqe5RqdQf
         C3aC6DKLVVq6VfFqbKutg1/Ii7UxddWpg8g4NrJDfJ2MjqqS3tNbXLvU3XUHVb3K1bXV
         +/VRwbc0Tp2bMcQvnE4RI6w7JxAnrdtGKTUClCc27nW7fayzHep06BR9C6xhcG0wwS/v
         5+MPbwJDQE+p0UjtQjeJdO0sZ1LuFlRgasvikwBalXeiqXTfkViq0vo8utQVYgBrnbY1
         SANY74puU/17FeXnOOS/p7EJyHUI1TF4r5OIRCSvkH0vQk8jcwM1OYyLwx3AP2P+wew8
         scBg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=W55iQkOR;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id dw9-20020a0565122c8900b0051cfcba5f46si417414lfb.13.2024.05.08.12.24.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 May 2024 12:24:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-41bab13ca81so866085e9.1
        for <kasan-dev@googlegroups.com>; Wed, 08 May 2024 12:24:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU6soLWz/DnqNgcHZG0XA0CaTzmFbWdCjXBXIzXatK57rq8E/rvGT2JxsoSYhf7LM+p0RxjUbFjvA3D8oQ8sKVIRloDD4fK040eDw==
X-Received: by 2002:a05:600c:1991:b0:41d:803c:b945 with SMTP id 5b1f17b1804b1-41f71309fafmr39869075e9.10.1715196281225;
        Wed, 08 May 2024 12:24:41 -0700 (PDT)
Received: from alex-rivos.ba.rivosinc.com (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-41f882089cbsm32567815e9.48.2024.05.08.12.24.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 May 2024 12:24:40 -0700 (PDT)
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
Subject: [PATCH 05/12] mm, riscv, arm64: Use common set_pte() function
Date: Wed,  8 May 2024 21:19:24 +0200
Message-Id: <20240508191931.46060-6-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20240508191931.46060-1-alexghiti@rivosinc.com>
References: <20240508191931.46060-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=W55iQkOR;       spf=pass (google.com: domain of alexghiti@rivosinc.com
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

Make riscv use the contpte aware set_pte() function from arm64.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/arm64/include/asm/pgtable.h | 16 ++--------------
 arch/riscv/include/asm/kfence.h  |  4 ++--
 arch/riscv/include/asm/pgtable.h |  7 +++++--
 arch/riscv/kernel/efi.c          |  2 +-
 arch/riscv/kernel/hibernate.c    |  2 +-
 arch/riscv/kvm/mmu.c             | 10 +++++-----
 arch/riscv/mm/init.c             |  2 +-
 arch/riscv/mm/kasan_init.c       | 14 +++++++-------
 arch/riscv/mm/pageattr.c         |  4 ++--
 mm/contpte.c                     | 18 ++++++++++++++++++
 10 files changed, 44 insertions(+), 35 deletions(-)

diff --git a/arch/arm64/include/asm/pgtable.h b/arch/arm64/include/asm/pgtable.h
index 8a0603257436..bb6210fb72c8 100644
--- a/arch/arm64/include/asm/pgtable.h
+++ b/arch/arm64/include/asm/pgtable.h
@@ -1432,20 +1432,8 @@ extern pte_t ptep_get(pte_t *ptep);
 extern pte_t ptep_get_lockless(pte_t *ptep);
 #define ptep_get_lockless ptep_get_lockless
 
-static inline void set_pte(pte_t *ptep, pte_t pte)
-{
-	/*
-	 * We don't have the mm or vaddr so cannot unfold contig entries (since
-	 * it requires tlb maintenance). set_pte() is not used in core code, so
-	 * this should never even be called. Regardless do our best to service
-	 * any call and emit a warning if there is any attempt to set a pte on
-	 * top of an existing contig range.
-	 */
-	pte_t orig_pte = __ptep_get(ptep);
-
-	WARN_ON_ONCE(pte_valid_cont(orig_pte));
-	__set_pte(ptep, pte_mknoncont(pte));
-}
+extern void set_pte(pte_t *ptep, pte_t pte);
+#define set_pte set_pte
 
 extern void set_ptes(struct mm_struct *mm, unsigned long addr,
 		     pte_t *ptep, pte_t pte, unsigned int nr);
diff --git a/arch/riscv/include/asm/kfence.h b/arch/riscv/include/asm/kfence.h
index f303fef8591c..36e9f638abf6 100644
--- a/arch/riscv/include/asm/kfence.h
+++ b/arch/riscv/include/asm/kfence.h
@@ -18,9 +18,9 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
 	pte_t *pte = virt_to_kpte(addr);
 
 	if (protect)
-		set_pte(pte, __pte(pte_val(__ptep_get(pte)) & ~_PAGE_PRESENT));
+		__set_pte(pte, __pte(pte_val(__ptep_get(pte)) & ~_PAGE_PRESENT));
 	else
-		set_pte(pte, __pte(pte_val(__ptep_get(pte)) | _PAGE_PRESENT));
+		__set_pte(pte, __pte(pte_val(__ptep_get(pte)) | _PAGE_PRESENT));
 
 	flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
 
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index 62cad1b974f1..4f8f673787e7 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -539,7 +539,7 @@ static inline int pte_same(pte_t pte_a, pte_t pte_b)
  * a page table are directly modified.  Thus, the following hook is
  * made available.
  */
-static inline void set_pte(pte_t *ptep, pte_t pteval)
+static inline void __set_pte(pte_t *ptep, pte_t pteval)
 {
 	WRITE_ONCE(*ptep, pteval);
 }
@@ -551,7 +551,7 @@ static inline void __set_pte_at(struct mm_struct *mm, pte_t *ptep, pte_t pteval)
 	if (pte_present(pteval) && pte_exec(pteval))
 		flush_icache_pte(mm, pteval);
 
-	set_pte(ptep, pteval);
+	__set_pte(ptep, pteval);
 }
 
 #define PFN_PTE_SHIFT		_PAGE_PFN_SHIFT
@@ -790,11 +790,14 @@ extern pte_t ptep_get_lockless(pte_t *ptep);
 extern void set_ptes(struct mm_struct *mm, unsigned long addr,
 		     pte_t *ptep, pte_t pteval, unsigned int nr);
 #define set_ptes set_ptes
+extern void set_pte(pte_t *ptep, pte_t pte);
+#define set_pte set_pte
 
 #else /* CONFIG_THP_CONTPTE */
 
 #define ptep_get		__ptep_get
 #define set_ptes		__set_ptes
+#define set_pte			__set_pte
 
 #endif /* CONFIG_THP_CONTPTE */
 
diff --git a/arch/riscv/kernel/efi.c b/arch/riscv/kernel/efi.c
index 3d2a635c69ac..673eca7705ba 100644
--- a/arch/riscv/kernel/efi.c
+++ b/arch/riscv/kernel/efi.c
@@ -72,7 +72,7 @@ static int __init set_permissions(pte_t *ptep, unsigned long addr, void *data)
 		val = pte_val(pte) & ~_PAGE_EXEC;
 		pte = __pte(val);
 	}
-	set_pte(ptep, pte);
+	__set_pte(ptep, pte);
 
 	return 0;
 }
diff --git a/arch/riscv/kernel/hibernate.c b/arch/riscv/kernel/hibernate.c
index 671b686c0158..97ed3df7a308 100644
--- a/arch/riscv/kernel/hibernate.c
+++ b/arch/riscv/kernel/hibernate.c
@@ -186,7 +186,7 @@ static int temp_pgtable_map_pte(pmd_t *dst_pmdp, pmd_t *src_pmdp, unsigned long
 		pte_t pte = READ_ONCE(*src_ptep);
 
 		if (pte_present(pte))
-			set_pte(dst_ptep, __pte(pte_val(pte) | pgprot_val(prot)));
+			__set_pte(dst_ptep, __pte(pte_val(pte) | pgprot_val(prot)));
 	} while (dst_ptep++, src_ptep++, start += PAGE_SIZE, start < end);
 
 	return 0;
diff --git a/arch/riscv/kvm/mmu.c b/arch/riscv/kvm/mmu.c
index 70c6cb3864d6..1ee6139d495f 100644
--- a/arch/riscv/kvm/mmu.c
+++ b/arch/riscv/kvm/mmu.c
@@ -155,7 +155,7 @@ static int gstage_set_pte(struct kvm *kvm, u32 level,
 			next_ptep = kvm_mmu_memory_cache_alloc(pcache);
 			if (!next_ptep)
 				return -ENOMEM;
-			set_pte(ptep, pfn_pte(PFN_DOWN(__pa(next_ptep)),
+			__set_pte(ptep, pfn_pte(PFN_DOWN(__pa(next_ptep)),
 					      __pgprot(_PAGE_TABLE)));
 		} else {
 			if (gstage_pte_leaf(ptep))
@@ -167,7 +167,7 @@ static int gstage_set_pte(struct kvm *kvm, u32 level,
 		ptep = &next_ptep[gstage_pte_index(addr, current_level)];
 	}
 
-	set_pte(ptep, *new_pte);
+	__set_pte(ptep, *new_pte);
 	if (gstage_pte_leaf(ptep))
 		gstage_remote_tlb_flush(kvm, current_level, addr);
 
@@ -251,7 +251,7 @@ static void gstage_op_pte(struct kvm *kvm, gpa_t addr,
 			return;
 
 		if (op == GSTAGE_OP_CLEAR)
-			set_pte(ptep, __pte(0));
+			__set_pte(ptep, __pte(0));
 		for (i = 0; i < PTRS_PER_PTE; i++)
 			gstage_op_pte(kvm, addr + i * next_page_size,
 					&next_ptep[i], next_ptep_level, op);
@@ -259,9 +259,9 @@ static void gstage_op_pte(struct kvm *kvm, gpa_t addr,
 			put_page(virt_to_page(next_ptep));
 	} else {
 		if (op == GSTAGE_OP_CLEAR)
-			set_pte(ptep, __pte(0));
+			__set_pte(ptep, __pte(0));
 		else if (op == GSTAGE_OP_WP)
-			set_pte(ptep, __pte(pte_val(__ptep_get(ptep)) & ~_PAGE_WRITE));
+			__set_pte(ptep, __pte(pte_val(__ptep_get(ptep)) & ~_PAGE_WRITE));
 		gstage_remote_tlb_flush(kvm, ptep_level, addr);
 	}
 }
diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index fe8e159394d8..bb5c6578204c 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -325,7 +325,7 @@ void __set_fixmap(enum fixed_addresses idx, phys_addr_t phys, pgprot_t prot)
 	ptep = &fixmap_pte[pte_index(addr)];
 
 	if (pgprot_val(prot))
-		set_pte(ptep, pfn_pte(phys >> PAGE_SHIFT, prot));
+		__set_pte(ptep, pfn_pte(phys >> PAGE_SHIFT, prot));
 	else
 		pte_clear(&init_mm, addr, ptep);
 	local_flush_tlb_page(addr);
diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 381d61f42ab8..b5061cb3ce4d 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -41,7 +41,7 @@ static void __init kasan_populate_pte(pmd_t *pmd, unsigned long vaddr, unsigned
 	do {
 		if (pte_none(__ptep_get(ptep))) {
 			phys_addr = memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
-			set_pte(ptep, pfn_pte(PFN_DOWN(phys_addr), PAGE_KERNEL));
+			__set_pte(ptep, pfn_pte(PFN_DOWN(phys_addr), PAGE_KERNEL));
 			memset(__va(phys_addr), KASAN_SHADOW_INIT, PAGE_SIZE);
 		}
 	} while (ptep++, vaddr += PAGE_SIZE, vaddr != end);
@@ -327,8 +327,8 @@ asmlinkage void __init kasan_early_init(void)
 		KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
 
 	for (i = 0; i < PTRS_PER_PTE; ++i)
-		set_pte(kasan_early_shadow_pte + i,
-			pfn_pte(virt_to_pfn(kasan_early_shadow_page), PAGE_KERNEL));
+		__set_pte(kasan_early_shadow_pte + i,
+			  pfn_pte(virt_to_pfn(kasan_early_shadow_page), PAGE_KERNEL));
 
 	for (i = 0; i < PTRS_PER_PMD; ++i)
 		set_pmd(kasan_early_shadow_pmd + i,
@@ -523,10 +523,10 @@ void __init kasan_init(void)
 		       kasan_mem_to_shadow((const void *)MODULES_VADDR + SZ_2G));
 
 	for (i = 0; i < PTRS_PER_PTE; i++)
-		set_pte(&kasan_early_shadow_pte[i],
-			mk_pte(virt_to_page(kasan_early_shadow_page),
-			       __pgprot(_PAGE_PRESENT | _PAGE_READ |
-					_PAGE_ACCESSED)));
+		__set_pte(&kasan_early_shadow_pte[i],
+			  mk_pte(virt_to_page(kasan_early_shadow_page),
+				 __pgprot(_PAGE_PRESENT | _PAGE_READ |
+					  _PAGE_ACCESSED)));
 
 	memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
 	init_task.kasan_depth = 0;
diff --git a/arch/riscv/mm/pageattr.c b/arch/riscv/mm/pageattr.c
index 98c9dc4b983c..d623e4fc11fc 100644
--- a/arch/riscv/mm/pageattr.c
+++ b/arch/riscv/mm/pageattr.c
@@ -71,7 +71,7 @@ static int pageattr_pte_entry(pte_t *pte, unsigned long addr,
 	pte_t val = __ptep_get(pte);
 
 	val = __pte(set_pageattr_masks(pte_val(val), walk));
-	set_pte(pte, val);
+	__set_pte(pte, val);
 
 	return 0;
 }
@@ -121,7 +121,7 @@ static int __split_linear_mapping_pmd(pud_t *pudp,
 
 			ptep_new = (pte_t *)page_address(pte_page);
 			for (i = 0; i < PTRS_PER_PTE; ++i, ++ptep_new)
-				set_pte(ptep_new, pfn_pte(pfn + i, prot));
+				__set_pte(ptep_new, pfn_pte(pfn + i, prot));
 
 			smp_wmb();
 
diff --git a/mm/contpte.c b/mm/contpte.c
index 060e0bc1a2a3..543ae5b5a863 100644
--- a/mm/contpte.c
+++ b/mm/contpte.c
@@ -17,6 +17,7 @@
  *   - __pte_clear()
  *   - __ptep_set_access_flags()
  *   - __ptep_set_wrprotect()
+ *   - __set_pte()
  *   - pte_cont()
  *   - arch_contpte_get_num_contig()
  *   - pte_valid_cont()
@@ -43,6 +44,7 @@
  *   - ptep_get()
  *   - set_ptes()
  *   - ptep_get_lockless()
+ *   - set_pte()
  */
 
 pte_t huge_ptep_get(pte_t *ptep)
@@ -658,4 +660,20 @@ __always_inline pte_t ptep_get_lockless(pte_t *ptep)
 
 	return contpte_ptep_get_lockless(ptep);
 }
+
+void set_pte(pte_t *ptep, pte_t pte)
+{
+	/*
+	 * We don't have the mm or vaddr so cannot unfold contig entries (since
+	 * it requires tlb maintenance). set_pte() is not used in core code, so
+	 * this should never even be called. Regardless do our best to service
+	 * any call and emit a warning if there is any attempt to set a pte on
+	 * top of an existing contig range.
+	 */
+	pte_t orig_pte = __ptep_get(ptep);
+
+	WARN_ON_ONCE(pte_valid_cont(orig_pte));
+	__set_pte(ptep, pte_mknoncont(pte));
+}
+
 #endif /* CONFIG_THP_CONTPTE */
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240508191931.46060-6-alexghiti%40rivosinc.com.
