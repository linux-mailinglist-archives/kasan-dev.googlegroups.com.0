Return-Path: <kasan-dev+bncBDXY7I6V6AMRBGFJ5CVQMGQER3E234Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id B5AA8812001
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 21:31:21 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-33637412100sf979118f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 12:31:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702499481; cv=pass;
        d=google.com; s=arc-20160816;
        b=iz+fmicbzK3CG/nouGs75rvdq+byZHTGbqYZX+GXK8Ik44RJ+0bx8esxDxHgoIGzM5
         E6JjEILsOj7yyIg9YhlhjTIFXQiujpmimjDzTP6udCcARzruWVWvf9b1wxwTMGQJnBH/
         9yGRECyMbkRvvO6YqB/hbMF98Tl/BwD3FRA+to/J6wF9/56q30wiibIuaGEaVr7R55aT
         7FyVwSnQSx4J/qVbYSRSEuM5GJFHtDZAuZ+3kZfZlUGzz93xr4F1OScEvNuMSMwnXJRR
         oJMb4T80OtHrTpFD/Gv0WeNnAVYpnZWAbyWpDKJXnSTBo7ogbHgLjSPlJNtPU0ZAaVDw
         EfHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=NgRIMM1MOkr6B0tAXcygGdtcGA/jV9swBNRLgOmLBX4=;
        fh=IGropsY/f620dSTjnkF1U3l/yVuB1Ulli/O+nFZzzpw=;
        b=aqo5UfqUkIVX+ftWUV4iGnfLAueC76wIMRpmJ3CgwDhkLSnbDLElIJ1cVS0kvniKOz
         bYfsSfFYw7e7cQQl5fKHfmLG/aY6KTIeU8LkE0cw27TgTTnB55+MacWnZCE+AqdjAIy0
         bVk+886r0aiZe9e6NME2XlcXfQcmWJrU9kb8H92GJypjAGFJizyb6ZVfY7t79lmwJIHd
         bkcX2DdQJeKgLUJQAbVg2QuQmkd1fyzt0TVzFF3rkfuiJeMPRPYsAGYDfDpYgzaKr6TT
         RnPxZIPPyPz6OMi2gvDKYGXkdMIeU5A3XNIN9BrA/HxjPURCp4lTPKGP1AvgcDUT2ahH
         Hkmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=MtkNGm82;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702499481; x=1703104281; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NgRIMM1MOkr6B0tAXcygGdtcGA/jV9swBNRLgOmLBX4=;
        b=GCv/ezNhVkjVKX0L8/wcqolzBTAZfUeQWwti5siZFyABFcSMNUe4iOm2maUSajALeL
         fOmxfHJneMnuvz/Iy+9jlDnPkQOSZD7g2RlLPbWiBprAAgScRNco7oaDJYNrJX3BeBRx
         MYIAeV9ff3mYMzEHcs3TxKpzc6XUEbvykpWh502uFnHeUiMlbTSz1xe+KbfZA+7/iMrr
         wFFVk7Pv2gzbi289yHZCUD8mBKAuzkWDiJX3LdsDu5L/FuSKUF1uNXAX0xyL/cMed6qA
         4Wi+raao1vn5DtRvrGeMSd97+Dse26j1lUnsX9/kd73jpqhMILC7zO9f1X4akYO9uwmj
         sX2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702499481; x=1703104281;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NgRIMM1MOkr6B0tAXcygGdtcGA/jV9swBNRLgOmLBX4=;
        b=Skfk1B8aiIhVQAsXYQtQ//CtwURPQ3KWT3PmPc35pXQ2yEKxevnkxIn39I2bE7WGB8
         p93ms7/ceA2kTpD6ZfVZUVuoXtjQWXeXXrvLZCoYhnmG5Z7ntZP208Lo2SCwig3dGYOK
         xHc4KX96tjkxHQ4hAYx5TfqutYiO/ptzG3CMym/yX96PeCAosh9oZDqa73EeSG7bxsof
         Iz1tQtuSFq7E+7yeisxH9eAP5Jey3ihtdpfXVfRxfLU4oOIvMst9M0yBivnnGluPG+wh
         7X7ljyAfNA3//jAIr3CT7UoWXL8jj2EZs/i1RyLIN8dUel1Jv+1ft85NAll/Sll8Dkuc
         NYlw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwXkcVkTN48d4dfWN0TJPp8aBpLr3kelP9QOioxjEAGTd2DbO1w
	WS+4RwCVKfoK5yUlYPSStlU=
X-Google-Smtp-Source: AGHT+IFWjMDMvn2LWSvugsc6lJTkYYZdw46oDGJ9zsMYQlmrVtFJThTbJ31nwvLXbZv1aNkQ2XD9ow==
X-Received: by 2002:adf:da43:0:b0:332:e431:c73c with SMTP id r3-20020adfda43000000b00332e431c73cmr3762163wrl.7.1702499480783;
        Wed, 13 Dec 2023 12:31:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:43c9:0:b0:333:325d:50b6 with SMTP id v9-20020a5d43c9000000b00333325d50b6ls1754239wrr.1.-pod-prod-03-eu;
 Wed, 13 Dec 2023 12:31:19 -0800 (PST)
X-Received: by 2002:a5d:4412:0:b0:333:2fd2:4b0f with SMTP id z18-20020a5d4412000000b003332fd24b0fmr5028106wrq.139.1702499478948;
        Wed, 13 Dec 2023 12:31:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702499478; cv=none;
        d=google.com; s=arc-20160816;
        b=miqSrVcLQAclZ07XsfwFXokR2uGnTvJIXvZLdWzIyirHbpxxnGnjExJ9u2R0WC9b9W
         vZ5ImHC7QSN5PxeUmFI6PlAZnhtRMSvv1VShk+WtOwOrNM7TQ3W2oXPlE2tkKocd2/5v
         HIrnT+eC+jcz4bCARZLVoYpyrEmsogKXtGIN8cCQVZ3e5hOaN1YZg88BZGKAh+y/e/xK
         mlrZ4TVh8ALEtT5urEib15SKrVi2IqOhs0R9jgH1pvwWFbWhsFIhoX8dRzMsjkJvMHrz
         saAH5O+0mz50r6xxUtd4jvNHhro14wBZU2wnpKWUPj2o9RM8VdUdfx4NL2a9b+qRDOQM
         CtLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=E15RwjGwh0jg6//BOgBWUm8VeEPhhxkhRr12JTaACPU=;
        fh=IGropsY/f620dSTjnkF1U3l/yVuB1Ulli/O+nFZzzpw=;
        b=czq+W4M2zQKtwoTXhM0L89OD/4OTMMCHkZVwvNcr/atDUCatwypB0jFFlwuHLcBF7d
         GG+u8AkDBfDc62uVwdnS+F3WUPK7QqGPkGdxktI/TBz/SYwLx/P1upCCkS3B3dZYUrxj
         yfuCAWTRq/izLa+80XYj/Tp+5334Cp72LwtKRwfHxInaYHXgN8PRlX2Pwe5ACknZcnLl
         BnxS3g3BHojkM/pzG0ZsUK34vBqQgtOlz0+kHlj0RbWbup2MQGFmb0a8BT/3nPhw/N+I
         fDlnUgRRI9bRyQGMGgLiWCXxs7Ja7Ryx+8thBvalxTK4HmXCHoOpPS/c6qJaWZ0cY9kE
         tCHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=MtkNGm82;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id t7-20020adfe107000000b0033636cd2db8si131827wrz.6.2023.12.13.12.31.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Dec 2023 12:31:18 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-336420a244dso655306f8f.0
        for <kasan-dev@googlegroups.com>; Wed, 13 Dec 2023 12:31:18 -0800 (PST)
X-Received: by 2002:a5d:5742:0:b0:336:370d:4c4f with SMTP id q2-20020a5d5742000000b00336370d4c4fmr973590wrw.60.1702499478475;
        Wed, 13 Dec 2023 12:31:18 -0800 (PST)
Received: from alex-rivos.ba.rivosinc.com (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id h3-20020a5d4303000000b0033629538fa2sm5560888wrq.18.2023.12.13.12.31.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Dec 2023 12:31:18 -0800 (PST)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Russell King <linux@armlinux.org.uk>,
	Ryan Roberts <ryan.roberts@arm.com>,
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
Subject: [PATCH v2 1/4] riscv: Use WRITE_ONCE() when setting page table entries
Date: Wed, 13 Dec 2023 21:29:58 +0100
Message-Id: <20231213203001.179237-2-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20231213203001.179237-1-alexghiti@rivosinc.com>
References: <20231213203001.179237-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=MtkNGm82;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

To avoid any compiler "weirdness" when accessing page table entries which
are concurrently modified by the HW, let's use WRITE_ONCE() macro
(commit 20a004e7b017 ("arm64: mm: Use READ_ONCE/WRITE_ONCE when accessing
page tables") gives a great explanation with more details).

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/include/asm/pgtable-64.h | 6 +++---
 arch/riscv/include/asm/pgtable.h    | 4 ++--
 2 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/arch/riscv/include/asm/pgtable-64.h b/arch/riscv/include/asm/pgtable-64.h
index 9a2c780a11e9..5d8431a390dd 100644
--- a/arch/riscv/include/asm/pgtable-64.h
+++ b/arch/riscv/include/asm/pgtable-64.h
@@ -202,7 +202,7 @@ static inline int pud_user(pud_t pud)
 
 static inline void set_pud(pud_t *pudp, pud_t pud)
 {
-	*pudp = pud;
+	WRITE_ONCE(*pudp, pud);
 }
 
 static inline void pud_clear(pud_t *pudp)
@@ -278,7 +278,7 @@ static inline unsigned long _pmd_pfn(pmd_t pmd)
 static inline void set_p4d(p4d_t *p4dp, p4d_t p4d)
 {
 	if (pgtable_l4_enabled)
-		*p4dp = p4d;
+		WRITE_ONCE(*p4dp, p4d);
 	else
 		set_pud((pud_t *)p4dp, (pud_t){ p4d_val(p4d) });
 }
@@ -351,7 +351,7 @@ static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
 static inline void set_pgd(pgd_t *pgdp, pgd_t pgd)
 {
 	if (pgtable_l5_enabled)
-		*pgdp = pgd;
+		WRITE_ONCE(*pgdp, pgd);
 	else
 		set_p4d((p4d_t *)pgdp, (p4d_t){ pgd_val(pgd) });
 }
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index 294044429e8e..c9f4b250b4ee 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -248,7 +248,7 @@ static inline int pmd_leaf(pmd_t pmd)
 
 static inline void set_pmd(pmd_t *pmdp, pmd_t pmd)
 {
-	*pmdp = pmd;
+	WRITE_ONCE(*pmdp, pmd);
 }
 
 static inline void pmd_clear(pmd_t *pmdp)
@@ -510,7 +510,7 @@ static inline int pte_same(pte_t pte_a, pte_t pte_b)
  */
 static inline void set_pte(pte_t *ptep, pte_t pteval)
 {
-	*ptep = pteval;
+	WRITE_ONCE(*ptep, pteval);
 }
 
 void flush_icache_pte(pte_t pte);
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213203001.179237-2-alexghiti%40rivosinc.com.
