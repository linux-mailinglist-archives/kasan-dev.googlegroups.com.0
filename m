Return-Path: <kasan-dev+bncBDXY7I6V6AMRBVVJ5CVQMGQEZC4GMCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 79E7E812008
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 21:32:24 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-50e0337b615sf2888198e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 12:32:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702499543; cv=pass;
        d=google.com; s=arc-20160816;
        b=IVIw2L7zzEpiBvRtWDtrM1mHkjLH6oKbKt1jn3OtsuAyvt40jOHJCaN6n3zMNJ5idB
         Zi4g6CkjMLatAeNvyFKr1SH5/Z4bgptaaioLUI/SovV0C4EcThdYU+Rxfyq63RzLcIQT
         8TfcM0RbP1W+mSoxxA2q9ir0X98LnuIX3qjStY4dC5uh96pjJxUV8beOu3kRZ+QfcmIR
         lOQu02fOTaMGLZA/VwyxrWAQUvQomqnIFCbhvSPrhmLyldgz82k6hYo9+fAxKtVx5fDN
         IuU/fczT7fRDmi1FhsWnNXP8Xt42Xve1Li2pmg1r+I9Pj17EYWKWgmyHSglLqN+KZGs5
         IFDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=70adWU6qK7Vbin6QIc6+Hb83LOPql0aM7K1r9m5aAAk=;
        fh=IGropsY/f620dSTjnkF1U3l/yVuB1Ulli/O+nFZzzpw=;
        b=03Cu+JA5+03bI3DhjPOzWEexRgsxzBDe5XZRuw2JxqyOepUIOcI/jL2U7ocudfgcSy
         nEd6QwP9EFsWWaCGixdYaxe8W/HikgjXz5pReNAfJrw8Wr+EVMkQowpnY+5sTyEfUe/6
         ZUrxBydaKRMfyxts8/EZEsV8HYw9PoI9MIml5i4ulRqbTXdYGdbKSJq3WR+6O692unrR
         7IVQLRC4Pss1NJt26428eWMfBxzcHvWCen5AbljevrJZSHnj0OJDvFwkXiyO0Ux6c6mR
         fW2z4ejPRljeET76HYfsh520C+dJG7t3SqxMURQROtphsyDX7Q4MBk5t+UMVZvyER6GZ
         iRpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=lLMjbFE5;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702499543; x=1703104343; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=70adWU6qK7Vbin6QIc6+Hb83LOPql0aM7K1r9m5aAAk=;
        b=ka3bnLS3CIwZy98y5MRDU14BHPS7wXhfJ2kxhIdAtogR8laT5m/iWlpTHIdz2honmU
         2Rqa0EtLTfEA1fAe+u7TGacN0ZwnG/u4uIdXb8VEksj2+lSYmXSQ4JN6OAE8PrZ/ZO5z
         QfaqlaDesf6FGB1GmoEkG8r8Ju4+tNlWTKIP70GMwWmJ7dfboK30aMETrsiJ5sHM0EeS
         Ec5dSXwK0EIIQM/hEVziiIYPWTGE3TFGjmFKWTLE1yM9PbhdTg1F7lI3xwEIBKyTZq8z
         sZTT4VAH7nxNUOnsUKa28ztB0GUBjq/SDkiwMhouCbi1yBZizDKzsXZCWuthRiNnR/aA
         59uQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702499543; x=1703104343;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=70adWU6qK7Vbin6QIc6+Hb83LOPql0aM7K1r9m5aAAk=;
        b=ciSMQlVBupCN6SesLiBCw/xZdzsVOw8TehyLAeHRV7F9cHSp4vdRmFkbvd7vBeCfHW
         kd4bYb8mwSBdNNoz7k66kBNJEUmhvVsqd+DfFGNt9S2a11snkhIvcCjQ3MOb/kXC593I
         A1YC/yZhGwu/fcICEEu5ZuQU/hbBXxlskXebjBZHyS7ognElfUSL3XeE+Vmu69P2Swvb
         3fFZ5rNzHBI5XVsMbGDEBmGyWTAhe+ctSbliwUN3Tu1RlcgxwxvUJGDq4gHxGueM4uko
         Sr+CKkb2D93bQgP1uXIS6WyGxc0dYT7j0YGDZ9YphJOajyG2NFniVvLd2hkKXZrbBaR1
         WaHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx0kdqQzPN9BON/r5Hep/B36iGZCnMu0nnNmvdi293VGjeGvJ8d
	9igPPc4dljKr2936fD3cXE8=
X-Google-Smtp-Source: AGHT+IHnThEB3dGMfh1lf4cq49ASzKLioUJ9aajPSZ8altpg/YcS6DusLNhujkqc8vE5336viBfimg==
X-Received: by 2002:a05:6512:2342:b0:50b:e47f:e96f with SMTP id p2-20020a056512234200b0050be47fe96fmr5191903lfu.57.1702499543161;
        Wed, 13 Dec 2023 12:32:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2256:b0:50b:fc70:9ae3 with SMTP id
 i22-20020a056512225600b0050bfc709ae3ls256739lfu.1.-pod-prod-03-eu; Wed, 13
 Dec 2023 12:32:21 -0800 (PST)
X-Received: by 2002:ac2:4db6:0:b0:50b:eef5:55fa with SMTP id h22-20020ac24db6000000b0050beef555famr3399212lfe.30.1702499541047;
        Wed, 13 Dec 2023 12:32:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702499541; cv=none;
        d=google.com; s=arc-20160816;
        b=NvDlcJDgJTbIgbPH6oH9PLtpBJ1qUK5Hex39wEl/HegwRw3jgG/dMG3mqf02BUCxfl
         bZXkomXjEd73os9zyJd5JqNAsSzJvyFJFlfEAQcvX37Khvt2nIDk9B0Sg/vtTym73pMu
         9I/pooJg+PsP9H4IrIyv3fdxCDoDP3258DyTMD85+G+YCNmax7XDrR8acauSTrN+xkb0
         gvtLZ2rz9ima3enu3Zia/47HBwhrbmfI5mqCtVVq2ldEGlok6yqk0iaLNdj1NGMrR1P+
         gvnn0g6pfTqe7DdgoQsfFrAHuahZtLAzlcu6ntDksNaZ3fDOR3C+CryHhEYTkOVdnjb+
         2ynA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lUqvcHnbHjun3bdBJPfvf0B8JWy5i7uak5v/0Wh9cSk=;
        fh=IGropsY/f620dSTjnkF1U3l/yVuB1Ulli/O+nFZzzpw=;
        b=rnL7AmJGM1j190eo8xs2O7Jk/Raj0HrSeh26fSdMt6So2endm6F/nCGD743qIbR5a8
         94aLw4bs3tOT0mzay8rVPS27d91pFlU+n1o6RbB/NZBz8Xvw5G/lzU3qrslA6YyJ4clh
         r4xYkr7+5XBWxax6aQH1ddMRbydx9kr0eA/ThiEWmmUx7JxZZGAseYkDbEd9aGY7xLGg
         yvm8aBmC64iiOaPfSlw4ZsXJggquAIrob8CHF83qedUaYdD0qPT5+DIry4wN/hXRBeJT
         QV7ND3SSZOUwrJ8T/mANAH1cfSgTwzK5QBn9ElxzicSnu8lD0Y+Y1ITqWwgBsN1dTeiE
         K//Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=lLMjbFE5;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id m6-20020a056512358600b0050bc24846e2si483977lfr.4.2023.12.13.12.32.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Dec 2023 12:32:21 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id ffacd0b85a97d-3333b46f26aso6625916f8f.1
        for <kasan-dev@googlegroups.com>; Wed, 13 Dec 2023 12:32:21 -0800 (PST)
X-Received: by 2002:a5d:51cc:0:b0:336:353b:2193 with SMTP id n12-20020a5d51cc000000b00336353b2193mr1550679wrv.61.1702499540379;
        Wed, 13 Dec 2023 12:32:20 -0800 (PST)
Received: from alex-rivos.ba.rivosinc.com (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id n10-20020a5d4c4a000000b003333abf3edfsm14139649wrt.47.2023.12.13.12.32.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Dec 2023 12:32:20 -0800 (PST)
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
Subject: [PATCH v2 2/4] mm: Introduce pudp/p4dp/pgdp_get() functions
Date: Wed, 13 Dec 2023 21:29:59 +0100
Message-Id: <20231213203001.179237-3-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20231213203001.179237-1-alexghiti@rivosinc.com>
References: <20231213203001.179237-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=lLMjbFE5;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

Instead of directly dereferencing page tables entries, which can cause
issues (see commit 20a004e7b017 ("arm64: mm: Use READ_ONCE/WRITE_ONCE when
accessing page tables"), let's introduce new functions to get the
pud/p4d/pgd entries (the pte and pmd versions already exist).

Note that arm pgd_t is actually an array so pgdp_get() is defined as a
macro to avoid a build error.

Those new functions will be used in subsequent commits by the riscv
architecture.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/arm/include/asm/pgtable.h |  2 ++
 include/linux/pgtable.h        | 21 +++++++++++++++++++++
 2 files changed, 23 insertions(+)

diff --git a/arch/arm/include/asm/pgtable.h b/arch/arm/include/asm/pgtable.h
index 16b02f44c7d3..d657b84b6bf7 100644
--- a/arch/arm/include/asm/pgtable.h
+++ b/arch/arm/include/asm/pgtable.h
@@ -151,6 +151,8 @@ extern pgprot_t phys_mem_access_prot(struct file *file, unsigned long pfn,
 
 extern pgd_t swapper_pg_dir[PTRS_PER_PGD];
 
+#define pgdp_get(pgpd)		READ_ONCE(*pgdp)
+
 #define pud_page(pud)		pmd_page(__pmd(pud_val(pud)))
 #define pud_write(pud)		pmd_write(__pmd(pud_val(pud)))
 
diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index af7639c3b0a3..8b7daccd11be 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -292,6 +292,27 @@ static inline pmd_t pmdp_get(pmd_t *pmdp)
 }
 #endif
 
+#ifndef pudp_get
+static inline pud_t pudp_get(pud_t *pudp)
+{
+	return READ_ONCE(*pudp);
+}
+#endif
+
+#ifndef p4dp_get
+static inline p4d_t p4dp_get(p4d_t *p4dp)
+{
+	return READ_ONCE(*p4dp);
+}
+#endif
+
+#ifndef pgdp_get
+static inline pgd_t pgdp_get(pgd_t *pgdp)
+{
+	return READ_ONCE(*pgdp);
+}
+#endif
+
 #ifndef __HAVE_ARCH_PTEP_TEST_AND_CLEAR_YOUNG
 static inline int ptep_test_and_clear_young(struct vm_area_struct *vma,
 					    unsigned long address,
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213203001.179237-3-alexghiti%40rivosinc.com.
