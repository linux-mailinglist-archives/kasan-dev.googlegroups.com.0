Return-Path: <kasan-dev+bncBDXY7I6V6AMRB5ND56YQMGQEXS5T67I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id C861E8C04F1
	for <lists+kasan-dev@lfdr.de>; Wed,  8 May 2024 21:26:46 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-572bf5dc2f4sf14051a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 08 May 2024 12:26:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715196406; cv=pass;
        d=google.com; s=arc-20160816;
        b=0uudelCkmplftTIMwfWvhNBLH40y0zfudGTcv0I2zoaBZj9KVIomQhI6Baae38GOcA
         1aI/RBhFbrDshYm6YdCRw/nSLsoB7Ovh8p4+0Ijj3YCkuJHdAdUyDTeSktXjScRfZNbe
         P+kTDWbL4NRpxj9ZLTpcc929tAQMI2cKdG0cQ+ZsIIeRpe2eDMrBGbfGyhCQdRSBcxfC
         nPW6Y7DNElXLotQBSuSrFji+UZ1/M1yyyIO875YNlKqEgH+aQoHjejE9TaKK5jNV1N3b
         jaGFM6Qa3fjwHdjCniGUsrM/g2PcwiG0JRJwhqF7w6hKrB8Yp/OvtQVrLP7DQKUxWTsQ
         k1OQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gIuOAZ53CjcKvIWwibiS+C/V6mpMmdTSdgIm+KWiraU=;
        fh=cn6hyS9PkoxtC7Bbvd044Xe/eZKMQI3y4YodoUiPw8Y=;
        b=Fa2LIwmxIddyhyHjSO+ToMRpNI33fAExHozudex87sJRiyh5UQpjLc67YqxFZewCEP
         Up64RNLFrrjt1whD7YAw36Fqu8jG23vWlSfUi1OIlI/ECyNbcC0eMTymHJRG7VlB0WZo
         qRNs3k47HIAXdG+1GPlIB2s46JMjNe5gfBUu5CypOy54wAwX038HPtYeaM0CN7gTyRw/
         +Sl/PiAoL9C/riYIhpbHm+LSwZoud9pNr41GdOsCdKBPwKd3E5F/GnrJybD8L6omsH/Q
         IWIlVEeR0ffzZvNDTirKKiowGSC53R2hSTTEm98HHW8qOhGZ/QJNQ8fQF+kO6rA+H4K7
         /9Ww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=kreoA4HZ;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715196406; x=1715801206; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gIuOAZ53CjcKvIWwibiS+C/V6mpMmdTSdgIm+KWiraU=;
        b=WxdviXYPnk0Efpd95i+1/VrCx8R6VKYxynxa+Zqz+JE29tFPka5qRlSoMg0+DIInkD
         uVPWW8wryjBxPAOfA/QDzqeFFMSjsyyTB9pcZTRqV2yfbkeLFocUZmgnmUjPwoLHyp+9
         9/ZTPYc5aFAi2y81y4h37NHjfqE4LrqID/mZLEAFZIuoqTshHBXXC5aDrt5Sp3W1lzr1
         Lpm5gBFDRYmQADham2Brg3Op2ZiGbpm6fsd9PJAPGsnWXsqbjJeGN3lNRjF0rA26P4n7
         DZZ/+Aku0JcewkAy+GbApKdPqxYCN3vBn+Qo9wHjXO0PBE2s5K2n7A+k4681LwhwjyOB
         1McQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715196406; x=1715801206;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gIuOAZ53CjcKvIWwibiS+C/V6mpMmdTSdgIm+KWiraU=;
        b=XblsqCTT9Za+ZZ2E8KQlkctLhv60jVd0L1SqhtJZWB5B7UquodDMIaPsvlcD3vQe0F
         4x2TG3uN4/YdCM5fKSk0F469QVsQ6i8y+5433+u/egeprEfqfpT1/w0eEe7YMxLfJY7D
         0vpBmpdHb7aM2RsehCQNkKVp1t15ju6opYnLS55Qr0yaCfn5uiUIaUMJ/Soat25z4v6h
         FWFCQd7rtHDV96uj/58SjrFj4S8pXW3CWD7rRsuE8TyQn5ylqwC7u9HJrssMCXg8rTO9
         hvHtY7JJzrbnAwc6qc0xuTJ7RLE8ErhCvkgbFu1PM1bduLX8ZUGWWgF1MRNQcgnHSLmV
         4Qiw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXTtPaPTyJPMuYqf9AOyroyZ2p1MkNUzdb+Qk06ZlU17M8e/ga3m/MuyPLD4CZCEVah42XvmOfrtzzcYCIgzOrPkNPNQCOXdA==
X-Gm-Message-State: AOJu0Yxwa/GYbF81Cjcew8d8w0SdOKO7Wc8Sltz0rKi/9PPnjuMmtg5B
	DMlrAPqdEV4sfjdd4F6tqCsHYM6afCIksDoT71znV88nVtoEnQzs
X-Google-Smtp-Source: AGHT+IGhXEN26zqdS0xta5EJCqdxC9AxUvuzOUT6vEa9HuLl+ogqyzRXIEboMPqdhHDu916uxPtbXg==
X-Received: by 2002:a05:6402:401c:b0:572:6698:9247 with SMTP id 4fb4d7f45d1cf-5731d99603emr2614380a12.1.1715196406059;
        Wed, 08 May 2024 12:26:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:320e:b0:572:6780:634f with SMTP id
 4fb4d7f45d1cf-57333321d8bls66940a12.1.-pod-prod-02-eu; Wed, 08 May 2024
 12:26:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWuDWypOU7gaHppQKCsmz45nfxsmWpoYXdNYShrvoRZyxMES/H/yRVjJ3rlIabDSYrbmQ+cydwZmsOUMbz8SqPFR716JoLuOO0+Wg==
X-Received: by 2002:a50:8747:0:b0:570:38a:57ea with SMTP id 4fb4d7f45d1cf-5731da697e0mr2476066a12.33.1715196404343;
        Wed, 08 May 2024 12:26:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715196404; cv=none;
        d=google.com; s=arc-20160816;
        b=D96cXS0IiQY3Md8Lk8MU9RYWfC+vShhdSTQyw7Qz6mqNaXMjniD6JFWH5hZreO0IEX
         DfQNmxMeJXYHX+DO1x5h3AJMtPW3Rm7qU/vgohw96PoHzjn2jWm32jOkLPt4Fn8zBU72
         uw6SWYNtTGuarJGmD1gFCboJlZlU/UoXdE6Y7qlcppfiZXFqFP7IOam9YOyCx2wSbltS
         AtFm08ABZgxadmI95dkUTYnfYLESsYqNKu9bXK1Rr3sitHPcdkpxOrNAwy+Y68G75q/f
         5RGG292bqimd0bKtKRtm3BhZa1umS2PRD/8w9c8TjMMURaQL7G0D1/Uxm2LoKiGBTa9K
         xeqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7NXxlYw1RM9+WdFNtDaqsh0kbg9AU8PQDaN/vzezo7A=;
        fh=lUhGR0in7xBLNeM3qGEgn+QF3s7SKPd4jjiAxKiTOVA=;
        b=H4VEXud2MPKeuewRTwG81Y36JqEJ6JZwMYTGTtTwGYWzCOHJNF7GHknzXXGSoPmqqk
         ozPUySj85IsSDUXTebnQLkiCGQcSmUQJK67FsK/8o0elYvtyQ48ZyOLvpDWJxfhu1IT/
         3Jgye7vakHIeTcc2TruvuAnL+9S/Gbkmi882w/TdnKlGEWMUxlUMpGTyrMYOM9GWOn4P
         crju4d+wB4zcYdWmJaoJPY10EBLNTJ2E39CwEX4VXs7fmYGJMr3OkchZBJS3Prd6q3N1
         Z7WcWoEO+ZvWR30vDWYlk9AZrx4kbO0JZaYWtVWckxR42v3/iovn9/SUSBNYWmPFxad7
         TJIw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=kreoA4HZ;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id f12-20020a0564021e8c00b005727dc54dfbsi398142edf.3.2024.05.08.12.26.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 May 2024 12:26:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id 5b1f17b1804b1-41ecffed96cso634835e9.1
        for <kasan-dev@googlegroups.com>; Wed, 08 May 2024 12:26:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXvU0MUMuCcbopXk7GE6niLU3c8EOSIWbTLBlbdbvDYdpmjEQsHK1mwrCiff44rKTAWCC9epOLGJR4H/Itj6i2R3hGGCH2jeVSyWg==
X-Received: by 2002:a5d:4522:0:b0:34c:bb79:452b with SMTP id ffacd0b85a97d-34fca62159dmr2733749f8f.52.1715196403826;
        Wed, 08 May 2024 12:26:43 -0700 (PDT)
Received: from alex-rivos.ba.rivosinc.com (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id o16-20020adfcf10000000b0034b1bd76d30sm15921429wrj.28.2024.05.08.12.26.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 May 2024 12:26:43 -0700 (PDT)
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
Subject: [PATCH 07/12] mm, riscv, arm64: Use common ptep_get_and_clear() function
Date: Wed,  8 May 2024 21:19:26 +0200
Message-Id: <20240508191931.46060-8-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20240508191931.46060-1-alexghiti@rivosinc.com>
References: <20240508191931.46060-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=kreoA4HZ;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

Make riscv use the contpte aware ptep_get_and_clear() function from arm64.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/arm64/include/asm/pgtable.h | 8 ++------
 arch/riscv/include/asm/pgtable.h | 7 +++++--
 mm/contpte.c                     | 8 ++++++++
 3 files changed, 15 insertions(+), 8 deletions(-)

diff --git a/arch/arm64/include/asm/pgtable.h b/arch/arm64/include/asm/pgtable.h
index 74e582f2884f..ff7fe1d9cabe 100644
--- a/arch/arm64/include/asm/pgtable.h
+++ b/arch/arm64/include/asm/pgtable.h
@@ -1473,12 +1473,8 @@ static inline pte_t get_and_clear_full_ptes(struct mm_struct *mm,
 }
 
 #define __HAVE_ARCH_PTEP_GET_AND_CLEAR
-static inline pte_t ptep_get_and_clear(struct mm_struct *mm,
-				unsigned long addr, pte_t *ptep)
-{
-	contpte_try_unfold(mm, addr, ptep, __ptep_get(ptep));
-	return __ptep_get_and_clear(mm, addr, ptep);
-}
+extern pte_t ptep_get_and_clear(struct mm_struct *mm,
+				unsigned long addr, pte_t *ptep);
 
 #define __HAVE_ARCH_PTEP_TEST_AND_CLEAR_YOUNG
 static inline int ptep_test_and_clear_young(struct vm_area_struct *vma,
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index 41534f4b8a6d..03cd640137ed 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -794,6 +794,9 @@ extern void set_pte(pte_t *ptep, pte_t pte);
 #define set_pte set_pte
 extern void pte_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep);
 #define pte_clear pte_clear
+#define __HAVE_ARCH_PTEP_GET_AND_CLEAR
+extern pte_t ptep_get_and_clear(struct mm_struct *mm,
+				unsigned long addr, pte_t *ptep);
 
 #else /* CONFIG_THP_CONTPTE */
 
@@ -801,11 +804,11 @@ extern void pte_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep);
 #define set_ptes		__set_ptes
 #define set_pte			__set_pte
 #define pte_clear		__pte_clear
+#define __HAVE_ARCH_PTEP_GET_AND_CLEAR
+#define ptep_get_and_clear	__ptep_get_and_clear
 
 #endif /* CONFIG_THP_CONTPTE */
 
-#define __HAVE_ARCH_PTEP_GET_AND_CLEAR
-#define ptep_get_and_clear	__ptep_get_and_clear
 #define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
 #define ptep_set_access_flags	__ptep_set_access_flags
 #define __HAVE_ARCH_PTEP_SET_WRPROTECT
diff --git a/mm/contpte.c b/mm/contpte.c
index c9eff6426ca0..5bf939639233 100644
--- a/mm/contpte.c
+++ b/mm/contpte.c
@@ -46,6 +46,7 @@
  *   - ptep_get_lockless()
  *   - set_pte()
  *   - pte_clear()
+ *   - ptep_get_and_clear()
  */
 
 pte_t huge_ptep_get(pte_t *ptep)
@@ -682,4 +683,11 @@ void pte_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
 	contpte_try_unfold(mm, addr, ptep, __ptep_get(ptep));
 	__pte_clear(mm, addr, ptep);
 }
+
+pte_t ptep_get_and_clear(struct mm_struct *mm,
+			 unsigned long addr, pte_t *ptep)
+{
+	contpte_try_unfold(mm, addr, ptep, __ptep_get(ptep));
+	return __ptep_get_and_clear(mm, addr, ptep);
+}
 #endif /* CONFIG_THP_CONTPTE */
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240508191931.46060-8-alexghiti%40rivosinc.com.
