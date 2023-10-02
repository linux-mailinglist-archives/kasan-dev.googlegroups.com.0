Return-Path: <kasan-dev+bncBDXY7I6V6AMRBK535OUAMGQEDRGHEOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 9374B7B5615
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Oct 2023 17:11:41 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-324810f3bfcsf1304594f8f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Oct 2023 08:11:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696259501; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ix3bUa7VHE6zbRWe53i2He9rYh0yTpWglMzzt/o8d90R6GB/Gz+MfzxyqFj4zKuVXV
         K5svzysvvUyhv/Tz9A2HtpYotIgnjbjJi9bBXVFDRTQRnE62n1FqGu8eBo4GQ3pAoaJx
         +f+2MIlxRLqrGHS6gR1ivY6jjwuDJdXc8J99l6aYRgwn2fCRKpLC8wVnO9mdJnMr75XS
         GZBnFTD4YqH6H6o6Nt8d2x28/flYbUGDiDt2O8ZaNrSRr9IU2GexyqV00ClQODWsyCDm
         YB8Khpu7bBek/ZceSlG6NNYZLvUaiu5iIJ3MRpfF3ze51yrkklf+clEDVPxpCAwnQuGy
         22Lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=twFzDPAA4/OIKm0ZetkTSUk7rgCMUppr10RzCuiLIQ0=;
        fh=uXvJMJMnIF8WaKRrdgquas9RQiOXXOyuQb5203rEpB4=;
        b=bvedbGs8eZr/womNBhmCx0PvlNu/SALWtXa8lC79iNZwYAP3PwtozOVuDPtI2EntLC
         D4bXpmg2CyYkCVRQqwA1TJYXgGKW71JDLBvVpZUAFLuzqCtyI3J5s2dOLe67pV/MG7sy
         UUVSRHQ1W3iDBUaWnV+7k1OM8FvqMhfhZQNJZq8G8jq+xX/uUc5PEQu8Q4hyZmPS6GXg
         OOrmnmaxLmCwNaqrAjm2wXrSf5CDddQ5zM8Z5BBbml/IxjTui91W0AIau96BZdbz91Xh
         ChheLssYeu8701zzX02LfhQlHOVaLev/XGaOAFS8emWU0j5j6u4hXW08S7I9meVOtZ6Z
         iyXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b="XTuTaJM/";
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696259501; x=1696864301; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=twFzDPAA4/OIKm0ZetkTSUk7rgCMUppr10RzCuiLIQ0=;
        b=k3Bk7fo3iHNqJ177k2M5TgxkYc9QKzFPxvHFA63UtHyEhnDps0HP6QlyZ1f9h+gb1x
         Mnd3Id5f1bVdU0jv6U4GSKpXgzrraoRFw+ATejIidThu6Z0iqLHZLwetB9lysyOjPrB9
         4eJGFGJpg0U6wIC7NJd5MOAksEhtxyfaEBq/f7oPqlqKLM/IsOFFSB60rShx1K61Iey5
         nsNBEAVy2F95nzeuiSK9463hLQ9ZwoXI9zpRa2yPU2nQDk7I2hGzVpJmy04SrUomIWlf
         KOO6XRGtCmIhQPl9m03p2gLFsy7wGCDBo/4HJxo5ZB4g0exCoceJJoiaF3ot2ysmBao0
         edZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696259501; x=1696864301;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=twFzDPAA4/OIKm0ZetkTSUk7rgCMUppr10RzCuiLIQ0=;
        b=EFilmXpQ1R8G6YQ6W6QUztSPeM95lRZYP//L7bvyzLRbqQoLwsqFYB9/E8YgGD4b9r
         KKZRUhWLXdpLDsi/ZvSuueVzfeY3oL9PCdrSrRnX85yshTWwR1P+OlrKYVKGVOk2D5yq
         ixV1mKjMUconjXhdoNGM+/31hbiuj8I0izwiJQctfYDeqkEnTVfS68H9kqdjDsi89nDy
         Q030dRnpQY5UrzoqflQZR6TT8iSYYdrn5/cPMr91Z1XGadvbn4RPafA8+xVxbh6Q5G9g
         /d3s35TdfDkUFUiwGXWNknBbJ6QzDtK1w3UV24ht5jHz2tH4y7uSZVFkRLWXKFmRSwVO
         c+Hw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwBrVsXd9PHJxA9JMQuP3XtBWydzRpiBI7ntJiCDVMzTkX5KnqT
	0mGD++0rih5DTi/7db1LwrA=
X-Google-Smtp-Source: AGHT+IG3+cg+1AE5GwfjK8uDlbM6KQtv02Smdtg7m4Wb9q06E8s/TJY4IHYVDlBc/D4Guj4BrqBl7Q==
X-Received: by 2002:a5d:4e0e:0:b0:31a:cca0:2f3a with SMTP id p14-20020a5d4e0e000000b0031acca02f3amr9907661wrt.0.1696259499707;
        Mon, 02 Oct 2023 08:11:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:601b:b0:406:3987:be03 with SMTP id
 az27-20020a05600c601b00b004063987be03ls1117750wmb.1.-pod-prod-00-eu-canary;
 Mon, 02 Oct 2023 08:11:38 -0700 (PDT)
X-Received: by 2002:adf:dec9:0:b0:320:968:f3b0 with SMTP id i9-20020adfdec9000000b003200968f3b0mr8911695wrn.35.1696259497784;
        Mon, 02 Oct 2023 08:11:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696259497; cv=none;
        d=google.com; s=arc-20160816;
        b=T1lUgekngJr9A2i699dFNMAmSb/0+rrp4956kYHF/dEfQZ4XnPa1JtS9RmpsN6bm8g
         TZxPs/H8/MnznuEZ4OtsF6XKWenTRV5A0Y+P5QD7XMZNb5IFURpvFKrfRu2v3rcnSDE5
         xvNweHv6jSzJpPL0iC1xRKJ+s5nl85SyIDP6Su+MUMadKpHPS14n4/HWK8rFh12WmmkD
         J4mEZjSel1MKgz+6grcgJKBbTO0JT0anseujJddUOUg74UzjK5soyqKm8+WesT9We5ma
         Fic943YaVnS5NjeRVixvBUiYgYEatROxNnPJfXOqdbGztpH1HEgO3apA7JoJYgxHdnK5
         7dBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CH5x2RpAAFVf+XEG+0f6TamSE9fPT169LwjSjxAPY4U=;
        fh=uXvJMJMnIF8WaKRrdgquas9RQiOXXOyuQb5203rEpB4=;
        b=GVluxGMyRV1I6rK9ZHawuVL81JonhQ6agemdz2OvNDeP5qIRURfkLX/q6JmrEejoPm
         V24dqfqA0rN7w7jm09Cd7615VQ1Nt4wiqVsaiIjfeOU0FS2lkesI1Xg/0//xksnHo0yL
         S52BkcU8/NYqoXIwVAuo42zQdPb0KAT/puHpzldl1JMl/rCNqs71P6dA8l5M9ng4di4Y
         dvdnNqwsUQs7JQqLiwjzXFE9xUZwbSG1vPBB9QZB2Ww+WZ0Bc+RfL9o6RKu6XNh/6bfo
         FGTja1GW9SGbkdx4yH55MKmfWtmgORAtWJItwuOMC7ys4PTU5KHQzNibUja1f1VucWcm
         rpFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b="XTuTaJM/";
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id bo9-20020a056000068900b00317e1e2b28asi1725938wrb.4.2023.10.02.08.11.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Oct 2023 08:11:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id 5b1f17b1804b1-40675f06f1fso5103705e9.1
        for <kasan-dev@googlegroups.com>; Mon, 02 Oct 2023 08:11:37 -0700 (PDT)
X-Received: by 2002:a05:600c:1c9d:b0:401:609f:7f9a with SMTP id k29-20020a05600c1c9d00b00401609f7f9amr10681875wms.8.1696259497220;
        Mon, 02 Oct 2023 08:11:37 -0700 (PDT)
Received: from alex-rivos.home (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id o14-20020a05600c4fce00b004065d67c3c9sm7473193wmq.8.2023.10.02.08.11.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Oct 2023 08:11:36 -0700 (PDT)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Ryan Roberts <ryan.roberts@arm.com>,
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
Subject: [PATCH 1/5] riscv: Use WRITE_ONCE() when setting page table entries
Date: Mon,  2 Oct 2023 17:10:27 +0200
Message-Id: <20231002151031.110551-2-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20231002151031.110551-1-alexghiti@rivosinc.com>
References: <20231002151031.110551-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b="XTuTaJM/";       spf=pass (google.com: domain of
 alexghiti@rivosinc.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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
index 7a5097202e15..a65a352dcfbf 100644
--- a/arch/riscv/include/asm/pgtable-64.h
+++ b/arch/riscv/include/asm/pgtable-64.h
@@ -198,7 +198,7 @@ static inline int pud_user(pud_t pud)
 
 static inline void set_pud(pud_t *pudp, pud_t pud)
 {
-	*pudp = pud;
+	WRITE_ONCE(*pudp, pud);
 }
 
 static inline void pud_clear(pud_t *pudp)
@@ -274,7 +274,7 @@ static inline unsigned long _pmd_pfn(pmd_t pmd)
 static inline void set_p4d(p4d_t *p4dp, p4d_t p4d)
 {
 	if (pgtable_l4_enabled)
-		*p4dp = p4d;
+		WRITE_ONCE(*p4dp, p4d);
 	else
 		set_pud((pud_t *)p4dp, (pud_t){ p4d_val(p4d) });
 }
@@ -347,7 +347,7 @@ static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
 static inline void set_pgd(pgd_t *pgdp, pgd_t pgd)
 {
 	if (pgtable_l5_enabled)
-		*pgdp = pgd;
+		WRITE_ONCE(*pgdp, pgd);
 	else
 		set_p4d((p4d_t *)pgdp, (p4d_t){ pgd_val(pgd) });
 }
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index b2ba3f79cfe9..b820775f4973 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -248,7 +248,7 @@ static inline int pmd_leaf(pmd_t pmd)
 
 static inline void set_pmd(pmd_t *pmdp, pmd_t pmd)
 {
-	*pmdp = pmd;
+	WRITE_ONCE(*pmdp, pmd);
 }
 
 static inline void pmd_clear(pmd_t *pmdp)
@@ -509,7 +509,7 @@ static inline int pte_same(pte_t pte_a, pte_t pte_b)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231002151031.110551-2-alexghiti%40rivosinc.com.
