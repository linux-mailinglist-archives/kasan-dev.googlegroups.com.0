Return-Path: <kasan-dev+bncBAABBAXY5K3AMGQEAUJH5SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id AF49296EDB4
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Sep 2024 10:23:32 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-718d5737df6sf721591b3a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Sep 2024 01:23:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725611011; cv=pass;
        d=google.com; s=arc-20240605;
        b=OCxRuAzOk7TipKyN+pF+z4vY5cPLTyJNUx8fmYbi+oTKiE5a74KUZIaJHmsBiYSeQU
         //LoljDrI7OTnvTPRLAuFntZyZBA5zrn13LhEzQ8zvGq1pfCPEAGHA6R2j/x/XDb8ya5
         7oQWsORRIiehOpdZA5Tyv6BWKqEaqilt2NMMpwcWgJAEjdHsbxPrnz28MuRSxXHYUq+D
         2nnr+sTZVhM8ZHNd7LGxYgcnMrQIUc7JHbNVsJ1xWJ14mpzuAlnRXn9ydrXtsU7pdLyA
         oLhkyVhkJsiKYfwmM4zf2WKV+GbwC74Eb+57VdpzwR/fYkcnryS5zIoTWxZd/+rLJRUz
         EUdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:mime-version:message-id
         :date:subject:cc:to:from:sender:dkim-signature;
        bh=bmAhG0SycRWd35d4r+mjq6BdpNuL1XvR3/vZl22reas=;
        fh=WnVOvM2mD3XndXnqD8811KGCpb+Uv+2lhPMHNKRLfpQ=;
        b=AnW8kxQQRV2Xh55eLsmflbs4gI2aUAYpQC4yW1sdOJ6WmU71KxfrhvVQA+ScnM3HLW
         R6eFrfTW239vUMOMct+KKpVvznAk/FtnMzuWol2wbR+BAsHGjouPq8IGjFx+D5tOTWH4
         bucR8TGselncn41DIq8XiGcL2HYsxxM4XJWyjBo8fEFxNyDa6qchpY4FwRT8MFX6S62o
         qJs704myM70+JkHaXRnmrbZZ5D4KNUGYFVYelbXSXE6BZ3LfJ3zEStiBaNcOghtXA5s+
         uVvHA99ATNB5NiyoYE5qjyqgTgCr9ci7aN2sbWb7bvcpO8Hf/h7Uifo/GVrhN/rRW76X
         sjrg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@uniontech.com header.s=onoh2408 header.b=E3+OMWMi;
       spf=pass (google.com: domain of wangyuli@uniontech.com designates 54.206.16.166 as permitted sender) smtp.mailfrom=wangyuli@uniontech.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=uniontech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725611011; x=1726215811; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:mime-version:message-id:date:subject
         :cc:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bmAhG0SycRWd35d4r+mjq6BdpNuL1XvR3/vZl22reas=;
        b=gAGq+xCIVUu1oA6mXFGKM2TJWB28qzc3h1obmLrrBG0/PG4rFUxZuHunWTytbFgr2j
         kdBrX+FQmAuoDoir8YRY/d7UvAtLLUpvI5IY3z89nsnsjwt6mAyiCOWbSgtocMSIOH4D
         /V35O1JylTstDkywaSrB/pw+o9fLXn3qqEQGfgSKFpgEYp9pDbNzCgqaotbV9Zjl0+hA
         7yGVdYP/Qy04wXIibd80afc5YHJAme4nsJenNexbUCp2JsZCa7/rLKsIyyQf5VleZWZl
         aL0LISBuft0tuxG+Hlphl012qkml6P77ob2B1q8FT4GweexoRyb8oiKWivbRWI/BIEtw
         Vvhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725611011; x=1726215811;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:message-id:date:subject:cc:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bmAhG0SycRWd35d4r+mjq6BdpNuL1XvR3/vZl22reas=;
        b=kWdZMVE/Q2gTYQYY46zTVBuRgIKHb23w2ooEg7sqIhyjA6yw5J0Tn0sjvWn1GMGHQe
         QOFJ36LVZAuyjV5C7HwraLtWuqSMQTs4v6XyQzFe6DjnrOaDqXUiM2Y8wc/XGXz23TFq
         vDBgBWIEJ/hXcAyYOPaeLVqcxly+P4gw0fGAbbmMlJYlWRTU9VeMWhrSNlzO32TGiKOP
         26pLbN/hpbOmwz5hB/tG5AO/6MIuHvT9oWBIY8CGrjPtjCr7/eEgA8QbPXrf28bOl0nv
         gLVyENiZ31+Ig3C5PzJgwmdj/8ckY4lCYlxhItjtG6jv1SlC3tv+DjgGlYpV7ynqL5ik
         U/pA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUpccVy8wY+lB830J+VZdQaqP3xUDii8vD2tVfoKc60Nv11I6GLnjAkjjwTjR2jIYzsg1luXA==@lfdr.de
X-Gm-Message-State: AOJu0YxBfodAjvSDv13+1gp9xBCAdIVlOzIx6cCRoms0Ob4LnKBJN4GX
	qRJ4EsMlRP4qCFsi2aQAOlRm0xANrVQNn2wI4mNgyBhf+ScGGBap
X-Google-Smtp-Source: AGHT+IFZvc9/kfDxoAwbG6eKoxL3SjgRPAyOWYN2IZ2NluRt4xVAYx0UG0OcwSuWrorH4/02vdOSKA==
X-Received: by 2002:a05:6a00:4b4c:b0:717:bce8:f8a9 with SMTP id d2e1a72fcca58-718d5dee47amr2037755b3a.1.1725611010912;
        Fri, 06 Sep 2024 01:23:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:139d:b0:714:251e:1c0f with SMTP id
 d2e1a72fcca58-718d51b0f35ls494991b3a.2.-pod-prod-06-us; Fri, 06 Sep 2024
 01:23:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV8FxYVLvES5dHWBzRqTGPukgG8O0xRorSGu92v/Fy68cOVgrjd2i3bU/hsR7bkTwWycxJTWE4FTlQ=@googlegroups.com
X-Received: by 2002:a05:6a00:1303:b0:70d:323f:d0c6 with SMTP id d2e1a72fcca58-718d5f542b1mr2101750b3a.24.1725611009821;
        Fri, 06 Sep 2024 01:23:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725611009; cv=none;
        d=google.com; s=arc-20240605;
        b=SMOM0XT1Vkbj3rvHohI7niexEnwhiSeCRRNNOUgO8KWCgN62tu1bcHK16QuCajbm6W
         HzM9ku2Eyi9QqfoLX+53OO1orZ5JdFEz17Qg5E4SMP/x1qrR+lTOkJiips7I0hNa+OK8
         /tuU/gCXXhG8Yr8/qw0DqyUZZcgsfbYx/DHC4dFK6HswVCXnx2Zf+9RUqVGMnfmPElUN
         w5DvhnJx6Ds6Thq7tufUBim5xCnf5Emc3/6RGG77ihrGP8VEuaDjjYw9JDDClRwTGefz
         YD61bl4Q5OAeXhF1UCllPwMNH4I/rNS39juFFMlf0CqRTQdaZ2GAW4oAtibg3FBoFE52
         tkqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=feedback-id:content-transfer-encoding:mime-version:message-id:date
         :subject:cc:to:from:dkim-signature;
        bh=AThVTapdK8W6lR9Hzn1lU3iQE9P312HGd4jzTLay1S0=;
        fh=gZAG9vHOZ16B4SEK/V8lEUbRtGWfKWOwkMT9Yi15/RE=;
        b=A+HCD24ApTNgx0UfQemlQ3/ThBJtOxuX8PSsbfeRFrEbUE1BghNoYydpC8/k0EvAel
         Q2Ml46xT319URXXMpgxKrCAC5ESjmBzUTHfufm+3Wp+VikMVNcnmKnyMFJV2jZ5YmH91
         q1GoP1hEU4699wMNVURopFl1pZpsEzGXqBujzLAERFnNpculp9RneSzdxh7YQG3k8HX6
         eqwEtWH+4/P4yLXj5sfvgH17145HDBLXtV3bvAMvKsqZrIwZIkEvhbARM2jnRBdmE7On
         x9ITRruygb6JvCg8bpieFoI27PzDfUu/CV+sGFhIAKvjTxQLeJg9wc7ZTKwzt4rRro5Z
         guQw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@uniontech.com header.s=onoh2408 header.b=E3+OMWMi;
       spf=pass (google.com: domain of wangyuli@uniontech.com designates 54.206.16.166 as permitted sender) smtp.mailfrom=wangyuli@uniontech.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=uniontech.com
Received: from smtpbgau1.qq.com (smtpbgau1.qq.com. [54.206.16.166])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7d4fbdc7a3fsi327262a12.5.2024.09.06.01.23.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 06 Sep 2024 01:23:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangyuli@uniontech.com designates 54.206.16.166 as permitted sender) client-ip=54.206.16.166;
X-QQ-mid: bizesmtp82t1725610983td3gjq13
X-QQ-Originating-IP: XS9dbmsREdHh9f9GsRKePQng3kgynBIBrvK4o5AKij8=
Received: from localhost.localdomain ( [113.57.152.160])
	by bizesmtp.qq.com (ESMTP) with 
	id ; Fri, 06 Sep 2024 16:22:59 +0800 (CST)
X-QQ-SSF: 0000000000000000000000000000000
X-QQ-GoodBg: 1
X-BIZMAIL-ID: 12750230750534342850
From: WangYuli <wangyuli@uniontech.com>
To: stable@vger.kernel.org,
	gregkh@linuxfoundation.org,
	sashal@kernel.org,
	alexghiti@rivosinc.com,
	palmer@rivosinc.com,
	wangyuli@uniontech.com
Cc: paul.walmsley@sifive.com,
	palmer@dabbelt.com,
	aou@eecs.berkeley.edu,
	anup@brainfault.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	rdunlap@infradead.org,
	dvlachos@ics.forth.gr,
	bhe@redhat.com,
	samuel.holland@sifive.com,
	guoren@kernel.org,
	linux@armlinux.org.uk,
	linux-arm-kernel@lists.infradead.org,
	willy@infradead.org,
	akpm@linux-foundation.org,
	fengwei.yin@intel.com,
	prabhakar.mahadev-lad.rj@bp.renesas.com,
	conor.dooley@microchip.com,
	glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	ardb@kernel.org,
	linux-efi@vger.kernel.org,
	atishp@atishpatra.org,
	kvm@vger.kernel.org,
	kvm-riscv@lists.infradead.org,
	qiaozhe@iscas.ac.cn,
	ryan.roberts@arm.com,
	ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com,
	vincenzo.frascino@arm.com,
	namcao@linutronix.de
Subject: [PATCH 6.6 1/4] riscv: Use WRITE_ONCE() when setting page table entries
Date: Fri,  6 Sep 2024 16:22:36 +0800
Message-ID: <9606AC2974BEDC1A+20240906082254.435410-1-wangyuli@uniontech.com>
X-Mailer: git-send-email 2.43.4
MIME-Version: 1.0
X-QQ-SENDSIZE: 520
Feedback-ID: bizesmtp:uniontech.com:qybglogicsvrgz:qybglogicsvrgz8a-1
X-Original-Sender: wangyuli@uniontech.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@uniontech.com header.s=onoh2408 header.b=E3+OMWMi;       spf=pass
 (google.com: domain of wangyuli@uniontech.com designates 54.206.16.166 as
 permitted sender) smtp.mailfrom=wangyuli@uniontech.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=uniontech.com
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

From: Alexandre Ghiti <alexghiti@rivosinc.com>

[ Upstream commit c30fa83b49897e708a52e122dd10616a52a4c82b ]

To avoid any compiler "weirdness" when accessing page table entries which
are concurrently modified by the HW, let's use WRITE_ONCE() macro
(commit 20a004e7b017 ("arm64: mm: Use READ_ONCE/WRITE_ONCE when accessing
page tables") gives a great explanation with more details).

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
Link: https://lore.kernel.org/r/20231213203001.179237-2-alexghiti@rivosinc.com
Signed-off-by: Palmer Dabbelt <palmer@rivosinc.com>
Signed-off-by: WangYuli <wangyuli@uniontech.com>
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
index 719c3041ae1c..f8e72df4113a 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -248,7 +248,7 @@ static inline int pmd_leaf(pmd_t pmd)
 
 static inline void set_pmd(pmd_t *pmdp, pmd_t pmd)
 {
-	*pmdp = pmd;
+	WRITE_ONCE(*pmdp, pmd);
 }
 
 static inline void pmd_clear(pmd_t *pmdp)
@@ -515,7 +515,7 @@ static inline int pte_same(pte_t pte_a, pte_t pte_b)
  */
 static inline void set_pte(pte_t *ptep, pte_t pteval)
 {
-	*ptep = pteval;
+	WRITE_ONCE(*ptep, pteval);
 }
 
 void flush_icache_pte(pte_t pte);
-- 
2.43.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9606AC2974BEDC1A%2B20240906082254.435410-1-wangyuli%40uniontech.com.
