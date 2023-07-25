Return-Path: <kasan-dev+bncBAABBOWR7WSQMGQEDP7CWWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id 024C7760A1E
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jul 2023 08:16:28 +0200 (CEST)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-569e7aec37bsf52574907b3.2
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jul 2023 23:16:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690265787; cv=pass;
        d=google.com; s=arc-20160816;
        b=x3v1Gx0hedVUSBFa+TTbqE8vwph2JorKNsC/i0H2aLREnGAZet87BrfVoc31CNIJwv
         2/DSGr4jsMNMYnkjP+9HT8jcb5E7dVEDGbldZaDCXaAXLc0Jg1GPFT8HzI1XVWfDSokn
         vXNHQclQ4TqQLn59MwhG+mzSCT42VdpPEa5szOiqjJwEjR600EN2zU77eks6X5/PWFfk
         VhGbqlyCy+ZWHZg0XtG7H4poQf+0uMW5N/7eB/sFv9X4wkWvDEcisb+EN78iZLv9EqPx
         Smy/jd95pIowqlJ/WPBoW/DulLm+pJ1ZKIiwl7douxXsQGnRaqI8ACLnyVoVrcI3+Wb3
         XtDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tmvh999t+HpaNrRZ4qhjm3Il8C3GqOWJXQmbNb+sDM8=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=HVpf2GpswHSM0sSm6h4MQwQjv2qiUTXaXyTcbRrXp9myf+6Dwb602u3/bpVCs+WqeX
         vdyqAvDWNEkmt9BXZ7uFvb8TEZC8H6WI3SyPpZmK1Wb7VFQBUSFkCwOh24CKXseEb01v
         pgFVLLB8WYCCbh+QLsscOVLk3vVeImiKoWbVGC6R1Onbwa1beqMmUL7tWy6urRhMW9Z6
         D5E0kLk2mrv5Nfm1r0C+laz97Accj0xACyKFW5ji+L319+RNtnLZwmRC2le1KttAg9KV
         vd2QUKRz3k4y3V6MvwvL2hzEacsalkCweuPv2WrwbkDU+0UKApH+HqX4J7dewzAPeWcO
         x7Uw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690265787; x=1690870587;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tmvh999t+HpaNrRZ4qhjm3Il8C3GqOWJXQmbNb+sDM8=;
        b=KjSeoDA3kN6c3jiwucBJ+o7E/QEIMw9BZ+KdDl6fYyPpvSwM/XI5enVrELKLCyqmRI
         sW1vPNk1ChKN2XutpF2+pokw8YjX5zr7QPkS5sEj0oaAUppk6/t1mX8Vw2rhdaxIZQif
         Ob2CdIBtydA5sWD+55ynpLe6FRPOhYhJ7ZrZOg3yxrVWvcv21Q9xwUcnHBpB+RjTJUa/
         6c4O0CG03NEVTjTQVUtX5gwu8G99hJjPICYafRQFkElRQ2eZEbsYWRvpksY2oteBQiQA
         BcPfdY/q453qAeW6dp5Gqf05hdA9DVPIcbKboo099nv0hKD/m7aUO7keYRQlb9dal0g2
         Xi0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690265787; x=1690870587;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tmvh999t+HpaNrRZ4qhjm3Il8C3GqOWJXQmbNb+sDM8=;
        b=kpjcg5hnIWQ04AHfkloSRF/jjWt5sx4XeTKEd6atiYtzxUoU+VGZ+nY6F2yp1id6tb
         Vb0FvPJxGOIUMxj4cgexMS7DUAHFyc6OvhjDh0Cr5z6SrNXNYU2eALg/rQuOBHSbRl8G
         KiXmU5zU3Df5Wx4usN5NoiLRPjC/eFc8Rdaqp167zFa5NP6lCzzQ4KEFv/R0cRu5Fk5G
         Fv4i4m4FoyF3S0r7m+e8sXg+PxIhNS4BMcbmtp7OcVqvAMozPtDDH1H5M93VWqJS08E5
         6s6sYIT/0ODwOrKwrZsq7gALa2L1igBN+BBAFM4E6dsp1LXjXRcxQoZ1H6B38vWHHI5L
         Hf0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLY67w5O8Ph7yEv20OpMcYjFg6eh2YnsRl+HIruXmiGo8D/oFIP5
	4+Ju1g/bN7rESiOq3iZntHI=
X-Google-Smtp-Source: APBJJlHYqsHZP2dhG8Es4/EHqskPdpIflyvOJuq6TH1InCe256ovU3ggCMwEPznT3l6e4qcxI+5axw==
X-Received: by 2002:a25:ce90:0:b0:cff:e73b:efdb with SMTP id x138-20020a25ce90000000b00cffe73befdbmr8880119ybe.52.1690265786729;
        Mon, 24 Jul 2023 23:16:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e211:0:b0:635:e560:ecc9 with SMTP id q17-20020a0ce211000000b00635e560ecc9ls3619774qvl.2.-pod-prod-08-us;
 Mon, 24 Jul 2023 23:16:26 -0700 (PDT)
X-Received: by 2002:a67:f6d8:0:b0:444:bb70:db73 with SMTP id v24-20020a67f6d8000000b00444bb70db73mr2758421vso.28.1690265786159;
        Mon, 24 Jul 2023 23:16:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690265786; cv=none;
        d=google.com; s=arc-20160816;
        b=BLMhuz6b/5YwCBQIihJdujAFYJ7O80LYeEERjlkTYYWukmB0k7DDohCteV/wgallLZ
         FrG0HKsACy/P1UtiJlOa+Vy2bfAp1Mopt7qea2N0sNgVlTmNaB/lR2k5EREUjZTKoGwz
         lYeEOuzVrkcNCvpa52VveAixPdenUg2EtyPWiueqIds5pAwC8qo2z39aeAaxHOE315Kk
         zaoqZbVBUzgYxKH1bwL1w840CpxBrOmfmXM5r6pypuajlYygEdZcBSqf6iPBKC0D0aXe
         ylCGYlRLqUj3zER9IrDP285PCOsMuld5I8R//TN5y9ulbedLDhPwlg1ho/LWLWW45Z2t
         Wvxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=IhGnxe2P5+ULV3kw8CSrg/6QSRV8cYfR7e12dyv3j8E=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=ay0hyGY9brAStEOTE29hJCS40NiqTM0ImJF5WE+aS5ISl8sVUebFm6FkfM5qKadTEZ
         5IbuhfP/39deV4MxiMSN7DXuyA6lQXzKQ1ky90SwSfuoctSE/EFWH6gox6bjXP+yvduy
         oAQtZSfR51Lqm3a2ZiApYIHyI5YaRkkCuqq24C+buMneFOqj2XHxW3kCjW1QqCrPbEhu
         w8lp1A6AkqcTAKkYaEfPWmmg1qlAt4Bj561ZE7e5S7OLOPSKyP3zsRw5YvelNDaz2iPm
         Ji+SNxBVLN+OaNYlAPjY5ZZ+KbWqbD+2yhi0VBFlbMCS24bu5o2RQFpsEQeKRnD3qbbu
         uBjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id r4-20020a67cd84000000b004437e608de4si627446vsl.2.2023.07.24.23.16.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 Jul 2023 23:16:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: 06f546de48c44ad099634202a5a5558d-20230725
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:5ca60565-7f43-4364-9457-75cadd98427e,IP:15,
	URL:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTI
	ON:release,TS:0
X-CID-INFO: VERSION:1.1.28,REQID:5ca60565-7f43-4364-9457-75cadd98427e,IP:15,UR
	L:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTION
	:release,TS:0
X-CID-META: VersionHash:176cd25,CLOUDID:cebc4ad2-cd77-4e67-bbfd-aa4eaace762f,B
	ulkID:230725141514N0X3POC0,BulkQuantity:0,Recheck:0,SF:44|38|24|17|19|102,
	TC:nil,Content:0,EDM:-3,IP:-2,URL:1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0
	,OSI:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0
X-CID-BAS: 0,_,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,TF_CID_SPAM_FSI,
	TF_CID_SPAM_ULS
X-UUID: 06f546de48c44ad099634202a5a5558d-20230725
X-User: lienze@kylinos.cn
Received: from ubuntu.. [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1695958714; Tue, 25 Jul 2023 14:15:11 +0800
From: Enze Li <lienze@kylinos.cn>
To: chenhuacai@kernel.org,
	kernel@xen0n.name,
	loongarch@lists.linux.dev,
	glider@google.com,
	elver@google.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Cc: zhangqing@loongson.cn,
	yangtiezhu@loongson.cn,
	dvyukov@google.com,
	Enze Li <lienze@kylinos.cn>
Subject: [PATCH 1/4 v2] LoongArch: mm: Add page table mapped mode support
Date: Tue, 25 Jul 2023 14:14:48 +0800
Message-Id: <20230725061451.1231480-2-lienze@kylinos.cn>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20230725061451.1231480-1-lienze@kylinos.cn>
References: <20230725061451.1231480-1-lienze@kylinos.cn>
MIME-Version: 1.0
X-Original-Sender: lienze@kylinos.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as
 permitted sender) smtp.mailfrom=lienze@kylinos.cn
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

According to LoongArch documentation online, there are two types of address
translation modes: direct mapped address translation mode (direct mapped mode)
and page table mapped address translation mode (page table mapped mode).

Currently, the upstream kernel only supports direct mapped mode.
This patch adds a function that determines whether page table mapped
mode should be used, and also adds the corresponding handler functions
for both modes.

For more details on the two modes, see [1].

[1] https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html#virtual-address-space-and-address-translation-mode

Signed-off-by: Enze Li <lienze@kylinos.cn>
---
 arch/loongarch/include/asm/page.h    | 19 ++++++++++++++++++-
 arch/loongarch/include/asm/pgtable.h |  2 ++
 arch/loongarch/mm/pgtable.c          |  6 ++++++
 3 files changed, 26 insertions(+), 1 deletion(-)

diff --git a/arch/loongarch/include/asm/page.h b/arch/loongarch/include/asm/page.h
index 26e8dccb6619..e43a2385b2cd 100644
--- a/arch/loongarch/include/asm/page.h
+++ b/arch/loongarch/include/asm/page.h
@@ -32,6 +32,7 @@
 
 #include <linux/kernel.h>
 #include <linux/pfn.h>
+#include <asm/cpu-features.h>
 
 /*
  * It's normally defined only for FLATMEM config but it's
@@ -84,7 +85,23 @@ typedef struct { unsigned long pgprot; } pgprot_t;
 #define sym_to_pfn(x)		__phys_to_pfn(__pa_symbol(x))
 
 #define virt_to_pfn(kaddr)	PFN_DOWN(PHYSADDR(kaddr))
-#define virt_to_page(kaddr)	pfn_to_page(virt_to_pfn(kaddr))
+
+static inline bool is_tlb_addr(unsigned long kaddr)
+{
+	if (unlikely((kaddr & GENMASK(BITS_PER_LONG - 1, cpu_vabits)) ==
+		     GENMASK(BITS_PER_LONG - 1, cpu_vabits)))
+		return true;
+	return false;
+}
+
+#define dwm_virt_to_page(kaddr)	pfn_to_page(virt_to_pfn(kaddr))
+
+#define virt_to_page(kaddr)						\
+({									\
+	is_tlb_addr((unsigned long)kaddr) ?				\
+	tlb_virt_to_page((unsigned long)kaddr) :			\
+	dwm_virt_to_page((unsigned long)kaddr);				\
+})
 
 extern int __virt_addr_valid(volatile void *kaddr);
 #define virt_addr_valid(kaddr)	__virt_addr_valid((volatile void *)(kaddr))
diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/include/asm/pgtable.h
index 38afeb7dd58b..98a0c98de9d1 100644
--- a/arch/loongarch/include/asm/pgtable.h
+++ b/arch/loongarch/include/asm/pgtable.h
@@ -353,6 +353,8 @@ static inline void pte_clear(struct mm_struct *mm, unsigned long addr, pte_t *pt
 #define PMD_T_LOG2	(__builtin_ffs(sizeof(pmd_t)) - 1)
 #define PTE_T_LOG2	(__builtin_ffs(sizeof(pte_t)) - 1)
 
+inline struct page *tlb_virt_to_page(unsigned long kaddr);
+
 extern pgd_t swapper_pg_dir[];
 extern pgd_t invalid_pg_dir[];
 
diff --git a/arch/loongarch/mm/pgtable.c b/arch/loongarch/mm/pgtable.c
index 36a6dc0148ae..20e7425d235d 100644
--- a/arch/loongarch/mm/pgtable.c
+++ b/arch/loongarch/mm/pgtable.c
@@ -9,6 +9,12 @@
 #include <asm/pgtable.h>
 #include <asm/tlbflush.h>
 
+inline struct page *tlb_virt_to_page(unsigned long kaddr)
+{
+	return pte_page(*virt_to_kpte(kaddr));
+}
+EXPORT_SYMBOL_GPL(tlb_virt_to_page);
+
 pgd_t *pgd_alloc(struct mm_struct *mm)
 {
 	pgd_t *ret, *init;
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230725061451.1231480-2-lienze%40kylinos.cn.
