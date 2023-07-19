Return-Path: <kasan-dev+bncBAABB7F532SQMGQEJWKRRUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id CB062759045
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 10:29:49 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-635df2bb4b4sf65666516d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 01:29:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689755388; cv=pass;
        d=google.com; s=arc-20160816;
        b=dhCbzfjkTwPUyfcWQDnmmaEx8t1mUbS4VD/LzMM+4Y2xL6ANsrPW1k6u78p1zRVT63
         6HYvR8eSWd2G7tkkRwM2S5M86QWrjpRfI2Ooc7raB5PXrd6QT49l5meU8dGQsQdM3LCw
         7JJ9T/VdIcAqClB8jS0h0D42vPKqJlyTvOges2hCavGdxaALlJVnqZ7OCX+Hzd5hh4Q5
         zwJ6aIqPFzpSl7XMQTWo2XMrMq6Buj7hITp9AOzDNfbS9jwIsJI7ziiz7XsD1Jus4VkU
         v/xcyHO5FH9nS6ppBH7W4aZmvBzSSuLSs0suOWWufcCEYLndGdOkCWrrCnoN3vKkPjjQ
         kW/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=K5kikGgdvzW+xo0k3zrbjDduVOBnac1Ny9QVDy+ybEM=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=HcCixOZe4VFdCGxeTXN+znLMJGttkUsuuif8SWa7k77vc+IO+zfh00ygjZhGwgAULR
         VPH538bY1ilpLDsG0zJHyJmIN0XzjXU4YaPA6K8Zgz0kD+4WCXc7GwM94BJqKudo/i1l
         xcrnJCtk7t4CKaW6i9Zr+DTZJa/b1Tl3rym0LmbSZYf7ilRWTSlwPhzXSsw+9vximECe
         b+j5aYj7sFJHOETxGAZau033GIN7O87L/Pggy8f8ylian2DsvIm3h571krwPFYW9/78b
         duA+mimktcfpEfg83Zrasle1znuG8YFClwG/tk5PBLpkvBfjtYreClYi3Jya21IrMNfL
         jp1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689755388; x=1692347388;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=K5kikGgdvzW+xo0k3zrbjDduVOBnac1Ny9QVDy+ybEM=;
        b=mJf+4/EGStcPNwUGXymgqtGnsdRQc9pJ3veMnE2+fI2vNKKKWIrgkfmtsC/fMD7Ov/
         CCN6yF4w5/+00w+o8vkeHmvvaCXw+RvNaapnRTXEq/ur0pBApNatVguU6U8PxW+pIt1p
         XZaw2mP03aFkxhARB5I5W3wHjlJFK775DiiL2XXuPgHosQuO0qF7CKobb5qM65cVKnc9
         Auat8/VoGzA3+ix+IXPVPRbk+3s3PEFlqKAFP1Ik+QIdlmzuPLpC/J9GDJMkBEyoDyHx
         M153M7lUuTU3gfLmeghTgagTrE0UlB3TUYuBgl2Vwd+pHs71WT1bQb05rKmtvLs/tcPO
         cCNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689755388; x=1692347388;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=K5kikGgdvzW+xo0k3zrbjDduVOBnac1Ny9QVDy+ybEM=;
        b=DnSiobB/3UJigWaEqH2BSJaGOKvG1GNS3pQ14jpM5fTWIQR+7reSetTKGuo165/BNm
         BNM+ForunWO+8tnJ/AdHjiWxRlLdmdvhnrtLgBz1YPzjfMK/aCJmy2+qX9zR/NXhyA70
         BHCXH06Ninttg4FHitqTj4B9wydV03QH/1LZ+wEnRpHFkwIfqsTwdLJk++g8MSoOs8dn
         P8ue8l5QCn0VHlj22UQ3R4TrZHu+46OWR/3Q3gljhoby+QCIM5X0bzP8sUy24ZCFif9/
         K1zhuvabK0o2R1Orrq8pqJQPNeOUFVac3AP5kMkYhCOmUpDmQQnwdf0XulqMtDkosa/S
         G4ew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLYHcSt3RRKf4qE9qo7FsgeS9k8POPBmdY5MqTvWhhwPz/KiMkq2
	ooIi0LEBd30zZ6CMPRmHzqE=
X-Google-Smtp-Source: APBJJlEMT/1fyMWeZ71uwM4wGna+CuZRzCANWWJsjghJ4igR9TtX6PHByALCaAHnPlaChd6++zJu/A==
X-Received: by 2002:ad4:5687:0:b0:635:e796:f707 with SMTP id bd7-20020ad45687000000b00635e796f707mr15589356qvb.19.1689755388597;
        Wed, 19 Jul 2023 01:29:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:9d09:0:b0:62f:fb47:5672 with SMTP id m9-20020a0c9d09000000b0062ffb475672ls206817qvf.1.-pod-prod-07-us;
 Wed, 19 Jul 2023 01:29:47 -0700 (PDT)
X-Received: by 2002:a0c:aa57:0:b0:5ef:5e1b:a365 with SMTP id e23-20020a0caa57000000b005ef5e1ba365mr14608707qvb.10.1689755387612;
        Wed, 19 Jul 2023 01:29:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689755387; cv=none;
        d=google.com; s=arc-20160816;
        b=Oi+K1VL+3VS0NMDfDY8ltkSulbkyaVKZvdSgmT9YC5Br4gqPRpIwOjJzzteH1kyr12
         bFXt3xJKImyM2W9lBVJ54bCu1l3UHcj6GFxOiWoCNPPcVUzMFPCvmyGo8SbjJFi9W58A
         6J4y+fLJne5cdJKZ8FmgpoZVK+zzJDY0Yae2K9QCHxAR69Nfy5HqTZwObf5laRn5K0x+
         rgsqedaGpPqNFLuv0CaKEHNCh1cxkE6UqIXwgeA2iK9lWQKoq/tWNWlHw5/0JqVybbmg
         2MEChW+L60DYuWaFnJkzPN7b6vnIoD0gYfDmXbaAVq2QGQBkUx9E5hZbIIYQ3V+3R7xt
         KYDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=/E8kyiKDUQnk0VfQ1mlnr9lGiDIiooII8OXzNiLAUWw=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=ShMfAmM4czysl6ZzmVDjxqOu1uWSkUnxKl75niE31fWyLEPFVNGNsS1flcZRXwFV9I
         vGmlKzqpNi2w2C4tM7vXFDmkvaDiRMyjmo8tKuHFO5g5qVRspfmQMafD5YBqEg/vedou
         dX0vCbX1IAYjLZtdpWSAJJ5TznlH6UPSNZSelxAjT18opq6KahBjd5O4ZHNpWqzoqQOi
         5AE49mcftuQacA3ZD0u0zEIrkJGhAtc8m5nLRfjm6rq/eVAHNUyaLjdaeLgZyZKYj+aV
         LQF+FftmX4+V9z9k3lA9LO7hCvc04Pi6hN9K8iVicNV/PtMyI3z+WB2guLoQBpBT75I2
         ldEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id s17-20020ad44391000000b00636438a5523si253935qvr.8.2023.07.19.01.29.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jul 2023 01:29:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: 62e820fc96cc4d168ad342c21586d40f-20230719
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:44c8e872-f164-4bb8-b9de-1fc0090e6674,IP:25,
	URL:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTI
	ON:release,TS:10
X-CID-INFO: VERSION:1.1.28,REQID:44c8e872-f164-4bb8-b9de-1fc0090e6674,IP:25,UR
	L:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTION
	:release,TS:10
X-CID-META: VersionHash:176cd25,CLOUDID:f917c5dc-dc79-4898-9235-1134b97257a8,B
	ulkID:230719161451G22TEPAY,BulkQuantity:1,Recheck:0,SF:24|17|19|44|38|102,
	TC:nil,Content:0,EDM:-3,IP:-2,URL:1,File:nil,Bulk:40,QS:nil,BEC:nil,COL:0,
	OSI:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0
X-CID-BAS: 0,_,0,_
X-CID-FACTOR: TF_CID_SPAM_ULS,TF_CID_SPAM_SNR,TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,
	TF_CID_SPAM_FSI
X-UUID: 62e820fc96cc4d168ad342c21586d40f-20230719
X-User: lienze@kylinos.cn
Received: from ubuntu.. [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1370030671; Wed, 19 Jul 2023 16:28:18 +0800
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
Subject: [PATCH 1/4] LoongArch: mm: Add page table mapped mode support
Date: Wed, 19 Jul 2023 16:27:29 +0800
Message-Id: <20230719082732.2189747-2-lienze@kylinos.cn>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20230719082732.2189747-1-lienze@kylinos.cn>
References: <20230719082732.2189747-1-lienze@kylinos.cn>
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

Currently, the upstream code only supports DMM (Direct Mapped Mode).
This patch adds a function that determines whether PTMM (Page Table
Mapped Mode) should be used, and also adds the corresponding handler
funcitons for both modes.

For more details on the two modes, see [1].

[1] https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html#virtual-address-space-and-address-translation-mode

Signed-off-by: Enze Li <lienze@kylinos.cn>
---
 arch/loongarch/include/asm/page.h    | 10 ++++++++++
 arch/loongarch/include/asm/pgtable.h |  6 ++++++
 arch/loongarch/mm/pgtable.c          | 25 +++++++++++++++++++++++++
 3 files changed, 41 insertions(+)

diff --git a/arch/loongarch/include/asm/page.h b/arch/loongarch/include/asm/page.h
index 26e8dccb6619..05919be15801 100644
--- a/arch/loongarch/include/asm/page.h
+++ b/arch/loongarch/include/asm/page.h
@@ -84,7 +84,17 @@ typedef struct { unsigned long pgprot; } pgprot_t;
 #define sym_to_pfn(x)		__phys_to_pfn(__pa_symbol(x))
 
 #define virt_to_pfn(kaddr)	PFN_DOWN(PHYSADDR(kaddr))
+
+#ifdef CONFIG_64BIT
+#define virt_to_page(kaddr)						\
+({									\
+	is_PTMM_addr((unsigned long)kaddr) ?				\
+	PTMM_virt_to_page((unsigned long)kaddr) :			\
+	DMM_virt_to_page((unsigned long)kaddr);				\
+})
+#else
 #define virt_to_page(kaddr)	pfn_to_page(virt_to_pfn(kaddr))
+#endif
 
 extern int __virt_addr_valid(volatile void *kaddr);
 #define virt_addr_valid(kaddr)	__virt_addr_valid((volatile void *)(kaddr))
diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/include/asm/pgtable.h
index ed6a37bb55b5..0fc074b8bd48 100644
--- a/arch/loongarch/include/asm/pgtable.h
+++ b/arch/loongarch/include/asm/pgtable.h
@@ -360,6 +360,12 @@ static inline void pte_clear(struct mm_struct *mm, unsigned long addr, pte_t *pt
 #define PMD_T_LOG2	(__builtin_ffs(sizeof(pmd_t)) - 1)
 #define PTE_T_LOG2	(__builtin_ffs(sizeof(pte_t)) - 1)
 
+#ifdef CONFIG_64BIT
+struct page *DMM_virt_to_page(unsigned long kaddr);
+struct page *PTMM_virt_to_page(unsigned long kaddr);
+bool is_PTMM_addr(unsigned long kaddr);
+#endif
+
 extern pgd_t swapper_pg_dir[];
 extern pgd_t invalid_pg_dir[];
 
diff --git a/arch/loongarch/mm/pgtable.c b/arch/loongarch/mm/pgtable.c
index 36a6dc0148ae..4c6448f996b6 100644
--- a/arch/loongarch/mm/pgtable.c
+++ b/arch/loongarch/mm/pgtable.c
@@ -9,6 +9,31 @@
 #include <asm/pgtable.h>
 #include <asm/tlbflush.h>
 
+#ifdef CONFIG_64BIT
+/* DMM stands for Direct Mapped Mode. */
+struct page *DMM_virt_to_page(unsigned long kaddr)
+{
+	return pfn_to_page(virt_to_pfn(kaddr));
+}
+EXPORT_SYMBOL_GPL(DMM_virt_to_page);
+
+/* PTMM stands for Page Table Mapped Mode. */
+struct page *PTMM_virt_to_page(unsigned long kaddr)
+{
+	return pte_page(*virt_to_kpte(kaddr));
+}
+EXPORT_SYMBOL_GPL(PTMM_virt_to_page);
+
+bool is_PTMM_addr(unsigned long kaddr)
+{
+	if (unlikely((kaddr & GENMASK(BITS_PER_LONG - 1, cpu_vabits)) ==
+		     GENMASK(BITS_PER_LONG - 1, cpu_vabits)))
+		return true;
+	return false;
+}
+EXPORT_SYMBOL_GPL(is_PTMM_addr);
+#endif
+
 pgd_t *pgd_alloc(struct mm_struct *mm)
 {
 	pgd_t *ret, *init;
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230719082732.2189747-2-lienze%40kylinos.cn.
