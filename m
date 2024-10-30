Return-Path: <kasan-dev+bncBAABBONJQ64QMGQESBKTUHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FAB39B5BDF
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2024 07:39:55 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-20c8b0b0736sf66748785ad.3
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2024 23:39:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730270394; cv=pass;
        d=google.com; s=arc-20240605;
        b=jT+UqHrQP9eObQUJTNTE+Dm1b5/P5isfYQ0qzAiNGc4CHDS6sbpBKNsl7sNxV0dW8f
         KdW05MGlU1v5DRjANbCjpzB8cAsfvQf12jM+G2ZWm7tHzOoqIhk+9qorhl8P6LkScJak
         tDnfs/7zXF6Z9Dcx8LAbMLqbHntyMGheUq3H26xXj2FAYR0UdmLQesTnnGbSwMuUATRN
         8aVPUY7GcvtxRCYLlL/pWKW/vEbz645gUtgszmAw2xwFUta6EXYQyE6jFDYdukQgUR1S
         6CVbPbR7/NKgPLO0hjZUivLWkPRxfIp4NvjszlAN6xahZFUQOFc0u5oyYr22erTW+c/Q
         8Y6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=b+uOiTwaem9d2rX0ezsrcGPw3cfMwX+Juc/Ti8bcX0A=;
        fh=wBK9hHnrxbeGweVWjC3dkGly+KlkKklHeeA5jDsaTVc=;
        b=VW5KNMab8XYDTMpi9micnywbYC7RYiqhBomupJtuWHvGTebVmafBCvLgxmQbJQIgof
         K9kwUwIcnOVDbYqFIrn83LUR9Yup48EZU+ynUxE87uyZv4USEj9f21NEV7JLxUEIq/tP
         fxmk51f3Vm7j97NlsKWUNgMnOoIx8MrrwKZIJvtJTyYxiZe1Kzw9EIo2WTOHHiYO7gwo
         IQ4PT75nWHBLoClZNBMZcmHwa2jfDWIeUpLuZ/UUbgvpSESmh9NnEZS/vAroPdxPmqWp
         QwLthBg5VxBFFtQuTfNjtGZd0/zC47RkDd7UOrTiwdWAo2oTnVdaa9lE9mqIXB28ifnX
         hFgg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730270394; x=1730875194; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=b+uOiTwaem9d2rX0ezsrcGPw3cfMwX+Juc/Ti8bcX0A=;
        b=JcVmOE/9piU6kQjpM7FW1annqRltX/UlfXtjS9oRaAW/3f68IVM3A/tYvt1FIHdPvq
         2uiu37FhT5r7/4pCyoYsHJ12PFCSvfMWty4MNKWhytDbPv7sQO4DNYdDrLlv312/5fPB
         Es7JJuLaA1znR34+CSZg+7HVJXUJcEz/43pMM+DP5FMRShuhszxxHL1g5r1Fa3Npj3Ez
         QlIxRQCyqhG1O1QlExOt6eLP9PI0EJLjizNHfBAx0e1IqSm34KDBek03xCrCWfhfccqG
         IECt7wTAmD9qOq4dzTL+hLf8CVhaDQZDWhLDlmXk4OX+3Bm51e65esNvvv4B8y9A2j/w
         EARw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730270394; x=1730875194;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=b+uOiTwaem9d2rX0ezsrcGPw3cfMwX+Juc/Ti8bcX0A=;
        b=VfC/fTm7l8UtPsPVs0v9I1/0qXl0Y5xBpRln0peTS9AA+k9mQfMXqQUHLHcBv/S5WB
         0sDYS6ii64F8SPraxFgvygDb9MuqKG5/ZPWjNe3nEjJ+Qqg0E3tGAUTvcse+WfHfyD4d
         +Zo83cBrpCRYu6a7EftZXKRGnC+pPOongHxDDxNQLWmAVEBECE3wd7RDpohDSAmxBN3L
         06n6pSwUycLsGJ49WICr4qJC5y33klw0vsQTFGgYwimTJxV+O5i1OTQ5KhCo1qdVgDDk
         UTEBtkZdlW1DFvQWRCcKZtAbiMkTdxFBn1yLLMxpLwWNk6dyCKftHoxdB0V3Of+hNZHu
         R/Wg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV+gN7FApEsm4Ms5EqtcYjBldWVU7+cGenL688+Iylo32sMbVeQj58mDqTeBOQ4us2WXxbxCw==@lfdr.de
X-Gm-Message-State: AOJu0YyRU6H9jgZ/mvrcpJRQsv3BOME+rKRQHZFyCyxzDw9zM7B861+b
	HIz9t0WBUhD8HoSDQ14W0YK47z8A83ySXAsAj3CcfcLaJQgDDKy3
X-Google-Smtp-Source: AGHT+IFA4tteMDlajp+9ZkyvFbDbEQjqpcgMyTLetngDO0uMhXhpf915GsgFYy3Jo/YesnWAx1S+3w==
X-Received: by 2002:a17:903:1d1:b0:20c:5909:cc30 with SMTP id d9443c01a7336-210c687cae8mr170931175ad.10.1730270393475;
        Tue, 29 Oct 2024 23:39:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:32d0:b0:20c:5404:ed6f with SMTP id
 d9443c01a7336-20fb536793dls22067515ad.2.-pod-prod-05-us; Tue, 29 Oct 2024
 23:39:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVnt/0FBW6esN2ozadfoO6bX0mL/dawFHHLGl4jJqYdx5fdWGJy9YEjVWJ9choG1pg1nqTHmmFB6y4=@googlegroups.com
X-Received: by 2002:a17:903:24d:b0:20c:774b:5aeb with SMTP id d9443c01a7336-210c687cbebmr159799425ad.3.1730270392379;
        Tue, 29 Oct 2024 23:39:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730270392; cv=none;
        d=google.com; s=arc-20240605;
        b=U3QsI/adcfa5eZ5qx2f0iz+HZ+BeDgCi2g1FDOp13EEwCkiDUZgKg7d0q4/t+JfC1S
         n3MzCgKuBpUY6ehQKEOeq/BV/wErZ8MuZMMu2olDSmUeE6PJONv0JXdrF4yEvkOed+rf
         TveWAAMSFQbXEGZU0jNCGgXW2kuhRsVwsMh0RLua6agMcMW1T3NZY8YKaVZAb5DTyMLx
         D/VPQlue1vVVUf0NLQvOYwtSZ6ubSSZS2AEdb++AadW3jBr9SgkfkwBQ/9bd3UBYc5sa
         Xc8vS0YhUD74xg7mMyI+ZjQqE5DgxnZIvMMG2kDx4iewhcAvFXhAGv05zB6JsMzjAtqS
         aYQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=vE++g1NdPLvsinZB5h+MGN6JeZyEcO5ckqJFwr/C+eo=;
        fh=yVUclo9opHBnbqbD8AfTlsT9ezAtQVHhJdUcfhcVps8=;
        b=kSBSxdt17a4hSKheZ6HUYlDUC7ZZWJuM+OOgXiCJMUKxomUo/R0ZWVI819UcwgQmvl
         RFhW/nYqA8EKSUUkpHrQs8oY1XrxSS2TJRSp1xgiXnadm6MKcgHUwD5DaYGgTcof+6US
         upHlEZ1eW+PyCUB+JdIB3Rzg7gnNDTq3V3REDfpS/NADbvdHgYrwzUZIuXeLVSKSuqR8
         zqebmgbbWn8ApdeJVttXsBgQPlsnZs5NwTfSoYWqvC1k9oburadQB9v+iV3Mwxs76Rxr
         EOcjjNU/qxdiA+CkUcLVUAMtKnJO6iTaXedDg1rVSEoOSbxg5zd9OQ8GmCy1I28hEyMZ
         mIHg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id d9443c01a7336-210bbd759e3si4812035ad.0.2024.10.29.23.39.51
        for <kasan-dev@googlegroups.com>;
        Tue, 29 Oct 2024 23:39:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.2.5.213])
	by gateway (Coremail) with SMTP id _____8CxieCQ1CFn_qgdAA--.61127S3;
	Wed, 30 Oct 2024 14:39:12 +0800 (CST)
Received: from localhost.localdomain (unknown [10.2.5.213])
	by front1 (Coremail) with SMTP id qMiowMDxPEeP1CFntLooAA--.23618S2;
	Wed, 30 Oct 2024 14:39:12 +0800 (CST)
From: Bibo Mao <maobibo@loongson.cn>
To: Huacai Chen <chenhuacai@kernel.org>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: loongarch@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	WANG Xuerui <kernel@xen0n.name>
Subject: [PATCH v2] mm: define general function pXd_init()
Date: Wed, 30 Oct 2024 14:39:05 +0800
Message-Id: <20241030063905.2434824-1-maobibo@loongson.cn>
X-Mailer: git-send-email 2.39.3
MIME-Version: 1.0
X-CM-TRANSID: qMiowMDxPEeP1CFntLooAA--.23618S2
X-CM-SenderInfo: xpdruxter6z05rqj20fqof0/
X-Coremail-Antispam: 1Uk129KBjDUn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7KY7
	ZEXasCq-sGcSsGvfJ3UbIjqfuFe4nvWSU5nxnvy29KBjDU0xBIdaVrnUUvcSsGvfC2Kfnx
	nUUI43ZEXa7xR_UUUUUUUUU==
X-Original-Sender: maobibo@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=maobibo@loongson.cn
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

Function pud_init(), pmd_init() and kernel_pte_init() are duplicated
defined in file kasan.c and sparse-vmemmap.c as weak functions. Move
them to generic header file pgtable.h, architecture can redefine them.

Signed-off-by: Bibo Mao <maobibo@loongson.cn>
---
v1 ... v2:
  1. Add general function definition about kernel_pte_init().
---
 arch/loongarch/include/asm/pgtable.h |  3 +++
 arch/mips/include/asm/pgtable-64.h   |  2 ++
 include/linux/mm.h                   |  3 ---
 include/linux/pgtable.h              | 21 +++++++++++++++++++++
 mm/kasan/init.c                      | 12 ------------
 mm/sparse-vmemmap.c                  | 12 ------------
 6 files changed, 26 insertions(+), 27 deletions(-)

diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/include/asm/pgtable.h
index 20714b73f14c..df5889d995f9 100644
--- a/arch/loongarch/include/asm/pgtable.h
+++ b/arch/loongarch/include/asm/pgtable.h
@@ -267,8 +267,11 @@ extern void set_pmd_at(struct mm_struct *mm, unsigned long addr, pmd_t *pmdp, pm
  * Initialize a new pgd / pud / pmd table with invalid pointers.
  */
 extern void pgd_init(void *addr);
+#define pud_init pud_init
 extern void pud_init(void *addr);
+#define pmd_init pmd_init
 extern void pmd_init(void *addr);
+#define kernel_pte_init kernel_pte_init
 extern void kernel_pte_init(void *addr);
 
 /*
diff --git a/arch/mips/include/asm/pgtable-64.h b/arch/mips/include/asm/pgtable-64.h
index 401c1d9e4409..45c8572a0462 100644
--- a/arch/mips/include/asm/pgtable-64.h
+++ b/arch/mips/include/asm/pgtable-64.h
@@ -316,7 +316,9 @@ static inline pmd_t *pud_pgtable(pud_t pud)
  * Initialize a new pgd / pud / pmd table with invalid pointers.
  */
 extern void pgd_init(void *addr);
+#define pud_init pud_init
 extern void pud_init(void *addr);
+#define pmd_init pmd_init
 extern void pmd_init(void *addr);
 
 /*
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 61fff5d34ed5..651bdc1bef48 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -3818,9 +3818,6 @@ void *sparse_buffer_alloc(unsigned long size);
 struct page * __populate_section_memmap(unsigned long pfn,
 		unsigned long nr_pages, int nid, struct vmem_altmap *altmap,
 		struct dev_pagemap *pgmap);
-void pud_init(void *addr);
-void pmd_init(void *addr);
-void kernel_pte_init(void *addr);
 pgd_t *vmemmap_pgd_populate(unsigned long addr, int node);
 p4d_t *vmemmap_p4d_populate(pgd_t *pgd, unsigned long addr, int node);
 pud_t *vmemmap_pud_populate(p4d_t *p4d, unsigned long addr, int node);
diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index e8b2ac6bd2ae..adee214c21f8 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -90,6 +90,27 @@ static inline unsigned long pud_index(unsigned long address)
 #define pgd_index(a)  (((a) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
 #endif
 
+#ifndef kernel_pte_init
+static inline void kernel_pte_init(void *addr)
+{
+}
+#define kernel_pte_init kernel_pte_init
+#endif
+
+#ifndef pmd_init
+static inline void pmd_init(void *addr)
+{
+}
+#define pmd_init pmd_init
+#endif
+
+#ifndef pud_init
+static inline void pud_init(void *addr)
+{
+}
+#define pud_init pud_init
+#endif
+
 #ifndef pte_offset_kernel
 static inline pte_t *pte_offset_kernel(pmd_t *pmd, unsigned long address)
 {
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index ac607c306292..ced6b29fcf76 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -106,10 +106,6 @@ static void __ref zero_pte_populate(pmd_t *pmd, unsigned long addr,
 	}
 }
 
-void __weak __meminit kernel_pte_init(void *addr)
-{
-}
-
 static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr,
 				unsigned long end)
 {
@@ -145,10 +141,6 @@ static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr,
 	return 0;
 }
 
-void __weak __meminit pmd_init(void *addr)
-{
-}
-
 static int __ref zero_pud_populate(p4d_t *p4d, unsigned long addr,
 				unsigned long end)
 {
@@ -187,10 +179,6 @@ static int __ref zero_pud_populate(p4d_t *p4d, unsigned long addr,
 	return 0;
 }
 
-void __weak __meminit pud_init(void *addr)
-{
-}
-
 static int __ref zero_p4d_populate(pgd_t *pgd, unsigned long addr,
 				unsigned long end)
 {
diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
index c0388b2e959d..cec67c5f37d8 100644
--- a/mm/sparse-vmemmap.c
+++ b/mm/sparse-vmemmap.c
@@ -184,10 +184,6 @@ static void * __meminit vmemmap_alloc_block_zero(unsigned long size, int node)
 	return p;
 }
 
-void __weak __meminit kernel_pte_init(void *addr)
-{
-}
-
 pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned long addr, int node)
 {
 	pmd_t *pmd = pmd_offset(pud, addr);
@@ -201,10 +197,6 @@ pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned long addr, int node)
 	return pmd;
 }
 
-void __weak __meminit pmd_init(void *addr)
-{
-}
-
 pud_t * __meminit vmemmap_pud_populate(p4d_t *p4d, unsigned long addr, int node)
 {
 	pud_t *pud = pud_offset(p4d, addr);
@@ -218,10 +210,6 @@ pud_t * __meminit vmemmap_pud_populate(p4d_t *p4d, unsigned long addr, int node)
 	return pud;
 }
 
-void __weak __meminit pud_init(void *addr)
-{
-}
-
 p4d_t * __meminit vmemmap_p4d_populate(pgd_t *pgd, unsigned long addr, int node)
 {
 	p4d_t *p4d = p4d_offset(pgd, addr);

base-commit: 81983758430957d9a5cb3333fe324fd70cf63e7e
-- 
2.39.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241030063905.2434824-1-maobibo%40loongson.cn.
