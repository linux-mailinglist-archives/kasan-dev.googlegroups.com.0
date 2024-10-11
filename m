Return-Path: <kasan-dev+bncBAABBZHBUO4AMGQEEUUD6KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id BBCF099A02C
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 11:33:35 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-2e2eba0efc6sf783310a91.3
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 02:33:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728639205; cv=pass;
        d=google.com; s=arc-20240605;
        b=DKiod8xUNyPJdkrbLX3v5mrmaj+EHzvi1ORbXxgnK/nvx6uXV9ny5ng4cAZ7esDjNT
         MXyrrlNhAi8dUJuWtYixgcvKK7kSOj5gaD8F2BGMhzWoHZShCqWTylZKeD8wC+spQuQG
         m2LWAW2ggpT9QM5Mxe6EyxaSMWesVix55EDfkNI/DYW2v1dE5tQgULtJN/2JdtrLpvtg
         bgUnLtofQUvt/KviNlzDw/fA/SMxHlj+rDeCuwjPRkwl9lar8jNOyGyWgTUblfYKp0cs
         PQqOWGVfsCb5cMkP+zHxXM90JVo0WPvVg0riHDwxnWox992vaCn8mX70HXWkwpYA/CW/
         Uveg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=2t0mTxQq+J+yWybetYUqD4nbOOv8N96bVn1Tf/z6f+Y=;
        fh=nHMmI1MSsjVDbCXLsdypN5AGCQ6HINX7JhufgJFB0tg=;
        b=FMjkKatwfxfneqFIxJSraODAumRSqyDyZizu0P7a3e7s9KuQyWq27dTHxrYJO6nPRI
         zj3lLWLbOrxmd4myLkT8VoLy5COYLpJJyHKlDjPnwjNMkOS2yuTN/EiSM4pJG329ifZb
         SyN6LSg7OLdYRAIdeyQdCVCauNKjtO3DlfccMM4lf4IMmNLL8o1X7BvLqAY/Gwmjuoqp
         b+COzXyI+l4c8EK8fbGM4/03IoYhgH0sQCdFtcXSMZqtjW6a+9JoScO/pC+J2VAJ6ZW8
         TqK5ljsJHDaFUkhXUCAmq9vYJHHDA6DGq8CMP0gCTTbsEIlemLxZnPsUJhni5G5jcI6q
         u4fA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728639205; x=1729244005; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2t0mTxQq+J+yWybetYUqD4nbOOv8N96bVn1Tf/z6f+Y=;
        b=whYj6Wehu31U685APGtPuuMzXxSHkAcM3PwBBltpBTc12ZLGV84SZRciNbEbybFzPU
         LBAWH/sFIJM+G5a3nDFwTKOVA1zMQhgt1GONtn2eCgI24Djr87OstWL3co9Qyqzxq0mu
         ZzlbWVrPA1ZJ3f+yymBqTN3vNxB3Hyzwz5oM0g+Lba3RQmGnT/ClcviT/m971biKtSdR
         IYzd73iQShdyQC9uFUTsO7MFH5Cn/OpUty2tw1EZFvr11Imi8cMKTih1L3waj5uzfjOd
         djvDG931zMGpFb+JLJznbJsrz6Rbk1xjNf7hvYFNQloUD4+aGXqNOvdEjdyYnMjGpTXC
         epQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728639205; x=1729244005;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2t0mTxQq+J+yWybetYUqD4nbOOv8N96bVn1Tf/z6f+Y=;
        b=NeSQuukpCEi5zvnE7TBA2dTMz84p6eAkAz8QApLxSeXE2GvblVdohgWvFMBc3uF1WA
         12vv7rEAoQE7UjrV0ECbO/NLHEJ/3PIFH0l68xQuulqx9WegibdRY/mHcPu3wfY0emnP
         MwQMgRThr4uwbZLN89l4Y4LPD8HQEVgFqyTusAGw7bDuY25c/PJid0T+a7xdDOZP77Ib
         reGYQWdzfh0kQYgnry4bHEZPcd1aS1HNNlRxjbkX5rcojrQCxrTMkBUZCDbDtrnLoXmP
         jVaz7c7G6cTeh30+JbPj8MjecHLvxxs8CS92SX2SDhS+uvUld3oT5meSeUCKZ541Nl9Z
         62og==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXNfHww80Yl+80Y5M53G0GMqvwhGFMUYP8X9VXTRznOgzkBrNEe8kZ1HDVChiYDJCF302BXZw==@lfdr.de
X-Gm-Message-State: AOJu0YyLvU8Ku4MfYTGQx1w95F7cqxHxifw4HVDoP0wIW75Emq6g7Rg2
	4ebbnpks/9FmASvx2Wn16QpNdvBhZg5t8cRFr8jmaTFjxnhswAvZ
X-Google-Smtp-Source: AGHT+IHW61yv73+qjCcQmVpSsYH5Z2aGNIs/rT0c4l3wqwEKqRrNWn9CbBHv8Igdzceb9Myosl61sQ==
X-Received: by 2002:a17:90a:3ea4:b0:2e2:bd34:f23b with SMTP id 98e67ed59e1d1-2e2f0c5c35dmr2669904a91.32.1728639204498;
        Fri, 11 Oct 2024 02:33:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c7c9:b0:2e1:1d4a:962a with SMTP id
 98e67ed59e1d1-2e2c833665els163096a91.1.-pod-prod-04-us; Fri, 11 Oct 2024
 02:33:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWP2x+tisAazTnSsQZnnWyCZVEwS5S+AgQqgf0ov4KnYCw35Aue2FzctCvZUyrw+X0v7sqOP21DbYk=@googlegroups.com
X-Received: by 2002:a17:90b:60d:b0:2e2:af54:d2fe with SMTP id 98e67ed59e1d1-2e2f0d83174mr2529982a91.34.1728639203418;
        Fri, 11 Oct 2024 02:33:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728639203; cv=none;
        d=google.com; s=arc-20240605;
        b=fe0UAyrFfgwWRAHxxozHGSk1cQUZkTh1WL++NXx7vEVtKjmlpEedDw01AvklyuIR38
         23ZfefwpAxLmMGvQRYsguiS4VZARC5jTnvnd0luXUQlH30kgVKcUnGTAqI4bgMWj7kgt
         ZBYUr3AUl02fG0Nq2GyNzbl+3i1LofbpW4njDemoiHqncLwMmDYUuTVeAE9IKpg0qfED
         GlGIPPsyhf759SJH3+PX296HNcur/2wefgmdfBbYxBgOgeva6dzPmEX7+PhNNa0irZHm
         nQKJ9G9YheMMIbfBTu4BD8UgyJQMArXnpHQGdLgBV7jmflSbwDN9zCwjL70o64Emt37w
         s7kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=MV0mExEMqeShhBINf+q9yEBzo1MDm85GoJhRrKQ0pFY=;
        fh=yVUclo9opHBnbqbD8AfTlsT9ezAtQVHhJdUcfhcVps8=;
        b=fyacFblZV6YNnYwu3UP0ERzd5Tmi/s9zy7QBgQoWlvm/W2p84sJub+tFSlHQ3W0sKl
         gyHrAkqJvO8ieGpMj9fcfF62a5ZeyS/+UnZgo7wTWiZFkids4TZ5Qzbil1PMAJJ+SJEb
         ggj77j2hH+/F8wKbcBO4cDnmpWGDDDDcQsMGXZctBkm7F0lL63kkRsjMCidW+MkDTs1E
         cV/dBfHSdGIVaawNgi1dPgvcseBNECZg2SP8Yged/YGd9sFz/bNaPHPrwwC5eRI6t9qb
         GDtANn8fukdliIFBGadVFsZhMWFDVAPWW0+SR58xUb+a87lMybxK9anT+lYzwaWR08yy
         CGFQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-2e281a92590si626411a91.0.2024.10.11.02.33.22
        for <kasan-dev@googlegroups.com>;
        Fri, 11 Oct 2024 02:33:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.2.5.213])
	by gateway (Coremail) with SMTP id _____8Bx14ng8Ahnq2QTAA--.28249S3;
	Fri, 11 Oct 2024 17:33:20 +0800 (CST)
Received: from localhost.localdomain (unknown [10.2.5.213])
	by front1 (Coremail) with SMTP id qMiowMBxXuTf8AhnWK8jAA--.48225S2;
	Fri, 11 Oct 2024 17:33:19 +0800 (CST)
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
Subject: [PATCH] mm: Define general function pXd_init()
Date: Fri, 11 Oct 2024 17:33:18 +0800
Message-Id: <20241011093318.519432-1-maobibo@loongson.cn>
X-Mailer: git-send-email 2.39.3
MIME-Version: 1.0
X-CM-TRANSID: qMiowMBxXuTf8AhnWK8jAA--.48225S2
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

Function pmd_init() and pud_init() are duplicated defined in file kasan.c
and sparse-vmemmap.c as weak function. Now move them to generic header
file pgtable.h, architecture can redefine them.

Signed-off-by: Bibo Mao <maobibo@loongson.cn>
---
 arch/loongarch/include/asm/pgtable.h |  2 ++
 arch/mips/include/asm/pgtable-64.h   |  2 ++
 include/linux/mm.h                   |  2 --
 include/linux/pgtable.h              | 14 ++++++++++++++
 mm/kasan/init.c                      |  8 --------
 mm/sparse-vmemmap.c                  |  8 --------
 6 files changed, 18 insertions(+), 18 deletions(-)

diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/include/asm/pgtable.h
index 9965f52ef65b..8bd653a6fa70 100644
--- a/arch/loongarch/include/asm/pgtable.h
+++ b/arch/loongarch/include/asm/pgtable.h
@@ -267,7 +267,9 @@ extern void set_pmd_at(struct mm_struct *mm, unsigned long addr, pmd_t *pmdp, pm
  * Initialize a new pgd / pud / pmd table with invalid pointers.
  */
 extern void pgd_init(void *addr);
+#define pud_init pud_init
 extern void pud_init(void *addr);
+#define pmd_init pmd_init
 extern void pmd_init(void *addr);
 
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
index ecf63d2b0582..651bdc1bef48 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -3818,8 +3818,6 @@ void *sparse_buffer_alloc(unsigned long size);
 struct page * __populate_section_memmap(unsigned long pfn,
 		unsigned long nr_pages, int nid, struct vmem_altmap *altmap,
 		struct dev_pagemap *pgmap);
-void pmd_init(void *addr);
-void pud_init(void *addr);
 pgd_t *vmemmap_pgd_populate(unsigned long addr, int node);
 p4d_t *vmemmap_p4d_populate(pgd_t *pgd, unsigned long addr, int node);
 pud_t *vmemmap_pud_populate(p4d_t *p4d, unsigned long addr, int node);
diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index e8b2ac6bd2ae..bec5356ee644 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -90,6 +90,20 @@ static inline unsigned long pud_index(unsigned long address)
 #define pgd_index(a)  (((a) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
 #endif
 
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
index 89895f38f722..6b2dac62e63a 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -139,10 +139,6 @@ static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr,
 	return 0;
 }
 
-void __weak __meminit pmd_init(void *addr)
-{
-}
-
 static int __ref zero_pud_populate(p4d_t *p4d, unsigned long addr,
 				unsigned long end)
 {
@@ -181,10 +177,6 @@ static int __ref zero_pud_populate(p4d_t *p4d, unsigned long addr,
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
index edcc7a6b0f6f..a0c884947861 100644
--- a/mm/sparse-vmemmap.c
+++ b/mm/sparse-vmemmap.c
@@ -196,10 +196,6 @@ pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned long addr, int node)
 	return pmd;
 }
 
-void __weak __meminit pmd_init(void *addr)
-{
-}
-
 pud_t * __meminit vmemmap_pud_populate(p4d_t *p4d, unsigned long addr, int node)
 {
 	pud_t *pud = pud_offset(p4d, addr);
@@ -213,10 +209,6 @@ pud_t * __meminit vmemmap_pud_populate(p4d_t *p4d, unsigned long addr, int node)
 	return pud;
 }
 
-void __weak __meminit pud_init(void *addr)
-{
-}
-
 p4d_t * __meminit vmemmap_p4d_populate(pgd_t *pgd, unsigned long addr, int node)
 {
 	p4d_t *p4d = p4d_offset(pgd, addr);

base-commit: 87d6aab2389e5ce0197d8257d5f8ee965a67c4cd
-- 
2.39.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241011093318.519432-1-maobibo%40loongson.cn.
