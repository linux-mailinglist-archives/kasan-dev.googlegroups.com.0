Return-Path: <kasan-dev+bncBAABBL4BRKAAMGQERKARDQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6503D2F8BC1
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Jan 2021 06:59:13 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id l2sf8065818pgi.5
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 21:59:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610776751; cv=pass;
        d=google.com; s=arc-20160816;
        b=uRLfBwggKd3iZ20fI2SYzHotCX7Q6nC1xCi+GSZ8nSzH8Zr7mnDaleVkOk5lEK6+5/
         7j8/N3q3P2C/FRWFDdGDfDffOe7bKH67MPI65i/KXUm8TZT8x4aLrRWoWCZs75wcb8W2
         lqnVgpUYCWDQlxMLrtByAlPEoBc6AM+TtYaecAqpW+ZJDGId7c8HfXT0f34xh88Uowc+
         /9UyWFlKPN4JbTX2LZAdKk7/wE6z148dl+kI7xDDV7nHw0r8u8jpKflYbLf4j9p68oyz
         HmygHvxVmvEfpKpC6twj6g7Gen7hzWEwJajNL35aMBgMd9g1aYUFElKP++a0xpiN56Z5
         a1iA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=YrSmRnm02JRBRk1OGWdxT/ONS+N8bajXWwUfx+iq5BI=;
        b=zlUYbtOKphYG/H0nJziYlb2d+3PbwNO0DxlcCdYYHYNwcUmIu+WGyZwDCdPL/3PoPs
         oqbdwGeir1sFuI/w2g1LYC7zYVE5crMmfRO4YjcnmF3L+zgNxaze+fuVVOH6OEv/XNNF
         QB5KD121gF014zL3OYzxrGrZw4a1xuVQJj/AwK71mCF1GuQGu8HxuMLr3yQAbkN/UJF3
         Ms7R4lRm9LF2sAvo4zfdHLHeL7RxnHGJH21/bbjVkkTe7HAL40yIGB31DlgBFPdhUoya
         WjJwNF1bInpALeGgtGfOa/mSAL90l5Zk5WGfm/LfwlnUZn/WZ5dfW8zRSen0M1BrS5HB
         6H7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) smtp.mailfrom=nylon7@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YrSmRnm02JRBRk1OGWdxT/ONS+N8bajXWwUfx+iq5BI=;
        b=GR/EYHo5OwGQYB334T9TAkSV6VF/18JQV4JHufMbyfjtEoPB5MYAy3+XxYdtG1ySyg
         9pHmfpG+CDVOer+mmzB2TJi7a4oAhUlZSyenyAKbeTXpmO/xTldS9N1NW0PTGBaQ6cyp
         V6BcHZm67WPfIIY8n3GCHtwkqmTJ0zpdxovW+roYquIRpbXrCOBBeIkLsbRF8jo8JpyF
         EUedXfO2EI2bulAjePXPwDPzamiUPR4CyUK71Bky92rY6jlHphyPZZTu2nN6ahhIbLFj
         eu0u4XW2JOZ1okqBFo9C8eTm99Em3OR1Rz8/cMsNKwvJ8Cc6fEzoewJnlicLQEAc0IRS
         V4Ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YrSmRnm02JRBRk1OGWdxT/ONS+N8bajXWwUfx+iq5BI=;
        b=CagSV+vLFZ7/8CjF4RfotXQtR7GhhlrRILdSJu773J32QA+5B9OdtTScn7rWAA3ysK
         zH5g6jKRc+hfSXOpusJR7uJhGe1K7/ER+vNM6DhiaUUogxo1mTHQjq/peBIkU2XFYNuh
         O6W+D3RJf8ZlU5svdD7+gGcUzSHs4WGLxnmX4346ws6pYVrLd8nbhqE28svt7+zjkX80
         lv3hk0zMuodzBek0Ay14plin5ljAU3b819iRjECQCVAhhkJk7Jx9vuOzFLfF9CmwhuGK
         UjqqQa72JYZpHVQ9+reJVlzVUcgLvwzuFFztOgifFkWx4yyCJ+gGigSSmGSgcEAVWUMF
         Jc6g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533RGGhGNnESJsll3kbdUebRRwr8s9f3HIG0dzV2hbh8BfnF7eav
	kVc5uy10KGZ917DHwbD5iqw=
X-Google-Smtp-Source: ABdhPJzw3h22IS2TYZNuthBnxEWnxkNxilMRaldN7HeHzsCn0FWxEUjhGiQdIYRoGZX7tjyyJpRphA==
X-Received: by 2002:a17:902:c38b:b029:db:fa4b:5d31 with SMTP id g11-20020a170902c38bb02900dbfa4b5d31mr15942125plg.5.1610776751714;
        Fri, 15 Jan 2021 21:59:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:511:: with SMTP id r17ls5616973pjz.1.canary-gmail;
 Fri, 15 Jan 2021 21:59:11 -0800 (PST)
X-Received: by 2002:a17:902:ed83:b029:de:84d2:9ce9 with SMTP id e3-20020a170902ed83b02900de84d29ce9mr3234570plj.2.1610776751224;
        Fri, 15 Jan 2021 21:59:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610776751; cv=none;
        d=google.com; s=arc-20160816;
        b=nHpxg3eoQyq3nNboju48NX6PfM2bi9sOgwPkf8NYRYJL8UKG6sKubjPmg14azYhyKG
         Vu9g3tLlZVlaOcTlZuhbzgOyHV+knoY5axuSvr2SJoNB+UZTMlIgQ634doJRZ2IlYkMf
         oIwbxYktj0iEHpw2EoKZVaBVr5U9/wHK9fDy73ebCEzooK9EokuuwXx9nPsW3dW+/7ni
         4bi0mbQ11daxNq9kGHlClwpxY1OsVwTehkyuPZocUoBixQXSPbELb1/+w5LTGCMRZ1wB
         PskH7fhsvz6bKDmgm0amgIlrWSPple920cSlKiUvwE/c75Oo55lC/PVq1/EA8doW9ayG
         1rOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=4YkDMXQjs2v2UYjBhZNJvU7Cj01XQD4cLghVR7A3Jug=;
        b=X1j2nNlN6JDfUcoWwJbRZfQtCXx/yX6CfMyV8rysx1D148NWsTa2ZoZmGwDBEU4bDZ
         f31pyjYT9mxf2kY1Mpj2yzgpkI0FKIp/4/T5LU7Rr/XgfnOObVq9Xa5+b+GQLhpAKVSn
         qYXGrMBCd5UjX6Cjkj0icKdPU3yPzAHtuJfeWhn3fNPgZaP1Bxj1QM1b5n4DXTWsV8zM
         Ut/20iLopUblkE8Gqx1iOwCEgi9bQrlb1VHHvwFzMxNZa2S2eNMrR/bAi0VRiWidbAoR
         aa2Rx6nRfZDetoXe+WbKp/GmEJHpTI+T3bkJTxMlBT5Nv7T6NfHWLKRvdBiZtuMBKCF4
         OLrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) smtp.mailfrom=nylon7@andestech.com
Received: from ATCSQR.andestech.com (atcsqr.andestech.com. [60.248.187.195])
        by gmr-mx.google.com with ESMTPS id q15si871629pfs.1.2021.01.15.21.59.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Jan 2021 21:59:11 -0800 (PST)
Received-SPF: pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) client-ip=60.248.187.195;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id 10G5tmlX057678;
	Sat, 16 Jan 2021 13:55:48 +0800 (GMT-8)
	(envelope-from nylon7@andestech.com)
Received: from atcfdc88.andestech.com (10.0.15.120) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.487.0; Sat, 16 Jan 2021
 13:58:44 +0800
From: Nylon Chen <nylon7@andestech.com>
To: <linux-kernel@vger.kernel.org>, <linux-riscv@lists.infradead.org>,
        <kasan-dev@googlegroups.com>
CC: <paul.walmsley@sifive.com>, <palmer@dabbelt.com>, <aou@eecs.berkeley.edu>,
        <aryabinin@virtuozzo.com>, <glider@google.com>, <dvyukov@google.com>,
        <nylon7717@gmail.com>, <alankao@andestech.com>, <nickhu@andestech.com>,
        "Nylon Chen" <nylon7@andestech.com>
Subject: [PATCH v2 1/1] riscv/kasan: add KASAN_VMALLOC support
Date: Sat, 16 Jan 2021 13:58:35 +0800
Message-ID: <20210116055836.22366-2-nylon7@andestech.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20210116055836.22366-1-nylon7@andestech.com>
References: <20210116055836.22366-1-nylon7@andestech.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.0.15.120]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com 10G5tmlX057678
X-Original-Sender: nylon7@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as
 permitted sender) smtp.mailfrom=nylon7@andestech.com
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

It references to x86/s390 architecture.

So, it doesn't map the early shadow page to cover VMALLOC space.

Prepopulate top level page table for the range that would otherwise be
empty.

lower levels are filled dynamically upon memory allocation while
booting.

Signed-off-by: Nylon Chen <nylon7@andestech.com>
Signed-off-by: Nick Hu <nickhu@andestech.com>
---
 arch/riscv/Kconfig         |  1 +
 arch/riscv/mm/kasan_init.c | 57 +++++++++++++++++++++++++++++++++++++-
 2 files changed, 57 insertions(+), 1 deletion(-)

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index 81b76d44725d..15a2c8088bbe 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -57,6 +57,7 @@ config RISCV
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if MMU && 64BIT
+	select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_KGDB_QXFER_PKT
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 12ddd1f6bf70..4b9149f963d3 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -9,6 +9,19 @@
 #include <linux/pgtable.h>
 #include <asm/tlbflush.h>
 #include <asm/fixmap.h>
+#include <asm/pgalloc.h>
+
+static __init void *early_alloc(size_t size, int node)
+{
+	void *ptr = memblock_alloc_try_nid(size, size,
+		__pa(MAX_DMA_ADDRESS), MEMBLOCK_ALLOC_ACCESSIBLE, node);
+
+	if (!ptr)
+		panic("%pS: Failed to allocate %zu bytes align=%zx nid=%d from=%llx\n",
+			__func__, size, size, node, (u64)__pa(MAX_DMA_ADDRESS));
+
+	return ptr;
+}
 
 extern pgd_t early_pg_dir[PTRS_PER_PGD];
 asmlinkage void __init kasan_early_init(void)
@@ -83,6 +96,40 @@ static void __init populate(void *start, void *end)
 	memset(start, 0, end - start);
 }
 
+void __init kasan_shallow_populate(void *start, void *end)
+{
+	unsigned long vaddr = (unsigned long)start & PAGE_MASK;
+	unsigned long vend = PAGE_ALIGN((unsigned long)end);
+	unsigned long pfn;
+	int index;
+	void *p;
+	pud_t *pud_dir, *pud_k;
+	pgd_t *pgd_dir, *pgd_k;
+	p4d_t *p4d_dir, *p4d_k;
+
+	while (vaddr < vend) {
+		index = pgd_index(vaddr);
+		pfn = csr_read(CSR_SATP) & SATP_PPN;
+		pgd_dir = (pgd_t *)pfn_to_virt(pfn) + index;
+		pgd_k = init_mm.pgd + index;
+		pgd_dir = pgd_offset_k(vaddr);
+		set_pgd(pgd_dir, *pgd_k);
+
+		p4d_dir = p4d_offset(pgd_dir, vaddr);
+		p4d_k  = p4d_offset(pgd_k, vaddr);
+
+		vaddr = (vaddr + PUD_SIZE) & PUD_MASK;
+		pud_dir = pud_offset(p4d_dir, vaddr);
+		pud_k = pud_offset(p4d_k, vaddr);
+
+		if (pud_present(*pud_dir)) {
+			p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
+			pud_populate(&init_mm, pud_dir, p);
+		}
+		vaddr += PAGE_SIZE;
+	}
+}
+
 void __init kasan_init(void)
 {
 	phys_addr_t _start, _end;
@@ -90,7 +137,15 @@ void __init kasan_init(void)
 
 	kasan_populate_early_shadow((void *)KASAN_SHADOW_START,
 				    (void *)kasan_mem_to_shadow((void *)
-								VMALLOC_END));
+								VMEMMAP_END));
+	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
+		kasan_shallow_populate(
+			(void *)kasan_mem_to_shadow((void *)VMALLOC_START),
+			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
+	else
+		kasan_populate_early_shadow(
+			(void *)kasan_mem_to_shadow((void *)VMALLOC_START),
+			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
 
 	for_each_mem_range(i, &_start, &_end) {
 		void *start = (void *)_start;
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210116055836.22366-2-nylon7%40andestech.com.
