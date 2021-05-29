Return-Path: <kasan-dev+bncBAABBRG3Y6CQMGQEMTDHNXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id AFDA1394AE8
	for <lists+kasan-dev@lfdr.de>; Sat, 29 May 2021 09:31:18 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id s3-20020a0568080083b02901eee88a8f42sf2943594oic.11
        for <lists+kasan-dev@lfdr.de>; Sat, 29 May 2021 00:31:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622273477; cv=pass;
        d=google.com; s=arc-20160816;
        b=F0WcQ5RGGvXf/8UA9iHgH/GRa996pQWuXLewGxY/egyhg556T8gltjbJcO87PB5Ek4
         R0uI4AIKErppd+12tq4q2y1Crxk0jmjYYXk34wHs5rgEpm/qtpOWOn3QXV6KsvizIKf5
         GwL5VgA9+sHDlGlrjU2PsmmuZWOV/HixU3G6TeAUG9yBtP7EHPouMgevoRpIf6J4bW3+
         qUlww5+yUDF1pcFJQzr+3RD4d9owPCk1gfZCzyv1pai8lbArbcbQIPQZE+ALVqovyjIR
         KoZfj9PFF0p6YwR9jJTrQGLj21zaZOedQYYGtKNv80JvJn/+gMmz79HE4z4KWdLovq3q
         szoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=/Mb7qVT/0xKar6543KNVheMSYi6qYuvLWj6w1YtahHY=;
        b=qFOb0IbK0krDISSgMbMPZrRWCpRMG4DsRjKANoEDvnzdYKRj4+UcCqhLYyzaL8s/1r
         2L/4Y9agDPH0z/B6Yc02lZqtN3nVG1A8WG1xu0YT1BJm1jk2ILIe1/ozwpx4pSVA6jTx
         /wm0+L2qJt2uBG10h/YDK7cj2a4fRdgGyVX6+1U8ZHdvwLIk1ixIXz1s4VSp34n8uO8W
         MBph81rbDFgkRl5Fs0r6dveMIFPaIdZteCJ/6y6G6BydGOeFiOCcI2Hn8yK0pK4UP5F+
         pEl0ST4+pQP5HBoq+x9p8LDkh2zY+OxYavQUIT8xDYUpGGBXJsLrd62nwoESQpbrhnPg
         TTXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/Mb7qVT/0xKar6543KNVheMSYi6qYuvLWj6w1YtahHY=;
        b=axEixxbMqyoIoRdgibCMfbJLu2vRipFZy9tzx0qM5NzaSq7QROKP5FEybymaPqSsXe
         mHyqsyZhzWp8OJSnzis/gyFBqAMhQ1QmEFI5YRLdAt2e3IhtITUaPuVQXb4LhcsWrydy
         dMvwQQdqp0SotYK43cJsu8GuLVRjB36jFOeh/EAORS+eH+vRFQexGu52PDgDXa2Ac76s
         ptMVQyMKKYBeldOYODCI/67Fo3WT68N3DrBvtnrsbLSKpzpugr2hq7JaAsq5uEu0lnc+
         t2KuGlbxLTt1Xs5evNQWghQnxsqxoZcl2eFbbgqUO2leQZ9BzvuFO9qWMYHfDOFoC4Mt
         rhpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/Mb7qVT/0xKar6543KNVheMSYi6qYuvLWj6w1YtahHY=;
        b=jx4jRVS053t95xDbeNfJ0LzZBYW27jQTj4RQxOBDvbW7SmDuOPaFX0Th+ic7MxJ/cf
         K25Ro9YcByNimiuHWpbcRetTT4m28sqGE3RBR2IGHN0S31uF2hl3FaLPPwoAw4TRkqj5
         Ub/X6oqqwPYlzjQb/3yn58hhzSMAioRFr30awggRr1UcAEIEtLriBV+fdZNU6bAfhrK1
         4T09vdoqmmNVud8Pvs7UA4cDHnF59ZiQOvHNg44KJTlqbsRnI791rbo2kQBVD67poMYa
         yb3xMz/cuqD9Db8XOcsBzyZnFHEDkm/eVNHmVc6wsxt64qNHDCfsike5KlR0gv7dYKAr
         oZnQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533M2M8kwqwQLRLl8900MqDQv1eNEGSXi0C2tQk34covsZTEnQNP
	IdAjI4njvV0WYVFcjkNbHAo=
X-Google-Smtp-Source: ABdhPJwN2pT0Z4SpfwCvG8UOQmf+ehTQCkebOB6b+naR4+zwFtxsa2/WICdcooRYGv35Pls2w/CECQ==
X-Received: by 2002:a05:6808:128a:: with SMTP id a10mr11693517oiw.161.1622273476374;
        Sat, 29 May 2021 00:31:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:77d1:: with SMTP id w17ls2734840otl.5.gmail; Sat, 29 May
 2021 00:31:16 -0700 (PDT)
X-Received: by 2002:a9d:7410:: with SMTP id n16mr9916393otk.262.1622273476087;
        Sat, 29 May 2021 00:31:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622273476; cv=none;
        d=google.com; s=arc-20160816;
        b=W7eyCXuiEgsNsgmoKR/QrJ2AKwCODHexEfXFQdwbxS4RjgTgx1BZ5V/eGluVuz2JRy
         6aaMjSa54ROmriGyioEckzKFKNSfN0hB1Yhn9Hf/M2zv2jE23gniyq4sPOI+YD+yoVd5
         WY4ozhq0s3PA9Nsb5308uzu6L8GIJyCkKUEZq2tA0IVnpX1VwcavLrsjfXFO/jVpZSFC
         FYFjqasm8WMzbzXSwnpA9Uy73G3A2lG/LjdOq3x9q4NhSe66PloNTMuezHO3g6gsGcKp
         ETtKq47czFknL9TOHz3pTk802rTZQMr0aaDIu2vvbmHeWsLUIJxQTRjme/nrLw2IY10c
         1mGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=Gy5nwgidZDYOgpUym7Cj6gFsP13g8wiS0WTVsg1IKkk=;
        b=my2c5a6xKKNaTNIR8bUNNyrd059+ZhJBgq7/jZGHWyfonxV4ZxFaMZDDBheUkSeuoA
         VKyNx5kKgpRoxNeSAUXUu0Xt5+B6zERWHb9x1ps1r6uygVMhZ2aN5PIvd88DeGYNMK/u
         sxlbkz2VC9hOomzr/Ao95RADg/LOBwGDNOdtEokHcVjio32Rpo/w/1enGt71iy5ZNbYn
         ARmyKNYMVZC86vyZTn1XSSYbTa8wO8gR+oPCWOymPLP+Qg58rc0siZxYOTfbyxqU67gz
         OoOh6aWeHyC/6oQNDUYuBCaOIO4VIBUbUHs4G3W7+J+LXQEw/u9Qup+iihhKEN1IYHZr
         l6PA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id c22si610527oiy.1.2021.05.29.00.31.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 29 May 2021 00:31:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.56])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4FsY7g50KqzYnXs;
	Sat, 29 May 2021 15:28:31 +0800 (CST)
Received: from dggpemm500009.china.huawei.com (7.185.36.225) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Sat, 29 May 2021 15:31:12 +0800
Received: from huawei.com (10.175.113.32) by dggpemm500009.china.huawei.com
 (7.185.36.225) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id 15.1.2176.2; Sat, 29 May
 2021 15:31:12 +0800
From: Liu Shixin <liushixin2@huawei.com>
To: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
	<palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Alexander Potapenko
	<glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
	<dvyukov@google.com>
CC: <linux-riscv@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Liu Shixin <liushixin2@huawei.com>
Subject: [PATCH -next] riscv: Enable KFENCE for riscv64
Date: Sat, 29 May 2021 16:03:40 +0800
Message-ID: <20210529080340.2987212-1-liushixin2@huawei.com>
X-Mailer: git-send-email 2.18.0.huawei.25
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.32]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 dggpemm500009.china.huawei.com (7.185.36.225)
X-CFilter-Loop: Reflected
X-Original-Sender: liushixin2@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liushixin2@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=liushixin2@huawei.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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

Add architecture specific implementation details for KFENCE and enable
KFENCE for the riscv64 architecture. In particular, this implements the
required interface in <asm/kfence.h>.

KFENCE requires that attributes for pages from its memory pool can
individually be set. Therefore, force the kfence pool to be mapped at
page granularity.

Testing this patch using the testcases in kfence_test.c and all passed.

Signed-off-by: Liu Shixin <liushixin2@huawei.com>
---
1. Add helper function split_pmd_page() which is used to split a pmd to ptes. 
2. Add the judgment on the result of pte_alloc_one_kernel().

 arch/riscv/Kconfig              |  1 +
 arch/riscv/include/asm/kfence.h | 63 +++++++++++++++++++++++++++++++++
 arch/riscv/mm/fault.c           | 11 +++++-
 3 files changed, 74 insertions(+), 1 deletion(-)
 create mode 100644 arch/riscv/include/asm/kfence.h

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index 4982130064ef..2f4903a7730f 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -65,6 +65,7 @@ config RISCV
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if MMU && 64BIT
 	select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
+	select HAVE_ARCH_KFENCE if MMU && 64BIT
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_KGDB_QXFER_PKT
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
diff --git a/arch/riscv/include/asm/kfence.h b/arch/riscv/include/asm/kfence.h
new file mode 100644
index 000000000000..d887a54042aa
--- /dev/null
+++ b/arch/riscv/include/asm/kfence.h
@@ -0,0 +1,63 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+#ifndef _ASM_RISCV_KFENCE_H
+#define _ASM_RISCV_KFENCE_H
+
+#include <linux/kfence.h>
+#include <linux/pfn.h>
+#include <asm-generic/pgalloc.h>
+#include <asm/pgtable.h>
+
+static inline int split_pmd_page(unsigned long addr)
+{
+	int i;
+	unsigned long pfn = PFN_DOWN(__pa((addr & PMD_MASK)));
+	pmd_t *pmd = pmd_off_k(addr);
+	pte_t *pte = pte_alloc_one_kernel(&init_mm);
+
+	if (!pte)
+		return -ENOMEM;
+
+	for (i = 0; i < PTRS_PER_PTE; i++)
+		set_pte(pte + i, pfn_pte(pfn + i, PAGE_KERNEL));
+	set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa(pte)), PAGE_TABLE));
+
+	flush_tlb_kernel_range(addr, addr + PMD_SIZE);
+	return 0;
+}
+
+static inline bool arch_kfence_init_pool(void)
+{
+	int ret;
+	unsigned long addr;
+	pmd_t *pmd;
+
+	for (addr = (unsigned long)__kfence_pool; is_kfence_address((void *)addr);
+	     addr += PAGE_SIZE) {
+		pmd = pmd_off_k(addr);
+
+		if (pmd_leaf(*pmd)) {
+			ret = split_pmd_page(addr);
+			if (ret)
+				return false;
+		}
+	}
+
+	return true;
+}
+
+static inline bool kfence_protect_page(unsigned long addr, bool protect)
+{
+	pte_t *pte = virt_to_kpte(addr);
+
+	if (protect)
+		set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
+	else
+		set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
+
+	flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
+
+	return true;
+}
+
+#endif /* _ASM_RISCV_KFENCE_H */
diff --git a/arch/riscv/mm/fault.c b/arch/riscv/mm/fault.c
index 096463cc6fff..aa08dd2f8fae 100644
--- a/arch/riscv/mm/fault.c
+++ b/arch/riscv/mm/fault.c
@@ -14,6 +14,7 @@
 #include <linux/signal.h>
 #include <linux/uaccess.h>
 #include <linux/kprobes.h>
+#include <linux/kfence.h>
 
 #include <asm/ptrace.h>
 #include <asm/tlbflush.h>
@@ -45,7 +46,15 @@ static inline void no_context(struct pt_regs *regs, unsigned long addr)
 	 * Oops. The kernel tried to access some bad page. We'll have to
 	 * terminate things with extreme prejudice.
 	 */
-	msg = (addr < PAGE_SIZE) ? "NULL pointer dereference" : "paging request";
+	if (addr < PAGE_SIZE)
+		msg = "NULL pointer dereference";
+	else {
+		if (kfence_handle_page_fault(addr, regs->cause == EXC_STORE_PAGE_FAULT, regs))
+			return;
+
+		msg = "paging request";
+	}
+
 	die_kernel_fault(msg, addr, regs);
 }
 
-- 
2.18.0.huawei.25

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210529080340.2987212-1-liushixin2%40huawei.com.
