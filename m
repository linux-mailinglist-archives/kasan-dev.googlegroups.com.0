Return-Path: <kasan-dev+bncBAABBH5EUCDAMGQE4EF4Y7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A23B3A7415
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 04:36:17 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id j11-20020a170902758bb02900ec9757f3dbsf5325964pll.17
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Jun 2021 19:36:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623724576; cv=pass;
        d=google.com; s=arc-20160816;
        b=IY3mjcE0Ocdk/fXISXJUcldiO1HgfB1gfkch0DlTAAxVVMm23IQCQuA/bXKcXetCx/
         nFvS0rHGbea1gzo5u6WuTUcIza9wY55kg8LdFETrkx9Q+taMMdGA0nowfcTG6J9A1wef
         wsw0td0J751V4HaYSdmpfX+Shf7iNjezaloSDbVm3uSoWOK7Xd6gUnE+OoAFJ3KoicOA
         1x33kYUmAe/asxQEwOgVrqml5Pki9CflfgGuUNmMk86HnlqZ62te16tF2VwtiBLBTmgr
         nb9mIWJQvvAb9DR07Vn3LOogAvqgBJm2ks/tneCHaELtidjRJnW81yCJJVKukvtO+t3+
         caNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=h2wJnro21PYxVTbspeBbYpMgdCYxFbUfTuHPR3CMvms=;
        b=TpgzcZBtCbCisjC64DqtmC+AqH5DnE/Vf4bKxCCVdj7N97CvMlSnJd2nAMDdKOo4vL
         Qcw+8l6EBabh2RVZiM8tBaNiKP3jRZMnlzc2EKnAXDbImKs7prBvoY4GZrf6lj3D7hiZ
         g9xGtcmvRG2d4pG1nnmY1cBaoIFQkqRJtMeg0Yi8IFe2pOW0RxBpyDEScDjhvnkaBWka
         E7it+kAocnGk/LSGa5dg9gSOo3CqQiEvQxKnz4a6NZj7hGePL4VJAZCSVdg9hcYEEKCj
         /Jrfk3BBkzRmWYkaL6Z9gf/lRmrKSl6InYABDO5Du01ZyrdhSMB0jFS2E0pAHqj4EmuK
         1CwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h2wJnro21PYxVTbspeBbYpMgdCYxFbUfTuHPR3CMvms=;
        b=tjyAEgnk/UUBm5l8mBC3P3LUSKnkG9hFayXeTKS4g7H67xEuW1uajllKtCb2reWJzS
         MxyVQfxrH4jfc7qeR4E9jSfmHM+Ig5pLwFESnjM/9yB1q+ft3n1/UF0faFeAqI1JtIBS
         98TSEISI5tTWLNJAjk6Q/BivBzSORlUFT5rdMd5Q3+xIA4/QHwBQI0Z1r4mIpz3ELeil
         pKBBaKzfJVfMYCAYessbLcfvsm9grFyy7jBWAN3ZUbxjDaDSq7RAy4+xIm5lGNiq2Duc
         db6y4JTj5vAcR5AoRbUy9l+zmpza/YoG3d8mNDbdV0+bXZB3L+4msxPi1kXgIr6rsV9N
         quvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=h2wJnro21PYxVTbspeBbYpMgdCYxFbUfTuHPR3CMvms=;
        b=DM8HnS6J8sL5eun8iywCLa/OhYgEBl/ysizlaQr+4nzDT9iaVQhXgZB6ONstUO7WlC
         rEJC8F6LPRoRGTGIHf7mfkVWmFMF0ILPTXBaNiJfl+JpxbQ0Yl3ZIihT92wNOn+3sjCr
         KmtAr6cskgfx2oPKLW106u+u8HdfNnNSdNVSmcfQc/H3x8mGbytB1yX5IlaiF8FW3RXY
         JByon1/Srpzmg1F5/5vJd8H19wrLNwTEIEpqqspEN7t3Fopm53XH+INtLiV/WoLDOjoP
         1OQYVMxLHwMIhzxpTwYhQjCHIRCtCii51bj07jMRxK3fD9AEMUwkEs+LiOpXj6pBzmP3
         MAxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5309Cz0NH0ppP98SBzoZVLj6ZSFFhBKp2/LW+8QQP7HBf8Ha7kZP
	B8oaBvqYGUmvdmYumO+wQJk=
X-Google-Smtp-Source: ABdhPJw8LeyoaoSMfziRgeiiSdWs61twY/olTIWotNzyJEjsAaIoSH0zVjnD0Uj2SB5iRI+7h7REAQ==
X-Received: by 2002:aa7:8f28:0:b029:2f4:9245:4ed with SMTP id y8-20020aa78f280000b02902f4924504edmr2011229pfr.24.1623724575837;
        Mon, 14 Jun 2021 19:36:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:fb0e:: with SMTP id x14ls9626876pfm.10.gmail; Mon, 14
 Jun 2021 19:36:15 -0700 (PDT)
X-Received: by 2002:a62:7587:0:b029:2e9:a997:1449 with SMTP id q129-20020a6275870000b02902e9a9971449mr2066048pfc.57.1623724575390;
        Mon, 14 Jun 2021 19:36:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623724575; cv=none;
        d=google.com; s=arc-20160816;
        b=DgN8G/AXvKTSjfAwVNMlk20bIL9/vMySo+tdB55uyVuFX7jkQ4sfELGcgLtfWkEtsO
         IWVLGBP2Fhsf4TIgGViEipe1eNJYhMdNY3Fnx/vvMbCyz6wJIxKWXwD6nAg3CygmFnzj
         IIvC1JP/f0RSUG8ed1F7ZOzTYcoOl1m3smeJnVxA2S9rZLpe/qHZHUN7RQ1g33rElOw1
         EtDMoNTe57Brb2xOg4ACkobPNgTloDenCOk8eH16r+abr+UGlBS5W6ibDfCGQXPWfOi2
         KuyDMA5NhovNmIIjaZC8bMEXkJNZFYom6HAaD1Qouej63us2/JK1KJkQbN4Se2Hdk8TF
         ZhvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=qH70eWL4H3WPCS8Rv8+ia8iR10xokWICkMm7XA6PAsE=;
        b=TSDgn/N8SYJvvLurZcapwU46QbBBZ+rE43l3d/nVXpzU/Pc0MBiYDZnq8LzqWv+1a6
         lQlEQw9HRy1DO4TkefhWEpLTT6F7ARAJZQ9MJlsbfXHgGgGtmQtba5T5JJySN3niX4Vw
         v6q/MdqhChB1eHCJiDG8n1sfz8VAxghxSLO/po7Dfu0BIc7XokFTB3i8K3nL+06zxMFA
         Y3u9DcUiOyq+ZoX1lOnHDFIyLMsr3ki0akI6NefKsB73nnlcJFdtK/WQ5O5UdkISk+30
         EF1X2YzjtE4sPzzoHNn7kCxTKFZnld5PJrplot4ykK9seHkw57ZHoPNDmYLmPJ8lJV5h
         PGyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id b3si311226pjz.1.2021.06.14.19.36.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 14 Jun 2021 19:36:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.56])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4G3skB1kYZz1BMSs;
	Tue, 15 Jun 2021 10:30:42 +0800 (CST)
Received: from dggpemm500009.china.huawei.com (7.185.36.225) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Tue, 15 Jun 2021 10:35:41 +0800
Received: from huawei.com (10.175.113.32) by dggpemm500009.china.huawei.com
 (7.185.36.225) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id 15.1.2176.2; Tue, 15 Jun
 2021 10:35:41 +0800
From: Liu Shixin <liushixin2@huawei.com>
To: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
	<palmer@dabbelt.com>, Palmer Dabbelt <palmerdabbelt@google.com>, Albert Ou
	<aou@eecs.berkeley.edu>, Alexander Potapenko <glider@google.com>, Marco Elver
	<elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
CC: <linux-riscv@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Liu Shixin <liushixin2@huawei.com>
Subject: [PATCH -next v2] riscv: Enable KFENCE for riscv64
Date: Tue, 15 Jun 2021 11:07:34 +0800
Message-ID: <20210615030734.2465923-1-liushixin2@huawei.com>
X-Mailer: git-send-email 2.18.0.huawei.25
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.32]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 dggpemm500009.china.huawei.com (7.185.36.225)
X-CFilter-Loop: Reflected
X-Original-Sender: liushixin2@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liushixin2@huawei.com designates 45.249.212.255 as
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
Acked-by: Marco Elver <elver@google.com>
Reviewed-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
v1->v2: Add the acked-by and Reviewed-by.

 arch/riscv/Kconfig              |  1 +
 arch/riscv/include/asm/kfence.h | 63 +++++++++++++++++++++++++++++++++
 arch/riscv/mm/fault.c           | 11 +++++-
 3 files changed, 74 insertions(+), 1 deletion(-)
 create mode 100644 arch/riscv/include/asm/kfence.h

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index 4c0bfb2569e9..1421da5ef1a2 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210615030734.2465923-1-liushixin2%40huawei.com.
