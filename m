Return-Path: <kasan-dev+bncBAABBVX326CAMGQEE5MDJMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id B6800376F04
	for <lists+kasan-dev@lfdr.de>; Sat,  8 May 2021 04:56:24 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id g11-20020a17090a578bb029015564873bf4sf6330684pji.7
        for <lists+kasan-dev@lfdr.de>; Fri, 07 May 2021 19:56:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620442583; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z/KkQBTxqw6i7KEwAOB9Ok4N4+5aGcu1ajY71ofOoeA1O15OnRKfFTv/tzRDwvjAP/
         2GqPLDfAJSM4cZ/TvpazEy5jRbOrmHB3hSGiKLrldCx8Oez0y1sn8FNVSAhBt5P4hcsU
         Dq3pR5E6N/YadbxsTsh5jIPLSSIpYx80fRlLaj6pZbN+sYIjMIx1YUDT5liK+QfkX+5y
         GlraS50va8zFkET6Fi0BYXuQ9vdHskH0YJLK3hlxmSv0pzbAFvBtqq29Yr82xL/b1nHk
         7Cz3zxHhbh25LaG3F1/ufyDShk2lyoh6NSsUbkyz9SWFSYcjWdRdg9a5HyPAwu436zjT
         iCbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=N2X0BRIapv7WAeySdok1UfdZZ1z8IwrWy/C9X+13/5k=;
        b=QaJxzoEftwW+dQXD9Ijfn8G47Sb47LyvygqSQ9LrWZ+ejxKVICs9KL59zyi03YOWp3
         Kjzm8smGugkWd3wgwlFSyz6PVx5zf48LBzeo69ZZXNWSB86a7t7FURPEMRMIRD04kA7c
         w02azSTG3JwdSfON+L71WnK7blAXPTTgjrjUFxRyCNgEdIczm77vrX7KHXVom7fdbFrd
         tNgNkXFVc5a6ynpSMJtiCjF140Hkf0NBY5a4fjGwIPTNryDSvIwTFT1uQUILeYJSncfv
         jOPxrfaiFgkdgneewIxp8Nh9UuwwBhMLbv8j+sJ8WS0a9xcJbK1gkT/U4Z/5oBY8ZxgM
         Hl2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N2X0BRIapv7WAeySdok1UfdZZ1z8IwrWy/C9X+13/5k=;
        b=MTbICClifmr6O02fj7wCOfdYuWBOosMLDQVjRTYDO2uVBdV64Q02TXoTmTH+AkvIcr
         /0g0+j3bgARUvdIw8Z96nVd0OT1Y3jeP236x/KtjALSh31j+nipn02pYkwb8NAYAvtm3
         fy6RIOYyHdTzWmXxxeijs99hYQCQcf0Ufn2iQbdBVw7va72rw+xZy+gv0QusNZrBT81i
         QpT+/nfseCT7hW1cD05TKTBF2zi22RMj91nGcZqWtypKqFuZBxzdUqUkNVMew0HUTfkO
         biwx2aMVqhK/DrCeKO4+RlYqdnGLz2lsUC/Q7Ea8Z1idr9xoqMpYdmYLuiZW7T7zi4Xw
         wgpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=N2X0BRIapv7WAeySdok1UfdZZ1z8IwrWy/C9X+13/5k=;
        b=lRYNoIAfOi2TUnx9WYgtNHSvTeAMV6zFhhIOzDzHBKQ8tA518rfD7g+guyzR44wVXb
         JDgsU8zCwJdNW8gAZ4tEPneubEZT4d50/sWyt7ouVm1iIz+DloIYa41EkidCB5oP8s6P
         sUo+ArJLqwxe/15tQBuAoSl/xAhjAgLV38Cn+wNDG5S/E2NBMTbZXptU7OEUm/xsth2k
         iIFuoNEjpNSImARMa+WBJUMG6+3p33EC6V1s8ALrMyox2zBK/YPv4xsO2hLb03tq1QD1
         6jFg1NdPNwZXUhkogGvZP28qTTPIbb2MBzcZnY5fkwd06kKmK0Ih2oqkOhp5sOnwWDVo
         tzLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5328EP4tEDgml0i+UGcu+iyJArGg/GFTMmcA5+FM+1zlb41sjyS0
	cJD45emQfu7ob7q5DlKJnbs=
X-Google-Smtp-Source: ABdhPJwaF9Ucaz9KEmNQpprMJHQdr0XFji02veL+eIsb6YF8KnGpViof2Hw8AJPTHmhXjf150yq7IQ==
X-Received: by 2002:a65:538d:: with SMTP id x13mr13486575pgq.108.1620442583034;
        Fri, 07 May 2021 19:56:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:89:: with SMTP id o9ls4296241pld.8.gmail; Fri, 07
 May 2021 19:56:22 -0700 (PDT)
X-Received: by 2002:a17:902:c943:b029:ee:8f40:6225 with SMTP id i3-20020a170902c943b02900ee8f406225mr13245823pla.52.1620442582458;
        Fri, 07 May 2021 19:56:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620442582; cv=none;
        d=google.com; s=arc-20160816;
        b=vobtRAbXvPt1pEfruGL+dlOJ225bmGHdKvJ7uJmu8CzLMJMFxByT/Q32BVBNDU7rim
         2CuPBoySFFQ1290pzhUizELeBSqTDCeWMuKoVnF88hj9TAStgHrzUqcWaDpvxzSZhMwL
         qGZ1sYm/V0C+jLvvy9Y621rSMdeCYfI7OeeZMiTFB48NDRrc5lGDS6wOUBZn/Iz+zkJO
         GhJGMxl5g5WPFvyiBlPD3Okj7tFEIbkyU2LRoxG2wI6AixqadJGuXBslnpYXzgOk+MAF
         OMXTK91xEPIE6AK+OIXlWaQCcm7gQf0iYe5rHUPiTkD9AO5oyBWwuXumuzLKB3cN5MM6
         jY1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=azyIcSgFQi9Z9Uz/QmVGIAlWzecQKYFiczRIL7ayE58=;
        b=U/YEnOdkc8spQ6QYldKOAbkQjV4kKqdTQowM9tVX34UNID42EN5zWNqQ1/HCIsYhLc
         lMcAqp1yfms7+lB8LUrc8MQHewD8ABTJ1eaVeDDbEdgo4zJDaYDpv7EZodZNVl5e3cSK
         VV4Hq+V3MJgbEaPE5WuxjugidFMr9BLbVecorDW6lVFfcgMePLLKumojMqLLLtmxgeZ8
         E9p4itM0SID+tmJ+TlXLr8Og3aIDdcTBOZjoqrJhDpcv0cOKRFPqjttlkd3jR7YZxHzW
         hCaZV8L8pOlhXY9OIxXborJz3vzJNc26ManKW8fTbkMIgcQJ39NXGcP1Y95BQuUjzaxr
         30+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga04-in.huawei.com (szxga04-in.huawei.com. [45.249.212.190])
        by gmr-mx.google.com with ESMTPS id ep1si444852pjb.2.2021.05.07.19.56.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 May 2021 19:56:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.190 as permitted sender) client-ip=45.249.212.190;
Received: from DGGEMS410-HUB.china.huawei.com (unknown [172.30.72.58])
	by szxga04-in.huawei.com (SkyGuard) with ESMTP id 4FcX1h1wfKz16Pb6;
	Sat,  8 May 2021 10:53:12 +0800 (CST)
Received: from huawei.com (10.175.113.32) by DGGEMS410-HUB.china.huawei.com
 (10.3.19.210) with Microsoft SMTP Server id 14.3.498.0; Sat, 8 May 2021
 10:55:41 +0800
From: Liu Shixin <liushixin2@huawei.com>
To: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
	<palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Alexander Potapenko
	<glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
	<dvyukov@google.com>
CC: <linux-riscv@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Liu Shixin <liushixin2@huawei.com>
Subject: [RFC] riscv: Enable KFENCE for riscv64
Date: Sat, 8 May 2021 11:29:12 +0800
Message-ID: <20210508032912.2693212-1-liushixin2@huawei.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.32]
X-CFilter-Loop: Reflected
X-Original-Sender: liushixin2@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liushixin2@huawei.com designates 45.249.212.190 as
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

I tested this patch using the testcases in kfence_test.c and all passed.

Signed-off-by: Liu Shixin <liushixin2@huawei.com>
---
 arch/riscv/Kconfig              |  1 +
 arch/riscv/include/asm/kfence.h | 51 +++++++++++++++++++++++++++++++++
 arch/riscv/mm/fault.c           | 11 ++++++-
 3 files changed, 62 insertions(+), 1 deletion(-)
 create mode 100644 arch/riscv/include/asm/kfence.h

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index c426e7d20907..000d8aba1030 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -64,6 +64,7 @@ config RISCV
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if MMU && 64BIT
 	select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
+	select HAVE_ARCH_KFENCE if MMU && 64BIT
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_KGDB_QXFER_PKT
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
diff --git a/arch/riscv/include/asm/kfence.h b/arch/riscv/include/asm/kfence.h
new file mode 100644
index 000000000000..590c5b7e3514
--- /dev/null
+++ b/arch/riscv/include/asm/kfence.h
@@ -0,0 +1,51 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+#ifndef _ASM_RISCV_KFENCE_H
+#define _ASM_RISCV_KFENCE_H
+
+#include <linux/pfn.h>
+#include <linux/slab.h>
+#include <linux/kfence.h>
+#include <asm/pgtable.h>
+
+static inline bool arch_kfence_init_pool(void)
+{
+	int i;
+	unsigned long addr;
+	pte_t *pte;
+	pmd_t *pmd;
+
+	for (addr = (unsigned long)__kfence_pool; is_kfence_address((void *)addr);
+	     addr += PAGE_SIZE) {
+		pte = virt_to_kpte(addr);
+		pmd = pmd_off_k(addr);
+
+		if (!pmd_leaf(*pmd) && pte_present(*pte))
+			continue;
+
+		pte = kmalloc(PAGE_SIZE, GFP_ATOMIC);
+		for (i = 0; i < PTRS_PER_PTE; i++)
+			set_pte(pte + i, pfn_pte(PFN_DOWN(__pa((addr & PMD_MASK) + i * PAGE_SIZE)), PAGE_KERNEL));
+
+		set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa(pte)), PAGE_TABLE));
+		flush_tlb_kernel_range(addr, addr + PMD_SIZE);
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
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210508032912.2693212-1-liushixin2%40huawei.com.
