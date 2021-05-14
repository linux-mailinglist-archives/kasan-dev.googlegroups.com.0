Return-Path: <kasan-dev+bncBAABB7OU66CAMGQEOEXB7EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id C0284380250
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 05:11:58 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id s11-20020ac85ecb0000b02901ded4f15245sf10364257qtx.22
        for <lists+kasan-dev@lfdr.de>; Thu, 13 May 2021 20:11:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620961917; cv=pass;
        d=google.com; s=arc-20160816;
        b=OJIWwH+mOf+aAqxcJ19QEo2b7bXgXecpHBRGYZr5/s4HyGI/nwudC/o+Y3xEg0ABJU
         g1S0mgpaGgpYjY70tTmMzYlIX6zU3G/fUgpr6vPL5X5T9v62J3TxLJ/WAVv7vWdCtYMy
         WcRlz2d4g2e1KgFiQrYRUjeNYFRdDgsQhEiZLfruU14pTcR5bYTTUHOyfRoQj+0V3lJQ
         C7ovf5aiiZfMScaljjJ43xSBxnTYECBgXgLBskNhAvTHP2L6Qy9ryElunVHT7vorxzM9
         sfE03Exn0AIny9xaZGjHq60itFIvg8nkRWB42YcJoRfMN6zigWX4GuHW/th/eMPiUcuD
         doOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ZNdVx3Vokanrr5GKhGiIHTlxl9qILMM51eKiYVbjhL0=;
        b=rdVzA3FWHBXzJnO4LCgf13jTadT93kTndTyx8ReGRQD6RjHufUvPI4UHBdjO4MtoZA
         yZraFxq8Y2QRP0l2I/OCJISUBU4pidheaovDSXoGwCWqToxMk83s5W5Lp5OpTX/Sea9I
         3Co2z7k+yld7uDvsxOk/RpVZH+7lTzjtv8Ji0Vb7UF+2P2Ksdvj/D2sa603zsQcbQd3y
         ydR2LW2DuD3gkQEfx46vwqzEg5LBShoHFDuJ1n73IAtY0TwiWcV5cbtIGBjnA6sDcppZ
         v2cP0wMPiXMHf8iP1+BqIekQvxtndiB5lGyjR2OSJNOP4jYpuAqPv9L2m10Mr9gUuI2O
         /hhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.32 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZNdVx3Vokanrr5GKhGiIHTlxl9qILMM51eKiYVbjhL0=;
        b=R8drEVrMQj64AG2zZiwhr2STjsTG5QqNA2qA/FzG4OozwzMc8OKFXLmoQbbuTMdPw7
         /KtgsPVJtnm0DtCuVQ70LORlCb5FZ9xdVAMAXA3lej0LmSadKa0sLBN0q7IUx2A/onjm
         p+sclzRTfNRdlxPpuyMrMCDpQ1gFTnPJkqKDc6PZFwwkW4sYHHJhJwh8mRJ7K17OhdkB
         pRN9rbUiwrHux3G/VNsrM6JHZDT6DxW9dZU9PWFGJvlXBAweb0xbrCUbR3AWP981bQ/U
         g1hbnyykaPnRq4dMnL5D7DvRgJpK/pz+xP7xEfmvZ7Cq2AClS4960zz8pT0sfQafOUwL
         6Scw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZNdVx3Vokanrr5GKhGiIHTlxl9qILMM51eKiYVbjhL0=;
        b=h0afL1HQWbzuCq2UMbSm6vBwAWda3ALDFSTWVh8RvLyfkl36TIDKk+NzKKYX1RLYoH
         0n0HZMN/f5mBEfr+SbNBheCJ39ZEAeBs9BKaMnPF3UxFNL+rTyZMpjiRnEhfchF6h5Ja
         OqKr53K3KmdLBZWmlX+h+SI8TBy5nWs8FdoS531+FFVq6X+fGh1Sq6sK/DLLgFjP7djk
         UDN/sf+n/QKhuIjJIIQHnEplF142eQmV5aU6Ud0SmeZgsZkRB8oxDlBzBgafoMU3uRau
         McxlHXRtAxtQ0munPtRWafl0RK8uoT8wrPqOisPJUYmr4OsjUHhDtn3ehphFNLnRwvvV
         rrpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531AUgIJ/pEPNIHTPtz+eWErFGGx7iVH1p5R2ZNBHtUNEGn/iLgP
	4QokRwm9edUTtPbr2Nu22b0=
X-Google-Smtp-Source: ABdhPJymXqJaGRZ+UIcmjmeudCoDS3S5p8Nd0UxmCGzcaeXPJ6gkH2agpsTv23tn0PE+mxi0N2hboA==
X-Received: by 2002:a05:620a:2149:: with SMTP id m9mr32015668qkm.284.1620961917670;
        Thu, 13 May 2021 20:11:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:7681:: with SMTP id r123ls5129665qkc.6.gmail; Thu, 13
 May 2021 20:11:57 -0700 (PDT)
X-Received: by 2002:a37:e508:: with SMTP id e8mr42520575qkg.82.1620961917283;
        Thu, 13 May 2021 20:11:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620961917; cv=none;
        d=google.com; s=arc-20160816;
        b=SEtUN5R2+QqtmANdF3bCFsmlZJOpruNESJhAb9CTgy9bV0QQOL4akL9t7kVES9jjub
         MoI2K7vjhT8sf0Exb3ptHqtjc0JT42nps9Af8cHeXw3T8OC3U+ugQcjDuO4XBoBcsG3b
         ueZFlVqqfHeVoHS0PgCAvrhhH12oUzY7KEjeTuniE2FdY4X7XzH6ytCFQzFtQOH6ix0W
         Kp0kGIpIYqEZKs9uz5xbBxnVEcnBo8F93NjxpHAqIGkSrdi2MqiobY682c4u2tm1etop
         Oa0mL0Lw1oQmH41/1lBt0nVK57jKAzBvP8tPUDomdcRhB5BGWSLAzDex4P9YDSt+G5dg
         iLJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=J/AT4UY5pnAR7D7K0k13qqQ47FVbBOjWkZrpkDXS1sM=;
        b=EU7KKlg4oom3YIl+RBeWxAXX9ztCwepJirZeiVVszp/YPd23Q+fdazbXhBT+KUukHC
         5bdFsZEAE0RVOoLt4Lb81T68mUuJsmq3t83SRXqq2NRukac4n4A8pWQ2IKtFW6YPdkbU
         4o5h2Y/NK2lK+pObuzgbPLzuh8dnQAhhqRVdd339zH+i3ISn12wprOEJoxnKQd1TAYUu
         otd0dKyszp9hIDc+X28KIT2XQHJCMGQkSPxo1OrJC20jrtWPxfMRF36iUg3vcF4wEMiF
         s47m9D6fP1W6urnnKkk9L2hvNGLLXuhY+H00s9JBNBqCckCZ/D+7oheRnRT3x2I0VMaW
         4NDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.32 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga06-in.huawei.com (szxga06-in.huawei.com. [45.249.212.32])
        by gmr-mx.google.com with ESMTPS id v64si468438qkc.1.2021.05.13.20.11.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 May 2021 20:11:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.32 as permitted sender) client-ip=45.249.212.32;
Received: from DGGEMS401-HUB.china.huawei.com (unknown [172.30.72.58])
	by szxga06-in.huawei.com (SkyGuard) with ESMTP id 4FhD5L6qvYzmWBC;
	Fri, 14 May 2021 11:09:10 +0800 (CST)
Received: from huawei.com (10.175.113.32) by DGGEMS401-HUB.china.huawei.com
 (10.3.19.201) with Microsoft SMTP Server id 14.3.498.0; Fri, 14 May 2021
 11:11:15 +0800
From: Liu Shixin <liushixin2@huawei.com>
To: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
	<palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Alexander Potapenko
	<glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
	<dvyukov@google.com>
CC: <linux-riscv@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Liu Shixin <liushixin2@huawei.com>
Subject: [PATCH RFC v2] riscv: Enable KFENCE for riscv64
Date: Fri, 14 May 2021 11:44:32 +0800
Message-ID: <20210514034432.2004082-1-liushixin2@huawei.com>
X-Mailer: git-send-email 2.18.0.huawei.25
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.32]
X-CFilter-Loop: Reflected
X-Original-Sender: liushixin2@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liushixin2@huawei.com designates 45.249.212.32 as
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
v1->v2: Change kmalloc() to pte_alloc_one_kernel() for allocating pte.

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
index 000000000000..c25d67e0b8ba
--- /dev/null
+++ b/arch/riscv/include/asm/kfence.h
@@ -0,0 +1,51 @@
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
+		pte = pte_alloc_one_kernel(&init_mm);
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
2.18.0.huawei.25

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210514034432.2004082-1-liushixin2%40huawei.com.
