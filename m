Return-Path: <kasan-dev+bncBDQ7NGWH7YJRB3WVW6GQMGQEFKQZUMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id C0F72469444
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 11:50:22 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id d26-20020ac244da000000b00417e1d212a2sf3716712lfm.0
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 02:50:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638787822; cv=pass;
        d=google.com; s=arc-20160816;
        b=JsMdg3l1OeWpR9RBkR/SPYLCINxvnyPAQr3ya+y7b365Ev30UlWd091jEEpcuxWeiX
         b5IvDXSOwh0T4XDMvo1jHt5dFPFRdfXK8sXrATz1T5qA3RJgUp5rvawJtY77iD56Jagg
         64W+MWaWr+Gu4O7QX2XqRZwVApcelOSXDRfA6SW65mnrHFXfGASStPN4kMr1xsObIPbU
         gFmiwR5q2gEMx+ZbnVxK/RQbqxRvBje07kWHXi4USUEeqAPEoGExoxcTUaaLQAwfPK23
         N1Kn3f7H+OgnJmQFtFeDBXoeHuI68vzzc7Gh0wX75uDSor/2N1vDvcOEOuhUPTXAMpdc
         GRvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=LZtOCzWI0ag0evwHP3eUirFPcr2/zYgdvbZYBsrDE00=;
        b=RBIjJ4qB54IcJBKM5aLkvYlA4wcyojNbcgj0jNVh0CLLXC3h3TXTdWD/3NtPfA8lyB
         NjVOMM55DHojz1dKegEglwGfnZfjV2dmF59a9HQ4Mbrcg6eojimgTUcQN7znTzExW5zp
         g9y8P9eXuks/q3yCOoZvMbTOkPPwaPr5dJfUl8PK0xX5Jf6RmZlbaC80cz/P2ztM+80M
         njQ00+KSdsXXddcA1CNwgsRPnuo4daLnUGSZOwwMEXJfLCTMli/N1RPdYcH7wZC4bNvE
         aP9MV9WQ5QWG7Q6oq64hG0Ukapze/Pd+VY/PqZackeTE3IFAjPNLdu7RQzFywVw4dRck
         sRSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b="SbqC6I/w";
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LZtOCzWI0ag0evwHP3eUirFPcr2/zYgdvbZYBsrDE00=;
        b=m2Z+suWalRuruZQCPphPgJWR4eS+agL3zbTG+inkDp8MCeAfPkPds8L9yytsSQ3Yha
         yscKgQxsEfyUdshsTW0YiSk8SLNNugsm/NqoI9XoZ1a5YRKghnBxOCS8ZTZS+I+Z1Go+
         ONsua1Q8trYucO+mnyJVM2cI3F55TaAt4eXTtzdqtm0uJnZ+zcC6QHs9vD+JI2EJvWrh
         eO9Qo0J+q9XngWNzmOmQHXt6QRM2EyBpaBeEvGS09xTTqZd4KzwnYLoW4qC7wI60hr4a
         O2HJcvRltar9ckhSkRl/3pAlPurEs+SuOcy36Z2ioqy8mrRB8rRTXzixk/KhCIvUrqSd
         uGjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LZtOCzWI0ag0evwHP3eUirFPcr2/zYgdvbZYBsrDE00=;
        b=mdG5TBcoq+fQwtQ3Gbq2OS2YLW0OXcK5+2yNQGD+wChDQ4wEDyhPmD3iZx+Y1rXyr/
         acxQIyZrYX14fHtlHfM/fPAlRBjrwQPIUabKpAccuLCZ/IcGfjbg/5Phqjlefl39UXuU
         6Rsa4JIvKH+zlUO+p/6w76sTYruvSNIJyGKkzT3VA5E2mIPZGn9jzcCFl+hid2vY8C2S
         s/S9MsLfrlafN0/8saeAEw6PuCpQumxjBcDrI/YekLGmmQOcAGp5wYeij9rPNzvwQxmq
         KxnXLc8ZkfK0LQ+I6gnss8EnOmUh6SMWM3Tr5ZAWE/W5dfQM40ucVs3cgMxL2fYk+PuK
         oAxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530lc7OkqFFWVAlrXDbW6i1Z/Tgpzsn/9k4F36hV4Ik5QbMMvUwZ
	cfv/A8mZoMnx5+uTr4mHAZo=
X-Google-Smtp-Source: ABdhPJy65J9rdtUQ4/UhGK8enDTlhoDcNda8wup0DiM89rS6H/RxQ4K2GtV8xBWrq8Dohfmexx9jPA==
X-Received: by 2002:a05:6512:200b:: with SMTP id a11mr34692745lfb.398.1638787822365;
        Mon, 06 Dec 2021 02:50:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls691604lfu.0.gmail; Mon, 06
 Dec 2021 02:50:21 -0800 (PST)
X-Received: by 2002:ac2:5ca8:: with SMTP id e8mr34873219lfq.391.1638787821555;
        Mon, 06 Dec 2021 02:50:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638787821; cv=none;
        d=google.com; s=arc-20160816;
        b=taLP/XA65WZnrwkGr+DWZxUwnU8Lh6tr91W11hYEVDtFsGH6H2HWPnNz8d7yi8YG/t
         4tecRCNbNvstA+RUkd280LUHB9wz4KWe4RiQ2ehFzb0bwnVoDmY9XyFSFJBh365JCTF/
         Ahs6VIlclBP2ek+3DleB/GQPb1huJq80BN/tRqiyBHJm41vTsUOB/0QkGjC/VFiTMd8W
         G08QffVjuyzhmikRKf1HEGhkxLV+JaEVUNiBcaDx3/7CtoEa6Fi6fwPVaCYV6iP/Kw+A
         3RnAO8TjEVOwkJ8ms8nfX6TGnZHqCJfB767LUSlJ/K9IUuShEzBV4W3qFZ/5LskAtFfA
         faCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AamuRCUDtOeG1u1NXrTV8g0J3yQ8ijBKUVLSOIso31U=;
        b=TQEY4ZXGd26LS9oKVtUtN25lFw0fykvSWDejDyhlHUG/+KEFvVXzYP+6Q+F9aswbR7
         LNhGQ+ajG5Isf+nvYoY0nY6rCJIHAbIBd0KD8onwWY/kokgf1ScB1RIjQtfPayDXonTu
         Rs2rgJrZhjyhKZZbky1ZTg0913bzSXCU3uHyU5+6j7UpHAzghfJCaqsfII5xLykWtWEX
         HwAPoIGqI+TyZ3qciP8w8juYygVUwbS3rEoe/Dhe6PyUCc38KZzMjPXqy5pSBAVHyiNW
         YInGCzk5X/rj8VuvNuyJbOnmJYtoTHoYpBsJUGVNc0D3yx/FdIO2GbzQTZHJBp02NSIM
         K+Mw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b="SbqC6I/w";
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id y8si213149lfj.0.2021.12.06.02.50.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:50:21 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com [209.85.221.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id BA1FF3F1F7
	for <kasan-dev@googlegroups.com>; Mon,  6 Dec 2021 10:50:20 +0000 (UTC)
Received: by mail-wr1-f69.google.com with SMTP id p17-20020adff211000000b0017b902a7701so1882519wro.19
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 02:50:20 -0800 (PST)
X-Received: by 2002:a05:600c:1d0e:: with SMTP id l14mr36985916wms.64.1638787820351;
        Mon, 06 Dec 2021 02:50:20 -0800 (PST)
X-Received: by 2002:a05:600c:1d0e:: with SMTP id l14mr36985880wms.64.1638787820171;
        Mon, 06 Dec 2021 02:50:20 -0800 (PST)
Received: from localhost.localdomain (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id y7sm10770064wrw.55.2021.12.06.02.50.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:50:19 -0800 (PST)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Zong Li <zong.li@sifive.com>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <Atish.Patra@rivosinc.com>,
	Christoph Hellwig <hch@lst.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Kees Cook <keescook@chromium.org>,
	Guo Ren <guoren@linux.alibaba.com>,
	Heinrich Schuchardt <heinrich.schuchardt@canonical.com>,
	Mayuresh Chitale <mchitale@ventanamicro.com>,
	panqinglin2020@iscas.ac.cn,
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org,
	linux-arch@vger.kernel.org
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Subject: [PATCH v3 03/13] riscv: Introduce functions to switch pt_ops
Date: Mon,  6 Dec 2021 11:46:47 +0100
Message-Id: <20211206104657.433304-4-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b="SbqC6I/w";       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

This simply gathers the different pt_ops initialization in functions
where a comment was added to explain why the page table operations must
be changed along the boot process.

Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/mm/init.c | 74 ++++++++++++++++++++++++++++++--------------
 1 file changed, 51 insertions(+), 23 deletions(-)

diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index 5010eba52738..1552226fb6bd 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -582,6 +582,52 @@ static void __init create_fdt_early_page_table(pgd_t *pgdir, uintptr_t dtb_pa)
 	dtb_early_pa = dtb_pa;
 }
 
+/*
+ * MMU is not enabled, the page tables are allocated directly using
+ * early_pmd/pud/p4d and the address returned is the physical one.
+ */
+void pt_ops_set_early(void)
+{
+	pt_ops.alloc_pte = alloc_pte_early;
+	pt_ops.get_pte_virt = get_pte_virt_early;
+#ifndef __PAGETABLE_PMD_FOLDED
+	pt_ops.alloc_pmd = alloc_pmd_early;
+	pt_ops.get_pmd_virt = get_pmd_virt_early;
+#endif
+}
+
+/*
+ * MMU is enabled but page table setup is not complete yet.
+ * fixmap page table alloc functions must be used as a means to temporarily
+ * map the allocated physical pages since the linear mapping does not exist yet.
+ *
+ * Note that this is called with MMU disabled, hence kernel_mapping_pa_to_va,
+ * but it will be used as described above.
+ */
+void pt_ops_set_fixmap(void)
+{
+	pt_ops.alloc_pte = kernel_mapping_pa_to_va((uintptr_t)alloc_pte_fixmap);
+	pt_ops.get_pte_virt = kernel_mapping_pa_to_va((uintptr_t)get_pte_virt_fixmap);
+#ifndef __PAGETABLE_PMD_FOLDED
+	pt_ops.alloc_pmd = kernel_mapping_pa_to_va((uintptr_t)alloc_pmd_fixmap);
+	pt_ops.get_pmd_virt = kernel_mapping_pa_to_va((uintptr_t)get_pmd_virt_fixmap);
+#endif
+}
+
+/*
+ * MMU is enabled and page table setup is complete, so from now, we can use
+ * generic page allocation functions to setup page table.
+ */
+void pt_ops_set_late(void)
+{
+	pt_ops.alloc_pte = alloc_pte_late;
+	pt_ops.get_pte_virt = get_pte_virt_late;
+#ifndef __PAGETABLE_PMD_FOLDED
+	pt_ops.alloc_pmd = alloc_pmd_late;
+	pt_ops.get_pmd_virt = get_pmd_virt_late;
+#endif
+}
+
 asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 {
 	pmd_t __maybe_unused fix_bmap_spmd, fix_bmap_epmd;
@@ -626,12 +672,8 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 	BUG_ON((kernel_map.virt_addr + kernel_map.size) > ADDRESS_SPACE_END - SZ_4K);
 #endif
 
-	pt_ops.alloc_pte = alloc_pte_early;
-	pt_ops.get_pte_virt = get_pte_virt_early;
-#ifndef __PAGETABLE_PMD_FOLDED
-	pt_ops.alloc_pmd = alloc_pmd_early;
-	pt_ops.get_pmd_virt = get_pmd_virt_early;
-#endif
+	pt_ops_set_early();
+
 	/* Setup early PGD for fixmap */
 	create_pgd_mapping(early_pg_dir, FIXADDR_START,
 			   (uintptr_t)fixmap_pgd_next, PGDIR_SIZE, PAGE_TABLE);
@@ -695,6 +737,8 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 		pr_warn("FIX_BTMAP_BEGIN:     %d\n", FIX_BTMAP_BEGIN);
 	}
 #endif
+
+	pt_ops_set_fixmap();
 }
 
 static void __init setup_vm_final(void)
@@ -703,16 +747,6 @@ static void __init setup_vm_final(void)
 	phys_addr_t pa, start, end;
 	u64 i;
 
-	/**
-	 * MMU is enabled at this point. But page table setup is not complete yet.
-	 * fixmap page table alloc functions should be used at this point
-	 */
-	pt_ops.alloc_pte = alloc_pte_fixmap;
-	pt_ops.get_pte_virt = get_pte_virt_fixmap;
-#ifndef __PAGETABLE_PMD_FOLDED
-	pt_ops.alloc_pmd = alloc_pmd_fixmap;
-	pt_ops.get_pmd_virt = get_pmd_virt_fixmap;
-#endif
 	/* Setup swapper PGD for fixmap */
 	create_pgd_mapping(swapper_pg_dir, FIXADDR_START,
 			   __pa_symbol(fixmap_pgd_next),
@@ -754,13 +788,7 @@ static void __init setup_vm_final(void)
 	csr_write(CSR_SATP, PFN_DOWN(__pa_symbol(swapper_pg_dir)) | SATP_MODE);
 	local_flush_tlb_all();
 
-	/* generic page allocation functions must be used to setup page table */
-	pt_ops.alloc_pte = alloc_pte_late;
-	pt_ops.get_pte_virt = get_pte_virt_late;
-#ifndef __PAGETABLE_PMD_FOLDED
-	pt_ops.alloc_pmd = alloc_pmd_late;
-	pt_ops.get_pmd_virt = get_pmd_virt_late;
-#endif
+	pt_ops_set_late();
 }
 #else
 asmlinkage void __init setup_vm(uintptr_t dtb_pa)
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211206104657.433304-4-alexandre.ghiti%40canonical.com.
