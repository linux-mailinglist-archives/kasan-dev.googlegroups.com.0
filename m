Return-Path: <kasan-dev+bncBAABB3HG27YAKGQEGNAE4LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id CC72C134601
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Jan 2020 16:21:16 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id n18sf1899960edo.17
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Jan 2020 07:21:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578496876; cv=pass;
        d=google.com; s=arc-20160816;
        b=iSENNtTAN2nrataYYPDHSIBGCmM+HQYvsIUqq1wEsfnv5BiwlGEls/zWcopCzcBZlA
         1kaDneWR3fD8kbLsFXSrx9XtNm/m/YoMngH8ZQQinnFYsubjTh0KTT7TV/emaxaFMeu1
         hcZewgxFFmOyWK8dFrs02IhpB3l6awRjifm9QIBpfdONAgY6zNL17vWJjzit64PufolD
         wW6N9nMB5xzgVeR96eY7Ejww2RSNPfRyQHGC8HFMw5A91Ac8DdK+jhmBmmyA9asjxaQv
         hbs5GOY+STqxZakrNPmX840bgzl+k1ovurLxaC7w6VQx/dXDg9GjUVEfj1P0kn4/xjew
         RsrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:ironport-sdr:sender
         :dkim-signature;
        bh=2Sfw1seVlLbfzcRl4Rqd8k6JC16Z4IjJv5b9XermoIo=;
        b=ypLYkUHnfnolnF++EFjFC4RvnMU7MoOTLx1kayd4D/cx27q+nANx88zcqdR3qb9WLi
         KEknF8ihicatweJXilkhj/YNENCQ4sdALcsZqlWJkLOZfqyTMsfq3zRvXIUqr0m3CAyd
         +Le6x1h2kTw/abYiyLqY7kAeJ/6AGcutcBoFCRRJxlFhjcHdNpxQBEVPvASt/LYJao8k
         YJzGmgKm+WB4YBTPEftEYeTlP43ZI5EhvuuVUEk5RFX345/9Q5uJpLidS7kjZYeiWik0
         PR1eINLzNUSD3KdQWzcavDEKQ4lSWNvVZ5aKbxKZ2DLPsNr4knGAyxydAve5eMTCN0yG
         cRiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=dqj9T3vv;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2Sfw1seVlLbfzcRl4Rqd8k6JC16Z4IjJv5b9XermoIo=;
        b=bTdjXf8Mb3USQouxjTBfegmh0oC/Omqw4BuXJmOZTuSPuakXoStg+LKQjtBf7Wcfi4
         fcEQR0WJ0yAxBrOkPYlB+5ou7NET+IFxg/A90smzbp8lTTgQIvhzDrvEtsKjs+g95jT8
         a0bEeti6LN3wLGP5PKf484h5tEYEW6qkUyFpI/gkxCIg4U79CHVE5AJI9EL3yGU0VAk1
         j+QFxdV4/8rZ0fNnq23EmrTQmbC3zfF+2+HAGvsTG7ys9u7ai5VK7O4whg1LkeK/0ryH
         ac1H65U7K0ekhZYydBz2A7l4YkB1UFMS13HbSerGwH+xhovgIAe8ysjAqQRVq0pqUgWb
         8bRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:from:to:cc:subject:date
         :message-id:in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2Sfw1seVlLbfzcRl4Rqd8k6JC16Z4IjJv5b9XermoIo=;
        b=i1czbRqjPbyea12frkeK96qu+s/JxAtqg77PngJotW28UvbTS0NbGpxbuHSRoq1oca
         C7DhhmmyaeckuEkynVk01QQ4lsXoLbmE0mA5rTPb36GDPpMq7ZyDxUH+pPsBVtB+ra6L
         YD/ATImW8Svb4MWdWgMotwyhYMCeRoGC6mB+jGwUZakVfzXsZS/DpDB9QDp0t6sy/wZa
         O855GvrbVrfZ5kNb+Z6sjGFZUMZ0q1RBDO/XPEMUUN9/RaQfv63f26xcEZjUHKwJflVm
         GOrQDUAh6E/Jiwjj6LBqgGOIlS8JBpqz43n2w5fuTXQXTkjx5Z4x/3TiR2OKmU88vOz9
         p78A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX3PiHtHRq9fCAEBN5PY07zF4OKwt5shQQ55m+oEw3xbkl/ROHw
	+MYFcWai/AWE/g44y+Sqcfk=
X-Google-Smtp-Source: APXvYqx9NORZipbuQGfcanUAtWIZAv+wFEOggT3kOhTX5nO8toATPEJVrVipxZJFnuf1vY58zx4QiQ==
X-Received: by 2002:aa7:d285:: with SMTP id w5mr5961393edq.246.1578496876450;
        Wed, 08 Jan 2020 07:21:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1f97:: with SMTP id t23ls787032ejr.11.gmail; Wed, 08
 Jan 2020 07:21:16 -0800 (PST)
X-Received: by 2002:a17:906:af6d:: with SMTP id os13mr5391656ejb.86.1578496876070;
        Wed, 08 Jan 2020 07:21:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578496876; cv=none;
        d=google.com; s=arc-20160816;
        b=fanSlF5+YCNTua6hIOtK2sgOM+o0TCsXaKUPowp5j76sGwa3N3BicmFx82XlmnM3sz
         6NAIrJDIRPU9xb0ysV9ZOetPMnqsMfDDFe4m6LChsl7CJcoctPy+XzsnTJ6g7URo5gyi
         M8evCSs/7ZSJY6k3UhGWBL7Dg6a89/iXLe81tQujV8DJ1+9KG2YcZAON3nexy6lXbGjU
         nbNXpVTpcUq/jXHeMJ7kw8rmtaI9SoNtXWSO7XyM1M/3BqmqQzBPCNg68u6pYqjqDIqp
         dYUdc1agt1eSvSqFHNTfeAW94fu+uSF1Onu8WB9js5ez39xlvuvsUg+EPKwJ8oggHVZ4
         +Ajg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:ironport-sdr:dkim-signature;
        bh=T2PEFkQdGRX7EWBtP43UbJwJhc/333YJCFLo1ZW6Zec=;
        b=J7nqu3DXsO6EMwFCyrddxW/GYI6UHOfi+TJA8cEPW0ZEyiw6dtzbG5INkLaezEKdwS
         3IRTnyEkzcyYU9qGPWDYgetIMexM+RGSXoSHqyDbPpxqhWlNlDkcBHMLs0MyjhgtXctW
         qi737DansqP3jz/RFOK/wDzRISPwYZnEL7+CAcvwJCpgdOTdaFAXpSMef36Hf/erR8U7
         adaKDq8HEmdAb0z05qbSKraMB43h2Of1pnU02w6vCxJvvcDnRH7przzG5s2W/0lUKirg
         ii99PK+/7F0PHsa6cm03Aio3jwshLSDOpJmBDYrcXfIbB1OGd98pzqt8G8a9+O9H1wTm
         PeZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=dqj9T3vv;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa5.hc3370-68.iphmx.com (esa5.hc3370-68.iphmx.com. [216.71.155.168])
        by gmr-mx.google.com with ESMTPS id ba12si148870edb.3.2020.01.08.07.21.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 08 Jan 2020 07:21:16 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) client-ip=216.71.155.168;
Received-SPF: None (esa5.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa5.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa5.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa5.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa5.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa5.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: DX+ggOVcUV+qjAM+GH2sUSi46yljxph9UiDZ5OvdtBvqC5kMO1PziVlbeWDiErFsikLJupbr6j
 e1GJp5zCy/6F3zEoqeeNBUnp1jCorCX2Lv0Aiur8r6exMyKmwDqJuw2jGva+/nJJXFvTQ2Ugl7
 MsXEecRWjr/VWKfr79oqpWhGuobCwHKJmBbBKn4tqnGTrqWdR7mqh2Qt3c/YNqtAyzHNee9e/R
 zXaizezM7fqVpwm8zpKNd8k535daqotbAfc1B7wEgWYPCbpvlXlweSc7xS8pQwblpvCKKTD4np
 1yI=
X-SBRS: 2.7
X-MesageID: 11004137
X-Ironport-Server: esa5.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.69,410,1571716800"; 
   d="scan'208";a="11004137"
From: Sergey Dyasli <sergey.dyasli@citrix.com>
To: <xen-devel@lists.xen.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Boris Ostrovsky
	<boris.ostrovsky@oracle.com>, Juergen Gross <jgross@suse.com>, "Stefano
 Stabellini" <sstabellini@kernel.org>, George Dunlap
	<george.dunlap@citrix.com>, Ross Lagerwall <ross.lagerwall@citrix.com>,
	Andrew Morton <akpm@linux-foundation.org>, Sergey Dyasli
	<sergey.dyasli@citrix.com>
Subject: [PATCH v1 2/4] x86/xen: add basic KASAN support for PV kernel
Date: Wed, 8 Jan 2020 15:20:58 +0000
Message-ID: <20200108152100.7630-3-sergey.dyasli@citrix.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20200108152100.7630-1-sergey.dyasli@citrix.com>
References: <20200108152100.7630-1-sergey.dyasli@citrix.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=dqj9T3vv;       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as
 permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=citrix.com
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

This enables to use Outline instrumentation for Xen PV kernels.

KASAN_INLINE and KASAN_VMALLOC options currently lead to boot crashes
and hence disabled.

Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
---
RFC --> v1:
- New functions with declarations in xen/xen-ops.h
- Fixed the issue with free_kernel_image_pages() with the help of
  xen_pv_kasan_unpin_pgd()
---
 arch/x86/mm/kasan_init_64.c | 12 ++++++++++++
 arch/x86/xen/Makefile       |  7 +++++++
 arch/x86/xen/enlighten_pv.c |  3 +++
 arch/x86/xen/mmu_pv.c       | 39 +++++++++++++++++++++++++++++++++++++
 drivers/xen/Makefile        |  2 ++
 include/xen/xen-ops.h       |  4 ++++
 kernel/Makefile             |  2 ++
 lib/Kconfig.kasan           |  3 ++-
 8 files changed, 71 insertions(+), 1 deletion(-)

diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index cf5bc37c90ac..902a6a152d33 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -13,6 +13,9 @@
 #include <linux/sched/task.h>
 #include <linux/vmalloc.h>
 
+#include <xen/xen.h>
+#include <xen/xen-ops.h>
+
 #include <asm/e820/types.h>
 #include <asm/pgalloc.h>
 #include <asm/tlbflush.h>
@@ -332,6 +335,11 @@ void __init kasan_early_init(void)
 	for (i = 0; pgtable_l5_enabled() && i < PTRS_PER_P4D; i++)
 		kasan_early_shadow_p4d[i] = __p4d(p4d_val);
 
+	if (xen_pv_domain()) {
+		pgd_t *pv_top_pgt = xen_pv_kasan_early_init();
+		kasan_map_early_shadow(pv_top_pgt);
+	}
+
 	kasan_map_early_shadow(early_top_pgt);
 	kasan_map_early_shadow(init_top_pgt);
 }
@@ -369,6 +377,8 @@ void __init kasan_init(void)
 				__pgd(__pa(tmp_p4d_table) | _KERNPG_TABLE));
 	}
 
+	xen_pv_kasan_pin_pgd(early_top_pgt);
+
 	load_cr3(early_top_pgt);
 	__flush_tlb_all();
 
@@ -433,6 +443,8 @@ void __init kasan_init(void)
 	load_cr3(init_top_pgt);
 	__flush_tlb_all();
 
+	xen_pv_kasan_unpin_pgd(early_top_pgt);
+
 	/*
 	 * kasan_early_shadow_page has been used as early shadow memory, thus
 	 * it may contain some garbage. Now we can clear and write protect it,
diff --git a/arch/x86/xen/Makefile b/arch/x86/xen/Makefile
index 084de77a109e..102fad0b0bca 100644
--- a/arch/x86/xen/Makefile
+++ b/arch/x86/xen/Makefile
@@ -1,3 +1,10 @@
+KASAN_SANITIZE_enlighten_pv.o := n
+KASAN_SANITIZE_enlighten.o := n
+KASAN_SANITIZE_irq.o := n
+KASAN_SANITIZE_mmu_pv.o := n
+KASAN_SANITIZE_p2m.o := n
+KASAN_SANITIZE_multicalls.o := n
+
 # SPDX-License-Identifier: GPL-2.0
 OBJECT_FILES_NON_STANDARD_xen-asm_$(BITS).o := y
 
diff --git a/arch/x86/xen/enlighten_pv.c b/arch/x86/xen/enlighten_pv.c
index ae4a41ca19f6..27de55699f24 100644
--- a/arch/x86/xen/enlighten_pv.c
+++ b/arch/x86/xen/enlighten_pv.c
@@ -72,6 +72,7 @@
 #include <asm/mwait.h>
 #include <asm/pci_x86.h>
 #include <asm/cpu.h>
+#include <asm/kasan.h>
 
 #ifdef CONFIG_ACPI
 #include <linux/acpi.h>
@@ -1231,6 +1232,8 @@ asmlinkage __visible void __init xen_start_kernel(void)
 	/* Get mfn list */
 	xen_build_dynamic_phys_to_machine();
 
+	kasan_early_init();
+
 	/*
 	 * Set up kernel GDT and segment registers, mainly so that
 	 * -fstack-protector code can be executed.
diff --git a/arch/x86/xen/mmu_pv.c b/arch/x86/xen/mmu_pv.c
index c8dbee62ec2a..cf6ff214d9ea 100644
--- a/arch/x86/xen/mmu_pv.c
+++ b/arch/x86/xen/mmu_pv.c
@@ -1771,6 +1771,36 @@ static void __init set_page_prot(void *addr, pgprot_t prot)
 {
 	return set_page_prot_flags(addr, prot, UVMF_NONE);
 }
+
+pgd_t * __init xen_pv_kasan_early_init(void)
+{
+	/* PV page tables must be read-only */
+	set_page_prot(kasan_early_shadow_pud, PAGE_KERNEL_RO);
+	set_page_prot(kasan_early_shadow_pmd, PAGE_KERNEL_RO);
+	set_page_prot(kasan_early_shadow_pte, PAGE_KERNEL_RO);
+
+	/* Return a pointer to the initial PV page tables */
+	return (pgd_t *)xen_start_info->pt_base;
+}
+
+void __init xen_pv_kasan_pin_pgd(pgd_t *pgd)
+{
+	if (!xen_pv_domain())
+		return;
+
+	set_page_prot(pgd, PAGE_KERNEL_RO);
+	pin_pagetable_pfn(MMUEXT_PIN_L4_TABLE, PFN_DOWN(__pa_symbol(pgd)));
+}
+
+void __init xen_pv_kasan_unpin_pgd(pgd_t *pgd)
+{
+	if (!xen_pv_domain())
+		return;
+
+	pin_pagetable_pfn(MMUEXT_UNPIN_TABLE, PFN_DOWN(__pa_symbol(pgd)));
+	set_page_prot(pgd, PAGE_KERNEL);
+}
+
 #ifdef CONFIG_X86_32
 static void __init xen_map_identity_early(pmd_t *pmd, unsigned long max_pfn)
 {
@@ -1943,6 +1973,15 @@ void __init xen_setup_kernel_pagetable(pgd_t *pgd, unsigned long max_pfn)
 	if (i && i < pgd_index(__START_KERNEL_map))
 		init_top_pgt[i] = ((pgd_t *)xen_start_info->pt_base)[i];
 
+#ifdef CONFIG_KASAN
+	/*
+	 * Copy KASAN mappings
+	 * ffffec0000000000 - fffffbffffffffff (=44 bits) kasan shadow memory (16TB)
+	 */
+	for (i = 0xec0 >> 3; i < 0xfc0 >> 3; i++)
+		init_top_pgt[i] = ((pgd_t *)xen_start_info->pt_base)[i];
+#endif
+
 	/* Make pagetable pieces RO */
 	set_page_prot(init_top_pgt, PAGE_KERNEL_RO);
 	set_page_prot(level3_ident_pgt, PAGE_KERNEL_RO);
diff --git a/drivers/xen/Makefile b/drivers/xen/Makefile
index 0c4efa6fe450..1e9e1e41c0a8 100644
--- a/drivers/xen/Makefile
+++ b/drivers/xen/Makefile
@@ -1,4 +1,6 @@
 # SPDX-License-Identifier: GPL-2.0
+KASAN_SANITIZE_features.o := n
+
 obj-$(CONFIG_HOTPLUG_CPU)		+= cpu_hotplug.o
 obj-y	+= grant-table.o features.o balloon.o manage.o preempt.o time.o
 obj-y	+= mem-reservation.o
diff --git a/include/xen/xen-ops.h b/include/xen/xen-ops.h
index d89969aa9942..91d66520f0a3 100644
--- a/include/xen/xen-ops.h
+++ b/include/xen/xen-ops.h
@@ -241,4 +241,8 @@ static inline void xen_preemptible_hcall_end(void)
 
 #endif /* CONFIG_PREEMPT */
 
+pgd_t *xen_pv_kasan_early_init(void);
+void xen_pv_kasan_pin_pgd(pgd_t *pgd);
+void xen_pv_kasan_unpin_pgd(pgd_t *pgd);
+
 #endif /* INCLUDE_XEN_OPS_H */
diff --git a/kernel/Makefile b/kernel/Makefile
index f2cc0d118a0b..1da6fd93c00c 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -12,6 +12,8 @@ obj-y     = fork.o exec_domain.o panic.o \
 	    notifier.o ksysfs.o cred.o reboot.o \
 	    async.o range.o smpboot.o ucount.o
 
+KASAN_SANITIZE_cpu.o := n
+
 obj-$(CONFIG_MODULES) += kmod.o
 obj-$(CONFIG_MULTIUSER) += groups.o
 
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 81f5464ea9e1..429a638625ea 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -98,6 +98,7 @@ config KASAN_OUTLINE
 
 config KASAN_INLINE
 	bool "Inline instrumentation"
+	depends on !XEN_PV
 	help
 	  Compiler directly inserts code checking shadow memory before
 	  memory accesses. This is faster than outline (in some workloads
@@ -147,7 +148,7 @@ config KASAN_SW_TAGS_IDENTIFY
 
 config KASAN_VMALLOC
 	bool "Back mappings in vmalloc space with real shadow memory"
-	depends on KASAN && HAVE_ARCH_KASAN_VMALLOC
+	depends on KASAN && HAVE_ARCH_KASAN_VMALLOC && !XEN_PV
 	help
 	  By default, the shadow region for vmalloc space is the read-only
 	  zero page. This means that KASAN cannot detect errors involving
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200108152100.7630-3-sergey.dyasli%40citrix.com.
