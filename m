Return-Path: <kasan-dev+bncBAABBDO7Q3YQKGQERTAHMRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D027140A51
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 13:58:54 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id v17sf10449329wrm.17
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 04:58:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579265933; cv=pass;
        d=google.com; s=arc-20160816;
        b=xemmnAuCH1Qd95NFK8bZU7sUxfjWvZeudeg0+lE65VUy1K4W8nOHL87hKIUvXaw06c
         tDedof4A1T8f/HPRA+mylPpiyXjTq9srjJ87crm3qGO5n5CA/1x6Dwct8/0zbNMyVwS2
         cFiltnGr95euMeunjSFWzz7mEgKYXtSeg5c0bRvXVcGOsgCYDj3W3JlYQAzdxt+GwKBe
         qt4C1Rh8tMvMdF47GgSBLwbLzUpSuE5Y2VAbChirblXpPKU2rpf7kj2KoURAnGheutmy
         GR1zUF6UlthPve7t3uZaq0dFiqEl6b9JwJU0+Q7nnt2qnqaXWmb2/FWZBf0AUxybT2TL
         D1ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:ironport-sdr:sender
         :dkim-signature;
        bh=3p1TSts5mBVNE3sm00SCVeFvDDIcUihD6SmYn+y0+Eg=;
        b=AF+Im6w1EwxyXu+oFLNlmpdX524KNDLwN499SAZKKzEGzuZwAZg2/J+N3iYR+0oYNQ
         5qNFJ92dOns2uKxP7OLufBcTqG5LJQnifAZEr1ZWP2/Uu+lSKZX6Zy7R6ZLpFrNzQJJ0
         RcQeOB8v7WmthyxcZCYW0vJm/mQ2gArJdeKTjs9vHXl8n8KmohInGObW5HQ+y+n27lEI
         0/yAeJ+FF/IDhTK6DFAyv2Z49KtmVQkGPSHMfaW35B/6oM8/Dau9sn4V8nNt2aOjwC7S
         PYRTkVbXQ3itTSf3LLebwsRkKpbjSbhTf1gvyA6YY2Gr11x5/iDQefBjDcY9MAOpuPOI
         yjtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=U5wMZ89d;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.175 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3p1TSts5mBVNE3sm00SCVeFvDDIcUihD6SmYn+y0+Eg=;
        b=P1+IjLPpODE2wmrRqCv/8zCmVQPF37kmTuSPpSEBGHm3Z2zUnHbNwrYSKs2RMdw4NQ
         RMCC/klRpSX2CwfBbJHoMkeYD+5/hbi6AE1a/LX/FM8/fMk/70rs1kMDEvKxH2UAFeBg
         sVcJ6dVuRhuVJpv+isvI30SAmHTaUOBuC2UCbsZLyXNYh+iScad4QXUAi506qZhme8pF
         M10gonVmb0OsSxh/IgpbVEfMkLp50Z7H6FSFCYu8NOeCxQkq0hXjmqLNJe2NdfA6dTNc
         qpyztBb44rJMYY8BGColfhcbNO7HUTJWQJSyCUHI0mavEq4Yew8HqX6INdPlEYIY3rSf
         XiiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:from:to:cc:subject:date
         :message-id:in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3p1TSts5mBVNE3sm00SCVeFvDDIcUihD6SmYn+y0+Eg=;
        b=p5z3khng7gh1ChJ52TR9nuVIT21pxX8vM48URcPRq1wBfyb9DMlP47ZtLe0PQ1vdhr
         HdUifk8n0ZS4d3chLmLF5MOkgcJFcVC+PdwO4NAvF9knF79ahD7wBdJ6AN8XOZMsO2Kf
         K4lwQR107Uz8PxE1K3Le5oMJpL+3k08UCKrTJWmCAUtbmQLH2No3ryqEX6C5iFtHykoY
         7h7SggEmHcb6XN1KautSckOUCj+7OJ+1llN5Pmk1FOm8F9yOvblHh3QesvqViqS0GtPU
         RW+z6g1ubBCUIy7D3hPFagXHEDIYzZpAmGyd4BAhQUQ5aT6YYXDsFxFWCUHNeaJqXv6p
         gMpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXNeYaCgU6BqicmEBy2KsbNTtIgEwfXiVb8zhKUZ2vrMZH6f4RW
	GcOFoyMYfUeUvcIRptejjr0=
X-Google-Smtp-Source: APXvYqyIxkoJoZfu4Z+7rbtyRIZ2oCvosicY42c7B4HwHarrNrLyRjMaTGglCiy5tWWLCGfbYaDxRg==
X-Received: by 2002:a5d:62d0:: with SMTP id o16mr2894941wrv.197.1579265933819;
        Fri, 17 Jan 2020 04:58:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6912:: with SMTP id t18ls8907579wru.7.gmail; Fri, 17 Jan
 2020 04:58:53 -0800 (PST)
X-Received: by 2002:a5d:6b88:: with SMTP id n8mr2990743wrx.288.1579265933416;
        Fri, 17 Jan 2020 04:58:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579265933; cv=none;
        d=google.com; s=arc-20160816;
        b=MfIU/UkaaVCb+HQ/Baw+m5U5zo+lTSID3/Lzzr5QbT4EYnjeVntpBf7A+z6R6yLuXz
         QPlOmapINuUCJbyYKPHN7V6YLWpgjrlvngcBFTwKlTS0y2IfwQNcTUJbb53BepOzgpwI
         EbRDEcZnB+GKlFFjJfdi77+d5YjyU5PCR1U6UZj5QRuhX1wjUa54yOJ+AtYh+CIkECvJ
         mseqs9cglEzh8X1pSdL0u2FsvigCyuHfEH91JMe8oXvEZpXSf2yApImD/FJ+p2Ek2RFR
         LEkvB7aXRUckhYfvOFRGP1Gb5/DDhHvTRYEESb2Ol38NM6aSCrDpEwtyfN5Hql3LPQrp
         fu2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:ironport-sdr:dkim-signature;
        bh=uq1fWNGTIFNOQQ49yJV7UV9UvGDsb13J3bemTmPbFKk=;
        b=zXUhbv/OXlXIRmq+86/xCZFt1yaB5XW0ej/S82GeKhTPxZW2ms32SZsP2fas+f0fba
         KZ3d6m9eCmrkqAIU+x0if2+iHUQwz3B6X5GqwTnKGcBdmcFPRckTXJPQYJ6iQLn/L55T
         mCLvGwbC8o8LHGcg4ZHmskAFhASJNe7MbatIgXmP+86MnF6pR0GgRj9TTNLFemxcKCJ8
         0IUyT4+K98T8LS5L7QiB3ks+Lepp61V8xtGCBgpzgDPSSkSFE+OECxmTYfKkymLiaD4v
         wEEtzqiaY42fLjZa1kXrlJiXfECbXmpU3L81+qpgWOjsY1erApyL5FmEOWwWzuwAC23g
         Z6ww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=U5wMZ89d;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.175 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa6.hc3370-68.iphmx.com (esa6.hc3370-68.iphmx.com. [216.71.155.175])
        by gmr-mx.google.com with ESMTPS id s82si338890wme.0.2020.01.17.04.58.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Jan 2020 04:58:53 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.175 as permitted sender) client-ip=216.71.155.175;
Received-SPF: None (esa6.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa6.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa6.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa6.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa6.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa6.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: D0PclziKwpbf2mE67IHsBMXSUsO637VOHeciRcXKoV4dZ/znm7ezy5sUfzEkiDTM1tPjAkpxI0
 9z1nh2VgQXK4qND5ZlC5PxX3k3Ak3hx44ptSXd9YyEIefZOsFtoKOH+nOmyCEPrXpPEUvzazv2
 5FSy4P2bKT7Nv9MhjwpYHUiT0vi2TTLkOaZUkDiqN71c2xmvNSXsidgGG+P2xcsdMKW3OhfNq3
 XBUg2XokzXqiTda2E3tvNu+PqUOpsQfdRpA92hKHVkurbuifgoHg753MU65hw2H3TMajL8F3c2
 AiQ=
X-SBRS: 2.7
X-MesageID: 11502058
X-Ironport-Server: esa6.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.70,330,1574139600"; 
   d="scan'208";a="11502058"
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
Subject: [PATCH v2 2/4] x86/xen: add basic KASAN support for PV kernel
Date: Fri, 17 Jan 2020 12:58:32 +0000
Message-ID: <20200117125834.14552-3-sergey.dyasli@citrix.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20200117125834.14552-1-sergey.dyasli@citrix.com>
References: <20200117125834.14552-1-sergey.dyasli@citrix.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=U5wMZ89d;       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.175 as
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
v1 --> v2:
- Fix compilation without CONFIG_XEN_PV
- Use macros for KASAN_SHADOW_START

RFC --> v1:
- New functions with declarations in xen/xen-ops.h
- Fixed the issue with free_kernel_image_pages() with the help of
  xen_pv_kasan_unpin_pgd()
---
 arch/x86/mm/kasan_init_64.c | 12 ++++++++++++
 arch/x86/xen/Makefile       |  7 +++++++
 arch/x86/xen/enlighten_pv.c |  3 +++
 arch/x86/xen/mmu_pv.c       | 38 +++++++++++++++++++++++++++++++++++++
 drivers/xen/Makefile        |  2 ++
 include/xen/xen-ops.h       | 10 ++++++++++
 kernel/Makefile             |  2 ++
 lib/Kconfig.kasan           |  3 ++-
 8 files changed, 76 insertions(+), 1 deletion(-)

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
index c8dbee62ec2a..5cd63e37a2db 100644
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
@@ -1943,6 +1973,14 @@ void __init xen_setup_kernel_pagetable(pgd_t *pgd, unsigned long max_pfn)
 	if (i && i < pgd_index(__START_KERNEL_map))
 		init_top_pgt[i] = ((pgd_t *)xen_start_info->pt_base)[i];
 
+#ifdef CONFIG_KASAN
+	/* Copy KASAN mappings */
+	for (i = pgd_index(KASAN_SHADOW_START);
+	     i < pgd_index(KASAN_SHADOW_END);
+	     i++)
+		init_top_pgt[i] = ((pgd_t *)xen_start_info->pt_base)[i];
+#endif /* ifdef CONFIG_KASAN */
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
index d89969aa9942..3d20f000af12 100644
--- a/include/xen/xen-ops.h
+++ b/include/xen/xen-ops.h
@@ -241,4 +241,14 @@ static inline void xen_preemptible_hcall_end(void)
 
 #endif /* CONFIG_PREEMPT */
 
+#if defined(CONFIG_XEN_PV)
+pgd_t *xen_pv_kasan_early_init(void);
+void xen_pv_kasan_pin_pgd(pgd_t *pgd);
+void xen_pv_kasan_unpin_pgd(pgd_t *pgd);
+#else
+static inline pgd_t *xen_pv_kasan_early_init(void) { return NULL; }
+static inline void xen_pv_kasan_pin_pgd(pgd_t *pgd) { }
+static inline void xen_pv_kasan_unpin_pgd(pgd_t *pgd) { }
+#endif /* defined(CONFIG_XEN_PV) */
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200117125834.14552-3-sergey.dyasli%40citrix.com.
