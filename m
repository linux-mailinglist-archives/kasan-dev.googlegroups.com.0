Return-Path: <kasan-dev+bncBAABBYWC4PXQKGQEC5O5RXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D301122E16
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2019 15:08:36 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id 6sf624224oij.13
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2019 06:08:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576591715; cv=pass;
        d=google.com; s=arc-20160816;
        b=tcGtZrh9xSiAKVFAls0MOfdRy4UvwUgfwrmKAXhhhJK+RAmyro+oIJ46LxvVrk2lHN
         EEQLfvUtVUtttco/YglXhPyjHf2PA99HHU3C9NhH55CqF67Ij17DkvkxNptlyStDsvGd
         08JUeDvnGDJmrA8hq63FhsxtTcNC4oKvSlFvs7UHZew22TYMk0YT5hOTy9XU7CEjt22L
         FwjMm7S6UPuRm9fdTcEXv/JpJNNqG6v1bNTKwLgaekBbWi1wyLBEC+qs62EAsa93n3SJ
         os5VDw0KqtdP87HB5puQWdHVQ+QStY5AdJqaa9X7JFi3qM8YEx9oQY5x08cQBnGlOlrK
         z61w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:ironport-sdr:sender
         :dkim-signature;
        bh=qAh9nTMGZCvmwaBMX+f0xg2T7yotFOKq+UDYQOkCZeg=;
        b=V75l0HuRK5VynRCWMaX1k8OcqC55CKw5c0mhfOICdHjQ5VoM0yCLlZPoWgWKqxzApd
         RRp2h1V9OlNwv5nIkL5NEMt1xTxCE7Dxwg8WydytcsMJ/zH5N6BsbrCpst7K2MR+v6wu
         Htz1ksjKdmFTgQe12qW3j+XpBk561h4qqITU3zj2bgHpX0kgQjTeNv+9MY4uGIorsU/s
         qvwQWvxpN5Urh8JryvsYoguxtu6m6ObryD1e/ESMsj/v6FFHxxgwqvPkdUOvwjDxESui
         8JIX9zxRRUr9OQh5NCL14k5GDltylbVe5CT84s3+4MaRS+uzrL+2YGyQUGd2id8N31oN
         YIkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=dMDWBRwV;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qAh9nTMGZCvmwaBMX+f0xg2T7yotFOKq+UDYQOkCZeg=;
        b=NmTjXavfy6MoH7uzb5J+mzwfg0pcKFTnKCBHpwf5sIB6Ul77Ln8WjHS5482aqlnG+O
         w4BZ1v7Z7enOn9FodugR3fMZ9iOeAQF6PlZYOCn9q2he6PpxYKS3ZdDRONuTmKB2L6fV
         kBi1wDRxr9PusBlR6IxvQ5RLJU+HtfcJQFbgVbYsrOvleOSfZTkvOgXnDyPY6QfmKD4N
         tMTb0DI89UJJYPdsmObtOBWLGO3XzpToYQJjUwl9Wvg4cI3DYxdsRfcGRbvrQiy8L3WA
         6C5A+KcLVPXdsBQqaONnnh8BKcQ2kOFcS/GQnBercPfXzgQnjIXgAG4NAij8gk+5KP7h
         c5sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:from:to:cc:subject:date
         :message-id:in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qAh9nTMGZCvmwaBMX+f0xg2T7yotFOKq+UDYQOkCZeg=;
        b=fA+zJhK9lZdnORbWJLk9Bd2tYFdRX6jgZExieX3yT+kaT2thfYju0m9bDIXKIjb5qM
         iWKg2emLRgLpihB5zN0KKOlIrVQ7WrujK1acw0BXQ7EvJY2g3E+9CZvUAtjIhqEl1XvO
         tCVQA3QJN2o3A0V3ARhxX3KeRSmdFCjlBLs1eITuzubU/7z9hqMvapjXo7bC0SttGIJU
         bHfHDRNZTR969oD36Cs3cfz2M5C0W7me8vQebOKqDoNjYLnvlc5+Bv6p5wddU1Yqb/rR
         AR616EYmpWZ4Z41tfvo5bzd+J6eAwJsTcQ7vccp5OazfThCi7qR5RSSLRAkc7eBMX9JT
         NraQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUVOraKa+uDTygYpHxleZ9jEBCFroyNOJ/DkQR0MwKtj08fmK4G
	/377tio4+JAJrnruGBf2/tE=
X-Google-Smtp-Source: APXvYqxfc/GD5VjjURgGtQLdf1w0rZGs7Bs/cw/urmDeLNPAdG+SObt8VuKi4DxRRsNZudFL6AmClg==
X-Received: by 2002:aca:2817:: with SMTP id 23mr1406723oix.133.1576591714902;
        Tue, 17 Dec 2019 06:08:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d549:: with SMTP id m70ls1534019oig.10.gmail; Tue, 17
 Dec 2019 06:08:34 -0800 (PST)
X-Received: by 2002:aca:d706:: with SMTP id o6mr1637322oig.19.1576591714484;
        Tue, 17 Dec 2019 06:08:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576591714; cv=none;
        d=google.com; s=arc-20160816;
        b=NrU/Z9zsdT4ApwQTPJg+yQqgcPm5ucontuj5ibFeJ5QKnWavEboMEadj0r+1J/z3/6
         5kBaVus257eQRQeBdUMgCQyeBq3NqN+M7AUr8H+DHh3jNv6wJ/ZSwKjC1vxXI+sDVlPo
         7kp43Gc/hZtkxn9gz4URANcHUf0oPFy4FPl7MQmALP0SbT2Bt9gRWsT8xEAjgyeYyavZ
         ok+YEam1EGK7Gi7YdZc0gh4snUReCWJwzsF7ybooLBRCQA49MhW1ZT9IhKh5TykgCL7S
         hBds5o+f+P1oRKFD8bUPgqk35bloDkLLvIsbh9tJrf7IV1y46N85oFT6URke0VnZdZYK
         GIVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:ironport-sdr:dkim-signature;
        bh=Stw/1RVoP5WWkQFoqw4gFqy8tcsQlXALWFdrWP6U/G4=;
        b=dGz15UByvXtUu2sBe7J7woQTTOTIqU00IMu3bA4ZTAFMHXFuRlQYgIQWgVC2G6v4sY
         1USZgF4cWRLa4w5P8dgguz1kkAA3OqxXnH5/JtrmV19rPPZPmnoEbe4/WuQuZ+JqSx+d
         9DELGtmD0DOyErdzzLhJktFJcePz68esJOwE5OHj/f5nUpE+hBkS4alTNiXJSY/WC5t6
         JQt0/vBHatuxbwsDy+FCUxTWMCC+WOrpvFkwp6l5vEhhAbapSEbW6iSu4NOLVEYfnkvi
         81XQ1Rp0TCqzIg4bC9MPnzKDWJSOPnEjRYw2524eVBDl/Nrf3ZyGA1Xuelzn36hnmvi/
         VBRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=dMDWBRwV;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa2.hc3370-68.iphmx.com (esa2.hc3370-68.iphmx.com. [216.71.145.153])
        by gmr-mx.google.com with ESMTPS id w63si1023058oif.2.2019.12.17.06.08.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 Dec 2019 06:08:34 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as permitted sender) client-ip=216.71.145.153;
Received-SPF: None (esa2.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa2.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa2.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa2.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa2.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa2.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: vTNHCHh/5quroKztrA/VQaZHeqhEeaqLFGVh7RsQIpPaIn2P5hLV2/P8ElTYM1ye+vK8PdN4vI
 EM/B4CNPsHIZJNfn5D98SRqCeY8dQ4iY2x0rNpsawnWgBMMUrR5Wd4lx8MFY4GB6/h/RnxX5Rh
 DXzoFiKbulmk9Thb6ePUROwDYo6FOg7veYQ3GEGS4q3xYkJf2pN8df6mCUJWToiiOZtwDa252J
 iCpOdkz8HNA0AgnQqnehmxFc0zj5ZzL3HU8VRrCRxr7VpjtGgQKWKk3+E7jDrZFER7AKWUM9M8
 5PE=
X-SBRS: 2.7
X-MesageID: 9817032
X-Ironport-Server: esa2.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.69,325,1571716800"; 
   d="scan'208";a="9817032"
From: Sergey Dyasli <sergey.dyasli@citrix.com>
To: <xen-devel@lists.xen.org>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Boris Ostrovsky
	<boris.ostrovsky@oracle.com>, Juergen Gross <jgross@suse.com>, "Stefano
 Stabellini" <sstabellini@kernel.org>, George Dunlap
	<george.dunlap@citrix.com>, Ross Lagerwall <ross.lagerwall@citrix.com>,
	Sergey Dyasli <sergey.dyasli@citrix.com>
Subject: [RFC PATCH 1/3] x86/xen: add basic KASAN support for PV kernel
Date: Tue, 17 Dec 2019 14:08:02 +0000
Message-ID: <20191217140804.27364-2-sergey.dyasli@citrix.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20191217140804.27364-1-sergey.dyasli@citrix.com>
References: <20191217140804.27364-1-sergey.dyasli@citrix.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=dMDWBRwV;       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as
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

Rough edges in the patch are marked with XXX.

Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
---
 arch/x86/mm/init.c          | 14 ++++++++++++++
 arch/x86/mm/kasan_init_64.c | 28 ++++++++++++++++++++++++++++
 arch/x86/xen/Makefile       |  7 +++++++
 arch/x86/xen/enlighten_pv.c |  3 +++
 arch/x86/xen/mmu_pv.c       | 13 +++++++++++--
 arch/x86/xen/multicalls.c   | 10 ++++++++++
 drivers/xen/Makefile        |  2 ++
 kernel/Makefile             |  2 ++
 lib/Kconfig.kasan           |  3 ++-
 9 files changed, 79 insertions(+), 3 deletions(-)

diff --git a/arch/x86/mm/init.c b/arch/x86/mm/init.c
index e7bb483557c9..0c98a45eec6c 100644
--- a/arch/x86/mm/init.c
+++ b/arch/x86/mm/init.c
@@ -8,6 +8,8 @@
 #include <linux/kmemleak.h>
 #include <linux/sched/task.h>
 
+#include <xen/xen.h>
+
 #include <asm/set_memory.h>
 #include <asm/e820/api.h>
 #include <asm/init.h>
@@ -835,6 +837,18 @@ void free_kernel_image_pages(const char *what, void *begin, void *end)
 	unsigned long end_ul = (unsigned long)end;
 	unsigned long len_pages = (end_ul - begin_ul) >> PAGE_SHIFT;
 
+	/*
+	 * XXX: skip this for now. Otherwise it leads to:
+	 *
+	 * (XEN) mm.c:2713:d157v0 Bad type (saw 8c00000000000001 != exp e000000000000000) for mfn 36f40 (pfn 02f40)
+	 * (XEN) mm.c:1043:d157v0 Could not get page type PGT_writable_page
+	 * (XEN) mm.c:1096:d157v0 Error getting mfn 36f40 (pfn 02f40) from L1 entry 8010000036f40067 for l1e_owner d157, pg_owner d157
+	 *
+	 * and further #PF error: [PROT] [WRITE] in the kernel.
+	 */
+	if (xen_pv_domain() && IS_ENABLED(CONFIG_KASAN))
+		return;
+
 	free_init_pages(what, begin_ul, end_ul);
 
 	/*
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index cf5bc37c90ac..caee2022f8b0 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -13,6 +13,8 @@
 #include <linux/sched/task.h>
 #include <linux/vmalloc.h>
 
+#include <xen/xen.h>
+
 #include <asm/e820/types.h>
 #include <asm/pgalloc.h>
 #include <asm/tlbflush.h>
@@ -20,6 +22,9 @@
 #include <asm/pgtable.h>
 #include <asm/cpu_entry_area.h>
 
+#include <xen/interface/xen.h>
+#include <asm/xen/hypervisor.h>
+
 extern struct range pfn_mapped[E820_MAX_ENTRIES];
 
 static p4d_t tmp_p4d_table[MAX_PTRS_PER_P4D] __initdata __aligned(PAGE_SIZE);
@@ -305,6 +310,12 @@ static struct notifier_block kasan_die_notifier = {
 };
 #endif
 
+#ifdef CONFIG_XEN
+/* XXX: this should go to some header */
+void __init set_page_prot(void *addr, pgprot_t prot);
+void __init pin_pagetable_pfn(unsigned cmd, unsigned long pfn);
+#endif
+
 void __init kasan_early_init(void)
 {
 	int i;
@@ -332,6 +343,16 @@ void __init kasan_early_init(void)
 	for (i = 0; pgtable_l5_enabled() && i < PTRS_PER_P4D; i++)
 		kasan_early_shadow_p4d[i] = __p4d(p4d_val);
 
+	if (xen_pv_domain()) {
+		/* PV page tables must have PAGE_KERNEL_RO */
+		set_page_prot(kasan_early_shadow_pud, PAGE_KERNEL_RO);
+		set_page_prot(kasan_early_shadow_pmd, PAGE_KERNEL_RO);
+		set_page_prot(kasan_early_shadow_pte, PAGE_KERNEL_RO);
+
+		/* Add mappings to the initial PV page tables */
+		kasan_map_early_shadow((pgd_t *)xen_start_info->pt_base);
+	}
+
 	kasan_map_early_shadow(early_top_pgt);
 	kasan_map_early_shadow(init_top_pgt);
 }
@@ -369,6 +390,13 @@ void __init kasan_init(void)
 				__pgd(__pa(tmp_p4d_table) | _KERNPG_TABLE));
 	}
 
+	if (xen_pv_domain()) {
+		/* PV page tables must be pinned */
+		set_page_prot(early_top_pgt, PAGE_KERNEL_RO);
+		pin_pagetable_pfn(MMUEXT_PIN_L4_TABLE,
+				  PFN_DOWN(__pa_symbol(early_top_pgt)));
+	}
+
 	load_cr3(early_top_pgt);
 	__flush_tlb_all();
 
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
index c8dbee62ec2a..eaf63f1f26af 100644
--- a/arch/x86/xen/mmu_pv.c
+++ b/arch/x86/xen/mmu_pv.c
@@ -1079,7 +1079,7 @@ static void xen_exit_mmap(struct mm_struct *mm)
 
 static void xen_post_allocator_init(void);
 
-static void __init pin_pagetable_pfn(unsigned cmd, unsigned long pfn)
+void __init pin_pagetable_pfn(unsigned cmd, unsigned long pfn)
 {
 	struct mmuext_op op;
 
@@ -1767,7 +1767,7 @@ static void __init set_page_prot_flags(void *addr, pgprot_t prot,
 	if (HYPERVISOR_update_va_mapping((unsigned long)addr, pte, flags))
 		BUG();
 }
-static void __init set_page_prot(void *addr, pgprot_t prot)
+void __init set_page_prot(void *addr, pgprot_t prot)
 {
 	return set_page_prot_flags(addr, prot, UVMF_NONE);
 }
@@ -1943,6 +1943,15 @@ void __init xen_setup_kernel_pagetable(pgd_t *pgd, unsigned long max_pfn)
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
diff --git a/arch/x86/xen/multicalls.c b/arch/x86/xen/multicalls.c
index 07054572297f..5e4729efbbe2 100644
--- a/arch/x86/xen/multicalls.c
+++ b/arch/x86/xen/multicalls.c
@@ -99,6 +99,15 @@ void xen_mc_flush(void)
 				ret++;
 	}
 
+	/*
+	 * XXX: Kasan produces quite a lot (~2000) of warnings in a form of:
+	 *
+	 *     (XEN) mm.c:3222:d155v0 mfn 3704b already pinned
+	 *
+	 * during kasan_init(). They are benign, but silence them for now.
+	 * Otherwise, booting takes too long due to printk() spam.
+	 */
+#ifndef CONFIG_KASAN
 	if (WARN_ON(ret)) {
 		pr_err("%d of %d multicall(s) failed: cpu %d\n",
 		       ret, b->mcidx, smp_processor_id());
@@ -121,6 +130,7 @@ void xen_mc_flush(void)
 			}
 		}
 	}
+#endif /* CONFIG_KASAN */
 
 	b->mcidx = 0;
 	b->argidx = 0;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191217140804.27364-2-sergey.dyasli%40citrix.com.
