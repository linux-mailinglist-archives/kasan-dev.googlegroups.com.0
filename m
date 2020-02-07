Return-Path: <kasan-dev+bncBAABBNPH6XYQKGQEYLAN6NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 895E415594A
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Feb 2020 15:27:01 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id n18sf1949734edo.17
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Feb 2020 06:27:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581085621; cv=pass;
        d=google.com; s=arc-20160816;
        b=qJFDLlgAIZD84qCycG2VA868HLwCWPB0izSkuvhDo1Z9SDFcISB84vZHlTVhhtmhEO
         KqiqICgdm8crTYKxDZVM3kczV8y3q5FV1+r9Vj14sy5EacJcCbdGqNWc1edqhtRS15Jd
         H+Jprd1MJFjRcm4muM7vhPo97rnVgPtErhanBjwdywWH4SLSJwsDCV3ELDkNLICsSSmm
         WoFP4uLIetoXWjt/zf4rgAZd+4t3RcK0BAVtgr+i+mg8Im6W207l6hLZebD7TVt/Z7VM
         EpzB/XEmZ+logyFseSTdrfZnO1+tbzeZmLSdoGmVupHxpXExLk+PjhqNHakShTjinmVE
         vEZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:ironport-sdr:sender
         :dkim-signature;
        bh=iwlShCTvk2IRRZHEpYLKAKnaHHCElnZH6/jwzJMjQ6c=;
        b=DSVX4fkN4JQxRmcayyS3gZr50irj412KcB6CN6lquB8ciMFm3ElxwXnFntEgrXZUXs
         4ibpktXQJT/zeQA0Y2RWr6yvZv/ygsukktQeiQwucxWnCHHvC6jdlPa3274mC2gmyIlY
         SbpB73UFxJaAX4a1+FkG2QoKXflCXHDP+Bd6EnQyn2bImlRyOJJAKWM9aqK4L8gcSXpI
         AZbWoTaRUhmAb7CAPvwhGO1EvVNIdyjoCNooZkZumczJPRB33PSHQhZhkzv3dz8DrGxe
         v/ptaw9iav7NdJSl2FK1nqrty3+3Uuzs3ZGCRaot4EG8iXLW/oHzQVvGjN4vgqrBNWbG
         L7eA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=a0Dvq2+E;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iwlShCTvk2IRRZHEpYLKAKnaHHCElnZH6/jwzJMjQ6c=;
        b=L7Bwd3cwj3aO0rZ/1rHKQv0VvUd71Wjlfi4Sm3tGzqzP3MvEi3sAzjNmuO1lerOziB
         HiJm6/ywq6+E8dAKnFzAbr2fGXoM3Et15aOSp+6mVlZJlCuhfgZ3NBC8gKt2YUoPl8iM
         EmFrgZLsrqViwUJglWRVpI55E6OlvoWptaLJdExknJszwipacrpXIDwg7WsP05piyulQ
         bzQhlwS5BsaRrAAWa6ZfcME9kCaDBuLHATuOI4SU8osy3VgAUpS4aVdFgGhTyqNbC3l1
         jmLa8H4aG6U2lW3RD+Op4xNOwan0jD999RbRWUZ6kfkXtB4syU/Ri7y1f36GvknqY4B7
         W1AA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:from:to:cc:subject:date
         :message-id:in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iwlShCTvk2IRRZHEpYLKAKnaHHCElnZH6/jwzJMjQ6c=;
        b=kApXVyGr4I61h+yBsSVcWhjzhx2lYecv7oZr3k8PAtye29m0J8eqIA5zC86uYiSmoF
         p/Ng9z7H7iK7StTAYMY3DHfQfxWo1wArQk7h2spR+49pLNVfQp2B+vrektqxcvmnQOH5
         j2Ku/bQ6jTA8C7rF+hBzHkxVPRAUG/GWCvZW2l64fuWjb/qzMboGXgQbinLRqYJHS8iF
         Q7saWUJJPjletSHG6HtGMBSzMzuc8NmcrL/4m/5GGz0q9my6bSqxUwWd32dJI+1/tpTl
         klFaKmJ5slE4GEWJX1L2qB8WD2+9qxIQShSmuXMurR/QhCmhg0pylbBNWe9/oLOa3g1I
         peFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVnDIZfaQKba8iXYiD59s8xq2304R+SMBAkEmLlkaG5oh6vlZpO
	Ppi6bpyJnvQ9lGzz4bl7Uis=
X-Google-Smtp-Source: APXvYqx3+hVAbdO6dzQNAz2ZyHyxxEYMmsH34D84cxkYf0FferzpgQUJBCiViP3M1gkB48emxYTn3w==
X-Received: by 2002:aa7:ca53:: with SMTP id j19mr8324217edt.305.1581085621233;
        Fri, 07 Feb 2020 06:27:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:7f99:: with SMTP id f25ls59627ejr.5.gmail; Fri, 07
 Feb 2020 06:27:00 -0800 (PST)
X-Received: by 2002:a17:906:4a12:: with SMTP id w18mr8771793eju.321.1581085620867;
        Fri, 07 Feb 2020 06:27:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581085620; cv=none;
        d=google.com; s=arc-20160816;
        b=IwuEL1nJq/YZhHXNFVeWY7JvJ1aZsVZK8lLbJ9tZEEH6FYt/7aqfmexNh6/p+YfwR2
         73Ug2G9rjG5PMzqz1PgqQ0Gr4ujjxOGiFHZaCyclTOITYKH85Tn3Y1zSdyO3wDWtJD/B
         +ciP6a1e8hr6M6F/Rgic2EG5TY+k5ODtFOF31eJ+jehb8gQExemD4edTovVLyeG9pDeT
         NQVwmkDJJJm7U83ev8xHaS/wGqCCi6a43yZWn/nuZ24rxsC4Gyek88pFSzuHpYpHVdOg
         VMY/gV553GvWl6RRfR6FYQhQHjcDRtkugmAdpH+wrCIh5Y2uzWGdvjS9s18GN47lZygp
         tM5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:ironport-sdr:dkim-signature;
        bh=6gT2u+XBZh68ntR+hLrTLZsonJkrVpX1qLysh+rU4ik=;
        b=U15fKytucrvDy36ssSthIolKmh8sGoNRTmQ7mRWWBuf7Soi1ckiiz7UwaMFKlOe6Ae
         EK08vAa+XpXG2bYIXINItqfeK6O1UlSfLqCpkpkKUSBTje0ZynbEBul5z5nA4Mklh5xw
         Kb8tdmZMHMynvlJcm2WamtjkVXebDTE+UChHlAU8RMpOKOXfTukJBRzYv/qcFD1kM05B
         x7mvvNRziHSajzlzttJxm5jNPd5OiijfnkFJhh9xxAHhom+RUgO7LnVgtrHLwV4oh3WV
         m2Cg2TxIi1z/8ktTyjvQvGlCe4nXvVbq2aTL/S+HzgzrZ7mFJvqVQA1+krbCV/OxBcaK
         UhdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=a0Dvq2+E;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa5.hc3370-68.iphmx.com (esa5.hc3370-68.iphmx.com. [216.71.155.168])
        by gmr-mx.google.com with ESMTPS id df10si169947edb.1.2020.02.07.06.27.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Feb 2020 06:27:00 -0800 (PST)
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
IronPort-SDR: JVR+CfOyL+tpYmHAlsitcbny7cVCDfpEkdNoxfH9qe1SlGKJAJ3g6EJhzTvj3+s9UDCFdzgiJ8
 e9hfHqgfjfh1B5+nE25y09t45e/no+XXb4ywMvS6UtmNeZIUjC5WPpurjMb34uuY/HBajQUxQQ
 owXrGCfWMF8JUnvvRP9Idg+rXw5TtSSypLeyDkztAqTvHKuPdqD8MbhesrPTnvSWdzet2BQCUh
 +y2yt1ZnsMxgca7ZHKU/qdg5DrXR8O41IQG5s0fbqmPmxQeWLqGb/KcuAL6GtkLGKEqrcohKAF
 PO0=
X-SBRS: 2.7
X-MesageID: 12479585
X-Ironport-Server: esa5.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.70,413,1574139600"; 
   d="scan'208";a="12479585"
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
Subject: [PATCH v3 2/4] x86/xen: add basic KASAN support for PV kernel
Date: Fri, 7 Feb 2020 14:26:50 +0000
Message-ID: <20200207142652.670-3-sergey.dyasli@citrix.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20200207142652.670-1-sergey.dyasli@citrix.com>
References: <20200207142652.670-1-sergey.dyasli@citrix.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=a0Dvq2+E;       spf=pass
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

Introduce and use xen_kasan_* functions that are needed to properly
initialise KASAN for Xen PV domains. Disable instrumentation for files
that are used by xen_start_kernel() before kasan_early_init() could
be called.

This enables to use Outline instrumentation for Xen PV kernels.
KASAN_INLINE and KASAN_VMALLOC options currently lead to boot crashes
and hence disabled.

Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
---
v2 --> v3:
- Fix compilation without CONFIG_KASAN
- Dropped _pv prefixes from new functions
- Made xen_kasan_early_init() call kasan_map_early_shadow() directly
- Updated description

v1 --> v2:
- Fix compilation without CONFIG_XEN_PV
- Use macros for KASAN_SHADOW_START

RFC --> v1:
- New functions with declarations in xen/xen-ops.h
- Fixed the issue with free_kernel_image_pages() with the help of
  xen_pv_kasan_unpin_pgd()
---
 arch/x86/mm/kasan_init_64.c | 10 ++++++++-
 arch/x86/xen/Makefile       |  7 ++++++
 arch/x86/xen/enlighten_pv.c |  3 +++
 arch/x86/xen/mmu_pv.c       | 43 +++++++++++++++++++++++++++++++++++++
 drivers/xen/Makefile        |  2 ++
 include/linux/kasan.h       |  2 ++
 include/xen/xen-ops.h       | 10 +++++++++
 lib/Kconfig.kasan           |  3 ++-
 8 files changed, 78 insertions(+), 2 deletions(-)

diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 763e71abc0fe..b862c03a2019 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -13,6 +13,8 @@
 #include <linux/sched/task.h>
 #include <linux/vmalloc.h>
 
+#include <xen/xen-ops.h>
+
 #include <asm/e820/types.h>
 #include <asm/pgalloc.h>
 #include <asm/tlbflush.h>
@@ -231,7 +233,7 @@ static void __init kasan_early_p4d_populate(pgd_t *pgd,
 	} while (p4d++, addr = next, addr != end && p4d_none(*p4d));
 }
 
-static void __init kasan_map_early_shadow(pgd_t *pgd)
+void __init kasan_map_early_shadow(pgd_t *pgd)
 {
 	/* See comment in kasan_init() */
 	unsigned long addr = KASAN_SHADOW_START & PGDIR_MASK;
@@ -317,6 +319,8 @@ void __init kasan_early_init(void)
 
 	kasan_map_early_shadow(early_top_pgt);
 	kasan_map_early_shadow(init_top_pgt);
+
+	xen_kasan_early_init();
 }
 
 void __init kasan_init(void)
@@ -348,6 +352,8 @@ void __init kasan_init(void)
 				__pgd(__pa(tmp_p4d_table) | _KERNPG_TABLE));
 	}
 
+	xen_kasan_pin_pgd(early_top_pgt);
+
 	load_cr3(early_top_pgt);
 	__flush_tlb_all();
 
@@ -412,6 +418,8 @@ void __init kasan_init(void)
 	load_cr3(init_top_pgt);
 	__flush_tlb_all();
 
+	xen_kasan_unpin_pgd(early_top_pgt);
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
index bbba8b17829a..a9a47f0bf22e 100644
--- a/arch/x86/xen/mmu_pv.c
+++ b/arch/x86/xen/mmu_pv.c
@@ -1771,6 +1771,41 @@ static void __init set_page_prot(void *addr, pgprot_t prot)
 {
 	return set_page_prot_flags(addr, prot, UVMF_NONE);
 }
+
+#ifdef CONFIG_KASAN
+void __init xen_kasan_early_init(void)
+{
+	if (!xen_pv_domain())
+		return;
+
+	/* PV page tables must be read-only */
+	set_page_prot(kasan_early_shadow_pud, PAGE_KERNEL_RO);
+	set_page_prot(kasan_early_shadow_pmd, PAGE_KERNEL_RO);
+	set_page_prot(kasan_early_shadow_pte, PAGE_KERNEL_RO);
+
+	/* Add KASAN mappings into initial PV page tables */
+	kasan_map_early_shadow((pgd_t *)xen_start_info->pt_base);
+}
+
+void __init xen_kasan_pin_pgd(pgd_t *pgd)
+{
+	if (!xen_pv_domain())
+		return;
+
+	set_page_prot(pgd, PAGE_KERNEL_RO);
+	pin_pagetable_pfn(MMUEXT_PIN_L4_TABLE, PFN_DOWN(__pa_symbol(pgd)));
+}
+
+void __init xen_kasan_unpin_pgd(pgd_t *pgd)
+{
+	if (!xen_pv_domain())
+		return;
+
+	pin_pagetable_pfn(MMUEXT_UNPIN_TABLE, PFN_DOWN(__pa_symbol(pgd)));
+	set_page_prot(pgd, PAGE_KERNEL);
+}
+#endif /* ifdef CONFIG_KASAN */
+
 #ifdef CONFIG_X86_32
 static void __init xen_map_identity_early(pmd_t *pmd, unsigned long max_pfn)
 {
@@ -1943,6 +1978,14 @@ void __init xen_setup_kernel_pagetable(pgd_t *pgd, unsigned long max_pfn)
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
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 5cde9e7c2664..2ab644229217 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -20,6 +20,8 @@ extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
 extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
 extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
 
+void kasan_map_early_shadow(pgd_t *pgd);
+
 int kasan_populate_early_shadow(const void *shadow_start,
 				const void *shadow_end);
 
diff --git a/include/xen/xen-ops.h b/include/xen/xen-ops.h
index 095be1d66f31..f67f1f2d73c6 100644
--- a/include/xen/xen-ops.h
+++ b/include/xen/xen-ops.h
@@ -241,4 +241,14 @@ static inline void xen_preemptible_hcall_end(void)
 
 #endif /* CONFIG_PREEMPTION */
 
+#if defined(CONFIG_XEN_PV) && defined(CONFIG_KASAN)
+void xen_kasan_early_init(void);
+void xen_kasan_pin_pgd(pgd_t *pgd);
+void xen_kasan_unpin_pgd(pgd_t *pgd);
+#else
+static inline void xen_kasan_early_init(void) { }
+static inline void xen_kasan_pin_pgd(pgd_t *pgd) { }
+static inline void xen_kasan_unpin_pgd(pgd_t *pgd) { }
+#endif /* if defined(CONFIG_XEN_PV) && defined(CONFIG_KASAN) */
+
 #endif /* INCLUDE_XEN_OPS_H */
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200207142652.670-3-sergey.dyasli%40citrix.com.
