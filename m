Return-Path: <kasan-dev+bncBC447XVYUEMRBC5W3WAQMGQEWDZS5XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id AEF0C324BB4
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 09:08:43 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id k7sf1944843lfu.6
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 00:08:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614240523; cv=pass;
        d=google.com; s=arc-20160816;
        b=RTw8I7GEwcRGOCdYTCi+hyIIEAXSXKzSa+Hr2mXm7k6Oh/gCxHJdr2nggVHnhphi/M
         rGqgFVNWQf+KonvBI5xMXHCYA3irwbj8SxYx5gnsO6PbxHY0V5ivC7w5Rc1u6P9l+KnE
         4h4wghBhCQcsphBj+shYkpBtkgH0FAUxNKCMaJTEtpyGNWJsRlH72/18IEafUDqTqC3t
         NmMIpmV6L6p8vNJzB+BppX8ZrX7Z5IuM6eSYVARoBD+1Nup04ji0OnBdgshMK41zNICI
         I1pc2sxhdQgm2azKNlvKoPAEuLVczTSFrj71Bpar4uFRFlZ6DL6TfctoY5C/MZazsMzg
         bKng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kVjz18fS3aoP71hZOiSL/5jhrwxRNOHbNnKnLZm7JCA=;
        b=Jk0PR7weq9vzDh5UgbjGnLFVsemEvG/MXgpjXcsuZr+7msphHJOxs3H+DOie6qe6e8
         m0a/PcXKScjQAPiC57IzcKw7NAlStMOSNCi9VEm33hLtqGz8dnxoqfP4P6xDkErnRxFI
         Rj3f2w2rMu4j9bStcglJJGyPWe3s++8hasu24C58IYi1ifS+Li0CapmA3M4N4UAMMOXT
         kyYcGQlweKXuPw9CQl/veV0ybfbHsQa0tKZM+mK0dAWPMbukrWqZAwp8M5RG7VPIB7yv
         lX5Hug88O2Y/2KG0aOLEPka75g8cx4KAdVP/vawZnfxCh/OcmJu45DobEDZTixyB+shY
         U5iQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.232 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kVjz18fS3aoP71hZOiSL/5jhrwxRNOHbNnKnLZm7JCA=;
        b=Ki5LCRRehfKK8Wb4yphQxLTYakp6hOjtEpOvAQhoHTzqAmcIvS+1iTWm6n3iaI/AxA
         TYivZTyei3N1O2g63r1GHpaM/4UISciwZw6E9PRXw9BWGk4D/KAF/GtcScyQyVQhOeNR
         3xnh3AtwXxgHo+W9UMLjcUHGIjv2l5yGbHV+4bia+S0LKc8sPxHZKjE3oPbBjFXuUre+
         HkTYYqZB+VHE66vXYGYKE6bg81xvMx0zgvV6Z9PiK9PWqfsghZpWcfASXrMs1gK3OkL3
         FU4Qyj3gZxxWvyqJPOpZiFj2FCqdeoiKHhZ8elsNFBdK28TKp12La+0ME4P/QMCJXmwC
         ZKJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kVjz18fS3aoP71hZOiSL/5jhrwxRNOHbNnKnLZm7JCA=;
        b=YzOYCxITHQgS8utK1tv1MXCnmOwT1Wnpi9F7nHAOnq9l+0KlzNYPzRmRxRqAqw1ntf
         +7+46yoxa7H5BaeJEpzmDQgAE2NH7jn0WeRpsQdKRS+9Lb0nnAtvkdSsO3u8KUe5yBeb
         z1iuRysFf0TVH9EhxKdfzbXq+Mg6mWPVlzt0SycV8SWIYcU/8Q5lLLOw1y80k+U9glFO
         rIt01eTwZjUgzOlGU8TQfe6P8zW4qFSlRr9B9CBWCR95ig+QDR/wehoTMaoeiUvaxvP+
         XLBDq+Dg770U2xaHDTDt/KDVCocPoQWCQP0JxMAg1r46QnZMRumy9bqNjOascMz5Vjwz
         ipDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531qx/0ZK7hxssr3d6iSsVgdghtcaX8kwRjngmBhAUwcvUH6rSyS
	MLy4cLZvPm3SLYUcBPXCyPw=
X-Google-Smtp-Source: ABdhPJzvPuB+flnw0e7GtCAb2YI7liFgPIU2aOQeqtws3zi17aTqWp/oBRuIpk+HNb942bnkFQ3C7Q==
X-Received: by 2002:a05:6512:21c7:: with SMTP id d7mr1334790lft.236.1614240523274;
        Thu, 25 Feb 2021 00:08:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8915:: with SMTP id d21ls687210lji.1.gmail; Thu, 25 Feb
 2021 00:08:42 -0800 (PST)
X-Received: by 2002:a2e:151e:: with SMTP id s30mr925177ljd.375.1614240522300;
        Thu, 25 Feb 2021 00:08:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614240522; cv=none;
        d=google.com; s=arc-20160816;
        b=OmYe2FtWw+q0fTgXRx1qhkh/SPngGs3Y+smPOAaZtiSx21Aeu1VuX5dOUfon9VwUgO
         u+9x6R4dAweWeq7+gFq0GpOuZL1OQhb0pJ3doS0eq8m3ua6nrNktV+XmW6DeIcPBUqRc
         +Fu18KC+mPI2mEbcTPzpYgwQXwKk1fitbYmw+E5XQVfaG3WZThcG95sYEqTv1nILGs8q
         YBKVTwgixbTDiNpiaDcktIh53UfoJrPFpszUWy1b/JD6TBf0FBkuhfU3kwrOIcMerm2/
         g9EmZ8GmxPihdjeTxv5SJbPeJndn2ezQB19INr7YOHAql/JE0cbDfGmvkfczQto0QHog
         A0Ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=GvHEX5VJhNaodtmCmmex+400p92Ha0iQXYt+g3GclD8=;
        b=gu/NjLYFpLeD8Nir57oFbW2jj69TNsY4ZPRmyOhqof4HLnMlNlDGr4seuW4tlL8EIy
         EXpdJy9SFYESNEjGNxkd2bVCOYMS6skbExZK66mwa++7G0VCk6SKMR7RtHp/h1VThEni
         T0Ai7Hl3rtv77x0/xb0sZAYl66FlR1aNcBLOvzDvXu3nV5iFWVDJzxJIjg8aDtiECOBf
         yndpjJY5GcrQ6lNgQlE5T8Vb2txE0OJFzfmZZ3ro7PTlS8ds347swfXtM8rRQQNLcd4c
         RIfsNQF++JgEpfZrZRlqXpV6XoTvONRUgQ3j2U+x3cobVWoW0hsBCit1cNAcAsj3Tlf5
         xkWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.232 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay12.mail.gandi.net (relay12.mail.gandi.net. [217.70.178.232])
        by gmr-mx.google.com with ESMTPS id t21si137579lfe.3.2021.02.25.00.08.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 25 Feb 2021 00:08:42 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.178.232 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.178.232;
Received: from localhost.localdomain (35.161.185.81.rev.sfr.net [81.185.161.35])
	(Authenticated sender: alex@ghiti.fr)
	by relay12.mail.gandi.net (Postfix) with ESMTPSA id D4AB9200006;
	Thu, 25 Feb 2021 08:08:34 +0000 (UTC)
From: Alexandre Ghiti <alex@ghiti.fr>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Arnd Bergmann <arnd@arndb.de>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org,
	linux-mm@kvack.org
Cc: Alexandre Ghiti <alex@ghiti.fr>,
	Anup Patel <anup@brainfault.org>
Subject: [PATCH 3/3] riscv: Prepare ptdump for vm layout dynamic addresses
Date: Thu, 25 Feb 2021 03:04:53 -0500
Message-Id: <20210225080453.1314-4-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210225080453.1314-1-alex@ghiti.fr>
References: <20210225080453.1314-1-alex@ghiti.fr>
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.178.232 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

This is a preparatory patch for sv48 support that will introduce
dynamic PAGE_OFFSET.

Dynamic PAGE_OFFSET implies that all zones (vmalloc, vmemmap, fixaddr...)
whose addresses depend on PAGE_OFFSET become dynamic and can't be used
to statically initialize the array used by ptdump to identify the
different zones of the vm layout.

Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
Reviewed-by: Anup Patel <anup@brainfault.org>
---
 arch/riscv/mm/ptdump.c | 67 ++++++++++++++++++++++++++++++++++--------
 1 file changed, 55 insertions(+), 12 deletions(-)

diff --git a/arch/riscv/mm/ptdump.c b/arch/riscv/mm/ptdump.c
index ace74dec7492..aa1b3bce61ab 100644
--- a/arch/riscv/mm/ptdump.c
+++ b/arch/riscv/mm/ptdump.c
@@ -58,29 +58,52 @@ struct ptd_mm_info {
 	unsigned long end;
 };
 
+enum address_markers_idx {
+#ifdef CONFIG_KASAN
+	KASAN_SHADOW_START_NR,
+	KASAN_SHADOW_END_NR,
+#endif
+	FIXMAP_START_NR,
+	FIXMAP_END_NR,
+	PCI_IO_START_NR,
+	PCI_IO_END_NR,
+#ifdef CONFIG_SPARSEMEM_VMEMMAP
+	VMEMMAP_START_NR,
+	VMEMMAP_END_NR,
+#endif
+	VMALLOC_START_NR,
+	VMALLOC_END_NR,
+	PAGE_OFFSET_NR,
+	MODULES_MAPPING_NR,
+	KERNEL_MAPPING_NR,
+	END_OF_SPACE_NR
+};
+
 static struct addr_marker address_markers[] = {
 #ifdef CONFIG_KASAN
-	{KASAN_SHADOW_START,	"Kasan shadow start"},
-	{KASAN_SHADOW_END,	"Kasan shadow end"},
+	{0, "Kasan shadow start"},
+	{0, "Kasan shadow end"},
 #endif
-	{FIXADDR_START,		"Fixmap start"},
-	{FIXADDR_TOP,		"Fixmap end"},
-	{PCI_IO_START,		"PCI I/O start"},
-	{PCI_IO_END,		"PCI I/O end"},
+	{0, "Fixmap start"},
+	{0, "Fixmap end"},
+	{0, "PCI I/O start"},
+	{0, "PCI I/O end"},
 #ifdef CONFIG_SPARSEMEM_VMEMMAP
-	{VMEMMAP_START,		"vmemmap start"},
-	{VMEMMAP_END,		"vmemmap end"},
+	{0, "vmemmap start"},
+	{0, "vmemmap end"},
 #endif
-	{VMALLOC_START,		"vmalloc() area"},
-	{VMALLOC_END,		"vmalloc() end"},
-	{PAGE_OFFSET,		"Linear mapping"},
+	{0, "vmalloc() area"},
+	{0, "vmalloc() end"},
+	{0, "Linear mapping"},
+	{0, "Modules mapping"},
+	{0, "Kernel mapping (kernel, BPF)"},
 	{-1, NULL},
 };
 
 static struct ptd_mm_info kernel_ptd_info = {
 	.mm		= &init_mm,
 	.markers	= address_markers,
-	.base_addr	= KERN_VIRT_START,
+	.base_addr	= 0,
 	.end		= ULONG_MAX,
 };
 
@@ -335,6 +358,26 @@ static int ptdump_init(void)
 {
 	unsigned int i, j;
 
+#ifdef CONFIG_KASAN
+	address_markers[KASAN_SHADOW_START_NR].start_address = KASAN_SHADOW_START;
+	address_markers[KASAN_SHADOW_END_NR].start_address = KASAN_SHADOW_END;
+#endif
+	address_markers[FIXMAP_START_NR].start_address = FIXADDR_START;
+	address_markers[FIXMAP_END_NR].start_address = FIXADDR_TOP;
+	address_markers[PCI_IO_START_NR].start_address = PCI_IO_START;
+	address_markers[PCI_IO_END_NR].start_address = PCI_IO_END;
+#ifdef CONFIG_SPARSEMEM_VMEMMAP
+	address_markers[VMEMMAP_START_NR].start_address = VMEMMAP_START;
+	address_markers[VMEMMAP_END_NR].start_address = VMEMMAP_END;
+#endif
+	address_markers[VMALLOC_START_NR].start_address = VMALLOC_START;
+	address_markers[VMALLOC_END_NR].start_address = VMALLOC_END;
+	address_markers[PAGE_OFFSET_NR].start_address = PAGE_OFFSET;
+	address_markers[MODULES_MAPPING_NR].start_address = MODULES_VADDR;
+	address_markers[KERNEL_MAPPING_NR].start_address = kernel_virt_addr;
+
+	kernel_ptd_info.base_addr = KERN_VIRT_START;
+
 	for (i = 0; i < ARRAY_SIZE(pg_level); i++)
 		for (j = 0; j < ARRAY_SIZE(pte_bits); j++)
 			pg_level[i].mask |= pte_bits[j].mask;
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210225080453.1314-4-alex%40ghiti.fr.
