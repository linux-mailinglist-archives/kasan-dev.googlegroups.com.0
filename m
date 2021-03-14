Return-Path: <kasan-dev+bncBC447XVYUEMRBT5HW6BAMGQEKS6NQNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0AB8B33A3CC
	for <lists+kasan-dev@lfdr.de>; Sun, 14 Mar 2021 10:13:52 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id a22sf11214149ljq.4
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Mar 2021 01:13:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615713231; cv=pass;
        d=google.com; s=arc-20160816;
        b=XKg+8mhSNuIxVRWjW12NpS+tpvN5ENHi4swebhMWyZ/DGlHt6u3OiMyvdPzVGNN+ft
         7IoPiXJpUf6G2sw21zMcGUfUKZGYFXodaqax8lCH5FWXUdT55aa6RbfP+guic/Eag8D0
         L0KjtSc4bp66Vrk7GK9zq/hWc5mNkaXcUdzVSPTEzC4YHlJnlWGbaKLWfBgytNoLnvve
         5glmbYVwIiaWRG2i6vp+gPP7brrJzXQxOD5x1t00ZWr8GN2nhopHJ0fLEB2l/WuRy8gf
         w4XE6kIsJ5wgEgsjIA7mVCrGuZ5H5W+chvaNDli5H+ICLnutoaF5OVs2LOSv+ulBRSOS
         S9Hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=POlxo66pWvbnZ1l2nS1ZiolJgReVvtsmwalj+nQ34ek=;
        b=uVhMiYTrOibBATqJ3ZAN0JvOko/JFFB/BtImHjNAlZDUeYKnHSmt8Wr/Uz1oCyCAtp
         fw+eMbi6oWQSg+5n9LFZnWbczLBNcgaFs9XiPNgpPwSPRlpDVHiNAzurw89tLq175RmZ
         7MMolsUYa8ksMbiNxcPkjjB691uO1cdGhik/wyJvhAwBxHrMAtvEMvZ5rnD+GBYBb2gm
         KpurfrfnKsr1wC3ydwijOYlxNaJ8mCxI1hyT6B0POofNjlgsFs8xDzodJFuaGkz6HN7L
         lVk7kIkNgEvtHuYJCvhrwMnCXTN0FtwiUbfsZiwSUxO+nmL10//zbmSyFJ49/FbwBByw
         XCbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=POlxo66pWvbnZ1l2nS1ZiolJgReVvtsmwalj+nQ34ek=;
        b=PIlaXk9a85J9KoGyrrkRD+tmKzT/7YvGUlfCeJg3yanwSLBwZgoHnprkXxP+8QluXO
         67rwePqIsEy938Yosnh1AtzvejeQ0gleMiOkvXPmoZ2Tl8iubdASFj7jUby2cl8bAg7f
         t+4tOBCdb+kmv6RP+GfpbHv/iGtFMeC5Y14rG8jhh/OTK/ioJlH2eTWo8xLguLRfFyrd
         M9ERrKQmsE1eD/mGuF5Po16X7ZjxiG4hes8OBLBQjsXgcosHi+hkFu4mobN+AgUVCgaa
         YZng9I56tDPrNN6qTbvvHSH0VFfNACLQGv1+m9KezYL8DU0k9z7XzwF85wCG/XtAu4Cz
         pl9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=POlxo66pWvbnZ1l2nS1ZiolJgReVvtsmwalj+nQ34ek=;
        b=fBslyQjaRgvJZzY+8oSvXRcPD/N/gm5rCObCWuojHLXNAa/XZQTEcu70pct8doMwz7
         wHOmBR2QTB8JMt4DBCGmSv8S0AVdIcsLL0vbxeIFopfdHk8z/UBZMNXQhO5mSEGzJ/lm
         GQuNBTkISTLAq4uen3L3/6tZzCABIj4sOwnM8/a/Rq720yIKwqrpCa9tD6CQx1Yg/PYi
         oAeKPqGZVxgWOrRRit7yrf7fHeI/F2PD+JRXQA9naDVyJ2C85ugyAhh69mazReAqv1hb
         P85FoG5LeoeoGsZykbPcQ4L0C5fc1yis2xzF+FdrD5p0+DJgmNqkR8Q5ixuDWLByeIja
         Q50w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532LI2u2K9xcy1q0OHynvxJKpzFKMm8Ew2z0zBbd9ib6FKhptGK8
	xFL2JOxbMwgCwJyh1rXRsVc=
X-Google-Smtp-Source: ABdhPJwVGEZT76C+sYLkP13IPnkHbzX8gK3yyS6NA5IhtTbR65uQJ8Qh0/LItBvBfZWGr1VlOB07Ig==
X-Received: by 2002:a2e:a60a:: with SMTP id v10mr7658593ljp.267.1615713231635;
        Sun, 14 Mar 2021 01:13:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls1212247lfu.3.gmail; Sun,
 14 Mar 2021 01:13:50 -0800 (PST)
X-Received: by 2002:ac2:5ed0:: with SMTP id d16mr4771886lfq.569.1615713230671;
        Sun, 14 Mar 2021 01:13:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615713230; cv=none;
        d=google.com; s=arc-20160816;
        b=jJd5CzcDGcb4mx4w1sfWqKnwgYUvSkLWQ+/u9PVaIbBXzElVINEH1MYh+/m15kwd3n
         62zVrLUCQsDh9aI1QViMYDKvwke+OQOHhsbdEo/QiOgacI/ermJ+Cl3B4v4TBnVuO1on
         yauhSWjVyTXKgKNMmMfFqAbJMXts/CulOg+5B4vga1d/17P2j1xg7B+tz+qFVwbWgBd9
         k6tWo6+IC3UnlOwribmH1oiMQ1D3Jxoj0IVDOyrSKwY31dK7nIgdDOG33Ly0ZafmyurV
         1NbkS8azBle5PyREX3vDcK9C0vDu2PRQ817qTOO6bfmu2RFSG43I6sasm7vtMH7v9pU2
         Obpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=GvHEX5VJhNaodtmCmmex+400p92Ha0iQXYt+g3GclD8=;
        b=WEUqTrwpqpVb1aHGbCciFfem1clLBAirTWYf2hdnATIG3h3FpD/5d5PXOrT+RHQfSO
         i60cnTGzuBIrYmz/Fq8hRwdb9NgFzWt6lHE5FI0X59efx2MQZU+DLKMSlMoXOV9njgVr
         QF6rUM4PNWaD4YjkOjVo8IhWjhnBstwUoUEZ/5DK7t6j0QqQLgU5fyCbkWyraIbenmhy
         0DEOcFz5tTYQzgMYmIN3jgAU1ot1P5X0rCrVYrSCuxnydH/TSbWt9056ge1WGp1HMDpw
         i6kHxdYsvr6gTCbp3TxApV73k5DPqSUa3EGuh9eyFhAwtR4vBC/PFrBFJ/1E3GOBXlk/
         WPoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay1-d.mail.gandi.net (relay1-d.mail.gandi.net. [217.70.183.193])
        by gmr-mx.google.com with ESMTPS id x41si287786lfu.10.2021.03.14.01.13.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 14 Mar 2021 01:13:50 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.193;
X-Originating-IP: 2.7.49.219
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay1-d.mail.gandi.net (Postfix) with ESMTPSA id 89591240006;
	Sun, 14 Mar 2021 09:13:44 +0000 (UTC)
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
Subject: [PATCH v3 3/3] riscv: Prepare ptdump for vm layout dynamic addresses
Date: Sun, 14 Mar 2021 05:10:27 -0400
Message-Id: <20210314091027.21592-4-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210314091027.21592-1-alex@ghiti.fr>
References: <20210314091027.21592-1-alex@ghiti.fr>
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.193 is neither permitted nor denied by best guess
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210314091027.21592-4-alex%40ghiti.fr.
