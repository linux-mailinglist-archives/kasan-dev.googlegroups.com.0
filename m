Return-Path: <kasan-dev+bncBC447XVYUEMRBPULWKBAMGQEULFBBYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 37D86339D44
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Mar 2021 10:28:31 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id h20sf10520387lji.21
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Mar 2021 01:28:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615627710; cv=pass;
        d=google.com; s=arc-20160816;
        b=O79unXltChp57CeYIYfkwy6sLS2liypTtuPrNKS4YQEOrqcFEOrIS8S+e4yK1OkB/w
         KmyBU+Hd4gziZjmnSEObUb1Syg4xgNId5GMfS8t+BH5d9YdJyf+GFlZbrJ0j0mUEaXNQ
         PDpUocONPfD0abqr6qvDIHw0bBbTymdUbCr0cNfI0NfwyIPT9a9Ozc0IgxA97ji7JwvO
         wZRq+jBjVba/fXc8oy2p/4J/96AdDQlbAv4HRSJ7+oZX198BwpGB8tszXIsQbcUwjO0l
         C9NwjVdnPxZEI2S9PDvkA60wyfWbv7VFiYMFlE15phX6Cq1vh5urQzEq2UnkTADsMF02
         5S+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=NsykM38Zm0xltRhA38Dlt/cYKJT/F4rpgvNQpM54Hzs=;
        b=LU99jUWCr2J8yQ7KTrKHFdC85KyjDo/uCr2M9RwAUw+tJmejmreJWiHXgM2NNFXvgp
         36f3IpNh9jHRZf1AkK7ibzs926pi8B+NsXvdXoPpFjOWHl2feTxyxtMrHi4VwLw1GyzQ
         6oSL55FsTPaL9RKEQB0QyNVxUvnfbrn4F5+TQ274VgZUB/TpohFX/sp40ADscGgS5zUu
         PE48nBQS24MK0ZE8t3bZMEj8F9ZOkb/UArT8BEwTazF9/1JGD8Tr4mS1wPo3uywQUg/T
         /1fWne2io6Psfus4bmS9jq7UAB+nRSN0RgcpIblmLITplFFMbxtBQyltGX95KWeC7vhH
         V+rg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.230 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NsykM38Zm0xltRhA38Dlt/cYKJT/F4rpgvNQpM54Hzs=;
        b=E9+02qZan7FRW1HDH6KczBwpnPVFkhTYeq/3ZoYSnFis59Q0GDuoqAQSlJOHfmhGQ1
         YGcxGKH7J2sD7f5PJl+ZEDFGvQDZsT9J7ZeSmO1Al50T+Gr2a7wfs5RTfnkr/kALQsqT
         D7fbsEjsXWZrm5TSsPkZYL9IWR1YdQNxh/e9QqE/gux9ShAZ4fwIABY/6ykrTDsN8Uaa
         aMKWeGEg+vNDOYAcQzGSpr9h+yudiWFMyvdm6uhRgOW5OlaS58G7zvKx8tMlrKWEre+H
         FJh8d5peD/3GX7UVP61lAftK22/li9AriCTufa3T6f6zsonj+6hDidElywENCkswQu5U
         hvTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NsykM38Zm0xltRhA38Dlt/cYKJT/F4rpgvNQpM54Hzs=;
        b=CrRLohXiSysuHICAIPvbE/u8CkU61RMmwGnPhwg9hILbZ4HMjoKOb1IWSIQQ6H8MC2
         hCuFnuv7hAC4YcozekjeHmvJVI9yPe4oatE1WdbaSwO8qovh+B9BpF0IN0DTfmlT3VAb
         yrYjVYY5OwSpDkUap3aNZXWpe6p6/577aQgHdnQwYU9nOTpy82N3ISHpZF4Cqi9rSlTW
         KS2PRxYRqiWI9hV4jJPOF9u4WiHEQV4/kFik4zlVEG2fstCJ8VI8/8bC9YCrBufZU3P2
         CkbOOe98+Zja5QoHKWdVdXqRIjIZsCo9DBAbeV2Byt/6oy/Oc3AILZdy2FekxCYWwiBm
         3v/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530zaN9kkLttkjitrltpG5UHJ5k22oCrrA3T2VaWcL8tdyxJ4pAM
	tjQHzOEm1IohXKN1P9Ml7xA=
X-Google-Smtp-Source: ABdhPJwtWuhIAgEBYYTFMQo0xNipiq2iWvyVS59/882uXfh+C9wOUex9Zn0fy6HxYFmGgkOp5P17XA==
X-Received: by 2002:a05:6512:230b:: with SMTP id o11mr2227747lfu.415.1615627710792;
        Sat, 13 Mar 2021 01:28:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:ac46:: with SMTP id r6ls62903lfc.2.gmail; Sat, 13 Mar
 2021 01:28:29 -0800 (PST)
X-Received: by 2002:a05:6512:1086:: with SMTP id j6mr2098891lfg.96.1615627709726;
        Sat, 13 Mar 2021 01:28:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615627709; cv=none;
        d=google.com; s=arc-20160816;
        b=i9xppQ81eBNjoE/Ho+QjVFUJm2P1BX76jeu+4wEfbZ3mbzERyGin7Rb1TtcqEsGLGc
         7nb90c6q8AYqDGwtAYwEblPbc2muSRSsF/0MlT8iKeAZjaSNJ07uGXGJGH07E+jBSkGS
         v3SDbsnkFLSSqKsFUQJ92od+opT6VvJ3T6PyuLfgyTSwJRB+i/rU7N5IaOtD06myX1OK
         k8q2xedgbmuQs3uJr8fB4tO4bU9jTv3MqxJqFPztvuj5SJr2wCN7KtXMkFGww56+w1bT
         +sFN7Vyv6WMQwQDZeRh8/A8iNWIXPVBdsxEtIdEB5lcZ0BkkAp68ilvyJF3BhtukoZj4
         XhWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=GvHEX5VJhNaodtmCmmex+400p92Ha0iQXYt+g3GclD8=;
        b=doxPotYAOo/pKngBqa5U20vG3N4vpZOsqKd7Ou6Wt4mUCMjphnmpv4NvdNYkVE1qPt
         8o5Mlvi+s5CGijsM+wzIWy00Rz86NY24uYgLd2ZHJrBdYRtQcxeXbZSztU4j0sqjqSK6
         pcs2XjtxMOLmcpHmMl8R99AxGMBQ6FEg1pRD8szNfjY8Z+VEJXIU4sWLQ9kSKFTAfIGs
         Wtgb5DbshAOj5AMMpLNtO/mORUZGv3/B4ltz/9Bcf6PECF/ANEo8QalkbMSK/HoawxTm
         XHCMAI6KtttRbgBqlS0l0NVMOUrC+hX6NNf5hSOooiLKuLrckyY35Q17cQDsKhkE7cKx
         lRcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.230 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay10.mail.gandi.net (relay10.mail.gandi.net. [217.70.178.230])
        by gmr-mx.google.com with ESMTPS id a66si279867lfd.7.2021.03.13.01.28.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 13 Mar 2021 01:28:29 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.178.230 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.178.230;
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay10.mail.gandi.net (Postfix) with ESMTPSA id 20414240003;
	Sat, 13 Mar 2021 09:28:22 +0000 (UTC)
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
Subject: [PATCH v2 3/3] riscv: Prepare ptdump for vm layout dynamic addresses
Date: Sat, 13 Mar 2021 04:25:09 -0500
Message-Id: <20210313092509.4918-4-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210313092509.4918-1-alex@ghiti.fr>
References: <20210313092509.4918-1-alex@ghiti.fr>
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.178.230 is neither permitted nor denied by best guess
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210313092509.4918-4-alex%40ghiti.fr.
