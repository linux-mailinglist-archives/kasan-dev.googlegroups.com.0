Return-Path: <kasan-dev+bncBC447XVYUEMRBEWPZSBQMGQEQCL2OAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id DDD4F35B629
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Apr 2021 18:45:06 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id a6sf4924744wro.15
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Apr 2021 09:45:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618159506; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZeHkg8pXnjGbSjEzUFgvtBoJ1QWMsI76PbGfCBpOLREIO6XN5vFNgU6w5BKXUz0SFy
         cjTaSWzC4Q238ysO4++sIvBnt6tlM/rShif0WGt0Hj3oeF6kj86hWWERLL7DjysiNyIu
         l0s0Eb5w4+hkS4m5NwwBeX8EqFurWGrGb5qE0dc6DcA5PJfcXzPAIW7h6Xxgk5sjPH5y
         aqU23K6c5C/Vgq2fnprXg5iiqsLtbyeQt2F3g+PqVL+75s1ADYfK6qRVxXKCoMFknlXa
         ePx6FcCZ93VgGYbsQaPOCu81IH6yQHPvOAEpkyhoBeT/H4LUxJ4E6MRNntynPaqvuNb/
         Lojg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rC9IU3w95bx7aZ3KU/j2EMuPR4PalmiJKPEGWiKxcbs=;
        b=q0LDC0mBIBJzEd+uqn4RMoQDfBOcgz+xrSNgxrWcJ6JWhWRljSf7HyCZX9qkqgTGlm
         87EEGABACo8+3fBVQ3kNsuFMz10xCB+MKQHxelb1W1FX12qJ5ev/MCpSxlT6LpbZd4Qa
         B+tx8+mNOZPygEf8sOwRZqcX9ZJJsfLxzcY5qgFJb0EO1/MqDegj0GOSYQd4GRIBz2vJ
         1r8pxoZ685Rwfht9hO0jZGvbEpOaYdzb82ruvquDNvzMRcHMYZNKraBx1e8Sd2BLcQtI
         VaQmiGeNfBfAUMt+AL5eCxr8niLm/cKL11n0wJ/bOM96o+woFGquaO8Ke81AVZNslhHw
         XCuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.231 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rC9IU3w95bx7aZ3KU/j2EMuPR4PalmiJKPEGWiKxcbs=;
        b=CLDuzPousz4jJEGvoiVGuJVu8GONyy7o7UYBpVRy70sq+l5sfyCOQIqaljxGMYmvlD
         ooFa6I1noYAejDE9IFSvW3ZX4B4hOSXo75OJpNyzp8WGLcvlR17tNHyd6chKvJZR57pJ
         K7YA0A87XJFhpqrcVtsL1/+ldrOoR0w0A9LeFw8xo2NUAall41O5DhHxdOH1Wnd83Yam
         vJzAEnoMjmSa5/KjbWQ9+kLNOwD7EvI7aCa40lHLFF2ioCwFhbTEOJoMbqQLxHhePA1E
         YjGkDjqBiZdMQT7zlYrHecm9NEihRUQPVo3PnV8G4A1VCvA3TbAuniH3z3FhcUfLS9ET
         tiAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rC9IU3w95bx7aZ3KU/j2EMuPR4PalmiJKPEGWiKxcbs=;
        b=onr/vsqIzhjUD1QZCjk+ibb8HRSg5G5HaAlascerYwoSFN3cSxTQMHtzHl0ijSMc1k
         GWcJD0N2YyEL9Q5vjO74YEoWlM/vCAuRLoqoT8bsI7eaaTIDD57BCyF9LZ4hJJePHTfH
         +VSXnbZJACUZaNT8qjGUk+QFTsaxcvzt92i0VWS0n4xxN1GtkEw5rWvZ3GX6fjhbgGPf
         b9VQyDFVMrEfPY3lkUh/PSfAq2bop7zkcSOlgqGSxBYIdgTfs5mtkbsaJHzSEiqCWozc
         EKrVj7LgVudSnJlEk0Zjkgjt7hphj5Hy62HKkDvUCJM60vQQUQBHzKo77hZ5vupFyRBQ
         rW9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531b0x6+kTaCitFo1CqM/u2bcB8B5PspbqB0oRH/c6aEJzxk9Ta8
	yb/6wbIIxw6/x32I9RcFGGc=
X-Google-Smtp-Source: ABdhPJwiv50VHg0ZlK+4/QsSSPYNQxBIiuFIhQSug00cU3p0xO/3FbKxenocAktlbyuBkfSa7qshow==
X-Received: by 2002:a5d:5609:: with SMTP id l9mr27195650wrv.190.1618159506615;
        Sun, 11 Apr 2021 09:45:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:9a6:: with SMTP id w38ls1559990wmp.2.gmail; Sun, 11
 Apr 2021 09:45:05 -0700 (PDT)
X-Received: by 2002:a1c:7e45:: with SMTP id z66mr22750733wmc.126.1618159505857;
        Sun, 11 Apr 2021 09:45:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618159505; cv=none;
        d=google.com; s=arc-20160816;
        b=ShgiQEKJ+a0YhMDg/Slr1FYzbMg3R5+D2pKZXCcxQLYGisW8XnQX2ELRXjD5v2R2ra
         ZJDHzqTexsq4Xvgc1EPnSrm6jtJqRwl2EsqmFNMdWtORPQzVQxtYEdK6sHu+1UBNf60a
         2c5VK0ACEdOuYTOdMWlD0vkqL/ppOXsNHw6OmFw55hJwnyw6QcTrD15vDrXyXPMzI91N
         sgfxTJEc3CmgdAEzBHgeuW3fSBwlZqurGiD13x345TB1KhhR5x1Z/MLbYfgxlnnzNsZB
         IOYd+rcONQi4hXfirOwvz65BJqmXJKs0ffW3cLO6N3ar99H1O8geQQMUHC1n1ZTq1zw9
         L3hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=SPxB88xAvzBOgb85DqnMbdC5D3pf52ZTNxFcXGYoVbk=;
        b=NXY2R9fA+ZXzhgXyhx55UpThMOCygCnDZTaLSwevz9FmkXNdP141GCKas5V2vreym6
         Nz0F6BtsFXWw0UPy6J7v3trfyOk5D/6WpA3eQGnmeeDOv7DD0fEtoBfQoMXco/HtwDGA
         3b+efvdtkFWnBOpQWi6Qe8ducelo38ONwDvLP5zlp5uIbWdK9+5vGSOZT4Jo8KKDw+tQ
         ncgrrXiVR/GPKBDBrTuCAkz0wfwZWPzkEGMwAyrP9qEXTcOEzZL4g8JleNpdO50CPGMN
         mzDquFP/SDt5ENnaij9vhdI7PztF+kTwyxZxeAB64Bf+ZpmCt9bIntfLLA9UOoKZntI0
         vuBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.231 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay11.mail.gandi.net (relay11.mail.gandi.net. [217.70.178.231])
        by gmr-mx.google.com with ESMTPS id x16si95547wmi.1.2021.04.11.09.45.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 11 Apr 2021 09:45:05 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.178.231 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.178.231;
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay11.mail.gandi.net (Postfix) with ESMTPSA id A5A4D100007;
	Sun, 11 Apr 2021 16:45:01 +0000 (UTC)
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
Subject: [PATCH v5 3/3] riscv: Prepare ptdump for vm layout dynamic addresses
Date: Sun, 11 Apr 2021 12:41:46 -0400
Message-Id: <20210411164146.20232-4-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210411164146.20232-1-alex@ghiti.fr>
References: <20210411164146.20232-1-alex@ghiti.fr>
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.178.231 is neither permitted nor denied by best guess
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
 arch/riscv/mm/ptdump.c | 73 +++++++++++++++++++++++++++++++++++-------
 1 file changed, 61 insertions(+), 12 deletions(-)

diff --git a/arch/riscv/mm/ptdump.c b/arch/riscv/mm/ptdump.c
index ace74dec7492..0aba4421115c 100644
--- a/arch/riscv/mm/ptdump.c
+++ b/arch/riscv/mm/ptdump.c
@@ -58,29 +58,56 @@ struct ptd_mm_info {
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
+#ifdef CONFIG_64BIT
+	MODULES_MAPPING_NR,
+#endif
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
+#endif
+	{0, "vmalloc() area"},
+	{0, "vmalloc() end"},
+	{0, "Linear mapping"},
+#ifdef CONFIG_64BIT
+	{0, "Modules mapping"},
 #endif
-	{VMALLOC_START,		"vmalloc() area"},
-	{VMALLOC_END,		"vmalloc() end"},
-	{PAGE_OFFSET,		"Linear mapping"},
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
 
@@ -335,6 +362,28 @@ static int ptdump_init(void)
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
+#ifdef CONFIG_64BIT
+	address_markers[MODULES_MAPPING_NR].start_address = MODULES_VADDR;
+#endif
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210411164146.20232-4-alex%40ghiti.fr.
