Return-Path: <kasan-dev+bncBDXY7I6V6AMRB5X46KPAMGQE4YJ7EYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 607A4689159
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Feb 2023 08:57:43 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id n6-20020a0565120ac600b004d5a68b0f94sf1914396lfu.14
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Feb 2023 23:57:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675411062; cv=pass;
        d=google.com; s=arc-20160816;
        b=U01ltoxRnOawnDdIwCee2LcaMVmd+b4LzZpOma1jwIs/LIJE01eNcSLABBK+d6xgDT
         ZEDtdKHiGbYSaqhcLx9RSnJecEsxwnhYdAZcslAIUvU1TOjHfyHH2N7t7zLwi1nLZCtT
         Tme2FaizScrcOO3Rd1Q/PEbzHzP+PDcZIRnaTf5jBbFiHSMFLKzQJbkgEJsyVN/BeIAB
         5xfojToA79ITH3C5gWlDdVHW5PRfrde4PhtXu97i1Ye31bFnQOtBhP0hOMnTQmdqWrkw
         CRudQCqv6gyeFQeT+SkpmnK6azk7cwNnDagXTZvU9+o+7GacsQm2B1Aiy0E7quUr6jDo
         wl8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=zy2nj/pXdUxKc8gdtJsEaE1Vz7Fu8CMdu/oWRFwEyCw=;
        b=kJolBjWnSyJZvn6sLMrn5h3eojOGs1eaeaobiyWWqc/EW+hNwTU4y0oI9kio7NM2YS
         9TF9ePF1Y+gHoNOQlzASUU27OWcPbt5BhI2kjCR1F3cJAJZMaZakl8xSY3a9lo9O3mkA
         NHIeurq9qMax+MUfueYBaZKLqO0PVbc/OsSM7qAD0h6+zesb7NPlL81xQpMq7w8z+5wO
         SO4bItKJAVwriol4vb4k9QjRMNq2G00d6GV2MBnFYyblBvaNZSp5aRV1vIaB5mPeN1ld
         pRmbqWR/pz/IU4f6CMpxe561gZGycd20ktIsbOXpW6rzTjsueZj0kYFyzT78oVxwx61A
         o0JQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=qeEtJh7X;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zy2nj/pXdUxKc8gdtJsEaE1Vz7Fu8CMdu/oWRFwEyCw=;
        b=MyM0M1ZYc51bjpNZs+TbGT1wzbeNpTS2Qb484pbp2onDEsIpJisUki7TvlOCSaNNPO
         SV50MC5aNyR5NJrEJjthgBoMy1WM8FDMQXz6q2cU9+H93UUXL7KLj18hHePGb2zxzudV
         edxzeLJy8Ffk4IQ7tpiUwxAZCi+Q8//HjmdxWPxmaQHB1B9xwKRaokV28VPlttluGcrp
         TeJdXzjp8FQRarhkzdzoPWe5rr8HnAWbbbDIiWW8S1TbxITmweV+2tQN4MciSM3fbhen
         QdfzqJTJ2fJkA6w34Rt42rzZ+wsLkbg4i3aYDwc+STlFDKqECryzh28X/bN+b2oxCANr
         X13w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zy2nj/pXdUxKc8gdtJsEaE1Vz7Fu8CMdu/oWRFwEyCw=;
        b=eiZLLRzQtgJfhSLfGG5+0hj7CnIkLm+U5+wZcr1yZzpW0uGBD2jiNOW0NOsHaVmKen
         Skcn1VQ6UQV0jJmUespjWntGRhbyCQPx+MUs8cGdbpPL58/zIHsWtEt6/llodfBpH9an
         67YCm08hsnkA2bgRbHiWCRmpp1i2YkxzxLSNVqKXUE9k31hy66CDVT770wfZVsWXilfm
         psV/CLf8hHbDGCRHDqWaoCWmdhEfcpFGEsES3VbVWgvEotIL2sa3Vbc9b6bJZ63fhTLq
         J8029WTS05GYJGhAMlpP3wxicJClK0aKLLUusZwKcM7I/uNTUfPRi101bls31uErSGlS
         /5gQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWnBIbZCQwuvm7+XNk+vBifuJdTIbJm7EPBW13LBpnaxUb5g5/N
	cPySXfgJFCMaAP20jYJ0+VY=
X-Google-Smtp-Source: AK7set+rMlavR4LT+Dbz80opwlni5T0nwMGJW/SmNmTzG8WNam/MQ9ZWgmFYTdc/kVbrnQj18zOwmw==
X-Received: by 2002:ac2:4bd5:0:b0:4cc:84da:1ef6 with SMTP id o21-20020ac24bd5000000b004cc84da1ef6mr1507269lfq.262.1675411062386;
        Thu, 02 Feb 2023 23:57:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:4006:b0:4cf:ff9f:bbfd with SMTP id
 br6-20020a056512400600b004cfff9fbbfdls3023549lfb.1.-pod-prod-gmail; Thu, 02
 Feb 2023 23:57:41 -0800 (PST)
X-Received: by 2002:a05:6512:208:b0:4b9:f5e5:8fbd with SMTP id a8-20020a056512020800b004b9f5e58fbdmr2205950lfo.52.1675411061041;
        Thu, 02 Feb 2023 23:57:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675411061; cv=none;
        d=google.com; s=arc-20160816;
        b=rNq8FZP8Ju/+wQQ2Z3AePC9CiKG6xQGUn6c2O/HJCoSATwDHaNhwP0vQ7APy0jgcXt
         rNBjUu31Ls3WMqnnkEoVLv1SDDJmxxMglrSjekkoOp0PdLC06aQDSHmHvEic/h5EsLz3
         8COKRjhMRtb20HDqme6sUdgil5d5T4CPylQO7EN9REp0qn0Fei49Vssgmbsb3YrpWJtK
         rzVufm9xty9H5L7yKZfxtkz6Z9Rq5dyuA1W3b3xzXq+P00DeVDIaK7dleuQGOylFpSV2
         y882YqqLifp+uHwauozdWJsR/Qzg/DnwCLUE4yQEwkY21nZJdLaeZdlQWFYsNZEmLcfb
         6d6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7CyWdPwmsoEln1rCKIxbXcZ7tw/K7pVLqcNgYwRXhLM=;
        b=kNggUADFpNKZQwPxEORUB6wcXBfuH8vt7QNhLyKQyL4oc+jasN0sSYzx0FmfunyYBH
         3xF5Zia+CdrLiLBaSrw5BUHnHecDfTlnqvBPLBXRQqlOTOszrLa+bkZtpVVzOoz1EIBX
         IaL0aU2I1XoYbx/Zu55InJH5IqxNvYUmVlhSypz38JNwZVy7VjadOE+YXmv1eXVQtMVO
         emcEQ8PKJd83oLPi5shIbXTAr307xUvaTvqPmOMY1yLvYJhClNnrrGEfD9vftrtFMAFE
         5ywI62fpusHCF3e1UF0tpGIYmyUKf+Vm5pYLYEOlp/YlIaugffnmShb4KnZXpO7XhWc6
         N8Bw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=qeEtJh7X;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id x23-20020ac24897000000b004d5786b729esi98882lfc.9.2023.02.02.23.57.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Feb 2023 23:57:41 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id u10so151264wmj.3
        for <kasan-dev@googlegroups.com>; Thu, 02 Feb 2023 23:57:41 -0800 (PST)
X-Received: by 2002:a05:600c:3b1e:b0:3db:1200:996e with SMTP id m30-20020a05600c3b1e00b003db1200996emr8797906wms.16.1675411060803;
        Thu, 02 Feb 2023 23:57:40 -0800 (PST)
Received: from alex-rivos.home (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id g10-20020a05600c310a00b003de77597f16sm1972622wmo.21.2023.02.02.23.57.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 02 Feb 2023 23:57:40 -0800 (PST)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Conor Dooley <conor@kernel.org>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH v4 5/6] riscv: Fix ptdump when KASAN is enabled
Date: Fri,  3 Feb 2023 08:52:31 +0100
Message-Id: <20230203075232.274282-6-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20230203075232.274282-1-alexghiti@rivosinc.com>
References: <20230203075232.274282-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=qeEtJh7X;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

The KASAN shadow region was moved next to the kernel mapping but the
ptdump code was not updated and it appears to break the dump of the kernel
page table, so fix this by moving the KASAN shadow region in ptdump.

Fixes: f7ae02333d13 ("riscv: Move KASAN mapping next to the kernel mapping")
Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/mm/ptdump.c | 24 ++++++++++++------------
 1 file changed, 12 insertions(+), 12 deletions(-)

diff --git a/arch/riscv/mm/ptdump.c b/arch/riscv/mm/ptdump.c
index 830e7de65e3a..20a9f991a6d7 100644
--- a/arch/riscv/mm/ptdump.c
+++ b/arch/riscv/mm/ptdump.c
@@ -59,10 +59,6 @@ struct ptd_mm_info {
 };
 
 enum address_markers_idx {
-#ifdef CONFIG_KASAN
-	KASAN_SHADOW_START_NR,
-	KASAN_SHADOW_END_NR,
-#endif
 	FIXMAP_START_NR,
 	FIXMAP_END_NR,
 	PCI_IO_START_NR,
@@ -74,6 +70,10 @@ enum address_markers_idx {
 	VMALLOC_START_NR,
 	VMALLOC_END_NR,
 	PAGE_OFFSET_NR,
+#ifdef CONFIG_KASAN
+	KASAN_SHADOW_START_NR,
+	KASAN_SHADOW_END_NR,
+#endif
 #ifdef CONFIG_64BIT
 	MODULES_MAPPING_NR,
 	KERNEL_MAPPING_NR,
@@ -82,10 +82,6 @@ enum address_markers_idx {
 };
 
 static struct addr_marker address_markers[] = {
-#ifdef CONFIG_KASAN
-	{0, "Kasan shadow start"},
-	{0, "Kasan shadow end"},
-#endif
 	{0, "Fixmap start"},
 	{0, "Fixmap end"},
 	{0, "PCI I/O start"},
@@ -97,6 +93,10 @@ static struct addr_marker address_markers[] = {
 	{0, "vmalloc() area"},
 	{0, "vmalloc() end"},
 	{0, "Linear mapping"},
+#ifdef CONFIG_KASAN
+	{0, "Kasan shadow start"},
+	{0, "Kasan shadow end"},
+#endif
 #ifdef CONFIG_64BIT
 	{0, "Modules/BPF mapping"},
 	{0, "Kernel mapping"},
@@ -362,10 +362,6 @@ static int __init ptdump_init(void)
 {
 	unsigned int i, j;
 
-#ifdef CONFIG_KASAN
-	address_markers[KASAN_SHADOW_START_NR].start_address = KASAN_SHADOW_START;
-	address_markers[KASAN_SHADOW_END_NR].start_address = KASAN_SHADOW_END;
-#endif
 	address_markers[FIXMAP_START_NR].start_address = FIXADDR_START;
 	address_markers[FIXMAP_END_NR].start_address = FIXADDR_TOP;
 	address_markers[PCI_IO_START_NR].start_address = PCI_IO_START;
@@ -377,6 +373,10 @@ static int __init ptdump_init(void)
 	address_markers[VMALLOC_START_NR].start_address = VMALLOC_START;
 	address_markers[VMALLOC_END_NR].start_address = VMALLOC_END;
 	address_markers[PAGE_OFFSET_NR].start_address = PAGE_OFFSET;
+#ifdef CONFIG_KASAN
+	address_markers[KASAN_SHADOW_START_NR].start_address = KASAN_SHADOW_START;
+	address_markers[KASAN_SHADOW_END_NR].start_address = KASAN_SHADOW_END;
+#endif
 #ifdef CONFIG_64BIT
 	address_markers[MODULES_MAPPING_NR].start_address = MODULES_VADDR;
 	address_markers[KERNEL_MAPPING_NR].start_address = kernel_map.virt_addr;
-- 
2.37.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230203075232.274282-6-alexghiti%40rivosinc.com.
