Return-Path: <kasan-dev+bncBDXY7I6V6AMRBQOQYOPAMGQEIGLCIHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BF5467ABAC
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 09:28:50 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id r20-20020a2e8e34000000b002838fc9f1fesf3833555ljk.9
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 00:28:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674635329; cv=pass;
        d=google.com; s=arc-20160816;
        b=oVSEg3FRL9d+AARz67IBsRidML8+jFO37oTOU1A6zoBIqvSorb8/MFhThq+u/4tGv/
         0SKKFHf7ROlhGix+y5xBhtzjqEDC3/ECcE6WRi9g+9nU3cR/Om/O5PN8TK+JjNCxmWdp
         pHlO0+ckqZRzXQyfQhuXz2DUQqcQUqq43ujM6DDjARr9yJCFVkRBneZmEfeSyGdTlLNi
         oLKOrdhtNWCRZVgwzcMXsfgz9fHunrhum5Xokceg1YSP71/W+CyhGroyAQYJCAwhhUf5
         HoiyY0i0jM+Vd2PQmsfmsMJAnLQvYALYcTaweqy9gdNcFWniI6YJo078hhkTumhGWwnN
         IqqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SR4kicKIsXSs0twmm+Cx0zxe7pRZRWxFvMTprVnjOGw=;
        b=vWM6ImlljAMNaEpnQEWRy5K3B1bjfgCgsARj9mybNIzJI85J7NxUKTXzdsekC2DH99
         13cUyW3Ry0L6jM3Feuq24epQ+scxATtJsAZycZkJDfDT5B5KdQp2NWSAvAarwhrjbxVJ
         iwwB+jMNNtrMTl934Z6pRtblL4UyGcomAhN20dx1kpLYbL5jjWPt6ZTZa0n0QOTl2Bq8
         cSdrPObGcfJo7wT4WKuDnB3nHKh6m/bHxz7BtjQHqr8ofUy6kwBfmV5lF0i1/fxzFgob
         iEwFkCH8cRCKMMsrlo3h069vsPD26Sf/avLOBZXV7rePd1dVAcGphgJHqpV7av8RgBrM
         Dxnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=OisDsC+E;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SR4kicKIsXSs0twmm+Cx0zxe7pRZRWxFvMTprVnjOGw=;
        b=nMgjRUORwHCY+3QuiXeLXRudPdKI6cQZz5/AcWIgbLZK9NGv1J7z2uao92SFwcWEjw
         g4uQOmwkXV0Ta1xn3SYJkebptse2aS0IOJ+qt2BRWl/5vPtnB/1MPZK7Hycgq7gGsQsm
         dyDAY6K86LaWHDwdHoVHTLBwiJOSr6Xqffv6rcvW9idJWLLbsd77vM9mWeZ+bp1DYqSp
         7wR8yrN6pHCuTQetYEw7ckAYQxMHq69j//qT3hGl4dM/7ORyU7GtxZofWXyb54GhaWcJ
         DoInQxGTsCPvgYXHGC/BOEUVQxKnBLIpIBMx89YnjXNDm2Bxvi2FTJdld6yWxEYFqWKA
         B4ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SR4kicKIsXSs0twmm+Cx0zxe7pRZRWxFvMTprVnjOGw=;
        b=WnpnR8FjCkvgGMHACIMZ+GmPR+hp4NiwSFkZj3mdgTdB2pH2v4wpPPjm2MD26L2evv
         2u3+2VZvVI5V6zGEuIffg4jpdW7iDhi42ucOZRJfcLK0axDyo7Cd7L+yUAee+dGOcglQ
         LXTSiqFy798smEXjBpolmS2gkTple19huAbk0QCV8HvifXADIxfaR+slwWTUGka0c2y1
         CvgQErDN8fdVQbbV37EHkOM8IugYgYv8SXKBEAs8Yc6HCR9JMM1tYRP6aptKzYvGKa9q
         qT6EmK8KrqGT12P46JPlVh/XoQH0fGh3CgFTYNx4N0z+zzQsYsUcpOLfCEToVzLE0ZJv
         Gsig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqRsP+BZJH9Ik9w3ugiGzHB1NHE2k6VFF/7xXGPc2mjEImf24hM
	TYfrAjJVlbvapRzC15Uz69Q=
X-Google-Smtp-Source: AMrXdXu4OWYPQhMq66ywNV/sSOMpQ0ETcYOSkj3Sdra1fDtdvV6w4YM+69AZwwB6Jvq9+58Hj3DspA==
X-Received: by 2002:a05:651c:544:b0:280:4ef:3cde with SMTP id q4-20020a05651c054400b0028004ef3cdemr2781336ljp.78.1674635329636;
        Wed, 25 Jan 2023 00:28:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:368e:b0:4cf:ff9f:bbfd with SMTP id
 d14-20020a056512368e00b004cfff9fbbfdls8941157lfs.1.-pod-prod-gmail; Wed, 25
 Jan 2023 00:28:48 -0800 (PST)
X-Received: by 2002:a05:6512:3ba8:b0:4d5:8bf9:92ef with SMTP id g40-20020a0565123ba800b004d58bf992efmr10546832lfv.60.1674635328522;
        Wed, 25 Jan 2023 00:28:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674635328; cv=none;
        d=google.com; s=arc-20160816;
        b=Fy8+ABrCTNCATWp9SBIOGO8MifrspaBn3KFtm5ytZgdJ/Et3wd2G2GJRW5bQtgM5hT
         cLeGLUpMdJg5z+KsggS1tsXJ8VqU9ZktI1+F2JpHZ59fX1q4U9NePYlxzNI2wlc7Nhhk
         eB42KXslve1F/7q6ny4zFHMwpyHFD1BVKhEM1P8rm7eejAHwB2xTV460+cMIazUcG6fV
         w2fXq5kIrNHbxH5FJwlMVEYmCeax2KQof8BLAbHXqkrw0wqtLuXgZsbzWO8//RGImL3m
         l2RfC+tYtYzsZ5x91Tn5XbeARgweQkT6UmhJ2COlNJw5iZN+WQRevQCwRjeO4qyo6yVX
         dq4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7CyWdPwmsoEln1rCKIxbXcZ7tw/K7pVLqcNgYwRXhLM=;
        b=S+uJAmcv0BVJwZ6MOdJf8KyBSZsP5yAGhgu7osmABO7X91MmvvLBMPiUobhKYhCJNi
         MkuNWksnA4MlwXRrUGDOut6nbd+e/ANjxfZviY8TERp78cwJ2TvLiMz51wLSgT3Dy27l
         6mTTz6V/G9PlEczojCrtWNfwjdmeM8p1ctm2h5EJacvBYmJO4A7V6FH6Qndb7JEUqNk7
         NZj6PhWF+vmKtoJgugMiiNmNvfAOhtiEUierZlatKiUlMV5PaYlVu/l4W58cWWSpHbpn
         1PAJZLouE+4gOOsazoczVTAr23bTTWFp3EfdOuaBzS/iZbp9xpnc65VJZ7pJSRZLZnV4
         n+yQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=OisDsC+E;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id f20-20020a0565123b1400b004d09f629f63si218929lfv.8.2023.01.25.00.28.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 00:28:48 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id f12-20020a7bc8cc000000b003daf6b2f9b9so674577wml.3
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 00:28:48 -0800 (PST)
X-Received: by 2002:a05:600c:43d3:b0:3da:fbcd:cdd2 with SMTP id f19-20020a05600c43d300b003dafbcdcdd2mr31194035wmn.9.1674635328028;
        Wed, 25 Jan 2023 00:28:48 -0800 (PST)
Received: from alex-rivos.home (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id d11-20020a05600c3acb00b003db30be4a54sm1080541wms.38.2023.01.25.00.28.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jan 2023 00:28:47 -0800 (PST)
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
Subject: [PATCH v3 5/6] riscv: Fix ptdump when KASAN is enabled
Date: Wed, 25 Jan 2023 09:23:32 +0100
Message-Id: <20230125082333.1577572-6-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20230125082333.1577572-1-alexghiti@rivosinc.com>
References: <20230125082333.1577572-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=OisDsC+E;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230125082333.1577572-6-alexghiti%40rivosinc.com.
