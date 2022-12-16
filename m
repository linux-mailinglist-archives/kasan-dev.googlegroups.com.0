Return-Path: <kasan-dev+bncBDXY7I6V6AMRBUVY6KOAMGQEGK4NSCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3511164EF07
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Dec 2022 17:26:59 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id u13-20020a056512128d00b004b53d7241f6sf1222891lfs.4
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Dec 2022 08:26:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671208018; cv=pass;
        d=google.com; s=arc-20160816;
        b=w6Ggfey4WWXe7+3n9Jl9E6WZ847ezJdRyj3pmPYDs5ICzl8gCPAXsSP76n4KyIQTMh
         UP1gO8TSM2WTk2JTLc1RR3su3UwCS7yl5cOFQ79r1tcu7jqiTSgxJYmRXNWSIOHROXeE
         NJ/LIlwy8GoyAyWj4SopLSP7fGtpID0NJPSBMlTL0G688FLnvUNAScgZrFUIrj9uV7ek
         i+ATed+9dz1NpIaR6rB1GI7O9Q3lwKDUNlD+3W6uRUfDOA9rzQdIoaU/wZlZFo6au47f
         zdlPUxk7wYBCUhB9uFmXvC+Ly87xmxhAJkyVwmOrjmw7KsNy1LknM7+ztk36mxKrDj8Z
         YGGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vF4lCaZKH97fCkMjsg1NPhqZysz+m4Lxprarl7AvYjw=;
        b=wB7Z7hDtoy8UGprxowNjdxqbs1TDmgwS104tnIGoHWm7OAjh9SrpCjZ8SJk8aojTvv
         Qddqck+d8lI17M935KbcAYIm/DciSEJoH6w1zkCweKkSAe+CliqzF2bgSUcm6nzNVx5k
         Oeo5TSuZSxrYbmvaDfHTYqQa3DUFiXHccxMJN9+7NBMNpy8xNGugv1skMs+QN9xSqW+w
         ZkB7XCNF10osn5iyQXXJ0OjIGFh5OsMv72plX4stom3Zn+jatckzEOjTb6sEDFEKBsCI
         iWu33U8u9Af0FWphjm2NjQ9CJTKDobkbOLXtRJZPg+ej6/I3cyE7dxM5UK0GBBVgCKqZ
         VPAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=Rvbra2pe;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vF4lCaZKH97fCkMjsg1NPhqZysz+m4Lxprarl7AvYjw=;
        b=AQMhPkbnryXIi3ViLBjul6rYLZ6L2x8obIxyd5BW0NVgH9+844pUtmmjunBxD1H0d1
         ZtxsUFdaYnzpC6te1BmuGOU/+VQ7sIgOGEQvk4Ee13NXOCtvztxiU5GiIPh2xaNaPrnS
         pCw9Z558uCFMxC5i6R91RCcAEvhe1aQyXHgdB8tHa54NyBxe5V1fV6Dc+YNd2fqFH3A2
         ytIpD7ed8SbEK/AkH0qfHNHrFV1yddwwg5IHAjnxEJeURyUHq2tAufY8wEa+qPQHy8WR
         XRzA83eE1VPUQ9z7x9UcRJJUYMlRSN7lS6Pu1DuQ+UL4bViDP0blkROBeSj0wcOvQgtz
         i4lA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vF4lCaZKH97fCkMjsg1NPhqZysz+m4Lxprarl7AvYjw=;
        b=c7QqN/jEgZjh/y6c9gY6epr0AGAB+iedJoE7u0QDmeYS3omSQ6WqHWTKJE3GXBxnt/
         BVSPjvzzZ/KYWFYo8Fsh1Wn2pmjdQaHdxbNFyY4gmp05t7SCppsT+0Sr9N0YNYb4vqJ3
         F27f0KQl9qDW4128GpTYP/GWTtWl/kLgsb1+VG9SkNH4IPLRKBb5Ryh+zcsgbtZ1ZPW6
         6GNmDfO8MT8Hbemsd4s+DtHnI3Zsgax8ghcGMT63Nv6dHUuBU+pFGdfFkp8GqeBfH2PP
         w4Xkk0y0l5IAY2K5MAbRLKvwF8WYwjw499/hNHj/sDuVCc0DVFmCr4tY6FPR0rAfb1le
         nvmg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pkSp8bsjXnKDMCs2R1EwgP8HeqpKpuAeoD4ntBOqxU+Bv3yzqmI
	kNX2RfmYP4IMt/jAq4Cme34=
X-Google-Smtp-Source: AA0mqf7qdWopvQ+lwLGksa+Tr8sO6GH7fX5ofTHcGsjpW9wB4vJhINdzvEORQKv2EeTvUOcGHqbzRw==
X-Received: by 2002:a19:5f0a:0:b0:498:f195:5113 with SMTP id t10-20020a195f0a000000b00498f1955113mr32131464lfb.159.1671208018379;
        Fri, 16 Dec 2022 08:26:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:34c1:b0:48b:2227:7787 with SMTP id
 w1-20020a05651234c100b0048b22277787ls467731lfr.3.-pod-prod-gmail; Fri, 16 Dec
 2022 08:26:57 -0800 (PST)
X-Received: by 2002:ac2:5ca3:0:b0:4b5:5b36:28b8 with SMTP id e3-20020ac25ca3000000b004b55b3628b8mr10141096lfq.1.1671208017338;
        Fri, 16 Dec 2022 08:26:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671208017; cv=none;
        d=google.com; s=arc-20160816;
        b=ljMgB628y9Xvr6NAbR5SbwvBb4fwRe3Q33Yw6FebixwAvH8idWznMb8BqKNdvYf43X
         VWd4sDOTM8C/DCnclHZ3SLUgsiH+N7Wv8k1Jeco4jNReezP3vGE9Rxh1i5/ARZwBT5vL
         AuHvJM+tl3Sh8HDNxbRRPP4pw8ieAYPq0Zr3QwbwmcFrW1Jz2u5A/9lk6dMDGXX3uA8R
         jvlpYq58aYkBQHcIqTti3S8Bb5QjbT5VGzglS8jWQw4sYgGAhAaBPawEiKDxZFw/H39h
         B/cI3zrSyE7evNOfGThXy3f131+DS9xwvz98SEAwmtGC32465L8R809S0VMGQk1uLB8E
         LwRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7CyWdPwmsoEln1rCKIxbXcZ7tw/K7pVLqcNgYwRXhLM=;
        b=JCQyh4ulqhqm27W8KuHZ1vW8mnubtrstQJnWdZ5dApSMAodJSVUKGKlZnQsd54t3tV
         lf+0h0w+2Znp9pa54Ck9XxRfTRDmHN3MSmxYIun8x8UpJGP/6R+cBLvV2pOya0qTdswB
         XCdpzfLVFhOgQDmUlqYemQRiCNfJqhJPFpzRHIkwGWaDPLgpA6oMBHLT9FqTjntZXiMx
         A2mHIkQI1MzgZnHpKM3CT+lIvkNUrHH9kMYETmG1IADBfwJp84CJL5CAO46iAjuBM7wi
         WhERZ09CCi0iugP3YAA5WD1zQRv6ZEOi+jSqjTe/4dy29/DcEQ++8J5Xgw+/QUHBpfXS
         VmWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=Rvbra2pe;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id s7-20020a056512314700b004abdb5d1128si129374lfi.2.2022.12.16.08.26.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Dec 2022 08:26:57 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id y16so3051601wrm.2
        for <kasan-dev@googlegroups.com>; Fri, 16 Dec 2022 08:26:57 -0800 (PST)
X-Received: by 2002:adf:f9c7:0:b0:242:4c28:c9a9 with SMTP id w7-20020adff9c7000000b002424c28c9a9mr19141287wrr.46.1671208016801;
        Fri, 16 Dec 2022 08:26:56 -0800 (PST)
Received: from alex-rivos.home (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id z7-20020a5d4407000000b0024245e543absm2554603wrq.88.2022.12.16.08.26.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Dec 2022 08:26:56 -0800 (PST)
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
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH 5/6] riscv: Fix ptdump when KASAN is enabled
Date: Fri, 16 Dec 2022 17:21:40 +0100
Message-Id: <20221216162141.1701255-6-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20221216162141.1701255-1-alexghiti@rivosinc.com>
References: <20221216162141.1701255-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=Rvbra2pe;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221216162141.1701255-6-alexghiti%40rivosinc.com.
