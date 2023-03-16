Return-Path: <kasan-dev+bncBDVL3PXJZILBBZVQZOQAMGQESPPHHFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A01F6BC9CB
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 09:50:48 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id i6-20020a170902c94600b0019d16e4ac0bsf643209pla.5
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 01:50:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678956646; cv=pass;
        d=google.com; s=arc-20160816;
        b=dAzoCvsopCjxe5fpjuurqedRVeOm3ruDEoNwL8gF3Zkj2wIYQDQ43wH2ESMKQiSxVG
         6oWAE0nBJs+YMgh4xdot3A4aQx16JWKVLPD5FcH0AhwaWmImOAtvicfsPAE8i2zdQv9f
         tnqqqhaC3VESuKbmhscW9MH0gxFtlxe+hrtbuNGa8k1LHXushKr1R2ly7aW8d+HuiZXy
         xNw2ADq0E5gaWeThKDTbMkwS547beY5ebaIKp1cWAhLh7y+y9TQWB3Bfbk9gDOfzdGSE
         mVPEXZRwXCZ6ifx+FWdJ5sx4lpZgKh4W/hMTKkwxsnIBjIzNGrPkyJW7cc1LmsNq4ZH9
         m7uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=51/nTYkosNBqLROCNsVRN91VZz41gTjCoyE1Rg/9T4g=;
        b=BjQsVAT8Z8W91PTRVRWAiRayw0E2mH8KhJigoXhQHCwOD+YczXARPGmLbzam04VSZR
         trOhe+/qDbDrRdOx9Hra0MyMUKB7nLD6EQl+HvYRhLnetJIQzST1X2lb6Cu9PgJkWHYi
         Kc20YCUCP0Ip9yDmkPFgv/rRIEHGJiJRL1//lvtQbLBax8g4g1oEym0eQV+NsO+O5Sis
         hzD7U7rGl8NZLVRN2TqCEn4YuDj/5LDLev+TEteA0M8CbSmiRdKzYeyERvy9FfBr2wJQ
         x0peIO73JxnABK2gaGCdUjQuVcHLBlOdazqM2M7ZiqWgUcY/GYl5+J2YA0lQejM5TZNy
         Vclg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=NSFDRT5F;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678956646;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=51/nTYkosNBqLROCNsVRN91VZz41gTjCoyE1Rg/9T4g=;
        b=Z5BXBvlV1XTpcThH6REwDWPJ0Pet28Lb13/RNOFTJSeVDBN+5z2oGJu2bOEjpCTHjL
         WS/LenurWllPVp3V4oleGUSGE54CE1hxaHQDf/Ko7tPcTZT6jCP5Ivt7p6U9yIgYWrDU
         7QCBOx3YHBBgCk2mNFBsXkN8M9Mb85pe1mQjpRdAXckbpJCWhOWqKKkIIPyj8XkH5VdV
         shpnysRo5vrEqssSZakYKbHcF5OqRoDN9OOJHYH6m5AlwCUTEXQebqY7GufG0kAodC/2
         1VhHa2DqJFxpHSzvk/MNNgI+8LkufbgA63jiKsiJsVgx6FG0H5DHO16kwKAB34hEdEXF
         mhGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678956646;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=51/nTYkosNBqLROCNsVRN91VZz41gTjCoyE1Rg/9T4g=;
        b=1n58zERQozEoK/nhMbIv/Ws2T/TASAvOXeRB6HbjXPEdqgvwfl61WrNewjamZMJrL5
         pmopC7WUAKLP4gPRD6rHKbxu//dNrJ79Yd2GPQjufyOrXu0I0/6TNyS44UPQuI3EYAQR
         AZV0nuErjybeBxtkuVYQn0IzQGDLSbChoSQFnNEGFrUcvEauSMHMOvad6qkAcfzw14sM
         g8nHF6yzb3w3RYthVze2k2O9b+lTZjaH6Pzgu2dNDj+z4eunyUHzCO1Xw2X3MIe9fbdE
         9pUrbLuGh255VAk+mcfllYTBhqVEMQnpy2CDwD5clXaTZbxDxZvtWKHqVFoOc5NorPu+
         E1eg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXW5zrCIi6pX/b8aohuaTXwGgh6ZNLEj2rvZ+ygT/yldGMIAATs
	/LreIK9DNcLG3Dm+Yl/piKM=
X-Google-Smtp-Source: AK7set8WCIfqhmbEXLEae0FarfMwv8Qraukirfyr+Wn55LbXFzb4eHml8KR8InKzVQioLgGIhwWNzQ==
X-Received: by 2002:a65:43c4:0:b0:50b:c950:b829 with SMTP id n4-20020a6543c4000000b0050bc950b829mr645404pgp.1.1678956646470;
        Thu, 16 Mar 2023 01:50:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4b02:b0:23c:1f9b:df20 with SMTP id
 lx2-20020a17090b4b0200b0023c1f9bdf20ls1360075pjb.1.-pod-control-gmail; Thu,
 16 Mar 2023 01:50:45 -0700 (PDT)
X-Received: by 2002:a17:902:d4c8:b0:19a:b033:2bb0 with SMTP id o8-20020a170902d4c800b0019ab0332bb0mr3346930plg.46.1678956645656;
        Thu, 16 Mar 2023 01:50:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678956645; cv=none;
        d=google.com; s=arc-20160816;
        b=hGhlcFYblJTN6ekotpJpzDbDp/Ql+FTCascAaFal9X3Pc6CGckzalW/VHmT1CNK4Kp
         Y+UD+dZnkec7CSSiikLx1U1qqY8yXFFHGDU430g3qFHWtQiQ4enY8KB4cVcgLQ5M7M3D
         ZnO3qBN+9/t/Eh0jVXYeTRYMsR2EITGy5aXySZ8fj9mGRZYaMaCq7HfGg6dTroaQsn84
         n+AUVMt9Wg+09QvQhZ6epeOd/0Ey43YT9O5l6N2QXUaeL3MKHse5CRFuUrvrtBQfqeK3
         3Neszx9rsGJqlratvxjn1Kn01YXuSd/pDyKBgDghPxNE8FZgEyTSD3TiKw9i3b1T19wy
         YGJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=e82hxHn52yqSiK6HiEB47+42nkEcrdxP6ydPxrg8nW8=;
        b=B9B1HapWDuYSCX5OBn5q/AFGqWqarh0M9yKl6hsRgOPdy1XK2Ge0o78h2AH9kxjNyc
         RGuo+jamOOzGVG69cGE8lohCDPPW3J5FEDmCiGgLQnHLQ2FmgLkhleCysKgedDO92ukx
         2iSTUciSQX1J9CuT+22TKIcHIihdXFcltEqSdcMdqWmASanzyVFCX8HAI9P9awiGMz8k
         IiNLBNY1hzF54EsSCqNxmaLefi95GCEpPFPXFy9poEpBBklcDWBSbB26pfB/FABghEKY
         uU//3KrkaVqOrzlqFkS5wyLblhzS7AtHqZlhzkmWG9XfpUScFuRkUmQ+g/U3kzoGyp+E
         5j8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=NSFDRT5F;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id n2-20020a170902968200b0019d20d70d5dsi283762plp.4.2023.03.16.01.50.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Mar 2023 01:50:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279873.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32G6I5GD029854;
	Thu, 16 Mar 2023 08:50:41 GMT
Received: from nalasppmta03.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3pbpy3h8a3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Mar 2023 08:50:41 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA03.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32G8oe0m000605
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Mar 2023 08:50:40 GMT
Received: from zhenhuah-gv.qualcomm.com (10.80.80.8) by
 nalasex01a.na.qualcomm.com (10.47.209.196) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.986.41; Thu, 16 Mar 2023 01:50:35 -0700
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
To: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <elver@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>, <wangkefeng.wang@huawei.com>
CC: Zhenhua Huang <quic_zhenhuah@quicinc.com>,
        <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>,
        <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>
Subject: [PATCH v9] mm,kfence: decouple kfence from page granularity mapping judgement
Date: Thu, 16 Mar 2023 16:50:20 +0800
Message-ID: <1678956620-26103-1-git-send-email-quic_zhenhuah@quicinc.com>
X-Mailer: git-send-email 2.7.4
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: 0HFkjlROkqOfuMDTe0_Xwv9AnTTKv4bV
X-Proofpoint-ORIG-GUID: 0HFkjlROkqOfuMDTe0_Xwv9AnTTKv4bV
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-16_06,2023-03-15_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501 mlxscore=0
 bulkscore=0 mlxlogscore=999 impostorscore=0 lowpriorityscore=0
 suspectscore=0 phishscore=0 malwarescore=0 adultscore=0 clxscore=1015
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2303150002 definitions=main-2303160074
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=NSFDRT5F;       spf=pass
 (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131
 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
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

Kfence only needs its pool to be mapped as page granularity, if it is
inited early. Previous judgement was a bit over protected. From [1], Mark
suggested to "just map the KFENCE region a page granularity". So I
decouple it from judgement and do page granularity mapping for kfence
pool only. Need to be noticed that late init of kfence pool still requires
page granularity mapping.

Page granularity mapping in theory cost more(2M per 1GB) memory on arm64
platform. Like what I've tested on QEMU(emulated 1GB RAM) with
gki_defconfig, also turning off rodata protection:
Before:
[root@liebao ]# cat /proc/meminfo
MemTotal:         999484 kB
After:
[root@liebao ]# cat /proc/meminfo
MemTotal:        1001480 kB

To implement this, also relocate the kfence pool allocation before the
linear mapping setting up, arm64_kfence_alloc_pool is to allocate phys
addr, __kfence_pool is to be set after linear mapping set up.

LINK: [1] https://lore.kernel.org/linux-arm-kernel/Y+IsdrvDNILA59UN@FVFF77S0Q05N/
Suggested-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
---
 arch/arm64/include/asm/kfence.h | 16 +++++++++++
 arch/arm64/mm/mmu.c             | 59 +++++++++++++++++++++++++++++++++++++++++
 arch/arm64/mm/pageattr.c        |  9 +++++--
 include/linux/kfence.h          |  1 +
 mm/kfence/core.c                |  4 +++
 5 files changed, 87 insertions(+), 2 deletions(-)

diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
index aa855c6..8143c91 100644
--- a/arch/arm64/include/asm/kfence.h
+++ b/arch/arm64/include/asm/kfence.h
@@ -10,6 +10,22 @@
 
 #include <asm/set_memory.h>
 
+extern phys_addr_t early_kfence_pool;
+
+#ifdef CONFIG_KFENCE
+
+extern char *__kfence_pool;
+static inline void kfence_set_pool(phys_addr_t addr)
+{
+	__kfence_pool = phys_to_virt(addr);
+}
+
+#else
+
+static inline void kfence_set_pool(phys_addr_t addr) { }
+
+#endif
+
 static inline bool arch_kfence_init_pool(void) { return true; }
 
 static inline bool kfence_protect_page(unsigned long addr, bool protect)
diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index 6f9d889..61944c70 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -24,6 +24,7 @@
 #include <linux/mm.h>
 #include <linux/vmalloc.h>
 #include <linux/set_memory.h>
+#include <linux/kfence.h>
 
 #include <asm/barrier.h>
 #include <asm/cputype.h>
@@ -38,6 +39,7 @@
 #include <asm/ptdump.h>
 #include <asm/tlbflush.h>
 #include <asm/pgalloc.h>
+#include <asm/kfence.h>
 
 #define NO_BLOCK_MAPPINGS	BIT(0)
 #define NO_CONT_MAPPINGS	BIT(1)
@@ -525,6 +527,48 @@ static int __init enable_crash_mem_map(char *arg)
 }
 early_param("crashkernel", enable_crash_mem_map);
 
+#ifdef CONFIG_KFENCE
+
+static bool kfence_early_init __initdata = !!CONFIG_KFENCE_SAMPLE_INTERVAL;
+/*
+ * early_param can be parsed before linear mapping
+ * set up
+ */
+static int __init parse_kfence_early_init(char *p)
+{
+	int val;
+
+	if (get_option(&p, &val))
+		kfence_early_init = !!val;
+	return 0;
+}
+early_param("kfence.sample_interval", parse_kfence_early_init);
+
+static phys_addr_t arm64_kfence_alloc_pool(void)
+{
+	phys_addr_t kfence_pool;
+
+	if (!kfence_early_init)
+		return 0;
+
+	kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
+	if (!kfence_pool)
+		pr_err("failed to allocate kfence pool\n");
+
+	return kfence_pool;
+}
+
+#else
+
+static phys_addr_t arm64_kfence_alloc_pool(void)
+{
+	return 0;
+}
+
+#endif
+
+phys_addr_t early_kfence_pool;
+
 static void __init map_mem(pgd_t *pgdp)
 {
 	static const u64 direct_map_end = _PAGE_END(VA_BITS_MIN);
@@ -543,6 +587,10 @@ static void __init map_mem(pgd_t *pgdp)
 	 */
 	BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
 
+	early_kfence_pool = arm64_kfence_alloc_pool();
+	if (early_kfence_pool)
+		memblock_mark_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
+
 	if (can_set_direct_map())
 		flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
 
@@ -608,6 +656,17 @@ static void __init map_mem(pgd_t *pgdp)
 		}
 	}
 #endif
+
+	/* Kfence pool needs page-level mapping */
+	if (early_kfence_pool) {
+		__map_memblock(pgdp, early_kfence_pool,
+			early_kfence_pool + KFENCE_POOL_SIZE,
+			pgprot_tagged(PAGE_KERNEL),
+			NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
+		memblock_clear_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
+		/* kfence_pool really mapped now */
+		kfence_set_pool(early_kfence_pool);
+	}
 }
 
 void mark_rodata_ro(void)
diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
index 79dd201..7ce5295 100644
--- a/arch/arm64/mm/pageattr.c
+++ b/arch/arm64/mm/pageattr.c
@@ -7,10 +7,12 @@
 #include <linux/module.h>
 #include <linux/sched.h>
 #include <linux/vmalloc.h>
+#include <linux/kfence.h>
 
 #include <asm/cacheflush.h>
 #include <asm/set_memory.h>
 #include <asm/tlbflush.h>
+#include <asm/kfence.h>
 
 struct page_change_data {
 	pgprot_t set_mask;
@@ -22,12 +24,15 @@ bool rodata_full __ro_after_init = IS_ENABLED(CONFIG_RODATA_FULL_DEFAULT_ENABLED
 bool can_set_direct_map(void)
 {
 	/*
-	 * rodata_full, DEBUG_PAGEALLOC and KFENCE require linear map to be
+	 * rodata_full and DEBUG_PAGEALLOC require linear map to be
 	 * mapped at page granularity, so that it is possible to
 	 * protect/unprotect single pages.
+	 *
+	 * Kfence pool requires page granularity mapping also if we init it
+	 * late.
 	 */
 	return (rodata_enabled && rodata_full) || debug_pagealloc_enabled() ||
-		IS_ENABLED(CONFIG_KFENCE);
+	    (IS_ENABLED(CONFIG_KFENCE) && !early_kfence_pool);
 }
 
 static int change_page_range(pte_t *ptep, unsigned long addr, void *data)
diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 726857a..91cbcc9 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -222,6 +222,7 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
 
 #else /* CONFIG_KFENCE */
 
+#define KFENCE_POOL_SIZE 0
 static inline bool is_kfence_address(const void *addr) { return false; }
 static inline void kfence_alloc_pool(void) { }
 static inline void kfence_init(void) { }
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 5349c37..e05ccf1 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -814,6 +814,10 @@ void __init kfence_alloc_pool(void)
 	if (!kfence_sample_interval)
 		return;
 
+	/* if the pool has already been initialized by arch, skip the below */
+	if (__kfence_pool)
+		return;
+
 	__kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
 
 	if (!__kfence_pool)
-- 
2.7.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1678956620-26103-1-git-send-email-quic_zhenhuah%40quicinc.com.
