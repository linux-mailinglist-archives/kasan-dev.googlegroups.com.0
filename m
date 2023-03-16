Return-Path: <kasan-dev+bncBDVL3PXJZILBBKUSZSQAMGQET64L2PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F7C46BCF3D
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 13:18:52 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id e129-20020a251e87000000b00b56598237f5sf1634005ybe.16
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 05:18:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678969131; cv=pass;
        d=google.com; s=arc-20160816;
        b=AXb+6F3VHIBmiM9VzbwaIATtvRMmCdot3gry9kEbEeLrM82M5E2QG6ogQl9t7NBmZb
         JYtBhpwWFpbxU3w1JbLtOcP/L4XQaUVl+evMOsqsRfoqeLcS/MFiJuA408Wz/eGAiOge
         IXD3no954AAZ4LP5sPEWcyLrgWSSFinsw6Kf4xVoBnZTfAK0T5d70KipiQdi8vovumPZ
         FSimpeaOdGiVBlf/EVrDAOQzWeG2e6d9ljxaNmKmbSI6Shu/hFVilFvEsvVxRObJ/GSE
         AoisAL3+ToYa+yoCMR0d8r1VAkVRKKh9eCrdn/bZgSbPwllExrOoEaWrdEbH/inhDgae
         E77g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=vJxiDTdynH8vfcBXRNpgXVeLlvLgXZeAmTizvPNRVUE=;
        b=pdl2D9u+TAUICUk7gq8rsb+bLKiVQyOZ9btLLhwUhYqhkHKfv4FQvH8u55EMmQzIQF
         cpmtmagfot0glZ4O24NOLZH6kDsAayn6SIP7BxicxUss4gVI+5vBlRWnXu6BH6GkPK1w
         IVw59kXsoMm9i1uce+P+JLrjDM4yx3uZcx83mWpUkN3mO+7gchPonQD/Up8VNuY3aqz9
         3jNBg5UCTfQt7bziWSLX+iFTWHhs8WkSSCZV/y1lj+xrH4POpDyR3dEPBvcP+hYqTgdu
         P2/gEESj3jk7W8LAVGwJlMaTjUAZfTMRvWlU6u8RrlEoIAX+eZpbjwwSzRl1L4L0lk6t
         2vdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=ZSYKbSe4;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678969131;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vJxiDTdynH8vfcBXRNpgXVeLlvLgXZeAmTizvPNRVUE=;
        b=F9FJlP19IzjnjQmU9KAo/O5APAR7+vVyqm5raVb8mRDCazy8iffSoq1alCsrGAzor6
         NuhsifFKTMR2Ht4RiEjsBReLg1y4TmZx+T3dYS82YhXlDpDFIzdeeE4tnxlSqdaUg4cu
         G1QLhrvLgpyZw2r2CuF2BuyrotWi1ZfcRwJHVr1jsaGL96SScuue5Dh0EBMyKKFz16Gl
         68dhXwZq53Q3FRI43oYnBqvWMvlZk8iyJpMJlkwbYsVSI2l7rak8i4Hss24aB0IRm3kp
         jXL8DKjV3jfejUsjQOeZubOgX5ree39j/nBrK9kg8Un1zuYOiqEl4hH+k3GThLwvvZMw
         ccVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678969131;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=vJxiDTdynH8vfcBXRNpgXVeLlvLgXZeAmTizvPNRVUE=;
        b=G/rEHMviqGgLEArfGCl4VgxzD71gpjmO4UYMAe57wCC3/FvDVetmoS/9V0GoN+kHJS
         wfoCsUQ5ydKNN6bP3eQTdTCYCmW1BNHBbUov0fh42UHH+K0L8BCT/DZ72wGMJ7C1k19Z
         37xPNuABbT3leW+S5eWKB2/4WugphQDDZbnoatNS1A+qbdrzTbqsz2TFYiQe+S2L+slb
         fIlm5lgQIQLWB3q+n9j+tRbF5zFclNy2TB7GyhFkIB13tsLgmi9wv4SQQRPLxS0IkHRT
         wem2SBnZDGeDdfZRLLwIABnGcYQvSRhTo4t/xVsjsJwAs80sSLovHhRhIfurU2ww3EHa
         EsJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUeaczRER1GfxnNa6mep84jRL1O8Cfa6QRLzYkPPgSWBcBDNjN7
	lsBiwo5Pvz3KRFdeKc0b/LGgRg==
X-Google-Smtp-Source: AK7set/QpsqZGlk0gdRPM6Kpj463XBsLR7rb+MjfK0HTjaJbwRS4yh3fM0uiLrCiP7kbr+L0GZHqbQ==
X-Received: by 2002:a81:af63:0:b0:52e:d380:ab14 with SMTP id x35-20020a81af63000000b0052ed380ab14mr736006ywj.3.1678969131130;
        Thu, 16 Mar 2023 05:18:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:72d6:0:b0:541:a39a:5892 with SMTP id n205-20020a8172d6000000b00541a39a5892ls659324ywc.5.-pod-prod-gmail;
 Thu, 16 Mar 2023 05:18:50 -0700 (PDT)
X-Received: by 2002:a81:484e:0:b0:544:5382:be95 with SMTP id v75-20020a81484e000000b005445382be95mr3192074ywa.15.1678969130373;
        Thu, 16 Mar 2023 05:18:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678969130; cv=none;
        d=google.com; s=arc-20160816;
        b=kfveWeB+CGfwc+FZE3By9EZveB6xkToRgFe75Yc0t8ijsT3gt3DSFNKSi2GhGiAWhR
         B4yd6NXH5CZNuNED/ii9Mdl77KXCZ9wZdl+C9TkuHCN3DtSX8aOZLS1/fzaja5SUYTGu
         xePiBriw2MzAe2o9/ZteSt/LGS0YeHc95cn44WPjhpsIj1D2oi0OgXgRPf2RJdhvONzb
         6t3PM824+Tvp1mc6MMrMBPX1xA6+LiZNt96mu7nseenYIwWG98vCxDnF4RLXaRribVAX
         F3wR6ItjV0HSQrXJVG0bclOI9fSkIV/71ASrAkn0n8S5v3A4JBUp1c3VpaUr1kAYHDq1
         5kAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=pt6m/4EMXuhZyv7EYfDFeBNPiQPywUM74OkTDbTcPuM=;
        b=CX0W9gbMc1yY0uhnAAvFRQSbE2IQZQW9/4xHowwytJ/+reWCjHZ0ZX1AjkWUCXYh6j
         HX9Fx0vRJPNpZOoaMXt9fRxH1jdMdj9zLkAFyZS8TdaWXKN6G18mXk1MsK4W8fTaFIAO
         WOtWnYacYMVn8N2PH+R7Yw/azFEHdX6zggKh0asNgLtLGaQEPKr7/9yr3S8lQVD3M/jX
         t0BSezLq8xwEpUJsZ/iHNrVOaWHvwCs/+sr+I+Svjqtx7VkfVG+eD4S72uvjHbgY/k7s
         bBLicicm/PVCOtMre+INtVZnHefNEv7biteahHj7Wd//lKiq8+FZI2T7cJ5rR3RPxRdV
         IDpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=ZSYKbSe4;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id bf9-20020a05690c028900b0053cba27e38dsi516257ywb.1.2023.03.16.05.18.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Mar 2023 05:18:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279865.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32G4kFOd011172;
	Thu, 16 Mar 2023 12:18:43 GMT
Received: from nalasppmta04.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3pbpxshs6r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Mar 2023 12:18:43 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA04.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32GCIgeF012416
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Mar 2023 12:18:42 GMT
Received: from zhenhuah-gv.qualcomm.com (10.80.80.8) by
 nalasex01a.na.qualcomm.com (10.47.209.196) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.986.41; Thu, 16 Mar 2023 05:18:37 -0700
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
To: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <elver@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>, <wangkefeng.wang@huawei.com>
CC: Zhenhua Huang <quic_zhenhuah@quicinc.com>,
        <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>,
        <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>
Subject: [PATCH v10] mm,kfence: decouple kfence from page granularity mapping judgement
Date: Thu, 16 Mar 2023 20:18:30 +0800
Message-ID: <1678969110-11941-1-git-send-email-quic_zhenhuah@quicinc.com>
X-Mailer: git-send-email 2.7.4
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: DCngU5f5BFwvwhE-Qhk82Xat-Ktq3CyO
X-Proofpoint-ORIG-GUID: DCngU5f5BFwvwhE-Qhk82Xat-Ktq3CyO
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-16_08,2023-03-16_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 phishscore=0
 lowpriorityscore=0 adultscore=0 priorityscore=1501 malwarescore=0
 impostorscore=0 mlxscore=0 mlxlogscore=999 suspectscore=0 bulkscore=0
 clxscore=1015 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2303150002 definitions=main-2303160102
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=ZSYKbSe4;       spf=pass
 (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131
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
 arch/arm64/include/asm/kfence.h | 10 +++++++
 arch/arm64/mm/mmu.c             | 61 +++++++++++++++++++++++++++++++++++++++++
 arch/arm64/mm/pageattr.c        |  7 +++--
 mm/kfence/core.c                |  4 +++
 4 files changed, 80 insertions(+), 2 deletions(-)

diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
index aa855c6..a81937f 100644
--- a/arch/arm64/include/asm/kfence.h
+++ b/arch/arm64/include/asm/kfence.h
@@ -19,4 +19,14 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
 	return true;
 }
 
+#ifdef CONFIG_KFENCE
+extern bool kfence_early_init;
+static inline bool arm64_kfence_can_set_direct_map(void)
+{
+	return !kfence_early_init;
+}
+#else /* CONFIG_KFENCE */
+static inline bool arm64_kfence_can_set_direct_map(void) { return false; }
+#endif /* CONFIG_KFENCE */
+
 #endif /* __ASM_KFENCE_H */
diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index ae25524d..aaf1801 100644
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
@@ -521,12 +523,67 @@ static int __init enable_crash_mem_map(char *arg)
 }
 early_param("crashkernel", enable_crash_mem_map);
 
+#ifdef CONFIG_KFENCE
+
+bool kfence_early_init = !!CONFIG_KFENCE_SAMPLE_INTERVAL;
+
+/* early_param() will be parsed before map_mem() below. */
+static int __init parse_kfence_early_init(char *arg)
+{
+	int val;
+
+	if (get_option(&arg, &val))
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
+	if (!kfence_pool) {
+		pr_err("failed to allocate kfence pool\n");
+		kfence_early_init = false;
+		return 0;
+	}
+
+	/* Temporarily mark as NOMAP. */
+	memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
+
+	return kfence_pool;
+}
+
+static void arm64_kfence_map_pool(phys_addr_t kfence_pool, pgd_t *pgdp)
+{
+	if (!kfence_pool)
+		return;
+
+	/* KFENCE pool needs page-level mapping. */
+	__map_memblock(pgdp, kfence_pool, kfence_pool + KFENCE_POOL_SIZE,
+			pgprot_tagged(PAGE_KERNEL),
+			NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
+	memblock_clear_nomap(kfence_pool, KFENCE_POOL_SIZE);
+	__kfence_pool = phys_to_virt(kfence_pool);
+}
+#else /* CONFIG_KFENCE */
+
+static inline phys_addr_t arm64_kfence_alloc_pool(void) { return 0; }
+static inline void arm64_kfence_map_pool(phys_addr_t kfence_pool, pgd_t *pgdp) { }
+
+#endif /* CONFIG_KFENCE */
+
 static void __init map_mem(pgd_t *pgdp)
 {
 	static const u64 direct_map_end = _PAGE_END(VA_BITS_MIN);
 	phys_addr_t kernel_start = __pa_symbol(_stext);
 	phys_addr_t kernel_end = __pa_symbol(__init_begin);
 	phys_addr_t start, end;
+	phys_addr_t early_kfence_pool;
 	int flags = NO_EXEC_MAPPINGS;
 	u64 i;
 
@@ -539,6 +596,8 @@ static void __init map_mem(pgd_t *pgdp)
 	 */
 	BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
 
+	early_kfence_pool = arm64_kfence_alloc_pool();
+
 	if (can_set_direct_map())
 		flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
 
@@ -604,6 +663,8 @@ static void __init map_mem(pgd_t *pgdp)
 		}
 	}
 #endif
+
+	arm64_kfence_map_pool(early_kfence_pool, pgdp);
 }
 
 void mark_rodata_ro(void)
diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
index debdecf..dd1291a 100644
--- a/arch/arm64/mm/pageattr.c
+++ b/arch/arm64/mm/pageattr.c
@@ -11,6 +11,7 @@
 #include <asm/cacheflush.h>
 #include <asm/set_memory.h>
 #include <asm/tlbflush.h>
+#include <asm/kfence.h>
 
 struct page_change_data {
 	pgprot_t set_mask;
@@ -22,12 +23,14 @@ bool rodata_full __ro_after_init = IS_ENABLED(CONFIG_RODATA_FULL_DEFAULT_ENABLED
 bool can_set_direct_map(void)
 {
 	/*
-	 * rodata_full, DEBUG_PAGEALLOC and KFENCE require linear map to be
+	 * rodata_full and DEBUG_PAGEALLOC require linear map to be
 	 * mapped at page granularity, so that it is possible to
 	 * protect/unprotect single pages.
+	 *
+	 * KFENCE pool requires page-granular mapping if initialized late.
 	 */
 	return (rodata_enabled && rodata_full) || debug_pagealloc_enabled() ||
-		IS_ENABLED(CONFIG_KFENCE);
+		arm64_kfence_can_set_direct_map();
 }
 
 static int change_page_range(pte_t *ptep, unsigned long addr, void *data)
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 1417888..bf2f194c 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -824,6 +824,10 @@ void __init kfence_alloc_pool(void)
 	if (!kfence_sample_interval)
 		return;
 
+	/* if the pool has already been initialized by arch, skip the below. */
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1678969110-11941-1-git-send-email-quic_zhenhuah%40quicinc.com.
